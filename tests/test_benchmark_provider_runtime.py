from __future__ import annotations

import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from zscope.benchmarking import provider_runtime
from zscope.benchmarking.isolation import build_oci_isolation_plan
from zscope.benchmarking.provider_runtime import (
    ProviderProbeError,
    ProviderProbeResponse,
    ProviderRuntimeContract,
    ProviderRuntimeError,
    load_explicit_api_key_file,
    probe_provider,
    reject_conflicting_provider_identity_environment,
    require_p6_provider_contract,
    required_environment_keys,
)
from zscope.benchmarking.runner import SPECS
from zscope.benchmarking import runner as benchmark_runner


RANGE_BASE_URL = "https://st8tp3ajl0df3n8b8l8qu.apigateway-cn-beijing.volceapi.com/v1"


def _regular_mode(monkeypatch: pytest.MonkeyPatch, path: Path, mode: int = 0o600) -> None:
    original_lstat = Path.lstat
    original_fstat = provider_runtime.os.fstat

    def shaped(result):
        return SimpleNamespace(
            st_mode=stat.S_IFREG | mode,
            st_dev=result.st_dev,
            st_ino=result.st_ino,
            st_size=result.st_size,
            st_mtime_ns=result.st_mtime_ns,
            st_ctime_ns=result.st_ctime_ns,
        )

    def fake_lstat(self: Path):
        result = original_lstat(self)
        if self == path:
            return shaped(result)
        return result

    def fake_fstat(descriptor: int):
        return shaped(original_fstat(descriptor))

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    monkeypatch.setattr(provider_runtime.os, "fstat", fake_fstat)


def _contract(config_path: Path) -> ProviderRuntimeContract:
    profile = SimpleNamespace(base_urls=[RANGE_BASE_URL], models=["GLM-5.2"])
    return ProviderRuntimeContract.from_effective_config(
        SimpleNamespace(llm=profile, llms={"default": profile}),
        config_path=config_path,
    )


def test_range_requires_only_api_key_while_java_keeps_variable_provider_identity() -> None:
    assert required_environment_keys(SPECS["c_cpp"].config_path) == ("Z_SCOPE_API_KEY",)
    assert required_environment_keys(SPECS["java"].config_path) == (
        "Z_SCOPE_API_KEY",
        "Z_SCOPE_LLM_BASE_URL",
        "Z_SCOPE_LLM_MODEL",
    )


def test_range_provider_config_is_exact_and_bounded() -> None:
    raw = yaml.safe_load(SPECS["c_cpp"].config_path.read_text(encoding="utf-8"))
    profile = raw["llms"]["default"]

    assert profile == {
        "base_urls": [RANGE_BASE_URL],
        "models": ["GLM-5.2"],
        "api_key": "${Z_SCOPE_API_KEY}",
        "base_url_max_concurrent_requests": 8,
        "max_tokens": 8192,
        "max_retries": 2,
        "retry_until_available": False,
        "require_exact_response_model": True,
        "timeout": 120,
    }
    assert raw["concurrency"]["llm_max_inflight"] == 8
    assert require_p6_provider_contract(SPECS["c_cpp"].config_path).model == "GLM-5.2"


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("llms", "default", "models"), ["GLM-5.2-alias"]),
        (("llms", "default", "base_urls"), ["https://example.invalid/v1"]),
        (("llms", "default", "api_key"), "${ANOTHER_KEY}"),
        (("llms", "default", "base_url_max_concurrent_requests"), 7),
        (("llms", "default", "max_tokens"), 4096),
        (("llms", "default", "max_tokens"), 8192.0),
        (("llms", "default", "max_retries"), 3),
        (("llms", "default", "max_retries"), 2.0),
        (("llms", "default", "retry_until_available"), True),
        (("llms", "default", "timeout"), 121),
        (("llms", "default", "timeout"), 120.0),
        (("concurrency", "llm_max_inflight"), 7),
        (("llms", "default", "require_exact_response_model"), False),
    ],
)
def test_p6_provider_contract_rejects_any_identity_or_concurrency_drift(
    tmp_path: Path, path: tuple[str, ...], value: object
) -> None:
    raw = yaml.safe_load(SPECS["c_cpp"].config_path.read_text(encoding="utf-8"))
    owner = raw
    for part in path[:-1]:
        owner = owner[part]
    owner[path[-1]] = value
    config = tmp_path / "zscope.yaml"
    config.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    with pytest.raises(ProviderRuntimeError, match="provider_identity_mismatch"):
        require_p6_provider_contract(config)


@pytest.mark.parametrize("drift", ["extra_profile", "role_routing"])
def test_p6_provider_contract_rejects_any_alternate_profile_route(
    tmp_path: Path, drift: str
) -> None:
    raw = yaml.safe_load(SPECS["c_cpp"].config_path.read_text(encoding="utf-8"))
    if drift == "extra_profile":
        raw["llms"]["alternate"] = dict(raw["llms"]["default"])
    else:
        raw["scan"]["llm_profiles"] = {
            "modeling": "default",
            "analysis": "alternate",
            "validation": "default",
        }
    config = tmp_path / "zscope.yaml"
    config.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    with pytest.raises(ProviderRuntimeError, match="provider_identity_mismatch"):
        require_p6_provider_contract(config)


def test_provider_runtime_contract_binds_resolved_identity_and_config() -> None:
    contract = _contract(SPECS["c_cpp"].config_path)
    payload = contract.as_dict()

    assert payload["base_url"] == RANGE_BASE_URL
    assert payload["model"] == "GLM-5.2"
    assert payload["required_environment_keys"] == ["Z_SCOPE_API_KEY"]
    assert len(payload["config_sha256"]) == 64
    assert len(payload["identity_sha256"]) == 64
    assert json.dumps(payload, sort_keys=True)


def test_p6_provider_identity_is_stable_across_depth_specific_execution_configs(
    tmp_path: Path,
) -> None:
    source = SPECS["c_cpp"].config_path
    identities = set()
    execution_hashes = set()
    for depth in ("fast", "balanced", "deep"):
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
        raw["scan"]["depth"] = depth
        execution = tmp_path / f"{depth}.yaml"
        execution.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

        contract = benchmark_runner._p6_provider_contract_for_execution(
            execution, source_config=source
        )
        identities.add(contract.identity_sha256)
        execution_hashes.add(provider_runtime._file_sha256(execution))

    assert len(execution_hashes) == 3
    assert identities == {require_p6_provider_contract(source).identity_sha256}


def test_fixed_provider_rejects_only_conflicting_legacy_identity() -> None:
    contract = _contract(SPECS["c_cpp"].config_path)
    reject_conflicting_provider_identity_environment(
        contract,
        {
            "Z_SCOPE_LLM_BASE_URL": RANGE_BASE_URL,
            "Z_SCOPE_LLM_MODEL": "GLM-5.2",
        },
    )

    with pytest.raises(ProviderRuntimeError, match="provider_identity_override_attempt"):
        reject_conflicting_provider_identity_environment(
            contract,
            {"Z_SCOPE_LLM_MODEL": "GLM-5.1"},
        )


def test_explicit_api_key_file_accepts_only_comments_export_and_one_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "private.env"
    path.write_text(
        "# private\n\nexport Z_SCOPE_API_KEY='key-value'\n",
        encoding="utf-8",
    )
    _regular_mode(monkeypatch, path)

    assert load_explicit_api_key_file(path) == {"Z_SCOPE_API_KEY": "key-value"}


@pytest.mark.parametrize(
    "content, message",
    [
        ("Z_SCOPE_LLM_MODEL=GLM-5.2\n", "unexpected provider credential key"),
        ("Z_SCOPE_API_KEY=one\nZ_SCOPE_API_KEY=two\n", "duplicate provider credential key"),
        ("Z_SCOPE_API_KEY=\n", "must not be empty"),
        ("Z_SCOPE_API_KEY='unterminated\n", "quoting is invalid"),
        ('Z_SCOPE_API_KEY="valid"trailing\n', "quoting is invalid"),
        ("Z_SCOPE_API_KEY=has\x00nul\n", "control characters"),
        ("not-an-assignment\n", "invalid provider credential assignment"),
        ("# no key\n", "provider_credentials_unavailable"),
    ],
)
def test_explicit_api_key_file_rejects_invalid_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: str,
    message: str,
) -> None:
    path = tmp_path / "private.env"
    path.write_text(content, encoding="utf-8")
    _regular_mode(monkeypatch, path)

    with pytest.raises(ProviderRuntimeError, match=message):
        load_explicit_api_key_file(path)


def test_explicit_api_key_file_rejects_symlink_nonregular_and_broad_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "private.env"
    path.write_text("Z_SCOPE_API_KEY=secret\n", encoding="utf-8")

    original_lstat = Path.lstat
    original_fstat = provider_runtime.os.fstat

    for unsafe_mode, message in (
        (stat.S_IFLNK | 0o777, "symbolic link"),
        (stat.S_IFDIR | 0o700, "regular file"),
        (stat.S_IFREG | 0o640, "permissions are too broad"),
    ):

        def shaped(result, selected_mode: int = unsafe_mode):
            return SimpleNamespace(
                st_mode=selected_mode,
                st_dev=result.st_dev,
                st_ino=result.st_ino,
                st_size=result.st_size,
                st_mtime_ns=result.st_mtime_ns,
                st_ctime_ns=result.st_ctime_ns,
            )

        def fake_lstat(self: Path):
            result = original_lstat(self)
            if self == path:
                return shaped(result)
            return result

        def fake_fstat(descriptor: int):
            return shaped(original_fstat(descriptor))

        with monkeypatch.context() as context:
            context.setattr(Path, "lstat", fake_lstat)
            context.setattr(provider_runtime.os, "fstat", fake_fstat)
            with pytest.raises(ProviderRuntimeError, match=message):
                load_explicit_api_key_file(path)


def test_explicit_api_key_file_rejects_replacement_between_lstat_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "private.env"
    path.write_text("Z_SCOPE_API_KEY=first\n", encoding="utf-8")
    _regular_mode(monkeypatch, path)
    original_open = provider_runtime.os.open
    replaced = False

    def replacing_open(target, flags, *args, **kwargs):
        nonlocal replaced
        if Path(target) == path and not replaced:
            replaced = True
            path.unlink()
            path.write_text("Z_SCOPE_API_KEY=replacement\n", encoding="utf-8")
        return original_open(target, flags, *args, **kwargs)

    monkeypatch.setattr(provider_runtime.os, "open", replacing_open)

    with pytest.raises(ProviderRuntimeError, match="changed during validation"):
        load_explicit_api_key_file(path)


def test_p6_provider_config_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    config = tmp_path / "duplicate.yaml"
    config.write_text(
        SPECS["c_cpp"].config_path.read_text(encoding="utf-8")
        + "\nconcurrency:\n  llm_max_inflight: 8\n",
        encoding="utf-8",
    )

    with pytest.raises(ProviderRuntimeError, match="unreadable"):
        require_p6_provider_contract(config)


def test_p6_provider_config_rejects_replacement_between_lstat_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "provider.yaml"
    config.write_bytes(SPECS["c_cpp"].config_path.read_bytes())
    original_open = provider_runtime.os.open
    replaced = False

    def replacing_open(target, flags, *args, **kwargs):
        nonlocal replaced
        if Path(target) == config and not replaced:
            replaced = True
            config.unlink()
            config.write_bytes(SPECS["c_cpp"].config_path.read_bytes() + b"\n")
        return original_open(target, flags, *args, **kwargs)

    monkeypatch.setattr(provider_runtime.os, "open", replacing_open)

    with pytest.raises(ProviderRuntimeError, match="changed during validation"):
        require_p6_provider_contract(config)


def test_p6_provider_contract_uses_one_frozen_config_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = provider_runtime._read_config_snapshot
    calls = 0

    def read_once(path: Path):
        nonlocal calls
        calls += 1
        return original(path)

    monkeypatch.setattr(provider_runtime, "_read_config_snapshot", read_once)

    contract = require_p6_provider_contract(SPECS["c_cpp"].config_path)

    assert contract.model == "GLM-5.2"
    assert calls == 1


def test_p6_provider_contract_rejects_symlink_config(tmp_path: Path) -> None:
    link = tmp_path / "provider.yaml"
    try:
        link.symlink_to(SPECS["c_cpp"].config_path)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(ProviderRuntimeError, match="symbolic link"):
        require_p6_provider_contract(link)


def test_oci_plan_uses_contract_endpoint_and_only_referenced_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_input = tmp_path / "sealed"
    output = tmp_path / "output"
    scan_input.mkdir()
    output.mkdir()
    (scan_input / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    monkeypatch.setattr(
        "zscope.benchmarking.isolation.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    contract = _contract(SPECS["c_cpp"].config_path)

    plan = build_oci_isolation_plan(
        runtime="podman",
        image="repo@sha256:" + "a" * 64,
        scan_input=scan_input,
        artifact_output=output,
        scan_command=("zscope", "-c", "/zscope-input/zscope.yaml"),
        environment={
            "Z_SCOPE_API_KEY": "secret",
            "Z_SCOPE_LLM_BASE_URL": "https://conflicting.invalid/v1",
            "Z_SCOPE_LLM_MODEL": "wrong-model",
            "Z_SCOPE_BENCHMARK_OCI_NETWORK": "model-only",
            "Z_SCOPE_BENCHMARK_OCI_MODEL_PROXY_CONTAINER": "proxy",
        },
        provider_contract=contract,
    )

    assert plan.environment_keys == ("Z_SCOPE_API_KEY",)
    assert plan.network_mode == "model-endpoint-only"
    assert plan.network_policy_sha256


def test_pilot_loads_only_explicit_file_into_trial_environment_without_global_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "pilot"
    key_file = (tmp_path / "private.env").resolve()
    observed: dict[str, object] = {}
    loaded_credentials = {"Z_SCOPE_API_KEY": "private-value"}
    monkeypatch.setattr(benchmark_runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        benchmark_runner,
        "oci_capability",
        lambda **_kwargs: {"available": True, "errors": []},
    )
    monkeypatch.setattr(benchmark_runner, "_validate_truth", lambda _path: {})
    monkeypatch.setattr(
        benchmark_runner,
        "load_explicit_api_key_file",
        lambda path: (
            observed.setdefault("key_path", path),
            loaded_credentials,
        )[1],
    )

    def fake_trial(_spec, _run_dir, _run_number, **kwargs):
        observed["credentials"] = dict(kwargs["credential_environment"])
        return {"queue_empty": True, "gate_failures": [], "metrics": {}}

    monkeypatch.setattr(benchmark_runner, "_run_trial", fake_trial)
    monkeypatch.setattr(
        benchmark_runner,
        "_aggregate",
        lambda *_args, **_kwargs: {"passed": True, "release_eligible": True},
    )
    monkeypatch.setenv("Z_SCOPE_P6_API_KEY_FILE", str(key_file))
    monkeypatch.setenv("Z_SCOPE_P6_CANDIDATE_COMMIT", "a" * 40)
    monkeypatch.setenv("Z_SCOPE_API_KEY", "global-value-must-not-win")

    result = benchmark_runner.run_benchmark("c_cpp", "pilot", output=output, scan_depth="fast")

    assert observed["key_path"] == key_file
    assert observed["credentials"] == {"Z_SCOPE_API_KEY": "private-value"}
    assert loaded_credentials == {}
    assert benchmark_runner.os.environ["Z_SCOPE_API_KEY"] == "global-value-must-not-win"
    assert result["formal_benchmark"] is False
    assert result["release_eligible"] is False


def test_pilot_clears_loaded_credentials_when_trial_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loaded_credentials = {"Z_SCOPE_API_KEY": "private-value"}
    key_file = (tmp_path / "private.env").resolve()
    monkeypatch.setattr(benchmark_runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        benchmark_runner,
        "oci_capability",
        lambda **_kwargs: {"available": True, "errors": []},
    )
    monkeypatch.setattr(benchmark_runner, "_validate_truth", lambda _path: {})
    monkeypatch.setattr(
        benchmark_runner,
        "load_explicit_api_key_file",
        lambda _path: loaded_credentials,
    )
    monkeypatch.setattr(
        benchmark_runner,
        "_run_trial",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            benchmark_runner.BenchmarkError("private trial failure")
        ),
    )
    monkeypatch.setenv("Z_SCOPE_P6_API_KEY_FILE", str(key_file))
    monkeypatch.setenv("Z_SCOPE_P6_CANDIDATE_COMMIT", "a" * 40)

    with pytest.raises(benchmark_runner.BenchmarkError, match="private trial failure"):
        benchmark_runner.run_benchmark(
            "c_cpp",
            "pilot",
            output=tmp_path / "pilot",
            scan_depth="fast",
        )

    assert loaded_credentials == {}


def test_pilot_never_auto_discovers_a_default_secret_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        benchmark_runner,
        "oci_capability",
        lambda **_kwargs: {"available": True, "errors": []},
    )
    monkeypatch.delenv("Z_SCOPE_P6_API_KEY_FILE", raising=False)
    monkeypatch.setenv("Z_SCOPE_P6_CANDIDATE_COMMIT", "a" * 40)

    with pytest.raises(benchmark_runner.BenchmarkError, match="provider_credentials_unavailable"):
        benchmark_runner.run_benchmark("c_cpp", "pilot", output=tmp_path / "pilot")


@pytest.mark.parametrize("candidate_commit", [None, "main", "A" * 40, "a" * 39])
def test_pilot_requires_exact_lowercase_candidate_commit_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    candidate_commit: str | None,
) -> None:
    monkeypatch.setattr(
        benchmark_runner,
        "oci_capability",
        lambda **_kwargs: {"available": True, "errors": []},
    )
    if candidate_commit is None:
        monkeypatch.delenv("Z_SCOPE_P6_CANDIDATE_COMMIT", raising=False)
    else:
        monkeypatch.setenv("Z_SCOPE_P6_CANDIDATE_COMMIT", candidate_commit)

    with pytest.raises(benchmark_runner.BenchmarkError, match="input_binding_failure"):
        benchmark_runner.run_benchmark("c_cpp", "pilot", output=tmp_path / "pilot")


def _probe_payload(*, model: str = "GLM-5.2", include_usage: bool = True, finish="stop"):
    payload = {
        "model": model,
        "choices": [{"finish_reason": finish, "message": {"content": '{"ok":true}'}}],
    }
    if include_usage:
        payload["usage"] = {
            "prompt_tokens": 10,
            "completion_tokens": 3,
            "total_tokens": 13,
        }
    return json.dumps(payload).encode("utf-8")


def test_neutral_probe_validates_model_usage_and_never_returns_response_body() -> None:
    contract = _contract(SPECS["c_cpp"].config_path)
    captured = {}

    def transport(request, timeout):
        captured["url"] = request.full_url
        captured["body"] = request.data
        captured["timeout"] = timeout
        return ProviderProbeResponse(status=200, body=_probe_payload())

    result = probe_provider(contract, api_key="private", transport=transport)

    assert result["passed"] is True
    assert result["model"] == "GLM-5.2"
    assert result["provider_usage_coverage"] == 1.0
    assert result["estimated_provider_call_count"] == 0
    assert result["usage_conservation"]["physical_call_count"] == 1
    assert result["usage_conservation"]["dimensions"]["token"] == {
        "numerator": 13,
        "denominator": 13,
        "conserved": True,
    }
    assert "response" not in result
    assert captured["url"] == RANGE_BASE_URL + "/chat/completions"
    assert b"ground_truth" not in captured["body"]
    assert b"fixture" not in captured["body"]


def test_neutral_probe_redirect_handler_never_reissues_authorization() -> None:
    request = provider_runtime.Request(
        RANGE_BASE_URL + "/chat/completions",
        headers={"Authorization": "Bearer private"},
        method="POST",
    )

    redirected = provider_runtime._RejectRedirects().redirect_request(
        request,
        None,
        302,
        "Found",
        {"Location": "https://attacker.invalid/collect"},
        "https://attacker.invalid/collect",
    )

    assert redirected is None


@pytest.mark.parametrize(
    "status, failure_class",
    [
        (401, "provider_credentials_unavailable"),
        (403, "provider_credentials_unavailable"),
        (404, "provider_protocol_incompatible"),
        (429, "provider_transport_exhausted"),
        (500, "provider_transport_exhausted"),
        (503, "provider_transport_exhausted"),
    ],
)
def test_neutral_probe_classifies_http_status_without_body(status: int, failure_class: str) -> None:
    contract = _contract(SPECS["c_cpp"].config_path)

    with pytest.raises(ProviderProbeError) as raised:
        probe_provider(
            contract,
            api_key="private",
            transport=lambda _request, _timeout: ProviderProbeResponse(
                status=status, body=b"sensitive provider error body"
            ),
        )

    assert raised.value.failure_class == failure_class
    assert "sensitive" not in str(raised.value)


@pytest.mark.parametrize(
    "body, failure_class",
    [
        (_probe_payload(model="alias-model"), "provider_identity_mismatch"),
        (_probe_payload(include_usage=False), "provider_usage_unverifiable"),
        (
            json.dumps(
                {
                    "model": "GLM-5.2",
                    "choices": [{"finish_reason": "stop", "message": {}}],
                    "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 3,
                        "total_tokens": 99,
                    },
                }
            ).encode("utf-8"),
            "provider_usage_unverifiable",
        ),
        (
            json.dumps(
                {
                    "model": "GLM-5.2",
                    "choices": [{"finish_reason": "stop", "message": {}}],
                    "usage": {
                        "prompt_tokens": -1,
                        "completion_tokens": 1,
                        "total_tokens": 0,
                    },
                }
            ).encode("utf-8"),
            "provider_usage_unverifiable",
        ),
        (_probe_payload(finish="length"), "provider_protocol_incompatible"),
        (
            json.dumps(
                {
                    "model": "GLM-5.2",
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"content": '{"ok":false}'},
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 3,
                        "total_tokens": 13,
                    },
                }
            ).encode("utf-8"),
            "provider_protocol_incompatible",
        ),
        (
            b'{"model":"GLM-5.2","model":"alias-model",'
            b'"choices":[{"finish_reason":"stop","message":{}}],'
            b'"usage":{"prompt_tokens":10,"completion_tokens":3,"total_tokens":13}}',
            "provider_protocol_incompatible",
        ),
        (b"not-json", "provider_protocol_incompatible"),
    ],
)
def test_neutral_probe_rejects_identity_usage_finish_and_protocol_drift(
    body: bytes, failure_class: str
) -> None:
    contract = _contract(SPECS["c_cpp"].config_path)

    with pytest.raises(ProviderProbeError) as raised:
        probe_provider(
            contract,
            api_key="private",
            transport=lambda _request, _timeout: ProviderProbeResponse(status=200, body=body),
        )

    assert raised.value.failure_class == failure_class


def test_neutral_probe_classifies_timeout_without_exception_text() -> None:
    contract = _contract(SPECS["c_cpp"].config_path)

    def transport(_request, _timeout):
        raise ProviderProbeError("provider_transport_exhausted")

    with pytest.raises(ProviderProbeError) as raised:
        probe_provider(contract, api_key="private", transport=transport)

    assert raised.value.failure_class == "provider_transport_exhausted"
    assert str(raised.value) == "provider probe failed"
