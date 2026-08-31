from __future__ import annotations

import json
from pathlib import Path

import pytest
import requests
from click.testing import CliRunner

from zscope.benchmarking import provider_runtime
from zscope.benchmarking import runner as benchmark_runner
from zscope.cli import cli as cli_module
from zscope.framework import provider_failure_marker
from zscope.framework.llm_client import LLMClient, ProviderFailureError


class _Response:
    def __init__(self, *, status: int = 200, lines: list[bytes] | None = None) -> None:
        self.status_code = status
        self.headers: dict[str, str] = {}
        self.text = "private provider response body"
        self._lines = lines or []

    def iter_lines(self):
        return iter(self._lines)

    def close(self) -> None:
        return None


def _strict_lines(*, model: str, usage: dict[str, int] | None) -> list[bytes]:
    chunk: dict[str, object] = {
        "model": model,
        "choices": [
            {
                "delta": {"role": "assistant", "content": "private model output"},
                "finish_reason": "stop",
            }
        ],
    }
    if usage is not None:
        chunk["usage"] = usage
    return [
        ("data: " + json.dumps(chunk)).encode("utf-8"),
        b"data: [DONE]",
    ]


def _llm_failure(monkeypatch: pytest.MonkeyPatch, kind: str) -> ProviderFailureError:
    strict = kind in {"usage", "model", "protocol"}
    client = LLMClient(
        api_key="private-key",
        base_url="https://provider.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=strict,
    )
    if kind == "auth":
        outcome: object = _Response(status=401)
    elif kind == "rate":
        outcome = _Response(status=429)
    elif kind == "server":
        outcome = _Response(status=503)
    elif kind == "timeout":
        outcome = requests.exceptions.Timeout("private timeout body")
    elif kind == "usage":
        outcome = _Response(lines=_strict_lines(model="unit-model", usage=None))
    elif kind == "model":
        outcome = _Response(
            lines=_strict_lines(
                model="alias-model",
                usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            )
        )
    elif kind == "protocol":
        outcome = _Response(lines=[b"event: private-provider-event", b"data: [DONE]"])
    else:  # pragma: no cover - the parametrization is the closed input set
        raise AssertionError(kind)

    def post(*_args, **_kwargs):
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(client.session, "post", post)
    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "constant request"}])
    return raised.value


@pytest.mark.parametrize(
    ("kind", "expected_class"),
    [
        ("auth", "provider_credentials_unavailable"),
        ("rate", "provider_transport_exhausted"),
        ("server", "provider_transport_exhausted"),
        ("timeout", "provider_transport_exhausted"),
        ("usage", "provider_usage_unverifiable"),
        ("model", "provider_identity_mismatch"),
        ("protocol", "provider_protocol_incompatible"),
    ],
)
def test_llm_cli_marker_runner_typed_failure_chain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
    expected_class: str,
) -> None:
    failure = _llm_failure(monkeypatch, kind)
    marker = tmp_path / provider_runtime.P6_PROVIDER_FAILURE_FILENAME
    monkeypatch.setattr(
        provider_failure_marker,
        "P6_PROVIDER_FAILURE_CONTAINER_PATH",
        marker.as_posix(),
    )
    assert cli_module._provider_failure_exit_code(failure, p6_pilot=True) == 2
    assert (
        benchmark_runner._p6_scan_provider_failure_class(
            marker,
            return_code=2,
        )
        == expected_class
    )

    marker_text = marker.read_text(encoding="utf-8")
    assert json.loads(marker_text) == {
        "schema_version": provider_runtime.P6_PROVIDER_FAILURE_SCHEMA_VERSION,
        "failure_class": expected_class,
        "failure_count": 1,
    }
    assert "private" not in marker_text
    assert str(failure) == ProviderFailureError.MESSAGE
    assert failure.__cause__ is None
    assert failure.__context__ is None


def test_p6_cli_marker_write_failure_uses_unaccepted_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker = tmp_path / "missing-parent" / provider_runtime.P6_PROVIDER_FAILURE_FILENAME
    monkeypatch.setattr(
        provider_failure_marker,
        "P6_PROVIDER_FAILURE_CONTAINER_PATH",
        marker.as_posix(),
    )
    assert (
        cli_module._provider_failure_exit_code(
            ProviderFailureError("provider_transport_exhausted"),
            p6_pilot=True,
        )
        == 3
    )
    assert not marker.exists()


@pytest.mark.parametrize(("marker_parent_exists", "expected_exit"), [(True, 2), (False, 3)])
def test_p6_cli_catch_reserves_exit_two_for_a_complete_marker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    marker_parent_exists: bool,
    expected_exit: int,
) -> None:
    config = tmp_path / "zscope.yaml"
    config.write_text("config_version: 2\n", encoding="utf-8")
    marker_parent = tmp_path if marker_parent_exists else tmp_path / "missing"
    marker = marker_parent / provider_runtime.P6_PROVIDER_FAILURE_FILENAME
    monkeypatch.setattr(
        provider_failure_marker,
        "P6_PROVIDER_FAILURE_CONTAINER_PATH",
        marker.as_posix(),
    )
    monkeypatch.setattr(
        cli_module.ConfigLoader,
        "load",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ProviderFailureError("provider_usage_unverifiable")
        ),
    )

    result = CliRunner().invoke(
        cli_module.main,
        ["--config", str(config), "--p6-pilot"],
    )

    assert result.exit_code == expected_exit
    assert marker.exists() is marker_parent_exists
    if marker_parent_exists:
        assert provider_runtime.load_p6_provider_failure_marker(marker)["failure_class"] == (
            "provider_usage_unverifiable"
        )


def test_p6_runner_rejects_marker_on_success_and_malformed_marker(
    tmp_path: Path,
) -> None:
    marker = tmp_path / provider_runtime.P6_PROVIDER_FAILURE_FILENAME
    marker.write_text(
        json.dumps(
            {
                "schema_version": provider_runtime.P6_PROVIDER_FAILURE_SCHEMA_VERSION,
                "failure_class": "provider_transport_exhausted",
                "failure_count": 1,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(benchmark_runner.BenchmarkError, match="oci_isolation_violation"):
        benchmark_runner._p6_scan_provider_failure_class(marker, return_code=0)

    marker.write_text('{"failure_class":"provider_transport_exhausted"}', encoding="utf-8")
    with pytest.raises(benchmark_runner.BenchmarkError, match="oci_isolation_violation"):
        benchmark_runner._p6_scan_provider_failure_class(marker, return_code=2)


def test_p6_provider_failure_marker_rejects_replacement_between_lstat_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / provider_runtime.P6_PROVIDER_FAILURE_FILENAME
    payload = {
        "schema_version": provider_runtime.P6_PROVIDER_FAILURE_SCHEMA_VERSION,
        "failure_class": "provider_transport_exhausted",
        "failure_count": 1,
    }
    marker.write_text(json.dumps(payload), encoding="utf-8")
    original_open = provider_runtime.os.open
    replaced = False

    def replacing_open(target, flags, *args, **kwargs):
        nonlocal replaced
        if Path(target) == marker and not replaced:
            replaced = True
            marker.unlink()
            marker.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        return original_open(target, flags, *args, **kwargs)

    monkeypatch.setattr(provider_runtime.os, "open", replacing_open)

    with pytest.raises(provider_runtime.ProviderRuntimeError, match="changed during read"):
        provider_runtime.load_p6_provider_failure_marker(marker)


def test_p6_runner_accepts_exit_two_without_marker_as_non_provider_partial(
    tmp_path: Path,
) -> None:
    assert (
        benchmark_runner._p6_scan_provider_failure_class(
            tmp_path / provider_runtime.P6_PROVIDER_FAILURE_FILENAME,
            return_code=2,
        )
        is None
    )


def test_p6_scanner_uses_hidden_flag_without_key_or_marker_environment() -> None:
    argv = benchmark_runner._container_scan_argv("python3", mode="pilot")

    assert argv[-1] == "--p6-pilot"
    assert "Z_SCOPE_API_KEY" not in argv
    assert "Z_SCOPE_P6_PROVIDER_FAILURE_PATH" not in argv
    assert provider_runtime.P6_PROVIDER_FAILURE_CONTAINER_PATH not in argv


def test_non_p6_provider_failure_does_not_request_a_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "_persist_p6_provider_failure",
        lambda _error: (_ for _ in ()).throw(AssertionError("must not write a marker")),
    )

    assert (
        cli_module._provider_failure_exit_code(
            ProviderFailureError("provider_transport_exhausted"),
            p6_pilot=False,
        )
        == 2
    )
