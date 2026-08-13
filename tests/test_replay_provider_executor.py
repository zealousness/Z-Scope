import json
import logging
from pathlib import Path

import pytest

from scripts.describe_validator_replay_provider import main as describe_provider_main
import scripts.run_validator_replay as replay_script
import zscope.benchmarking.replay_provider as replay_provider
from scripts.run_validator_replay import build_parser as replay_cli_parser
from zscope.benchmarking.replay_bundle import build_validator_replay_bundle
from zscope.benchmarking.replay_provider import (
    PROVIDER_CONFIG_SCHEMA_VERSION,
    BuiltinProviderReplayExecutor,
    BuiltinReplayProviderError,
    ReplayProviderSpec,
    assert_expected_builtin_identity,
    derive_builtin_execution_identity,
    load_replay_provider_spec,
)
from zscope.benchmarking.validator_replay import ReplayCall


def _spec(*, structured: bool = True, model: str = "glm-5.1") -> ReplayProviderSpec:
    return ReplayProviderSpec(
        base_url="https://provider.invalid/v1",
        api_key_env="Z_SCOPE_REPLAY_API_KEY",
        model=model,
        timeout_seconds=120.0,
        supports_structured_output=structured,
        temperature=0.0,
    )


def _call(
    arm_id: str = "A",
    *,
    call_kind: str = "direct",
    validation_pass: str = "initial",
) -> ReplayCall:
    return ReplayCall(
        arm_id=arm_id,
        arm_spec_sha256="a" * 64,
        protocol_mode=(
            "legacy_multi_turn_upper_bound" if arm_id == "E" else "validator_v3_bounded"
        ),
        trial_index=1,
        call_index=1,
        call_kind=call_kind,
        validation_pass=validation_pass,
        validation_cluster_uid="VAL-1",
        candidate_uid="CAND-1",
        group_sha256="b" * 64,
        input_sha256="c" * 64,
        validator_input={
            "candidate_uid": "CAND-1",
            "validation_cluster_uid": "VAL-1",
            "validation_pass": validation_pass,
            "evidence_slice": {"evidence_ref_catalog": {}},
        },
        decision_policy={},
        limits={
            "effective_max_output_tokens": 8192,
            "legacy_session_expected_tokens": 1_000_000,
            "run_expected_total_tokens": 1_000_000,
            "projected_tokens_for_call": 1_000_000,
        },
    )


def _result(call: ReplayCall) -> dict:
    return {
        "schema_version": "zscope.validator-result.v3",
        "candidate_uid": call.candidate_uid,
        "validation_cluster_uid": call.validation_cluster_uid,
        "pass": call.validation_pass,
        "verdict": "verified",
        "reasoning": "Frozen evidence supports the bounded decision.",
        "positive_evidence": ["answer-free evidence was sufficient"],
        "negative_evidence": [],
        "evidence_refs": [],
        "blocking_negative_evidence": False,
        "missing_fact_request": None,
        "stop_reason": "decision_complete",
    }


def _usage() -> dict:
    return {
        "prompt_tokens": 100,
        "cached_prompt_tokens": 20,
        "completion_tokens": 30,
        "reasoning_tokens": 10,
        "total_tokens": 130,
        "estimated": False,
    }


class _FakeClient:
    def __init__(self, response: dict) -> None:
        self.response = response
        self.calls = []

    def chat_completion(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        return self.response


def test_provider_config_is_strict_answer_free_and_identity_is_derived(tmp_path: Path) -> None:
    path = tmp_path / "provider.json"
    raw = {
        "schema_version": PROVIDER_CONFIG_SCHEMA_VERSION,
        "base_url": "https://provider.invalid/v1/",
        "api_key_env": "Z_SCOPE_REPLAY_API_KEY",
        "model": "glm-5.1",
        "timeout_seconds": 120,
        "supports_structured_output": True,
        "temperature": 0,
        "transport": "requests",
    }
    path.write_text(json.dumps(raw), encoding="utf-8")

    spec = load_replay_provider_spec(path)
    identity = derive_builtin_execution_identity(spec)
    assert spec.base_url == "https://provider.invalid/v1"
    assert set(identity) == {
        "executor_sha256",
        "model_spec_sha256",
        "prompt_sha256",
    }
    assert all(len(value) == 64 for value in identity.values())
    assert identity != derive_builtin_execution_identity(_spec(model="another-model"))

    raw["project_root"] = "C:/scanner/source"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(BuiltinReplayProviderError, match="missing or unknown"):
        load_replay_provider_spec(path)

    raw.pop("project_root")
    raw["base_url"] = "https://provider.invalid/v1?api_key=secret"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(BuiltinReplayProviderError, match="query"):
        load_replay_provider_spec(path)


def test_provider_identity_cli_is_offline_and_replay_help_exposes_builtin_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "provider.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": PROVIDER_CONFIG_SCHEMA_VERSION,
                "base_url": "https://provider.invalid/v1",
                "api_key_env": "Z_SCOPE_REPLAY_API_KEY",
                "model": "glm-5.1",
                "timeout_seconds": 120,
                "supports_structured_output": True,
                "temperature": 0,
                "transport": "requests",
            }
        ),
        encoding="utf-8",
    )

    assert describe_provider_main(["--provider-config", str(path)]) == 0
    described = json.loads(capsys.readouterr().out)
    assert described["schema_version"] == "zscope.validator-replay-provider-identity.v1"
    assert (
        described["model_spec_sha256"]
        == derive_builtin_execution_identity(load_replay_provider_spec(path))["model_spec_sha256"]
    )
    help_text = replay_cli_parser().format_help()
    assert "--builtin-provider-config" in help_text
    assert "--expected-executor-sha256" in help_text
    assert "--trusted-executor-oci-evidence-sha256" not in help_text
    assert "always non-formal" in help_text
    assert "Arm E" in help_text


@pytest.mark.parametrize(
    ("arm_id", "call_kind", "validation_pass"),
    [
        ("B", "direct", "initial"),
        ("B", "format_repair", "initial"),
        ("C", "fact_recheck", "evidence_recheck"),
        ("D", "direct", "initial"),
    ],
)
def test_a_d_each_executor_invocation_is_one_fresh_provider_attempt(
    arm_id: str,
    call_kind: str,
    validation_pass: str,
) -> None:
    call = _call(arm_id, call_kind=call_kind, validation_pass=validation_pass)
    clients = []

    def factory(_spec, _api_key):
        client = _FakeClient(
            {
                "choices": [
                    {
                        "message": {"content": json.dumps(_result(call))},
                        "finish_reason": "stop",
                    }
                ],
                "model": "glm-5.1",
                "usage": _usage(),
            }
        )
        clients.append(client)
        return client

    executor = BuiltinProviderReplayExecutor(_spec(), "secret", client_factory=factory)
    provider_logger = logging.getLogger("zscope.framework.llm_client")
    provider_logger.disabled = False
    response = executor.execute(call)

    assert len(clients) == 1
    assert len(clients[0].calls) == 1
    assert response["result"] == _result(call)
    assert response["usage"] == {
        "prompt_tokens": 100,
        "cached_prompt_tokens": 20,
        "completion_tokens": 30,
        "reasoning_tokens": 10,
        "total_tokens": 130,
        "tool_call_count": 0,
        "api_attempt_count": 1,
        "provider_reported": True,
    }
    assert response["execution_identity"] == executor.execution_identity
    assert provider_logger.disabled is False
    assert "validator_input_json" not in json.dumps(response)
    _messages, kwargs = clients[0].calls[0]
    assert kwargs["response_format"]["json_schema"]["strict"] is True
    assert kwargs["max_tokens"] == 8192


def test_arm_a_uses_exact_generic_loop_forced_final_bridge_and_differs_from_b() -> None:
    arm_a = _call("A", call_kind="legacy_forced_final")
    arm_a = ReplayCall(**{**arm_a.__dict__, "protocol_mode": "legacy_single_turn_bridge"})
    arm_b = _call("B", call_kind="direct")
    a_fake = _FakeClient(
        {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "emit_validator_result_v3",
                                    "arguments": json.dumps(_result(arm_a)),
                                }
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": _usage(),
        }
    )
    b_fake = _FakeClient(
        {
            "choices": [
                {
                    "message": {"content": json.dumps(_result(arm_b))},
                    "finish_reason": "stop",
                }
            ],
            "usage": _usage(),
        }
    )
    clients = iter((a_fake, b_fake))
    executor = BuiltinProviderReplayExecutor(
        _spec(structured=True),
        "secret",
        client_factory=lambda _spec, _key: next(clients),
    )

    assert executor.execute(arm_a)["result"] == _result(arm_a)
    assert executor.execute(arm_b)["result"] == _result(arm_b)

    a_messages, a_kwargs = a_fake.calls[0]
    b_messages, b_kwargs = b_fake.calls[0]
    assert a_messages[-1] == {
        "role": "user",
        "content": (
            "This is the final allowed iteration (1/1). Regular tool use is now "
            "disabled. Submit the required final result by calling "
            "emit_validator_result_v3; do not ask for more tools or more turns."
        ),
    }
    assert a_messages[-1]["content"] == replay_provider._LEGACY_FORCED_FINAL_INSTRUCTION
    assert "response_format" not in a_kwargs
    assert "tool_choice" not in a_kwargs
    assert a_kwargs["tools"][0]["function"]["name"] == "emit_validator_result_v3"
    assert b_messages[-1] != a_messages[-1]
    assert b_kwargs["response_format"]["json_schema"]["strict"] is True


def test_arm_d_bounded_turn_uses_action_schema_without_spending_query_quota_in_executor() -> None:
    call = _call(
        "D",
        call_kind="bounded_investigation_turn",
        validation_pass="investigation_synthesis",
    )
    action = {
        "schema_version": "zscope.validator-replay-action.v1",
        "action": "query",
        "query": {
            "schema_version": "zscope.validator-replay-query.v1",
            "query_kind": "fact_by_uid",
            "key": "FACT-1",
            "reason": "resolve one frozen fact",
        },
        "result": None,
    }
    fake = _FakeClient(
        {
            "choices": [{"message": {"content": json.dumps(action)}, "finish_reason": "stop"}],
            "usage": _usage(),
        }
    )
    executor = BuiltinProviderReplayExecutor(
        _spec(structured=True), "secret", client_factory=lambda _spec, _key: fake
    )

    response = executor.execute(call)

    assert response["result"] == action
    assert response["usage"]["api_attempt_count"] == 1
    assert response["usage"]["tool_call_count"] == 0
    _messages, kwargs = fake.calls[0]
    assert kwargs["response_format"]["json_schema"]["name"] == "validator_replay_action"


def test_non_structured_provider_uses_one_required_terminal_tool() -> None:
    call = _call("B")
    fake = _FakeClient(
        {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "emit_validator_result_v3",
                                    "arguments": json.dumps(_result(call)),
                                }
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": _usage(),
        }
    )
    executor = BuiltinProviderReplayExecutor(
        _spec(structured=False),
        "secret",
        client_factory=lambda _spec, _key: fake,
    )

    response = executor.execute(call)

    assert response["result"] == _result(call)
    assert response["usage"]["tool_call_count"] == 1
    assert len(fake.calls) == 1
    _messages, kwargs = fake.calls[0]
    assert kwargs["tool_choice"]["function"]["name"] == "emit_validator_result_v3"
    assert "response_format" not in kwargs


def test_missing_provider_usage_and_builtin_arm_e_fail_closed_without_retry() -> None:
    call = _call("A")
    fake = _FakeClient(
        {
            "choices": [{"message": {"content": json.dumps(_result(call))}}],
            "usage": {**_usage(), "estimated": True},
        }
    )
    executor = BuiltinProviderReplayExecutor(
        _spec(), "secret", client_factory=lambda _spec, _key: fake
    )
    with pytest.raises(BuiltinReplayProviderError, match="authoritative usage"):
        executor.execute(call)
    assert len(fake.calls) == 1

    factory_calls = []
    arm_e_executor = BuiltinProviderReplayExecutor(
        _spec(),
        "secret",
        client_factory=lambda _spec, _key: factory_calls.append(True),
    )
    with pytest.raises(BuiltinReplayProviderError, match="Arm E"):
        arm_e_executor.execute(_call("E", call_kind="legacy_multi_turn_session"))
    assert factory_calls == []


def test_cost_expectation_does_not_gate_complete_provider_request() -> None:
    call = _call("A")
    limits = dict(call.limits)
    limits["run_expected_total_tokens"] = 1
    starved = ReplayCall(**{**call.__dict__, "limits": limits})
    fake = _FakeClient(
        {
            "choices": [{"message": {"content": json.dumps(_result(starved))}}],
            "usage": _usage(),
        }
    )
    executor = BuiltinProviderReplayExecutor(
        _spec(), "secret", client_factory=lambda _spec, _key: fake
    )

    result = executor.execute(starved)
    assert result["result"]["verdict"] == "verified"
    assert len(fake.calls) == 1


def test_external_expected_identity_cannot_be_replaced_by_self_report() -> None:
    executor = BuiltinProviderReplayExecutor(
        _spec(), "secret", client_factory=lambda _spec, _key: object()
    )
    assert_expected_builtin_identity(executor, executor.execution_identity)
    forged = dict(executor.execution_identity)
    forged["prompt_sha256"] = "0" * 64
    with pytest.raises(BuiltinReplayProviderError, match="externally expected prompt_sha256"):
        assert_expected_builtin_identity(executor, forged)


def test_replay_cli_builtin_mode_binds_expected_identity_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = {
        "run_manifest": {
            "source_tree_hash": "a" * 64,
            "config_hash": "b" * 64,
            "effective_rules_sha256": "c" * 64,
            "candidate_schema_version": "zscope.candidate.v3.3",
            "knowledge_db_version": "14",
        },
        "candidate_terminal_states": [
            {
                "validation_cluster_uid": "VAL-1",
                "candidate_uid": "CAND-1",
                "occurrence_uids": ["OCC-1"],
                "entries": ["entry"],
                "issue": {
                    "candidate_uid": "CAND-1",
                    "category": "memory_safety",
                    "function": "sink",
                    "location": "src/demo.c:1",
                    "description": "answer-free candidate",
                    "evidence_pack": {},
                },
            }
        ],
    }
    bundle = build_validator_replay_bundle(report)
    bundle_path = tmp_path / "bundle.json"
    provider_path = tmp_path / "provider.json"
    output_path = tmp_path / "run.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    provider_path.write_text("{}", encoding="utf-8")
    identity = {
        field: character * 64
        for field, character in zip(
            ("executor_sha256", "model_spec_sha256", "prompt_sha256"), "def"
        )
    }

    class FakeBuiltin:
        execution_identity = identity

        def execute(self, call):
            return {
                "result": _result(call),
                "usage": {
                    "prompt_tokens": 100,
                    "cached_prompt_tokens": 20,
                    "completion_tokens": 30,
                    "reasoning_tokens": 10,
                    "total_tokens": 130,
                    "tool_call_count": 0,
                    "api_attempt_count": 1,
                    "provider_reported": True,
                },
                "execution_identity": identity,
            }

    monkeypatch.setattr(
        replay_script.BuiltinProviderReplayExecutor,
        "from_config",
        lambda _path: FakeBuiltin(),
    )
    for key in list(__import__("os").environ):
        if "GROUND_TRUTH" in key.upper() or "BENCHMARK_TRUTH" in key.upper():
            monkeypatch.delenv(key, raising=False)
    argv = [
        "--bundle",
        str(bundle_path),
        "--expected-bundle-sha256",
        bundle["bundle_sha256"],
        "--arm",
        "A",
        "--builtin-provider-config",
        str(provider_path),
        "--expected-executor-sha256",
        identity["executor_sha256"],
        "--expected-model-spec-sha256",
        identity["model_spec_sha256"],
        "--expected-prompt-sha256",
        identity["prompt_sha256"],
        "--expected-total-tokens",
        "2000000",
        "--output",
        str(output_path),
    ]

    assert replay_script.main(argv) == 0
    assert output_path.exists()
    forged = list(argv)
    forged[forged.index("--expected-prompt-sha256") + 1] = "0" * 64
    with pytest.raises(SystemExit):
        replay_script.main(forged)
