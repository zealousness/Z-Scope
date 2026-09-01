from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from scripts import run_p6_synthetic_replay as replay_cli
from zscope.benchmarking.p6_synthetic_replay import (
    REPLAY_MAX_CONTRACT_REGENERATIONS,
    REPLAY_MAX_INFLIGHT,
    REPLAY_MAX_TRANSPORT_RETRIES,
    SyntheticReplayError,
    assert_answer_free_payload,
    compile_synthetic_project,
    execute_scanner,
    failure_result,
    install_replay_call_guards,
    materialize_replay_workspace,
    synthetic_scenarios,
    validate_replay_report,
)
from zscope.benchmarking.provider_runtime import (
    P6_PROVIDER_BASE_URL,
    P6_PROVIDER_MODEL,
    P6_PROVIDER_RESPONSE_MODEL,
)
from zscope.core.validation.authority import TERMINAL_AUTHORITY_DECISION_V4
from zscope.core.validation.proof_kernel.closure import PROMOTION_CERTIFICATE_VERSION
from zscope.framework.llm_client import LLMClient
from zscope.config.config import ConfigLoader


def _provider_config(path: Path) -> Path:
    value = {
        "config_version": 2,
        "llms": {
            "default": {
                "base_urls": [P6_PROVIDER_BASE_URL],
                "models": [P6_PROVIDER_MODEL],
                "response_model_map": {
                    P6_PROVIDER_MODEL: P6_PROVIDER_RESPONSE_MODEL,
                },
                "api_key": "${Z_SCOPE_API_KEY}",
                "base_url_max_concurrent_requests": 8,
                "max_tokens": 8192,
                "max_retries": 1,
                "retry_until_available": False,
                "supports_structured_output": False,
                "require_exact_response_model": True,
                "timeout": 120,
            }
        },
        "project": {
            "id": "neutral-provider-config",
            "root": ".",
            "source_root": ".",
            "language": "c_cpp",
        },
        "scan": {
            "task": "",
            "llm_profiles": {
                "modeling": "default",
                "analysis": "default",
                "validation": "default",
            },
        },
        "indexing": {
            "backend": "unified",
            "svf": {
                "scope": "auto",
                "entry_depth": 4,
                "max_selected_tus": 32,
                "fallback": "full",
                "groups_file": "",
                "always_include": [],
                "exclusive_pools": [],
                "shared_pools": [],
                "heap_limit_mb": 4096,
                "timeout_seconds": 120,
            },
            "tools": {
                "clangd": "clangd",
                "gclang": "gclang",
                "get_bc": "get-bc",
                "llvm_link": "llvm-link",
            },
        },
        "concurrency": {
            "entry_workers": 8,
            "validator_workers": 8,
            "investigator_workers": 1,
            "evidence_completion_workers": 2,
            "index_workers": 4,
            "svf_workers": 2,
            "llm_max_inflight": 8,
        },
    }
    path.write_text(yaml.safe_dump(value, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return path.resolve()


def _workspace(tmp_path: Path):
    return materialize_replay_workspace(
        root=(tmp_path / "work").resolve(),
        source_config_path=_provider_config(tmp_path / "provider.yaml"),
    )


def _confirmed_state(entry: str, index: int) -> dict[str, Any]:
    return {
        "candidate_uid": f"candidate-{index}",
        "validation_cluster_uid": f"cluster-{index}",
        "reported_from_entry": entry,
        "candidate_disposition": "confirmed",
        "proof_kernel_promotion_certificate": {
            "schema_version": PROMOTION_CERTIFICATE_VERSION,
            "disposition": "confirmed",
            "integrity_status": "verified",
        },
        "proof_kernel_closure_evaluation": {
            "complete": True,
            "disposition": "confirmed",
        },
        "terminal_authority_decision": {
            "schema_version": TERMINAL_AUTHORITY_DECISION_V4,
            "terminal": True,
            "disposition": "confirmed",
        },
    }


def _write_success_artifacts(workspace, *, call_count: int = 10) -> tuple[dict, list[dict]]:
    states = [
        _confirmed_state(scenario.vulnerable_entry, index)
        for index, scenario in enumerate(workspace.scenarios, start=1)
    ]
    functions = [
        {"function": entry, "error": ""}
        for scenario in workspace.scenarios
        for entry in (scenario.vulnerable_entry, scenario.protected_entry)
    ]
    events: list[dict[str, Any]] = []
    for sequence in range(1, call_count + 1):
        events.append(
            {
                "schema_version": "zscope.llm-usage-event.v2",
                "sequence": sequence,
                "call_id": f"call-{sequence}",
                "reservation_id": f"call-{sequence}",
                "outcome": "success",
                "prompt_tokens": 100 + sequence,
                "completion_tokens": 10,
                "total_tokens": 110 + sequence,
                "provider_reported": True,
                "conservative_charge": False,
                "budget_violation": False,
                "requested_model": P6_PROVIDER_MODEL,
                "provider_response_model": P6_PROVIDER_RESPONSE_MODEL,
                "retry": False,
                "repair": False,
                "tool_call_count": sequence % 2,
                "call_kind": "initial",
                "validation_cluster_uid": f"usage-cluster-{sequence}",
            }
        )
    prompt_tokens = sum(row["prompt_tokens"] for row in events)
    completion_tokens = sum(row["completion_tokens"] for row in events)
    total_tokens = sum(row["total_tokens"] for row in events)
    tool_calls = sum(row["tool_call_count"] for row in events)
    snapshots = workspace.project_root / ".zscope_snapshots"
    snapshots.mkdir(parents=True)
    events_path = snapshots / "llm_usage_events_local.jsonl"
    events_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in events),
        encoding="utf-8",
    )
    trace_root = snapshots / "decision_traces"
    trace_root.mkdir()
    trace_path = trace_root / "manifest.json"
    trace_sha = "a" * 64
    trace_manifest = {
        "schema_version": "zscope.decision-trace-manifest.v1",
        "manifest_sha256": trace_sha,
        "complete": True,
        "errors": [],
        "llm_usage_events": {
            "available": True,
            "event_count": call_count,
            "referenced_call_count": call_count,
            "trace_token_total": total_tokens,
            "usage_token_total": total_tokens,
            "missing_call_ids": [],
            "unreferenced_call_ids": [],
            "duplicate_call_ids": [],
            "provider_usage_coverage": 1.0,
            "conservation_valid": True,
        },
    }
    trace_path.write_text(json.dumps(trace_manifest, sort_keys=True) + "\n", encoding="utf-8")
    totals = {
        "request_count": call_count,
        "successful_calls": call_count,
        "provider_reported_calls": call_count,
        "estimated_or_conservative_calls": 0,
        "failed_or_unknown_calls": 0,
        "budget_violation_count": 0,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "tool_call_count": tool_calls,
    }
    report = {
        "summary": {
            "functions_completed": len(functions),
            "functions_failed": 0,
            "total_issues": len(states),
            "llm_usage": {
                "scan_token_usage": {
                    "depth": "balanced",
                    "telemetry_complete": True,
                    "active_reservation_count": 0,
                    "reserved_tokens": 0,
                    "usage_attribution": {
                        "provider_usage_coverage": 1.0,
                        "totals": totals,
                    },
                }
            },
        },
        "function_results": functions,
        "issues": copy.deepcopy(states),
        "candidate_terminal_states": states,
        "run_manifest": {
            "validation_queue_drained": True,
            "terminal_outcome_count": len(states),
            "report_invariant_status": {"valid": True},
            "decision_trace": {
                "manifest_path": str(trace_path.resolve()),
                "manifest_sha256": trace_sha,
                "complete": True,
                "errors": [],
            },
        },
    }
    workspace.report_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
    return report, events


def _rewrite_report(workspace, report: dict[str, Any]) -> None:
    workspace.report_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")


def _rewrite_events(workspace, events: list[dict[str, Any]]) -> None:
    path = next((workspace.project_root / ".zscope_snapshots").glob("llm_usage_events_*.jsonl"))
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in events),
        encoding="utf-8",
    )


def test_public_suite_has_five_neutral_pairs() -> None:
    scenarios = synthetic_scenarios()
    assert len(scenarios) == 5
    assert len({scenario.scenario_id for scenario in scenarios}) == 5
    assert all(scenario.vulnerable_entry != scenario.protected_entry for scenario in scenarios)
    packet = [scenario.model_input() for scenario in scenarios]
    assert_answer_free_payload(packet)
    serialized = json.dumps(packet, sort_keys=True).casefold().replace("\\", "/")
    markers = (
        "ground" + "_" + "tr" + "uth",
        "tr" + "uth",
        "expect" + "ed",
        "scor" + "er",
        "test" + "/" + "range",
        "range" + "-",
        "range" + "_",
        "fix" + "ture",
    )
    assert not any(marker in serialized for marker in markers)
    sources = "\n".join(scenario.source for scenario in scenarios)
    for token in ("malloc", "memcpy", "calloc", "pthread_create", "values[index]"):
        assert token in sources


@pytest.mark.parametrize(
    "marker",
    (
        "ground" + "_" + "tr" + "uth",
        "tr" + "uth",
        "expect" + "ed",
        "scor" + "er",
        "test" + "/" + "range",
        "range" + "-" + "001",
        "range" + "_" + "001",
        "fix" + "ture",
    ),
)
def test_recursive_canary_rejects_each_answer_marker(marker: str) -> None:
    with pytest.raises(SyntheticReplayError) as caught:
        assert_answer_free_payload({"outer": [{"inner": marker}]})
    assert caught.value.failure_class == "input_binding_failure"


def test_runtime_is_frozen_to_one_call_in_flight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path)
    runtime = yaml.safe_load(workspace.config_path.read_text(encoding="utf-8"))
    profile = runtime["llms"]["default"]
    assert profile["models"] == [P6_PROVIDER_MODEL]
    assert profile["base_urls"] == [P6_PROVIDER_BASE_URL]
    assert profile["base_url_max_concurrent_requests"] == REPLAY_MAX_INFLIGHT == 1
    assert profile["max_retries"] == REPLAY_MAX_TRANSPORT_RETRIES == 1
    assert profile["retry_until_available"] is False
    assert runtime["concurrency"] == {
        "entry_workers": 1,
        "validator_workers": 1,
        "investigator_workers": 1,
        "evidence_completion_workers": 1,
        "index_workers": 1,
        "svf_workers": 1,
        "llm_max_inflight": 1,
    }
    assert runtime["project"]["entry_discovery"] == {
        "enabled": False,
        "interface_files": ["api.h"],
        "max_entries": 10,
        "max_functions": 64,
    }
    assert_answer_free_payload(runtime)
    monkeypatch.setenv("Z_SCOPE_API_KEY", "private-value")
    effective = ConfigLoader.load(str(workspace.config_path), scan_depth="balanced")
    assert effective.llm.models == [P6_PROVIDER_MODEL]
    assert effective.concurrency.llm_max_inflight == 1
    assert effective.project.entry_discovery.enabled is False


def test_replay_requires_a_fresh_work_root(tmp_path: Path) -> None:
    occupied = (tmp_path / "occupied").resolve()
    occupied.mkdir()
    (occupied / "old.txt").write_text("old", encoding="utf-8")
    with pytest.raises(SyntheticReplayError) as caught:
        materialize_replay_workspace(
            root=occupied,
            source_config_path=_provider_config(tmp_path / "provider.yaml"),
        )
    assert caught.value.failure_class == "input_binding_failure"


def test_compiler_contract_is_strict_and_complete(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    calls: list[list[str]] = []

    def runner(arguments, **kwargs):
        calls.append(list(arguments))
        assert kwargs["cwd"] == workspace.project_root
        assert kwargs["stdout"] is subprocess.DEVNULL
        assert kwargs["stderr"] is subprocess.DEVNULL
        return subprocess.CompletedProcess(arguments, 0)

    compile_synthetic_project(workspace, runner=runner)
    assert len(calls) == 5
    for arguments in calls:
        assert arguments[:6] == ["cc", "-std=c11", "-Werror", "-Wall", "-Wextra", "-pthread"]
        assert "-c" in arguments


def test_recursive_canary_stops_before_scanner(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    marker = "ground" + "_" + "tr" + "uth"
    first = workspace.project_root / workspace.scenarios[0].source_name
    first.write_text(first.read_text(encoding="utf-8") + f"\n/* {marker} */\n", encoding="utf-8")
    called = False

    def runner(*args, **kwargs):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(args[0], 0)

    with pytest.raises(SyntheticReplayError) as caught:
        execute_scanner(workspace, api_key="private-value", runner=runner)
    assert caught.value.failure_class == "input_binding_failure"
    assert called is False


def test_scanner_boundary_passes_key_only_in_child_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path)
    workspace.report_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.delenv("Z_SCOPE_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("Z_SCOPE_LLM_MODEL", raising=False)
    captured: dict[str, Any] = {}

    def runner(command, **kwargs):
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        assert kwargs["stdout"] is subprocess.DEVNULL
        assert kwargs["stderr"] is subprocess.DEVNULL
        return subprocess.CompletedProcess(command, 0)

    execute_scanner(workspace, api_key="private-value", runner=runner)
    assert captured["environment"]["Z_SCOPE_API_KEY"] == "private-value"
    assert "private-value" not in json.dumps(captured["command"])
    assert "--scan-depth" in captured["command"]
    assert "balanced" in captured["command"]
    assert "--p6-pilot" in captured["command"]
    bootstrap = captured["command"][2]
    assert "install_replay_call_guards" in bootstrap


def test_pre_call_guard_enforces_retry_and_regeneration_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def original(self, *args, **kwargs):
        calls.append(str(kwargs.get("trace_label") or ""))
        return {"ok": True}

    monkeypatch.setattr(LLMClient, "chat_completion", original)
    install_replay_call_guards()
    client = object.__new__(LLMClient)
    client.max_retries = 1
    client.retry_until_available = False
    client.models = [P6_PROVIDER_MODEL]
    client._base_url_states = [SimpleNamespace(url=P6_PROVIDER_BASE_URL)]
    label = (
        "proof_engine_v3; call_kind=contract_regeneration; " "validation_cluster_uid=cluster-one"
    )
    assert client.chat_completion([], trace_label=label) == {"ok": True}
    with pytest.raises(RuntimeError):
        client.chat_completion([], trace_label=label)
    assert len(calls) == 1
    client.max_retries = 2
    with pytest.raises(RuntimeError):
        client.chat_completion([], trace_label="call_kind=initial")
    assert len(calls) == 1
    assert LLMClient.TRANSIENT_AUTH_RETRY_LIMIT == 0
    assert LLMClient.TRANSIENT_CLIENT_RESPONSE_RETRY_LIMIT == 0


def test_success_validates_model_usage_and_six_way_conservation(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    _write_success_artifacts(workspace)
    result = validate_replay_report(workspace)
    assert result["passed"] is True
    assert result["formal_evidence"] is False
    assert result["release_eligible"] is False
    assert result["provider"]["model"] == P6_PROVIDER_MODEL
    assert result["runtime"] == {
        "llm_max_inflight": 1,
        "base_url_max_concurrent_requests": 1,
        "max_transport_retries": 1,
        "max_contract_regenerations": 1,
        "source_config_sha256": workspace.source_config_sha256,
        "runtime_config_sha256": workspace.runtime_config_sha256,
    }
    assert set(result["usage"]["conservation"]) == {
        "call",
        "token",
        "tool",
        "trace",
        "finding",
        "terminal",
    }
    assert all(row["conserved"] is True for row in result["usage"]["conservation"].values())
    assert all(row["entries_scanned"] == 2 for row in result["scenarios"])
    assert all(row["protected_confirmation_count"] == 0 for row in result["scenarios"])
    assert_answer_free_payload(result)


def test_protected_confirmation_fails_semantic_gate(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    report["candidate_terminal_states"].append(
        _confirmed_state(workspace.scenarios[0].protected_entry, 99)
    )
    report["issues"].append(copy.deepcopy(report["candidate_terminal_states"][-1]))
    report["summary"]["total_issues"] += 1
    report["run_manifest"]["terminal_outcome_count"] += 1
    _rewrite_report(workspace, report)
    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "semantic"
    assert caught.value.failure_class == "anonymous_qualification_failed"


def test_incomplete_certificate_fails_closed(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    del report["candidate_terminal_states"][0]["proof_kernel_promotion_certificate"]
    _rewrite_report(workspace, report)
    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "proof"
    assert caught.value.failure_class == "terminal_state_inconsistent"


@pytest.mark.parametrize("response_model", [P6_PROVIDER_MODEL, P6_PROVIDER_RESPONSE_MODEL])
def test_response_identity_accepts_the_frozen_contract_aliases(
    tmp_path: Path,
    response_model: str,
) -> None:
    workspace = _workspace(tmp_path)
    _, events = _write_success_artifacts(workspace)
    events[0]["provider_response_model"] = response_model
    _rewrite_events(workspace, events)
    assert validate_replay_report(workspace)["passed"] is True


def test_response_identity_mismatch_fails_closed(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    _, events = _write_success_artifacts(workspace)
    events[0]["provider_response_model"] = "unbound-response-model"
    _rewrite_events(workspace, events)
    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.failure_class == "provider_identity_mismatch"


def test_token_mismatch_fails_conservation(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    report["summary"]["llm_usage"]["scan_token_usage"]["usage_attribution"]["totals"][
        "total_tokens"
    ] += 1
    _rewrite_report(workspace, report)
    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.failure_class == "accounting_conservation_failure"


@pytest.mark.parametrize(
    ("field", "value", "failure_class"),
    [
        ("retry", True, "provider_transport_exhausted"),
        ("call_kind", "contract_regeneration", "provider_protocol_incompatible"),
    ],
)
def test_retry_and_regeneration_are_bounded_per_call_chain(
    tmp_path: Path,
    field: str,
    value: Any,
    failure_class: str,
) -> None:
    workspace = _workspace(tmp_path)
    _, events = _write_success_artifacts(workspace)
    events[0][field] = value
    events[1][field] = value
    events[1]["validation_cluster_uid"] = events[0]["validation_cluster_uid"]
    _rewrite_events(workspace, events)
    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.failure_class == failure_class
    assert REPLAY_MAX_CONTRACT_REGENERATIONS == 1


def test_failure_projection_and_cli_never_expose_exception_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    error = SyntheticReplayError("provider", "provider_transport_exhausted", 2)
    projection = failure_result(error)
    assert projection["failure"] == {
        "stage": "provider",
        "failure_class": "provider_transport_exhausted",
        "failure_count": 2,
    }
    assert_answer_free_payload(projection)

    def fail(**kwargs):
        raise error

    monkeypatch.setattr(replay_cli, "run_synthetic_replay", fail)
    output = (tmp_path / "result.json").resolve()
    code = replay_cli.main(
        [
            "--config",
            str((tmp_path / "provider.yaml").resolve()),
            "--api-key-file",
            str((tmp_path / "secret.env").resolve()),
            "--work-root",
            str((tmp_path / "work").resolve()),
            "--output",
            str(output),
        ]
    )
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert captured.err == "stage=provider; class=provider_transport_exhausted:2; count=2\n"
    assert json.loads(output.read_text(encoding="utf-8")) == projection


def test_p6_docs_freeze_synthetic_replay_before_cold_balanced() -> None:
    root = Path(__file__).resolve().parents[1]
    protocol = (root / "docs" / "range-benchmark.md").read_text(encoding="utf-8")
    phase = (
        root
        / "docs"
        / "design"
        / "zscope-2.0-security-architecture"
        / "phases"
        / "P6-pilot-validation.md"
    ).read_text(encoding="utf-8")
    interfaces = (root / "docs" / "modules" / "interfaces-reporting.md").read_text(encoding="utf-8")

    replay_offset = protocol.index("scripts/run_p6_synthetic_replay.py")
    balanced_offset = protocol.index("完成一次 cold balanced", replay_offset)
    assert replay_offset < balanced_offset
    assert "--api-key-file /tmp/zscope-p6-key.env" in protocol
    assert "llm_max_inflight=1" in protocol
    assert "真实网络调用加入零网络 pytest" in protocol
    assert "deepseek-v4-flash-ga-260731" in phase
    assert "11,999,999" in phase
    assert "TP >= 82/136" in phase and "TP = 61/61" in phase
    assert "Claude Code `2.1.233`" in phase
    assert "DSH `0.1.0-rc.6`" in phase
    assert "Codex CLI `0.144.4`" in phase
    assert "`audit_observations` 是独立、守恒的 shadow-observation 集合" in interfaces
