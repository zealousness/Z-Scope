"""Tests for the S09 development evaluation prep and comparison helper.

These tests cover the development-only boundaries of
``scripts/agent_plan_evaluation.py``: answer isolation rejection, strict
identity binding for comparisons, preservation of missing/failed/
cancelled runs and retry costs, N/A handling for zero denominators, and
explicit cold/incremental difference reporting.  Nothing here starts a
scan, reads ground truth, or forms formal benchmark conclusions.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

import pytest

from zscope.reporting.json_io import write_report_atomic

from scripts.agent_plan_evaluation import _expected_record_id, main

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "agent_plan_evaluation.py"

IDENTITY_SCHEMA_VERSION = "zscope.agent-plan-evaluation-identity.v1"
RUN_SCHEMA_VERSION = "zscope.agent-plan-evaluation-run.v1"
PLAN_SCHEMA_VERSION = "zscope.agent-plan-evaluation-plan.v1"
COMPARISON_SCHEMA_VERSION = "zscope.agent-plan-evaluation-comparison.v1"

BASE_IDENTITY: Dict[str, Any] = {
    "schema_version": IDENTITY_SCHEMA_VERSION,
    "source_tree_hash": "ab" * 32,
    "source_revision": "rev-1",
    "project_id": "dev-fixture",
    "entry_functions": ["main"],
    "build_context_ids": ["bc-1"],
    "scanner_identity": "git:010f402",
    "config_hash": "cf" * 32,
    "model_manifest_hash": "mm" * 32,
    "model_provider": "hw",
    "model_name": "glm-5.3",
    "tools": {"clang_indexer": "d3" * 32},
    "candidate_schema_version": "v3.5",
    "validation_policy_version": "v3",
    "report_schema_version": 2,
}

DEFAULT_TERMINAL_STATES: List[Dict[str, Any]] = [
    {"candidate_disposition": "confirmed", "status": "confirmed", "build_context_id": "bc-1"},
    {"candidate_disposition": "confirmed", "status": "confirmed", "build_context_id": "bc-1"},
    {
        "candidate_disposition": "needs_review",
        "status": "needs_review",
        "needs_review_sub_state": "protocol_pending",
        "build_context_id": "bc-1",
    },
    {"candidate_disposition": "needs_review", "status": "needs_review", "build_context_id": "bc-1"},
    {
        "candidate_disposition": "rejected_with_proof",
        "status": "rejected_with_proof",
        "build_context_id": "bc-1",
    },
    {
        "candidate_disposition": "deferred_budget",
        "status": "deferred_budget",
        "build_context_id": "bc-1",
    },
]

DEFAULT_LEDGER_EVENTS: List[Dict[str, Any]] = [
    {
        "call_id": "c1",
        "outcome": "success",
        "prompt_tokens": 100,
        "completion_tokens": 50,
        "total_tokens": 150,
        "cached_prompt_tokens": 20,
        "reasoning_tokens": 0,
        "retry": False,
        "repair": False,
        "provider_reported": True,
        "duration_ms": 1000,
        "model": "glm-5.3",
        "tool_call_count": 2,
    },
    {
        "call_id": "c2",
        "outcome": "failed_unknown_usage",
        "prompt_tokens": 80,
        "completion_tokens": 0,
        "total_tokens": 80,
        "retry": True,
        "repair": False,
        "provider_reported": True,
        "duration_ms": 400,
        "model": "glm-5.3",
    },
    {
        "call_id": "c3",
        "outcome": "denied",
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "retry": False,
        "provider_reported": False,
        "duration_ms": 0,
        "model": "glm-5.3",
    },
]


def _write_json(path: Path, value: Mapping[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(value), indent=2) + "\n", encoding="utf-8")
    return path


def _identity_dict(**overrides: Any) -> Dict[str, Any]:
    merged = dict(BASE_IDENTITY)
    for key, value in overrides.items():
        if value is None:
            merged.pop(key, None)
        else:
            merged[key] = value
    return merged


def _write_identity(tmp_path: Path, name: str = "identity.json", **overrides: Any) -> Path:
    return _write_json(tmp_path / name, _identity_dict(**overrides))


def _report_dict(
    *,
    terminal_states: Optional[List[Dict[str, Any]]] = None,
    manifest_overrides: Optional[Mapping[str, Any]] = None,
    metadata: Optional[Mapping[str, Any]] = None,
    completeness: str = "complete",
    include_manifest: bool = True,
    schema_version: int = 2,
    extra: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    manifest: Dict[str, Any] = {
        "schema_version": "zscope.run-manifest.v1",
        "run_id": "run-1",
        "entry_function": "main",
        "project_id": BASE_IDENTITY["project_id"],
        "source_tree_hash": BASE_IDENTITY["source_tree_hash"],
        "config_hash": BASE_IDENTITY["config_hash"],
        "model_manifest_hash": BASE_IDENTITY["model_manifest_hash"],
        "candidate_schema_version": BASE_IDENTITY["candidate_schema_version"],
        "validation_policy_version": BASE_IDENTITY["validation_policy_version"],
        "issue_count": 2,
        "needs_review_count": 2,
        "pending_validation_count": 0,
        "llm_usage": {"total_tokens": 230, "request_count": 3},
    }
    manifest.update(dict(manifest_overrides or {}))
    report: Dict[str, Any] = {
        "entry_function": "main",
        "overall_verdict": "issues_found",
        "schema_version": schema_version,
        "completeness": completeness,
        "scan_outcome": "issues_found",
        "metadata": dict(metadata or {}),
        "needs_review_governance": {
            "raw_occurrence_count": 9,
            "raw_projection_count": 6,
            "pending_validation_count": 0,
        },
    }
    if include_manifest:
        report["run_manifest"] = manifest
    if terminal_states is not None:
        report["candidate_terminal_states"] = terminal_states
    report.update(dict(extra or {}))
    return report


def _write_report(
    tmp_path: Path,
    name: str = "report.json",
    **kwargs: Any,
) -> Path:
    return _write_json(tmp_path / name, _report_dict(**kwargs))


def _write_ledger(
    tmp_path: Path, events: List[Dict[str, Any]], name: str = "llm_usage_events.jsonl"
) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
    return path


def _write_shared_report(
    tmp_path: Path,
    name: str = "report.json",
    **kwargs: Any,
) -> Path:
    """Write a report through the actual product storage writer.

    The file on disk is a ``zscope.shared-json.v1`` storage envelope,
    exactly like production reports; ``write_report_atomic`` also drops a
    ``.timings.json`` sidecar next to it.
    """

    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    write_report_atomic(path, _report_dict(**kwargs))
    return path


def _scan_input_root(tmp_path: Path) -> Path:
    root = tmp_path / "scan-input"
    (root / "src").mkdir(parents=True)
    (root / "src" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    return root


def _record_run(
    tmp_path: Path,
    *,
    label: str,
    mode: str,
    identity: Path,
    report: Optional[Path],
    ledger: Optional[Path] = None,
    plan: Optional[Path] = None,
    variant_id: Optional[str] = None,
    run_status: Optional[str] = None,
    status_note: str = "",
    wall_seconds: Optional[float] = None,
    projections: Optional[List[Path]] = None,
) -> Path:
    output = tmp_path / "runs" / f"{label}.json"
    argv = [
        "record",
        "--identity",
        str(identity),
        "--mode",
        mode,
        "--label",
        label,
        "--output",
        str(output),
    ]
    if report is not None:
        argv += ["--report", str(report)]
    if ledger is not None:
        argv += ["--usage-ledger", str(ledger)]
    if plan is not None:
        argv += ["--plan", str(plan)]
    if variant_id is not None:
        argv += ["--variant-id", variant_id]
    if run_status is not None:
        argv += ["--run-status", run_status]
    if status_note:
        argv += ["--status-note", status_note]
    if wall_seconds is not None:
        argv += ["--wall-seconds", str(wall_seconds)]
    for projection in projections or []:
        argv += ["--projection", f"artifact={projection}"]
    assert main(argv) == 0
    return output


def _load(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Plan: answer isolation (EVAL01) and matrix generation
# ---------------------------------------------------------------------------


def test_plan_rejects_ground_truth_in_scan_input(tmp_path: Path, capsys) -> None:
    root = _scan_input_root(tmp_path)
    (root / "benchmark").mkdir()
    _write_json(root / "benchmark" / "ground_truth.json", {"total_vulnerabilities": 1})
    identity = _write_identity(tmp_path)
    output = tmp_path / "plan.json"

    code = main(
        [
            "plan",
            "--identity",
            str(identity),
            "--scan-input-root",
            str(root),
            "--output",
            str(output),
        ]
    )

    assert code == 2
    assert "answer_leak_detected" in capsys.readouterr().err
    assert not output.exists()


def test_plan_rejects_scanner_state_and_history_in_scan_input(tmp_path: Path) -> None:
    root = _scan_input_root(tmp_path)
    (root / ".zscope_knowledge").mkdir()
    (root / "src" / "report.json").write_text("{}", encoding="utf-8")
    identity = _write_identity(tmp_path)

    code = main(
        [
            "plan",
            "--identity",
            str(identity),
            "--scan-input-root",
            str(root),
            "--output",
            str(tmp_path / "plan.json"),
        ]
    )

    assert code == 2


def test_plan_rejects_truth_shaped_json_in_scan_input(tmp_path: Path) -> None:
    root = _scan_input_root(tmp_path)
    _write_json(root / "src" / "meta.json", {"matched_pairs": []})
    identity = _write_identity(tmp_path)

    code = main(
        [
            "plan",
            "--identity",
            str(identity),
            "--scan-input-root",
            str(root),
            "--output",
            str(tmp_path / "plan.json"),
        ]
    )

    assert code == 2


def test_plan_rejects_incomplete_identity(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path, model_manifest_hash=None)
    code = main(
        [
            "plan",
            "--identity",
            str(identity),
            "--scan-input-root",
            str(_scan_input_root(tmp_path)),
            "--output",
            str(tmp_path / "plan.json"),
        ]
    )
    assert code == 2


def test_plan_generates_dev_only_matrix_without_autostart(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    output = tmp_path / "plan.json"
    changed_hash = "cd" * 32
    code = main(
        [
            "plan",
            "--identity",
            str(identity),
            "--scan-input-root",
            str(_scan_input_root(tmp_path)),
            "--variant",
            "baseline",
            "--variant",
            "id=add-callback,kind=source_change,change=added_callback,"
            f"source-tree-hash={changed_hash},note=worker gains a callback",
            "--mode",
            "cold",
            "--mode",
            "incremental",
            "--scan-command-template",
            "zscope -c zscope.yaml scan --mode {mode} --variant {variant}",
            "--preflight-tool",
            "cmake",
            "--preflight-env",
            "Z_SCOPE_LLM_BASE_URL",
            "--output",
            str(output),
        ]
    )
    assert code == 0
    plan = _load(output)
    assert plan["schema_version"] == PLAN_SCHEMA_VERSION
    assert plan["benchmark_scope"] == "development_only"
    assert plan["autostart"] is False
    assert plan["formal_eligible"] is False
    assert plan["release_eligible"] is False
    assert plan["answer_isolation"]["status"] == "answer_free"
    assert len(plan["matrix"]) == 4  # 2 variants x 2 modes
    cells = {cell["cell_id"]: cell for cell in plan["matrix"]}
    assert cells["baseline:cold"]["command"] == (
        "zscope -c zscope.yaml scan --mode cold --variant baseline"
    )
    assert cells["add-callback:incremental"]["command"] == (
        "zscope -c zscope.yaml scan --mode incremental --variant add-callback"
    )
    for cell in plan["matrix"]:
        assert cell["autostart"] is False
        assert cell["command_source"] == "operator_template"
    variant_cell = cells["add-callback:cold"]
    assert variant_cell["expected_identity"]["source_tree_hash"] == changed_hash
    assert variant_cell["expected_identity"]["config_hash"] == BASE_IDENTITY["config_hash"]
    baseline_cell = cells["baseline:cold"]
    assert (
        baseline_cell["expected_identity"]["source_tree_hash"] == BASE_IDENTITY["source_tree_hash"]
    )
    actions = [step["action"] for step in plan["workflow"]]
    assert actions[0] == "verify_answer_free_input"
    assert "apply_declared_change" in actions
    assert "incremental_rescan" in actions
    assert "independent_cold_rescan" in actions
    assert actions[-1] == "compare"
    assert plan["preflight"]["execution"]["status"] == "not_run"
    assert plan["preflight"]["tools"][0]["name"] == "cmake"
    assert plan["preflight"]["env_vars"][0]["name"] == "Z_SCOPE_LLM_BASE_URL"


def test_plan_run_preflight_records_missing_tools_and_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _write_identity(tmp_path)
    output = tmp_path / "plan.json"
    monkeypatch.setenv("Z_SCOPE_LLM_BASE_URL", "http://127.0.0.1:1/v1")
    code = main(
        [
            "plan",
            "--identity",
            str(identity),
            "--scan-input-root",
            str(_scan_input_root(tmp_path)),
            "--preflight-tool",
            "definitely-missing-tool-xyz",
            "--preflight-env",
            "Z_SCOPE_LLM_BASE_URL",
            "--preflight-env",
            "Z_SCOPE_MISSING_ENV_VAR_XYZ",
            "--run-preflight",
            "--output",
            str(output),
        ]
    )
    assert code == 0
    plan = _load(output)
    execution = plan["preflight"]["execution"]
    assert execution["status"] == "failed"
    assert "tool:definitely-missing-tool-xyz" in execution["missing"]
    assert "env:Z_SCOPE_MISSING_ENV_VAR_XYZ" in execution["missing"]
    # Env values are secrets: only booleans are recorded.
    assert execution["env_results"] == {
        "Z_SCOPE_LLM_BASE_URL": True,
        "Z_SCOPE_MISSING_ENV_VAR_XYZ": False,
    }
    assert "127.0.0.1" not in json.dumps(plan)


# ---------------------------------------------------------------------------
# Record: answer isolation, identity binding, missing/failed/cancelled runs
# ---------------------------------------------------------------------------


def test_record_rejects_report_with_scoring_fields(tmp_path: Path, capsys) -> None:
    identity = _write_identity(tmp_path)
    report = _write_report(
        tmp_path,
        extra={"matched_pairs": [{"truth": 1, "issue": 2}]},
    )
    output = tmp_path / "run.json"
    code = main(
        [
            "record",
            "--identity",
            str(identity),
            "--mode",
            "cold",
            "--label",
            "cold",
            "--report",
            str(report),
            "--output",
            str(output),
        ]
    )
    assert code == 2
    assert "answer_leak_detected" in capsys.readouterr().err
    assert not output.exists()


def test_record_rejects_projection_with_truth_fields(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    report = _write_report(tmp_path)
    projection = _write_json(tmp_path / "proj.json", {"ground_truth": [1, 2]})
    code = main(
        [
            "record",
            "--identity",
            str(identity),
            "--mode",
            "cold",
            "--label",
            "cold",
            "--report",
            str(report),
            "--projection",
            f"coverage={projection}",
            "--output",
            str(tmp_path / "run.json"),
        ]
    )
    assert code == 2


def test_record_rejects_report_identity_conflict(tmp_path: Path, capsys) -> None:
    identity = _write_identity(tmp_path)
    report = _write_report(tmp_path, manifest_overrides={"config_hash": "ee" * 32})
    code = main(
        [
            "record",
            "--identity",
            str(identity),
            "--mode",
            "cold",
            "--label",
            "cold",
            "--report",
            str(report),
            "--output",
            str(tmp_path / "run.json"),
        ]
    )
    assert code == 2
    assert "identity_mismatch" in capsys.readouterr().err


def test_record_rejects_old_report_schema(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    report = _write_report(tmp_path, schema_version=1)
    code = main(
        [
            "record",
            "--identity",
            str(identity),
            "--mode",
            "cold",
            "--label",
            "cold",
            "--report",
            str(report),
            "--output",
            str(tmp_path / "run.json"),
        ]
    )
    assert code == 2


def test_record_extracts_counts_coverage_and_costs(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    report = _write_report(
        tmp_path,
        terminal_states=DEFAULT_TERMINAL_STATES,
        metadata={"build_coverage": {"status": "indexed", "instances": 2, "failed_instances": []}},
    )
    ledger = _write_ledger(tmp_path, DEFAULT_LEDGER_EVENTS)
    projection = _write_json(
        tmp_path / "coverage_projection.json", {"reuse": {"compiled_tus": 0, "reused_tus": 2}}
    )
    record_path = _record_run(
        tmp_path,
        label="cold",
        mode="cold",
        identity=identity,
        report=report,
        ledger=ledger,
        wall_seconds=12.5,
        projections=[projection],
    )
    record = _load(record_path)
    assert record["schema_version"] == RUN_SCHEMA_VERSION
    assert record["benchmark_scope"] == "development_only"
    assert record["formal_eligible"] is False
    assert record["run_status"]["status"] == "complete"
    counts = record["counts"]
    assert counts["source"] == "candidate_terminal_states"
    assert counts["candidate_count"] == 6
    assert counts["confirmed_count"] == 2
    assert counts["with_review_count"] == 2
    assert counts["pending_count"] == 2  # protocol_pending + deferred_budget
    assert counts["ruled_out_count"] == 1
    assert counts["needs_review_sub_states"] == {"protocol_pending": 1}
    assert record["coverage"]["status"] == "indexed"
    assert record["governance_projection"]["raw_occurrence_count"] == 9
    usage = record["resources"]["usage_ledger"]
    aggregates = usage["aggregates"]
    assert aggregates["request_count"] == 3
    assert aggregates["successful_calls"] == 1
    assert aggregates["denied_requests"] == 1
    assert aggregates["failed_or_unknown_calls"] == 1
    assert aggregates["retry_count"] == 1
    assert aggregates["retry_token_cost"] == 80
    assert aggregates["failed_or_denied_token_cost"] == 80
    assert record["resources"]["wall_seconds"] == 12.5
    assert record["resources"]["report_llm_usage"]["total_tokens"] == 230
    assert record["projections"]["artifact"]["reuse"]["reused_tus"] == 2
    assert record["identity_binding"]["report_manifest"] == "bound"


def test_record_preserves_missing_report_as_null_not_zero(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    record_path = _record_run(
        tmp_path,
        label="no-report",
        mode="warm",
        identity=identity,
        report=tmp_path / "does-not-exist.json",
        status_note="run crashed before report was written",
    )
    record = _load(record_path)
    assert record["run_status"]["status"] == "missing_report"
    assert record["counts"]["candidate_count"] is None
    assert record["counts"]["confirmed_count"] is None
    assert record["counts"]["pending_count"] is None
    assert record["coverage"] is None
    assert record["inputs"]["report"]["missing"] is True
    assert record["inputs"]["report"]["sha256"] is None


def test_record_preserves_cancelled_and_failed_statuses(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    cancelled = _record_run(
        tmp_path,
        label="cancelled",
        mode="cold",
        identity=identity,
        report=None,
        run_status="cancelled",
        status_note="operator cancelled the nightly window",
    )
    failed = _record_run(
        tmp_path,
        label="failed",
        mode="cold",
        identity=identity,
        report=tmp_path / "absent.json",
        run_status="failed",
        status_note="engine crashed",
    )
    assert _load(cancelled)["run_status"]["status"] == "cancelled"
    assert _load(cancelled)["run_status"]["operator_declared"] is True
    assert _load(failed)["run_status"]["status"] == "failed"


def test_record_fallback_counts_stay_null_for_absent_fields(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    report = _write_report(tmp_path, terminal_states=None)
    record_path = _record_run(
        tmp_path, label="fallback", mode="cold", identity=identity, report=report
    )
    counts = _load(record_path)["counts"]
    assert counts["source"] == "run_manifest_fallback"
    assert counts["candidate_count"] is None
    assert counts["confirmed_count"] == 2
    assert counts["ruled_out_count"] is None


def test_record_binds_to_plan_matrix(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    plan_output = tmp_path / "plan.json"
    assert (
        main(
            [
                "plan",
                "--identity",
                str(identity),
                "--scan-input-root",
                str(_scan_input_root(tmp_path)),
                "--mode",
                "cold",
                "--output",
                str(plan_output),
            ]
        )
        == 0
    )
    plan = _load(plan_output)
    report = _write_report(tmp_path)
    record_path = _record_run(
        tmp_path,
        label="bound",
        mode="cold",
        identity=identity,
        report=report,
        plan=plan_output,
        variant_id="baseline",
    )
    record = _load(record_path)
    assert record["plan_id"] == plan["plan_id"]
    assert record["variant_id"] == "baseline"

    code = main(
        [
            "record",
            "--identity",
            str(identity),
            "--mode",
            "incremental",
            "--label",
            "bad-mode",
            "--report",
            str(report),
            "--plan",
            str(plan_output),
            "--variant-id",
            "baseline",
            "--output",
            str(tmp_path / "runs" / "bad-mode.json"),
        ]
    )
    assert code == 2  # mode not declared in plan


# ---------------------------------------------------------------------------
# Shared storage reports (zscope.shared-json.v1 via the product writer)
# ---------------------------------------------------------------------------


def test_record_and_compare_accept_real_shared_storage_reports(tmp_path: Path) -> None:
    # Positive case from the coordinator review: a report written by the
    # actual ``write_report_atomic`` must be recorded from its logical
    # content and compare normally (here even cross-format against a
    # legacy plain-JSON report of the same identity).
    identity = _write_identity(tmp_path)
    cold_report = _write_shared_report(
        tmp_path / "cold",
        terminal_states=DEFAULT_TERMINAL_STATES,
        metadata={"build_coverage": {"status": "indexed", "instances": 2}},
    )
    incremental_states = DEFAULT_TERMINAL_STATES + [
        {
            "candidate_disposition": "needs_review",
            "status": "needs_review",
            "needs_review_sub_state": "protocol_pending",
            "build_context_id": "bc-1",
        }
    ]
    incremental_report = _write_report(
        tmp_path / "inc",
        terminal_states=incremental_states,
        metadata={"build_coverage": {"status": "indexed", "instances": 2}},
    )
    run_cold = _record_run(
        tmp_path, label="cold", mode="cold", identity=identity, report=cold_report
    )
    run_inc = _record_run(
        tmp_path,
        label="incremental",
        mode="incremental",
        identity=identity,
        report=incremental_report,
    )
    record = _load(run_cold)
    assert record["run_status"]["status"] == "complete"
    # Extraction saw the logical report, not the storage envelope.
    assert record["counts"]["candidate_count"] == 6
    assert record["counts"]["confirmed_count"] == 2
    assert record["counts"]["pending_count"] == 2
    assert record["coverage"]["status"] == "indexed"
    assert record["identity_binding"]["report_manifest"] == "bound"
    report_format = record["inputs"]["report"]["format"]
    assert report_format["storage"] == "shared-json"
    assert report_format["storage_schema"] == "zscope.shared-json.v1"
    assert report_format["envelope_extra_keys"] == []
    # The frozen SHA covers the raw stored bytes (the envelope itself).
    raw = cold_report.read_bytes()
    assert record["inputs"]["report"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert json.loads(raw)["storage_schema"] == "zscope.shared-json.v1"
    comparison = _comparison(
        tmp_path, [f"cold={run_cold}", f"incremental={run_inc}"], baseline="cold"
    )
    assert comparison["comparison_status"] == "compared"
    assert comparison["identity_bound_same_version"] is True
    assert comparison["counts_comparison"]["candidate_count"]["cold"] == 6
    assert comparison["counts_comparison"]["candidate_count"]["incremental"] == 7
    assert comparison["counts_comparison"]["pending_count"]["incremental"] == 3


def test_record_rejects_shared_report_with_missing_reference(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    report_path = _write_shared_report(tmp_path)
    envelope = _load(report_path)
    root_node = envelope["objects"][envelope["root"][1]]
    referenced = [
        child[1] for _key, child in root_node[1] if isinstance(child, list) and child[0] == "ref"
    ]
    assert referenced
    del envelope["objects"][referenced[0]]
    report_path.write_text(json.dumps(envelope), encoding="utf-8")

    code = main(
        [
            "record",
            "--identity",
            str(identity),
            "--mode",
            "cold",
            "--label",
            "cold",
            "--report",
            str(report_path),
            "--output",
            str(tmp_path / "run.json"),
        ]
    )
    assert code == 2


def test_record_rejects_shared_report_with_wrong_object_digest(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    report_path = _write_shared_report(tmp_path)
    envelope = _load(report_path)
    root_node = envelope["objects"][envelope["root"][1]]
    # Mutate the stored object without updating its content digest.
    root_node[1][0][1] = ["value", "tampered"]
    report_path.write_text(json.dumps(envelope), encoding="utf-8")

    code = main(
        [
            "record",
            "--identity",
            str(identity),
            "--mode",
            "cold",
            "--label",
            "cold",
            "--report",
            str(report_path),
            "--output",
            str(tmp_path / "run.json"),
        ]
    )
    assert code == 2


def test_record_rejects_truth_marker_encoded_in_shared_report(tmp_path: Path, capsys) -> None:
    # The forbidden marker lives in the logical report and is encoded
    # into the shared storage; rejection must happen on the decoded
    # logical report, not on the envelope's storage keys.
    identity = _write_identity(tmp_path)
    report_path = _write_shared_report(
        tmp_path, extra={"matched_pairs": [{"truth": 1, "issue": 2}]}
    )
    code = main(
        [
            "record",
            "--identity",
            str(identity),
            "--mode",
            "cold",
            "--label",
            "cold",
            "--report",
            str(report_path),
            "--output",
            str(tmp_path / "run.json"),
        ]
    )
    assert code == 2
    assert "answer_leak_detected" in capsys.readouterr().err


def test_record_rejects_truth_marker_in_envelope_extra_keys(tmp_path: Path) -> None:
    # Truth material smuggled into non-standard envelope metadata is
    # rejected as well, so shared storage does not lower the answer
    # isolation standard relative to plain JSON.
    identity = _write_identity(tmp_path)
    report_path = _write_shared_report(tmp_path)
    envelope = _load(report_path)
    envelope["matched_pairs"] = []
    report_path.write_text(json.dumps(envelope), encoding="utf-8")

    code = main(
        [
            "record",
            "--identity",
            str(identity),
            "--mode",
            "cold",
            "--label",
            "cold",
            "--report",
            str(report_path),
            "--output",
            str(tmp_path / "run.json"),
        ]
    )
    assert code == 2


# ---------------------------------------------------------------------------
# Compare: identity rejection, N/A denominators, explicit differences
# ---------------------------------------------------------------------------


def _comparison(
    tmp_path: Path, runs: List[str], *, baseline: Optional[str] = None, **flags: Any
) -> Dict[str, Any]:
    output = tmp_path / "comparison.json"
    argv = ["compare", "--output", str(output)]
    for spec in runs:
        argv += ["--run", spec]
    if baseline:
        argv += ["--baseline", baseline]
    for key, value in flags.items():
        flag = "--" + key.replace("_", "-")
        if value is True:
            argv.append(flag)
        else:
            argv += [flag, str(value)]
    assert main(argv) == 0
    return _load(output)


def test_compare_rejects_different_model(tmp_path: Path) -> None:
    identity_a = _write_identity(tmp_path / "a", name="identity.json")
    identity_b = _write_identity(
        tmp_path / "b", name="identity.json", model_manifest_hash="ee" * 32
    )
    report_a = _write_report(tmp_path / "a")
    report_b = _write_report(tmp_path / "b", manifest_overrides={"model_manifest_hash": "ee" * 32})
    run_a = _record_run(tmp_path, label="cold", mode="cold", identity=identity_a, report=report_a)
    run_b = _record_run(tmp_path, label="warm", mode="warm", identity=identity_b, report=report_b)
    comparison = _comparison(tmp_path, [f"cold={run_a}", f"warm={run_b}"], baseline="cold")
    assert comparison["schema_version"] == COMPARISON_SCHEMA_VERSION
    assert comparison["comparison_status"] == "rejected_identity_mismatch"
    assert "model_manifest_hash" in comparison["identity_check"]["mismatched_fields"]
    assert comparison["counts_comparison"] == {"not_computed_reason": "rejected_identity_mismatch"}
    assert comparison["derived_metrics"] == {"not_computed_reason": "rejected_identity_mismatch"}
    assert comparison["formal_eligible"] is False


def test_compare_rejects_different_source_and_build_context(tmp_path: Path) -> None:
    report = _write_report(tmp_path / "base", terminal_states=DEFAULT_TERMINAL_STATES)
    identity_base = _write_identity(tmp_path / "base")
    run_base = _record_run(
        tmp_path, label="cold", mode="cold", identity=identity_base, report=report
    )

    other_source = _write_identity(tmp_path / "src", source_tree_hash="11" * 32)
    report_src = _write_report(tmp_path / "src", manifest_overrides={"source_tree_hash": "11" * 32})
    run_src = _record_run(
        tmp_path, label="src", mode="cold", identity=other_source, report=report_src
    )
    comparison = _comparison(tmp_path, [f"cold={run_base}", f"src={run_src}"], baseline="cold")
    assert comparison["comparison_status"] == "rejected_identity_mismatch"
    assert "source_tree_hash" in comparison["identity_check"]["mismatched_fields"]

    other_build = _write_identity(tmp_path / "bc", build_context_ids=["bc-9"])
    report_bc = _write_report(
        tmp_path / "bc",
        terminal_states=[dict(item, build_context_id="bc-9") for item in DEFAULT_TERMINAL_STATES],
    )
    run_bc = _record_run(tmp_path, label="bc", mode="cold", identity=other_build, report=report_bc)
    comparison = _comparison(tmp_path, [f"cold={run_base}", f"bc={run_bc}"], baseline="cold")
    assert comparison["comparison_status"] == "rejected_identity_mismatch"
    assert "build_context_ids" in comparison["identity_check"]["mismatched_fields"]


def test_compare_rejects_old_candidate_schema(tmp_path: Path) -> None:
    identity_old = _write_identity(tmp_path / "old", candidate_schema_version="v3.4")
    report_old = _write_report(
        tmp_path / "old", manifest_overrides={"candidate_schema_version": "v3.4"}
    )
    run_old = _record_run(
        tmp_path, label="old", mode="cold", identity=identity_old, report=report_old
    )
    identity_new = _write_identity(tmp_path / "new")
    report_new = _write_report(tmp_path / "new")
    run_new = _record_run(
        tmp_path, label="new", mode="cold", identity=identity_new, report=report_new
    )
    comparison = _comparison(tmp_path, [f"old={run_old}", f"new={run_new}"], baseline="new")
    assert comparison["comparison_status"] == "rejected_identity_mismatch"
    assert "candidate_schema_version" in comparison["identity_check"]["mismatched_fields"]


def test_compare_untested_when_identity_incomplete(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    report = _write_report(tmp_path)
    run_a = _record_run(tmp_path, label="cold", mode="cold", identity=identity, report=report)
    run_b = _record_run(tmp_path, label="warm", mode="warm", identity=identity, report=report)

    # Forge a record whose identity lost a required field but whose
    # record_id was recomputed for the edited body.  This exercises the
    # compare-side defense-in-depth branch (e.g. records produced by a
    # future tool version with fewer fields); plain tampering that keeps
    # the stale record_id is rejected at load time by the tests below.
    forged = _load(run_b)
    forged["identity"].pop("scanner_identity")
    forged["record_id"] = _expected_record_id(forged)
    _write_json(run_b, forged)

    comparison = _comparison(tmp_path, [f"cold={run_a}", f"warm={run_b}"], baseline="cold")
    assert comparison["comparison_status"] == "untested_identity_incomplete"
    assert "scanner_identity" in comparison["identity_check"]["missing_fields"]


def test_compare_rejects_tampered_record_body_with_stale_record_id(tmp_path: Path, capsys) -> None:
    # Coordinator review repro (synthetic): two records with different
    # model manifest hashes; the warm record body is edited to the cold
    # identity with an inflated confirmed_count while keeping the frozen
    # record_id and leaving the external report/usage files untouched.
    # Before the fix this turned rejected_identity_mismatch into
    # compared with confirmed_count=999.
    identity_a = _write_identity(tmp_path / "a", name="identity.json")
    identity_b = _write_identity(
        tmp_path / "b", name="identity.json", model_manifest_hash="ee" * 32
    )
    report_a = _write_report(tmp_path / "a")
    report_b = _write_report(tmp_path / "b", manifest_overrides={"model_manifest_hash": "ee" * 32})
    run_a = _record_run(tmp_path, label="cold", mode="cold", identity=identity_a, report=report_a)
    run_b = _record_run(tmp_path, label="warm", mode="warm", identity=identity_b, report=report_b)

    before = _comparison(tmp_path, [f"cold={run_a}", f"warm={run_b}"], baseline="cold")
    assert before["comparison_status"] == "rejected_identity_mismatch"

    tampered = _load(run_b)
    stale_record_id = tampered["record_id"]
    tampered["identity"] = _load(run_a)["identity"]
    tampered["counts"]["confirmed_count"] = 999
    _write_json(run_b, tampered)
    assert _load(run_b)["record_id"] == stale_record_id  # stale ID kept

    output = tmp_path / "comparison-after.json"
    code = main(
        [
            "compare",
            "--run",
            f"cold={run_a}",
            "--run",
            f"warm={run_b}",
            "--baseline",
            "cold",
            "--output",
            str(output),
        ]
    )
    assert code == 2
    assert "record_integrity" in capsys.readouterr().err
    # No comparison artifact is written, so no quality metrics exist at
    # all for the tampered run.
    assert not output.exists()


def test_compare_rejects_tampered_counts_coverage_and_costs(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    report = _write_report(tmp_path)
    ledger = _write_ledger(tmp_path, DEFAULT_LEDGER_EVENTS)
    run_a = _record_run(tmp_path, label="cold", mode="cold", identity=identity, report=report)
    run_b = _record_run(
        tmp_path, label="warm", mode="warm", identity=identity, report=report, ledger=ledger
    )

    tampered = _load(run_b)
    tampered["counts"]["pending_count"] = 0
    tampered["coverage"] = {"status": "indexed", "instances": 99}
    tampered["resources"]["usage_ledger"]["aggregates"]["total_tokens"] = 1
    tampered["resources"]["usage_ledger"]["aggregates"]["retry_token_cost"] = 0
    tampered["resources"]["wall_seconds"] = 0.1
    _write_json(run_b, tampered)  # stale record_id kept

    code = main(
        [
            "compare",
            "--run",
            f"cold={run_a}",
            "--run",
            f"warm={run_b}",
            "--baseline",
            "cold",
            "--output",
            str(tmp_path / "comparison.json"),
        ]
    )
    assert code == 2


def test_compare_missing_or_malformed_record_id_fails(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    report = _write_report(tmp_path)
    run_a = _record_run(tmp_path, label="cold", mode="cold", identity=identity, report=report)
    run_b = _record_run(tmp_path, label="warm", mode="warm", identity=identity, report=report)

    for bad_id in (None, "", "not-a-record-id"):
        tampered = _load(run_b)
        if bad_id is None:
            tampered.pop("record_id")
        else:
            tampered["record_id"] = bad_id
        _write_json(run_b, tampered)
        code = main(
            [
                "compare",
                "--run",
                f"cold={run_a}",
                "--run",
                f"warm={run_b}",
                "--baseline",
                "cold",
                "--output",
                str(tmp_path / "comparison.json"),
            ]
        )
        assert code == 2


def test_recomputed_record_id_cannot_bypass_bound_report_identity(tmp_path: Path) -> None:
    # Even a forger who recomputes record_id for the edited body cannot
    # swap the identity of a report-manifest-bound record: compare
    # re-anchors the report-provided identity fields to the unmodified
    # report file and refuses to compute quality metrics.
    identity_a = _write_identity(tmp_path / "a", name="identity.json")
    identity_b = _write_identity(
        tmp_path / "b", name="identity.json", model_manifest_hash="ee" * 32
    )
    report_a = _write_report(tmp_path / "a")
    report_b = _write_report(tmp_path / "b", manifest_overrides={"model_manifest_hash": "ee" * 32})
    run_a = _record_run(tmp_path, label="cold", mode="cold", identity=identity_a, report=report_a)
    run_b = _record_run(tmp_path, label="warm", mode="warm", identity=identity_b, report=report_b)

    forged = _load(run_b)
    forged["identity"] = _load(run_a)["identity"]
    forged["record_id"] = _expected_record_id(forged)
    _write_json(run_b, forged)

    comparison = _comparison(tmp_path, [f"cold={run_a}", f"warm={run_b}"], baseline="cold")
    assert comparison["comparison_status"] == "untested_record_integrity"
    anchor = [
        v
        for v in comparison["integrity"]["violations"]
        if v.get("check") == "identity_vs_bound_report"
    ]
    assert anchor
    assert anchor[0]["field"] == "model_manifest_hash"
    assert anchor[0]["report_value"] == json.dumps("ee" * 32)
    assert comparison["counts_comparison"] == {"not_computed_reason": "untested_record_integrity"}
    assert comparison["identity_bound_same_version"] is False


def test_recomputed_record_id_cannot_bypass_bound_report_identity_shared(
    tmp_path: Path,
) -> None:
    # Defense in depth on the shared-storage path: even a forger who
    # recomputes record_id cannot swap the identity of a record bound to
    # a ``zscope.shared-json.v1`` report; the anchor decodes the logical
    # report through the official reader and compares identity fields.
    identity_a = _write_identity(tmp_path / "a", name="identity.json")
    identity_b = _write_identity(
        tmp_path / "b", name="identity.json", model_manifest_hash="ee" * 32
    )
    report_a = _write_shared_report(tmp_path / "a")
    report_b = _write_shared_report(
        tmp_path / "b", manifest_overrides={"model_manifest_hash": "ee" * 32}
    )
    run_a = _record_run(tmp_path, label="cold", mode="cold", identity=identity_a, report=report_a)
    run_b = _record_run(tmp_path, label="warm", mode="warm", identity=identity_b, report=report_b)

    forged = _load(run_b)
    forged["identity"] = _load(run_a)["identity"]
    forged["record_id"] = _expected_record_id(forged)
    _write_json(run_b, forged)

    comparison = _comparison(tmp_path, [f"cold={run_a}", f"warm={run_b}"], baseline="cold")
    assert comparison["comparison_status"] == "untested_record_integrity"
    anchor = [
        v
        for v in comparison["integrity"]["violations"]
        if v.get("check") == "identity_vs_bound_report"
    ]
    assert anchor
    assert anchor[0]["field"] == "model_manifest_hash"
    assert anchor[0]["report_value"] == json.dumps("ee" * 32)
    assert comparison["counts_comparison"] == {"not_computed_reason": "untested_record_integrity"}


def test_declared_only_identity_is_not_reported_as_measured_same_version(
    tmp_path: Path,
) -> None:
    # Records without a report manifest keep the explicit declared
    # identity source, but the comparison must not describe that untested
    # source as a measured same-version binding.
    identity = _write_identity(tmp_path)
    report_a = _write_report(tmp_path / "a", include_manifest=False)
    report_b = _write_report(tmp_path / "b", include_manifest=False)
    run_a = _record_run(tmp_path, label="cold", mode="cold", identity=identity, report=report_a)
    run_b = _record_run(tmp_path, label="warm", mode="warm", identity=identity, report=report_b)

    comparison = _comparison(tmp_path, [f"cold={run_a}", f"warm={run_b}"], baseline="cold")
    assert comparison["comparison_status"] == "compared"
    assert comparison["identity_bound_same_version"] is False
    for label in ("cold", "warm"):
        assert comparison["identity_binding_sources"][label]["source"] == "declared_only"
        assert comparison["identity_binding_sources"][label]["declared_only_records"] == 1
    assert any("declared-only" in caveat for caveat in comparison["caveats"])
    assert any("not a measured same-version binding" in caveat for caveat in comparison["caveats"])


def test_compare_flags_tampered_input_after_freeze(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    report = _write_report(tmp_path)
    run_a = _record_run(tmp_path, label="cold", mode="cold", identity=identity, report=report)
    run_b = _record_run(tmp_path, label="warm", mode="warm", identity=identity, report=report)

    report.write_text(json.dumps(_report_dict()) + "\n", encoding="utf-8")  # content changed

    comparison = _comparison(tmp_path, [f"cold={run_a}", f"warm={run_b}"], baseline="cold")
    assert comparison["comparison_status"] == "untested_input_modified_after_freeze"
    assert comparison["integrity"]["violations"]
    assert comparison["counts_comparison"]["not_computed_reason"] == (
        "untested_input_modified_after_freeze"
    )


def test_compare_lists_explicit_cold_incremental_differences(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    cold_report = _write_report(
        tmp_path / "cold",
        terminal_states=DEFAULT_TERMINAL_STATES,
        metadata={"build_coverage": {"status": "indexed", "instances": 2}},
    )
    incremental_states = list(DEFAULT_TERMINAL_STATES) + [
        {
            "candidate_disposition": "needs_review",
            "status": "needs_review",
            "needs_review_sub_state": "protocol_pending",
            "build_context_id": "bc-1",
        }
    ]
    incremental_report = _write_report(
        tmp_path / "inc",
        terminal_states=incremental_states,
        metadata={"build_coverage": {"status": "partial", "instances": 2}},
    )
    run_cold = _record_run(
        tmp_path,
        label="cold",
        mode="cold",
        identity=identity,
        report=cold_report,
        wall_seconds=100.0,
    )
    run_inc = _record_run(
        tmp_path,
        label="incremental",
        mode="incremental",
        identity=identity,
        report=incremental_report,
        wall_seconds=20.0,
    )
    comparison = _comparison(
        tmp_path, [f"cold={run_cold}", f"incremental={run_inc}"], baseline="cold"
    )
    assert comparison["comparison_status"] == "compared"
    assert comparison["identity_bound_same_version"] is True
    counts = comparison["counts_comparison"]
    assert counts["candidate_count"]["cold"] == 6
    assert counts["candidate_count"]["incremental"] == 7
    assert counts["pending_count"]["cold"] == 2
    assert counts["pending_count"]["incremental"] == 3
    assert counts["confirmed_count"]["difference_vs_baseline"] is False
    assert counts["coverage"]["difference_vs_baseline"] is True
    difference_fields = {item["field"] for item in comparison["differences"]}
    assert {"candidate_count", "pending_count", "coverage"} <= difference_fields
    assert "resources.wall_seconds" in difference_fields
    assert comparison["runs"]["cold"]["sample_size"] == 1
    assert any(
        "single-run samples are not a stable advantage" in caveat
        for caveat in comparison["caveats"]
    )


def test_compare_preserves_missing_report_and_costs_not_as_zero(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    ledger = _write_ledger(tmp_path, DEFAULT_LEDGER_EVENTS)
    report = _write_report(tmp_path, terminal_states=DEFAULT_TERMINAL_STATES)
    run_ok = _record_run(
        tmp_path, label="cold", mode="cold", identity=identity, report=report, ledger=ledger
    )
    run_missing = _record_run(
        tmp_path,
        label="warm",
        mode="warm",
        identity=identity,
        report=tmp_path / "never-written.json",
        status_note="warm rerun crashed; no report",
    )
    comparison = _comparison(tmp_path, [f"cold={run_ok}", f"warm={run_missing}"], baseline="cold")
    assert comparison["comparison_status"] == "compared"
    counts = comparison["counts_comparison"]
    assert counts["candidate_count"]["warm"] is None  # missing, not zero
    assert counts["candidate_count"]["cold"] == 6
    assert counts["candidate_count"]["difference_vs_baseline"] is True
    warm_resources = comparison["resource_comparison"]["warm"]
    assert warm_resources["usage_ledger"]["present"] is False
    assert warm_resources["usage_ledger"]["total_tokens"] == 0
    assert warm_resources["wall_seconds"]["median"] is None
    assert comparison["runs"]["warm"]["run_statuses"] == ["missing_report"]
    assert comparison["runs"]["warm"]["all_runs_complete"] is False


def test_compare_failure_and_retry_costs_are_summed_and_visible(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    report = _write_report(tmp_path)
    heavy_events = DEFAULT_LEDGER_EVENTS + [
        {
            "call_id": "c4",
            "outcome": "failed_unknown_usage",
            "prompt_tokens": 500,
            "completion_tokens": 0,
            "total_tokens": 500,
            "retry": True,
            "provider_reported": True,
            "duration_ms": 900,
            "model": "glm-5.3",
        }
    ]
    run_cold = _record_run(
        tmp_path,
        label="cold",
        mode="cold",
        identity=identity,
        report=report,
        ledger=_write_ledger(tmp_path / "l1", DEFAULT_LEDGER_EVENTS, name="a.jsonl"),
    )
    run_warm = _record_run(
        tmp_path,
        label="warm",
        mode="warm",
        identity=identity,
        report=report,
        ledger=_write_ledger(tmp_path / "l2", heavy_events, name="b.jsonl"),
    )
    comparison = _comparison(tmp_path, [f"cold={run_cold}", f"warm={run_warm}"], baseline="cold")
    assert comparison["comparison_status"] == "compared"
    cold_ledger = comparison["resource_comparison"]["cold"]["usage_ledger"]
    warm_ledger = comparison["resource_comparison"]["warm"]["usage_ledger"]
    assert cold_ledger["failed_or_unknown_calls"] == 1
    assert warm_ledger["failed_or_unknown_calls"] == 2
    assert warm_ledger["retry_count"] == 2
    assert warm_ledger["retry_token_cost"] == 580
    assert warm_ledger["failed_or_denied_token_cost"] == 580
    difference_fields = {item["field"] for item in comparison["differences"]}
    assert "resources.usage_ledger.failed_or_unknown_calls" in difference_fields
    assert "resources.usage_ledger.retry_token_cost" in difference_fields


def test_confirmation_rate_zero_denominator_is_na_not_100(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    clean_report = _write_report(
        tmp_path / "clean", terminal_states=[], manifest_overrides={"issue_count": 0}
    )
    fallback_report = _write_report(tmp_path / "fallback", terminal_states=None)
    run_clean = _record_run(
        tmp_path, label="clean", mode="cold", identity=identity, report=clean_report
    )
    run_fallback = _record_run(
        tmp_path, label="fallback", mode="warm", identity=identity, report=fallback_report
    )
    comparison = _comparison(
        tmp_path, [f"clean={run_clean}", f"fallback={run_fallback}"], baseline="clean"
    )
    assert comparison["comparison_status"] == "compared"
    clean_counts = _load(run_clean)["counts"]
    assert clean_counts["candidate_count"] == 0
    assert clean_counts["confirmed_count"] == 0
    clean_rate = comparison["derived_metrics"]["clean"]["confirmation_rate"]
    assert clean_rate["status"] == "na_zero_denominator"
    assert clean_rate["value"] is None
    assert clean_rate["denominator"] == 0
    fallback_rate = comparison["derived_metrics"]["fallback"]["confirmation_rate"]
    assert fallback_rate["status"] == "missing_input"
    assert fallback_rate["value"] is None
    assert fallback_rate["denominator"] is None


# ---------------------------------------------------------------------------
# Declared variant comparisons (offline dev workflow)
# ---------------------------------------------------------------------------


def _variant_plan(tmp_path: Path) -> Path:
    identity = _write_identity(tmp_path)
    changed_hash = "cd" * 32
    output = tmp_path / "plan.json"
    assert (
        main(
            [
                "plan",
                "--identity",
                str(identity),
                "--scan-input-root",
                str(_scan_input_root(tmp_path)),
                "--variant",
                f"id=add-callback,kind=source_change,change=added_callback,"
                f"source-tree-hash={changed_hash}",
                "--mode",
                "cold",
                "--mode",
                "incremental",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    return output


def test_variant_comparison_requires_plan(tmp_path: Path) -> None:
    identity = _write_identity(tmp_path)
    report = _write_report(tmp_path)
    run_a = _record_run(tmp_path, label="cold", mode="cold", identity=identity, report=report)
    run_b = _record_run(tmp_path, label="warm", mode="warm", identity=identity, report=report)
    output = tmp_path / "comparison.json"
    code = main(
        [
            "compare",
            "--run",
            f"cold={run_a}",
            "--run",
            f"warm={run_b}",
            "--variant-comparison",
            "--output",
            str(output),
        ]
    )
    assert code == 2


def test_variant_comparison_allows_declared_source_change_only(tmp_path: Path) -> None:
    plan_path = _variant_plan(tmp_path)
    plan = _load(plan_path)
    changed_hash = "cd" * 32

    baseline_identity = _write_identity(tmp_path / "b", name="identity.json")
    baseline_report = _write_report(tmp_path / "b")
    run_baseline = _record_run(
        tmp_path,
        label="baseline",
        mode="cold",
        identity=baseline_identity,
        report=baseline_report,
        plan=plan_path,
        variant_id="baseline",
    )

    variant_identity = _write_identity(
        tmp_path / "v", name="identity.json", source_tree_hash=changed_hash
    )
    variant_report = _write_report(
        tmp_path / "v", manifest_overrides={"source_tree_hash": changed_hash}
    )
    run_variant = _record_run(
        tmp_path,
        label="add-callback",
        mode="incremental",
        identity=variant_identity,
        report=variant_report,
        plan=plan_path,
        variant_id="add-callback",
    )

    comparison = _comparison(
        tmp_path,
        [f"baseline={run_baseline}", f"add-callback={run_variant}"],
        baseline="baseline",
        variant_comparison=True,
        plan=plan_path,
    )
    assert comparison["comparison_status"] == "compared"
    assert comparison["mode"] == "declared_variant_diff"
    assert comparison["identity_bound_same_version"] is False
    binding = comparison["variant_binding"]
    assert binding["status"] == "bound"
    assert binding["label_variants"]["add-callback"]["declared_change"] == "added_callback"
    assert any(
        "not a same-version quality equivalence claim" in caveat for caveat in comparison["caveats"]
    )


def test_variant_comparison_rejects_undeclared_identity_drift(tmp_path: Path) -> None:
    plan_path = _variant_plan(tmp_path)
    changed_hash = "cd" * 32

    baseline_identity = _write_identity(tmp_path / "b", name="identity.json")
    run_baseline = _record_run(
        tmp_path,
        label="baseline",
        mode="cold",
        identity=baseline_identity,
        report=_write_report(tmp_path / "b"),
        plan=plan_path,
        variant_id="baseline",
    )
    assert _load(run_baseline)["plan_id"] == _load(plan_path)["plan_id"]

    # A variant record that also swaps the model is not declared by the
    # plan: it must fail closed at record time instead of ever reaching a
    # comparison that could pretend to be a declared variant diff.
    variant_identity = _write_identity(
        tmp_path / "v",
        name="identity.json",
        source_tree_hash=changed_hash,
        model_manifest_hash="ee" * 32,
    )
    output = tmp_path / "runs" / "drift.json"
    code = main(
        [
            "record",
            "--identity",
            str(variant_identity),
            "--mode",
            "incremental",
            "--label",
            "add-callback",
            "--report",
            str(
                _write_report(
                    tmp_path / "v",
                    manifest_overrides={
                        "source_tree_hash": changed_hash,
                        "model_manifest_hash": "ee" * 32,
                    },
                )
            ),
            "--plan",
            str(plan_path),
            "--variant-id",
            "add-callback",
            "--output",
            str(output),
        ]
    )
    assert code == 2
    assert not output.exists()


# ---------------------------------------------------------------------------
# CLI sanity
# ---------------------------------------------------------------------------


def test_cli_runs_standalone(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "plan" in result.stdout and "record" in result.stdout and "compare" in result.stdout
