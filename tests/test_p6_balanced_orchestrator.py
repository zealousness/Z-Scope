from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from types import SimpleNamespace

import pytest

from scripts import p6_balanced_orchestrator as orchestrator_cli
from tests.p6_v4_test_support import confirmed_product_v4_issue
from scripts.p6_balanced_quality_gate import (
    P6BalancedQualityGateError,
    build_quality_gate,
    load_quality_gate,
    validate_quality_failure_aggregate,
    validate_quality_gate_bundle,
)
from zscope.benchmarking import p6_balanced_orchestrator as balanced_orchestrator
from zscope.benchmarking.p6_balanced_orchestrator import (
    BalancedRunIdentity,
    P6BalancedOrchestratorError,
    freeze_balanced_scan,
    revalidate_complete_local_balanced_evidence,
    revalidate_balanced_quality_bundle,
    score_frozen_balanced_scan,
    validate_frozen_balanced_scan,
    validate_complete_local_balanced_evidence,
    validate_quality_revalidation_receipt,
    verify_committed_local_balanced_evidence,
)
from zscope.benchmarking.p6_protocol import canonical_sha256
from zscope.benchmarking.provider_runtime import require_p6_provider_contract
from zscope.benchmarking.runner import BenchmarkError, build_p6_answer_free_producer_metrics
from zscope.framework.llm_usage import LLMUsageAttribution, LLMUsageEvent
from zscope.orchestration.decision_trace import DecisionTraceStore


REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG = REPO_ROOT / "test/range/zscope.benchmark.yaml"
LEGACY_TRUTH = REPO_ROOT / "test/range/benchmark/ground_truth.json"
V16_TRUTH = REPO_ROOT / "test/range/benchmark/v16/ground_truth.json"
_REAL_MATERIALIZE_CONTROL_PLANE_TREE = balanced_orchestrator._materialize_control_plane_tree


def _git_object_sha1(kind: str, payload: bytes) -> str:
    header = f"{kind} {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _git_flat_tree_sha1(root: Path) -> str:
    entries = bytearray()
    children = sorted(root.iterdir(), key=lambda value: value.name.encode("utf-8"))
    assert children and all(child.is_file() and not child.is_symlink() for child in children)
    for child in children:
        entries.extend(b"100644 ")
        entries.extend(child.name.encode("utf-8"))
        entries.append(0)
        entries.extend(bytes.fromhex(_git_object_sha1("blob", child.read_bytes())))
    return _git_object_sha1("tree", bytes(entries))


def _function_source_sha256(path: Path, name: str) -> str:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    )
    lines = source.splitlines(keepends=True)
    payload = "".join(lines[function.lineno - 1 : function.end_lineno]).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@pytest.fixture(autouse=True)
def _sealed_test_control_plane(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit scorers use a small immutable-tree projection, never the live checkout."""

    def materialize(*, repository_root: Path, control_plane_commit: str, destination: Path) -> Any:
        destination.mkdir(mode=0o700)
        source_root = Path(repository_root)
        required = {
            *balanced_orchestrator._CANONICAL_SOURCE_FILES.values(),
            *balanced_orchestrator._CANONICAL_TRUTH_FILES.values(),
            "zscope/benchmarking/benchmark_v5.py",
            "zscope/benchmarking/p6_protocol.py",
        }
        manifest = hashlib.sha256()
        for relative in sorted(required):
            source = source_root / relative
            payload = source.read_bytes() if source.is_file() else b"# sealed test source\n"
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            manifest.update(relative.encode("utf-8"))
            manifest.update(b"\0")
            manifest.update(hashlib.sha256(payload).digest())
        return balanced_orchestrator._ControlPlaneTreeSnapshot(
            root=destination,
            commit_sha=control_plane_commit,
            tree_sha="e" * 40,
            manifest_sha256=manifest.hexdigest(),
        )

    monkeypatch.setattr(
        balanced_orchestrator,
        "_materialize_control_plane_tree",
        materialize,
    )


def _dump(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", "utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _identity() -> BalancedRunIdentity:
    return BalancedRunIdentity(
        workflow_run_id="33260000001",
        workflow_run_attempt=2,
        attempt_id="p6-33260000001-2",
        control_plane_commit="c" * 40,
        candidate_git_sha="1" * 40,
        candidate_git_tree="2" * 40,
    )


def test_p6_change_scope_preserves_attested_scorers_truth_and_review_packets() -> None:
    """The P6 product repair must not smuggle in an answer-authority change."""

    expected_blobs = {
        "zscope/benchmarking/protocol.py": "0d50d3de3550e929988e5f6b77e603a6fceb95d7",
        "scripts/score_range_v5.py": "a5563b29e1d20df7a0ff325f4d7dd509dbcae625",
        "zscope/cli/benchmark.py": "3371c6f4179bb26e197df72f77d8572b3459bf4f",
        "test/range/benchmark/ground_truth.json": ("68dea065fefacbdea6d66da2feee2dc82c4c915b"),
        "test/range/benchmark/v16/ground_truth.json": ("9caebd6cd964985db500624eed27bc85cbdc88b9"),
        "test/range/benchmark/v16/review-packet-catalog.json": (
            "2da54076b7caae63ed1d8c974cc262d8bcdafacb"
        ),
    }
    for relative, expected in expected_blobs.items():
        assert _git_object_sha1("blob", (REPO_ROOT / relative).read_bytes()) == expected

    packet_root = REPO_ROOT / "test/range/benchmark/v16/review-packets"
    assert _git_flat_tree_sha1(packet_root) == "31034bd42054e28cbaa0ae7b1d1eb033cf243cd4"

    entry_gate = json.loads(
        (
            REPO_ROOT / "docs/design/zscope-2.0-security-architecture/acceptance/p6-entry-gate.json"
        ).read_text(encoding="utf-8")
    )
    assert entry_gate["e0_attestation"]["component_commits"]["scorer"] == (
        "6ad0ba64247de56a497135e8daf7aac988da715d"
    )
    assert entry_gate["e0_attestation"]["component_commits"]["truth"] == (
        "3e05889ba5773d8fc8c7e22ae9b75dcfe43e05c4"
    )
    assert entry_gate["review_packets"]["review_source_sha"] == (
        "b839d7e63145d126f610094ae1998e7fa68df706"
    )
    assert entry_gate["review_packets"]["source_packet_tree_git_sha1"] == (
        "31034bd42054e28cbaa0ae7b1d1eb033cf243cd4"
    )
    assert entry_gate["review_packets"]["unchanged"] is True

    assert balanced_orchestrator._CANONICAL_SOURCE_FILES["legacy_scorer_engine"] == (
        "zscope/benchmarking/protocol.py"
    )
    assert balanced_orchestrator._CANONICAL_SOURCE_FILES["legacy_scorer_wrapper"] == (
        "zscope/benchmarking/runner.py"
    )
    # runner.py also owns producer telemetry and is modified by P6.  Its
    # legacy score envelope remains byte-identical to the attested baseline.
    assert (
        _function_source_sha256(REPO_ROOT / "zscope/benchmarking/runner.py", "score_artifact")
        == "bbabbc309438b2fa33451f12c6e199ca43bf0466bbb178faa30cfc25ae80871d"
    )


def test_legacy_launcher_loads_frozen_engine_before_modified_wrapper(tmp_path: Path) -> None:
    launcher = tmp_path / "launcher.py"
    engine = tmp_path / "protocol.py"
    wrapper = tmp_path / "runner.py"
    entry = tmp_path / "benchmark.py"
    result = tmp_path / "result.txt"
    launcher.write_text(balanced_orchestrator._LEGACY_SCORER_LAUNCHER, encoding="utf-8")
    engine.write_text("SCORER_ENGINE = 'frozen-protocol'\n", encoding="utf-8")
    wrapper.write_text(
        "from zscope.benchmarking.protocol import SCORER_ENGINE\n"
        "WRAPPER_RESULT = SCORER_ENGINE + ':producer-wrapper'\n",
        encoding="utf-8",
    )
    entry.write_text(
        "import pathlib, sys\n"
        "from zscope.benchmarking.runner import WRAPPER_RESULT\n"
        "pathlib.Path(sys.argv[1]).write_text(WRAPPER_RESULT, encoding='utf-8')\n",
        encoding="utf-8",
    )

    subprocess.run(
        [sys.executable, str(launcher), str(engine), str(wrapper), str(entry), str(result)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.read_text(encoding="utf-8") == "frozen-protocol:producer-wrapper"


def _conservation(calls: int = 8) -> dict[str, Any]:
    return {
        "physical_call_count": calls,
        "provider_reported_call_count": calls,
        "estimated_call_count": 0,
        "provider_usage_coverage": 1.0,
        "requested_model": "deepseek-v4-flash",
        "requested_model_coverage": 1.0,
        "response_model": "deepseek-v4-flash-ga-260731",
        "response_model_coverage": 1.0,
        "queue_empty": True,
        "dimensions": {
            name: {"numerator": calls, "denominator": calls, "conserved": True}
            for name in ("token", "tool", "trace", "finding", "terminal")
        },
    }


def _confirmed_v4_issue() -> dict[str, Any]:
    return confirmed_product_v4_issue(
        project_id="p6-balanced-orchestrator-test",
        revision="rev-p6-balanced-orchestrator-test",
    )


def _producer_tree(
    tmp_path: Path,
    *,
    confirmed_terminal: bool = False,
    post_terminal_call: bool = False,
    benign_detail: str | None = None,
) -> tuple[Path, Path, Path, Path]:
    identity = _identity()
    report_path = tmp_path / "producer/run-01/report.json"
    metrics_path = tmp_path / "producer/run-01/producer-metrics.json"
    usage_path = tmp_path / "producer/run-01/llm_usage_events.jsonl"
    trace_path = tmp_path / "producer/run-01/decision_trace_manifest.json"
    event = LLMUsageEvent(
        sequence=1,
        reservation_id="call-1",
        outcome="success",
        prompt_tokens=10,
        completion_tokens=5,
        total_tokens=15,
        reserved_total_tokens=20,
        provider_reported=True,
        conservative_charge=False,
        budget_violation=False,
        attribution=LLMUsageAttribution(
            stage="validation",
            agent="validator_agent",
            candidate_uid="candidate-1",
            validation_cluster_uid="",
            llm_ref="validation",
            call_kind="initial_decision",
        ),
        budget_stage="validation",
        model="deepseek-v4-flash",
        finish_reason="stop",
        cached_prompt_tokens=0,
        reasoning_tokens=0,
    ).to_dict()
    event["provider_response_model"] = "deepseek-v4-flash-ga-260731"
    events = [event]
    if post_terminal_call:
        second = LLMUsageEvent(
            sequence=2,
            reservation_id="call-2",
            outcome="success",
            prompt_tokens=3,
            completion_tokens=2,
            total_tokens=5,
            reserved_total_tokens=8,
            provider_reported=True,
            conservative_charge=False,
            budget_violation=False,
            attribution=LLMUsageAttribution(
                stage="validation",
                agent="validator_agent",
                candidate_uid="candidate-1",
                validation_cluster_uid="VAL_confirmed_trace",
                llm_ref="validation",
                call_kind="initial_decision",
            ),
            budget_stage="validation",
            model="deepseek-v4-flash",
            finish_reason="stop",
            cached_prompt_tokens=0,
            reasoning_tokens=0,
        ).to_dict()
        second["provider_response_model"] = "deepseek-v4-flash-ga-260731"
        events.append(second)
    usage_path.parent.mkdir(parents=True, exist_ok=True)
    usage_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in events),
        encoding="utf-8",
    )
    trace_store = DecisionTraceStore(trace_path.parent, scan_uid="P6_BALANCED_TEST")
    trace_store.record_coverage_event(
        "AUDIT_BALANCED_TEST",
        reason_code="AUDIT_UNIT_CREATED",
        producer="test",
        call_ids=("call-1",),
        token_delta=15,
    )
    confirmed_issue: dict[str, Any] | None = None
    if confirmed_terminal:
        confirmed_issue = _confirmed_v4_issue()
        confirmed_cluster_uid = str(confirmed_issue["validation_cluster_uid"])
        trace_store.record_terminal_transition(
            confirmed_issue,
            level="V1",
            authority=confirmed_issue["terminal_authority_decision"],
        )
        trace_store.finalize_issue(
            confirmed_issue, view_memberships=("default", "with_needs_review")
        )
        if post_terminal_call:
            trace_store.append_event(
                confirmed_cluster_uid,
                stage="provider",
                actor="test_provider",
                reason_code="LLM_USAGE_BOUND",
                call_ids=("call-2",),
                token_delta=0,
            )
            confirmed_issue["decision_trace_sha256"] = trace_store.trace(confirmed_cluster_uid)[
                "document_sha256"
            ]
    trace_store.snapshot()
    trace_manifest = json.loads(trace_path.read_text(encoding="utf-8"))
    trace_manifest["llm_usage_events"].update(
        {
            "available": True,
            "path": usage_path.name,
            "file_sha256": _sha(usage_path),
            "event_count": len(events),
        }
    )
    trace_manifest_unsigned = dict(trace_manifest)
    trace_manifest_unsigned.pop("manifest_sha256", None)
    trace_manifest["manifest_sha256"] = canonical_sha256(trace_manifest_unsigned)
    _dump(trace_path, trace_manifest)
    trace_artifact = {
        "schema_version": "zscope.decision-trace-artifact.v1",
        "path": trace_path.name,
        "sha256": _sha(trace_path),
        "manifest_sha256": trace_manifest["manifest_sha256"],
        "trace_count": trace_manifest["trace_count"],
        "coverage_trace_count": trace_manifest["coverage_trace_count"],
        "evidence_object_count": trace_manifest["evidence_object_count"],
        "model_event_count": trace_manifest["model_event_count"],
        "complete": True,
        "answer_free": True,
    }
    usage_artifact = {
        "schema_version": "zscope.llm-usage-events-artifact.v1",
        "path": usage_path.name,
        "sha256": _sha(usage_path),
        "call_count": len(events),
        "answer_free": True,
    }
    scan_usage = {
        "active_reservation_count": 0,
        "rejected_before_model_count": 0,
        "rejected_before_model_reasons": {},
        "rejected_before_model_attempts": [],
        "p6_balanced_admission": {
            "enabled": True,
            "soft_token_watermark": 10_500_000,
            "maximum_tokens": 11_999_999,
            "request_count": 4 if post_terminal_call else 3,
            "admitted_request_count": 2 if post_terminal_call else 1,
            "denied_request_count": 2,
            "denied_reasons": {
                "p6_token_soft_watermark": 2,
            },
            "request_conservation_passed": True,
        },
    }
    report = {
        "answer_material_present": False,
        "issues": [confirmed_issue] if confirmed_issue is not None else [],
        "issues_with_needs_review": [],
        "candidate_terminal_states": ([confirmed_issue] if confirmed_issue is not None else []),
        "report_views": {
            "default": {"issues": [confirmed_issue] if confirmed_issue is not None else []},
            "with_needs_review": {
                "issues": [confirmed_issue] if confirmed_issue is not None else []
            },
        },
        "metadata": {
            "audit_observation_count": 0,
            "audit_observations": [],
            **({"benign_detail": benign_detail} if benign_detail is not None else {}),
            "llm_usage": {"scan_token_usage": copy.deepcopy(scan_usage)},
            "llm_usage_events_artifact": dict(usage_artifact),
        },
        "summary": {
            "validator_protocol_exhausted_count": 0,
            "llm_usage": {"scan_token_usage": copy.deepcopy(scan_usage)},
        },
        "run_manifest": {
            "validation_queue_drained": True,
            "finding_root_count": 0,
            "llm_usage": {"scan_token_usage": copy.deepcopy(scan_usage)},
            "llm_usage_events_artifact": dict(usage_artifact),
            "decision_trace_artifact": trace_artifact,
        },
    }
    _dump(report_path, report)
    contract = require_p6_provider_contract(CONFIG)
    metrics = build_p6_answer_free_producer_metrics(
        report_path=report_path,
        run_dir=report_path.parent,
        provider_contract=contract,
    )
    assert metrics["provider_usage_coverage"] == 1.0
    assert metrics["estimated_provider_call_count"] == 0
    assert metrics["p6_admission_conservation"] == {
        "enabled": True,
        "request_count": 4 if post_terminal_call else 3,
        "admitted_request_count": 2 if post_terminal_call else 1,
        "denied_request_count": 2,
        "denied_reasons": {
            "p6_token_soft_watermark": 2,
        },
        "request_conservation_passed": True,
        "zero_call_denial_conservation_passed": True,
    }
    _dump(metrics_path, metrics)
    image_digest = "sha256:" + "7" * 64
    image_ref = "localhost/zscope-p6@" + image_digest
    image_id = "sha256:" + "8" * 64
    runtime_sha = "5" * 64
    cache_sha = "6" * 64
    phase_execution = {
        "phase": "scan",
        "p6_workflow_run_id": identity.workflow_run_id,
        "p6_workflow_run_attempt": identity.workflow_run_attempt,
        "p6_attempt_id": identity.attempt_id,
    }
    aggregate = {
        "language": "cpp",
        "mode": "pilot",
        "scan_depth": "balanced",
        "formal_benchmark": False,
        "release_eligible": False,
        "answer_free_producer": True,
        "cold_runs": 1,
        "all_completed": True,
        "passed": True,
        "git_sha": identity.candidate_git_sha,
        "git_tree": identity.candidate_git_tree,
        "runs": [
            {
                "completed": True,
                "formal_benchmark": False,
                "release_eligible": False,
                "answer_free_producer": True,
                "queue_empty": True,
                "gate_failures": [],
                "input_manifest_sha256": "b" * 64,
                "metrics": metrics,
                "provenance": {
                    "runtime_spec_sha256": "3" * 64,
                    "candidate_commit": identity.candidate_git_sha,
                    "provider_runtime": contract.as_dict(),
                },
                "artifact_hashes": {
                    "files": {
                        "report.json": _sha(report_path),
                        "producer-metrics.json": _sha(metrics_path),
                        "llm_usage_events.jsonl": _sha(usage_path),
                        "decision_trace_manifest.json": _sha(trace_path),
                    }
                },
                "cold_cache": {
                    "identity_sha256": cache_sha,
                    "empty_at_start": True,
                    "reused": False,
                },
                "isolation": {
                    "image": image_ref,
                    "image_id": image_id,
                    "runtime_source_sha256": runtime_sha,
                    "provider_identity_sha256": contract.identity_sha256,
                    "producer_source_sandbox": {
                        "schema_version": "zscope.p6-producer-source-sandbox.v2",
                        "runtime_source_sha256": runtime_sha,
                        "scan_input_manifest_sha256": "b" * 64,
                        "host_process_sandbox": {
                            "schema_version": "zscope.p6-host-producer-sandbox.v1",
                            "candidate_commit": identity.candidate_git_sha,
                            "candidate_git_tree": identity.candidate_git_tree,
                            "file_count": 100,
                            "source_manifest_sha256": "c" * 64,
                            "receipt_sha256": "d" * 64,
                            "scorer_present": False,
                            "truth_present": False,
                            "expected_answer_present": False,
                            "review_decision_present": False,
                            "postscore_evidence_present": False,
                        },
                        "scorer_present": False,
                        "truth_present": False,
                        "expected_present": False,
                        "review_decision_present": False,
                        "postscore_evidence_present": False,
                    },
                    "phase_executions": [phase_execution],
                },
            }
        ],
    }
    aggregate_path = tmp_path / "producer/aggregate.json"
    _dump(aggregate_path, aggregate)
    projection = {
        "schema_version": "zscope.p6-depth-projection.v1",
        "scan_depth": "balanced",
        "control_plane_commit": identity.control_plane_commit,
        "producer_attempt_id": identity.attempt_id,
        "artifact_sha256": canonical_sha256(aggregate),
        "git_sha": identity.candidate_git_sha,
        "git_tree": identity.candidate_git_tree,
        "provider_identity_sha256": contract.identity_sha256,
        "call_count": metrics["usage_accounting"]["call_count"],
        "provider_usage_coverage": metrics["provider_usage_coverage"],
        "provider_response_model_coverage": metrics["provider_response_model_coverage"],
        "estimated_provider_call_count": metrics["estimated_provider_call_count"],
        "queue_empty": metrics["queue_empty"],
        "token_conservation_passed": metrics["token_conservation_passed"],
        "telemetry_complete_rate": metrics["telemetry_complete_rate"],
        "eligible_count": 0,
        "entered_count": 0,
        "usage_conservation": metrics["p6_conservation"],
        "toolchain_evidence_sha256": "4" * 64,
        "oci_image_ref": image_ref,
        "oci_image_digest": image_digest,
        "oci_image_id": image_id,
        "runtime_source_sha256": runtime_sha,
        "toolchain_oci_execution_sha256": "9" * 64,
        "oci_execution_sha256": "a" * 64,
        "cache_identity_sha256": cache_sha,
        "cache_empty_at_start": True,
        "cache_reused": False,
        "formal_benchmark": False,
        "release_eligible": False,
    }
    projection_path = tmp_path / "producer-projection.json"
    _dump(projection_path, projection)
    return aggregate_path, report_path, metrics_path, projection_path


def _freeze(tmp_path: Path) -> tuple[Path, Path]:
    aggregate, report, metrics, projection = _producer_tree(tmp_path)
    output = tmp_path / "frozen"
    freeze_balanced_scan(
        aggregate_path=aggregate,
        report_path=report,
        producer_metrics_path=metrics,
        projection_path=projection,
        provider_config_path=CONFIG,
        identity=_identity(),
        output=output,
    )
    return output, projection


@pytest.mark.parametrize("category_index", range(7))
def test_freeze_rejects_each_actual_canary_from_a_benign_report_field(
    tmp_path: Path, category_index: int
) -> None:
    from zscope.benchmarking.p6_protocol import derive_p6_artifact_canaries

    identity = _identity()
    canaries = derive_p6_artifact_canaries(
        workflow_run_id=identity.workflow_run_id,
        workflow_run_attempt=identity.workflow_run_attempt,
        candidate_git_sha=identity.candidate_git_sha,
    )
    aggregate, report, metrics, projection = _producer_tree(
        tmp_path,
        benign_detail=canaries[category_index].decode("utf-8"),
    )
    output = tmp_path / "frozen"

    with pytest.raises(P6BalancedOrchestratorError, match="protected canary"):
        freeze_balanced_scan(
            aggregate_path=aggregate,
            report_path=report,
            producer_metrics_path=metrics,
            projection_path=projection,
            provider_config_path=CONFIG,
            identity=identity,
            output=output,
            literal_canaries=canaries,
        )

    assert not output.exists()


def test_control_plane_materializer_uses_the_exact_committed_tree(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    environment = dict(os.environ)
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    for command in (
        ["git", "init", "-q"],
        ["git", "config", "user.name", "P6 Test"],
        ["git", "config", "user.email", "p6-test@example.invalid"],
    ):
        subprocess.run(command, cwd=repository, env=environment, check=True)
    committed = repository / "zscope/benchmarking/benchmark_v5.py"
    committed.parent.mkdir(parents=True)
    committed.write_text("COMMITTED = True\n", encoding="utf-8")
    dependency = repository / "zscope/benchmarking/p6_protocol.py"
    dependency.write_text("PROTOCOL = 'sealed'\n", encoding="utf-8")
    extra = repository / "complete-execution-closure.txt"
    extra.write_text("included\n", encoding="utf-8")
    subprocess.run(["git", "add", "--all"], cwd=repository, env=environment, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "sealed tree"],
        cwd=repository,
        env=environment,
        check=True,
    )
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"],
        cwd=repository,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    committed.write_text("LIVE_PATH_TAMPERED = True\n", encoding="utf-8")

    snapshot = _REAL_MATERIALIZE_CONTROL_PLANE_TREE(
        repository_root=repository,
        control_plane_commit=commit,
        destination=tmp_path / "snapshot",
    )
    try:
        assert snapshot.commit_sha == commit
        assert snapshot.tree_sha == tree
        assert (snapshot.root / "zscope/benchmarking/benchmark_v5.py").read_text("utf-8") == (
            "COMMITTED = True\n"
        )
        assert (snapshot.root / "zscope/benchmarking/p6_protocol.py").read_text("utf-8") == (
            "PROTOCOL = 'sealed'\n"
        )
        assert (snapshot.root / "complete-execution-closure.txt").read_text("utf-8") == (
            "included\n"
        )
    finally:
        balanced_orchestrator._remove_control_plane_tree(snapshot)


def test_truth_bytes_come_only_from_the_private_control_plane_tree(tmp_path: Path) -> None:
    live = tmp_path / "live"
    committed = tmp_path / "committed"
    expected_payloads: dict[str, bytes] = {}
    for name, relative in balanced_orchestrator._CANONICAL_TRUTH_FILES.items():
        live_path = live / relative
        committed_path = committed / relative
        live_path.parent.mkdir(parents=True, exist_ok=True)
        committed_path.parent.mkdir(parents=True, exist_ok=True)
        live_path.write_bytes(b'{"dirty_live_truth":true}\n')
        expected_payloads[name] = f'{{"committed":"{name}"}}\n'.encode()
        committed_path.write_bytes(expected_payloads[name])

    snapshots = balanced_orchestrator._canonical_truth_snapshots(
        repository_root=live,
        execution_root=committed,
        legacy_truth_path=live / balanced_orchestrator._CANONICAL_TRUTH_FILES["legacy_truth"],
        v16_truth_path=live / balanced_orchestrator._CANONICAL_TRUTH_FILES["v16_truth"],
    )

    assert {name: snapshot.payload for name, snapshot in snapshots.items()} == expected_payloads


def test_live_truth_symlink_cannot_supply_scoring_bytes(tmp_path: Path) -> None:
    live = tmp_path / "live"
    committed = tmp_path / "committed"
    attacker = tmp_path / "attacker.json"
    attacker.write_text('{"attacker":true}\n', encoding="utf-8")
    for name, relative in balanced_orchestrator._CANONICAL_TRUTH_FILES.items():
        live_path = live / relative
        committed_path = committed / relative
        live_path.parent.mkdir(parents=True, exist_ok=True)
        committed_path.parent.mkdir(parents=True, exist_ok=True)
        committed_path.write_text(f'{{"committed":"{name}"}}\n', encoding="utf-8")
        try:
            live_path.symlink_to(attacker)
        except OSError:
            pytest.skip("symlink creation is unavailable")

    snapshots = balanced_orchestrator._canonical_truth_snapshots(
        repository_root=live,
        execution_root=committed,
        legacy_truth_path=live / balanced_orchestrator._CANONICAL_TRUTH_FILES["legacy_truth"],
        v16_truth_path=live / balanced_orchestrator._CANONICAL_TRUTH_FILES["v16_truth"],
    )

    assert all(b"attacker" not in snapshot.payload for snapshot in snapshots.values())


def test_scorers_keep_using_snapshot_after_live_dependency_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    frozen, projection = _freeze(tmp_path)
    live_root = tmp_path / "live-control-plane"
    required = {
        *balanced_orchestrator._CANONICAL_SOURCE_FILES.values(),
        "zscope/benchmarking/benchmark_v5.py",
        "zscope/benchmarking/p6_protocol.py",
    }
    for relative in sorted(required):
        target = live_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"# original {relative}\n", encoding="utf-8")
    (live_root / balanced_orchestrator._CANONICAL_SOURCE_FILES["provider_config"]).write_bytes(
        CONFIG.read_bytes()
    )
    legacy_truth = live_root / "test/range/benchmark/ground_truth.json"
    v16_truth = live_root / "test/range/benchmark/v16/ground_truth.json"
    legacy_truth.parent.mkdir(parents=True, exist_ok=True)
    v16_truth.parent.mkdir(parents=True, exist_ok=True)
    legacy_truth.write_bytes(LEGACY_TRUTH.read_bytes())
    v16_truth.write_bytes(V16_TRUTH.read_bytes())
    dependencies = (
        "zscope/benchmarking/benchmark_v5.py",
        "zscope/benchmarking/p6_protocol.py",
    )

    def materialize_then_replace_live(
        *, repository_root: Path, control_plane_commit: str, destination: Path
    ) -> Any:
        shutil.copytree(repository_root, destination)
        for relative in dependencies:
            (Path(repository_root) / relative).write_text(
                f"# tampered {relative}\n", encoding="utf-8"
            )
        return balanced_orchestrator._ControlPlaneTreeSnapshot(
            root=destination,
            commit_sha=control_plane_commit,
            tree_sha="e" * 40,
            manifest_sha256="f" * 64,
        )

    monkeypatch.setattr(
        balanced_orchestrator,
        "_materialize_control_plane_tree",
        materialize_then_replace_live,
    )

    class SnapshotCheckingRunner(ScoreRunner):
        def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            execution_root = Path(str(kwargs["env"]["PYTHONPATH"]))
            assert execution_root != live_root
            assert Path(str(kwargs["cwd"])) == execution_root
            for relative in dependencies:
                assert (execution_root / relative).read_text("utf-8") == (
                    f"# original {relative}\n"
                )
                assert (live_root / relative).read_text("utf-8") == (f"# tampered {relative}\n")
            return super().__call__(argv, **kwargs)

    runner = SnapshotCheckingRunner()
    score_frozen_balanced_scan(
        frozen_root=frozen,
        projection_path=projection,
        legacy_truth_path=legacy_truth,
        v16_truth_path=v16_truth,
        identity=_identity(),
        output=tmp_path / "quality",
        repository_root=live_root,
        process_runner=runner,
        python_executable="python",
    )
    assert len(runner.calls) == 3


def _view(truth_count: int, tp: int, fp: int, prefix: str) -> dict[str, Any]:
    return {
        "ground_truth_count": truth_count,
        "true_positives": tp,
        "false_negatives": truth_count - tp,
        "false_positives_raw": fp,
        "matched": [f"{prefix}-{index}" for index in range(tp)],
    }


def _v16_partition_ids() -> tuple[list[str], list[str]]:
    truth = json.loads(V16_TRUTH.read_text(encoding="utf-8"))
    product: list[str] = []
    design: list[str] = []
    for row in truth["vulnerabilities"]:
        kind = row["verification_contract"]["kind"]
        if kind in {"concrete_trigger", "public_api_contract"}:
            product.append(row["id"])
        elif kind == "pattern_model":
            design.append(row["id"])
    assert len(product) == 61
    assert len(design) == 75
    return product, design


class ScoreRunner:
    def __init__(self, *, fail_quality: bool = False) -> None:
        self.calls: list[tuple[list[str], dict[str, str]]] = []
        self.fail_quality = fail_quality

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        command = [str(value) for value in argv]
        environment = dict(kwargs.get("env") or {})
        self.calls.append((command, environment))
        output = Path(command[command.index("--output") + 1])
        if "legacy-scorer-launcher.py" in " ".join(command):
            legacy = {
                "report_views": {
                    "default": _view(
                        136,
                        81 if self.fail_quality else 96,
                        0 if self.fail_quality else 10,
                        "legacy",
                    ),
                    "with_needs_review": _view(136, 125, 100, "legacy"),
                }
            }
            legacy["report_views"]["with_needs_review"]["matched"] = [
                *legacy["report_views"]["default"]["matched"],
                *[
                    f"legacy-extra-{index}"
                    for index in range(125 - len(legacy["report_views"]["default"]["matched"]))
                ],
            ]
            _dump(output, legacy)
            return subprocess.CompletedProcess(command, 0)
        if Path(command[1]).name == "v16_scorer.py":
            product_ids, design_ids = _v16_partition_ids()
            v16 = {
                "product": {
                    "default": {
                        **_view(61, 43, 4, "v16"),
                        "matched": product_ids[:43],
                    },
                    "with_needs_review": {
                        **_view(61, 61, 40, "v16"),
                        "matched": product_ids,
                    },
                },
                "design_risk": {
                    "default": {
                        "truth_count": 75,
                        "true_positives": 4,
                        "matched": design_ids[:4],
                    },
                    "with_needs_review": {
                        "truth_count": 75,
                        "true_positives": 8,
                        "matched": design_ids[:8],
                    },
                },
            }
            _dump(output, v16)
            return subprocess.CompletedProcess(command, 0)
        if Path(command[1]).name == "quality_gate.py":
            from scripts.p6_balanced_quality_gate import main

            return subprocess.CompletedProcess(command, main(command[2:]))
        raise AssertionError(command)


def test_shared_freeze_then_dual_score_and_strict_gate_is_truth_isolated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    frozen, projection = _freeze(tmp_path)
    runner = ScoreRunner()
    monkeypatch.setenv("Z_SCOPE_API_KEY", "must-never-reach-a-scorer")
    monkeypatch.setenv("Z_SCOPE_LLM_BASE_URL", "https://wrong.example/v1")
    monkeypatch.setenv("GH_PAT", "must-never-reach-a-scorer-either")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "must-never-reach-a-scorer-either")
    monkeypatch.setenv("RANDOM_PRIVATE_CANARY", "must-never-reach-a-scorer-either")
    monkeypatch.setenv("PYTHONPATH", "must-never-reach-a-scorer-pythonpath")
    monkeypatch.setenv("LD_LIBRARY_PATH", "must-never-reach-a-scorer-loader")
    monkeypatch.setenv("DYLD_LIBRARY_PATH", "must-never-reach-a-scorer-loader")
    output = tmp_path / "quality"
    failure_aggregate = tmp_path / "failure-aggregate.json"

    gate = score_frozen_balanced_scan(
        frozen_root=frozen,
        projection_path=projection,
        legacy_truth_path=LEGACY_TRUTH,
        v16_truth_path=V16_TRUTH,
        identity=_identity(),
        output=output,
        failure_aggregate_path=failure_aggregate,
        repository_root=REPO_ROOT,
        process_runner=runner,
        python_executable="python",
    )

    assert gate["hard_gate_passed"] is True
    assert not failure_aggregate.exists()
    assert load_quality_gate(output / "p6-balanced-quality-gate.json") == gate
    assert validate_quality_gate_bundle(output) == gate
    assert {path.name for path in output.iterdir()} == {
        "bindings.json",
        "frozen-manifest.json",
        "frozen-report.json",
        "legacy-score.json",
        "p6-balanced-quality-gate.json",
        "producer-projection.json",
        "trace-sidecars.json",
        "llm_usage_events.jsonl",
        "usage-evidence.json",
        "v16-score.json",
        "v16-truth-partitions.json",
    }
    assert gate["artifacts"]["frozen_manifest"]["sha256"] == _sha(frozen / "manifest.json")
    assert gate["artifacts"]["report"]["sha256"] == _sha(frozen / "report.json")
    assert gate["artifacts"]["usage_evidence"]["sha256"] == _sha(frozen / "usage-evidence.json")
    frozen_usage = json.loads((frozen / "usage-evidence.json").read_text("utf-8"))
    frozen_manifest = json.loads((frozen / "manifest.json").read_text("utf-8"))
    assert frozen_usage["llm_usage_events_sha256"] == frozen_manifest["llm_usage_events_sha256"]
    assert (
        frozen_usage["llm_usage_events_call_count"]
        == frozen_manifest["llm_usage_events_call_count"]
    )
    admission = frozen_usage["score_fields"]["p6_admission_conservation"]
    assert admission["request_count"] == 3
    assert admission["admitted_request_count"] == 1
    assert admission["denied_request_count"] == 2
    assert admission["denied_reasons"] == {"p6_token_soft_watermark": 2}
    legacy_score = json.loads((output / "legacy-score.json").read_text("utf-8"))
    assert legacy_score["p6_admission_conservation"] == admission
    assert len(runner.calls) == 3
    legacy_env = runner.calls[0][1]
    private_legacy_truth = Path(legacy_env["Z_SCOPE_BENCHMARK_TRUTH"])
    assert private_legacy_truth.name == "legacy-truth.json"
    assert private_legacy_truth != LEGACY_TRUTH.resolve()
    assert ".scorer-input" in private_legacy_truth.parts
    v16_truth_argument = Path(runner.calls[1][0][runner.calls[1][0].index("--truth") + 1])
    assert v16_truth_argument.name == "v16-truth.json"
    assert v16_truth_argument != V16_TRUTH.resolve()
    assert ".scorer-input" in v16_truth_argument.parts
    legacy_report_argument = Path(runner.calls[0][0][runner.calls[0][0].index("--report") + 1])
    v16_report_argument = Path(runner.calls[1][0][runner.calls[1][0].index("--report") + 1])
    assert legacy_report_argument == v16_report_argument
    assert legacy_report_argument.name == "frozen-report.json"
    assert ".scorer-input" in legacy_report_argument.parts
    assert not private_legacy_truth.exists()
    assert not v16_truth_argument.exists()
    assert not legacy_report_argument.exists()
    assert "Z_SCOPE_BENCHMARK_TRUTH" not in runner.calls[1][1]
    assert all("Z_SCOPE_API_KEY" not in environment for _, environment in runner.calls)
    assert all("GH_PAT" not in environment for _, environment in runner.calls)
    assert all("AWS_ACCESS_KEY_ID" not in environment for _, environment in runner.calls)
    assert all("RANDOM_PRIVATE_CANARY" not in environment for _, environment in runner.calls)
    execution_roots = {Path(environment["PYTHONPATH"]) for _, environment in runner.calls}
    assert len(execution_roots) == 1
    assert REPO_ROOT.resolve() not in execution_roots
    assert all(root.name == "tree" for root in execution_roots)
    assert all(not root.exists() for root in execution_roots)
    assert all("LD_LIBRARY_PATH" not in environment for _, environment in runner.calls)
    assert all("DYLD_LIBRARY_PATH" not in environment for _, environment in runner.calls)
    assert all(
        "must-never-reach-a-scorer" not in json.dumps(environment)
        for _, environment in runner.calls
    )
    assert V16_TRUTH.as_posix() not in (frozen / "manifest.json").read_text("utf-8")

    tampered = json.loads((output / "legacy-score.json").read_text("utf-8"))
    tampered["report_views"]["with_needs_review"]["matched"][0] = "substituted"
    _dump(output / "legacy-score.json", tampered)
    with pytest.raises(P6BalancedQualityGateError, match="digest binding"):
        validate_quality_gate_bundle(output)


def test_failed_dual_score_preserves_only_answer_free_quality_aggregate(tmp_path: Path) -> None:
    frozen, projection = _freeze(tmp_path)
    runner = ScoreRunner(fail_quality=True)
    output = tmp_path / "quality"
    aggregate_path = tmp_path / "quality-failure-aggregate.json"

    with pytest.raises(P6BalancedOrchestratorError, match="balanced scorer failed"):
        score_frozen_balanced_scan(
            frozen_root=frozen,
            projection_path=projection,
            legacy_truth_path=LEGACY_TRUTH,
            v16_truth_path=V16_TRUTH,
            identity=_identity(),
            output=output,
            failure_aggregate_path=aggregate_path,
            repository_root=REPO_ROOT,
            process_runner=runner,
            python_executable="python",
        )

    assert not output.exists()
    aggregate = json.loads(aggregate_path.read_text("utf-8"))
    validate_quality_failure_aggregate(aggregate)
    assert aggregate["legacy_v15"]["default"]["true_positives"] == 81
    encoded = json.dumps(aggregate, sort_keys=True)
    assert "matched" not in encoded
    assert "legacy-" not in encoded
    assert "v16-" not in encoded


def _quality_bundle(tmp_path: Path) -> tuple[Path, ScoreRunner]:
    frozen, projection = _freeze(tmp_path)
    runner = ScoreRunner()
    quality = tmp_path / "quality"
    score_frozen_balanced_scan(
        frozen_root=frozen,
        projection_path=projection,
        legacy_truth_path=LEGACY_TRUTH,
        v16_truth_path=V16_TRUTH,
        identity=_identity(),
        output=quality,
        repository_root=REPO_ROOT,
        process_runner=runner,
        python_executable="python",
    )
    return quality, runner


def _complete_local_evidence(tmp_path: Path) -> tuple[Path, Path]:
    candidate, _ = _quality_bundle(tmp_path)
    evidence = tmp_path / "local-balanced-evidence"
    evidence.mkdir()
    receipt = evidence / "quality-revalidation-receipt.json"
    revalidate_balanced_quality_bundle(
        restored_bundle=candidate,
        legacy_truth_path=LEGACY_TRUTH,
        v16_truth_path=V16_TRUTH,
        identity=_identity(),
        output=evidence / "quality",
        receipt_path=receipt,
        repository_root=REPO_ROOT,
        process_runner=ScoreRunner(),
        python_executable="python",
        git_head_resolver=lambda _root: _identity().control_plane_commit,
    )
    return evidence, receipt


def test_local_evidence_requires_complete_bundle_not_standalone_gate(tmp_path: Path) -> None:
    quality, _ = _quality_bundle(tmp_path)
    standalone = tmp_path / "standalone-evidence"
    standalone.mkdir()
    shutil.copy2(quality / "p6-balanced-quality-gate.json", standalone / "quality-gate.json")

    with pytest.raises(P6BalancedOrchestratorError, match="members"):
        validate_complete_local_balanced_evidence(
            evidence_root=standalone,
            expected_receipt_sha256=_sha(standalone / "quality-gate.json"),
        )


def test_complete_local_evidence_is_canonically_rescored_and_byte_compared(
    tmp_path: Path,
) -> None:
    evidence, receipt_path = _complete_local_evidence(tmp_path)
    expected_digest = _sha(receipt_path)

    receipt, gate, identity = validate_complete_local_balanced_evidence(
        evidence_root=evidence,
        expected_receipt_sha256=expected_digest,
    )
    runner = ScoreRunner()
    replayed_receipt, replayed_gate, replayed_identity = (
        revalidate_complete_local_balanced_evidence(
            evidence_root=evidence,
            expected_receipt_sha256=expected_digest,
            repository_root=REPO_ROOT,
            process_runner=runner,
            python_executable="python",
        )
    )

    assert identity == replayed_identity == _identity()
    assert receipt == replayed_receipt
    assert gate == replayed_gate
    assert gate["hard_gate_passed"] is True
    assert len(runner.calls) == 3


def test_committed_local_evidence_accepts_only_complete_normal_merge_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    def git(*arguments: str) -> str:
        return subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout.strip()

    git("init", "--quiet", "--initial-branch=main")
    git("config", "user.name", "P6 Test")
    git("config", "user.email", "p6@example.invalid")
    (repository / "README.md").write_text("base\n", encoding="utf-8")
    git("add", "README.md")
    git("commit", "--quiet", "-m", "base")
    base = git("rev-parse", "HEAD")
    git("switch", "--quiet", "-c", "evidence")
    (repository / "zscope").mkdir()
    (repository / "zscope/__init__.py").write_text("\n", encoding="utf-8")
    git("add", "zscope/__init__.py")
    git("commit", "--quiet", "-m", "candidate")
    tested = git("rev-parse", "HEAD")
    tested_tree = git("rev-parse", "HEAD^{tree}")
    evidence_root = repository / balanced_orchestrator.LOCAL_BALANCED_EVIDENCE_ROOT
    quality = evidence_root / "quality"
    quality.mkdir(parents=True)
    for filename in balanced_orchestrator._QUALITY_BUNDLE_FILES.values():
        (quality / filename).write_text("{}\n", encoding="utf-8")
    (evidence_root / "quality-revalidation-receipt.json").write_text("{}\n", encoding="utf-8")
    git("add", balanced_orchestrator.LOCAL_BALANCED_EVIDENCE_ROOT)
    git("commit", "--quiet", "-m", "local evidence")
    evidence_commit = git("rev-parse", "HEAD")
    git("switch", "--quiet", "main")
    assert git("rev-parse", "HEAD") == base
    git("merge", "--quiet", "--no-ff", "evidence", "-m", "merge evidence")
    hosted = git("rev-parse", "HEAD")

    identity = BalancedRunIdentity(
        workflow_run_id="33260000009",
        workflow_run_attempt=1,
        attempt_id="p6-33260000009-1",
        control_plane_commit=tested,
        candidate_git_sha=tested,
        candidate_git_tree=tested_tree,
    )

    def fake_revalidate(**kwargs: Any) -> tuple[dict[str, Any], dict[str, Any], Any]:
        staged = Path(kwargs["evidence_root"])
        assert {path.name for path in (staged / "quality").iterdir()} == set(
            balanced_orchestrator._QUALITY_BUNDLE_FILES.values()
        )
        assert (staged / "quality-revalidation-receipt.json").is_file()
        return (
            {"content_sha256": "d" * 64},
            {
                "content_sha256": "e" * 64,
                "bindings": {
                    "git_commit": tested,
                    "git_tree": tested_tree,
                    "candidate_sha256": hashlib.sha256(tested.encode("ascii")).hexdigest(),
                    "provider_identity_sha256": "p" * 64,
                    "runtime_sha256": "r" * 64,
                    "config_sha256": "q" * 64,
                },
            },
            identity,
        )

    def fake_materialize(**kwargs: Any) -> Any:
        destination = Path(kwargs["destination"])
        (destination / "zscope").mkdir(parents=True)
        (destination / "zscope/__init__.py").write_text("\n", encoding="utf-8")
        (destination / "test/range").mkdir(parents=True)
        (destination / "test/range/zscope.benchmark.yaml").write_text(
            "llms: {}\n", encoding="utf-8"
        )
        return balanced_orchestrator._ControlPlaneTreeSnapshot(
            root=destination,
            commit_sha=hosted,
            tree_sha=git("rev-parse", f"{hosted}^{{tree}}"),
            manifest_sha256="f" * 64,
        )

    def fake_prepare(destination: Path, **_kwargs: Any) -> str:
        destination.mkdir(parents=True)
        (destination / "__init__.py").write_text("\n", encoding="utf-8")
        return "r" * 64

    monkeypatch.setattr(
        balanced_orchestrator,
        "_resolve_repository_head",
        lambda _root, process_runner: hosted,
    )
    monkeypatch.setattr(
        balanced_orchestrator,
        "revalidate_complete_local_balanced_evidence",
        fake_revalidate,
    )
    monkeypatch.setattr(balanced_orchestrator, "_materialize_control_plane_tree", fake_materialize)
    monkeypatch.setattr(balanced_orchestrator, "_remove_control_plane_tree", lambda _value: None)
    monkeypatch.setattr(balanced_orchestrator, "prepare_p6_runtime_source", fake_prepare)
    monkeypatch.setattr(
        balanced_orchestrator,
        "require_p6_provider_contract",
        lambda _path: SimpleNamespace(identity_sha256="p" * 64, config_sha256="q" * 64),
    )

    result = verify_committed_local_balanced_evidence(
        repository_root=repository,
        hosted_control_plane_commit=hosted,
        evidence_commit=evidence_commit,
        expected_receipt_sha256="c" * 64,
    )

    assert result["tested_commit"] == tested
    assert result["canonical_revalidation_passed"] is True
    assert result["complete_bundle_present"] is True


def test_authoritative_revalidation_rescores_and_reproduces_every_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    restored, _ = _quality_bundle(tmp_path)
    runner = ScoreRunner()
    for name, value in {
        "Z_SCOPE_API_KEY": "secret-canary",
        "GH_PAT": "secret-canary",
        "AWS_SECRET_ACCESS_KEY": "secret-canary",
        "PYTHONPATH": "untrusted-pythonpath",
        "LD_LIBRARY_PATH": "untrusted-loader",
        "DYLD_LIBRARY_PATH": "untrusted-loader",
        "RANDOM_PRIVATE_CANARY": "secret-canary",
    }.items():
        monkeypatch.setenv(name, value)
    output = tmp_path / "revalidated"
    receipt_path = tmp_path / "receipt.json"

    receipt = revalidate_balanced_quality_bundle(
        restored_bundle=restored,
        legacy_truth_path=LEGACY_TRUTH,
        v16_truth_path=V16_TRUTH,
        identity=_identity(),
        output=output,
        receipt_path=receipt_path,
        repository_root=REPO_ROOT,
        process_runner=runner,
        python_executable="python",
        git_head_resolver=lambda _root: _identity().control_plane_commit,
    )

    validate_quality_revalidation_receipt(receipt, identity=_identity())
    assert json.loads(receipt_path.read_text("utf-8")) == receipt
    assert {path.name for path in output.iterdir()} == {path.name for path in restored.iterdir()}
    assert all(
        (output / path.name).read_bytes() == path.read_bytes() for path in restored.iterdir()
    )
    assert receipt["byte_exact"] is True
    assert receipt["input_bundle_sha256s"] == receipt["output_bundle_sha256s"]
    execution_roots = {Path(environment["PYTHONPATH"]) for _, environment in runner.calls}
    assert len(execution_roots) == 1
    assert REPO_ROOT.resolve() not in execution_roots
    assert all(root.name == "control-plane" for root in execution_roots)
    assert all(not root.exists() for root in execution_roots)
    assert all("LD_LIBRARY_PATH" not in environment for _, environment in runner.calls)
    assert all("DYLD_LIBRARY_PATH" not in environment for _, environment in runner.calls)
    assert all("secret-canary" not in environment.values() for _, environment in runner.calls)


def test_quality_revalidation_receipt_schema_is_closed_and_validator_rejects_reseal(
    tmp_path: Path,
) -> None:
    schema = json.loads(
        (REPO_ROOT / "zscope/benchmarking/p6_quality_revalidation_receipt.schema.json").read_text(
            "utf-8"
        )
    )
    open_objects: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object" and value.get("additionalProperties") is not False:
                open_objects.append(path)
            for name, child in value.items():
                visit(child, f"{path}.{name}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(schema, "$")
    assert open_objects == []

    restored, _ = _quality_bundle(tmp_path)
    receipt = revalidate_balanced_quality_bundle(
        restored_bundle=restored,
        legacy_truth_path=LEGACY_TRUTH,
        v16_truth_path=V16_TRUTH,
        identity=_identity(),
        output=tmp_path / "revalidated",
        receipt_path=tmp_path / "receipt.json",
        repository_root=REPO_ROOT,
        process_runner=ScoreRunner(),
        python_executable="python",
        git_head_resolver=lambda _root: _identity().control_plane_commit,
    )
    forged = copy.deepcopy(receipt)
    forged["unexpected"] = True
    forged.pop("content_sha256")
    forged["content_sha256"] = canonical_sha256(forged)
    with pytest.raises(P6BalancedOrchestratorError, match="receipt fields"):
        validate_quality_revalidation_receipt(forged, identity=_identity())


def test_revalidate_cli_requires_external_identity_and_receipt_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_revalidate(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {}

    monkeypatch.setattr(orchestrator_cli, "revalidate_balanced_quality_bundle", fake_revalidate)
    identity = _identity()
    result = orchestrator_cli.main(
        [
            "revalidate",
            "--workflow-run-id",
            identity.workflow_run_id,
            "--workflow-run-attempt",
            str(identity.workflow_run_attempt),
            "--attempt-id",
            identity.attempt_id,
            "--control-plane-commit",
            identity.control_plane_commit,
            "--candidate-git-sha",
            identity.candidate_git_sha,
            "--candidate-git-tree",
            identity.candidate_git_tree,
            "--restored-bundle",
            str(tmp_path / "restored"),
            "--legacy-truth",
            str(LEGACY_TRUTH),
            "--v16-truth",
            str(V16_TRUTH),
            "--repository-root",
            str(REPO_ROOT),
            "--output",
            str(tmp_path / "output"),
            "--receipt",
            str(tmp_path / "receipt.json"),
        ]
    )
    assert result == 0
    assert captured["identity"] == identity
    assert captured["restored_bundle"] == tmp_path / "restored"
    assert captured["receipt_path"] == tmp_path / "receipt.json"


def test_verify_local_evidence_cli_requires_complete_receipt_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_verify(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {}

    monkeypatch.setattr(
        orchestrator_cli,
        "verify_committed_local_balanced_evidence",
        fake_verify,
    )
    result = orchestrator_cli.main(
        [
            "verify-local-evidence",
            "--repository-root",
            str(tmp_path),
            "--hosted-control-plane-commit",
            "a" * 40,
            "--evidence-commit",
            "b" * 40,
            "--receipt-sha256",
            "c" * 64,
        ]
    )

    assert result == 0
    assert captured == {
        "repository_root": tmp_path,
        "hosted_control_plane_commit": "a" * 40,
        "evidence_commit": "b" * 40,
        "expected_receipt_sha256": "c" * 64,
    }


@pytest.mark.parametrize("mutation", ("missing_usage", "changed_usage", "extra", "symlink"))
def test_authoritative_revalidation_rejects_non_exact_or_tampered_bundle(
    tmp_path: Path, mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    restored, _ = _quality_bundle(tmp_path)
    if mutation == "missing_usage":
        (restored / "usage-evidence.json").unlink()
    elif mutation == "changed_usage":
        usage = json.loads((restored / "usage-evidence.json").read_text("utf-8"))
        usage["attempt_id"] = "p6-tampered-attempt"
        _dump(restored / "usage-evidence.json", usage)
    elif mutation == "extra":
        (restored / "unexpected.json").write_text("{}\n", encoding="utf-8")
    else:
        original_is_symlink = Path.is_symlink
        monkeypatch.setattr(
            Path,
            "is_symlink",
            lambda path: path.name == "usage-evidence.json" or original_is_symlink(path),
        )
    runner = ScoreRunner()

    with pytest.raises((P6BalancedOrchestratorError, P6BalancedQualityGateError)):
        revalidate_balanced_quality_bundle(
            restored_bundle=restored,
            legacy_truth_path=LEGACY_TRUTH,
            v16_truth_path=V16_TRUTH,
            identity=_identity(),
            output=tmp_path / "revalidated",
            receipt_path=tmp_path / "receipt.json",
            repository_root=REPO_ROOT,
            process_runner=runner,
            python_executable="python",
            git_head_resolver=lambda _root: _identity().control_plane_commit,
        )
    assert runner.calls == []


def test_authoritative_revalidation_rejects_non_source_head_before_scoring(
    tmp_path: Path,
) -> None:
    restored, _ = _quality_bundle(tmp_path)
    runner = ScoreRunner()
    with pytest.raises(P6BalancedOrchestratorError, match="HEAD"):
        revalidate_balanced_quality_bundle(
            restored_bundle=restored,
            legacy_truth_path=LEGACY_TRUTH,
            v16_truth_path=V16_TRUTH,
            identity=_identity(),
            output=tmp_path / "revalidated",
            receipt_path=tmp_path / "receipt.json",
            repository_root=REPO_ROOT,
            process_runner=runner,
            git_head_resolver=lambda _root: "f" * 40,
        )
    assert runner.calls == []


def _rebuild_bundle_gate(root: Path) -> None:
    artifact_names = {
        "bindings": "bindings.json",
        "frozen_manifest": "frozen-manifest.json",
        "legacy_score": "legacy-score.json",
        "producer_projection": "producer-projection.json",
        "report": "frozen-report.json",
        "trace_sidecars": "trace-sidecars.json",
        "usage_events": "llm_usage_events.jsonl",
        "usage_evidence": "usage-evidence.json",
        "v16_score": "v16-score.json",
        "v16_truth_partitions": "v16-truth-partitions.json",
    }
    gate = build_quality_gate(
        report=json.loads((root / "frozen-report.json").read_text("utf-8")),
        legacy_score=json.loads((root / "legacy-score.json").read_text("utf-8")),
        v16_score=json.loads((root / "v16-score.json").read_text("utf-8")),
        v16_truth_partitions=json.loads(
            (root / "v16-truth-partitions.json").read_text("utf-8")
        ),
        producer_projection=json.loads((root / "producer-projection.json").read_text("utf-8")),
        bindings=json.loads((root / "bindings.json").read_text("utf-8")),
        frozen_manifest=json.loads((root / "frozen-manifest.json").read_text("utf-8")),
        usage_evidence=json.loads((root / "usage-evidence.json").read_text("utf-8")),
        usage_events_call_count=sum(
            bool(line.strip())
            for line in (root / "llm_usage_events.jsonl").read_text("utf-8").splitlines()
        ),
        trace_sidecars=json.loads((root / "trace-sidecars.json").read_text("utf-8")),
        artifact_sha256s={name: _sha(root / filename) for name, filename in artifact_names.items()},
    )
    (root / "p6-balanced-quality-gate.json").write_text(
        json.dumps(gate, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_authoritative_revalidation_rejects_fully_resealed_score_attack(
    tmp_path: Path,
) -> None:
    restored, _ = _quality_bundle(tmp_path)
    legacy = json.loads((restored / "legacy-score.json").read_text("utf-8"))
    legacy["report_views"]["with_needs_review"]["matched"][-1] = "forged-score-id"
    _dump(restored / "legacy-score.json", legacy)
    _rebuild_bundle_gate(restored)
    validate_quality_gate_bundle(restored)
    runner = ScoreRunner()

    with pytest.raises(P6BalancedOrchestratorError, match="byte-exactly"):
        revalidate_balanced_quality_bundle(
            restored_bundle=restored,
            legacy_truth_path=LEGACY_TRUTH,
            v16_truth_path=V16_TRUTH,
            identity=_identity(),
            output=tmp_path / "revalidated",
            receipt_path=tmp_path / "receipt.json",
            repository_root=REPO_ROOT,
            process_runner=runner,
            python_executable="python",
            git_head_resolver=lambda _root: _identity().control_plane_commit,
        )
    assert len(runner.calls) == 3


def test_authoritative_revalidation_requires_byte_identical_gate_serialization(
    tmp_path: Path,
) -> None:
    restored, _ = _quality_bundle(tmp_path)
    gate_path = restored / "p6-balanced-quality-gate.json"
    _dump(gate_path, json.loads(gate_path.read_text("utf-8")))
    validate_quality_gate_bundle(restored)
    runner = ScoreRunner()

    with pytest.raises(P6BalancedOrchestratorError, match="byte-exactly"):
        revalidate_balanced_quality_bundle(
            restored_bundle=restored,
            legacy_truth_path=LEGACY_TRUTH,
            v16_truth_path=V16_TRUTH,
            identity=_identity(),
            output=tmp_path / "revalidated",
            receipt_path=tmp_path / "receipt.json",
            repository_root=REPO_ROOT,
            process_runner=runner,
            python_executable="python",
            git_head_resolver=lambda _root: _identity().control_plane_commit,
        )
    assert len(runner.calls) == 3


@pytest.mark.parametrize(
    "wrong_identity",
    (
        BalancedRunIdentity("999", 2, "p6-33260000001-2", "c" * 40, "1" * 40, "2" * 40),
        BalancedRunIdentity("33260000001", 3, "p6-33260000001-2", "c" * 40, "1" * 40, "2" * 40),
        BalancedRunIdentity("33260000001", 2, "p6-33260000001-3", "c" * 40, "1" * 40, "2" * 40),
        BalancedRunIdentity("33260000001", 2, "p6-33260000001-2", "d" * 40, "1" * 40, "2" * 40),
        BalancedRunIdentity("33260000001", 2, "p6-33260000001-2", "c" * 40, "3" * 40, "2" * 40),
        BalancedRunIdentity("33260000001", 2, "p6-33260000001-2", "c" * 40, "1" * 40, "4" * 40),
    ),
)
def test_authoritative_revalidation_requires_all_external_expected_identities(
    tmp_path: Path, wrong_identity: BalancedRunIdentity
) -> None:
    restored, _ = _quality_bundle(tmp_path)
    runner = ScoreRunner()
    with pytest.raises(P6BalancedOrchestratorError):
        revalidate_balanced_quality_bundle(
            restored_bundle=restored,
            legacy_truth_path=LEGACY_TRUTH,
            v16_truth_path=V16_TRUTH,
            identity=wrong_identity,
            output=tmp_path / "revalidated",
            receipt_path=tmp_path / "receipt.json",
            repository_root=REPO_ROOT,
            process_runner=runner,
            git_head_resolver=lambda _root: wrong_identity.control_plane_commit,
        )
    assert runner.calls == []


def test_freeze_rejects_report_not_bound_by_selected_aggregate(tmp_path: Path) -> None:
    aggregate, report, metrics, projection = _producer_tree(tmp_path)
    _dump(
        report,
        {
            "answer_material_present": False,
            "run_manifest": {"validation_queue_drained": True},
            "tampered": True,
        },
    )

    with pytest.raises(
        P6BalancedOrchestratorError,
        match="producer metrics cannot be recomputed|report-to-producer",
    ):
        freeze_balanced_scan(
            aggregate_path=aggregate,
            report_path=report,
            producer_metrics_path=metrics,
            projection_path=projection,
            provider_config_path=CONFIG,
            identity=_identity(),
            output=tmp_path / "frozen",
        )


def test_freeze_rejects_cross_attempt_usage_sidecar_before_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    aggregate, report, metrics, projection = _producer_tree(tmp_path)
    usage_path = metrics.parent / "llm_usage_events.jsonl"
    rows = [json.loads(line) for line in usage_path.read_text(encoding="utf-8").splitlines()]
    rows[0]["call_chain_id"] = "llm-call-chain-9"
    rows[0]["logical_operation_id"] = "e" * 64
    usage_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )

    def forbidden_metrics(**_kwargs: Any) -> dict[str, Any]:
        raise AssertionError("producer metrics must not run before usage binding validation")

    monkeypatch.setattr(
        balanced_orchestrator,
        "build_p6_answer_free_producer_metrics",
        forbidden_metrics,
    )
    with pytest.raises(P6BalancedOrchestratorError, match="usage artifact binding"):
        freeze_balanced_scan(
            aggregate_path=aggregate,
            report_path=report,
            producer_metrics_path=metrics,
            projection_path=projection,
            provider_config_path=CONFIG,
            identity=_identity(),
            output=tmp_path / "frozen",
        )


@pytest.mark.parametrize(
    ("declaration", "error"),
    (
        ("metadata", "usage artifact binding"),
        ("run_manifest", "usage artifact binding"),
        ("decision_trace", "decision-trace usage binding"),
        ("aggregate", "aggregate usage binding"),
    ),
)
def test_freeze_requires_every_usage_sidecar_declaration(
    tmp_path: Path, declaration: str, error: str
) -> None:
    aggregate_path, report_path, metrics_path, projection_path = _producer_tree(tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    trace_path = metrics_path.parent / "decision_trace_manifest.json"
    if declaration in {"metadata", "run_manifest"}:
        report[declaration]["llm_usage_events_artifact"]["sha256"] = "f" * 64
    elif declaration == "decision_trace":
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        trace["llm_usage_events"]["file_sha256"] = "f" * 64
        unsigned_trace = dict(trace)
        unsigned_trace.pop("manifest_sha256", None)
        trace["manifest_sha256"] = canonical_sha256(unsigned_trace)
        _dump(trace_path, trace)
        artifact = report["run_manifest"]["decision_trace_artifact"]
        artifact["sha256"] = _sha(trace_path)
        artifact["manifest_sha256"] = trace["manifest_sha256"]
        aggregate["runs"][0]["artifact_hashes"]["files"][trace_path.name] = _sha(trace_path)
    else:
        aggregate["runs"][0]["artifact_hashes"]["files"]["llm_usage_events.jsonl"] = "f" * 64

    _dump(report_path, report)
    aggregate["runs"][0]["artifact_hashes"]["files"]["report.json"] = _sha(report_path)
    _dump(aggregate_path, aggregate)
    projection = json.loads(projection_path.read_text(encoding="utf-8"))
    projection["artifact_sha256"] = canonical_sha256(aggregate)
    _dump(projection_path, projection)

    with pytest.raises(P6BalancedOrchestratorError, match=error):
        freeze_balanced_scan(
            aggregate_path=aggregate_path,
            report_path=report_path,
            producer_metrics_path=metrics_path,
            projection_path=projection_path,
            provider_config_path=CONFIG,
            identity=_identity(),
            output=tmp_path / "frozen",
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "aggregate_failed",
        "run_incomplete",
        "run_gate_failure",
        "metrics_substitution",
        "phase_attempt",
    ),
)
def test_freeze_revalidates_the_complete_selected_attempt(tmp_path: Path, mutation: str) -> None:
    aggregate_path, report, metrics, projection_path = _producer_tree(tmp_path)
    aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    if mutation == "aggregate_failed":
        aggregate["passed"] = False
    elif mutation == "run_incomplete":
        aggregate["runs"][0]["completed"] = False
    elif mutation == "run_gate_failure":
        aggregate["runs"][0]["gate_failures"] = ["internal_failure"]
    elif mutation == "metrics_substitution":
        aggregate["runs"][0]["metrics"]["tokens"] += 1
    else:
        aggregate["runs"][0]["isolation"]["phase_executions"][0]["p6_workflow_run_attempt"] += 1
    _dump(aggregate_path, aggregate)
    projection = json.loads(projection_path.read_text(encoding="utf-8"))
    projection["artifact_sha256"] = canonical_sha256(aggregate)
    _dump(projection_path, projection)

    with pytest.raises(P6BalancedOrchestratorError, match="complete|incomplete|lineage"):
        freeze_balanced_scan(
            aggregate_path=aggregate_path,
            report_path=report,
            producer_metrics_path=metrics,
            projection_path=projection_path,
            provider_config_path=CONFIG,
            identity=_identity(),
            output=tmp_path / "frozen",
        )


@pytest.mark.parametrize("post_terminal_call", (False, True))
def test_freeze_recomputes_v4_authority_and_post_terminal_calls_from_trace(
    tmp_path: Path, post_terminal_call: bool
) -> None:
    aggregate, report, metrics_path, projection = _producer_tree(
        tmp_path,
        confirmed_terminal=True,
        post_terminal_call=post_terminal_call,
    )
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    assert metrics["p6_terminal_authority"]["confirmed_v4_report_count"] == 1
    assert metrics["p6_terminal_authority"]["confirmed_v4_trace_count"] == 1
    assert metrics["p6_terminal_authority"]["post_terminal_model_call_count"] == int(
        post_terminal_call
    )
    output = tmp_path / "frozen"
    if post_terminal_call:
        with pytest.raises(P6BalancedOrchestratorError, match="failed closed"):
            freeze_balanced_scan(
                aggregate_path=aggregate,
                report_path=report,
                producer_metrics_path=metrics_path,
                projection_path=projection,
                provider_config_path=CONFIG,
                identity=_identity(),
                output=output,
            )
    else:
        frozen = freeze_balanced_scan(
            aggregate_path=aggregate,
            report_path=report,
            producer_metrics_path=metrics_path,
            projection_path=projection,
            provider_config_path=CONFIG,
            identity=_identity(),
            output=output,
        )
        assert frozen["attempt_id"] == _identity().attempt_id


@pytest.mark.parametrize(
    ("mutation", "failure"),
    (
        ("producer_hash", "policy evidence disagree"),
        ("producer_material", "producer occurrence"),
        ("immutable_identity", "policy identity disagree"),
    ),
)
def test_producer_metrics_rejects_terminal_provenance_drift(
    tmp_path: Path,
    mutation: str,
    failure: str,
) -> None:
    _, report_path, _, _ = _producer_tree(tmp_path, confirmed_terminal=True)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    terminal = report["candidate_terminal_states"][0]
    if mutation == "producer_hash":
        terminal["proof_kernel_producer_binding_sha256"] = "f" * 64
    elif mutation == "producer_material":
        terminal["source"]["file"] = "src/other.c"
    else:
        terminal["sink_identity"] = "SINK_tampered"
    _dump(report_path, report)

    with pytest.raises(BenchmarkError, match=failure):
        build_p6_answer_free_producer_metrics(
            report_path=report_path,
            run_dir=report_path.parent,
            provider_contract=require_p6_provider_contract(CONFIG),
        )


def test_producer_metrics_revalidates_confirmed_alias_without_double_count(
    tmp_path: Path,
) -> None:
    _, report_path, _, _ = _producer_tree(tmp_path, confirmed_terminal=True)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    terminal = report["candidate_terminal_states"][0]
    terminal.update(
        {
            "candidate_disposition": "deduplicated_alias",
            "status": "deduplicated_alias",
            "validation_status": "deduplicated_alias",
            "finding_root_original_disposition": "confirmed",
            "finding_root_uid": "ROOT_test_confirmed_alias",
            "finding_root_primary_validation_cluster_uid": "VAL_primary",
        }
    )
    _dump(report_path, report)

    metrics = build_p6_answer_free_producer_metrics(
        report_path=report_path,
        run_dir=report_path.parent,
        provider_contract=require_p6_provider_contract(CONFIG),
    )

    assert metrics["p6_terminal_authority"]["confirmed_v4_report_count"] == 0
    assert metrics["p6_terminal_authority"]["confirmed_v4_trace_count"] == 0


def test_frozen_manifest_or_report_tamper_fails_before_any_scorer(tmp_path: Path) -> None:
    frozen, projection = _freeze(tmp_path)
    report = json.loads((frozen / "report.json").read_text("utf-8"))
    report["tampered"] = True
    _dump(frozen / "report.json", report)
    runner = ScoreRunner()

    with pytest.raises(P6BalancedOrchestratorError, match="artifact digest"):
        score_frozen_balanced_scan(
            frozen_root=frozen,
            projection_path=projection,
            legacy_truth_path=LEGACY_TRUTH,
            v16_truth_path=V16_TRUTH,
            identity=_identity(),
            output=tmp_path / "quality",
            repository_root=REPO_ROOT,
            process_runner=runner,
        )
    assert runner.calls == []


def test_frozen_projection_identity_mismatch_is_fail_closed(tmp_path: Path) -> None:
    frozen, projection = _freeze(tmp_path)
    other = copy.deepcopy(_identity())
    wrong = BalancedRunIdentity(
        workflow_run_id=other.workflow_run_id,
        workflow_run_attempt=other.workflow_run_attempt,
        attempt_id=other.attempt_id,
        control_plane_commit=other.control_plane_commit,
        candidate_git_sha="f" * 40,
        candidate_git_tree=other.candidate_git_tree,
    )
    with pytest.raises(P6BalancedOrchestratorError):
        validate_frozen_balanced_scan(
            frozen_root=frozen,
            projection_path=projection,
            identity=wrong,
        )


def test_freeze_copies_the_single_report_snapshot_after_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    aggregate, report, metrics, projection = _producer_tree(tmp_path)
    original_report = report.read_bytes()
    forged = tmp_path / "forged-report.json"
    forged.write_text(
        '{"answer_material_present":false,"run_manifest":{"validation_queue_drained":true}}\n',
        encoding="utf-8",
    )
    original_snapshot = balanced_orchestrator._snapshot_regular_file
    replaced = False

    def replace_after_snapshot(path: Path, *, name: str) -> Any:
        nonlocal replaced
        snapshot = original_snapshot(path, name=name)
        if Path(path) == report and not replaced:
            replaced = True
            report.unlink()
            forged.replace(report)
        return snapshot

    monkeypatch.setattr(
        balanced_orchestrator,
        "_snapshot_regular_file",
        replace_after_snapshot,
    )
    output = tmp_path / "frozen"
    freeze_balanced_scan(
        aggregate_path=aggregate,
        report_path=report,
        producer_metrics_path=metrics,
        projection_path=projection,
        provider_config_path=CONFIG,
        identity=_identity(),
        output=output,
    )

    assert replaced is True
    assert (output / "report.json").read_bytes() == original_report
    assert (output / "report.json").read_bytes() != report.read_bytes()


def test_frozen_projection_symlink_is_rejected_before_validation(tmp_path: Path) -> None:
    frozen, projection = _freeze(tmp_path)
    target = tmp_path / "projection-target.json"
    projection.replace(target)
    try:
        projection.symlink_to(target)
    except OSError:
        pytest.skip("file symlinks are unavailable on this platform")

    with pytest.raises(P6BalancedOrchestratorError, match="regular file"):
        validate_frozen_balanced_scan(
            frozen_root=frozen,
            projection_path=projection,
            identity=_identity(),
        )


def test_score_rejects_noncanonical_truth_path_before_any_scorer(tmp_path: Path) -> None:
    frozen, projection = _freeze(tmp_path)
    alias = tmp_path / "truth-alias.json"
    alias.write_text("{}\n", encoding="utf-8")
    runner = ScoreRunner()

    with pytest.raises(P6BalancedOrchestratorError, match="canonical Truth paths"):
        score_frozen_balanced_scan(
            frozen_root=frozen,
            projection_path=projection,
            legacy_truth_path=alias,
            v16_truth_path=V16_TRUTH,
            identity=_identity(),
            output=tmp_path / "quality",
            repository_root=REPO_ROOT,
            process_runner=runner,
        )
    assert runner.calls == []


def test_revalidation_snapshots_each_canonical_source_exactly_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    restored, _ = _quality_bundle(tmp_path)
    source_paths: list[str] = []
    truth_paths: list[str] = []
    original_snapshot = balanced_orchestrator._snapshot_regular_file

    def count_snapshot(path: Path, *, name: str) -> Any:
        if name == "canonical scoring source":
            source_paths.append(os.path.normcase(os.path.abspath(str(path))))
        elif name == "committed canonical Truth input":
            truth_paths.append(os.path.normcase(os.path.abspath(str(path))))
        return original_snapshot(path, name=name)

    monkeypatch.setattr(
        balanced_orchestrator,
        "_snapshot_regular_file",
        count_snapshot,
    )
    revalidate_balanced_quality_bundle(
        restored_bundle=restored,
        legacy_truth_path=LEGACY_TRUTH,
        v16_truth_path=V16_TRUTH,
        identity=_identity(),
        output=tmp_path / "revalidated",
        receipt_path=tmp_path / "receipt.json",
        repository_root=REPO_ROOT,
        process_runner=ScoreRunner(),
        python_executable="python",
        git_head_resolver=lambda _root: _identity().control_plane_commit,
    )

    assert len(source_paths) == len(balanced_orchestrator._CANONICAL_SOURCE_FILES)
    assert len(set(source_paths)) == len(source_paths)
    assert len(truth_paths) == len(balanced_orchestrator._CANONICAL_TRUTH_FILES)
    assert len(set(truth_paths)) == len(truth_paths)
    assert all(
        path
        not in {
            os.path.normcase(os.path.abspath(str(LEGACY_TRUTH))),
            os.path.normcase(os.path.abspath(str(V16_TRUTH))),
        }
        for path in truth_paths
    )
    assert all(
        any(
            Path(path).as_posix().lower().endswith("/" + relative)
            for relative in balanced_orchestrator._CANONICAL_TRUTH_FILES.values()
        )
        for path in truth_paths
    )


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX dirfd semantics")
def test_quality_bundle_path_swap_restore_remains_descriptor_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    restored, _ = _quality_bundle(tmp_path)
    replacement = tmp_path / "replacement"
    parked = tmp_path / "parked"
    shutil.copytree(restored, replacement)
    (replacement / "quality-gate.json").write_text("{}\n", encoding="utf-8")
    original_snapshot_at = balanced_orchestrator._snapshot_regular_file_at
    swapped = False

    def swap_restore(directory_fd: int, member: str, *, name: str) -> Any:
        nonlocal swapped
        if swapped:
            return original_snapshot_at(directory_fd, member, name=name)
        swapped = True
        restored.rename(parked)
        replacement.rename(restored)
        try:
            return original_snapshot_at(directory_fd, member, name=name)
        finally:
            restored.rename(replacement)
            parked.rename(restored)

    monkeypatch.setattr(
        balanced_orchestrator,
        "_snapshot_regular_file_at",
        swap_restore,
    )
    runner = ScoreRunner()
    receipt = revalidate_balanced_quality_bundle(
        restored_bundle=restored,
        legacy_truth_path=LEGACY_TRUTH,
        v16_truth_path=V16_TRUTH,
        identity=_identity(),
        output=tmp_path / "revalidated",
        receipt_path=tmp_path / "receipt.json",
        repository_root=REPO_ROOT,
        process_runner=runner,
        python_executable="python",
        git_head_resolver=lambda _root: _identity().control_plane_commit,
    )

    assert swapped is True
    assert receipt["byte_exact"] is True
    assert len(runner.calls) == 3


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX dirfd semantics")
def test_quality_bundle_directory_replacement_fails_before_scorer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    restored, _ = _quality_bundle(tmp_path)
    replacement = tmp_path / "replacement"
    parked = tmp_path / "parked"
    shutil.copytree(restored, replacement)
    original_snapshot_at = balanced_orchestrator._snapshot_regular_file_at
    swapped = False

    def replace_directory(directory_fd: int, member: str, *, name: str) -> Any:
        nonlocal swapped
        if not swapped:
            swapped = True
            restored.rename(parked)
            replacement.rename(restored)
        return original_snapshot_at(directory_fd, member, name=name)

    monkeypatch.setattr(
        balanced_orchestrator,
        "_snapshot_regular_file_at",
        replace_directory,
    )
    runner = ScoreRunner()
    with pytest.raises(P6BalancedOrchestratorError, match="changed during snapshot"):
        revalidate_balanced_quality_bundle(
            restored_bundle=restored,
            legacy_truth_path=LEGACY_TRUTH,
            v16_truth_path=V16_TRUTH,
            identity=_identity(),
            output=tmp_path / "revalidated",
            receipt_path=tmp_path / "receipt.json",
            repository_root=REPO_ROOT,
            process_runner=runner,
            python_executable="python",
            git_head_resolver=lambda _root: _identity().control_plane_commit,
        )
    assert runner.calls == []


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX openat semantics")
def test_quality_bundle_member_replacement_between_stat_and_open_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    restored, _ = _quality_bundle(tmp_path)
    member = restored / "usage-evidence.json"
    parked = tmp_path / "parked-usage-evidence.json"
    replacement = tmp_path / "replacement-usage-evidence.json"
    replacement.write_bytes(member.read_bytes())
    original_open = balanced_orchestrator.os.open
    swapped = False

    def swap_member_before_open(
        path: Any,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path == member.name and dir_fd is not None and not swapped:
            swapped = True
            member.rename(parked)
            replacement.rename(member)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(balanced_orchestrator.os, "open", swap_member_before_open)
    runner = ScoreRunner()
    with pytest.raises(P6BalancedOrchestratorError, match="changed before secure open"):
        revalidate_balanced_quality_bundle(
            restored_bundle=restored,
            legacy_truth_path=LEGACY_TRUTH,
            v16_truth_path=V16_TRUTH,
            identity=_identity(),
            output=tmp_path / "revalidated",
            receipt_path=tmp_path / "receipt.json",
            repository_root=REPO_ROOT,
            process_runner=runner,
            python_executable="python",
            git_head_resolver=lambda _root: _identity().control_plane_commit,
        )
    assert swapped is True
    assert runner.calls == []
