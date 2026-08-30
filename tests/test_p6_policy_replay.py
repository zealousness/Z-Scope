from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from scripts.run_p6_policy_replay import P6PolicyReplayError, replay_trace_root
from scripts.reverify_v3_trace import reverify_trace_root
from zscope.orchestration.decision_trace import DecisionTraceStore
from zscope.benchmarking.p6_protocol import canonical_sha256


def _trace_root(tmp_path: Path) -> Path:
    store = DecisionTraceStore(tmp_path, scan_uid="P6_REPLAY")
    store.bind_candidate("VAL_1", candidate_uids=("CAND_1",))
    store.finalize_issue(
        {
            "candidate_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "candidate_disposition": "needs_review",
            "validation_status": "needs_review",
            "proof_coverage": "incomplete",
            "terminal_authority_decision": {
                "schema_version": "zscope.terminal-authority-decision.v3",
                "disposition": "needs_review",
                "terminal": True,
                "reason_code": "NEEDS_REVIEW_OPEN_CLAUSES",
                "authority": "zscope.proof-checker",
                "next_action": "",
                "conflict_resolution": None,
            },
        },
        view_memberships=("default", "with_needs_review"),
    )
    store.snapshot()
    return tmp_path


def test_policy_replay_executes_every_hash_bound_trace_without_calls(tmp_path: Path) -> None:
    payload = replay_trace_root(
        _trace_root(tmp_path),
        control_plane_commit="a" * 40,
        candidate_git_sha="a" * 40,
        workflow_run_id="123",
        workflow_run_attempt=1,
    )

    assert payload["trace_count"] == 1
    assert payload["llm_calls"] == 0
    assert "network_calls" not in payload
    assert payload["truth_inputs"] == 0
    assert payload["formal_evidence"] is False
    assert len(payload["result_root_sha256"]) == 64


def test_policy_replay_rejects_manifest_or_trace_tampering(tmp_path: Path) -> None:
    root = _trace_root(tmp_path)
    manifest_path = root / "decision_trace_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["trace_count"] = 99
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(P6PolicyReplayError, match="manifest hash"):
        replay_trace_root(
            root,
            control_plane_commit="a" * 40,
            candidate_git_sha="a" * 40,
            workflow_run_id="123",
            workflow_run_attempt=1,
        )


def _rebind_manifest(root: Path, transform) -> None:
    path = root / "decision_trace_manifest.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    transform(value)
    value.pop("manifest_sha256", None)
    value["manifest_sha256"] = canonical_sha256(value)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_policy_replay_rejects_duplicate_keys_in_trace(tmp_path: Path) -> None:
    root = _trace_root(tmp_path)
    manifest = json.loads((root / "decision_trace_manifest.json").read_text(encoding="utf-8"))
    trace_path = root / next(iter(manifest["traces"].values()))["path"]
    text = trace_path.read_text(encoding="utf-8")
    trace_path.write_text('{"schema_version":"duplicate",' + text[1:], encoding="utf-8")

    with pytest.raises(P6PolicyReplayError, match="duplicate JSON key"):
        replay_trace_root(
            root,
            control_plane_commit="a" * 40,
            candidate_git_sha="a" * 40,
            workflow_run_id="123",
            workflow_run_attempt=1,
        )


def test_policy_replay_rejects_rebound_record_drift(tmp_path: Path) -> None:
    root = _trace_root(tmp_path)
    _rebind_manifest(
        root,
        lambda value: next(iter(value["traces"].values())).__setitem__("event_count", 99),
    )

    with pytest.raises(P6PolicyReplayError, match="record binding"):
        replay_trace_root(
            root,
            control_plane_commit="a" * 40,
            candidate_git_sha="a" * 40,
            workflow_run_id="123",
            workflow_run_attempt=1,
        )


def test_policy_replay_rejects_coverage_trace_tampering(tmp_path: Path) -> None:
    root = _trace_root(tmp_path)
    manifest = json.loads((root / "decision_trace_manifest.json").read_text(encoding="utf-8"))
    trace_record = next(iter(manifest["traces"].values()))
    (root / "coverage.json").write_bytes((root / trace_record["path"]).read_bytes())

    def add_coverage(value):
        value["coverage_trace_count"] = 1
        value["coverage_traces"] = {
            "AUDIT_1": {
                key: item for key, item in trace_record.items() if key != "terminal_disposition"
            }
        }
        value["coverage_traces"]["AUDIT_1"]["path"] = "coverage.json"

    _rebind_manifest(root, add_coverage)
    with pytest.raises(P6PolicyReplayError, match="coverage trace verification"):
        replay_trace_root(
            root,
            control_plane_commit="a" * 40,
            candidate_git_sha="a" * 40,
            workflow_run_id="123",
            workflow_run_attempt=1,
        )


def test_policy_replay_rejects_symlinked_trace(tmp_path: Path) -> None:
    root = _trace_root(tmp_path)
    manifest = json.loads((root / "decision_trace_manifest.json").read_text(encoding="utf-8"))
    trace_path = root / next(iter(manifest["traces"].values()))["path"]
    target = tmp_path / "trace-target.json"
    target.write_bytes(trace_path.read_bytes())
    trace_path.unlink()
    try:
        trace_path.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")

    with pytest.raises(P6PolicyReplayError, match="symbolic link"):
        replay_trace_root(
            root,
            control_plane_commit="a" * 40,
            candidate_git_sha="a" * 40,
            workflow_run_id="123",
            workflow_run_attempt=1,
        )


def test_certificate_reverify_is_strict_answer_free_and_manifest_bound(
    tmp_path: Path,
) -> None:
    payload = reverify_trace_root(
        _trace_root(tmp_path),
        control_plane_commit="a" * 40,
        candidate_git_sha="a" * 40,
        workflow_run_id="123",
        workflow_run_attempt=1,
    )

    assert payload["passed"] is True
    assert payload["llm_calls"] == 0
    assert payload["truth_inputs"] == 0
    assert payload["trace_manifest_complete"] is True
    assert "clusters" not in payload
    assert "validation_cluster_uid" not in json.dumps(payload)
    body = dict(payload)
    evidence_sha256 = body.pop("evidence_sha256")
    assert evidence_sha256 == canonical_sha256(body)


def test_certificate_reverify_rejects_duplicate_trace_keys(tmp_path: Path) -> None:
    root = _trace_root(tmp_path)
    manifest = json.loads((root / "decision_trace_manifest.json").read_text(encoding="utf-8"))
    trace_path = root / next(iter(manifest["traces"].values()))["path"]
    text = trace_path.read_text(encoding="utf-8")
    trace_path.write_text('{"schema_version":"duplicate",' + text[1:], encoding="utf-8")

    with pytest.raises(P6PolicyReplayError, match="duplicate JSON key"):
        reverify_trace_root(
            root,
            control_plane_commit="a" * 40,
            candidate_git_sha="a" * 40,
            workflow_run_id="123",
            workflow_run_attempt=1,
        )
