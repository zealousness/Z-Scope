#!/usr/bin/env python3
"""Reclassify frozen V3 verifier events without model calls or truth data."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Dict, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.run_p6_policy_replay import (
    P6PolicyReplayError,
    _regular_bytes,
    _strict_object,
    _validate_record,
    _validate_usage_sidecar,
)
from zscope.benchmarking.p6_protocol import canonical_sha256
from zscope.cli.explain import _reverify
from zscope.orchestration.decision_trace import (
    DECISION_TRACE_MANIFEST_VERSION,
    DecisionTraceError,
    verify_coverage_trace,
    verify_decision_trace,
)


def reverify_trace_root(
    root: Path,
    *,
    control_plane_commit: str = "0" * 40,
    candidate_git_sha: str = "0" * 40,
    workflow_run_id: str = "1",
    workflow_run_attempt: int = 1,
) -> Dict[str, Any]:
    """Strictly reverify the already sealed trace corpus without exposing identities."""

    root = Path(os.path.abspath(root))
    if (
        re.fullmatch(r"[0-9a-f]{40}", control_plane_commit) is None
        or re.fullmatch(r"[0-9a-f]{40}", candidate_git_sha) is None
        or not workflow_run_id.isdigit()
        or workflow_run_id.startswith("0")
        or isinstance(workflow_run_attempt, bool)
        or workflow_run_attempt < 1
    ):
        raise P6PolicyReplayError("workflow lineage is invalid")
    manifest_raw = _regular_bytes(root, PurePosixPath("decision_trace_manifest.json"))
    manifest = _strict_object(root, PurePosixPath("decision_trace_manifest.json"))
    if manifest.get("schema_version") != DECISION_TRACE_MANIFEST_VERSION:
        raise P6PolicyReplayError("trace manifest schema is unsupported")
    claimed_manifest_sha = str(manifest.get("manifest_sha256") or "")
    manifest_body = dict(manifest)
    manifest_body.pop("manifest_sha256", None)
    if claimed_manifest_sha != canonical_sha256(manifest_body):
        raise P6PolicyReplayError("trace manifest hash mismatch")
    if manifest.get("complete") is not True:
        raise P6PolicyReplayError("trace manifest is incomplete")
    traces = manifest.get("traces")
    if not isinstance(traces, Mapping) or manifest.get("trace_count") != len(traces):
        raise P6PolicyReplayError("trace manifest accounting mismatch")
    counts: Counter[str] = Counter()
    fact_kind_counts: Counter[str] = Counter()
    v3_entered_count = 0
    terminal_trace_count = 0
    empty_required_fact_v3_count = 0
    verifier_cluster_count = 0
    for cluster_uid, record in sorted(traces.items()):
        if not isinstance(record, Mapping):
            raise P6PolicyReplayError("invalid trace manifest record")
        relative = PurePosixPath(str(record.get("path") or ""))
        trace = _strict_object(root, relative)
        valid, _reason = verify_decision_trace(trace)
        if not valid or str(trace.get("validation_cluster_uid") or "") != str(cluster_uid):
            raise P6PolicyReplayError("decision trace verification failed")
        _validate_record(record, trace, relative=relative, terminal=True)
        result = _reverify(trace, root, allow_incomplete_trace=True)
        events = [value for value in trace.get("events") or [] if isinstance(value, Mapping)]
        entered = [
            value
            for value in events
            if value.get("stage") == "V3" and value.get("reason_code") == "V3_ENTERED"
        ]
        if entered:
            v3_entered_count += 1
            if any(
                not (value.get("details") or {}).get("required_fact_kinds")
                for value in entered
                if isinstance(value.get("details"), Mapping)
            ):
                empty_required_fact_v3_count += 1
        if trace.get("terminal_event_uid"):
            terminal_trace_count += 1
        classifications = [
            str(value.get("classification") or "unclassified")
            for value in result.get("claim_results") or []
            if isinstance(value, Mapping)
        ]
        if classifications:
            verifier_cluster_count += 1
        counts.update(classifications)
        fact_kind_counts.update(
            str(value.get("fact_kind") or "unknown")
            for value in result.get("claim_results") or []
            if isinstance(value, Mapping)
        )
    coverage = manifest.get("coverage_traces")
    if not isinstance(coverage, Mapping) or manifest.get("coverage_trace_count") != len(coverage):
        raise P6PolicyReplayError("coverage trace manifest accounting mismatch")
    for audit_unit_uid, record in sorted(coverage.items()):
        if not isinstance(record, Mapping):
            raise P6PolicyReplayError("coverage trace manifest record is invalid")
        relative = PurePosixPath(str(record.get("path") or ""))
        trace = _strict_object(root, relative)
        valid, _reason = verify_coverage_trace(trace)
        if not valid or str(trace.get("audit_unit_uid") or "") != str(audit_unit_uid):
            raise P6PolicyReplayError("coverage trace verification failed")
        _validate_record(record, trace, relative=relative, terminal=False)
    for count_name, hashes_name in (
        ("evidence_object_count", "evidence_object_sha256"),
        ("model_event_count", "model_event_sha256"),
    ):
        hashes = manifest.get(hashes_name)
        if (
            not isinstance(hashes, list)
            or manifest.get(count_name) != len(hashes)
            or hashes != sorted(set(hashes))
            or any(
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                for value in hashes
            )
        ):
            raise P6PolicyReplayError("trace content-addressed accounting mismatch")
    _validate_usage_sidecar(root, manifest)
    payload: Dict[str, Any] = {
        "schema_version": "zscope.v3-trace-reverification.v1",
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
        "control_plane_commit": control_plane_commit,
        "candidate_git_sha": candidate_git_sha,
        "trace_manifest_sha256": claimed_manifest_sha,
        "trace_manifest_file_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "trace_manifest_complete": True,
        "cluster_count": len(traces),
        "terminal_trace_count": terminal_trace_count,
        "v3_entered_cluster_count": v3_entered_count,
        "v3_entered_with_empty_required_facts": empty_required_fact_v3_count,
        "verifier_cluster_count": verifier_cluster_count,
        "claim_count": sum(counts.values()),
        "classification_counts": dict(sorted(counts.items())),
        "fact_kind_counts": dict(sorted(fact_kind_counts.items())),
        "passed": True,
        "llm_calls": 0,
        "truth_inputs": 0,
        "answer_material_present": False,
        "formal_evidence": False,
        "release_eligible": False,
    }
    payload["evidence_sha256"] = canonical_sha256(payload)
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reverify every frozen V3 claim/certificate without LLM or truth"
    )
    parser.add_argument("--trace-root", required=True, type=Path)
    parser.add_argument("--control-plane-commit", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-run-attempt", required=True, type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = reverify_trace_root(
            args.trace_root,
            control_plane_commit=args.control_plane_commit,
            candidate_git_sha=args.candidate_commit,
            workflow_run_id=args.workflow_run_id,
            workflow_run_attempt=args.workflow_run_attempt,
        )
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        DecisionTraceError,
        P6PolicyReplayError,
    ):
        return 2
    encoded = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
