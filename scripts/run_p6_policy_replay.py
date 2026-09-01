#!/usr/bin/env python3
"""Replay every frozen decision trace through the product policy engine offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, Mapping, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.benchmarking.p6_protocol import canonical_sha256
from zscope.cli.explain import _policy_replay
from zscope.orchestration.decision_trace import (
    DECISION_TRACE_MANIFEST_VERSION,
    DecisionTraceError,
    verify_coverage_trace,
    verify_decision_trace,
)


class P6PolicyReplayError(RuntimeError):
    """Raised when frozen policy-replay input is not self-authenticating."""


_MAX_JSON_BYTES = 32 * 1024 * 1024


def _reject_constant(_value: str) -> None:
    raise P6PolicyReplayError("non-finite JSON number")


def _strict_json_bytes(raw: bytes) -> Any:
    def reject_duplicates(rows: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise P6PolicyReplayError("duplicate JSON key")
            result[key] = value
        return result

    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise P6PolicyReplayError("JSON is not strict UTF-8") from exc


def _regular_bytes(root: Path, relative: PurePosixPath) -> bytes:
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise P6PolicyReplayError("artifact path is not canonical")
    root = Path(os.path.abspath(root))
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise P6PolicyReplayError("frozen trace root is unavailable") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise P6PolicyReplayError("frozen trace root is not a link-free directory")
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            current_stat = current.lstat()
        except OSError as exc:
            raise P6PolicyReplayError("frozen trace artifact is unavailable") from exc
        if stat.S_ISLNK(current_stat.st_mode):
            raise P6PolicyReplayError("frozen trace artifact traverses a symbolic link")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(current_stat.st_mode):
            raise P6PolicyReplayError("frozen trace artifact parent is not a directory")
        if index == len(relative.parts) - 1 and not stat.S_ISREG(current_stat.st_mode):
            raise P6PolicyReplayError("frozen trace artifact is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(current), flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise P6PolicyReplayError("frozen trace artifact changed type")
            raw = handle.read(_MAX_JSON_BYTES + 1)
    except OSError as exc:
        raise P6PolicyReplayError("frozen trace artifact cannot be opened safely") from exc
    if len(raw) > _MAX_JSON_BYTES:
        raise P6PolicyReplayError("frozen trace artifact exceeds the size limit")
    return raw


def _strict_object(root: Path, relative: PurePosixPath) -> Dict[str, Any]:
    value = _strict_json_bytes(_regular_bytes(root, relative))
    if not isinstance(value, dict):
        raise P6PolicyReplayError("JSON root is not an object")
    return value


def _validate_record(
    record: Mapping[str, Any],
    document: Mapping[str, Any],
    *,
    relative: PurePosixPath,
    terminal: bool,
) -> None:
    expected: Dict[str, Any] = {
        "path": relative.as_posix(),
        "trace_root_sha256": str(document.get("trace_root_sha256") or ""),
        "document_sha256": str(document.get("document_sha256") or ""),
        "event_count": len(document.get("events") or []),
    }
    if terminal:
        expected["terminal_disposition"] = str(document.get("terminal_disposition") or "")
    if dict(record) != expected:
        raise P6PolicyReplayError("trace manifest record binding mismatch")


def _validate_usage_sidecar(root: Path, manifest: Mapping[str, Any]) -> None:
    usage = manifest.get("llm_usage_events")
    if not isinstance(usage, Mapping):
        raise P6PolicyReplayError("trace usage binding is unavailable")
    available = usage.get("available") is True
    relative_text = str(usage.get("path") or "")
    file_sha = str(usage.get("file_sha256") or "")
    if not available:
        if relative_text or file_sha or int(usage.get("event_count") or 0) != 0:
            raise P6PolicyReplayError("empty trace usage binding is inconsistent")
        return
    relative = PurePosixPath(relative_text)
    raw = _regular_bytes(root, relative)
    if hashlib.sha256(raw).hexdigest() != file_sha:
        raise P6PolicyReplayError("trace usage sidecar hash mismatch")
    events: list[Mapping[str, Any]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        value = _strict_json_bytes(line)
        if not isinstance(value, Mapping):
            raise P6PolicyReplayError("trace usage sidecar row is not an object")
        events.append(value)
    if len(events) != int(usage.get("event_count") or 0):
        raise P6PolicyReplayError("trace usage sidecar count mismatch")
    call_ids = sorted(str(row.get("call_id") or "") for row in events)
    if not all(call_ids) or call_ids != sorted(usage.get("referenced_call_ids") or []):
        raise P6PolicyReplayError("trace usage sidecar call binding mismatch")
    if usage.get("conservation_valid") is not True:
        raise P6PolicyReplayError("trace usage sidecar is not conserved")


def replay_trace_root(
    root: Path,
    *,
    control_plane_commit: str,
    candidate_git_sha: str,
    workflow_run_id: str,
    workflow_run_attempt: int,
) -> Mapping[str, Any]:
    if (
        re.fullmatch(r"[0-9a-f]{40}", control_plane_commit) is None
        or re.fullmatch(r"[0-9a-f]{40}", candidate_git_sha) is None
        or not workflow_run_id.isdigit()
        or workflow_run_id.startswith("0")
        or isinstance(workflow_run_attempt, bool)
        or workflow_run_attempt < 1
    ):
        raise P6PolicyReplayError("workflow lineage is invalid")
    root = Path(os.path.abspath(root))
    manifest_relative = PurePosixPath("decision_trace_manifest.json")
    manifest_file_sha256 = hashlib.sha256(_regular_bytes(root, manifest_relative)).hexdigest()
    manifest = _strict_object(root, manifest_relative)
    if manifest.get("schema_version") != DECISION_TRACE_MANIFEST_VERSION:
        raise P6PolicyReplayError("trace manifest schema is unsupported")
    claimed_manifest_sha = str(manifest.get("manifest_sha256") or "")
    manifest_projection = dict(manifest)
    manifest_projection.pop("manifest_sha256", None)
    if claimed_manifest_sha != canonical_sha256(manifest_projection):
        raise P6PolicyReplayError("trace manifest hash mismatch")
    if manifest.get("complete") is not True:
        raise P6PolicyReplayError("trace manifest is incomplete")
    traces = manifest.get("traces")
    if not isinstance(traces, Mapping) or manifest.get("trace_count") != len(traces):
        raise P6PolicyReplayError("trace manifest accounting mismatch")

    result_hashes: list[str] = []
    match_counts: Counter[str] = Counter()
    policy_issue_counts: Counter[str] = Counter()
    for cluster_uid, record in sorted(traces.items()):
        if not isinstance(record, Mapping):
            raise P6PolicyReplayError("trace manifest record is invalid")
        relative_text = str(record.get("path") or "")
        relative = PurePosixPath(relative_text)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise P6PolicyReplayError("trace path is not canonical")
        trace = _strict_object(root, relative)
        valid, _reason = verify_decision_trace(trace)
        if not valid:
            raise P6PolicyReplayError("decision trace verification failed")
        if str(trace.get("validation_cluster_uid") or "") != str(cluster_uid):
            raise P6PolicyReplayError("trace cluster identity mismatch")
        _validate_record(record, trace, relative=relative, terminal=True)
        replay = _policy_replay(trace, root)
        if (
            replay.get("matches_frozen_terminal") is not True
            or replay.get("policy_issue") != "none"
        ):
            raise P6PolicyReplayError("terminal policy replay mismatch")
        result_hashes.append(canonical_sha256(replay))
        match_counts[str(bool(replay.get("matches_frozen_terminal"))).lower()] += 1
        policy_issue_counts[str(replay.get("policy_issue") or "none")] += 1

    coverage = manifest.get("coverage_traces")
    if not isinstance(coverage, Mapping) or manifest.get("coverage_trace_count") != len(coverage):
        raise P6PolicyReplayError("coverage trace manifest accounting mismatch")
    for audit_unit_uid, record in sorted(coverage.items()):
        if not isinstance(record, Mapping):
            raise P6PolicyReplayError("coverage trace manifest record is invalid")
        relative_text = str(record.get("path") or "")
        relative = PurePosixPath(relative_text)
        coverage_trace = _strict_object(root, relative)
        valid, _reason = verify_coverage_trace(coverage_trace)
        if not valid:
            raise P6PolicyReplayError("coverage trace verification failed")
        if str(coverage_trace.get("audit_unit_uid") or "") != str(audit_unit_uid):
            raise P6PolicyReplayError("coverage trace identity mismatch")
        _validate_record(record, coverage_trace, relative=relative, terminal=False)

    for count_name, hashes_name in (
        ("evidence_object_count", "evidence_object_sha256"),
        ("model_event_count", "model_event_sha256"),
    ):
        hashes = manifest.get(hashes_name)
        if (
            not isinstance(hashes, list)
            or manifest.get(count_name) != len(hashes)
            or hashes != sorted(set(hashes))
            or any(re.fullmatch(r"[0-9a-f]{64}", str(value)) is None for value in hashes)
        ):
            raise P6PolicyReplayError("trace content-addressed accounting mismatch")
    _validate_usage_sidecar(root, manifest)

    payload: Dict[str, Any] = {
        "schema_version": "zscope.p6-policy-replay-evidence.v1",
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
        "control_plane_commit": control_plane_commit,
        "candidate_git_sha": candidate_git_sha,
        "trace_manifest_sha256": claimed_manifest_sha,
        "trace_manifest_file_sha256": manifest_file_sha256,
        "trace_count": len(result_hashes),
        "result_root_sha256": canonical_sha256(sorted(result_hashes)),
        "terminal_match_counts": dict(sorted(match_counts.items())),
        "policy_issue_counts": dict(sorted(policy_issue_counts.items())),
        "llm_calls": 0,
        "truth_inputs": 0,
        "answer_material_present": False,
        "formal_evidence": False,
        "release_eligible": False,
    }
    payload["evidence_sha256"] = canonical_sha256(payload)
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run frozen P6 policy replay without a model")
    parser.add_argument("--trace-root", required=True, type=Path)
    parser.add_argument("--control-plane-commit", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-run-attempt", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        payload = replay_trace_root(
            args.trace_root,
            control_plane_commit=args.control_plane_commit,
            candidate_git_sha=args.candidate_commit,
            workflow_run_id=args.workflow_run_id,
            workflow_run_attempt=args.workflow_run_attempt,
        )
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    except (OSError, ValueError, json.JSONDecodeError, DecisionTraceError, P6PolicyReplayError):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
