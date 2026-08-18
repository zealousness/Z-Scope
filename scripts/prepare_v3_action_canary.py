#!/usr/bin/env python3
"""Prepare an answer-free V3 EvidenceAction canary from frozen decision traces.

This preflight never calls a model and never reads a scorer or truth file.  It
reconstructs only the V3-entered obligation, binds it to the current source
snapshot, executes the finite local actions, and records which clauses can be
closed by replayable EvidenceCertificate v2 records.  A model canary may start
only after this artifact demonstrates executable actions for the selected
clusters; this artifact is not itself a completed V3 session.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.core.validation.fact_capabilities import FunctionIRFactService
from zscope.orchestration.decision_trace import (
    DecisionTraceError,
    load_decision_trace,
)


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _json(path: Path) -> Dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise DecisionTraceError(f"{path} must contain one JSON object")
    return value


def _endpoint(raw: Any) -> Any:
    if isinstance(raw, Mapping):
        return dict(raw)
    text = str(raw or "").strip()
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, Mapping):
            return dict(parsed)
    return {"expression": text} if text else {}


def _location(obligation: Mapping[str, Any]) -> tuple[str, int]:
    raw = str(obligation.get("location") or "")
    file_value, separator, line_value = raw.rpartition(":")
    if separator and line_value.isdigit():
        return file_value, int(line_value)
    source = _endpoint(obligation.get("source_uid"))
    sink = _endpoint(obligation.get("sink_uid"))
    for value in (sink, source):
        if isinstance(value, Mapping) and value.get("file"):
            return str(value["file"]), int(value.get("line") or 0)
    return raw, 0


def _inside(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise DecisionTraceError(f"source path escapes answer-free root: {relative}") from exc
    if any(part.lower() in {"benchmark", "ground_truth", "truth"} for part in candidate.parts):
        raise DecisionTraceError(f"answer-bearing source path is forbidden: {relative}")
    if not candidate.is_file():
        raise DecisionTraceError(f"source file does not exist: {candidate}")
    return candidate


def _v3_records(root: Path) -> list[tuple[str, Dict[str, Any], Dict[str, Any]]]:
    manifest = _json(root / "decision_trace_manifest.json")
    traces = manifest.get("traces")
    if not isinstance(traces, Mapping):
        raise DecisionTraceError("trace manifest has no traces mapping")
    result: list[tuple[str, Dict[str, Any], Dict[str, Any]]] = []
    for cluster_uid, record in sorted(traces.items()):
        if not isinstance(record, Mapping):
            raise DecisionTraceError(f"invalid trace manifest record: {cluster_uid}")
        trace_path = (root / str(record.get("path") or "")).resolve()
        try:
            trace_path.relative_to(root.resolve())
        except ValueError as exc:
            raise DecisionTraceError("trace path escapes trace root") from exc
        trace = load_decision_trace(trace_path)
        entered = next(
            (
                dict(event)
                for event in trace.get("events") or []
                if isinstance(event, Mapping)
                and event.get("stage") == "V3"
                and event.get("reason_code") == "V3_ENTERED"
            ),
            None,
        )
        if entered is not None:
            result.append((str(cluster_uid), trace, entered))
    return result


def _model_input(root: Path, trace: Mapping[str, Any]) -> Dict[str, Any]:
    candidates: list[str] = []
    for event in trace.get("events") or []:
        if not isinstance(event, Mapping) or event.get("stage") not in {"V1", "V2"}:
            continue
        candidates.extend(
            str(value)
            for value in event.get("output_refs") or []
            if str(value).startswith("model_events/")
        )
    if not candidates:
        raise DecisionTraceError("V3 trace has no retained V1/V2 structured input")
    model_path = (root / candidates[-1]).resolve()
    try:
        model_path.relative_to(root.resolve())
    except ValueError as exc:
        raise DecisionTraceError("model event path escapes trace root") from exc
    model = _json(model_path)
    structured = model.get("structured_input")
    if not isinstance(structured, Mapping):
        raise DecisionTraceError("model event has no structured input")
    return dict(structured)


def _select_currently_eligible(
    rows: Sequence[Mapping[str, Any]],
    *,
    limit: int,
) -> tuple[list[Dict[str, Any]], list[Dict[str, Any]]]:
    """Separate historical V3 mistakes from sessions the current registry admits."""

    eligible: list[Dict[str, Any]] = []
    excluded: list[Dict[str, Any]] = []
    for raw in rows:
        row = dict(raw)
        if not row.get("required_fact_kinds"):
            row["current_v3_exclusion_reason"] = "empty_required_facts"
            excluded.append(row)
        elif not row.get("actions"):
            row["current_v3_exclusion_reason"] = "no_executable_action"
            excluded.append(row)
        else:
            eligible.append(row)
    return eligible[:limit], excluded


def prepare_canary(
    *,
    trace_root: Path,
    source_root: Path,
    compile_commands_path: Path,
    limit: int,
) -> Dict[str, Any]:
    trace_root = trace_root.resolve()
    source_root = source_root.resolve()
    compile_commands_path = compile_commands_path.resolve()
    if limit < 1:
        raise DecisionTraceError("limit must be positive")
    manifest = _json(trace_root / "decision_trace_manifest.json")
    service = FunctionIRFactService(compile_commands_path, enabled=True)
    historical_rows: list[Dict[str, Any]] = []
    source_hashes: Dict[str, str] = {}
    historical_v3 = _v3_records(trace_root)
    for cluster_uid, trace, entered in historical_v3:
        structured = _model_input(trace_root, trace)
        evidence_slice = structured.get("evidence_slice")
        evidence_slice = evidence_slice if isinstance(evidence_slice, Mapping) else {}
        obligation = evidence_slice.get("obligation")
        if not isinstance(obligation, Mapping):
            raise DecisionTraceError(f"{cluster_uid} has no structured obligation")
        relative_file, line = _location(obligation)
        source_file = _inside(source_root, relative_file)
        source_hashes[relative_file] = hashlib.sha256(source_file.read_bytes()).hexdigest()
        details = entered.get("details")
        details = details if isinstance(details, Mapping) else {}
        required = tuple(
            sorted(
                {
                    str(value).strip().lower()
                    for value in details.get("required_fact_kinds") or []
                    if str(value).strip()
                }
            )
        )
        decision_facts = evidence_slice.get("decision_facts")
        decision_facts = dict(decision_facts) if isinstance(decision_facts, Mapping) else {}
        issue: Dict[str, Any] = {
            "candidate_uid": str(obligation.get("candidate_uid") or ""),
            "validation_cluster_uid": cluster_uid,
            "function": str(obligation.get("function") or ""),
            "file": str(source_file),
            "line": line,
            "category": str(obligation.get("category") or ""),
            "defect_family": str(obligation.get("defect_family") or ""),
            "source": _endpoint(obligation.get("source_uid")),
            "sink": _endpoint(obligation.get("sink_uid")),
            "security_obligation": {
                **dict(obligation),
                "required_fact_kinds": list(required),
            },
            "decision_fact_slice": decision_facts,
            "missing_fact_kinds": list(required),
        }
        actions = service.actions(issue, evidence_slice, required)
        action_results = []
        closed: set[str] = set()
        for action in actions:
            result = service.execute(action, issue, evidence_slice)
            fact = result.fact
            if isinstance(fact, Mapping):
                closed.update(
                    str(value) for value in fact.get("satisfies_fact_kinds") or [] if str(value)
                )
            action_results.append(
                {
                    "action_id": action.action_id,
                    "fact_kind": action.fact_kind,
                    "status": result.status,
                    "reason_code": result.reason_code,
                    "certificate_sha256": str(result.certificate.get("certificate_sha256") or ""),
                    "certificate_coverage": str(result.certificate.get("coverage") or ""),
                    "closed_clause": action.fact_kind in closed,
                }
            )
        historical_rows.append(
            {
                "validation_cluster_uid": cluster_uid,
                "candidate_uids": list(trace.get("candidate_uids") or []),
                "function": issue["function"],
                "file": relative_file,
                "required_fact_kinds": list(required),
                "action_count": len(actions),
                "closed_fact_kinds": sorted(closed),
                "remaining_fact_kinds": sorted(set(required) - closed),
                "actions": action_results,
            }
        )
    rows, excluded = _select_currently_eligible(historical_rows, limit=limit)
    closed_rows = sum(bool(value["closed_fact_kinds"]) for value in rows)
    empty_required = sum(
        value.get("current_v3_exclusion_reason") == "empty_required_facts" for value in excluded
    )
    no_action = sum(
        value.get("current_v3_exclusion_reason") == "no_executable_action" for value in excluded
    )
    expected_sessions = min(limit, len(historical_rows) - len(excluded))
    body: Dict[str, Any] = {
        "schema_version": "zscope.v3-action-canary-preflight.v1",
        "trace_manifest_sha256": str(manifest.get("manifest_sha256") or ""),
        "trace_manifest_complete": manifest.get("complete") is True,
        "source_root_sha256": _sha(source_hashes),
        "source_file_sha256": dict(sorted(source_hashes.items())),
        "compile_commands_sha256": hashlib.sha256(compile_commands_path.read_bytes()).hexdigest(),
        "historical_v3_cluster_count": len(historical_rows),
        "currently_eligible_cluster_count": len(historical_rows) - len(excluded),
        "selected_cluster_count": len(rows),
        "clusters_closing_at_least_one_clause": closed_rows,
        "historical_clusters_excluded_empty_required_facts": empty_required,
        "historical_clusters_excluded_no_executable_action": no_action,
        "ready_for_model_canary": bool(
            expected_sessions >= 3 and len(rows) == expected_sessions and closed_rows >= 3
        ),
        "model_calls": 0,
        "truth_inputs": 0,
        "clusters": rows,
        "historical_v3_exclusions": excluded,
    }
    body["artifact_sha256"] = _sha(body)
    return body


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prepare a no-model, answer-free V3 EvidenceAction canary"
    )
    parser.add_argument("--trace-root", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--compile-commands", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    result = prepare_canary(
        trace_root=args.trace_root,
        source_root=args.source_root,
        compile_commands_path=args.compile_commands,
        limit=args.limit,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0 if result["ready_for_model_canary"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
