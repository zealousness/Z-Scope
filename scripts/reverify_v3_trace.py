#!/usr/bin/env python3
"""Reclassify frozen V3 verifier events without model calls or truth data."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.cli.explain import _reverify
from zscope.orchestration.decision_trace import DecisionTraceError, load_decision_trace


def _json(path: Path) -> Dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise DecisionTraceError(f"{path} must contain one JSON object")
    return value


def reverify_trace_root(root: Path) -> Dict[str, Any]:
    root = root.resolve()
    manifest_path = root / "decision_trace_manifest.json"
    manifest = _json(manifest_path)
    traces = manifest.get("traces")
    if not isinstance(traces, Mapping):
        raise DecisionTraceError("trace manifest has no traces mapping")
    rows: list[Dict[str, Any]] = []
    counts: Counter[str] = Counter()
    fact_kind_counts: Counter[str] = Counter()
    v3_entered_count = 0
    terminal_trace_count = 0
    empty_required_fact_v3_count = 0
    for cluster_uid, record in sorted(traces.items()):
        if not isinstance(record, Mapping):
            raise DecisionTraceError(f"invalid trace record for {cluster_uid}")
        relative = Path(str(record.get("path") or ""))
        trace_path = (root / relative).resolve()
        try:
            trace_path.relative_to(root)
        except ValueError as exc:
            raise DecisionTraceError("trace path escapes the snapshot root") from exc
        trace = load_decision_trace(trace_path)
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
        counts.update(classifications)
        fact_kind_counts.update(
            str(value.get("fact_kind") or "unknown")
            for value in result.get("claim_results") or []
            if isinstance(value, Mapping)
        )
        rows.append(
            {
                "validation_cluster_uid": str(cluster_uid),
                "classifications": classifications,
                "all_claims_match": bool(result.get("all_claims_match")),
            }
        )
    return {
        "schema_version": "zscope.v3-trace-reverification.v1",
        "trace_manifest_sha256": str(manifest.get("manifest_sha256") or ""),
        "trace_manifest_complete": manifest.get("complete") is True,
        "cluster_count": len(rows),
        "terminal_trace_count": terminal_trace_count,
        "v3_entered_cluster_count": v3_entered_count,
        "v3_entered_with_empty_required_facts": empty_required_fact_v3_count,
        "verifier_cluster_count": sum(bool(value["classifications"]) for value in rows),
        "claim_count": sum(len(value["classifications"]) for value in rows),
        "classification_counts": dict(sorted(counts.items())),
        "fact_kind_counts": dict(sorted(fact_kind_counts.items())),
        "clusters": rows,
        "llm_calls": 0,
        "truth_inputs": 0,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reverify every frozen V3 claim/certificate without LLM or truth"
    )
    parser.add_argument("--trace-root", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = reverify_trace_root(args.trace_root)
    except (OSError, ValueError, json.JSONDecodeError, DecisionTraceError) as exc:
        parser.error(str(exc))
    encoded = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
