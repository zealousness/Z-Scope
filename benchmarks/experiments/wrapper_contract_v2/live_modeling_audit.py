"""Audit committed modeling attempts and usage spans while a retained trial runs."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

from zscope.reporting.json_io import write_json_atomic


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.workspace / "scan-input/.zscope_snapshots"
    args.output.mkdir(parents=True, exist_ok=True)
    errors: Counter = Counter()
    kinds: Counter = Counter()
    units: dict = {}
    metadata_tokens = failed_tokens = 0
    for path in (root / ".semantic-modeling").glob("*.attempts.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        attempts = data.get("attempts") or []
        uid = data.get("audit_unit_uid") or path.stem
        symbol = json.loads(data["symbol"])
        units[uid] = {
            "symbol": symbol, "success": data.get("success"), "attempts": attempts,
            "metadata_tokens": sum(int(a.get("cumulative_total_tokens") or 0) for a in attempts),
        }
        metadata_tokens += units[uid]["metadata_tokens"]
        if len(attempts) > 1 or not data.get("success"):
            shutil.copy2(path, args.output / path.name)
        for attempt in attempts:
            if not attempt.get("success"):
                failed_tokens += int(attempt.get("cumulative_total_tokens") or 0)
                errors.update(attempt.get("validation_errors") or [attempt.get("error") or "unknown"])
    by_unit: Counter = Counter()
    by_kind: Counter = Counter()
    call_ids = set()
    for path in root.glob("llm_usage_events_*.jsonl"):
        contents = path.read_bytes()
        for line in contents[:contents.rfind(b"\n") + 1].splitlines():
            row = json.loads(line)
            if row.get("agent") != "semantic_modeler":
                continue
            call_id = (path.name, row.get("call_id"))
            if call_id in call_ids:
                continue
            call_ids.add(call_id)
            attribution = row.get("attribution") or {}
            uid = row.get("audit_unit_uid") or attribution.get("audit_unit_uid") or "unattributed"
            tokens = int(row.get("total_tokens") or 0)
            by_unit[uid] += tokens
            by_kind[row.get("call_kind") or attribution.get("call_kind") or "unknown"] += tokens
    for path in root.glob("*.json"):
        obj = json.loads(path.read_text(encoding="utf-8"))
        if obj.get("func_name"):
            kinds[obj.get("snapshot_kind") or "unknown"] += 1
    for uid, row in units.items():
        row["usage_span_tokens"] = by_unit[uid]
    result = {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "note": "Only latest committed attempt records have final status; absent records may still be running. After recovery, earlier attempts may have been superseded and remain in the interruption archive. Failed-attempt tokens are attempt metadata, distinct from provider-span accounting.",
        "snapshot_kinds": dict(kinds), "completed_llm_units": len(units),
        "failed_units": [row["symbol"] for row in units.values() if not row["success"]],
        "retried_units": [row for row in units.values() if len(row["attempts"]) > 1],
        "failed_attempt_tokens": failed_tokens, "completed_attempt_metadata_tokens": metadata_tokens,
        "usage_span_tokens": sum(by_unit.values()), "usage_span_tokens_by_attempt": dict(by_kind),
        "errors": dict(errors),
        "most_expensive_completed_units": sorted(units.values(), key=lambda row: -row["usage_span_tokens"])[:12],
    }
    write_json_atomic(args.output / "summary.json", result)
    print(json.dumps({k: v for k, v in result.items() if k not in {"most_expensive_completed_units", "retried_units", "note"}}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
