"""Collect usage and raw session outcomes; these are not final candidate verdicts."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re


def payload(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def audit(workspace, output):
    scan = workspace / "scan-input"
    groups = defaultdict(lambda: {"tokens": 0, "calls": 0, "sessions": []})
    kinds, rungs = Counter(), Counter()
    cached = 0
    tool_calls, tool_bytes, cached_replays = Counter(), Counter(), Counter()
    for path in (scan / ".zscope_snapshots").glob("llm_usage_events_*.jsonl"):
        for line in path.read_bytes().splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("agent") != "validator_agent":
                continue
            tokens = int(row.get("total_tokens") or 0)
            kinds[row.get("call_kind") or "unknown"] += tokens
            rungs[row.get("escalation_rung") or "unknown"] += tokens
            cached += int(row.get("cached_prompt_tokens") or 0)
            group = groups[row.get("validation_cluster_uid") or "unknown"]
            group["tokens"] += tokens
            group["calls"] += 1
    for path in (scan / ".zscope_conversations").rglob("*validator_agent*.jsonl"):
        session, end, evidence, last_result = {}, {}, {}, {}
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                event = row.get("event")
                if event == "session_start":
                    session = row.get("session") or {}
                elif event == "session_end":
                    end = row
                elif event == "tool_result":
                    name = str(row.get("tool_name") or "unknown")
                    tool_calls[name] += 1
                    tool_bytes[name] += int(row.get("result_size_bytes") or 0)
                    cached_replays[name] += int(bool(row.get("cached_replay")))
                elif event == "exchange":
                    if not evidence:
                        for message in row.get("request_messages") or []:
                            if message.get("role") != "user":
                                continue
                            text = str(message.get("content") or "")
                            pos = text.find('{"schema_version"')
                            if pos < 0:
                                continue
                            try:
                                evidence = json.JSONDecoder().raw_decode(text[pos:])[0]
                            except ValueError:
                                pass
                            break
                    for call in (row.get("response_message") or {}).get("tool_calls") or []:
                        function = call.get("function") or {}
                        if function.get("name") == "emit_validator_result_v3":
                            last_result = payload(function.get("arguments"))
        match = re.search(r"validation_cluster_uid=([^; ]+)", str(session.get("label") or ""))
        if not match:
            continue
        group = groups[match[1]]
        obligation = evidence.get("obligation") or {}
        if obligation:
            group["obligation"] = obligation
            group["canonical_occurrence"] = evidence.get("canonical_occurrence")
        missing = last_result.get("missing_fact_request") or {}
        group["sessions"].append({
            "path": str(path.relative_to(scan)), "label": session.get("label"),
            "ended": bool(end), "iterations": end.get("iterations"),
            "wall_seconds": end.get("wall_seconds"),
            "terminal_tool_valid": end.get("terminal_tool_valid"),
            "loop_guard_triggered": end.get("loop_guard_triggered"),
            "raw_verdict": last_result.get("verdict"),
            "raw_missing_fact_kind": missing.get("fact_kind"),
            "raw_reasoning": last_result.get("reasoning"),
        })
    family_tokens = Counter()
    for group in groups.values():
        family_tokens[(group.get("obligation") or {}).get("defect_family") or "unknown"] += group["tokens"]
    result = {"schema_version": "zscope.live-validator-audit.v1",
              "note": "Raw model session outcomes are provisional; official candidate and scoring outcomes require the frozen final report.",
              "groups_involved": len(groups), "tokens_by_call_kind": dict(kinds),
              "tokens_by_rung": dict(rungs), "tokens_by_family": dict(family_tokens),
              "cached_prompt_tokens": cached,
              "tool_result_count": dict(tool_calls), "tool_result_bytes": dict(tool_bytes),
              "cached_tool_replays": dict(cached_replays),
              "groups": dict(sorted(groups.items(), key=lambda item: item[1]["tokens"], reverse=True))}
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k:v for k,v in result.items() if k not in {"groups", "note"}}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    audit(args.workspace, args.output)
