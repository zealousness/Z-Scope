"""Read-only live telemetry; no scanner inputs or model requests are modified."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import re


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    logs = {name: (args.run / f"{name}.log") for name in ("scan", "index", "score")}
    phase = next((name for name in ("score", "scan", "index") if logs[name].exists()), "build")
    lines = (
        logs[phase].read_text(encoding="utf-8", errors="replace").splitlines()
        if phase in logs
        else []
    )
    snapshot_root = args.workspace / "scan-input/.zscope_snapshots"
    snapshots = []
    for path in snapshot_root.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and data.get("func_name"):
            snapshots.append(data)
    by_agent, by_kind, calls = Counter(), Counter(), Counter()
    validator_groups = set()
    for path in snapshot_root.glob("llm_usage_events_*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue  # Concurrent writer may not have finished its last line.
            agent = event.get("agent", "unknown")
            by_agent[agent] += int(event.get("total_tokens") or 0)
            by_kind[event.get("call_kind") or "unspecified"] += int(event.get("total_tokens") or 0)
            calls[agent] += 1
            group = event.get("validation_cluster_uid") or (event.get("attribution") or {}).get(
                "validation_cluster_uid"
            )
            if agent == "validator_agent" and group:
                validator_groups.add(group)
    scan = (
        logs["scan"].read_text(encoding="utf-8", errors="replace") if logs["scan"].exists() else ""
    )
    publication = snapshot_root / ".semantic-modeling/publication.json"
    result = {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "phase": phase,
        "last_log": lines[-1][:300] if lines else "",
        "saved_snapshots": len(snapshots),
        "snapshot_kinds": dict(Counter(s.get("snapshot_kind", "unknown") for s in snapshots)),
        "contracts_in_snapshots": sum(len(s.get("interface_contracts") or []) for s in snapshots),
        "model_retries": dict(
            Counter(
                re.findall(r"restarting after invalid terminal output[^\n]*reason=([^\n]*)", scan)
            )
        ),
        "calls_by_agent": dict(calls),
        "tokens_by_agent": dict(by_agent),
        "tokens_by_kind": dict(by_kind),
        "observed_validator_groups": len(validator_groups),
        "publication_available": publication.exists(),
        "score_available": (args.run / "score.json").exists(),
    }
    if publication.exists():
        stats = json.loads(publication.read_text(encoding="utf-8")).get("stats") or {}
        result["modeling"] = {k: v for k, v in stats.items() if not isinstance(v, (dict, list))}
        result["modeling"]["partial_reason_count"] = len(stats.get("partial_reasons", []))
    with (args.run / "progress.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(result, ensure_ascii=False) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
