"""Audit modeling attempts from thread logs without inventing token attribution."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re


THREAD = re.compile(r"\[T:(zscope-modeling_\d+)\]")
START = re.compile(r"\[semantic-retry\] starting .*index_name=(.*?) attempt=(\d+)/(\d+)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    args = parser.parse_args()
    active, rows = {}, {}
    unassigned = 0
    for line in (args.run / "scan.log").read_text(encoding="utf-8").splitlines():
        thread_match = THREAD.search(line)
        if not thread_match:
            continue
        thread = thread_match[1]
        start = START.search(line)
        if start:
            index, attempt = start[1], int(start[2])
            active[thread] = (index, attempt)
            row = rows.setdefault(index, {"attempts": [], "http_200_by_attempt": Counter()})
            row["attempts"].append(attempt)
        if 'POST /v1/chat/completions HTTP/1.1" 200' in line:
            if thread in active:
                index, attempt = active[thread]
                rows[index]["http_200_by_attempt"][attempt] += 1
            else:
                unassigned += 1
    publication = args.run / "semantic-publication/publication.json"
    if not publication.exists():
        publication = args.run / "semantic-evidence/.semantic-modeling/publication.json"
    snapshots = {}
    if publication.exists():
        snapshots = {
            snapshot["index_name"]: snapshot
            for snapshot in json.loads(publication.read_text(encoding="utf-8"))["snapshots"]
        }
    result_rows = []
    for index, row in rows.items():
        snapshot = snapshots.get(index)
        result_rows.append(
            {
                "index_name": index,
                "attempts": row["attempts"],
                "http_200_observations": sum(row["http_200_by_attempt"].values()),
                "http_200_by_attempt": dict(row["http_200_by_attempt"]),
                "normalized_contract_count": (
                    len(snapshot["normalized_interface_contracts"]) if snapshot else None
                ),
            }
        )
    result = {
        "note": "HTTP response observations can be attributed by sequential worker logs; token events lack symbol identity, so per-symbol token attribution is unavailable. HTTP 200 does not imply valid terminal output. Snapshot absence during an active scan is not a failure.",
        "attempted_symbols": len(rows),
        "attempts": sum(len(row["attempts"]) for row in rows.values()),
        "http_200_observations": sum(row["http_200_observations"] for row in result_rows),
        "retry_http_200_observations": sum(
            count
            for row in rows.values()
            for attempt, count in row["http_200_by_attempt"].items()
            if attempt > 1
        ),
        "unassigned_http_200_observations": unassigned,
        "symbols": sorted(result_rows, key=lambda row: -row["http_200_observations"]),
    }
    (args.run / "modeling-attempt-audit.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({k: v for k, v in result.items() if k != "symbols"}, ensure_ascii=False))


if __name__ == "__main__":
    main()
