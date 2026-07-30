"""Stream a legacy report and replay CandidateEnvelope v3 review governance."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
from typing import Any, Dict, Iterator

from zscope.orchestration.candidate_envelope import (
    CANDIDATE_SCHEMA_VERSION,
    annotate_issue_identity,
)
from zscope.reporting.views import (
    NEEDS_REVIEW_DISPOSITIONS,
    NEEDS_REVIEW_STATUSES,
    OPERATIONAL_DISPOSITIONS,
)


def iter_array_for_key(
    path: Path,
    key: str,
    *,
    chunk_size: int = 1024 * 1024,
) -> Iterator[Dict[str, Any]]:
    """Yield object items from the first JSON array matching ``key``."""

    marker = f'"{key}": ['
    decoder = json.JSONDecoder()
    with path.open("r", encoding="utf-8") as stream:
        buffer = ""
        while marker not in buffer:
            chunk = stream.read(chunk_size)
            if not chunk:
                raise ValueError(f"JSON array key not found: {key}")
            buffer = (buffer + chunk)[-max(len(marker) * 2, chunk_size * 2) :]
        buffer = buffer.split(marker, 1)[1]

        while True:
            buffer = buffer.lstrip()
            if buffer.startswith("]"):
                return
            if buffer.startswith(","):
                buffer = buffer[1:].lstrip()
            while True:
                try:
                    value, end = decoder.raw_decode(buffer)
                    break
                except json.JSONDecodeError:
                    chunk = stream.read(chunk_size)
                    if not chunk:
                        raise ValueError(f"Truncated JSON array: {key}")
                    buffer += chunk
            buffer = buffer[end:]
            if isinstance(value, dict):
                yield value


def replay(
    report_path: Path,
    *,
    project_id: str,
    project_root: str,
    revision: str,
) -> Dict[str, Any]:
    raw_observations = 0
    actionable_observations = 0
    candidate_uids: set[str] = set()
    validation_groups: set[str] = set()
    occurrence_uids: set[str] = set()
    operational_uids: set[str] = set()
    by_disposition: Counter[str] = Counter()
    by_reason: Counter[str] = Counter()

    for ordinal, item in enumerate(
        iter_array_for_key(report_path, "audit_observations")
    ):
        raw_observations += 1
        disposition = str(
            item.get("candidate_disposition") or ""
        ).lower()
        validation = str(item.get("validation_status") or "").lower()
        reason = str(item.get("reason") or item.get("deferred_reason") or "")
        if disposition:
            by_disposition[disposition] += 1
        if reason:
            by_reason[reason] += 1

        if disposition in OPERATIONAL_DISPOSITIONS:
            operational_uids.add(
                str(
                    item.get("operational_uid")
                    or item.get("candidate_uid")
                    or f"operational:{ordinal}"
                )
            )
            continue
        if (
            disposition not in NEEDS_REVIEW_DISPOSITIONS
            and validation not in NEEDS_REVIEW_STATUSES
        ):
            continue

        actionable_observations += 1
        envelope = annotate_issue_identity(
            item,
            project_id=project_id,
            project_root=project_root,
            revision=revision,
            entry_function=str(
                item.get("entry_identity")
                or item.get("entry_function")
                or item.get("analyzed_from")
                or ""
            ),
            ordinal=ordinal,
            default_disposition="needs_review",
        )
        candidate_uids.add(envelope.candidate_uid)
        validation_groups.add(envelope.validation_cluster_uid)
        raw_occurrences = item.get("occurrence_uids")
        if isinstance(raw_occurrences, list) and raw_occurrences:
            occurrence_uids.update(
                str(value) for value in raw_occurrences if str(value)
            )
        else:
            occurrence_uid = str(item.get("occurrence_uid") or "")
            if occurrence_uid:
                occurrence_uids.add(occurrence_uid)
            else:
                occurrence_uids.add(envelope.occurrence_uid)

    raw_occurrence_count = len(occurrence_uids)
    displayed = len(validation_groups)
    return {
        "candidate_schema_version": CANDIDATE_SCHEMA_VERSION,
        "report": str(report_path),
        "raw_observation_count": raw_observations,
        "actionable_security_observation_count": actionable_observations,
        "raw_projection_count": actionable_observations,
        "raw_occurrence_count": raw_occurrence_count,
        "unique_candidate_count": len(candidate_uids),
        "unique_validation_group_count": displayed,
        "displayed_review_count": displayed,
        "operational_obligation_count": len(operational_uids),
        "grouped_alias_count": max(0, actionable_observations - displayed),
        "retained_occurrence_count": raw_occurrence_count,
        "occurrence_loss_count": 0,
        "validation_not_completed_count": int(
            by_reason.get("validation_not_completed", 0)
        ),
        "pending_validation_count": sum(
            count
            for reason, count in by_reason.items()
            if reason.startswith("nonterminal_status:")
        ),
        "reduction_percent": round(
            (1.0 - displayed / actionable_observations) * 100.0,
            4,
        )
        if actionable_observations
        else 0.0,
        "by_disposition": dict(sorted(by_disposition.items())),
        "by_reason": dict(sorted(by_reason.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--project-id", default="range")
    parser.add_argument("--project-root", default="test/range")
    parser.add_argument("--revision", default="")
    parser.add_argument("--max-review", type=int, default=1500)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    summary = replay(
        args.report,
        project_id=args.project_id,
        project_root=args.project_root,
        revision=args.revision,
    )
    encoded = json.dumps(summary, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    if int(summary["displayed_review_count"]) > max(0, args.max_review):
        return 1
    if int(summary["occurrence_loss_count"]) != 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
