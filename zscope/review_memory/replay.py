"""Offline paired replay of Review Memory selection.

This module deliberately does not run a scan or mutate a report. It compares
the existing report disposition with the advisory projection that would have
been supplied to Validator, so it is safe to run against archived artifacts.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .matcher import match_patterns


def _issues(payload: Any) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    values: List[Any] = list(payload.get("issues") or [])
    for bucket in (payload.get("findings"),):
        if isinstance(bucket, list):
            values.extend(bucket)
    result = []
    seen = set()
    for item in values:
        if not isinstance(item, dict):
            continue
        key = str(item.get("issue_id") or item.get("id") or item.get("dedup_key") or id(item))
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def paired_replay(
    payload: Dict[str, Any], pattern: Dict[str, Any], *, scan_id: str = "offline-replay"
) -> Dict[str, Any]:
    """Return baseline/advisory projections and conservative audit metrics."""
    issues = _issues(payload)
    project_key = str(pattern.get("project_id") or "")
    rows = []
    matched = 0
    potential_suppression = 0
    overturned = 0
    for issue in issues:
        # Paired replay is a conservative source-compatibility audit. Runtime
        # contract matching may reuse a semantic pattern across functions, but
        # replay must not claim impact for a changed archived source context.
        source_fingerprints = {str(value) for value in pattern.get("source_fingerprints", []) if value}
        current_source = str(issue.get("source_context_fingerprint") or "")
        source_compatible = not source_fingerprints or current_source in source_fingerprints
        hints = match_patterns(issue, [pattern], project_id=project_key, limit=1) if source_compatible else []
        hit = bool(hints)
        matched += int(hit)
        status = str(issue.get("validation_status") or issue.get("policy_disposition") or "")
        # A historical rejected result is not proof of a current false positive;
        # this metric is explicitly only a potential impact indicator.
        potential = hit and status in {"validated", "confirmed", "true_positive"}
        potential_suppression += int(potential)
        if hit and status in {"rejected", "false_positive"}:
            overturned += int(bool(issue.get("user_rebuttal")))
        rows.append({
            "issue_id": issue.get("issue_id") or issue.get("id") or issue.get("dedup_key"),
            "baseline": {"validation_status": status},
            "advisory": {"hints": hints, "would_inject": hit},
            "potential_false_suppression": potential,
        })
    count = len(issues)
    return {
        "schema_version": "zscope.review-memory-replay.v1",
        "mode": "offline_paired_projection",
        "pattern_id": pattern.get("pattern_id"),
        "candidate_count": count,
        "matched": matched,
        "match_rate": matched / count if count else 0.0,
        "potential_false_suppression": potential_suppression,
        "pattern_overturn_count": overturned,
        "rows": rows,
        "verdict_changed": False,
        "validator_invoked": False,
        "scan_id": scan_id,
    }
