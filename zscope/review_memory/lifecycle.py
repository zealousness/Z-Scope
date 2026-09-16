from __future__ import annotations

from typing import Any, Dict


def qualify_for_advisory(pattern: Dict[str, Any]) -> bool:
    if not pattern.get("project_id") or pattern.get("status") not in {"proposed", "advisory"}:
        return False
    contract = pattern.get("match_contract") or {}
    groups = contract.get("groups", []) if isinstance(contract, dict) else []
    predicates = [p for group in groups if isinstance(group, dict) for p in group.get("all", []) if isinstance(p, dict)]
    features = [item for item in pattern.get("trigger_features", []) if isinstance(item, dict)]
    if not predicates and not any(item.get("matchable") and item.get("value") for item in features):
        return False
    if predicates and any(not p.get("path") or p.get("operator", "eq") not in {"eq", "contains"} for p in predicates):
        return False
    return bool(
        pattern.get("evidence_refs")
        and (pattern.get("required_checks") or pattern.get("counter_conditions"))
    )


def qualify_and_activate(pattern: Dict[str, Any]) -> Dict[str, Any]:
    if not qualify_for_advisory(pattern):
        raise ValueError("pattern does not satisfy advisory qualification")
    result = dict(pattern)
    result["status"] = "advisory"
    return result
