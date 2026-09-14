from __future__ import annotations

from typing import Any, Dict


def qualify_for_advisory(pattern: Dict[str, Any]) -> bool:
    if not pattern.get("project_id") or pattern.get("status") not in {"proposed", "advisory"}:
        return False
    features = [item for item in pattern.get("trigger_features", []) if isinstance(item, dict)]
    if not any(item.get("matchable") and item.get("value") for item in features):
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
