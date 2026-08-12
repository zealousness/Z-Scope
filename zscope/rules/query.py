"""Shared read-only query/serialization service for CLI and Web rule views."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from .catalog import (
    EffectiveRuleSet,
    SUPPORTED_ENGINES,
    SUPPORTED_LANGUAGES,
    SUPPORTED_STATUSES,
    serialize_effective_rules,
)


EFFECTIVE_STATUSES = frozenset({"enabled", "disabled", "unavailable"})


def query_effective_rules(
    effective: EffectiveRuleSet,
    *,
    language: Optional[str] = None,
    engine: Optional[str] = None,
    skill: Optional[str] = None,
    status: Optional[str] = None,
    query: Optional[str] = None,
) -> Dict[str, Any]:
    """Serialize one EffectiveRuleSet and apply presentation-only filters."""

    filters = {
        "language": str(language or "").strip(),
        "engine": str(engine or "").strip(),
        "skill": str(skill or "").strip(),
        "status": str(status or "").strip(),
        "q": str(query or "").strip(),
    }
    validate_rule_filters(filters)
    payload = serialize_effective_rules(effective)
    all_rules = [dict(item) for item in payload.get("rules", [])]
    rows = [item for item in all_rules if _matches(item, filters)]
    payload["catalog_summary"] = dict(payload.get("summary") or {})
    payload["summary"] = _summary(rows)
    payload["filters"] = filters
    payload["facets"] = {
        "languages": _facet(all_rules, "language"),
        "engines": _facet(all_rules, "engine"),
        "skills": _facet(all_rules, "skill"),
        "statuses": _facet(all_rules, "effective_status"),
        "catalog_statuses": _facet(all_rules, "status"),
    }
    payload["rules"] = rows
    payload["enabled_ids"] = [
        str(item.get("id") or "") for item in rows if item.get("effective_status") == "enabled"
    ]
    payload["disabled"] = [
        {"id": item.get("id"), "reason": item.get("effective_reason")}
        for item in rows
        if item.get("effective_status") == "disabled"
    ]
    payload["unavailable"] = [
        {"id": item.get("id"), "reason": item.get("effective_reason")}
        for item in rows
        if item.get("effective_status") == "unavailable"
    ]
    return payload


def validate_rule_filters(filters: Mapping[str, str]) -> None:
    language = str(filters.get("language") or "")
    if language and language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"language must be one of: {', '.join(sorted(SUPPORTED_LANGUAGES))}")
    engine = str(filters.get("engine") or "")
    if engine and engine not in SUPPORTED_ENGINES:
        raise ValueError(f"engine must be one of: {', '.join(sorted(SUPPORTED_ENGINES))}")
    status = str(filters.get("status") or "")
    allowed_statuses = EFFECTIVE_STATUSES | SUPPORTED_STATUSES
    if status and status not in allowed_statuses:
        raise ValueError(f"status must be one of: {', '.join(sorted(allowed_statuses))}")


def _matches(item: Mapping[str, Any], filters: Mapping[str, str]) -> bool:
    for field in ("language", "engine", "skill"):
        expected = filters.get(field)
        if expected and item.get(field) != expected:
            return False
    status = filters.get("status")
    if status and status not in {item.get("status"), item.get("effective_status")}:
        return False
    needle = str(filters.get("q") or "").casefold()
    if not needle:
        return True
    haystack = "\n".join(
        str(item.get(field) or "") for field in ("id", "cwe", "title", "defect_class", "summary")
    ).casefold()
    return needle in haystack


def _summary(rules: list[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "total": len(rules),
        "enabled": sum(item.get("effective_status") == "enabled" for item in rules),
        "disabled": sum(item.get("effective_status") == "disabled" for item in rules),
        "unavailable": sum(item.get("effective_status") == "unavailable" for item in rules),
    }


def _facet(rules: list[Dict[str, Any]], field: str) -> list[str]:
    return sorted({str(item.get(field) or "") for item in rules if item.get(field)})
