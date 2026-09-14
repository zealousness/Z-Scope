from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple


def _feature_value(issue: Dict[str, Any], kind: str) -> str:
    aliases = {
        "fingerprint": ("stable_fingerprint", "candidate_uid"),
        "source_context_fingerprint": ("source_context_fingerprint",),
        "ast": ("ast_fingerprint", "ast_feature_fingerprint"),
        "cfg": ("cfg_fingerprint", "cfg_feature_fingerprint"),
        "call_graph": ("call_graph_fingerprint", "call_graph_feature_fingerprint"),
        "type": ("type_fingerprint", "type_feature_fingerprint"),
        "macro": ("macro_fingerprint", "macro_feature_fingerprint"),
    }
    for key in aliases.get(kind, (kind,)):
        value = issue.get(key)
        if value:
            return str(value)
    return ""


def _matching_features(issue: Dict[str, Any], pattern: Dict[str, Any]) -> List[Tuple[str, str]]:
    matches: List[Tuple[str, str]] = []
    for feature in pattern.get("trigger_features", []):
        if not isinstance(feature, dict) or not feature.get("matchable"):
            continue
        kind = str(feature.get("kind") or "")
        value = str(feature.get("value") or "")
        if value and _feature_value(issue, kind) == value:
            matches.append((kind, value))
    return matches


def match_patterns(issue: Dict[str, Any], patterns: Iterable[Dict[str, Any]], *, project_id: str, limit: int = 3) -> List[Dict[str, Any]]:
    results = []
    for pattern in patterns:
        if pattern.get("status") != "advisory" or pattern.get("project_id") != project_id:
            continue
        scope = pattern.get("scope") or {}
        if scope.get("rule") and scope.get("rule") != issue.get("rule"):
            continue
        category = issue.get("category") or issue.get("defect_class") or issue.get("subcategory")
        scoped_category = scope.get("category") or scope.get("defect_class") or scope.get("subcategory")
        if scoped_category and scoped_category != category:
            continue
        source_fingerprints = {str(value) for value in pattern.get("source_fingerprints", []) if value}
        current_source = str(issue.get("source_context_fingerprint") or "")
        if source_fingerprints and (not current_source or current_source not in source_fingerprints):
            continue
        matches = _matching_features(issue, pattern)
        if not matches:
            continue
        bases = [kind for kind, _value in matches]
        results.append({"pattern_id": pattern.get("pattern_id"), "summary": pattern.get("false_positive_reason", ""), "match_basis": bases, "required_checks": pattern.get("required_checks", []), "counter_conditions": pattern.get("counter_conditions", []), "evidence_refs": pattern.get("evidence_refs", []), "authority": "advisory"})
        if len(results) >= limit:
            break
    return results
