from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

from .identity import candidate_projection, normalize_candidate_value


def _scope_matches(issue: Dict[str, Any], scope: Dict[str, Any]) -> bool:
    current = candidate_projection(issue)["fields"]
    aliases = {"rule_id": ("rule_id", "rule"), "rule": ("rule", "rule_id")}
    for path, expected in scope.items():
        if expected in (None, "", [], {}):
            continue
        keys = aliases.get(path, (path,))
        actual = next((current.get(key) for key in keys if current.get(key) not in (None, "", [], {})), None)
        if normalize_candidate_value(actual) != normalize_candidate_value(expected):
            return False
    return True


def _predicate_matches(fields: Dict[str, Any], predicate: Dict[str, Any]) -> bool:
    path = str(predicate.get("path") or "")
    if path not in fields:
        return False
    actual = normalize_candidate_value(fields[path])
    expected = normalize_candidate_value(predicate.get("value"))
    if str(predicate.get("operator") or "eq") == "contains":
        return expected in actual if isinstance(actual, list) else str(expected) in str(actual)
    return bool(actual == expected)


def _contract_matches(issue: Dict[str, Any], contract: Dict[str, Any]) -> Tuple[List[str], bool]:
    fields = candidate_projection(issue)["fields"]
    for group in contract.get("groups", []):
        predicates = group.get("all", []) if isinstance(group, dict) else []
        if predicates and all(_predicate_matches(fields, predicate) for predicate in predicates):
            return [str(predicate.get("path")) for predicate in predicates], True
    return [], False


def _legacy_feature_value(issue: Dict[str, Any], kind: str) -> str:
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
        if issue.get(key):
            return str(issue[key])
    return ""


def _legacy_matches(issue: Dict[str, Any], pattern: Dict[str, Any]) -> List[str]:
    return [
        str(feature.get("kind"))
        for feature in pattern.get("trigger_features", [])
        if isinstance(feature, dict) and feature.get("matchable")
        and feature.get("value")
        and _legacy_feature_value(issue, str(feature.get("kind"))) == str(feature.get("value"))
    ]


def match_patterns(issue: Dict[str, Any], patterns: Iterable[Dict[str, Any]], *, project_id: str, limit: int = 3) -> List[Dict[str, Any]]:
    if limit <= 0:
        return []
    results: List[Dict[str, Any]] = []
    for pattern in patterns:
        if pattern.get("status") != "advisory" or pattern.get("project_id") != project_id:
            continue
        if not _scope_matches(issue, pattern.get("scope") or {}):
            continue
        contract = pattern.get("match_contract")
        if isinstance(contract, dict) and contract.get("groups"):
            bases, matched = _contract_matches(issue, contract)
        else:
            bases = _legacy_matches(issue, pattern)
            matched = bool(bases)
            source_fingerprints = {str(value) for value in pattern.get("source_fingerprints", []) if value}
            current_source = str(issue.get("source_context_fingerprint") or "")
            if source_fingerprints and (not current_source or current_source not in source_fingerprints):
                matched = False
        if not matched:
            continue
        results.append({
            "pattern_id": pattern.get("pattern_id"), "summary": pattern.get("false_positive_reason", ""),
            "match_basis": bases, "required_checks": pattern.get("required_checks", []),
            "counter_conditions": pattern.get("counter_conditions", []), "evidence_refs": pattern.get("evidence_refs", []),
            "authority": "advisory", "contract_digest": pattern.get("contract_digest", ""),
        })
        if len(results) >= max(0, limit):
            break
    return results
