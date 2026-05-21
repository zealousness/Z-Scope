"""Backend signal candidate conversion helpers."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List


RESOURCE_ACQUIRE_KINDS = {"allocator", "calloc", "reallocator", "resource", "resource_acquire"}


def resource_release_pairs_from_overlay(overlay: Dict[str, Any]) -> List[tuple[str, str, str]]:
    pairs: List[tuple[str, str, str]] = []
    for row in overlay.get("resource_models", []) if isinstance(overlay, dict) else []:
        if not isinstance(row, dict):
            continue
        kind = str(row.get("kind") or "").lower()
        if kind not in RESOURCE_ACQUIRE_KINDS:
            continue
        acquire = str(row.get("name") or "").strip()
        for pair in split_config_pair_names(row.get("pair")):
            if acquire and pair:
                pairs.append((acquire, pair, str(row.get("source") or "user_config")))
    seen = set()
    deduped = []
    for item in pairs:
        key = (item[0], item[1])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def split_config_pair_names(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def clang_pair_row_to_candidate(
    row: Dict[str, Any],
    *,
    entry_func: str,
    pair_source: str,
) -> Dict[str, Any]:
    func = str(row.get("function") or "")
    file_path = str(row.get("file_path") or "")
    line = int(row.get("line") or 0)
    acquire = str(row.get("acquire_func") or "")
    release = str(row.get("release_func") or "")
    candidate_id = f"CLANG_PAIR_MEMORY_LEAK_{func}_{line}_{uuid.uuid5(uuid.NAMESPACE_URL, acquire + release).hex[:8]}"
    positive = [
        f"Clang/KnowledgeDB call graph shows `{func}` calls `{acquire}` at {file_path}:{line}",
        f"No same-function call to configured release `{release}` was found in Clang call_edges",
        f"Pair source: {pair_source}",
    ]
    evidence = {
        "candidate_id": candidate_id,
        "candidate_source": "clang_knowledgedb_call_edges",
        "defect_class": "memory_leak",
        "rule": "configured_acquire_without_release",
        "source": {"expression": acquire, "file": file_path, "line": line},
        "sink": {"operation": f"missing {release}", "file": file_path, "line": line},
        "path": {
            "function": func,
            "entry_function": entry_func,
            "backend": "Clang KnowledgeDB call_edges",
            "complete_in_function": False,
            "path_constraints": [
                "same function lacks configured release call",
                "validator must check ownership transfer and caller-side cleanup",
            ],
        },
        "positive_evidence": positive,
        "negative_evidence": ["ownership transfer or caller-side release has not been ruled out"],
        "resource_pair": {"acquire": acquire, "release": release, "source": pair_source},
    }
    return {
        "id": candidate_id,
        "candidate_id": candidate_id,
        "function": func,
        "location": f"{file_path}:{line}" if file_path else f"{func}:{line}",
        "category": "memory_leak",
        "subcategory": "memory_leak",
        "defect_class": "memory_leak",
        "finding_kind": "clang_callgraph_candidate",
        "candidate_source": "clang_knowledgedb_call_edges",
        "rule": "configured_acquire_without_release",
        "description": f"`{func}` calls configured acquire `{acquire}` without same-function `{release}` in Clang call graph.",
        "root_cause": "Configured resource acquisition has no matching release in the same extracted function body.",
        "suggested_fix": "Release the resource on all paths or document/validate ownership transfer to another owner.",
        "confidence": 0.68,
        "rule_confidence": 0.68,
        "impact_level": "medium",
        "reasoning": "Clang KnowledgeDB call-edge candidate normalized into Z-SCOPE evidence pack.",
        "source": acquire,
        "sink": f"missing {release}",
        "positive_evidence": positive,
        "negative_evidence": evidence["negative_evidence"],
        "evidence_pack": evidence,
    }


def joern_rule_match_to_candidate(match: Any, entry_func: str = "") -> Dict[str, Any]:
    data = match.to_dict() if hasattr(match, "to_dict") else dict(match)
    rule_id = str(data.get("rule_id") or data.get("rule") or "joern_rule")
    func = str(data.get("function") or data.get("func_name") or entry_func)
    file_path = str(data.get("file_path") or data.get("filename") or "")
    line = int(data.get("line_number") or data.get("lineNumber") or 0)
    defect_class = class_from_joern_category(str(data.get("category") or rule_id))
    candidate_id = f"JOERN_{defect_class.upper()}_{func}_{line}_{uuid.uuid5(uuid.NAMESPACE_URL, rule_id).hex[:8]}"
    source = str(data.get("rule_name") or rule_id)
    sink = str(data.get("code_snippet") or data.get("code") or rule_id)
    evidence_items = data.get("evidence") if isinstance(data.get("evidence"), list) else []
    positive = [f"Joern CPG rule `{rule_id}` matched `{func}` at {file_path}:{line}"]
    for item in evidence_items[:6]:
        positive.append(json.dumps(item, ensure_ascii=False, default=str))
    evidence = {
        "candidate_id": candidate_id,
        "candidate_source": "joern_cpg",
        "defect_class": defect_class,
        "rule": rule_id,
        "source": {"expression": source, "file": file_path, "line": line},
        "sink": {"operation": sink, "file": file_path, "line": line},
        "path": {
            "function": func,
            "entry_function": entry_func,
            "backend": "Joern CPG",
            "complete_in_function": False,
        },
        "positive_evidence": positive,
        "negative_evidence": [],
        "raw_match": data,
    }
    confidence = max(0.0, min(1.0, float(data.get("score") or 6.0) / 10.0))
    return {
        "id": candidate_id,
        "candidate_id": candidate_id,
        "function": func,
        "location": f"{file_path}:{line}" if file_path else f"{func}:{line}",
        "category": defect_class,
        "subcategory": defect_class,
        "defect_class": defect_class,
        "finding_kind": "joern_cpg_candidate",
        "candidate_source": "joern_cpg",
        "rule": rule_id,
        "description": f"Joern CPG rule `{rule_id}` reported `{source}` in `{func}`.",
        "root_cause": "Joern CPG query found a configured resource/protocol pattern requiring validation.",
        "suggested_fix": "Validate the CPG path and repair the missing release, lifetime, or protocol operation.",
        "confidence": confidence,
        "rule_confidence": confidence,
        "impact_level": "high" if defect_class in {"use_after_free", "double_free", "memory_leak"} else "medium",
        "reasoning": "Joern CPG candidate normalized into Z-SCOPE evidence pack.",
        "source": source,
        "sink": sink,
        "positive_evidence": positive,
        "negative_evidence": [],
        "evidence_pack": evidence,
    }


def class_from_backend_bug(bug_type: str) -> str:
    text = bug_type.replace("_", " ").replace("-", " ").lower()
    if any(word in text for word in ("double", "dfree")):
        return "double_free"
    if any(word in text for word in ("uaf", "use after", "dangling")):
        return "use_after_free"
    if "leak" in text:
        return "memory_leak"
    if any(word in text for word in ("overflow", "bounds", "oob")):
        return "bounds"
    if "race" in text:
        return "race"
    return "backend_signal"


def class_from_joern_category(category: str) -> str:
    text = category.replace("_", " ").replace("-", " ").lower()
    if any(word in text for word in ("double", "dfree")):
        return "double_free"
    if any(word in text for word in ("uaf", "use after", "dangling")):
        return "use_after_free"
    if any(word in text for word in ("null", "deref")):
        return "null_pointer_dereference"
    if any(word in text for word in ("path traversal", "directory traversal")):
        return "path_traversal"
    if any(word in text for word in ("integer", "divide", "division", "modulo", "shift", "wrap", "trunc")):
        return "integer_overflow"
    if any(word in text for word in ("leak", "resource", "alloc", "memory")):
        return "memory_leak"
    if any(word in text for word in ("bounds", "overflow", "buffer", "oob")):
        return "bounds"
    if any(word in text for word in ("format", "printf")):
        return "format_string"
    if "command" in text or "system" in text:
        return "command_injection"
    return text.replace(" ", "_") or "joern_signal"
