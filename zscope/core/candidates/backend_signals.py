"""Backend signal candidate conversion helpers."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, cast


RESOURCE_ACQUIRE_KINDS = {"allocator", "calloc", "reallocator", "resource", "resource_acquire"}


def _as_dict(value: Any) -> Dict[str, Any]:
    return cast(Dict[str, Any], value) if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    return cast(List[Any], value) if isinstance(value, list) else []


def resource_release_pairs_from_overlay(overlay: Dict[str, Any]) -> List[tuple[str, str, str]]:
    from ...semantics.models import LocalPatternSemantics

    semantics = LocalPatternSemantics()
    semantics.merge_overlay(overlay if isinstance(overlay, dict) else {})
    registry = semantics.contracts
    pairs = [
        (edge.acquire.name, edge.release.name, edge.source)
        for edge in registry.pairs
        if any(c.role in RESOURCE_ACQUIRE_KINDS for c in registry.find(edge.acquire.name))
        and registry.allows(edge.acquire.name, edge.release.name)
    ]
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
    from ...semantics.contracts import parse_pair_targets

    return [target.name for target in parse_pair_targets(value) if target.name]


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
    obligation = _as_dict(row.get("lifecycle_obligation"))
    object_id = str(obligation.get("acquisition_id") or "")
    candidate_id = f"CLANG_PAIR_MEMORY_LEAK_{func}_{line}_{uuid.uuid5(uuid.NAMESPACE_URL, acquire + release + object_id).hex[:8]}"
    positive = [
        f"Clang/KnowledgeDB call graph shows `{func}` calls `{acquire}` at {file_path}:{line}",
        f"Acquisition object: {obligation.get('object') or 'unresolved'}; ownership exits require checking",
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
                "release must refer to the same object and resource domain on the relevant path",
                "return/output/container ownership transfer must be checked",
            ],
        },
        "positive_evidence": positive,
        "negative_evidence": ["ownership transfer or caller-side release has not been ruled out"],
        "resource_pair": {"acquire": acquire, "release": release, "source": pair_source},
        "contract_version": row.get("contract_version", ""),
        "call_semantics": row.get("call_semantics", []),
        "interface_inference_is_proof": False,
        "lifecycle_obligation": obligation,
        "lifecycle_gap": row.get("lifecycle_gap", ""),
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
        "description": f"核验 `{func}` 中 `{acquire}` 获取对象的释放或所有权转移义务。",
        "root_cause": "获取站点的同对象、同资源域与出口所有权义务需要闭合。",
        "suggested_fix": "Release the resource on all paths or document/validate ownership transfer to another owner.",
        "confidence": 0.68,
        "rule_confidence": 0.68,
        "impact_level": "medium",
        "reasoning": "Clang KnowledgeDB call-edge candidate normalized into Z-SCOPE evidence pack.",
        "source": acquire,
        "sink": f"missing {release}",
        "lifecycle_obligation": obligation,
        "contract_version": row.get("contract_version", ""),
        "resource_identity": object_id,
        "positive_evidence": positive,
        "negative_evidence": evidence["negative_evidence"],
        "evidence_pack": evidence,
    }


def joern_rule_match_to_candidate(match: Any, entry_func: str = "") -> Dict[str, Any]:
    data = match.to_dict() if hasattr(match, "to_dict") else dict(match)
    if data.get("provider") and data.get("source") and data.get("sink"):
        return java_provider_signal_to_candidate(data, entry_func=entry_func)
    rule_id = str(data.get("rule_id") or data.get("rule") or "joern_rule")
    func = str(data.get("function") or data.get("func_name") or entry_func)
    file_path = str(data.get("file_path") or data.get("filename") or "")
    line = int(data.get("line_number") or data.get("lineNumber") or 0)
    defect_class = class_from_joern_category(str(data.get("category") or rule_id))
    candidate_id = f"JOERN_{defect_class.upper()}_{func}_{line}_{uuid.uuid5(uuid.NAMESPACE_URL, rule_id).hex[:8]}"
    source = str(data.get("rule_name") or rule_id)
    sink = str(data.get("code_snippet") or data.get("code") or rule_id)
    evidence_items = _as_list(data.get("evidence"))
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
        "description": f"Joern CPG 规则 `{rule_id}` 在 `{func}` 中报告了 `{source}`。",
        "root_cause": "Joern CPG 查询发现了一个需要验证的配置资源/协议模式。",
        "suggested_fix": "Validate the CPG path and repair the missing release, lifetime, or protocol operation.",
        "confidence": confidence,
        "rule_confidence": confidence,
        "impact_level": (
            "high" if defect_class in {"use_after_free", "double_free", "memory_leak"} else "medium"
        ),
        "reasoning": "Joern CPG candidate normalized into Z-SCOPE evidence pack.",
        "source": source,
        "sink": sink,
        "positive_evidence": positive,
        "negative_evidence": [],
        "evidence_pack": evidence,
    }


def java_provider_signal_to_candidate(
    signal: Dict[str, Any], entry_func: str = ""
) -> Dict[str, Any]:
    """Normalize Java provider signals into evidence-only candidates."""

    provider = str(signal.get("provider") or "java_signal")
    rule_id = str(signal.get("rule_id") or signal.get("rule") or f"{provider}_signal")
    defect_class = class_from_joern_category(
        str(signal.get("category") or signal.get("defect_class") or rule_id)
    )
    source = _as_dict(signal.get("source"))
    sink = _as_dict(signal.get("sink"))
    path = _as_list(signal.get("path"))
    file_path = str(sink.get("file") or source.get("file") or "")
    line = int(sink.get("line") or source.get("line") or 0)
    func = str(
        sink.get("function")
        or source.get("function")
        or (path[-1].get("method") if path and isinstance(path[-1], dict) else "")
        or entry_func
    )
    precision = str(signal.get("precision") or "source_level_approx")
    confidence = float(signal.get("confidence") or signal.get("score") or 6.0)
    if confidence > 1.0:
        confidence = max(0.0, min(1.0, confidence / 10.0))
    candidate_id = (
        f"JAVA_{provider.upper()}_{defect_class.upper()}_{func}_{line}_"
        f"{uuid.uuid5(uuid.NAMESPACE_URL, rule_id + provider).hex[:8]}"
    )
    limitations = signal.get("limitations")
    if not isinstance(limitations, list):
        limitation_text = str(signal.get("limitation") or "")
        limitations = [limitation_text] if limitation_text else []
    evidence = {
        "candidate_id": candidate_id,
        "candidate_source": f"java_{provider}_signal",
        "defect_class": defect_class,
        "rule": rule_id,
        "language": "java",
        "provider": provider,
        "precision": precision,
        "source": source or {"expression": "java provider source", "kind": "java_provider_source"},
        "sink": sink or {"operation": rule_id, "kind": "java_provider_sink"},
        "path": {
            "function": func,
            "entry_function": entry_func,
            "call_path": [
                str(item.get("method") or item.get("function") or item.get("code") or "")
                for item in path
                if isinstance(item, dict)
            ],
            "provider_path": path,
            "complete_in_function": precision == "exact_flow" and len(path) <= 1,
            "complete_to_entry": bool(entry_func and path),
            "guard_status": "unknown",
        },
        "guards": signal.get("guards") if isinstance(signal.get("guards"), list) else [],
        "limitations": limitations,
        "positive_evidence": [
            f"Java provider `{provider}` emitted `{rule_id}` with precision `{precision}`."
        ],
        "negative_evidence": [],
        "raw_signal": signal.get("raw_evidence") or signal,
        "validation_notes": [
            "Provider signals are evidence-only and must be verified by the Validator Agent."
        ],
    }
    return {
        "id": candidate_id,
        "candidate_id": candidate_id,
        "function": func,
        "entry_function": entry_func,
        "language": "java",
        "location": f"{file_path}:{line}" if file_path and line else file_path or func,
        "category": defect_class,
        "subcategory": defect_class,
        "defect_class": defect_class,
        "finding_kind": "java_provider_signal_candidate",
        "candidate_source": f"java_{provider}_signal",
        "rule": rule_id,
        "description": f"Java 提供方 `{provider}` 报告了针对 `{func}` 的 `{defect_class}` 证据。",
        "root_cause": "Java 分析提供方报告了需要验证的源到汇（source-to-sink）证据。",
        "suggested_fix": "Confirm exposure, guards, sanitizers, and sink exploitability before fixing.",
        "confidence": confidence,
        "rule_confidence": confidence,
        "impact_level": (
            "high"
            if defect_class in {"command_injection", "unsafe_deserialization", "sql_injection"}
            else "medium"
        ),
        "reasoning": "Java provider signal normalized into a Z-SCOPE evidence pack.",
        "source": source.get("expression") or source.get("kind") or "java provider source",
        "sink": sink.get("operation") or sink.get("kind") or rule_id,
        "positive_evidence": evidence["positive_evidence"],
        "negative_evidence": [],
        "limitations": limitations,
        "evidence_pack": evidence,
        "validation_required": True,
        "must_validate": True,
        "candidate_role": "evidence_only",
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
    java_categories = (
        (("nosql", "mongo", "elasticsearch"), "nosql_injection"),
        (("jpa", "jpql", "native query"), "jpa_injection"),
        (("sql injection",), "sql_injection"),
        (("ldap",), "ldap_injection"),
        (("jndi",), "jndi_injection"),
        (("file upload", "multipart"), "file_upload"),
        (("template",), "template_injection"),
        (("open redirect", "redirect"), "open_redirect"),
        (("header injection", "response splitting"), "header_injection"),
        (("cookie",), "insecure_cookie"),
        (("cors",), "cors_misconfiguration"),
        (("authz", "authorization", "csrf"), "authz_bypass"),
        (("ssrf", "server side request forgery"), "ssrf"),
        (("xxe", "xml external entity"), "xxe"),
        (("deserialization", "read object"), "unsafe_deserialization"),
        (("jwt",), "jwt_misuse"),
        (("regex", "redos"), "regex_dos"),
        (("reflection",), "reflection_injection"),
        (("class loading", "classloader"), "dynamic_class_loading"),
        (("resource exhaustion",), "resource_exhaustion"),
        (("temp file", "temporary file"), "temp_file_risk"),
        (("race", "concurrency"), "concurrency_race"),
    )
    for terms, normalized in java_categories:
        if any(term in text for term in terms):
            return normalized
    if any(word in text for word in ("code injection", "expression", "script", "eval")):
        return "code_injection"
    if any(
        word in text
        for word in ("integer", "divide", "division", "modulo", "shift", "wrap", "trunc")
    ):
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
