"""Candidate normalization and evidence-merge helpers."""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Dict, List, Optional, Set


def clang_tooling_matcher_candidates_from_evidence(
    func_name: str,
    file_path: str,
    tooling_evidence: Dict[str, Any],
    *,
    allowed_skills: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    ast_dump = tooling_evidence.get("ast_dump") if isinstance(tooling_evidence, dict) else {}
    ast_summary = ast_dump.get("summary") if isinstance(ast_dump, dict) else {}
    target = ast_summary.get("target_function") if isinstance(ast_summary, dict) else {}
    facts = target.get("matcher_facts") if isinstance(target, dict) else []
    if not isinstance(facts, list):
        return []
    allowed = set(allowed_skills) if allowed_skills is not None else None
    issues: List[Dict[str, Any]] = []
    for fact in facts:
        if not isinstance(fact, dict):
            continue
        defect_class = defect_class_from_clang_matcher_fact(fact)
        if not defect_class:
            continue
        skill = skill_for_matcher_defect(defect_class)
        if allowed is not None and skill not in allowed:
            continue
        issues.append(
            clang_matcher_fact_to_candidate(
                func_name,
                file_path,
                fact,
                defect_class,
                tooling_evidence,
            )
        )
    return issues


def defect_class_from_clang_matcher_fact(fact: Dict[str, Any]) -> str:
    rule = str(fact.get("rule_id") or "")
    category = str(fact.get("category") or "")
    if rule == "clang_ast_resource_balance_summary":
        acquires = int(fact.get("acquire_call_count") or 0)
        releases = int(fact.get("release_call_count") or 0)
        return "memory_leak" if acquires > releases else ""
    if category in {"double_free", "use_after_free"}:
        return category
    if category in {"bounds", "format_string", "command_injection"}:
        return category
    return ""


def skill_for_matcher_defect(defect_class: str) -> str:
    return {
        "bounds": "bounds_and_integer",
        "format_string": "string_and_format",
        "command_injection": "string_and_format",
        "memory_leak": "resource_lifecycle",
        "double_free": "temporal_memory",
        "use_after_free": "temporal_memory",
    }.get(defect_class, "resource_lifecycle")


def clang_matcher_fact_to_candidate(
    func_name: str,
    file_path: str,
    fact: Dict[str, Any],
    defect_class: str,
    tooling_evidence: Dict[str, Any],
) -> Dict[str, Any]:
    rule = str(fact.get("rule_id") or "clang_ast_matcher_fact")
    line = int(fact.get("line") or 0)
    if not line:
        line = int(((tooling_evidence.get("range") or {}) if isinstance(tooling_evidence, dict) else {}).get("start_line") or 0)
    callee = str(fact.get("callee") or fact.get("resource_symbol") or rule)
    candidate_id = f"CLANG_AST_MATCHER_{defect_class.upper()}_{func_name}_{line}_{uuid.uuid5(uuid.NAMESPACE_URL, rule + callee).hex[:8]}"
    location = f"{file_path}:{line}" if file_path else f"{func_name}:{line}"
    positive = [
        f"Clang AST matcher fact `{rule}` matched `{callee}` in `{func_name}` at {location}",
    ]
    if rule == "clang_ast_resource_balance_summary":
        positive.append(
            f"Resource balance summary: acquire={fact.get('acquire_call_count', 0)}, "
            f"release={fact.get('release_call_count', 0)}"
        )
    if fact.get("resource_symbol"):
        positive.append(f"Resource symbol involved: `{fact.get('resource_symbol')}`")
    negative = [
        "AST matcher evidence is syntactic; Validator must confirm data/control feasibility and semantic ownership.",
    ]
    evidence = {
        "candidate_id": candidate_id,
        "candidate_source": "clang_ast_matcher",
        "checker": "clang_ast_matcher_checker",
        "defect_class": defect_class,
        "rule": rule,
        "source": {"expression": callee, "file": file_path, "line": line},
        "sink": {"operation": callee, "file": file_path, "line": line},
        "path": {
            "function": func_name,
            "backend": "Clang AST matcher facts",
            "complete_in_function": False,
            "path_constraints": [
                "AST matcher fact is path-insensitive",
                "validator must check guards, ownership transfer, aliases, and reachability",
            ],
        },
        "clang_matcher_fact": fact,
        "clang_tooling": compact_clang_tooling_evidence(tooling_evidence),
        "positive_evidence": positive,
        "negative_evidence": negative,
        "evidence_refs": [],
    }
    return {
        "id": candidate_id,
        "candidate_id": candidate_id,
        "function": func_name,
        "location": location,
        "category": defect_class,
        "subcategory": defect_class,
        "defect_class": defect_class,
        "finding_kind": "clang_ast_matcher_candidate",
        "candidate_source": "clang_ast_matcher",
        "evidence_checker": "clang_ast_matcher_checker",
        "rule": rule,
        "description": f"Clang AST matcher fact `{rule}` identified `{callee}` in `{func_name}`.",
        "root_cause": "Clang AST tooling produced a syntactic matcher fact requiring semantic validation.",
        "suggested_fix": "Validate the fact against concrete data/control flow before changing code.",
        "confidence": 0.64 if defect_class != "memory_leak" else 0.58,
        "rule_confidence": 0.64 if defect_class != "memory_leak" else 0.58,
        "impact_level": "high" if defect_class in {"command_injection", "double_free", "use_after_free"} else "medium",
        "reasoning": "Clang AST matcher fact normalized into an evidence-only candidate for Validator review.",
        "source": callee,
        "sink": callee,
        "dedup_key": "|".join([defect_class, file_path.replace("\\", "/").lower(), str(line), rule, callee]),
        "positive_evidence": positive,
        "negative_evidence": negative,
        "evidence_pack": evidence,
        "evidence_refs": [],
    }


def compact_clang_tooling_evidence(tooling_evidence: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(tooling_evidence, dict):
        return {}
    ast_dump = tooling_evidence.get("ast_dump") if isinstance(tooling_evidence.get("ast_dump"), dict) else {}
    cfg_dump = tooling_evidence.get("cfg_dump") if isinstance(tooling_evidence.get("cfg_dump"), dict) else {}
    ast_summary = ast_dump.get("summary") if isinstance(ast_dump.get("summary"), dict) else {}
    cfg_summary = cfg_dump.get("summary") if isinstance(cfg_dump.get("summary"), dict) else {}
    target = ast_summary.get("target_function") if isinstance(ast_summary.get("target_function"), dict) else {}
    return {
        "schema": tooling_evidence.get("schema"),
        "status": tooling_evidence.get("status"),
        "execution_enabled": tooling_evidence.get("execution_enabled"),
        "compile_command_found": tooling_evidence.get("compile_command_found"),
        "range": tooling_evidence.get("range"),
        "ast_target_function": {
            "name": target.get("name"),
            "line": target.get("line"),
            "type": target.get("type"),
            "matcher_facts": target.get("matcher_facts", [])[:16],
        },
        "cfg_summary": {
            "parse_ok": cfg_summary.get("parse_ok"),
            "block_count": cfg_summary.get("block_count"),
            "edge_count": cfg_summary.get("edge_count"),
            "entry_blocks": cfg_summary.get("entry_blocks", []),
            "exit_blocks": cfg_summary.get("exit_blocks", []),
        },
    }


def dedupe_rule_candidates(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: Dict[str, Dict[str, Any]] = {}
    for issue in issues:
        key = rule_candidate_dedup_key(issue)
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = issue
        else:
            merge_rule_candidate_duplicate(existing, issue)
    return list(deduped.values())


def rule_candidate_dedup_key(issue: Dict[str, Any]) -> str:
    evidence = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    if issue.get("internal_sink_lifted") or evidence.get("internal_sink_lifted"):
        sink_func = str(evidence.get("sink_function") or issue.get("function") or "")
        location = str(issue.get("location") or "").replace("\\", "/").lower()
        return "|".join(
            [
                "lifted_internal_sink",
                str(issue.get("defect_class") or issue.get("category") or ""),
                sink_func,
                location,
                str(issue.get("rule") or ""),
                str(issue.get("source") or ""),
                str(issue.get("sink") or ""),
            ]
        )
    return str(
        issue.get("dedup_key")
        or issue.get("candidate_id")
        or issue.get("id")
        or (
            issue.get("function"),
            issue.get("defect_class"),
            issue.get("rule"),
            issue.get("file") or issue.get("file_path"),
            issue.get("line"),
        )
    )


def merge_rule_candidate_duplicate(primary: Dict[str, Any], duplicate: Dict[str, Any]) -> None:
    primary_sources = primary.setdefault("duplicate_sources", [])
    if not isinstance(primary_sources, list):
        primary_sources = []
        primary["duplicate_sources"] = primary_sources
    entry = {
        "candidate_id": duplicate.get("candidate_id") or duplicate.get("id"),
        "entry_function": duplicate.get("entry_function") or duplicate.get("analyzed_from"),
        "analyzed_from": duplicate.get("analyzed_from"),
        "call_path": duplicate.get("call_path") or [],
        "location": duplicate.get("location"),
        "candidate_source": duplicate.get("candidate_source"),
    }
    if entry not in primary_sources:
        primary_sources.append(entry)

    for field in ("positive_evidence", "negative_evidence", "evidence_refs"):
        current = primary.setdefault(field, [])
        incoming = duplicate.get(field) or []
        if not isinstance(current, list) or not isinstance(incoming, list):
            continue
        for item in incoming:
            if item not in current:
                current.append(item)

    primary_path = primary.get("call_path")
    duplicate_path = duplicate.get("call_path")
    if duplicate_path and primary_path != duplicate_path:
        paths = primary.setdefault("call_paths", [])
        if isinstance(paths, list):
            if primary_path and primary_path not in paths:
                paths.append(primary_path)
            if duplicate_path not in paths:
                paths.append(duplicate_path)

    primary_pack = primary.get("evidence_pack") if isinstance(primary.get("evidence_pack"), dict) else {}
    duplicate_pack = duplicate.get("evidence_pack") if isinstance(duplicate.get("evidence_pack"), dict) else {}
    if not primary_pack:
        primary["evidence_pack"] = primary_pack
    if duplicate_pack:
        pack_sources = primary_pack.setdefault("duplicate_sources", [])
        if isinstance(pack_sources, list) and entry not in pack_sources:
            pack_sources.append(entry)
        duplicate_edges = duplicate_pack.get("call_path_edges") or []
        if duplicate_edges:
            edge_sets = primary_pack.setdefault("duplicate_call_path_edges", [])
            if isinstance(edge_sets, list) and duplicate_edges not in edge_sets:
                edge_sets.append(duplicate_edges)


def merge_unified_evidence_candidates(candidates: List[Dict[str, Any]], *, enabled: bool) -> List[Dict[str, Any]]:
    """Merge Clang and SVF evidence for the same issue in unified mode."""
    if not enabled:
        return candidates
    merged: List[Dict[str, Any]] = []
    for candidate in candidates:
        match = next(
            (
                existing
                for existing in merged
                if unified_candidates_may_refer_same_issue(existing, candidate)
            ),
            None,
        )
        if match is None:
            merged.append(candidate)
            continue
        attach_unified_secondary_evidence(match, candidate)
    return merged


def unified_candidates_may_refer_same_issue(
    left: Dict[str, Any],
    right: Dict[str, Any],
) -> bool:
    left_source = candidate_source_name(left)
    right_source = candidate_source_name(right)
    if not {left_source, right_source} & {"svf_value_flow"}:
        return False
    if not ({left_source, right_source} & {"clang_ast_cfg", "clang_ast_matcher", "clang_knowledgedb_call_edges"}):
        return False
    if not defect_classes_compatible(left, right):
        return False
    left_file, left_line = candidate_file_line(left)
    right_file, right_line = candidate_file_line(right)
    if left_file and right_file and left_file != right_file:
        return False
    left_funcs = candidate_function_names(left)
    right_funcs = candidate_function_names(right)
    if left_funcs and right_funcs and left_funcs.isdisjoint(right_funcs):
        return False
    if left_line and right_line and abs(left_line - right_line) <= 8:
        return True
    return bool(candidate_symbols(left) & candidate_symbols(right))


def candidate_source_name(issue: Dict[str, Any]) -> str:
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    return str(pack.get("candidate_source") or issue.get("candidate_source") or issue.get("finding_kind") or "")


def defect_classes_compatible(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    left_cls = str(left.get("defect_class") or left.get("category") or "")
    right_cls = str(right.get("defect_class") or right.get("category") or "")
    if left_cls == right_cls:
        return True
    return "memory_safety" in {left_cls, right_cls} and bool(left_cls and right_cls)


def candidate_file_line(issue: Dict[str, Any]) -> tuple[str, int]:
    file_path, line = parse_location_file_line(str(issue.get("location") or ""))
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    for key in ("source_path", "value_flow", "path"):
        data = pack.get(key) if isinstance(pack.get(key), dict) else {}
        reported = data.get("reported_location") if isinstance(data.get("reported_location"), dict) else {}
        if not file_path:
            file_path = str(data.get("file") or reported.get("file") or "")
        if not line:
            line = int(data.get("line") or reported.get("line") or 0)
    return file_path.replace("\\", "/").lower(), line


def parse_location_file_line(location: str) -> tuple[str, int]:
    match = re.match(r"^(?P<file>.*?):(?P<line>\d+)(?:-\d+)?$", str(location or ""))
    if not match:
        return "", 0
    return match.group("file").replace("\\", "/").lower(), int(match.group("line"))


def candidate_function_names(issue: Dict[str, Any]) -> Set[str]:
    names = {
        str(issue.get("function") or ""),
        str(issue.get("entry_function") or ""),
        str(issue.get("analyzed_from") or ""),
    }
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    for key in ("path", "source_path", "value_flow"):
        data = pack.get(key) if isinstance(pack.get(key), dict) else {}
        names.update(
            str(data.get(field) or "")
            for field in (
                "function",
                "target_function",
                "entry_function",
                "source_function",
                "source_func",
                "sink_function",
                "sink_func",
            )
        )
        names.update(str(item) for item in data.get("call_path") or [] if str(item))
    return {name for name in names if name}


def candidate_symbols(issue: Dict[str, Any]) -> Set[str]:
    fields = [
        issue.get("source"),
        issue.get("sink"),
        issue.get("description"),
        issue.get("root_cause"),
        issue.get("positive_evidence"),
        issue.get("evidence_pack"),
    ]
    text = "\n".join(json.dumps(field, ensure_ascii=False, default=str) for field in fields if field)
    tokens = {
        token
        for token in re.findall(r"[A-Za-z_]\w*", text)
        if len(token) >= 3
        and token.lower()
        not in {
            "src",
            "line",
            "file",
            "candidate",
            "source",
            "sink",
            "function",
            "validator",
            "clang",
            "saber",
            "value",
            "flow",
        }
    }
    return tokens


def attach_unified_secondary_evidence(primary: Dict[str, Any], secondary: Dict[str, Any]) -> None:
    primary_pack = primary.get("evidence_pack") if isinstance(primary.get("evidence_pack"), dict) else {}
    if not primary_pack:
        primary["evidence_pack"] = primary_pack
    secondary_pack = secondary.get("evidence_pack") if isinstance(secondary.get("evidence_pack"), dict) else {}
    compact = {
        "candidate_id": secondary.get("candidate_id") or secondary.get("id"),
        "candidate_source": candidate_source_name(secondary),
        "checker": secondary.get("evidence_checker") or secondary_pack.get("checker"),
        "function": secondary.get("function"),
        "location": secondary.get("location"),
        "defect_class": secondary.get("defect_class") or secondary.get("category"),
        "rule": secondary.get("rule"),
        "source": secondary.get("source"),
        "sink": secondary.get("sink"),
        "evidence_pack": secondary_pack,
    }
    merged = primary_pack.setdefault("merged_backend_evidence", [])
    if isinstance(merged, list) and compact not in merged:
        merged.append(compact)
    sources = primary.setdefault("merged_candidate_sources", [])
    if isinstance(sources, list):
        for source in (candidate_source_name(primary), compact["candidate_source"]):
            if source and source not in sources:
                sources.append(source)
    primary_pack["merged_candidate_sources"] = list(primary.get("merged_candidate_sources") or [])
    primary_pack["unified_backend_components"] = ["clang", "svf"]
    primary["unified_evidence_merged"] = True
    primary["validation_required"] = True
    primary["must_validate"] = True

    for field in ("positive_evidence", "negative_evidence", "evidence_refs"):
        current = primary.setdefault(field, [])
        incoming = secondary.get(field) or []
        if not isinstance(current, list) or not isinstance(incoming, list):
            continue
        for item in incoming:
            if item not in current:
                current.append(item)
    note = (
        f"Unified evidence merge attached `{compact['candidate_source']}` "
        f"candidate `{compact['candidate_id']}` for Validator correlation."
    )
    positive = primary.setdefault("positive_evidence", [])
    if isinstance(positive, list) and note not in positive:
        positive.append(note)
