"""Validator-facing evidence pack and rejection-policy helpers."""

from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from typing import Any, Callable, Dict, List, Mapping, Optional, cast

from ...common.issue_identity import canonical_issue_key, flatten_issue_text, parse_issue_location
from ..candidates.evidence_models import build_evidence_models
from ...snapshots.modeling_input import SemanticModelInputError, resolve_function_info
from .context_budget import record_projection

VALIDATOR_EVIDENCE_SLICE_VERSION = "zscope.validator-evidence-slice.v2"
VALIDATOR_EVIDENCE_SLICE_V3 = "zscope.validator-evidence-slice.v3.1"
VALIDATOR_PROTOCOL_VERSION = "zscope.validator-protocol.v2"
VALIDATOR_PROTOCOL_V3 = "zscope.validator-protocol.v3"

# Baseline list cap for the project-knowledge projection compaction.  The
# effective cap is raised to the Wiki selection caps (resolved lazily to avoid
# an import cycle) so no already-selected constraint/excerpt is dropped here.
_PROJECT_KNOWLEDGE_PROJECTION_LIST_ITEMS = 16


def _wiki_selection_max_list_items() -> int:
    try:
        from ...wiki.service import MAX_SOURCE_EXCERPTS, MAX_WIKI_CONSTRAINTS

        return int(max(MAX_WIKI_CONSTRAINTS, MAX_SOURCE_EXCERPTS))
    except Exception:
        return _PROJECT_KNOWLEDGE_PROJECTION_LIST_ITEMS


_WIKI_SELECTION_MAX_LIST_ITEMS = _wiki_selection_max_list_items()

VALIDATOR_MISSING_FACT_KINDS = frozenset(
    {
        "guard_dominance",
        "caller_contract",
        "source_controllability",
        "ownership_transfer",
        "cleanup_coverage",
        "lockset",
        "happens_before",
        "object_identity",
        "value_range",
        "source_sink_reachability",
        "signal_context",
        "container_reachability",
        "type_layout",
    }
)


def _as_dict(value: Any) -> Dict[str, Any]:
    """Narrow dynamic state/evidence mappings without copying them."""
    return cast(Dict[str, Any], value) if isinstance(value, dict) else {}


def validation_verdict(val_data: Dict[str, Any]) -> str:
    """Normalize old boolean validator output and tri-state verdicts."""
    verdict = str(val_data.get("verdict") or "").strip().lower()
    aliases = {
        "valid": "verified",
        "true": "verified",
        "confirmed": "verified",
        "invalid": "rejected",
        "false": "rejected",
        "reject": "rejected",
        "needs_review": "uncertain",
        "unknown": "uncertain",
    }
    if not verdict and "is_valid" in val_data:
        return "verified" if bool(val_data.get("is_valid")) else "rejected"
    verdict = aliases.get(verdict, verdict)
    if verdict in {"verified", "rejected", "uncertain"}:
        return verdict
    return "uncertain"


def is_entry_root_dead_code_rejection(
    val_data: Dict[str, Any],
    evidence_pack: Dict[str, Any],
) -> bool:
    """Detect validator rejections that contradict explicit scan-root evidence."""
    if validation_verdict(val_data) != "rejected":
        return False
    if not _entry_root_reachable(evidence_pack):
        return False

    text = flatten_issue_text(
        [
            val_data.get("reasoning"),
            val_data.get("negative_evidence"),
            val_data.get("guard_analysis"),
            val_data.get("missing_context"),
        ]
    ).lower()
    if not text:
        return False
    dead_code_terms = (
        "dead code",
        "unreachable",
        "not reachable",
        "no caller",
        "no callers",
        "zero caller",
        "zero callers",
        "absence from main",
        "not called from main",
        "main函数",
        "没有调用者",
        "无调用者",
        "调用图为空",
        "worker",
        "start wrapper",
        "死代码",
        "不可达",
    )
    return any(term in text for term in dead_code_terms)


# Interprocedural lock-protocol claims whose deterministic resolution needs
# the callers' lock state at the call site (plan Phase 1.2 "调用方持锁").
_CALLER_LOCK_RULES = frozenset(
    {
        "clang_cfg_unlock_without_matching_lock",
        "clang_cfg_refcount_update_after_unlock",
    }
)


def _direct_callers_from_paths(issue: Mapping[str, Any]) -> List[str]:
    """Extract direct caller names from the candidate's recorded call paths."""

    callers: List[str] = []
    raw_paths = issue.get("call_paths")
    paths: List[Any] = list(raw_paths) if isinstance(raw_paths, (list, tuple)) else []
    single = issue.get("call_path")
    if isinstance(single, (list, tuple)):
        paths.append(single)
    for path in paths:
        if not isinstance(path, (list, tuple)) or len(path) < 2:
            continue
        direct = str(path[-2] or "").strip()
        if direct and direct not in callers:
            callers.append(direct)
    return callers


def _caller_lock_states(
    code_index: Any,
    issue_func: str,
    caller_names: List[str],
    limit: int = 8,
) -> List[Dict[str, Any]]:
    """Derive each caller's held lock at its call site of ``issue_func``.

    Lexical bracket analysis of every resolvable caller body: a call site is
    guarded by ``held_lock`` when a LOCK of that mutex appears before the
    call with no matching UNLOCK in between.  Unresolvable callers are
    reported with ``resolved: False`` so consumers can distinguish "unknown"
    from "unlocked" and stay conservative.  Only the first call site per
    caller is analysed by design.
    """

    from .evidence_completion import EvidenceCompletionQueue  # lazy: avoids import cycle

    target = str(issue_func or "").strip()
    call_pattern = re.compile(rf"\b{re.escape(target)}\s*\(") if target else None
    states: List[Dict[str, Any]] = []
    for raw in caller_names:
        caller = str(raw or "").strip()
        if not caller or not call_pattern or len(states) >= limit:
            continue
        try:
            impl = code_index.get_function_impl(caller, max_lines=None, warn_missing=False)
        except Exception:
            impl = None
        code = str((impl or {}).get("code") or "")
        held_lock = ""
        call_site_line = 0
        if code:
            stack: List[str] = []
            for line_number, text in enumerate(code.splitlines(), start=1):
                if call_pattern.search(text):
                    call_site_line = line_number
                    held_lock = stack[-1] if stack else ""
                    break
                acquired = EvidenceCompletionQueue._lock_argument(text, acquire=True)
                if acquired:
                    stack.append(acquired)
                    continue
                released = EvidenceCompletionQueue._lock_argument(text, acquire=False)
                if released:
                    for index in range(len(stack) - 1, -1, -1):
                        if stack[index] == released:
                            stack.pop(index)
                            break
        states.append(
            {
                "caller": caller,
                "call_site_line": call_site_line,
                "held_lock": held_lock,
                # A retrievable body without the call site says nothing about
                # the lock state; treat it as unresolved, not as unguarded.
                "resolved": bool(code) and call_site_line > 0,
            }
        )
    return states


def build_validation_evidence_pack(
    issue: Dict[str, Any],
    state: Dict[str, Any],
    issue_code: str,
    *,
    code_index: Any,
    snapshot_store: Any,
    score_components_fn: Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, float]],
    issue_key_fn: Callable[[Dict[str, Any]], str] = canonical_issue_key,
) -> Dict[str, Any]:
    """Build compact candidate evidence so the validator starts from facts."""
    issue_func = str(issue.get("function") or state["agent_context"]["func_name"])
    location = str(issue.get("location") or "")
    file_path, line = parse_issue_location(location)
    snippet = None
    if file_path and line:
        snippet = code_index.get_file_snippet(
            file_path,
            max(1, line - 12),
            line + 12,
        )

    snapshot = None
    try:
        info = resolve_function_info(
            code_index,
            issue_func,
            file_path=file_path or "",
        )
        snapshot = snapshot_store.load_snapshot(str(info["index_name"]))
    except (SemanticModelInputError, AttributeError):
        snapshot = None
    try:
        callers = code_index.get_callers(issue_func, limit=8)
    except Exception:
        callers = []
    try:
        callees = code_index.get_callees(issue_func, limit=12)
    except Exception:
        callees = []

    agent_context = _as_dict(state.get("agent_context"))
    analysis_entry = str(state.get("entry_func") or agent_context.get("func_name") or "").strip()
    issue_entry = str(issue.get("entry_function") or issue.get("analyzed_from") or "").strip()
    candidate_path = issue.get("call_path") or issue.get("call_paths")
    candidate_evidence = _as_dict(issue.get("evidence_pack"))
    candidate_path_evidence = _as_dict(candidate_evidence.get("path"))
    entry_custom_prompt = str(agent_context.get("entry_custom_prompt") or "")
    entry_exposure = _entry_exposure_from_prompt(entry_custom_prompt)
    entry_is_external_root = entry_exposure in {
        "api",
        "communication",
        "thread",
        "other_user_input",
    }
    reachable_from_entry = bool(
        issue.get("reachable_from_entry")
        or (analysis_entry and issue_func == analysis_entry)
        or issue_entry
        or candidate_evidence.get("entry_function")
        or (candidate_path_evidence.get("complete_to_entry"))
    )
    validation_requirements = _base_validation_requirements()
    validation_requirements.extend(category_validation_requirements(issue))
    caller_lock_states: List[Dict[str, Any]] = []
    if str(issue.get("rule") or "") in _CALLER_LOCK_RULES:
        caller_lock_states = _caller_lock_states(
            code_index,
            issue_func,
            _direct_callers_from_paths(issue),
        )
    return {
        "mode": "tri_state_exploitability_validation",
        "dedup_key": issue.get("dedup_key") or issue_key_fn(issue),
        "candidate_id": issue.get("candidate_id") or issue.get("id"),
        "candidate_role": issue.get("candidate_role") or "evidence_only",
        "candidate_is_conclusion": False,
        "validation_required": issue.get(
            "validation_required", candidate_evidence.get("validation_required", True)
        ),
        "proofs": issue.get("proofs") or candidate_evidence.get("proofs") or {},
        "audit_observation_reason": issue.get("audit_observation_reason")
        or candidate_evidence.get("audit_observation_reason"),
        "va_unreviewed": bool(
            issue.get("va_unreviewed") or candidate_evidence.get("va_unreviewed")
        ),
        "backend_profile": issue.get("backend_profile")
        or candidate_evidence.get("backend_profile"),
        "evidence_checker": issue.get("evidence_checker") or candidate_evidence.get("checker"),
        "evidence_engines": issue.get("evidence_engines")
        or candidate_evidence.get("evidence_engines")
        or [],
        "semantic_overlays": issue.get("semantic_overlays")
        or candidate_evidence.get("semantic_overlays")
        or {},
        "semantic_overlay_evidence": issue.get("semantic_overlay_evidence")
        or candidate_evidence.get("semantic_overlay_evidence")
        or {},
        "caller_lock_states": caller_lock_states,
        "finding_kind": issue.get("finding_kind"),
        "defect_class": issue.get("defect_class") or issue.get("subcategory"),
        "rule_confidence": issue.get("rule_confidence"),
        "score_components": issue.get("score_components") or score_components_fn(issue, {}),
        "evidence_refs": issue.get("evidence_refs")
        or candidate_evidence.get("evidence_refs")
        or [],
        "finding_summary": {
            "id": issue.get("id"),
            "function": issue_func,
            "location": location,
            "category": issue.get("category"),
            "subcategory": issue.get("subcategory"),
            "confidence": issue.get("confidence"),
            "description": issue.get("description"),
            "source": issue.get("source"),
            "sink": issue.get("sink"),
            "cwe": issue.get("cwe"),
        },
        "entry_context": {
            "current_analysis_entry": analysis_entry,
            "entry_custom_prompt": entry_custom_prompt,
            "entry_exposure": entry_exposure,
            "entry_is_external_root": entry_is_external_root,
            "entry_is_scan_root": bool(analysis_entry),
            "zero_callers_is_expected_for_entry": bool(analysis_entry),
            "public_trigger": (
                (
                    "Header-declared/configured entry function is an external scan root; "
                    "zero repository callers does not make it dead code."
                )
                if entry_is_external_root
                else (
                    "Configured entry function is the scan root; zero repository callers above "
                    "the selected root is not sufficient dead-code evidence."
                )
            ),
            "issue_entry_function": issue_entry,
            "reachable_from_entry": reachable_from_entry,
            "internal_sink_lifted": bool(issue.get("internal_sink_lifted")),
            "call_path": candidate_path or candidate_evidence.get("call_path"),
            "candidate_path": candidate_path_evidence,
        },
        "candidate_evidence": candidate_evidence,
        "evidence_models": issue.get("evidence_models") or build_evidence_models(issue),
        "positive_evidence": issue.get("positive_evidence")
        or candidate_evidence.get("positive_evidence")
        or [],
        "negative_evidence": issue.get("negative_evidence")
        or candidate_evidence.get("negative_evidence")
        or [],
        "primary_location_snippet": snippet,
        "function_context": {
            "code": issue_code,
            "snapshot_summary": compact_snapshot(snapshot),
            "callers": callers,
            "callees": callees,
        },
        "validation_requirements": validation_requirements,
    }


def build_validator_evidence_slice_v2(
    issue: Mapping[str, Any],
    evidence_pack: Mapping[str, Any],
    issue_code: str,
) -> Dict[str, Any]:
    """Build one decision-complete, occurrence-compact Validator payload.

    A validation cluster may contain hundreds of entry occurrences.  Those
    paths are audit provenance, not independent decision facts, so the model
    receives one canonical path and stable references to the remaining data.
    The full issue/report objects remain untouched and available outside the
    prompt.
    """

    pack = dict(evidence_pack or {})
    finding = pack.get("finding_summary")
    if not isinstance(finding, Mapping):
        finding = {}
    function_context = pack.get("function_context")
    if not isinstance(function_context, Mapping):
        function_context = {}
    entry_context = pack.get("entry_context")
    if not isinstance(entry_context, Mapping):
        entry_context = {}

    def first_path(*values: Any) -> List[str]:
        for raw in values:
            if not isinstance(raw, list) or not raw:
                continue
            candidate = raw[0] if isinstance(raw[0], list) else raw
            if isinstance(candidate, list):
                return [str(item) for item in candidate if str(item)]
        return []

    occurrence_uids = issue.get("occurrence_uids")
    if not isinstance(occurrence_uids, list):
        occurrence_uids = []
    primary_occurrence = str(
        issue.get("primary_occurrence_uid")
        or issue.get("occurrence_uid")
        or (occurrence_uids[0] if occurrence_uids else "")
    )
    occurrence_count = max(
        1,
        int(issue.get("occurrence_count") or len(occurrence_uids) or 1),
    )
    aliases = issue.get("alias_occurrence_uids")
    if not isinstance(aliases, list):
        aliases = occurrence_uids[1:]

    fact_slice = issue.get("decision_fact_slice")
    if not isinstance(fact_slice, Mapping):
        fact_slice = {}
    security_obligation = issue.get("security_obligation")
    if not isinstance(security_obligation, Mapping):
        security_obligation = {}
    deterministic_proofs = issue.get("deterministic_proofs")
    if not isinstance(deterministic_proofs, list):
        deterministic_proofs = []

    missing_fact_kinds = _normalized_missing_fact_kinds(
        issue.get("missing_fact_kinds") or fact_slice.get("missing_fact_kinds")
    )
    representative_path = first_path(
        issue.get("entry_paths"),
        issue.get("call_paths"),
        issue.get("call_path"),
        entry_context.get("call_path"),
    )
    code = str(issue_code or function_context.get("code") or "")
    location_snippet = pack.get("primary_location_snippet")
    if isinstance(location_snippet, Mapping):
        location_snippet = {
            key: _compact_validation_value(value, max_string_chars=1400)
            for key, value in location_snippet.items()
            if key in {"file", "start_line", "end_line", "code", "content", "text"}
        }
    elif location_snippet not in (None, ""):
        location_snippet = _trim_text(str(location_snippet), 1800)

    result: Dict[str, Any] = {
        "schema_version": VALIDATOR_EVIDENCE_SLICE_VERSION,
        "protocol_version": VALIDATOR_PROTOCOL_VERSION,
        "obligation": {
            "candidate_uid": issue.get("candidate_uid"),
            "validation_cluster_uid": issue.get("validation_cluster_uid"),
            "obligation_uid": issue.get("obligation_uid"),
            "defect_family": issue.get("defect_class") or issue.get("category"),
            "obligation_shape": issue.get("obligation_shape"),
            "subject_uid": issue.get("resource_identity") or security_obligation.get("subject_uid"),
            "source_uid": issue.get("source_identity") or security_obligation.get("source_uid"),
            "sink_uid": issue.get("sink_identity") or security_obligation.get("sink_uid"),
            "function": issue.get("function") or finding.get("function"),
            "location": issue.get("location") or finding.get("location"),
            "category": issue.get("category") or finding.get("category"),
            "subcategory": issue.get("subcategory") or finding.get("subcategory"),
            "cwe": issue.get("cwe") or finding.get("cwe"),
        },
        "canonical_occurrence": {
            "occurrence_uid": primary_occurrence,
            "entry_identity": issue.get("entry_identity")
            or entry_context.get("current_analysis_entry"),
            "reachable_from_entry": bool(
                issue.get("reachable_from_entry") or entry_context.get("reachable_from_entry")
            ),
            "representative_call_path": representative_path,
        },
        "decision_facts": {
            "version": issue.get("decision_fact_version"),
            "coverage": issue.get("decision_fact_coverage") or fact_slice.get("coverage"),
            "fact_uids": list(fact_slice.get("fact_uids") or [])[:32],
            "edge_uids": list(fact_slice.get("edge_uids") or [])[:32],
            "dependency_code_hashes": list(fact_slice.get("dependency_code_hashes") or [])[:8],
            "missing_fact_kinds": missing_fact_kinds,
            "deterministic_proofs": [
                _compact_validation_value(item, max_string_chars=1200)
                for item in deterministic_proofs[:8]
                if isinstance(item, Mapping)
            ],
        },
        "evidence": {
            "source": issue.get("source") or finding.get("source"),
            "sink": issue.get("sink") or finding.get("sink"),
            "positive": _compact_validation_value(
                issue.get("positive_evidence") or pack.get("positive_evidence") or [],
                max_list_items=8,
                max_string_chars=1200,
            ),
            "negative": _compact_validation_value(
                issue.get("negative_evidence") or pack.get("negative_evidence") or [],
                max_list_items=8,
                max_string_chars=1200,
            ),
            "path_constraints": _compact_validation_value(
                issue.get("path_constraints") or [],
                max_list_items=8,
                max_string_chars=1000,
            ),
        },
        "code": {
            "function_context": code,
            "location_snippet": location_snippet,
        },
        "alias_summary": {
            "occurrence_count": occurrence_count,
            "alias_count": max(0, occurrence_count - 1),
            # Alias identities remain in the canonical report/ledger.  The
            # Validator only needs a fixed-size audit commitment; embedding
            # N UIDs would make prompt cost grow with entry fan-out.
            "alias_uid_set_hash": hashlib.sha256(
                "\n".join(sorted(str(value) for value in aliases if str(value))).encode("utf-8")
            ).hexdigest(),
        },
        "validation_requirements": list(pack.get("validation_requirements") or []),
    }
    for key, original in (
        ("fact_uids", list(fact_slice.get("fact_uids") or [])),
        ("edge_uids", list(fact_slice.get("edge_uids") or [])),
        ("dependency_code_hashes", list(fact_slice.get("dependency_code_hashes") or [])),
        ("deterministic_proofs", deterministic_proofs),
    ):
        record_projection(result, "decision_facts." + key, original, result["decision_facts"][key])
    for key, original in (
        ("positive", issue.get("positive_evidence") or pack.get("positive_evidence") or []),
        ("negative", issue.get("negative_evidence") or pack.get("negative_evidence") or []),
        ("path_constraints", issue.get("path_constraints") or []),
    ):
        record_projection(result, "evidence." + key, original, result["evidence"][key])
    record_projection(result, "code.location_snippet", pack.get("primary_location_snippet"), location_snippet)
    record_projection(result, "validation_requirements", pack.get("validation_requirements") or [], result["validation_requirements"])
    return result


def build_validator_project_knowledge_projection(
    knowledge: Mapping[str, Any], issue: Mapping[str, Any]
) -> Dict[str, Any]:
    """Project Wiki context into the compact shape shown to Validator LLMs."""

    target_value = knowledge.get("target")
    target: Mapping[str, Any] = (
        target_value if isinstance(target_value, Mapping) else {}
    )
    issue_file = (
        str(
            issue.get("candidate_file")
            or issue.get("relative_file")
            or issue.get("file_path")
            or issue.get("file")
            or ""
        )
        .replace("\\", "/")
        .lstrip("/")
    )
    if not issue_file:
        location = str(issue.get("location") or "").replace("\\", "/")
        match = re.match(r"^(.*?):\d+(?::\d+)?$", location)
        issue_file = match.group(1).lstrip("/") if match else ""
    raw_constraints = [
        item for item in knowledge.get("constraints") or [] if isinstance(item, Mapping)
    ]
    constraint_subject_ids = list(
        dict.fromkeys(
            str(item.get("subject_id") or "")
            for item in raw_constraints
            if str(item.get("subject_id") or "")
        )
    )
    # Target identity comes from the candidate/evidence obligation only.
    # Never infer it from whichever constraints happened to match.
    target_subject_ids = _candidate_subject_ids(issue)
    target_obligation_kinds = _candidate_obligation_kinds(issue)
    projected_target = {
        "project_id": str(target.get("project_id") or knowledge.get("project_id") or ""),
        "module_ids": list(target.get("module_ids") or []),
        "subject_ids": target_subject_ids,
        "obligation_kinds": target_obligation_kinds,
        "candidate_file": str(
            issue_file
            or (
                ""
                if str(target.get("candidate_file") or "") == "unknown.md"
                else target.get("candidate_file")
            )
            or "unknown.md"
        ),
        "function_name": str(
            target.get("function_name") or target.get("function_id") or issue.get("function") or ""
        ),
    }
    constraints = []
    for item in raw_constraints:
        subject_kind = item.get("subject_kind") or (
            item.get("subject", {}).get("kind", "")
            if isinstance(item.get("subject"), Mapping)
            else ""
        )
        subject_id = str(item.get("subject_id") or "")
        prefix = f"{subject_kind}:" if subject_kind else ""
        if prefix and subject_id.startswith(prefix):
            subject_id = subject_id[len(prefix) :]
        constraints.append(
            {
                "constraint_id": item.get("constraint_id"),
                "kind": item.get("kind"),
                "subject_id": subject_id,
                "subject_kind": subject_kind,
                "statement": item.get("statement"),
                "authority": item.get("authority"),
                "normativity": item.get("normativity"),
                "status": item.get("status"),
                "source_refs": list(item.get("source_refs") or []),
                "conflicts_with": list(item.get("conflicts_with") or []),
            }
        )
    selection_value = knowledge.get("selection")
    selection: Mapping[str, Any] = (
        selection_value if isinstance(selection_value, Mapping) else {}
    )
    return {
        "resolution_mode": knowledge.get("resolution_mode"),
        "wiki_revision_id": knowledge.get("wiki_revision_id"),
        "target": projected_target,
        "constraints": constraints,
        "source_excerpts": list(knowledge.get("source_excerpts") or []),
        "conflicts": list(knowledge.get("conflicts") or []),
        "omitted_constraint_count": int(selection.get("omitted_constraint_count", 0) or 0),
        "omitted_source_excerpt_count": int(selection.get("omitted_source_excerpt_count", 0) or 0),
        "fallback_reason": selection.get("fallback_reason"),
    }


def _candidate_subject_ids(issue: Mapping[str, Any]) -> list[str]:
    values = issue.get("subject_ids") or issue.get("subject_id") or issue.get("subject")
    if isinstance(values, Mapping):
        values = values.get("canonical_id") or values.get("id")
    if isinstance(values, str):
        values = [values]
    return list(dict.fromkeys(str(value).strip() for value in (values or []) if str(value).strip()))


def _candidate_obligation_kinds(issue: Mapping[str, Any]) -> list[str]:
    values = (
        issue.get("obligation_kinds")
        or issue.get("missing_fact_kinds")
        or issue.get("fact_kinds")
        or issue.get("obligation_kind")
        or issue.get("fact_kind")
    )
    if isinstance(values, str):
        values = [values]
    return list(dict.fromkeys(str(value).strip() for value in (values or []) if str(value).strip()))


def build_validator_evidence_slice_v3(
    issue: Mapping[str, Any],
    evidence_pack: Mapping[str, Any],
    issue_code: str,
    *,
    validation_pass: str = "initial",
    evidence_delta: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the readable, reference-addressable Validator v3 projection.

    v2 deliberately committed most decision data by UID/hash.  That is useful
    for audit identity but forces a model to guess what those facts mean.  v3
    keeps the commitments and adds bounded fact payloads, path edges, semantic
    claims, and a catalog of the only references a model may cite.
    """

    result = build_validator_evidence_slice_v2(issue, evidence_pack, issue_code)
    result["schema_version"] = VALIDATOR_EVIDENCE_SLICE_V3
    result["protocol_version"] = VALIDATOR_PROTOCOL_V3
    result["validation_pass"] = validation_pass

    pack = dict(evidence_pack or {})
    fact_slice = issue.get("decision_fact_slice")
    if not isinstance(fact_slice, Mapping):
        fact_slice = {}
    fact_payloads: Any = (
        issue.get("decision_facts")
        or fact_slice.get("facts")
        or fact_slice.get("fact_payloads")
        or pack.get("decision_facts")
        or []
    )
    if isinstance(fact_payloads, Mapping):
        fact_payloads = [
            {"fact_uid": str(key), "payload": value}
            for key, value in fact_payloads.items()
        ]
    elif not isinstance(fact_payloads, list):
        fact_payloads = []
    result["decision_facts"]["facts"] = [
        _compact_validation_value(item, max_list_items=12, max_string_chars=1600)
        for item in fact_payloads[:32]
        if isinstance(item, Mapping)
    ]

    function_context = pack.get("function_context")
    if not isinstance(function_context, Mapping):
        function_context = {}
    result["code"]["snapshot_summary"] = _compact_validation_value(
        function_context.get("snapshot_summary") or {},
        max_list_items=12,
        max_string_chars=1600,
    )
    result["code"]["callers"] = _compact_validation_value(
        function_context.get("callers") or [],
        max_list_items=8,
        max_string_chars=700,
    )
    result["code"]["callees"] = _compact_validation_value(
        function_context.get("callees") or [],
        max_list_items=12,
        max_string_chars=700,
    )

    semantic_claims = (
        issue.get("security_semantic_claims")
        or pack.get("security_semantic_claims")
        or pack.get("semantic_overlays")
        or []
    )
    if isinstance(semantic_claims, Mapping):
        semantic_claims = list(semantic_claims.values())
    if not isinstance(semantic_claims, list):
        semantic_claims = []
    result["semantic_claims"] = [
        _compact_validation_value(item, max_list_items=8, max_string_chars=1200)
        for item in semantic_claims[:16]
        if isinstance(item, Mapping)
    ]
    result["evidence_delta"] = _compact_validation_value(
        dict(evidence_delta or {}),
        max_list_items=24,
        max_string_chars=1800,
    )
    record_projection(result, "decision_facts.facts", fact_payloads, result["decision_facts"]["facts"])
    for key in ("snapshot_summary", "callers", "callees"):
        original: Any = function_context.get(key) or ({} if key == "snapshot_summary" else [])
        record_projection(result, "code." + key, original, result["code"][key])
    record_projection(result, "semantic_claims", semantic_claims, result["semantic_claims"])
    record_projection(result, "evidence_delta", dict(evidence_delta or {}), result["evidence_delta"])

    # Project knowledge keeps its full audit envelope in the evidence pack and
    # exposes only the decision-relevant projection to the Validator model.
    project_knowledge = pack.get("project_knowledge")
    if isinstance(project_knowledge, Mapping):
        result["project_knowledge"] = _compact_validation_value(
            build_validator_project_knowledge_projection(project_knowledge, issue),
            # The list cap must not be lower than the Wiki selection caps:
            # a selected constraint that is silently dropped here is lost with
            # no omitted-entry identity, unlike the token-budget selector.
            max_list_items=max(
                _WIKI_SELECTION_MAX_LIST_ITEMS,
                _PROJECT_KNOWLEDGE_PROJECTION_LIST_ITEMS,
            ),
            max_string_chars=1800,
        )

    catalog: Dict[str, Dict[str, Any]] = {}

    def add_ref(ref: Any, kind: str, summary: Any = "") -> None:
        normalized = str(ref or "").strip()
        if not normalized or len(catalog) >= 128:
            return
        catalog.setdefault(
            normalized,
            {
                "kind": kind,
                "summary": _compact_validation_value(summary, max_string_chars=600),
            },
        )

    decision = result.get("decision_facts") or {}
    for ref in decision.get("fact_uids") or []:
        add_ref(ref, "decision_fact")
    for ref in decision.get("edge_uids") or []:
        add_ref(ref, "path_edge")
    for ref in decision.get("dependency_code_hashes") or []:
        add_ref(ref, "code_hash")
    for fact in decision.get("facts") or []:
        if not isinstance(fact, Mapping):
            continue
        add_ref(
            fact.get("fact_uid") or fact.get("uid") or fact.get("id"),
            "decision_fact",
            fact,
        )
    for proof in decision.get("deterministic_proofs") or []:
        if not isinstance(proof, Mapping):
            continue
        for ref in proof.get("fact_ids") or []:
            add_ref(ref, "proof_fact", proof.get("summary"))
        add_ref(proof.get("code_hash"), "code_hash", proof.get("summary"))
    for ref in pack.get("evidence_refs") or []:
        add_ref(ref, "candidate_evidence")
    for index, value in enumerate(result.get("evidence", {}).get("positive") or []):
        add_ref(f"evidence:positive:{index}", "positive_evidence", value)
    for index, value in enumerate(result.get("evidence", {}).get("negative") or []):
        add_ref(f"evidence:negative:{index}", "negative_evidence", value)
    path = result.get("canonical_occurrence", {}).get("representative_call_path") or []
    for index, (caller, callee) in enumerate(zip(path, path[1:])):
        add_ref(f"path-edge:{index}:{caller}->{callee}", "call_path", [caller, callee])
    location = result.get("obligation", {}).get("location")
    if location:
        add_ref(f"location:{location}", "source_location", location)
    for claim in result.get("semantic_claims") or []:
        if not isinstance(claim, Mapping):
            continue
        add_ref(claim.get("claim_id"), "semantic_claim", claim)
        for ref in claim.get("evidence_refs") or []:
            add_ref(ref, "semantic_claim_evidence", claim.get("kind"))
    delta = result.get("evidence_delta")
    if isinstance(delta, Mapping):
        for ref in delta.get("evidence_refs") or []:
            add_ref(ref, "evidence_delta")
        for fact in delta.get("facts") or []:
            if isinstance(fact, Mapping):
                add_ref(
                    fact.get("fact_uid") or fact.get("uid") or fact.get("id"),
                    "evidence_delta_fact",
                    fact,
                )
    result["evidence_ref_catalog"] = catalog
    knowledge = result.get("project_knowledge")
    if isinstance(knowledge, Mapping):
        for item in knowledge.get("constraints") or []:
            if isinstance(item, Mapping):
                add_ref(item.get("constraint_id"), "project_constraint", item.get("statement"))
                for ref in item.get("source_refs") or []:
                    add_ref(ref, "project_document_ref", item.get("statement"))
        for item in knowledge.get("source_excerpts") or []:
            if isinstance(item, Mapping):
                add_ref(item.get("ref_id"), "project_document_ref", item.get("relative_path"))
    return result


def normalize_missing_fact_kinds(value: Any) -> List[str]:
    """Project obligation vocabulary onto Validator/provider fact kinds.

    Security obligations retain low-level event labels for provenance, while
    evidence completion and V3 promotion operate on the fixed public fact
    vocabulary.  Keeping this projection in one place prevents an event label
    that no provider or Validator tool can emit from becoming an impossible
    promotion requirement.
    """

    raw_values = value if isinstance(value, list) else [value]
    result: List[str] = []
    aliases = {
        "event:shared_state_access": "lockset",
        "event:acquire": "ownership_transfer",
        "event:exit": "cleanup_coverage",
        "reachability": "source_sink_reachability",
        "contract": "caller_contract",
    }
    for raw in raw_values:
        text = str(raw or "").strip().lower()
        if not text:
            continue
        normalized = aliases.get(text, text)
        if normalized not in VALIDATOR_MISSING_FACT_KINDS:
            continue
        if normalized not in result:
            result.append(normalized)
    return result


# Private compatibility name for older in-module callers and historical
# imports.  New code should use the public normalizer above.
_normalized_missing_fact_kinds = normalize_missing_fact_kinds


def category_validation_requirements(issue: Dict[str, Any]) -> List[str]:
    category = (
        str(issue.get("defect_class") or issue.get("subcategory") or issue.get("category") or "")
        .replace("-", "_")
        .lower()
    )
    requirements_by_category: Dict[str, List[str]] = {
        "signed_unsigned": [
            "For signed/unsigned conversion, a negative signed return cast to size_t before a copy/IO length is a concrete sink when the pre-cast value is not checked.",
            "A post-cast warning or truncation log is not a sufficient guard if the dangerous copy/IO still executes.",
        ],
        "integer_overflow": [
            "For serialized/wire lengths, header-size addition and allocation/copy-size arithmetic require an explicit overflow or backing-buffer bound check.",
        ],
        "object_publication": [
            "For object publication, a pointer stored in a global/list/callback slot or ready flag set before member initialization is security-relevant if readers can observe the partially initialized object.",
            "Do not reject solely because the same function later initializes fields; compare publication order with reader visibility.",
        ],
        "memory_leak": [
            "Freeing a wrapper object does not release nested owned members, child lists, duplicated strings, mutexes, or role-specific resources unless code shows that cleanup explicitly.",
            "A role-specific release helper only proves cleanup for the role it actually receives; compare stored role and release argument.",
            "If the candidate names a member/child allocation as the leaked resource, do not reject it merely because the parent container is freed.",
            "If an insert/link helper can attach an object to a global structure and then return failure, an ignored return value can lose rollback and cleanup ownership; global reachability alone does not prove a valid cleanup protocol.",
            "Do not reinterpret a negative helper return as success unless a documented or enforced contract proves that negative status is an expected non-failure mode.",
        ],
        "infinite_loop": [
            "For poisoned/self-linked list nodes, evaluate concurrent or stale iterators that may already hold the node before unlink; a fresh traversal from the current head is not sufficient to disprove the loop.",
            "A self-link used as a poison marker needs a visible traversal guard; otherwise any walker that follows next pointers can spin on the same node.",
        ],
        "log_amplification": [
            "A self-referential or poisoned traversal with a loop-internal log/error emission can be a resource-exhaustion defect even without memory corruption.",
            "For traversal findings, consider stale/current iterator state and concurrent mutation paths, not only whether a fresh traversal from the head reaches the node.",
        ],
        "race": [
            "Macro-guarded locks must be evaluated under all configured compilation branches; a no-op lock branch does not protect shared state.",
        ],
        "reader_state_race": [
            "For reader-state races, atomic reader-count operations do not protect side fields such as reader identity unless that side field is also atomic or protected by the rwlock protocol.",
        ],
        "global_mode_race": [
            "For global-mode races, registration, mode selection, and callback dispatch must be protected by a common lock or immutable mode snapshot.",
        ],
        "registration_race": [
            "For registration races, a pre-lock check of a global slot/list followed by a later locked update is still a race; validation must require one lock covering check and update.",
        ],
        "key_generation_race": [
            "For ftok-style key generation, path existence/state checks and key derivation/registration must be atomic with respect to path changes or use a stable opened object.",
        ],
        "slot_race": [
            "For slot-claim races, an ignored CAS/compare-exchange result is a concrete bug when field writes continue after a failed claim could leave the slot owned by another thread.",
        ],
        "shared_memory_race": [
            "For create-if-absent shared resources, lookup and insertion must be atomic under the same lock; a pre-lock lookup is not sufficient.",
        ],
        "callback_self_destroy_race": [
            "For callback self-destruction, validate whether the callback receives the current object as context and can release it before the caller resumes dereferencing it.",
        ],
        "premature_destroy": [
            "For premature-destroy findings, freeing a shared pool/object while an active task/refcount branch says users remain is a concrete lifetime bug unless the code first waits, refcounts, or marks all users stopped.",
            "Publishing a global/shared pointer and then freeing that same global object in the active-user branch leaves a dangling shared reference even if allocation happened in the same function.",
        ],
        "alloc_free_mismatch": [
            "For allocator/free mismatch, allocation and release callbacks must be registered and selected as a validated pair; a no-op/free callback paired with a custom/header allocator is not safe by type compatibility alone.",
        ],
        "sigpipe_unhandled": [
            "For peer writes, write/send paths to sockets or peer fds need SIGPIPE suppression or handling; checking the negative return value is insufficient if the process can receive SIGPIPE first.",
        ],
        "lost_wakeup": [
            "For wakeup bugs, publishing an event/list node is not enough; require a signal, trigger, scheduler kick, or documented polling guarantee for the consumer.",
        ],
        "signal_deadlock": [
            "For signal/exception handlers, locks, semaphores, formatting, and logging are unsafe when the path can run asynchronously or re-enter code holding the same primitive.",
        ],
        "signal_race": [
            "For signal/exception handlers, allocation, logging, and writes to shared global state are unsafe unless the code uses an async-signal-safe handoff such as writing minimal data to a pipe or atomic flag.",
            "Do not reject signal shared-state findings solely because writes are local to the handler; the handler can asynchronously interleave with normal code that owns or reads the same global state.",
        ],
        "held_lock_callback": [
            "Calling a callback/function pointer while holding a non-recursive lock is a lock-order and reentrancy risk when the callback is externally supplied, stored globally, or can evolve independently of the current no-op sample.",
            "Do not reject solely because the currently registered callback body is empty; validate the callback registration contract and whether callers control the callback.",
        ],
        "alignment": [
            "Casting byte-buffer offsets such as packet + 1 to integer pointers is undefined behavior on strict-alignment targets and can be security-relevant when reachable from an external parsing API.",
            "Do not reduce unaligned dereference to a style issue solely because one wrapper currently passes a local buffer; validate the exposed parser contract and callee signature.",
        ],
        "unchecked_return": [
            "Returning success from a classifier/probe branch after a lower-level error or ambiguous status is a concrete contract bug when callers use zero as success.",
        ],
        "state_inconsistency": [
            "For state restoration, saving `previous` is not a guard unless the changed state is restored on every failure path before return.",
            "A later assignment like `previous = state` is not restoration; require `state = previous` before the failure return.",
        ],
        "fd_type_mismatch": [
            "Reliable/encoded descriptors and raw file descriptors are distinct API contracts; passing one representation to the other validator is a concrete misuse even if both are integers.",
            "A representation mismatch remains valid when the raw-fd helper fails closed or rejects the encoded value; the issue is the reachable API-contract break and lost descriptor operation, not only memory corruption.",
        ],
        "protocol_mixup": [
            "Protocol mismatch accepted on a non-strict/auth fallback is a boundary validation issue, not a harmless style choice.",
        ],
        "version_filtering": [
            "Parsing a protocol version and explicitly ignoring it means low/unsupported versions can reach state processing unless another guard proves otherwise.",
        ],
        "size_limit_mismatch": [
            "When a byte cache limit and an element-count specification are both present, validate whether the computed byte limit can reject or mis-size values that the public count contract says are valid.",
        ],
        "busy_loop": [
            "For receive/read retry loops, EAGAIN/EINTR handling needs a timeout, retry budget, blocking wait, or caller-visible failure; a bare continue can be a resource-exhaustion path.",
        ],
        "dynamic_array_race": [
            "For global dynamic array resizing, the capacity check, new allocation, global pointer publish, capacity update, and old-array free must be protected by the same lock or atomic handoff.",
        ],
        "fd_encoding_mismatch": [
            "Raw fd indexes must not be passed to validators expecting encoded/check-value fds unless code constructs the encoded representation first.",
            "Do not reject solely because the mixed representation fails closed in one local branch; the finding is the reachable API-contract mismatch between raw fd indexes and encoded/check-value fd validators.",
        ],
        "semantic_mismatch": [
            "For semantic-contract mismatches, type compatibility is not enough; compare the unit/domain promised by the caller with the callee's documented or inferred contract.",
            "A callee parameter name, accumulator field, threshold, or downstream side effect can establish the expected unit even when the C type is only int.",
        ],
        "byte_order_logic": [
            "For byte-order logic, copying wire bytes into host integers and using bit-index operations requires explicit endian normalization or a byte-order-independent scan.",
            "If the computed byte/bit offset influences a later decision, index, copy, or status value, treat the host-order-dependent offset as a concrete semantic sink.",
        ],
        "uninitialized_output": [
            "For output-parameter structs, require memset/zero initialization or assignments for all externally visible fields before copying the temporary object to the caller.",
        ],
        "file_type_validation": [
            "For mapping/file validation, regular files, character devices, shared memory, and anonymous mappings can require different size/existence checks.",
        ],
        "log_level_misuse": [
            "For log-level findings, verify that the branch represents a normal/idempotent state and returns success; ERROR logs in such paths can create alert pollution rather than a functional failure.",
        ],
        "logic_error": [
            "For traversal logic errors, compare the index used to select a parent/group object with the index used to access the member; cached traversal state can go stale across loop iterations.",
        ],
        "state_machine": [
            "For state-machine findings, every successful publication branch must transition the shared lifecycle state consistently with the identity/data fields it publishes.",
        ],
    }
    return list(requirements_by_category.get(category, []))


def trim_code(code: str, max_lines: int = 140) -> str:
    lines = str(code or "").splitlines()
    if len(lines) <= max_lines:
        return code
    head = max_lines // 2
    tail = max_lines - head
    return "\n".join(
        lines[:head] + ["/* ... trimmed for validator evidence pack ... */"] + lines[-tail:]
    )


def compact_snapshot(snapshot: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(snapshot, dict):
        return None
    compact = {
        "summary": snapshot.get("summary"),
        "parameters": snapshot.get("parameters"),
        "return_values": snapshot.get("return_values"),
        "effects": snapshot.get("effects"),
        "error_handling": snapshot.get("error_handling"),
        "project_callees": snapshot.get("project_callees"),
        "external_callees": snapshot.get("external_callees"),
        "referenced_globals": snapshot.get("referenced_globals"),
        "referenced_macros": snapshot.get("referenced_macros"),
        "referenced_types": _compact_referenced_types_for_evidence(
            snapshot.get("referenced_types")
        ),
        "suspicious_points": snapshot.get("suspicious_points"),
    }
    for field in (
        "project_callees_truncation",
        "external_callees_truncation",
        "referenced_globals_truncation",
        "referenced_macros_truncation",
        "unresolved_referenced_types",
        "referenced_types_truncation",
    ):
        if field in snapshot:
            compact[field] = snapshot[field]
    return compact


def _compact_referenced_types_for_evidence(
    value: Any,
    definition_bytes_limit: int = 16 * 1024,
) -> List[Dict[str, Any]]:
    """Keep every type identity while bounding definition text in validator prompts."""
    result: List[Dict[str, Any]] = []
    used = 0
    for raw_item in value if isinstance(value, list) else []:
        if not isinstance(raw_item, dict):
            continue
        item = deepcopy(raw_item)
        definition = str(item.get("full_definition") or "")
        definition_bytes = len(definition.encode("utf-8"))
        if used + definition_bytes <= definition_bytes_limit:
            used += definition_bytes
        else:
            item.pop("full_definition", None)
            item["definition_omitted"] = "validation_evidence_byte_budget"
        result.append(item)
    return result


def _entry_root_reachable(evidence_pack: Dict[str, Any]) -> bool:
    entry_context = evidence_pack.get("entry_context")
    if not isinstance(entry_context, dict):
        return False
    return bool(
        entry_context.get("entry_is_external_root") and entry_context.get("reachable_from_entry")
    )


def _entry_exposure_from_prompt(entry_custom_prompt: str) -> str:
    prompt_lower = str(entry_custom_prompt or "").lower()
    if "public api declared" in prompt_lower or "header file" in prompt_lower:
        return "api"
    if "communication or ipc entry" in prompt_lower:
        return "communication"
    if "thread entry" in prompt_lower or "thread creator" in prompt_lower:
        return "thread"
    if "user-controlled input entry" in prompt_lower:
        return "other_user_input"
    return "configured"


def _base_validation_requirements() -> List[str]:
    return [
        "Treat every candidate as evidence only; do not accept it solely because a regex, graph, or backend rule emitted it.",
        "Independently audit semantic overlay assumptions from user_config, including custom alloc/free/lock/macros and pointer target models.",
        "Return verdict=verified only if there is a concrete public/API or caller-controlled trigger path.",
        "Return verdict=rejected when local evidence or guards disprove the candidate.",
        "Return verdict=uncertain only when the candidate is plausible but decisive context is missing.",
        "Identify source, sink, source controllability, and the missing/insufficient guard.",
        "Reject hardening/style/theoretical findings without a source-to-sink path.",
        "For integer overflow, multiplication/addition must be checked before the operation or by a proven bounded operand.",
        "When this evidence pack names a current analysis entry, treat that configured/header-discovered entry as the public trigger for internal callee findings.",
        "The current_analysis_entry is the root selected for this scan. It is normal for a header/configured root to have zero repository callers, to be absent from main, or to have no separate worker/start wrapper; do not use those facts alone as dead-code evidence.",
        "When entry_is_external_root is true and reachable_from_entry/call_path evidence connects the entry to the sink, validate triggerability from an external invocation of the entry and its parameters, task payload, received bytes, or callback contract; do not require an additional repository-internal caller above the entry.",
        "Do not reject an internal callee solely because its direct caller list is empty; rely on entry exposure and call-path evidence instead.",
        "If reachable_from_entry, complete_to_entry, call_path, or entry_function evidence is present, reject reachability only when code evidence disproves that specific path.",
        "If the only negative reachability evidence is zero callers for current_analysis_entry, absence from main, or absence of a worker creator, choose uncertain instead of rejected unless code disproves the entry-to-sink path.",
    ]


FINDING_CORE_FIELDS = (
    "id",
    "candidate_id",
    "candidate_source",
    "candidate_role",
    "candidate_schema_version",
    "candidate_uid",
    "occurrence_uid",
    "history_key",
    "evidence_hash",
    "decision_evidence_hash",
    "provenance_hash",
    "validation_cluster_uid",
    "context_signature",
    "dedup_key",
    "function",
    "entry_function",
    "sink_function",
    "target_function",
    "location",
    "file",
    "line",
    "start_line",
    "end_line",
    "category",
    "subcategory",
    "defect_class",
    "cwe",
    "confidence",
    "rule_confidence",
    "impact_level",
    "source",
    "sink",
    "description",
    "reasoning",
    "root_cause",
    "suggested_fix",
    "guard_analysis",
    "exploit_scenario",
    "validation_status",
    "finding_kind",
    "reachable_from_entry",
    "internal_sink_lifted",
    "call_path",
    "call_paths",
    "path_constraints",
    "evidence_refs",
    "positive_evidence",
    "negative_evidence",
    "code_snippet",
    "source_loc",
    "sink_loc",
    "backend_profile",
    "evidence_checker",
    "evidence_engines",
    "score_components",
    "validation_required",
    "audit_observation_reason",
    "proofs",
    "evidence_models",
    "va_unreviewed",
)

RAW_PAYLOAD_KEYS = {
    "raw",
    "raw_data",
    "raw_evidence",
    "raw_metadata",
    "raw_report",
    "raw_reports",
    "raw_output",
    "raw_outputs",
    "metadata",
    "reports",
    "report",
    "tool_output",
    "tool_outputs",
    "conversation",
    "messages",
    "full_ast",
    "ast_dump",
    "cfg_dump",
    "clang_dump",
    "joern_dump",
    "svf_dump",
}


def compact_validation_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return a validator-facing finding that keeps facts and trims bulky payloads."""
    compact = {
        key: _compact_validation_value(value)
        for key, value in finding.items()
        if key in FINDING_CORE_FIELDS and value not in (None, "", [], {})
    }

    evidence_pack = finding.get("evidence_pack")
    if isinstance(evidence_pack, dict):
        compact["evidence_summary"] = _compact_candidate_evidence(evidence_pack)
    return compact


def compact_validation_evidence_pack(evidence_pack: Dict[str, Any]) -> Dict[str, Any]:
    """Trim validator evidence without changing the semantic contract of the pack."""
    compact: Dict[str, Any] = {}
    omitted_keys: List[str] = []
    for key, value in evidence_pack.items():
        if _is_raw_payload_key(key):
            omitted_keys.append(key)
            continue
        if key == "candidate_evidence" and isinstance(value, dict):
            compact[key] = _compact_candidate_evidence(value)
        elif key in {"semantic_overlays", "semantic_overlay_evidence"}:
            compact[key] = _compact_validation_value(value, max_list_items=8, max_dict_items=16)
        else:
            compact[key] = _compact_validation_value(value)

    if omitted_keys:
        compact["compaction_metadata"] = {
            "omitted_large_payload_keys": sorted(omitted_keys),
            "policy": "validator_input_compaction",
        }
    return compact


def _compact_candidate_evidence(value: Dict[str, Any]) -> Dict[str, Any]:
    kept: Dict[str, Any] = {}
    omitted_keys: List[str] = []
    for key, item in value.items():
        if _is_raw_payload_key(key):
            omitted_keys.append(key)
            continue
        if key in {
            "id",
            "candidate_id",
            "candidate_source",
            "checker",
            "backend_profile",
            "defect_class",
            "category",
            "function",
            "entry_function",
            "sink_function",
            "target_function",
            "source",
            "sink",
            "location",
            "source_loc",
            "sink_loc",
            "path",
            "call_path",
            "call_paths",
            "evidence_refs",
            "positive_evidence",
            "negative_evidence",
            "finding_summary",
            "semantic_overlays",
            "evidence_models",
            "semantic_overlay_evidence",
            "path_constraints",
            "score_components",
            "validation_required",
            "audit_observation_reason",
            "proofs",
            "va_unreviewed",
        }:
            kept[key] = _compact_validation_value(item)

    if omitted_keys:
        kept["compaction_metadata"] = {
            "omitted_large_payload_keys": sorted(omitted_keys),
            "policy": "candidate_evidence_compaction",
        }
    return kept


def _compact_validation_value(
    value: Any,
    *,
    max_string_chars: int = 2400,
    max_list_items: int = 12,
    max_dict_items: int = 24,
) -> Any:
    if isinstance(value, str):
        return _trim_text(value, max_string_chars)
    if isinstance(value, list):
        compact_items = [
            _compact_validation_value(
                item,
                max_string_chars=max_string_chars,
                max_list_items=max_list_items,
                max_dict_items=max_dict_items,
            )
            for item in value[:max_list_items]
        ]
        if len(value) > max_list_items:
            compact_items.append({"omitted_items": len(value) - max_list_items})
        return compact_items
    if isinstance(value, dict):
        compact: Dict[str, Any] = {}
        omitted_keys: List[str] = []
        for idx, (key, item) in enumerate(value.items()):
            key_text = str(key)
            if _is_raw_payload_key(key_text):
                omitted_keys.append(key_text)
                continue
            if idx >= max_dict_items:
                omitted_keys.append(key_text)
                continue
            compact[key_text] = _compact_validation_value(
                item,
                max_string_chars=max_string_chars,
                max_list_items=max_list_items,
                max_dict_items=max_dict_items,
            )
        if omitted_keys:
            compact["_omitted_keys"] = sorted(omitted_keys)
        return compact
    return value


def _is_raw_payload_key(key: str) -> bool:
    normalized = str(key or "").strip().lower()
    if normalized in RAW_PAYLOAD_KEYS:
        return True
    return normalized.startswith("raw_") or normalized.endswith("_raw")


def _trim_text(value: str, max_chars: int) -> str:
    text = str(value or "")
    if len(text) <= max_chars:
        return text
    head = max_chars // 2
    tail = max_chars - head
    return text[:head] + "\n/* ... trimmed for validator input compaction ... */\n" + text[-tail:]
