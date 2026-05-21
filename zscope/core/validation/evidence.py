"""Validator-facing evidence pack and rejection-policy helpers."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from ...common.issue_identity import canonical_issue_key, flatten_issue_text, parse_issue_location


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
    return "rejected"


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
        "test case",
        "test code",
        "测试代码",
        "测试用例",
        "demo code",
        "example code",
        "model code",
        "模型代码",
        "benchmark",
        "fixture",
        "validation fixture",
        "real_model",
        "issue41",
        "td_run",
        "not production code",
        "non-production code",
        "非生产",
        "intentionally constructed",
        "intentionally vulnerable",
        "故意构造",
        "死代码",
        "不可达",
    )
    return any(term in text for term in dead_code_terms)


def is_entry_root_contract_scope_rejection(
    val_data: Dict[str, Any],
    evidence_pack: Dict[str, Any],
) -> bool:
    """Keep contract-sensitive reachable findings for review when validation is too local."""
    if validation_verdict(val_data) != "rejected":
        return False
    if not _entry_root_reachable(evidence_pack):
        return False
    category = str(
        evidence_pack.get("defect_class")
        or (evidence_pack.get("finding_summary") or {}).get("category")
        or ""
    ).replace("-", "_").lower()
    if category not in {
        "held_lock_callback",
        "log_amplification",
        "version_filtering",
        "fd_encoding_mismatch",
        "size_limit_mismatch",
        "busy_loop",
        "dynamic_array_race",
    }:
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
    scope_terms = (
        "current",
        "currently",
        "当前",
        "目前",
        "hardcoded",
        "hard-coded",
        "硬编码",
        "no-op",
        "empty callback",
        "空回调",
        "not controllable",
        "not caller controllable",
        "不可控",
        "无法控制",
        "fails closed",
        "one local branch",
        "only local",
        "本地分支",
        "dead code",
        "unreachable",
        "死代码",
        "不可达",
    )
    return any(term in text for term in scope_terms)


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

    snapshot = snapshot_store.load_snapshot(issue_func)
    try:
        callers = code_index.get_callers(issue_func, limit=8)
    except Exception:
        callers = []
    try:
        callees = code_index.get_callees(issue_func, limit=12)
    except Exception:
        callees = []

    agent_context = state.get("agent_context") if isinstance(state.get("agent_context"), dict) else {}
    analysis_entry = str(state.get("entry_func") or agent_context.get("func_name") or "").strip()
    issue_entry = str(issue.get("entry_function") or issue.get("analyzed_from") or "").strip()
    candidate_path = issue.get("call_path") or issue.get("call_paths")
    candidate_evidence = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    entry_custom_prompt = str(agent_context.get("entry_custom_prompt") or "")
    entry_exposure = _entry_exposure_from_prompt(entry_custom_prompt)
    entry_is_external_root = entry_exposure in {"api", "communication", "thread", "other_user_input"}
    reachable_from_entry = bool(
        issue.get("reachable_from_entry")
        or (analysis_entry and issue_func == analysis_entry)
        or issue_entry
        or candidate_evidence.get("entry_function")
        or (
            isinstance(candidate_evidence.get("path"), dict)
            and candidate_evidence.get("path", {}).get("complete_to_entry")
        )
    )
    validation_requirements = _base_validation_requirements()
    validation_requirements.extend(category_validation_requirements(issue))
    return {
        "mode": "tri_state_exploitability_validation",
        "dedup_key": issue.get("dedup_key") or issue_key_fn(issue),
        "candidate_id": issue.get("candidate_id") or issue.get("id"),
        "candidate_role": issue.get("candidate_role") or "evidence_only",
        "candidate_is_conclusion": False,
        "validation_required": True,
        "backend_profile": issue.get("backend_profile") or candidate_evidence.get("backend_profile"),
        "evidence_checker": issue.get("evidence_checker") or candidate_evidence.get("checker"),
        "evidence_engines": issue.get("evidence_engines") or candidate_evidence.get("evidence_engines") or [],
        "semantic_overlays": issue.get("semantic_overlays") or candidate_evidence.get("semantic_overlays") or {},
        "semantic_overlay_evidence": issue.get("semantic_overlay_evidence")
        or candidate_evidence.get("semantic_overlay_evidence")
        or {},
        "finding_kind": issue.get("finding_kind"),
        "defect_class": issue.get("defect_class") or issue.get("subcategory"),
        "rule_confidence": issue.get("rule_confidence"),
        "score_components": issue.get("score_components") or score_components_fn(issue, {}),
        "evidence_refs": issue.get("evidence_refs") or candidate_evidence.get("evidence_refs") or [],
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
                "Header-declared/configured entry function is an external scan root; "
                "zero repository callers does not make it dead code."
            )
            if entry_is_external_root
            else (
                "Configured entry function is the scan root; zero repository callers above "
                "the selected root is not sufficient dead-code evidence."
            ),
            "issue_entry_function": issue_entry,
            "reachable_from_entry": reachable_from_entry,
            "internal_sink_lifted": bool(issue.get("internal_sink_lifted")),
            "call_path": candidate_path or candidate_evidence.get("call_path"),
            "candidate_path": candidate_evidence.get("path") if isinstance(candidate_evidence, dict) else {},
        },
        "candidate_evidence": candidate_evidence,
        "positive_evidence": issue.get("positive_evidence") or candidate_evidence.get("positive_evidence") or [],
        "negative_evidence": issue.get("negative_evidence") or candidate_evidence.get("negative_evidence") or [],
        "primary_location_snippet": snippet,
        "function_context": {
            "code": trim_code(issue_code, max_lines=140),
            "snapshot_summary": compact_snapshot(snapshot),
            "callers": callers,
            "callees": callees,
        },
        "validation_requirements": validation_requirements,
    }


def category_validation_requirements(issue: Dict[str, Any]) -> List[str]:
    category = str(
        issue.get("defect_class")
        or issue.get("subcategory")
        or issue.get("category")
        or ""
    ).replace("-", "_").lower()
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
        ],
        "log_amplification": [
            "A self-referential or poisoned traversal with a loop-internal log/error emission can be a resource-exhaustion defect even without memory corruption.",
            "For traversal findings, consider stale/current iterator state and concurrent mutation paths, not only whether a fresh traversal from the head reaches the node.",
        ],
        "race": [
            "Macro-guarded locks must be evaluated under all configured compilation branches; a no-op lock branch does not protect shared state.",
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
    }
    return list(requirements_by_category.get(category, []))


def trim_code(code: str, max_lines: int = 140) -> str:
    lines = str(code or "").splitlines()
    if len(lines) <= max_lines:
        return code
    head = max_lines // 2
    tail = max_lines - head
    return "\n".join(lines[:head] + ["/* ... trimmed for validator evidence pack ... */"] + lines[-tail:])


def compact_snapshot(snapshot: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(snapshot, dict):
        return None
    return {
        "summary": snapshot.get("summary"),
        "resources": snapshot.get("resources"),
        "error_handling": snapshot.get("error_handling"),
        "concurrency": snapshot.get("concurrency"),
        "suspicious_points": snapshot.get("suspicious_points"),
        "semantic_fingerprint": snapshot.get("semantic_fingerprint"),
    }


def _entry_root_reachable(evidence_pack: Dict[str, Any]) -> bool:
    entry_context = evidence_pack.get("entry_context")
    if not isinstance(entry_context, dict):
        return False
    return bool(
        entry_context.get("entry_is_external_root")
        and entry_context.get("reachable_from_entry")
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
        "Do not reject an internal callee solely because its direct caller list is empty, its name looks like a test/demo/model, or it contains words such as real_model, issue, leak, race, or td_run; rely on entry exposure and call-path evidence instead.",
        "When the configured scan root is a benchmark, fixture, model, or validation corpus, treat files under that configured project root as the code under audit; names indicating a modeled bug are not a reason to reject a reachable defect.",
        "If reachable_from_entry, complete_to_entry, call_path, or entry_function evidence is present, reject reachability only when code evidence disproves that specific path.",
        "If the only negative reachability evidence is zero callers for current_analysis_entry, absence from main, or absence of a worker creator, choose uncertain instead of rejected unless code disproves the entry-to-sink path.",
    ]
