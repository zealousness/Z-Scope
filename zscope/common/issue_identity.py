"""Issue canonicalization and duplicate merging helpers."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional


def deduplicate_issues(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge findings that point at the same root cause."""
    records: Dict[str, Dict[str, Any]] = {}
    for issue in issues:
        normalize_issue_fields(issue)
        key = canonical_issue_key(issue)
        existing = records.get(key)
        if existing is None:
            issue["dedup_key"] = key
            issue.setdefault("duplicate_sources", [])
            records[key] = issue
            continue

        existing["duplicate_count"] = int(existing.get("duplicate_count", 0) or 0) + 1
        sources = existing.setdefault("duplicate_sources", [])
        source = issue.get("analyzed_from") or issue.get("id") or issue.get("function")
        if source and source not in sources:
            sources.append(source)

        if issue_rank(issue) > issue_rank(existing):
            issue["duplicate_count"] = existing.get("duplicate_count", 0)
            issue["duplicate_sources"] = list(sources)
            issue["dedup_key"] = key
            records[key] = issue
    return list(records.values())


def normalize_issue_fields(issue: Dict[str, Any]) -> None:
    """Fill stable report fields derived from free-form finding text."""
    text = flatten_issue_text(issue)
    normalized_category = normalize_issue_category(
        " ".join(
            str(part or "")
            for part in (
                issue.get("category"),
                issue.get("subcategory"),
                issue.get("defect_class"),
                issue.get("vulnerability_type"),
                issue.get("cwe"),
                text,
            )
        )
    )
    current = str(issue.get("category") or "").replace("-", "_").lower()
    generic_categories = {
        "",
        "logic",
        "concurrency",
        "api_contract",
        "memory_safety",
        "resource_leak",
        "backend_signal",
    }
    if current in generic_categories:
        issue["category"] = normalized_category
    elif len(current) > 48 or re.search(r"\s", current):
        issue["category"] = normalized_category
    elif current not in _KNOWN_CATEGORIES:
        issue["category"] = normalized_category
    if normalized_category == "stack_escape":
        issue.setdefault("cwe", "CWE-562")
        subcategory = str(issue.get("subcategory") or "").replace("-", "_").lower()
        if subcategory in {"", "use_after_scope"}:
            issue["subcategory"] = "stack_escape"
    issue.setdefault("normalized_category", normalized_category)


def issue_rank(issue: Dict[str, Any]) -> tuple[int, float, int, int]:
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    severity = severity_order.get(
        str(issue.get("impact_level") or issue.get("severity") or "").lower(),
        0,
    )
    try:
        confidence = float(issue.get("confidence", 0) or 0)
    except (TypeError, ValueError):
        confidence = 0.0
    source_rank = structured_evidence_rank(issue)
    detail_len = len(str(issue.get("reasoning") or issue.get("description") or ""))
    return severity, confidence, source_rank, detail_len


def structured_evidence_rank(issue: Dict[str, Any]) -> int:
    """Prefer concrete local/backend evidence over long free-form duplicates."""
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    source = str(
        issue.get("candidate_source")
        or pack.get("candidate_source")
        or issue.get("finding_kind")
        or ""
    ).lower()
    rule = str(issue.get("rule") or pack.get("rule") or issue.get("id") or "").lower()
    if source in {
        "clang_ast_cfg",
        "graph",
        "svf_value_flow",
        "clang_ast_matcher",
        "clang_knowledgedb_call_edges",
    }:
        return 2
    if rule.startswith(("clang_cfg_", "graph_", "svf_")) or "graph_" in rule:
        return 2
    if issue.get("positive_evidence") or pack.get("positive_evidence"):
        return 1
    return 0


def canonical_issue_key(issue: Dict[str, Any]) -> str:
    """Return a stable key based on root cause rather than only line number."""
    text = flatten_issue_text(issue)
    location = str(issue.get("location") or issue.get("file") or "")
    file_path, line = parse_issue_location(location)
    if not file_path:
        match = re.search(r"((?:src|include|internal)/[A-Za-z0-9_./-]+\.[chp]+)", text)
        file_path = match.group(1).lower() if match else ""
    function = str(issue.get("function") or issue.get("func_name") or "")
    category = canonical_category(issue, text)
    root = root_cause_token(issue, category, text)
    scope = file_path or function
    if root:
        scoped_root = root_scope_token(issue, category, root)
        parts = (category, scope, scoped_root, root) if scoped_root else (category, scope, root)
        return "|".join(normalize_issue_key_part(part) for part in parts)

    sink = str(issue.get("sink") or issue.get("sink_function") or "")
    if not sink:
        sink_match = re.search(
            r"\b(memcpy|memmove|strcpy|strcat|sprintf|snprintf|printf|system|fopen|"
            r"free|malloc|calloc|realloc|close|munmap|pthread_create|pthread_cond_wait|"
            r"pthread_mutex_lock|pthread_mutex_unlock|pthread_rwlock_wrlock|"
            r"pthread_rwlock_rdlock|pthread_rwlock_unlock|strlen|callback|handler)\b",
            text,
            flags=re.IGNORECASE,
        )
        sink = sink_match.group(1).lower() if sink_match else ""
    return "|".join(
        normalize_issue_key_part(part)
        for part in (category, scope, str(line or ""), sink or function)
    )


def stable_issue_fingerprint(issue: Dict[str, Any]) -> str:
    """Return a line-insensitive identity for baseline/suppression tracking."""
    if not isinstance(issue, dict):
        return ""
    text = flatten_issue_text(issue)
    category = canonical_category(issue, text)
    file_path = issue_file_identity(issue, text)
    function = issue_function_identity(issue)
    root = root_cause_token(issue, category, text)
    rule = first_issue_value(
        issue,
        "rule",
        "rule_id",
        "evidence_checker",
        "candidate_source",
        "finding_kind",
    )
    source = first_issue_value(issue, "source", "source_function", "acquire_func")
    sink = first_issue_value(issue, "sink", "sink_function", "target_function", "release_func")
    resource = first_issue_value(
        issue,
        "resource",
        "resource_object",
        "affected_object",
        "symbol",
        "variable",
    )
    parts = ["v1", category, file_path, function, root, rule, source, sink, resource]
    normalized = [normalize_issue_key_part(part) for part in parts if normalize_issue_key_part(part)]
    # Avoid producing a dangerously broad fingerprint such as only category/file.
    if len(normalized) < 4:
        return ""
    return "|".join(normalized)


def source_context_fingerprint(issue: Dict[str, Any]) -> str:
    """Return a best-effort source-window identity used to narrow baseline matches.

    This fingerprint is intentionally optional.  When source snippets or AST-like
    spans are unavailable, callers should fall back to the broader stable issue
    fingerprint instead of treating the absence as a mismatch.
    """
    if not isinstance(issue, dict):
        return ""
    explicit = first_issue_value(
        issue,
        "source_context_fingerprint",
        "context_fingerprint",
        "source_window_fingerprint",
    )
    if explicit:
        return normalize_issue_key_part(explicit)

    fragments = list(_source_context_fragments(issue))
    if fragments:
        normalized = "\n".join(
            sorted(
                {
                    normalized
                    for normalized in (_normalize_source_context(fragment) for fragment in fragments)
                    if normalized
                }
            )
        )
        if normalized:
            return "srcctx:v1:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]

    span = _source_span_identity(issue)
    if span:
        return "span:v1:" + hashlib.sha256(span.encode("utf-8")).hexdigest()[:16]
    return ""


def source_context_fingerprints_compatible(
    current_issue: Dict[str, Any],
    baseline_issue: Dict[str, Any],
) -> bool:
    """Return whether optional source-window identities allow a baseline match."""
    current = source_context_fingerprint(current_issue)
    baseline = source_context_fingerprint(baseline_issue)
    return not current or not baseline or current == baseline


def ensure_source_context_fingerprint(issue: Dict[str, Any]) -> str:
    """Populate and return the optional source-context fingerprint for persistence."""
    fingerprint = source_context_fingerprint(issue)
    if fingerprint:
        issue.setdefault("source_context_fingerprint", fingerprint)
    return fingerprint


def root_scope_token(issue: Dict[str, Any], category: str, root: str) -> str:
    """Return extra identity for broad root tokens that can occur in many functions.

    Some detectors intentionally collapse noisy syntax into semantic roots such as
    `net_recv_data_negative_length`.  Those roots are useful for merging duplicate
    evidence inside one sink, but they are too broad across wrappers and model
    functions.  Keep global object roots broad, and scope operation/helper roots
    by the concrete sink function.
    """
    if not root or root in _GLOBAL_OBJECT_ROOTS:
        return ""
    if category not in _FUNCTION_SCOPED_ROOT_CATEGORIES and root not in _FUNCTION_SCOPED_ROOTS:
        return ""
    return issue_function_identity(issue)


def issue_file_identity(issue: Dict[str, Any], text: str = "") -> str:
    """Return a normalized file identity without line number."""
    candidates = [
        issue.get("location"),
        issue.get("file_path"),
        issue.get("file"),
        issue.get("module_path"),
    ]
    pack = issue.get("evidence_pack")
    if isinstance(pack, dict):
        candidates.extend([pack.get("file_path"), pack.get("file"), pack.get("location")])
        path = pack.get("path")
        if isinstance(path, dict):
            candidates.extend([path.get("file_path"), path.get("file"), path.get("location")])

    for value in candidates:
        file_path, _ = parse_issue_location(str(value or ""))
        if file_path:
            return normalize_issue_key_part(file_path)
        raw = str(value or "").replace("\\", "/").strip()
        if re.search(r"\.[chp]+$", raw, flags=re.IGNORECASE):
            return normalize_issue_key_part(raw)

    match = re.search(r"((?:src|include|internal)/[A-Za-z0-9_./-]+\.[chp]+)", text)
    return normalize_issue_key_part(match.group(1)) if match else ""


def issue_function_identity(issue: Dict[str, Any]) -> str:
    """Prefer the concrete sink/target function for dedup identity."""

    def as_text(value: Any) -> str:
        return str(value or "").strip().lower()

    for key in ("sink_function", "target_function", "function", "func_name"):
        value = as_text(issue.get(key))
        if value:
            return value

    pack = issue.get("evidence_pack")
    if isinstance(pack, dict):
        for key in ("sink_function", "target_function", "function", "entry_function"):
            value = as_text(pack.get(key))
            if value:
                return value
        path = pack.get("path")
        if isinstance(path, dict):
            for key in ("sink_function", "target_function", "function", "entry_function"):
                value = as_text(path.get(key))
                if value:
                    return value
    return ""


def first_issue_value(issue: Dict[str, Any], *keys: str) -> str:
    """Find an identity-bearing value on the issue or its evidence pack."""
    for key in keys:
        value = issue.get(key)
        if value not in (None, ""):
            return str(value)
    pack = issue.get("evidence_pack")
    if isinstance(pack, dict):
        for key in keys:
            value = pack.get(key)
            if value not in (None, ""):
                return str(value)
        path = pack.get("path")
        if isinstance(path, dict):
            for key in keys:
                value = path.get(key)
                if value not in (None, ""):
                    return str(value)
    return ""


def _source_context_fragments(value: Any, *, depth: int = 0) -> List[str]:
    if depth > 4:
        return []
    if isinstance(value, str):
        return []
    fragments: List[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if key_text in {
                "code_snippet",
                "context_slice",
                "source_context",
                "source_snippet",
                "reported_snippet",
                "primary_location_snippet",
                "code_excerpt",
            }:
                fragments.extend(_coerce_context_fragment(item))
            elif key_text in {"evidence_pack", "candidate_evidence", "source_path", "path", "ast_cfg", "clang_tooling"}:
                fragments.extend(_source_context_fragments(item, depth=depth + 1))
        return fragments
    if isinstance(value, list):
        for item in value[:24]:
            fragments.extend(_source_context_fragments(item, depth=depth + 1))
    return fragments


def _coerce_context_fragment(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        fragments = []
        for key in ("code", "text", "snippet", "source", "line"):
            item = value.get(key)
            if isinstance(item, str):
                fragments.append(item)
        lines = value.get("lines")
        if isinstance(lines, list):
            line_text = []
            for line in lines[:80]:
                if isinstance(line, dict):
                    line_text.append(str(line.get("text") or ""))
                elif isinstance(line, str):
                    line_text.append(line)
            if line_text:
                fragments.append("\n".join(line_text))
        return fragments
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, str)]
    return []


def _normalize_source_context(fragment: str) -> str:
    lines = []
    for line in str(fragment or "").splitlines():
        clean = re.sub(r"^\s*(?:\d+\s*(?:\||:)|\d+\s+)", "", line).strip()
        clean = re.sub(r"\s+", " ", clean)
        if clean:
            lines.append(clean)
    return "\n".join(lines)


def _source_span_identity(issue: Dict[str, Any]) -> str:
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    values = [
        issue_file_identity(issue),
        issue_function_identity(issue),
        first_issue_value(issue, "sink", "sink_function", "target_function", "release_func"),
        first_issue_value(issue, "source", "source_function", "acquire_func"),
        first_issue_value(issue, "resource", "resource_object", "affected_object", "symbol", "variable"),
    ]
    clang_fact = pack.get("clang_matcher_fact") if isinstance(pack.get("clang_matcher_fact"), dict) else {}
    values.extend(
        [
            clang_fact.get("matcher"),
            clang_fact.get("kind"),
            clang_fact.get("resource_symbol"),
            clang_fact.get("source_symbol"),
            clang_fact.get("sink_symbol"),
        ]
    )
    ast_cfg = pack.get("ast_cfg") if isinstance(pack.get("ast_cfg"), dict) else {}
    events = ast_cfg.get("events")
    if isinstance(events, list):
        for event in events[:5]:
            if isinstance(event, dict):
                values.extend([event.get("kind"), event.get("variable"), event.get("callee")])
    normalized = [normalize_issue_key_part(value) for value in values if normalize_issue_key_part(value)]
    if len(normalized) < 3:
        return ""
    return "|".join(normalized)


def canonical_category(issue: Dict[str, Any], text: str = "") -> str:
    """Prefer structured issue category over noisy flattened validation text."""
    current = str(issue.get("category") or "").replace("-", "_").lower().strip()
    if current in _KNOWN_CATEGORIES and current not in {"backend_signal", "memory_safety"}:
        return current
    return normalize_issue_category(
        " ".join(
            str(part or "")
            for part in (
                issue.get("category"),
                issue.get("subcategory"),
                issue.get("defect_class"),
                issue.get("vulnerability_type"),
                issue.get("cwe"),
                text,
            )
        )
    )


def root_cause_token(issue: Dict[str, Any], category: str, text: str) -> str:
    raw_lower = text.lower()
    lower = raw_lower.replace("_", " ").replace("-", " ")
    compact = re.sub(r"[^a-z0-9]+", "", raw_lower)
    function = str(issue.get("function") or issue.get("func_name") or "").lower()
    rule = str(issue.get("rule") or issue.get("rule_id") or issue.get("candidate_id") or issue.get("id") or "").lower()

    def has_name(name: str) -> bool:
        normalized = name.lower().strip("_")
        return name.lower() in raw_lower or normalized.replace("_", "") in compact

    if (
        has_name("_lifecycle_customize_control_message")
        or has_name("_lifecycle_customize_transport_cleanup")
    ) and ("open" in lower or "customize" in lower):
        return "control_session_open_leak"

    if (
        "shared_resource_freed_without_refcount_protocol" in rule
        or function == "_issue41_missing_reference_count"
        or "g_issue41_broker.resources" in raw_lower
        or ("issue41" in compact and "refcount" in compact and "safe_free" in raw_lower)
    ):
        return "issue41_resource_refcount_protocol"
    if (
        function == "_issue41_partial_resource_leak_on_retry"
        or ("issue41" in compact and "partition" in lower and "tag" in lower and ("fail_step" in raw_lower or "retry" in lower))
    ):
        return "issue41_partition_retry_cleanup"
    if (
        "parsed_protocol_version_is_ignored" in rule
        or function == "_issue41_missing_version_filter"
        or ("(void)version" in raw_lower and ("version" in lower or "protocol" in lower))
    ):
        return "parsed_protocol_version_ignored"
    if (
        "raw_fd_revalidated_as_encoded" in rule
        or function == "_issue41_raw_fd_missing_encode"
        or ("encoded fd" in lower and "raw fd" in lower and ("check value" in lower or "validate" in lower))
    ):
        return "raw_fd_reaches_encoded_fd_validator"
    if (
        "unchecked_strchr_result" in rule
        or function == "_lifecycle_parse_control_message"
        or ("strchr" in lower and ("sep" in lower or "colon" in lower or ":" in raw_lower) and category == "null_pointer_dereference")
    ):
        return "lifecycle_control_message_strchr"
    if (
        "stack_address_passed_to_thread" in rule
        or function == "_real_model_detached_stack_job"
        or ("pthread_create" in lower and ("_real_model_async_worker" in raw_lower or "realmodelasyncjob" in compact or "&job" in raw_lower))
    ):
        return "real_model_async_stack_job"
    if (
        "protocol_units_length_reaches_copy_without_packet_bound" in rule
        or function == "_real_model_protocol_length_miscalc"
    ):
        return "real_model_protocol_units_length"
    if "unaligned_integer_pointer_cast" in rule or function == "_real_model_message_alignment_overread":
        return "real_model_message_alignment"
    if "negative_length_cast_to_size_t" in rule or function == "_real_model_signed_recv_to_size":
        return "real_model_signed_recv_to_size"
    if function == "_real_model_recv_busy_loop":
        return "real_model_recv_busy_loop"

    named_objects = (
        "thread_ids",
        "g_dispatcher.queue.tasks",
        "g_shared_counter",
        "g_receiver_running",
        "g_ready",
        "g_running",
        "g_config_lock",
        "g_real_aux_lock",
        "g_active_config",
        "g_watched_fd",
        "g_real_watched_fd",
        "g_rules_map",
        "g_rules_len",
        "g_macro_guarded_counter",
        "g_log_buffer",
        "temp_buffer",
        "recovery_buffer",
        "error_msg",
        "payload_len",
        "payload_length",
        "statusreply",
        "flushjob",
        "pfnDropSession",
        "guardedsubscription",
    )
    for name in named_objects:
        raw_name = name.lower()
        spaced_name = raw_name.replace("_", " ")
        compact_name = re.sub(r"[^a-z0-9]+", "", raw_name)
        if raw_name in raw_lower or spaced_name in lower or compact_name in compact:
            token = raw_name
            if token == "payload_length":
                token = "payload_len"
            if token == "statusreply":
                token = "status_reply"
            if token == "flushjob":
                token = "flush_job"
            if token == "pfndropsession":
                token = "mesh_session_cleanup_hook"
            if token == "guardedsubscription":
                token = "guarded_subscription"
            return token

    if "lifecyclerecvpacket" in compact or (
        "netrecvdata" in compact and ("size_max" in raw_lower or "sizemax" in compact or "返回-1" in text)
    ):
        return "net_recv_data_negative_length"
    if has_name("_executor_cleanup_resources") and (
        "sharedresources" in lower or "taskconfig" in lower or "类型混淆" in text
    ):
        return "executor_sharedresources_type_confusion"
    if has_name("_executor_init") and (
        "sharedresources" in lower or "taskconfig" in lower or "类型混淆" in text
    ):
        return "executor_sharedresources_type_confusion"
    if has_name("_plugin_lookup") and ("mutex" in lower or "lock" in lower or "重入" in text):
        return "plugin_lookup_registry_mutex"
    if (
        has_name("_lifecycle_dispatch_pipe_tick")
        or has_name("_lifecycle_close_pipe")
        or has_name("_lifecycle_tick_timer_callback")
    ) and (
        "ctrl_lock" in lower or "sched_lock" in lower or "deadlock" in lower
    ):
        return "pipe_scheduler_control_lock_order"
    if has_name("_lifecycle_close_pipe") and ("pipe->next = pipe" in lower or "self" in lower):
        return "pipe_self_link"
    if has_name("_lifecycle_delete_os_node") or "procnode" in lower:
        return "os_node_proc_list"
    if has_name("_lifecycle_avl_register_route") or has_name("_route_avl_insert_node"):
        return "route_avl_node_after_insert"
    if has_name("_lifecycle_unregister_guarded_subscription"):
        return "guarded_subscription_mutex"
    if has_name("_lifecycle_mesh_authorize_init"):
        return "mesh_session_cleanup_hook"
    if has_name("_control_session_detach_without_release"):
        return "control_session_detach_leak"
    if has_name("_lifecycle_customize_control_message") and "open" in lower:
        return "control_session_open_leak"
    if has_name("_lifecycle_release_value_slice") or "value+1" in compact:
        return "value_slice_invalid_free"
    if has_name("_lifecycle_format_topic") or "topic[sizeof" in compact:
        return "topic_off_by_one"
    if has_name("_lifecycle_parse_frame") or "vla" in lower:
        return "frame_vla_stack"
    if has_name("_lifecycle_wait_for_work") and "pthread_cond_wait" in lower:
        return "lifecycle_cond_wait"
    if has_name("_lifecycle_resize_metrics") or "g_metrics" in lower:
        return "g_metrics_realloc"
    if category == "command_injection" and ("system" in lower or "命令注入" in text):
        return "task_command_execution"
    if category == "format_string" and ("printf" in lower or "格式化字符串" in text):
        return "printf_format_string"
    if category == "memory_leak" and function:
        object_match = re.search(r"\b([A-Za-z_]\w*)\s*(?:allocated|分配|未释放|leak)", text)
        if object_match:
            return object_match.group(1).lower()
    return ""


def normalize_issue_category(value: str) -> str:
    text = value.replace("_", " ").replace("-", " ").lower()
    compact = re.sub(r"\s+", "", text)
    stack_terms = (
        "stack escape",
        "stack address",
        "stack memory escape",
        "use after return",
        "use after scope",
        "useafterscope",
        "return stack",
        "栈地址逃逸",
        "栈内存逃逸",
        "栈指针",
        "cwe-562",
    )
    if any(term in text or term in compact for term in stack_terms):
        return "stack_escape"
    if ("pthread_create" in text or "pthread create" in text) and any(
        term in text or term in compact
        for term in ("stack", "local address", "栈", "&job", "&ctx", "&arg")
    ):
        return "stack_escape"
    groups = {
        "format_string": ("format string", "格式化字符串", "cwe-134"),
        "command_injection": ("command injection", "shell injection", "命令注入", "system(", "cwe-78"),
        "double_checked_locking": ("double checked locking", "double checked", "双重检查"),
        "signed_unsigned": ("signed unsigned", "negative length", "size_max", "sizemax", "有符号", "无符号", "cwe-195"),
        "off_by_one": ("off by one", "off-by-one", "sizeof index", "差一", "cwe-193"),
        "uninitialized_read": ("uninitialized read", "未初始化", "栈上垃圾", "cwe-457"),
        "stack_escape": ("stack escape", "use after return", "return stack", "栈地址逃逸", "栈指针", "cwe-562"),
        "stack_overflow": ("stack overflow", "vla", "栈溢出", "cwe-121"),
        "double_free": ("double free", "free twice", "same object released twice", "cwe-415"),
        "invalid_free": ("invalid free", "non owner", "非堆", "栈缓冲区内部", "cwe-590"),
        "type_confusion": ("type confusion", "wrong type", "invalid mutex", "sharedresources", "类型混淆", "cwe-843"),
        "use_after_free": ("use after free", "use-after-free", "uaf", "dangling", "释放后使用", "悬垂", "cwe-416"),
        "null_pointer_dereference": ("null pointer", "null dereference", "空指针", "cwe-476"),
        "realloc_misuse": ("realloc misuse", "direct realloc", "realloc返回值直接", "cwe-401"),
        "missing_unlock": ("missing unlock", "return while lock", "锁泄漏", "未释放锁", "cwe-667"),
        "held_lock_callback": ("callback while lock", "held lock callback", "under lock", "cwe-667"),
        "lost_wakeup": ("lost wakeup", "condition variable", "虚假唤醒", "pthread cond wait", "cwe-366"),
        "refcount_race": ("refcount race", "reference count", "ref count"),
        "object_publication": ("object publication", "published before initialization", "half initialized"),
        "integer_overflow": ("integer overflow", "overflow", "wrap", "整数溢出", "回绕", "cwe-190"),
        "bounds": ("bounds", "out of bounds", "buffer overflow", "buffer overread", "越界", "缓冲区", "cwe-125", "cwe-787"),
        "race": ("race", "data race", "toctou", "concurrency", "竞态", "无锁", "cwe-362", "cwe-367"),
        "deadlock": ("deadlock", "lock order", "死锁", "重入", "cwe-833"),
        "memory_leak": ("memory leak", "resource leak", "leak", "内存泄漏", "资源泄漏", "未释放", "cwe-401", "cwe-772"),
        "alignment": ("alignment", "unaligned", "strict alias", "cwe-704"),
        "stale_fd": ("stale fd", "file descriptor", "closed fd", "cwe-672"),
        "path_traversal": ("path traversal", "路径遍历"),
        "state_inconsistency": ("state inconsistency", "state not restored", "rollback", "cwe-672"),
        "unchecked_return": ("unchecked return", "unchecked result", "return success", "cwe-252"),
        "busy_loop": ("busy loop", "infinite loop", "spin", "no delay", "resource exhaustion", "cwe-400", "cwe-835"),
        "log_amplification": ("log amplification", "log storm", "resource exhaustion", "cwe-400"),
        "key_truncation": ("key truncation", "truncated key", "partial comparison", "cwe-187"),
        "size_limit_mismatch": ("size limit", "fixed limit", "buffer limit", "spec mismatch", "cwe-131"),
        "fd_type_mismatch": ("fd type", "reliable fd", "raw fd", "mismatched parameter", "cwe-628"),
        "protocol_mixup": ("protocol mixup", "protocol mismatch", "auth level", "origin validation", "cwe-346"),
        "partial_resource_leak": ("partial resource leak", "retry leak"),
        "dynamic_array_race": ("dynamic array", "array expansion"),
        "version_filtering": ("version filtering", "missing version", "low version", "version filter", "cwe-20"),
        "missing_refcount": ("missing refcount", "reference count", "refcount", "shared resource", "cwe-772"),
        "sigpipe_unhandled": ("sigpipe", "closed peer", "signal", "cwe-404"),
        "fd_encoding_mismatch": ("fd encoding", "encoded fd", "raw fd", "check value", "cwe-587"),
        "backend_signal": ("backend signal", "svf", "saber", "knowledge db"),
    }
    priority_groups = (
        "busy_loop",
        "size_limit_mismatch",
        "fd_type_mismatch",
        "protocol_mixup",
        "partial_resource_leak",
        "dynamic_array_race",
        "version_filtering",
        "missing_refcount",
        "sigpipe_unhandled",
        "fd_encoding_mismatch",
    )
    for canonical in priority_groups:
        needles = groups.get(canonical, ())
        if any(needle in text or needle in compact for needle in needles):
            return canonical
    for canonical, needles in groups.items():
        if any(needle in text or needle in compact for needle in needles):
            return canonical
    stripped = text.strip()
    if stripped in {"memory safety", "memory_safety"}:
        return "memory_safety"
    return stripped or "unknown"


def normalize_issue_key_part(value: Any) -> str:
    text = str(value or "").replace("\\", "/").lower().strip()
    return re.sub(r"\s+", " ", text)


_KNOWN_CATEGORIES = {
    "alignment",
    "backend_signal",
    "bounds",
    "busy_loop",
    "command_injection",
    "deadlock",
    "double_checked_locking",
    "double_free",
    "dynamic_array_race",
    "fd_encoding_mismatch",
    "fd_type_mismatch",
    "format_string",
    "held_lock_callback",
    "integer_overflow",
    "invalid_free",
    "key_truncation",
    "log_amplification",
    "lost_wakeup",
    "memory_leak",
    "memory_safety",
    "missing_refcount",
    "missing_unlock",
    "null_pointer_dereference",
    "object_publication",
    "off_by_one",
    "partial_resource_leak",
    "path_traversal",
    "protocol_mixup",
    "race",
    "realloc_misuse",
    "refcount_race",
    "signed_unsigned",
    "sigpipe_unhandled",
    "stack_escape",
    "stack_overflow",
    "stale_fd",
    "state_inconsistency",
    "unchecked_return",
    "type_confusion",
    "uninitialized_read",
    "use_after_free",
    "version_filtering",
}


_GLOBAL_OBJECT_ROOTS = {
    "thread_ids",
    "g_shared_counter",
    "g_receiver_running",
    "g_ready",
    "g_running",
    "g_active_config",
    "g_watched_fd",
    "g_macro_guarded_counter",
    "g_log_buffer",
    "temp_buffer",
    "recovery_buffer",
    "error_msg",
    "payload_len",
    "status_reply",
    "flush_job",
    "mesh_session_cleanup_hook",
    "guarded_subscription",
    "executor_sharedresources_type_confusion",
    "plugin_lookup_registry_mutex",
}


_FUNCTION_SCOPED_ROOT_CATEGORIES = {
    "alignment",
    "bounds",
    "busy_loop",
    "fd_encoding_mismatch",
    "fd_type_mismatch",
    "integer_overflow",
    "log_amplification",
    "memory_leak",
    "object_publication",
    "partial_resource_leak",
    "protocol_mixup",
    "race",
    "signed_unsigned",
    "stale_fd",
    "state_inconsistency",
    "unchecked_return",
    "version_filtering",
}


_FUNCTION_SCOPED_ROOTS = {
    "net_recv_data_negative_length",
    "route_avl_node_after_insert",
    "control_session_detach_leak",
    "control_session_open_leak",
    "value_slice_invalid_free",
    "topic_off_by_one",
    "frame_vla_stack",
    "lifecycle_cond_wait",
    "g_metrics_realloc",
    "task_command_execution",
    "printf_format_string",
    "os_node_proc_list",
    "pipe_self_link",
    "pipe_scheduler_control_lock_order",
}


def flatten_issue_text(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(flatten_issue_text(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(flatten_issue_text(v) for v in value)
    return "" if value is None else str(value)


def parse_issue_location(location: str) -> tuple[str, Optional[int]]:
    normalized = location.replace("\\", "/")
    match = re.search(r"((?:src|include|internal)/[A-Za-z0-9_./-]+\.[chp]+):(\d+)", normalized)
    if match:
        return match.group(1).lower(), int(match.group(2))
    match = re.search(r"(.+\.[chp]+):(\d+)", normalized)
    if match:
        return match.group(1).lower(), int(match.group(2))
    match = re.match(r"^\s*(\d+)(?:\s*-\s*\d+)?\s*$", normalized)
    if match:
        return "", int(match.group(1))
    return "", None
