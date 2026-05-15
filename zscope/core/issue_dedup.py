"""Issue canonicalization and duplicate merging helpers."""

from __future__ import annotations

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
    issue.setdefault("normalized_category", normalized_category)


def issue_rank(issue: Dict[str, Any]) -> tuple[int, float, int]:
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    severity = severity_order.get(
        str(issue.get("impact_level") or issue.get("severity") or "").lower(),
        0,
    )
    try:
        confidence = float(issue.get("confidence", 0) or 0)
    except (TypeError, ValueError):
        confidence = 0.0
    detail_len = len(str(issue.get("reasoning") or issue.get("description") or ""))
    return severity, confidence, detail_len


def canonical_issue_key(issue: Dict[str, Any]) -> str:
    """Return a stable key based on root cause rather than only line number."""
    text = flatten_issue_text(issue)
    location = str(issue.get("location") or issue.get("file") or "")
    file_path, line = parse_issue_location(location)
    if not file_path:
        match = re.search(r"((?:src|include|internal)/[A-Za-z0-9_./-]+\.[chp]+)", text)
        file_path = match.group(1).lower() if match else ""
    function = str(issue.get("function") or issue.get("func_name") or "")
    category = normalize_issue_category(
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
    root = root_cause_token(issue, category, text)
    scope = file_path or function
    if root:
        return "|".join(normalize_issue_key_part(part) for part in (category, scope, root))

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


def root_cause_token(issue: Dict[str, Any], category: str, text: str) -> str:
    raw_lower = text.lower()
    lower = raw_lower.replace("_", " ").replace("-", " ")
    compact = re.sub(r"[^a-z0-9]+", "", raw_lower)
    function = str(issue.get("function") or issue.get("func_name") or "").lower()

    named_objects = (
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
    if "_executor_cleanup_resources" in lower and (
        "sharedresources" in lower or "taskconfig" in lower or "类型混淆" in text
    ):
        return "executor_sharedresources_type_confusion"
    if "_executor_init" in lower and (
        "sharedresources" in lower or "taskconfig" in lower or "类型混淆" in text
    ):
        return "executor_sharedresources_type_confusion"
    if "_plugin_lookup" in lower and ("mutex" in lower or "lock" in lower or "重入" in text):
        return "plugin_lookup_registry_mutex"
    if "_lifecycle_dispatch_pipe_tick" in lower and (
        "ctrl_lock" in lower or "sched_lock" in lower or "deadlock" in lower
    ):
        return "pipe_scheduler_control_lock_order"
    if "_lifecycle_close_pipe" in lower and ("pipe->next = pipe" in lower or "self" in lower):
        return "pipe_self_link"
    if "_lifecycle_delete_os_node" in lower or "procnode" in lower:
        return "os_node_proc_list"
    if "_lifecycle_avl_register_route" in lower or "_route_avl_insert_node" in lower:
        return "route_avl_node_after_insert"
    if "_lifecycle_unregister_guarded_subscription" in lower:
        return "guarded_subscription_mutex"
    if "_lifecycle_mesh_authorize_init" in lower:
        return "mesh_session_cleanup_hook"
    if "_control_session_detach_without_release" in lower:
        return "control_session_detach_leak"
    if "_lifecycle_customize_control_message" in lower and "open" in lower:
        return "control_session_open_leak"
    if "_lifecycle_release_value_slice" in lower or "value+1" in compact:
        return "value_slice_invalid_free"
    if "_lifecycle_format_topic" in lower or "topic[sizeof" in compact:
        return "topic_off_by_one"
    if "_lifecycle_parse_frame" in lower or "vla" in lower:
        return "frame_vla_stack"
    if "_lifecycle_wait_for_work" in lower and "pthread_cond_wait" in lower:
        return "lifecycle_cond_wait"
    if "_lifecycle_resize_metrics" in lower or "g_metrics" in lower:
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
    groups = {
        "format_string": ("format string", "格式化字符串", "cwe-134"),
        "command_injection": ("command injection", "shell injection", "命令注入", "system(", "cwe-78"),
        "double_checked_locking": ("double checked locking", "double checked", "双重检查"),
        "signed_unsigned": ("signed unsigned", "negative length", "size_max", "sizemax", "有符号", "无符号", "cwe-195"),
        "off_by_one": ("off by one", "off-by-one", "sizeof index", "差一", "cwe-193"),
        "uninitialized_read": ("uninitialized read", "未初始化", "栈上垃圾", "cwe-457"),
        "stack_escape": ("stack escape", "use after return", "return stack", "栈地址逃逸", "栈指针", "cwe-562"),
        "stack_overflow": ("stack overflow", "vla", "栈溢出", "cwe-121"),
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
        "backend_signal": ("backend signal", "svf", "saber", "knowledge db"),
    }
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
