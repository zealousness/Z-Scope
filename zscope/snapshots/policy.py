"""Static snapshot construction policy for trivial and lightweight functions."""

from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Dict, List


LIGHTWEIGHT_MACRO_RE = re.compile(
    r"^(?:LOG_(?:DEBUG|INFO|WARN|ERROR)|LOCK(?:_READ|_WRITE)?|UNLOCK|"
    r"ARRAY_SIZE|OFFSET_OF|RETURN_IF_(?:NULL|ERR)|GOTO_IF_(?:NULL|ERR)|"
    r"MIN|MAX|CLAMP|STR_LEN|STR_EQ|STR_EMPTY|LIKELY|UNLIKELY)$"
)
LIGHTWEIGHT_WRAPPER_RE = re.compile(
    r"^_(?:log|lock|unlock|lock_read|lock_write)_wrapper$"
)
LIGHTWEIGHT_ALLOCATOR_WRAPPER_RE = re.compile(r"^_safe_(?:malloc|calloc|realloc)$")

DETERMINISTIC_SNAPSHOT_REQUIRED_FIELDS = (
    "func_name",
    "index_name",
    "file_path",
    "start_line",
    "end_line",
    "signature",
    "snapshot_kind",
    "is_static",
    "is_macro",
    "referenced_globals",
    "referenced_macros",
    "referenced_types",
    "summary",
    "parameters",
    "return_values",
    "effects",
    "error_handling",
    "project_callees",
    "external_callees",
    "suspicious_points",
    "code",
)
DETERMINISTIC_SNAPSHOT_OPTIONAL_FIELDS = (
    "referenced_globals_truncation",
    "referenced_macros_truncation",
    "unresolved_referenced_types",
    "referenced_types_truncation",
    "project_callees_truncation",
    "external_callees_truncation",
    "unresolved_callees",
    "unresolved_callees_truncation",
)
DETERMINISTIC_SNAPSHOT_KINDS = frozenset({"syntactic", "lightweight"})

_SUSPICIOUS_CATEGORY_MAP = {
    "protocol_mixup": "state_protocol",
    "version_filtering": "input_validation",
    "fd_encoding_mismatch": "type_confusion",
    "fd_type_mismatch": "type_confusion",
    "bounds": "bounds",
    "state_inconsistency": "state_protocol",
    "unchecked_return": "error_handling",
    "invalid_free": "memory_safety",
    "resource_allocation_without_limits": "resource_lifecycle",
    "untrusted_pointer": "memory_safety",
    "out_of_bounds_write": "bounds",
    "lock_protocol_violation": "concurrency",
    "entry_forwarding": "api_contract",
}
_CANONICAL_SUSPICIOUS_CATEGORIES = frozenset(
    {
        "memory_safety",
        "resource_lifecycle",
        "bounds",
        "integer",
        "string_format",
        "null_error",
        "ownership",
        "concurrency",
        "state_protocol",
        "type_confusion",
        "input_validation",
        "error_handling",
        "global_state",
        "callback",
        "api_contract",
        "other",
    }
)


def _snapshot_line(impl: Dict[str, Any]) -> int | None:
    try:
        line = int(impl.get("start_line") or 0)
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def _matching_source_line(
    code: str,
    start_line: int | None,
    pattern: str,
) -> int | None:
    regex = re.compile(pattern, re.IGNORECASE)
    for offset, raw_line in enumerate(code.splitlines()):
        numbered = re.match(r"^\s*(\d+)\s*\|\s?(.*)$", raw_line)
        source_line = numbered.group(2) if numbered else raw_line
        if not regex.search(source_line):
            continue
        if numbered:
            return int(numbered.group(1))
        return (start_line + offset) if start_line is not None else None
    return start_line


def _unknown_return_values() -> Dict[str, Any]:
    return {
        "return_type": "unknown",
        "meaning": "Deterministic snapshot does not infer a complete return contract.",
        "nullable": "unknown",
        "success_cases": [],
        "failure_cases": [],
    }


def _normalize_project_callees(value: Any) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for raw_callee in value if isinstance(value, list) else []:
        if isinstance(raw_callee, dict):
            if "is_macro" in raw_callee:
                raise ValueError("project callee uses legacy is_macro field")
            index_name = str(
                raw_callee.get("callee_index_name")
                or raw_callee.get("index_name")
                or raw_callee.get("callee_name")
                or raw_callee.get("name")
                or ""
            ).strip()
            raw_lines = raw_callee.get("direct_callsite_lines")
            if raw_lines is None:
                raw_lines = raw_callee.get("callsite_lines")
            if not isinstance(raw_lines, list):
                raw_lines = [raw_callee.get("callsite_line")]
            callsite_lines = sorted(
                {
                    int(line)
                    for line in raw_lines
                    if isinstance(line, int) and not isinstance(line, bool) and line > 0
                }
            )
            summary = str(raw_callee.get("callee_summary") or "").strip()
            signature = str(raw_callee.get("callee_signature") or "").strip()
            indirect_callsites = [
                deepcopy(item)
                for item in list(raw_callee.get("indirect_callsites") or [])
                if isinstance(item, dict)
            ]
        else:
            index_name = str(raw_callee or "").strip()
            callsite_lines = []
            summary = ""
            signature = ""
            indirect_callsites = []
        if not index_name:
            continue

        callee = {
            "callee_index_name": index_name,
            "callee_signature": signature,
            "is_static": bool(raw_callee.get("is_static")) if isinstance(raw_callee, dict) else False,
            "callee_summary": summary or "unknown",
            "direct_callsite_lines": callsite_lines,
            "indirect_callsites": indirect_callsites,
        }
        result.append(callee)
    return result


def _normalize_external_callees(value: Any) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for raw_callee in value if isinstance(value, list) else []:
        if not isinstance(raw_callee, dict):
            continue
        callee_name = str(raw_callee.get("callee_name") or "").strip()
        signature = str(raw_callee.get("callee_signature") or "").strip()
        if not callee_name or not signature:
            continue
        raw_lines = raw_callee.get("direct_callsite_lines")
        if raw_lines is None:
            raw_lines = raw_callee.get("callsite_lines")
        if not isinstance(raw_lines, list):
            raw_lines = [raw_callee.get("callsite_line")]
        callsite_lines = sorted(
            {
                int(line)
                for line in raw_lines
                if isinstance(line, int) and not isinstance(line, bool) and line > 0
            }
        )
        result.append(
            {
                "callee_name": callee_name,
                "callee_signature": signature,
                "direct_callsite_lines": callsite_lines,
                "indirect_callsites": [
                    deepcopy(item)
                    for item in list(raw_callee.get("indirect_callsites") or [])
                    if isinstance(item, dict)
                ],
            }
        )
    return result


def _normalize_unresolved_callees(value: Any) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for raw_callee in value if isinstance(value, list) else []:
        if not isinstance(raw_callee, dict):
            continue
        callee_name = str(raw_callee.get("callee_name") or "").strip()
        if not callee_name:
            continue
        raw_lines = raw_callee.get("direct_callsite_lines")
        if not isinstance(raw_lines, list):
            raw_lines = [raw_callee.get("callsite_line")]
        result.append(
            {
                "callee_name": callee_name,
                "direct_callsite_lines": sorted(
                    {
                        int(line)
                        for line in raw_lines
                        if isinstance(line, int) and not isinstance(line, bool) and line > 0
                    }
                ),
                "indirect_callsites": [
                    deepcopy(item)
                    for item in list(raw_callee.get("indirect_callsites") or [])
                    if isinstance(item, dict)
                ],
            }
        )
    return result


def _normalize_suspicious_points(value: Any) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for raw_point in value if isinstance(value, list) else []:
        if not isinstance(raw_point, dict):
            continue
        point = deepcopy(raw_point)
        point.pop("confidence", None)
        raw_category = str(point.get("category") or "")
        point["category"] = _SUSPICIOUS_CATEGORY_MAP.get(
            raw_category,
            raw_category if raw_category in _CANONICAL_SUSPICIOUS_CATEGORIES else "other",
        )
        existing_lines = str(point.get("lines") or "").strip()
        if existing_lines:
            point["lines"] = existing_lines
        else:
            line = point.get("line")
            point["lines"] = str(line) if isinstance(line, int) and line > 0 else "unknown"
        point["description"] = str(point.get("description") or "")
        result.append(point)
    return result


def _expected_deterministic_fields(snapshot: Dict[str, Any]) -> tuple[str, ...]:
    fields: List[str] = []
    for field in DETERMINISTIC_SNAPSHOT_REQUIRED_FIELDS:
        fields.append(field)
        if field == "referenced_macros":
            for optional in (
                "referenced_globals_truncation",
                "referenced_macros_truncation",
            ):
                if optional in snapshot:
                    fields.append(optional)
        elif field == "referenced_types":
            for optional in (
                "unresolved_referenced_types",
                "referenced_types_truncation",
            ):
                if optional in snapshot:
                    fields.append(optional)
        elif field == "external_callees":
            for optional in (
                "project_callees_truncation",
                "external_callees_truncation",
            ):
                if optional in snapshot:
                    fields.append(optional)
            if "unresolved_callees" in snapshot:
                fields.append("unresolved_callees")
                if "unresolved_callees_truncation" in snapshot:
                    fields.append("unresolved_callees_truncation")
    return tuple(fields)


def is_current_deterministic_snapshot_shape(snapshot: Dict[str, Any]) -> bool:
    """Return whether a deterministic snapshot uses the current persisted shape."""

    if str(snapshot.get("snapshot_kind") or "") not in DETERMINISTIC_SNAPSHOT_KINDS:
        return False
    if any(field not in snapshot for field in DETERMINISTIC_SNAPSHOT_REQUIRED_FIELDS):
        return False
    if not isinstance(snapshot.get("referenced_types"), list):
        return False
    if not isinstance(snapshot.get("referenced_macros"), list) or any(
        not isinstance(item, dict)
        or set(item)
        != {"macro_index_name", "definition", "is_function_like", "reference_lines"}
        for item in snapshot.get("referenced_macros", [])
    ):
        return False
    if not isinstance(snapshot.get("project_callees"), list) or any(
        not isinstance(item, dict) or "is_macro" in item
        for item in snapshot.get("project_callees", [])
    ):
        return False
    if "unresolved_referenced_types" in snapshot and (
        not isinstance(snapshot.get("unresolved_referenced_types"), list)
        or not snapshot.get("unresolved_referenced_types")
    ):
        return False
    if "unresolved_callees" in snapshot and (
        not isinstance(snapshot.get("unresolved_callees"), list)
        or not snapshot.get("unresolved_callees")
        or any(
            not isinstance(item, dict)
            or set(item)
            != {"callee_name", "direct_callsite_lines", "indirect_callsites"}
            for item in snapshot.get("unresolved_callees", [])
        )
    ):
        return False
    if "referenced_types_truncation" in snapshot and not isinstance(
        snapshot.get("referenced_types_truncation"), dict
    ):
        return False
    if "unresolved_callees_truncation" in snapshot and not isinstance(
        snapshot.get("unresolved_callees_truncation"), dict
    ):
        return False
    allowed = set(DETERMINISTIC_SNAPSHOT_REQUIRED_FIELDS) | set(
        DETERMINISTIC_SNAPSHOT_OPTIONAL_FIELDS
    )
    if set(snapshot) - allowed:
        return False
    return tuple(snapshot) == _expected_deterministic_fields(snapshot)


def _build_deterministic_snapshot(
    func_name: str,
    impl: Dict[str, Any],
    *,
    snapshot_kind: str,
    summary: str,
    return_values: Dict[str, Any],
    effects: List[Dict[str, Any]],
    error_handling: Dict[str, Any],
    suspicious_points: List[Dict[str, Any]],
) -> Dict[str, Any]:
    snapshot: Dict[str, Any] = {
        "func_name": str(func_name),
        "index_name": impl.get("index_name"),
        "file_path": impl.get("file_path") or impl.get("file"),
        "start_line": impl.get("start_line"),
        "end_line": impl.get("end_line"),
        "signature": impl.get("signature"),
        "snapshot_kind": snapshot_kind,
        "is_static": bool(impl.get("is_static")),
        "is_macro": bool(impl.get("is_macro")),
        "referenced_globals": deepcopy(list(impl.get("referenced_globals") or [])),
        "referenced_macros": deepcopy(list(impl.get("referenced_macros") or [])),
    }
    for field in (
        "referenced_globals_truncation",
        "referenced_macros_truncation",
    ):
        if field in impl:
            snapshot[field] = deepcopy(impl[field])
    snapshot["referenced_types"] = deepcopy(list(impl.get("referenced_types") or []))
    for field in (
        "unresolved_referenced_types",
        "referenced_types_truncation",
    ):
        if field in impl:
            snapshot[field] = deepcopy(impl[field])
    snapshot.update(
        {
            "summary": summary,
            "parameters": [],
            "return_values": deepcopy(return_values),
            "effects": deepcopy(effects),
            "error_handling": deepcopy(error_handling),
            "project_callees": _normalize_project_callees(impl.get("project_callees")),
            "external_callees": _normalize_external_callees(impl.get("external_callees")),
        }
    )
    unresolved_callees = _normalize_unresolved_callees(impl.get("unresolved_callees"))
    if unresolved_callees:
        snapshot["unresolved_callees"] = unresolved_callees
    for field in (
        "project_callees_truncation",
        "external_callees_truncation",
        "unresolved_callees_truncation",
    ):
        if field in impl:
            snapshot[field] = deepcopy(impl[field])
    snapshot["suspicious_points"] = _normalize_suspicious_points(suspicious_points)
    snapshot["code"] = str(impl.get("code") or "")
    if not is_current_deterministic_snapshot_shape(snapshot):
        raise ValueError("deterministic snapshot fields do not match the canonical shape")
    return snapshot


def build_trivial_snapshot(
    func_name: str,
    impl: Dict[str, Any],
) -> Dict[str, Any]:
    """Create a persisted syntactic snapshot for a short function."""
    suspicious_points = trivial_suspicious_points(func_name, impl)
    return _build_deterministic_snapshot(
        func_name,
        impl,
        snapshot_kind="syntactic",
        summary=(
            "Short function stored verbatim without LLM semantic modeling; "
            "security-sensitive contracts remain auditable through suspicious points."
        ),
        return_values=_unknown_return_values(),
        effects=[],
        error_handling={"error_paths": []},
        suspicious_points=suspicious_points,
    )


def trivial_suspicious_points(
    func_name: str,
    impl: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Surface short but security-sensitive functions to later audit stages."""
    del func_name
    code = str(impl.get("code") or "")
    text = code.lower()
    start_line = int(impl.get("start_line") or 0)
    file_path = str(impl.get("file_path") or impl.get("file") or "unknown")
    evidence_location = f"{file_path}:{start_line}"
    points: List[Dict[str, Any]] = []

    def line_for(pattern: str, default_offset: int = 0) -> int:
        regex = re.compile(pattern)
        for offset, raw in enumerate(code.splitlines()):
            cleaned = re.sub(r"^\s*\d+\s*\|\s*", "", raw).strip()
            if regex.search(cleaned):
                nums = re.findall(r"^\s*(\d+)\s*\|", raw)
                if nums:
                    try:
                        return int(nums[0])
                    except ValueError:
                        pass
                return max(1, start_line + offset)
        return max(1, start_line + default_offset)

    def add(
        *,
        kind: str,
        category: str,
        description: str,
        reason: str,
        pattern: str,
    ) -> None:
        line_no = line_for(pattern)
        points.append(
            {
                "type": kind,
                "category": category,
                "description": description,
                "reason": reason,
                "location": f"{file_path}:{line_no}",
                "line": line_no,
                "source": "trivial_syntactic_contract",
            }
        )

    if "detected_protocol" in text and "auth_level" in text and re.search(r"return\s+0\s*;", text):
        add(
            kind="protocol_contract",
            category="protocol_mixup",
            description="Short protocol/auth gate can accept a protocol mismatch on a success branch.",
            reason="Protocol mismatch plus non-strict auth fallback is security semantics, not a trivial wrapper.",
            pattern=r"detected_protocol\s!=",
        )

    if re.search(r"\bversion\s*=", text) and re.search(r"\(void\)\s*version\s*;", text):
        add(
            kind="version_filtering_contract",
            category="version_filtering",
            description="Protocol version is parsed and explicitly ignored.",
            reason="Version filtering is a boundary contract even when the function body is short.",
            pattern=r"\bversion\s*=",
        )

    if "_validate_encoded_fd" in text and re.search(r"\braw_[a-z_0-9]*fd\s*=", text):
        add(
            kind="fd_encoding_contract",
            category="fd_encoding_mismatch",
            description="Raw fd-derived value is passed to an encoded-fd validator.",
            reason="Fd representation conversion is a contract check that should remain auditable.",
            pattern=r"\braw_[A-Za-z_0-9]*fd\s*=",
        )

    if "reliable_fd" in text and re.search(r"\b[A-Za-z_]\w*is_inter_fd\s*\(\s*reliable_fd\s*\)", text):
        add(
            kind="fd_type_contract",
            category="fd_type_mismatch",
            description="Reliable/encoded fd is passed to a raw/inter-fd classifier.",
            reason="Fd representation contracts remain auditable even when the wrapper is one return statement.",
            pattern=r"[A-Za-z_]\w*is_inter_fd\s*\(\s*reliable_fd\s*\)",
        )

    if re.search(r"\b\w+\s*=\s*(?:\([^)]*\)\s*)?\(?\s*\w+\s*(?:\*|<<)", text) and re.search(
        r"\bmem(?:cpy|move)\s*\([^;]*(?:packet|frame|wire|blob)\s*\+[^;]*\)",
        text,
    ):
        add(
            kind="protocol_length_contract",
            category="bounds",
            description="Short protocol parser derives a copy length from packet data and copies from the frame without an input-length proof.",
            reason="Derived protocol lengths and copy sinks remain auditable even when the function body is short.",
            pattern=r"\bmem(?:cpy|move)\s*\(",
        )

    state_assign = re.search(
        r"\b(?P<state>g_[A-Za-z_0-9.]*state[A-Za-z_0-9.]*)\s*=",
        code,
    )
    if state_assign and re.search(r"\breturn\s+-1\s*;", text):
        state_name = state_assign.group("state")
        restore = re.search(rf"\b{re.escape(state_name)}\s*=\s*previous\s*;", code)
        if not restore:
            add(
                kind="state_restore_contract",
                category="state_inconsistency",
                description="Shared state is changed before an error return without restoring the saved previous value.",
                reason="Saving a previous value is only protective when the state variable itself is restored on every failure path.",
                pattern=rf"\b{re.escape(state_name)}\s*=",
            )

    if re.search(r"\breturn\s+0\s*;", text) and re.search(r"(?:error|fail|ssl|probe|status)", text):
        add(
            kind="error_status_contract",
            category="unchecked_return",
            description="Short status/probe helper can return success from an ambiguous error path.",
            reason="Return-code translation is security-relevant even in small helpers.",
            pattern=r"\breturn\s+0\s*;",
        )

    local_danger_patterns = [
        (
            r"\bfree\s*\([^;]*(?:\+|-|&|\[[^]]+\])",
            "invalid_free_primitive",
            "invalid_free",
            "Short helper releases a pointer expression that may not be the owning allocation base.",
            "Pointer-expression deallocation remains security-relevant even in a short helper.",
        ),
        (
            r"\b(?:malloc|calloc|realloc|_safe_malloc|_safe_calloc|_safe_realloc)\s*\([^;]*(?:count|size|len|window|batch|segment)",
            "unbounded_allocation_primitive",
            "resource_allocation_without_limits",
            "Short helper allocates heap memory from a data-derived size/count.",
            "Allocation quota and protocol-size checks can be hidden by short helper summaries.",
        ),
        (
            r"\*\s*\([^;)]*\*\s*\)\s*(?:\([^)]*\)\s*)?[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*",
            "wire_pointer_primitive",
            "untrusted_pointer",
            "Short helper casts a structured field into a pointer and dereferences it.",
            "Wire/header pointer casts should remain visible to focused validation.",
        ),
        (
            r"\bfor\s*\([^;]*;\s*[A-Za-z_]\w*\s*<\s*[A-Za-z_]\w*(?:->|\.)?[A-Za-z_0-9]*[^;]*;[^)]*\).*?\[[A-Za-z_]\w*\]\s*=",
            "fixed_array_count_primitive",
            "out_of_bounds_write",
            "Short helper writes a fixed array through a count-driven loop index.",
            "Count-driven local writes should remain auditable even when semantic modeling is skipped.",
        ),
        (
            r"\b(?:pthread_mutex_unlock|UNLOCK|spin_unlock|mtx_unlock)\s*\(",
            "unlock_primitive",
            "lock_protocol_violation",
            "Short helper releases a lock and may rely on a caller-held-lock contract.",
            "Lock-protocol boundaries should remain visible to later validation.",
        ),
    ]
    for pattern, kind, category, description, reason in local_danger_patterns:
        if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
            add(
                kind=kind,
                category=category,
                description=description,
                reason=reason,
                pattern=pattern,
            )

    callees = [
        str(callee["callee_index_name"])
        for callee in _normalize_project_callees(impl.get("project_callees"))
    ] + [
        str(callee["callee_name"])
        for callee in (
            _normalize_external_callees(impl.get("external_callees"))
            + _normalize_unresolved_callees(impl.get("unresolved_callees"))
        )
    ]
    if callees and re.search(r"\breturn\s+[A-Za-z_]\w*\s*\(", text):
        points.append(
            {
                "type": "facade_forwarding_contract",
                "category": "entry_forwarding",
                "description": (
                    "Short entry facade forwards caller-controlled state to source callees; "
                    "audit the callee path instead of treating the facade as a terminal helper."
                ),
                "reason": (
                    "Trivial functions are stored without LLM modeling, but API and message "
                    "facades still define reachability and trust boundaries."
                ),
                "location": evidence_location,
                "line": start_line,
                "source": "trivial_syntactic_contract",
                "callees": callees,
            }
        )

    return points


def is_lightweight_snapshot_candidate(func_name: str, impl: Dict[str, Any]) -> bool:
    """Return true for macros/wrappers that can be summarized without an LLM call."""
    if impl.get("is_macro"):
        if LIGHTWEIGHT_MACRO_RE.match(func_name):
            return True
        code = str(impl.get("code") or "")
        return bool(
            re.search(r"#\s*define\s+\w+\s+\(?[0-9A-Za-z_+\-*/<>=&| ]+\)?\s*$", code)
            and len(code.splitlines()) <= 3
        )
    if LIGHTWEIGHT_WRAPPER_RE.match(func_name):
        return True
    if _looks_like_checked_allocator_wrapper(func_name, impl):
        return True
    return False


def _looks_like_checked_allocator_wrapper(func_name: str, impl: Dict[str, Any]) -> bool:
    if not LIGHTWEIGHT_ALLOCATOR_WRAPPER_RE.match(func_name):
        return False
    code = str(impl.get("code") or "")
    cleaned_lines = [
        re.sub(r"^\s*\d+\s*\|\s*", "", line).strip()
        for line in code.splitlines()
    ]
    logic_lines = [line for line in cleaned_lines if line and line not in {"{", "}"}]
    if len(logic_lines) > 14:
        return False

    allocator_name = {
        "_safe_malloc": "malloc",
        "_safe_calloc": "calloc",
        "_safe_realloc": "realloc",
    }.get(func_name)
    if not allocator_name:
        return False
    body = "\n".join(logic_lines)
    if not re.search(rf"\b{allocator_name}\s*\(", body):
        return False
    if not re.search(r"\breturn\s+[A-Za-z_]\w*\s*;", body):
        return False
    disallowed_side_effects = r"\b(?:memcpy|memmove|strcpy|strncpy|strcat|strncat|pthread_|socket|send|recv|read|write|open|fopen)\b"
    return not re.search(disallowed_side_effects, body)


def build_lightweight_snapshot(
    func_name: str,
    impl: Dict[str, Any],
) -> Dict[str, Any]:
    """Create a lightweight static snapshot for common macros and tiny wrapper APIs."""
    code = str(impl.get("code") or "")
    upper = func_name.upper()
    line = _snapshot_line(impl)
    return_values = _unknown_return_values()
    effects: List[Dict[str, Any]] = []
    error_handling: Dict[str, Any] = {"error_paths": []}
    summary = "Lightweight macro/wrapper summarized without LLM semantic modeling."

    if upper.startswith("LOG_") or func_name == "_log_wrapper":
        summary = (
            "Logging helper. Validate format-string safety at the call site where "
            "the format argument is chosen; this helper alone is not a vulnerability."
        )
        effects.append(
            {
                "category": "io",
                "description": "Writes a formatted diagnostic message to the logging sink.",
                "line": line,
                "object": "log output",
                "api": func_name,
                "details": {
                    "direction": "write",
                    "operation_kind": "log",
                },
            }
        )
    elif upper.startswith("LOCK") or upper == "UNLOCK" or "lock" in func_name:
        is_unlock = upper == "UNLOCK" or "unlock" in func_name.lower()
        operation = "release" if is_unlock else "acquire"
        summary = (
            "Locking helper. Treat calls as acquiring or releasing the referenced "
            "mutex/rwlock at the call site; inspect caller ordering for deadlocks."
        )
        effects.append(
            {
                "category": "lock",
                "description": (
                    f"Deterministically identified wrapper that may {operation} "
                    "the caller-provided lock."
                ),
                "line": line,
                "object": "lock argument",
                "api": func_name,
                "details": {"operation_kind": operation},
            }
        )
    elif upper in {"MIN", "MAX", "CLAMP", "ARRAY_SIZE", "OFFSET_OF"}:
        summary = "Pure expression macro. Analyze bounds at the caller expression."
    elif upper.startswith(("RETURN_IF_", "GOTO_IF_")):
        summary = "Guard/control-flow macro. Analyze the caller's guarded path."
        exit_action = "goto" if upper.startswith("GOTO_IF_") else "return"
        error_handling = {
            "error_paths": [
                {
                    "trigger": "The guard condition evaluates true.",
                    "exit_line": line,
                    "exit_action": exit_action,
                    "exit_states": [],
                }
            ]
        }
    elif _looks_like_checked_allocator_wrapper(func_name, impl):
        allocator = func_name.removeprefix("_safe_")
        allocation_line = _matching_source_line(
            code,
            line,
            rf"\b{re.escape(allocator)}\s*\(",
        )
        failure_line = _matching_source_line(code, line, r"\breturn\s+NULL\b")
        summary = (
            f"Checked {allocator} wrapper. Treat the returned pointer as caller-owned; "
            "callers must handle NULL before dereference, copy, or ownership transfer."
        )
        return_values = {
            "return_type": "pointer",
            "meaning": f"Returns storage produced by {allocator} on success.",
            "nullable": "yes",
            "ownership": "caller_owned",
            "success_cases": [
                {
                    "value": "non-NULL pointer",
                    "condition": f"The underlying {allocator} call succeeds.",
                }
            ],
            "failure_cases": [
                {
                    "value": "NULL",
                    "condition": (
                        f"The underlying {allocator} call fails for a nonzero request."
                    ),
                }
            ],
            "caller_obligation": "Check for NULL before using the returned pointer.",
        }
        effects = [
            {
                "category": "memory",
                "description": f"Calls {allocator} to obtain heap storage.",
                "line": allocation_line,
                "object": "returned pointer",
                "api": allocator,
                "details": {
                    "allocation_kind": allocator,
                    "failure_value": "NULL",
                },
            },
            {
                "category": "ownership",
                "description": "Transfers ownership of successful allocation to the caller.",
                "line": allocation_line,
                "object": "returned pointer",
                "details": {
                    "owner_before": "wrapper",
                    "owner_after": "caller",
                    "transfer_kind": "return",
                },
            },
        ]
        error_handling = {
            "error_paths": [
                {
                    "trigger": (
                        f"The underlying {allocator} call returns NULL for a nonzero request."
                    ),
                    "exit_line": failure_line,
                    "exit_action": "return NULL",
                    "exit_states": [
                        {
                            "kind": "memory",
                            "object": "returned pointer",
                            "state": "not_acquired",
                            "owner": "none",
                        }
                    ],
                    "return_value": "NULL",
                }
            ]
        }

    return _build_deterministic_snapshot(
        func_name,
        impl,
        snapshot_kind="lightweight",
        summary=summary,
        return_values=return_values,
        effects=effects,
        error_handling=error_handling,
        suspicious_points=[],
    )


def is_trivial_function(code: str, max_lines_threshold: int) -> bool:
    """Decide whether a function is too simple for deep semantic modeling."""
    if max_lines_threshold <= 0:
        return False

    lines = code.split("\n")
    clean_lines = []
    in_block_comment = False
    for line in lines:
        line = line.strip()
        line = re.sub(r"^\d+\s*\|\s*", "", line)
        if not line:
            continue

        if in_block_comment:
            if "*/" in line:
                in_block_comment = False
                line = line[line.find("*/") + 2:].strip()
            else:
                continue

        if "/*" in line:
            if "*/" in line:
                line = re.sub(r"/\*.*?\*/", "", line).strip()
            else:
                in_block_comment = True
                line = line[: line.find("/*")].strip()

        if "//" in line:
            line = line[: line.find("//")].strip()

        if line:
            clean_lines.append(line)

    logic_lines = [line for line in clean_lines if line not in ("{", "}")]
    if len(logic_lines) > max_lines_threshold + 1:
        return False

    clean_code_body = " ".join(clean_lines).lower()
    risky_keywords = [
        r"malloc",
        r"calloc",
        r"realloc",
        r"free",
        r"alloc",
        r"new\s",
        r"delete\s",
        r"memcpy",
        r"memmove",
        r"strcpy",
        r"strncpy",
        r"strcat",
        r"strncat",
        r"lock",
        r"mutex",
        r"mtx",
        r"cond",
        r"thread",
        r"spin",
        r"pthread",
        r"file",
        r"fopen",
        r"fclose",
        r"read",
        r"write",
        r"socket",
        r"send",
        r"recv",
        r"connect",
        r"open",
        r"close",
    ]
    return not any(re.search(keyword, clean_code_body) for keyword in risky_keywords)
