"""Static snapshot construction policy for trivial and lightweight functions."""

from __future__ import annotations

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


def build_trivial_snapshot(
    func_name: str,
    impl: Dict[str, Any],
    location: str,
) -> Dict[str, Any]:
    """Create a persisted syntactic snapshot for a short function."""
    suspicious_points = trivial_suspicious_points(func_name, impl, location)
    return {
        "type": "function_snapshot",
        "func_name": func_name,
        "location": location,
        "file_path": impl.get("file"),
        "start_line": impl.get("start_line"),
        "end_line": impl.get("end_line"),
        "signature": impl.get("signature"),
        "summary": "Short function stored verbatim without LLM semantic modeling.",
        "snapshot_kind": "syntactic",
        "is_trivial": True,
        "code": impl.get("code", ""),
        "inputs": [],
        "outputs": [],
        "resources": {},
        "error_handling": {},
        "concurrency": {},
        "semantic_fingerprint": {
            "key_semantics": [
                "short function source is embedded in snapshot",
                "trivial functions are not LLM-modeled, but security-sensitive contracts remain auditable",
            ]
        },
        "suspicious_points": suspicious_points,
        "callees": impl.get("callees", []),
    }


def trivial_suspicious_points(
    func_name: str,
    impl: Dict[str, Any],
    location: str,
) -> List[Dict[str, Any]]:
    """Surface short but security-sensitive functions to later audit stages."""
    del func_name
    code = str(impl.get("code") or "")
    text = code.lower()
    start_line = int(impl.get("start_line") or 0)
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
        confidence: float,
    ) -> None:
        line_no = line_for(pattern)
        points.append(
            {
                "type": kind,
                "category": category,
                "description": description,
                "reason": reason,
                "location": f"{location.split(':', 1)[0]}:{line_no}",
                "line": line_no,
                "confidence": confidence,
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
            confidence=0.86,
        )

    if re.search(r"\bversion\s*=", text) and re.search(r"\(void\)\s*version\s*;", text):
        add(
            kind="version_filtering_contract",
            category="version_filtering",
            description="Protocol version is parsed and explicitly ignored.",
            reason="Version filtering is a boundary contract even when the function body is short.",
            pattern=r"\bversion\s*=",
            confidence=0.88,
        )

    if "_validate_encoded_fd" in text and re.search(r"\braw_[a-z_0-9]*fd\s*=", text):
        add(
            kind="fd_encoding_contract",
            category="fd_encoding_mismatch",
            description="Raw fd-derived value is passed to an encoded-fd validator.",
            reason="Fd representation conversion is a contract check that should remain auditable.",
            pattern=r"\braw_[A-Za-z_0-9]*fd\s*=",
            confidence=0.86,
        )

    if "reliable_fd" in text and re.search(r"\b[A-Za-z_]\w*is_inter_fd\s*\(\s*reliable_fd\s*\)", text):
        add(
            kind="fd_type_contract",
            category="fd_type_mismatch",
            description="Reliable/encoded fd is passed to a raw/inter-fd classifier.",
            reason="Fd representation contracts remain auditable even when the wrapper is one return statement.",
            pattern=r"[A-Za-z_]\w*is_inter_fd\s*\(\s*reliable_fd\s*\)",
            confidence=0.86,
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
            confidence=0.84,
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
                confidence=0.84,
            )

    if re.search(r"\breturn\s+0\s*;", text) and re.search(r"(?:error|fail|ssl|probe|status)", text):
        add(
            kind="error_status_contract",
            category="unchecked_return",
            description="Short status/probe helper can return success from an ambiguous error path.",
            reason="Return-code translation is security-relevant even in small helpers.",
            pattern=r"\breturn\s+0\s*;",
            confidence=0.7,
        )

    callees = [
        str(callee)
        for callee in (impl.get("callees") or [])
        if str(callee).strip()
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
                "location": location,
                "line": start_line,
                "confidence": 0.8,
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
    return False


def build_lightweight_snapshot(
    func_name: str,
    impl: Dict[str, Any],
    location: str,
) -> Dict[str, Any]:
    """Create a lightweight static snapshot for common macros and tiny wrapper APIs."""
    code = str(impl.get("code") or "")
    upper = func_name.upper()
    key_semantics: List[str] = ["lightweight static snapshot; no LLM call"]
    resources: Dict[str, Any] = {}
    concurrency: Dict[str, Any] = {}
    error_handling: Dict[str, Any] = {}
    summary = "Lightweight macro/wrapper summarized without LLM semantic modeling."

    if upper.startswith("LOG_") or func_name == "_log_wrapper":
        summary = (
            "Logging helper. Validate format-string safety at the call site where "
            "the format argument is chosen; this helper alone is not a vulnerability."
        )
        key_semantics.append("logging side effect")
    elif upper.startswith("LOCK") or upper == "UNLOCK" or "lock" in func_name:
        summary = (
            "Locking helper. Treat calls as acquiring or releasing the referenced "
            "mutex/rwlock at the call site; inspect caller ordering for deadlocks."
        )
        concurrency = {"lock_effect": "call-site lock/unlock wrapper"}
        key_semantics.append("synchronization wrapper")
    elif upper in {"MIN", "MAX", "CLAMP", "ARRAY_SIZE", "OFFSET_OF"}:
        summary = "Pure expression macro. Analyze bounds at the caller expression."
        key_semantics.append("pure expression macro")
    elif upper.startswith(("RETURN_IF_", "GOTO_IF_")):
        summary = "Guard/control-flow macro. Analyze the caller's guarded path."
        error_handling = {"control_flow": "guard macro expands to return/goto"}
        key_semantics.append("guard macro")

    return {
        "type": "function_snapshot",
        "func_name": func_name,
        "location": location,
        "file_path": impl.get("file"),
        "start_line": impl.get("start_line"),
        "end_line": impl.get("end_line"),
        "signature": impl.get("signature"),
        "summary": summary,
        "snapshot_kind": "lightweight",
        "is_trivial": True,
        "is_macro": bool(impl.get("is_macro")),
        "code": code,
        "inputs": [],
        "outputs": [],
        "resources": resources,
        "error_handling": error_handling,
        "concurrency": concurrency,
        "semantic_fingerprint": {"key_semantics": key_semantics},
        "suspicious_points": [],
        "callees": impl.get("callees", []),
    }


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
