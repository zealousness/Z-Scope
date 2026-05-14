"""Infer human-reviewable user configuration rows from a project."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..config.user_config_workbook import SHEET_HEADERS
from ..core.deterministic_candidates import DeterministicCandidateGenerator


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".inc", ".inl", ".ph"}
DEFAULT_API_NAMES = (
    DeterministicCandidateGenerator._DEFAULT_ALLOCATORS
    | DeterministicCandidateGenerator._DEFAULT_CALLOC_ALLOCATORS
    | DeterministicCandidateGenerator._DEFAULT_REALLOCATORS
    | DeterministicCandidateGenerator._DEFAULT_DEALLOCATORS
    | DeterministicCandidateGenerator._DEFAULT_COPY_SINKS
    | DeterministicCandidateGenerator._DEFAULT_LOCK_APIS
    | DeterministicCandidateGenerator._DEFAULT_UNLOCK_APIS
)
WRAPPER_NAME_HINT_RE = re.compile(
    r"alloc|free|dealloc|lock|unlock|copy|cpy|move|create|destroy|"
    r"open|close|acquire|release|get|put|ref|unref",
    re.IGNORECASE,
)
ALLOC_NAME_RE = re.compile(r"(Create|Add|Alloc|Apply|Register|Bind|Connect|Join)", re.I)
RELEASE_NAME_RE = re.compile(r"(Delete|Remove|Free|Release|Close|Destroy|Leave)", re.I)
DISPATCH_NAME_RE = re.compile(r"(MsgProc|Dispatch|Route)", re.I)
FAULT_NAME_RE = re.compile(r"(Fault|Error|Cleanup|Abort)", re.I)
QUERY_NAME_RE = re.compile(r"(Get|Query|Info|Stat)", re.I)
INIT_NAME_RE = re.compile(r"(Init|Finit|ResInit|ResFinit)", re.I)
ALLOC_CALL_RE = re.compile(
    r"\b([A-Za-z_]\w*(?:alloc|create|new|open|socket|mmap|register|bind|connect)\w*)\s*\(",
    re.I,
)
RELEASE_CALL_RE = re.compile(
    r"\b([A-Za-z_]\w*(?:free|release|destroy|delete|remove|close|munmap|unregister|unbind|disconnect)\w*)\s*\(",
    re.I,
)
GLOBAL_DS_RE = re.compile(
    r"\b(g_[A-Za-z0-9_]+|LIST|List|Hash|hash|Map|map|BitMap|Bitmap|RBTree|Tree|ADD|DEL|REMOVE|INSERT)\b"
)
LOCK_RE = re.compile(r"(mutex|rwlock|spinlock|pthread_mutex|pthread_rwlock|\bLOCK\b|\bUNLOCK\b)", re.I)
ERROR_PATH_RE = re.compile(r"\b(return|goto|ERROR|FAIL|ERR|ENOMEM|EINVAL)\b")
MESSAGE_TYPE_RE = re.compile(
    r"\b([A-Z][A-Z0-9_]+_(?:MSG|REQUEST|NOTIFY|APPLY|FREE|CLOSE)\w*)\b"
)
LITERAL_PARAM_CALL_RE = re.compile(
    r"\b(?P<callee>[A-Za-z_]\w*)\s*\((?P<args>[^;{}]*\b(?:TRUE|FALSE|true|false|0|1)\b[^;{}]*)\)\s*;",
    re.S,
)
ROLE_FIELD_RE = re.compile(r"\b([A-Za-z_]\w*(?:type|role|mode|kind|state|status)\w*)\b", re.I)
FUNCTION_LIKE_MACRO_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(.*)$")
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
CASE_BLOCK_RE = re.compile(
    r"\bcase\s+(?P<message>[A-Za-z_]\w*)\s*:\s*(?P<body>.*?)(?=\bcase\b|\bdefault\b|})",
    re.S,
)
TABLE_HANDLER_RE = re.compile(
    r"\{\s*(?P<message>[A-Z][A-Z0-9_]*\w*)\s*,\s*(?P<handler>[A-Za-z_]\w*)\s*\}"
)


@dataclass
class FunctionEvidence:
    name: str
    code: str
    file_path: str = ""
    message_type: str = ""
    allocation_calls: List[str] = field(default_factory=list)
    release_calls: List[str] = field(default_factory=list)
    global_structures: List[str] = field(default_factory=list)
    role_fields: List[str] = field(default_factory=list)
    literal_param_calls: List[Tuple[str, str]] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)

    @property
    def has_locks(self) -> bool:
        return bool(LOCK_RE.search(self.code))

    @property
    def has_error_paths(self) -> bool:
        return bool(ERROR_PATH_RE.search(self.code))

    @property
    def has_global_ds(self) -> bool:
        return bool(self.global_structures)

    @property
    def has_conditional_literal_release(self) -> bool:
        release_names = ("close", "free", "release", "remove", "destroy", "delete")
        return any(
            any(part in callee.lower() for part in release_names)
            for callee, _ in self.literal_param_calls
        )


def infer_user_config_rows(code_index: Any, snapshot_dir: Optional[Path] = None) -> Dict[str, List[Dict[str, Any]]]:
    """Infer rows for a user config workbook without requiring an LLM call."""

    rows: Dict[str, List[Dict[str, Any]]] = {name: [] for name in SHEET_HEADERS}
    symbols: Dict[str, Dict[str, Any]] = {}
    roles: Dict[str, str] = {}
    evidence_by_name: Dict[str, FunctionEvidence] = {}

    function_names = sorted(set(code_index.list_functions(limit=100000)))
    macro_records = list(_scan_function_like_macros(code_index))

    for name in function_names:
        kind = _classify_symbol_name(name)
        if kind:
            roles[name] = kind
            _add_symbol(symbols, name, kind, "function", "inferred:name", 0.72)

    for name, body in macro_records:
        kind = _classify_symbol_name(name) or _classify_body(body, roles)
        if kind:
            roles[name] = kind
            _add_symbol(symbols, name, kind, "macro", "inferred:macro", 0.78, body=body)

    for name in function_names:
        impl = code_index.get_function_impl(name, max_lines=240, warn_missing=False)
        if not impl:
            continue
        code = str(impl.get("code") or "")
        evidence_by_name[name] = _evidence_from_impl(name, impl)
        body_kind = _classify_body(code, roles) if (name not in roles or _should_inspect_body(name)) else ""
        if body_kind and (name not in roles or _body_role_can_refine(roles[name], body_kind)):
            roles[name] = body_kind
            _add_symbol(
                symbols,
                name,
                body_kind,
                "function",
                "inferred:body",
                0.80,
                body=code,
                signature=str(impl.get("signature") or ""),
            )

    for name, kind, confidence in _roles_from_snapshots(snapshot_dir):
        roles.setdefault(name, kind)
        _add_symbol(symbols, name, kind, "function", "inferred:semantic_snapshot", confidence)

    for item in symbols.values():
        rows[_sheet_for_kind(str(item.get("kind") or ""))].append(item)
    for pair in _infer_pairs(roles):
        sheet_rows = rows[pair["sheet"]]
        acquire = pair["acquire_func"]
        release = pair["release_func"]
        acquire_row = next((row for row in sheet_rows if row.get("symbol_name") == acquire), None)
        if acquire_row is None:
            acquire_row = _symbol_row(
                acquire,
                _acquire_kind_for_sheet(pair["sheet"]),
                "function",
                "inferred:pair_name",
                0.70,
                description=pair["description"],
            )
            sheet_rows.append(acquire_row)
        acquire_row["pair"] = _merge_csv(acquire_row.get("pair", ""), release)

        if not any(row.get("symbol_name") == release for row in sheet_rows):
            sheet_rows.append(
                _symbol_row(
                    release,
                    _release_kind_for_sheet(pair["sheet"]),
                    "function",
                    "inferred:pair_name",
                    0.70,
                    description=pair["description"],
                )
            )
    _merge_handler_evidence(rows, evidence_by_name, function_names)
    for sheet in ("resource", "lock"):
        rows[sheet] = sorted(rows[sheet], key=lambda item: item["symbol_name"])
    rows["dispatcher"] = sorted(
        rows["dispatcher"],
        key=lambda item: (
            item.get("dispatcher_name", ""),
            item.get("message_type", ""),
            item.get("handler_name", ""),
        ),
    )
    rows["module_lifecycle"] = sorted(rows["module_lifecycle"], key=lambda item: item["symbol_name"])
    return rows


def _add_symbol(
    symbols: Dict[str, Dict[str, Any]],
    name: str,
    kind: str,
    symbol_type: str,
    source: str,
    confidence: float,
    *,
    body: str = "",
    signature: str = "",
) -> None:
    if not name or name in DEFAULT_API_NAMES:
        return
    existing = symbols.get(name)
    if existing:
        if confidence > float(existing.get("confidence") or 0):
            existing["kind"] = kind
            existing["source"] = source
            existing["confidence"] = f"{confidence:.2f}"
        description = _description_for_kind(name, kind, symbol_type, body, signature)
        if body and description:
            existing["description"] = description
        return
    symbols[name] = _symbol_row(
        name,
        kind,
        symbol_type,
        source,
        confidence,
        description=_description_for_kind(name, kind, symbol_type, body, signature),
    )


def _symbol_row(
    name: str,
    kind: str,
    symbol_type: str,
    source: str,
    confidence: float,
    *,
    description: str = "",
) -> Dict[str, Any]:
    return {
        "symbol_name": name,
        "kind": kind,
        "symbol_type": symbol_type,
        "pair": "",
        "description": description or f"{symbol_type} `{name}` inferred as {kind}.",
        "source": source,
        "confidence": f"{confidence:.2f}",
        "notes": "Review before enabling in production scans.",
    }


def _classify_symbol_name(name: str) -> str:
    deterministic = DeterministicCandidateGenerator._classify_api_name(name)
    if deterministic:
        return deterministic
    lower = name.lower()
    if _paired_lifecycle_name(lower, acquire=True):
        return "resource_acquire"
    if _paired_lifecycle_name(lower, acquire=False):
        return "deallocator"
    return ""


def _classify_body(code: str, roles: Dict[str, str]) -> str:
    callees = set(CALL_RE.findall(code))
    called_roles = {_normalize_role(roles[name]) for name in callees if name in roles}
    lowered = code.lower()
    if re.search(r"\b(?:malloc|calloc)\s*\(", lowered):
        called_roles.add("allocator")
    if re.search(r"\brealloc\s*\(", lowered):
        called_roles.add("reallocator")
    if re.search(r"\bfree\s*\(", lowered):
        called_roles.add("deallocator")
    if re.search(r"(?:->|\.)\s*(?:alloc|malloc|calloc|new)\s*\(", lowered):
        called_roles.add("allocator")
    if re.search(r"(?:->|\.)\s*(?:realloc|resize)\s*\(", lowered):
        called_roles.add("reallocator")
    if re.search(r"(?:->|\.)\s*(?:free|dealloc|delete|release)\s*\(", lowered):
        called_roles.add("deallocator")
    if re.search(r"(?:->|\.)\s*lock\s*\(", lowered):
        called_roles.add("lock")
    if re.search(r"(?:->|\.)\s*unlock\s*\(", lowered):
        called_roles.add("unlock")
    if re.search(r"\b(?:pthread_mutex_lock|pthread_rwlock_[rw]dlock)\s*\(", lowered):
        called_roles.add("lock")
    if re.search(r"\b(?:pthread_mutex_unlock|pthread_rwlock_unlock)\s*\(", lowered):
        called_roles.add("unlock")
    if re.search(r"\b(?:memcpy|memmove|strncpy|strcpy)\s*\(", lowered):
        called_roles.add("copy")

    if "allocator" in called_roles and "deallocator" not in called_roles:
        return "allocator"
    if "reallocator" in called_roles:
        return "reallocator"
    if "deallocator" in called_roles and "allocator" not in called_roles:
        return "deallocator"
    if "lock" in called_roles and "unlock" not in called_roles:
        return "lock"
    if "unlock" in called_roles and "lock" not in called_roles:
        return "unlock"
    if "copy" in called_roles:
        return "copy"
    return ""


def _roles_from_snapshots(snapshot_dir: Optional[Path]) -> List[Tuple[str, str, float]]:
    if not snapshot_dir:
        return []
    root = Path(snapshot_dir)
    if not root.exists():
        return []
    roles: List[Tuple[str, str, float]] = []
    for path in root.glob("*.json"):
        if path.name.endswith("_final.json"):
            continue
        try:
            snapshot = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(snapshot, dict):
            continue
        name = str(snapshot.get("func_name") or "")
        kind = _classify_snapshot_text(json.dumps(snapshot, ensure_ascii=False).lower())
        if name and kind:
            roles.append((name, kind, 0.80))
    return roles


def _infer_pairs(roles: Dict[str, str]) -> List[Dict[str, Any]]:
    pairs: List[Dict[str, Any]] = []
    normalized = {name: _normalize_role(kind) for name, kind in roles.items()}
    resource_acquires = [
        name for name, kind in normalized.items() if kind in {"allocator", "calloc", "reallocator", "resource_acquire"}
    ]
    resource_releases = [name for name, kind in normalized.items() if kind == "deallocator"]
    lock_acquires = [name for name, kind in normalized.items() if kind == "lock"]
    lock_releases = [name for name, kind in normalized.items() if kind == "unlock"]

    pairs.extend(
        _pair_by_stem(
            resource_acquires,
            resource_releases,
            "resource",
            "memory",
            "inferred:pair_name",
            "Resource acquisition/release candidate.",
        )
    )
    pairs.extend(
        _pair_by_stem(
            lock_acquires,
            lock_releases,
            "lock",
            "lock",
            "inferred:pair_name",
            "Lock/unlock candidate.",
        )
    )
    return pairs


def _pair_by_stem(
    acquires: Sequence[str],
    releases: Sequence[str],
    sheet: str,
    category: str,
    source: str,
    description: str,
) -> List[Dict[str, Any]]:
    result = []
    seen = set()
    for acquire in acquires:
        acquire_stem = _pair_stem(acquire)
        for release in releases:
            if acquire == release:
                continue
            release_stem = _pair_stem(release)
            if not _stems_match(acquire_stem, release_stem):
                continue
            key = (sheet, acquire, release)
            if key in seen:
                continue
            seen.add(key)
            result.append(
                {
                    "sheet": sheet,
                    "category": category,
                    "acquire_func": acquire,
                    "release_func": release,
                    "source": source,
                    "confidence": "0.70",
                    "description": description,
                    "notes": "Many-to-many pairs are supported; keep all valid release functions.",
                }
            )
    return result


def _merge_handler_evidence(
    rows: Dict[str, List[Dict[str, Any]]],
    evidence_by_name: Dict[str, FunctionEvidence],
    known_names: Sequence[str],
) -> None:
    dispatcher_handler_names = set()
    for name in sorted(evidence_by_name):
        evidence = evidence_by_name[name]
        category = _handler_category(evidence)
        if category == "dispatch":
            dispatcher_rows = _dispatcher_rows(evidence, evidence_by_name, known_names)
            dispatcher_handler_names.update(
                row["handler_name"] for row in dispatcher_rows if row.get("handler_name")
            )
            rows.setdefault("dispatcher", []).extend(dispatcher_rows)
        elif category == "init_destroy":
            rows.setdefault("module_lifecycle", []).append(
                _module_lifecycle_row(evidence, known_names)
            )

    if dispatcher_handler_names:
        rows["resource"] = [
            row
            for row in rows.get("resource", [])
            if not (
                row.get("symbol_name") in dispatcher_handler_names
                and str(row.get("source", "")).startswith("inferred")
            )
        ]


def _dispatcher_rows(
    dispatcher: FunctionEvidence,
    evidence_by_name: Dict[str, FunctionEvidence],
    known_names: Sequence[str],
) -> List[Dict[str, Any]]:
    branch_pairs = _dispatcher_branches(dispatcher, known_names)
    rows = []
    for message_type, handler_name in branch_pairs:
        handler_evidence = evidence_by_name.get(handler_name)
        handler_kind = _dispatcher_handler_kind(handler_evidence)
        rows.append(
            {
                "dispatcher_name": dispatcher.name,
                "file_path": dispatcher.file_path,
                "message_type": message_type,
                "handler_name": handler_name,
                "handler_kind": handler_kind,
                "resource": _resource_name(handler_evidence) if handler_evidence else "",
                "pair": "",
                "description": _dispatcher_description(dispatcher, handler_evidence, handler_kind),
                "source": "inferred:dispatcher",
                "confidence": "0.74",
                "notes": "Review message type, resource name, and handler pair before production scans.",
            }
        )
    if not rows:
        rows.append(
            {
                "dispatcher_name": dispatcher.name,
                "file_path": dispatcher.file_path,
                "message_type": dispatcher.message_type,
                "handler_name": "",
                "handler_kind": "dispatcher",
                "resource": "",
                "pair": "",
                "description": _dispatcher_description(dispatcher, None, "dispatcher"),
                "source": "inferred:dispatcher",
                "confidence": "0.60",
                "notes": "No concrete branch handler was extracted; review dispatcher manually.",
            }
        )
    _fill_dispatcher_pairs(rows)
    return rows


def _evidence_from_impl(name: str, impl: Dict[str, Any]) -> FunctionEvidence:
    code = str(impl.get("code") or "")
    return FunctionEvidence(
        name=name,
        code=code,
        file_path=str(impl.get("file") or ""),
        message_type=_first_match(MESSAGE_TYPE_RE, code),
        allocation_calls=_unique(ALLOC_CALL_RE.findall(code)),
        release_calls=_unique(RELEASE_CALL_RE.findall(code)),
        global_structures=_unique(GLOBAL_DS_RE.findall(code)),
        role_fields=_unique(ROLE_FIELD_RE.findall(code)),
        literal_param_calls=_literal_param_calls(code),
        calls=_unique(CALL_RE.findall(code)),
    )


def _dispatcher_branches(dispatcher: FunctionEvidence, known_names: Sequence[str]) -> List[Tuple[str, str]]:
    known = set(known_names)
    rows: List[Tuple[str, str]] = []
    seen = set()

    for match in CASE_BLOCK_RE.finditer(dispatcher.code):
        message = match.group("message")
        handler = _first_known_call(match.group("body"), known, dispatcher.name)
        if not handler:
            continue
        key = (message, handler)
        if key not in seen:
            rows.append(key)
            seen.add(key)

    for match in TABLE_HANDLER_RE.finditer(dispatcher.code):
        message = match.group("message")
        handler = match.group("handler")
        if handler not in known or handler == dispatcher.name:
            continue
        key = (message, handler)
        if key not in seen:
            rows.append(key)
            seen.add(key)
    return rows


def _first_known_call(code: str, known_names: set, current_name: str) -> str:
    ignored = {
        current_name,
        "if",
        "for",
        "while",
        "switch",
        "return",
        "sizeof",
        "case",
    }
    for callee in CALL_RE.findall(code):
        if callee in ignored:
            continue
        if callee in known_names:
            return callee
    return ""


def _dispatcher_handler_kind(evidence: Optional[FunctionEvidence]) -> str:
    if not evidence:
        return "unknown"
    category = _handler_category(evidence)
    if category == "allocation":
        return "resource_acquire"
    if category == "release":
        return "resource_release"
    if category == "fault":
        return "cleanup"
    if category == "query":
        return "query"
    if category == "dispatch":
        return "dispatcher"
    return "other"


def _fill_dispatcher_pairs(rows: List[Dict[str, Any]]) -> None:
    release_handlers = [
        row["handler_name"]
        for row in rows
        if row.get("handler_name") and row.get("handler_kind") in {"resource_release", "cleanup"}
    ]
    for row in rows:
        if row.get("handler_kind") != "resource_acquire":
            continue
        handler = row.get("handler_name", "")
        candidates = _name_pair_candidates(handler, "allocation")
        matched = [release for release in release_handlers if release in candidates]
        if not matched and len(release_handlers) == 1:
            matched = release_handlers
        row["pair"] = _merge_csv(row.get("pair", ""), ", ".join(matched))


def _dispatcher_description(
    dispatcher: FunctionEvidence,
    handler: Optional[FunctionEvidence],
    handler_kind: str,
) -> str:
    if handler is None:
        style = "table/function-pointer dispatch" if _looks_like_table_dispatch(dispatcher.code) else "switch/case dispatch"
        return (
            f"Dispatcher `{dispatcher.name}` uses {style}. Review branch coverage, duplicate/default handling, "
            "message buffer cleanup, and branch-specific resource ownership."
        )
    if handler_kind == "resource_acquire":
        return (
            f"Handler `{handler.name}` appears to acquire resource `{_resource_name(handler)}` via "
            f"{_call_summary(handler.allocation_calls, 'allocator/resource creation')} under dispatcher `{dispatcher.name}`."
        )
    if handler_kind == "resource_release":
        return (
            f"Handler `{handler.name}` appears to release resource `{_resource_name(handler)}` via "
            f"{_call_summary(handler.release_calls, 'release/free/close')} under dispatcher `{dispatcher.name}`."
        )
    if handler_kind == "cleanup":
        return (
            f"Handler `{handler.name}` appears to clean up resources from {_global_ds_summary(handler)} "
            f"under dispatcher `{dispatcher.name}`."
        )
    if handler_kind == "query":
        return f"Handler `{handler.name}` appears to be a query/read-only branch under dispatcher `{dispatcher.name}`."
    return f"Handler `{handler.name}` is a dispatcher branch under `{dispatcher.name}`."


def _module_lifecycle_row(evidence: FunctionEvidence, known_names: Sequence[str]) -> Dict[str, Any]:
    kind = "finit" if re.search(r"(Finit|Destroy)", evidence.name) else "init"
    pair = _module_lifecycle_pair(evidence.name, known_names, kind)
    return {
        "symbol_name": evidence.name,
        "file_path": evidence.file_path,
        "kind": kind,
        "pair": pair,
        "needs_finit": "review" if kind == "init" else "",
        "error_path_cleanup_required": "review" if kind == "init" else "",
        "description": _module_lifecycle_description(evidence, kind, pair),
        "source": "inferred:module_lifecycle",
        "confidence": "0.70",
        "notes": (
            "User must confirm whether init-owned resources live for process lifetime, "
            "whether reset-on-failure makes cleanup unnecessary, and whether finit/error cleanup is required."
        ),
    }


def _module_lifecycle_pair(name: str, known_names: Sequence[str], kind: str) -> str:
    candidates = []
    if kind == "init":
        candidates.extend(
            [
                name.replace("ResInit", "ResFinit"),
                name.replace("Init", "Finit"),
                name.replace("Create", "Destroy"),
            ]
        )
    else:
        candidates.extend(
            [
                name.replace("ResFinit", "ResInit"),
                name.replace("Finit", "Init"),
                name.replace("Destroy", "Create"),
            ]
        )
    known_lower = {item.lower(): item for item in known_names}
    for candidate in candidates:
        found = known_lower.get(candidate.lower())
        if found and found != name:
            return found
    return ""


def _module_lifecycle_description(evidence: FunctionEvidence, kind: str, pair: str) -> str:
    action = "initializes" if kind == "init" else "finalizes"
    pair_text = f" Paired function candidate: {pair}." if pair else ""
    return (
        f"Function `{evidence.name}` {action} module-level resources."
        f"{pair_text} Review whether resources require process-lifetime cleanup and whether error branches must roll back."
    )


def _handler_category(evidence: FunctionEvidence) -> str:
    name = evidence.name
    has_dispatch_body = (
        "switch" in evidence.code
        or "case " in evidence.code
        or re.search(
            r"\b(?:handler|dispatch|proc|ops)\w*(?:table|api|map|list|array)\b",
            evidence.code,
            re.I,
        )
    )
    if DISPATCH_NAME_RE.search(name) and has_dispatch_body:
        return "dispatch"
    if FAULT_NAME_RE.search(name):
        return "fault"
    if INIT_NAME_RE.search(name):
        return "init_destroy"
    if evidence.has_conditional_literal_release:
        return "release"
    if ALLOC_NAME_RE.search(name):
        return "allocation"
    if RELEASE_NAME_RE.search(name):
        return "release"
    if evidence.allocation_calls:
        return "allocation"
    if evidence.release_calls:
        return "release"
    if QUERY_NAME_RE.search(name):
        return "query"
    if DISPATCH_NAME_RE.search(name):
        return "dispatch"
    if has_dispatch_body and evidence.message_type:
        return "dispatch"
    return "generic"


def _name_pair_candidates(function_name: str, category: str) -> List[str]:
    pairs = (
        ("Apply", "Release"),
        ("Alloc", "Free"),
        ("Create", "Destroy"),
        ("Add", "Del"),
        ("Add", "Delete"),
        ("Register", "Unregister"),
        ("Bind", "Close"),
        ("Connect", "Close"),
        ("Join", "Leave"),
    )
    candidates = []
    for left, right in pairs:
        if left in function_name:
            candidates.append(function_name.replace(left, right))
        if right in function_name:
            candidates.append(function_name.replace(right, left))
    if category == "fault":
        candidates.extend(name for name in candidates if RELEASE_NAME_RE.search(name))
    return candidates


def _literal_param_calls(code: str) -> List[Tuple[str, str]]:
    calls = []
    for match in LITERAL_PARAM_CALL_RE.finditer(code):
        callee = match.group("callee")
        args = " ".join(match.group("args").split())
        if any(word in callee.lower() for word in ("close", "free", "release", "remove", "destroy", "delete")):
            calls.append((callee, args))
    return calls[:3]


def _resource_name(evidence: FunctionEvidence) -> str:
    lower = evidence.name.lower()
    if "port" in lower:
        return "port"
    if "member" in lower:
        return "member node"
    if "conn" in lower:
        return "connection"
    if "bind" in lower:
        return "bind_info"
    if "listen" in lower:
        return "listen_info"
    if "shm" in lower:
        return "shared memory"
    if "fd" in lower or "socket" in lower:
        return "fd/socket"
    return "resource"


def _global_ds_summary(evidence: FunctionEvidence) -> str:
    if not evidence.global_structures:
        return "global/shared data structures"
    return "/".join(evidence.global_structures[:3])


def _call_summary(calls: Sequence[str], fallback: str) -> str:
    return "/".join(_unique(calls)[:4]) if calls else fallback


def _looks_like_table_dispatch(code: str) -> bool:
    return bool(re.search(r"\b(?:handler|dispatch|proc|ops)\w*(?:table|api|map|list|array)\b", code, re.I))


def _find_row(rows: Sequence[Dict[str, Any]], key: str, value: str) -> Optional[Dict[str, Any]]:
    return next((row for row in rows if row.get(key) == value), None)


def _merge_sentence(existing: Any, incoming: Any) -> str:
    left = str(existing or "").strip()
    right = str(incoming or "").strip()
    if not left:
        return right
    if not right or right in left:
        return left
    return f"{left} {right}"


def _merge_source(existing: Any, incoming: str) -> str:
    return _merge_csv(existing, incoming)


def _first_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1) if match else ""


def _unique(items: Iterable[str]) -> List[str]:
    result = []
    seen = set()
    for item in items:
        text = str(item).strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(text)
    return result


def _scan_function_like_macros(code_index: Any) -> Iterable[Tuple[str, str]]:
    seen_files = set()
    for root in _scan_roots(code_index):
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path in seen_files or not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            if _skip_path(code_index, path):
                continue
            seen_files.add(path)
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            idx = 0
            while idx < len(lines):
                line = lines[idx]
                match = FUNCTION_LIKE_MACRO_RE.match(line)
                if not match:
                    idx += 1
                    continue
                body_lines = [line]
                while body_lines[-1].rstrip().endswith("\\") and idx + 1 < len(lines):
                    idx += 1
                    body_lines.append(lines[idx])
                yield match.group(1), "\n".join(body_lines)
                idx += 1


def _scan_roots(code_index: Any) -> List[Path]:
    roots = [Path(code_index.source_root)]
    project_root = Path(code_index.project_root)
    if project_root.resolve() != roots[0].resolve():
        roots.append(project_root)
    include_paths = [Path(path) for path in getattr(code_index, "include_paths", []) or []]
    for path in include_paths:
        if path not in roots:
            roots.append(path)
    return roots


def _skip_path(code_index: Any, path: Path) -> bool:
    parts = set(path.parts)
    if parts & {".git", ".venv", ".mypy_cache", ".pytest_cache", ".zscope_snapshots", "build", "tmp"}:
        return True
    is_allowed = getattr(code_index, "_is_path_allowed", None)
    if callable(is_allowed):
        try:
            return not bool(is_allowed(path))
        except Exception:
            return True
    return False


def _classify_snapshot_text(text: str) -> str:
    if re.search(r"\b(?:unlock|release lock|mutex unlock|rwlock unlock)\b", text):
        return "unlock"
    if re.search(r"\b(?:lock|mutex|rwlock|spinlock)\b", text):
        return "lock"
    if re.search(r"\b(?:realloc|resize allocation)\b", text):
        return "reallocator"
    if re.search(r"\b(?:free|dealloc|release memory|frees allocated)\b", text):
        return "deallocator"
    if re.search(r"\b(?:allocates|allocator|malloc|returns allocated|caller must free)\b", text):
        return "allocator"
    if re.search(r"\b(?:copy|memcpy|copies memory|buffer copy)\b", text):
        return "copy"
    return ""


def _memory_behavior_for_kind(kind: str) -> Dict[str, Any]:
    normalized = _normalize_role(kind)
    if normalized in {"allocator", "calloc", "resource_acquire"}:
        return {"allocates": True, "caller_owns_return": True}
    if normalized == "reallocator":
        return {"reallocates": True, "caller_owns_return": True}
    if normalized == "deallocator":
        return {"releases": True}
    if normalized == "copy":
        return {"copies_memory": True}
    return {}


def _concurrency_behavior_for_kind(kind: str) -> Dict[str, Any]:
    normalized = _normalize_role(kind)
    if normalized == "lock":
        return {"acquires_lock": True}
    if normalized == "unlock":
        return {"releases_lock": True}
    return {}


def _return_semantics_for_kind(kind: str) -> str:
    normalized = _normalize_role(kind)
    if normalized in {"allocator", "calloc", "resource_acquire"}:
        return "returns acquired resource or failure/null value"
    if normalized == "reallocator":
        return "returns resized resource or failure/null value"
    if normalized == "deallocator":
        return "releases resource passed by caller"
    return ""


def _sheet_for_kind(kind: str) -> str:
    kind = str(kind or "").lower()
    if kind in {"lock", "unlock"}:
        return "lock"
    return "resource"


def _acquire_kind_for_sheet(sheet: str) -> str:
    return {"resource": "allocator", "lock": "lock"}.get(sheet, "allocator")


def _release_kind_for_sheet(sheet: str) -> str:
    return {"resource": "deallocator", "lock": "unlock"}.get(sheet, "deallocator")


def _split_csv(value: Any) -> List[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _merge_csv(existing: Any, incoming: Any) -> str:
    values = []
    seen = set()
    for item in _split_csv(existing) + _split_csv(incoming):
        if item not in seen:
            values.append(item)
            seen.add(item)
    return ", ".join(values)


def _description_for_kind(
    name: str,
    kind: str,
    symbol_type: str,
    body: str,
    signature: str = "",
) -> str:
    params = _parameter_names(name, body, signature)
    param_text = ", ".join(params) if params else "unknown"
    size_params = [p for p in params if re.search(r"size|len|length|num|count|cnt|bytes|n$", p, re.I)]
    pointer_params = [p for p in params if re.search(r"ptr|buf|buffer|data|mem|addr|p$", p, re.I)]
    kind = str(kind or "").lower()
    if kind in {"allocator", "calloc", "resource_acquire"}:
        size_text = ", ".join(size_params) if size_params else "review size/count parameter"
        return (
            f"{symbol_type} `{name}` allocates/returns an owned resource. "
            f"Params: {param_text}; size/count params: {size_text}; "
            "Return: owned pointer/resource on success, failure/null value possible."
        )
    if kind == "reallocator":
        owner_text = pointer_params[0] if pointer_params else "review owner pointer parameter"
        size_text = ", ".join(size_params) if size_params else "review new size parameter"
        return (
            f"{symbol_type} `{name}` resizes an owned resource. "
            f"Owner param: {owner_text}; size param: {size_text}; "
            "Return: resized owned resource or failure/null value."
        )
    if kind in {"deallocator", "resource_release"}:
        target = pointer_params[0] if pointer_params else (params[0] if params else "review released parameter")
        return f"{symbol_type} `{name}` releases resource passed by caller. Released param: {target}."
    if kind == "lock":
        lock_obj = pointer_params[0] if pointer_params else (params[0] if params else "review lock parameter")
        return f"{symbol_type} `{name}` acquires lock object. Lock param: {lock_obj}."
    if kind == "unlock":
        lock_obj = pointer_params[0] if pointer_params else (params[0] if params else "review lock parameter")
        return f"{symbol_type} `{name}` releases lock object. Lock param: {lock_obj}."
    if body:
        callees = sorted(set(CALL_RE.findall(body)) - {name})
        if callees:
            return f"{symbol_type} `{name}` inferred as {kind}. Calls: " + ", ".join(callees[:6])
    return f"{symbol_type} `{name}` inferred as {kind}."


def _parameter_names(name: str, body: str, signature: str) -> List[str]:
    text = signature or _signature_from_body(name, body)
    if not text and body.lstrip().startswith("#"):
        text = body.splitlines()[0]
    match = re.search(rf"\b{re.escape(name)}\s*\((?P<params>[^)]*)\)", text)
    if not match:
        return []
    raw_params = [item.strip() for item in match.group("params").split(",")]
    names = []
    for raw in raw_params:
        if not raw or raw == "void":
            continue
        raw = raw.split("=")[0].strip()
        identifiers = re.findall(r"\b[A-Za-z_]\w*\b", raw)
        if identifiers:
            names.append(identifiers[-1])
    return names


def _signature_from_body(name: str, body: str) -> str:
    cleaned_lines = []
    for raw_line in str(body or "").splitlines()[:8]:
        cleaned = re.sub(r"^\s*\d+\s*\|\s*", "", raw_line).strip()
        cleaned_lines.append(cleaned)
        if "{" in cleaned or cleaned.endswith("\\"):
            break
    text = " ".join(cleaned_lines)
    idx = text.find("{")
    return text[:idx].strip() if idx >= 0 else text.strip()


def _normalize_role(kind: str) -> str:
    if kind in {"calloc"}:
        return "allocator"
    return str(kind or "")


def _body_role_can_refine(existing: str, body_kind: str) -> bool:
    if existing == body_kind:
        return True
    if existing == "resource_acquire" and body_kind in {"allocator", "reallocator"}:
        return True
    return False


def _should_inspect_body(name: str) -> bool:
    return bool(WRAPPER_NAME_HINT_RE.search(name))


def _has_any(text: str, *needles: str) -> bool:
    return any(item in text for item in needles)


def _paired_lifecycle_name(lower: str, *, acquire: bool) -> bool:
    if acquire:
        return bool(
            re.search(
                r"(?:^|_)(?:create|add|apply|register|bind|connect|join|open|acquire|get|ref)(?:_|$)",
                lower,
            )
        )
    return bool(
        re.search(
            r"(?:^|_)(?:delete|del|remove|destroy|free|close|release|leave|unregister|put|unref)(?:_|$)",
            lower,
        )
    )


def _pair_stem(name: str) -> str:
    stem = name.lower()
    for token in (
        "calloc",
        "malloc",
        "realloc",
        "alloc",
        "dealloc",
        "free",
        "unlock",
        "lock",
        "unregister",
        "register",
        "unsubscribe",
        "subscribe",
        "remove",
        "add",
        "apply",
        "uninstall",
        "install",
        "destroy",
        "create",
        "close",
        "open",
        "release",
        "leave",
        "join",
        "unbind",
        "bind",
        "disconnect",
        "connect",
        "acquire",
        "unref",
        "ref",
        "put",
        "get",
    ):
        stem = stem.replace(token, "")
    return re.sub(r"[^a-z0-9]", "", stem)


def _stems_match(left: str, right: str) -> bool:
    if not left or not right:
        return False
    if left == right:
        return True
    short, long = sorted((left, right), key=len)
    return len(short) >= 4 and long.startswith(short)
