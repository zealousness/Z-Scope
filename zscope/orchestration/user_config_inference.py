"""Infer human-reviewable user configuration rows from a project."""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..common.utils import extract_json_blocks
from ..config.user_config_workbook import SHEET_HEADERS
from ..core.candidates.regex import RegexCandidateGenerator
from ..semantics.defaults import default_local_pattern_semantics


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".inc", ".inl", ".ph"}


def _default_api_names() -> set[str]:
    semantics = default_local_pattern_semantics()
    names: set[str] = set()
    for attr in (
        "allocators",
        "calloc_allocators",
        "reallocators",
        "deallocators",
        "copy_sinks",
        "lock_apis",
        "unlock_apis",
    ):
        names.update(str(name) for name in getattr(semantics, attr, {}))
    return names


DEFAULT_API_NAMES = _default_api_names()
SKIPPED_DEFAULT_API_NAMES = DEFAULT_API_NAMES
WRAPPER_NAME_HINT_RE = re.compile(
    r"alloc|free|dealloc|lock|unlock|copy|cpy|move|create|destroy|"
    r"open|close|acquire|release|get|put|ref|unref",
    re.IGNORECASE,
)
API_ACTION_TOKENS = {
    "alloc",
    "malloc",
    "calloc",
    "realloc",
    "free",
    "dealloc",
    "lock",
    "unlock",
    "copy",
    "cpy",
    "move",
}
CONSTANT_NOISE_TOKENS = {
    "err",
    "error",
    "fail",
    "failed",
    "invalid",
    "null",
    "max",
    "min",
    "size",
    "len",
    "length",
    "num",
    "count",
    "cnt",
    "flag",
    "flags",
    "type",
    "kind",
    "mode",
    "state",
    "status",
    "default",
    "limit",
}
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
LOCK_RE = re.compile(
    r"(mutex|rwlock|spinlock|pthread_mutex|pthread_rwlock|\bLOCK\b|\bUNLOCK\b)", re.I
)
ERROR_PATH_RE = re.compile(r"\b(return|goto|ERROR|FAIL|ERR|ENOMEM|EINVAL)\b")
MESSAGE_TYPE_RE = re.compile(r"\b([A-Z][A-Z0-9_]+_(?:MSG|REQUEST|NOTIFY|APPLY|FREE|CLOSE)\w*)\b")
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
LLM_REVIEWABLE_SHEETS = {"resource", "lock", "dispatcher", "module_lifecycle"}
LLM_REVIEW_BATCH_SIZE = 8
PAIRABLE_SHEETS = ("resource", "lock")


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


def infer_user_config_rows(
    code_index: Any, snapshot_dir: Optional[Path] = None
) -> Dict[str, List[Dict[str, Any]]]:
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
        kind = _classify_symbol_name(name) or _classify_body(
            body,
            roles,
            propagate_project_roles=True,
        )
        if kind:
            roles[name] = kind
            _add_symbol(symbols, name, kind, "macro", "inferred:macro", 0.78, body=body)

    for name in function_names:
        impl = code_index.get_function_impl(name, max_lines=240, warn_missing=False)
        if not impl:
            continue
        code = str(impl.get("code") or "")
        evidence_by_name[name] = _evidence_from_impl(name, impl)
        body_kind = (
            _classify_body(code, roles) if (name in roles or _should_inspect_body(name)) else ""
        )
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
    rows["module_lifecycle"] = sorted(
        rows["module_lifecycle"], key=lambda item: item["symbol_name"]
    )
    return rows


def filter_user_config_rows_with_llm(
    rows: Dict[str, List[Dict[str, Any]]],
    code_index: Any,
    llm_client: Any,
    *,
    batch_size: int = LLM_REVIEW_BATCH_SIZE,
    max_workers: int = 1,
) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, int]]:
    """Ask an LLM to remove noisy inferred user-config candidates.

    The workbook schema is unchanged. The LLM can only keep, drop, or revise
    existing rows; it cannot introduce new columns.
    """

    normalized = {name: [dict(row) for row in rows.get(name, [])] for name in SHEET_HEADERS}
    candidates = _llm_review_candidates(normalized, code_index)
    stats = {
        "reviewed": 0,
        "kept": 0,
        "dropped": 0,
        "revised": 0,
        "unreviewed": 0,
        "errors": 0,
    }
    if not candidates:
        return normalized, stats

    decisions: Dict[str, Dict[str, Any]] = {}
    batches = list(_chunks(candidates, max(1, batch_size)))
    worker_count = max(1, min(_coerce_positive_int(max_workers, 1), len(batches)))
    if worker_count == 1:
        for batch in batches:
            try:
                batch_decisions = _request_llm_user_config_decisions_for_thread(llm_client, batch)
            except Exception:
                stats["errors"] += 1
                continue
            decisions.update(batch_decisions)
            stats["reviewed"] += len(batch_decisions)
    else:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_to_batch = {
                executor.submit(
                    _request_llm_user_config_decisions_for_thread,
                    llm_client,
                    batch,
                ): batch
                for batch in batches
            }
            for future in as_completed(future_to_batch):
                try:
                    batch_decisions = future.result()
                except Exception:
                    stats["errors"] += 1
                    continue
                decisions.update(batch_decisions)
                stats["reviewed"] += len(batch_decisions)

    filtered: Dict[str, List[Dict[str, Any]]] = {name: [] for name in SHEET_HEADERS}
    dropped_by_sheet: Dict[str, set[str]] = {sheet: set() for sheet in SHEET_HEADERS}

    for sheet, sheet_rows in normalized.items():
        for idx, row in enumerate(sheet_rows):
            candidate_id = _candidate_id(sheet, idx)
            decision = decisions.get(candidate_id)
            if not decision:
                filtered[sheet].append(row)
                if sheet in LLM_REVIEWABLE_SHEETS:
                    stats["unreviewed"] += 1
                continue

            action = str(decision.get("action") or "keep").strip().lower()
            if action not in {"keep", "drop", "revise"}:
                action = "keep"
            if action == "drop":
                dropped_by_sheet[sheet].add(_row_primary_name(sheet, row))
                stats["dropped"] += 1
                continue

            revised = _apply_llm_decision(sheet, row, decision)
            if action == "revise":
                stats["revised"] += 1
            else:
                stats["kept"] += 1
            filtered[sheet].append(revised)

    _remove_pairs_to_dropped_symbols(filtered, dropped_by_sheet)
    return filtered, stats


def _llm_review_candidates(
    rows: Dict[str, List[Dict[str, Any]]],
    code_index: Any,
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    for sheet in ("resource", "lock"):
        for idx, row in enumerate(rows.get(sheet, [])):
            symbol = str(row.get("symbol_name") or "")
            candidates.append(
                {
                    "id": _candidate_id(sheet, idx),
                    "sheet": sheet,
                    "row": _llm_safe_row(row),
                    "generalized_pattern": _generalized_symbol_pattern(symbol),
                    "evidence": _symbol_evidence(code_index, symbol),
                }
            )
    for idx, row in enumerate(rows.get("dispatcher", [])):
        dispatcher = str(row.get("dispatcher_name") or "")
        handler = str(row.get("handler_name") or "")
        candidates.append(
            {
                "id": _candidate_id("dispatcher", idx),
                "sheet": "dispatcher",
                "row": _llm_safe_row(row),
                "generalized_pattern": "",
                "evidence": {
                    "dispatcher": _symbol_evidence(code_index, dispatcher),
                    "handler": _symbol_evidence(code_index, handler) if handler else {},
                },
            }
        )
    for idx, row in enumerate(rows.get("module_lifecycle", [])):
        symbol = str(row.get("symbol_name") or "")
        pair = str(row.get("pair") or "")
        candidates.append(
            {
                "id": _candidate_id("module_lifecycle", idx),
                "sheet": "module_lifecycle",
                "row": _llm_safe_row(row),
                "generalized_pattern": "",
                "evidence": {
                    "symbol": _symbol_evidence(code_index, symbol),
                    "pair": _symbol_evidence(code_index, pair) if pair else {},
                },
            }
        )
    return candidates


def _request_llm_user_config_decisions(
    llm_client: Any,
    candidates: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    messages = [
        {"role": "system", "content": _llm_user_config_system_prompt()},
        {
            "role": "user",
            "content": (
                "Review these inferred Z-Scope user_config workbook candidates. "
                "Return JSON only.\n"
                + json.dumps({"candidates": candidates}, ensure_ascii=False, indent=2)
            ),
        },
    ]
    response = llm_client.chat_completion(
        messages,
        temperature=0.0,
        max_tokens=4096,
        trace_agent="user_config_infer_filter",
        trace_label="llm_screen_user_config",
    )
    content = str(response.get("choices", [{}])[0].get("message", {}).get("content", ""))
    parsed_blocks = extract_json_blocks(content)
    decisions: Dict[str, Dict[str, Any]] = {}
    for block in parsed_blocks:
        raw_items = block.get("items") or block.get("decisions") or []
        if not isinstance(raw_items, list):
            continue
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            candidate_id = str(item.get("id") or "").strip()
            if candidate_id:
                decisions[candidate_id] = item
        if decisions:
            break
    return decisions


def _request_llm_user_config_decisions_for_thread(
    llm_client: Any,
    candidates: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    try:
        return _request_llm_user_config_decisions(llm_client, candidates)
    finally:
        _close_llm_thread_session(llm_client)


def _close_llm_thread_session(llm_client: Any) -> None:
    close_thread_session = getattr(llm_client, "close_thread_session", None)
    if callable(close_thread_session):
        close_thread_session()


def _llm_user_config_system_prompt() -> str:
    return (
        "You are screening candidates for a human-editable Z-Scope user_config.xlsx. "
        "The workbook columns are fixed; you may only keep, drop, or revise existing rows.\n\n"
        "Decision rules:\n"
        "- Keep resource rows only for APIs/macros that themselves model resource allocation, "
        "reallocation, release, copy, open/close-style ownership transfer, bitmap/list resource "
        "acquire/release, or closely equivalent project resource operations.\n"
        "- Keep lock rows only for APIs/macros that themselves acquire or release locks. "
        "Do not keep business functions that merely call a lock/unlock helper.\n"
        "- Drop constants, limits, error/status macros, flag/type/mode names, enum-like names, "
        "and condition helpers even if their names contain alloc/free/lock. Examples: "
        "ALLOCATOR_ERR, ALLOC_SIZE_MAX_1, FOO_LOCK_FLAG.\n"
        "- Drop ordinary callers/wrappers whose main business logic merely calls an already-kept "
        "allocator/deallocator/lock/unlock. Do not turn every caller of XXX_ALLOC into an allocator, "
        "and do not turn every caller of XXX_FREE into a paired deallocator.\n"
        "- Keep thin macro aliases such as DDM_ALLOC, ANYXML_MALLOC, DDM_FREE, ANYXML_LOCK. "
        "Treat project-specific prefixes as generalized patterns: DDM_ALLOC should be understood "
        "as XXX_ALLOC, DDM_FREE as XXX_FREE, DDM_LOCK as XXX_LOCK. Return that abstraction in "
        "generalized_pattern or notes, but keep the actual symbol_name unchanged.\n"
        "- When evidence shows resource lifecycle patterns, consider allocation/release APIs, "
        "global list/hash/bitmap operations, error-path cleanup, cross-handler acquire/release, "
        "conditional literal parameters (TRUE/FALSE/0/1), and concurrency protection. Use these "
        "signals to revise descriptions/notes, not to invent extra workbook columns.\n"
        "- For resource and lock rows, verify and correct the description so it explicitly states "
        "where the modeled object is located. Use these exact key names inside description when "
        "applicable: resource_output=return, resource_output=argN, resource_output=argN_deref, "
        "resource_input=argN, old_resource=argN, size_arg=argN, lock_arg=argN, "
        "failure_values=NULL/-1/0. Examples: malloc => resource_output=return; size_arg=arg1; "
        "free => resource_input=arg1; pthread_mutex_lock => lock_arg=arg1. If the position is "
        "not visible in the evidence, write resource_output=review or resource_input=review.\n"
        "- Keep dispatcher rows only when the evidence shows switch/case or table-driven message "
        "dispatch to handlers.\n"
        "- Keep module_lifecycle rows only for real init/finit/create/destroy module lifecycle "
        "functions, not arbitrary helpers containing Init or Destroy in unrelated names.\n"
        "- Prefer dropping a noisy candidate over keeping speculative configuration. The workbook "
        "will be manually reviewed later.\n\n"
        "Return exactly one JSON object with this schema:\n"
        '{ "items": [ { "id": string, "action": "keep"|"drop"|"revise", '
        '"kind": optional string, "pair": optional string, "description": optional string, '
        '"confidence": optional number, "generalized_pattern": optional string, '
        '"notes": string } ] }\n'
        "No markdown, no prose outside JSON."
    )


def _apply_llm_decision(
    sheet: str, row: Dict[str, Any], decision: Dict[str, Any]
) -> Dict[str, Any]:
    updated = dict(row)
    action = str(decision.get("action") or "keep").strip().lower()
    for field in ("kind", "pair", "description"):
        value = str(decision.get(field) or "").strip()
        if field == "kind" and action != "revise":
            continue
        if value and field in SHEET_HEADERS.get(sheet, []):
            updated[field] = value
    _ensure_location_markers(sheet, row, updated)
    confidence = decision.get("confidence")
    if confidence not in (None, "") and "confidence" in SHEET_HEADERS.get(sheet, []):
        updated["confidence"] = f"{_coerce_confidence(confidence):.2f}"
    pattern = str(decision.get("generalized_pattern") or "").strip()
    if not pattern:
        pattern = _generalized_symbol_pattern(_row_primary_name(sheet, row))
    note = str(decision.get("notes") or "").strip()
    if pattern:
        note = _append_note(note, f"pattern={pattern}")
    if note and "notes" in SHEET_HEADERS.get(sheet, []):
        updated["notes"] = _append_note(str(updated.get("notes") or ""), note)
    if "source" in SHEET_HEADERS.get(sheet, []):
        updated["source"] = _merge_csv(updated.get("source", ""), "llm:screened")
    return updated


def _ensure_location_markers(sheet: str, original: Dict[str, Any], updated: Dict[str, Any]) -> None:
    if "description" not in SHEET_HEADERS.get(sheet, []):
        return
    kind = str(updated.get("kind") or original.get("kind") or "").strip().lower()
    marker_names: List[str] = []
    if sheet == "lock" and kind in {"lock", "unlock"}:
        marker_names.append("lock_arg")
    elif sheet == "resource":
        if kind in {"allocator", "calloc", "resource_acquire", "reallocator"}:
            marker_names.append("resource_output")
            if _extract_marker(original.get("description", ""), "size_arg"):
                marker_names.append("size_arg")
            if _extract_marker(original.get("description", ""), "failure_values"):
                marker_names.append("failure_values")
        if kind == "reallocator":
            marker_names.append("old_resource")
        if kind in {"deallocator", "resource_release"}:
            marker_names.append("resource_input")
        if kind == "copy":
            for marker in ("resource_output", "resource_input", "size_arg"):
                if _extract_marker(original.get("description", ""), marker):
                    marker_names.append(marker)

    description = str(updated.get("description") or "")
    for marker in marker_names:
        if re.search(rf"\b{re.escape(marker)}\s*=", description):
            continue
        fallback = _extract_marker(original.get("description", ""), marker) or f"{marker}=review"
        description = _append_description_marker(description, fallback)
    updated["description"] = description


def _extract_marker(text: Any, marker: str) -> str:
    match = re.search(rf"\b{re.escape(marker)}\s*=\s*([^;.]+)", str(text or ""))
    if not match:
        return ""
    return f"{marker}={match.group(1).strip()}"


def _append_description_marker(description: str, marker_text: str) -> str:
    base = str(description or "").strip()
    if not base:
        return marker_text
    separator = " " if base.endswith((".", ";")) else "; "
    return f"{base}{separator}{marker_text}."


def _remove_pairs_to_dropped_symbols(
    rows: Dict[str, List[Dict[str, Any]]],
    dropped_by_sheet: Dict[str, set[str]],
) -> None:
    for sheet in PAIRABLE_SHEETS:
        dropped = dropped_by_sheet.get(sheet, set())
        if not dropped:
            continue
        for row in rows.get(sheet, []):
            pairs = [item for item in _split_csv(row.get("pair", "")) if item not in dropped]
            row["pair"] = ", ".join(pairs)


def _symbol_evidence(code_index: Any, symbol: str) -> Dict[str, Any]:
    if not symbol:
        return {}
    impl = None
    get_impl = getattr(code_index, "get_function_impl", None)
    if callable(get_impl):
        try:
            impl = get_impl(symbol, max_lines=80, warn_missing=False)
        except TypeError:
            impl = get_impl(symbol)
        except Exception:
            impl = None
    if not impl:
        return {"symbol": symbol, "found": False}
    code = str(impl.get("code") or "")
    return {
        "symbol": symbol,
        "found": True,
        "file": str(impl.get("file") or ""),
        "signature": str(impl.get("signature") or ""),
        "is_macro": bool(impl.get("is_macro")),
        "calls": _unique(CALL_RE.findall(code))[:12],
        "code_excerpt": _truncate_text(code, 1200),
    }


def _llm_safe_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: row.get(key, "") for key in row.keys() if key in set().union(*SHEET_HEADERS.values())
    }


def _candidate_id(sheet: str, idx: int) -> str:
    return f"{sheet}:{idx}"


def _chunks(items: Sequence[Dict[str, Any]], size: int) -> Iterable[List[Dict[str, Any]]]:
    for start in range(0, len(items), size):
        yield list(items[start : start + size])


def _coerce_positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _row_primary_name(sheet: str, row: Dict[str, Any]) -> str:
    if sheet == "dispatcher":
        return str(row.get("handler_name") or row.get("dispatcher_name") or "")
    return str(row.get("symbol_name") or "")


def _truncate_text(text: str, limit: int) -> str:
    value = str(text or "")
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...<truncated>"


def _coerce_confidence(value: Any) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.70
    if score > 1.0:
        score = score / 100.0
    return max(0.0, min(1.0, score))


def _append_note(existing: str, note: str) -> str:
    left = str(existing or "").strip()
    right = str(note or "").strip()
    if not right:
        return left
    if not left:
        return right
    if right in left:
        return left
    return f"{left}; {right}"


def _generalized_symbol_pattern(name: str) -> str:
    text = str(name or "").strip()
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", text):
        return ""
    for action in (
        "MALLOC",
        "CALLOC",
        "REALLOC",
        "ALLOC",
        "FREE",
        "DEALLOC",
        "UNLOCK",
        "LOCK",
        "COPY",
        "CPY",
        "MOVE",
    ):
        suffix = f"_{action}"
        if text.endswith(suffix) and text != action:
            return f"XXX{suffix}"
    return ""


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
    if not name or name in SKIPPED_DEFAULT_API_NAMES:
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


def _identifier_tokens(name: str) -> List[str]:
    return [token for token in re.split(r"_+", str(name or "").lower()) if token]


def _looks_like_constant_config_symbol(name: str) -> bool:
    text = str(name or "").strip()
    if not re.fullmatch(r"[A-Z0-9_]+", text):
        return False
    tokens = _identifier_tokens(text)
    if not tokens:
        return False
    if tokens[-1] in API_ACTION_TOKENS:
        return False
    return any(token in CONSTANT_NOISE_TOKENS or token.isdigit() for token in tokens)


def _role_has_api_action_shape(name: str, role: str) -> bool:
    role = _normalize_role(role)
    actions_by_role = {
        "allocator": ("alloc", "malloc"),
        "calloc": ("calloc",),
        "reallocator": ("realloc",),
        "deallocator": ("free", "dealloc"),
        "copy": ("copy", "cpy", "move"),
        "lock": ("lock",),
        "unlock": ("unlock",),
    }
    return any(_has_action_token(name, action) for action in actions_by_role.get(role, ()))


def _has_action_token(name: str, action: str) -> bool:
    lower = str(name or "").lower()
    if lower == action or lower.endswith(action):
        return True
    if lower.startswith(action + "_") or f"_{action}_" in lower or lower.endswith("_" + action):
        return True
    return False


def _classify_symbol_name(name: str) -> str:
    if _looks_like_constant_config_symbol(name):
        return ""
    regex_role = RegexCandidateGenerator._classify_api_name(name)
    if regex_role and _role_has_api_action_shape(name, regex_role):
        return regex_role
    lower = name.lower()
    if _paired_lifecycle_name(lower, acquire=True):
        return "resource_acquire"
    if _paired_lifecycle_name(lower, acquire=False):
        return "deallocator"
    return ""


def _classify_body(
    code: str,
    roles: Dict[str, str],
    *,
    propagate_project_roles: bool = False,
) -> str:
    callees = set(CALL_RE.findall(code))
    called_roles = (
        {_normalize_role(roles[name]) for name in callees if name in roles}
        if propagate_project_roles
        else set()
    )
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
        name
        for name, kind in normalized.items()
        if kind in {"allocator", "calloc", "reallocator", "resource_acquire"}
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
    dispatcher_handler_names: set[str] = set()
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


def _dispatcher_branches(
    dispatcher: FunctionEvidence, known_names: Sequence[str]
) -> List[Tuple[str, str]]:
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
            return str(callee)
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
        style = (
            "table/function-pointer dispatch"
            if _looks_like_table_dispatch(dispatcher.code)
            else "switch/case dispatch"
        )
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
        if any(
            word in callee.lower()
            for word in ("close", "free", "release", "remove", "destroy", "delete")
        ):
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
    return bool(
        re.search(r"\b(?:handler|dispatch|proc|ops)\w*(?:table|api|map|list|array)\b", code, re.I)
    )


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
            if (
                path in seen_files
                or not path.is_file()
                or path.suffix.lower() not in SOURCE_SUFFIXES
            ):
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
    skipped_directories = {
        ".git",
        ".venv",
        ".mypy_cache",
        ".pytest_cache",
        ".zscope_snapshots",
        "build",
        "tmp",
    }
    absolute_path = path.absolute()
    for root in _scan_roots(code_index):
        try:
            relative_path = absolute_path.relative_to(root.absolute())
        except ValueError:
            continue
        if set(relative_path.parts[:-1]) & skipped_directories:
            return True
        break
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
    size_params = [
        p for p in params if re.search(r"size|len|length|num|count|cnt|bytes|n$", p, re.I)
    ]
    pointer_params = [p for p in params if re.search(r"ptr|buf|buffer|data|mem|addr|p$", p, re.I)]
    kind = str(kind or "").lower()
    if kind in {"allocator", "calloc", "resource_acquire"}:
        size_text = ", ".join(size_params) if size_params else "review size/count parameter"
        size_arg = _first_param_ref(params, size_params) or "review"
        resource_output = _resource_output_ref(name, body, signature)
        return (
            f"{symbol_type} `{name}` allocates/returns an owned resource. "
            f"Params: {param_text}; size/count params: {size_text}; "
            f"resource_output={resource_output}; size_arg={size_arg}; "
            "failure_values=NULL/review. Return: owned pointer/resource on success, failure/null value possible."
        )
    if kind == "reallocator":
        owner_text = pointer_params[0] if pointer_params else "review owner pointer parameter"
        size_text = ", ".join(size_params) if size_params else "review new size parameter"
        owner_arg = _first_param_ref(params, [owner_text]) if owner_text in params else "review"
        size_arg = _first_param_ref(params, size_params) or "review"
        resource_output = _resource_output_ref(name, body, signature)
        return (
            f"{symbol_type} `{name}` resizes an owned resource. "
            f"Owner param: {owner_text}; size param: {size_text}; "
            f"old_resource={owner_arg}; resource_output={resource_output}; size_arg={size_arg}; "
            "failure_values=NULL/review. Return: resized owned resource or failure/null value."
        )
    if kind in {"deallocator", "resource_release"}:
        target = (
            pointer_params[0]
            if pointer_params
            else (params[0] if params else "review released parameter")
        )
        target_arg = _first_param_ref(params, [target]) if target in params else "review"
        return (
            f"{symbol_type} `{name}` releases resource passed by caller. "
            f"resource_input={target_arg}; Released param: {target}."
        )
    if kind == "lock":
        lock_obj = (
            pointer_params[0]
            if pointer_params
            else (params[0] if params else "review lock parameter")
        )
        lock_arg = _first_param_ref(params, [lock_obj]) if lock_obj in params else "review"
        return f"{symbol_type} `{name}` acquires lock object. lock_arg={lock_arg}; Lock param: {lock_obj}."
    if kind == "unlock":
        lock_obj = (
            pointer_params[0]
            if pointer_params
            else (params[0] if params else "review lock parameter")
        )
        lock_arg = _first_param_ref(params, [lock_obj]) if lock_obj in params else "review"
        return f"{symbol_type} `{name}` releases lock object. lock_arg={lock_arg}; Lock param: {lock_obj}."
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


def _first_param_ref(params: Sequence[str], candidates: Sequence[str]) -> str:
    candidate_set = {str(item) for item in candidates if item}
    for idx, param in enumerate(params, start=1):
        if param in candidate_set:
            return f"arg{idx}"
    return ""


def _resource_output_ref(name: str, body: str, signature: str) -> str:
    text = signature or _signature_from_body(name, body)
    macro_text = body.splitlines()[0] if body.lstrip().startswith("#") else ""
    if macro_text:
        text = macro_text
    lowered = str(text or "").lower()
    if re.search(r"\bvoid\s+" + re.escape(name).lower() + r"\s*\(", lowered):
        params = _parameter_names(name, body, signature)
        pointer_like = [
            p for p in params if re.search(r"out|ret|result|obj|handle|ptr|buf|p$", p, re.I)
        ]
        ref = _first_param_ref(params, pointer_like)
        return f"{ref}_deref" if ref else "review"
    return "return"


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
