"""Human-editable XLSX user configuration support."""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import zipfile
import weakref
from functools import wraps
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, ParamSpec, Tuple, TypeVar, cast
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape


SYMBOL_SHEETS = ("resource", "lock")

# Extra documentation sheet written into every workbook.  It is intentionally
# NOT part of SHEET_HEADERS so the reader ignores it while Excel shows it.
README_SHEET_NAME = "README"

RESOURCE_KINDS = frozenset(
    {
        "allocator",
        "calloc",
        "reallocator",
        "deallocator",
        "copy",
        "resource_acquire",
        "resource_release",
        "io_acquire",
        "io_release",
        "send_sink",
        "recv_source",
        "format_sink",
        "callback_register",
        "ownership_transfer",
        "thread_create", "thread_release", "standard_operation",
    }
)
LOCK_KINDS = frozenset({"lock", "unlock", "lock_init", "lock_destroy", "lock_state", "lock_wait", "condition_init", "condition_destroy", "condition_signal"})
VALID_KINDS = RESOURCE_KINDS | LOCK_KINDS

SHEET_HEADERS: Dict[str, List[str]] = {
    "contract_review": ["review_id", "symbol_name", "kind", "symbol_type", "file_path",
                        "signature", "contract", "pair", "status", "source",
                        "source_evidence", "affected_interfaces", "pending_conditions", "minimum_proven",
                        "graph_minimum_proven", "minimum_scope", "notes"],
    "resource": [
        "symbol_name",
        "kind",
        "symbol_type",
        "pair",
        "description",
        "source",
        "confidence",
        "notes",
        "file_path",
        "signature",
        "contract",
        "status",
    ],
    "lock": [
        "symbol_name",
        "kind",
        "symbol_type",
        "pair",
        "description",
        "source",
        "confidence",
        "notes",
        "file_path",
        "signature",
        "contract",
        "status",
    ],
    "dispatcher": [
        "dispatcher_name",
        "file_path",
        "message_type",
        "handler_name",
        "handler_kind",
        "resource",
        "pair",
        "description",
        "source",
        "confidence",
        "notes",
    ],
    "module_lifecycle": [
        "symbol_name",
        "file_path",
        "kind",
        "pair",
        "needs_finit",
        "error_path_cleanup_required",
        "description",
        "source",
        "confidence",
        "notes",
    ],
    "pointer_targets": [
        "pointer_location",
        "scope",
        "target_functions",
        "context",
        "source",
        "notes",
    ],
    "function_intents": [
        "symbol_name",
        "file_path",
        "caller_constraints",
        "concurrency_group",
        "concurrent_with",
        "intents",
    ],
}


_WORKBOOK_LOCKS: weakref.WeakValueDictionary[str, Any] = weakref.WeakValueDictionary()
_WORKBOOK_LOCKS_GUARD = threading.Lock()
_P = ParamSpec("_P")
_T = TypeVar("_T")


def _workbook_lock(path: Path) -> Any:
    key = os.path.normcase(str(path.resolve()))
    with _WORKBOOK_LOCKS_GUARD:
        lock = _WORKBOOK_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _WORKBOOK_LOCKS[key] = lock
        return lock


def _workbook_transaction(method: Callable[_P, _T]) -> Callable[_P, _T]:
    """Serialize a whole read/merge/write transaction across local instances."""
    @wraps(method)
    def serialized(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        workbook = cast("UserConfigWorkbook", args[0])
        with workbook._cache_lock:
            return method(*args, **kwargs)

    return serialized


class UserConfigWorkbook:
    """Read and write the XLSX user configuration workbook."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._cache_lock = _workbook_lock(self.path)
        self._rows_cache_key: Tuple[int, int] = (-2, -2)
        self._rows_cache: Optional[Dict[str, List[Dict[str, str]]]] = None
        self.read_warnings: List[str] = []

    def exists(self) -> bool:
        return self.path.exists()

    @_workbook_transaction
    def read_rows(self) -> Dict[str, List[Dict[str, str]]]:
        cache_key = self._cache_key()
        with self._cache_lock:
            if self._rows_cache is not None and self._rows_cache_key == cache_key:
                return self._clone_rows(self._rows_cache)

        rows: Dict[str, List[Dict[str, str]]] = {name: [] for name in SHEET_HEADERS}
        if self.path.exists():
            rows = _read_xlsx(self.path)
        self.read_warnings = _collect_kind_warnings(rows)

        after_key = self._cache_key()
        with self._cache_lock:
            if after_key == cache_key:
                self._rows_cache_key = after_key
                self._rows_cache = self._clone_rows(rows)
        return self._clone_rows(rows)

    @_workbook_transaction
    def write_rows(self, rows_by_sheet: Dict[str, List[Dict[str, Any]]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        normalized: Dict[str, List[Dict[str, str]]] = {}
        source_rows = _normalize_workbook_shape(rows_by_sheet)
        for sheet, headers in SHEET_HEADERS.items():
            rows = source_rows.get(sheet, [])
            normalized[sheet] = [_normalize_row(row, headers) for row in rows]
        with self._cache_lock:
            if self.path.exists() and self.read_rows() == normalized:
                return
            fd, temporary = tempfile.mkstemp(suffix=".xlsx", dir=self.path.parent)
            os.close(fd)
            try:
                _write_xlsx(Path(temporary), normalized)
                os.replace(temporary, self.path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            self._refresh_cache(normalized)

    @_workbook_transaction
    def merge_generated(
        self,
        generated: Dict[str, List[Dict[str, Any]]],
        *,
        covered_symbols: Optional[Iterable[Tuple[str, str, str]]] = None,
    ) -> Dict[str, int]:
        existing = self.read_rows()
        requested_sheets = set(generated)
        generated = _normalize_workbook_shape(generated)
        merged = {name: list(existing.get(name, [])) for name in SHEET_HEADERS}
        added = 0
        refreshed = 0
        removed = 0
        covered = set(covered_symbols) if covered_symbols is not None else None
        for sheet, rows in generated.items():
            if sheet not in SHEET_HEADERS or sheet not in requested_sheets:
                continue
            key_fields = _key_fields_for_sheet(sheet)
            by_key = {_row_key(row, key_fields): row for row in merged.get(sheet, [])}
            generated_keys = set()
            for row in rows:
                key = _row_key(row, key_fields)
                if not key:
                    continue
                current = by_key.get(key)
                normalized = _normalize_row(row, SHEET_HEADERS[sheet])
                # An unscoped manual declaration overrides inferred scoped rows too.
                if sheet in SYMBOL_SHEETS and any(
                    old.get("symbol_name") == normalized.get("symbol_name")
                    and (
                        not old.get("file_path")
                        or old.get("file_path") == normalized.get("file_path")
                    )
                    and (
                        not old.get("signature")
                        or old.get("signature") == normalized.get("signature")
                    )
                    and not _is_inferred_row(sheet, old)
                    for old in existing.get(sheet, [])
                ):
                    continue
                generated_keys.add(key)
                if current is None:
                    merged.setdefault(sheet, []).append(normalized)
                    by_key[key] = normalized
                    added += 1
                    continue
                can_refresh_existing = _is_inferred_row(sheet, current)
                if can_refresh_existing and current != normalized:
                    current.clear()
                    current.update(normalized)
                    refreshed += 1
            kept_rows = []
            for row in merged.get(sheet, []):
                key = _row_key(row, key_fields)
                identity = tuple(
                    str(row.get(f) or "") for f in ("symbol_name", "file_path", "signature")
                )
                in_scope = covered is None or (sheet in (*SYMBOL_SHEETS, "contract_review") and identity in covered)
                if key and key not in generated_keys and _is_inferred_row(sheet, row) and in_scope:
                    removed += 1
                    continue
                kept_rows.append(row)
            merged[sheet] = kept_rows
        if merged != existing:
            self.write_rows(merged)
        return {"added": added, "refreshed": refreshed, "removed": removed, "stale": removed}


    @_workbook_transaction
    def import_confirmed_reviews(self) -> Dict[str, int]:
        """Materialize confirmed specifications, and retract only review-owned rows."""
        from ..semantics.contracts import ApiContract
        from ..semantics.contract_conditions import predicate_errors

        rows = self.read_rows()
        before = deepcopy(rows)
        for sheet in SYMBOL_SHEETS:
            rows[sheet] = [r for r in rows[sheet]
                           if not str(r.get("source") or "").startswith("user:contract_review:")]
        imported = 0
        for review in rows.get("contract_review", []):
            if str(review.get("status") or "").lower() != "confirmed":
                continue
            contract = ApiContract.from_row(review)
            if contract is None:
                raise ValueError("Confirmed review has an invalid contract: " + str(review.get("review_id")))
            predicates = [contract.preconditions] + [c.get("when") for c in contract.effect_cases]
            if any(predicate_errors(p) for p in predicates) or contract.carrier.kind == "unknown":
                raise ValueError("Confirmed review has invalid conditions or carrier")
            sheet = _sheet_for_kind(contract.role)
            if any(r.get("symbol_name") == contract.symbol.name
                   and not _is_inferred_row(sheet, r) for r in rows[sheet]):
                continue
            raw = contract.to_dict()
            raw.update(source="user:contract_review:" + str(review["review_id"]),
                       status="confirmed", verification={"method": "manual_specification",
                           "review_id": review["review_id"]})
            rows[sheet].append(_normalize_row({
                **review, "source": raw["source"], "contract": raw, "status": "confirmed",
            }, SHEET_HEADERS[sheet]))
            imported += 1
        if rows != before:
            self.write_rows(rows)
        return {"imported": imported}

    def list_external_functions(self) -> List[Dict[str, Any]]:
        items = []
        rows_by_sheet = self.read_rows()
        for sheet in SYMBOL_SHEETS:
            for row in rows_by_sheet.get(sheet, []):
                if _is_active(row) and row.get("symbol_name"):
                    items.append(_workbook_symbol_to_db(row, sheet))
        return sorted(items, key=lambda item: item.get("func_name", ""))

    @_workbook_transaction
    def upsert_external_function(
        self,
        func_name: str,
        description: str,
        library: str = "",
        memory_behavior: Optional[Dict[str, Any]] = None,
        concurrency_behavior: Optional[Dict[str, Any]] = None,
        return_semantics: str = "",
    ) -> None:
        kind = _kind_from_semantics(memory_behavior, concurrency_behavior, return_semantics)
        sheet_name = _sheet_for_kind(kind)
        rows = self.read_rows()
        row = _find_symbol_row(rows, sheet_name, func_name)
        if row is None:
            row = {"symbol_name": func_name, "kind": kind, "symbol_type": "function"}
            rows.setdefault(sheet_name, []).append(row)
        row.update(
            {
                "kind": row.get("kind") or kind,
                "description": description,
                "source": row.get("source") or "user",
                "notes": _merge_notes(row.get("notes", ""), library, return_semantics),
            }
        )
        self.write_rows(rows)

    @_workbook_transaction
    def delete_external_function(self, func_name: str) -> None:
        rows = self.read_rows()
        for sheet in SYMBOL_SHEETS:
            rows[sheet] = [
                row for row in rows.get(sheet, []) if row.get("symbol_name") != func_name
            ]
        self.write_rows(rows)

    def list_paired_functions(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        from ..semantics.contracts import ACQUIRE_ROLES, RELEASE_ROLES, ApiContract

        result: List[Dict[str, Any]] = []
        next_id = 1
        rows_by_sheet = self.read_rows()
        for sheet in SYMBOL_SHEETS:
            for row in rows_by_sheet.get(sheet, []):
                if not _is_active(row):
                    continue
                contract = ApiContract.from_row(row)
                if contract is None or contract.role not in ACQUIRE_ROLES | RELEASE_ROLES:
                    continue
                pair_category = (
                    "lock"
                    if sheet == "lock"
                    else ("io" if contract.role.startswith("io_") else "memory")
                )
                if category and category not in {pair_category, sheet}:
                    continue
                for target in contract.pairs:
                    acquire, release = (
                        (contract.symbol, target)
                        if contract.role in ACQUIRE_ROLES
                        else (target, contract.symbol)
                    )
                    result.append(
                        {
                            "id": next_id,
                            "category": pair_category,
                            "acquire_func": acquire.name,
                            "release_func": release.name,
                            "acquire_file_path": acquire.file_path,
                            "release_file_path": release.file_path,
                            "acquire_signature": acquire.signature,
                            "release_signature": release.signature,
                            "acquire_symbol_type": acquire.symbol_type,
                            "release_symbol_type": release.symbol_type,
                            "conditions": [] if contract.effect_cases else contract.conditions,
                            "source": contract.source,
                            "evidence": contract.pair_evidence or contract.evidence,
                            "confidence": contract.confidence,
                            "description": row.get("description", ""),
                        }
                    )
                    next_id += 1
        return result

    @_workbook_transaction
    def upsert_paired_function(
        self,
        category: str,
        acquire_func: str,
        release_func: str,
        description: str = "",
    ) -> None:
        sheet_name = _sheet_for_pair_category(category)
        rows = self.read_rows()
        acquire_row = _find_symbol_row(rows, sheet_name, acquire_func)
        if acquire_row is None:
            acquire_row = {
                "symbol_name": acquire_func,
                "kind": _acquire_kind_for_category(category),
                "symbol_type": "function",
                "source": "user",
            }
            rows.setdefault(sheet_name, []).append(acquire_row)
        acquire_row["pair"] = _merge_csv(acquire_row.get("pair", ""), release_func)
        acquire_row["description"] = acquire_row.get("description") or description
        acquire_row["source"] = acquire_row.get("source") or "user"

        release_row = _find_symbol_row(rows, sheet_name, release_func)
        if release_row is None:
            rows.setdefault(sheet_name, []).append(
                {
                    "symbol_name": release_func,
                    "kind": _release_kind_for_category(category),
                    "symbol_type": "function",
                    "description": "",
                    "source": "user",
                }
            )
        self.write_rows(rows)

    @_workbook_transaction
    def delete_paired_function(self, row_id: int) -> None:
        rows = self.read_rows()
        current = 1
        for sheet in SYMBOL_SHEETS:
            for row in rows.get(sheet, []):
                if not _is_active(row):
                    continue
                pairs = _split_csv(row.get("pair", ""))
                for release in list(pairs):
                    if current == row_id:
                        row["pair"] = ", ".join(item for item in pairs if item != release)
                        self.write_rows(rows)
                        return
                    current += 1

    def list_pointer_targets(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for row in self.read_rows().get("pointer_targets", []):
            if not _is_active(row):
                continue
            rows.append(
                {
                    "id": len(rows) + 1,
                    "pointer_location": row.get("pointer_location", ""),
                    "scope": row.get("scope", "*") or "*",
                    "target_functions": row.get("target_functions", "[]") or "[]",
                    "context": row.get("context", ""),
                }
            )
        return rows

    @_workbook_transaction
    def upsert_pointer_target(
        self,
        pointer_location: str,
        scope: str,
        target_functions: List[str],
        context: str = "",
    ) -> None:
        rows = self.read_rows()
        sheet = rows.setdefault("pointer_targets", [])
        row = next(
            (
                item
                for item in sheet
                if item.get("pointer_location") == pointer_location
                and item.get("scope", "*") == scope
            ),
            None,
        )
        if row is None:
            row = {"pointer_location": pointer_location, "scope": scope or "*"}
            sheet.append(row)
        row.update(
            {
                "scope": scope or "*",
                "target_functions": json.dumps(target_functions, ensure_ascii=False),
                "context": context,
                "source": row.get("source") or "user",
                "notes": row.get("notes", ""),
            }
        )
        self.write_rows(rows)

    @_workbook_transaction
    def delete_pointer_target(self, row_id: int) -> None:
        rows = self.read_rows()
        kept = []
        next_id = 1
        deleted = False
        for row in rows.get("pointer_targets", []):
            if _is_active(row):
                if next_id == row_id:
                    deleted = True
                    next_id += 1
                    continue
                next_id += 1
            kept.append(row)
        if deleted:
            rows["pointer_targets"] = kept
            self.write_rows(rows)

    def list_dispatchers(self) -> List[Dict[str, Any]]:
        return [dict(row) for row in self.read_rows().get("dispatcher", []) if _is_active(row)]

    def list_module_lifecycle(self) -> List[Dict[str, Any]]:
        return [
            dict(row) for row in self.read_rows().get("module_lifecycle", []) if _is_active(row)
        ]

    def get_function_intent(
        self, func_name: str, file_path: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        for row in self.read_rows().get("function_intents", []):
            if not _is_active(row) or row.get("symbol_name") != func_name:
                continue
            if file_path and row.get("file_path", "") != file_path:
                continue
            return _intent_row_to_db(row)
        return None

    def list_function_intents(self) -> List[Dict[str, Any]]:
        return [
            _intent_row_to_db(row)
            for row in self.read_rows().get("function_intents", [])
            if _is_active(row)
        ]

    @_workbook_transaction
    def upsert_function_intent(
        self,
        func_name: str,
        file_path: str = "",
        caller_constraints: Optional[Dict[str, Any]] = None,
        concurrency_group: str = "",
        concurrent_with: Optional[List[str]] = None,
        notes: str = "",
    ) -> None:
        rows = self.read_rows()
        sheet = rows.setdefault("function_intents", [])
        row = next(
            (
                item
                for item in sheet
                if item.get("symbol_name") == func_name and item.get("file_path", "") == file_path
            ),
            None,
        )
        if row is None:
            row = {"symbol_name": func_name, "file_path": file_path}
            sheet.append(row)
        row.update(
            {
                "caller_constraints": json.dumps(caller_constraints or {}, ensure_ascii=False),
                "concurrency_group": concurrency_group,
                "concurrent_with": json.dumps(concurrent_with or [], ensure_ascii=False),
                "intents": _intent_text(
                    caller_constraints, concurrency_group, concurrent_with, notes
                ),
            }
        )
        self.write_rows(rows)

    @_workbook_transaction
    def delete_function_intent(self, func_name: str, file_path: str = "") -> None:
        rows = self.read_rows()
        rows["function_intents"] = [
            row
            for row in rows.get("function_intents", [])
            if not (row.get("symbol_name") == func_name and row.get("file_path", "") == file_path)
        ]
        self.write_rows(rows)

    def _cache_key(self) -> Tuple[int, int]:
        try:
            stat = self.path.stat()
        except OSError:
            return (-1, -1)
        return (int(stat.st_mtime_ns), int(stat.st_size))

    def _refresh_cache(self, rows: Dict[str, List[Dict[str, str]]]) -> None:
        with self._cache_lock:
            self._rows_cache_key = self._cache_key()
            self._rows_cache = self._clone_rows(rows)

    @staticmethod
    def _clone_rows(rows: Dict[str, List[Dict[str, str]]]) -> Dict[str, List[Dict[str, str]]]:
        return deepcopy(rows)


def _normalize_workbook_shape(
    rows_by_sheet: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, List[Dict[str, Any]]]:
    normalized = {name: list(rows_by_sheet.get(name, [])) for name in SHEET_HEADERS}
    return _collapse_symbol_rows(normalized)


def _collapse_symbol_rows(
    rows_by_sheet: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, List[Dict[str, Any]]]:
    for sheet in SYMBOL_SHEETS:
        by_name: Dict[Tuple[str, ...], Dict[str, Any]] = {}
        for row in rows_by_sheet.get(sheet, []):
            name = str(row.get("symbol_name") or "").strip()
            if not name:
                continue
            row_key = _row_key(row, _key_fields_for_sheet(sheet))
            current = by_name.get(row_key)
            if current is None:
                by_name[row_key] = dict(row)
                continue
            for key, value in row.items():
                if key == "pair":
                    current[key] = _merge_csv(current.get(key, ""), value)
                elif value and not current.get(key):
                    current[key] = value
        rows_by_sheet[sheet] = list(by_name.values())
    return rows_by_sheet


def _normalize_row(row: Dict[str, Any], headers: Iterable[str]) -> Dict[str, str]:
    return {header: _cell_text(row.get(header, "")) for header in headers}


def _workbook_symbol_to_db(row: Dict[str, str], sheet: str) -> Dict[str, Any]:
    kind = row.get("kind", "")
    return {
        **dict(row),
        "func_name": row.get("symbol_name", ""),
        "symbol_name": row.get("symbol_name", ""),
        "kind": kind,
        "symbol_type": row.get("symbol_type", ""),
        "library": "",
        "description": row.get("description", ""),
        "memory_behavior": json.dumps(_memory_behavior_for_kind(kind, sheet), ensure_ascii=False),
        "concurrency_behavior": json.dumps(
            _concurrency_behavior_for_kind(kind, sheet), ensure_ascii=False
        ),
        "return_semantics": _return_semantics_for_kind(kind),
    }


def _intent_row_to_db(row: Dict[str, str]) -> Dict[str, Any]:
    item = dict(row)
    item["func_name"] = item.get("symbol_name", "")
    item.setdefault("notes", item.get("intents", ""))
    item.setdefault("caller_constraints", "{}")
    item.setdefault("concurrency_group", "")
    item.setdefault("concurrent_with", "[]")
    return item


def _cell_text(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value or "").strip()


def _is_active(row: Dict[str, str]) -> bool:
    return str(row.get("status") or "active").strip().lower() in {"active", "valid", "confirmed"}


def _is_inferred_row(sheet: str, row: Dict[str, str]) -> bool:
    if sheet == "contract_review" and row.get("status") in {"confirmed", "rejected"}:
        return False
    if str(row.get("source", "")).startswith("inferred"):
        return True
    if sheet == "function_intents":
        return str(row.get("intents", "")).lstrip().startswith("[inferred:")
    return False


def _key_fields_for_sheet(sheet: str) -> Tuple[str, ...]:
    if sheet == "contract_review":
        return ("review_id",)
    if sheet in SYMBOL_SHEETS:
        return ("symbol_name", "file_path", "signature", "kind", "contract")
    if sheet == "dispatcher":
        return ("dispatcher_name", "file_path", "message_type", "handler_name")
    if sheet == "module_lifecycle":
        return ("symbol_name", "file_path")
    if sheet == "pointer_targets":
        return ("pointer_location", "scope")
    if sheet == "function_intents":
        return ("symbol_name", "file_path")
    return ("name",)


def _row_key(row: Dict[str, Any], fields: Iterable[str]) -> Tuple[str, ...]:

    def field_value(field: str) -> str:
        value = row.get(field, "")
        if field == "contract" and value:
            try:
                parsed = json.loads(value) if isinstance(value, str) else value
                if isinstance(parsed, dict):
                    return json.dumps(
                        {key: parsed.get(key) for key in ("carrier", "conditions")}, sort_keys=True
                    )
            except (ValueError, TypeError):
                pass
        return str(value or "").strip()

    values = tuple(field_value(field) for field in fields)
    return values if any(values) else tuple()


def _find_symbol_row(
    rows: Dict[str, List[Dict[str, str]]], sheet: str, symbol_name: str
) -> Optional[Dict[str, str]]:
    return next(
        (row for row in rows.setdefault(sheet, []) if row.get("symbol_name") == symbol_name),
        None,
    )


def _sheet_for_kind(kind: str) -> str:
    text = str(kind or "").lower()
    if text in LOCK_KINDS:
        return "lock"
    return "resource"


def _sheet_for_pair_category(category: str) -> str:
    text = str(category or "").lower()
    if any(word in text for word in ("lock", "mutex", "rwlock", "spin")):
        return "lock"
    return "resource"


def _acquire_kind_for_sheet(sheet: str) -> str:
    return {"resource": "allocator", "lock": "lock"}.get(sheet, "allocator")


def _release_kind_for_sheet(sheet: str) -> str:
    return {"resource": "deallocator", "lock": "unlock"}.get(sheet, "deallocator")


def _acquire_kind_for_category(category: str) -> str:
    text = str(category or "").lower()
    if _sheet_for_pair_category(text) == "lock":
        return "lock"
    if any(word in text for word in ("file", "fd", "socket", "io", "handle", "描述符", "句柄", "文件", "套接字")):
        return "io_acquire"
    return "allocator"


def _release_kind_for_category(category: str) -> str:
    text = str(category or "").lower()
    if _sheet_for_pair_category(text) == "lock":
        return "unlock"
    if any(word in text for word in ("file", "fd", "socket", "io", "handle", "描述符", "句柄", "文件", "套接字")):
        return "io_release"
    return "deallocator"


def _kind_from_semantics(
    memory_behavior: Optional[Dict[str, Any]],
    concurrency_behavior: Optional[Dict[str, Any]],
    return_semantics: str,
) -> str:
    memory = memory_behavior or {}
    concurrency = concurrency_behavior or {}
    text = " ".join(
        [
            json.dumps(memory, ensure_ascii=False),
            json.dumps(concurrency, ensure_ascii=False),
            return_semantics or "",
        ]
    ).lower()
    if memory.get("reallocates") or "realloc" in text:
        return "reallocator"
    if memory.get("allocates") or "allocate" in text or "alloc" in text:
        return "allocator"
    if memory.get("releases") or "free" in text or "release memory" in text:
        return "deallocator"
    if concurrency.get("acquires_lock"):
        return "lock"
    if concurrency.get("releases_lock"):
        return "unlock"
    return "resource"


def _memory_behavior_for_kind(kind: str, sheet: str) -> Dict[str, Any]:
    kind = str(kind or "").lower()
    if sheet == "resource" and kind in {"allocator", "calloc", "resource_acquire", "resource"}:
        return {"allocates": True, "caller_owns_return": True}
    if kind == "reallocator":
        return {"reallocates": True, "caller_owns_return": True}
    if kind in {"deallocator", "resource_release"}:
        return {"releases": True}
    if kind == "copy":
        return {"copies_memory": True}
    return {}


def _concurrency_behavior_for_kind(kind: str, sheet: str) -> Dict[str, Any]:
    kind = str(kind or "").lower()
    if sheet == "lock" and kind == "lock":
        return {"acquires_lock": True}
    if sheet == "lock" and kind == "unlock":
        return {"releases_lock": True}
    return {}


def _return_semantics_for_kind(kind: str) -> str:
    kind = str(kind or "").lower()
    if kind in {"allocator", "calloc", "resource_acquire", "resource"}:
        return "returns acquired resource or failure/null value"
    if kind == "reallocator":
        return "returns resized resource or failure/null value"
    if kind in {"deallocator", "resource_release"}:
        return "releases resource passed by caller"
    return ""


def _split_csv(value: Any) -> List[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _merge_csv(existing: Any, incoming: Any) -> str:
    if (
        isinstance(existing, list)
        or isinstance(incoming, list)
        or any(str(value).lstrip().startswith("[") for value in (existing, incoming))
    ):
        from dataclasses import asdict
        from ..semantics.contracts import parse_pair_targets

        targets = list(dict.fromkeys(parse_pair_targets(existing) + parse_pair_targets(incoming)))
        return json.dumps(
            [asdict(target) for target in targets], ensure_ascii=False, sort_keys=True
        )
    values = []
    seen = set()
    for item in _split_csv(existing) + _split_csv(incoming):
        if item not in seen:
            values.append(item)
            seen.add(item)
    return ", ".join(values)


def _merge_notes(existing: str, library: str, return_semantics: str) -> str:
    extras = []
    if library:
        extras.append(f"library={library}")
    if return_semantics:
        extras.append(f"return={return_semantics}")
    return _merge_csv(existing, "; ".join(extras))


def _intent_text(
    caller_constraints: Optional[Dict[str, Any]],
    concurrency_group: str,
    concurrent_with: Optional[List[str]],
    notes: str,
) -> str:
    parts = []
    if caller_constraints:
        parts.append(f"caller_constraints={json.dumps(caller_constraints, ensure_ascii=False)}")
    if concurrency_group:
        parts.append(f"concurrency_group={concurrency_group}")
    if concurrent_with:
        parts.append(f"concurrent_with={', '.join(concurrent_with)}")
    if notes:
        parts.append(notes)
    return "; ".join(parts)


def _col_letter(index: int) -> str:
    result = ""
    while index:
        index, rem = divmod(index - 1, 26)
        result = chr(65 + rem) + result
    return result


def _collect_kind_warnings(rows: Dict[str, List[Dict[str, str]]]) -> List[str]:
    """Report symbol rows whose kind is outside the documented enum."""

    warnings: List[str] = []
    for sheet in SYMBOL_SHEETS:
        for row in rows.get(sheet, []):
            kind = str(row.get("kind") or "").strip().lower()
            if kind and kind not in VALID_KINDS:
                warnings.append(
                    f"{sheet}:{row.get('symbol_name', '')} unknown kind '{kind}' "
                    f"(valid: {', '.join(sorted(VALID_KINDS))})"
                )
    return warnings


def _write_xlsx(path: Path, rows_by_sheet: Dict[str, List[Dict[str, str]]]) -> None:
    sheet_names = list(SHEET_HEADERS) + [README_SHEET_NAME]
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _content_types(sheet_names))
        zf.writestr("_rels/.rels", _root_rels())
        zf.writestr("xl/workbook.xml", _workbook_xml(sheet_names))
        zf.writestr("xl/_rels/workbook.xml.rels", _workbook_rels(sheet_names))
        zf.writestr("xl/styles.xml", _styles_xml())
        for idx, name in enumerate(sheet_names, start=1):
            if name == README_SHEET_NAME:
                xml = _readme_worksheet_xml()
            else:
                xml = _worksheet_xml(name, rows_by_sheet.get(name, []))
            zf.writestr(f"xl/worksheets/sheet{idx}.xml", xml)


def _worksheet_xml(sheet: str, rows: List[Dict[str, str]]) -> str:
    headers = SHEET_HEADERS[sheet]
    all_rows = [dict(zip(headers, headers))] + rows
    xml_rows = []
    for row_idx, row in enumerate(all_rows, start=1):
        cells = []
        for col_idx, header in enumerate(headers, start=1):
            ref = f"{_col_letter(col_idx)}{row_idx}"
            value = escape(str(row.get(header, "")))
            style = ' s="1"' if row_idx == 1 else ""
            cells.append(f'<c r="{ref}"{style} t="inlineStr"><is><t>{value}</t></is></c>')
        xml_rows.append(f'<row r="{row_idx}">{"".join(cells)}</row>')
    max_col = _col_letter(len(headers))
    col_widths = "".join(
        f'<col min="{idx}" max="{idx}" width="{_column_width(header)}" customWidth="1"/>'
        for idx, header in enumerate(headers, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        "</sheetView></sheetViews>"
        f'<dimension ref="A1:{max_col}{len(all_rows)}"/>'
        f"<cols>{col_widths}</cols>"
        f"<sheetData>{''.join(xml_rows)}</sheetData>"
        "</worksheet>"
    )


def _column_width(header: str) -> int:
    if header in {"description", "notes"}:
        return 52
    if header in {"symbol_name", "pair", "dispatcher_name", "handler_name", "pointer_location",
                  "target_functions", "file_path"}:
        return 30
    return 16


README_LINES = (
    "Z-Scope user_config 工作簿说明 / User Config Workbook Guide",
    "",
    "1. 本工作簿由 Z-SCOPE 读取,是规则层的用户自定义风险接口配置。Z-SCOPE reads this workbook as the rule-facing user-defined risk interface configuration.",
    "2. 只编辑数据行;不要修改表头名称、列顺序或本 README 表。Edit data rows only; never rename headers or reorder columns.",
    "3. resource 表 kind 枚举: " + ", ".join(sorted(RESOURCE_KINDS)),
    "4. lock 表 kind 枚举: " + ", ".join(sorted(LOCK_KINDS)),
    "5. pair 列填逗号分隔的互补接口名(allocator 的 pair 是 deallocator;io_acquire 的 pair 是 io_release;lock 的 pair 是 unlock)。",
    "6. contract 使用 JSON: carrier.kind=return|argument|output_argument|global, argument_index 从 0 开始;member_path/global_name 标识成员或全局载体,conditions 表达适用条件。description/notes 只作说明,不推断角色。",
    "7. source 列约定: 人工角色/配对优先;inferred:* 由普通扫描或 --infer-user-config 生成,仅刷新本轮覆盖范围。失败或过期的 status 不参与规则。",
    "8. confidence 为 0~1;低于 0.75 或 notes 含 llm:conflict 的行请优先人工确认。",
    "9. kind 拼写错误的行会被忽略并在推理报告中记录告警,请按第 3/4 条修正。",
    "10. --infer-user-config 会在同目录生成 user_config.infer_report.md,含全部推理行、低置信度清单与统计。",
    "11. 所有 C/C++ 档位在规则前增量并发建模,写入并重读本工作簿后生效;file_path/signature 用于消歧,pair 可用结构化 JSON 数组。怀疑点不写本工作簿,仅作为 Validator 背景,不产生独立候选。",
    "12. contract_review 仅列不能静态证明的根协议;核对 contract/source_evidence/pending_conditions 后将 status 改为 confirmed 才会导入。pending/rejected 不生效,撤销确认会移除对应导入行。",
    "13. affected_interfaces 是已核验组合关系可影响的接口;确认根契约不证明某次调用成功,也不授权独立的不透明释放端。",
)


def _readme_worksheet_xml() -> str:
    xml_rows = []
    for row_idx, line in enumerate(README_LINES, start=1):
        value = escape(line)
        xml_rows.append(
            f'<row r="{row_idx}"><c r="A{row_idx}" t="inlineStr"><is><t>{value}</t></is></c></row>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<dimension ref="A1:A%d"/>' % max(len(README_LINES), 1)
        + '<cols><col min="1" max="1" width="120" customWidth="1"/></cols>'
        f"<sheetData>{''.join(xml_rows)}</sheetData>"
        "</worksheet>"
    )


def _read_xlsx(path: Path) -> Dict[str, List[Dict[str, str]]]:
    rows_by_sheet: Dict[str, List[Dict[str, str]]] = {name: [] for name in SHEET_HEADERS}
    with zipfile.ZipFile(path) as zf:
        shared = _read_shared_strings(zf)
        workbook = ET.fromstring(zf.read("xl/workbook.xml"))
        rels = _read_workbook_rels(zf)
        ns = {
            "m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
            "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        }
        for sheet_el in workbook.findall(".//m:sheet", ns):
            name = sheet_el.attrib.get("name", "")
            if name not in SHEET_HEADERS:
                continue
            rel_id = sheet_el.attrib.get(f"{{{ns['r']}}}id", "")
            target = rels.get(rel_id)
            if not target:
                continue
            target_path = target.lstrip("/")
            sheet_path = target_path if target_path.startswith("xl/") else "xl/" + target_path
            if sheet_path not in zf.namelist():
                continue
            matrix = _read_sheet_matrix(zf.read(sheet_path), shared)
            if not matrix:
                continue
            headers = [item.strip() for item in matrix[0]]
            parsed_rows = []
            for values in matrix[1:]:
                row = {
                    headers[idx]: values[idx] if idx < len(values) else ""
                    for idx in range(len(headers))
                }
                if any(str(value).strip() for value in row.values()):
                    parsed_rows.append(row)
            rows_by_sheet[name].extend(parsed_rows)
    return rows_by_sheet


def _read_sheet_matrix(xml_bytes: bytes, shared: List[str]) -> List[List[str]]:
    root = ET.fromstring(xml_bytes)
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    matrix: List[List[str]] = []
    for row_el in root.findall(".//m:row", ns):
        values: Dict[int, str] = {}
        for cell in row_el.findall("m:c", ns):
            ref = cell.attrib.get("r", "")
            col_idx = _column_index(ref)
            cell_type = cell.attrib.get("t", "")
            text = ""
            if cell_type == "inlineStr":
                text = "".join(t.text or "" for t in cell.findall(".//m:t", ns))
            else:
                value_el = cell.find("m:v", ns)
                raw = str(value_el.text or "") if value_el is not None else ""
                if cell_type == "s" and raw.isdigit():
                    text = shared[int(raw)] if int(raw) < len(shared) else ""
                else:
                    text = raw or ""
            values[col_idx] = text
        if values:
            max_idx = max(values)
            matrix.append([values.get(idx, "") for idx in range(1, max_idx + 1)])
    return matrix


def _column_index(ref: str) -> int:
    letters = re.sub(r"[^A-Z]", "", ref.upper())
    value = 0
    for ch in letters:
        value = value * 26 + (ord(ch) - 64)
    return value or 1


def _read_shared_strings(zf: zipfile.ZipFile) -> List[str]:
    if "xl/sharedStrings.xml" not in zf.namelist():
        return []
    root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    return [
        "".join(t.text or "" for t in si.findall(".//m:t", ns)) for si in root.findall("m:si", ns)
    ]


def _read_workbook_rels(zf: zipfile.ZipFile) -> Dict[str, str]:
    root = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
    ns = {"r": "http://schemas.openxmlformats.org/package/2006/relationships"}
    return {
        rel.attrib.get("Id", ""): rel.attrib.get("Target", "")
        for rel in root.findall("r:Relationship", ns)
    }


def _content_types(sheet_names: List[str]) -> str:
    sheets = "".join(
        f'<Override PartName="/xl/worksheets/sheet{idx}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for idx, _ in enumerate(sheet_names, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        f"{sheets}</Types>"
    )


def _root_rels() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        "</Relationships>"
    )


def _workbook_xml(sheet_names: List[str]) -> str:
    sheets = "".join(
        f'<sheet name="{escape(name)}" sheetId="{idx}" r:id="rId{idx}"/>'
        for idx, name in enumerate(sheet_names, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{sheets}</sheets></workbook>"
    )


def _workbook_rels(sheet_names: List[str]) -> str:
    rels = "".join(
        f'<Relationship Id="rId{idx}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{idx}.xml"/>'
        for idx, _ in enumerate(sheet_names, start=1)
    )
    rels += (
        f'<Relationship Id="rId{len(sheet_names) + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f"{rels}</Relationships>"
    )


def _styles_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2">'
        '<font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><color rgb="FF1F1F1F"/><name val="Calibri"/></font>'
        "</fonts>"
        '<fills count="3">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FFD9E1F2"/>'
        '<bgColor indexed="64"/></patternFill></fill>'
        "</fills>"
        '<borders count="1"><border/></borders>'
        '<cellStyleXfs count="1"><xf/></cellStyleXfs>'
        '<cellXfs count="2">'
        '<xf xfId="0"/>'
        '<xf xfId="0" fontId="1" fillId="2" applyFont="1" applyFill="1"/>'
        "</cellXfs>"
        "</styleSheet>"
    )
