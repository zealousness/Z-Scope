"""Revision-bound symbol identities shared by the six LLM-facing tools."""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SYMBOL_KINDS = {"function", "method", "macro", "type", "global", "external"}
SEARCHABLE_KINDS = ("function", "method", "macro", "type", "global")
SYMBOL_ID_PATTERN = r"^zs1:(?:function|method|macro|type|global|external):[0-9a-f]{24}$"


def valid_symbol_id(value: Any) -> bool:
    return bool(re.fullmatch(SYMBOL_ID_PATTERN, str(value or "")))


LITERAL_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "kind": {
            "type": "string",
            "enum": ["boolean", "string", "character", "integer", "floating"],
        },
        "raw": {"type": "string"},
        "normalized_value": {"type": "string"},
    },
    "required": ["kind", "raw", "normalized_value"],
    "additionalProperties": False,
}

MACRO_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "form": {"type": "string", "enum": ["function_like", "object_like"]},
        "definition": {"type": "string"},
        "definition_truncated": {"type": "boolean"},
        "replacement_text": {"type": "string"},
        "literal": {"anyOf": [LITERAL_SCHEMA, {"type": "null"}]},
    },
    "required": [
        "form",
        "definition",
        "definition_truncated",
        "replacement_text",
        "literal",
    ],
    "additionalProperties": False,
}

SYMBOL_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "symbol_id": {"type": "string", "pattern": SYMBOL_ID_PATTERN},
        "kind": {"type": "string", "enum": sorted(SYMBOL_KINDS)},
        "name": {"type": "string"},
        "qualified_name": {"type": "string"},
        "signature": {"type": ["string", "null"]},
        "location": {
            "type": "object",
            "properties": {
                "file": {"type": ["string", "null"]},
                "start_line": {"type": ["integer", "null"], "minimum": 1},
                "end_line": {"type": ["integer", "null"], "minimum": 1},
            },
            "required": ["file", "start_line", "end_line"],
            "additionalProperties": False,
        },
        "origin": {"type": "string"},
        "macro": MACRO_SCHEMA,
    },
    "required": [
        "symbol_id",
        "kind",
        "name",
        "qualified_name",
        "signature",
        "location",
        "origin",
    ],
    "additionalProperties": False,
}

SYMBOL_REF_SCHEMA: Dict[str, Any] = {
    **SYMBOL_SCHEMA,
    "properties": {
        **SYMBOL_SCHEMA["properties"],
        "symbol_id": {"type": ["string", "null"], "pattern": SYMBOL_ID_PATTERN},
    },
}


def normalize_project_path(value: Any) -> str:
    return str(value or "").replace("\\", "/").removeprefix("./")


def _positive_line(value: Any, fallback: int = 0) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = fallback
    return parsed if parsed > 0 else max(0, fallback)


def project_relative_path_error(value: Any) -> str:
    """Return a stable validation error for paths that escape the project scope."""
    raw = str(value or "")
    normalized = raw.replace("\\", "/")
    if not normalized:
        return "path must be non-empty"
    if re.search(r"[\x00-\x1f\x7f]", normalized):
        return "path must not contain control characters"
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        return "path must be project-root relative"
    if ".." in PurePosixPath(normalized).parts:
        return "path must not contain '..' segments"
    return ""


def symbol_id_for(record: Dict[str, Any]) -> str:
    kind = str(record.get("kind") or "external")
    canonical = "\x1f".join(
        (
            kind,
            str(record.get("qualified_name") or record.get("name") or ""),
            normalize_project_path(record.get("file")),
            str(int(record.get("start_line") or 0)),
            str(int(record.get("end_line") or record.get("start_line") or 0)),
            str(record.get("signature") or ""),
        )
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
    return f"zs1:{kind}:{digest}"


def _balanced_outer_parentheses(value: str) -> bool:
    if len(value) < 2 or value[0] != "(" or value[-1] != ")":
        return False
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quote:
            if char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and index != len(value) - 1:
                return False
            if depth < 0:
                return False
    return depth == 0 and not quote


def classify_direct_literal(replacement: str) -> Optional[Dict[str, str]]:
    """Classify a direct literal without evaluating expressions or other macros."""
    raw = str(replacement or "").strip()
    value = raw
    while _balanced_outer_parentheses(value):
        value = value[1:-1].strip()
    if value in {"true", "false", "TRUE", "FALSE"}:
        return {"kind": "boolean", "raw": raw, "normalized_value": value.lower()}
    if re.fullmatch(r'(?:u8|u|U|L)?"(?:\\.|[^"\\])*"', value, re.S):
        return {"kind": "string", "raw": raw, "normalized_value": value}
    if re.fullmatch(r"(?:u8|u|U|L)?'(?:\\.|[^'\\])+'", value, re.S):
        return {"kind": "character", "raw": raw, "normalized_value": value}

    integer = re.fullmatch(
        r"(?P<sign>[+-]?)(?P<body>(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|0[0-7]*|[1-9][0-9]*))"
        r"(?P<suffix>(?:[uU](?:ll|LL|l|L)?|(?:ll|LL|l|L)[uU]?))?",
        value,
    )
    if integer:
        body = integer.group("body")
        sign = -1 if integer.group("sign") == "-" else 1
        if body.lower().startswith("0x"):
            parsed = int(body[2:], 16)
        elif body.lower().startswith("0b"):
            parsed = int(body[2:], 2)
        elif len(body) > 1 and body.startswith("0"):
            parsed = int(body, 8)
        else:
            parsed = int(body, 10)
        return {
            "kind": "integer",
            "raw": raw,
            "normalized_value": str(sign * parsed),
        }

    floating = re.fullmatch(
        r"[+-]?(?:(?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?|\d+[eE][+-]?\d+)[fFlL]?",
        value,
    )
    if floating:
        normalized = re.sub(r"[fFlL]$", "", value)
        return {"kind": "floating", "raw": raw, "normalized_value": normalized}
    return None


def macro_metadata(name: str, definition: str, is_function_like: bool) -> Dict[str, Any]:
    raw = str(definition or "")
    logical = re.sub(r"\\\r?\n", "", raw).strip()
    match = re.match(rf"^\s*#\s*define\s+{re.escape(name)}(?P<tail>.*)$", logical, re.S)
    tail = str(match.group("tail") if match else "")
    replacement = tail
    if is_function_like and tail.startswith("("):
        depth = 0
        body_start = len(tail)
        for index, char in enumerate(tail):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    body_start = index + 1
                    break
        replacement = tail[body_start:]
    replacement = replacement.strip()
    return {
        "form": "function_like" if is_function_like else "object_like",
        "definition": raw[:2000],
        "definition_truncated": len(raw) > 2000,
        "replacement_text": replacement[:2000],
        "literal": None if is_function_like else classify_direct_literal(replacement),
    }


@dataclass(frozen=True)
class SymbolSnapshot:
    epoch: int
    records: Tuple[Dict[str, Any], ...]
    by_id: Dict[str, Dict[str, Any]]
    providers: Tuple[str, ...]


class SymbolCatalog:
    """Build and resolve deterministic symbol IDs for the current index revision."""

    def __init__(self, code_index: Any, user_config: Any = None) -> None:
        self.code_index = code_index
        self.user_config = user_config
        self._lock = threading.RLock()
        self._snapshot: Optional[SymbolSnapshot] = None

    @property
    def epoch(self) -> int:
        return int(getattr(self.code_index, "_index_epoch", 0) or 0)

    def snapshot(self) -> SymbolSnapshot:
        epoch = self.epoch
        with self._lock:
            if self._snapshot is not None and self._snapshot.epoch == epoch:
                return self._snapshot
            records, providers = self._collect_records()
            ordered = sorted(
                records,
                key=lambda item: (
                    str(item.get("kind") or ""),
                    str(item.get("qualified_name") or ""),
                    str(item.get("file") or ""),
                    int(item.get("start_line") or 0),
                    str(item.get("signature") or ""),
                ),
            )
            by_id: Dict[str, Dict[str, Any]] = {}
            for record in ordered:
                identifier = symbol_id_for(record)
                if identifier in by_id and by_id[identifier] != record:
                    raise RuntimeError(f"symbol_id collision: {identifier}")
                record["symbol_id"] = identifier
                by_id[identifier] = record
            self._snapshot = SymbolSnapshot(
                epoch=epoch,
                records=tuple(ordered),
                by_id=by_id,
                providers=tuple(sorted(providers)),
            )
            return self._snapshot

    def resolve(self, identifier: str) -> Optional[Dict[str, Any]]:
        record = self.snapshot().by_id.get(str(identifier or ""))
        return dict(record) if record else None

    def search(
        self,
        query: str,
        kinds: Sequence[str],
        match_mode: str,
        path_prefix: Optional[str],
    ) -> List[Dict[str, Any]]:
        pattern = re.compile(query) if match_mode == "regex" else None
        normalized_prefix = normalize_project_path(path_prefix).rstrip("/")
        requested = set(kinds or SEARCHABLE_KINDS)
        result: List[Tuple[int, Dict[str, Any]]] = []
        for record in self.snapshot().records:
            kind = str(record.get("kind") or "")
            if kind == "external":
                if "function" not in requested and "method" not in requested:
                    continue
            elif kind not in requested:
                continue
            file_path = normalize_project_path(record.get("file"))
            if normalized_prefix and not (
                file_path == normalized_prefix or file_path.startswith(normalized_prefix + "/")
            ):
                continue
            fields = tuple(
                field[:4096]
                for field in (
                    str(record.get("name") or ""),
                    str(record.get("qualified_name") or ""),
                    str(record.get("signature") or ""),
                )
            )
            score = self._match_score(query, fields, match_mode, pattern)
            if score is not None:
                result.append((score, record))
        kind_order = {kind: index for index, kind in enumerate(SEARCHABLE_KINDS)}
        result.sort(
            key=lambda item: (
                item[0],
                kind_order.get(str(item[1].get("kind")), 99),
                str(item[1].get("qualified_name") or ""),
                str(item[1].get("file") or ""),
                int(item[1].get("start_line") or 0),
                str(item[1].get("symbol_id") or ""),
            )
        )
        return [dict(record) for _, record in result]

    @staticmethod
    def _match_score(
        query: str,
        fields: Iterable[str],
        match_mode: str,
        pattern: Optional[re.Pattern[str]],
    ) -> Optional[int]:
        best: Optional[int] = None
        for field in fields:
            if match_mode == "exact" and field == query:
                candidate = 0
            elif match_mode == "prefix" and field.startswith(query):
                candidate = 1
            elif match_mode == "substring" and query in field:
                candidate = 2 + field.find(query)
            elif match_mode == "regex" and pattern is not None and pattern.search(field):
                candidate = 3
            else:
                continue
            best = candidate if best is None else min(best, candidate)
        return best

    def _database(self) -> Any:
        backend = getattr(self.code_index, "_backend", None)
        db = getattr(backend, "db", None)
        if db is not None:
            return db
        clang = getattr(backend, "_clang", None)
        return getattr(clang, "db", None) if clang is not None else None

    def _origin(self) -> str:
        backend = getattr(self.code_index, "_backend", None)
        frontend = str(getattr(backend, "_frontend", "") or "")
        if frontend:
            return f"clang_{frontend}"
        return str(getattr(self.code_index, "backend_name", "regex") or "regex")

    def _file(self, value: Any) -> str:
        normalizer = getattr(self.code_index, "_normalize_index_file_value", None)
        try:
            normalized = normalizer(str(value or "")) if callable(normalizer) else value
        except Exception:
            normalized = value
        result = normalize_project_path(normalized)
        return "" if result and project_relative_path_error(result) else result

    def _collect_records(self) -> Tuple[List[Dict[str, Any]], set[str]]:
        records: List[Dict[str, Any]] = []
        providers: set[str] = set()
        origin = self._origin()
        providers.add(origin)

        with getattr(self.code_index, "_cache_lock", self._lock):
            functions = [
                (key, dict(value))
                for key, value in getattr(self.code_index, "_function_index", {}).items()
            ]
        for index_name, item in functions:
            name = str(item.get("name") or item.get("qualified_name") or index_name)
            qualified = str(item.get("qualified_name") or item.get("method_full_name") or name)
            language = str(item.get("language") or getattr(self.code_index, "language", ""))
            kind = "method" if language.lower() == "java" or item.get("class_name") else "function"
            start_line = _positive_line(item.get("start_line") or item.get("lineNumber"))
            end_line = _positive_line(item.get("end_line") or item.get("lineNumberEnd"), start_line)
            records.append(
                {
                    "kind": kind,
                    "name": name,
                    "qualified_name": qualified,
                    "signature": str(item.get("signature") or f"{qualified}(...)") or None,
                    "file": self._file(item.get("file") or item.get("filename")),
                    "start_line": start_line,
                    "end_line": end_line,
                    "origin": origin,
                    "index_name": str(item.get("index_name") or index_name),
                    "raw": item,
                }
            )

        db = self._database()
        macros: List[Dict[str, Any]] = []
        if db is not None and callable(getattr(db, "get_all_macro_definitions", None)):
            macros = list(db.get_all_macro_definitions() or [])
            if macros:
                providers.add("knowledge_db")
        macro_index_getter = getattr(self.code_index, "_get_macro_definition_index", None)
        source_macros = macro_index_getter() if callable(macro_index_getter) else {}
        known_macro_keys = {
            (
                str(item.get("name") or ""),
                normalize_project_path(item.get("file_path") or item.get("file")),
                int(item.get("start_line") or item.get("line") or 0),
            )
            for item in macros
        }
        for name, items in source_macros.items():
            for item in items:
                key = (
                    name,
                    normalize_project_path(item.get("file_path")),
                    int(item.get("start_line") or 0),
                )
                if key not in known_macro_keys:
                    macros.append(dict(item))
                    providers.add("source_scan")
        for item in macros:
            name = str(item.get("name") or "")
            start = int(item.get("start_line") or item.get("line") or 0)
            end = int(item.get("end_line") or start)
            function_like = bool(item.get("is_function_like"))
            definition = str(item.get("definition") or "")
            records.append(
                {
                    "kind": "macro",
                    "name": name,
                    "qualified_name": name,
                    "signature": None,
                    "file": self._file(item.get("file_path") or item.get("file")),
                    "start_line": start,
                    "end_line": end,
                    "origin": "knowledge_db" if item.get("id") is not None else "source_scan",
                    "index_name": str(
                        item.get("macro_index_name")
                        or f"{name}@{item.get('file_path')}:{start}-{end}"
                    ),
                    "macro": macro_metadata(name, definition, function_like),
                    "raw": dict(item),
                }
            )

        types: List[Dict[str, Any]] = []
        if db is not None and callable(getattr(db, "get_all_type_definitions", None)):
            types = list(db.get_all_type_definitions() or [])
        backend = getattr(self.code_index, "_backend", None)
        type_lister = getattr(backend, "list_type_infos", None)
        if not types and callable(type_lister):
            types = [dict(item) for item in type_lister() or []]
            if types:
                providers.add(origin)
                for item in types:
                    item["_catalog_origin"] = origin
        if not types:
            type_index_getter = getattr(self.code_index, "_get_regex_type_definition_index", None)
            type_index = type_index_getter() if callable(type_index_getter) else {}
            for items in type_index.values():
                types.extend(items)
            if types:
                providers.add("source_scan")
        for item in types:
            name = str(item.get("name") or "")
            qualified = str(item.get("fullName") or item.get("qualified_name") or name)
            start = _positive_line(item.get("start_line") or item.get("lineNumber"))
            records.append(
                {
                    "kind": "type",
                    "name": name,
                    "qualified_name": qualified,
                    "signature": str(item.get("kind") or "type"),
                    "file": self._file(
                        item.get("file_path") or item.get("file") or item.get("filename")
                    ),
                    "start_line": start,
                    "end_line": _positive_line(
                        item.get("end_line") or item.get("lineNumberEnd"), start
                    ),
                    "origin": str(
                        item.get("_catalog_origin")
                        or ("knowledge_db" if item.get("id") is not None else "source_scan")
                    ),
                    "index_name": str(item.get("type_index_name") or name),
                    "raw": dict(item),
                }
            )

        globals_: List[Dict[str, Any]] = []
        if db is not None and callable(getattr(db, "get_global_variables", None)):
            globals_ = list(db.get_global_variables() or [])
        if not globals_:
            global_index_getter = getattr(self.code_index, "_get_global_definition_index", None)
            global_index = global_index_getter() if callable(global_index_getter) else {}
            for items in global_index.values():
                globals_.extend(items)
            if globals_:
                providers.add("source_scan")
        for item in globals_:
            name = str(item.get("name") or "")
            line = int(item.get("line") or item.get("start_line") or 0)
            records.append(
                {
                    "kind": "global",
                    "name": name,
                    "qualified_name": name,
                    "signature": str(item.get("type_str") or item.get("type") or "") or None,
                    "file": self._file(item.get("file_path") or item.get("file")),
                    "start_line": line,
                    "end_line": int(item.get("end_line") or line),
                    "origin": "knowledge_db" if "type_str" in item else "source_scan",
                    "index_name": name,
                    "raw": dict(item),
                }
            )

        if self.user_config is not None:
            getter = getattr(self.user_config, "list_external_functions", None)
            for item in getter() if callable(getter) else []:
                name = str(
                    item.get("function_name") or item.get("func_name") or item.get("name") or ""
                )
                if not name:
                    continue
                records.append(
                    {
                        "kind": "external",
                        "name": name,
                        "qualified_name": name,
                        "signature": str(item.get("signature") or f"{name}(...)") or None,
                        "file": "",
                        "start_line": 0,
                        "end_line": 0,
                        "origin": "user_config",
                        "index_name": name,
                        "raw": dict(item),
                    }
                )
                providers.add("user_config")

        deduped: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        for item in records:
            dedup_key = (
                item["kind"],
                item["qualified_name"],
                item["file"],
                item["start_line"],
                item["end_line"],
                item.get("signature"),
            )
            deduped.setdefault(dedup_key, item)
        return list(deduped.values()), providers


def public_symbol(record: Dict[str, Any], *, include_macro: bool = True) -> Dict[str, Any]:
    start_line = _positive_line(record.get("start_line"))
    end_line = _positive_line(record.get("end_line"))
    result: Dict[str, Any] = {
        "symbol_id": record["symbol_id"],
        "kind": record["kind"],
        "name": record["name"],
        "qualified_name": record["qualified_name"],
        "signature": record.get("signature"),
        "location": {
            "file": record.get("file") or None,
            "start_line": start_line or None,
            "end_line": end_line or None,
        },
        "origin": record.get("origin") or "unknown",
    }
    if include_macro and record.get("macro") is not None:
        result["macro"] = record["macro"]
    return result
