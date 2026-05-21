"""Project-local semantic inference for local candidate generators."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List

from ..semantics.defaults import default_local_pattern_semantics
from ..semantics.models import LocalPatternSemantics, classify_api_name

logger = logging.getLogger(__name__)


SOURCE_SUFFIXES = {".h", ".hh", ".hpp", ".c", ".cc", ".cpp"}
IGNORED_SOURCE_SCAN_PARTS = {
    ".git",
    ".venv",
    ".mypy_cache",
    ".pytest_cache",
    ".zscope_snapshots",
    "zscope.egg-info",
    "build",
    "tmp",
}


class LocalPatternSemanticBuilder:
    """Build merged local-pattern semantics from code, user config, and snapshots."""

    def __init__(self, code_index: Any, user_config: Any, snapshot_store: Any, exclude_paths: Iterable[Path]):
        self.code_index = code_index
        self.user_config = user_config
        self.snapshot_store = snapshot_store
        self.exclude_paths = [Path(path) for path in exclude_paths]

    def build(self) -> LocalPatternSemantics:
        semantics = default_local_pattern_semantics()
        semantics.merge(self.scan_typedef_aliases())
        semantics.merge(self.semantics_from_user_config())
        semantics.merge(self.semantics_from_snapshots())
        semantics.merge(self.semantics_from_function_names())
        logger.info(
            "Local pattern semantics: %d typedef alias(es), %d allocator(s), %d deallocator(s), "
            "%d reallocator(s), %d copy sink(s), %d lock API(s), %d unlock API(s).",
            len(semantics.type_aliases),
            len(semantics.allocators) + len(semantics.calloc_allocators),
            len(semantics.deallocators),
            len(semantics.reallocators),
            len(semantics.copy_sinks),
            len(semantics.lock_apis),
            len(semantics.unlock_apis),
        )
        return semantics

    def scan_typedef_aliases(self) -> LocalPatternSemantics:
        semantics = LocalPatternSemantics()
        roots = [self.code_index.source_root]
        if self.code_index.project_root not in roots:
            roots.append(self.code_index.project_root)
        base_pattern = (
            r"(?:size_t|u?int(?:8|16|32|64)_t|"
            r"(?:unsigned|signed)?\s*(?:char|short|int|long|long\s+long))"
        )
        typedef_re = re.compile(
            rf"\btypedef\s+(?P<base>{base_pattern})\s+(?P<alias>[A-Za-z_]\w*)\s*;",
            re.MULTILINE,
        )
        define_re = re.compile(
            rf"^\s*#\s*define\s+(?P<alias>[A-Za-z_]\w*)\s+(?P<base>{base_pattern})\s*$",
            re.MULTILINE,
        )
        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if skip_semantic_source_scan_path(path, self.exclude_paths):
                    continue
                if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
                    continue
                try:
                    if path.stat().st_size > 1_000_000:
                        continue
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for match in list(typedef_re.finditer(text)) + list(define_re.finditer(text)):
                    alias = match.group("alias")
                    if alias not in {"size_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t"}:
                        semantics.type_aliases[alias] = re.sub(r"\s+", " ", match.group("base")).strip()
        return semantics

    def semantics_from_user_config(self) -> LocalPatternSemantics:
        semantics = LocalPatternSemantics()
        for ext in self.user_config.list_external_functions():
            name = str(ext.get("func_name") or "")
            kind = str(ext.get("kind") or "").lower()
            add_api_for_config_kind(semantics, name, kind, "user_config")
            memory = parse_jsonish(ext.get("memory_behavior"))
            concurrency = parse_jsonish(ext.get("concurrency_behavior"))
            text = " ".join(
                [
                    str(ext.get("description") or ""),
                    str(ext.get("return_semantics") or ""),
                    json.dumps(memory, ensure_ascii=False),
                    json.dumps(concurrency, ensure_ascii=False),
                ]
            ).lower()
            add_api_from_semantic_text(semantics, name, text, "user_config")

        for pair in self.user_config.list_paired_functions():
            category = str(pair.get("category") or "").lower()
            acquire = str(pair.get("acquire_func") or "")
            release = str(pair.get("release_func") or "")
            if _looks_like_lock_category(category):
                semantics.add_api("lock", acquire, "user_config:paired_functions")
                semantics.add_api("unlock", release, "user_config:paired_functions")
            elif _looks_like_resource_category(category):
                semantics.add_api("allocator", acquire, "user_config:paired_functions")
                semantics.add_api("deallocator", release, "user_config:paired_functions")
            else:
                add_api_by_name_heuristic(semantics, acquire, "user_config:paired_functions")
                add_api_by_name_heuristic(semantics, release, "user_config:paired_functions")
        return semantics

    def semantics_from_snapshots(self) -> LocalPatternSemantics:
        semantics = LocalPatternSemantics()
        snapshot_dir = self.snapshot_store.snapshot_dir
        if not snapshot_dir.exists():
            return semantics
        for path in snapshot_dir.glob("*.json"):
            if path.name.endswith("_final.json"):
                continue
            try:
                snapshot = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(snapshot, dict):
                continue
            name = str(snapshot.get("func_name") or "")
            if not name:
                continue
            text = snapshot_contract_text(snapshot)
            add_api_from_semantic_text(semantics, name, text, "semantic_snapshot")
        return semantics

    def semantics_from_function_names(self) -> LocalPatternSemantics:
        semantics = LocalPatternSemantics()
        for name in self.code_index.list_functions(limit=100000):
            add_api_by_name_heuristic(semantics, name, "name_heuristic")
        return semantics


def skip_semantic_source_scan_path(path: Path, exclude_paths: Iterable[Path]) -> bool:
    if any(part in IGNORED_SOURCE_SCAN_PARTS for part in path.parts):
        return True
    try:
        resolved = path.resolve()
    except OSError:
        return True
    return any(
        resolved == excluded or excluded in resolved.parents
        for excluded in exclude_paths
    )


def add_api_for_config_kind(
    semantics: LocalPatternSemantics,
    name: str,
    kind: str,
    source: str,
) -> None:
    if kind in {"allocator", "resource_acquire"}:
        semantics.add_api("allocator", name, source)
    elif kind == "calloc":
        semantics.add_api("calloc", name, source)
    elif kind == "reallocator":
        semantics.add_api("reallocator", name, source)
    elif kind in {"deallocator", "resource_release"}:
        semantics.add_api("deallocator", name, source)
    elif kind == "copy":
        semantics.add_api("copy", name, source)
    elif kind == "lock":
        semantics.add_api("lock", name, source)
    elif kind == "unlock":
        semantics.add_api("unlock", name, source)


def parse_jsonish(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return {"text": str(value)}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def snapshot_contract_text(snapshot: Dict[str, Any]) -> str:
    fields = [
        snapshot.get("summary"),
        snapshot.get("role"),
        snapshot.get("outputs"),
        snapshot.get("key_semantics"),
        snapshot.get("semantic_fingerprint"),
    ]
    if snapshot.get("snapshot_kind") == "lightweight":
        fields.extend([snapshot.get("resources"), snapshot.get("concurrency")])
    return " ".join(json.dumps(field, ensure_ascii=False) for field in fields if field).lower()


def add_api_by_name_heuristic(
    semantics: LocalPatternSemantics,
    name: str,
    source: str,
) -> None:
    category = classify_api_name(name)
    if category:
        semantics.add_api(category, name, source)


def add_api_from_semantic_text(
    semantics: LocalPatternSemantics,
    name: str,
    text: str,
    source: str,
) -> None:
    if not name:
        return
    if source == "semantic_snapshot":
        # Snapshot text describes a function's internal behavior; generic words
        # such as "locks" or "release" must not reclassify that function itself.
        add_api_by_name_heuristic(semantics, name, source)
        return
    lower = text.lower()
    if "realloc" in lower or "重新分配" in lower:
        semantics.add_api("reallocator", name, source)
    if any(word in lower for word in ("calloc", "zeroed allocation", "零初始化分配")):
        semantics.add_api("calloc", name, source)
    if any(word in lower for word in ("allocate", "allocates", "allocation", "returns allocated", "分配", "返回已分配")):
        semantics.add_api("allocator", name, source)
    if any(word in lower for word in ("free", "deallocate", "release memory", "释放内存", "释放资源")):
        semantics.add_api("deallocator", name, source)
    if any(word in lower for word in ("copy", "memcpy", "memmove", "buffer_bounds", "拷贝", "复制")):
        semantics.add_api("copy", name, source)
    if any(word in lower for word in ("acquire lock", "lock acquisition", "locks", "lock acquire", "加锁", "获取锁")):
        semantics.add_api("lock", name, source)
    if any(word in lower for word in ("unlock", "release lock", "lock release", "解锁", "释放锁")):
        semantics.add_api("unlock", name, source)
    add_api_by_name_heuristic(semantics, name, source)


def _looks_like_lock_category(category: str) -> bool:
    return any(word in category for word in ("lock", "mutex", "rwlock", "spin", "sync", "concurrency", "锁", "互斥"))


def _looks_like_resource_category(category: str) -> bool:
    return any(word in category for word in ("memory", "resource", "alloc", "内存", "资源", "分配", "释放"))
