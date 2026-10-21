"""Project-local semantic inference for local candidate generators."""

from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List

from ..semantics.defaults import default_local_pattern_semantics
from ..semantics.models import LocalPatternSemantics, classify_api_name
from .contracts import ApiContract, ApiPair, SymbolIdentity

logger = logging.getLogger(__name__)


SOURCE_SUFFIXES = {".h", ".hh", ".hpp", ".c", ".cc", ".cpp"}
IGNORED_SOURCE_SCAN_PARTS = {
    ".git",
    ".venv",
    ".mypy_cache",
    ".pytest_cache",
    ".zscope_snapshots",
    ".zscope_conversations",
    "zscope.egg-info",
    "benchmark_runs",
    "build",
    "codeql_runs",
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
        logger.info(
            "Local pattern semantics: %d typedef alias(es), %d allocator(s), %d deallocator(s), "
            "%d reallocator(s), %d copy sink(s), %d lock API(s), %d unlock API(s), "
            "%d io acquirer(s), %d io releaser(s), %d send sink(s), %d recv source(s), "
            "%d format sink(s), %d callback registrar(s).",
            len(semantics.type_aliases),
            len(semantics.allocators) + len(semantics.calloc_allocators),
            len(semantics.deallocators),
            len(semantics.reallocators),
            len(semantics.copy_sinks),
            len(semantics.lock_apis),
            len(semantics.unlock_apis),
            len(semantics.io_acquirers),
            len(semantics.io_releasers),
            len(semantics.send_sinks),
            len(semantics.recv_sources),
            len(semantics.format_sinks),
            len(semantics.callback_registrars),
        )
        return semantics

    def scan_typedef_aliases(self) -> LocalPatternSemantics:
        semantics = LocalPatternSemantics()
        roots: list[Path] = []
        for attribute in ("source_root", "project_root"):
            value = getattr(self.code_index, attribute, None)
            if value is None:
                continue
            root = Path(value)
            if root not in roots:
                roots.append(root)
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
        started = time.monotonic()
        scanned_files = 0
        for root in roots:
            if not root.exists():
                continue
            for path in iter_semantic_source_files(root, self.exclude_paths):
                scanned_files += 1
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
        logger.info(
            "Local typedef semantics scan: roots=%d source_files=%d duration=%.2fs",
            len(roots),
            scanned_files,
            time.monotonic() - started,
        )
        return semantics

    def semantics_from_user_config(self) -> LocalPatternSemantics:
        semantics = LocalPatternSemantics()
        classifier = getattr(self.code_index, "call_model_status", None)
        if callable(classifier):
            names = {c.symbol.name for c in default_local_pattern_semantics().contracts.contracts}
            semantics.contracts.shadowed_symbols = {n for n in names if classifier(n) == "project"}
        for ext in self.user_config.list_external_functions():
            contract = ApiContract.from_row(ext)
            if contract is not None:
                semantics.contracts.add(contract)
                semantics.add_api(contract.role, contract.symbol.name, contract.source)

        for pair in self.user_config.list_paired_functions():
            category = str(pair.get("category") or "").lower()
            acquire = str(pair.get("acquire_func") or "")
            release = str(pair.get("release_func") or "")
            semantics.contracts.pairs.append(
                ApiPair(
                    SymbolIdentity.from_value(
                        {
                            "name": acquire,
                            "file_path": pair.get("acquire_file_path"),
                            "signature": pair.get("acquire_signature"),
                            "symbol_type": pair.get("acquire_symbol_type"),
                        }
                    ),
                    SymbolIdentity.from_value(
                        {
                            "name": release,
                            "file_path": pair.get("release_file_path"),
                            "signature": pair.get("release_signature"),
                            "symbol_type": pair.get("release_symbol_type"),
                        }
                    ),
                    pair.get("conditions") or [],
                    str(pair.get("source") or "user_config"),
                    pair.get("evidence") or [],
                )
            )
            if str(pair.get("source") or "").startswith("inferred"):
                # A generated pair reference cannot manufacture a manual role
                # for an unmodeled target or change a builtin's provenance.
                continue
            if _looks_like_lock_category(category):
                semantics.add_api("lock", acquire, "user_config:paired_functions")
                semantics.add_api("unlock", release, "user_config:paired_functions")
            elif _looks_like_io_category(category):
                semantics.add_api("io_acquire", acquire, "user_config:paired_functions")
                semantics.add_api("io_release", release, "user_config:paired_functions")
            elif _looks_like_resource_category(category):
                if not any(
                    c.role in {"allocator", "calloc", "reallocator"}
                    for c in semantics.contracts.find(acquire)
                ):
                    semantics.add_api("allocator", acquire, "user_config:paired_functions")
                semantics.add_api("deallocator", release, "user_config:paired_functions")
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
            role = classify_snapshot_role(snapshot)
            if role:
                semantics.add_api(role, name, "semantic_snapshot")
                continue
            text = snapshot_contract_text(snapshot)
            add_api_from_semantic_text(semantics, name, text, "semantic_snapshot")
        return semantics

    def semantics_from_function_names(self) -> LocalPatternSemantics:
        semantics = LocalPatternSemantics()
        for name in self.code_index.list_functions(limit=100000):
            add_api_by_name_heuristic(semantics, name, "name_heuristic")
        return semantics


def _is_generated_semantic_directory_name(name: str) -> bool:
    normalized = str(name or "").strip()
    return (
        normalized in IGNORED_SOURCE_SCAN_PARTS
        or normalized.startswith(".zscope_")
    )


def _resolved_paths(paths: Iterable[Path]) -> tuple[Path, ...]:
    resolved: list[Path] = []
    for path in paths:
        try:
            resolved.append(Path(path).resolve())
        except OSError:
            continue
    return tuple(resolved)


def _path_is_excluded(path: Path, exclude_paths: Iterable[Path]) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return True
    return any(
        resolved == excluded or excluded in resolved.parents
        for excluded in exclude_paths
    )


def iter_semantic_source_files(
    root: Path,
    exclude_paths: Iterable[Path],
) -> Iterator[Path]:
    """Yield source files without descending into generated/excluded trees."""

    resolved_excludes = _resolved_paths(exclude_paths)
    try:
        resolved_root = Path(root).resolve()
    except OSError:
        return

    for current, directory_names, file_names in os.walk(
        resolved_root,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current)
        directory_names[:] = [
            name
            for name in directory_names
            if not _is_generated_semantic_directory_name(name)
            and not _path_is_excluded(current_path / name, resolved_excludes)
        ]
        for name in file_names:
            path = current_path / name
            if path.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            if _path_is_excluded(path, resolved_excludes):
                continue
            yield path


def skip_semantic_source_scan_path(path: Path, exclude_paths: Iterable[Path]) -> bool:
    if any(
        _is_generated_semantic_directory_name(part)
        for part in path.parts
    ):
        return True
    return _path_is_excluded(path, _resolved_paths(exclude_paths))


def add_api_for_config_kind(
    semantics: LocalPatternSemantics,
    name: str,
    kind: str,
    source: str,
) -> bool:
    normalized = str(kind or "").strip().lower()
    if normalized in {"allocator", "resource", "resource_acquire"}:
        semantics.add_api("allocator", name, source)
    elif normalized == "calloc":
        semantics.add_api("calloc", name, source)
    elif normalized == "reallocator":
        semantics.add_api("reallocator", name, source)
    elif normalized in {"deallocator", "resource_release"}:
        semantics.add_api("deallocator", name, source)
    elif normalized == "copy":
        semantics.add_api("copy", name, source)
    elif normalized == "lock":
        semantics.add_api("lock", name, source)
    elif normalized == "unlock":
        semantics.add_api("unlock", name, source)
    elif normalized == "io_acquire":
        semantics.add_api("io_acquire", name, source)
    elif normalized == "io_release":
        semantics.add_api("io_release", name, source)
    elif normalized == "send_sink":
        semantics.add_api("send_sink", name, source)
    elif normalized == "recv_source":
        semantics.add_api("recv_source", name, source)
    elif normalized == "format_sink":
        semantics.add_api("format_sink", name, source)
    elif normalized == "callback_register":
        semantics.add_api("callback_register", name, source)
    elif normalized == "ownership_transfer":
        semantics.add_api("ownership_transfer", name, source)
    else:
        if normalized:
            logger.warning(
                "Unknown user-config API kind %r for %r; row ignored by semantics.",
                normalized,
                name,
            )
        return False
    return True


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


_SNAPSHOT_VALID_ROLES = frozenset(
    {
        "allocator",
        "calloc",
        "reallocator",
        "deallocator",
        "copy",
        "lock",
        "unlock",
        "io_acquire",
        "io_release",
        "send_sink",
        "recv_source",
        "format_sink",
        "callback_register",
        "ownership_transfer",
    }
)


def classify_snapshot_role(snapshot: Dict[str, Any]) -> str:
    """Classify a semantic snapshot into a risk-interface role.

    The explicit ``role`` field (stamped by the scan-time LLM interface probe)
    wins; otherwise the structured effects details drive a deterministic
    fallback so fast scans benefit from lightweight snapshots without any LLM
    call.  Returns "" when the snapshot does not describe a recognizable risk
    interface.
    """

    explicit = str(snapshot.get("role") or "").strip().lower()
    if explicit in _SNAPSHOT_VALID_ROLES:
        return explicit
    categories: set[str] = set()
    operation_kinds: set[str] = set()
    for effect in snapshot.get("effects") or []:
        if not isinstance(effect, dict):
            continue
        categories.add(str(effect.get("category") or "").lower())
        details = parse_jsonish(effect.get("details"))
        operation_kinds.add(str(details.get("operation_kind") or "").lower())
    return_values = parse_jsonish(snapshot.get("return_values"))
    ownership = str(return_values.get("ownership") or "").lower()
    if "lock" in categories:
        if "release" in operation_kinds:
            return "unlock"
        if "acquire" in operation_kinds:
            return "lock"
    if ownership == "caller_owned" and "memory" in categories:
        return "allocator"
    if "memory" in categories and "release" in operation_kinds:
        return "deallocator"
    if "io" in categories and "log" in operation_kinds:
        return "format_sink"
    return ""


def snapshot_contract_text(snapshot: Dict[str, Any]) -> str:
    fields = [
        snapshot.get("summary"),
        snapshot.get("role"),
        snapshot.get("return_values"),
        snapshot.get("effects"),
        snapshot.get("error_handling"),
        snapshot.get("referenced_types"),
        snapshot.get("semantic_fingerprint"),
    ]
    if "return_values" not in snapshot:
        fields.append(snapshot.get("outputs"))
    if "effects" not in snapshot:
        fields.extend(
            [
                snapshot.get("resources"),
                snapshot.get("concurrency"),
                snapshot.get("key_semantics"),
            ]
        )
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
    if any(
        word in lower
        for word in (
            "opens",
            "open a",
            "open the",
            "creates socket",
            "accepts connection",
            "maps memory",
            "returns a file descriptor",
            "returns file descriptor",
            "acquire fd",
            "打开",
            "创建套接字",
            "接受连接",
            "返回文件描述符",
            "获取句柄",
        )
    ):
        semantics.add_api("io_acquire", name, source)
    if any(
        word in lower
        for word in (
            "closes",
            "close a",
            "close the",
            "closes socket",
            "unmaps",
            "releases fd",
            "releases the file descriptor",
            "关闭",
            "释放句柄",
            "释放文件描述符",
        )
    ):
        semantics.add_api("io_release", name, source)
    if any(
        word in lower
        for word in (
            "sends",
            "send data",
            "transmits",
            "writes data out",
            "network sink",
            "发送",
            "写出数据",
            "外发",
        )
    ):
        semantics.add_api("send_sink", name, source)
    if any(
        word in lower
        for word in (
            "receives",
            "receive data",
            "reads external",
            "reads input",
            "returns external input",
            "untrusted input",
            "external input source",
            "接收",
            "读取外部",
            "外部输入",
        )
    ):
        semantics.add_api("recv_source", name, source)
    if any(
        word in lower
        for word in (
            "formats",
            "format string",
            "printf-style",
            "printf style",
            "formatted output",
            "log output",
            "格式化",
            "打印日志",
            "日志输出",
        )
    ):
        semantics.add_api("format_sink", name, source)
    if any(
        word in lower
        for word in (
            "registers callback",
            "registers a callback",
            "callback registration",
            "subscribes handler",
            "installs hook",
            "注册回调",
            "订阅",
            "挂载回调",
        )
    ):
        semantics.add_api("callback_register", name, source)
    add_api_by_name_heuristic(semantics, name, source)


def _looks_like_lock_category(category: str) -> bool:
    return any(word in category for word in ("lock", "mutex", "rwlock", "spin", "sync", "concurrency", "锁", "互斥"))


def _looks_like_resource_category(category: str) -> bool:
    return any(word in category for word in ("memory", "resource", "alloc", "内存", "资源", "分配", "释放"))


def _looks_like_io_category(category: str) -> bool:
    return any(
        word in category
        for word in ("file", "fd", "socket", "io", "handle", "描述符", "句柄", "文件", "套接字")
    )
