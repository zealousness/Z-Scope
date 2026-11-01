"""Input fingerprinting for scan jobs.

Every attempt binds the real inputs it ran against: the saved config bytes,
the effective scan depth, declared build/entry inputs and a bounded source
manifest.  Resume recomputes the fingerprint; any change revokes the previous
attempt's binding and is recorded with the components that changed.

The manifest hashes ``(path, size, mtime_ns)`` tuples — content changes that
preserve size and mtime are not detected, which is the documented limit of
mtime-based invalidation (same trade-off as existing index caches).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import JobError

_MANIFEST_LIMIT = 50_000
_HASH_CHUNK = 1024 * 1024
# Product report artifacts are outputs, not source inputs. In particular a
# first-window report must not invalidate the next window's input identity.
_GENERATED_REPORTS = frozenset({"zscope_batch_report.json", "zscope_report.json"})
_SKIPPED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".zscope_jobs",
        ".zscope_knowledge",
        ".zscope_snapshots",
        ".zscope_bc",
        ".zscope-compile-commands",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
    }
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_HASH_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _file_component(path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if path is None:
        return None
    try:
        stat = path.stat()
    except OSError:
        return {"path": str(path), "exists": False}
    component: Dict[str, Any] = {
        "path": str(path),
        "exists": True,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }
    if path.is_file():
        try:
            component["sha256"] = _sha256_file(path)
        except OSError:
            component["sha256"] = None
    return component


def _source_manifest(source_root: Path) -> Dict[str, Any]:
    digest = hashlib.sha256()
    entries = 0
    capped = False
    errors: List[str] = []
    try:
        for dirpath, dirnames, filenames in os.walk(source_root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in _SKIPPED_DIRS)
            for name in sorted(filenames):
                if name in _GENERATED_REPORTS and Path(dirpath) == source_root:
                    continue
                if entries >= _MANIFEST_LIMIT:
                    capped = True
                    break
                full = Path(dirpath) / name
                try:
                    stat = full.stat()
                except OSError:
                    continue
                try:
                    rel = full.relative_to(source_root).as_posix()
                except ValueError:
                    rel = str(full)
                digest.update(
                    f"{rel}\0{stat.st_size}\0{stat.st_mtime_ns}\n".encode("utf-8", "replace")
                )
                entries += 1
            if capped:
                break
    except OSError as exc:  # pragma: no cover - defensive
        errors.append(str(exc))
    return {
        "root": str(source_root),
        "entries": entries,
        "capped": capped,
        "sha256": digest.hexdigest(),
        "errors": errors,
    }


def _tool_components(tool_paths: List[Path]) -> Dict[str, Any]:
    tools: Dict[str, Any] = {}
    for path in tool_paths:
        try:
            stat = path.stat()
        except OSError:
            tools[str(path)] = {"exists": False}
            continue
        tools[str(path)] = {
            "exists": True,
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "is_dir": path.is_dir(),
        }
    return tools


def compute_input_fingerprint(
    config_path: Path,
    *,
    scan_depth: Optional[str],
) -> Dict[str, Any]:
    """Compute the fingerprint over the saved config and resolved inputs."""

    from ...config.config import ConfigLoader

    config_file = Path(config_path)
    if not config_file.is_file():
        raise JobError(
            "config_unavailable",
            f"saved config does not exist: {config_file}",
            status_code=503,
        )
    try:
        config_sha = _sha256_file(config_file)
    except OSError as exc:
        raise JobError(
            "config_unavailable",
            f"saved config is not readable: {config_file}: {exc}",
            status_code=503,
        ) from exc
    try:
        config = ConfigLoader.load(str(config_file), scan_depth=scan_depth, read_only=True)
    except JobError:
        raise
    except Exception as exc:
        raise JobError(
            "config_unavailable",
            f"saved config failed to load: {type(exc).__name__}: {exc}",
            status_code=503,
        ) from exc

    project = config.project
    project_root = Path(project.project_root)
    source_root = project_root

    compile_commands = getattr(project, "compile_commands_path", None)
    entry_list_path: Optional[Path] = None
    entry_functions_list = getattr(project, "entry_functions_list", None)
    if isinstance(entry_functions_list, Path):
        entry_list_path = entry_functions_list
    elif isinstance(entry_functions_list, str) and entry_functions_list.strip():
        candidate = Path(entry_functions_list)
        entry_list_path = candidate if candidate.is_absolute() else project_root / candidate
    user_config_file = getattr(project, "user_config_file", None)

    tool_paths: List[Path] = []
    tools = getattr(config.indexing, "tools", None)
    for attr in ("clangd", "clang_indexer", "gclang", "get_bc", "llvm_link", "svf_bin_dir"):
        value = getattr(tools, attr, None) if tools is not None else None
        if isinstance(value, str) and value.strip():
            tool_paths.append(Path(value))
    java_tools = getattr(config.indexing, "java", None)
    joern = getattr(java_tools, "joern", None) if java_tools is not None else None
    joern_command = getattr(joern, "command", None) if joern is not None else None
    if isinstance(joern_command, str) and joern_command.strip():
        tool_paths.append(Path(joern_command.split()[0]))

    components: Dict[str, Any] = {
        "config_file": {
            "path": str(config_file.resolve()),
            "sha256": config_sha,
        },
        "scan_depth": scan_depth or config.scan.depth,
        "project": {
            "root": str(project_root),
            "project_id": getattr(project, "project_id", None) or project_root.name,
            "language": getattr(project, "language", None),
            "source_root": str(source_root),
        },
        "compile_commands": _file_component(
            Path(compile_commands) if isinstance(compile_commands, (str, Path)) else None
        ),
        "entry_functions_list": _file_component(entry_list_path),
        "project_semantics": _file_component(getattr(project, "semantics_file", None)),
        "user_config_file": _file_component(
            Path(user_config_file) if isinstance(user_config_file, (str, Path)) else None
        ),
        "tools": _tool_components(tool_paths),
        "source_manifest": _source_manifest(source_root),
    }
    canonical = json.dumps(components, sort_keys=True, ensure_ascii=False, default=str)
    fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {
        "sha256": fingerprint,
        "components": components,
        "project_root": str(project_root),
        "project_id": components["project"]["project_id"],
        "config_sha256": config_sha,
    }


def diff_components(old: Dict[str, Any], new: Dict[str, Any]) -> List[str]:
    """Return the dotted names of fingerprint components that changed."""

    changed: List[str] = []

    def _compare(prefix: str, left: Any, right: Any) -> None:
        if isinstance(left, dict) and isinstance(right, dict):
            keys = set(left) | set(right)
            for key in sorted(keys):
                _compare(f"{prefix}.{key}" if prefix else key, left.get(key), right.get(key))
            return
        if left != right:
            changed.append(prefix)

    _compare("", old, new)
    return changed
