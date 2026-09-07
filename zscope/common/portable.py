"""Locate resources in a relocatable release without changing public config fields.

Only the release launcher sets Z_SCOPE_BUNDLE_ROOT. Source installations retain
their existing PATH/repository discovery. Explicit user commands never pass
through this module's default selection.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


def bundle_root() -> Optional[Path]:
    value = os.environ.get("Z_SCOPE_BUNDLE_ROOT", "")
    return Path(value).expanduser().resolve() if value else None


def bundle_manifest() -> Optional[Dict[str, Any]]:
    root = bundle_root()
    if root is None:
        return None
    manifest = json.loads((root / "bundle.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "zscope.portable.v1":
        raise ValueError("Unsupported portable bundle manifest")
    if manifest.get("profile") not in {"cpp", "java"}:
        raise ValueError("Invalid portable bundle profile")
    return dict(manifest)


def resource(section: str, name: str) -> Optional[Path]:
    root = bundle_root()
    manifest = bundle_manifest()
    if root is None or manifest is None:
        return None
    relative = manifest.get(section, {}).get(name)
    if not isinstance(relative, str) or not relative:
        raise FileNotFoundError(
            f"Portable {manifest['profile']} bundle does not contain {section}:{name}"
        )
    path = root / relative
    try:
        path.resolve().relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Bundle resource escapes the release directory: {relative}") from exc
    if Path(relative).is_absolute() or not path.is_file():
        raise FileNotFoundError(f"Missing portable resource: {path}")
    return path


def default_tool(name: str, fallback: Optional[str] = None) -> str:
    path = resource("tools", name)
    if path is not None:
        if not os.access(str(path), os.X_OK):
            raise PermissionError(f"Portable tool is not executable: {path}")
        return str(path)
    return name if fallback is None else fallback


def default_svf_directory() -> str:
    if bundle_root() is None:
        return ""
    return str(Path(default_tool("wpa")).parent)


def java_jar(name: str) -> Optional[Path]:
    return resource("java_jars", name)


def bundled_executable(command: str) -> Optional[Path]:
    """Inspect a selected launcher's payload without changing tool selection.

    Version/loader/cache checks need the real ELF, while execution must retain
    the launcher's name (notably clang++ and the shared portable dispatcher).
    """
    root = bundle_root()
    manifest = bundle_manifest()
    if root is None or manifest is None:
        return None
    path = Path(command).absolute()
    for _ in range(40):
        if path.parent.resolve() == root / "bin" and path.name in manifest.get("executables", {}):
            return resource("executables", path.name)
        if not path.is_symlink():
            return None
        target = Path(os.readlink(path))
        path = target if target.is_absolute() else path.parent / target
    raise ValueError("Too many tool launcher symlinks")
