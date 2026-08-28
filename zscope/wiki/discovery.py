"""Deterministic, project-root-scoped Markdown discovery.

Discovery is deliberately conservative.  It does not follow directory links,
does not read unsupported files, and never decodes a file until its size and
root-boundary checks have passed.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from .models import DiscoveredFile, DiscoveryIssue


MARKDOWN_SUFFIXES = frozenset({".md", ".markdown"})
DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_TOTAL_BYTES = 100 * 1024 * 1024
MAX_PRUNE_PATHS = 64
MAX_PRUNE_PATH_LENGTH = 512
MAX_PRUNE_PATH_PARTS = 32

# These directories are generated state, tool caches, or vendored material.
# ``artifacts`` is intentionally absent: an artifact document is classified
# and audited rather than silently hidden from the manifest.
MANDATORY_PRUNE_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".zscope_knowledge",
        ".zscope_snapshots",
        ".zscope_state",
        ".cache",
        "__pycache__",
        "build",
        "cmake-build-debug",
        "cmake-build-release",
        "dist",
        "node_modules",
        "target",
        "vendor",
        "third_party",
        "generated",
        "coverage",
        "profile",
    }
)


@dataclass(frozen=True)
class DiscoveryResult:
    """Result of a bounded discovery pass."""

    files: Tuple[DiscoveredFile, ...] = ()
    issues: Tuple[DiscoveryIssue, ...] = ()
    unsupported_extensions: Dict[str, int] = field(default_factory=dict)
    unsupported_paths: Tuple[Tuple[str, str], ...] = ()

    def __iter__(self):
        # A small compatibility convenience for callers that unpack results.
        yield self.files
        yield self.issues


def _root_from(value: Union[Path, str, object]) -> Path:
    root = getattr(value, "project_root", value)
    return Path(root).expanduser().resolve()


def _posix_relative(path: Path, root: Path) -> str:
    return PurePosixPath(path.relative_to(root)).as_posix()


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _normalize_prune_paths(
    prune_paths: Optional[Union[Path, str, Iterable[Union[Path, str]]]],
) -> Tuple[Tuple[str, ...], ...]:
    """Return bounded project-relative directory prefixes for discovery.

    Prune paths are configuration-derived traversal controls, not glob
    patterns.  They are deliberately validated without resolving them: a
    caller can prune a state directory before it exists, and discovery never
    follows directory symlinks in the first place.
    """

    if prune_paths is None:
        values: Sequence[Union[Path, str]] = ()
    elif isinstance(prune_paths, (str, Path)):
        values = (prune_paths,)
    else:
        try:
            values = tuple(prune_paths)
        except TypeError as exc:
            raise ValueError("prune_paths must be a path or iterable of paths") from exc
    if len(values) > MAX_PRUNE_PATHS:
        raise ValueError(f"prune_paths may contain at most {MAX_PRUNE_PATHS} paths")

    normalized = set()
    for raw_path in values:
        value = str(raw_path).strip()
        if (
            not value
            or len(value) > MAX_PRUNE_PATH_LENGTH
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise ValueError("prune path must be bounded non-control text")
        native = Path(value)
        windows = PureWindowsPath(value)
        if native.is_absolute() or windows.is_absolute() or windows.drive:
            raise ValueError("prune path must be project-root relative")
        parts = native.parts
        if (
            not parts
            or len(parts) > MAX_PRUNE_PATH_PARTS
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise ValueError("prune path must be a bounded project-relative directory")
        normalized.add(tuple(parts))
    return tuple(sorted(normalized))


def _is_pruned(relative_parts: Tuple[str, ...], prune_paths: Tuple[Tuple[str, ...], ...]) -> bool:
    return any(relative_parts[: len(prefix)] == prefix for prefix in prune_paths)


def _iter_entries(
    root: Path,
    *,
    prune_paths: Tuple[Tuple[str, ...], ...] = (),
) -> Iterable[Tuple[Path, os.DirEntry[str]]]:
    """Yield regular entries in lexical order without following dir links."""

    stack: List[Path] = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError:
            continue
        child_dirs: List[Path] = []
        for entry in entries:
            path = Path(entry.path)
            try:
                relative_parts = path.relative_to(root).parts
            except ValueError:
                continue
            if _is_pruned(relative_parts, prune_paths):
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.is_symlink() or entry.name in MANDATORY_PRUNE_DIRS:
                        continue
                    child_dirs.append(path)
                else:
                    yield path, entry
            except OSError:
                yield path, entry
        stack.extend(reversed(child_dirs))


def discover_markdown(
    project_root: Union[Path, str, object],
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    prune_paths: Optional[Union[Path, str, Iterable[Union[Path, str]]]] = None,
) -> DiscoveryResult:
    """Discover bounded Markdown files under ``project_root``.

    File symlinks are permitted only when their resolved target remains inside
    the root.  Invalid UTF-8, unreadable files, and limits become issues; no
    source text from those files is returned.
    """

    root = _root_from(project_root)
    if not root.is_dir():
        raise ValueError(f"project root is not a directory: {root}")
    if max_file_bytes <= 0 or max_files <= 0 or max_total_bytes <= 0:
        raise ValueError("discovery limits must be positive")
    normalized_prune_paths = _normalize_prune_paths(prune_paths)

    files: List[DiscoveredFile] = []
    issues: List[DiscoveryIssue] = []
    unsupported: Dict[str, int] = {}
    unsupported_paths: List[Tuple[str, str]] = []
    total_bytes = 0

    for path, entry in _iter_entries(root, prune_paths=normalized_prune_paths):
        try:
            relative = _posix_relative(path, root)
        except ValueError:
            issues.append(DiscoveryIssue(str(path), "path_outside_project_root"))
            continue

        suffix = path.suffix.lower()
        if suffix not in MARKDOWN_SUFFIXES:
            extension = suffix or "<none>"
            unsupported[extension] = unsupported.get(extension, 0) + 1
            unsupported_paths.append((relative, extension))
            continue
        if len(files) >= max_files:
            issues.append(DiscoveryIssue(relative, "max_file_count_exceeded"))
            continue

        is_symlink = path.is_symlink()
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            issues.append(DiscoveryIssue(relative, "symlink_target_unavailable" if is_symlink else "file_unavailable"))
            continue
        if not _is_within(resolved, root):
            issues.append(DiscoveryIssue(relative, "symlink_outside_project_root", "sensitive_rejected"))
            continue
        try:
            size = int(resolved.stat().st_size)
        except OSError:
            issues.append(DiscoveryIssue(relative, "stat_failed"))
            continue
        if size > max_file_bytes:
            issues.append(DiscoveryIssue(relative, "max_file_bytes_exceeded"))
            continue
        if total_bytes + size > max_total_bytes:
            issues.append(DiscoveryIssue(relative, "max_total_bytes_exceeded"))
            continue
        try:
            raw = resolved.read_bytes()
            if len(raw) > max_file_bytes:
                issues.append(DiscoveryIssue(relative, "max_file_bytes_exceeded"))
                continue
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            issues.append(DiscoveryIssue(relative, "invalid_utf8"))
            continue
        except OSError:
            issues.append(DiscoveryIssue(relative, "read_failed"))
            continue
        digest = _digest(raw)
        files.append(
            DiscoveredFile(
                relative_path=relative,
                absolute_path=path,
                size_bytes=size,
                content_digest=digest,
                text=text,
                is_symlink=is_symlink,
            )
        )
        total_bytes += size

    files.sort(key=lambda item: item.relative_path)
    issues.sort(key=lambda item: item.relative_path)
    return DiscoveryResult(
        tuple(files),
        tuple(issues),
        dict(sorted(unsupported.items())),
        tuple(sorted(unsupported_paths)),
    )


class MarkdownDiscovery:
    """State-free facade useful to callers that prefer an object API."""

    def __init__(self, project_root: Union[Path, str, object], **limits: int):
        self.project_root = project_root
        self.limits = limits

    def run(self) -> DiscoveryResult:
        return discover_markdown(self.project_root, **self.limits)

    discover = run


# Public alias used by early callers and tests.
discover = discover_markdown


__all__ = [
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_TOTAL_BYTES",
    "MAX_PRUNE_PATHS",
    "MAX_PRUNE_PATH_LENGTH",
    "MAX_PRUNE_PATH_PARTS",
    "MANDATORY_PRUNE_DIRS",
    "DiscoveryResult",
    "discover_markdown",
    "discover",
    "MarkdownDiscovery",
]
