#!/usr/bin/env python3
"""Resolve a P6 upload tree without following any symbolic link."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable, Tuple


class P6ArtifactTreeError(ValueError):
    """The requested upload tree is not a link-free regular-file tree."""


def _normalized(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _resolved_regular_file(root: Path, lexical: Path) -> Path:
    """Revalidate one lexical member before a caller opens it.

    ``resolve`` is deliberately after ``lstat``: resolving first would erase the
    evidence that a dispatcher supplied a link alias.  Equality between the
    lexical and resolved names additionally rejects links introduced in any
    ancestor component.
    """

    try:
        mode = lexical.lstat().st_mode
    except OSError as exc:
        raise P6ArtifactTreeError("P6 artifact path is unavailable") from exc
    if stat.S_ISLNK(mode):
        raise P6ArtifactTreeError("P6 artifact path contains a symbolic link")
    if not stat.S_ISREG(mode):
        raise P6ArtifactTreeError("P6 artifact path is not a regular file")
    try:
        resolved = lexical.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise P6ArtifactTreeError("P6 artifact path escapes the control plane") from exc
    if _normalized(resolved) != _normalized(lexical):
        raise P6ArtifactTreeError("P6 artifact path contains a symbolic link")
    return resolved


def revalidate_regular_file(control: Path, path: Path) -> Path:
    """Revalidate a previously discovered member immediately before reading."""

    root = control.resolve(strict=True)
    return _resolved_regular_file(root, Path(os.path.abspath(path)))


def discover_regular_files(control: Path, values: Iterable[str]) -> Tuple[Path, ...]:
    lexical_root = Path(os.path.abspath(control))
    try:
        root_mode = lexical_root.lstat().st_mode
        root = lexical_root.resolve(strict=True)
    except OSError as exc:
        raise P6ArtifactTreeError("P6 control plane is unavailable") from exc
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise P6ArtifactTreeError("P6 control plane must be a link-free directory")
    if _normalized(root) != _normalized(lexical_root):
        raise P6ArtifactTreeError("P6 control plane contains a symbolic link")
    requested = []
    for value in values:
        if not value.strip():
            continue
        lexical = Path(os.path.abspath(Path(value)))
        try:
            relative = lexical.relative_to(root)
        except ValueError as exc:
            raise P6ArtifactTreeError("P6 artifact path escapes the control plane") from exc
        cursor = root
        for component in relative.parts:
            cursor = cursor / component
            try:
                mode = cursor.lstat().st_mode
            except OSError as exc:
                raise P6ArtifactTreeError("P6 artifact path is unavailable") from exc
            if stat.S_ISLNK(mode):
                raise P6ArtifactTreeError("P6 artifact path contains a symbolic link")
        try:
            resolved = lexical.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            raise P6ArtifactTreeError("P6 artifact path escapes the control plane") from exc
        if _normalized(resolved) != _normalized(lexical):
            raise P6ArtifactTreeError("P6 artifact path contains a symbolic link")
        requested.append(lexical)
    if not requested or len(set(requested)) != len(requested):
        raise P6ArtifactTreeError("P6 artifact path set is empty or duplicated")

    files = []
    for requested_path in requested:
        if root not in requested_path.parents:
            raise P6ArtifactTreeError("P6 artifact path escapes the control plane")
        if requested_path.is_dir():
            for raw_root, directories, filenames in os.walk(
                requested_path, topdown=True, followlinks=False
            ):
                directory = Path(raw_root)
                for name in (*directories, *filenames):
                    member = directory / name
                    mode = member.lstat().st_mode
                    if stat.S_ISLNK(mode):
                        raise P6ArtifactTreeError("P6 artifact tree contains a symbolic link")
                    if stat.S_ISREG(mode):
                        files.append(_resolved_regular_file(root, member))
                    elif not stat.S_ISDIR(mode):
                        raise P6ArtifactTreeError("P6 artifact tree contains a special file")
        elif requested_path.is_file():
            files.append(_resolved_regular_file(root, requested_path))
        else:
            raise P6ArtifactTreeError("P6 artifact path is not a regular file or directory")
    if not files or len(set(files)) != len(files):
        raise P6ArtifactTreeError("P6 artifact file set is empty or duplicated")
    return tuple(sorted(files, key=lambda path: path.relative_to(root).as_posix()))


__all__ = [
    "P6ArtifactTreeError",
    "discover_regular_files",
    "revalidate_regular_file",
]
