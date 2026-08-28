"""Deterministic freshness, incremental closure, conflict and lock helpers."""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

from .identity import stable_id
from .models import SourceManifest
from .source_index import SourceIndex


@dataclass(frozen=True)
class SourceDelta:
    added_source_ids: Tuple[str, ...]
    changed_source_ids: Tuple[str, ...]
    removed_source_ids: Tuple[str, ...]


def _sources(manifest: Union[SourceManifest, Mapping[str, Any]]) -> Dict[str, Dict[str, Any]]:
    if isinstance(manifest, SourceManifest):
        return {
            item.source_id: {
                "relative_path": item.relative_path,
                "content_digest": item.content_digest,
                "module_hints": item.module_hints,
            }
            for item in manifest.accepted
        }
    return {str(item["source_id"]): dict(item) for item in manifest.get("accepted", ())}


def compare_manifests(
    previous: Union[SourceManifest, Mapping[str, Any]],
    current: Union[SourceManifest, Mapping[str, Any]],
) -> SourceDelta:
    old = _sources(previous)
    new = _sources(current)
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(
        source_id
        for source_id in set(old) & set(new)
        if old[source_id].get("content_digest") != new[source_id].get("content_digest")
        or old[source_id].get("relative_path") != new[source_id].get("relative_path")
    )
    return SourceDelta(tuple(added), tuple(changed), tuple(removed))


def dirty_page_closure(
    delta: SourceDelta,
    *,
    source_to_pages: Mapping[str, Sequence[str]],
    project_page_id: str,
    page_dependencies: Optional[Mapping[str, Sequence[str]]] = None,
) -> Tuple[str, ...]:
    """Return stable source -> page -> dependent-page closure."""

    normalized_project_page_id = str(project_page_id or "").strip()
    if not normalized_project_page_id:
        raise ValueError("project_page_id is required")
    dirty: Set[str] = {normalized_project_page_id}
    for source_id in (
        *delta.added_source_ids,
        *delta.changed_source_ids,
        *delta.removed_source_ids,
    ):
        dirty.update(source_to_pages.get(source_id, ()))
    dependencies = page_dependencies or {}
    changed = True
    while changed:
        changed = False
        for page_id, parents in dependencies.items():
            if page_id in dirty:
                continue
            if any(parent in dirty for parent in parents):
                dirty.add(page_id)
                changed = True
    return tuple(sorted(dirty))


def merge_constraint_proposals(
    existing: Sequence[Mapping[str, Any]], proposals: Sequence[Mapping[str, Any]]
) -> List[Dict[str, Any]]:
    """Merge same-slot equal values and preserve unequal values as conflicts."""

    result = [dict(item) for item in existing]
    by_slot: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for item in result:
        subject = item.get("subject", {})
        slot = (
            str(subject.get("canonical_id", item.get("subject_id", ""))),
            str(item.get("kind", "")),
            json.dumps(item.get("scope", {}), sort_keys=True, ensure_ascii=False),
        )
        by_slot.setdefault(slot, []).append(item)
    for proposal in proposals:
        item = dict(proposal)
        subject = item.get("subject", {})
        slot = (
            str(subject.get("canonical_id", item.get("subject_id", ""))),
            str(item.get("kind", "")),
            json.dumps(item.get("scope", {}), sort_keys=True, ensure_ascii=False),
        )
        matches = by_slot.setdefault(slot, [])
        same = next(
            (
                candidate
                for candidate in matches
                if candidate.get("normalized_value") == item.get("normalized_value")
            ),
            None,
        )
        if same is not None:
            same["source_refs"] = sorted(
                set(same.get("source_refs", ())) | set(item.get("source_refs", ()))
            )
            same["page_refs"] = sorted(
                set(same.get("page_refs", ())) | set(item.get("page_refs", ()))
            )
            continue
        for conflict in matches:
            conflict["status"] = "conflicted"
            conflict.setdefault("conflicts_with", [])
            conflict["conflicts_with"] = sorted(
                set(conflict["conflicts_with"]) | {item.get("constraint_id")}
            )
            item.setdefault("conflicts_with", [])
            item["conflicts_with"] = sorted(
                set(item["conflicts_with"]) | {conflict.get("constraint_id")}
            )
            item["status"] = "conflicted"
        matches.append(item)
        result.append(item)
    return result


def propagate_stale(
    constraints: Sequence[Mapping[str, Any]],
    removed_source_ids: Iterable[str],
    *,
    source_ref_to_source: Optional[Mapping[str, str]] = None,
) -> List[Dict[str, Any]]:
    removed = set(removed_source_ids)
    ref_sources = dict(source_ref_to_source or {})
    result = []
    for item in constraints:
        copy = dict(item)
        refs = set(copy.get("source_refs", ()))
        supported_sources = {ref_sources.get(str(ref)) for ref in refs}
        if (
            refs & removed
            or supported_sources & removed
            or any(
                str(ref).startswith("docsrc_") and str(ref).split(":", 1)[0] in removed
                for ref in refs
            )
        ):
            copy["status"] = "stale"
        result.append(copy)
    return result


class WikiWriterLock:
    """Portable exclusive-create lock for project-level Wiki maintenance.

    The lock file is a tiny, self-describing JSON owner record.  A lock is
    recoverable only when its recorded PID is provably dead; malformed and
    symlinked lock files fail closed so a damaged state cannot be mistaken for
    an available writer slot.
    """

    SCHEMA_VERSION = "zscope.wiki-writer-lock.v1"
    _TOKEN = re.compile(r"^[0-9a-f]{32}$")

    def __init__(self, path: Union[Path, str], *, timeout_seconds: float = 0.0) -> None:
        self.path = Path(path)
        self.timeout_seconds = float(timeout_seconds)
        self._fd: Optional[int] = None
        self._token: Optional[str] = None

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        return True

    @classmethod
    def _read_owner(cls, path: Path) -> dict:
        if path.is_symlink():
            raise RuntimeError("Wiki writer lock must not be a symlink")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise RuntimeError("Wiki writer lock is unreadable") from exc
        if len(raw) > 4096:
            raise RuntimeError("Wiki writer lock exceeds size limit")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RuntimeError("Wiki writer lock is malformed") from exc
        if not isinstance(value, dict):
            raise RuntimeError("Wiki writer lock is malformed")
        if value.get("schema_version") != cls.SCHEMA_VERSION:
            raise RuntimeError("Wiki writer lock schema is unsupported")
        pid = value.get("pid")
        token = value.get("token")
        created_at = value.get("created_at")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise RuntimeError("Wiki writer lock owner PID is invalid")
        if not isinstance(token, str) or cls._TOKEN.fullmatch(token) is None:
            raise RuntimeError("Wiki writer lock owner token is invalid")
        if not isinstance(created_at, str) or not created_at or len(created_at) > 80:
            raise RuntimeError("Wiki writer lock timestamp is invalid")
        return {
            "schema_version": cls.SCHEMA_VERSION,
            "pid": pid,
            "token": token,
            "created_at": created_at,
        }

    def _write_owner(self, fd: int, owner: dict) -> None:
        payload = (json.dumps(owner, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("failed to write Wiki writer lock")
            view = view[written:]
        os.fsync(fd)

    def __enter__(self) -> "WikiWriterLock":
        if self.path.is_symlink() or self.path.parent.is_symlink():
            raise RuntimeError("Wiki writer lock path must not traverse symlinks")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + max(0.0, self.timeout_seconds)
        while True:
            try:
                flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                self._fd = os.open(self.path, flags, 0o600)
                self._token = uuid.uuid4().hex
                owner = {
                    "schema_version": self.SCHEMA_VERSION,
                    "pid": os.getpid(),
                    "token": self._token,
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                self._write_owner(self._fd, owner)
                return self
            except FileExistsError:
                owner = self._read_owner(self.path)
                if not self._pid_alive(int(owner["pid"])):
                    try:
                        self.path.unlink()
                    except FileNotFoundError:
                        continue
                    continue
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"Wiki writer lock is held: {self.path}")
                time.sleep(0.01)
            except Exception:
                if self._fd is not None:
                    os.close(self._fd)
                    self._fd = None
                    try:
                        self.path.unlink()
                    except FileNotFoundError:
                        pass
                self._token = None
                raise

    def __exit__(self, *_exc: Any) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        token = self._token
        self._token = None
        if not token or not self.path.exists() or self.path.is_symlink():
            return
        try:
            owner = self._read_owner(self.path)
        except RuntimeError:
            return
        if owner.get("pid") != os.getpid() or owner.get("token") != token:
            return
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


__all__ = [
    "SourceDelta",
    "compare_manifests",
    "dirty_page_closure",
    "merge_constraint_proposals",
    "propagate_stale",
    "WikiWriterLock",
]
