"""Bounded, project-locked source access shared by search and read tools.

No index, subprocess, model or persistent cache is used here. On POSIX every
component is opened relative to a pinned directory descriptor with NOFOLLOW.
On platforms without that primitive we fail closed rather than claim race safety.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from threading import RLock
from typing import Any

from ..common.cancellation import current_cancellation_token
from .contracts import invalid_request, page_result, tool_result
from .symbols import project_relative_path_error

_PRIVATE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".codex",
    ".claude",
    ".ssh",
    ".aws",
    ".azure",
    ".zscope",
    ".zscope_snapshots",
    ".zscope_knowledge",
    ".zscope-compile-commands",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "node_modules",
    ".venv",
    "venv",
    "reports",
    "report",
    "artifacts",
    "benchmark-artifacts",
    "release-evidence",
    "records",
    "handoffs",
    "truth",
    "ground_truth",
    "review-memory",
}
_PRIVATE_NAMES = {
    "agents.md",
    "agent.md",
    "claude.md",
    "gemini.md",
    "skill.md",
    "answer.md",
    "answers.md",
    "ground_truth.md",
    "ground_truth.json",
    "ground-truth.md",
    "ground-truth.json",
    "credentials",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "report.json",
    "report.md",
    "zscope_batch_report.json",
    "zscope_batch_report.md",
}
_SECRET = re.compile(
    r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|"
    r'(?i:"(?:api[_-]?key|password|secret|access_token)"\s*:\s*"(?!\$\{|\")[^\"]+)|'
    r"(?im:^\s*authorization\s*[:=]\s*(?:bearer|basic)\s+\S+)|"
    r"(?im:^\s*[\"']?(?:api[_-]?key|password|secret|access_token)[\"']?\s*[:=]\s*[\"']?"
    r"(?!\$\{|os\.|None\b|null\b|[\"']?\s*$)[^\s\"']+)"
)
_CONCLUSION_KEYS = {
    "findings",
    "ground_truth",
    "report_views",
    "candidate_ledger",
    "verdict",
    "user_rebuttal",
    "suspicious_points",
    "review_hints",
    "validation_reasoning",
    "policy_disposition",
    "model_verdict",
}


@dataclass(frozen=True)
class SearchLimits:
    entries: int = 20000
    files: int = 10000
    file_bytes: int = 2 * 1024 * 1024
    total_bytes: int = 64 * 1024 * 1024
    matches: int = 5000
    seconds: float = 5.0
    views: int = 4
    view_seconds: float = 300.0


class SourceAccessError(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def source_lines(text: str) -> list[str]:
    """Split physical CR/LF source lines, retaining their original terminators."""
    # The final empty EOF match is not a physical source line.
    return re.findall(r"[^\r\n]*(?:\r\n|\r|\n|$)", text)[:-1]


class ProjectSourceAccess:
    def __init__(self, root: Path, *, excluded: Any = (), limits: SearchLimits | None = None):
        self.root = Path(root).resolve()
        self.excluded = tuple((self.root / p).resolve() for p in (excluded or ()))
        try:
            root_stat = self.root.stat()
            self._root_identity: tuple[int, int] | None = (root_stat.st_dev, root_stat.st_ino)
        except OSError:
            self._root_identity = None
        self.limits = limits or SearchLimits()
        self._views: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._lock = RLock()

    @classmethod
    def for_index(cls, index: Any) -> ProjectSourceAccess | None:
        root = getattr(index, "project_root", None)
        return (
            cls(Path(root), excluded=getattr(index, "exclude_paths", ()))
            if isinstance(root, (str, Path))
            else None
        )

    def allowed(self, relative: str) -> bool:
        if project_relative_path_error(relative):
            return False
        path = PurePosixPath(relative.replace("\\", "/"))
        parts = {p.lower() for p in path.parts}
        name = path.name.lower()
        if parts & _PRIVATE_DIRS or name in _PRIVATE_NAMES:
            return False
        if (
            name == ".env"
            or name.startswith(".env.")
            or name.endswith(
                (".env", ".pem", ".key", ".p12", ".pfx", ".sarif", ".db", ".sqlite", ".sqlite3")
            )
        ):
            return False
        if any(
            word in name
            for word in (
                "ground_truth",
                "ground-truth",
                "scan-report",
                "batch-report",
                "model_trace",
                "model-trace",
            )
        ):
            return False
        absolute = self.root.joinpath(*path.parts)
        return not any(absolute == p or p in absolute.parents for p in self.excluded)

    def _open(self, relative: str, *, directory: bool = False) -> int:
        if relative and not self.allowed(relative):
            raise SourceAccessError("corpus_denied")
        if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
            raise SourceAccessError("secure_read_unavailable")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(self.root, flags | os.O_DIRECTORY)
        try:
            root_stat = os.fstat(fd)
            if (root_stat.st_dev, root_stat.st_ino) != self._root_identity:
                raise SourceAccessError("project_root_changed")
            parts = PurePosixPath(relative.replace("\\", "/")).parts if relative else ()
            for i, part in enumerate(parts):
                child = os.open(
                    part,
                    flags | (os.O_DIRECTORY if directory or i < len(parts) - 1 else 0),
                    dir_fd=fd,
                )
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    def identity(self, relative: str, *, directory: bool = False) -> tuple[int, ...]:
        try:
            fd = self._open(relative, directory=directory)
            try:
                return file_identity(os.fstat(fd))
            finally:
                os.close(fd)
        except OSError:
            raise SourceAccessError("file_unavailable") from None

    def read(
        self, relative: str, *, max_bytes: int | None = None
    ) -> tuple[str, str, tuple[int, ...]]:
        limit = self.limits.file_bytes if max_bytes is None else max_bytes
        try:
            fd = self._open(relative)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise SourceAccessError("not_regular_file")
                if before.st_size > limit:
                    raise SourceAccessError("file_byte_budget")
                raw = stream.read(limit + 1)
                after = os.fstat(stream.fileno())
                if len(raw) > limit:
                    raise SourceAccessError("file_byte_budget")
                if file_identity(before) != file_identity(after):
                    raise SourceAccessError("source_changed")
            if self.identity(relative) != file_identity(after):
                raise SourceAccessError("source_changed")
        except OSError:
            raise SourceAccessError("file_unavailable") from None
        if b"\x00" in raw:
            raise SourceAccessError("binary_file")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise SourceAccessError("invalid_utf8") from None
        if _SECRET.search(text):
            raise SourceAccessError("sensitive_content")
        if PurePosixPath(relative).suffix.lower() in {".json", ".jsonl", ".yaml", ".yml", ".md"}:
            # Typed serialization keys, not ordinary words in source code.
            if re.search(
                r'(?m)(?:^|[\{\[,])\s*["\']?(?:'
                + "|".join(sorted(_CONCLUSION_KEYS))
                + r')["\']?\s*:',
                text,
            ):
                raise SourceAccessError("conclusion_artifact")
            if PurePosixPath(relative).suffix.lower() == ".json":
                try:
                    obj = json.loads(text)
                    if isinstance(obj, dict) and _CONCLUSION_KEYS.intersection(obj):
                        raise SourceAccessError("conclusion_artifact")
                except (ValueError, RecursionError):
                    pass
        return text, hashlib.sha256(raw).hexdigest(), file_identity(after)

    def snippet(self, relative: str, start: int, end: int, max_lines: int) -> dict[str, Any] | None:
        text, revision, _ = self.read(relative)
        lines = source_lines(text)
        if start > len(lines):
            return None
        stop = min(len(lines), end, start + max_lines - 1)
        return {
            "file": relative.replace("\\", "/"),
            "start_line": start,
            "end_line": stop,
            "code": "".join(
                f"{i} | {line}" for i, line in enumerate(lines[start - 1 : stop], start)
            ),
            "total_lines": len(lines),
            "truncated": stop < min(end, len(lines)),
            "revision": revision,
        }

    def search(self, arguments: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            return self._search(arguments)

    def _search(self, arguments: dict[str, Any]) -> dict[str, Any]:
        scope = str(arguments["scope"])
        query = str(arguments["query"])
        prefix = PurePosixPath(
            str(arguments.get("path_prefix") or "").replace("\\", "/")
        ).as_posix()
        prefix = "" if prefix == "." else prefix
        identity = (scope, query, prefix, tuple(map(str, self.excluded)))
        offset, limit = int(arguments.get("offset", 0)), int(arguments.get("limit", 20))
        view_id = arguments.get("view_id")
        if view_id:
            view = self._views.get(view_id)
            if (
                view is None
                or view["query"] != identity
                or time.monotonic() - view["created"] > self.limits.view_seconds
                or not self._unchanged(view)
            ):
                self._views.pop(view_id, None)
                return invalid_request(
                    code="search_view_expired",
                    path="view_id",
                    message="Search view changed or expired; restart with offset=0 and no view_id.",
                )
        else:
            if offset:
                return invalid_request(
                    code="search_view_required",
                    path="view_id",
                    message="Continue text/files searches with the returned view_id.",
                )
            view = self._scan(scope, query, prefix)
            view["query"] = identity
            view["created"] = time.monotonic()
            view_id = hashlib.sha256(
                repr((identity, view["watched"], view["created"])).encode()
            ).hexdigest()
            self._views[view_id] = view
            while len(self._views) > self.limits.views:
                self._views.popitem(last=False)
        matches = view["matches"]
        selected = matches[offset : offset + limit]
        missing = sorted(view["missing"])
        return tool_result(
            status="partial" if missing else ("ok" if matches else "not_found"),
            data={"symbols": [], "scope": scope, "matches": selected, "view_id": view_id},
            providers=["project_text"],
            missing=missing,
            coverage_details={
                "corpus_complete": not missing,
                "scanned_files": view["files"],
                "scanned_bytes": view["bytes"],
                "visited_entries": view["entries"],
                "last_scanned_path": view["last"],
                "excluded_count": view["excluded"],
                "result_total_is_corpus_total": not missing,
            },
            page=page_result(offset, limit, len(selected), len(matches)),
            next_actions=(
                [
                    "Narrow path_prefix or query and restart; paging these matches does not resume corpus scanning."
                ]
                if missing
                else []
            ),
        )

    def _unchanged(self, view: dict[str, Any]) -> bool:
        try:
            return all(
                self.identity(path, directory=is_dir) == expected
                for path, is_dir, expected in view["watched"]
            )
        except SourceAccessError:
            return False

    def _scan(self, scope: str, query: str, prefix: str) -> dict[str, Any]:
        view: dict[str, Any] = {
            "matches": [],
            "watched": [],
            "missing": set(),
            "files": 0,
            "bytes": 0,
            "entries": 0,
            "last": "",
            "excluded": 0,
        }
        deadline = time.monotonic() + self.limits.seconds
        stack = [""]
        stop = False
        while stack and not stop:
            token = current_cancellation_token()
            if token is not None:
                token.raise_if_cancelled()
            directory = stack.pop()
            try:
                fd = self._open(directory, directory=True)
                try:
                    view["watched"].append((directory, True, file_identity(os.fstat(fd))))
                    names = []
                    with os.scandir(fd) as entries:
                        for entry in entries:
                            view["entries"] += 1
                            if view["entries"] > self.limits.entries or time.monotonic() > deadline:
                                view["missing"].add(
                                    "entry_budget"
                                    if view["entries"] > self.limits.entries
                                    else "time_budget"
                                )
                                stop = True
                                break
                            names.append(
                                (
                                    entry.name,
                                    entry.is_dir(follow_symlinks=False),
                                    entry.is_symlink(),
                                )
                            )
                finally:
                    os.close(fd)
            except (OSError, SourceAccessError):
                view["missing"].add("directory_unavailable")
                continue
            for name, is_dir, is_link in sorted(names):
                if token is not None:
                    token.raise_if_cancelled()
                relative = f"{directory}/{name}" if directory else name
                if not self.allowed(relative):
                    view["excluded"] += 1
                    continue
                if prefix and not (
                    relative == prefix
                    or relative.startswith(prefix + "/")
                    or (is_dir and prefix.startswith(relative + "/"))
                ):
                    continue
                if is_link:
                    view["missing"].add("symlink_excluded")
                    continue
                if is_dir:
                    stack.append(relative)
                    continue
                if (
                    view["files"] >= self.limits.files
                    or view["bytes"] >= self.limits.total_bytes
                    or time.monotonic() > deadline
                ):
                    reason = (
                        "file_budget"
                        if view["files"] >= self.limits.files
                        else (
                            "byte_budget"
                            if view["bytes"] >= self.limits.total_bytes
                            else "time_budget"
                        )
                    )
                    view["missing"].add(reason)
                    stop = True
                    break
                view["files"] += 1
                view["last"] = relative
                try:
                    before = self.identity(relative)
                    view["watched"].append((relative, False, before))
                    remaining = min(self.limits.file_bytes, self.limits.total_bytes - view["bytes"])
                    # Charge attempted bytes too, including rejected files.
                    view["bytes"] += min(before[3], remaining)
                    text, revision, _ = self.read(relative, max_bytes=remaining)
                except SourceAccessError as exc:
                    if exc.reason in {
                        "sensitive_content",
                        "conclusion_artifact",
                        "corpus_denied",
                        "binary_file",
                    }:
                        view["excluded"] += 1
                    else:
                        view["missing"].add(exc.reason)
                    continue
                rows: list[tuple[int | None, int | None, str]] = (
                    [(None, None, relative)] if scope == "files" and query in relative else []
                )
                if scope == "text":
                    for line, value in enumerate(source_lines(text), 1):
                        value = value.rstrip("\r\n")
                        column = value.find(query)
                        if column >= 0:
                            begin = max(0, column - 100)
                            rows.append((line, column + 1, value[begin : begin + 512]))
                            if len(rows) + len(view["matches"]) >= self.limits.matches:
                                break
                        if time.monotonic() > deadline:
                            view["missing"].add("time_budget")
                            stop = True
                            break
                for hit_line, hit_column, snippet in rows:
                    view["matches"].append(
                        {
                            "file": relative,
                            "line": hit_line,
                            "column": hit_column,
                            "text": snippet,
                            "revision": revision,
                        }
                    )
                if len(view["matches"]) >= self.limits.matches:
                    view["missing"].add("match_budget")
                    stop = True
                    break
        view["matches"].sort(key=lambda row: (row["file"], row["line"] or 0, row["column"] or 0))
        if not self._unchanged(view):
            view["matches"] = []
            view["missing"].add("source_changed")
        return view
