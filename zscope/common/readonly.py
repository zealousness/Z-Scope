"""Read checkpointed SQLite state without creating journals or migrating it.

An active WAL cannot safely be ignored by immutable SQLite; refuse that state.
The writer owns checkpointing. File descriptors pin every path component, and
identity is checked again after reading. No project files are created here.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Iterator

from .cancellation import current_cancellation_token


class ReadonlyStateError(Exception):
    pass


def open_beneath(root: Path, relative: str) -> int:
    parts = PurePosixPath(relative.replace("\\", "/")).parts
    if not parts or any(p in {"..", ".", "/"} or ":" in p for p in parts):
        raise ReadonlyStateError("invalid_state_path")
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise ReadonlyStateError("secure_read_unavailable")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(root, flags | os.O_DIRECTORY)
    try:
        for i, part in enumerate(parts):
            child = os.open(part, flags | (os.O_DIRECTORY if i < len(parts) - 1 else 0), dir_fd=fd)
            os.close(fd)
            fd = child
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ReadonlyStateError("invalid_state_file")
        return fd
    except BaseException:
        os.close(fd)
        raise


def identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_bytes(root: Path, relative: str, *, limit: int = 16 * 1024 * 1024) -> bytes:
    with os.fdopen(open_beneath(root, relative), "rb") as stream:
        before = identity(os.fstat(stream.fileno()))
        if before[2] > limit:
            raise ReadonlyStateError("state_byte_budget")
        data = stream.read(limit + 1)
        if len(data) > limit or identity(os.fstat(stream.fileno())) != before:
            raise ReadonlyStateError("state_changed")
        other = open_beneath(root, relative)
        try:
            if identity(os.fstat(other)) != before:
                raise ReadonlyStateError("state_changed")
        finally:
            os.close(other)
        return data


def _no_wal(root: Path, relative: str) -> None:
    try:
        fd = open_beneath(root, relative + "-wal")
    except FileNotFoundError:
        return
    os.close(fd)
    raise ReadonlyStateError("active_wal_unavailable")


@contextmanager
def readonly_database(root: Path, relative: str) -> Iterator[sqlite3.Connection]:
    _no_wal(root, relative)
    fd = open_beneath(root, relative)
    before = identity(os.fstat(fd))
    try:
        # Linux is the supported validation/runtime environment for this profile.
        conn = sqlite3.connect(f"file:/proc/self/fd/{fd}?mode=ro&immutable=1", uri=True)
        try:
            conn.row_factory = sqlite3.Row
            conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 16 * 1024 * 1024)
            conn.execute("PRAGMA query_only=ON")
            token = current_cancellation_token()
            if token is not None:
                conn.set_progress_handler(lambda: int(token.is_cancelled()), 1000)
            yield conn
            _no_wal(root, relative)
            other = open_beneath(root, relative)
            try:
                if identity(os.fstat(other)) != before or identity(os.fstat(fd)) != before:
                    raise ReadonlyStateError("state_changed")
            finally:
                os.close(other)
        finally:
            conn.close()
    finally:
        os.close(fd)
