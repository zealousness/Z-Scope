"""Inspection of committed snapshots, never a modeling or migration entrypoint."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from ..common.readonly import ReadonlyStateError, read_bytes, readonly_database
from ..common.utils import compute_code_hash
from ..reporting.shared_objects import decode_storage


class ReadonlySnapshotStore:
    def __init__(self, snapshot_dir: Path, *, project_root: Path | None = None):
        self.snapshot_dir = Path(snapshot_dir)
        self.project_root = project_root

    def inspect(self, index_name: str, source: Any = None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "missing",
            "reason": "snapshot_missing",
            "data": None,
            "hash": None,
        }
        try:
            root = self.project_root or self.snapshot_dir
            relative_dir = self.snapshot_dir.absolute().relative_to(root.absolute())
            with readonly_database(root, (relative_dir / "snapshots.db").as_posix()) as conn:
                row = conn.execute(
                    "SELECT * FROM snapshots WHERE index_name=?", (index_name,)
                ).fetchone()
                if row is None:
                    return result
                filename = str(row["snapshot_file"])
                try:
                    raw = read_bytes(root, (relative_dir / filename).as_posix())
                except FileNotFoundError:
                    return {**result, "status": "corrupt", "reason": "snapshot_payload_missing"}
                snapshot = decode_storage(json.loads(raw))
                if not isinstance(snapshot, dict) or snapshot.get("index_name") != index_name:
                    raise ValueError("snapshot_identity_mismatch")
                result.update(data=snapshot, hash=hashlib.sha256(raw).hexdigest())
                if source is not None:
                    code = source.read(str(row["file_path"]))[0].splitlines(keepends=True)
                    start, end = int(row["start_line"]), int(row["end_line"])
                    if (
                        start < 1
                        or end < start
                        or end > len(code)
                        or compute_code_hash("".join(code[start - 1 : end])) != row["code_hash"]
                    ):
                        result.update(status="stale", reason="source_changed", data=None)
                        return result
                # Legacy stores do not persist an independently verifiable full
                # input identity (headers/build/callee/manual/wiki/spec). A matching
                # function body or an unchanged DB is not proof of freshness.
                result.update(status="unverifiable", reason="complete_input_identity_unavailable")
                return result
        except FileNotFoundError:
            return result
        except (sqlite3.Error, ValueError, TypeError, KeyError, RecursionError):
            return {**result, "status": "corrupt", "reason": "invalid_snapshot_state", "data": None}
        except (OSError, ReadonlyStateError):
            return {
                **result,
                "status": "unavailable",
                "reason": "snapshot_state_unavailable",
                "data": None,
            }
        except Exception as exc:
            # SourceAccessError lives in tools; keep the persistence layer free
            # of a tools dependency and never expose a path or raw exception.
            if type(exc).__name__ != "SourceAccessError":
                raise
            return {
                **result,
                "status": "unverifiable",
                "reason": "source_unavailable",
                "data": None,
            }
