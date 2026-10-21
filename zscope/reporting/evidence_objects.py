"""Transactional, append-only shared evidence for immutable checkpoints."""

from __future__ import annotations
import json
from contextlib import closing
from pathlib import Path
import sqlite3
import threading
from typing import Any
from .shared_objects import ObjectEncoder, ObjectDecoder, STORAGE_SCHEMA


class _CheckpointEncoder(ObjectEncoder):
    """References may reuse committed nodes in this specific external store.

    The ordinary report encoder still emits a self-contained object table.
    Only immutable decoder-backed nodes can take this path; edited views are
    encoded normally, and fresh stores receive the complete dependency graph.
    """

    def __init__(self, stored: frozenset[str]) -> None:
        super().__init__()
        self._stored = stored

    def _import_refs(self, node: Any, decoder: Any) -> None:
        if node[0] == "ref" and node[1] in self._stored:
            return
        super()._import_refs(node, decoder)


class EvidenceObjectStore:
    _guard = threading.RLock()
    _known: dict[str, set[str]] = {}

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / "objects.sqlite3"

    def put(self, value: Any) -> dict[str, Any]:
        with self._guard:
            prior_key = (
                str(self.path.resolve()) + ":" + str(self.path.stat().st_ino)
                if self.path.exists() else None
            )
            stored = frozenset(self._known.get(prior_key, ())) if prior_key else frozenset()
        encoder: ObjectEncoder = _CheckpointEncoder(stored)
        encoded = encoder.envelope(value)
        with self._guard, closing(sqlite3.connect(self.path, timeout=60)) as db:
            key = str(self.path.resolve()) + ":" + str(self.path.stat().st_ino)
            if key != prior_key and stored:
                # A replaced database cannot inherit another inode's references.
                encoder = ObjectEncoder()
                encoded = encoder.envelope(value)
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS objects (digest TEXT PRIMARY KEY, node TEXT NOT NULL)"
            )
            known = self._known.setdefault(key, set())
            missing = [
                (uid, json.dumps(node, ensure_ascii=False, separators=(",", ":")))
                for uid, node in encoder.objects.items()
                if uid not in known
            ]
            db.executemany("INSERT OR IGNORE INTO objects VALUES (?, ?)", missing)
            db.commit()
            known.update(uid for uid, _ in missing)
        return {"storage_schema": STORAGE_SCHEMA, "root": encoded["root"]}

    def get(self, reference: dict[str, Any]) -> Any:
        objects: dict[str, Any] = {}
        pending: set[str] = set()

        def references(node: Any) -> None:
            if not isinstance(node, list) or len(node) != 2:
                raise ValueError("invalid evidence object")
            kind, body = node
            if kind == "ref":
                if body not in objects:
                    pending.add(body)
            elif kind == "map":
                for _, child in body:
                    references(child)
            elif kind == "list":
                for child in body:
                    references(child)

        references(reference.get("root"))
        with closing(sqlite3.connect(f"file:{self.path.as_posix()}?mode=ro", uri=True)) as db:
            while pending:
                batch = list(pending)[:500]
                pending.difference_update(batch)
                rows = db.execute(
                    "SELECT digest,node FROM objects WHERE digest IN ("
                    + ",".join("?" for _ in batch)
                    + ")",
                    batch,
                ).fetchall()
                if len(rows) != len(batch):
                    raise ValueError("missing checkpoint evidence")
                for uid, raw in rows:
                    objects[uid] = json.loads(raw)
                for uid, _ in rows:
                    references(objects[uid])
        return ObjectDecoder({**reference, "objects": objects}).root
