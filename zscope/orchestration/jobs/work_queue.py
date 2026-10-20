"""Persistent work queue for one scan job (S08 JOB04/JOB06 queue core).

The queue is a small, self-contained SQLite data structure scoped to exactly
one ``job_id`` and one ``input_revision``.  It exists so a scan session can
stop accepting new work at the ``stop_at`` window (JOB04) and drain batches
with deduplicated identities, bounded attempts and age-ordered fairness
(JOB06) while every state transition survives process restarts.

Proposed API (implemented below):

* ``WorkQueue(db_path, *, job_id, input_revision, ...)`` opens (or creates)
  the queue; a different ``job_id`` or ``input_revision`` is rejected.
* ``enqueue(items, batch_no)`` adds work; ``batch_no`` must be exactly the
  batch after the highest batch ever claimed, so new discoveries can only
  enter the next batch.
* ``claim_batch(max_items, now=None, stop_time=None)`` claims work inside one
  IMMEDIATE transaction; at or after ``stop_time`` it claims nothing.
* ``complete(item_id, claim_token)`` / ``defer(item_id, reason, claim_token)``
  finish claimed work bound to the *current* claim: the token is a required
  argument and must match the assigned claim, so a stale claimant cannot
  finish work whose lease was re-assigned.  They keep working after the
  window closed so already claimed work can finish bounded.
* ``settle(item_id, action, claim_token, discoveries, ...)`` commits one
  verdict *and* every acceptable discovered child in a single transaction:
  a process exit can no longer land between a durable parent verdict and
  its children, any child-enqueue failure rolls the parent's verdict back,
  and batch/capacity bounds replace the verdict with an explicit deferral
  (``discovery_batch_limit`` / ``discovery_queue_limit``) so the obligation
  stays unresolved instead of silently losing the child.
* ``snapshot(now=None)`` returns the machine payload with real counts and the
  real remaining item identities/reasons.
* ``recover(new_input_revision)`` re-binds the queue after an input change,
  re-pending previously completed/failed/deferred/active items instead of
  granting old completions.  ``WorkQueue.open_for_recovery(...)`` is the
  restart entry point for a queue recorded under an older revision.

Guarantees held by this module alone:

* Scope.  The database records ``job_id``/``input_revision`` and the persisted
  bounds (``max_attempts``/``max_batches``); opening with different values is
  a conflict, an unknown input revision is rejected until an explicit
  recovery re-binds it.
* Identity.  Work identity is ``(kind, scope_key, build)``.  An unknown build
  (``None``) is kept in its own sentinel slot and never wildcards across
  builds; re-enqueueing an existing identity is a reported duplicate, never a
  retry.  Without a new input revision the same identity is not re-attempted.
* Honesty.  Completion only happens through an explicit active->completed
  transition bound to the current claim token; a crashed owner leaves its
  item active under the stored lease and nothing fabricates a completion,
  and an owner whose lease was re-assigned cannot complete or defer the
  work with or without its old token.  Reopening reads the real queue and
  lease state; snapshots report real counts, remaining identities and
  deferral/failure reasons.
* Bounds.  Attempts per item, batch chain length, deferral backoff, payload
  size, enqueue size and total queue size are bounded, so discovery chains
  cannot recurse without limit and difficult items cannot loop forever.

Explicitly NOT provided here (kept out on purpose): this queue does not wire
into ``scan_session``/``ParallelAnalyzer``, does not start, cancel or kill any
scanner or LLM work, and does not interpret or execute item payloads.  Item
payloads are opaque structured data validated for shape and size only; no
commands, argv, receipts or credentials are stored or run by this module.
The coordinator owns the shared-session wiring; consumers of the old
``stop_at`` report projection stay pending until then.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence

from .models import JobError, epoch_to_iso

WORK_QUEUE_SCHEMA = "zscope.scan-job-work-queue.v1"
WORK_QUEUE_SCHEMA_VERSION = 1

#: Sentinel build key for work whose exact build identity is not established.
#: It is a slot of its own: unknown-build items deduplicate among themselves
#: but never merge with, or wildcard over, any concrete build key.
UNKNOWN_BUILD_KEY = ""

ITEM_STATUSES = ("pending", "active", "completed", "deferred", "failed")
UNRESOLVED_STATUSES = ("pending", "active", "deferred")

_MAX_JOB_ID_CHARS = 128
_MAX_INPUT_REVISION_CHARS = 256
_MAX_PROJECT_ROOT_CHARS = 1024
_MAX_KIND_CHARS = 128
_MAX_SCOPE_KEY_CHARS = 512
_MAX_BUILD_CHARS = 256
_MAX_REASON_CHARS = 512
_MAX_PAYLOAD_CHARS = 8192
_MAX_ENQUEUE_ITEMS = 5000
_MAX_QUEUE_ITEMS = 100_000
_MAX_CLAIM_ITEMS = 1000
_MAX_RETRY_AFTER_SECONDS = 86_400.0
_SNAPSHOT_LIST_LIMIT = 2000
_RECOVERY_LOG_LIMIT = 50

_ITEM_KEYS = frozenset({"kind", "scope_key", "build", "payload"})


def read_bound_queue_counts(
    db_path: Path | str, *, job_id: str, input_revision: str
) -> Optional[Dict[str, int]]:
    """Read measured counts without creating, recovering or changing a queue.

    The detached owner uses this after the scanner exits. A report's business
    questions and a pending JSON sample are not measurements of queue work.
    Missing, damaged or differently bound queues remain unknown.
    """

    if not job_id or not input_revision:
        return None
    connection: Optional[sqlite3.Connection] = None
    try:
        connection = sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=ro", uri=True)
        connection.execute("BEGIN")
        meta = dict(connection.execute("SELECT key, value FROM meta"))
        if (
            meta.get("schema_id") != WORK_QUEUE_SCHEMA
            or meta.get("schema_version") != str(WORK_QUEUE_SCHEMA_VERSION)
            or meta.get("job_id") != job_id
            or meta.get("input_revision") != input_revision
        ):
            return None
        counts = {status: 0 for status in ITEM_STATUSES}
        for status, count in connection.execute(
            "SELECT status, COUNT(*) FROM items GROUP BY status"
        ):
            if status not in counts:
                return None
            counts[status] = int(count)
        return counts
    except (OSError, ValueError, sqlite3.Error):
        return None
    finally:
        if connection is not None:
            connection.close()


_FAIL_REASON_EXHAUSTED = "max_attempts_exhausted"

#: Deferral reasons used when discovered children cannot be accepted under
#: the persisted bounds; the parent obligation stays unresolved instead of
#: being completed with its children silently lost.
DEFER_REASON_DISCOVERY_BATCH_LIMIT = "discovery_batch_limit"
DEFER_REASON_DISCOVERY_QUEUE_LIMIT = "discovery_queue_limit"

_SQLITE_PRAGMA_LOCK = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS items (
    item_id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    scope_key TEXT NOT NULL,
    build_key TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    batch_no INTEGER NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    attempts INTEGER NOT NULL DEFAULT 0,
    total_attempts INTEGER NOT NULL DEFAULT 0,
    deferred_count INTEGER NOT NULL DEFAULT 0,
    next_eligible_at REAL,
    claim_token TEXT,
    claim_expires_at REAL,
    claimed_at REAL,
    completed_at REAL,
    last_defer_reason TEXT,
    last_deferred_at REAL,
    fail_reason TEXT,
    failed_at REAL,
    revoked_from_status TEXT,
    revoked_at REAL,
    enqueued_epoch REAL NOT NULL,
    last_touched_epoch REAL NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (kind, scope_key, build_key)
);
CREATE INDEX IF NOT EXISTS idx_items_status ON items(status);
CREATE TABLE IF NOT EXISTS recoveries (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    from_input_revision TEXT NOT NULL,
    to_input_revision TEXT NOT NULL,
    re_pended INTEGER NOT NULL
);
"""

# Deferred items parked on a persisted discovery bound: their handler
# finished but its children cannot be scheduled under max_batches / the
# queue capacity, so the obligation must stay durable unresolved work.
# They are neither claimable (retrying the handler cannot change the
# bounds) nor attempt-exhausted into ``failed``; only an explicit input
# recovery re-verifies them.
_DISCOVERY_BLOCK_REASONS = (DEFER_REASON_DISCOVERY_BATCH_LIMIT, DEFER_REASON_DISCOVERY_QUEUE_LIMIT)
_PARKED_SQL = "(status = 'deferred' AND last_defer_reason IN (:blocked_batch, :blocked_queue))"

# Candidate predicate for claimability: plain pending items, deferred items
# whose backoff elapsed (except discovery-bound parked ones), and active
# items whose lease expired (the owner may have crashed; the lease is the
# only honest evidence we keep).
_CANDIDATE_SQL = (
    "(status = 'pending') "
    "OR (status = 'deferred' AND last_defer_reason NOT IN "
    "(:blocked_batch, :blocked_queue) "
    "AND (next_eligible_at IS NULL OR next_eligible_at <= :now)) "
    "OR (status = 'active' AND claim_expires_at IS NOT NULL AND claim_expires_at <= :now)"
)


# -- validation helpers ------------------------------------------------------


def _require_text(value: Any, *, field: str, max_chars: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise JobError("invalid_request", f"{field} must be a non-empty string", status_code=400)
    if len(value) > max_chars:
        raise JobError(
            "invalid_request",
            f"{field} must be at most {max_chars} characters",
            status_code=400,
        )
    return value


def _require_int(value: Any, *, field: str, minimum: int, maximum: Optional[int] = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise JobError("invalid_request", f"{field} must be an integer", status_code=400)
    if value < minimum:
        raise JobError("invalid_request", f"{field} must be at least {minimum}", status_code=400)
    if maximum is not None and value > maximum:
        raise JobError("invalid_request", f"{field} must be at most {maximum}", status_code=400)
    return int(value)


def _require_epoch(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise JobError("invalid_request", f"{field} must be a number", status_code=400)
    return float(value)


def _require_positive_float(value: Any, *, field: str, minimum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise JobError("invalid_request", f"{field} must be a number", status_code=400)
    number = float(value)
    if number < minimum:
        raise JobError("invalid_request", f"{field} must be at least {minimum}", status_code=400)
    return number


def _parse_item(raw: Any) -> Dict[str, Any]:
    """Validate one enqueue entry; only known structured fields are accepted."""

    if not isinstance(raw, dict):
        raise JobError("invalid_request", "each item must be a JSON object", status_code=400)
    unknown = sorted(set(raw) - _ITEM_KEYS)
    if unknown:
        raise JobError(
            "invalid_request",
            "item fields are limited to kind, scope_key, build, payload; "
            f"got unknown field(s): {', '.join(unknown)}",
            status_code=400,
        )
    kind = _require_text(raw.get("kind"), field="item.kind", max_chars=_MAX_KIND_CHARS)
    scope_key = _require_text(
        raw.get("scope_key"), field="item.scope_key", max_chars=_MAX_SCOPE_KEY_CHARS
    )
    build = raw.get("build")
    if build is None:
        build_key = UNKNOWN_BUILD_KEY
    else:
        build = _require_text(build, field="item.build", max_chars=_MAX_BUILD_CHARS)
        build_key = build
    payload = raw.get("payload")
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise JobError("invalid_request", "item.payload must be a JSON object", status_code=400)
    try:
        encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise JobError(
            "invalid_request", f"item.payload is not finite JSON data: {exc}", status_code=400
        ) from exc
    if len(encoded) > _MAX_PAYLOAD_CHARS:
        raise JobError(
            "invalid_request",
            f"item.payload must encode to at most {_MAX_PAYLOAD_CHARS} characters",
            status_code=400,
        )
    return {
        "kind": kind,
        "scope_key": scope_key,
        "build": build,
        "build_key": build_key,
        "payload_json": encoded,
    }


def _decode_payload(raw: Any) -> Dict[str, Any]:
    try:
        decoded = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _identity_of(row: sqlite3.Row) -> Dict[str, Any]:
    build_key = row["build_key"]
    return {
        "item_id": int(row["item_id"]),
        "kind": row["kind"],
        "scope_key": row["scope_key"],
        "build": None if build_key == UNKNOWN_BUILD_KEY else build_key,
    }


def _open_connection(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(db_path), timeout=30.0, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 30000")
    with _SQLITE_PRAGMA_LOCK:
        try:
            connection.execute("PRAGMA journal_mode = WAL")
        except sqlite3.OperationalError:
            # Another connection is switching journal mode; correctness comes
            # from busy_timeout, WAL itself is best effort here.
            pass
    connection.execute("PRAGMA synchronous = NORMAL")
    return connection


def _read_meta_map(connection: sqlite3.Connection) -> Dict[str, str]:
    return {
        str(row["key"]): str(row["value"])
        for row in connection.execute("SELECT key, value FROM meta")
    }


def _read_frontier(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT value FROM meta WHERE key = 'frontier_batch'").fetchone()
    return int(row["value"]) if row is not None else 0


def _perform_recovery(
    connection: sqlite3.Connection, *, new_input_revision: str, now: float
) -> Dict[str, Any]:
    """Re-pend every non-pending item and re-bind the recorded input revision.

    Old completions are revoked rather than granted: with a different input
    revision the previous verdicts are stale, so the items return to pending
    with ``attempts``/``deferred_count`` reset while ``total_attempts`` keeps
    the cumulative audit trail.  The caller has already validated the job
    scope and that the new revision differs from the recorded one.
    """

    at = epoch_to_iso(now)
    by_status: Dict[str, int] = {}
    for row in connection.execute(
        "SELECT status, COUNT(*) AS n FROM items WHERE status != 'pending' GROUP BY status"
    ):
        by_status[str(row["status"])] = int(row["n"])
    re_pended = sum(by_status.values())
    old_row = connection.execute("SELECT value FROM meta WHERE key = 'input_revision'").fetchone()
    old_revision = str(old_row["value"]) if old_row is not None else ""
    connection.execute(
        "UPDATE items SET status = 'pending', attempts = 0, deferred_count = 0, "
        "next_eligible_at = NULL, claim_token = NULL, claim_expires_at = NULL, "
        "claimed_at = NULL, revoked_from_status = status, revoked_at = ?, "
        "last_touched_epoch = ?, updated_at = ? WHERE status != 'pending'",
        (now, now, at),
    )
    connection.execute(
        "UPDATE meta SET value = ? WHERE key = 'input_revision'", (new_input_revision,)
    )
    count_row = connection.execute("SELECT value FROM meta WHERE key = 'recovery_count'").fetchone()
    recovery_count = (int(count_row["value"]) if count_row is not None else 0) + 1
    connection.execute(
        "UPDATE meta SET value = ? WHERE key = 'recovery_count'", (str(recovery_count),)
    )
    connection.execute("UPDATE meta SET value = ? WHERE key = 'updated_at'", (at,))
    connection.execute(
        "INSERT INTO recoveries (at, from_input_revision, to_input_revision, re_pended) "
        "VALUES (?, ?, ?, ?)",
        (at, old_revision, new_input_revision, re_pended),
    )
    return {
        "from_input_revision": old_revision,
        "to_input_revision": new_input_revision,
        "re_pended": re_pended,
        "by_previous_status": by_status,
        "recovered_at": at,
    }


class WorkQueue:
    """WAL-backed persistent work queue for one ``job_id``/``input_revision``.

    Instances are safe for concurrent calls from multiple threads or
    processes: every operation opens its own connection and writes inside one
    ``BEGIN IMMEDIATE`` transaction, so claims never overlap.  Only
    :meth:`recover` mutates instance state (it re-binds the input revision of
    the instance that performed it).
    """

    def __init__(
        self,
        db_path: Path | str,
        *,
        job_id: str,
        input_revision: str,
        project_root: Optional[str] = None,
        max_attempts: int = 3,
        max_batches: int = 32,
        lease_seconds: float = 600.0,
        defer_base_seconds: float = 1.0,
        defer_max_seconds: float = 3600.0,
    ) -> None:
        self.db_path = Path(db_path)
        self.job_id = _require_text(job_id, field="job_id", max_chars=_MAX_JOB_ID_CHARS)
        self.input_revision = _require_text(
            input_revision, field="input_revision", max_chars=_MAX_INPUT_REVISION_CHARS
        )
        self.project_root: Optional[str] = None
        if project_root is not None:
            self.project_root = _require_text(
                str(project_root), field="project_root", max_chars=_MAX_PROJECT_ROOT_CHARS
            )
        self.max_attempts = _require_int(max_attempts, field="max_attempts", minimum=1)
        self.max_batches = _require_int(max_batches, field="max_batches", minimum=1)
        self.lease_seconds = _require_positive_float(
            lease_seconds, field="lease_seconds", minimum=0.001
        )
        self.defer_base_seconds = _require_positive_float(
            defer_base_seconds, field="defer_base_seconds", minimum=0.0
        )
        self.defer_max_seconds = _require_positive_float(
            defer_max_seconds, field="defer_max_seconds", minimum=0.0
        )
        if self.defer_max_seconds < self.defer_base_seconds:
            raise JobError(
                "invalid_request",
                "defer_max_seconds must be at least defer_base_seconds",
                status_code=400,
            )
        self._initialize_and_bind()

    # -- connection plumbing -------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        return _open_connection(self.db_path)

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    # -- scope / initialization -----------------------------------------------

    def _initialize_and_bind(self) -> None:
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise JobError(
                "queue_unavailable",
                f"cannot create work queue directory at {self.db_path.parent}: {exc}",
                status_code=503,
            ) from exc
        try:
            connection = self._connect()
        except sqlite3.Error as exc:
            raise JobError(
                "queue_unavailable",
                f"cannot open work queue at {self.db_path}: {exc}",
                status_code=503,
            ) from exc
        try:
            try:
                # Steady-state opens skip the DDL entirely: concurrent readers
                # never take a write lock just to reopen the queue.
                present = connection.execute(
                    "SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'table' "
                    "AND name IN ('meta', 'items', 'recoveries')"
                ).fetchone()
                if present is None or int(present["n"]) < 3:
                    connection.executescript(_SCHEMA)
            except sqlite3.Error as exc:
                raise JobError(
                    "queue_unavailable",
                    f"cannot initialize work queue at {self.db_path}: {exc}",
                    status_code=503,
                ) from exc
            try:
                connection.execute("BEGIN IMMEDIATE")
                meta = _read_meta_map(connection)
                if meta.get("schema_id"):
                    self._check_scope(meta)
                else:
                    now = time.time()
                    at = epoch_to_iso(now)
                    connection.executemany(
                        "INSERT INTO meta (key, value) VALUES (?, ?)",
                        [
                            ("schema_id", WORK_QUEUE_SCHEMA),
                            ("schema_version", str(WORK_QUEUE_SCHEMA_VERSION)),
                            ("job_id", self.job_id),
                            ("input_revision", self.input_revision),
                            ("project_root", self.project_root or ""),
                            ("max_attempts", str(self.max_attempts)),
                            ("max_batches", str(self.max_batches)),
                            ("frontier_batch", "0"),
                            ("recovery_count", "0"),
                            ("created_at", at),
                            ("updated_at", at),
                        ],
                    )
                connection.execute("COMMIT")
            except BaseException:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
        except JobError:
            raise
        except sqlite3.Error as exc:
            raise JobError(
                "queue_unavailable",
                f"cannot bind work queue at {self.db_path}: {exc}",
                status_code=503,
            ) from exc
        finally:
            connection.close()

    def _check_scope(self, meta: Dict[str, str]) -> None:
        recorded_job = meta.get("job_id", "")
        if recorded_job != self.job_id:
            raise JobError(
                "job_scope_mismatch",
                "work queue belongs to a different job",
                status_code=409,
                details={
                    "recorded_job_id": recorded_job,
                    "requested_job_id": self.job_id,
                },
            )
        recorded_revision = meta.get("input_revision", "")
        if recorded_revision != self.input_revision:
            raise JobError(
                "input_revision_mismatch",
                "work queue is bound to a different input revision; recover "
                "explicitly after a real input change",
                status_code=409,
                details={
                    "recorded_input_revision": recorded_revision,
                    "requested_input_revision": self.input_revision,
                },
            )
        for field, value in (
            ("max_attempts", self.max_attempts),
            ("max_batches", self.max_batches),
        ):
            recorded = meta.get(field)
            if recorded is not None and recorded != str(value):
                raise JobError(
                    "queue_bounds_mismatch",
                    f"{field} is part of the persisted queue bounds and cannot "
                    "change between opens",
                    status_code=409,
                    details={"field": field, "recorded": recorded, "requested": str(value)},
                )

    # -- public API -----------------------------------------------------------

    def enqueue(self, items: Sequence[Dict[str, Any]], *, batch_no: int) -> Dict[str, Any]:
        """Add work items to exactly the next batch.

        ``batch_no`` must equal ``frontier_batch + 1`` where the frontier is
        the highest batch ever claimed, so new discoveries can only enter the
        batch after the one currently being worked.  Items whose identity
        ``(kind, scope_key, build)`` already exists are reported as
        duplicates and are not re-enqueued or retried.
        """

        if not isinstance(items, (list, tuple)):
            raise JobError("invalid_request", "items must be a list of work items", status_code=400)
        if not items:
            raise JobError("invalid_request", "items must not be empty", status_code=400)
        if len(items) > _MAX_ENQUEUE_ITEMS:
            raise JobError(
                "invalid_request",
                f"at most {_MAX_ENQUEUE_ITEMS} items per enqueue",
                status_code=400,
            )
        parsed = [_parse_item(raw) for raw in items]
        batch_no = _require_int(batch_no, field="batch_no", minimum=1)
        if batch_no > self.max_batches:
            raise JobError(
                "batch_limit_exceeded",
                f"batch_no {batch_no} exceeds max_batches {self.max_batches}",
                status_code=409,
                details={"batch_no": batch_no, "max_batches": self.max_batches},
            )
        now = time.time()
        at = epoch_to_iso(now)
        try:
            with self._write() as connection:
                frontier = _read_frontier(connection)
                if batch_no != frontier + 1:
                    if frontier + 1 > self.max_batches:
                        raise JobError(
                            "batch_limit_exceeded",
                            "the discovery batch chain reached max_batches; "
                            "no further batch can be enqueued",
                            status_code=409,
                            details={"max_batches": self.max_batches, "frontier_batch": frontier},
                        )
                    raise JobError(
                        "invalid_request",
                        f"new work must target the next batch ({frontier + 1}); got {batch_no}",
                        status_code=400,
                        details={"frontier_batch": frontier, "batch_no": batch_no},
                    )
                count_row = connection.execute("SELECT COUNT(*) AS n FROM items").fetchone()
                existing = int(count_row["n"]) if count_row is not None else 0
                if existing + len(parsed) > _MAX_QUEUE_ITEMS:
                    raise JobError(
                        "queue_limit_exceeded",
                        f"work queue is limited to {_MAX_QUEUE_ITEMS} items",
                        status_code=409,
                        details={"current_items": existing},
                    )
                enqueued: List[Dict[str, Any]] = []
                duplicates: List[Dict[str, Any]] = []
                for item in parsed:
                    try:
                        cursor = connection.execute(
                            "INSERT INTO items (kind, scope_key, build_key, status, batch_no, "
                            "payload_json, attempts, total_attempts, deferred_count, "
                            "enqueued_epoch, last_touched_epoch, created_at, updated_at) "
                            "VALUES (?, ?, ?, 'pending', ?, ?, 0, 0, 0, ?, ?, ?, ?)",
                            (
                                item["kind"],
                                item["scope_key"],
                                item["build_key"],
                                batch_no,
                                item["payload_json"],
                                now,
                                now,
                                at,
                                at,
                            ),
                        )
                        enqueued.append(
                            {
                                "item_id": int(cursor.lastrowid or 0),
                                "kind": item["kind"],
                                "scope_key": item["scope_key"],
                                "build": item["build"],
                            }
                        )
                    except sqlite3.IntegrityError:
                        row = connection.execute(
                            "SELECT item_id, status FROM items "
                            "WHERE kind = ? AND scope_key = ? AND build_key = ?",
                            (item["kind"], item["scope_key"], item["build_key"]),
                        ).fetchone()
                        duplicates.append(
                            {
                                "kind": item["kind"],
                                "scope_key": item["scope_key"],
                                "build": item["build"],
                                "existing_item_id": int(row["item_id"]) if row else None,
                                "existing_status": str(row["status"]) if row else None,
                            }
                        )
                connection.execute("UPDATE meta SET value = ? WHERE key = 'updated_at'", (at,))
        except JobError:
            raise
        except sqlite3.Error as exc:
            raise JobError(
                "queue_unavailable", f"cannot enqueue work items: {exc}", status_code=503
            ) from exc
        return {
            "schema": WORK_QUEUE_SCHEMA,
            "batch_no": batch_no,
            "enqueued": enqueued,
            "duplicates": duplicates,
            "frontier_batch": frontier,
        }

    def claim_batch(
        self, max_items: int, *, now: Optional[float] = None, stop_time: Optional[float] = None
    ) -> Dict[str, Any]:
        """Claim up to ``max_items`` claimable items in one transaction.

        Claimable items are pending items, deferred items whose backoff
        elapsed and active items whose lease expired (a crashed owner).  When
        ``stop_time`` is given and ``now >= stop_time`` the window is closed:
        nothing is claimed and no state changes; already claimed work still
        finishes through :meth:`complete` / :meth:`defer`.

        Eligible items whose attempts are exhausted transition to ``failed``
        in the same transaction (reported as ``failed_exhausted``) instead of
        being claimed or skipped forever.  Selection order is batch number,
        then least-recently-touched, so older batches and long-waiting items
        are served first and difficult items are not starved by easy ones.
        """

        max_items = _require_int(max_items, field="max_items", minimum=1, maximum=_MAX_CLAIM_ITEMS)
        current = _require_epoch(now, field="now") if now is not None else time.time()
        if stop_time is not None:
            deadline = _require_epoch(stop_time, field="stop_time")
            if current >= deadline:
                return {"claimed": [], "window_closed": True, "failed_exhausted": []}
        try:
            with self._write() as connection:
                params: Dict[str, Any] = {
                    "now": current,
                    "max_attempts": self.max_attempts,
                    "blocked_batch": DEFER_REASON_DISCOVERY_BATCH_LIMIT,
                    "blocked_queue": DEFER_REASON_DISCOVERY_QUEUE_LIMIT,
                }
                # Discovery-bound parked items are not candidates at all, so
                # the attempt-exhaustion sweep can never turn them into a
                # fake execution failure.
                exhausted_rows = connection.execute(
                    f"SELECT item_id FROM items WHERE ({_CANDIDATE_SQL}) "
                    "AND attempts >= :max_attempts",
                    params,
                ).fetchall()
                failed_exhausted: List[int] = []
                if exhausted_rows:
                    failed_exhausted = [int(row["item_id"]) for row in exhausted_rows]
                    placeholders = ", ".join("?" for _ in failed_exhausted)
                    connection.execute(
                        "UPDATE items SET status = 'failed', fail_reason = ?, failed_at = ?, "
                        "claim_token = NULL, claim_expires_at = NULL, next_eligible_at = NULL, "
                        f"last_touched_epoch = ?, updated_at = ? "
                        f"WHERE item_id IN ({placeholders})",
                        (
                            _FAIL_REASON_EXHAUSTED,
                            current,
                            current,
                            epoch_to_iso(current),
                            *failed_exhausted,
                        ),
                    )
                rows = connection.execute(
                    f"SELECT * FROM items WHERE ({_CANDIDATE_SQL}) AND attempts < :max_attempts "
                    "ORDER BY batch_no ASC, last_touched_epoch ASC, item_id ASC "
                    "LIMIT :limit",
                    {**params, "limit": max_items},
                ).fetchall()
                claimed: List[Dict[str, Any]] = []
                max_batch_claimed = 0
                for row in rows:
                    token = uuid.uuid4().hex
                    expires = current + self.lease_seconds
                    connection.execute(
                        "UPDATE items SET status = 'active', attempts = attempts + 1, "
                        "total_attempts = total_attempts + 1, claim_token = ?, "
                        "claim_expires_at = ?, claimed_at = ?, next_eligible_at = NULL, "
                        "last_touched_epoch = ?, updated_at = ? WHERE item_id = ?",
                        (
                            token,
                            expires,
                            current,
                            current,
                            epoch_to_iso(current),
                            int(row["item_id"]),
                        ),
                    )
                    max_batch_claimed = max(max_batch_claimed, int(row["batch_no"]))
                    claimed.append(
                        {
                            **_identity_of(row),
                            "payload": _decode_payload(row["payload_json"]),
                            "batch_no": int(row["batch_no"]),
                            "attempts": int(row["attempts"]) + 1,
                            "total_attempts": int(row["total_attempts"]) + 1,
                            "deferred_count": int(row["deferred_count"]),
                            "last_defer_reason": row["last_defer_reason"],
                            "claim_token": token,
                            "claim_expires_at": expires,
                            "claim_expires_at_iso": epoch_to_iso(expires),
                        }
                    )
                if claimed:
                    frontier = _read_frontier(connection)
                    if max_batch_claimed > frontier:
                        connection.execute(
                            "UPDATE meta SET value = ? WHERE key = 'frontier_batch'",
                            (str(max_batch_claimed),),
                        )
        except JobError:
            raise
        except sqlite3.Error as exc:
            raise JobError(
                "queue_unavailable", f"cannot claim work items: {exc}", status_code=503
            ) from exc
        return {"claimed": claimed, "window_closed": False, "failed_exhausted": failed_exhausted}

    def _apply_complete_transition(
        self, connection: sqlite3.Connection, row: sqlite3.Row, *, now: float
    ) -> None:
        at = epoch_to_iso(now)
        connection.execute(
            "UPDATE items SET status = 'completed', completed_at = ?, "
            "claim_token = NULL, claim_expires_at = NULL, next_eligible_at = NULL, "
            "last_touched_epoch = ?, updated_at = ? WHERE item_id = ?",
            (now, now, at, int(row["item_id"])),
        )

    def _apply_defer_transition(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        reason: str,
        retry_after_seconds: Optional[float],
        now: float,
        bounded: bool = True,
    ) -> tuple[str, int, Optional[float]]:
        """Apply the defer transition; returns (status, deferred_count, next_eligible).

        With ``bounded=True`` (the handler path) an item whose attempts are
        exhausted transitions to ``failed``.  The discovery-bounds path passes
        ``bounded=False``: a parent whose children cannot be scheduled under
        the persisted bounds must stay an explicit unresolved obligation, not
        be failed into nothing by attempt accounting.
        """

        at = epoch_to_iso(now)
        item_id = int(row["item_id"])
        deferred_count = int(row["deferred_count"]) + 1
        if bounded and int(row["attempts"]) >= self.max_attempts:
            connection.execute(
                "UPDATE items SET status = 'failed', fail_reason = ?, failed_at = ?, "
                "deferred_count = ?, claim_token = NULL, claim_expires_at = NULL, "
                "next_eligible_at = NULL, last_touched_epoch = ?, updated_at = ? "
                "WHERE item_id = ?",
                (_FAIL_REASON_EXHAUSTED, now, deferred_count, now, at, item_id),
            )
            return ("failed", deferred_count, None)
        if retry_after_seconds is not None:
            backoff = float(retry_after_seconds)
        else:
            backoff = min(
                self.defer_base_seconds * (2 ** (deferred_count - 1)),
                self.defer_max_seconds,
            )
        next_eligible_at = now + backoff
        connection.execute(
            "UPDATE items SET status = 'deferred', deferred_count = ?, "
            "last_defer_reason = ?, last_deferred_at = ?, next_eligible_at = ?, "
            "claim_token = NULL, claim_expires_at = NULL, last_touched_epoch = ?, "
            "updated_at = ? WHERE item_id = ?",
            (deferred_count, reason, now, next_eligible_at, now, at, item_id),
        )
        return ("deferred", deferred_count, next_eligible_at)

    @staticmethod
    def _validate_retry_after(value: Any) -> Optional[float]:
        if value is None:
            return None
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or float(value) < 0
            or float(value) > _MAX_RETRY_AFTER_SECONDS
        ):
            raise JobError(
                "invalid_request",
                f"retry_after_seconds must be between 0 and {_MAX_RETRY_AFTER_SECONDS}",
                status_code=400,
            )
        return float(value)

    def complete(
        self, item_id: int, *, claim_token: str, now: Optional[float] = None
    ) -> Dict[str, Any]:
        """Finish a claimed item bound to its *current* claim.

        Only an active item can be completed and the claim token must match
        the claim that is currently assigned; a stale claimant (one whose
        lease expired and whose item was re-claimed) is rejected with or
        without its token, so a re-assigned lease cannot be completed by the
        previous owner.
        """

        item_id = _require_int(item_id, field="item_id", minimum=1)
        current = _require_epoch(now, field="now") if now is not None else time.time()
        at = epoch_to_iso(current)
        try:
            with self._write() as connection:
                row = self._active_item(connection, item_id, claim_token)
                self._apply_complete_transition(connection, row, now=current)
        except JobError:
            raise
        except sqlite3.Error as exc:
            raise JobError(
                "queue_unavailable", f"cannot complete item {item_id}: {exc}", status_code=503
            ) from exc
        return {
            **_identity_of(row),
            "status": "completed",
            "batch_no": int(row["batch_no"]),
            "attempts": int(row["attempts"]),
            "total_attempts": int(row["total_attempts"]),
            "deferred_count": int(row["deferred_count"]),
            "completed_at": current,
            "completed_at_iso": at,
        }

    def defer(
        self,
        item_id: int,
        reason: str,
        *,
        claim_token: str,
        retry_after_seconds: Optional[float] = None,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Return a claimed item to the deferred state with a bounded backoff.

        The deferral binds to the *current* claim: the claim token must match
        the assigned claim, so a stale claimant cannot defer work whose lease
        was re-assigned.  The deferral reason is persisted and shown in
        snapshots.  The backoff grows exponentially with the deferral count
        and is capped by ``defer_max_seconds``; an explicit
        ``retry_after_seconds`` overrides it.  When the claim already consumed
        ``max_attempts`` attempts the item transitions to ``failed`` instead
        of being deferred again.
        """

        item_id = _require_int(item_id, field="item_id", minimum=1)
        reason = _require_text(reason, field="reason", max_chars=_MAX_REASON_CHARS)
        current = _require_epoch(now, field="now") if now is not None else time.time()
        backoff_override = self._validate_retry_after(retry_after_seconds)
        at = epoch_to_iso(current)
        try:
            with self._write() as connection:
                row = self._active_item(connection, item_id, claim_token)
                status, deferred_count, next_eligible_at = self._apply_defer_transition(
                    connection,
                    row,
                    reason=reason,
                    retry_after_seconds=backoff_override,
                    now=current,
                )
        except JobError:
            raise
        except sqlite3.Error as exc:
            raise JobError(
                "queue_unavailable", f"cannot defer item {item_id}: {exc}", status_code=503
            ) from exc
        if status == "failed":
            return {
                **_identity_of(row),
                "status": "failed",
                "batch_no": int(row["batch_no"]),
                "attempts": int(row["attempts"]),
                "total_attempts": int(row["total_attempts"]),
                "deferred_count": deferred_count,
                "reason": _FAIL_REASON_EXHAUSTED,
                "failed_at": current,
                "failed_at_iso": at,
            }
        return {
            **_identity_of(row),
            "status": "deferred",
            "batch_no": int(row["batch_no"]),
            "attempts": int(row["attempts"]),
            "total_attempts": int(row["total_attempts"]),
            "deferred_count": deferred_count,
            "reason": reason,
            "next_eligible_at": next_eligible_at,
            "next_eligible_at_iso": (
                epoch_to_iso(next_eligible_at) if next_eligible_at is not None else None
            ),
        }

    def settle(
        self,
        item_id: int,
        *,
        action: str,
        claim_token: str,
        reason: Optional[str] = None,
        retry_after_seconds: Optional[float] = None,
        discoveries: Sequence[Dict[str, Any]] = (),
        expected_input_revision: Optional[str] = None,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Commit one verdict and its acceptable discoveries in ONE transaction.

        The verdict (``complete``/``defer`` bound to the *current* claim
        token) and the enqueue of every acceptable discovered child happen
        inside a single ``BEGIN IMMEDIATE`` transaction, so a process exit
        can no longer land between a durable parent verdict and its
        children.  Any child-enqueue failure rolls the parent's verdict
        back: a parent is never completed while its discovered work is lost.

        Rejections (the item is left unchanged under its claim, nothing
        written):

        * ``expected_input_revision`` that differs from the queue's recorded
          revision → 409 ``input_revision_mismatch``;
        * item not active, unknown, or a foreign claim token → the same
          404/409 codes as :meth:`complete` / :meth:`defer`;
        * malformed discovery items → 400 ``discovery_invalid`` (the handler
          replays on a later attempt; nothing is enqueued).

        Bounds: when the acceptable children would exceed ``max_batches`` or
        the queue capacity, the requested verdict is *replaced* by a deferral
        with reason ``discovery_batch_limit`` / ``discovery_queue_limit`` and
        the result reports ``discovery_blocked`` — the parent stays an
        explicit unresolved obligation with the handler as its replay source
        instead of completing with its children silently lost.  This
        deferral is not attempt-bounded into ``failed`` and is *parked*: it
        is excluded from claimability and from the attempt-exhaustion sweep,
        so a same-input resume keeps it as real remaining work (never
        drained, never a busy retry loop); only :meth:`recover` after a real
        input change re-pends and re-verifies it.

        Existing identities among the discoveries are reported as duplicates
        and are never re-enqueued; children enter exactly the next batch
        (``frontier + 1``), the same rule as :meth:`enqueue`.
        """

        if action not in ("complete", "defer"):
            raise JobError(
                "invalid_request", "action must be 'complete' or 'defer'", status_code=400
            )
        if action == "complete" and (reason is not None or retry_after_seconds is not None):
            raise JobError(
                "invalid_request",
                "reason/retry_after_seconds are only valid with action='defer'",
                status_code=400,
            )
        item_id = _require_int(item_id, field="item_id", minimum=1)
        if action == "defer":
            reason = _require_text(reason, field="reason", max_chars=_MAX_REASON_CHARS)
        backoff_override = self._validate_retry_after(retry_after_seconds)
        if not isinstance(discoveries, (list, tuple)):
            raise JobError(
                "invalid_request", "discoveries must be a list of work items", status_code=400
            )
        try:
            parsed = [_parse_item(raw) for raw in discoveries]
        except JobError as exc:
            raise JobError(
                "discovery_invalid",
                f"discovered item rejected: {exc.message}",
                status_code=400,
                details={"cause": exc.code},
            ) from exc
        current = _require_epoch(now, field="now") if now is not None else time.time()
        at = epoch_to_iso(current)
        try:
            with self._write() as connection:
                if expected_input_revision is not None:
                    meta = _read_meta_map(connection)
                    if meta.get("input_revision", "") != expected_input_revision:
                        raise JobError(
                            "input_revision_mismatch",
                            "the queue is bound to a different input revision; the "
                            "settlement was rejected without writing",
                            status_code=409,
                            details={
                                "recorded_input_revision": meta.get("input_revision", ""),
                                "expected_input_revision": expected_input_revision,
                            },
                        )
                row = self._active_item(connection, item_id, claim_token)
                duplicates: List[Dict[str, Any]] = []
                new_items: List[Dict[str, Any]] = []
                seen_identities: set[tuple[str, str, str]] = set()
                for item in parsed:
                    identity = (item["kind"], item["scope_key"], item["build_key"])
                    if identity in seen_identities:
                        # The same child twice inside one result: a duplicate
                        # of the first copy being enqueued by this very
                        # transaction, never a second INSERT (the UNIQUE
                        # constraint must not reject a legitimate result).
                        duplicates.append(
                            {
                                "kind": item["kind"],
                                "scope_key": item["scope_key"],
                                "build": item["build"],
                                "existing_item_id": None,
                                "existing_status": None,
                            }
                        )
                        continue
                    seen_identities.add(identity)
                    existing = connection.execute(
                        "SELECT item_id, status FROM items "
                        "WHERE kind = ? AND scope_key = ? AND build_key = ?",
                        identity,
                    ).fetchone()
                    if existing is not None:
                        duplicates.append(
                            {
                                "kind": item["kind"],
                                "scope_key": item["scope_key"],
                                "build": item["build"],
                                "existing_item_id": int(existing["item_id"]),
                                "existing_status": str(existing["status"]),
                            }
                        )
                    else:
                        new_items.append(item)
                discovery_blocked: Optional[str] = None
                batch_no = _read_frontier(connection) + 1
                if new_items:
                    if batch_no > self.max_batches:
                        discovery_blocked = "batch_limit"
                    else:
                        count_row = connection.execute("SELECT COUNT(*) AS n FROM items").fetchone()
                        existing_total = int(count_row["n"]) if count_row is not None else 0
                        if existing_total + len(new_items) > _MAX_QUEUE_ITEMS:
                            discovery_blocked = "queue_limit"
                status = ""
                deferred_count = int(row["deferred_count"])
                next_eligible_at: Optional[float] = None
                applied_reason: Optional[str] = None
                if discovery_blocked is not None:
                    applied_reason = (
                        DEFER_REASON_DISCOVERY_BATCH_LIMIT
                        if discovery_blocked == "batch_limit"
                        else DEFER_REASON_DISCOVERY_QUEUE_LIMIT
                    )
                    status, deferred_count, next_eligible_at = self._apply_defer_transition(
                        connection,
                        row,
                        reason=applied_reason,
                        retry_after_seconds=None,
                        now=current,
                        bounded=False,
                    )
                elif action == "complete":
                    self._apply_complete_transition(connection, row, now=current)
                    status = "completed"
                else:
                    applied_reason = reason
                    status, deferred_count, next_eligible_at = self._apply_defer_transition(
                        connection,
                        row,
                        reason=str(reason),
                        retry_after_seconds=backoff_override,
                        now=current,
                    )
                enqueued: List[Dict[str, Any]] = []
                if discovery_blocked is None and new_items:
                    for item in new_items:
                        cursor = connection.execute(
                            "INSERT INTO items (kind, scope_key, build_key, status, batch_no, "
                            "payload_json, attempts, total_attempts, deferred_count, "
                            "enqueued_epoch, last_touched_epoch, created_at, updated_at) "
                            "VALUES (?, ?, ?, 'pending', ?, ?, 0, 0, 0, ?, ?, ?, ?)",
                            (
                                item["kind"],
                                item["scope_key"],
                                item["build_key"],
                                batch_no,
                                item["payload_json"],
                                current,
                                current,
                                at,
                                at,
                            ),
                        )
                        enqueued.append(
                            {
                                "item_id": int(cursor.lastrowid or 0),
                                "kind": item["kind"],
                                "scope_key": item["scope_key"],
                                "build": item["build"],
                            }
                        )
                    connection.execute("UPDATE meta SET value = ? WHERE key = 'updated_at'", (at,))
        except JobError:
            raise
        except sqlite3.Error as exc:
            raise JobError(
                "queue_unavailable", f"cannot settle item {item_id}: {exc}", status_code=503
            ) from exc
        result: Dict[str, Any] = {
            **_identity_of(row),
            "status": status,
            "batch_no": int(row["batch_no"]),
            "attempts": int(row["attempts"]),
            "total_attempts": int(row["total_attempts"]),
            "deferred_count": deferred_count,
            "discovery_blocked": discovery_blocked,
            "enqueued": enqueued,
            "duplicates": duplicates,
        }
        if status == "completed":
            result["completed_at"] = current
            result["completed_at_iso"] = at
        elif status == "failed":
            result["reason"] = _FAIL_REASON_EXHAUSTED
            result["failed_at"] = current
            result["failed_at_iso"] = at
        else:
            result["reason"] = applied_reason
            result["next_eligible_at"] = next_eligible_at
            result["next_eligible_at_iso"] = (
                epoch_to_iso(next_eligible_at) if next_eligible_at is not None else None
            )
        return result

    def snapshot(self, *, now: Optional[float] = None) -> Dict[str, Any]:
        """Return the machine-readable queue state; counts are real SQL counts."""

        current = _require_epoch(now, field="now") if now is not None else time.time()
        try:
            with self._read() as connection:
                meta = _read_meta_map(connection)
                counts = {status: 0 for status in ITEM_STATUSES}
                for row in connection.execute(
                    "SELECT status, COUNT(*) AS n FROM items GROUP BY status"
                ):
                    counts[str(row["status"])] = int(row["n"])
                remaining_rows = connection.execute(
                    "SELECT * FROM items WHERE status IN ('pending', 'active', 'deferred') "
                    "ORDER BY batch_no ASC, item_id ASC LIMIT ?",
                    (_SNAPSHOT_LIST_LIMIT + 1,),
                ).fetchall()
                failed_rows = connection.execute(
                    "SELECT * FROM items WHERE status = 'failed' "
                    "ORDER BY failed_at ASC, item_id ASC LIMIT ?",
                    (_SNAPSHOT_LIST_LIMIT + 1,),
                ).fetchall()
                completed_rows = connection.execute(
                    "SELECT * FROM items WHERE status = 'completed' "
                    "ORDER BY completed_at ASC, item_id ASC LIMIT ?",
                    (_SNAPSHOT_LIST_LIMIT + 1,),
                ).fetchall()
                eligible_row = connection.execute(
                    "SELECT COUNT(*) AS n FROM items WHERE status = 'deferred' "
                    "AND last_defer_reason NOT IN (?, ?) "
                    "AND (next_eligible_at IS NULL OR next_eligible_at <= ?)",
                    (*_DISCOVERY_BLOCK_REASONS, current),
                ).fetchone()
                parked_row = connection.execute(
                    "SELECT COUNT(*) AS n FROM items WHERE " + _PARKED_SQL,
                    {
                        "blocked_batch": DEFER_REASON_DISCOVERY_BATCH_LIMIT,
                        "blocked_queue": DEFER_REASON_DISCOVERY_QUEUE_LIMIT,
                    },
                ).fetchone()
                expired_row = connection.execute(
                    "SELECT COUNT(*) AS n FROM items WHERE status = 'active' "
                    "AND claim_expires_at IS NOT NULL AND claim_expires_at <= ?",
                    (current,),
                ).fetchone()
                max_batch_row = connection.execute(
                    "SELECT MAX(batch_no) AS m FROM items"
                ).fetchone()
                recovery_rows = connection.execute(
                    "SELECT * FROM recoveries ORDER BY seq DESC LIMIT ?",
                    (_RECOVERY_LOG_LIMIT + 1,),
                ).fetchall()
        except sqlite3.Error as exc:
            raise JobError(
                "queue_unavailable", f"cannot read work queue snapshot: {exc}", status_code=503
            ) from exc
        remaining_truncated = len(remaining_rows) > _SNAPSHOT_LIST_LIMIT
        failed_truncated = len(failed_rows) > _SNAPSHOT_LIST_LIMIT
        completed_truncated = len(completed_rows) > _SNAPSHOT_LIST_LIMIT
        recoveries_truncated = len(recovery_rows) > _RECOVERY_LOG_LIMIT
        return {
            "schema": WORK_QUEUE_SCHEMA,
            "schema_version": WORK_QUEUE_SCHEMA_VERSION,
            "job_id": self.job_id,
            "input_revision": self.input_revision,
            "project_root": self.project_root,
            "generated_at": epoch_to_iso(current),
            "now": current,
            "counts": counts,
            "unresolved_count": counts["pending"] + counts["active"] + counts["deferred"],
            "deferred_eligible_count": int(eligible_row["n"]) if eligible_row else 0,
            "discovery_blocked_count": int(parked_row["n"]) if parked_row else 0,
            "lease_expired_active_count": int(expired_row["n"]) if expired_row else 0,
            "frontier_batch": int(meta.get("frontier_batch", "0") or 0),
            "max_batch_enqueued": (
                int(max_batch_row["m"]) if max_batch_row and max_batch_row["m"] else 0
            ),
            "max_attempts": self.max_attempts,
            "max_batches": self.max_batches,
            "remaining": [
                self._remaining_projection(row, current)
                for row in remaining_rows[:_SNAPSHOT_LIST_LIMIT]
            ],
            "remaining_truncated": remaining_truncated,
            "failed": [self._failed_projection(row) for row in failed_rows[:_SNAPSHOT_LIST_LIMIT]],
            "failed_truncated": failed_truncated,
            "completed": [
                self._completed_projection(row) for row in completed_rows[:_SNAPSHOT_LIST_LIMIT]
            ],
            "completed_truncated": completed_truncated,
            "recoveries": [
                {
                    "seq": int(row["seq"]),
                    "at": row["at"],
                    "from_input_revision": row["from_input_revision"],
                    "to_input_revision": row["to_input_revision"],
                    "re_pended": int(row["re_pended"]),
                }
                for row in recovery_rows[:_RECOVERY_LOG_LIMIT]
            ],
            "recoveries_truncated": recoveries_truncated,
            "recovery_count": int(meta.get("recovery_count", "0") or 0),
        }

    def recover(self, new_input_revision: str, *, now: Optional[float] = None) -> Dict[str, Any]:
        """Re-bind the queue to a new input revision, revoking old verdicts.

        Every non-pending item (completed, failed, deferred or active under a
        stale lease) returns to pending for re-verification instead of
        keeping a completion that was earned against different inputs.  The
        same identity is not retried without such an input change; calling
        this with the current revision is rejected.
        """

        new_input_revision = _require_text(
            new_input_revision, field="new_input_revision", max_chars=_MAX_INPUT_REVISION_CHARS
        )
        if new_input_revision == self.input_revision:
            raise JobError(
                "invalid_request",
                "recovery requires a different input revision; the queue is "
                "already bound to this one",
                status_code=400,
                details={"input_revision": self.input_revision},
            )
        current = _require_epoch(now, field="now") if now is not None else time.time()
        try:
            with self._write() as connection:
                meta = _read_meta_map(connection)
                if meta.get("job_id", "") != self.job_id:
                    raise JobError(
                        "job_scope_mismatch",
                        "work queue belongs to a different job",
                        status_code=409,
                        details={"recorded_job_id": meta.get("job_id", "")},
                    )
                if meta.get("input_revision", "") != self.input_revision:
                    raise JobError(
                        "input_revision_mismatch",
                        "work queue was re-bound concurrently; reload and retry",
                        status_code=409,
                        details={"recorded_input_revision": meta.get("input_revision", "")},
                    )
                summary = _perform_recovery(
                    connection, new_input_revision=new_input_revision, now=current
                )
        except JobError:
            raise
        except sqlite3.Error as exc:
            raise JobError(
                "queue_unavailable", f"cannot recover work queue: {exc}", status_code=503
            ) from exc
        self.input_revision = new_input_revision
        return summary

    @classmethod
    def open_for_recovery(
        cls,
        db_path: Path | str,
        *,
        job_id: str,
        new_input_revision: str,
        **kwargs: Any,
    ) -> "WorkQueue":
        """Recover a queue recorded under an older input revision after a restart.

        The constructor rejects an unknown input revision by design; this is
        the explicit recovery entry point for that case.  It validates the
        job scope, re-pends every non-pending item and returns an instance
        bound to the new revision.
        """

        db_path = Path(db_path)
        job_id = _require_text(job_id, field="job_id", max_chars=_MAX_JOB_ID_CHARS)
        new_input_revision = _require_text(
            new_input_revision, field="new_input_revision", max_chars=_MAX_INPUT_REVISION_CHARS
        )
        if not db_path.is_file():
            # recovery only applies to an existing queue; do not create one
            raise JobError(
                "queue_not_found",
                f"no initialized work queue at {db_path}; nothing to recover",
                status_code=404,
            )
        try:
            connection = _open_connection(db_path)
        except sqlite3.Error as exc:
            raise JobError(
                "queue_unavailable",
                f"cannot open work queue at {db_path}: {exc}",
                status_code=503,
            ) from exc
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
                tables = connection.execute(
                    "SELECT COUNT(*) AS n FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'meta'"
                ).fetchone()
                if tables is None or int(tables["n"]) < 1:
                    raise JobError(
                        "queue_not_found",
                        f"no initialized work queue at {db_path}; nothing to recover",
                        status_code=404,
                    )
                meta = _read_meta_map(connection)
                if not meta.get("schema_id"):
                    raise JobError(
                        "queue_not_found",
                        f"no initialized work queue at {db_path}; nothing to recover",
                        status_code=404,
                    )
                if meta.get("job_id", "") != job_id:
                    raise JobError(
                        "job_scope_mismatch",
                        "work queue belongs to a different job",
                        status_code=409,
                        details={"recorded_job_id": meta.get("job_id", "")},
                    )
                recorded = meta.get("input_revision", "")
                if new_input_revision == recorded:
                    raise JobError(
                        "invalid_request",
                        "recovery requires a different input revision; the queue "
                        "is already bound to this one",
                        status_code=400,
                        details={"input_revision": recorded},
                    )
                _perform_recovery(
                    connection, new_input_revision=new_input_revision, now=time.time()
                )
                connection.execute("COMMIT")
            except BaseException:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
        except JobError:
            raise
        except sqlite3.Error as exc:
            raise JobError(
                "queue_unavailable", f"cannot recover work queue: {exc}", status_code=503
            ) from exc
        finally:
            connection.close()
        return cls(db_path, job_id=job_id, input_revision=new_input_revision, **kwargs)

    # -- internal ----------------------------------------------------------

    def _active_item(
        self, connection: sqlite3.Connection, item_id: int, claim_token: str
    ) -> sqlite3.Row:
        row: Optional[sqlite3.Row] = connection.execute(
            "SELECT * FROM items WHERE item_id = ?", (item_id,)
        ).fetchone()
        if row is None:
            raise JobError("item_not_found", f"unknown item_id {item_id}", status_code=404)
        if row["status"] != "active":
            raise JobError(
                "invalid_state",
                f"item {item_id} is {row['status']!r}; only active items can be "
                "completed or deferred",
                status_code=409,
                details={"item_id": item_id, "status": row["status"]},
            )
        _require_text(claim_token, field="claim_token", max_chars=128)
        if row["claim_token"] != claim_token:
            raise JobError(
                "stale_claim",
                "claim token does not match; the item was re-claimed after " "its lease expired",
                status_code=409,
                details={"item_id": item_id},
            )
        return row

    @staticmethod
    def _remaining_projection(row: sqlite3.Row, now: float) -> Dict[str, Any]:
        status = str(row["status"])
        next_eligible = row["next_eligible_at"]
        claim_expires = row["claim_expires_at"]
        reason = None
        if status == "deferred":
            reason = row["last_defer_reason"]
        elif status == "failed":
            reason = row["fail_reason"]
        return {
            **_identity_of(row),
            "status": status,
            "batch_no": int(row["batch_no"]),
            "attempts": int(row["attempts"]),
            "total_attempts": int(row["total_attempts"]),
            "deferred_count": int(row["deferred_count"]),
            "reason": reason,
            "next_eligible_at": next_eligible,
            "next_eligible_at_iso": epoch_to_iso(next_eligible) if next_eligible else None,
            "claim_expires_at": claim_expires,
            "claim_expires_at_iso": epoch_to_iso(claim_expires) if claim_expires else None,
            "lease_expired": bool(
                status == "active" and claim_expires is not None and claim_expires <= now
            ),
            "deferred_eligible": bool(
                status == "deferred" and (next_eligible is None or next_eligible <= now)
            ),
            "revoked_from_status": row["revoked_from_status"],
        }

    @staticmethod
    def _failed_projection(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            **_identity_of(row),
            "batch_no": int(row["batch_no"]),
            "attempts": int(row["attempts"]),
            "total_attempts": int(row["total_attempts"]),
            "deferred_count": int(row["deferred_count"]),
            "fail_reason": row["fail_reason"],
            "failed_at": row["failed_at"],
            "failed_at_iso": epoch_to_iso(row["failed_at"]) if row["failed_at"] else None,
        }

    @staticmethod
    def _completed_projection(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            **_identity_of(row),
            "batch_no": int(row["batch_no"]),
            "attempts": int(row["attempts"]),
            "total_attempts": int(row["total_attempts"]),
            "deferred_count": int(row["deferred_count"]),
            "completed_at": row["completed_at"],
            "completed_at_iso": (
                epoch_to_iso(row["completed_at"]) if row["completed_at"] else None
            ),
        }
