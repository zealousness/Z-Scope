"""SQLite persistence for persistent scan jobs (single source of truth).

The store is scoped to one project root.  All job mutations go through
optimistic-revision updates inside IMMEDIATE transactions so the Web service,
a CLI client and the detached owner process never fork the state.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import sqlite3
import stat
import threading
import weakref
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Literal,
    Optional,
    Sequence,
    Tuple,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from .instance_results import (
        CurrentAttempt,
        ExpectedInstance,
        FrozenJSON,
        InstanceKey,
        PreparedInstanceResult,
        RecoveryIdentity,
        TrustedInstanceResultReceipt,
    )
    from .work_queue import WorkQueue

from .models import ACTIVE_STATUSES, TERMINAL_STATUSES, JobError, bounded_event_data, utc_now_iso

SCHEMA_ID = "zscope.scan-jobs.store"
SCHEMA_VERSION = 1

_SQLITE_PRAGMA_LOCK = threading.Lock()


@dataclass
class _ConnectionObservation:
    thread: threading.Thread
    generation: object = field(default_factory=object)
    trace_count: int = 0
    closed: bool = False
    user_trace: Optional[Callable[[str], object]] = None
    user_trace_depth: int = 0


_CONNECTION_OBSERVATIONS: weakref.WeakKeyDictionary[sqlite3.Connection, _ConnectionObservation] = (
    weakref.WeakKeyDictionary()
)
_TRANSACTION_CONTROL = re.compile(
    r"\A(?:\s|;|\ufeff|--[^\r\n]*(?:\r\n?|\n|\Z)|/\*.*?(?:\*/|\Z))*"
    r"(?:BEGIN|COMMIT|END|ROLLBACK|SAVEPOINT|RELEASE)\b",
    re.IGNORECASE | re.DOTALL,
)


def _end_observed_generation(connection: sqlite3.Connection) -> None:
    observation = _CONNECTION_OBSERVATIONS.get(connection)
    if observation is not None:
        observation.generation = object()


class _StoreConnection(sqlite3.Connection):
    """Forward SQLite operations while retaining a private transaction observer.

    SQLite's native trace covers connection/cursor SQL and the implicit COMMIT
    before executescript. Public tracing is relayed by that same native callback,
    so replacing a user's callback cannot remove the private lifetime observer.
    Non-SQL transaction exits revoke before forwarding the original operation.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        _CONNECTION_OBSERVATIONS[self] = _ConnectionObservation(threading.current_thread())
        super().set_trace_callback(self._observe_statement)

    def _observe_statement(self, statement: str) -> None:
        observation = _CONNECTION_OBSERVATIONS.get(self)
        if observation is None:
            return
        observation.trace_count += 1
        # SQLite prefixes statements reentered from a trace callback with
        # "-- ". That text is observational, not the original SQL grammar:
        # a real COMMIT/BEGIN can look like comments. Any actual SQL observed
        # during user tracing therefore ends the old capability generation.
        if observation.user_trace_depth or _TRANSACTION_CONTROL.match(statement):
            _end_observed_generation(self)
        if observation.user_trace is not None:
            observation.user_trace_depth += 1
            try:
                observation.user_trace(statement)
            finally:
                observation.user_trace_depth -= 1

    def set_trace_callback(self, trace_callback: Optional[Callable[[str], object]]) -> None:
        # Forward the real setter (including closed-connection errors), keeping
        # the native dispatcher installed even when public tracing is disabled.
        super().set_trace_callback(self._observe_statement)
        _CONNECTION_OBSERVATIONS[self].user_trace = trace_callback

    def commit(self) -> None:
        _end_observed_generation(self)
        super().commit()

    def rollback(self) -> None:
        _end_observed_generation(self)
        super().rollback()

    def close(self) -> None:
        _end_observed_generation(self)
        observation = _CONNECTION_OBSERVATIONS.get(self)
        if observation is not None:
            observation.closed = True
        super().close()

    def __exit__(self, *args: Any) -> Literal[False]:
        _end_observed_generation(self)
        return super().__exit__(*args)


@dataclass(frozen=True)
class _MainDatabaseIdentity:
    lexical: str
    physical: str
    device: int
    inode: int
    lexical_device: int
    lexical_inode: int
    lexical_mode: int


def _main_database_identity(path: Path) -> Optional[_MainDatabaseIdentity]:
    try:
        lexical = os.path.abspath(path)
        physical = str(Path(lexical).resolve(strict=True))
        actual = os.stat(lexical)
        entry = os.lstat(lexical)
        if not stat.S_ISREG(actual.st_mode) or not actual.st_ino:
            return None
        return _MainDatabaseIdentity(
            lexical,
            physical,
            actual.st_dev,
            actual.st_ino,
            entry.st_dev,
            entry.st_ino,
            entry.st_mode,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None


def _observed_main_is_current(
    connection: sqlite3.Connection,
    identity: _MainDatabaseIdentity,
    generation: object,
) -> bool:
    observation = _CONNECTION_OBSERVATIONS.get(connection)
    if (
        observation is None
        or observation.closed
        or observation.thread is not threading.current_thread()
        or observation.generation is not generation
        or (connection.row_factory is not None and connection.row_factory is not sqlite3.Row)
    ):
        return False
    try:
        if not connection.in_transaction:
            return False
        before_trace = observation.trace_count
        main = [row for row in connection.execute("PRAGMA database_list") if row[1] == "main"]
        # A native statement must actually reach our private observer. An
        # unobserved/custom connection is never promoted to a live capability.
        if (
            observation.trace_count <= before_trace
            or observation.generation is not generation
            or not connection.in_transaction
            or (connection.row_factory is not None and connection.row_factory is not sqlite3.Row)
            or len(main) != 1
            or not main[0][2]
        ):
            return False
        actual = _main_database_identity(Path(main[0][2]))
        return (
            actual is not None
            and actual.lexical == identity.physical
            and actual.physical == identity.physical
            and (actual.device, actual.inode) == (identity.device, identity.inode)
            and _main_database_identity(Path(identity.lexical)) == identity
        )
    except (OSError, RuntimeError, TypeError, ValueError, IndexError, KeyError, sqlite3.Error):
        return False


@dataclass(frozen=True)
class _WriteFrame:
    issuer: "JobStore"
    connection: sqlite3.Connection
    identity: _MainDatabaseIdentity
    generation: object
    thread: threading.Thread
    nonce: object = field(default_factory=object)


@dataclass(frozen=True)
class _WriteScope:
    frame: Optional[_WriteFrame]


_WRITE_SCOPES = threading.local()
_LIVE_WRITE_FRAMES: Dict[object, _WriteFrame] = {}


def _transaction_unavailable() -> JobError:
    return JobError(
        "store_transaction_unavailable",
        "no current verified Store write transaction is available on this thread",
        status_code=409,
    )


@contextmanager
def _issued_write_scope(
    store: "JobStore",
    connection: sqlite3.Connection,
    before_open: Optional[_MainDatabaseIdentity],
) -> Iterator[None]:
    frame = None
    observation = _CONNECTION_OBSERVATIONS.get(connection)
    if (
        before_open is not None
        and observation is not None
        and _main_database_identity(store.db_path) == before_open
        and _observed_main_is_current(connection, before_open, observation.generation)
    ):
        frame = _WriteFrame(
            store, connection, before_open, observation.generation, threading.current_thread()
        )
        _LIVE_WRITE_FRAMES[frame.nonce] = frame
    scope = _WriteScope(frame)
    previous = getattr(_WRITE_SCOPES, "current", None)
    _WRITE_SCOPES.current = scope
    try:
        yield
    finally:
        # Revoke before the original owner commits, rolls back or closes,
        # including BaseException and failed original cleanup operations.
        if frame is not None:
            _LIVE_WRITE_FRAMES.pop(frame.nonce, None)
        _WRITE_SCOPES.current = previous


@dataclass(frozen=True)
class SettlementClaim:
    item_id: int
    claim_token: str = field(repr=False)
    kind: str
    scope_key: str
    build: str


@dataclass(frozen=True)
class InstanceSettlementAck:
    identity: str
    mode: Literal["restored", "executed"]
    committed: bool
    queue_result_json: "FrozenJSON"
    receipt: Optional["TrustedInstanceResultReceipt"]
    reuse_unavailable_reason: Optional[str]


@dataclass(frozen=True)
class InstanceCompletionRequest:
    """Token-free handler request; scheduler supplies the private claim."""

    current: "CurrentAttempt"
    expected: "RecoveryIdentity"
    instance: "InstanceKey"
    semantics_digest: str
    mode: Literal["restored", "executed"]
    prepared: Optional["PreparedInstanceResult"]
    restored_receipt: Optional["TrustedInstanceResultReceipt"]
    input_current_guard: Callable[[], None] = field(repr=False)
    accept_settlement: Callable[[InstanceSettlementAck], None] = field(repr=False)


def _instance_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _instance_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _instance_loads(raw: str) -> Any:
    def pairs(rows: List[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise ValueError("duplicate instance receipt JSON key")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    input_revision TEXT NOT NULL,
    status TEXT NOT NULL,
    phase TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    updated_at TEXT NOT NULL,
    requested_stop_at TEXT,
    resolved_stop_time TEXT,
    stop_at_epoch REAL,
    scan_depth TEXT,
    config_path TEXT NOT NULL,
    config_sha256 TEXT NOT NULL,
    project_root TEXT NOT NULL,
    project_id TEXT NOT NULL,
    working_directory TEXT NOT NULL,
    run_dir TEXT NOT NULL,
    owner_pid INTEGER,
    owner_token TEXT NOT NULL,
    owner_start_ticks INTEGER,
    owner_boot_id TEXT,
    owner_heartbeat_at TEXT,
    scanner_pid INTEGER,
    scanner_start_ticks INTEGER,
    cancel_requested_at TEXT,
    input_components_json TEXT NOT NULL DEFAULT '{}',
    progress_json TEXT NOT NULL DEFAULT '{}',
    coverage_json TEXT NOT NULL DEFAULT '{}',
    questions_json TEXT NOT NULL DEFAULT '[]',
    pending_count INTEGER,
    report_json TEXT NOT NULL DEFAULT '{}',
    artifacts_json TEXT NOT NULL DEFAULT '[]',
    error_code TEXT,
    error_message TEXT
);
CREATE TABLE IF NOT EXISTS attempts (
    job_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    attempt_no INTEGER NOT NULL,
    status TEXT NOT NULL,
    input_revision TEXT NOT NULL,
    started_at TEXT,
    ended_at TEXT,
    exit_code INTEGER,
    exit_signal INTEGER,
    report_path TEXT,
    report_id TEXT,
    error_code TEXT,
    error_message TEXT,
    PRIMARY KEY (job_id, run_id)
);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    at TEXT NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_job ON events(job_id, seq);
CREATE TABLE IF NOT EXISTS bound_event_receipts (
    event_seq INTEGER PRIMARY KEY,
    job_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    run_dir TEXT NOT NULL,
    input_revision TEXT NOT NULL,
    plan_fingerprint TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bound_completion
    ON bound_event_receipts(job_id, input_revision, plan_fingerprint, event_seq);
CREATE TABLE IF NOT EXISTS requests (
    request_id TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    job_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

# Every schema object the script creates, so a same-version store that lost one
# is repaired by ``initialize`` instead of being trusted.
_SCHEMA_OBJECTS = frozenset(
    re.findall(r"CREATE (?:TABLE|INDEX) IF NOT EXISTS ([A-Za-z_][A-Za-z0-9_]*)", _SCHEMA)
)

_JOB_COLUMNS = (
    "job_id",
    "run_id",
    "revision",
    "input_revision",
    "status",
    "phase",
    "created_at",
    "started_at",
    "updated_at",
    "requested_stop_at",
    "resolved_stop_time",
    "stop_at_epoch",
    "scan_depth",
    "config_path",
    "config_sha256",
    "project_root",
    "project_id",
    "working_directory",
    "run_dir",
    "owner_pid",
    "owner_token",
    "owner_start_ticks",
    "owner_boot_id",
    "owner_heartbeat_at",
    "scanner_pid",
    "scanner_start_ticks",
    "cancel_requested_at",
    "input_components_json",
    "progress_json",
    "coverage_json",
    "questions_json",
    "pending_count",
    "report_json",
    "artifacts_json",
    "error_code",
    "error_message",
)


def _row_to_job(row: sqlite3.Row) -> Dict[str, Any]:
    job: Dict[str, Any] = {}
    for column in _JOB_COLUMNS:
        job[column] = row[column]
    for key in ("progress_json", "coverage_json", "report_json", "input_components_json"):
        try:
            job[key] = json.loads(job[key] or "{}")
        except (TypeError, ValueError):
            job[key] = {}
    for key in ("questions_json", "artifacts_json"):
        try:
            job[key] = json.loads(job[key] or "[]")
        except (TypeError, ValueError):
            job[key] = []
    return job


@dataclass
class RequestReservation:
    """Outcome of a transactional request reservation.

    ``created`` is False only for a same-key, same-payload replay of an
    already registered marker: ``job_id`` then names the job the marker is
    bound to and ``job`` is None (the caller re-reads it to serve current
    state).  A marker with a different endpoint or payload never gets this
    far — the reservation methods reject it with 409 before any mutation.
    """

    created: bool
    job_id: str
    job: Optional[Dict[str, Any]] = None


def _append_event_on(
    connection: sqlite3.Connection,
    job_id: str,
    *,
    run_id: str,
    kind: str,
    message: str,
    data: Optional[Dict[str, Any]] = None,
) -> int:
    payload = json.dumps(bounded_event_data(data), ensure_ascii=False)
    cursor = connection.execute(
        "INSERT INTO events (job_id, run_id, at, kind, message, data_json) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (job_id, run_id, utc_now_iso(), kind, message, payload),
    )
    return int(cursor.lastrowid or 0)


def _finish_attempt_on(
    connection: sqlite3.Connection,
    job_id: str,
    run_id: str,
    fields: Dict[str, Any],
) -> None:
    """finish_attempt's INSERT/UPDATE logic, on an open transaction."""

    columns = (
        "job_id",
        "run_id",
        "attempt_no",
        "status",
        "input_revision",
        "started_at",
        "ended_at",
        "exit_code",
        "exit_signal",
        "report_path",
        "report_id",
        "error_code",
        "error_message",
    )
    row = connection.execute(
        "SELECT attempt_no FROM attempts WHERE job_id = ? AND run_id = ?",
        (job_id, run_id),
    ).fetchone()
    if row is None:
        max_row = connection.execute(
            "SELECT COALESCE(MAX(attempt_no), 0) AS max_no FROM attempts " "WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        attempt_no = int(max_row["max_no"]) + 1 if max_row is not None else 1
        params = {column: fields.get(column) for column in columns}
        params["job_id"] = job_id
        params["run_id"] = run_id
        params["attempt_no"] = attempt_no
        # attempts.input_revision is NOT NULL by design: every attempt,
        # including one whose owner died or failed to spawn before
        # recording itself, must stay bound to the input it ran
        # against.  The job row always carries that binding, so the
        # INSERT backfills from it inside the same transaction.
        if params.get("input_revision") is None:
            job_row = connection.execute(
                "SELECT input_revision FROM jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if job_row is not None:
                params["input_revision"] = job_row["input_revision"]
        connection.execute(
            f"INSERT INTO attempts ({', '.join(columns)}) "
            f"VALUES ({', '.join(':' + c for c in columns)})",
            params,
        )
        return
    assignments = ", ".join(
        f"{column} = :u_{column}"
        for column in columns
        if column not in ("job_id", "run_id", "attempt_no") and column in fields
    )
    if not assignments:
        return
    params = {"job_id": job_id, "run_id": run_id}
    for column in columns:
        if column in ("job_id", "run_id", "attempt_no") or column not in fields:
            continue
        params[f"u_{column}"] = fields[column]
    connection.execute(
        f"UPDATE attempts SET {assignments} WHERE job_id = :job_id AND run_id = :run_id",
        params,
    )


class JobStore:
    """WAL-backed single-writer-friendly store for one project."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)

    # -- connection plumbing -------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.db_path), timeout=30.0, factory=_StoreConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 30000")
        with _SQLITE_PRAGMA_LOCK:
            try:
                connection.execute("PRAGMA journal_mode = WAL")
            except sqlite3.OperationalError:
                # Another connection is switching journal mode; WAL is best
                # effort here because correctness comes from busy_timeout.
                pass
        connection.execute("PRAGMA synchronous = NORMAL")
        return connection

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        before_open = _main_database_identity(self.db_path)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            with _issued_write_scope(self, connection, before_open):
                yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _active_transaction_connection(self) -> sqlite3.Connection:
        """Return only this thread's issued, still-current physical Store write.

        Wrappers for the exact same canonical database may share the real
        connection. Attempt/owner/input authorization remains the original SQL
        checks in bound_attempt, independently repeated for every borrower.
        """
        scope = getattr(_WRITE_SCOPES, "current", None)
        if not isinstance(scope, _WriteScope) or scope.frame is None:
            raise _transaction_unavailable()
        frame = scope.frame
        if (
            not isinstance(frame, _WriteFrame)
            or type(frame.nonce) is not object
            or _LIVE_WRITE_FRAMES.get(frame.nonce) is not frame
            or frame.thread is not threading.current_thread()
        ):
            # A copied/foreign locator is not authority and cannot revoke the
            # genuine owner's issued frame as a side effect of being rejected.
            raise _transaction_unavailable()
        if _main_database_identity(frame.issuer.db_path) != frame.identity:
            _LIVE_WRITE_FRAMES.pop(frame.nonce, None)
            raise _transaction_unavailable()
        if _main_database_identity(self.db_path) != frame.identity:
            # A foreign wrapper does not revoke the genuine owner's frame.
            raise _transaction_unavailable()
        if (
            not _observed_main_is_current(frame.connection, frame.identity, frame.generation)
            or _main_database_identity(frame.issuer.db_path) != frame.identity
        ):
            _LIVE_WRITE_FRAMES.pop(frame.nonce, None)
            raise _transaction_unavailable()
        # Native tracing may invoke user code. Check the requesting wrapper
        # again after the real PRAGMA, as well as the original issuer above.
        if _main_database_identity(self.db_path) != frame.identity:
            raise _transaction_unavailable()
        return frame.connection

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def bound_attempt(
        self,
        *,
        job_id: str,
        run_id: str,
        owner_token: str,
        expected_input_revision: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Hold the job row's write lock while an attempt-side queue write commits.

        Session-side consumers (the work scheduler) must not trust a binding
        they merely *read*: the job row can flip (newer run, foreign owner
        token, terminal state, changed input revision) between the read and
        the work-queue write.  This context takes one ``BEGIN IMMEDIATE``
        transaction on the job store, validates the attempt binding inside
        it and holds the lock open until the caller's queue transaction has
        committed, so no concurrent writer can flip the binding in between.

        Lock discipline (deadlock-free by construction):

        * the store lock is always taken *before* any work-queue lock
          (store → queue ordering); nothing in this package takes them in
          the reverse order;
        * callers must not write the job store inside the block — appending
          events or progress from a second connection would block on the
          lock held here (same-timeout self-deadlock) — emit them after;
        * handlers/callbacks must run outside the block; only the queue
          settlement belongs here.

        A nested currentness check may transparently borrow the verified active
        transaction for this exact Store on the same thread. It repeats these
        SQL binding checks without acquiring or finishing another transaction.
        Other threads retain the original independent BEGIN/lock protocol.

        The transaction writes nothing; committing merely releases the lock.
        Raises :class:`JobError` (409/404) with the same reason codes the
        session-side hook reports — ``job_missing``, ``run_superseded``,
        ``owner_token_mismatch``, ``job_terminal``, ``input_revision_changed``
        — or ``store_unreadable`` when the row cannot be read at all; an
        unreadable binding is never authorization.
        """

        owns_connection = getattr(_WRITE_SCOPES, "current", None) is None
        before_open = _main_database_identity(self.db_path) if owns_connection else None
        connection = self._connect() if owns_connection else self._active_transaction_connection()
        locked = False
        try:
            try:
                if owns_connection:
                    connection.execute("BEGIN IMMEDIATE")
                    locked = True
                row = connection.execute(
                    "SELECT * FROM jobs WHERE job_id = ?", (job_id,)
                ).fetchone()
                if row is None:
                    raise JobError(
                        "job_missing", f"no job row {job_id!r} in the job store", status_code=404
                    )
                job = _row_to_job(row)
                if job["run_id"] != run_id:
                    raise JobError(
                        "run_superseded",
                        "the job belongs to a different run; this attempt stands down",
                        status_code=409,
                    )
                if job["owner_token"] != owner_token:
                    raise JobError(
                        "owner_token_mismatch",
                        "owner token does not match the job row; refusing to consume work",
                        status_code=409,
                    )
                if job["status"] in TERMINAL_STATUSES:
                    raise JobError(
                        "job_terminal",
                        f"job is already in terminal state {job['status']!r}",
                        status_code=409,
                    )
                if (
                    expected_input_revision is not None
                    and job["input_revision"] != expected_input_revision
                ):
                    raise JobError(
                        "input_revision_changed",
                        "the job row is bound to a different input revision; the queue "
                        "settlement was rejected without writing",
                        status_code=409,
                        details={
                            "recorded_input_revision": job["input_revision"],
                            "expected_input_revision": expected_input_revision,
                        },
                    )
            except sqlite3.Error as exc:
                raise JobError(
                    "store_unreadable", f"cannot bind the job attempt: {exc}", status_code=503
                ) from exc
            if owns_connection:
                with _issued_write_scope(self, connection, before_open):
                    yield job
                try:
                    connection.commit()
                except sqlite3.Error as exc:
                    raise JobError(
                        "store_unreadable",
                        f"cannot release the attempt binding: {exc}",
                        status_code=503,
                    ) from exc
            else:
                yield job
        except BaseException:
            if locked:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
            raise
        finally:
            if owns_connection:
                connection.close()

    def initialize(self) -> None:
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            if self._schema_is_current():
                # Already initialized: a status read must not take the write
                # lock. A concurrent publisher can hold it for seconds, and
                # turning every read into a write turned that into a 503 (or a
                # multi-second stall) instead of a served job row.
                return
            with self._write() as connection:
                connection.executescript(_SCHEMA)
                connection.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                    ("schema_id", SCHEMA_ID),
                )
                connection.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                    ("schema_version", str(SCHEMA_VERSION)),
                )
        except sqlite3.Error as exc:
            raise JobError(
                "store_unavailable",
                f"cannot initialize job store at {self.db_path}: {exc}",
                status_code=503,
            ) from exc

    def _schema_is_current(self) -> bool:
        """True when this file already carries the expected schema.

        The check covers both the recorded version and every object the script
        creates, because a same-version database can still be missing a table
        (a dropped or partially written store must be repaired, not trusted).
        Misses (absent file, unreadable store, other version, missing object)
        fall back to the initializing write path.
        """

        if not self.db_path.is_file():
            return False
        try:
            with self._read() as connection:
                row = connection.execute(
                    "SELECT value FROM meta WHERE key = 'schema_version'"
                ).fetchone()
                if row is None or str(row["value"]) != str(SCHEMA_VERSION):
                    return False
                names = {
                    str(name)
                    for (name,) in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type IN ('table', 'index')"
                    )
                }
        except sqlite3.Error:
            return False
        return _SCHEMA_OBJECTS.issubset(names)

    def check_available(self) -> None:
        try:
            with self._read() as connection:
                row = connection.execute(
                    "SELECT value FROM meta WHERE key = 'schema_version'"
                ).fetchone()
        except sqlite3.Error as exc:
            raise JobError(
                "store_unavailable",
                f"job store at {self.db_path} is not readable: {exc}",
                status_code=503,
            ) from exc
        if row is None:
            raise JobError(
                "store_unavailable",
                f"job store at {self.db_path} is not initialized",
                status_code=503,
            )

    # -- job lifecycle -------------------------------------------------------

    def create_job(self, fields: Dict[str, Any]) -> Dict[str, Any]:
        payload = {column: fields.get(column) for column in _JOB_COLUMNS}
        for key, default in (
            ("progress_json", {}),
            ("coverage_json", {}),
            ("report_json", {}),
            ("input_components_json", {}),
            ("questions_json", []),
            ("artifacts_json", []),
        ):
            payload[key] = json.dumps(payload[key] if payload[key] is not None else default)
        columns = ", ".join(_JOB_COLUMNS)
        placeholders = ", ".join(f":{column}" for column in _JOB_COLUMNS)
        try:
            with self._write() as connection:
                active = connection.execute(
                    "SELECT job_id, status FROM jobs "
                    "WHERE status IN ('queued', 'running', 'stopping') LIMIT 1"
                ).fetchone()
                if active is not None:
                    raise JobError(
                        "project_scan_active",
                        "another scan job is already active for this project",
                        status_code=409,
                        details={
                            "active_job_id": active["job_id"],
                            "status": active["status"],
                        },
                    )
                connection.execute(
                    f"INSERT INTO jobs ({columns}) VALUES ({placeholders})",
                    payload,
                )
        except JobError:
            raise
        except sqlite3.Error as exc:
            raise JobError(
                "store_unavailable",
                f"cannot create job: {exc}",
                status_code=503,
            ) from exc
        job = self.get_job(str(payload["job_id"]))
        assert job is not None  # nosec - row was just inserted
        return job

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        try:
            with self._read() as connection:
                row = connection.execute(
                    "SELECT * FROM jobs WHERE job_id = ?", (job_id,)
                ).fetchone()
        except sqlite3.Error as exc:
            raise JobError(
                "store_unavailable",
                f"cannot read job store: {exc}",
                status_code=503,
            ) from exc
        return _row_to_job(row) if row is not None else None

    def get_job_for_update(
        self, connection: sqlite3.Connection, job_id: str
    ) -> Optional[Dict[str, Any]]:
        row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        return _row_to_job(row) if row is not None else None

    def list_jobs(self) -> List[Dict[str, Any]]:
        try:
            with self._read() as connection:
                rows = connection.execute(
                    "SELECT * FROM jobs ORDER BY created_at ASC, job_id ASC"
                ).fetchall()
        except sqlite3.Error as exc:
            raise JobError(
                "store_unavailable",
                f"cannot read job store: {exc}",
                status_code=503,
            ) from exc
        return [_row_to_job(row) for row in rows]

    def update_job(
        self,
        job_id: str,
        *,
        expected_revision: int,
        updates: Dict[str, Any],
        bump_revision: bool = True,
        attempt_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Optimistic update, optionally publishing its terminal attempt atomically."""

        if attempt_fields is not None and (
            updates.get("status") not in TERMINAL_STATUSES
            or attempt_fields.get("status") != updates.get("status")
        ):
            raise ValueError("attempt_fields must match the job's terminal status")

        assignments: List[str] = []
        params: Dict[str, Any] = {"job_id": job_id, "expected_revision": expected_revision}
        for key, value in updates.items():
            if key not in _JOB_COLUMNS or key == "job_id":
                raise ValueError(f"cannot update job column {key!r}")
            if key.endswith("_json") and not isinstance(value, str):
                value = json.dumps(value)
            assignments.append(f"{key} = :u_{key}")
            params[f"u_{key}"] = value
        if bump_revision:
            assignments.append("revision = revision + 1")
        assignments.append("updated_at = :u_updated_at")
        params["u_updated_at"] = utc_now_iso()
        sql = (
            f"UPDATE jobs SET {', '.join(assignments)} "
            "WHERE job_id = :job_id AND revision = :expected_revision"
        )
        with self._write() as connection:
            cursor = connection.execute(sql, params)
            if cursor.rowcount != 1:
                raise JobError(
                    "revision_conflict",
                    f"job {job_id} revision changed concurrently; reload and retry",
                    status_code=409,
                    details={"job_id": job_id, "expected_revision": expected_revision},
                )
            job = self.get_job_for_update(connection, job_id)
            if attempt_fields is not None:
                assert job is not None
                _finish_attempt_on(connection, job_id, str(job["run_id"]), attempt_fields)
        assert job is not None
        return job

    def conditional_update(
        self,
        job_id: str,
        *,
        expected_revision: int,
        from_statuses: tuple[str, ...],
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Check status+revision and update atomically in one transaction."""

        assignments: List[str] = []
        params: Dict[str, Any] = {"job_id": job_id, "expected_revision": expected_revision}
        for key, value in updates.items():
            if key not in _JOB_COLUMNS or key == "job_id":
                raise ValueError(f"cannot update job column {key!r}")
            if key.endswith("_json") and not isinstance(value, str):
                value = json.dumps(value)
            assignments.append(f"{key} = :u_{key}")
            params[f"u_{key}"] = value
        assignments.append("revision = revision + 1")
        assignments.append("updated_at = :u_updated_at")
        params["u_updated_at"] = utc_now_iso()
        status_placeholders = ", ".join(f":s_{i}" for i in range(len(from_statuses)))
        for index, status in enumerate(from_statuses):
            params[f"s_{index}"] = status
        sql = (
            f"UPDATE jobs SET {', '.join(assignments)} "
            f"WHERE job_id = :job_id AND revision = :expected_revision "
            f"AND status IN ({status_placeholders})"
        )
        with self._write() as connection:
            current = self.get_job_for_update(connection, job_id)
            if current is None:
                raise JobError("job_not_found", f"unknown job_id {job_id!r}", status_code=404)
            if int(current["revision"]) != expected_revision:
                raise JobError(
                    "revision_conflict",
                    "base_revision does not match the current job revision",
                    status_code=409,
                    details={
                        "job_id": job_id,
                        "expected_revision": expected_revision,
                        "current_revision": int(current["revision"]),
                    },
                )
            if current["status"] not in from_statuses:
                raise JobError(
                    "invalid_state",
                    f"job is {current['status']!r}; expected one of {sorted(from_statuses)}",
                    status_code=409,
                    details={"job_id": job_id, "status": current["status"]},
                )
            connection.execute(sql, params)
            job = self.get_job_for_update(connection, job_id)
        assert job is not None
        return job

    def heartbeat(self, job_id: str, *, owner_token: str, at: str) -> bool:
        """Token-guarded liveness write; never bumps the public revision."""

        with self._write() as connection:
            cursor = connection.execute(
                "UPDATE jobs SET owner_heartbeat_at = ? WHERE job_id = ? AND owner_token = ?",
                (at, job_id, owner_token),
            )
            return cursor.rowcount == 1

    # -- attempts ------------------------------------------------------------

    def record_attempt(self, fields: Dict[str, Any]) -> None:
        columns = (
            "job_id",
            "run_id",
            "attempt_no",
            "status",
            "input_revision",
            "started_at",
            "ended_at",
            "exit_code",
            "exit_signal",
            "report_path",
            "report_id",
            "error_code",
            "error_message",
        )
        params = {column: fields.get(column) for column in columns}
        with self._write() as connection:
            connection.execute(
                f"INSERT OR REPLACE INTO attempts ({', '.join(columns)}) "
                f"VALUES ({', '.join(':' + c for c in columns)})",
                params,
            )

    def list_attempts(self, job_id: str) -> List[Dict[str, Any]]:
        with self._read() as connection:
            rows = connection.execute(
                "SELECT * FROM attempts WHERE job_id = ? ORDER BY attempt_no ASC", (job_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def attempt_for(self, job_id: str, run_id: str) -> Optional[Dict[str, Any]]:
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM attempts WHERE job_id = ? AND run_id = ?", (job_id, run_id)
            ).fetchone()
        return dict(row) if row is not None else None

    def finish_attempt(self, job_id: str, run_id: str, fields: Dict[str, Any]) -> None:
        """Update the existing attempt row, keeping its attempt number."""

        with self._write() as connection:
            _finish_attempt_on(connection, job_id, run_id, fields)

    def next_attempt_no(self, job_id: str) -> int:
        with self._read() as connection:
            row = connection.execute(
                "SELECT COALESCE(MAX(attempt_no), 0) AS max_no FROM attempts WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        return int(row["max_no"]) + 1 if row is not None else 1

    # -- events --------------------------------------------------------------

    def append_event(
        self,
        job_id: str,
        *,
        run_id: str,
        kind: str,
        message: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> int:
        with self._write() as connection:
            return _append_event_on(
                connection, job_id, run_id=run_id, kind=kind, message=message, data=data
            )

    def _checked_bound_job(
        self,
        connection: sqlite3.Connection,
        *,
        job_id: str,
        run_id: str,
        owner_token: str,
        input_revision: Optional[str],
    ) -> Dict[str, Any]:
        job = self.get_job_for_update(connection, job_id)
        if job is None:
            raise JobError("job_missing", "the job does not exist", status_code=404)
        if job["run_id"] != run_id:
            raise JobError("run_superseded", "the current run changed", status_code=409)
        if not owner_token or job["owner_token"] != owner_token:
            raise JobError("owner_token_mismatch", "the current owner changed", status_code=409)
        if job["status"] in TERMINAL_STATUSES:
            raise JobError("job_terminal", "the job is terminal", status_code=409)
        if job["status"] not in ACTIVE_STATUSES:
            raise JobError("invalid_state", "the job state is unknown", status_code=409)
        if input_revision is not None and job["input_revision"] != input_revision:
            raise JobError("input_revision_changed", "the input revision changed", status_code=409)
        return job

    def _checkpoint_data_bound(
        self,
        data: Dict[str, Any],
        *,
        job_id: str,
        run_dir: str,
        input_revision: str,
        plan_fingerprint: str,
    ) -> bool:
        """Check receipt coordinates only; callers still verify bytes and semantics."""
        digest = data.get("checkpoint_sha256")
        raw_path = data.get("checkpoint_path")
        if (
            not input_revision
            or not plan_fingerprint
            or data.get("plan_fingerprint") != plan_fingerprint
            or data.get("input_revision", input_revision) != input_revision
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
            or not isinstance(raw_path, str)
            or not Path(raw_path).is_absolute()
        ):
            return False
        try:
            job_dir = (self.db_path.parent / job_id).resolve()
            directory = Path(run_dir).resolve()
            path = Path(raw_path).resolve()
            return (
                directory.is_relative_to(job_dir)
                and path.is_relative_to(directory)
                and path.suffix == ".json"
            )
        except (OSError, RuntimeError, ValueError):
            return False

    def append_bound_event(
        self,
        job_id: str,
        *,
        run_id: str,
        owner_token: str,
        kind: str,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        expected_input_revision: Optional[str] = None,
        input_current_guard: Optional[Callable[[], None]] = None,
    ) -> Dict[str, Any]:
        """Commit a receipt under the current attempt lock, without a read/write gap.

        Ordinary append_event logs never create bound receipts. A checkpoint
        receipt names an immutable file inside its producer run directory;
        the receiver must independently verify bytes, instance identities and
        current semantic versions. The receipt alone is not analysis proof.
        """
        if kind == "instance_result_persisted":
            raise JobError(
                "reserved_event_kind",
                "instance results require current queue settlement",
                status_code=409,
            )
        payload = dict(data or {})
        plan = payload.get("plan_fingerprint", "")
        if not isinstance(plan, str):
            raise JobError(
                "invalid_checkpoint_binding", "invalid plan fingerprint", status_code=409
            )
        try:
            with self._write() as connection:
                job = self._checked_bound_job(
                    connection,
                    job_id=job_id,
                    run_id=run_id,
                    owner_token=owner_token,
                    input_revision=expected_input_revision,
                )
                if kind == "instance_checkpoint_persisted" and not self._checkpoint_data_bound(
                    payload,
                    job_id=job_id,
                    run_dir=str(job["run_dir"]),
                    input_revision=str(job["input_revision"]),
                    plan_fingerprint=plan,
                ):
                    raise JobError(
                        "invalid_checkpoint_binding",
                        "checkpoint coordinates do not match the run",
                        status_code=409,
                    )
                if input_current_guard is not None:
                    input_current_guard()
                seq = _append_event_on(
                    connection, job_id, run_id=run_id, kind=kind, message=message, data=payload
                )
                connection.execute(
                    "INSERT INTO bound_event_receipts "
                    "(event_seq,job_id,run_id,run_dir,input_revision,plan_fingerprint) VALUES (?,?,?,?,?,?)",
                    (
                        seq,
                        job_id,
                        run_id,
                        str(Path(job["run_dir"]).resolve()),
                        job["input_revision"],
                        plan,
                    ),
                )
                row = connection.execute("SELECT at FROM events WHERE seq=?", (seq,)).fetchone()
                assert row is not None
                return {
                    "seq": seq,
                    "at": row["at"],
                    "job_id": job_id,
                    "run_id": run_id,
                    "input_revision": job["input_revision"],
                    "plan_fingerprint": plan,
                }
        except sqlite3.Error as exc:
            raise JobError(
                "store_unreadable", "cannot publish a bound event", status_code=503
            ) from exc

    def _checked_instance_attempt(
        self,
        connection: sqlite3.Connection,
        *,
        current: "CurrentAttempt",
        expected: "RecoveryIdentity",
    ) -> Dict[str, Any]:
        if (
            not current.input_revision
            or current.job_id != expected.job_id
            or current.input_revision != expected.input_revision
            or not expected.plan_fingerprint
        ):
            raise JobError(
                "invalid_instance_binding", "unknown instance input or plan", status_code=409
            )
        job = self._checked_bound_job(
            connection,
            job_id=current.job_id,
            run_id=current.run_id,
            owner_token=current.owner_token,
            input_revision=current.input_revision,
        )
        directory = current.run_dir.resolve(strict=True)
        job_directory = (self.db_path.parent / current.job_id).resolve(strict=True)
        if (
            not directory.is_relative_to(job_directory)
            or directory == job_directory
            or directory != Path(job["run_dir"]).resolve(strict=True)
        ):
            raise JobError(
                "invalid_instance_binding", "current run directory changed", status_code=409
            )
        return job

    def _trusted_instance_results_on(
        self,
        connection: sqlite3.Connection,
        *,
        current: "CurrentAttempt",
        expected: "RecoveryIdentity",
        instances: Tuple["ExpectedInstance", ...],
    ) -> Tuple["TrustedInstanceResultReceipt", ...]:
        from .instance_results import TrustedInstanceResultReceipt

        self._checked_instance_attempt(connection, current=current, expected=expected)
        wanted = {instance.key.identity: instance for instance in instances}
        if len(wanted) != len(instances) or any(
            not all(asdict(instance.key).values()) or not _instance_sha(instance.semantics_digest)
            for instance in instances
        ):
            raise JobError(
                "invalid_instance_binding", "incomplete expected instance set", status_code=409
            )
        rows = connection.execute(
            "SELECT e.seq,e.kind,e.job_id AS event_job_id,e.run_id,e.data_json,"
            "r.run_id AS receipt_run_id,r.run_dir,r.input_revision,r.plan_fingerprint,"
            "a.attempt_no,a.input_revision AS attempt_input_revision "
            "FROM bound_event_receipts r LEFT JOIN events e ON e.seq=r.event_seq "
            "LEFT JOIN attempts a ON a.job_id=r.job_id AND a.run_id=r.run_id "
            "WHERE r.job_id=? AND r.input_revision=? AND r.plan_fingerprint=? "
            "ORDER BY r.event_seq DESC",
            (current.job_id, expected.input_revision, expected.plan_fingerprint),
        ).fetchall()
        seen: set[str] = set()
        result: list["TrustedInstanceResultReceipt"] = []
        job_directory = (self.db_path.parent / current.job_id).resolve(strict=True)
        for row in rows:
            if row["seq"] is None:
                return ()
            try:
                data = _instance_loads(row["data_json"])
                if (
                    row["kind"] != "instance_result_persisted"
                    and row["event_job_id"] == current.job_id
                    and row["run_id"] == row["receipt_run_id"]
                    and isinstance(data, dict)
                    and "instance" not in data
                ):
                    # Ordinary bound checkpoints/diagnostics do not shadow
                    # instance results and cannot authorize them.
                    continue
                identity = data["instance"]["identity"]
            except (TypeError, ValueError, KeyError, RuntimeError):
                # A malformed row with no attributable identity cannot authorize
                # older rows for an invented identity. Reanalyse conservatively.
                return ()
            if not isinstance(identity, str):
                return ()
            if identity not in wanted or identity in seen:
                continue
            seen.add(identity)
            target = wanted[identity]
            try:
                producer_directory = Path(row["run_dir"]).resolve(strict=True)
                artifact = Path(data["artifact_path"])
                digest = data["content_sha256"]
                byte_count = data["byte_count"]
                if (
                    row["kind"] != "instance_result_persisted"
                    or row["event_job_id"] != current.job_id
                    or row["run_id"] != row["receipt_run_id"]
                    or set(data)
                    != {
                        "identity",
                        "instance",
                        "producer_run_id",
                        "producer_attempt_no",
                        "instance_semantics_digest",
                        "artifact_path",
                        "content_sha256",
                        "byte_count",
                    }
                    or row["attempt_input_revision"] != expected.input_revision
                    or type(row["attempt_no"]) is not int
                    or row["attempt_no"] <= 0
                    or not producer_directory.is_relative_to(job_directory)
                    or producer_directory == job_directory
                    or data["producer_run_id"] != row["run_id"]
                    or type(data["producer_attempt_no"]) is not int
                    or data["producer_attempt_no"] != row["attempt_no"]
                    or _instance_json(data["identity"]) != _instance_json(asdict(expected))
                    or data["instance"] != asdict(target.key)
                    or data["instance_semantics_digest"] != target.semantics_digest
                    or not _instance_sha(digest)
                    or type(byte_count) is not int
                    or byte_count <= 0
                    or not artifact.is_absolute()
                    or artifact.is_symlink()
                    or (producer_directory / "instance-results").is_symlink()
                    or artifact.parent != producer_directory / "instance-results"
                    or artifact.name
                    != hashlib.sha256(identity.encode("utf-8")).hexdigest() + "." + digest + ".json"
                    or artifact.resolve(strict=True).parent
                    != (producer_directory / "instance-results").resolve(strict=True)
                ):
                    continue
                result.append(
                    TrustedInstanceResultReceipt(
                        event_seq=int(row["seq"]),
                        kind="instance_result_persisted",
                        producer_run_id=str(row["run_id"]),
                        producer_run_dir=producer_directory,
                        producer_attempt_no=int(row["attempt_no"]),
                        identity=expected,
                        instance=target.key,
                        instance_semantics_digest=target.semantics_digest,
                        artifact_path=artifact,
                        content_sha256=digest,
                        byte_count=byte_count,
                    )
                )
            except (OSError, RuntimeError, ValueError, TypeError, KeyError):
                continue
        return tuple(result)

    def trusted_instance_results(
        self,
        *,
        current: "CurrentAttempt",
        expected: "RecoveryIdentity",
        instances: Tuple["ExpectedInstance", ...],
    ) -> Tuple["TrustedInstanceResultReceipt", ...]:
        try:
            with self._write() as connection:
                return self._trusted_instance_results_on(
                    connection, current=current, expected=expected, instances=instances
                )
        except sqlite3.Error as exc:
            raise JobError(
                "store_unreadable", "cannot read bound instance results", status_code=503
            ) from exc

    def settle_instance_result(
        self,
        *,
        current: "CurrentAttempt",
        queue: "WorkQueue",
        claim: SettlementClaim,
        expected: "RecoveryIdentity",
        instance: "InstanceKey",
        mode: Literal["restored", "executed"],
        semantics_digest: str,
        prepared: Optional["PreparedInstanceResult"],
        restored_receipt: Optional["TrustedInstanceResultReceipt"],
        discoveries: Sequence[Dict[str, Any]],
        input_current_guard: Callable[[], None],
        now: Optional[float] = None,
    ) -> InstanceSettlementAck:
        """Store→queue fence; queue commit precedes the bound SQL receipt.

        The two DB transactions are deliberately not described as atomic.
        A crash or receipt failure after queue commit leaves no reusable result
        and the next run reanalyses that instance.
        """
        from .instance_results import (
            ExpectedInstance,
            FrozenJSON,
            RecoveryAccepted,
            TrustedInstanceResultReceipt,
            verify_instance_result,
        )
        from .work_queue import WorkQueue

        if (
            not isinstance(queue, WorkQueue)
            or mode not in {"restored", "executed"}
            or claim.kind != "instance_analysis"
            or claim.scope_key != instance.identity
            or claim.build != instance.build_context_id
            or not _instance_sha(semantics_digest)
            or queue.job_id != current.job_id
            or queue.input_revision != current.input_revision
            or not queue.db_path.resolve(strict=True).is_relative_to(
                current.run_dir.resolve(strict=True)
            )
        ):
            raise JobError(
                "invalid_instance_binding", "instance queue coordinates mismatch", status_code=409
            )
        with self._write() as connection:
            self._checked_instance_attempt(connection, current=current, expected=expected)
            attempt = connection.execute(
                "SELECT attempt_no,input_revision FROM attempts WHERE job_id=? AND run_id=?",
                (current.job_id, current.run_id),
            ).fetchone()
            if attempt is None or attempt["input_revision"] != current.input_revision:
                raise JobError(
                    "invalid_instance_binding", "producer attempt missing", status_code=409
                )
            input_current_guard()
            receipt: Optional["TrustedInstanceResultReceipt"] = None
            if mode == "executed" and restored_receipt is not None:
                raise JobError(
                    "invalid_instance_binding",
                    "executed result cannot carry a restore receipt",
                    status_code=409,
                )
            if mode == "restored":
                if prepared is not None or restored_receipt is None:
                    raise JobError(
                        "invalid_instance_binding", "restore receipt required", status_code=409
                    )
                trusted = self._trusted_instance_results_on(
                    connection,
                    current=current,
                    expected=expected,
                    instances=(ExpectedInstance(instance, semantics_digest),),
                )
                if restored_receipt not in trusted:
                    raise JobError(
                        "invalid_instance_binding",
                        "restore receipt no longer current",
                        status_code=409,
                    )
                receipt = restored_receipt
            elif prepared is not None:
                if (
                    restored_receipt is not None
                    or prepared.payload.producer_run_id != current.run_id
                ):
                    raise JobError(
                        "invalid_instance_binding", "executed producer mismatch", status_code=409
                    )
                receipt = TrustedInstanceResultReceipt(
                    event_seq=1,
                    kind="instance_result_persisted",
                    producer_run_id=current.run_id,
                    producer_run_dir=current.run_dir.resolve(strict=True),
                    producer_attempt_no=int(attempt["attempt_no"]),
                    identity=expected,
                    instance=instance,
                    instance_semantics_digest=semantics_digest,
                    artifact_path=prepared.artifact_path,
                    content_sha256=prepared.content_sha256,
                    byte_count=prepared.byte_count,
                )
            if receipt is not None:
                verified = verify_instance_result(
                    receipt,
                    expected=expected,
                    instance=ExpectedInstance(instance, semantics_digest),
                )
                if not isinstance(verified, RecoveryAccepted):
                    raise JobError(
                        "invalid_instance_binding",
                        "instance artifact verification failed",
                        status_code=409,
                    )
                if prepared is not None and verified.payload != prepared.payload:
                    raise JobError(
                        "invalid_instance_binding", "prepared artifact changed", status_code=409
                    )
            receipt_data: Optional[Dict[str, Any]] = None
            if prepared is not None:
                data = {
                    "identity": asdict(expected),
                    "instance": asdict(instance),
                    "producer_run_id": current.run_id,
                    "producer_attempt_no": int(attempt["attempt_no"]),
                    "instance_semantics_digest": semantics_digest,
                    "artifact_path": str(prepared.artifact_path),
                    "content_sha256": prepared.content_sha256,
                    "byte_count": prepared.byte_count,
                }
                # Recovery metadata must survive the real event writer's
                # default-space, character-based bounds without truncation.
                # Check before committing the separate queue transaction and
                # reuse this exact normalized JSON data for the SQL insert.
                receipt_data = bounded_event_data(data)
                if _instance_json(receipt_data) != _instance_json(data):
                    raise JobError(
                        "invalid_instance_binding",
                        "instance result receipt exceeds event bounds",
                        status_code=409,
                    )
            input_current_guard()
            result = queue.settle(
                claim.item_id,
                action="complete",
                claim_token=claim.claim_token,
                discoveries=list(discoveries),
                expected_input_revision=current.input_revision,
                now=now,
            )
            if (
                result.get("item_id") != claim.item_id
                or result.get("kind") != claim.kind
                or result.get("scope_key") != instance.identity
                or result.get("build") != instance.build_context_id
            ):
                raise JobError(
                    "invalid_instance_binding",
                    "settled queue item coordinates mismatch",
                    status_code=409,
                )
            committed = result.get("status") == "completed"
            if committed:
                input_current_guard()
            if (
                committed
                and prepared is not None
                and receipt is not None
                and receipt_data is not None
            ):
                seq = _append_event_on(
                    connection,
                    current.job_id,
                    run_id=current.run_id,
                    kind="instance_result_persisted",
                    message="complete prevalidation instance result settled",
                    data=receipt_data,
                )
                connection.execute(
                    "INSERT INTO bound_event_receipts (event_seq,job_id,run_id,run_dir,input_revision,plan_fingerprint) VALUES (?,?,?,?,?,?)",
                    (
                        seq,
                        current.job_id,
                        current.run_id,
                        str(current.run_dir.resolve(strict=True)),
                        current.input_revision,
                        expected.plan_fingerprint,
                    ),
                )
                receipt = replace(receipt, event_seq=seq)
            return InstanceSettlementAck(
                identity=instance.identity,
                mode=mode,
                committed=committed,
                queue_result_json=FrozenJSON(_instance_json(result)),
                receipt=receipt if committed else None,
                reuse_unavailable_reason=(
                    "instance_result_not_prepared"
                    if committed and prepared is None and mode == "executed"
                    else None
                ),
            )

    def trusted_completion(
        self,
        job_id: str,
        *,
        run_id: str,
        owner_token: str,
        input_revision: str,
        plan_fingerprint: str,
    ) -> Optional[Dict[str, Any]]:
        """Read a bound completion for this exact input/plan under a current owner.

        A prior run may supply its immutable file receipt. Same job, current
        owner, exact input and exact plan are all required; legacy log events
        cannot supply authority. Callers must verify the file and recheck the
        current binding before publishing restored state.
        """
        if not input_revision or not plan_fingerprint:
            raise JobError("invalid_checkpoint_binding", "unknown input or plan", status_code=409)
        try:
            with self._write() as connection:
                self._checked_bound_job(
                    connection,
                    job_id=job_id,
                    run_id=run_id,
                    owner_token=owner_token,
                    input_revision=input_revision,
                )
                row = connection.execute(
                    "SELECT e.*,r.run_dir AS receipt_run_dir,r.input_revision AS receipt_input_revision,"
                    "r.plan_fingerprint AS receipt_plan FROM bound_event_receipts r "
                    "JOIN events e ON e.seq=r.event_seq AND e.job_id=r.job_id AND e.run_id=r.run_id "
                    "WHERE r.job_id=? AND r.input_revision=? AND r.plan_fingerprint=? "
                    "AND e.kind='instance_checkpoint_persisted' ORDER BY r.event_seq DESC LIMIT 1",
                    (job_id, input_revision, plan_fingerprint),
                ).fetchone()
                if row is None:
                    return None
                try:
                    data = json.loads(row["data_json"])
                except (TypeError, ValueError):
                    return None
                if not isinstance(data, dict) or not self._checkpoint_data_bound(
                    data,
                    job_id=job_id,
                    run_dir=row["receipt_run_dir"],
                    input_revision=input_revision,
                    plan_fingerprint=plan_fingerprint,
                ):
                    return None
                return {
                    "seq": int(row["seq"]),
                    "at": row["at"],
                    "job_id": job_id,
                    "run_id": row["run_id"],
                    "run_dir": row["receipt_run_dir"],
                    "input_revision": row["receipt_input_revision"],
                    "plan_fingerprint": row["receipt_plan"],
                    "data": data,
                }
        except sqlite3.Error as exc:
            raise JobError(
                "store_unreadable", "cannot read a bound completion", status_code=503
            ) from exc

    def latest_event(self, job_id: str, *, run_id: str, kind: str) -> Optional[Dict[str, Any]]:
        """Read one current-attempt receipt without paging historical events."""
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM events WHERE job_id=? AND run_id=? AND kind=? "
                "ORDER BY seq DESC LIMIT 1",
                (job_id, run_id, kind),
            ).fetchone()
        if row is None:
            return None
        try:
            data = json.loads(row["data_json"] or "{}")
        except (ValueError, TypeError):
            data = {}
        return {
            "seq": int(row["seq"]),
            "job_id": row["job_id"],
            "run_id": row["run_id"],
            "at": row["at"],
            "kind": row["kind"],
            "message": row["message"],
            "data": data if isinstance(data, dict) else {},
        }

    def list_events(
        self, job_id: str, *, after_seq: int, limit: int
    ) -> tuple[List[Dict[str, Any]], bool]:
        with self._read() as connection:
            rows = connection.execute(
                "SELECT * FROM events WHERE job_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
                (job_id, after_seq, limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        events: List[Dict[str, Any]] = []
        for row in rows[:limit]:
            try:
                data = json.loads(row["data_json"] or "{}")
            except (TypeError, ValueError):
                data = {}
            events.append(
                {
                    "seq": int(row["seq"]),
                    "job_id": row["job_id"],
                    "run_id": row["run_id"],
                    "at": row["at"],
                    "kind": row["kind"],
                    "message": row["message"],
                    "data": data,
                }
            )
        return events, has_more

    # -- request idempotency ---------------------------------------------------

    def get_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM requests WHERE request_id = ?", (request_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def record_request(
        self,
        *,
        request_id: str,
        endpoint: str,
        payload_hash: str,
        job_id: str,
    ) -> None:
        with self._write() as connection:
            connection.execute(
                "INSERT INTO requests (request_id, endpoint, payload_hash, job_id, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (request_id, endpoint, payload_hash, job_id, utc_now_iso()),
            )

    def record_request_if_new(
        self,
        *,
        request_id: str,
        endpoint: str,
        payload_hash: str,
        job_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Insert the request marker; return the conflicting row when present."""

        with self._write() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO requests "
                "(request_id, endpoint, payload_hash, job_id, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (request_id, endpoint, payload_hash, job_id, utc_now_iso()),
            )
            if cursor.rowcount == 1:
                return None
            row = connection.execute(
                "SELECT * FROM requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            return dict(row) if row is not None else None

    # -- transactional request reservations ------------------------------------

    @staticmethod
    def _raise_on_marker_mismatch(
        row: sqlite3.Row,
        request_id: str,
        endpoint: str,
        payload_hash: str,
    ) -> None:
        if row["endpoint"] != endpoint or row["payload_hash"] != payload_hash:
            raise JobError(
                "request_id_conflict",
                "request_id was already used with a different request",
                status_code=409,
                details={"request_id": request_id},
            )

    @staticmethod
    def _insert_request(
        connection: sqlite3.Connection,
        request_id: str,
        endpoint: str,
        payload_hash: str,
        job_id: str,
        now: str,
    ) -> None:
        connection.execute(
            "INSERT INTO requests (request_id, endpoint, payload_hash, job_id, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (request_id, endpoint, payload_hash, job_id, now),
        )

    def create_job_with_request(
        self,
        *,
        fields: Dict[str, Any],
        request_id: str,
        endpoint: str,
        payload_hash: str,
    ) -> RequestReservation:
        """Atomically create the job row and register its request marker.

        The marker and the job row commit together in one IMMEDIATE
        transaction, before any launch side effect: a duplicate request with
        the same endpoint and payload replays the marker's job (across
        service instances, processes and restarts), a different payload on
        the same key fails with 409 without creating anything, and the
        project's single-active-scan mutex holds in the same transaction.
        """

        payload = {column: fields.get(column) for column in _JOB_COLUMNS}
        for key, default in (
            ("progress_json", {}),
            ("coverage_json", {}),
            ("report_json", {}),
            ("input_components_json", {}),
            ("questions_json", []),
            ("artifacts_json", []),
        ):
            payload[key] = json.dumps(payload[key] if payload[key] is not None else default)
        columns = ", ".join(_JOB_COLUMNS)
        placeholders = ", ".join(f":{column}" for column in _JOB_COLUMNS)
        try:
            with self._write() as connection:
                existing = connection.execute(
                    "SELECT endpoint, payload_hash, job_id FROM requests " "WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if existing is not None:
                    self._raise_on_marker_mismatch(existing, request_id, endpoint, payload_hash)
                    return RequestReservation(False, str(existing["job_id"]))
                active = connection.execute(
                    "SELECT job_id, status FROM jobs "
                    "WHERE status IN ('queued', 'running', 'stopping') LIMIT 1"
                ).fetchone()
                if active is not None:
                    raise JobError(
                        "project_scan_active",
                        "another scan job is already active for this project",
                        status_code=409,
                        details={
                            "active_job_id": active["job_id"],
                            "status": active["status"],
                        },
                    )
                connection.execute(f"INSERT INTO jobs ({columns}) VALUES ({placeholders})", payload)
                self._insert_request(
                    connection,
                    request_id,
                    endpoint,
                    payload_hash,
                    str(fields["job_id"]),
                    utc_now_iso(),
                )
                job = self.get_job_for_update(connection, str(fields["job_id"]))
                assert job is not None  # nosec - inserted in this transaction
                return RequestReservation(True, str(fields["job_id"]), job)
        except JobError:
            raise
        except sqlite3.Error as exc:
            raise JobError(
                "store_unavailable",
                f"cannot create job: {exc}",
                status_code=503,
            ) from exc

    def arm_attempt_with_request(
        self,
        *,
        job_id: str,
        expected_revision: int,
        from_statuses: Tuple[str, ...],
        updates: Dict[str, Any],
        request_id: str,
        endpoint: str,
        payload_hash: str,
    ) -> RequestReservation:
        """Atomically re-arm the job for a new attempt and register the marker.

        The marker check, the status+revision guard and the re-arm update
        commit in one IMMEDIATE transaction, so a duplicate resume replays
        the armed attempt, a conflicting key starts no work, and a stale
        base_revision can never arm a second attempt.
        """

        assignments: List[str] = []
        params: Dict[str, Any] = {"job_id": job_id, "expected_revision": expected_revision}
        for key, value in updates.items():
            if key not in _JOB_COLUMNS or key == "job_id":
                raise ValueError(f"cannot update job column {key!r}")
            if key.endswith("_json") and not isinstance(value, str):
                value = json.dumps(value)
            assignments.append(f"{key} = :u_{key}")
            params[f"u_{key}"] = value
        assignments.append("revision = revision + 1")
        assignments.append("updated_at = :u_updated_at")
        params["u_updated_at"] = utc_now_iso()
        with self._write() as connection:
            existing = connection.execute(
                "SELECT endpoint, payload_hash, job_id FROM requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if existing is not None:
                self._raise_on_marker_mismatch(existing, request_id, endpoint, payload_hash)
                return RequestReservation(False, str(existing["job_id"]))
            current = self.get_job_for_update(connection, job_id)
            if current is None:
                raise JobError("job_not_found", f"unknown job_id {job_id!r}", status_code=404)
            if int(current["revision"]) != expected_revision:
                raise JobError(
                    "revision_conflict",
                    "base_revision does not match the current job revision",
                    status_code=409,
                    details={
                        "job_id": job_id,
                        "expected_revision": expected_revision,
                        "current_revision": int(current["revision"]),
                    },
                )
            if current["status"] not in from_statuses:
                raise JobError(
                    "invalid_state",
                    f"job is {current['status']!r}; expected one of {sorted(from_statuses)}",
                    status_code=409,
                    details={"job_id": job_id, "status": current["status"]},
                )
            connection.execute(
                f"UPDATE jobs SET {', '.join(assignments)} "
                "WHERE job_id = :job_id AND revision = :expected_revision",
                params,
            )
            self._insert_request(
                connection, request_id, endpoint, payload_hash, job_id, utc_now_iso()
            )
            updated = self.get_job_for_update(connection, job_id)
            assert updated is not None
            return RequestReservation(True, job_id, updated)

    def cancel_with_request(
        self,
        *,
        job_id: str,
        expected_revision: int,
        request_id: str,
        endpoint: str,
        payload_hash: str,
    ) -> RequestReservation:
        """Atomically register the cancel request and apply its action.

        Cancellable jobs get ``cancel_requested_at`` (their owner finalizes
        the teardown).  A queued job whose owner was never spawned has
        nothing to observe that flag, so it is finalized to ``cancelled``
        inside the same transaction together with its attempt row and
        terminal event.  A ``stopping`` job only registers the marker — the
        cancellation is already in progress.
        """

        now = utc_now_iso()
        with self._write() as connection:
            existing = connection.execute(
                "SELECT endpoint, payload_hash, job_id FROM requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if existing is not None:
                self._raise_on_marker_mismatch(existing, request_id, endpoint, payload_hash)
                return RequestReservation(False, str(existing["job_id"]))
            current = self.get_job_for_update(connection, job_id)
            if current is None:
                raise JobError("job_not_found", f"unknown job_id {job_id!r}", status_code=404)
            status = str(current["status"])
            if status not in ("queued", "running", "stopping"):
                raise JobError(
                    "invalid_state",
                    f"cannot cancel a job in state {status!r}",
                    status_code=409,
                    details={"job_id": job_id, "status": status},
                )
            if status == "stopping":
                self._insert_request(connection, request_id, endpoint, payload_hash, job_id, now)
                return RequestReservation(True, job_id, current)
            if int(current["revision"]) != expected_revision:
                raise JobError(
                    "revision_conflict",
                    "base_revision does not match the current job revision",
                    status_code=409,
                    details={
                        "job_id": job_id,
                        "expected_revision": expected_revision,
                        "current_revision": int(current["revision"]),
                    },
                )
            self._insert_request(connection, request_id, endpoint, payload_hash, job_id, now)
            if status == "queued" and current["owner_pid"] is None:
                # No owner exists for this run; a cancel flag alone would
                # never be observed.  Finalize honestly inside the marker
                # transaction, keeping the attempt record bound.
                connection.execute(
                    "UPDATE jobs SET status = 'cancelled', phase = NULL, "
                    "cancel_requested_at = :cancel_at, error_code = :code, "
                    "error_message = :message, revision = revision + 1, "
                    "updated_at = :cancel_at "
                    "WHERE job_id = :job_id AND revision = :expected_revision",
                    {
                        "cancel_at": now,
                        "code": "cancelled",
                        "message": "cancelled before the owner process started",
                        "job_id": job_id,
                        "expected_revision": expected_revision,
                    },
                )
                _finish_attempt_on(
                    connection,
                    job_id,
                    str(current["run_id"]),
                    {
                        "status": "cancelled",
                        "ended_at": now,
                        "error_code": "cancelled",
                        "error_message": "cancelled before the owner process started",
                    },
                )
                _append_event_on(
                    connection,
                    job_id,
                    run_id=str(current["run_id"]),
                    kind="cancel_requested",
                    message="cancel requested; the owner stops scheduling and reaps its group",
                    data={"base_revision": expected_revision},
                )
                _append_event_on(
                    connection,
                    job_id,
                    run_id=str(current["run_id"]),
                    kind="job_terminal",
                    message="job reached terminal state cancelled",
                    data={
                        "status": "cancelled",
                        "exit_code": None,
                        "error_code": "cancelled",
                    },
                )
                updated = self.get_job_for_update(connection, job_id)
                assert updated is not None
                return RequestReservation(True, job_id, updated)
            connection.execute(
                "UPDATE jobs SET cancel_requested_at = :cancel_at, "
                "revision = revision + 1, updated_at = :cancel_at "
                "WHERE job_id = :job_id AND revision = :expected_revision",
                {
                    "cancel_at": now,
                    "job_id": job_id,
                    "expected_revision": expected_revision,
                },
            )
            _append_event_on(
                connection,
                job_id,
                run_id=str(current["run_id"]),
                kind="cancel_requested",
                message="cancel requested; the owner stops scheduling and reaps its group",
                data={"base_revision": expected_revision},
            )
            updated = self.get_job_for_update(connection, job_id)
            assert updated is not None
            return RequestReservation(True, job_id, updated)
