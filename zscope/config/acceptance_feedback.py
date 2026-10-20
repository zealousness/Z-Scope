"""Persistent acceptance dispositions bound to server-resolved issue identity.

Implements the storage and service boundary for the internal coordination
contract ``zscope.acceptance-dispositions.v1``.  Dispositions
(``duplicate``/``risk_accept``/``followup``/``clear``) are acceptance markers
only: they never write validation verdicts, business answers, baselines,
suppressions, or Review Memory, and they never hide a pending issue.

The store only accepts an :class:`IssueScope` derived by the backend from the
current report.  Clients never supply digests, object identity, or paths; the
coordinator injects a resolver (see :func:`resolver_from_report`) so every
GET/POST re-binds to the live report, the exact build context, and the object
digest.  A changed report, issue, build, or object digest starts a fresh
identity chain instead of reusing stale feedback; an unknown build context is
never treated as a wildcard.

Persistence uses one dedicated SQLite database with ``BEGIN IMMEDIATE``
transactions, a per-identity monotonic revision for optimistic concurrency,
and a ``request_id`` ledger so retries are idempotent while reusing the same
request id for a different payload is rejected.  ``clear`` and identity
changes keep the full history; ``risk_accept`` may carry an ``expires_at``
after which the marker lapses and the issue shows its natural state again.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Callable, Mapping, Optional

from ..common.issue_identity import (
    first_issue_value,
    issue_build_context_id,
    issue_resource_signature,
)
from ..reporting.issue_markdown import (
    context_revision,
    digest,
    issue_identity,
    review_revision,
)
from ..reporting.views import (
    DEFAULT_REPORT_VIEW,
    WITH_NEEDS_REVIEW_REPORT_VIEW,
    findings_for_view,
)

SCHEMA = "zscope.acceptance-dispositions.v1"
DISPOSITION_TYPES = frozenset({"duplicate", "risk_accept", "followup", "clear"})

MAX_ID_CHARS = 512
MAX_REQUEST_ID_CHARS = 128
MAX_REASON_CHARS = 2000
MAX_TITLE_CHARS = 200

Clock = Callable[[], datetime]
Resolver = Callable[[str, str], Optional["IssueResolution"]]

_REQUIRED_POST_KEYS = {
    "report_id",
    "issue_id",
    "build_context_id",
    "base_revision",
    "request_id",
    "type",
}
_ALLOWED_POST_KEYS = _REQUIRED_POST_KEYS | {"reason", "duplicate_of", "title", "expires_at"}
# Optional detail each disposition type accepts; anything else is rejected so
# only fields with a real consumer are ever persisted.
_TYPE_OPTIONAL_FIELDS = {
    "duplicate": frozenset({"duplicate_of"}),
    "risk_accept": frozenset({"expires_at"}),
    "followup": frozenset({"title"}),
    "clear": frozenset(),
}


class DispositionError(Exception):
    """Safe, contract-mappable failure; never carries paths or secrets."""

    status_code = 400
    code = "invalid_request"

    def __init__(self, message: str, *, code: Optional[str] = None):
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code


class DispositionValidationError(DispositionError):
    status_code = 400
    code = "invalid_request"


class DispositionNotFound(DispositionError):
    status_code = 404
    code = "not_found"


class DispositionConflict(DispositionError):
    status_code = 409
    code = "conflict"


class DispositionUnavailable(DispositionError):
    status_code = 503
    code = "unavailable"

    def __init__(self) -> None:
        super().__init__("处置存储暂不可用，请稍后重试", code=self.code)


@dataclass(frozen=True)
class IssueScope:
    """Server-derived identity of one issue in the current report.

    ``build_context_id`` of ``None`` means the build is unknown and matches
    only another unknown build; it is never a wildcard.
    """

    report_id: str
    issue_id: str
    build_context_id: Optional[str]
    issue_digest: str
    object_digest: str

    @property
    def scope_key(self) -> str:
        return digest(
            {
                "report_id": self.report_id,
                "issue_id": self.issue_id,
                "build_context_id": self.build_context_id,
                "issue_digest": self.issue_digest,
                "object_digest": self.object_digest,
            }
        )


@dataclass(frozen=True)
class IssueResolution:
    """One resolved issue plus the eligible ``duplicate_of`` targets.

    ``duplicate_targets`` holds the server-computed issue ids of the current
    report that are real, distinct from the issue, and in the same build.
    """

    scope: IssueScope
    duplicate_targets: frozenset


def _issue_object_digest(issue: Mapping[str, Any]) -> str:
    """Digest of the concrete object identity; empty when none is known."""
    resource = issue_resource_signature(dict(issue))
    explicit = first_issue_value(
        dict(issue),
        "affected_object",
        "resource_object",
        "object_uid",
        "owner_object",
        "resource",
    )
    if not resource and not explicit:
        return ""
    return digest({"object": explicit, "resource_signature": resource})


def resolver_from_report(report: Mapping[str, Any], *, report_id: str) -> Resolver:
    """Build a resolver binding dispositions to the current server report.

    The coordinator passes the canonical ``report_identity`` so this module
    never re-derives report identity behind the web layer's back.  Issues
    whose identity is ambiguous cannot be bound and resolve to ``None``.
    """
    if not isinstance(report_id, str) or not report_id:
        raise ValueError("report_id 必须为非空字符串")
    catalog: dict[str, dict[str, Any]] = {}
    ambiguous: set[str] = set()
    source = report if isinstance(report, Mapping) else {}
    for view in (DEFAULT_REPORT_VIEW, WITH_NEEDS_REVIEW_REPORT_VIEW):
        for issue in findings_for_view(dict(source), view):
            key = issue_identity(issue)
            if key in catalog and review_revision(catalog[key]) != review_revision(issue):
                ambiguous.add(key)
            catalog.setdefault(key, issue)
    scopes: dict[str, IssueScope] = {}
    for key, issue in catalog.items():
        if key in ambiguous:
            continue
        scopes[key] = IssueScope(
            report_id=report_id,
            issue_id=key,
            build_context_id=issue_build_context_id(issue) or None,
            issue_digest=context_revision(issue),
            object_digest=_issue_object_digest(issue),
        )

    def resolve(requested_report_id: str, requested_issue_id: str) -> Optional[IssueResolution]:
        if requested_report_id != report_id:
            return None
        scope = scopes.get(requested_issue_id)
        if scope is None:
            return None
        targets = frozenset(
            key
            for key, candidate in scopes.items()
            if key != scope.issue_id and candidate.build_context_id == scope.build_context_id
        )
        return IssueResolution(scope=scope, duplicate_targets=targets)

    return resolve


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso8601(value: str) -> datetime:
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise DispositionValidationError("时间必须是 ISO8601 格式") from None
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        raise DispositionValidationError("时间必须携带时区偏移")
    return parsed


def _require_text(value: Any, field: str, *, max_chars: int, required: bool) -> str:
    if value is None:
        if required:
            raise DispositionValidationError(f"缺少{field}")
        return ""
    if not isinstance(value, str):
        raise DispositionValidationError(f"{field}必须是字符串")
    if "\x00" in value:
        raise DispositionValidationError(f"{field}包含非法字符")
    text = value.strip()
    if required and not text:
        raise DispositionValidationError(f"请填写{field}")
    if len(text) > max_chars:
        raise DispositionValidationError(f"{field}长度不能超过 {max_chars} 字")
    return text


def _require_token(value: Any, field: str, *, max_chars: int) -> str:
    """Identity/idempotency token: exact, visible, and control-character free."""
    if not isinstance(value, str):
        raise DispositionValidationError(f"{field}必须是字符串")
    if not value or value != value.strip():
        raise DispositionValidationError(f"{field}不能为空或包含首尾空白")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise DispositionValidationError(f"{field}包含非法字符")
    if len(value) > max_chars:
        raise DispositionValidationError(f"{field}长度不能超过 {max_chars} 字")
    return value


def validate_command(command: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
    """Validate one disposition command and return its normalized form."""
    disposition_type = command.get("type")
    if not isinstance(disposition_type, str) or disposition_type not in DISPOSITION_TYPES:
        raise DispositionValidationError("处置类型必须是 duplicate/risk_accept/followup/clear")
    base_revision = command.get("base_revision")
    if type(base_revision) is not int or base_revision < 0:
        raise DispositionValidationError("base_revision 必须是非负整数")
    request_id = _require_token(command.get("request_id"), "request_id", max_chars=MAX_REQUEST_ID_CHARS)
    reason = _require_text(
        command.get("reason"),
        "处置说明",
        max_chars=MAX_REASON_CHARS,
        required=disposition_type != "clear",
    )
    allowed = _TYPE_OPTIONAL_FIELDS[disposition_type]
    duplicate_of = _require_text(
        command.get("duplicate_of"),
        "duplicate_of",
        max_chars=MAX_ID_CHARS,
        required=disposition_type == "duplicate",
    )
    title = _require_text(command.get("title"), "标题", max_chars=MAX_TITLE_CHARS, required=False)
    expires_raw = command.get("expires_at")
    expires_at = ""
    if expires_raw not in (None, ""):
        expires_at = _parse_iso8601(str(expires_raw)).astimezone(timezone.utc).isoformat()
    for field, value in (("duplicate_of", duplicate_of), ("title", title), ("expires_at", expires_at)):
        if field not in allowed and value:
            raise DispositionValidationError(f"{disposition_type} 处置不接受 {field}")
    if disposition_type == "risk_accept" and expires_at:
        if _parse_iso8601(expires_at) <= now:
            raise DispositionValidationError("风险接受过期时间必须晚于当前时间")
    return {
        "type": disposition_type,
        "reason": reason,
        "duplicate_of": duplicate_of or None,
        "title": title or None,
        "expires_at": expires_at or None,
        "base_revision": base_revision,
        "request_id": request_id,
    }


def _row_disposition(row: sqlite3.Row) -> dict[str, Any]:
    disposition: dict[str, Any] = {"type": row["type"], "reason": row["reason"]}
    if row["duplicate_of"]:
        disposition["duplicate_of"] = row["duplicate_of"]
    if row["title"]:
        disposition["title"] = row["title"]
    if row["expires_at"]:
        disposition["expires_at"] = row["expires_at"]
    disposition["updated_at"] = row["updated_at"]
    disposition["request_id"] = row["request_id"]
    return disposition


def disposition_envelope(
    *,
    scope: IssueScope,
    revision: int,
    disposition: Optional[dict[str, Any]],
    writable: bool,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "report_id": scope.report_id,
        "issue_id": scope.issue_id,
        "build_context_id": scope.build_context_id,
        "revision": revision,
        "disposition": disposition,
        "writable": bool(writable),
    }


def error_envelope(exc: DispositionError) -> dict[str, Any]:
    return {"error": exc.message, "code": exc.code}


class AcceptanceFeedbackStore:
    """SQLite-backed disposition store; the only writer of its own database."""

    def __init__(self, db_path: Any, *, clock: Optional[Clock] = None):
        self.db_path = Path(db_path)
        self._clock: Clock = clock or _utc_now
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def now(self) -> datetime:
        return self._clock()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS acceptance_dispositions (
                    scope_key TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    request_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    duplicate_of TEXT,
                    title TEXT,
                    expires_at TEXT,
                    report_id TEXT NOT NULL,
                    issue_id TEXT NOT NULL,
                    build_context_id TEXT,
                    issue_digest TEXT NOT NULL,
                    object_digest TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (scope_key, revision)
                );
                CREATE TABLE IF NOT EXISTS acceptance_disposition_requests (
                    request_id TEXT PRIMARY KEY,
                    scope_key TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    outcome_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _latest_row(self, conn: sqlite3.Connection, scope_key: str) -> Optional[sqlite3.Row]:
        row: Optional[sqlite3.Row] = conn.execute(
            "SELECT * FROM acceptance_dispositions WHERE scope_key = ? "
            "ORDER BY revision DESC LIMIT 1",
            (scope_key,),
        ).fetchone()
        return row

    def _is_active(self, row: sqlite3.Row) -> bool:
        if row["type"] == "clear":
            return False
        if row["type"] == "risk_accept" and row["expires_at"]:
            if _parse_iso8601(str(row["expires_at"])) <= self.now():
                return False
        return True

    def current(self, scope: IssueScope) -> dict[str, Any]:
        """Return ``{"revision": int, "disposition": dict|None}`` for one scope."""
        conn = self._connect()
        try:
            row = self._latest_row(conn, scope.scope_key)
            if row is None:
                return {"revision": 0, "disposition": None}
            return {
                "revision": int(row["revision"]),
                "disposition": _row_disposition(row) if self._is_active(row) else None,
            }
        finally:
            conn.close()

    def save(self, scope: IssueScope, command: Mapping[str, Any]) -> dict[str, Any]:
        """Atomically append one disposition; conflicts never lose old records."""
        prepared = validate_command(command, now=self.now())
        payload_digest = digest({"scope_key": scope.scope_key, **prepared})
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            ledger = conn.execute(
                "SELECT * FROM acceptance_disposition_requests WHERE request_id = ?",
                (prepared["request_id"],),
            ).fetchone()
            if ledger is not None:
                if (
                    ledger["scope_key"] != scope.scope_key
                    or ledger["payload_digest"] != payload_digest
                ):
                    raise DispositionConflict(
                        "同一 request_id 已用于不同请求", code="request_id_conflict"
                    )
                conn.commit()
                replayed: dict[str, Any] = json.loads(str(ledger["outcome_json"]))
                return replayed
            latest = self._latest_row(conn, scope.scope_key)
            current_revision = int(latest["revision"]) if latest is not None else 0
            if prepared["base_revision"] != current_revision:
                raise DispositionConflict(
                    "处置状态已变化，保留草稿；请刷新后重试", code="revision_conflict"
                )
            if prepared["type"] == "clear" and (
                latest is None or not self._is_active(latest)
            ):
                raise DispositionValidationError("当前没有可撤回的处置")
            new_revision = current_revision + 1
            updated_at = self.now().isoformat()
            conn.execute(
                "INSERT INTO acceptance_dispositions "
                "(scope_key, revision, request_id, type, reason, duplicate_of, title, "
                "expires_at, report_id, issue_id, build_context_id, issue_digest, "
                "object_digest, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scope.scope_key,
                    new_revision,
                    prepared["request_id"],
                    prepared["type"],
                    prepared["reason"],
                    prepared["duplicate_of"],
                    prepared["title"],
                    prepared["expires_at"],
                    scope.report_id,
                    scope.issue_id,
                    scope.build_context_id,
                    scope.issue_digest,
                    scope.object_digest,
                    updated_at,
                ),
            )
            if prepared["type"] == "clear":
                outcome: dict[str, Any] = {"revision": new_revision, "disposition": None}
            else:
                outcome = {
                    "revision": new_revision,
                    "disposition": {
                        key: value
                        for key, value in (
                            ("type", prepared["type"]),
                            ("reason", prepared["reason"]),
                            ("duplicate_of", prepared["duplicate_of"]),
                            ("title", prepared["title"]),
                            ("expires_at", prepared["expires_at"]),
                            ("updated_at", updated_at),
                            ("request_id", prepared["request_id"]),
                        )
                        if value is not None
                    },
                }
            conn.execute(
                "INSERT INTO acceptance_disposition_requests "
                "(request_id, scope_key, payload_digest, revision, outcome_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    prepared["request_id"],
                    scope.scope_key,
                    payload_digest,
                    new_revision,
                    json.dumps(outcome, ensure_ascii=False, sort_keys=True),
                    updated_at,
                ),
            )
            conn.commit()
            return outcome
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def history(self, report_id: str, issue_id: str) -> list[dict[str, Any]]:
        """Return every recorded row for one issue, including cleared/stale chains."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM acceptance_dispositions WHERE report_id = ? AND issue_id = ? "
                "ORDER BY rowid",
                (report_id, issue_id),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()


class AcceptanceDispositionService:
    """GET/POST wiring boundary for the coordinator's HTTP layer.

    ``resolve`` is injected per request so binding always uses the report the
    server holds right now; client-supplied identity fields are only lookup
    hints and are re-checked against the resolved scope.
    """

    def __init__(self, store: AcceptanceFeedbackStore, *, writable: bool = True):
        self.store = store
        self.writable = bool(writable)

    def get_dispositions(self, query: Mapping[str, Any], resolve: Resolver) -> tuple[int, dict[str, Any]]:
        try:
            report_id, issue_id = self._read_query(query)
            resolution = resolve(report_id, issue_id)
            if resolution is None:
                raise DispositionNotFound("报告或问题不存在，请刷新列表")
            state = self.store.current(resolution.scope)
        except DispositionError as exc:
            return exc.status_code, error_envelope(exc)
        except sqlite3.Error:
            return DispositionUnavailable.status_code, error_envelope(DispositionUnavailable())
        envelope = disposition_envelope(
            scope=resolution.scope,
            revision=int(state["revision"]),
            disposition=state["disposition"],
            writable=self.writable,
        )
        return 200, envelope

    def post_disposition(self, payload: Any, resolve: Resolver) -> tuple[int, dict[str, Any]]:
        try:
            command = self._read_command(payload)
            resolution = resolve(command["report_id"], command["issue_id"])
            if resolution is None:
                raise DispositionConflict(
                    "报告或问题已变化，保留草稿；请重新载入后核对", code="stale_scope"
                )
            scope = resolution.scope
            if command["build_context_id"] != scope.build_context_id:
                raise DispositionConflict(
                    "构建身份与当前问题不一致，保留草稿；请刷新后核对", code="stale_scope"
                )
            if command["type"] == "duplicate":
                target = command["duplicate_of"]
                if target == scope.issue_id or target not in resolution.duplicate_targets:
                    raise DispositionValidationError(
                        "duplicate_of 必须是当前报告中真实、不同且同构建的问题"
                    )
            state = self.store.save(scope, command)
        except DispositionError as exc:
            return exc.status_code, error_envelope(exc)
        except sqlite3.Error:
            return DispositionUnavailable.status_code, error_envelope(DispositionUnavailable())
        envelope = disposition_envelope(
            scope=scope,
            revision=int(state["revision"]),
            disposition=state["disposition"],
            writable=self.writable,
        )
        return 200, {"success": True, **envelope}

    @staticmethod
    def _read_query(query: Mapping[str, Any]) -> tuple[str, str]:
        if not isinstance(query, Mapping):
            raise DispositionValidationError("查询参数无效")
        report_id = _require_token(query.get("report_id"), "report_id", max_chars=MAX_ID_CHARS)
        issue_id = _require_token(query.get("issue_id"), "issue_id", max_chars=MAX_ID_CHARS)
        return report_id, issue_id

    @staticmethod
    def _read_command(payload: Any) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise DispositionValidationError("请求必须是 JSON 对象")
        unknown = set(payload) - _ALLOWED_POST_KEYS
        if unknown:
            raise DispositionValidationError("请求包含未知字段")
        missing = _REQUIRED_POST_KEYS - set(payload)
        if missing:
            raise DispositionValidationError("请求缺少必需字段")
        report_id = _require_token(payload.get("report_id"), "report_id", max_chars=MAX_ID_CHARS)
        issue_id = _require_token(payload.get("issue_id"), "issue_id", max_chars=MAX_ID_CHARS)
        build_raw = payload.get("build_context_id")
        if build_raw is not None and not isinstance(build_raw, str):
            raise DispositionValidationError("build_context_id 必须是字符串或 null")
        build_context_id = _require_text(
            build_raw, "build_context_id", max_chars=MAX_ID_CHARS, required=False
        )
        command: dict[str, Any] = {
            "report_id": report_id,
            "issue_id": issue_id,
            "build_context_id": build_context_id or None,
            "base_revision": payload.get("base_revision"),
            "request_id": payload.get("request_id"),
            "type": payload.get("type"),
            "reason": payload.get("reason"),
            "duplicate_of": payload.get("duplicate_of"),
            "title": payload.get("title"),
            "expires_at": payload.get("expires_at"),
        }
        return command
