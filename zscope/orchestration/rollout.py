"""Persistent controller and fail-closed runtime policy for balanced rollout.

The controller accepts completed observation windows and persists an auditable
state machine.  :func:`apply_persisted_rollout_policy` is the deliberately small
runtime boundary that consumes that state.  Keeping the mutation in one place
prevents CLI, Web, MCP, and embedded scans from interpreting rollout stages
differently.
"""

from __future__ import annotations

import json
import hashlib
import hmac
import math
import os
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, BinaryIO, Callable, Dict, Iterator, Mapping, Optional, Tuple, Union

from .._version import __version__


ROLLOUT_STATE_SCHEMA_VERSION = "zscope.balanced-rollout-state.v1"
ROLLOUT_WINDOW_SCHEMA_VERSION = "zscope.rollout-observation-window.v1"
ROLLOUT_DECISION_SCHEMA_VERSION = "zscope.rollout-decision.v1"
ROLLOUT_RECORD_SCHEMA_VERSION = "zscope.rollout-observation-record.v1"
ROLLOUT_RUNTIME_POLICY_SCHEMA_VERSION = "zscope.rollout-runtime-policy.v1"
ROLLOUT_SIGNED_ENVELOPE_SCHEMA_VERSION = "zscope.balanced-rollout-signed-envelope.v1"
ROLLOUT_STATE_FILENAME = "balanced_rollout_state.json"
ROLLOUT_MANAGEMENT_KEY_ENV = "Z_SCOPE_BALANCED_ROLLOUT_HMAC_KEY"
ROLLOUT_RELEASE_ID_ENV = "Z_SCOPE_BALANCED_ROLLOUT_RELEASE_ID"
ROLLOUT_SIGNING_ALGORITHM = "HMAC-SHA256"
ROLLOUT_SIGNED_LANGUAGE = "c_cpp"
ROLLOUT_SIGNED_POLICY_ID = "zscope.balanced-default-policy.v1"
ROLLOUT_ENVELOPE_TTL_SECONDS = 90 * 24 * 60 * 60
ROLLOUT_CLOCK_SKEW_SECONDS = 5 * 60
_MIN_MANAGEMENT_KEY_BYTES = 32

ROLLOUT_STAGES = (
    "telemetry_only",
    "validator_opt_in",
    "semantic_shadow",
    "10",
    "50",
    "100",
    "balanced_default",
)
ROLLOUT_ACTIONS = frozenset({"initialize", "hold", "promote", "rollback_fast"})
MIN_STAGE_DAYS = 7
MIN_DISTINCT_PROJECTS = 20
BALANCED_DEFAULT_STABLE_WINDOWS = 2

_NEXT_STAGE = {current: following for current, following in zip(ROLLOUT_STAGES, ROLLOUT_STAGES[1:])}
_RECOMMENDED_BALANCED_PERCENT = {
    "telemetry_only": 0,
    "validator_opt_in": 0,
    "semantic_shadow": 0,
    "10": 10,
    "50": 50,
    "100": 100,
    "balanced_default": 100,
}
_HARD_FAILURES = frozenset(
    {"token_conservation", "attribution_complete", "silent_rejection_without_proof"}
)
_THRESHOLD_BREACHES = frozenset(
    {
        "precision@25",
        "high_critical_precision",
        "incomplete_scan_rate",
        "p95_wall_time_vs_approved_ratio",
    }
)


class RolloutStateError(ValueError):
    """Raised when persisted rollout data violates the strict state schema."""


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _normalize_management_key(value: Union[bytes, str]) -> bytes:
    if isinstance(value, str):
        normalized = value.encode("utf-8")
    elif isinstance(value, bytes):
        normalized = value
    else:
        raise RolloutStateError("rollout management key must be bytes or text")
    if len(normalized) < _MIN_MANAGEMENT_KEY_BYTES:
        raise RolloutStateError(
            f"rollout management key must contain at least {_MIN_MANAGEMENT_KEY_BYTES} bytes"
        )
    return normalized


def rollout_management_key_from_environment(*, required: bool = False) -> Optional[bytes]:
    """Read the rollout authenticator from its dedicated process environment.

    The secret is intentionally unavailable through public YAML, CLI flags, or
    report metadata.  Error text never includes the value.
    """

    raw = os.environ.get(ROLLOUT_MANAGEMENT_KEY_ENV)
    if raw is None or raw == "":
        if required:
            raise RolloutStateError(
                f"{ROLLOUT_MANAGEMENT_KEY_ENV} is required for rollout state signing"
            )
        return None
    return _normalize_management_key(raw)


def _rollout_release_identity(value: Optional[str] = None) -> str:
    identity = value if value is not None else os.environ.get(ROLLOUT_RELEASE_ID_ENV)
    return _strict_text(
        identity or f"zscope@{__version__}",
        path="rollout release identity",
        max_length=256,
    )


def _sign_rollout_envelope(unsigned: Mapping[str, Any], key: bytes) -> str:
    return hmac.new(key, _canonical_json_bytes(unsigned), hashlib.sha256).hexdigest()


def _build_signed_rollout_envelope(
    state: "RolloutState",
    *,
    key: bytes,
    release_identity: str,
) -> Dict[str, Any]:
    issued = _parse_timestamp(state.updated_at, path="state.updated_at")
    expires = issued + timedelta(seconds=ROLLOUT_ENVELOPE_TTL_SECONDS)
    unsigned: Dict[str, Any] = {
        "schema_version": ROLLOUT_SIGNED_ENVELOPE_SCHEMA_VERSION,
        "algorithm": ROLLOUT_SIGNING_ALGORITHM,
        "policy_id": ROLLOUT_SIGNED_POLICY_ID,
        "language": ROLLOUT_SIGNED_LANGUAGE,
        "release_identity": release_identity,
        "sequence": len(state.decisions),
        "issued_at": _format_timestamp(issued),
        "expires_at": _format_timestamp(expires),
        "state": state.to_dict(),
    }
    return {**unsigned, "signature": _sign_rollout_envelope(unsigned, key)}


def _verify_signed_rollout_envelope(
    value: Any,
    *,
    key: bytes,
    release_identity: str,
    now: datetime,
) -> "RolloutState":
    fields = {
        "schema_version",
        "algorithm",
        "policy_id",
        "language",
        "release_identity",
        "sequence",
        "issued_at",
        "expires_at",
        "state",
        "signature",
    }
    data = _exact_mapping(value, fields, path="signed rollout envelope")
    if data["schema_version"] != ROLLOUT_SIGNED_ENVELOPE_SCHEMA_VERSION:
        raise RolloutStateError("signed rollout envelope schema is unsupported")
    if data["algorithm"] != ROLLOUT_SIGNING_ALGORITHM:
        raise RolloutStateError("signed rollout envelope algorithm is unsupported")
    if data["policy_id"] != ROLLOUT_SIGNED_POLICY_ID:
        raise RolloutStateError("signed rollout envelope policy identity mismatch")
    if data["language"] != ROLLOUT_SIGNED_LANGUAGE:
        raise RolloutStateError("signed rollout envelope language mismatch")
    if data["release_identity"] != release_identity:
        raise RolloutStateError("signed rollout envelope release identity mismatch")
    sequence = _strict_integer(data["sequence"], path="signed rollout envelope.sequence", minimum=1)
    issued = _parse_timestamp(data["issued_at"], path="signed rollout envelope.issued_at")
    expires = _parse_timestamp(data["expires_at"], path="signed rollout envelope.expires_at")
    if expires <= issued:
        raise RolloutStateError("signed rollout envelope expiry must follow issuance")
    if (expires - issued).total_seconds() > ROLLOUT_ENVELOPE_TTL_SECONDS:
        raise RolloutStateError("signed rollout envelope exceeds maximum lifetime")
    if issued > now + timedelta(seconds=ROLLOUT_CLOCK_SKEW_SECONDS):
        raise RolloutStateError("signed rollout envelope issuance is in the future")
    if now >= expires:
        raise RolloutStateError("signed rollout envelope has expired")
    signature = _strict_text(
        data["signature"],
        path="signed rollout envelope.signature",
        max_length=64,
    )
    if len(signature) != 64 or any(character not in "0123456789abcdef" for character in signature):
        raise RolloutStateError("signed rollout envelope signature is invalid")
    unsigned = {field: data[field] for field in fields if field != "signature"}
    expected = _sign_rollout_envelope(unsigned, key)
    if not hmac.compare_digest(signature, expected):
        raise RolloutStateError("signed rollout envelope authentication failed")
    state = RolloutState.from_dict(data["state"])
    if sequence != len(state.decisions):
        raise RolloutStateError("signed rollout envelope sequence does not match state history")
    if state.updated_at != data["issued_at"]:
        raise RolloutStateError("signed rollout envelope issuance does not match state update")
    return state


def deterministic_rollout_bucket(project_id: Any) -> int:
    """Return a stable 0..99 bucket without leaking source paths into state.

    ``project.id`` is mandatory runtime identity after config composition.  A
    cryptographic digest avoids Python's process-randomized ``hash()`` and
    therefore keeps enrollment identical across CLI, Web, MCP, and restarts.
    """

    identity = str(project_id or "").strip()
    if not identity:
        raise RolloutStateError("project identity is required for rollout enrollment")
    digest = hashlib.sha256(identity.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % 100


def _unmanaged_runtime_policy(
    config: Any,
    state_path: Path,
    *,
    state_present: bool = False,
    state_sha256: str = "",
    enrollment_reason: str = "rollout_state_not_installed",
    state_error: str = "",
) -> Dict[str, Any]:
    scan = getattr(config, "scan", None)
    if scan is None:
        raise RolloutStateError("effective config lacks scan")
    requested_depth = str(getattr(scan, "depth", "fast") or "fast")
    requested_source = str(getattr(scan, "depth_source", "default") or "default")
    explicit_depth = requested_source in {"cli", "config", "interface_request"}
    effective_depth = requested_depth if explicit_depth or not state_present else "fast"
    forced_fast = effective_depth == "fast" and requested_depth != "fast"
    if effective_depth != requested_depth:
        scan.depth = effective_depth
        scan.depth_source = "rollout_unmanaged"
    semantic_mode = str(
        getattr(getattr(config, "analysis", None), "security_semantic_enrichment_mode", "shadow")
        or "shadow"
    )
    return {
        "schema_version": ROLLOUT_RUNTIME_POLICY_SCHEMA_VERSION,
        "managed": False,
        "stage": "unmanaged",
        "state_path": str(state_path),
        "state_sha256": state_sha256,
        "state_authenticated": False,
        "requested_depth": requested_depth,
        "requested_depth_source": requested_source,
        "effective_depth": effective_depth,
        "effective_depth_source": str(getattr(scan, "depth_source", "default") or "default"),
        "recommended_balanced_percent": 0,
        "project_bucket": None,
        "enrolled": False,
        "enrollment_reason": enrollment_reason,
        "forced_fast": forced_fast,
        "semantic_enrichment_mode": semantic_mode if effective_depth != "fast" else "disabled",
        "active_discovery_mode": "active" if effective_depth != "fast" else "disabled",
        "shadow_findings_visible_in_default": False,
        "state_error": state_error,
    }


def apply_persisted_rollout_policy(
    config: Any,
    *,
    state_path: Optional[Union[Path, str]] = None,
    management_key: Optional[Union[bytes, str]] = None,
    release_identity: Optional[str] = None,
) -> Dict[str, Any]:
    """Apply one persisted rollout decision to an effective scan config.

    The state file is an internal release-control artifact, not a public YAML
    field.  Absence means the installation has not opted into managed rollout
    and preserves existing behavior.  A present but unauthenticated artifact
    is ignored: omitted depth remains ``fast``, while an explicit user depth
    remains authoritative and the failure is visible through ``state_error``.

    Explicit ``balanced``/``deep`` requests are accepted from
    ``validator_opt_in`` onward.  Default traffic uses deterministic project
    enrollment only in the 10/50/100 stages; Java is never enrolled before its
    independent language gate changes the public config parser.
    """

    scan = getattr(config, "scan", None)
    analysis = getattr(config, "analysis", None)
    project = getattr(config, "project", None)
    if scan is None or analysis is None or project is None:
        raise RolloutStateError("effective config lacks scan, analysis, or project")

    resolved_path = (
        Path(
            state_path
            if state_path is not None
            else Path(str(getattr(analysis, "snapshot_dir", ".zscope_snapshots")))
            / ROLLOUT_STATE_FILENAME
        )
        .expanduser()
        .resolve()
    )
    requested_depth = str(getattr(scan, "depth", "fast") or "fast").strip().lower()
    requested_source = str(getattr(scan, "depth_source", "default") or "default")
    setattr(scan, "requested_depth", requested_depth)
    setattr(scan, "requested_depth_source", requested_source)

    if not resolved_path.is_file():
        policy = _unmanaged_runtime_policy(config, resolved_path)
        setattr(scan, "rollout", policy)
        return policy

    try:
        key = (
            _normalize_management_key(management_key)
            if management_key is not None
            else rollout_management_key_from_environment()
        )
    except RolloutStateError as exc:
        try:
            state_sha256 = hashlib.sha256(resolved_path.read_bytes()).hexdigest()
            read_error = ""
        except OSError as read_exc:
            state_sha256 = ""
            read_error = f"; state read failed: {type(read_exc).__name__}"
        policy = _unmanaged_runtime_policy(
            config,
            resolved_path,
            state_present=True,
            state_sha256=state_sha256,
            enrollment_reason="rollout_management_key_invalid",
            state_error=f"{type(exc).__name__}: {exc}{read_error}",
        )
        setattr(scan, "rollout", policy)
        return policy
    if key is None:
        try:
            state_sha256 = hashlib.sha256(resolved_path.read_bytes()).hexdigest()
            state_error = ""
        except OSError as exc:
            state_sha256 = ""
            state_error = f"state read failed: {type(exc).__name__}"
        policy = _unmanaged_runtime_policy(
            config,
            resolved_path,
            state_present=True,
            state_sha256=state_sha256,
            enrollment_reason="rollout_management_key_unavailable",
            state_error=state_error,
        )
        setattr(scan, "rollout", policy)
        return policy

    state_error = ""
    state_sha256 = ""
    try:
        raw = resolved_path.read_bytes()
        state_sha256 = hashlib.sha256(raw).hexdigest()
        state = BalancedRolloutController(
            resolved_path,
            management_key=key,
            release_identity=release_identity,
        ).load()
        stage = state.stage
        percentage = state.recommended_balanced_percent
    except (OSError, ValueError) as exc:
        # Authentication, expiry, schema, and threshold failures make the
        # project-local artifact non-authoritative.  Ignore it so an explicit
        # user opt-in still works, while implicit traffic remains fast.
        policy = _unmanaged_runtime_policy(
            config,
            resolved_path,
            state_present=True,
            state_sha256=state_sha256,
            enrollment_reason="rollout_state_authentication_failed",
            state_error=f"{type(exc).__name__}: {exc}",
        )
        setattr(scan, "rollout", policy)
        return policy

    explicit_depth = requested_source in {"cli", "config", "interface_request"}
    language = str(getattr(project, "language", "") or "").strip().lower()
    project_id = str(
        getattr(project, "project_id", "") or getattr(project, "project_root", "") or ""
    ).strip()
    project_bucket: Optional[int] = None
    enrolled = False
    enrollment_reason = "stage_forces_fast"
    effective_depth = "fast"
    semantic_mode = "disabled"
    discovery_mode = "disabled"

    if stage in {"telemetry_only", "invalid_state"}:
        pass
    elif stage == "validator_opt_in":
        if explicit_depth:
            effective_depth = requested_depth
            enrolled = requested_depth != "fast"
            enrollment_reason = "explicit_validator_opt_in"
        else:
            enrollment_reason = "validator_opt_in_requires_explicit_depth"
    elif stage == "semantic_shadow":
        if explicit_depth:
            effective_depth = requested_depth
            enrolled = requested_depth != "fast"
            enrollment_reason = "explicit_semantic_shadow_opt_in"
        else:
            enrollment_reason = "semantic_shadow_requires_explicit_depth"
        if effective_depth != "fast":
            semantic_mode = "shadow"
            discovery_mode = "shadow"
    elif stage in {"10", "50", "100"}:
        if explicit_depth:
            effective_depth = requested_depth
            enrolled = requested_depth != "fast"
            enrollment_reason = "explicit_depth"
        elif language == "c_cpp":
            project_bucket = deterministic_rollout_bucket(project_id)
            enrolled = project_bucket < percentage
            effective_depth = "balanced" if enrolled else "fast"
            enrollment_reason = (
                "deterministic_project_enrollment" if enrolled else "deterministic_project_holdback"
            )
        else:
            enrollment_reason = "language_gate_fast_only"
        if effective_depth != "fast":
            semantic_mode = "active"
            discovery_mode = "active"
    elif stage == "balanced_default":
        if explicit_depth:
            effective_depth = requested_depth
            enrollment_reason = "explicit_depth"
        elif language == "c_cpp":
            effective_depth = "balanced"
            enrollment_reason = "c_cpp_balanced_default"
        else:
            enrollment_reason = "language_gate_fast_only"
        enrolled = effective_depth != "fast"
        if enrolled:
            semantic_mode = "active"
            discovery_mode = "active"
    else:  # Strict RolloutState normally makes this unreachable.
        state_error = f"unsupported rollout stage: {stage}"
        stage = "invalid_state"

    changed_depth = effective_depth != requested_depth
    if changed_depth:
        scan.depth = effective_depth
        scan.depth_source = "rollout"
    rollout_forced_fast = effective_depth == "fast" and (
        stage in {"telemetry_only", "invalid_state"}
        or (not explicit_depth and stage != "balanced_default")
        or requested_depth != "fast"
    )
    # Managed active/shadow stages own semantic application.  The disabled
    # value stays in policy only because AnalysisConfig intentionally accepts
    # the stable shadow|active contract.
    if semantic_mode in {"shadow", "active"}:
        analysis.security_semantic_enrichment_mode = semantic_mode

    policy = {
        "schema_version": ROLLOUT_RUNTIME_POLICY_SCHEMA_VERSION,
        "managed": True,
        "stage": stage,
        "state_path": str(resolved_path),
        "state_sha256": state_sha256,
        "state_authenticated": True,
        "requested_depth": requested_depth,
        "requested_depth_source": requested_source,
        "effective_depth": str(scan.depth),
        "effective_depth_source": str(scan.depth_source),
        "recommended_balanced_percent": int(percentage),
        "project_bucket": project_bucket,
        "enrolled": bool(enrolled),
        "enrollment_reason": enrollment_reason,
        "forced_fast": rollout_forced_fast,
        "semantic_enrichment_mode": semantic_mode,
        "active_discovery_mode": discovery_mode,
        "shadow_findings_visible_in_default": False,
        "state_error": state_error,
    }
    setattr(scan, "rollout", policy)
    return policy


def rollout_runtime_policy(config: Any) -> Dict[str, Any]:
    """Return a copy of the effective runtime policy for reports/interfaces."""

    value = getattr(getattr(config, "scan", None), "rollout", None)
    return dict(value) if isinstance(value, Mapping) else {}


def rollout_active_discovery_mode(config: Any) -> str:
    """Return disabled|shadow|active for the candidate-blind stage."""

    policy = rollout_runtime_policy(config)
    if policy:
        return str(policy.get("active_discovery_mode") or "disabled")
    depth = str(getattr(getattr(config, "scan", None), "depth", "fast") or "fast")
    return "disabled" if depth == "fast" else "active"


def _exact_mapping(value: Any, fields: set[str], *, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RolloutStateError(f"{path} must be an object")
    actual = set(value)
    if actual != fields:
        missing = sorted(fields - actual)
        extra = sorted(actual - fields)
        raise RolloutStateError(f"{path} fields mismatch: missing={missing}, extra={extra}")
    return value


def _strict_text(value: Any, *, path: str, max_length: int = 1000) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RolloutStateError(f"{path} must be a non-empty string")
    if len(value) > max_length:
        raise RolloutStateError(f"{path} exceeds {max_length} characters")
    return value.strip()


def _strict_bool(value: Any, *, path: str) -> bool:
    if not isinstance(value, bool):
        raise RolloutStateError(f"{path} must be boolean")
    return value


def _strict_number(
    value: Any,
    *,
    path: str,
    minimum: float = 0.0,
    maximum: Optional[float] = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RolloutStateError(f"{path} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise RolloutStateError(f"{path} is outside its allowed range")
    if maximum is not None and result > maximum:
        raise RolloutStateError(f"{path} is outside its allowed range")
    return result


def _strict_integer(value: Any, *, path: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise RolloutStateError(f"{path} must be an integer >= {minimum}")
    return int(value)


def _parse_timestamp(value: Any, *, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RolloutStateError(f"{path} must be an RFC3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RolloutStateError(f"{path} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise RolloutStateError(f"{path} must use UTC")
    return parsed


def _format_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime):
        raise RolloutStateError("clock must return datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise RolloutStateError("clock must return a timezone-aware datetime")
    normalized = value.astimezone(timezone.utc)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class RolloutThresholds:
    precision_at_25_min: float = 0.70
    high_critical_precision_min: float = 0.80
    incomplete_scan_rate_max: float = 0.05
    p95_wall_time_vs_approved_ratio_max: float = 1.50

    def __post_init__(self) -> None:
        _strict_number(
            self.precision_at_25_min,
            path="thresholds.precision_at_25_min",
            maximum=1.0,
        )
        _strict_number(
            self.high_critical_precision_min,
            path="thresholds.high_critical_precision_min",
            maximum=1.0,
        )
        _strict_number(
            self.incomplete_scan_rate_max,
            path="thresholds.incomplete_scan_rate_max",
            maximum=1.0,
        )
        _strict_number(
            self.p95_wall_time_vs_approved_ratio_max,
            path="thresholds.p95_wall_time_vs_approved_ratio_max",
        )

    def to_dict(self) -> Dict[str, float]:
        return {
            "precision_at_25_min": float(self.precision_at_25_min),
            "high_critical_precision_min": float(self.high_critical_precision_min),
            "incomplete_scan_rate_max": float(self.incomplete_scan_rate_max),
            "p95_wall_time_vs_approved_ratio_max": float(self.p95_wall_time_vs_approved_ratio_max),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "RolloutThresholds":
        data = _exact_mapping(
            value,
            {
                "precision_at_25_min",
                "high_critical_precision_min",
                "incomplete_scan_rate_max",
                "p95_wall_time_vs_approved_ratio_max",
            },
            path="thresholds",
        )
        return cls(
            precision_at_25_min=_strict_number(
                data["precision_at_25_min"],
                path="thresholds.precision_at_25_min",
                maximum=1.0,
            ),
            high_critical_precision_min=_strict_number(
                data["high_critical_precision_min"],
                path="thresholds.high_critical_precision_min",
                maximum=1.0,
            ),
            incomplete_scan_rate_max=_strict_number(
                data["incomplete_scan_rate_max"],
                path="thresholds.incomplete_scan_rate_max",
                maximum=1.0,
            ),
            p95_wall_time_vs_approved_ratio_max=_strict_number(
                data["p95_wall_time_vs_approved_ratio_max"],
                path="thresholds.p95_wall_time_vs_approved_ratio_max",
            ),
        )


@dataclass(frozen=True)
class ObservationWindow:
    window_id: str
    started_at: str
    ended_at: str
    project_ids: Tuple[str, ...]
    precision_at_25: float
    high_critical_precision: float
    incomplete_scan_rate: float
    p95_wall_time_vs_approved_ratio: float
    token_conservation: bool
    attribution_complete: bool
    silent_rejection_without_proof: bool

    def __post_init__(self) -> None:
        _strict_text(self.window_id, path="window.window_id", max_length=256)
        started = _parse_timestamp(self.started_at, path="window.started_at")
        ended = _parse_timestamp(self.ended_at, path="window.ended_at")
        if ended <= started:
            raise RolloutStateError("window.ended_at must be later than started_at")
        if not isinstance(self.project_ids, tuple) or not self.project_ids:
            raise RolloutStateError("window.project_ids must be a non-empty tuple")
        normalized_projects = tuple(
            _strict_text(item, path="window.project_ids[]", max_length=256)
            for item in self.project_ids
        )
        if len(set(normalized_projects)) != len(normalized_projects):
            raise RolloutStateError("window.project_ids must be unique")
        _strict_number(
            self.precision_at_25,
            path="window.precision@25",
            maximum=1.0,
        )
        _strict_number(
            self.high_critical_precision,
            path="window.high_critical_precision",
            maximum=1.0,
        )
        _strict_number(
            self.incomplete_scan_rate,
            path="window.incomplete_scan_rate",
            maximum=1.0,
        )
        _strict_number(
            self.p95_wall_time_vs_approved_ratio,
            path="window.p95_wall_time_vs_approved_ratio",
        )
        _strict_bool(self.token_conservation, path="window.token_conservation")
        _strict_bool(self.attribution_complete, path="window.attribution_complete")
        _strict_bool(
            self.silent_rejection_without_proof,
            path="window.silent_rejection_without_proof",
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": ROLLOUT_WINDOW_SCHEMA_VERSION,
            "window_id": self.window_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "project_ids": list(self.project_ids),
            "precision@25": float(self.precision_at_25),
            "high_critical_precision": float(self.high_critical_precision),
            "incomplete_scan_rate": float(self.incomplete_scan_rate),
            "p95_wall_time_vs_approved_ratio": float(self.p95_wall_time_vs_approved_ratio),
            "token_conservation": self.token_conservation,
            "attribution_complete": self.attribution_complete,
            "silent_rejection_without_proof": self.silent_rejection_without_proof,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ObservationWindow":
        fields = {
            "schema_version",
            "window_id",
            "started_at",
            "ended_at",
            "project_ids",
            "precision@25",
            "high_critical_precision",
            "incomplete_scan_rate",
            "p95_wall_time_vs_approved_ratio",
            "token_conservation",
            "attribution_complete",
            "silent_rejection_without_proof",
        }
        data = _exact_mapping(value, fields, path="window")
        if data["schema_version"] != ROLLOUT_WINDOW_SCHEMA_VERSION:
            raise RolloutStateError("window.schema_version is unsupported")
        raw_projects = data["project_ids"]
        if not isinstance(raw_projects, list):
            raise RolloutStateError("window.project_ids must be an array")
        return cls(
            window_id=_strict_text(data["window_id"], path="window.window_id", max_length=256),
            started_at=_strict_text(data["started_at"], path="window.started_at"),
            ended_at=_strict_text(data["ended_at"], path="window.ended_at"),
            project_ids=tuple(raw_projects),
            precision_at_25=_strict_number(
                data["precision@25"], path="window.precision@25", maximum=1.0
            ),
            high_critical_precision=_strict_number(
                data["high_critical_precision"],
                path="window.high_critical_precision",
                maximum=1.0,
            ),
            incomplete_scan_rate=_strict_number(
                data["incomplete_scan_rate"],
                path="window.incomplete_scan_rate",
                maximum=1.0,
            ),
            p95_wall_time_vs_approved_ratio=_strict_number(
                data["p95_wall_time_vs_approved_ratio"],
                path="window.p95_wall_time_vs_approved_ratio",
            ),
            token_conservation=_strict_bool(
                data["token_conservation"], path="window.token_conservation"
            ),
            attribution_complete=_strict_bool(
                data["attribution_complete"], path="window.attribution_complete"
            ),
            silent_rejection_without_proof=_strict_bool(
                data["silent_rejection_without_proof"],
                path="window.silent_rejection_without_proof",
            ),
        )


@dataclass(frozen=True)
class RolloutDecision:
    action: str
    from_stage: str
    to_stage: str
    effective_depth: str
    recommended_balanced_percent: int
    owner: str
    reason: str
    rationale: str
    timestamp: str
    hard_failures: Tuple[str, ...] = ()
    threshold_breaches: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.action not in ROLLOUT_ACTIONS:
            raise RolloutStateError("decision.action is unsupported")
        if self.from_stage not in ROLLOUT_STAGES or self.to_stage not in ROLLOUT_STAGES:
            raise RolloutStateError("decision stage is unsupported")
        if self.effective_depth not in {"fast", "balanced"}:
            raise RolloutStateError("decision.effective_depth is unsupported")
        expected_depth = "balanced" if self.to_stage == "balanced_default" else "fast"
        if self.effective_depth != expected_depth:
            raise RolloutStateError("decision effective depth does not match target stage")
        expected_percent = _RECOMMENDED_BALANCED_PERCENT[self.to_stage]
        if self.recommended_balanced_percent != expected_percent:
            raise RolloutStateError("decision balanced percentage does not match target stage")
        if self.action == "initialize" and (
            self.from_stage != "telemetry_only" or self.to_stage != "telemetry_only"
        ):
            raise RolloutStateError("initialize decision must remain telemetry_only")
        if self.action == "hold" and self.from_stage != self.to_stage:
            raise RolloutStateError("hold decision cannot change stage")
        if self.action == "promote" and _NEXT_STAGE.get(self.from_stage) != self.to_stage:
            raise RolloutStateError("promote decision must advance exactly one stage")
        if self.action == "rollback_fast" and self.to_stage != "telemetry_only":
            raise RolloutStateError("rollback_fast decision must target telemetry_only")
        _strict_text(self.owner, path="decision.owner", max_length=256)
        _strict_text(self.reason, path="decision.reason", max_length=1000)
        _strict_text(self.rationale, path="decision.rationale", max_length=2000)
        _parse_timestamp(self.timestamp, path="decision.timestamp")
        for field_name, values in (
            ("hard_failures", self.hard_failures),
            ("threshold_breaches", self.threshold_breaches),
        ):
            if not isinstance(values, tuple):
                raise RolloutStateError(f"decision.{field_name} must be a tuple")
            for item in values:
                _strict_text(item, path=f"decision.{field_name}[]", max_length=256)
        if len(set(self.hard_failures)) != len(self.hard_failures):
            raise RolloutStateError("decision.hard_failures must be unique")
        if len(set(self.threshold_breaches)) != len(self.threshold_breaches):
            raise RolloutStateError("decision.threshold_breaches must be unique")
        if not set(self.hard_failures).issubset(_HARD_FAILURES):
            raise RolloutStateError("decision.hard_failures contains an unknown invariant")
        if not set(self.threshold_breaches).issubset(_THRESHOLD_BREACHES):
            raise RolloutStateError("decision.threshold_breaches contains an unknown metric")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": ROLLOUT_DECISION_SCHEMA_VERSION,
            "action": self.action,
            "from_stage": self.from_stage,
            "to_stage": self.to_stage,
            "effective_depth": self.effective_depth,
            "recommended_balanced_percent": self.recommended_balanced_percent,
            "owner": self.owner,
            "reason": self.reason,
            "rationale": self.rationale,
            "timestamp": self.timestamp,
            "hard_failures": list(self.hard_failures),
            "threshold_breaches": list(self.threshold_breaches),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "RolloutDecision":
        fields = {
            "schema_version",
            "action",
            "from_stage",
            "to_stage",
            "effective_depth",
            "recommended_balanced_percent",
            "owner",
            "reason",
            "rationale",
            "timestamp",
            "hard_failures",
            "threshold_breaches",
        }
        data = _exact_mapping(value, fields, path="decision")
        if data["schema_version"] != ROLLOUT_DECISION_SCHEMA_VERSION:
            raise RolloutStateError("decision.schema_version is unsupported")
        hard_failures = data["hard_failures"]
        threshold_breaches = data["threshold_breaches"]
        if not isinstance(hard_failures, list) or not isinstance(threshold_breaches, list):
            raise RolloutStateError("decision failure fields must be arrays")
        return cls(
            action=_strict_text(data["action"], path="decision.action"),
            from_stage=_strict_text(data["from_stage"], path="decision.from_stage"),
            to_stage=_strict_text(data["to_stage"], path="decision.to_stage"),
            effective_depth=_strict_text(data["effective_depth"], path="decision.effective_depth"),
            recommended_balanced_percent=_strict_integer(
                data["recommended_balanced_percent"],
                path="decision.recommended_balanced_percent",
            ),
            owner=_strict_text(data["owner"], path="decision.owner", max_length=256),
            reason=_strict_text(data["reason"], path="decision.reason", max_length=1000),
            rationale=_strict_text(data["rationale"], path="decision.rationale", max_length=2000),
            timestamp=_strict_text(data["timestamp"], path="decision.timestamp"),
            hard_failures=tuple(hard_failures),
            threshold_breaches=tuple(threshold_breaches),
        )


@dataclass(frozen=True)
class RecordedObservation:
    stage: str
    owner: str
    reason: str
    timestamp: str
    window: ObservationWindow

    def __post_init__(self) -> None:
        if self.stage not in ROLLOUT_STAGES:
            raise RolloutStateError("observation_record.stage is unsupported")
        _strict_text(self.owner, path="observation_record.owner", max_length=256)
        _strict_text(self.reason, path="observation_record.reason", max_length=1000)
        _parse_timestamp(self.timestamp, path="observation_record.timestamp")
        if not isinstance(self.window, ObservationWindow):
            raise RolloutStateError("observation_record.window is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": ROLLOUT_RECORD_SCHEMA_VERSION,
            "stage": self.stage,
            "owner": self.owner,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "window": self.window.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "RecordedObservation":
        data = _exact_mapping(
            value,
            {"schema_version", "stage", "owner", "reason", "timestamp", "window"},
            path="observation_record",
        )
        if data["schema_version"] != ROLLOUT_RECORD_SCHEMA_VERSION:
            raise RolloutStateError("observation_record.schema_version is unsupported")
        return cls(
            stage=_strict_text(data["stage"], path="observation_record.stage"),
            owner=_strict_text(data["owner"], path="observation_record.owner", max_length=256),
            reason=_strict_text(data["reason"], path="observation_record.reason", max_length=1000),
            timestamp=_strict_text(data["timestamp"], path="observation_record.timestamp"),
            window=ObservationWindow.from_dict(data["window"]),
        )


@dataclass(frozen=True)
class RolloutState:
    stage: str
    effective_depth: str
    recommended_balanced_percent: int
    stage_entered_at: str
    updated_at: str
    owner: str
    reason: str
    thresholds: RolloutThresholds
    stage_project_ids: Tuple[str, ...]
    consecutive_threshold_breaches: int
    stable_windows_at_100: int
    observations: Tuple[RecordedObservation, ...]
    decisions: Tuple[RolloutDecision, ...]

    def __post_init__(self) -> None:
        if self.stage not in ROLLOUT_STAGES:
            raise RolloutStateError("state.stage is unsupported")
        expected_depth = "balanced" if self.stage == "balanced_default" else "fast"
        if self.effective_depth != expected_depth:
            raise RolloutStateError("state.effective_depth does not match stage")
        if self.recommended_balanced_percent != _RECOMMENDED_BALANCED_PERCENT[self.stage]:
            raise RolloutStateError("state recommended percentage does not match stage")
        entered = _parse_timestamp(self.stage_entered_at, path="state.stage_entered_at")
        updated = _parse_timestamp(self.updated_at, path="state.updated_at")
        if updated < entered:
            raise RolloutStateError("state.updated_at precedes stage_entered_at")
        _strict_text(self.owner, path="state.owner", max_length=256)
        _strict_text(self.reason, path="state.reason", max_length=1000)
        if not isinstance(self.thresholds, RolloutThresholds):
            raise RolloutStateError("state.thresholds is invalid")
        if not isinstance(self.stage_project_ids, tuple):
            raise RolloutStateError("state.stage_project_ids must be a tuple")
        for project_id in self.stage_project_ids:
            _strict_text(project_id, path="state.stage_project_ids[]", max_length=256)
        if len(set(self.stage_project_ids)) != len(self.stage_project_ids):
            raise RolloutStateError("state.stage_project_ids must be unique")
        _strict_integer(
            self.consecutive_threshold_breaches,
            path="state.consecutive_threshold_breaches",
        )
        _strict_integer(self.stable_windows_at_100, path="state.stable_windows_at_100")
        if self.stage != "100" and self.stable_windows_at_100 != 0:
            raise RolloutStateError("stable_windows_at_100 is only valid in stage 100")
        if not isinstance(self.observations, tuple) or not isinstance(self.decisions, tuple):
            raise RolloutStateError("state audit collections must be tuples")
        if not self.decisions:
            raise RolloutStateError("state must contain at least one decision")
        if any(not isinstance(item, RecordedObservation) for item in self.observations):
            raise RolloutStateError("state.observations contains an invalid record")
        if any(not isinstance(item, RolloutDecision) for item in self.decisions):
            raise RolloutStateError("state.decisions contains an invalid decision")
        window_ids = [item.window.window_id for item in self.observations]
        if len(set(window_ids)) != len(window_ids):
            raise RolloutStateError("state observation window IDs must be unique")
        latest = self.decisions[-1]
        if latest.to_stage != self.stage:
            raise RolloutStateError("state stage does not match the latest decision")
        if latest.timestamp != self.updated_at:
            raise RolloutStateError("state updated_at does not match the latest decision")
        if latest.owner != self.owner or latest.reason != self.reason:
            raise RolloutStateError("state audit owner/reason do not match the latest decision")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": ROLLOUT_STATE_SCHEMA_VERSION,
            "stage": self.stage,
            "effective_depth": self.effective_depth,
            "recommended_balanced_percent": self.recommended_balanced_percent,
            "stage_entered_at": self.stage_entered_at,
            "updated_at": self.updated_at,
            "owner": self.owner,
            "reason": self.reason,
            "thresholds": self.thresholds.to_dict(),
            "stage_project_ids": list(self.stage_project_ids),
            "consecutive_threshold_breaches": self.consecutive_threshold_breaches,
            "stable_windows_at_100": self.stable_windows_at_100,
            "observations": [item.to_dict() for item in self.observations],
            "decisions": [item.to_dict() for item in self.decisions],
        }

    @classmethod
    def from_dict(cls, value: Any) -> "RolloutState":
        fields = {
            "schema_version",
            "stage",
            "effective_depth",
            "recommended_balanced_percent",
            "stage_entered_at",
            "updated_at",
            "owner",
            "reason",
            "thresholds",
            "stage_project_ids",
            "consecutive_threshold_breaches",
            "stable_windows_at_100",
            "observations",
            "decisions",
        }
        data = _exact_mapping(value, fields, path="state")
        if data["schema_version"] != ROLLOUT_STATE_SCHEMA_VERSION:
            raise RolloutStateError("state.schema_version is unsupported")
        project_ids = data["stage_project_ids"]
        observations = data["observations"]
        decisions = data["decisions"]
        if not isinstance(project_ids, list):
            raise RolloutStateError("state.stage_project_ids must be an array")
        if not isinstance(observations, list) or not isinstance(decisions, list):
            raise RolloutStateError("state audit collections must be arrays")
        return cls(
            stage=_strict_text(data["stage"], path="state.stage"),
            effective_depth=_strict_text(data["effective_depth"], path="state.effective_depth"),
            recommended_balanced_percent=_strict_integer(
                data["recommended_balanced_percent"],
                path="state.recommended_balanced_percent",
            ),
            stage_entered_at=_strict_text(data["stage_entered_at"], path="state.stage_entered_at"),
            updated_at=_strict_text(data["updated_at"], path="state.updated_at"),
            owner=_strict_text(data["owner"], path="state.owner", max_length=256),
            reason=_strict_text(data["reason"], path="state.reason", max_length=1000),
            thresholds=RolloutThresholds.from_dict(data["thresholds"]),
            stage_project_ids=tuple(project_ids),
            consecutive_threshold_breaches=_strict_integer(
                data["consecutive_threshold_breaches"],
                path="state.consecutive_threshold_breaches",
            ),
            stable_windows_at_100=_strict_integer(
                data["stable_windows_at_100"], path="state.stable_windows_at_100"
            ),
            observations=tuple(RecordedObservation.from_dict(item) for item in observations),
            decisions=tuple(RolloutDecision.from_dict(item) for item in decisions),
        )


Clock = Callable[[], datetime]
WindowInput = Union[ObservationWindow, Mapping[str, Any]]


class BalancedRolloutController:
    """Persist rollout evidence and return decisions without routing traffic."""

    def __init__(
        self,
        state_path: Union[Path, str],
        *,
        thresholds: Optional[RolloutThresholds] = None,
        clock: Optional[Clock] = None,
        management_key: Optional[Union[bytes, str]] = None,
        release_identity: Optional[str] = None,
    ) -> None:
        self.state_path = Path(state_path)
        self.thresholds = thresholds or RolloutThresholds()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.management_key = (
            _normalize_management_key(management_key) if management_key is not None else None
        )
        self.release_identity = _rollout_release_identity(release_identity)
        self._lock = threading.RLock()
        self._process_lock_path = self.state_path.with_name(f".{self.state_path.name}.lock")

    @contextmanager
    def _process_lock(self) -> Iterator[None]:
        """Serialize state read/modify/write cycles across OS processes."""

        self._process_lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self._process_lock_path.open("a+b") as handle:
            self._ensure_lock_byte(handle)
            self._lock_file(handle)
            try:
                yield
            finally:
                self._unlock_file(handle)

    @staticmethod
    def _ensure_lock_byte(handle: BinaryIO) -> None:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()

    @staticmethod
    def _lock_file(handle: BinaryIO) -> None:
        handle.seek(0)
        if os.name == "nt":  # pragma: no cover - platform-selected branch
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            return
        import importlib

        fcntl = importlib.import_module("fcntl")
        getattr(fcntl, "flock")(handle.fileno(), getattr(fcntl, "LOCK_EX"))

    @staticmethod
    def _unlock_file(handle: BinaryIO) -> None:
        handle.seek(0)
        if os.name == "nt":  # pragma: no cover - platform-selected branch
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            return
        import importlib

        fcntl = importlib.import_module("fcntl")
        getattr(fcntl, "flock")(handle.fileno(), getattr(fcntl, "LOCK_UN"))

    def initialize(self, *, owner: str, reason: str) -> RolloutState:
        """Create the initial telemetry-only state, or validate and return it."""

        owner = _strict_text(owner, path="owner", max_length=256)
        reason = _strict_text(reason, path="reason", max_length=1000)
        with self._lock, self._process_lock():
            return self._initialize_unlocked(owner=owner, reason=reason)

    def load(self) -> RolloutState:
        with self._lock, self._process_lock():
            state = self._load_unlocked()
            self._assert_threshold_identity(state)
            return state

    def record_window(
        self,
        window: WindowInput,
        *,
        owner: str,
        reason: str,
    ) -> RolloutDecision:
        """Record one non-overlapping window and atomically persist its decision."""

        owner = _strict_text(owner, path="owner", max_length=256)
        reason = _strict_text(reason, path="reason", max_length=1000)
        normalized_window = (
            window if isinstance(window, ObservationWindow) else ObservationWindow.from_dict(window)
        )
        with self._lock, self._process_lock():
            state = self._initialize_unlocked(owner=owner, reason=reason)
            decision, _new_state = self._record_window_unlocked(
                state,
                normalized_window,
                owner=owner,
                reason=reason,
            )
            return decision

    def record_window_cas(
        self,
        window: WindowInput,
        *,
        expected_state_sha256: str,
        owner: str,
        reason: str,
    ) -> Tuple[RolloutDecision, RolloutState, str, str]:
        """Record a window only when the protected caller observed this state.

        The comparison and atomic replace occur while holding both the in-process
        mutex and a sibling lock file, so two operator processes cannot both
        commit against the same predecessor.
        """

        owner = _strict_text(owner, path="owner", max_length=256)
        reason = _strict_text(reason, path="reason", max_length=1000)
        expected = str(expected_state_sha256 or "").strip()
        if len(expected) != 64 or any(
            character not in "0123456789abcdef" for character in expected
        ):
            raise RolloutStateError("expected state SHA-256 must be 64 lowercase hexadecimal chars")
        normalized_window = (
            window if isinstance(window, ObservationWindow) else ObservationWindow.from_dict(window)
        )
        with self._lock, self._process_lock():
            if not self.state_path.is_file():
                raise RolloutStateError("rollout state must be initialized before CAS record")
            previous_sha256 = hashlib.sha256(self.state_path.read_bytes()).hexdigest()
            if previous_sha256 != expected:
                raise RolloutStateError(
                    "rollout state changed since the operator read it "
                    f"(expected {expected}, current {previous_sha256})"
                )
            state = self._load_unlocked()
            self._assert_threshold_identity(state)
            decision, new_state = self._record_window_unlocked(
                state,
                normalized_window,
                owner=owner,
                reason=reason,
            )
            state_sha256 = hashlib.sha256(self.state_path.read_bytes()).hexdigest()
            return decision, new_state, previous_sha256, state_sha256

    def _initialize_unlocked(self, *, owner: str, reason: str) -> RolloutState:
        if self.state_path.exists():
            state = self._load_unlocked()
            self._assert_threshold_identity(state)
            return state
        timestamp = self._now_text()
        decision = self._decision(
            action="initialize",
            from_stage="telemetry_only",
            to_stage="telemetry_only",
            owner=owner,
            reason=reason,
            rationale="rollout_initialized",
            timestamp=timestamp,
        )
        state = RolloutState(
            stage="telemetry_only",
            effective_depth="fast",
            recommended_balanced_percent=0,
            stage_entered_at=timestamp,
            updated_at=timestamp,
            owner=owner,
            reason=reason,
            thresholds=self.thresholds,
            stage_project_ids=(),
            consecutive_threshold_breaches=0,
            stable_windows_at_100=0,
            observations=(),
            decisions=(decision,),
        )
        self._persist_unlocked(state)
        return state

    def _record_window_unlocked(
        self,
        state: RolloutState,
        normalized_window: ObservationWindow,
        *,
        owner: str,
        reason: str,
    ) -> Tuple[RolloutDecision, RolloutState]:
        self._assert_threshold_identity(state)
        now = self._now()
        now_text = _format_timestamp(now)
        if now < _parse_timestamp(state.updated_at, path="state.updated_at"):
            raise RolloutStateError("clock moved backwards relative to persisted state")
        self._validate_new_window(state, normalized_window, now)

        hard_failures = self._hard_failures(normalized_window)
        threshold_breaches = self._threshold_breaches(normalized_window)
        observed_stage = state.stage
        record = RecordedObservation(
            stage=observed_stage,
            owner=owner,
            reason=reason,
            timestamp=now_text,
            window=normalized_window,
        )
        observations = (*state.observations, record)
        projects = tuple(sorted(set(state.stage_project_ids) | set(normalized_window.project_ids)))
        breach_count = state.consecutive_threshold_breaches + 1 if threshold_breaches else 0
        stable_at_100 = (
            state.stable_windows_at_100 + 1
            if observed_stage == "100" and not hard_failures and not threshold_breaches
            else 0
        )

        action = "hold"
        target_stage = observed_stage
        rationale = "stage_observation_recorded"
        if hard_failures:
            action = "rollback_fast"
            target_stage = "telemetry_only"
            rationale = "hard_invariant_failed:" + ",".join(hard_failures)
        elif breach_count >= 2:
            action = "rollback_fast"
            target_stage = "telemetry_only"
            rationale = "two_consecutive_threshold_breaches:" + ",".join(threshold_breaches)
        elif threshold_breaches:
            rationale = "threshold_breach_observed:" + ",".join(threshold_breaches)
        elif observed_stage != "balanced_default":
            elapsed_days = (
                now - _parse_timestamp(state.stage_entered_at, path="state.stage_entered_at")
            ).total_seconds() / 86_400
            duration_ready = elapsed_days >= MIN_STAGE_DAYS
            projects_ready = len(projects) >= MIN_DISTINCT_PROJECTS
            stable_ready = (
                observed_stage != "100" or stable_at_100 >= BALANCED_DEFAULT_STABLE_WINDOWS
            )
            if duration_ready and projects_ready and stable_ready:
                action = "promote"
                target_stage = _NEXT_STAGE[observed_stage]
                rationale = f"promotion_requirements_satisfied:{observed_stage}->{target_stage}"
            else:
                missing = []
                if not duration_ready:
                    missing.append("minimum_7_days")
                if not projects_ready:
                    missing.append("minimum_20_projects")
                if not stable_ready:
                    missing.append("two_stable_windows_at_100")
                rationale = "promotion_waiting:" + ",".join(missing)
        else:
            rationale = "balanced_default_stable"

        decision = self._decision(
            action=action,
            from_stage=observed_stage,
            to_stage=target_stage,
            owner=owner,
            reason=reason,
            rationale=rationale,
            timestamp=now_text,
            hard_failures=hard_failures,
            threshold_breaches=threshold_breaches,
        )
        # A rollback starts a fresh telemetry-only observation period even when
        # the controller was already in telemetry_only.
        reset_stage = action == "rollback_fast" or target_stage != observed_stage
        new_state = RolloutState(
            stage=target_stage,
            effective_depth=("balanced" if target_stage == "balanced_default" else "fast"),
            recommended_balanced_percent=_RECOMMENDED_BALANCED_PERCENT[target_stage],
            stage_entered_at=(now_text if reset_stage else state.stage_entered_at),
            updated_at=now_text,
            owner=owner,
            reason=reason,
            thresholds=state.thresholds,
            stage_project_ids=(() if reset_stage else projects),
            consecutive_threshold_breaches=(0 if reset_stage else breach_count),
            stable_windows_at_100=(0 if reset_stage or target_stage != "100" else stable_at_100),
            observations=observations,
            decisions=(*state.decisions, decision),
        )
        self._persist_unlocked(new_state)
        return decision, new_state

    def _validate_new_window(
        self,
        state: RolloutState,
        window: ObservationWindow,
        now: datetime,
    ) -> None:
        if any(item.window.window_id == window.window_id for item in state.observations):
            raise RolloutStateError(f"duplicate observation window_id: {window.window_id}")
        started = _parse_timestamp(window.started_at, path="window.started_at")
        ended = _parse_timestamp(window.ended_at, path="window.ended_at")
        if ended > now:
            raise RolloutStateError("observation window cannot end in the future")
        stage_entered = _parse_timestamp(state.stage_entered_at, path="state.stage_entered_at")
        if started < stage_entered:
            raise RolloutStateError("observation window starts before the current stage")
        current_stage_windows = [
            item.window for item in state.observations if item.stage == state.stage
        ]
        if current_stage_windows:
            latest_end = max(
                _parse_timestamp(item.ended_at, path="window.ended_at")
                for item in current_stage_windows
            )
            if started < latest_end:
                raise RolloutStateError("observation windows for a stage must not overlap")

    @staticmethod
    def _hard_failures(window: ObservationWindow) -> Tuple[str, ...]:
        failures = []
        if not window.token_conservation:
            failures.append("token_conservation")
        if not window.attribution_complete:
            failures.append("attribution_complete")
        if window.silent_rejection_without_proof:
            failures.append("silent_rejection_without_proof")
        return tuple(failures)

    def _threshold_breaches(self, window: ObservationWindow) -> Tuple[str, ...]:
        breaches = []
        if window.precision_at_25 < self.thresholds.precision_at_25_min:
            breaches.append("precision@25")
        if window.high_critical_precision < self.thresholds.high_critical_precision_min:
            breaches.append("high_critical_precision")
        if window.incomplete_scan_rate > self.thresholds.incomplete_scan_rate_max:
            breaches.append("incomplete_scan_rate")
        if (
            window.p95_wall_time_vs_approved_ratio
            > self.thresholds.p95_wall_time_vs_approved_ratio_max
        ):
            breaches.append("p95_wall_time_vs_approved_ratio")
        return tuple(breaches)

    @staticmethod
    def _decision(
        *,
        action: str,
        from_stage: str,
        to_stage: str,
        owner: str,
        reason: str,
        rationale: str,
        timestamp: str,
        hard_failures: Tuple[str, ...] = (),
        threshold_breaches: Tuple[str, ...] = (),
    ) -> RolloutDecision:
        return RolloutDecision(
            action=action,
            from_stage=from_stage,
            to_stage=to_stage,
            effective_depth=("balanced" if to_stage == "balanced_default" else "fast"),
            recommended_balanced_percent=_RECOMMENDED_BALANCED_PERCENT[to_stage],
            owner=owner,
            reason=reason,
            rationale=rationale,
            timestamp=timestamp,
            hard_failures=hard_failures,
            threshold_breaches=threshold_breaches,
        )

    def _assert_threshold_identity(self, state: RolloutState) -> None:
        if state.thresholds != self.thresholds:
            raise RolloutStateError(
                "persisted rollout thresholds differ from controller thresholds"
            )

    def _now(self) -> datetime:
        value = self.clock()
        _format_timestamp(value)
        return value.astimezone(timezone.utc)

    def _now_text(self) -> str:
        return _format_timestamp(self._now())

    def _load_unlocked(self) -> RolloutState:
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise
        except (OSError, json.JSONDecodeError) as exc:
            raise RolloutStateError(f"cannot read rollout state: {exc}") from exc
        if (
            isinstance(raw, Mapping)
            and raw.get("schema_version") == ROLLOUT_SIGNED_ENVELOPE_SCHEMA_VERSION
        ):
            if self.management_key is None:
                raise RolloutStateError("signed rollout state requires a management key")
            return _verify_signed_rollout_envelope(
                raw,
                key=self.management_key,
                release_identity=self.release_identity,
                now=self._now(),
            )
        if self.management_key is not None:
            raise RolloutStateError("unsigned rollout state is not authoritative")
        return RolloutState.from_dict(raw)

    def _persist_unlocked(self, state: RolloutState) -> None:
        persisted: Mapping[str, Any]
        if self.management_key is not None:
            persisted = _build_signed_rollout_envelope(
                state,
                key=self.management_key,
                release_identity=self.release_identity,
            )
        else:
            persisted = state.to_dict()
        payload = (
            json.dumps(
                persisted,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary: Optional[Path] = None
        descriptor = -1
        try:
            descriptor, raw_path = tempfile.mkstemp(
                prefix=f".{self.state_path.name}.",
                suffix=".tmp",
                dir=str(self.state_path.parent),
            )
            temporary = Path(raw_path)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.state_path)
            temporary = None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary is not None:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass


__all__ = [
    "BALANCED_DEFAULT_STABLE_WINDOWS",
    "MIN_DISTINCT_PROJECTS",
    "MIN_STAGE_DAYS",
    "ROLLOUT_RUNTIME_POLICY_SCHEMA_VERSION",
    "ROLLOUT_MANAGEMENT_KEY_ENV",
    "ROLLOUT_RELEASE_ID_ENV",
    "ROLLOUT_SIGNED_ENVELOPE_SCHEMA_VERSION",
    "ROLLOUT_STATE_FILENAME",
    "ROLLOUT_STAGES",
    "BalancedRolloutController",
    "ObservationWindow",
    "RolloutDecision",
    "RolloutState",
    "RolloutStateError",
    "RolloutThresholds",
    "apply_persisted_rollout_policy",
    "deterministic_rollout_bucket",
    "rollout_active_discovery_mode",
    "rollout_management_key_from_environment",
    "rollout_runtime_policy",
]
