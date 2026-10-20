"""Per-instance successful-result artifact codec for the S08 recovery slice.

This module owns the frozen ``zscope.instance-result.v1`` byte contract: it
encodes one *successful, complete, pre-validation* instance analysis into an
immutable artifact file and strictly re-validates a trusted coordinate receipt
against such a file.  It is deliberately dependency-free — it imports no
product module at all, in particular no ``store``, ``scan_work``,
``session_scheduler`` or ``ParallelAnalyzer`` — because those seams are
coordinator-owned: the protected SQL writer, the trusted joined reader, queue
claim settlement, the live-ledger exporter/importer and every real consumer
live outside this file.  ``prepare_instance_result`` only encodes and
atomically publishes a file (never a SQL receipt); ``verify_instance_result``
only validates bytes, schema, identity and completeness (it is never a
capability, an admission decision or a bypass for re-running the current
validation chain).

Artifact contract
-----------------

The artifact is ``<producer_run_dir>/instance-results/<sha256(identity
UTF-8)>.<content_sha256>.json`` where ``identity`` is the instance identity
string and ``content_sha256`` is the SHA-256 of the exact file bytes.  The
document is canonical JSON: UTF-8, ``sort_keys``, compact separators, no
ASCII escaping and no NaN/Infinity.  It repeats the producer job/input/plan
identity, versions, registry/semantics/dependency digests, the exact instance
identity/build/usr/source, the per-instance semantics digest, the typed
completion marker, the complete pending-record projection, and the outcome
projection.  It never contains its own path or digest (avoiding a
self-referential content hash) and never contains an owner or claim token:
``CurrentAttempt.owner_token`` is repr-suppressed process input that must not
reach disk or logs.

Wire document (all key sets are exact; unknown keys are rejected):

``schema`` / ``recovery_policy``
    The fixed version labels ``zscope.instance-result.v1`` and
    ``zscope.instance-recovery.v1``.
``producer_run_id``
    The producer run that wrote the artifact.
``identity``
    The full :class:`RecoveryIdentity` (job, input revision, plan
    fingerprint, version pairs, registry/semantics-policy/semantics-manifest/
    dependency digests).
``instance`` / ``instance_semantics_digest``
    The exact :class:`InstanceKey` and its per-instance S01 snapshot digest.
``completion``
    The :class:`AnalysisCompletion` marker.  Only ``state="complete"`` with
    ``collection_closed`` and ``input_current`` true and no active-stage
    errors is recoverable; anything else must be re-analyzed.
``manifest``
    Derived by the codec from the records themselves: complete
    record/obligation/occurrence counts *and* a membership identity digest
    over every record merge key and occurrence UID.  The counting caliber is:
    ``record_count`` = number of records, ``obligation_count`` = distinct
    ``obligation_uid`` values across *all* records (triage leads included),
    ``occurrence_count`` = total of each record's deduplicated UID list; the
    digest covers each record's merge key plus its sorted unique UID list.
    Counts alone never prove completeness — a same-count occurrence
    replacement breaks the membership digest — and the manifest must also
    equal the completion's expected counts.  Full occurrence path/entry/
    context rows, owners, roles, record bytes and duplicate-count diagnostics
    are the coordinator's versioned locked manifest stored in
    ``outcome_json`` and compared against the live ledger under its lock;
    this inner digest is not that gate.  The coordinator exporter must
    establish the same membership against the live ledger under its lock
    before calling prepare.
``records``
    The complete, lossless, pre-validation pending projection per record:
    the :class:`PendingCandidate` coordinates plus ``record_json`` (the
    frozen ``zscope.instance-pending-record.v1`` field set, which excludes
    terminal disposition/proof/attempt fields structurally).  Only
    ``pending``/``queued`` neutral records are representable; a saved
    confirmation/rejection/suppression disposition, decision proof,
    validation-attempt/cache state or live receipt marker anywhere in the
    document makes the whole instance miss.  Embedded
    ``candidate_schema_version``/``decision_context_version`` must belong to
    the module's supported version sets and agree with the identity's
    declared ``"candidate_schema"`` (required) and
    ``"candidate_decision_context"`` (optional) components.  Occurrence
    attribution follows the live ledger: ``occurrence_uids`` is the
    deduplicated UID list while ``occurrences`` keeps one full row per
    distinct (uid, entry, paths, context) attribution, so one UID may
    legitimately carry several path rows; the UID list, its coverage of the
    rows and the complete row set are validated separately and rows are
    never reshaped to force a 1:1 mapping.  A shared validation cluster may
    also legitimately declare several contexts in ``validation_contexts``:
    the record keeps its primary context while each row carries the context
    of its own add — every row context must be declared, every declared
    context must be carried by at least one row, and rows sharing a UID must
    agree on entry/context.
``outcome``
    The decoded value of ``outcome_json``.  The codec requires it to be a
    JSON object exposing ``"diagnostic_gaps"`` as a list of strings (possibly
    empty); that is the fixed wire location of the artifact rule's
    "diagnostic gaps" requirement.  All other outcome keys are the
    coordinator exporter's projection and are preserved verbatim.

Immutability and crash behaviour
--------------------------------

The file is published atomically (exclusive temp file, ``fsync``, hard-link
into place, directory ``fsync``) and is never overwritten: re-publishing the
same bytes is an idempotent re-verification, while a pre-existing different
byte sequence at the same path is refused.  A crash before the link leaves
only an orphan temp file; a file without a coordinator-side bound SQL receipt
is ignorable by design.  The reverse order (receipt without a settled queue
claim) is structurally impossible from this module because it never writes
SQL.  Verification reads the artifact bytes exactly once, re-checks the
resolved path against the producer's own ``instance-results`` directory (no
``..``, no subdirectories, no symlinks, exact hashed basename), matches the
byte count and SHA-256, requires canonical bytes, and fully revalidates the
document before returning a typed payload.

Input strictness and the typed miss boundary
--------------------------------------------

``FrozenJSON`` fields accept exact ``bytes`` only: bytearray, memoryview,
str or any other mutable/foreign type is rejected before decoding, so no
caller-owned alias can survive into a prepared or decoded payload (the
frozen outer dataclasses never freeze nested values by themselves).  All
typed inputs are type-checked *before* any membership test, decode or path
conversion, and every serialized payload is bounded by explicit byte, node
and depth caps (``_MAX_JSON_BYTES``/``_MAX_JSON_NODES``/``_MAX_JSON_DEPTH``)
enforced by a non-recursive inspection walk.  Consequently malformed input
of any shape — wrong enum types, string outcomes, invalid path arguments,
invalid payload objects, cyclic-looking deep JSON, lone surrogates — is
returned as a typed :class:`RecoveryMiss` (fail closed, artifact unwritten,
no receipt minted) instead of letting TypeError/AttributeError/RecursionError
escape the public boundary; genuine program errors are not hidden by a
catch-all, and the existing duplicate-key/invalid-UTF-8/NaN/Infinity/
float-overflow rejections are preserved.  ``prepare_instance_result``
applies the *same* whole-envelope bounds (depth, nodes, total canonical
bytes) to the assembled document before any directory or file write, so a
successfully prepared artifact is always within every limit its own
verifier enforces; an over-envelope payload is a typed miss with nothing
written.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, NewType, cast

__all__ = [
    "FrozenJSON",
    "InstanceKey",
    "ExpectedInstance",
    "RecoveryIdentity",
    "CurrentAttempt",
    "AnalysisCompletion",
    "PendingCandidate",
    "InstanceResultPayload",
    "PreparedInstanceResult",
    "TrustedInstanceResultReceipt",
    "RecoveryAccepted",
    "RecoveryMiss",
    "prepare_instance_result",
    "verify_instance_result",
    "INSTANCE_RESULT_SCHEMA",
    "PENDING_RECORD_SCHEMA",
    "RECOVERY_POLICY_VERSION",
    "COMPLETION_SCHEMA",
    "INSTANCE_RESULT_EVENT_KIND",
    "ARTIFACT_DIR_NAME",
    "SUPPORTED_CANDIDATE_SCHEMA_VERSIONS",
    "SUPPORTED_DECISION_CONTEXT_VERSIONS",
    "VERSION_KEY_CANDIDATE_SCHEMA",
    "VERSION_KEY_CANDIDATE_DECISION_CONTEXT",
]

INSTANCE_RESULT_SCHEMA: Literal["zscope.instance-result.v1"] = "zscope.instance-result.v1"
PENDING_RECORD_SCHEMA: Literal["zscope.instance-pending-record.v1"] = (
    "zscope.instance-pending-record.v1"
)
RECOVERY_POLICY_VERSION: Literal["zscope.instance-recovery.v1"] = "zscope.instance-recovery.v1"
COMPLETION_SCHEMA: Literal["zscope.instance-analysis-completion.v1"] = (
    "zscope.instance-analysis-completion.v1"
)
INSTANCE_RESULT_EVENT_KIND: Literal["instance_result_persisted"] = "instance_result_persisted"
ARTIFACT_DIR_NAME = "instance-results"

_CompletionState = Literal["complete", "error", "cancelled", "deferred", "incomplete", "unknown"]
_RecordStatus = Literal["pending", "queued"]
_RecordRole = Literal["triage_lead", "validation_obligation"]

COMPLETION_STATES = frozenset(
    {"complete", "error", "cancelled", "deferred", "incomplete", "unknown"}
)
ELIGIBLE_COMPLETION_STATE = "complete"
RECORD_STATUSES = frozenset({"pending", "queued"})
RECORD_ROLES = frozenset({"triage_lead", "validation_obligation"})

# Embedded record schema versions this codec supports, centralized here so
# the module stays stdlib-only.  The record's ``candidate_schema_version``
# must be supported *and* equal the identity's declared
# ``"candidate_schema"`` component; ``decision_context_version`` must be
# supported and, when the identity declares the optional
# ``"candidate_decision_context"`` component, equal it.  The two key names
# are the explicit coordinator-facing convention (mirroring
# ``scan_work.instance_versions``); a future schema version requires
# deliberately extending these sets, never an arbitrary non-empty string.
SUPPORTED_CANDIDATE_SCHEMA_VERSIONS = frozenset({"zscope.candidate.v3.5"})
SUPPORTED_DECISION_CONTEXT_VERSIONS = frozenset(
    {
        "zscope.decision-context.v3.1",
        "zscope.decision-context.v3.2",
        "zscope.decision-context.v3.3",
    }
)
VERSION_KEY_CANDIDATE_SCHEMA = "candidate_schema"
VERSION_KEY_CANDIDATE_DECISION_CONTEXT = "candidate_decision_context"

# The frozen wire key sets.  Every decode compares exact sets, so schema drift
# or smuggled terminal/proof fields are rejected instead of silently ignored.
_DOCUMENT_KEYS = frozenset(
    {
        "schema",
        "recovery_policy",
        "producer_run_id",
        "identity",
        "instance",
        "instance_semantics_digest",
        "completion",
        "manifest",
        "records",
        "outcome",
    }
)
_IDENTITY_KEYS = frozenset(
    {
        "job_id",
        "input_revision",
        "plan_fingerprint",
        "versions",
        "registry_digest",
        "semantics_policy",
        "semantics_digest",
        "dependency_digest",
    }
)
_INSTANCE_KEYS = frozenset({"identity", "build_context_id", "usr", "source"})
_COMPLETION_KEYS = frozenset(
    {
        "schema",
        "state",
        "collection_closed",
        "input_current",
        "expected_record_count",
        "expected_obligation_count",
        "expected_occurrence_count",
        "active_stage_errors",
    }
)
_MANIFEST_KEYS = frozenset(
    {"record_count", "obligation_count", "occurrence_count", "membership_digest"}
)
_RECORD_KEYS = frozenset(
    {
        "schema",
        "candidate_uid",
        "obligation_uid",
        "validation_cluster_uid",
        "build_context_id",
        "owner_instances",
        "status",
        "record_role",
        "record_json",
    }
)
# The complete pre-validation CandidateRecord projection (frozen contract
# ``persistence_complete_projection.record_json_required_fields``).  Terminal
# disposition/proof/attempt fields are structurally absent, not merely empty.
_RECORD_JSON_KEYS = frozenset(
    {
        "candidate_schema_version",
        "candidate_uid",
        "candidate_id",
        "obligation_uid",
        "validation_cluster_uid",
        "history_key",
        "build_context_id",
        "decision_context_version",
        "evidence_hash",
        "decision_evidence_hash",
        "provenance_hashes",
        "evidence_hashes",
        "context_signature",
        "validation_contexts",
        "occurrence_uids",
        "occurrences",
        "entries",
        "call_paths",
        "entry_paths",
        "sources",
        "record_role",
        "status",
        "defect_class",
        "canonical_source",
        "canonical_sink",
        "root_cause_key",
        "dedup_key",
        "ticket",
    }
)
_OCCURRENCE_KEYS = frozenset(
    {"occurrence_uid", "entry_identity", "call_paths", "context_signature"}
)
_TICKET_KEYS = frozenset(
    {
        "id",
        "skill",
        "task",
        "trigger",
        "line",
        "context_slice",
        "priority_score",
        "priority_reasons",
        "origin",
        "sink",
        "resource_kind",
        "source",
        "sources",
        "call_paths",
        "dedup_key",
        "evidence",
    }
)

# Serialized adjudication authority is contamination, not data.  A saved
# confirmation/rejection/suppression or non-empty proof anywhere in the
# document disqualifies the whole instance; neutral producer assertions such
# as a default "needs_review" envelope disposition remain representable.
_AUTHORITY_VALUES = frozenset(
    {
        "confirmed",
        "validated",
        "verified",
        "verified_vulnerability",
        "rejected",
        "rejected_with_proof",
        "suppressed",
        "user_suppression",
    }
)
_AUTHORITY_KEYS = frozenset(
    {
        "candidate_disposition",
        "disposition",
        "terminal_disposition",
        "validation_status",
        "finding_status",
        "finding_kind",
        "deterministic_prevalidation_decision",
        "status",
        "verdict",
    }
)
_PROOF_KEYS = frozenset({"decision_proof"})
_ATTEMPT_STATE_KEYS = frozenset(
    {
        "validation_cache",
        "validation_cache_key",
        "validation_attempt_state",
        "validation_attempt_count",
        "validator_receipt_id",
        "validation_receipt_id",
        "live_receipt_id",
    }
)

_HEX_DIGITS = frozenset("0123456789abcdef")

FrozenJSON = NewType("FrozenJSON", bytes)


class _ValidationError(ValueError):
    """Internal strict-validation failure; converted to a RecoveryMiss."""


# ---------------------------------------------------------------------------
# Frozen typed interfaces (contract zscope.instance-result.v1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InstanceKey:
    """One exact analysis instance: build context, USR and source coordinates."""

    identity: str
    build_context_id: str
    usr: str
    source: str


@dataclass(frozen=True)
class ExpectedInstance:
    """The instance a current reader requests, with its semantics digest."""

    key: InstanceKey
    semantics_digest: str


@dataclass(frozen=True)
class RecoveryIdentity:
    """The common identity a reusable result and its readers must agree on."""

    job_id: str
    input_revision: str
    plan_fingerprint: str
    versions: tuple[tuple[str, str], ...]
    registry_digest: str
    semantics_policy: str
    semantics_digest: str  # ordered whole-plan semantic manifest digest
    dependency_digest: str


@dataclass(frozen=True)
class CurrentAttempt:
    """The current attempt coordinates a trusted reader/settler binds to.

    ``owner_token`` is process input only: it is excluded from ``repr`` and
    must never reach disk, logs or an artifact payload.
    """

    job_id: str
    run_id: str
    owner_token: str = field(repr=False)
    input_revision: str
    run_dir: Path


@dataclass(frozen=True)
class AnalysisCompletion:
    """Typed completion evidence from the real collection-phase boundary."""

    schema: Literal["zscope.instance-analysis-completion.v1"]
    state: _CompletionState
    collection_closed: bool
    input_current: bool
    expected_record_count: int
    expected_obligation_count: int
    expected_occurrence_count: int
    active_stage_errors: tuple[str, ...]


@dataclass(frozen=True)
class PendingCandidate:
    """One complete, neutral, pre-validation candidate record projection."""

    schema: Literal["zscope.instance-pending-record.v1"]
    candidate_uid: str
    obligation_uid: str
    validation_cluster_uid: str
    build_context_id: str
    owner_instances: tuple[InstanceKey, ...]
    status: _RecordStatus
    record_role: _RecordRole
    record_json: FrozenJSON  # complete CandidateRecord projection (see module doc)


@dataclass(frozen=True)
class InstanceResultPayload:
    """The full recoverable content of one instance analysis result."""

    schema: Literal["zscope.instance-result.v1"]
    producer_run_id: str
    identity: RecoveryIdentity
    instance: InstanceKey
    instance_semantics_digest: str
    completion: AnalysisCompletion
    outcome_json: FrozenJSON
    records: tuple[PendingCandidate, ...]


@dataclass(frozen=True)
class PreparedInstanceResult:
    """An encoded artifact ready for a coordinator-side bound settlement."""

    payload: InstanceResultPayload
    artifact_path: Path
    content_sha256: str
    byte_count: int


@dataclass(frozen=True)
class TrustedInstanceResultReceipt:
    """Trusted producer coordinates returned by the coordinator's joined reader."""

    event_seq: int
    kind: Literal["instance_result_persisted"]
    producer_run_id: str
    producer_run_dir: Path
    producer_attempt_no: int
    identity: RecoveryIdentity
    instance: InstanceKey
    instance_semantics_digest: str
    artifact_path: Path
    content_sha256: str
    byte_count: int


@dataclass(frozen=True)
class RecoveryAccepted:
    """A strictly verified result; admission/settlement stays with the coordinator."""

    receipt: TrustedInstanceResultReceipt
    payload: InstanceResultPayload


@dataclass(frozen=True)
class RecoveryMiss:
    """A refused lookup or validation; the instance must be re-analyzed."""

    instance: InstanceKey
    reason: str


# ---------------------------------------------------------------------------
# Canonical strict JSON
# ---------------------------------------------------------------------------


def _canonical_bytes(value: object) -> bytes:
    """The deterministic wire encoding: sorted, compact, UTF-8, finite only."""

    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _ValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise _ValidationError(f"non-finite JSON constant: {name}")


# Bounds for untrusted serialized JSON.  They are deliberately generous far
# beyond any real candidate/outcome projection so complete evidence survives,
# while a pathological document fails as data, never as an escape.
_MAX_JSON_BYTES = 64 * 1024 * 1024
_MAX_JSON_NODES = 4_000_000
_MAX_JSON_DEPTH = 256


def _inspect_json_value(value: object) -> None:
    """Iteratively bound a parsed tree: JSON types, finite floats, depth, nodes.

    The walk is non-recursive on purpose: a document that parsed (possibly
    just under the interpreter recursion limit) is still rejected here by the
    codec's own depth/node caps instead of recursing inside the codec.
    """

    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise _ValidationError("JSON payload exceeds the node limit")
        if depth > _MAX_JSON_DEPTH:
            raise _ValidationError("JSON payload exceeds the nesting depth limit")
        if isinstance(item, float):
            if not math.isfinite(item):
                raise _ValidationError("JSON payload contains a non-finite float")
        elif isinstance(item, dict):
            for key, sub_item in item.items():
                if not isinstance(key, str):
                    raise _ValidationError("JSON object keys must be strings")
                stack.append((sub_item, depth + 1))
        elif isinstance(item, list):
            for sub_item in item:
                stack.append((sub_item, depth + 1))
        elif item is not None and not isinstance(item, (str, bool, int)):
            raise _ValidationError("JSON payload contains a non-JSON value")


def _strict_loads(raw: bytes) -> Any:
    """Decode immutable bytes as strict, bounded JSON.

    Only exact ``bytes`` are accepted: bytearray/memoryview/str inputs are
    rejected so no mutable alias can travel into a payload.  Invalid UTF-8,
    duplicate keys, NaN/Infinity constants, non-finite floats and excessive
    byte/depth/node counts all become validation errors; deeply nested input
    that exhausts the JSON parser becomes a validation error too, never an
    exception escaping the public boundary.
    """

    if not isinstance(raw, bytes):
        raise _ValidationError("JSON payload must be immutable bytes")
    if len(raw) > _MAX_JSON_BYTES:
        raise _ValidationError("JSON payload exceeds the byte limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _ValidationError("payload is not valid UTF-8") from error
    try:
        value: Any = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_constant,
        )
    except _ValidationError:
        raise
    except RecursionError as error:
        raise _ValidationError("JSON payload nesting exceeds the parser limit") from error
    except ValueError as error:
        raise _ValidationError(f"invalid JSON: {error}") from error
    _inspect_json_value(value)
    return value


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_sha256_hex(value: object) -> bool:
    return (
        isinstance(value, str) and len(value) == 64 and all(char in _HEX_DIGITS for char in value)
    )


def _identity_filename_hash(identity: str) -> str:
    return _sha256_hex(identity.encode("utf-8"))


def _artifact_name(identity: str, content_sha256: str) -> str:
    return f"{_identity_filename_hash(identity)}.{content_sha256}.json"


# ---------------------------------------------------------------------------
# Structural validators (shared by encode and decode)
# ---------------------------------------------------------------------------


def _require_str(value: object, what: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise _ValidationError(f"{what} must be a string")
    if not allow_empty and not value:
        raise _ValidationError(f"{what} must not be empty")
    return value


def _require_int(value: object, what: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _ValidationError(f"{what} must be an integer")
    if value < minimum:
        raise _ValidationError(f"{what} must be >= {minimum}")
    return value


def _require_bool(value: object, what: str) -> bool:
    if not isinstance(value, bool):
        raise _ValidationError(f"{what} must be a boolean")
    return value


def _require_str_list(value: object, what: str) -> list[str]:
    if not isinstance(value, list):
        raise _ValidationError(f"{what} must be a list")
    return [_require_str(item, f"{what} item") for item in value]


def _require_path_list(value: object, what: str) -> list[list[str]]:
    if not isinstance(value, list):
        raise _ValidationError(f"{what} must be a list")
    result: list[list[str]] = []
    for path in value:
        if not isinstance(path, list):
            raise _ValidationError(f"{what} entries must be lists")
        result.append([_require_str(item, f"{what} segment") for item in path])
    return result


def _validate_instance_key(key: object, what: str) -> InstanceKey:
    if not isinstance(key, InstanceKey):
        raise _ValidationError(f"{what} must be an InstanceKey")
    for name in ("identity", "build_context_id", "usr", "source"):
        value = getattr(key, name)
        if not isinstance(value, str) or not value:
            raise _ValidationError(f"{what}.{name} must be a non-empty string")
    return key


def _validate_recovery_identity(identity: object, what: str) -> RecoveryIdentity:
    if not isinstance(identity, RecoveryIdentity):
        raise _ValidationError(f"{what} must be a RecoveryIdentity")
    for name in (
        "job_id",
        "input_revision",
        "plan_fingerprint",
        "registry_digest",
        "semantics_policy",
        "semantics_digest",
        "dependency_digest",
    ):
        value = getattr(identity, name)
        if not isinstance(value, str) or not value:
            raise _ValidationError(f"{what}.{name} must be a non-empty string")
    versions = identity.versions
    if not isinstance(versions, tuple) or not versions:
        raise _ValidationError(f"{what}.versions must be a non-empty tuple")
    seen: set[str] = set()
    for pair in versions:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise _ValidationError(f"{what}.versions entries must be (name, version) tuples")
        name, version = pair
        if not isinstance(name, str) or not name:
            raise _ValidationError(f"{what}.versions names must be non-empty strings")
        if not isinstance(version, str) or not version:
            raise _ValidationError(f"{what}.versions values must be non-empty strings")
        if name in seen:
            raise _ValidationError(f"{what}.versions has duplicate name: {name}")
        seen.add(name)
    return identity


def _validate_completion(completion: object, what: str) -> AnalysisCompletion:
    if not isinstance(completion, AnalysisCompletion):
        raise _ValidationError(f"{what} must be an AnalysisCompletion")
    if completion.schema != COMPLETION_SCHEMA:
        raise _ValidationError(f"{what}.schema is not {COMPLETION_SCHEMA}")
    if not isinstance(completion.state, str) or completion.state not in COMPLETION_STATES:
        raise _ValidationError(f"{what}.state is not a known completion state")
    if not isinstance(completion.collection_closed, bool):
        raise _ValidationError(f"{what}.collection_closed must be a boolean")
    if not isinstance(completion.input_current, bool):
        raise _ValidationError(f"{what}.input_current must be a boolean")
    _require_int(completion.expected_record_count, f"{what}.expected_record_count", minimum=0)
    _require_int(
        completion.expected_obligation_count,
        f"{what}.expected_obligation_count",
        minimum=0,
    )
    _require_int(
        completion.expected_occurrence_count,
        f"{what}.expected_occurrence_count",
        minimum=0,
    )
    if not isinstance(completion.active_stage_errors, tuple) or any(
        not isinstance(error, str) for error in completion.active_stage_errors
    ):
        raise _ValidationError(f"{what}.active_stage_errors must be a tuple of strings")
    return completion


def _completion_eligible(completion: AnalysisCompletion) -> bool:
    """Only a closed, current, error-free complete collection may be reused."""

    return (
        completion.state == ELIGIBLE_COMPLETION_STATE
        and completion.collection_closed
        and completion.input_current
        and not completion.active_stage_errors
    )


def _contamination_reason(value: object, path: str = "$") -> str:
    """Reject serialized adjudication authority anywhere in the document."""

    if isinstance(value, dict):
        for key, item in value.items():
            where = f"{path}.{key}"
            if key in _PROOF_KEYS and item:
                return f"saved decision proof at {where}"
            if key in _ATTEMPT_STATE_KEYS and item:
                return f"saved validation attempt/cache state at {where}"
            if (
                key in _AUTHORITY_KEYS
                and isinstance(item, str)
                and item.strip().lower() in _AUTHORITY_VALUES
            ):
                return f"saved adjudication authority at {where}"
            nested = _contamination_reason(item, where)
            if nested:
                return nested
        return ""
    if isinstance(value, list):
        for index, item in enumerate(value):
            nested = _contamination_reason(item, f"{path}[{index}]")
            if nested:
                return nested
    return ""


# ---------------------------------------------------------------------------
# Pending record projection validation
# ---------------------------------------------------------------------------


def _parse_record_json(raw: bytes) -> dict[str, Any]:
    value = _strict_loads(raw)
    if not isinstance(value, dict):
        raise _ValidationError("record_json must decode to a JSON object")
    if set(value) != _RECORD_JSON_KEYS:
        missing = sorted(_RECORD_JSON_KEYS - set(value))
        extra = sorted(set(value) - _RECORD_JSON_KEYS)
        raise _ValidationError(
            f"record_json key set mismatch (missing={missing}, unexpected={extra})"
        )
    if _canonical_bytes(value) != raw:
        raise _ValidationError("record_json is not canonical JSON")
    return value


def _validate_record_json_types(projection: dict[str, Any], record: PendingCandidate) -> None:
    for name in (
        "candidate_schema_version",
        "candidate_uid",
        "candidate_id",
        "obligation_uid",
        "validation_cluster_uid",
        "build_context_id",
        "decision_context_version",
        "evidence_hash",
        "decision_evidence_hash",
        "context_signature",
        "status",
        "record_role",
        "dedup_key",
    ):
        _require_str(projection[name], f"record_json.{name}")
    for name in (
        "history_key",
        "defect_class",
        "canonical_source",
        "canonical_sink",
        "root_cause_key",
    ):
        _require_str(projection[name], f"record_json.{name}", allow_empty=True)
    for name in (
        "provenance_hashes",
        "evidence_hashes",
        "validation_contexts",
        "occurrence_uids",
        "entries",
        "sources",
    ):
        _require_str_list(projection[name], f"record_json.{name}")
    for name in ("call_paths", "entry_paths"):
        _require_path_list(projection[name], f"record_json.{name}")

    occurrences = projection["occurrences"]
    if not isinstance(occurrences, list):
        raise _ValidationError("record_json.occurrences must be a list")
    occurrence_uids = projection["occurrence_uids"]
    if not isinstance(occurrence_uids, list):
        raise _ValidationError("record_json.occurrence_uids must be a list")
    # The live ledger deduplicates ``occurrence_uids`` while storing one full
    # CandidateOccurrence row per distinct (uid, entry, paths, context)
    # attribution: one UID may legitimately carry several path rows.  The UID
    # list, its coverage of the rows, and the complete row set are therefore
    # checked separately; rows are never reshaped, deduplicated or re-keyed
    # to force a 1:1 mapping with the UID list.
    if len(set(occurrence_uids)) != len(occurrence_uids):
        raise _ValidationError("record_json.occurrence_uids contains duplicate UIDs")
    # A shared validation cluster legitimately aggregates occurrences across
    # equivalent entry wrappers: the record keeps its first (primary) context
    # while ``validation_contexts`` declares every merged context, and each
    # occurrence row carries the context of its own add.  Rows are validated
    # against the complete declared membership — never rewritten to the
    # primary context — and every declared context must be carried by at
    # least one row; an unknown or undeclared context stays a miss.
    declared_contexts_list = projection["validation_contexts"]
    if len(set(declared_contexts_list)) != len(declared_contexts_list):
        raise _ValidationError("record_json.validation_contexts contains duplicates")
    declared_contexts = set(declared_contexts_list)
    if projection["context_signature"] not in declared_contexts:
        raise _ValidationError(
            "record context_signature is not among its declared validation_contexts"
        )
    row_uids: set[str] = set()
    row_contexts: set[str] = set()
    seen_rows: set[tuple[str, str, tuple[tuple[str, ...], ...], str]] = set()
    uid_entry_context: dict[str, tuple[str, str]] = {}
    for occurrence in occurrences:
        if not isinstance(occurrence, dict) or set(occurrence) != _OCCURRENCE_KEYS:
            raise _ValidationError(
                "record_json.occurrences entries must have exactly "
                "(occurrence_uid, entry_identity, call_paths, context_signature)"
            )
        uid = _require_str(occurrence["occurrence_uid"], "occurrence.occurrence_uid")
        entry = _require_str(
            occurrence["entry_identity"], "occurrence.entry_identity", allow_empty=True
        )
        paths = _require_path_list(occurrence["call_paths"], "occurrence.call_paths")
        context = _require_str(occurrence["context_signature"], "occurrence.context_signature")
        if context not in declared_contexts:
            raise _ValidationError(
                "occurrence context_signature is not among the declared validation_contexts"
            )
        row = (uid, entry, tuple(tuple(path) for path in paths), context)
        if row in seen_rows:
            raise _ValidationError("record_json.occurrences contains duplicate identical rows")
        seen_rows.add(row)
        row_uids.add(uid)
        row_contexts.add(context)
        entry_context = uid_entry_context.get(uid)
        if entry_context is None:
            uid_entry_context[uid] = (entry, context)
        elif entry_context != (entry, context):
            raise _ValidationError("occurrence rows sharing one UID disagree on entry/context")
    if row_uids != set(occurrence_uids):
        raise _ValidationError(
            "record_json occurrence rows and occurrence_uids do not cover each other exactly"
        )
    if row_contexts != declared_contexts:
        raise _ValidationError(
            "occurrence rows do not carry every declared validation context exactly"
        )

    ticket = projection["ticket"]
    if not isinstance(ticket, dict) or set(ticket) != _TICKET_KEYS:
        raise _ValidationError(
            "record_json.ticket must be the complete SubAgentTicket.to_dict projection"
        )
    _require_str(ticket["id"], "ticket.id")
    _require_str(ticket["skill"], "ticket.skill")
    _require_str(ticket["task"], "ticket.task")
    _require_str(ticket["trigger"], "ticket.trigger", allow_empty=True)
    _require_int(ticket["line"], "ticket.line", minimum=0)
    _require_str(ticket["context_slice"], "ticket.context_slice", allow_empty=True)
    _require_int(ticket["priority_score"], "ticket.priority_score", minimum=0)
    _require_str_list(ticket["priority_reasons"], "ticket.priority_reasons")
    _require_str(ticket["origin"], "ticket.origin", allow_empty=True)
    _require_str(ticket["sink"], "ticket.sink", allow_empty=True)
    _require_str(ticket["resource_kind"], "ticket.resource_kind", allow_empty=True)
    _require_str(ticket["source"], "ticket.source", allow_empty=True)
    _require_str_list(ticket["sources"], "ticket.sources")
    _require_path_list(ticket["call_paths"], "ticket.call_paths")
    _require_str(ticket["dedup_key"], "ticket.dedup_key")
    if not isinstance(ticket["evidence"], dict):
        raise _ValidationError("ticket.evidence must be a JSON object")

    # The projection must describe exactly the record it travels with.
    for wire_name, record_value in (
        ("candidate_uid", record.candidate_uid),
        ("obligation_uid", record.obligation_uid),
        ("validation_cluster_uid", record.validation_cluster_uid),
        ("build_context_id", record.build_context_id),
        ("status", record.status),
        ("record_role", record.record_role),
    ):
        if projection[wire_name] != record_value:
            raise _ValidationError(f"record_json.{wire_name} does not match the record")


def _validate_record_versions(
    projection: dict[str, Any], version_map: dict[str, str], what: str
) -> None:
    """Bind the embedded record schema to the supported and declared versions.

    An embedded schema the codec does not support, or one that contradicts
    the recovery identity's declared version components, is a miss: identity
    agreement is schema/data validation, not admission authority.
    """

    schema = projection["candidate_schema_version"]
    if schema not in SUPPORTED_CANDIDATE_SCHEMA_VERSIONS:
        raise _ValidationError(f"{what}: unsupported candidate schema version: {schema!r}")
    declared_schema = version_map.get(VERSION_KEY_CANDIDATE_SCHEMA)
    if declared_schema is None:
        raise _ValidationError(
            f"{what}: identity does not declare '{VERSION_KEY_CANDIDATE_SCHEMA}'"
        )
    if declared_schema != schema:
        raise _ValidationError(
            f"{what}: candidate schema version does not match the recovery identity"
        )
    decision = projection["decision_context_version"]
    if decision not in SUPPORTED_DECISION_CONTEXT_VERSIONS:
        raise _ValidationError(f"{what}: unsupported decision context version: {decision!r}")
    declared_decision = version_map.get(VERSION_KEY_CANDIDATE_DECISION_CONTEXT)
    if declared_decision is not None and declared_decision != decision:
        raise _ValidationError(
            f"{what}: decision context version does not match the recovery identity"
        )


def _validate_record(
    record: object,
    payload_instance: InstanceKey,
    what: str,
    version_map: dict[str, str],
) -> dict[str, Any]:
    if not isinstance(record, PendingCandidate):
        raise _ValidationError(f"{what} must be a PendingCandidate")
    if record.schema != PENDING_RECORD_SCHEMA:
        raise _ValidationError(f"{what}.schema is not {PENDING_RECORD_SCHEMA}")
    for name in ("candidate_uid", "obligation_uid", "validation_cluster_uid", "build_context_id"):
        value = getattr(record, name)
        if not isinstance(value, str) or not value:
            raise _ValidationError(f"{what}.{name} must be a non-empty string")
    if not isinstance(record.status, str) or record.status not in RECORD_STATUSES:
        raise _ValidationError(f"{what}.status must be pending or queued")
    if not isinstance(record.record_role, str) or record.record_role not in RECORD_ROLES:
        raise _ValidationError(f"{what}.record_role must be triage_lead or validation_obligation")
    if not isinstance(record.owner_instances, tuple) or not record.owner_instances:
        raise _ValidationError(f"{what}.owner_instances must be a non-empty tuple")
    owns_payload_instance = False
    for owner in record.owner_instances:
        _validate_instance_key(owner, f"{what}.owner_instances entry")
        if owner.build_context_id != record.build_context_id:
            raise _ValidationError(
                f"{what} mixes instances of different build contexts; "
                "same-name records across builds must never merge"
            )
        if owner == payload_instance:
            owns_payload_instance = True
    if not owns_payload_instance:
        raise _ValidationError(f"{what} is not owned by the instance this result file describes")
    if record.build_context_id != payload_instance.build_context_id:
        raise _ValidationError(f"{what}.build_context_id does not match the payload instance")
    if not isinstance(record.record_json, bytes):
        raise _ValidationError(f"{what}.record_json must be canonical JSON bytes")
    projection = _parse_record_json(record.record_json)
    _validate_record_json_types(projection, record)
    _validate_record_versions(projection, version_map, what)
    return projection


def _manifest_from_records(
    records: tuple[PendingCandidate, ...], projections: dict[int, dict[str, Any]]
) -> dict[str, Any]:
    """Complete counts plus a membership digest over every merge key and UID.

    Count fields alone cannot prove completeness: replacing one occurrence
    with another keeps every count, so the digest covers the exact per-record
    merge keys and the full occurrence multiset.
    """

    record_entries: list[list[Any]] = []
    obligation_uids: list[str] = []
    occurrence_uids: list[str] = []
    seen_clusters: set[str] = set()
    seen_merge_keys: set[tuple[str, str, str, str, str, str]] = set()
    for index, record in enumerate(records):
        projection = projections[index]
        if record.validation_cluster_uid in seen_clusters:
            raise _ValidationError("duplicate validation_cluster_uid in records")
        seen_clusters.add(record.validation_cluster_uid)
        evidence_hash = projection["evidence_hash"]
        context_signature = projection["context_signature"]
        uids_value = projection["occurrence_uids"]
        if not isinstance(evidence_hash, str) or not isinstance(context_signature, str):
            raise _ValidationError("record_json identity fields must be strings")
        if not isinstance(uids_value, list):
            raise _ValidationError("record_json.occurrence_uids must be a list")
        uids = [str(uid) for uid in uids_value]
        merge_key = (
            record.build_context_id,
            record.candidate_uid,
            record.obligation_uid,
            record.validation_cluster_uid,
            evidence_hash,
            context_signature,
        )
        if merge_key in seen_merge_keys:
            raise _ValidationError("duplicate record merge key in records")
        seen_merge_keys.add(merge_key)
        record_entries.append(list(merge_key) + [sorted(uids)])
        obligation_uids.append(record.obligation_uid)
        occurrence_uids.extend(uids)
    membership_payload = {
        "records": sorted(record_entries),
        "obligation_uids": sorted(obligation_uids),
        "occurrence_uids": sorted(occurrence_uids),
    }
    return {
        "record_count": len(records),
        "obligation_count": len(set(obligation_uids)),
        "occurrence_count": len(occurrence_uids),
        "membership_digest": _sha256_hex(_canonical_bytes(membership_payload)),
    }


def _validate_manifest_agreement(manifest: dict[str, Any], completion: AnalysisCompletion) -> None:
    if manifest["record_count"] != completion.expected_record_count:
        raise _ValidationError("manifest record count does not match completion evidence")
    if manifest["obligation_count"] != completion.expected_obligation_count:
        raise _ValidationError("manifest obligation count does not match completion evidence")
    if manifest["occurrence_count"] != completion.expected_occurrence_count:
        raise _ValidationError("manifest occurrence count does not match completion evidence")


def _parse_outcome(raw: bytes) -> dict[str, Any]:
    value = _strict_loads(raw)
    if not isinstance(value, dict):
        raise _ValidationError("outcome_json must decode to a JSON object")
    if _canonical_bytes(value) != raw:
        raise _ValidationError("outcome_json is not canonical JSON")
    gaps = value.get("diagnostic_gaps")
    if not isinstance(gaps, list) or any(not isinstance(gap, str) for gap in gaps):
        raise _ValidationError('outcome_json must carry "diagnostic_gaps" as a list of strings')
    return value


# ---------------------------------------------------------------------------
# Wire document build (encode) and rebuild (decode)
# ---------------------------------------------------------------------------


def _validated_document(payload: InstanceResultPayload) -> dict[str, Any]:
    """Validate a payload and derive its canonical wire document."""

    if not isinstance(payload, InstanceResultPayload):
        raise _ValidationError("payload must be an InstanceResultPayload")
    if payload.schema != INSTANCE_RESULT_SCHEMA:
        raise _ValidationError(f"payload.schema is not {INSTANCE_RESULT_SCHEMA}")
    _require_str(payload.producer_run_id, "payload.producer_run_id")
    identity = _validate_recovery_identity(payload.identity, "payload.identity")
    instance = _validate_instance_key(payload.instance, "payload.instance")
    _require_str(payload.instance_semantics_digest, "payload.instance_semantics_digest")
    completion = _validate_completion(payload.completion, "payload.completion")
    if not _completion_eligible(completion):
        raise _ValidationError(
            "only a complete, closed, current, error-free collection may be persisted; "
            "this result must be re-analyzed instead"
        )
    if not isinstance(payload.records, tuple):
        raise _ValidationError("payload.records must be a tuple")
    version_map = dict(identity.versions)
    projections: dict[int, dict[str, Any]] = {}
    for index, record in enumerate(payload.records):
        projections[index] = _validate_record(record, instance, f"records[{index}]", version_map)
    outcome = _parse_outcome(payload.outcome_json)
    manifest = _manifest_from_records(payload.records, projections)
    _validate_manifest_agreement(manifest, completion)
    document: dict[str, Any] = {
        "schema": INSTANCE_RESULT_SCHEMA,
        "recovery_policy": RECOVERY_POLICY_VERSION,
        "producer_run_id": payload.producer_run_id,
        "identity": {
            "job_id": identity.job_id,
            "input_revision": identity.input_revision,
            "plan_fingerprint": identity.plan_fingerprint,
            "versions": [[name, version] for name, version in identity.versions],
            "registry_digest": identity.registry_digest,
            "semantics_policy": identity.semantics_policy,
            "semantics_digest": identity.semantics_digest,
            "dependency_digest": identity.dependency_digest,
        },
        "instance": {
            "identity": instance.identity,
            "build_context_id": instance.build_context_id,
            "usr": instance.usr,
            "source": instance.source,
        },
        "instance_semantics_digest": payload.instance_semantics_digest,
        "completion": {
            "schema": completion.schema,
            "state": completion.state,
            "collection_closed": completion.collection_closed,
            "input_current": completion.input_current,
            "expected_record_count": completion.expected_record_count,
            "expected_obligation_count": completion.expected_obligation_count,
            "expected_occurrence_count": completion.expected_occurrence_count,
            "active_stage_errors": list(completion.active_stage_errors),
        },
        "manifest": manifest,
        "records": [
            {
                "schema": record.schema,
                "candidate_uid": record.candidate_uid,
                "obligation_uid": record.obligation_uid,
                "validation_cluster_uid": record.validation_cluster_uid,
                "build_context_id": record.build_context_id,
                "owner_instances": [
                    {
                        "identity": owner.identity,
                        "build_context_id": owner.build_context_id,
                        "usr": owner.usr,
                        "source": owner.source,
                    }
                    for owner in record.owner_instances
                ],
                "status": record.status,
                "record_role": record.record_role,
                "record_json": projections[index],
            }
            for index, record in enumerate(payload.records)
        ],
        "outcome": outcome,
    }
    reason = _contamination_reason(document)
    if reason:
        raise _ValidationError(reason)
    return document


def _decoded_identity(value: object) -> RecoveryIdentity:
    if not isinstance(value, dict) or set(value) != _IDENTITY_KEYS:
        raise _ValidationError("document identity key set mismatch")
    versions = value["versions"]
    if not isinstance(versions, list) or not versions:
        raise _ValidationError("document identity versions must be a non-empty list")
    pairs: list[tuple[str, str]] = []
    for pair in versions:
        if not isinstance(pair, list) or len(pair) != 2:
            raise _ValidationError("document identity versions entries must be pairs")
        name = _require_str(pair[0], "identity.versions name")
        version = _require_str(pair[1], "identity.versions value")
        pairs.append((name, version))
    identity = RecoveryIdentity(
        job_id=_require_str(value["job_id"], "identity.job_id"),
        input_revision=_require_str(value["input_revision"], "identity.input_revision"),
        plan_fingerprint=_require_str(value["plan_fingerprint"], "identity.plan_fingerprint"),
        versions=tuple(pairs),
        registry_digest=_require_str(value["registry_digest"], "identity.registry_digest"),
        semantics_policy=_require_str(value["semantics_policy"], "identity.semantics_policy"),
        semantics_digest=_require_str(value["semantics_digest"], "identity.semantics_digest"),
        dependency_digest=_require_str(value["dependency_digest"], "identity.dependency_digest"),
    )
    return _validate_recovery_identity(identity, "identity")


def _decoded_instance(value: object, what: str) -> InstanceKey:
    if not isinstance(value, dict) or set(value) != _INSTANCE_KEYS:
        raise _ValidationError(f"{what} key set mismatch")
    return _validate_instance_key(
        InstanceKey(
            identity=_require_str(value["identity"], f"{what}.identity"),
            build_context_id=_require_str(value["build_context_id"], f"{what}.build_context_id"),
            usr=_require_str(value["usr"], f"{what}.usr"),
            source=_require_str(value["source"], f"{what}.source"),
        ),
        what,
    )


def _decoded_completion(value: object) -> AnalysisCompletion:
    if not isinstance(value, dict) or set(value) != _COMPLETION_KEYS:
        raise _ValidationError("completion key set mismatch")
    if value["schema"] != COMPLETION_SCHEMA:
        raise _ValidationError(f"completion schema is not {COMPLETION_SCHEMA}")
    completion = AnalysisCompletion(
        schema=COMPLETION_SCHEMA,
        state=cast(_CompletionState, _require_str(value["state"], "completion.state")),
        collection_closed=_require_bool(value["collection_closed"], "completion.collection_closed"),
        input_current=_require_bool(value["input_current"], "completion.input_current"),
        expected_record_count=_require_int(
            value["expected_record_count"], "completion.expected_record_count", minimum=0
        ),
        expected_obligation_count=_require_int(
            value["expected_obligation_count"],
            "completion.expected_obligation_count",
            minimum=0,
        ),
        expected_occurrence_count=_require_int(
            value["expected_occurrence_count"],
            "completion.expected_occurrence_count",
            minimum=0,
        ),
        active_stage_errors=tuple(
            _require_str_list(value["active_stage_errors"], "completion.active_stage_errors")
        ),
    )
    _validate_completion(completion, "completion")
    return completion


def _decoded_document(document: object) -> InstanceResultPayload:
    """Strictly validate a decoded wire document and rebuild the typed payload."""

    if not isinstance(document, dict) or set(document) != _DOCUMENT_KEYS:
        raise _ValidationError("document key set mismatch")
    if document["schema"] != INSTANCE_RESULT_SCHEMA:
        raise _ValidationError(f"document schema is not {INSTANCE_RESULT_SCHEMA}")
    if document["recovery_policy"] != RECOVERY_POLICY_VERSION:
        raise _ValidationError(f"document recovery policy is not {RECOVERY_POLICY_VERSION}")
    producer_run_id = _require_str(document["producer_run_id"], "document.producer_run_id")
    identity = _decoded_identity(document["identity"])
    instance = _decoded_instance(document["instance"], "document.instance")
    semantics_digest = _require_str(
        document["instance_semantics_digest"], "document.instance_semantics_digest"
    )
    completion = _decoded_completion(document["completion"])
    if not _completion_eligible(completion):
        raise _ValidationError(
            "completion marker is not a successful complete collection; "
            "this instance must be re-analyzed"
        )
    raw_manifest = document["manifest"]
    if not isinstance(raw_manifest, dict) or set(raw_manifest) != _MANIFEST_KEYS:
        raise _ValidationError("manifest key set mismatch")
    if not _is_sha256_hex(raw_manifest["membership_digest"]):
        raise _ValidationError("manifest.membership_digest must be a lowercase SHA-256 hex")
    raw_records = document["records"]
    if not isinstance(raw_records, list):
        raise _ValidationError("document.records must be a list")
    version_map = dict(identity.versions)
    records: list[PendingCandidate] = []
    projections: dict[int, dict[str, Any]] = {}
    for index, raw_record in enumerate(raw_records):
        if not isinstance(raw_record, dict) or set(raw_record) != _RECORD_KEYS:
            raise _ValidationError(f"records[{index}] key set mismatch")
        if raw_record["schema"] != PENDING_RECORD_SCHEMA:
            raise _ValidationError(f"records[{index}].schema is not {PENDING_RECORD_SCHEMA}")
        owners_raw = raw_record["owner_instances"]
        if not isinstance(owners_raw, list) or not owners_raw:
            raise _ValidationError(f"records[{index}].owner_instances must be a non-empty list")
        owners = tuple(
            _decoded_instance(owner, f"records[{index}].owner_instances[{owner_index}]")
            for owner_index, owner in enumerate(owners_raw)
        )
        record_json_value = raw_record["record_json"]
        # Re-derive the canonical record_json bytes from the embedded value;
        # a document whose bytes are canonical makes this byte-exact.
        record = PendingCandidate(
            schema=PENDING_RECORD_SCHEMA,
            candidate_uid=_require_str(
                raw_record["candidate_uid"], f"records[{index}].candidate_uid"
            ),
            obligation_uid=_require_str(
                raw_record["obligation_uid"], f"records[{index}].obligation_uid"
            ),
            validation_cluster_uid=_require_str(
                raw_record["validation_cluster_uid"],
                f"records[{index}].validation_cluster_uid",
            ),
            build_context_id=_require_str(
                raw_record["build_context_id"], f"records[{index}].build_context_id"
            ),
            owner_instances=owners,
            status=cast(
                _RecordStatus,
                _require_str(raw_record["status"], f"records[{index}].status"),
            ),
            record_role=cast(
                _RecordRole,
                _require_str(raw_record["record_role"], f"records[{index}].record_role"),
            ),
            record_json=FrozenJSON(_canonical_bytes(record_json_value)),
        )
        projections[index] = _validate_record(record, instance, f"records[{index}]", version_map)
        records.append(record)
    outcome_value = document["outcome"]
    if not isinstance(outcome_value, dict):
        raise _ValidationError("document.outcome must be a JSON object")
    outcome_gaps = outcome_value.get("diagnostic_gaps")
    if not isinstance(outcome_gaps, list) or any(not isinstance(gap, str) for gap in outcome_gaps):
        raise _ValidationError('document.outcome must carry "diagnostic_gaps" as a list of strings')
    manifest = {
        "record_count": _require_int(
            raw_manifest["record_count"], "manifest.record_count", minimum=0
        ),
        "obligation_count": _require_int(
            raw_manifest["obligation_count"], "manifest.obligation_count", minimum=0
        ),
        "occurrence_count": _require_int(
            raw_manifest["occurrence_count"], "manifest.occurrence_count", minimum=0
        ),
        "membership_digest": raw_manifest["membership_digest"],
    }
    recomputed = _manifest_from_records(tuple(records), projections)
    if manifest != recomputed:
        raise _ValidationError(
            "manifest does not match the decoded records (counts or membership digest)"
        )
    _validate_manifest_agreement(manifest, completion)
    payload = InstanceResultPayload(
        schema=INSTANCE_RESULT_SCHEMA,
        producer_run_id=producer_run_id,
        identity=identity,
        instance=instance,
        instance_semantics_digest=semantics_digest,
        completion=completion,
        outcome_json=FrozenJSON(_canonical_bytes(outcome_value)),
        records=tuple(records),
    )
    reason = _contamination_reason(document)
    if reason:
        raise _ValidationError(reason)
    return payload


# ---------------------------------------------------------------------------
# Artifact publication and path fencing
# ---------------------------------------------------------------------------


def _require_absolute_run_dir(run_dir: Path, what: str) -> None:
    if not isinstance(run_dir, Path):
        raise _ValidationError(f"{what} must be a Path")
    if not run_dir.is_absolute():
        raise _ValidationError(f"{what} must be an absolute path")
    if ".." in run_dir.parts:
        raise _ValidationError(f"{what} must not contain '..' components")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    handle = os.open(path, flags)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)


def _publish_immutable(target: Path, raw: bytes) -> str:
    """Atomically publish ``raw`` at ``target``; never overwrite other bytes."""

    directory = target.parent
    try:
        directory.mkdir(parents=True, exist_ok=True)
        if os.path.islink(directory):
            return "instance-results exists as a symlink; refusing to publish through it"
        if not directory.is_dir():
            return "instance-results exists but is not a directory"
        if os.path.islink(target):
            return "artifact path exists as a symlink; refusing to reuse it"
        if target.exists():
            existing = target.read_bytes()
            if existing == raw:
                return ""  # idempotent republication of identical content
            return "artifact path already holds different content; refusing to overwrite"
        temporary = directory / (f".{target.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}")
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, target)
            except FileExistsError:
                if os.path.islink(target):
                    return "artifact path appeared as a symlink; refusing to reuse it"
                existing = target.read_bytes()
                if existing == raw:
                    return ""
                return "artifact path was concurrently published with different content"
        finally:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        if target.read_bytes() != raw:
            return "published artifact does not read back identically"
        _fsync_directory(directory)
        return ""
    except OSError as error:
        return f"artifact publication failed: {error}"


def _validate_artifact_path(receipt: TrustedInstanceResultReceipt) -> None:
    """Fence the receipt's artifact inside the producer's own instance-results."""

    _require_absolute_run_dir(receipt.producer_run_dir, "receipt.producer_run_dir")
    artifact = receipt.artifact_path
    if not isinstance(artifact, Path):
        raise _ValidationError("receipt.artifact_path must be a Path")
    if not artifact.is_absolute():
        raise _ValidationError("receipt.artifact_path must be an absolute path")
    if ".." in artifact.parts:
        raise _ValidationError("receipt.artifact_path must not contain '..' components")
    expected_directory = receipt.producer_run_dir / ARTIFACT_DIR_NAME
    if artifact.parent != expected_directory:
        raise _ValidationError("artifact path escapes the producer's instance-results directory")
    expected_name = _artifact_name(receipt.instance.identity, receipt.content_sha256)
    if artifact.name != expected_name:
        raise _ValidationError(
            "artifact basename does not match the instance identity and content digest"
        )
    if os.path.islink(artifact):
        raise _ValidationError("artifact path is a symlink; refusing to read through it")
    if os.path.islink(expected_directory):
        raise _ValidationError("instance-results directory is a symlink; refusing traversal")
    resolved_artifact = Path(os.path.realpath(artifact))
    resolved_directory = Path(os.path.realpath(expected_directory))
    if resolved_artifact.parent != resolved_directory:
        raise _ValidationError("resolved artifact path escapes the producer directory")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def prepare_instance_result(
    payload: InstanceResultPayload, *, producer_run_dir: Path
) -> PreparedInstanceResult | RecoveryMiss:
    """Encode one successful complete result and publish it immutably.

    The payload is fully validated (schema, identity, eligible completion,
    complete neutral records, manifest counts, no serialized adjudication
    authority) *before* any byte is written.  Publication is atomic and never
    overwrites different content.  This function performs no SQL and grants no
    receipt; only the coordinator's settlement path may bind the artifact to
    the current attempt.  Malformed input of any shape is a typed
    :class:`RecoveryMiss`, never an exception escaping this boundary.
    """

    miss_instance = (
        payload.instance
        if isinstance(payload, InstanceResultPayload) and isinstance(payload.instance, InstanceKey)
        else InstanceKey(identity="", build_context_id="", usr="", source="")
    )
    try:
        if isinstance(producer_run_dir, Path):
            run_dir = producer_run_dir
        elif isinstance(producer_run_dir, str):
            run_dir = Path(producer_run_dir)
        else:
            raise _ValidationError("producer_run_dir must be a Path or string")
        _require_absolute_run_dir(run_dir, "producer_run_dir")
        document = _validated_document(payload)
        # The assembled envelope must satisfy exactly the resource bounds the
        # verifier applies to the whole artifact (depth, nodes, total bytes);
        # otherwise prepare could publish an immutable file its own verify
        # must reject.  Both checks run before any directory or file write.
        _inspect_json_value(document)
        raw = _canonical_bytes(document)
        if len(raw) > _MAX_JSON_BYTES:
            raise _ValidationError("assembled artifact document exceeds the byte limit")
        content_sha256 = _sha256_hex(raw)
        target = (
            run_dir / ARTIFACT_DIR_NAME / _artifact_name(payload.instance.identity, content_sha256)
        )
        reason = _publish_immutable(target, raw)
        if reason:
            return RecoveryMiss(instance=payload.instance, reason=reason)
        return PreparedInstanceResult(
            payload=payload,
            artifact_path=target,
            content_sha256=content_sha256,
            byte_count=len(raw),
        )
    except _ValidationError as error:
        return RecoveryMiss(instance=miss_instance, reason=str(error))
    except (OSError, ValueError) as error:
        return RecoveryMiss(instance=miss_instance, reason=f"artifact encoding failed: {error}")


def verify_instance_result(
    receipt: TrustedInstanceResultReceipt,
    *,
    expected: RecoveryIdentity,
    instance: ExpectedInstance,
) -> RecoveryAccepted | RecoveryMiss:
    """Strictly verify a trusted receipt's artifact against the expected plan.

    This is byte/schema/identity/completeness validation only: it never
    confers reuse authority.  The coordinator must still re-check the current
    job/run/owner/input binding, dependency currentness and the queue claim
    before admitting, settling or publishing anything built from the result.
    """

    if isinstance(instance, ExpectedInstance) and isinstance(instance.key, InstanceKey):
        requested = instance.key
    else:
        # A malformed request cannot name an instance; report the miss against
        # an empty key rather than fabricating or crashing.
        requested = InstanceKey(identity="", build_context_id="", usr="", source="")
    try:
        if not isinstance(receipt, TrustedInstanceResultReceipt):
            raise _ValidationError("receipt must be a TrustedInstanceResultReceipt")
        if receipt.kind != INSTANCE_RESULT_EVENT_KIND:
            raise _ValidationError(f"receipt kind is not {INSTANCE_RESULT_EVENT_KIND}")
        _require_int(receipt.event_seq, "receipt.event_seq", minimum=1)
        _require_int(receipt.producer_attempt_no, "receipt.producer_attempt_no", minimum=1)
        _require_str(receipt.producer_run_id, "receipt.producer_run_id")
        _validate_recovery_identity(receipt.identity, "receipt.identity")
        _validate_instance_key(receipt.instance, "receipt.instance")
        _require_str(receipt.instance_semantics_digest, "receipt.instance_semantics_digest")
        if not _is_sha256_hex(receipt.content_sha256):
            raise _ValidationError("receipt.content_sha256 must be a lowercase SHA-256 hex")
        _require_int(receipt.byte_count, "receipt.byte_count", minimum=0)
        if not isinstance(instance, ExpectedInstance):
            raise _ValidationError("instance must be an ExpectedInstance")
        _validate_instance_key(requested, "instance.key")
        _require_str(instance.semantics_digest, "instance.semantics_digest")
        if not isinstance(expected, RecoveryIdentity):
            raise _ValidationError("expected must be a RecoveryIdentity")
        _validate_recovery_identity(expected, "expected")
        if receipt.identity != expected:
            raise _ValidationError(
                "receipt recovery identity does not match the current expected identity"
            )
        if receipt.instance != requested:
            raise _ValidationError("receipt instance does not match the requested instance")
        if receipt.instance_semantics_digest != instance.semantics_digest:
            raise _ValidationError("receipt semantics digest does not match the expected instance")
        _validate_artifact_path(receipt)
        if receipt.artifact_path.stat().st_size > _MAX_JSON_BYTES:
            raise _ValidationError("artifact exceeds the byte limit")
        raw = receipt.artifact_path.read_bytes()
        if len(raw) != receipt.byte_count:
            raise _ValidationError("artifact byte count does not match the receipt")
        if _sha256_hex(raw) != receipt.content_sha256:
            raise _ValidationError("artifact bytes do not match the receipt digest")
        document = _strict_loads(raw)
        if _canonical_bytes(document) != raw:
            raise _ValidationError("artifact bytes are not canonical JSON")
        payload = _decoded_document(document)
        if payload.producer_run_id != receipt.producer_run_id:
            raise _ValidationError("document producer run does not match the receipt")
        if payload.identity != receipt.identity:
            raise _ValidationError("document identity does not match the receipt")
        if payload.instance != receipt.instance:
            raise _ValidationError("document instance does not match the receipt")
        if payload.instance_semantics_digest != receipt.instance_semantics_digest:
            raise _ValidationError("document semantics digest does not match the receipt")
        return RecoveryAccepted(receipt=receipt, payload=payload)
    except _ValidationError as error:
        return RecoveryMiss(instance=requested, reason=str(error))
    except (OSError, ValueError) as error:
        return RecoveryMiss(instance=requested, reason=f"artifact verification failed: {error}")
