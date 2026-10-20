"""Job-driven instance work for a ScanSession (the session-side producer).

A scan session started by a job owner consumes the owner-passed
``ZSCOPE_JOB_*`` identity and drains one persistent work queue through
``SessionWorkScheduler``.  The work is the *real* per-instance analysis and the
scan-level validation/checkpoint, never a mocked callback list:

``instance_analysis``   analyze one scheduled ``(BuildContext, USR)`` instance
``instance_validation`` run the shared scan-level validation queue once
``instance_checkpoint`` project the instance report and persist the completion
                        record (data only; no saved command is ever executed)

All three share one :class:`~zscope.orchestration.parallel_analyzer.InstanceWorkBatch`,
so the candidate ledger, decision-fact cache, validation result cache and
cross-instance dedup survive every work item.  The queue itself is the resume
mechanism: on the same input revision completed identities are never reclaimed,
and a real input change re-pends every verdict.
"""

from __future__ import annotations

import hashlib
from contextlib import nullcontext
import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from ...semantics.instance_semantics import InstanceSemanticsSnapshot
    from .instance_results import RecoveryIdentity, TrustedInstanceResultReceipt

from ...common.cancellation import CancellationError
from ...common.validator_protocol import VALIDATION_POLICY_VERSION
from ..candidate_envelope import CANDIDATE_SCHEMA_VERSION
from ..entry_instances import ENTRY_INSTANCE_SCHEMA
from ..parallel_analyzer import InstanceWorkBatch, ParallelAnalyzer
from .session_scheduler import ClaimedWork, HandlerOutcome, WorkComplete, WorkDefer
from .store import JobStore, InstanceCompletionRequest, InstanceSettlementAck

logger = logging.getLogger(__name__)

WORK_KIND_INSTANCE = "instance_analysis"
WORK_KIND_VALIDATION = "instance_validation"
WORK_KIND_CHECKPOINT = "instance_checkpoint"

CHECKPOINT_SCHEMA = "zscope.scan-session-instance-checkpoint.v1"
CHECKPOINT_FILENAME = "instance-checkpoint.json"
CHECKPOINT_RECEIPT_KIND = "instance_checkpoint_persisted"
PLAN_FINGERPRINT_SCHEMA = "zscope.instance-plan-fingerprint.v2"

_STOP_REASON_PREFIX = "session_stop:"

__all__ = [
    "WORK_KIND_INSTANCE",
    "WORK_KIND_VALIDATION",
    "WORK_KIND_CHECKPOINT",
    "CHECKPOINT_SCHEMA",
    "CHECKPOINT_FILENAME",
    "CHECKPOINT_RECEIPT_KIND",
    "PLAN_FINGERPRINT_SCHEMA",
    "instance_work_items",
    "validation_work_item",
    "checkpoint_work_item",
    "compute_plan_fingerprint",
    "instance_versions",
    "registry_fingerprint",
    "carries_confirmation_authority",
    "InstanceWorkHandlers",
    "persist_checkpoint",
    "verify_bound_checkpoint",
]


def instance_versions() -> Dict[str, str]:
    """The verifiable schema/policy versions an instance completion commits to."""

    from ..candidate_envelope import DECISION_CONTEXT_VERSION
    from ..candidates import PENDING_WIRE_ADAPTER_VERSION
    from .instance_results import RECOVERY_POLICY_VERSION, VERSION_KEY_CANDIDATE_DECISION_CONTEXT

    return {
        "entry_instances": ENTRY_INSTANCE_SCHEMA,
        "instance_analysis": "zscope.instance-analysis.v1",
        "candidate_schema": CANDIDATE_SCHEMA_VERSION,
        VERSION_KEY_CANDIDATE_DECISION_CONTEXT: DECISION_CONTEXT_VERSION,
        "instance_recovery": RECOVERY_POLICY_VERSION,
        "pending_wire_adapter": PENDING_WIRE_ADAPTER_VERSION,
        "validation_policy": VALIDATION_POLICY_VERSION,
        "snapshot_candidate_policy": _snapshot_candidate_policy_version(),
    }


def registry_fingerprint() -> Optional[Dict[str, str]]:
    """The verifiable contract-compiler / default-registry dependency, or ``None``.

    The instance path consumes only the generator's standard (default) roots, so
    its real semantic dependency is the current contract compiler version and
    the current content of the default contract registry — not a fixed label.
    Anything unreadable yields ``None`` so the caller treats the dependency as
    unverifiable and refuses to reuse a completion.
    """

    from ...semantics import contracts, standard_api

    compiler = str(getattr(contracts, "CONTRACT_COMPILER_VERSION", "") or "")
    api_version = str(getattr(standard_api, "STANDARD_API_VERSION", "") or "")
    try:
        standard = standard_api.standard_contracts()
    except Exception:
        return None
    if not compiler or not api_version or not isinstance(standard, list) or not standard:
        return None
    return {
        "contract_compiler": compiler,
        "standard_api": api_version,
        "standard_contracts_sha256": hashlib.sha256(
            _canonical_json(standard).encode("utf-8")
        ).hexdigest(),
    }


_CONFIRMATION_KEYS = frozenset(
    {
        "candidate_disposition",
        "validation_status",
        "finding_status",
        "finding_kind",
        "deterministic_prevalidation_decision",
    }
)
_CONFIRMING_VALUES = frozenset({"confirmed", "validated", "verified", "verified_vulnerability"})


def carries_confirmation_authority(value: Any) -> bool:
    """True when serialized content claims confirmation/validation/proof authority.

    Restoring a report/candidate from disk must never hand a *current* consumer
    a confirmed finding or a decision proof: such authority can only come from
    this run's native/Registry/Validator adjudication.  Any such marker makes
    the bound completion unusable, so the scan runs the current chain instead.
    """

    if isinstance(value, dict):
        for key, item in value.items():
            if key == "decision_proof" and item:
                return True
            if key in _CONFIRMATION_KEYS and isinstance(item, str):
                if item.strip().lower() in _CONFIRMING_VALUES:
                    return True
            if carries_confirmation_authority(item):
                return True
        return False
    if isinstance(value, list):
        return any(carries_confirmation_authority(item) for item in value)
    return False


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _readonly_sqlite_uri(path: Path) -> str:
    """A true read-only SQLite URI that preserves the exact file identity.

    The path is resolved and percent-encoded via :meth:`Path.as_uri`, so
    characters like ``#``, ``?`` or spaces cannot be reinterpreted as the
    URI's query/fragment separators (a hand-built ``file:{path}?mode=ro``
    lets a ``#`` swallow the query, making SQLite open — and create — a
    truncated read-write path).  ``mode=ro`` guarantees the file is never
    created or modified by this lookup.
    """

    return path.resolve().as_uri() + "?mode=ro"


def _business_answers_digest(config: Any) -> Optional[str]:
    """Digest the project's recorded business answers, or ``None`` if unverifiable.

    Answers live in the project user-config state database, located exactly
    the way the product derives its :class:`UserConfigStore` (an ``.xlsx``
    workbook path or a directory holding ``user_config.state.db``).  Only the
    *answer history* is read (never the analyzer-written baselines, which
    change during every scan), through a read-only connection that never
    initializes or repairs anything.

    A first run with no store file yet, or a verified empty answer table,
    legitimately digests to the empty value.  A store that exists but cannot
    be verified — corrupt database, unknown/missing schema column, read
    error, unopenable path — yields ``None`` so the caller treats the
    dependency as unverifiable instead of reusing a completion whose premise
    it cannot re-establish.
    """

    analysis = getattr(config, "analysis", None)
    raw = getattr(analysis, "user_config_db", None) or getattr(analysis, "snapshot_dir", None)
    if not raw:
        return None
    path = Path(str(raw))
    if path.suffix.lower() == ".xlsx":
        path = path.with_suffix(".state.db")
    elif path.is_dir() or not path.suffix:
        path = path / "user_config.state.db"
    if not path.is_file():
        # No recorded answers yet: identical to a verified empty history.
        # This read-only path never creates or initializes the store.
        return hashlib.sha256().hexdigest()
    try:
        connection = sqlite3.connect(_readonly_sqlite_uri(path), uri=True)
    except sqlite3.Error:
        return None
    try:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT subject_key, revision, answer, origin, source_note "
            "FROM protocol_assumption_answers ORDER BY subject_key, revision"
        ).fetchall()
    except sqlite3.Error:
        # The store exists but its answer history cannot be verified —
        # a corrupt database, an unknown schema or a failed read is a
        # miss, never an assumed empty answer history.
        return None
    finally:
        connection.close()
    digest = hashlib.sha256()
    for row in rows:
        digest.update(
            _canonical_json(
                {
                    "subject_key": str(row["subject_key"]),
                    "revision": int(row["revision"]),
                    "answer": str(row["answer"]),
                    "origin": str(row["origin"]),
                    "source_note": str(row["source_note"]),
                }
            ).encode("utf-8")
        )
    return digest.hexdigest()


def _file_digest(path: Path) -> Optional[str]:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def compute_plan_fingerprint(
    plan: Any,
    config: Any,
    *,
    semantics_by_instance: Mapping[str, "InstanceSemanticsSnapshot"],
) -> Optional[str]:
    """A deterministic fingerprint of the exact current instance plan.

    Covers the precise ``(identity, build_context_id, usr, source)`` instance
    set, the entry coordinates, the candidate/validation/entry-instance/
    instance-analysis/snapshot-policy versions, the instance semantics marker,
    the enabled rule ids, and the verifiable semantic/feedback dependencies
    (the user-authored semantic workbook and the recorded business answers).
    Any dependency that cannot be verified yields ``None`` so the caller never
    reuses a completion whose premise it cannot re-establish.
    """

    instances = list(getattr(plan, "instances", []) or [])
    if not instances:
        return None
    from ..instance_semantics_context import SEMANTICS_POLICY, semantics_manifest_digest
    from ...retrieval.instance_index import instance_scope_from_entry_instance

    scopes = [instance_scope_from_entry_instance(instance) for instance in instances]
    if len({scope.identity for scope in scopes}) != len(scopes):
        return None
    if set(semantics_by_instance) != {scope.identity for scope in scopes}:
        return None
    for scope in scopes:
        snapshot = semantics_by_instance[scope.identity]
        if (
            snapshot.scope != scope
            or snapshot.authority_policy != SEMANTICS_POLICY
            or snapshot.schema != "zscope.instance-semantics.v1"
            or not snapshot.digest
        ):
            return None
    entries = sorted(
        {
            str(getattr(instance, "source", "") or "") + "::" + name
            for instance in instances
            for name in (getattr(instance, "function_names", ()) or ())
        }
    )
    project = getattr(config, "project", None)
    workbook_digest: Optional[str] = None
    workbook_path = getattr(project, "user_config_file", None)
    if workbook_path:
        workbook_digest = _file_digest(Path(str(workbook_path)))
        if workbook_digest is None:
            return None
    answers = _business_answers_digest(config)
    if answers is None:
        return None
    registry = registry_fingerprint()
    if registry is None:
        return None
    rules = getattr(config, "rules", None)
    rule_ids = sorted(str(value) for value in (getattr(rules, "enabled_ids", None) or []))
    disabled_ids = sorted(str(value) for value in (getattr(rules, "disabled_ids", None) or []))
    payload = {
        "schema": PLAN_FINGERPRINT_SCHEMA,
        **instance_versions(),
        "instance_semantics": SEMANTICS_POLICY,
        "instance_semantics_manifest": semantics_manifest_digest(semantics_by_instance),
        "registry": registry,
        "language": str(getattr(project, "language", "") or ""),
        "project_root": str(getattr(project, "project_root", "") or ""),
        "source_root": str(getattr(project, "source_root", "") or ""),
        "rule_ids": rule_ids,
        "disabled_rule_ids": disabled_ids,
        "workbook_sha256": workbook_digest,
        "business_answers_sha256": answers,
        "entries": entries,
        "instances": sorted(
            (
                str(getattr(instance, "identity", "") or ""),
                str(getattr(instance, "build_context_id", "") or ""),
                str(getattr(instance, "usr", "") or ""),
                str(getattr(instance, "source", "") or ""),
            )
            for instance in instances
        ),
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _snapshot_candidate_policy_version() -> str:
    from ...snapshots.policy import SNAPSHOT_CANDIDATE_POLICY_VERSION

    return str(SNAPSHOT_CANDIDATE_POLICY_VERSION)


def current_recovery_identity(
    *,
    analyzer: ParallelAnalyzer,
    job_id: str,
    input_revision: str,
    plan_fingerprint: str,
) -> "RecoveryIdentity":
    """Bind data reuse to the complete current semantic and policy inputs."""
    from dataclasses import asdict
    from .instance_results import RecoveryIdentity
    from ..instance_semantics_context import canonical_bytes, SEMANTICS_POLICY

    analyzer.require_current_instance_inputs()
    context = analyzer._instance_semantics_context
    registry = registry_fingerprint()
    if context is None or registry is None or not all((job_id, input_revision, plan_fingerprint)):
        raise ValueError("instance_recovery_dependencies_unverifiable")
    dependency = {
        "semantics_dependencies": asdict(context.dependencies),
        "workbook_sha256": context.workbook.workbook_sha256,
        "scopes": [scope.to_payload() for _identity, scope in sorted(context.scopes.items())],
    }
    return RecoveryIdentity(
        job_id=job_id,
        input_revision=input_revision,
        plan_fingerprint=plan_fingerprint,
        versions=tuple(sorted(instance_versions().items())),
        registry_digest=hashlib.sha256(canonical_bytes(registry)).hexdigest(),
        semantics_policy=SEMANTICS_POLICY,
        semantics_digest=context.manifest_digest(),
        dependency_digest=hashlib.sha256(canonical_bytes(dependency)).hexdigest(),
    )


def _instance_payload(instance: Any) -> Dict[str, Any]:
    return {
        "identity": str(getattr(instance, "identity", "") or ""),
        "usr": str(getattr(instance, "usr", "") or ""),
        "source": str(getattr(instance, "source", "") or ""),
        "function_names": [str(name) for name in (getattr(instance, "function_names", ()) or ())],
    }


def instance_work_items(plan: Any) -> List[Dict[str, Any]]:
    """One work item per scheduled compile instance."""

    items: List[Dict[str, Any]] = []
    for instance in list(getattr(plan, "instances", []) or []):
        identity = str(getattr(instance, "identity", "") or "")
        if not identity:
            continue
        items.append(
            {
                "kind": WORK_KIND_INSTANCE,
                "scope_key": identity,
                "build": str(getattr(instance, "build_context_id", "") or "") or None,
                "payload": _instance_payload(instance),
            }
        )
    return items


def validation_work_item(*, identities: List[str]) -> Dict[str, Any]:
    """The single scan-level validation item, keyed to the analyzed set."""

    return {
        "kind": WORK_KIND_VALIDATION,
        "scope_key": "scan-validation",
        "build": None,
        "payload": {"identities": sorted(str(value) for value in identities)},
    }


def checkpoint_work_item() -> Dict[str, Any]:
    return {
        "kind": WORK_KIND_CHECKPOINT,
        "scope_key": "scan-checkpoint",
        "build": None,
        "payload": {},
    }


def persist_checkpoint(
    run_dir: Path | str,
    payload: Dict[str, Any],
    *,
    store_path: Optional[Path | str] = None,
    job_id: str = "",
    run_id: str = "",
    owner_token: str = "",
    input_revision: str = "",
    plan_fingerprint: str = "",
    input_current_guard: Optional[Callable[[], None]] = None,
    runtime_outputs: Optional[Any] = None,
) -> Optional[Path]:
    """Publish the immutable completion file and its bound SQL receipt.

    The file lives inside the *producer's own run directory* under a
    run-independent name, is published atomically, and is co-signed by
    ``append_bound_event``: the store re-checks the current job/run/owner/input
    binding inside the same transaction that records the receipt, so a receipt
    can never outlive the attempt that produced it.  Any failure leaves the
    checkpoint unpublished (the caller keeps the item unresolved).
    """

    if (
        not job_id
        or not run_id
        or not owner_token
        or not input_revision
        or store_path is None
        or not plan_fingerprint
    ):
        return None
    from ...retrieval.code_index import _JobRuntimeOutputs

    if runtime_outputs is not None and (
        not isinstance(runtime_outputs, _JobRuntimeOutputs)
        or runtime_outputs._store_path != Path(store_path)
        or runtime_outputs._job_id != job_id
        or runtime_outputs._run_id != run_id
        or runtime_outputs._owner_token != owner_token
        or runtime_outputs._run_dir != Path(run_dir)
        or runtime_outputs.input_revision != input_revision
    ):
        return None
    target = Path(run_dir) / CHECKPOINT_FILENAME
    tmp = target.with_name(target.name + ".tmp")
    try:
        with JobStore(store_path).bound_attempt(
            job_id=job_id,
            run_id=run_id,
            owner_token=owner_token,
            expected_input_revision=input_revision,
        ) as job:
            if job.get("run_dir") != str(Path(run_dir)) or Path(run_dir).resolve() != Path(run_dir):
                return None
            if input_current_guard is not None:
                input_current_guard()
            fence = (
                runtime_outputs.writer()
                if isinstance(runtime_outputs, _JobRuntimeOutputs)
                else nullcontext()
            )
            with fence:
                target.parent.mkdir(parents=True, exist_ok=True)
                tmp.write_text(
                    json.dumps(
                        {"schema": CHECKPOINT_SCHEMA, **payload}, indent=2, ensure_ascii=False
                    ),
                    encoding="utf-8",
                )
                os.replace(tmp, target)
                digest = hashlib.sha256(target.read_bytes()).hexdigest()
            if input_current_guard is not None:
                input_current_guard()
    except OSError:
        return None
    try:
        JobStore(store_path).append_bound_event(
            str(job_id),
            run_id=str(run_id),
            owner_token=str(owner_token),
            kind=CHECKPOINT_RECEIPT_KIND,
            message="instance checkpoint persisted",
            data={
                "plan_fingerprint": str(plan_fingerprint),
                "checkpoint_sha256": digest,
                "checkpoint_path": str(target),
                "input_revision": str(input_revision or ""),
            },
            expected_input_revision=str(input_revision or "") or None,
            input_current_guard=input_current_guard,
        )
    except Exception:
        logger.warning("bound checkpoint receipt was not published", exc_info=True)
        return None
    return target


def verify_bound_checkpoint(
    receipt: Mapping[str, Any],
    *,
    plan: Any,
    input_revision: str,
) -> Optional[Dict[str, Any]]:
    """Verify a trusted completion receipt's immutable file and coordinates.

    ``receipt`` comes from ``JobStore.trusted_completion`` — a real bound SQL
    receipt for this job/input/exact-plan, possibly from an earlier run.  It
    proves coordinates only, so the file is re-read here: its bytes must match
    the recorded digest, and its JSON must name the same job, the receipt's
    producer run, the same input revision and plan fingerprint, and exactly the
    current scheduled instances.  The receipt alone never authorizes a skip.
    """

    data = receipt.get("data")
    if not isinstance(data, Mapping):
        return None
    raw_path = data.get("checkpoint_path")
    digest = data.get("checkpoint_sha256")
    if not isinstance(raw_path, str) or not isinstance(digest, str):
        return None
    try:
        raw = Path(raw_path).read_bytes()
    except OSError:
        return None
    if hashlib.sha256(raw).hexdigest() != digest:
        return None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("schema") != CHECKPOINT_SCHEMA:
        return None
    if payload.get("versions") != instance_versions():
        return None
    registry = registry_fingerprint()
    if registry is None or payload.get("registry") != registry:
        return None
    if str(payload.get("job_id") or "") != str(receipt.get("job_id") or ""):
        return None
    if str(payload.get("run_id") or "") != str(receipt.get("run_id") or ""):
        return None
    if str(payload.get("plan_fingerprint") or "") != str(receipt.get("plan_fingerprint") or ""):
        return None
    if str(payload.get("input_revision") or "") != str(input_revision or ""):
        return None
    if not isinstance(payload.get("report"), dict):
        return None
    analysis = payload.get("instance_analysis")
    if not isinstance(analysis, dict):
        return None
    if str(analysis.get("status") or "") != "analyzed":
        return None
    covered = {
        str(item.get("identity") or "")
        for item in (analysis.get("instances") or [])
        if isinstance(item, dict)
    }
    wanted = {
        str(getattr(instance, "identity", "") or "")
        for instance in (getattr(plan, "instances", []) or [])
    }
    if not wanted or covered != wanted:
        return None
    if carries_confirmation_authority(analysis) or carries_confirmation_authority(
        payload.get("report")
    ):
        # Serialized confirmation/validation/proof is not current adjudication:
        # this completion cannot authorize a current confirmed finding.
        return None
    return payload


class InstanceWorkHandlers:
    """Real handlers over one shared :class:`InstanceWorkBatch`.

    ``analyzer`` is the session's ``ParallelAnalyzer``; the batch is opened
    lazily on the first analysis item so the handler construction stays cheap
    for an empty plan.  ``run_dir`` is this attempt's own run directory: the
    immutable completion file lives there and is co-signed by a bound job-store
    receipt for ``job_id``/``run_id``/``owner_token``, so only a genuine
    completion of a current attempt can ever be honoured.
    """

    def __init__(
        self,
        *,
        plan: Any,
        analyzer: ParallelAnalyzer,
        run_dir: Path | str,
        input_revision: str,
        store_path: Optional[Path | str] = None,
        job_id: str = "",
        run_id: str = "",
        owner_token: str = "",
        plan_fingerprint: str = "",
        hook: Any = None,
        snapshot_fn: Optional[Callable[[], Dict[str, Any]]] = None,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.plan = plan
        self.analyzer = analyzer
        self.run_dir = Path(run_dir)
        self.input_revision = str(input_revision or "")
        self.store_path = Path(store_path) if store_path is not None else None
        self.job_id = str(job_id or "")
        self.run_id = str(run_id or "")
        self.owner_token = str(owner_token or "")
        self.plan_fingerprint = str(plan_fingerprint or "")
        self.hook = hook
        self._snapshot_fn = snapshot_fn
        self._now = now_fn
        self._batch: Optional[InstanceWorkBatch] = None
        self._expected = len(instance_work_items(plan))
        self._analyzed = 0
        self._validated = False
        self._report_payload: Optional[Dict[str, Any]] = None
        self._combined_report: Optional[Dict[str, Any]] = None
        self._checkpoint_path: Optional[Path] = None
        self._analysis_error: Optional[str] = None
        self._stopped_reason: str = ""
        self._recovery: Optional["RecoveryIdentity"] = None
        self._pending_instance_completions: Dict[str, InstanceCompletionRequest] = {}
        self._restored_run_ids: Dict[str, str] = {}
        self._closed_recovery_summary: Optional[Dict[str, Any]] = None

    # -- public -------------------------------------------------------------

    def handlers(self) -> Dict[str, Callable[[ClaimedWork], HandlerOutcome]]:
        return {
            WORK_KIND_INSTANCE: self.handle_instance_analysis,
            WORK_KIND_VALIDATION: self.handle_validation,
            WORK_KIND_CHECKPOINT: self.handle_checkpoint,
        }

    @property
    def report_payload(self) -> Optional[Dict[str, Any]]:
        return self._report_payload

    @property
    def checkpoint_path(self) -> Optional[Path]:
        return self._checkpoint_path

    @property
    def analysis_error(self) -> Optional[str]:
        return self._analysis_error

    @property
    def recovery_summary(self) -> Dict[str, Any]:
        batch = self._batch
        if batch is None and self._closed_recovery_summary is not None:
            closed_summary = json.loads(json.dumps(self._closed_recovery_summary))
            if not isinstance(closed_summary, dict):
                raise ValueError("instance_recovery_summary_not_mapping")
            return closed_summary
        restored = sorted(batch.restored_instances) if batch is not None else []
        executed = sorted(batch.executed_instances) if batch is not None else []
        analyzed = sorted(batch.settled_instances) if batch is not None else []
        return {
            "planned_instances": self._expected,
            "restored_instances": len(restored),
            "executed_instances": len(executed),
            "analyzed_instances": len(analyzed),
            "restored_identities": restored,
            "executed_identities": executed,
            "analyzed_identities": analyzed,
            "restored_from_run_ids": sorted(set(self._restored_run_ids.values())),
            "restored_instance_runs": dict(sorted(self._restored_run_ids.items())),
            "current_validation_state": (
                batch.validation_state if batch is not None else "NOT_STARTED"
            ),
        }

    def release(self) -> None:
        """Release an open batch that never reached its checkpoint."""

        batch = self._batch
        self._closed_recovery_summary = self.recovery_summary
        self._batch = None
        if batch is None:
            return
        try:
            self.analyzer.abandon_instance_batch(batch)
        except Exception:
            logger.warning("could not release the stopped instance batch", exc_info=True)

    # -- handlers -----------------------------------------------------------

    def handle_instance_analysis(self, work: ClaimedWork) -> HandlerOutcome:
        stopped = self._stop_reason(work)
        if stopped:
            return WorkDefer(reason=f"{_STOP_REASON_PREFIX}{stopped}")
        try:
            batch = self._ensure_batch()
            self._note_phase("analyzing_instances")
            self._require_current_recovery()
            request = self._pending_instance_completions.get(work.scope_key)
            if request is None:
                request = self._prepare_instance_completion(batch, work.scope_key)
                self._pending_instance_completions[work.scope_key] = request
        except CancellationError as exc:
            # A window/cancel that reached the real analyzer is a stop, not a
            # verdict: the item stays unresolved instead of being completed.
            return WorkDefer(reason=f"{_STOP_REASON_PREFIX}{exc}")
        except Exception as exc:  # a real failure stays a bounded deferral
            self._analysis_error = f"{type(exc).__name__}: {exc}"
            return WorkDefer(reason=f"instance_analysis_error:{self._analysis_error}")
        stopped = self._stop_reason(work)
        if stopped:
            return WorkDefer(reason=f"{_STOP_REASON_PREFIX}{stopped}")
        discoveries: List[Dict[str, Any]] = []
        if self._remaining_planned_instances(work.scope_key) == 0:
            discoveries.append(
                validation_work_item(
                    identities=[
                        scope.identity
                        for _entry, scope in self._require_batch().scoped_entries
                        if scope is not None
                    ]
                )
            )
        return WorkComplete(
            detail={
                "identity": work.scope_key,
                "settled_instances_before_ack": self._analyzed,
                "mode": request.mode,
            },
            discoveries=discoveries,
            instance_completion=request,
        )

    def _require_current_recovery(self) -> None:
        actual = current_recovery_identity(
            analyzer=self.analyzer,
            job_id=self.job_id,
            input_revision=self.input_revision,
            plan_fingerprint=self.plan_fingerprint,
        )
        if self._recovery is None:
            self._recovery = actual
        elif actual != self._recovery:
            raise ValueError("instance_recovery_identity_no_longer_current")

    def _prepare_instance_completion(
        self, batch: InstanceWorkBatch, identity: str
    ) -> InstanceCompletionRequest:
        from .instance_results import (
            CurrentAttempt,
            ExpectedInstance,
            InstanceKey,
            PreparedInstanceResult,
            RecoveryAccepted,
            RecoveryMiss,
            prepare_instance_result,
            verify_instance_result,
        )

        self._require_current_recovery()
        assert self._recovery is not None
        instance = next(item for item in batch.instances if item.identity == identity)
        key = InstanceKey(
            instance.identity, instance.build_context_id, instance.usr, instance.source
        )
        context = self.analyzer._instance_semantics_context
        if context is None or self.store_path is None:
            raise ValueError("instance_result_bound_context_missing")
        semantics = context.require(context.scopes[identity])
        current = CurrentAttempt(
            self.job_id, self.run_id, self.owner_token, self.input_revision, self.run_dir
        )
        expected_instance = ExpectedInstance(key, semantics.digest)
        trusted = JobStore(self.store_path).trusted_instance_results(
            current=current,
            expected=self._recovery,
            instances=(expected_instance,),
        )
        for receipt in trusted:
            admitted = verify_instance_result(
                receipt, expected=self._recovery, instance=expected_instance
            )
            if not isinstance(admitted, RecoveryAccepted):
                continue
            try:
                self.analyzer.restore_instance_result(batch, admitted=admitted)
            except (ValueError, TypeError, KeyError):
                # The complete target instance remains untouched on a late
                # projection conflict; execute that instance in this run.
                continue
            self._require_current_recovery()
            return InstanceCompletionRequest(
                current=current,
                expected=self._recovery,
                instance=key,
                semantics_digest=semantics.digest,
                mode="restored",
                prepared=None,
                restored_receipt=receipt,
                input_current_guard=self._require_current_recovery,
                accept_settlement=self.accept_instance_settlement,
            )
        self.analyzer.run_instance_batch(batch, [identity])
        self.analyzer.require_instance_collection_closed(batch, identity=identity)
        exported = self.analyzer.export_instance_result(
            batch,
            identity=identity,
            recovery=self._recovery,
            producer_run_id=self.run_id,
        )
        prepared: Optional[PreparedInstanceResult] = None
        if not isinstance(exported, RecoveryMiss):
            from ...retrieval.code_index import _JobRuntimeOutputs

            runtime_outputs = getattr(context.code_index, "_job_runtime_outputs", None)
            if isinstance(runtime_outputs, _JobRuntimeOutputs):
                encoded = runtime_outputs.prepare_result(exported)
            else:
                with JobStore(self.store_path).bound_attempt(
                    job_id=self.job_id,
                    run_id=self.run_id,
                    owner_token=self.owner_token,
                    expected_input_revision=self.input_revision,
                ) as job:
                    if job.get("run_dir") != str(self.run_dir):
                        raise ValueError("instance_result_physical_run_directory_mismatch")
                    self._require_current_recovery()
                    encoded = prepare_instance_result(exported, producer_run_dir=self.run_dir)
                    self._require_current_recovery()
            if isinstance(encoded, PreparedInstanceResult):
                prepared = encoded
        self._require_current_recovery()
        return InstanceCompletionRequest(
            current=current,
            expected=self._recovery,
            instance=key,
            semantics_digest=semantics.digest,
            mode="executed",
            prepared=prepared,
            restored_receipt=None,
            input_current_guard=self._require_current_recovery,
            accept_settlement=self.accept_instance_settlement,
        )

    def accept_instance_settlement(self, ack: InstanceSettlementAck) -> None:
        """Only the scheduler's committed queue acknowledgement changes P/R/E."""
        batch = self._require_batch()
        with batch.admission_lock:
            request = self._pending_instance_completions.get(ack.identity)
            if (
                ack.committed is not True
                or ack.mode not in {"restored", "executed"}
                or request is None
                or request.mode != ack.mode
            ):
                raise ValueError("instance_settlement_ack_mismatch")
            if ack.mode == "restored" and request.restored_receipt is None:
                raise ValueError("instance_restored_ack_receipt_missing")
            chosen = (
                batch.restored_instances if ack.mode == "restored" else batch.executed_instances
            )
            other = batch.executed_instances if ack.mode == "restored" else batch.restored_instances
            if ack.identity in other:
                raise ValueError("instance_settlement_modes_overlap")
            chosen.add(ack.identity)
            if ack.mode == "restored":
                assert request.restored_receipt is not None
                self._restored_run_ids[ack.identity] = request.restored_receipt.producer_run_id
            batch.settled_instances.add(ack.identity)
            if batch.settled_instances != batch.restored_instances | batch.executed_instances:
                raise ValueError("instance_settlement_partition_invalid")
            self._analyzed = len(batch.settled_instances)

    def _stop_reason(self, work: ClaimedWork) -> str:
        """A real stop signalled on the claimed item or the shared analyzer."""

        if work.cancellation.is_cancelled():
            return work.cancellation.reason or "cancelled"
        token = self.analyzer.cancellation_token
        if token is not None and token.is_cancelled():
            return token.reason or "cancelled"
        return ""

    def _remaining_planned_instances(self, current_identity: str) -> int:
        """The frozen plan minus acknowledged P and this uncommitted claim.

        This route has no dynamic instance discovery. P is updated solely
        after a real settlement acknowledgement, so a missing/truncated queue
        snapshot cannot lose the final validation child or invent completion.
        """
        batch = self._require_batch()
        with batch.admission_lock:
            planned = {instance.identity for instance in batch.instances}
            if current_identity not in planned or not batch.settled_instances <= planned:
                raise ValueError("instance_completion_not_in_frozen_plan")
            return len(planned - batch.settled_instances - {current_identity})

    def handle_validation(self, work: ClaimedWork) -> HandlerOutcome:
        stopped = self._stop_reason(work)
        if stopped:
            return WorkDefer(reason=f"{_STOP_REASON_PREFIX}{stopped}")
        batch = self._ensure_batch()
        self._note_phase("validating_instances")
        try:
            wanted = {item.identity for item in batch.instances}
            if (
                batch.settled_instances != wanted
                or batch.restored_instances & batch.executed_instances
            ):
                raise ValueError("instance_validation_analysis_set_incomplete")
            self.analyzer.require_current_instance_inputs()
            self.analyzer.validate_instance_batch(batch)
        except CancellationError as exc:
            return WorkDefer(reason=f"{_STOP_REASON_PREFIX}{exc}")
        except Exception as exc:
            self._analysis_error = f"{type(exc).__name__}: {exc}"
            return WorkDefer(reason=f"instance_validation_error:{self._analysis_error}")
        self._validated = True
        return WorkComplete(detail={"validated": True}, discoveries=[checkpoint_work_item()])

    def handle_checkpoint(self, work: ClaimedWork) -> HandlerOutcome:
        stopped = self._stop_reason(work)
        if stopped:
            return WorkDefer(reason=f"{_STOP_REASON_PREFIX}{stopped}")
        batch = self._ensure_batch()
        if batch.validation_state != "DONE":
            return WorkDefer(reason="checkpoint_current_validation_not_done")
        self.analyzer.require_current_instance_inputs()
        report = self.analyzer.finish_instance_batch(batch)
        payload = report.to_payload()
        payload["instance_recovery"] = self.recovery_summary
        self._report_payload = payload
        self._note_phase("checkpointing")
        results = self.analyzer.last_instance_results()
        combined = self.analyzer.generate_combined_report(results, None)
        self._combined_report = combined
        from ...retrieval.code_index import _JobRuntimeOutputs

        runtime_outputs = getattr(self.analyzer.code_index, "_job_runtime_outputs", None)
        fence = (
            runtime_outputs.writer()
            if isinstance(runtime_outputs, _JobRuntimeOutputs)
            else nullcontext()
        )
        with fence:
            markdown = self.analyzer.generate_combined_markdown_report(
                results, self.run_dir / "instance-report.md"
            )
        registry = registry_fingerprint()
        if registry is None:
            # Without a verifiable contract/registry dependency the completion
            # cannot authorize a later reuse.
            return WorkDefer(reason="checkpoint_registry_unverifiable")
        self._checkpoint_path = persist_checkpoint(
            self.run_dir,
            {
                "job_id": self.job_id,
                "run_id": self.run_id,
                "input_revision": self.input_revision,
                "plan_fingerprint": self.plan_fingerprint,
                "versions": instance_versions(),
                "registry": registry,
                "analyzed_instances": payload.get("analyzed_instances"),
                "instance_scope_complete": payload.get("instance_scope_complete"),
                "scan_coverage_complete": payload.get("scan_coverage_complete"),
                "checkpointed_at": self._now(),
                # The coverage payload is projected from the verified ledger; the
                # combined report is captured verbatim so a later run of the same
                # exact plan reproduces the findings without re-analyzing them.
                "instance_analysis": payload,
                "markdown": markdown,
                "report": combined,
            },
            store_path=self.store_path,
            job_id=self.job_id,
            run_id=self.run_id,
            owner_token=self.owner_token,
            input_revision=self.input_revision,
            plan_fingerprint=self.plan_fingerprint,
            input_current_guard=self._require_current_recovery,
            runtime_outputs=runtime_outputs,
        )
        detail = {
            "analyzed_instances": payload.get("analyzed_instances"),
            "checkpoint": str(self._checkpoint_path) if self._checkpoint_path else None,
        }
        if self._checkpoint_path is None:
            # The checkpoint record is the completion evidence; without it the
            # item stays unresolved instead of pretending the run finished.
            return WorkDefer(reason="checkpoint_not_persisted")
        return WorkComplete(detail=detail)

    # -- internals ----------------------------------------------------------

    def _ensure_batch(self) -> InstanceWorkBatch:
        if self._batch is None:
            self._batch = self.analyzer.open_instance_batch(self.plan)
        return self._batch

    def _require_batch(self) -> InstanceWorkBatch:
        return self._ensure_batch()

    def _note_phase(self, phase: str) -> None:
        note = getattr(self.hook, "note_phase", None)
        if callable(note):
            note(phase)
