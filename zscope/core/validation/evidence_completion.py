"""Bounded deterministic evidence-completion for unresolved validation groups."""

from __future__ import annotations

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, cast

from .evidence import normalize_missing_fact_kinds
from .execution_context import current_execution_context, rebound_execution_context
from .proofs import deterministic_decision_proof

IssueFactProvider = Callable[[Mapping[str, Any]], Optional[Dict[str, Any]]]
EvidenceFactProvider = Callable[
    [Mapping[str, Any], Optional[Mapping[str, Any]]],
    Optional[Dict[str, Any]],
]


SUPPORTED_FACT_KINDS = frozenset(
    {
        "guard_dominance",
        "caller_contract",
        "source_controllability",
        "ownership_transfer",
        "cleanup_coverage",
        "lockset",
        "happens_before",
        "object_identity",
        "value_range",
        "source_sink_reachability",
        "signal_context",
        "container_reachability",
        "type_layout",
    }
)


def _as_mapping(value: Any) -> Mapping[str, Any]:
    """Narrow structured evidence while keeping the original mapping."""
    return cast(Mapping[str, Any], value) if isinstance(value, Mapping) else {}


def _as_list(value: Any) -> list[Any]:
    """Narrow repeated list-valued evidence fields for static checking."""
    return cast(list[Any], value) if isinstance(value, list) else []


@dataclass(frozen=True)
class EvidenceCompletionRequest:
    validation_cluster_uid: str
    missing_fact: str
    reason: str


@dataclass(frozen=True)
class EvidenceResolution:
    """Result of the single typed FACT_RESOLUTION transition."""

    request: EvidenceCompletionRequest
    status: str
    fact_kind: str
    evidence_delta: Dict[str, Any]
    evidence_delta_hash: str
    proof_added: bool = False


@dataclass(frozen=True)
class EvidenceResolutionBatch:
    """All deterministic fact work required by one security obligation."""

    resolutions: tuple[EvidenceResolution, ...]
    evidence_delta: Dict[str, Any]
    evidence_delta_hash: str
    proof_added: bool

    @property
    def has_evidence_delta(self) -> bool:
        return bool(self.evidence_delta_hash and self.evidence_delta)


class EvidenceCompletionQueue:
    """Promote already-collected deterministic facts before asking for review.

    This deliberately does not ask an LLM to manufacture proof.  Backends may
    attach ``evidence_completion_proofs`` while gathering facts; a candidate is
    re-evaluated at most once after those facts are promoted into the stable
    deterministic-proof interface.  The queue also runs a bounded set of local
    providers.  A normal scan always closes the request as either ``completed``
    or ``exhausted``: ``requested`` is not a terminal state and must never leak
    into a completed report.
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        max_workers: int = 2,
        enable_v11_providers: bool = True,
        enable_v12_providers: bool = False,
        fact_timeout_seconds: float = 5.0,
    ) -> None:
        self.enabled = bool(enabled)
        self.max_workers = max(1, int(max_workers or 2))
        self.fact_timeout_seconds = max(0.001, float(fact_timeout_seconds))
        self._fact_provider_executor = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="zscope-fact-provider",
        )
        # v1.1 providers are independently switchable while their transition
        # audit is running.  Existing v3 providers remain available so a
        # disabled rollout cannot change prior evidence semantics.
        self.enable_v11_providers = bool(enable_v11_providers)
        self.enable_v12_providers = bool(enable_v12_providers)

    def resolve_requested_fact(
        self,
        issue: Dict[str, Any],
        *,
        validator_data: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]] = None,
    ) -> Optional[EvidenceResolution]:
        """Resolve exactly the fact kind named by an uncertain v3 result.

        Providers are selected by fact kind.  This is intentionally separate
        from the broad prevalidation sweep: a Validator request must not cause
        every local prover to run again, and a response is allowed to trigger
        this transition only once per cluster/fact/subject tuple.
        """

        if not self.enabled or str(validator_data.get("verdict") or "").lower() != "uncertain":
            return None
        raw_request = validator_data.get("missing_fact_request")
        if not isinstance(raw_request, Mapping):
            return None
        fact_kind = str(raw_request.get("fact_kind") or "").strip().lower()
        request = EvidenceCompletionRequest(
            validation_cluster_uid=str(issue.get("validation_cluster_uid") or ""),
            missing_fact=fact_kind,
            reason=str(raw_request.get("reason") or "deterministic evidence incomplete"),
        )
        if fact_kind not in SUPPORTED_FACT_KINDS:
            return self._resolution(issue, request, "unsupported", fact_kind, {})

        attempt_key = hashlib.sha256(
            json.dumps(
                {
                    "cluster": request.validation_cluster_uid,
                    "fact_kind": fact_kind,
                    "subject_uid": str(raw_request.get("subject_uid") or ""),
                    "function_uid": str(raw_request.get("function_uid") or ""),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        attempted = issue.setdefault("evidence_completion_request_hashes", [])
        if not isinstance(attempted, list):
            attempted = []
            issue["evidence_completion_request_hashes"] = attempted
        if attempt_key in attempted:
            return self._resolution(issue, request, "duplicate_request", fact_kind, {})
        attempted.append(attempt_key)
        issue["evidence_completion_attempt_count"] = (
            int(issue.get("evidence_completion_attempt_count") or 0) + 1
        )

        provider_status, generated, provider_error = self._run_requested_fact_providers(
            fact_kind,
            issue,
            validation_evidence,
        )
        if provider_status != "completed":
            issue["evidence_completion_status"] = provider_status
            issue["evidence_completion_terminal_status"] = provider_status
            issue["evidence_completion_missing_fact"] = fact_kind
            if provider_error:
                issue["evidence_completion_error"] = provider_error
            return self._resolution(issue, request, provider_status, fact_kind, {})
        proofs = self._authoritative_completion_proofs(issue, generated)
        if issue.get("blocking_negative_evidence") is True:
            proofs = [
                proof for proof in proofs if str(proof.get("outcome") or "").lower() != "reject"
            ]
        facts = self._requested_fact_payloads(fact_kind, issue, validation_evidence)
        facts, rejected_fact_uids = self._filter_requested_fact_uids(
            facts,
            validation_evidence,
        )
        if rejected_fact_uids:
            issue["validator_missing_fact_request_rejected"] = "unknown_fact_uid"
            issue["rejected_fact_uids"] = rejected_fact_uids
            return self._resolution(issue, request, "unsupported", fact_kind, {})
        facts = self._normalize_resolved_facts(
            fact_kind,
            facts,
            issue,
            validation_evidence,
        )
        delta: Dict[str, Any] = {"fact_kind": fact_kind, "facts": facts, "proofs": proofs}
        refs: list[str] = []
        for fact in facts:
            if not isinstance(fact, Mapping):
                continue
            ref = fact.get("fact_uid") or fact.get("uid") or fact.get("id")
            if ref:
                refs.append(str(ref))
        for proof in proofs:
            refs.extend(str(ref) for ref in proof.get("fact_ids") or [] if str(ref))
            if proof.get("code_hash"):
                refs.append(str(proof["code_hash"]))
        delta["evidence_refs"] = sorted(set(refs))

        if proofs:
            existing = issue.setdefault("deterministic_proofs", [])
            if not isinstance(existing, list):
                existing = []
                issue["deterministic_proofs"] = existing
            known = {
                (str(item.get("outcome") or ""), str(item.get("proof_kind") or ""))
                for item in existing
                if isinstance(item, Mapping)
            }
            for proof in proofs:
                identity = (str(proof.get("outcome") or ""), str(proof.get("proof_kind") or ""))
                if identity not in known:
                    existing.append(proof)
                    known.add(identity)
            issue["evidence_completion_status"] = "completed"
            issue["evidence_completion_terminal_status"] = "completed_with_proof"
            issue["evidence_completion_missing_fact"] = fact_kind
            return self._resolution(
                issue,
                request,
                "completed_with_proof",
                fact_kind,
                delta,
                proof_added=True,
            )
        if facts:
            existing_facts = issue.setdefault("evidence_completion_facts", [])
            if not isinstance(existing_facts, list):
                existing_facts = []
                issue["evidence_completion_facts"] = existing_facts
            existing_facts.extend(facts)
            issue["evidence_completion_status"] = "completed_partial"
            issue["evidence_completion_terminal_status"] = "completed_partial"
            issue["evidence_completion_missing_fact"] = fact_kind
            return self._resolution(issue, request, "completed_partial", fact_kind, delta)

        issue["evidence_completion_status"] = "exhausted"
        issue["evidence_completion_terminal_status"] = "exhausted"
        issue["evidence_completion_missing_fact"] = fact_kind
        return self._resolution(issue, request, "exhausted", fact_kind, {})

    def resolve_required_facts(
        self,
        issue: Dict[str, Any],
        *,
        validator_data: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]] = None,
    ) -> EvidenceResolutionBatch:
        """Resolve every locally supported fact required by the obligation.

        The model may still name one especially useful missing fact, but that
        request is no longer the coverage boundary.  The immutable obligation
        and its decision slice determine the remaining provider fan-out.
        """

        resolutions: list[EvidenceResolution] = []
        raw_request = validator_data.get("missing_fact_request")
        request = dict(raw_request) if isinstance(raw_request, Mapping) else {}
        for fact_kind in self.required_resolution_fact_kinds(issue, validator_data):
            synthetic = {
                "verdict": "uncertain",
                "missing_fact_request": {
                    "fact_kind": fact_kind,
                    "subject_uid": str(
                        request.get("subject_uid")
                        or issue.get("resource_identity")
                        or issue.get("source_identity")
                        or ""
                    ),
                    "function_uid": str(
                        request.get("function_uid")
                        or issue.get("function_signature")
                        or issue.get("function")
                        or ""
                    ),
                    "reason": str(
                        request.get("reason") or f"security obligation requires {fact_kind}"
                    ),
                },
            }
            resolution = self.resolve_requested_fact(
                issue,
                validator_data=synthetic,
                validation_evidence=validation_evidence,
            )
            if resolution is not None:
                resolutions.append(resolution)

        facts: list[Dict[str, Any]] = []
        proofs: list[Dict[str, Any]] = []
        evidence_refs: set[str] = set()
        fact_kinds: set[str] = set()
        proof_added = False
        for resolution in resolutions:
            proof_added = proof_added or resolution.proof_added
            if not resolution.evidence_delta:
                continue
            fact_kinds.add(resolution.fact_kind)
            facts.extend(
                dict(value)
                for value in resolution.evidence_delta.get("facts") or []
                if isinstance(value, Mapping)
            )
            proofs.extend(
                dict(value)
                for value in resolution.evidence_delta.get("proofs") or []
                if isinstance(value, Mapping)
            )
            evidence_refs.update(
                str(value)
                for value in resolution.evidence_delta.get("evidence_refs") or []
                if str(value)
            )

        delta: Dict[str, Any] = {}
        if facts or proofs:
            delta = {
                "fact_kinds": sorted(fact_kinds),
                "facts": self._deduplicate_records(facts, "fact_uid"),
                "proofs": self._deduplicate_records(proofs, "proof_kind"),
                "evidence_refs": sorted(evidence_refs),
                "resolution_statuses": [
                    {"fact_kind": value.fact_kind, "status": value.status} for value in resolutions
                ],
            }
        stable = json.dumps(delta, ensure_ascii=False, sort_keys=True, default=str)
        delta_hash = hashlib.sha256(stable.encode("utf-8")).hexdigest() if delta else ""
        issue["validator_fact_resolutions"] = [
            {
                "fact_kind": value.fact_kind,
                "status": value.status,
                "evidence_delta_hash": value.evidence_delta_hash,
                "proof_added": value.proof_added,
            }
            for value in resolutions
        ]
        if proof_added:
            aggregate_status = "completed_with_proof"
        elif delta:
            aggregate_status = "completed_partial"
        elif any(value.status == "timeout" for value in resolutions):
            aggregate_status = "timeout"
        elif any(value.status == "provider_error" for value in resolutions):
            aggregate_status = "provider_error"
        elif resolutions:
            aggregate_status = "exhausted"
        else:
            aggregate_status = "not_applicable"
        issue["evidence_completion_status"] = aggregate_status
        issue["evidence_completion_terminal_status"] = aggregate_status
        if delta.get("facts"):
            self._apply_fact_delta_to_decision_context(issue, delta["facts"])
        return EvidenceResolutionBatch(
            resolutions=tuple(resolutions),
            evidence_delta=delta,
            evidence_delta_hash=delta_hash,
            proof_added=proof_added,
        )

    @staticmethod
    def _apply_fact_delta_to_decision_context(
        issue: Dict[str, Any],
        facts: Iterable[Mapping[str, Any]],
    ) -> None:
        fact_slice = issue.get("decision_fact_slice")
        fact_slice = dict(fact_slice) if isinstance(fact_slice, Mapping) else {}
        missing = set(
            normalize_missing_fact_kinds(
                issue.get("missing_fact_kinds") or fact_slice.get("missing_fact_kinds") or []
            )
        )
        fact_uids = {str(value) for value in fact_slice.get("fact_uids") or [] if str(value)}
        code_hashes = {
            str(value) for value in fact_slice.get("dependency_code_hashes") or [] if str(value)
        }
        fact_payloads = [
            dict(value) for value in fact_slice.get("facts") or [] if isinstance(value, Mapping)
        ]
        known_payloads = {
            str(value.get("fact_uid") or value.get("uid") or value.get("id") or "")
            for value in fact_payloads
        }
        resolved: set[str] = set()
        for fact in facts:
            uid = str(fact.get("fact_uid") or "")
            if uid:
                fact_uids.add(uid)
                if uid not in known_payloads:
                    fact_payloads.append(dict(fact))
                    known_payloads.add(uid)
            dependency = str(fact.get("dependency_code_hash") or "")
            if dependency:
                code_hashes.add(dependency)
            kind = str(fact.get("fact_kind") or fact.get("kind") or "")
            if kind:
                resolved.add(kind)
            raw_satisfies = fact.get("satisfies_fact_kinds")
            if isinstance(raw_satisfies, Sequence) and not isinstance(raw_satisfies, str):
                resolved.update(str(value) for value in raw_satisfies if str(value))
        remaining = sorted(missing - resolved)
        fact_slice.update(
            {
                "fact_uids": sorted(fact_uids),
                "dependency_code_hashes": sorted(code_hashes),
                "missing_fact_kinds": remaining,
                "coverage": "complete" if not remaining and fact_uids else "partial",
                "facts": fact_payloads,
            }
        )
        issue["decision_fact_slice"] = fact_slice
        issue["missing_fact_kinds"] = remaining
        issue["decision_fact_coverage"] = fact_slice["coverage"]
        if fact_slice["coverage"] == "complete" and code_hashes:
            issue["candidate_promotion_eligible"] = True
            issue["candidate_promotion_reason"] = "required_local_facts_complete"

    @staticmethod
    def required_resolution_fact_kinds(
        issue: Mapping[str, Any],
        validator_data: Mapping[str, Any],
    ) -> tuple[str, ...]:
        """Map obligation facts to the narrow local provider vocabulary."""

        ordered: list[str] = []

        def add(value: Any) -> None:
            normalized = str(value or "").strip().lower()
            if normalized in SUPPORTED_FACT_KINDS and normalized not in ordered:
                ordered.append(normalized)

        raw_request = validator_data.get("missing_fact_request")
        if isinstance(raw_request, Mapping):
            add(raw_request.get("fact_kind"))

        obligation = issue.get("security_obligation")
        obligation = obligation if isinstance(obligation, Mapping) else {}
        raw_missing = issue.get("missing_fact_kinds")
        has_missing_contract = isinstance(raw_missing, Sequence) and not isinstance(
            raw_missing, str
        )
        missing = (
            list(raw_missing)
            if isinstance(raw_missing, Sequence) and not isinstance(raw_missing, str)
            else []
        )
        fact_slice = issue.get("decision_fact_slice")
        if isinstance(fact_slice, Mapping):
            slice_missing = fact_slice.get("missing_fact_kinds")
            if isinstance(slice_missing, Sequence) and not isinstance(slice_missing, str):
                has_missing_contract = True
                missing.extend(slice_missing)
        raw_required = issue.get("obligation_required_fact_kinds") or obligation.get(
            "required_fact_kinds"
        )
        if (
            not has_missing_contract
            and isinstance(raw_required, Sequence)
            and not isinstance(raw_required, str)
        ):
            missing.extend(raw_required)

        category = str(issue.get("defect_class") or issue.get("category") or "").lower()
        for raw_kind in missing:
            kind = str(raw_kind or "").strip().lower()
            add(kind)
            if kind in {"event:shared_state_access", "event:lock", "event:unlock"}:
                add("lockset")
                add("happens_before")
            elif kind in {"event:acquire", "event:exit", "event:release"}:
                add("cleanup_coverage")
                add("ownership_transfer")
                add("caller_contract")
            elif kind in {
                "event:release_effect_applies",
                "event:same_allocation_generation",
                "event:receiver_survives_release",
                "event:business_release_requirement",
                "event:responsibility_endpoint",
            }:
                # Schedule investigation of the open protocol obligations.
                # Generic contract/cleanup results do not themselves supply
                # these object- and generation-specific facts.
                add("caller_contract")
                add("cleanup_coverage")
            elif kind in {"event:later_slot_access", "event:feasible_lifecycle_path"}:
                add("caller_contract")
                add("source_sink_reachability")
            elif kind in {"source", "sink", "guard", "sanitizer"}:
                add("source_controllability")
                add("source_sink_reachability")
                add("guard_dominance")
                if any(token in category for token in ("bound", "overflow", "size", "index")):
                    add("value_range")
                    add("type_layout")

        # Older candidates can carry a partial promotion status without an
        # explicit missing-kind list.  Use the defect family only to select
        # providers; it never creates a fact or proof by itself.
        if not ordered and issue.get("candidate_promotion_eligible") is False:
            if any(token in category for token in ("race", "lock", "thread", "concurr")):
                add("lockset")
                add("happens_before")
            elif any(token in category for token in ("leak", "release", "ownership", "free")):
                add("cleanup_coverage")
                add("ownership_transfer")
                add("caller_contract")
            elif any(token in category for token in ("bound", "overflow", "size", "index")):
                add("value_range")
                add("guard_dominance")
                add("source_sink_reachability")
                add("type_layout")
            else:
                add("caller_contract")
                add("source_sink_reachability")
        return tuple(ordered)

    @staticmethod
    def _deduplicate_records(
        records: Iterable[Mapping[str, Any]],
        identity_key: str,
    ) -> list[Dict[str, Any]]:
        output: list[Dict[str, Any]] = []
        seen: set[str] = set()
        for record in records:
            identity = str(record.get(identity_key) or "")
            if not identity:
                identity = hashlib.sha256(
                    json.dumps(record, ensure_ascii=False, sort_keys=True, default=str).encode(
                        "utf-8"
                    )
                ).hexdigest()
            if identity in seen:
                continue
            seen.add(identity)
            output.append(dict(record))
        return output

    @staticmethod
    def _normalize_resolved_facts(
        fact_kind: str,
        facts: Iterable[Mapping[str, Any]],
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> list[Dict[str, Any]]:
        """Attach auditable provenance to accepted local fact records."""

        evidence = _as_mapping(validation_evidence)
        function_context = _as_mapping(evidence.get("function_context"))
        code = str(function_context.get("code") or "")
        dependency_hash = str(
            issue.get("dependency_code_hash")
            or issue.get("code_hash")
            or issue.get("source_fingerprint")
            or evidence.get("dependency_code_hash")
            or (hashlib.sha256(code.encode("utf-8")).hexdigest() if code else "")
        )
        location = {
            "file": str(issue.get("file") or issue.get("file_path") or ""),
            "function": str(issue.get("function_signature") or issue.get("function") or ""),
            "line": issue.get("line") or issue.get("start_line"),
        }
        normalized: list[Dict[str, Any]] = []
        for raw in facts:
            fact = dict(raw)
            stable = json.dumps(
                {"kind": fact_kind, "fact": fact, "dependency": dependency_hash},
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            )
            uid = str(fact.get("fact_uid") or fact.get("uid") or fact.get("id") or "")
            if not uid:
                uid = "FACT_LOCAL_" + hashlib.sha256(stable.encode("utf-8")).hexdigest()[:32]
            raw_location = fact.get("location")
            fact.update(
                {
                    "fact_uid": uid,
                    "fact_kind": str(fact.get("fact_kind") or fact.get("kind") or fact_kind),
                    "producer_engine": str(
                        fact.get("producer_engine") or "local_deterministic_fact_provider"
                    ),
                    "location": (
                        dict(raw_location) if isinstance(raw_location, Mapping) else location
                    ),
                    "dependency_code_hash": str(
                        fact.get("dependency_code_hash") or dependency_hash
                    ),
                    "evidence_ref": uid,
                    "origin": "deterministic_provider",
                }
            )
            normalized.append(fact)
        return normalized

    def _run_requested_fact_providers(
        self,
        fact_kind: str,
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> tuple[str, list[Dict[str, Any]], str]:
        """Run the named provider set behind a bounded exception-safe boundary.

        The task runs on this queue's own provider pool, which does not
        inherit the submitting thread's contextvars: the submitter's precise
        execution context is captured here and explicitly rebound on the
        provider thread with a finally-restore, so pool threads reused across
        variants never see another instance's scope and a late (timed-out)
        task cannot leak its binding into the next one.  The provider input
        is frozen at submit time — a deep copy of the issue and evidence —
        so parent-thread mutations during execution cannot cross the request
        boundary, and provider writes land only on the frozen copy.
        """

        context = current_execution_context()
        frozen_issue: Any = deepcopy(issue)
        frozen_evidence: Any = deepcopy(validation_evidence)

        def provider_task() -> list[Dict[str, Any]]:
            with rebound_execution_context(context):
                return list(
                    self._requested_completion_proofs(
                        fact_kind,
                        frozen_issue,
                        frozen_evidence,
                    )
                )

        future = self._fact_provider_executor.submit(provider_task)
        try:
            return "completed", future.result(timeout=self.fact_timeout_seconds), ""
        except FuturesTimeoutError:
            future.cancel()
            return "timeout", [], "fact provider timed out"
        except Exception as exc:
            return "provider_error", [], f"{type(exc).__name__}: {exc}"[:500]

    @staticmethod
    def _resolution(
        issue: Dict[str, Any],
        request: EvidenceCompletionRequest,
        status: str,
        fact_kind: str,
        delta: Dict[str, Any],
        *,
        proof_added: bool = False,
    ) -> EvidenceResolution:
        stable = json.dumps(delta, ensure_ascii=False, sort_keys=True, default=str)
        delta_hash = hashlib.sha256(stable.encode("utf-8")).hexdigest() if delta else ""
        issue["evidence_delta_hash"] = delta_hash
        issue["evidence_resolution_status"] = status
        return EvidenceResolution(
            request=request,
            status=status,
            fact_kind=fact_kind,
            evidence_delta=dict(delta),
            evidence_delta_hash=delta_hash,
            proof_added=proof_added,
        )

    @staticmethod
    def _requested_fact_payloads(
        fact_kind: str,
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> list[Dict[str, Any]]:
        """Read backend-produced typed facts; never synthesize model evidence."""

        sources = [
            issue.get("fact_completion_by_kind"),
            _as_mapping(issue.get("evidence_pack")).get("fact_completion_by_kind"),
            _as_mapping(validation_evidence).get("fact_completion_by_kind"),
        ]
        result: list[Dict[str, Any]] = []
        for source in sources:
            if not isinstance(source, Mapping):
                continue
            raw = source.get(fact_kind)
            values = raw if isinstance(raw, list) else [raw]
            for item in values:
                if isinstance(item, Mapping):
                    result.append(dict(item))
        return result[:32]

    @staticmethod
    def _filter_requested_fact_uids(
        facts: Iterable[Mapping[str, Any]],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> tuple[list[Dict[str, Any]], list[str]]:
        """Reject typed facts whose UID is absent from the trusted evidence slice.

        Providers may add a new deterministic fact during resolution, so a
        missing allow-list does not make every fact invalid.  When the slice
        does advertise a catalog, however, a model/provider-supplied UID must
        already be present there or be a content-addressed local fact with no
        external UID.  This prevents a forged UID from entering V2 evidence.
        """

        evidence = _as_mapping(validation_evidence)
        allowed: set[str] = set()
        catalog = evidence.get("evidence_ref_catalog")
        if isinstance(catalog, Mapping):
            allowed.update(str(key) for key in catalog if str(key))
        fact_slice = _as_mapping(evidence.get("decision_fact_slice"))
        for key in ("fact_uids", "edge_uids"):
            allowed.update(str(value) for value in _as_list(fact_slice.get(key)) if str(value))
        if not allowed:
            return [dict(fact) for fact in facts], []

        accepted: list[Dict[str, Any]] = []
        rejected: list[str] = []
        for fact in facts:
            uid = str(fact.get("fact_uid") or fact.get("uid") or fact.get("id") or "")
            if uid and uid not in allowed:
                rejected.append(uid)
                continue
            accepted.append(dict(fact))
        return accepted, sorted(set(rejected))

    def _requested_completion_proofs(
        self,
        fact_kind: str,
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Iterable[Dict[str, Any]]:
        """Dispatch one fact kind to its narrow deterministic providers."""

        with_evidence: Dict[str, list[EvidenceFactProvider]] = {
            "guard_dominance": [self._guard_dominance_proof],
            "caller_contract": [],
            "source_controllability": [],
            "ownership_transfer": [],
            "cleanup_coverage": [
                *(
                    [
                        self._failed_member_acquisition_cleanup_proof,
                        self._incomplete_owner_cleanup_proof,
                        self._lifecycle_protocol_confirmation_proof,
                    ]
                    if self.enable_v11_providers
                    else []
                ),
            ],
            "lockset": [
                self._local_lock_dominance_proof,
                *(
                    [
                        self._balanced_lock_protocol_proof,
                        self._lock_held_on_failure_return_proof,
                    ]
                    if self.enable_v11_providers
                    else []
                ),
            ],
            "happens_before": [
                self._local_lock_dominance_proof,
                *([self._balanced_lock_protocol_proof] if self.enable_v11_providers else []),
            ],
            "object_identity": [self._distinct_object_identity_proof],
            "value_range": (
                [self._allocation_copy_capacity_proof] if self.enable_v11_providers else []
            ),
            "source_sink_reachability": [self._cfg_obligation_confirmation_proof],
            "signal_context": [],
            "container_reachability": (
                [self._container_unlink_without_release_proof] if self.enable_v11_providers else []
            ),
            "type_layout": [],
        }
        issue_only: Dict[str, list[IssueFactProvider]] = {
            "guard_dominance": [self._ast_guard_dominance_proof],
            "caller_contract": [self._graph_contract_confirmation_proof],
            "source_controllability": [],
            "ownership_transfer": [
                self._fd_transfer_or_failure_proof,
                self._resource_transfer_proof,
            ],
            "cleanup_coverage": [],
            "lockset": [],
            "happens_before": [],
            "object_identity": [],
            "value_range": [self._allocation_context_proof],
            "source_sink_reachability": [self._graph_contract_confirmation_proof],
            "signal_context": [],
            "container_reachability": [],
            "type_layout": [self._array_shape_rejection_proof],
        }
        # Some providers have issue-only signatures despite producing a caller
        # or graph fact.  Do not invoke the same function through both tables.
        for issue_provider in issue_only.get(fact_kind, []):
            generated = issue_provider(issue)
            if generated is not None:
                yield generated
        for evidence_provider in with_evidence.get(fact_kind, []):
            generated = evidence_provider(issue, validation_evidence)
            if generated is not None:
                yield generated

        if not self.enable_v12_providers:
            return
        v12: Dict[str, list[EvidenceFactProvider]] = {
            "guard_dominance": [self._fixed_array_guard_v12_rejection_proof],
            "caller_contract": [self._external_allocation_v12_proof],
            "source_controllability": [self._entry_parameter_system_sink_v12_proof],
            "ownership_transfer": [
                self._ownership_transfer_v12_rejection_proof,
                self._caller_owned_field_transfer_v12_rejection_proof,
                self._source_lifecycle_acquire_exit_proof,
            ],
            "cleanup_coverage": [
                self._exact_leak_path_v12_proof,
                self._source_lifecycle_acquire_exit_proof,
                self._matching_release_before_exit_v12_rejection_proof,
                self._zero_initialized_member_failure_v12_rejection_proof,
            ],
            "lockset": [
                self._external_callback_under_lock_v12_proof,
                self._single_shared_access_v12_rejection_proof,
                self._caller_lock_context_proof,
                self._source_lockset_dominance_proof,
            ],
            "happens_before": [
                self._external_callback_under_lock_v12_proof,
                self._source_lockset_dominance_proof,
            ],
            "object_identity": [self._caller_owned_field_transfer_v12_rejection_proof],
            "value_range": [
                self._allocation_overflow_v12_proof,
                self._allocation_capacity_v12_rejection_proof,
                self._exact_allocation_copy_v12_rejection_proof,
                self._derived_allocation_bound_v12_rejection_proof,
            ],
            "source_sink_reachability": [self._entry_parameter_system_sink_v12_proof],
            "signal_context": [self._signal_context_v12_proof],
            "container_reachability": [self._self_referential_container_v12_proof],
            "type_layout": [
                self._fixed_array_guard_v12_rejection_proof,
                self._derived_allocation_bound_v12_rejection_proof,
            ],
        }
        for v12_provider in v12.get(fact_kind, []):
            generated = v12_provider(issue, validation_evidence)
            if generated is not None:
                yield generated

    def complete(
        self,
        issue: Dict[str, Any],
        *,
        validator_data: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]] = None,
    ) -> Optional[EvidenceCompletionRequest]:
        if not self.enabled or str(issue.get("evidence_completion_status") or "") in {
            "completed",
            "exhausted",
            "not_applicable",
            "engine_failed",
            "interrupted",
        }:
            return None
        if not self._eligible(issue, validator_data):
            issue.setdefault("evidence_completion_status", "not_applicable")
            issue.setdefault("evidence_completion_terminal_status", "not_applicable")
            return None

        request = EvidenceCompletionRequest(
            validation_cluster_uid=str(issue.get("validation_cluster_uid") or ""),
            missing_fact=self._missing_fact(issue, validator_data),
            reason=str(validator_data.get("reasoning") or "deterministic evidence incomplete"),
        )
        proofs = self._authoritative_completion_proofs(
            issue,
            self._completion_proofs(issue, validation_evidence),
        )
        # A Validator may identify a concrete counter-fact that conflicts with
        # an otherwise local rejection proof.  Keep that conflict visible for
        # review instead of allowing the post-validation completion pass to
        # erase it.  This is intentionally scoped to rejection: a complete
        # positive proof is still evidence of a real obligation.
        if issue.get("blocking_negative_evidence") is True:
            proofs = [
                proof for proof in proofs if str(proof.get("outcome") or "").lower() != "reject"
            ]
        if proofs:
            existing = issue.get("deterministic_proofs")
            if not isinstance(existing, list):
                existing = []
                issue["deterministic_proofs"] = existing
            existing.extend(proofs)
            issue["evidence_completion_status"] = "completed"
            issue["evidence_completion_terminal_status"] = "completed_with_proof"
            issue["evidence_completion_missing_fact"] = request.missing_fact
        else:
            # This is one bounded, deterministic completion pass.  Do not
            # pretend an unimplemented asynchronous worker will finish later.
            issue["evidence_completion_status"] = "exhausted"
            issue["evidence_completion_terminal_status"] = "exhausted"
            issue["evidence_completion_missing_fact"] = request.missing_fact
        issue["evidence_completion_attempt_count"] = (
            int(issue.get("evidence_completion_attempt_count") or 0) + 1
        )
        return request

    def complete_prevalidation(
        self,
        issue: Dict[str, Any],
        *,
        validation_evidence: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Promote already available deterministic facts before an LLM call.

        This is intentionally not a second validation path: it runs the same
        bounded providers used after a Validator response, but does not mark an
        unresolved candidate exhausted.  That lets a later Validator name one
        missing fact while ensuring complete local proof never pays for an LLM
        invocation.
        """

        if not self.enabled:
            return False
        existing = issue.get("deterministic_proofs")
        proofs = self._authoritative_completion_proofs(
            issue,
            self._completion_proofs(issue, validation_evidence),
        )
        # A Validator may identify a concrete counter-fact that conflicts with
        # an otherwise local rejection proof.  Keep that conflict visible for
        # review instead of allowing the post-validation completion pass to
        # erase it.  This is intentionally scoped to rejection: a complete
        # positive proof is still evidence of a real obligation.
        if issue.get("blocking_negative_evidence") is True:
            proofs = [
                proof for proof in proofs if str(proof.get("outcome") or "").lower() != "reject"
            ]
        if not proofs:
            issue.setdefault("prevalidation_fact_completion", "not_applicable")
            return False
        if not isinstance(existing, list):
            existing = []
            issue["deterministic_proofs"] = existing
        authoritative_existing = self._authoritative_completion_proofs(
            issue,
            (item for item in existing if isinstance(item, Mapping)),
        )
        known = {
            (str(item.get("outcome") or ""), str(item.get("proof_kind") or ""))
            for item in authoritative_existing
        }
        for proof in proofs:
            key = (str(proof.get("outcome") or ""), str(proof.get("proof_kind") or ""))
            if key not in known:
                existing.append(proof)
                known.add(key)
        issue["prevalidation_fact_completion"] = "completed_with_proof"
        issue["evidence_completion_status"] = "completed"
        issue["evidence_completion_terminal_status"] = "completed_with_proof"
        issue["evidence_completion_attempt_count"] = (
            int(issue.get("evidence_completion_attempt_count") or 0) + 1
        )
        return True

    @staticmethod
    def _authoritative_completion_proofs(
        issue: Mapping[str, Any],
        proofs: Iterable[Mapping[str, Any]],
    ) -> list[Dict[str, Any]]:
        """Keep only proofs accepted by the same policy used for routing.

        A provider may recognize a semantic pattern while still lacking a
        traceable fact/CFG identity.  Such a record is useful diagnostic data,
        but must not close evidence completion as ``completed_with_proof``.
        Filtering here prevents prevalidation from suppressing the one allowed
        post-Validator completion pass with an unusable proof.
        """

        accepted: list[Dict[str, Any]] = []
        for raw_proof in proofs:
            proof = dict(raw_proof)
            outcome = str(proof.get("outcome") or proof.get("decision") or "").lower()
            normalized_outcome = (
                "reject"
                if outcome in {"reject", "rejected"}
                else "confirm" if outcome in {"confirm", "confirmed"} else ""
            )
            if not normalized_outcome:
                continue
            trial = dict(issue)
            trial["deterministic_proofs"] = [proof]
            trial.pop("decision_proofs", None)
            trial.pop("proofs", None)
            pack = issue.get("evidence_pack")
            if isinstance(pack, Mapping):
                clean_pack = dict(pack)
                clean_pack.pop("deterministic_proofs", None)
                clean_pack.pop("decision_proofs", None)
                clean_pack.pop("proofs", None)
                trial["evidence_pack"] = clean_pack
            if (
                deterministic_decision_proof(
                    trial,
                    outcome=normalized_outcome,
                )
                is not None
            ):
                accepted.append(proof)
        return accepted

    def _completion_proofs(
        self,
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]] = None,
    ) -> Iterable[Dict[str, Any]]:
        pack = _as_mapping(issue.get("evidence_pack"))
        values = (
            issue.get("evidence_completion_proofs"),
            pack.get("evidence_completion_proofs"),
        )
        for value in values:
            if isinstance(value, Mapping):
                if "proof_kind" in value or "kind" in value:
                    yield dict(value)
                else:
                    for item in value.values():
                        if isinstance(item, Mapping):
                            yield dict(item)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    if isinstance(item, Mapping):
                        yield dict(item)
        local_lock_proof = EvidenceCompletionQueue._local_lock_dominance_proof(
            issue,
            validation_evidence,
        )
        if local_lock_proof is not None:
            yield local_lock_proof
        guard_proof = EvidenceCompletionQueue._guard_dominance_proof(
            issue,
            validation_evidence,
        )
        if guard_proof is not None:
            yield guard_proof
        ast_guard_proof = EvidenceCompletionQueue._ast_guard_dominance_proof(issue)
        if ast_guard_proof is not None:
            yield ast_guard_proof
        fd_transfer_proof = EvidenceCompletionQueue._fd_transfer_or_failure_proof(issue)
        if fd_transfer_proof is not None:
            yield fd_transfer_proof
        allocation_proof = EvidenceCompletionQueue._allocation_context_proof(issue)
        if allocation_proof is not None:
            yield allocation_proof
        array_proof = EvidenceCompletionQueue._array_shape_rejection_proof(issue)
        if array_proof is not None:
            yield array_proof
        transfer_proof = EvidenceCompletionQueue._resource_transfer_proof(issue)
        if transfer_proof is not None:
            yield transfer_proof
        field_proof = EvidenceCompletionQueue._distinct_object_identity_proof(
            issue,
            validation_evidence,
        )
        if field_proof is not None:
            yield field_proof
        confirmation_proof = EvidenceCompletionQueue._cfg_obligation_confirmation_proof(
            issue,
            validation_evidence,
        )
        if confirmation_proof is not None:
            yield confirmation_proof
        graph_confirmation_proof = EvidenceCompletionQueue._graph_contract_confirmation_proof(issue)
        if graph_confirmation_proof is not None:
            yield graph_confirmation_proof
        if self.enable_v11_providers:
            lock_protocol_proof = EvidenceCompletionQueue._balanced_lock_protocol_proof(
                issue,
                validation_evidence,
            )
            if lock_protocol_proof is not None:
                yield lock_protocol_proof
            allocation_copy_proof = EvidenceCompletionQueue._allocation_copy_capacity_proof(
                issue,
                validation_evidence,
            )
            if allocation_copy_proof is not None:
                yield allocation_copy_proof
            failed_member_proof = EvidenceCompletionQueue._failed_member_acquisition_cleanup_proof(
                issue,
                validation_evidence,
            )
            if failed_member_proof is not None:
                yield failed_member_proof
            pointer_provenance_proof = EvidenceCompletionQueue._pointer_offset_provenance_proof(
                issue,
                validation_evidence,
            )
            if pointer_provenance_proof is not None:
                yield pointer_provenance_proof
            async_stack_proof = EvidenceCompletionQueue._async_stack_escape_proof(
                issue,
                validation_evidence,
            )
            if async_stack_proof is not None:
                yield async_stack_proof
            unlink_proof = EvidenceCompletionQueue._container_unlink_without_release_proof(
                issue,
                validation_evidence,
            )
            if unlink_proof is not None:
                yield unlink_proof
            failure_lock_proof = EvidenceCompletionQueue._lock_held_on_failure_return_proof(
                issue,
                validation_evidence,
            )
            if failure_lock_proof is not None:
                yield failure_lock_proof
            incomplete_cleanup_proof = EvidenceCompletionQueue._incomplete_owner_cleanup_proof(
                issue,
                validation_evidence,
            )
            if incomplete_cleanup_proof is not None:
                yield incomplete_cleanup_proof
            lifecycle_protocol_proof = (
                EvidenceCompletionQueue._lifecycle_protocol_confirmation_proof(
                    issue,
                    validation_evidence,
                )
            )
            if lifecycle_protocol_proof is not None:
                yield lifecycle_protocol_proof
        if self.enable_v12_providers:
            for provider in (
                EvidenceCompletionQueue._external_allocation_v12_proof,
                EvidenceCompletionQueue._allocation_overflow_v12_proof,
                EvidenceCompletionQueue._signal_context_v12_proof,
                EvidenceCompletionQueue._entry_parameter_system_sink_v12_proof,
                EvidenceCompletionQueue._external_callback_under_lock_v12_proof,
                EvidenceCompletionQueue._self_referential_container_v12_proof,
                EvidenceCompletionQueue._exact_leak_path_v12_proof,
                EvidenceCompletionQueue._all_callers_bounded_allocation_v12_proof,
                EvidenceCompletionQueue._allocation_capacity_v12_rejection_proof,
                EvidenceCompletionQueue._fixed_array_guard_v12_rejection_proof,
                EvidenceCompletionQueue._ownership_transfer_v12_rejection_proof,
                EvidenceCompletionQueue._single_shared_access_v12_rejection_proof,
                EvidenceCompletionQueue._exact_allocation_copy_v12_rejection_proof,
                EvidenceCompletionQueue._matching_release_before_exit_v12_rejection_proof,
                EvidenceCompletionQueue._zero_initialized_member_failure_v12_rejection_proof,
                EvidenceCompletionQueue._caller_owned_field_transfer_v12_rejection_proof,
                EvidenceCompletionQueue._derived_allocation_bound_v12_rejection_proof,
            ):
                generated = provider(issue, validation_evidence)
                if generated is not None:
                    yield generated

    @staticmethod
    def _external_allocation_v12_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        allocations = [
            event
            for event in events
            if str(event.get("kind") or "").lower() == "unbounded_allocation"
        ]
        if not allocations or path.get("complete_in_function") is not True:
            return None
        allocations = [
            event
            for event in allocations
            if EvidenceCompletionQueue._allocation_call_names(
                str(event.get("expression") or ""), issue, validation_evidence
            )
            and re.search(r"(?:=|\breturn\b)", str(event.get("expression") or ""))
        ]
        if not allocations:
            return None
        if path.get("complete_to_entry") is not True:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code:
            code = str(issue.get("code_snippet") or "")
        allocations = [
            event
            for event in allocations
            if EvidenceCompletionQueue._allocation_source_bound_to_parameters(
                event,
                code,
            )
        ]
        if not allocations:
            return None
        function = str(issue.get("function") or path.get("function") or "")
        call_edges = [
            edge
            for edge in path.get("call_edges") or []
            if isinstance(edge, Mapping) and str(edge.get("callee") or "") == function
        ]
        external_edges = []
        for edge in call_edges:
            mappings = [
                item for item in edge.get("parameter_mapping") or [] if isinstance(item, Mapping)
            ]
            if any(item.get("source_parameter") for item in mappings):
                caller = edge.get("guard_summary")
                caller = caller if isinstance(caller, Mapping) else {}
                caller_side = caller.get("caller_side")
                caller_side = caller_side if isinstance(caller_side, Mapping) else {}
                checks = [
                    str(item.get("text") or "")
                    for item in caller_side.get("checks") or []
                    if isinstance(item, Mapping)
                ]
                if not any(
                    EvidenceCompletionQueue._terminating_upper_bound(check) for check in checks
                ):
                    external_edges.append(edge)
        if not external_edges:
            return None
        event = allocations[0]
        fact_ids = [
            f"ast_cfg:{event.get('line')}:unbounded_allocation",
            *[
                f"call_edge:{edge.get('caller')}->{edge.get('callee')}:{edge.get('call_line')}"
                for edge in external_edges[:8]
            ],
        ]
        return {
            "outcome": "confirm",
            "proof_kind": "external_value_controls_unbounded_allocation",
            "producer_engine": "project_contract_allocation_v12",
            "proof_version": "zscope.decision-proof.v4",
            "fact_ids": fact_ids,
            "cfg_nodes": [str(event.get("line") or "")],
            "subject_identity": EvidenceCompletionQueue._normalize_symbol(event.get("variable")),
            "code_hash": EvidenceCompletionQueue._evidence_code_hash(issue, ast_cfg),
            "facts": [
                "external_source_to_allocation",
                "allocation_path_complete",
                "no_upper_bound_guard",
            ],
            "completeness": "complete",
            "scope": "完整的入口到分配点调用契约",
            "summary": "外部可控值在完整路径上到达分配点，且缺少上界防护",
        }

    @staticmethod
    def _allocation_overflow_v12_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        arithmetic = [
            event
            for event in events
            if str(event.get("kind") or "").lower() == "integer_size_arithmetic"
        ]
        if not arithmetic or path.get("complete_in_function") is not True:
            return None
        event = arithmetic[0]
        expression = str(event.get("expression") or "")
        allocation_names = EvidenceCompletionQueue._allocation_call_names(
            expression, issue, validation_evidence
        )
        if not allocation_names or not re.search(r"(?:\*|\+)", expression):
            return None
        # A generic ``size + constant`` or ``count * sizeof`` in a helper is
        # not by itself a proof that a violating value is externally
        # reachable.  Field-derived request data and calloc count arithmetic
        # carry the stronger source/range contract implemented by v1.2.
        if "->" not in expression and not EvidenceCompletionQueue._allocation_call_names(
            expression, issue, validation_evidence, roles={"calloc"}
        ):
            return None
        guards = [
            str(item.get("condition") or item.get("text") or "")
            for item in ast_cfg.get("condition_guards") or []
            if isinstance(item, Mapping)
        ]
        if any("SIZE_MAX" in guard or "overflow" in guard.lower() for guard in guards):
            return None
        return EvidenceCompletionQueue._proof_from_ast(
            issue,
            outcome="confirm",
            proof_kind="allocation_arithmetic_overflow_reaches_sink",
            producer_engine="clang_value_range_v12",
            events=[event],
            facts=[
                "overflow_value_reachable",
                "arithmetic_precedes_guard",
                "allocation_sink_reached",
            ],
            summary="未检查的分配大小算术运算先于任何溢出防护求值，并最终到达分配器",
            scope="完整的过程内分配表达式",
            subject_identity=EvidenceCompletionQueue._normalize_symbol(
                event.get("variable") or expression
            ),
        )

    @staticmethod
    def _signal_context_v12_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        obligation = issue.get("security_obligation")
        obligation = obligation if isinstance(obligation, Mapping) else {}
        family = str(
            obligation.get("defect_family")
            or issue.get("defect_class")
            or issue.get("category")
            or ""
        ).lower()
        if not family.startswith("signal_"):
            return None
        call_paths = issue.get("call_paths") or issue.get("entry_paths") or []
        signatures = [
            str(value)
            for path in call_paths
            for value in (path if isinstance(path, (list, tuple)) else [path])
        ]
        signal_roots = [
            value
            for value in signatures
            if re.search(r"\(\s*int\s+\w*sig\w*\s*,\s*void\s*\*", value, re.IGNORECASE)
        ]
        if not signal_roots:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code:
            code = str(issue.get("code_snippet") or "")
        unsafe = re.search(
            r"\b(?:snprintf|sprintf|printf|malloc|calloc|realloc|free|pthread_mutex_(?:lock|trylock)|LOG_[A-Z_]+)\s*\(",
            code,
        )
        if unsafe is None:
            return None
        line = int(issue.get("line") or 0)
        return EvidenceCompletionQueue._proof_from_code(
            issue,
            outcome="confirm",
            proof_kind="registered_signal_path_calls_unsafe_operation",
            producer_engine="project_call_contract_signal_v12",
            code=code,
            line_numbers=[line],
            facts=["signal_context_reachable", "async_signal_unsafe_operation"],
            summary="信号上下文入口到达了异步信号安全子集之外的操作",
            scope="信号根可达性与目标函数快照",
            subject_identity=str(obligation.get("subject_uid") or "signal_context"),
        )

    @staticmethod
    def _entry_parameter_system_sink_v12_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Confirm a command sink fed directly by a scanned entry parameter.

        A non-literal ``system`` call alone is only a lead: its argument may be
        a locally generated constant or a fully sanitized buffer.  This proof
        additionally requires the sink operand to be a formal parameter of the
        function, that function to be the recorded entry boundary, a complete
        local/entry path, and no structured sanitizer fact.  The decision is
        therefore derived from source and entry identity, not model prose.
        """

        if str(issue.get("rule") or "").lower() != "clang_cfg_system_with_nonliteral_command":
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if (
            path.get("complete_in_function") is not True
            or path.get("complete_to_entry") is not True
        ):
            return None
        sinks = [
            event
            for event in events
            if str(event.get("kind") or "").lower() == "system_call"
            and str(event.get("api") or "system").lower() == "system"
        ]
        if len(sinks) != 1:
            return None
        event = sinks[0]
        source = EvidenceCompletionQueue._normalize_symbol(event.get("variable"))
        if not re.fullmatch(r"[A-Za-z_]\w*", source):
            return None
        function = str(issue.get("function") or path.get("function") or "").strip()
        entry_identity = str(issue.get("entry_identity") or "")
        if not function or not re.search(rf"\b{re.escape(function)}\s*\(", entry_identity):
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code:
            return None
        parameters = EvidenceCompletionQueue._function_parameter_names(code)
        if not parameters:
            # Frozen reports intentionally keep only the exact sink slice, but
            # the immutable entry identity still contains the full signature.
            # This fallback makes offline replay equivalent to live routing
            # without consulting a model or reconstructing broad source text.
            parameters = EvidenceCompletionQueue._function_parameter_names(f"{entry_identity} {{")
        if source not in parameters:
            return None
        sanitizer_kinds = {
            "command_sanitizer",
            "shell_escape",
            "allowlist_validation",
            "validated_command",
        }
        if any(str(item.get("kind") or "").lower() in sanitizer_kinds for item in events):
            return None
        guards = [
            str(item.get("condition") or item.get("text") or "")
            for item in ast_cfg.get("condition_guards") or []
            if isinstance(item, Mapping)
        ]
        if any(
            source in guard
            and re.search(
                r"\b(?:sanitize|escape|allowlist|validate_(?:command|shell))\w*\s*\(",
                guard,
                re.IGNORECASE,
            )
            for guard in guards
        ):
            return None
        return EvidenceCompletionQueue._proof_from_ast(
            issue,
            outcome="confirm",
            proof_kind="entry_parameter_reaches_system_sink",
            producer_engine="clang_command_dataflow_v12",
            events=[event],
            facts=[
                "scanned_entry_parameter_source",
                "nonliteral_system_sink",
                "entry_to_sink_path_complete",
                "no_structured_command_sanitizer",
            ],
            summary="扫描入口参数在完整路径上到达 system()，且缺少结构化清洗",
            scope="入口参数到命令执行汇点的数据流",
            subject_identity=source,
        )

    @staticmethod
    def _external_callback_under_lock_v12_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Confirm an externally supplied callback invoked while a lock is held.

        Merely observing a function-pointer call in a critical section is not
        enough because an internal callback may have a closed lock contract.
        This provider requires a direct assignment from an entry parameter to
        the called callback object, plus ordered lock/callback/unlock facts in
        the same complete function body.  Stored callbacks without that direct
        provenance remain review items.
        """

        if str(issue.get("rule") or "").lower() != "clang_cfg_callback_while_lock_held":
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if (
            path.get("complete_in_function") is not True
            or path.get("complete_to_entry") is not True
        ):
            return None
        lock_events = [item for item in events if str(item.get("kind") or "").lower() == "lock"]
        callback_events = [
            item for item in events if str(item.get("kind") or "").lower() == "callback_call"
        ]
        if len(lock_events) != 1 or len(callback_events) != 1:
            return None
        lock_event = lock_events[0]
        callback_event = callback_events[0]
        try:
            lock_line = int(lock_event.get("line") or 0)
            callback_line = int(callback_event.get("line") or 0)
        except (TypeError, ValueError):
            return None
        if not (0 < lock_line < callback_line):
            return None
        lock_match = re.search(
            r"\b(?:pthread_mutex_lock)\s*\(\s*&?([^)]+)\)",
            str(lock_event.get("expression") or ""),
        )
        callback_match = re.search(
            r"\b([A-Za-z_]\w*)\s*\(",
            str(callback_event.get("expression") or ""),
        )
        if lock_match is None or callback_match is None:
            return None
        lock_identity = EvidenceCompletionQueue._normalize_symbol(lock_match.group(1))
        callback_identity = callback_match.group(1)
        function = str(issue.get("function") or path.get("function") or "")
        source_formals: set[str] = set()
        source_edges: list[Mapping[str, Any]] = []
        for edge in path.get("call_edges") or []:
            if not isinstance(edge, Mapping) or str(edge.get("callee") or "") != function:
                continue
            mappings = [
                item
                for item in edge.get("parameter_mapping") or []
                if isinstance(item, Mapping) and item.get("source_parameter")
            ]
            formals = {
                str(item.get("formal") or "").strip()
                for item in mappings
                if str(item.get("formal") or "").strip()
            }
            if formals:
                source_formals.update(formals)
                source_edges.append(edge)
        if not source_formals or not source_edges:
            return None
        # Prefer the full numbered function body: the ordering proof compares
        # absolute source lines, and the short snippet window can miss the
        # assignment or unlock and strand a provable claim in review.
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code:
            code = str(issue.get("code_snippet") or "")
        if not code:
            return None
        assignment_line = 0
        assigned_formal = ""
        for raw_line in code.splitlines():
            numbered = re.match(r"\s*(\d+)\s*\|\s*(.*)$", raw_line)
            if numbered is None:
                continue
            line_number = int(numbered.group(1))
            statement = numbered.group(2)
            for formal in source_formals:
                if re.search(
                    rf"\b{re.escape(callback_identity)}\s*=\s*{re.escape(formal)}\s*;",
                    statement,
                ):
                    assignment_line = line_number
                    assigned_formal = formal
                    break
            if assignment_line:
                break
        if not (lock_line < assignment_line <= callback_line) or not assigned_formal:
            return None
        unlock_line = 0
        for raw_line in code.splitlines():
            numbered = re.match(r"\s*(\d+)\s*\|\s*(.*)$", raw_line)
            if numbered is None or int(numbered.group(1)) <= callback_line:
                continue
            statement = numbered.group(2)
            unlock = re.search(
                r"\b(?:pthread_mutex_unlock)\s*\(\s*&?([^)]+)\)",
                statement,
            )
            if (
                unlock
                and EvidenceCompletionQueue._normalize_symbol(unlock.group(1)) == lock_identity
            ):
                unlock_line = int(numbered.group(1))
                break
        if unlock_line <= callback_line:
            return None
        source_edge = source_edges[0]
        call_line = int(source_edge.get("call_line") or 0)
        fact_ids = [
            f"ast_cfg:{lock_line}:lock",
            f"source_cfg:{assignment_line}:external_callback_assignment",
            f"ast_cfg:{callback_line}:callback_call",
            f"source_cfg:{unlock_line}:unlock",
        ]
        if call_line > 0:
            fact_ids.append(
                f"call_edge:{source_edge.get('caller')}->{source_edge.get('callee')}:{call_line}"
            )
        return {
            "outcome": "confirm",
            "proof_kind": "external_callback_invoked_under_lock",
            "producer_engine": "clang_lock_callback_contract_v12",
            "proof_version": "zscope.decision-proof.v4",
            "fact_ids": fact_ids,
            "cfg_nodes": [
                str(lock_line),
                str(assignment_line),
                str(callback_line),
                str(unlock_line),
            ],
            "subject_identity": callback_identity,
            "code_hash": EvidenceCompletionQueue._code_hash(code, issue),
            "facts": [
                "entry_parameter_callback_source",
                "callback_assignment_under_lock",
                "callback_invoked_before_matching_unlock",
                "entry_to_callback_path_complete",
            ],
            "completeness": "complete",
            "scope": "完整的外部回调临界区",
            "summary": "入口提供的回调在加锁之后、匹配解锁之前被调用",
        }

    @staticmethod
    def _self_referential_container_v12_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        obligation = issue.get("security_obligation")
        obligation = obligation if isinstance(obligation, Mapping) else {}
        family = str(
            obligation.get("defect_family")
            or issue.get("defect_class")
            or issue.get("category")
            or ""
        ).lower()
        if family not in {"infinite_loop", "loop_nontermination"}:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code:
            code = str(issue.get("code_snippet") or "")
        match = re.search(r"\b([A-Za-z_]\w*)\s*->\s*next\s*=\s*\1\s*;", code)
        if match is None:
            return None
        variable = match.group(1)
        traversal = re.search(
            rf"\b{re.escape(variable)}\s*=\s*{re.escape(variable)}\s*->\s*next\b",
            code,
        )
        if traversal is None:
            traversal = re.search(
                r"\b[A-Za-z_]\w*\s*=\s*&\s*\(\s*\*[A-Za-z_]\w*\s*\)\s*->\s*next\b",
                code,
            )
        if traversal is None:
            return None
        cycle_guard = re.search(
            rf"(?:{re.escape(variable)}\s*->\s*next\s*==\s*{re.escape(variable)}|visited\s*\[|cycle_(?:check|detect))",
            code,
            re.IGNORECASE,
        )
        if cycle_guard is not None:
            return None
        line = EvidenceCompletionQueue._issue_line(issue)
        return EvidenceCompletionQueue._proof_from_code(
            issue,
            outcome="confirm",
            proof_kind="reachable_self_link_without_cycle_guard",
            producer_engine="clang_container_protocol_v12",
            code=code,
            line_numbers=[line],
            facts=[
                "self_link_assignment",
                "container_traversal_reachable",
                "cycle_guard_missing",
            ],
            summary="可达容器节点存在自链接，而遍历过程没有环防护",
            scope="完整的容器修改与遍历快照",
            subject_identity=variable,
        )

    @staticmethod
    def _source_lifecycle_acquire_exit_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Derive ``event:acquire``/``event:exit`` facts from the function body.

        Serves value-flow leak candidates whose security obligation requests
        acquire/exit lifecycle facts but whose engine supplied no CFG events:
        the clang CFG checkers attach event evidence only to their own
        candidates, so value-flow leak reports reach fact resolution with an
        empty event stream and every event-shaped provider declines.  This
        provider re-derives the same lifecycle facts straight from the
        validator's function source (the same signal the
        ``clang_cfg_acquire_without_release_on_exit`` checker extracts).

        The claim resolved here is deliberately the path-independent negative
        existential only: when the whole function body contains neither a
        release of an allocated resource nor an ownership transfer of it, no
        intraprocedural path can clean the resource up, so the leak claim is
        confirmed without relying on path completeness.  Branch-dependent
        (partial) claims and ambiguous releases stay reviewable on purpose.
        """

        rule = str(issue.get("rule") or "").lower()
        if rule not in {"svf_value_flow_memory_leak", "svf_value_flow_partial_memory_leak"}:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code or len(code) > 64 * 1024:
            return None

        from ...semantics.defaults import default_local_pattern_semantics

        semantics = default_local_pattern_semantics()
        evidence_pack = _as_mapping(issue.get("evidence_pack"))
        semantics.merge_overlay(
            dict(
                (validation_evidence or {}).get("semantic_contracts")
                or issue.get("semantic_contracts")
                or evidence_pack.get("semantic_contracts")
                or {}
            )
        )
        allocators = {
            c.symbol.name
            for c in semantics.contracts.contracts
            if c.role in {"allocator", "calloc", "reallocator"}
            and c.effects_trusted
            and c.carrier.kind == "return"
        }
        if not allocators:
            return None
        allocation = re.compile(
            r"\b([A-Za-z_]\w*)\s*=\s*(?:\(\s*[\w\s\*]+?\s*\)\s*)?"
            + r"(?:"
            + "|".join(re.escape(name) for name in sorted(allocators))
            + r")\s*\("
        )

        allocations: list[tuple[str, int]] = []
        for line_number, text in enumerate(code.splitlines(), start=1):
            match = allocation.search(text)
            if match:
                allocations.append((match.group(1), line_number))
        if not allocations:
            return None
        # Address-of escapes (e.g. ``&var[i]`` handed to pthread_create) may
        # transfer ownership implicitly; such bodies stay reviewable instead
        # of risking a wrong deterministic confirm.
        if any(re.search(rf"&\s*\b{re.escape(name)}\b", code) for name, _ in allocations):
            return None

        def var_released_or_transferred(variable: str, code_text: str) -> bool:
            pattern = rf"\b{re.escape(variable)}\b"
            for line in code_text.splitlines():
                # A call receiving the object may consume it. Without complete
                # callee/alias evidence this negative-existential provider must
                # abstain, regardless of the function's name or model verdict.
                if re.search(rf"\b(?!if\b|while\b|switch\b)[A-Za-z_]\w*\s*\([^;]*{pattern}", line):
                    return True
                if re.search(rf"\breturn\b[^;\n]*{pattern}", line, re.IGNORECASE):
                    return True
                if re.search(
                    rf"[A-Za-z_]\w*[^\n;=]*=" rf"[^;\n]*{pattern}",
                    line,
                ):
                    return True
            return False

        for variable, acquire_line in allocations:
            if var_released_or_transferred(variable, code):
                continue
            return EvidenceCompletionQueue._proof_from_code(
                issue,
                outcome="confirm",
                proof_kind="source_lifecycle_acquire_without_release",
                producer_engine="source_lifecycle_event_facts_v12",
                code=code,
                line_numbers=[acquire_line],
                facts=[
                    "event:acquire",
                    "event:exit",
                    "no_intraprocedural_release",
                    "no_ownership_transfer",
                ],
                summary=(
                    f"第 {acquire_line} 行的分配 '{variable}' 在整个函数体内没有任何释放，"
                    "也没有所有权转移"
                ),
                scope="整个函数体；路径无关的否定存在证明",
                subject_identity=variable,
            )
        return None

    _SOURCE_LOCKSET_RULES = frozenset(
        {
            "clang_cfg_unsynchronized_shared_flag_or_counter",
            "clang_cfg_global_state_written_with_and_without_lock",
            "clang_cfg_global_state_write_without_lock",
            "clang_cfg_global_pointer_length_pair_published_without_lock",
            "clang_cfg_global_mapping_unmapped_without_invalidation",
            "clang_cfg_lookup_before_insert_lock",
            "clang_cfg_global_registration_slot_checked_before_lock",
        }
    )

    @staticmethod
    def _caller_lock_context_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Lexical caller summaries are context, not current instance proof.

        They cover only recorded callers and the first textual call site, and
        cannot establish all-call coverage, aliases, mode or temporal state.
        Keep these claims reviewable until a current compiler-backed checker
        closes the interprocedural obligation.
        """
        return None

    @staticmethod
    def _source_lockset_dominance_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Refute unsynchronized-access claims when one lock dominates writes.

        Serves shared-global-state rules whose obligation requests
        ``event:shared_state_access``/``lockset`` facts.  The deterministic
        refutation is intraprocedural and path-independent for the write set:
        when every write to the reported global inside the function body is
        nested under the same LOCK (with a matching UNLOCK present), no
        intraprocedural path exhibits the claimed unsynchronized write.
        Reads and callee-side behaviour stay reviewable; any unguarded write
        leaves the claim untouched.
        """

        rule = str(issue.get("rule") or "").lower()
        if rule not in EvidenceCompletionQueue._SOURCE_LOCKSET_RULES:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code or len(code) > 64 * 1024:
            return None
        resource = EvidenceCompletionQueue._normalize_symbol(
            issue.get("source") or issue.get("resource_identity") or ""
        )
        if not resource or len(resource) > 120:
            return None

        write_pattern = re.compile(
            rf"\b{re.escape(resource)}\b\s*(?:\[[^\]]*\]\s*)?"
            r"(?:=(?!=)|\+=|-=|\*=|/=|%=|\|\|=|&=|\^=|<<=|>>=|\+\+|--)"
            rf"|\b{re.escape(resource)}\b\s*\.\s*[A-Za-z_]\w*\s*=(?!=)"
            rf"|\b{re.escape(resource)}\b\s*->\s*[A-Za-z_]\w*\s*=(?!=)"
        )
        from ...semantics.defaults import default_local_pattern_semantics

        semantics = default_local_pattern_semantics()
        semantics.merge_overlay(
            dict(
                (validation_evidence or {}).get("semantic_contracts")
                or issue.get("semantic_contracts")
                or _as_mapping(issue.get("evidence_pack")).get("semantic_contracts")
                or {}
            )
        )
        registry = semantics.contracts
        if re.search(r"\b(?:if|else|for|while|switch|goto)\b", code):
            return None
        from ...semantics.contract_compiler import read_source_facts

        header = re.search(r"\b([A-Za-z_]\w*)\s*\([^{};]*\)\s*\{", code)
        if header is None:
            return None
        source_facts = read_source_facts({"code": code, "func_name": header[1]}, registry)
        if not source_facts.complete or source_facts.unknown_calls:
            return None
        held: list[tuple[str, str]] = []
        write_locks: list[str] = []
        write_lines: list[int] = []
        saw_unlock = False
        for line_number, text in enumerate(code.splitlines(), start=1):
            for name in re.findall(r"\b([A-Za-z_]\w*)\s*\(", text):
                args = registry.call_arguments(name, text)
                if args is None:
                    continue
                for event in registry.match_call(name, "lock", args):
                    if event.applicability != "applies" or event.lock_mode != "exclusive":
                        return None
                    held.append((name, event.object))
                for event in registry.match_call(name, "unlock", args):
                    if event.applicability != "applies":
                        return None
                    for index in range(len(held) - 1, -1, -1):
                        if (
                            registry.release_status(
                                held[index][0], name, args, acquired_object=held[index][1]
                            )
                            == "applies"
                        ):
                            held.pop(index)
                            saw_unlock = True
                            break
            if write_pattern.search(text):
                if not held:
                    return None
                write_locks.append(held[-1][1])
                write_lines.append(line_number)
        if not write_lines or len(set(write_locks)) != 1:
            return None
        if not saw_unlock:
            return None
        # The refutation targets unsynchronized-WRITE claims.  A flagged
        # unlocked read (e.g. the double-checked-locking idiom) is not
        # refuted by a locked write set and stays reviewable.
        sink_text = str(issue.get("sink") or "")
        if not write_pattern.search(sink_text):
            return None
        lock_name = write_locks[0]
        return EvidenceCompletionQueue._proof_from_code(
            issue,
            outcome="reject",
            proof_kind="source_lockset_dominates_access",
            producer_engine="source_lockset_event_facts_v12",
            code=code,
            line_numbers=write_lines,
            facts=[
                "event:shared_state_access",
                "lockset",
                "lock_dominates_access",
                "all_writes_guarded",
                f"all_writes_guarded_by:{lock_name}",
            ],
            summary=(
                f"本函数体内对 '{resource}' 的全部 {len(write_lines)} 次写入都嵌套在 "
                f"'{lock_name}' 之下，且存在匹配的解锁"
            ),
            scope=f"{resource} 的全部本地写入",
            subject_identity=resource,
        )

    @staticmethod
    def _exact_leak_path_v12_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        acquisitions = [
            event
            for event in events
            if str(event.get("kind") or "").lower() in {"acquire", "allocation", "resource_acquire"}
            and event.get("success_path", True) is not False
        ]
        exits = [
            event
            for event in events
            if str(event.get("kind") or "").lower()
            in {"exit_without_release", "return_without_release"}
        ]
        if len(acquisitions) != 1 or not exits:
            return None
        subject = EvidenceCompletionQueue._normalize_symbol(
            acquisitions[0].get("access_path")
            or acquisitions[0].get("field_path")
            or acquisitions[0].get("variable")
        )
        if not subject:
            return None
        release_or_transfer = [
            event
            for event in events
            if str(event.get("kind") or "").lower()
            in {"release", "free", "ownership_transfer", "return_transfer", "container_transfer"}
            and EvidenceCompletionQueue._normalize_symbol(
                event.get("access_path") or event.get("field_path") or event.get("variable")
            )
            == subject
        ]
        if release_or_transfer:
            return None
        return EvidenceCompletionQueue._proof_from_ast(
            issue,
            outcome="confirm",
            proof_kind="exact_acquisition_exit_leak",
            producer_engine="clang_ownership_cfg_v12",
            events=[acquisitions[0], *exits],
            facts=[
                "successful_acquisition",
                "reachable_exit_without_release",
                "ownership_not_transferred",
            ],
            summary="成功的字段敏感获取到达某个出口，且没有释放或所有权转移",
            scope="完整的获取到出口所有权路径",
            subject_identity=subject,
        )

    @staticmethod
    def _terminating_upper_bound(text: str) -> bool:
        value = str(text or "")
        has_upper = bool(re.search(r"(?:>|>=)\s*(?:[A-Z_][A-Z0-9_]*|sizeof\s*\(|\d+)", value))
        terminates = bool(re.search(r"\b(?:return|goto|break|continue|abort|exit)\b", value))
        return has_upper and terminates

    @staticmethod
    def _allocation_call_names(
        expression: str,
        issue: Optional[Mapping[str, Any]] = None,
        evidence: Optional[Mapping[str, Any]] = None,
        *,
        roles: Optional[set[str]] = None,
    ) -> list[str]:
        from ...semantics.defaults import default_local_pattern_semantics

        semantics = default_local_pattern_semantics()
        pack = (issue or {}).get("evidence_pack") or {}
        overlay = (
            (evidence or {}).get("semantic_contracts")
            or (issue or {}).get("semantic_contracts")
            or pack.get("semantic_contracts")
            or {}
        )
        semantics.merge_overlay(dict(overlay))
        names = {
            c.symbol.name
            for c in semantics.contracts.contracts
            if c.role in (roles or {"allocator", "calloc", "reallocator"})
            and c.source in {"user", "user_config", "builtin_defaults"}
            and not c.conditions
        }
        return [
            name
            for name in re.findall(r"\b([A-Za-z_]\w*)\s*\(", str(expression or ""))
            if name in names
        ]

    @staticmethod
    def _allocation_source_bound_to_parameters(
        event: Mapping[str, Any],
        code: str,
    ) -> bool:
        text = re.sub(r"^\s*\d+\s*\|\s*", "", str(code or ""), flags=re.MULTILINE)
        parameters = EvidenceCompletionQueue._function_parameter_names(text)
        if not parameters:
            return False
        expression = str(event.get("variable") or event.get("expression") or "")
        identifiers = set(re.findall(r"[A-Za-z_]\w*", expression))
        if identifiers & parameters:
            # Arithmetic additions are routed through the overflow provider;
            # keeping them here would display the same root twice.
            return "+" not in expression
        # Common string-allocation wrappers compute ``len = strlen(param)+1``
        # before calling the allocator.  This is a direct deterministic data
        # dependency rather than a name heuristic.
        simple_variable = EvidenceCompletionQueue._normalize_symbol(event.get("variable"))
        if not re.fullmatch(r"[A-Za-z_]\w*", simple_variable):
            return False
        return any(
            re.search(
                rf"\b{re.escape(simple_variable)}\s*=\s*strlen\s*\(\s*{re.escape(parameter)}\s*\)",
                text,
            )
            for parameter in parameters
        )

    @staticmethod
    def _function_parameter_names(code: str) -> set[str]:
        text = re.sub(r"^\s*\d+\s*\|\s*", "", str(code or ""), flags=re.MULTILINE)
        signature = re.search(
            r"\b[A-Za-z_]\w*(?:\s+|\s*\*+\s*)[A-Za-z_]\w*\s*\(([^)]*)\)\s*\{",
            text,
        )
        if signature is None:
            return set()
        parameters: set[str] = set()
        for declaration in signature.group(1).split(","):
            names = re.findall(r"[A-Za-z_]\w*", declaration)
            if names and names[-1] != "void":
                parameters.add(names[-1])
        return parameters

    @staticmethod
    def _all_callers_bounded_allocation_v12_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if not any(
            str(event.get("kind") or "").lower() == "unbounded_allocation" for event in events
        ):
            return None
        if path.get("complete_to_entry") is not True:
            return None
        function = str(issue.get("function") or path.get("function") or "")
        edges = [
            edge
            for edge in path.get("call_edges") or []
            if isinstance(edge, Mapping) and str(edge.get("callee") or "") == function
        ]
        if not edges:
            return None
        bounded = []
        for edge in edges:
            mappings = [
                item for item in edge.get("parameter_mapping") or [] if isinstance(item, Mapping)
            ]
            if not mappings:
                return None
            arguments = [str(item.get("actual") or "") for item in mappings]
            constant = all(
                bool(re.fullmatch(r"(?:\d+|sizeof\s*\([^)]*\)|[A-Z_][A-Z0-9_]*)", arg.strip()))
                for arg in arguments
            )
            summary = edge.get("guard_summary")
            summary = summary if isinstance(summary, Mapping) else {}
            caller = summary.get("caller_side")
            caller = caller if isinstance(caller, Mapping) else {}
            checks = [
                str(item.get("text") or "")
                for item in caller.get("checks") or []
                if isinstance(item, Mapping)
            ]
            guarded = any(
                EvidenceCompletionQueue._terminating_upper_bound(check) for check in checks
            )
            if not constant and not guarded:
                return None
            bounded.append(edge)
        event = next(
            event
            for event in events
            if str(event.get("kind") or "").lower() == "unbounded_allocation"
        )
        return EvidenceCompletionQueue._proof_from_ast(
            issue,
            outcome="reject",
            proof_kind="all_reachable_callers_bound_allocation",
            producer_engine="project_call_contract_allocation_v12",
            events=[event],
            facts=["all_reachable_callers_bounded", "guard_dominates_allocation"],
            summary="每个可达调用方都提供常量容量或终止性上界防护",
            scope="完整的可达调用方集合",
            subject_identity=EvidenceCompletionQueue._normalize_symbol(event.get("variable")),
        )

    @staticmethod
    def _allocation_capacity_v12_rejection_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        pack = _as_mapping(issue.get("evidence_pack"))
        proof_facts = _as_mapping(pack.get("proof_facts"))
        if not (
            proof_facts.get("allocation_capacity_covers_sink") is True
            and proof_facts.get("signedness_safe") is True
        ):
            return None
        ast_cfg, _path, events = EvidenceCompletionQueue._ast_pack(issue)
        selected = [event for event in events if event.get("line")]
        if not selected:
            return None
        return EvidenceCompletionQueue._proof_from_ast(
            issue,
            outcome="reject",
            proof_kind="allocation_capacity_covers_sink",
            producer_engine="clang_value_range_v12",
            events=selected,
            facts=["allocation_capacity_covers_sink", "signedness_safe"],
            summary="已证明的分配容量覆盖汇点长度，且符号类型兼容",
            scope="完整的分配到汇点值关系",
        )

    @staticmethod
    def _fixed_array_guard_v12_rejection_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        arrays = [
            event for event in events if str(event.get("kind") or "").lower() == "fixed_array"
        ]
        loops = [event for event in events if str(event.get("kind") or "").lower() == "count_loop"]
        if len(arrays) != 1 or len(loops) != 1:
            return None
        capacity = str(arrays[0].get("api") or "")
        bound = str(loops[0].get("api") or "")
        constraints = [str(value) for value in path.get("path_constraints") or []]
        guarded = any(
            capacity
            and bound
            and capacity in value
            and bound in value
            and re.search(r"(?:>|>=)", value)
            for value in constraints
        )
        if not guarded:
            return None
        return EvidenceCompletionQueue._proof_from_ast(
            issue,
            outcome="reject",
            proof_kind="fixed_array_index_proved_in_range",
            producer_engine="clang_value_range_v12",
            events=[arrays[0], loops[0]],
            facts=["all_paths_index_in_range", "fixed_array_capacity"],
            summary="终止性防护在每条路径上都将循环上界限制在定长数组容量之内",
            scope="完整的受防护循环",
            subject_identity=EvidenceCompletionQueue._normalize_symbol(arrays[0].get("variable")),
        )

    @staticmethod
    def _ownership_transfer_v12_rejection_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        pack = _as_mapping(issue.get("evidence_pack"))
        ownership = pack.get("ownership")
        ownership = _as_mapping(ownership)
        if not (
            ownership.get("all_exits_release_or_transfer") is True
            and ownership.get("field_sensitive_object")
        ):
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True or not events:
            return None
        return EvidenceCompletionQueue._proof_from_ast(
            issue,
            outcome="reject",
            proof_kind="ownership_transferred_on_all_exits",
            producer_engine="clang_ownership_cfg_v12",
            events=events,
            facts=["same_field_sensitive_object", "all_exits_release_or_transfer"],
            summary="每个可行出口都释放或转移同一个字段敏感资源",
            scope="完整的所有权出口集合",
            subject_identity=str(ownership.get("field_sensitive_object")),
        )

    @staticmethod
    def _single_shared_access_v12_rejection_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        accesses = [
            event
            for event in events
            if str(event.get("kind") or "").lower() == "shared_state_access"
        ]
        pack = _as_mapping(issue.get("evidence_pack"))
        concurrency = pack.get("concurrency")
        concurrency = _as_mapping(concurrency)
        if len(accesses) != 1 or path.get("complete_in_function") is not True:
            return None
        if concurrency.get("project_access_set_complete") is not True:
            return None
        if concurrency.get("conflicting_accesses") or pack.get("conflicting_accesses"):
            return None
        return EvidenceCompletionQueue._proof_from_ast(
            issue,
            outcome="reject",
            proof_kind="single_shared_access_not_race",
            producer_engine="clang_concurrency_v12",
            events=accesses,
            facts=["single_shared_access_event"],
            summary="完整候选证据中仅存在一次共享状态访问事件，因此不构成冲突访问对",
            scope="完整的候选并发证据",
            subject_identity=EvidenceCompletionQueue._normalize_symbol(accesses[0].get("variable")),
        )

    @staticmethod
    def _normalized_value_expression(value: Any) -> str:
        """Normalize a side-effect-free length expression for exact equality.

        This helper deliberately does not perform algebra.  A proof is emitted
        only when the allocator and copy events carry the same expression after
        whitespace and redundant outer parentheses are removed.
        """

        text = re.sub(r"\s+", "", str(value or ""))
        while len(text) > 1 and text.startswith("(") and text.endswith(")"):
            depth = 0
            wraps = True
            for index, char in enumerate(text):
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                    if depth == 0 and index != len(text) - 1:
                        wraps = False
                        break
            if not wraps:
                break
            text = text[1:-1]
        return text

    @staticmethod
    def _event_lvalue(event: Mapping[str, Any]) -> str:
        expression = str(event.get("expression") or "")
        lhs = expression.split("=", 1)[0].strip() if "=" in expression else ""
        match = re.search(r"([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*$", lhs)
        return EvidenceCompletionQueue._normalize_symbol(
            match.group(1) if match else event.get("variable")
        )

    @staticmethod
    def _exact_allocation_copy_v12_rejection_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Reject a narrowed-copy lead when both operations use one exact length."""

        if (
            str(issue.get("rule") or "").lower()
            != "clang_cfg_narrowed_allocation_original_length_copy"
        ):
            return None
        _ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        allocations = [
            item
            for item in events
            if str(item.get("kind") or "").lower() == "narrowed_heap_allocation"
        ]
        copies = [
            item
            for item in events
            if str(item.get("kind") or "").lower() == "original_length_heap_copy"
        ]
        for allocation in allocations:
            allocated_object = EvidenceCompletionQueue._normalize_symbol(allocation.get("variable"))
            allocated_length = EvidenceCompletionQueue._normalized_value_expression(
                allocation.get("api")
            )
            if not allocated_object or not allocated_length:
                continue
            for copied in copies:
                copied_object = EvidenceCompletionQueue._normalize_symbol(copied.get("variable"))
                copied_length = EvidenceCompletionQueue._normalized_value_expression(
                    copied.get("api")
                )
                if allocated_object != copied_object or allocated_length != copied_length:
                    continue
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="exact_allocation_length_covers_copy",
                    producer_engine="clang_value_relation_v12",
                    events=[allocation, copied],
                    facts=[
                        "same_field_sensitive_object",
                        "allocation_length_equals_copy_length",
                    ],
                    summary="分配与拷贝对同一对象使用完全相同的长度表达式",
                    scope="完整的本地分配到拷贝关系",
                    subject_identity=allocated_object,
                )
        return None

    @staticmethod
    def _matching_release_before_exit_v12_rejection_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Reject a leak edge when the same object is released before that edge."""

        if str(issue.get("rule") or "").lower() != "clang_cfg_acquire_without_release_on_exit":
            return None
        _ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code or len(code) > 64 * 1024:
            return None
        code_lines = code.splitlines()
        brace_depths: list[int] = []
        depth = 0
        for text in code_lines:
            # This is a lexical branch witness, not a C parser.  Structured
            # AST/CFG events still provide the authoritative acquire/exit
            # nodes; depth merely prevents a release in a sibling branch from
            # being attached to the reported exit.
            depth -= text.count("}")
            brace_depths.append(depth)
            depth += text.count("{")
        for acquisition in (
            item for item in events if str(item.get("kind") or "").lower() == "acquire"
        ):
            subject = EvidenceCompletionQueue._event_lvalue(acquisition)
            acquire_text = str(acquisition.get("expression") or "").strip()
            if not subject or not acquire_text:
                continue
            acquire_offset = code.find(acquire_text)
            if acquire_offset < 0:
                continue
            acquire_index = code[:acquire_offset].count("\n")
            acquire_line = int(acquisition.get("line") or 0)
            if acquire_line <= 0:
                continue
            source_line_base = acquire_line - acquire_index
            escaped = re.escape(subject).replace(r"\->", r"\s*->\s*").replace(r"\.", r"\s*\.\s*")
            exits = [
                item
                for item in events
                if str(item.get("kind") or "").lower() == "exit"
                and int(item.get("line") or 0) > int(acquisition.get("line") or 0)
            ]
            for exited in exits:
                exit_line = int(exited.get("line") or 0)
                exit_index = exit_line - source_line_base
                if not (acquire_index < exit_index < len(code_lines)):
                    continue
                if "return" not in code_lines[exit_index]:
                    continue
                release_index = next(
                    (
                        index
                        for index in range(acquire_index + 1, exit_index)
                        if re.search(
                            rf"\b(?:free)\s*\(\s*{escaped}\s*\)\s*;",
                            code_lines[index],
                        )
                        and brace_depths[index] == brace_depths[exit_index]
                    ),
                    -1,
                )
                if release_index < 0:
                    continue
                release_line = source_line_base + release_index
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="matching_release_precedes_reported_exit",
                    producer_engine="clang_ownership_cfg_v12",
                    events=[
                        acquisition,
                        {"kind": "matching_release", "line": release_line},
                        exited,
                    ],
                    facts=[
                        "same_field_sensitive_object",
                        "release_dominates_reported_exit",
                    ],
                    summary="同一字段敏感资源在所报告的出口边之前已被释放",
                    scope="完整的已报告获取到出口路径",
                    subject_identity=subject,
                )
        return None

    @staticmethod
    def _zero_initialized_member_failure_v12_rejection_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Reject a parent cleanup lead on a failed member acquisition branch."""

        if (
            str(issue.get("rule") or "").lower()
            != "clang_cfg_parent_release_without_owned_member_cleanup"
        ):
            return None
        _ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code or len(code) > 64 * 1024:
            return None
        sink = str(issue.get("sink") or "")
        parent_match = re.search(r"\b(?:free)\s*\(\s*([A-Za-z_]\w*)\s*\)", sink)
        if parent_match is None:
            return None
        parent = parent_match.group(1)
        parent_zeroed = re.search(
            rf"\b{re.escape(parent)}\b\s*=\s*[^;]*(?:calloc|zalloc)[A-Za-z_0-9]*\s*\(",
            code,
            re.IGNORECASE,
        )
        if parent_zeroed is None:
            return None
        assignment = re.search(
            rf"(?P<member>{re.escape(parent)}\s*->\s*[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*)"
            r"\s*=\s*[^;]*(?:alloc|dup|open|create)[A-Za-z_0-9]*\s*\([^;]*;",
            code[parent_zeroed.end() :],
            re.IGNORECASE,
        )
        if assignment is None:
            return None
        member = EvidenceCompletionQueue._normalize_symbol(assignment.group("member"))
        assignment_offset = parent_zeroed.end() + assignment.start()
        escaped_member = re.escape(member).replace(r"\->", r"\s*->\s*").replace(r"\.", r"\s*\.\s*")
        branch = re.search(
            rf"if\s*\(\s*!\s*{escaped_member}\s*\)\s*\{{?"
            rf"(?P<body>.{{0,600}}?\b(?:free)\s*\(\s*{re.escape(parent)}\s*\)\s*;)"
            r"(?P<tail>.{0,160}?\breturn\b)",
            code[assignment_offset:],
            re.DOTALL,
        )
        if branch is None:
            return None
        issue_line = EvidenceCompletionQueue._issue_line(issue)
        return EvidenceCompletionQueue._proof_from_code(
            issue,
            outcome="reject",
            proof_kind="zero_initialized_member_failed_before_parent_release",
            producer_engine="clang_ownership_cfg_v12",
            code=code,
            line_numbers=[issue_line],
            facts=[
                "zero_initialized_parent",
                "member_acquisition_failed",
                "parent_cleanup_on_failure_only",
            ],
            summary="在父对象释放之前，零初始化成员在其获取失败分支上为空",
            scope="完整的成员获取失败分支",
            subject_identity=member,
        )

    @staticmethod
    def _caller_owned_field_transfer_v12_rejection_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Prove transfer into a field of a caller-provided owner object."""

        if str(issue.get("rule") or "").lower() != "clang_cfg_acquire_without_release_on_exit":
            return None
        _ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code or len(code) > 64 * 1024:
            return None
        signature = code.split("{", 1)[0]
        pointer_parameters = set(
            re.findall(r"\b[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*\s*\*+\s*([A-Za-z_]\w*)", signature)
        )
        if not pointer_parameters:
            return None
        exits = [item for item in events if str(item.get("kind") or "").lower() == "exit"]
        success_exits = [
            item
            for item in exits
            if re.search(r"\breturn\s+0\s*;", str(item.get("expression") or ""))
        ]
        if not success_exits:
            return None
        for acquisition in (
            item for item in events if str(item.get("kind") or "").lower() == "acquire"
        ):
            subject = EvidenceCompletionQueue._event_lvalue(acquisition)
            parent = subject.split("->", 1)[0] if "->" in subject else ""
            if parent not in pointer_parameters:
                continue
            return EvidenceCompletionQueue._proof_from_ast(
                issue,
                outcome="reject",
                proof_kind="caller_owned_field_transfer",
                producer_engine="clang_ownership_cfg_v12",
                events=[acquisition, *success_exits],
                facts=[
                    "field_sensitive_object",
                    "caller_owned_parent",
                    "successful_return_transfers_responsibility",
                ],
                summary="获取的对象在成功返回之前被存入调用方提供的所有者字段",
                scope="完整的调用方所有者字段转移路径",
                subject_identity=subject,
            )
        return None

    @staticmethod
    def _derived_allocation_bound_v12_rejection_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Propagate a terminating upper bound through one local size expression."""

        if (
            str(issue.get("rule") or "").lower()
            != "clang_cfg_external_size_allocation_without_limit"
        ):
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code or len(code) > 64 * 1024:
            return None
        allocations = [
            item for item in events if str(item.get("kind") or "").lower() == "unbounded_allocation"
        ]
        returns = (
            (ast_cfg.get("scope_summary") or {}).get("return_lines")
            if isinstance(ast_cfg.get("scope_summary"), Mapping)
            else []
        )
        returns = _as_list(returns)
        guards = _as_list(ast_cfg.get("condition_guards"))
        for allocation in allocations:
            derived = EvidenceCompletionQueue._normalize_symbol(allocation.get("variable"))
            allocation_line = int(allocation.get("line") or 0)
            if not re.fullmatch(r"[A-Za-z_]\w*", derived) or allocation_line <= 0:
                continue
            assignment = re.search(rf"\b{re.escape(derived)}\s*=\s*(?P<value>[^;]+);", code)
            if assignment is None:
                continue
            value = assignment.group("value")
            dynamic_value = re.sub(r"\bsizeof\s*\([^)]*\)", "", value)
            sources = {
                token
                for token in re.findall(r"\b[A-Za-z_]\w*\b", dynamic_value)
                if token not in {"sizeof", "size_t", "uint32_t", "uint64_t"} and not token.isupper()
            }
            if len(sources) != 1:
                continue
            source = next(iter(sources))
            for guard in guards:
                if not isinstance(guard, Mapping):
                    continue
                guard_line = int(guard.get("line") or 0)
                condition = str(guard.get("condition") or "")
                if not re.search(
                    rf"\b{re.escape(source)}\s*>\s*(?:[A-Z][A-Z0-9_]*|\d+)\b", condition
                ):
                    continue
                if not (
                    guard_line < allocation_line
                    and any(
                        guard_line < int(line) <= guard_line + 3
                        for line in returns
                        if isinstance(line, int)
                    )
                ):
                    continue
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="terminating_allocation_upper_bound",
                    producer_engine="clang_value_relation_v12",
                    events=[guard, allocation],
                    facts=[
                        "explicit_upper_bound",
                        "terminating_guard",
                        "guard_dominates_allocation",
                    ],
                    summary="唯一动态源上的终止性上界会传播到派生的分配大小",
                    scope="完整的本地上界到分配关系",
                    subject_identity=derived,
                )
        return None

    @staticmethod
    def _lifecycle_protocol_confirmation_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Confirm explicit borrow/owner/concurrency protocol violations.

        These patterns used to reach a Validator with an accurate structured
        event but no proof because the earlier provider covered only generic
        source-to-sink pairs.  Each branch below requires the detector's
        field-sensitive event and a complete local path; it never treats a
        rule name or a model explanation as proof on its own.
        """

        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        rule = str(issue.get("rule") or "").lower()
        by_kind: Dict[str, list[Mapping[str, Any]]] = {}
        for event in events:
            kind = str(event.get("kind") or "").lower()
            if kind:
                by_kind.setdefault(kind, []).append(event)
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)

        def proof(
            kind: str,
            selected: Iterable[Mapping[str, Any]],
            facts: list[str],
            summary: str,
            subject: str = "",
        ) -> Dict[str, Any]:
            return EvidenceCompletionQueue._proof_from_ast(
                issue,
                outcome="confirm",
                proof_kind=kind,
                producer_engine="clang_ast_cfg_protocol_v11",
                events=selected,
                facts=facts,
                summary=summary,
                scope="完整的过程内所有权/并发协议路径",
                subject_identity=subject,
            )

        if rule == "clang_cfg_parent_release_without_owned_member_cleanup":
            leaks = by_kind.get("owned_member_leak", [])
            if len(leaks) == 1:
                member = EvidenceCompletionQueue._normalize_symbol(
                    leaks[0].get("variable")
                ).replace("->", ".")
                owner = member.rsplit(".", 1)[0] if "." in member else ""
                if (
                    owner
                    and re.search(
                        rf"\b(?:free)\s*\(\s*{re.escape(owner)}\s*\)",
                        code,
                        re.IGNORECASE,
                    )
                    and not re.search(
                        rf"\b(?:free)\s*\(\s*{re.escape(member.replace('.', '->'))}\s*\)",
                        code,
                        re.IGNORECASE,
                    )
                    and re.search(
                        rf"\b{re.escape(member.replace('.', '->'))}\s*=\s*"
                        r"(?:[A-Za-z_]\w*\s*\()?[^;]*(?:alloc|dup|open|create)[A-Za-z_0-9]*\s*\(",
                        code,
                        re.IGNORECASE,
                    )
                ):
                    return proof(
                        "owned_member_left_live_when_parent_released",
                        [leaks[0]],
                        ["field_sensitive_owned_member", "parent_release", "member_not_released"],
                        "被识别为归属成员的字段在其父对象被释放时仍然存活",
                        member,
                    )

        return None

    @staticmethod
    def _function_code(
        validation_evidence: Optional[Mapping[str, Any]],
        issue: Mapping[str, Any],
    ) -> str:
        evidence = _as_mapping(validation_evidence)
        function_context = _as_mapping(evidence.get("function_context"))
        return str(function_context.get("code") or issue.get("issue_code") or "")

    @staticmethod
    def _code_hash(code: str, issue: Mapping[str, Any]) -> str:
        return str(
            issue.get("dependency_code_hash")
            or issue.get("code_hash")
            or hashlib.sha256(code.encode("utf-8")).hexdigest()
        )

    @staticmethod
    def _evidence_code_hash(issue: Mapping[str, Any], evidence: Mapping[str, Any]) -> str:
        """Return a stable hash for structured code facts when source text is absent.

        The AST/CFG collector records source-derived statement facts even when
        a function body is intentionally omitted from the LLM validation
        context.  Hashing their canonical representation keeps a proof tied to
        the exact code snapshot instead of falling back to a hash of an empty
        string.
        """

        explicit = str(issue.get("dependency_code_hash") or issue.get("code_hash") or "")
        if explicit:
            return explicit
        encoded = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @staticmethod
    def _ast_pack(
        issue: Mapping[str, Any],
    ) -> tuple[Mapping[str, Any], Mapping[str, Any], list[Mapping[str, Any]]]:
        pack = _as_mapping(issue.get("evidence_pack"))
        ast_cfg = _as_mapping(pack.get("ast_cfg"))
        path = _as_mapping(pack.get("path"))
        events = [item for item in _as_list(ast_cfg.get("events")) if isinstance(item, Mapping)]
        return ast_cfg, path, events

    @staticmethod
    def _normalize_symbol(value: Any) -> str:
        return re.sub(r"\s+", "", str(value or "").lstrip("*&"))

    @staticmethod
    def _proof_from_ast(
        issue: Mapping[str, Any],
        *,
        outcome: str,
        proof_kind: str,
        producer_engine: str,
        events: Iterable[Mapping[str, Any]],
        facts: Iterable[str],
        summary: str,
        scope: str,
        subject_identity: str = "",
    ) -> Dict[str, Any]:
        selected = list(events)
        fact_ids = [
            f"ast_cfg:{item.get('line')}:{item.get('kind')}"
            for item in selected
            if item.get("line") not in (None, "") and item.get("kind")
        ]
        ast_cfg, _path, _events = EvidenceCompletionQueue._ast_pack(issue)
        return {
            "outcome": outcome,
            "proof_kind": proof_kind,
            "producer_engine": producer_engine,
            "proof_version": "zscope.decision-proof.v4",
            "fact_ids": fact_ids,
            "cfg_nodes": [
                str(item.get("line")) for item in selected if item.get("line") not in (None, "")
            ],
            "subject_identity": subject_identity,
            "code_hash": EvidenceCompletionQueue._evidence_code_hash(issue, ast_cfg),
            "facts": list(facts),
            "completeness": (
                "partial" if ast_cfg.get("unresolved_interface_effects") else "complete"
            ),
            "scope": scope,
            "summary": summary,
        }

    @staticmethod
    def _proof_from_code(
        issue: Mapping[str, Any],
        *,
        outcome: str,
        proof_kind: str,
        producer_engine: str,
        code: str,
        line_numbers: Iterable[int],
        facts: Iterable[str],
        summary: str,
        scope: str,
        subject_identity: str = "",
    ) -> Dict[str, Any]:
        lines = sorted({int(line) for line in line_numbers if int(line) > 0})
        if not lines:
            issue_line = EvidenceCompletionQueue._issue_line(issue)
            if issue_line > 0:
                lines = [issue_line]
        return {
            "outcome": outcome,
            "proof_kind": proof_kind,
            "producer_engine": producer_engine,
            "proof_version": "zscope.decision-proof.v4",
            "fact_ids": [f"source_cfg:{line}" for line in lines],
            "cfg_nodes": [str(line) for line in lines],
            "subject_identity": subject_identity,
            "code_hash": EvidenceCompletionQueue._code_hash(code, issue),
            "facts": list(facts),
            "completeness": "complete",
            "scope": scope,
            "summary": summary,
        }

    @staticmethod
    def _issue_line(issue: Mapping[str, Any]) -> int:
        try:
            line = int(issue.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        if line > 0:
            return line
        for key in (
            "location",
            "primary_location",
            "source_location",
            "sink_location",
        ):
            value = str(issue.get(key) or "")
            match = re.search(r":(\d+)(?::\d+)?(?:\D.*)?$", value)
            if match:
                return int(match.group(1))
        return 0

    @staticmethod
    def _code_lines(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> list[str]:
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code or len(code) > 64 * 1024:
            return []
        return code.splitlines()

    @staticmethod
    def _lock_argument(text: str, *, acquire: bool) -> str:
        names = (
            r"(?:pthread_mutex_lock|pthread_rwlock_(?:rdlock|wrlock))"
            if acquire
            else r"(?:pthread_mutex_unlock|pthread_rwlock_unlock)"
        )
        match = re.search(rf"\b{names}\s*\(\s*&?([^,)]+)", text)
        return EvidenceCompletionQueue._normalize_symbol(match.group(1)) if match else ""

    @staticmethod
    def _balanced_lock_protocol_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Prove only a straight-line, trusted, explicitly paired protocol."""
        from ...semantics.defaults import default_local_pattern_semantics

        rule = str(issue.get("rule") or "").lower()
        if rule not in {
            "clang_cfg_return_with_lock_held",
            "clang_cfg_unlock_without_matching_lock",
        }:
            return None
        _, path, _ = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        code = "\n".join(lines)
        if re.search(r"\b(?:if|else|goto|switch|case|for|while)\b", code):
            return None
        semantics = default_local_pattern_semantics()
        pack = issue.get("evidence_pack") or {}
        overlay = (
            (validation_evidence or {}).get("semantic_contracts")
            or issue.get("semantic_contracts")
            or pack.get("semantic_contracts")
            or {}
        )
        semantics.merge_overlay(dict(overlay))
        registry = semantics.contracts
        for contract in registry.contracts:
            if contract.role in {"lock", "unlock"} and re.search(
                rf"\b{re.escape(contract.symbol.name)}\s*\(", code
            ):
                if contract.source.startswith("inferred") or contract.conditions:
                    return None
        names = set(semantics.lock_apis) | set(semantics.unlock_apis)
        pattern = re.compile(
            r"\b(?P<api>"
            + "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
            + r")\s*\((?P<args>[^)]*)\)"
        )
        held: list[tuple[str, str]] = []
        seen_acquire = False
        returns = []
        for number, line in enumerate(lines, 1):
            for match in pattern.finditer(line):
                api = match["api"]
                role = "lock" if api in semantics.lock_apis else "unlock"
                if registry.effect_status(api, role, line) != "applies":
                    return None
                obj = registry.resolve_object(api, role, match["args"].split(","))
                if not obj:
                    return None
                if role == "lock":
                    held.append((api, obj))
                    seen_acquire = True
                else:
                    index = next(
                        (
                            i
                            for i in range(len(held) - 1, -1, -1)
                            if held[i][1] == obj
                            and registry.release_in_text(held[i][0], api, line, obj) == "applies"
                        ),
                        None,
                    )
                    if index is None:
                        return None
                    held.pop(index)
            if re.search(r"\breturn\b", line):
                returns.append(number)
                if held:
                    return None
        if held or not seen_acquire:
            return None
        if not returns:
            # A straight-line void function exits at its closing brace.
            returns = [len(lines)]
        return EvidenceCompletionQueue._proof_from_code(
            issue,
            outcome="reject",
            proof_kind="balanced_lock_return_paths",
            producer_engine="clang_ast_cfg_lock_protocol",
            code=code,
            line_numbers=returns,
            facts=["all_return_paths_unlocked"],
            summary="Every return follows an explicit compatible release of the same lock.",
            scope="complete straight-line lock protocol",
        )

    @staticmethod
    def _allocation_copy_capacity_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Reject a copy-overflow claim when a complete capacity relation is explicit."""

        if str(issue.get("rule") or "").lower() not in {
            "clang_cfg_narrowed_allocation_original_length_copy",
            "clang_cfg_heap_copy_length_mismatch",
        }:
            return None
        _ast_cfg, path, _events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        allocations: dict[str, tuple[str, int]] = {}
        for index, text in enumerate(lines, start=1):
            match = re.search(
                r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^;=]+\)\s*)?"
                r"(?:malloc|calloc)\s*\(\s*(?P<size>[^,)]+)",
                text,
                re.IGNORECASE,
            )
            if match:
                allocations[match.group("var")] = (match.group("size").replace(" ", ""), index)
        for index, text in enumerate(lines, start=1):
            call = re.search(
                r"\b(?:memcpy|memmove)\s*\(\s*(?P<dst>[A-Za-z_]\w*)\s*,[^,]+,\s*(?P<len>[^)]+)\)",
                text,
            )
            if not call or call.group("dst") not in allocations:
                continue
            size, allocation_line = allocations[call.group("dst")]
            length = call.group("len").replace(" ", "")
            plus_one = re.fullmatch(r"\(?([A-Za-z_]\w*)\+1\)?", size)
            if plus_one is None or plus_one.group(1) != length:
                continue
            # A terminating overflow guard is the explicit source-derived
            # witness that makes ``n + 1`` a complete capacity proof.
            symbol = plus_one.group(1)
            guard = next(
                (
                    guard_line
                    for guard_line, item in enumerate(lines[: allocation_line - 1], start=1)
                    if re.search(
                        rf"\b{re.escape(symbol)}\b\s*>=\s*(?:SIZE_MAX|UINT(?:32|64)_MAX|[A-Z][A-Z0-9_]*)",
                        item,
                    )
                    and re.search(r"\breturn\b", "\n".join(lines[guard_line - 1 : guard_line + 3]))
                ),
                0,
            )
            if not guard:
                continue
            return EvidenceCompletionQueue._proof_from_code(
                issue,
                outcome="reject",
                proof_kind="allocation_capacity_dominates_copy",
                producer_engine="clang_ast_cfg_capacity_relation",
                code=code,
                line_numbers=[guard, allocation_line, index],
                facts=["allocation_capacity_exceeds_copy", "same_length_symbol"],
                summary="受防护的 n + 1 字节分配支配 n 字节的拷贝",
                scope="完整的分配到拷贝容量关系",
                subject_identity=call.group("dst"),
            )
        return None

    @staticmethod
    def _failed_member_acquisition_cleanup_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Reject parent-member leak reports on an allocation-failure-only branch."""

        if (
            str(issue.get("rule") or "").lower()
            != "clang_cfg_parent_release_without_owned_member_cleanup"
        ):
            return None
        _ast_cfg, path, _events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        source = str(issue.get("source") or "")
        member_match = re.search(r"\b([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)", source)
        parent_match = re.search(r"free\s*\(\s*([A-Za-z_]\w*)\s*\)", str(issue.get("sink") or ""))
        if not member_match or not parent_match or member_match.group(1) != parent_match.group(1):
            return None
        parent, member = member_match.groups()
        pattern = re.compile(rf"if\s*\(\s*!\s*{re.escape(parent)}\s*->\s*{re.escape(member)}\s*\)")
        for index, text in enumerate(lines, start=1):
            if not pattern.search(text):
                continue
            window = "\n".join(lines[index - 1 : index + 5])
            if not re.search(rf"free\s*\(\s*{re.escape(parent)}\s*\)", window):
                continue
            if not re.search(r"\breturn\b", window):
                continue
            return EvidenceCompletionQueue._proof_from_code(
                issue,
                outcome="reject",
                proof_kind="failed_member_acquisition_cleanup",
                producer_engine="clang_ast_cfg_ownership",
                code=code,
                line_numbers=[index],
                facts=["member_acquisition_failed", "parent_cleanup_on_failure_only"],
                summary="父对象仅在其归属成员获取失败的分支上被释放",
                scope="完整的成员获取失败分支",
                subject_identity=f"{parent}->{member}",
            )
        return None

    @staticmethod
    def _pointer_offset_provenance_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Distinguish pointer-relative buffer access from integer-to-pointer use."""

        if str(issue.get("rule") or "").lower() != "clang_cfg_wire_integer_cast_to_pointer_deref":
            return None
        _ast_cfg, path, _events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        pointer_params = {
            item for item in re.findall(r"\b[A-Za-z_]\w*\s*\*\s*([A-Za-z_]\w*)", code.split("{")[0])
        }
        for index, text in enumerate(lines, start=1):
            match = re.search(
                r"\([^)]*\*[^)]*\)\s*\(\s*([A-Za-z_]\w*)\s*\+\s*[^)]+\)",
                text,
            )
            if not match or match.group(1) not in pointer_params:
                continue
            return EvidenceCompletionQueue._proof_from_code(
                issue,
                outcome="reject",
                proof_kind="pointer_offset_not_data_pointer",
                producer_engine="clang_ast_cfg_pointer_provenance",
                code=code,
                line_numbers=[index],
                facts=["pointer_derived_from_pointer_base", "not_data_integer_cast"],
                summary="所报告的转换来自指针参数加偏移，而非序列化的整数数据",
                scope="完整的本地指针来源",
                subject_identity=match.group(1),
            )
        return None

    @staticmethod
    def _async_stack_escape_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Confirm a local stack address escaping through an asynchronous worker."""

        category = str(issue.get("defect_class") or issue.get("category") or "").lower()
        rule = str(issue.get("rule") or "").lower()
        if category != "stack_escape" and rule != "clang_cfg_stack_address_passed_to_thread":
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        stack_events = [
            item for item in events if str(item.get("kind") or "").lower() == "stack_object"
        ]
        escape_events = [
            item for item in events if str(item.get("kind") or "").lower() == "thread_arg_escape"
        ]
        if not stack_events or not escape_events:
            return None
        stack = stack_events[0]
        escaped = next(
            (
                item
                for item in escape_events
                if EvidenceCompletionQueue._normalize_symbol(item.get("variable"))
                == EvidenceCompletionQueue._normalize_symbol(stack.get("variable"))
            ),
            None,
        )
        if escaped is None:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        escape_line = int(escaped.get("line") or 0)
        # The asynchronous lifetime proof is deliberately strict: detached
        # worker creation is enough, while a join before every return negates
        # the escape.  A non-detached thread without a join remains reviewable.
        detached = bool(re.search(r"\bpthread_detach\s*\(", code))
        joined_after_escape = any(
            re.search(r"\bpthread_join\s*\(", text) for text in lines[max(escape_line, 0) :]
        )
        if not detached or joined_after_escape:
            return None
        return EvidenceCompletionQueue._proof_from_ast(
            issue,
            outcome="confirm",
            proof_kind="async_stack_address_escape",
            producer_engine="clang_ast_cfg_async_lifetime",
            events=[stack, escaped],
            facts=["stack_object_address_escapes", "async_lifetime_unbounded"],
            summary="本地栈对象被传递给分离线程，且没有配套的 join",
            scope="完整的本地异步线程交接",
            subject_identity=EvidenceCompletionQueue._normalize_symbol(stack.get("variable")),
        )

    @staticmethod
    def _container_unlink_without_release_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Confirm an unlinked container owner that has no release or transfer path."""

        rule = str(issue.get("rule") or "").lower()
        if rule not in {
            "container_unlink_without_release",
            "clang_cfg_container_unlink_without_release",
        }:
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        unlink_events = [
            item
            for item in events
            if str(item.get("kind") or "").lower()
            in {"container_unlink", "container_detach", "ownership_unlink"}
        ]
        if not unlink_events:
            lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
            if not lines:
                return None
            for index, text in enumerate(lines, start=1):
                if re.search(r"\*\s*[A-Za-z_]\w*\s*=\s*[A-Za-z_]\w*\s*->\s*next", text):
                    unlink_events = [
                        {"kind": "container_unlink", "line": index, "expression": text}
                    ]
                    break
        if not unlink_events:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        unlink_line = int(unlink_events[0].get("line") or 0)
        remainder = "\n".join(lines[unlink_line:])
        subject = EvidenceCompletionQueue._normalize_symbol(
            unlink_events[0].get("variable") or issue.get("resource_identity")
        )
        if not subject:
            assign = re.search(
                r"\*\s*[A-Za-z_]\w*\s*=\s*([A-Za-z_]\w*)\s*->\s*next",
                str(unlink_events[0].get("expression") or ""),
            )
            subject = assign.group(1) if assign else ""
        if not subject:
            return None
        if re.search(
            rf"\b(?:free)\s*\(\s*{re.escape(subject)}\b",
            remainder,
            re.IGNORECASE,
        ):
            return None
        if re.search(rf"\b(?:return|\*)\s*{re.escape(subject)}\b", remainder):
            return None
        return EvidenceCompletionQueue._proof_from_code(
            issue,
            outcome="confirm",
            proof_kind="container_unlink_without_release",
            producer_engine="clang_ast_cfg_container_ownership",
            code=code,
            line_numbers=[unlink_line],
            facts=["container_owner_unlinked", "ownership_not_transferred_or_released"],
            summary="容器所有权链接被移除，其后对被分离对象没有任何释放或转移",
            scope="完整的本地容器分离路径",
            subject_identity=subject,
        )

    @staticmethod
    def _lock_held_on_failure_return_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Confirm a failure branch that returns while a local lock remains held."""

        if str(issue.get("rule") or "").lower() != "clang_cfg_return_with_lock_held":
            return None
        _ast_cfg, path, _events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        held: list[tuple[str, int]] = []
        for index, text in enumerate(lines, start=1):
            acquired = EvidenceCompletionQueue._lock_argument(text, acquire=True)
            if acquired:
                held.append((acquired, index))
            released = EvidenceCompletionQueue._lock_argument(text, acquire=False)
            if released:
                match_index = next(
                    (item for item in range(len(held) - 1, -1, -1) if held[item][0] == released),
                    -1,
                )
                if match_index >= 0:
                    held.pop(match_index)
            if not (held and re.search(r"\breturn\s*-?(?:1|[A-Za-z_]\w*)\s*;", text)):
                continue
            # A return inside a failure branch is a complete witness only if a
            # preceding condition names the failed acquisition or NULL guard.
            preceding = "\n".join(lines[max(0, index - 5) : index])
            if not re.search(r"\bif\s*\([^)]*(?:!|==\s*NULL|<\s*0)", preceding):
                continue
            lock, lock_line = held[-1]
            return EvidenceCompletionQueue._proof_from_code(
                issue,
                outcome="confirm",
                proof_kind="lock_held_on_failure_return",
                producer_engine="clang_ast_cfg_lock_protocol",
                code=code,
                line_numbers=[lock_line, index],
                facts=["lock_acquired_before_failure", "failure_returns_with_lock_held"],
                summary="失败分支在匹配的本地加锁之后返回，且中途没有解锁",
                scope="完整的本地失败返回锁路径",
                subject_identity=lock,
            )
        return None

    @staticmethod
    def _incomplete_owner_cleanup_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Confirm a field-sensitive cleanup that omits initialized owner members."""

        category = str(issue.get("defect_class") or issue.get("category") or "").lower()
        rule = str(issue.get("rule") or "").lower()
        if category not in {"incomplete_cleanup", "memory_leak"} and "member_cleanup" not in rule:
            return None
        _ast_cfg, path, _events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        initialized: dict[str, set[str]] = {}
        released: dict[str, set[str]] = {}
        for index, text in enumerate(lines, start=1):
            assignment = re.search(
                r"\b(?P<owner>[A-Za-z_]\w*(?:(?:\s*->\s*|\s*\.\s*)[A-Za-z_]\w+)*?)\s*(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)\s*=\s*"
                r"(?P<api>[A-Za-z_]\w*)\s*\(",
                text,
                re.IGNORECASE,
            )
            if assignment and re.search(
                r"(?:alloc|dup|open|create)", assignment.group("api"), re.IGNORECASE
            ):
                owner = EvidenceCompletionQueue._normalize_symbol(assignment.group("owner"))
                initialized.setdefault(owner, set()).add(assignment.group("field"))
            cleanup = re.search(
                r"\b(?:free|close|release)\s*\(\s*(?P<owner>[A-Za-z_]\w*(?:(?:\s*->\s*|\s*\.\s*)[A-Za-z_]\w+)*?)\s*(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)",
                text,
                re.IGNORECASE,
            )
            if cleanup:
                owner = EvidenceCompletionQueue._normalize_symbol(cleanup.group("owner"))
                released.setdefault(owner, set()).add(cleanup.group("field"))
        for owner, fields in initialized.items():
            missing = fields - released.get(owner, set())
            if len(fields) < 2 or not missing:
                continue
            owner_release_line = next(
                (
                    index
                    for index, text in enumerate(lines, start=1)
                    if re.search(
                        rf"\b(?:free|close)\s*\(\s*"
                        rf"(?:{re.escape(owner.replace('.', '->'))}|{re.escape(owner)})"
                        rf"(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)?",
                        text,
                        re.IGNORECASE,
                    )
                ),
                0,
            )
            if not owner_release_line:
                continue
            return EvidenceCompletionQueue._proof_from_code(
                issue,
                outcome="confirm",
                proof_kind="incomplete_owner_cleanup",
                producer_engine="clang_ast_cfg_ownership",
                code=code,
                line_numbers=[owner_release_line],
                facts=["multiple_owned_members_initialized", "owned_member_not_released"],
                summary="清理/重置路径释放了所有者，但已初始化的归属成员仍未被清理",
                scope="完整的字段敏感所有者清理路径",
                subject_identity=owner,
            )
        return None

    @staticmethod
    def _ast_guard_dominance_proof(issue: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Reject a null-dereference candidate using AST guard and CFG facts.

        This is deliberately stricter than a textual nearby-check heuristic:
        the acquisition, guard, terminating return and reported dereference
        must belong to one complete intraprocedural path, and all reference the
        same normalized value.
        """

        if str(issue.get("rule") or "").lower() not in {
            "clang_cfg_allocation_result_used_without_null_check",
            "clang_cfg_alloc_result_deref_without_null_guard",
        }:
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        acquires = [
            item
            for item in events
            if str(item.get("kind") or "").lower() in {"acquire", "allocation_result"}
        ]
        uses = [
            item
            for item in events
            if str(item.get("kind") or "").lower() in {"deref", "unchecked_allocation_use"}
        ]
        guards = _as_list(ast_cfg.get("condition_guards"))
        returns = _as_list(_as_mapping(ast_cfg.get("scope_summary")).get("return_lines"))
        if not isinstance(returns, list):
            return None
        for acquire in acquires:
            symbol = EvidenceCompletionQueue._normalize_symbol(acquire.get("variable"))
            acquire_line = int(acquire.get("line") or 0)
            if not symbol or acquire_line <= 0:
                continue
            for use in uses:
                use_line = int(use.get("line") or 0)
                if (
                    EvidenceCompletionQueue._normalize_symbol(use.get("variable")) != symbol
                    or use_line < acquire_line
                ):
                    continue
                for guard in guards:
                    if not isinstance(guard, Mapping):
                        continue
                    guard_line = int(guard.get("line") or 0)
                    condition = str(guard.get("condition") or "")
                    null_check = re.compile(
                        rf"(?:!\s*\*?\s*{re.escape(symbol)}\b|\*?\s*{re.escape(symbol)}\s*==\s*(?:NULL|nullptr|0)\b|(?:NULL|nullptr|0)\s*==\s*\*?\s*{re.escape(symbol)}\b)"
                    )
                    if not (acquire_line < guard_line <= use_line and null_check.search(condition)):
                        continue
                    # A return immediately after (or in the same tiny branch
                    # as) the guard is the conservative local termination
                    # witness available in the fact model.
                    if not any(
                        guard_line < int(line) <= guard_line + 3
                        for line in returns
                        if isinstance(line, int)
                    ):
                        continue
                    return EvidenceCompletionQueue._proof_from_ast(
                        issue,
                        outcome="reject",
                        proof_kind="guard_dominates_sink",
                        producer_engine="clang_ast_cfg_guard_dominance",
                        events=[acquire, {"kind": "null_guard", "line": guard_line}, use],
                        facts=[
                            "same_symbol",
                            "terminating_null_guard",
                            "guard_dominates_reported_use",
                            "guard_dominates_sink",
                        ],
                        summary="终止性 null 防护支配所报告的分配使用",
                        scope="完整的过程内分配到使用路径",
                        subject_identity=symbol,
                    )
        return None

    @staticmethod
    def _fd_transfer_or_failure_proof(issue: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Reject FD-leak candidates proven to be failed acquisition or transfer.

        A descriptor is not leaked on the branch where acquisition explicitly
        failed.  Likewise, returning the descriptor transfers ownership to the
        caller. A global-looking name or a member write does not establish a
        durable owner; those cases require an explicit ownership proof.
        """

        if str(issue.get("rule") or "").lower() != "clang_cfg_fd_open_return_without_close":
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path and path.get("complete_in_function") is not True:
            return None
        opens = [item for item in events if str(item.get("kind") or "").lower() == "fd_open"]
        exits = [
            item
            for item in events
            if str(item.get("kind") or "").lower() == "return_without_fd_close"
        ]
        guards = _as_list(ast_cfg.get("condition_guards"))
        for opened in opens:
            fd = EvidenceCompletionQueue._normalize_symbol(opened.get("variable"))
            open_line = int(opened.get("line") or 0)
            expression = str(opened.get("expression") or "")
            if not fd or open_line <= 0:
                continue
            lhs = expression.split("=", 1)[0].strip() if "=" in expression else ""
            for exited in exits:
                exit_line = int(exited.get("line") or 0)
                return_expression = str(exited.get("expression") or "")
                if exit_line <= open_line:
                    continue
                if re.search(rf"\breturn\s+{re.escape(fd)}\s*;", return_expression):
                    return EvidenceCompletionQueue._proof_from_ast(
                        issue,
                        outcome="reject",
                        proof_kind="return_value_ownership_transfer",
                        producer_engine="clang_ast_cfg_fd_ownership",
                        events=[opened, exited],
                        facts=["descriptor_returned_to_caller", "ownership_transfer_complete"],
                        summary="描述符作为所有权结果返回给调用方",
                        scope="描述符所有权转移",
                        subject_identity=fd,
                    )
                if not re.search(r"\breturn\s*-1\s*;", return_expression):
                    continue
                for guard in guards:
                    if not isinstance(guard, Mapping):
                        continue
                    guard_line = int(guard.get("line") or 0)
                    condition = str(guard.get("condition") or "")
                    failed_fd = re.compile(
                        rf"\b{re.escape(fd)}\s*(?:<|<=)\s*(?:0|-1)\b|\b{re.escape(fd)}\s*==\s*-1\b"
                    )
                    path_constraints = [
                        str(value) for value in _as_list(path.get("path_constraints"))
                    ]
                    guard_is_on_path = any(
                        f"line {guard_line}:" in constraint for constraint in path_constraints
                    )
                    if (
                        open_line < guard_line < exit_line
                        and (guard_is_on_path or exit_line - guard_line <= 3)
                        and failed_fd.search(condition)
                    ):
                        return EvidenceCompletionQueue._proof_from_ast(
                            issue,
                            outcome="reject",
                            proof_kind="failed_acquisition_exit",
                            producer_engine="clang_ast_cfg_fd_ownership",
                            events=[
                                opened,
                                {"kind": "fd_failure_guard", "line": guard_line},
                                exited,
                            ],
                            facts=["fd_failure_guard", "failure_return"],
                            summary="所报告的 return 受失败的描述符获取所防护",
                            scope="描述符获取失败分支",
                            subject_identity=fd,
                        )
        return None

    @staticmethod
    def _allocation_context_proof(issue: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Reject allocation-limit leads when a complete local fact disproves them.

        The provider does not guess that a caller has a limit.  It accepts only
        an explicit terminating upper-bound guard in the same function.  An
        allocation-wrapper body without a caller fact remains a triage signal,
        not a rejection proof: missing caller evidence cannot prove that no
        reachable caller controls the allocation size.
        """

        if (
            str(issue.get("rule") or "").lower()
            != "clang_cfg_external_size_allocation_without_limit"
        ):
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        allocations = [
            item for item in events if str(item.get("kind") or "").lower() == "unbounded_allocation"
        ]
        guards = _as_list(ast_cfg.get("condition_guards"))
        summary = _as_mapping(ast_cfg.get("scope_summary"))
        returns = _as_list(summary.get("return_lines"))
        for allocation in allocations:
            expression = str(allocation.get("expression") or "")
            line = int(allocation.get("line") or 0)
            terms = {
                token
                for token in re.findall(r"\b[A-Za-z_]\w*\b", str(allocation.get("variable") or ""))
                if token.lower() not in {"size", "sizeof", "void", "char", "int", "long", "short"}
            }
            if not terms or line <= 0:
                continue
            for guard in guards:
                if not isinstance(guard, Mapping):
                    continue
                guard_line = int(guard.get("line") or 0)
                condition = str(guard.get("condition") or "")
                bounded = any(
                    re.search(rf"\b{re.escape(term)}\s*>\s*(?:[A-Z][A-Z0-9_]*|\d+)\b", condition)
                    for term in terms
                )
                if not (
                    bounded
                    and guard_line < line
                    and any(
                        guard_line < int(ret) <= guard_line + 3
                        for ret in returns
                        if isinstance(ret, int)
                    )
                ):
                    continue
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="terminating_allocation_upper_bound",
                    producer_engine="clang_ast_cfg_allocation_context",
                    events=[allocation, {"kind": "upper_bound_guard", "line": guard_line}],
                    facts=[
                        "explicit_upper_bound",
                        "terminating_guard",
                        "guard_dominates_allocation",
                    ],
                    summary="终止性上界防护支配该分配",
                    scope="完整的过程内分配路径",
                )
        return None

    @staticmethod
    def _array_shape_rejection_proof(issue: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Reject fixed-array leads contradicted by the structured array facts."""

        if str(issue.get("rule") or "").lower() != "clang_cfg_unbounded_count_indexes_fixed_array":
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        by_kind = {str(item.get("kind") or "").lower(): item for item in events}
        fixed = by_kind.get("fixed_array")
        loop = by_kind.get("count_loop")
        write = by_kind.get("array_write")
        if not (fixed and loop and write):
            return None
        fixed_var = EvidenceCompletionQueue._normalize_symbol(fixed.get("variable"))
        write_var = EvidenceCompletionQueue._normalize_symbol(write.get("variable"))
        write_expression = str(write.get("expression") or "")
        if (
            fixed_var
            and write_var
            and (
                fixed_var != write_var
                or (
                    bool(write_expression)
                    and not re.search(rf"\b{re.escape(fixed_var)}\s*\[", write_expression)
                )
            )
        ):
            return EvidenceCompletionQueue._proof_from_ast(
                issue,
                outcome="reject",
                proof_kind="array_sink_identity_mismatch",
                producer_engine="clang_ast_cfg_bounds",
                events=[fixed, write],
                facts=["fixed_array_identity", "write_identity_mismatch"],
                summary="所报告的写入目标与建模的定长数组不是同一对象",
                scope="完整的过程内数组访问路径",
                subject_identity=f"{fixed_var}!={write_var}",
            )
        declarations = _as_list(ast_cfg.get("declarations"))
        if fixed_var and any(
            isinstance(item, Mapping)
            and EvidenceCompletionQueue._normalize_symbol(item.get("name")) == fixed_var
            and int(item.get("pointer_depth") or 0) > 0
            for item in declarations
        ):
            return EvidenceCompletionQueue._proof_from_ast(
                issue,
                outcome="reject",
                proof_kind="dynamic_array_not_fixed_storage",
                producer_engine="clang_ast_cfg_bounds",
                events=[fixed, write],
                facts=["pointer_declaration", "dynamic_array_storage"],
                summary="被索引对象声明为动态指针存储，而非定长数组",
                scope="完整的过程内数组访问路径",
                subject_identity=fixed_var,
            )
        loop_expression = str(loop.get("expression") or "")
        count_match = re.search(r"<\s*([A-Za-z_]\w*)", loop_expression)
        count = count_match.group(1) if count_match else ""
        guards = _as_list(ast_cfg.get("condition_guards"))
        summary = _as_mapping(ast_cfg.get("scope_summary"))
        returns = _as_list(summary.get("return_lines"))
        for guard in guards:
            if not isinstance(guard, Mapping):
                continue
            guard_line = int(guard.get("line") or 0)
            condition = str(guard.get("condition") or "")
            has_bound = bool(
                count
                and re.search(
                    rf"\b{re.escape(count)}\s*>\s*(?:ARRAY_SIZE\s*\(\s*{re.escape(fixed_var)}\b|[A-Z][A-Z0-9_]*)",
                    condition,
                )
            )
            if has_bound and any(
                guard_line < int(ret) <= guard_line + 3 for ret in returns if isinstance(ret, int)
            ):
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="array_bound_guard_dominates_loop",
                    producer_engine="clang_ast_cfg_bounds",
                    events=[fixed, {"kind": "array_bound_guard", "line": guard_line}, loop, write],
                    facts=[
                        "fixed_array_bound",
                        "terminating_upper_bound_guard",
                        "guard_dominates_loop",
                    ],
                    summary="终止性数组大小防护支配该计数循环",
                    scope="完整的过程内定长数组循环",
                    subject_identity=fixed_var,
                )
        return None

    @staticmethod
    def _resource_transfer_proof(issue: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Reject leak leads whose ownership transfer is explicit in AST facts."""

        if str(issue.get("rule") or "").lower() != "clang_cfg_acquire_without_release_on_exit":
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        acquires = [item for item in events if str(item.get("kind") or "").lower() == "acquire"]
        exits = [item for item in events if str(item.get("kind") or "").lower() == "exit"]
        for acquire in acquires:
            expression = str(acquire.get("expression") or "")
            lhs = expression.split("=", 1)[0].strip() if "=" in expression else ""
            if lhs.startswith("*"):
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="output_parameter_ownership_transfer",
                    producer_engine="clang_ast_cfg_ownership",
                    events=[acquire],
                    facts=["resource_stored_in_output_parameter", "ownership_transfer_complete"],
                    summary="资源通过输出所有权参数返回",
                    scope="资源所有权转移",
                    subject_identity=lhs,
                )
            parent = lhs.split("->", 1)[0].strip() if "->" in lhs else ""
            if parent and any(
                re.search(
                    rf"\breturn\s+{re.escape(parent)}\s*;", str(exited.get("expression") or "")
                )
                for exited in exits
            ):
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="returned_parent_ownership_transfer",
                    producer_engine="clang_ast_cfg_ownership",
                    events=[acquire, *exits],
                    facts=[
                        "resource_stored_in_parent",
                        "parent_returned_to_caller",
                        "ownership_transfer_complete",
                    ],
                    summary="持有该资源的父对象被返回给调用方",
                    scope="资源所有权转移",
                    subject_identity=parent,
                )
        return None

    @staticmethod
    def _guard_dominance_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Prove an allocation result is checked on every local failure path.

        This provider only accepts an explicit null condition followed by a
        terminating return/goto before the reported dereference.  It therefore
        rejects neither merely adjacent checks nor non-terminating logging
        branches.
        """

        if str(issue.get("rule") or "").lower() not in {
            "clang_cfg_allocation_result_used_without_null_check",
            "clang_cfg_alloc_result_deref_without_null_guard",
        }:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        source = str(issue.get("source") or "")
        sink = str(issue.get("sink") or "")
        if not code or not source or not sink or len(code) > 64 * 1024:
            return None
        allocation = re.search(r"\b(?P<var>[A-Za-z_]\w*)\s*=", source)
        if allocation is None:
            return None
        var = allocation.group("var")
        lines = code.splitlines()
        source_index = next((i for i, line in enumerate(lines) if source.strip() in line), -1)
        sink_index = next(
            (i for i in range(source_index + 1, len(lines)) if sink.strip() in lines[i]),
            -1,
        )
        if source_index < 0 or sink_index < 0:
            return None
        null_condition = re.compile(
            rf"(?:!\s*{re.escape(var)}\b|\b{re.escape(var)}\s*==\s*(?:NULL|nullptr|0)\b|\b(?:NULL|nullptr|0)\s*==\s*{re.escape(var)}\b)"
        )
        for index in range(source_index + 1, sink_index):
            if not re.search(r"\bif\s*\(", lines[index]) or not null_condition.search(lines[index]):
                continue
            branch = lines[index]
            brace_depth = branch.count("{") - branch.count("}")
            end = index + 1
            if brace_depth > 0:
                while end < sink_index and brace_depth > 0:
                    brace_depth += lines[end].count("{") - lines[end].count("}")
                    branch += "\n" + lines[end]
                    end += 1
            if re.search(r"\b(?:return|goto)\b", branch):
                return {
                    "outcome": "reject",
                    "proof_kind": "guard_dominates_sink",
                    "producer_engine": "clang_ast_cfg_guard_dominance",
                    "fact_ids": [
                        f"cfg:{source_index + 1}",
                        f"cfg:{index + 1}",
                        f"cfg:{sink_index + 1}",
                    ],
                    "cfg_nodes": [str(source_index + 1), str(index + 1), str(sink_index + 1)],
                    "subject_identity": var,
                    "code_hash": EvidenceCompletionQueue._code_hash(code, issue),
                    "facts": ["guard_dominates_sink"],
                    "completeness": "complete",
                    "scope": f"经所报告解引用到达的分配 `{var}`",
                    "summary": f"针对 `{var}` 的终止性 NULL 防护支配所报告的使用",
                }
        return None

    @staticmethod
    def _distinct_object_identity_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Reject a same-object lifetime claim when full access paths differ."""

        if str(issue.get("rule") or "").lower() not in {
            "clang_cfg_same_object_released_twice",
            "clang_cfg_use_after_release",
        }:
            return None
        source = str(issue.get("source") or "")
        sink = str(issue.get("sink") or "")
        source_path = EvidenceCompletionQueue._longest_access_path(source)
        sink_path = EvidenceCompletionQueue._longest_access_path(sink)
        if not source_path or not sink_path or source_path == sink_path:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code:
            return None
        return {
            "outcome": "reject",
            "proof_kind": "distinct_object_identity",
            "producer_engine": "clang_ast_cfg_field_identity",
            "fact_ids": [f"object:{source_path}", f"object:{sink_path}"],
            "subject_identity": f"{source_path}!={sink_path}",
            "code_hash": EvidenceCompletionQueue._code_hash(code, issue),
            "facts": ["distinct_object_identity"],
            "completeness": "complete",
            "scope": "源对象与汇点的访问路径",
            "summary": f"`{source_path}` 与 `{sink_path}` 是不同的对象访问路径",
        }

    @staticmethod
    def _longest_access_path(text: str) -> str:
        candidates = re.findall(
            r"\b[A-Za-z_]\w*(?:(?:\s*->\s*|\s*\.\s*)[A-Za-z_]\w+|\s*\[[^\]]+\])+",
            text,
        )
        if not candidates:
            return ""
        return re.sub(r"\s+", "", max(candidates, key=len))

    _FREE_CALL_RE = re.compile(r"\b(?:free)\s*\(\s*([^)]*)\)")
    _SINK_IS_FREE_RE = re.compile(r"^\s*(?:free)\s*\(")
    _IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")
    _SINK_RESERVED = {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "sizeof",
        "else",
        "do",
        "case",
        "break",
        "continue",
        "NULL",
        "free",
        "const",
        "unsigned",
        "signed",
        "struct",
        "size_t",
    }

    @staticmethod
    def _infunction_release_contradiction(sink_expression: str, function_code: str) -> bool:
        """Return True when the function body frees an object named in the sink.

        Deterministic and purely textual: the obligation sink names an object
        (call arguments, or the assigned value of a store); if the same
        function body contains a ``free``/``free`` of that identifier,
        the acquire/release obligation is self-contradicted.  Same-name means
        same variable intraprocedurally, so this cannot cross functions.
        """
        sink = str(sink_expression or "").strip()
        if not sink or not str(function_code or "").strip():
            return False
        # For call-shaped sinks only the arguments name the obligation object;
        # the callee identifier itself is never the freed object.
        inner = sink
        call = re.match(r"^[A-Za-z_]\w*\s*\((.*)\)\s*;?\s*$", sink, re.S)
        if call:
            inner = call.group(1)
        tokens = {
            token
            for token in EvidenceCompletionQueue._IDENT_RE.findall(inner)
            if token not in EvidenceCompletionQueue._SINK_RESERVED
        }
        if not tokens:
            return False
        for match in EvidenceCompletionQueue._FREE_CALL_RE.finditer(str(function_code)):
            freed = {
                token
                for token in EvidenceCompletionQueue._IDENT_RE.findall(match.group(1) or "")
                if token not in EvidenceCompletionQueue._SINK_RESERVED
            }
            if freed & tokens:
                return True
        return False

    @staticmethod
    def _cfg_obligation_confirmation_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Confirm a small set of complete, deterministic CFG obligations.

        These are not model classifications.  Every accepted shape requires a
        complete intraprocedural path and both ends of a semantically specific
        event pair (or a three-event state transition).  Broad heuristic rules
        such as generic leaks and unconstrained allocations intentionally do
        not appear here because their ownership/contract evidence is not yet
        complete.
        """

        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        event_kinds = {
            str(item.get("kind") or "").strip().lower()
            for item in events
            if isinstance(item, Mapping)
        }
        if not event_kinds or path.get("complete_in_function") is not True:
            return None

        # Each event set captures a complete source-to-sink safety obligation,
        # not merely a suspicious API name.  The categories are deliberately
        # generic across C/C++ projects and do not depend on project paths,
        # function names, descriptions, or model prose.  The rule-specific
        # contracts below prevent an otherwise identical low-level event from
        # being reinterpreted as a different vulnerability family.
        obligation_shapes = (
            {"uninitialized_pointer_decl", "uninitialized_pointer_use"},
            {"header_length", "header_length_copy"},
            {"wide_count_read", "wide_count_sink"},
            {"length_field_load", "copy_length_use"},
            {"offset_pointer", "offset_length_copy"},
            {"unaligned_pointer_cast", "unaligned_deref"},
            {"cond_wait"},
            {"state_snapshot", "state_overwrite", "error_return_without_restore"},
            {"path_check", "path_use"},
            {"probe_status", "probe_error_condition", "success_possible_return"},
        )
        direct_contracts = {
            "clang_cfg_unchecked_pointer_backtrack": {
                "pointer_backtrack",
                "backtracked_pointer_sink",
            },
            "clang_cfg_timer_callback_object_lock_without_scheduler_lock": {
                "global_scheduler_walk",
                "object_lock_in_callback",
            },
            "clang_cfg_free_derived_pointer_alias": {"pointer_derivation", "invalid_free_alias"},
            "clang_cfg_realloc_lost_original": {"realloc_assign"},
            "clang_cfg_fd_closed_without_owner_invalidation": {"fd_close"},
            "clang_cfg_requested_permission_not_applied_to_mode": {
                "hardcoded_permission",
                "requested_permission_check",
            },
            "clang_cfg_parsed_protocol_version_is_ignored": {
                "protocol_version_parse",
                "protocol_version_ignored",
            },
            "clang_cfg_raw_fd_revalidated_as_encoded": {"encoded_fd_validate", "raw_fd_derive"},
            "clang_cfg_fixed_byte_limit_before_spec_count_check": {"spec_byte_limit_mismatch"},
            "clang_cfg_path_state_key_generation_before_locked_registration": {
                "key_generation",
                "locked_registration_lookup",
                "path_state_check",
            },
            "clang_cfg_unchecked_strchr_result": {"strchr_result", "unchecked_pointer_use"},
            "clang_cfg_shared_resource_freed_without_refcount_protocol": {
                "free_without_refcount",
                "refcount_state",
            },
            "clang_cfg_global_dynamic_array_resize_without_lock": {
                "dynamic_array_publish",
                "dynamic_array_resize_guard",
            },
            "clang_cfg_size_addition_without_overflow_guard": {"integer_size_arithmetic"},
            "clang_cfg_unchecked_param_indexes_fixed_global_array": {"global_array_index"},
            "clang_cfg_full_key_lookup_truncated_key_insert": {
                "full_key_lookup",
                "truncated_key_store",
            },
            "clang_cfg_slot_overwrite_without_existing_owner_cleanup": {"slot_overwrite"},
            "clang_cfg_unbounded_vla_or_stack_array": {"runtime_stack_array"},
            "clang_cfg_role_specific_release_argument_mismatch": {"role_check", "role_release"},
            "clang_cfg_shell_command_concat_env": {"command_concat", "environment_source"},
            "clang_cfg_partial_aggregate_sent_with_sizeof": {"aggregate_decl", "aggregate_send"},
        }
        rule = str(issue.get("rule") or "").lower()
        matched = next((shape for shape in obligation_shapes if shape.issubset(event_kinds)), None)
        if matched is None:
            contract = direct_contracts.get(rule)
            if contract and contract.issubset(event_kinds):
                matched = contract
        if matched is None:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        # M3' guard: scoped to the acquire-without-release family
        # (memory_leak).  A sink that is itself a free call (invalid_free /
        # refcount obligations) is excluded: the release there is the claim
        # under test, not a contradiction.  When the confirmed function body
        # releases the obligation object on its own, an acquire/release
        # confirmation is self-contradictory and the proof is dropped so the
        # item routes through the normal ladder.
        sink_expression = str(issue.get("sink") or "")
        if (
            issue.get("obligation_infunction_release_guard") is True
            and str(issue.get("category") or "") == "memory_leak"
            and not EvidenceCompletionQueue._SINK_IS_FREE_RE.match(sink_expression)
            and EvidenceCompletionQueue._infunction_release_contradiction(
                sink_expression, str(code or "")
            )
        ):
            return None
        fact_ids = [
            f"cfg:{item.get('line')}:{item.get('kind')}"
            for item in events
            if isinstance(item, Mapping)
            and str(item.get("kind") or "").lower() in matched
            and item.get("line") not in (None, "")
        ]
        if len(fact_ids) < len(matched):
            return None
        return EvidenceCompletionQueue._proof_from_ast(
            issue,
            outcome="confirm",
            proof_kind="deterministic_cfg_obligation_path",
            producer_engine="clang_ast_cfg_obligation_prover",
            events=[item for item in events if str(item.get("kind") or "").lower() in matched],
            facts=["source_to_sink_complete", "event_path_complete", *sorted(matched)],
            summary="确定性 AST/CFG 事件证实了所报告的安全义务",
            scope="完整的过程内 AST/CFG 源到汇点路径",
            subject_identity=str(
                issue.get("resource_identity")
                or issue.get("source_identity")
                or issue.get("resource_signature")
                or ""
            ),
        )

    @staticmethod
    def _graph_contract_confirmation_proof(issue: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Confirm graph candidates only when their complete contract is explicit.

        Most graph leads deliberately remain reviews because their evidence is
        interprocedural and incomplete.  These two contracts carry ordered,
        source-derived graph facts sufficient to prove the violation without
        consulting a model description or an external evaluation label.
        """

        pack = _as_mapping(issue.get("evidence_pack"))
        path = _as_mapping(pack.get("path"))
        rule = str(issue.get("rule") or "").lower()
        if path.get("complete_in_function") is not True:
            return None
        if rule == "published_before_member_initialization":
            try:
                source_line = int(path.get("source_line") or 0)
                publish_line = int(path.get("publish_line") or 0)
                late_init_line = int(path.get("late_init_line") or 0)
            except (TypeError, ValueError):
                return None
            if not (0 < source_line < publish_line < late_init_line):
                return None
            return {
                "outcome": "confirm",
                "proof_kind": "ordered_publication_before_initialization",
                "producer_engine": "graph_contract_prover",
                "proof_version": "zscope.decision-proof.v2",
                "fact_ids": [
                    f"graph_cfg:{source_line}:allocation",
                    f"graph_cfg:{publish_line}:publication",
                    f"graph_cfg:{late_init_line}:late_member_initialization",
                ],
                "cfg_nodes": [str(source_line), str(publish_line), str(late_init_line)],
                "subject_identity": str(path.get("function") or ""),
                "code_hash": EvidenceCompletionQueue._evidence_code_hash(issue, path),
                "facts": ["allocation_before_publication", "publication_before_initialization"],
                "completeness": "complete",
                "scope": "完整的同函数发布生命周期",
                "summary": "对象在后续的成员初始化之前已被发布",
            }
        if rule == "same_function_helper_alloc_wrapper_member_leak":
            try:
                source_line = int(path.get("source_line") or 0)
                sink_line = int(path.get("sink_line") or 0)
            except (TypeError, ValueError):
                return None
            allocation = str(path.get("allocation_function") or "")
            cleanup = str(path.get("cleanup_function") or "")
            if not (allocation and cleanup and 0 < source_line < sink_line):
                return None
            return {
                "outcome": "confirm",
                "proof_kind": "same_function_owned_member_cleanup_gap",
                "producer_engine": "graph_contract_prover",
                "proof_version": "zscope.decision-proof.v2",
                "fact_ids": [
                    f"graph_cfg:{source_line}:wrapper_allocation",
                    f"graph_cfg:{sink_line}:wrapper_release",
                ],
                "cfg_nodes": [str(source_line), str(sink_line)],
                "subject_identity": f"{allocation}->{cleanup}",
                "code_hash": EvidenceCompletionQueue._evidence_code_hash(issue, path),
                "facts": ["same_function_helper_contract", "owned_member_not_released"],
                "completeness": "complete",
                "scope": "完整的同函数辅助分配与清理路径",
                "summary": "包装器被释放，而其建模的归属成员未被释放",
            }
        return None

    @staticmethod
    def _local_lock_dominance_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Prove a false "with and without lock" claim from one local body.

        This narrow provider deliberately applies only to the AST/CFG global
        state rule.  It requires every assignment to the named object visible
        in the complete function body to be nested under the same lock, with a
        corresponding unlock, so adjacent text alone cannot suppress a race.
        """

        if str(issue.get("rule") or "").lower() not in {
            "clang_cfg_global_state_written_with_and_without_lock",
            "clang_cfg_global_state_write_without_lock",
        }:
            return None
        evidence = _as_mapping(validation_evidence)
        function_context = _as_mapping(evidence.get("function_context"))
        code = str(function_context.get("code") or "")
        resource = str(
            issue.get("resource_signature") or issue.get("resource_identity") or ""
        ).strip()
        if not code or not resource or len(code) > 64 * 1024:
            return None

        # Reuse guarded contract resolution. A spelling-only mutex prefix
        # cannot establish success, mode or even the current API definition.
        adapted = dict(issue, source=resource)
        proof = EvidenceCompletionQueue._source_lockset_dominance_proof(
            adapted, validation_evidence
        )
        if proof is None:
            return None
        return dict(
            proof, proof_kind="lock_dominates_access", producer_engine="clang_ast_cfg_local_lockset"
        )

    @staticmethod
    def _eligible(issue: Mapping[str, Any], validator_data: Mapping[str, Any]) -> bool:
        severity = str(issue.get("impact_level") or issue.get("severity") or "").lower()
        try:
            priority = int(issue.get("priority_score") or 0)
        except (TypeError, ValueError):
            priority = 0
        verdict = str(validator_data.get("verdict") or "").lower()
        return bool(
            severity in {"high", "critical"}
            or priority >= 70
            or verdict in {"verified", "rejected"}
        )

    @staticmethod
    def _missing_fact(issue: Mapping[str, Any], validator_data: Mapping[str, Any]) -> str:
        category = str(issue.get("defect_class") or issue.get("category") or "").lower()
        verdict = str(validator_data.get("verdict") or "").lower()
        if category in {"race", "deadlock", "unsynchronized_shared_state"}:
            return "lock_or_happens_before"
        if category in {"bounds", "integer_overflow", "buffer_overflow"}:
            return "guard_or_value_range"
        if category in {"use_after_free", "memory_leak", "resource_lifecycle"}:
            return "ownership_or_cleanup_path"
        return "cross_procedure_contract" if verdict else "decision_evidence"
