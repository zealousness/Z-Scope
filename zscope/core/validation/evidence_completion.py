"""Bounded deterministic evidence-completion for unresolved validation groups."""

from __future__ import annotations

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, cast

from .evidence import normalize_missing_fact_kinds
from .proofs import deterministic_decision_proof


IssueFactProvider = Callable[[Mapping[str, Any]], Optional[Dict[str, Any]]]
EvidenceFactProvider = Callable[
    [Mapping[str, Any], Optional[Mapping[str, Any]]],
    Optional[Dict[str, Any]],
]
CertifiedFactProvider = Callable[
    [str, Mapping[str, Any], Optional[Mapping[str, Any]]],
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
class RequiredFactPlan:
    """Deterministic fact work derived from one immutable obligation."""

    validation_cluster_uid: str
    fact_kinds: tuple[str, ...]
    derivation_basis: tuple[str, ...]
    schema_version: str = "zscope.required-fact-plan.v1"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "validation_cluster_uid": self.validation_cluster_uid,
            "fact_kinds": list(self.fact_kinds),
            "derivation_basis": list(self.derivation_basis),
        }


@dataclass(frozen=True)
class EvidenceClosureState:
    """Auditable closure state after one deterministic provider batch."""

    required_fact_kinds: tuple[str, ...]
    resolved_fact_kinds: tuple[str, ...]
    missing_fact_kinds: tuple[str, ...]
    conflicting_fact_kinds: tuple[str, ...]
    complete: bool
    closure_hash: str
    schema_version: str = "zscope.evidence-closure-state.v1"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "required_fact_kinds": list(self.required_fact_kinds),
            "resolved_fact_kinds": list(self.resolved_fact_kinds),
            "missing_fact_kinds": list(self.missing_fact_kinds),
            "conflicting_fact_kinds": list(self.conflicting_fact_kinds),
            "complete": self.complete,
            "closure_hash": self.closure_hash,
        }


@dataclass(frozen=True)
class EvidenceResolution:
    """Result of the single typed FACT_RESOLUTION transition."""

    request: EvidenceCompletionRequest
    status: str
    fact_kind: str
    evidence_delta: Dict[str, Any]
    evidence_delta_hash: str
    proof_added: bool = False
    terminal_status: str = "no_match"
    provider_ids: tuple[str, ...] = ()
    miss_reason: str = ""


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
        certified_fact_provider: Optional[CertifiedFactProvider] = None,
        require_replayable_certificates: bool = False,
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
        self.certified_fact_provider = certified_fact_provider
        self.require_replayable_certificates = bool(require_replayable_certificates)

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
            return self._resolution(
                issue,
                request,
                "unsupported",
                fact_kind,
                {},
                terminal_status="unsupported",
                miss_reason="fact kind is not supported by a deterministic provider",
            )

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
            return self._resolution(
                issue,
                request,
                "duplicate_request",
                fact_kind,
                {},
                terminal_status="no_match",
                miss_reason="the same cluster/fact/subject request was already resolved",
            )
        attempted.append(attempt_key)
        issue["evidence_completion_attempt_count"] = (
            int(issue.get("evidence_completion_attempt_count") or 0) + 1
        )

        provider_status, generated, provider_error, provider_ids = (
            self._run_requested_fact_providers(
                fact_kind,
                issue,
                validation_evidence,
            )
        )
        if provider_status != "completed":
            issue["evidence_completion_status"] = provider_status
            issue["evidence_completion_terminal_status"] = provider_status
            issue["evidence_completion_missing_fact"] = fact_kind
            if provider_error:
                issue["evidence_completion_error"] = provider_error
            return self._resolution(
                issue,
                request,
                provider_status,
                fact_kind,
                {},
                terminal_status=provider_status,
                provider_ids=provider_ids,
                miss_reason=provider_error,
            )
        proof_candidates = list(generated)
        proof_candidates.extend(
            dict(value["deterministic_proof"])
            for value in generated
            if isinstance(value, Mapping) and isinstance(value.get("deterministic_proof"), Mapping)
        )
        proofs = self._authoritative_completion_proofs(issue, proof_candidates)
        if issue.get("blocking_negative_evidence") is True:
            proofs = [
                proof for proof in proofs if str(proof.get("outcome") or "").lower() != "reject"
            ]
        facts = [
            dict(value)
            for value in generated
            if isinstance(value, Mapping)
            and not (value.get("outcome") or value.get("decision") or value.get("proof_kind"))
        ]
        facts.extend(self._requested_fact_payloads(fact_kind, issue, validation_evidence))
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
        if facts and "backend_fact_catalog" not in provider_ids:
            provider_ids = (*provider_ids, "backend_fact_catalog")
        conflicting = any(
            str(fact.get("status") or "").lower() == "conflicting"
            or fact.get("conflicting") is True
            for fact in facts
        )
        if conflicting:
            issue["evidence_completion_status"] = "conflicting"
            issue["evidence_completion_terminal_status"] = "conflicting"
            issue["evidence_completion_missing_fact"] = fact_kind
            return self._resolution(
                issue,
                request,
                "conflicting",
                fact_kind,
                {},
                terminal_status="conflicting",
                provider_ids=provider_ids,
                miss_reason="deterministic providers returned conflicting facts",
            )
        delta: Dict[str, Any] = {"fact_kind": fact_kind, "facts": facts, "proofs": proofs}
        refs: list[str] = []
        for fact in facts:
            if not isinstance(fact, Mapping):
                continue
            ref = fact.get("fact_uid") or fact.get("uid") or fact.get("id")
            if ref:
                refs.append(str(ref))
            refs.extend(str(value) for value in _as_list(fact.get("evidence_refs")) if str(value))
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
                terminal_status="resolved",
                provider_ids=provider_ids,
            )
        if facts:
            existing_facts = issue.setdefault("evidence_completion_facts", [])
            if not isinstance(existing_facts, list):
                existing_facts = []
                issue["evidence_completion_facts"] = existing_facts
            existing_facts.extend(facts)
            issue["evidence_completion_status"] = "completed_partial"
            resolved = any(
                fact_kind
                in {str(value) for value in fact.get("satisfies_fact_kinds") or [] if str(value)}
                for fact in facts
            )
            terminal_status = "resolved" if resolved else "unknown"
            issue["evidence_completion_terminal_status"] = terminal_status
            issue["evidence_completion_missing_fact"] = fact_kind
            return self._resolution(
                issue,
                request,
                "completed_partial",
                fact_kind,
                delta,
                terminal_status=terminal_status,
                provider_ids=provider_ids,
                miss_reason=(
                    "deterministic providers returned observations but did not prove the "
                    "required predicate"
                    if not resolved
                    else ""
                ),
            )

        issue["evidence_completion_status"] = "exhausted"
        # Keep the legacy aggregate field for replay compatibility, but expose
        # the precise terminal contract used by new reports.
        issue["evidence_completion_terminal_status"] = "no_match"
        issue["evidence_completion_missing_fact"] = fact_kind
        return self._resolution(
            issue,
            request,
            "exhausted",
            fact_kind,
            {},
            terminal_status="no_match",
            provider_ids=provider_ids,
            miss_reason="available deterministic providers produced no fact for this obligation",
        )

    def resolve_required_facts(
        self,
        issue: Dict[str, Any],
        *,
        validator_data: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]] = None,
        fact_kinds_override: Optional[Sequence[str]] = None,
    ) -> EvidenceResolutionBatch:
        """Resolve every locally supported fact required by the obligation.

        The model may still name one especially useful missing fact, but that
        request is no longer the coverage boundary.  The immutable obligation
        and its decision slice determine the remaining provider fan-out.
        """

        resolutions: list[EvidenceResolution] = []
        fact_plan = self.build_required_fact_plan(issue, validator_data)
        if fact_kinds_override is not None:
            override = tuple(
                dict.fromkeys(
                    str(value).strip().lower()
                    for value in fact_kinds_override
                    if str(value).strip().lower() in SUPPORTED_FACT_KINDS
                )
            )
            fact_plan = RequiredFactPlan(
                validation_cluster_uid=fact_plan.validation_cluster_uid,
                fact_kinds=override,
                derivation_basis=(*fact_plan.derivation_basis, "explicit_incremental_fact_plan"),
            )
        issue["required_fact_plan"] = fact_plan.to_dict()
        # A candidate can arrive with a complete slice and later acquire more
        # required clauses from its normalized SecurityObligation.  Materialize
        # the entire plan into the decision slice before running providers so
        # an unknown observation cannot leave stale ``coverage=complete`` or
        # ``candidate_promotion_eligible=True`` state behind.
        fact_slice = issue.get("decision_fact_slice")
        fact_slice = dict(fact_slice) if isinstance(fact_slice, Mapping) else {}
        existing_facts = [
            dict(value) for value in fact_slice.get("facts") or [] if isinstance(value, Mapping)
        ]
        already_resolved = self._resolved_fact_kinds(existing_facts)
        existing_missing = set(
            normalize_missing_fact_kinds(
                issue.get("missing_fact_kinds") or fact_slice.get("missing_fact_kinds") or []
            )
        )
        planned_missing = (existing_missing | set(fact_plan.fact_kinds)) - already_resolved
        fact_slice["missing_fact_kinds"] = sorted(planned_missing)
        if planned_missing:
            fact_slice["coverage"] = "partial"
            issue["candidate_promotion_eligible"] = False
            issue["candidate_promotion_reason"] = "required_fact_plan_open"
        issue["decision_fact_slice"] = fact_slice
        issue["missing_fact_kinds"] = sorted(planned_missing)
        issue["decision_fact_coverage"] = str(fact_slice.get("coverage") or "partial")
        raw_request = validator_data.get("missing_fact_request")
        request = dict(raw_request) if isinstance(raw_request, Mapping) else {}
        for fact_kind in fact_plan.fact_kinds:
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
                "terminal_status": value.terminal_status,
                "provider_ids": list(value.provider_ids),
                "miss_reason": value.miss_reason,
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
        elif any(value.terminal_status == "conflicting" for value in resolutions):
            aggregate_status = "conflicting"
        elif resolutions:
            aggregate_status = "exhausted"
        else:
            aggregate_status = "not_applicable"
        issue["evidence_completion_status"] = aggregate_status
        terminal_statuses = {value.terminal_status for value in resolutions}
        issue["evidence_completion_terminal_status"] = (
            next(iter(terminal_statuses))
            if len(terminal_statuses) == 1
            else ("mixed" if terminal_statuses else "not_applicable")
        )
        if delta.get("facts"):
            self._apply_fact_delta_to_decision_context(issue, delta["facts"])
        final_slice = issue.get("decision_fact_slice")
        final_slice = final_slice if isinstance(final_slice, Mapping) else {}
        all_decision_facts = [
            value for value in final_slice.get("facts") or [] if isinstance(value, Mapping)
        ]
        resolved_from_facts = self._resolved_fact_kinds(all_decision_facts)
        resolved_fact_kinds = tuple(sorted(resolved_from_facts))
        conflicting_fact_kinds = tuple(
            sorted(
                {value.fact_kind for value in resolutions if value.terminal_status == "conflicting"}
            )
        )
        prior_closure = issue.get("evidence_closure_state")
        prior_closure = prior_closure if isinstance(prior_closure, Mapping) else {}
        required_for_closure = set(fact_plan.fact_kinds) | {
            str(value)
            for value in prior_closure.get("required_fact_kinds") or []
            if str(value)
        }
        missing_fact_kinds = tuple(sorted(required_for_closure - set(resolved_fact_kinds)))
        closure_payload = {
            "required": sorted(required_for_closure),
            "resolved": list(resolved_fact_kinds),
            "missing": list(missing_fact_kinds),
            "conflicting": list(conflicting_fact_kinds),
            "decision_fact_coverage": str(issue.get("decision_fact_coverage") or "unknown"),
        }
        closure_hash = hashlib.sha256(
            json.dumps(
                closure_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        closure = EvidenceClosureState(
            required_fact_kinds=tuple(sorted(required_for_closure)),
            resolved_fact_kinds=resolved_fact_kinds,
            missing_fact_kinds=missing_fact_kinds,
            conflicting_fact_kinds=conflicting_fact_kinds,
            complete=bool(
                fact_plan.fact_kinds
                and not missing_fact_kinds
                and not conflicting_fact_kinds
                and str(issue.get("decision_fact_coverage") or "") == "complete"
            ),
            closure_hash=closure_hash,
        )
        issue["evidence_closure_state"] = closure.to_dict()
        # Closure is the authoritative view of required clauses.  Keep the
        # compatibility fields aligned so downstream V3 eligibility and
        # promotion cannot disagree with it.
        final_slice = dict(final_slice)
        final_slice["missing_fact_kinds"] = list(missing_fact_kinds)
        final_slice["coverage"] = "complete" if closure.complete else "partial"
        issue["decision_fact_slice"] = final_slice
        issue["missing_fact_kinds"] = list(missing_fact_kinds)
        issue["decision_fact_coverage"] = final_slice["coverage"]
        if closure.complete:
            issue["candidate_promotion_eligible"] = True
            issue["candidate_promotion_reason"] = "required_local_facts_complete"
        else:
            issue["candidate_promotion_eligible"] = False
            issue["candidate_promotion_reason"] = (
                "required_local_facts_conflicting"
                if conflicting_fact_kinds
                else "required_local_facts_incomplete"
            )
        return EvidenceResolutionBatch(
            resolutions=tuple(resolutions),
            evidence_delta=delta,
            evidence_delta_hash=delta_hash,
            proof_added=proof_added,
        )

    @staticmethod
    def _resolved_fact_kinds(facts: Iterable[Mapping[str, Any]]) -> set[str]:
        """Return only predicates a deterministic fact explicitly closes."""

        resolved: set[str] = set()
        for fact in facts:
            raw_satisfies = fact.get("satisfies_fact_kinds")
            if isinstance(raw_satisfies, Sequence) and not isinstance(raw_satisfies, str):
                resolved.update(str(value) for value in raw_satisfies if str(value))
                continue
            # Read-only compatibility for old persisted fact records.  New
            # providers always emit ``satisfies_fact_kinds``.  A legacy record
            # may close its own kind only when it explicitly says the fact is
            # known; an unknown observation never closes a clause.
            if str(fact.get("status") or "").lower() in {
                "known",
                "verified_true",
                "resolved",
                "complete",
            } and fact.get("fact_kind"):
                resolved.add(str(fact["fact_kind"]))
        return resolved

    @staticmethod
    def build_required_fact_plan(
        issue: Mapping[str, Any],
        validator_data: Mapping[str, Any],
    ) -> RequiredFactPlan:
        """Record why each deterministic fact kind is part of this batch."""

        kinds = EvidenceCompletionQueue.required_resolution_fact_kinds(issue, validator_data)
        basis: list[str] = []
        request = validator_data.get("missing_fact_request")
        if isinstance(request, Mapping) and request.get("fact_kind"):
            basis.append("validator_missing_fact_request")
        obligation = issue.get("security_obligation")
        if isinstance(obligation, Mapping) and obligation.get("required_fact_kinds"):
            basis.append("security_obligation.required_fact_kinds")
        if issue.get("obligation_required_fact_kinds"):
            basis.append("candidate.obligation_required_fact_kinds")
        fact_slice = issue.get("decision_fact_slice")
        if isinstance(fact_slice, Mapping) and fact_slice.get("missing_fact_kinds"):
            basis.append("decision_fact_slice.missing_fact_kinds")
        if issue.get("candidate_promotion_eligible") is False:
            basis.append("promotion_policy_gap")
        return RequiredFactPlan(
            validation_cluster_uid=str(issue.get("validation_cluster_uid") or ""),
            fact_kinds=kinds,
            derivation_basis=tuple(dict.fromkeys(basis)),
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
            raw_satisfies = fact.get("satisfies_fact_kinds")
            if isinstance(raw_satisfies, Sequence) and not isinstance(raw_satisfies, str):
                resolved.update(str(value) for value in raw_satisfies if str(value))
            else:
                kind = str(fact.get("fact_kind") or fact.get("kind") or "")
                if kind:
                    resolved.add(kind)
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
        missing = (
            list(raw_missing)
            if isinstance(raw_missing, Sequence) and not isinstance(raw_missing, str)
            else []
        )
        fact_slice = issue.get("decision_fact_slice")
        if isinstance(fact_slice, Mapping):
            slice_missing = fact_slice.get("missing_fact_kinds")
            if isinstance(slice_missing, Sequence) and not isinstance(slice_missing, str):
                missing.extend(slice_missing)
        raw_required = issue.get("obligation_required_fact_kinds") or obligation.get(
            "required_fact_kinds"
        )
        if isinstance(raw_required, Sequence) and not isinstance(raw_required, str):
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

    def _normalize_resolved_facts(
        self,
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
            normalized_location = (
                dict(raw_location) if isinstance(raw_location, Mapping) else location
            )
            producer = str(fact.get("producer_engine") or "local_deterministic_fact_provider")
            raw_refs = fact.get("evidence_refs")
            evidence_refs = [
                str(value)
                for value in (raw_refs if isinstance(raw_refs, list) else [])
                if str(value)
            ]
            evidence_refs.append(uid)
            raw_satisfies = fact.get("satisfies_fact_kinds")
            satisfies_values = raw_satisfies if isinstance(raw_satisfies, list) else [fact_kind]
            if self.require_replayable_certificates:
                from .fact_capabilities import verify_certificate_v2

                certificate = fact.get("verification_certificate")
                authoritative = (
                    isinstance(certificate, Mapping)
                    and verify_certificate_v2(certificate)
                    and str(certificate.get("status") or "") == "verified_true"
                    and certificate.get("quantifier_coverage_complete") is True
                )
                if not authoritative:
                    satisfies_values = []
                    fact["status"] = "unknown"
                    fact["certificate_authoritative"] = False
                else:
                    fact["certificate_authoritative"] = True
            fact.update(
                {
                    "fact_uid": uid,
                    "fact_kind": str(fact.get("fact_kind") or fact.get("kind") or fact_kind),
                    "producer_engine": producer,
                    "provider_id": str(fact.get("provider_id") or producer),
                    "location": normalized_location,
                    "locations": [normalized_location],
                    "dependency_code_hash": str(
                        fact.get("dependency_code_hash") or dependency_hash
                    ),
                    "evidence_ref": uid,
                    "evidence_refs": sorted(set(evidence_refs)),
                    "satisfies_fact_kinds": sorted(
                        {str(value) for value in satisfies_values if str(value)}
                    ),
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
    ) -> tuple[str, list[Dict[str, Any]], str, tuple[str, ...]]:
        """Run the named provider set behind a bounded exception-safe boundary."""

        provider_ids = (f"local_deterministic:{fact_kind}",)
        future = self._fact_provider_executor.submit(
            lambda: list(
                self._requested_completion_proofs(
                    fact_kind,
                    issue,
                    validation_evidence,
                )
            )
        )
        try:
            return "completed", future.result(timeout=self.fact_timeout_seconds), "", provider_ids
        except FuturesTimeoutError:
            future.cancel()
            return "timeout", [], "fact provider timed out", provider_ids
        except Exception as exc:
            return (
                "provider_error",
                [],
                f"{type(exc).__name__}: {exc}"[:500],
                provider_ids,
            )

    @staticmethod
    def _resolution(
        issue: Dict[str, Any],
        request: EvidenceCompletionRequest,
        status: str,
        fact_kind: str,
        delta: Dict[str, Any],
        *,
        proof_added: bool = False,
        terminal_status: str = "no_match",
        provider_ids: Sequence[str] = (),
        miss_reason: str = "",
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
            terminal_status=terminal_status,
            provider_ids=tuple(str(value) for value in provider_ids if str(value)),
            miss_reason=str(miss_reason or "")[:500],
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
        result.extend(
            EvidenceCompletionQueue._structured_ir_fact_payloads(
                fact_kind,
                issue,
                validation_evidence,
            )
        )
        return result[:32]

    @staticmethod
    def _structured_ir_fact_payloads(
        fact_kind: str,
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> list[Dict[str, Any]]:
        """Project existing AST/CFG/backend facts into the typed fact protocol.

        These are deterministic observations, not new proof claims.  A record
        closes its requested kind only when the backing IR explicitly marks
        the relevant path/contract complete; otherwise it is still useful V2
        evidence but carries an empty ``satisfies_fact_kinds`` list.
        """

        pack = _as_mapping(issue.get("evidence_pack"))
        evidence = _as_mapping(validation_evidence)
        ast_cfg = _as_mapping(pack.get("ast_cfg") or evidence.get("ast_cfg"))
        path = _as_mapping(pack.get("path") or evidence.get("path"))
        concurrency = _as_mapping(pack.get("concurrency") or evidence.get("concurrency"))
        obligation = _as_mapping(issue.get("security_obligation"))
        source = pack.get("source") or issue.get("source")
        sink = pack.get("sink") or issue.get("sink")
        resource = (
            issue.get("resource_identity")
            or pack.get("resource")
            or obligation.get("subject_uid")
            or issue.get("source_identity")
            or ""
        )
        observations: Dict[str, Any] = {}
        conclusive = False

        if fact_kind == "source_sink_reachability":
            if source and sink:
                observations = {
                    "source": source,
                    "sink": sink,
                    "path_complete": bool(
                        path.get("complete")
                        or path.get("complete_in_function")
                        or path.get("complete_to_entry")
                    ),
                    "cfg_nodes": list(path.get("cfg_nodes") or []),
                }
                conclusive = observations["path_complete"]
        elif fact_kind in {"source_controllability", "caller_contract"}:
            external = bool(
                issue.get("externally_reachable")
                or issue.get("external_reachability")
                or path.get("complete_to_entry")
                and issue.get("reachable_from_entry")
            )
            if external or path.get("complete_to_entry"):
                observations = {
                    "source": source,
                    "entry_identity": str(issue.get("entry_identity") or ""),
                    "complete_to_entry": bool(path.get("complete_to_entry")),
                    "externally_reachable": external,
                }
                conclusive = bool(external and path.get("complete_to_entry"))
        elif fact_kind in {"guard_dominance", "value_range"}:
            guards = [
                dict(value)
                for value in _as_list(ast_cfg.get("condition_guards"))
                if isinstance(value, Mapping)
            ]
            constraints = [
                dict(value)
                for value in _as_list(ast_cfg.get("path_constraints"))
                if isinstance(value, Mapping)
            ]
            if guards or constraints:
                observations = {"guards": guards[:24], "path_constraints": constraints[:24]}
                if fact_kind == "guard_dominance":
                    conclusive = any(
                        value.get("dominates") is True or value.get("is_conclusive") is True
                        for value in guards
                    )
                else:
                    range_fields = {
                        "min",
                        "max",
                        "lower_bound",
                        "upper_bound",
                        "capacity",
                        "range",
                    }
                    conclusive = any(
                        value.get("is_conclusive") is True
                        or value.get("complete") is True
                        or bool(range_fields.intersection(value))
                        for value in (*guards, *constraints)
                    )
        elif fact_kind == "type_layout":
            declarations = [
                dict(value)
                for value in _as_list(ast_cfg.get("declarations"))
                if isinstance(value, Mapping)
            ]
            if declarations:
                observations = {"declarations": declarations[:32], "subject": resource}
                conclusive = any(
                    value.get("size") is not None
                    or value.get("array_extent") is not None
                    or value.get("type_size") is not None
                    for value in declarations
                )
        elif fact_kind in {"lockset", "happens_before"}:
            lockset = concurrency.get("must_hold_locks") or concurrency.get("lockset")
            hb_edges = concurrency.get("happens_before") or concurrency.get("hb_edges")
            events = [
                dict(value)
                for value in _as_list(ast_cfg.get("events"))
                if isinstance(value, Mapping)
                and any(
                    token in str(value.get("kind") or "").lower()
                    for token in ("lock", "unlock", "thread", "callback")
                )
            ]
            if lockset or hb_edges or events:
                observations = {
                    "must_hold_locks": lockset or [],
                    "happens_before_edges": hb_edges or [],
                    "events": events[:32],
                }
                conclusive = bool(
                    (fact_kind == "lockset" and lockset is not None)
                    or (fact_kind == "happens_before" and hb_edges is not None)
                )
        elif fact_kind in {"cleanup_coverage", "ownership_transfer"}:
            events = [
                dict(value)
                for value in _as_list(ast_cfg.get("events"))
                if isinstance(value, Mapping)
                and any(
                    token in str(value.get("kind") or "").lower()
                    for token in ("alloc", "acquire", "free", "release", "close", "return")
                )
            ]
            if events or any(
                path.get(field)
                for field in (
                    "all_exits_covered",
                    "complete_exit_coverage",
                    "cleanup_complete",
                    "ownership_transfer_complete",
                )
            ):
                observations = {
                    "resource": resource,
                    "events": events[:32],
                    "all_exits_covered": bool(
                        path.get("all_exits_covered")
                        or path.get("complete_exit_coverage")
                        or path.get("cleanup_complete")
                    ),
                    "transfer_complete": bool(path.get("ownership_transfer_complete")),
                }
                conclusive = bool(
                    observations["all_exits_covered"]
                    if fact_kind == "cleanup_coverage"
                    else observations["transfer_complete"]
                )
        else:
            explicit = pack.get(fact_kind) or evidence.get(fact_kind) or obligation.get(fact_kind)
            if isinstance(explicit, Mapping):
                observations = dict(explicit)
                conclusive = bool(
                    explicit.get("complete") is True or explicit.get("is_conclusive") is True
                )

        if not observations:
            return []
        return [
            {
                "value": observations,
                "status": "known" if conclusive else "unknown",
                "provider_id": "structured_ir_fact_provider",
                "producer_engine": "structured_ir_fact_provider",
                "satisfies_fact_kinds": [fact_kind] if conclusive else [],
            }
        ]

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
            certificate = fact.get("verification_certificate")
            certificate_is_local = False
            if isinstance(certificate, Mapping):
                from .fact_capabilities import verify_certificate_v2

                certificate_is_local = verify_certificate_v2(certificate)
            if uid and uid not in allowed and not certificate_is_local:
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

        if self.certified_fact_provider is not None:
            generated = self.certified_fact_provider(fact_kind, issue, validation_evidence)
            if generated is not None and str(generated.get("fact_kind") or fact_kind) == fact_kind:
                yield generated

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
            ],
            "cleanup_coverage": [
                self._exact_leak_path_v12_proof,
                self._matching_release_before_exit_v12_rejection_proof,
                self._zero_initialized_member_failure_v12_rejection_proof,
            ],
            "lockset": [
                self._external_callback_under_lock_v12_proof,
                self._single_shared_access_v12_rejection_proof,
            ],
            "happens_before": [self._external_callback_under_lock_v12_proof],
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
            if EvidenceCompletionQueue._allocation_call_names(str(event.get("expression") or ""))
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
            "scope": "complete entry-to-allocation caller contract",
            "summary": "an externally controlled value reaches an allocation on a complete path without an upper-bound guard",
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
        allocation_names = EvidenceCompletionQueue._allocation_call_names(expression)
        if not allocation_names or not re.search(r"(?:\*|\+)", expression):
            return None
        # A generic ``size + constant`` or ``count * sizeof`` in a helper is
        # not by itself a proof that a violating value is externally
        # reachable.  Field-derived request data and calloc count arithmetic
        # carry the stronger source/range contract implemented by v1.2.
        if "->" not in expression and not any(
            "calloc" in name.lower() for name in allocation_names
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
            summary="unchecked allocation-size arithmetic is evaluated before any overflow guard and reaches the allocator",
            scope="complete intraprocedural allocation expression",
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
            summary="a signal-context entry reaches an operation outside the async-signal-safe subset",
            scope="signal-root reachability and target function snapshot",
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
            summary="a scanned entry parameter reaches system() on a complete path without a structured sanitizer",
            scope="entry-parameter to command-sink data flow",
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
            r"\b(?:LOCK|pthread_mutex_lock)\s*\(\s*&?([^)]+)\)",
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
        code = str(issue.get("code_snippet") or "")
        if not code:
            code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
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
                r"\b(?:UNLOCK|pthread_mutex_unlock)\s*\(\s*&?([^)]+)\)",
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
            "scope": "complete external-callback critical section",
            "summary": "an entry-supplied callback is invoked after lock acquisition and before the matching unlock",
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
            summary="a reachable container node is self-linked while the traversal has no cycle guard",
            scope="complete container mutation and traversal snapshot",
            subject_identity=variable,
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
            summary="a successful field-sensitive acquisition reaches an exit without release or ownership transfer",
            scope="complete acquisition-to-exit ownership path",
            subject_identity=subject,
        )

    @staticmethod
    def _terminating_upper_bound(text: str) -> bool:
        value = str(text or "")
        has_upper = bool(re.search(r"(?:>|>=)\s*(?:[A-Z_][A-Z0-9_]*|sizeof\s*\(|\d+)", value))
        terminates = bool(re.search(r"\b(?:return|goto|break|continue|abort|exit)\b", value))
        return has_upper and terminates

    @staticmethod
    def _allocation_call_names(expression: str) -> list[str]:
        return [
            name
            for name in re.findall(r"\b([A-Za-z_]\w*)\s*\(", str(expression or ""))
            if any(token in name.lower() for token in ("malloc", "calloc", "realloc", "alloc"))
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
            summary="every reachable caller supplies a constant capacity or a terminating upper-bound guard",
            scope="complete reachable caller set",
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
            summary="the proven allocation capacity covers the sink length with compatible signedness",
            scope="complete allocation-to-sink value relation",
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
            summary="a terminating guard caps the loop bound to the fixed-array capacity on every path",
            scope="complete guarded loop",
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
            summary="every feasible exit releases or transfers the same field-sensitive resource",
            scope="complete ownership exit set",
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
            summary="only one shared-state access event exists in the complete candidate evidence, so no conflicting pair is established",
            scope="complete candidate concurrency evidence",
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
                    summary="the allocation and copy use the same exact length expression for the same object",
                    scope="complete local allocation-to-copy relation",
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
                            rf"\b(?:SAFE_FREE|free)\s*\(\s*{escaped}\s*\)\s*;",
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
                    summary="the same field-sensitive resource is released before the reported exit edge",
                    scope="complete reported acquisition-to-exit path",
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
        parent_match = re.search(r"\b(?:SAFE_FREE|free)\s*\(\s*([A-Za-z_]\w*)\s*\)", sink)
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
            rf"(?P<body>.{{0,600}}?\b(?:SAFE_FREE|free)\s*\(\s*{re.escape(parent)}\s*\)\s*;)"
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
            summary="the zero-initialized member is null on its acquisition-failure branch before the parent is released",
            scope="complete member-acquisition failure branch",
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
                summary="the acquired object is stored in a field of a caller-provided owner before successful return",
                scope="complete caller-owner field transfer path",
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
                    summary="a terminating upper bound on the sole dynamic source propagates to the derived allocation size",
                    scope="complete local bound-to-allocation relation",
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
                scope="complete intraprocedural ownership/concurrency protocol path",
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
                        rf"\b(?:safe_free|free|release|destroy)\s*\(\s*{re.escape(owner)}\s*\)",
                        code,
                        re.IGNORECASE,
                    )
                    and not re.search(
                        rf"\b(?:safe_free|free|release|destroy)\s*\(\s*{re.escape(member.replace('.', '->'))}\s*\)",
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
                        "a field identified as owned remains live when its parent is released",
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
            "completeness": "complete",
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
            r"(?:LOCK|pthread_mutex_lock|pthread_rwlock_[rw]dlock)"
            if acquire
            else r"(?:UNLOCK|pthread_mutex_unlock|pthread_rwlock_unlock)"
        )
        match = re.search(rf"\b{names}\s*\(\s*&?([^,)]+)", text)
        return EvidenceCompletionQueue._normalize_symbol(match.group(1)) if match else ""

    @staticmethod
    def _balanced_lock_protocol_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Reject simple lock-protocol false positives from complete source CFG.

        The provider deliberately handles only lexical lock/unlock pairs with
        no ``goto``/``switch``/``else`` ambiguity between the matching pair.
        More complicated interprocedural or branch-dependent protocols remain
        reviewable until the project fact pass supplies a formal contract.
        """

        rule = str(issue.get("rule") or "").lower()
        if rule not in {
            "clang_cfg_return_with_lock_held",
            "clang_cfg_unlock_without_matching_lock",
        }:
            return None
        _ast_cfg, path, _events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        # This fallback has source order, not a formal CFG.  It can therefore
        # emit a *complete* rejection proof only for a single straight-line
        # must-path.  In particular, an acquire in one branch must never be
        # paired with an unlock in another branch merely because it appears
        # earlier in the file.
        if re.search(
            r"\b(?:if|else|switch|case|default|for|while|do|goto|break|continue)\b|\?",
            code,
        ):
            return None

        if rule == "clang_cfg_unlock_without_matching_lock":
            held: list[tuple[str, int]] = []
            matched_pairs: list[tuple[str, int, int]] = []
            for index, text in enumerate(lines):
                acquire = EvidenceCompletionQueue._lock_argument(text, acquire=True)
                if acquire:
                    held.append((acquire, index + 1))
                release = EvidenceCompletionQueue._lock_argument(text, acquire=False)
                if not release:
                    continue
                match_index = next(
                    (item for item in range(len(held) - 1, -1, -1) if held[item][0] == release),
                    -1,
                )
                if match_index < 0:
                    return None
                _lock, acquire_line = held.pop(match_index)
                matched_pairs.append((release, acquire_line, index + 1))
            # Without a target CFG node, more than one unlock is ambiguous:
            # proving any safe pair would not disprove the reported one.
            if held or len(matched_pairs) != 1:
                return None
            lock, acquire_line, release_line = matched_pairs[0]
            return EvidenceCompletionQueue._proof_from_code(
                issue,
                outcome="reject",
                proof_kind="matching_lock_dominates_unlock",
                producer_engine="clang_ast_cfg_lock_protocol",
                code=code,
                line_numbers=[acquire_line, release_line],
                facts=["matching_lock_dominates_unlock"],
                summary="the reported unlock has one matching acquisition on the same straight-line must-path",
                scope="complete straight-line lock protocol path",
                subject_identity=lock,
            )

        # For a return-with-lock-held candidate, inspect every return in a
        # branch-free local body.  Each acquire must have a matching release
        # before its subsequent return.  This intentionally refuses to prove
        # safety in a body containing ``else`` because a linear scan is then
        # insufficient to establish all paths.
        if re.search(r"\belse\b", code):
            return None
        return_held: list[tuple[str, int]] = []
        return_lines: list[int] = []
        for index, text in enumerate(lines):
            acquired = EvidenceCompletionQueue._lock_argument(text, acquire=True)
            if acquired:
                return_held.append((acquired, index + 1))
            released = EvidenceCompletionQueue._lock_argument(text, acquire=False)
            if released:
                match_index = next(
                    (
                        item
                        for item in range(len(return_held) - 1, -1, -1)
                        if return_held[item][0] == released
                    ),
                    -1,
                )
                if match_index >= 0:
                    return_held.pop(match_index)
            if re.search(r"\breturn\b", text):
                return_lines.append(index + 1)
                if return_held:
                    return None
        if return_lines:
            return EvidenceCompletionQueue._proof_from_code(
                issue,
                outcome="reject",
                proof_kind="balanced_lock_return_paths",
                producer_engine="clang_ast_cfg_lock_protocol",
                code=code,
                line_numbers=return_lines,
                facts=["all_return_paths_unlocked"],
                summary="every reachable return in the complete local lock protocol is preceded by matching unlocks",
                scope="complete branch-free local lock protocol",
            )
        return None

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
                r"(?:[A-Za-z_]\w*(?:alloc|malloc|calloc)[A-Za-z_0-9]*)\s*\(\s*(?P<size>[^,)]+)",
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
                summary="a guarded allocation of n + 1 bytes dominates a copy of n bytes",
                scope="complete allocation-to-copy capacity relation",
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
        parent_match = re.search(
            r"SAFE_FREE\s*\(\s*([A-Za-z_]\w*)\s*\)", str(issue.get("sink") or "")
        )
        if not member_match or not parent_match or member_match.group(1) != parent_match.group(1):
            return None
        parent, member = member_match.groups()
        pattern = re.compile(rf"if\s*\(\s*!\s*{re.escape(parent)}\s*->\s*{re.escape(member)}\s*\)")
        for index, text in enumerate(lines, start=1):
            if not pattern.search(text):
                continue
            window = "\n".join(lines[index - 1 : index + 5])
            if not re.search(rf"SAFE_FREE\s*\(\s*{re.escape(parent)}\s*\)", window):
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
                summary="the parent is released only on the branch where its owned member acquisition failed",
                scope="complete member-acquisition failure branch",
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
                summary="the reported cast is derived from a pointer parameter plus an offset, not from serialized integer data",
                scope="complete local pointer provenance",
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
            summary="a local stack object is passed to a detached worker without a completing join",
            scope="complete local asynchronous thread handoff",
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
            rf"\b(?:SAFE_FREE|free|release|destroy)\s*\(\s*{re.escape(subject)}\b",
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
            summary="the container ownership link is removed and no release or transfer of the detached object follows",
            scope="complete local container-detach path",
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
                summary="a failure branch returns after a matching local lock acquisition without an intervening unlock",
                scope="complete local failure-return lock path",
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
                r"\b(?:SAFE_FREE|free|close|release)\s*\(\s*(?P<owner>[A-Za-z_]\w*(?:(?:\s*->\s*|\s*\.\s*)[A-Za-z_]\w+)*?)\s*(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)",
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
                        rf"\b(?:SAFE_FREE|free|close|release|reset|destroy)\s*\(\s*"
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
                summary="a cleanup/reset path releases an owner while initialized owned members remain uncleaned",
                scope="complete field-sensitive owner cleanup path",
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
                        summary="a terminating null guard dominates the reported allocation use",
                        scope="complete intraprocedural allocation-to-use path",
                        subject_identity=symbol,
                    )
        return None

    @staticmethod
    def _fd_transfer_or_failure_proof(issue: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Reject FD-leak candidates proven to be failed acquisition or transfer.

        A descriptor is not leaked on the branch where acquisition explicitly
        failed.  Likewise, returning the descriptor transfers ownership to the
        caller.  Global storage is treated as a durable ownership transfer only
        for the conventional, explicit ``g_`` global form; arbitrary member
        writes remain reviewable because their lifetime is not proven here.
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
            if re.match(r"^g_[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)+$", lhs):
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="durable_global_owner_transfer",
                    producer_engine="clang_ast_cfg_fd_ownership",
                    events=[opened],
                    facts=["fd_stored_in_global_owner", "ownership_transfer_complete"],
                    summary="the descriptor is assigned to an explicit global owner",
                    scope="descriptor ownership transfer",
                    subject_identity=lhs,
                )
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
                        summary="the descriptor is returned to the caller as the ownership result",
                        scope="descriptor ownership transfer",
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
                            summary="the reported return is guarded by a failed descriptor acquisition",
                            scope="failed descriptor acquisition branch",
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
                    summary="a terminating upper-bound guard dominates the allocation",
                    scope="complete intraprocedural allocation path",
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
                summary="the reported write targets a different object than the modeled fixed array",
                scope="complete intraprocedural array access path",
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
                summary="the indexed object is declared as dynamic pointer storage, not a fixed array",
                scope="complete intraprocedural array access path",
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
                    summary="a terminating array-size guard dominates the counted loop",
                    scope="complete intraprocedural fixed-array loop",
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
            if lhs.startswith("g_"):
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="durable_global_owner_transfer",
                    producer_engine="clang_ast_cfg_ownership",
                    events=[acquire],
                    facts=["resource_stored_in_global_owner", "ownership_transfer_complete"],
                    summary="the acquired resource is stored in explicit global ownership",
                    scope="resource ownership transfer",
                    subject_identity=lhs,
                )
            if lhs.startswith("*"):
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="output_parameter_ownership_transfer",
                    producer_engine="clang_ast_cfg_ownership",
                    events=[acquire],
                    facts=["resource_stored_in_output_parameter", "ownership_transfer_complete"],
                    summary="the resource is returned through an output ownership parameter",
                    scope="resource ownership transfer",
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
                    summary="the parent holding the resource is returned to the caller",
                    scope="resource ownership transfer",
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
                    "scope": f"allocation `{var}` through reported dereference",
                    "summary": f"a terminating NULL guard for `{var}` dominates the reported use",
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
            "scope": "source and sink access paths",
            "summary": f"`{source_path}` and `{sink_path}` are distinct object access paths",
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
            "clang_cfg_nonliteral_format_string": {"format_sink"},
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
            summary="deterministic AST/CFG events establish the reported safety obligation",
            scope="complete intraprocedural AST/CFG source-to-sink path",
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
                "scope": "complete same-function publication lifecycle",
                "summary": "the object is published before a later member initialization",
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
                "scope": "complete same-function helper allocation and cleanup path",
                "summary": "the wrapper is released while its modeled owned member is not released",
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

        # This provider is intentionally a *must* proof.  A text-order stack
        # is sound only for one straight-line CFG region; once a branch or
        # early transfer appears, different paths must not be spliced into a
        # synthetic lock/unlock pair.  Rich CFG providers may still prove
        # those functions, but this local fallback returns unknown.
        control_flow = re.compile(
            r"\b(?:if|else|switch|case|default|for|while|do|goto|break|continue)\b|\?"
        )
        lines = code.splitlines()
        if any(control_flow.search(line) for line in lines):
            return None

        def lock_identity(value: str) -> str:
            return re.sub(r"\s+", "", value.strip().lstrip("&"))

        held: list[tuple[str, int]] = []
        assignment_locks: list[str] = []
        fact_ids: list[str] = []
        cfg_nodes: list[str] = []
        for offset, line in enumerate(lines, start=1):
            for match in re.finditer(r"\b(?:LOCK|pthread_mutex_lock)\s*\(\s*&?([^,)]+)", line):
                held.append((lock_identity(match.group(1)), offset))
            if resource in line and re.search(rf"\b{re.escape(resource)}\s*=", line):
                if not held:
                    return None
                assignment_locks.append(held[-1][0])
                fact_ids.extend([f"local_cfg:lock:{held[-1][1]}", f"local_cfg:access:{offset}"])
                cfg_nodes.extend([str(held[-1][1]), str(offset)])
            if re.search(r"\breturn\b", line) and held:
                return None
            for match in re.finditer(r"\b(?:UNLOCK|pthread_mutex_unlock)\s*\(\s*&?([^,)]+)", line):
                lock = lock_identity(match.group(1))
                matched = False
                for index in range(len(held) - 1, -1, -1):
                    if held[index][0] == lock:
                        acquisition_line = held[index][1]
                        held.pop(index)
                        fact_ids.append(f"local_cfg:unlock:{offset}")
                        cfg_nodes.extend([str(acquisition_line), str(offset)])
                        matched = True
                        break
                # An unlock without a lexically active matching acquisition
                # is exactly the cross-branch shape that caused the Range
                # false counterproof.  It cannot support a must-hold proof.
                if not matched:
                    return None
        if held:
            return None
        if not assignment_locks or len(set(assignment_locks)) != 1:
            return None
        lock_name = assignment_locks[0]
        if not any(item.startswith("local_cfg:unlock:") for item in fact_ids):
            return None
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        return {
            "outcome": "reject",
            "proof_kind": "lock_dominates_access",
            "producer_engine": "clang_ast_cfg_local_lockset",
            "fact_ids": sorted(set(fact_ids)),
            "code_hash": code_hash,
            "facts": ["lock_dominates_access", "all_accesses_guarded"],
            "completeness": "complete",
            "scope": f"all assignments to {resource} in one straight-line CFG region",
            "subject_identity": resource,
            "cfg_nodes": sorted(set(cfg_nodes), key=lambda value: int(value)),
            "assumptions": ["single straight-line CFG region with balanced lock state"],
            "summary": f"all local assignments to {resource} are nested under {lock_name}",
        }

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
