"""Deterministic replay of Validator positive and counter claims.

The Validator is allowed to make a semantic judgement, but the policy layer
only promotes that judgement when its citations resolve to the current
candidate's immutable evidence slice.  Numeric scores remain useful for
ranking; they are deliberately absent from this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Sequence, Tuple

from ...common.issue_identity import issue_build_context_id
from ...common.validator_protocol import VALIDATOR_RESULT_VERSION
from ...rules.validation_obligations import binding_for_issue
from .evidence import normalize_missing_fact_kinds, validation_verdict


CLAIM_REPLAY_VERSION = "zscope.validation-claim-replay.v1"

_AUTHORITATIVE_REF_KINDS = frozenset(
    {
        "decision_fact",
        "decision_edge",
        "path_edge",
        "proof_fact",
        "candidate_evidence",
        "positive_evidence",
        "negative_evidence",
        "call_path",
        "source_location",
        "semantic_claim",
        "semantic_claim_evidence",
        "evidence_delta",
        "evidence_delta_fact",
    }
)
_CURRENT_FACT_REF_KINDS = frozenset(
    {
        "decision_fact",
        "decision_edge",
        "path_edge",
        "proof_fact",
        "evidence_delta_fact",
    }
)

# Local detector events for these rules are useful discovery evidence, but a
# verified model verdict must cite facts that close the actual mechanism.
# This prevents the Validator from turning a declaration/use pair, arbitrary
# size addition, or runtime-looking stack expression into a confirmed issue
# without the corresponding path/range proof.
_RULE_POSITIVE_FACT_REQUIREMENTS = {
    "clang_cfg_pointer_may_be_uninitialized_before_use": {
        "uninitialized_on_reachable_path",
    },
    "clang_cfg_size_addition_without_overflow_guard": {
        "overflow_value_reachable",
        "overflow_reaches_security_sink",
    },
    "clang_cfg_unbounded_vla_or_stack_array": {
        "runtime_bound_controllable",
        "safe_upper_bound_absent",
    },
}


@dataclass(frozen=True)
class ClaimReplayResult:
    accepted: bool
    claim_kind: str
    checker: str
    cited_refs: Tuple[str, ...]
    replayed_roles: Tuple[str, ...]
    failures: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": CLAIM_REPLAY_VERSION,
            "accepted": self.accepted,
            "claim_kind": self.claim_kind,
            "checker": self.checker,
            "cited_refs": list(self.cited_refs),
            "replayed_roles": list(self.replayed_roles),
            "failures": list(self.failures),
        }


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _nonempty(value: Any) -> bool:
    if value in (None, "", (), [], {}):
        return False
    return bool(str(value).strip()) if isinstance(value, str) else True


def _strings(value: Any) -> Tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        return ()
    return tuple(str(item).strip() for item in value if str(item).strip())


def _fact_kinds(issue: Mapping[str, Any]) -> set[str]:
    fact_slice = _mapping(issue.get("decision_fact_slice"))
    result: set[str] = set()
    for fact in fact_slice.get("facts") or []:
        if not isinstance(fact, Mapping):
            continue
        kind = str(fact.get("fact_kind") or fact.get("kind") or "").strip().lower()
        if kind:
            result.add(kind)
        for value in fact.get("satisfies_fact_kinds") or []:
            if str(value).strip():
                result.add(str(value).strip().lower())
    return result


def _role_presence(issue: Mapping[str, Any]) -> set[str]:
    fact_slice = _mapping(issue.get("decision_fact_slice"))
    security = _mapping(issue.get("security_obligation"))
    fact_kinds = _fact_kinds(issue)
    source = (
        issue.get("source_identity")
        or issue.get("canonical_source")
        or issue.get("source")
        or security.get("source_uid")
    )
    sink = (
        issue.get("sink_identity")
        or issue.get("canonical_sink")
        or issue.get("sink")
        or security.get("sink_uid")
    )
    roles: set[str] = set()
    if _nonempty(source) or "source" in fact_kinds or "event:acquire" in fact_kinds:
        roles.add("source")
    if _nonempty(sink) or "sink" in fact_kinds or "event:exit" in fact_kinds:
        roles.add("sink")
    if (
        fact_slice.get("edge_uids")
        or issue.get("path_constraints")
        or issue.get("call_path")
        or issue.get("call_paths")
        or ({"source", "sink"} <= roles and fact_slice.get("fact_uids"))
    ):
        roles.add("path")
    if issue.get("guard") or issue.get("guards") or issue.get("path_constraints"):
        roles.add("guard")
    # A complete local source/sink slice plus explicit Validator discussion of
    # negative evidence can represent the absence of the required guard.  The
    # claim replay still requires the cited facts below; this does not turn an
    # absent guard into a free-form model assertion.
    if {"source", "sink"} <= roles and str(fact_slice.get("coverage") or "") == "complete":
        roles.add("guard")
    if issue.get("resource_identity") or "object_identity" in fact_kinds:
        roles.add("object_identity")
    if {"ownership_transfer", "event:acquire"} & fact_kinds:
        roles.add("ownership")
    if {"cleanup_coverage", "event:release"} & fact_kinds:
        roles.update({"release", "exit"})
    if issue.get("lock_identity"):
        roles.add("lock")
    if {"lockset", "happens_before", "event:lock"} & fact_kinds:
        roles.update({"synchronization", "lock"})
    if {"event:shared_state_access", "shared_state_access", "access"} & fact_kinds:
        roles.add("access")
    if (
        issue.get("protocol_state")
        or issue.get("state_identity")
        or {
            "protocol_state",
            "state_transition",
        }
        & fact_kinds
    ):
        roles.add("state")
    if issue.get("contract_identity") or {"caller_contract", "contract"} & fact_kinds:
        roles.add("contract")
    return roles


def _catalog_checks(
    issue: Mapping[str, Any],
    val_data: Mapping[str, Any],
) -> tuple[Tuple[str, ...], list[str]]:
    refs = _strings(val_data.get("evidence_refs"))
    catalog = _mapping(issue.get("validator_evidence_ref_catalog"))
    failures: list[str] = []
    if not refs:
        failures.append("positive_claim_has_no_evidence_refs")
        return refs, failures
    if not catalog:
        failures.append("evidence_ref_catalog_missing")
        return refs, failures
    authoritative = 0
    current_fact_refs = 0
    fact_slice = _mapping(issue.get("decision_fact_slice"))
    current_ids = {
        str(value)
        for value in (
            list(fact_slice.get("fact_uids") or []) + list(fact_slice.get("edge_uids") or [])
        )
        if str(value)
    }
    for ref in refs:
        record = _mapping(catalog.get(ref))
        if not record:
            failures.append(f"unknown_evidence_ref:{ref}")
            continue
        kind = str(record.get("kind") or "")
        if kind in _AUTHORITATIVE_REF_KINDS:
            authoritative += 1
            if record.get("summary") in (None, "", {}, []):
                failures.append(f"unreadable_evidence_ref:{ref}")
        if kind in _CURRENT_FACT_REF_KINDS and ref in current_ids:
            current_fact_refs += 1
    if authoritative == 0:
        failures.append("no_authoritative_fact_or_edge_cited")
    if current_fact_refs == 0:
        failures.append("no_current_fact_or_edge_cited")
    return refs, failures


def _identity_checks(issue: Mapping[str, Any], val_data: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    expected_candidate = str(
        issue.get("candidate_uid") or issue.get("candidate_id") or issue.get("id") or ""
    )
    expected_cluster = str(issue.get("validation_cluster_uid") or "")
    if not expected_candidate or str(val_data.get("candidate_uid") or "") != expected_candidate:
        failures.append("candidate_uid_mismatch")
    if (
        not expected_cluster
        or str(val_data.get("validation_cluster_uid") or "") != expected_cluster
    ):
        failures.append("validation_cluster_uid_mismatch")
    if not issue_build_context_id(issue):
        failures.append("build_context_missing")
    return failures


def replay_positive_claim(
    issue: Mapping[str, Any],
    val_data: Mapping[str, Any],
) -> ClaimReplayResult:
    """Replay a verified result against the current typed obligation."""

    binding = binding_for_issue(issue)
    failures: list[str] = []
    checker = binding.profile.positive_checker if binding is not None else "unbound"
    if binding is None:
        failures.append("validation_obligation_profile_missing")
    failures.extend(_identity_checks(issue, val_data))
    if str(val_data.get("schema_version") or "") != VALIDATOR_RESULT_VERSION:
        failures.append("validator_protocol_not_current")
    if validation_verdict(dict(val_data)) != "verified":
        failures.append("validator_verdict_not_verified")
    if str(val_data.get("stop_reason") or "") not in {
        "decision_complete",
        "investigation_complete",
    }:
        failures.append("validator_decision_not_complete")
    if val_data.get("missing_fact_request") is not None:
        failures.append("validator_still_requests_fact")
    if val_data.get("blocking_negative_evidence") is not False:
        failures.append("blocking_counterfact_present_or_unspecified")
    if not _strings(val_data.get("positive_evidence")):
        failures.append("positive_claim_missing")
    if issue.get("evidence_conflict"):
        failures.append("evidence_conflict")
    contract = _mapping(_mapping(issue.get("evidence_pack")).get("hierarchical_contract"))
    if _mapping(contract.get("hypothesis")).get("assumptions"):
        failures.append("unresolved_semantic_hypothesis_assumptions")
    if issue.get("build_scope_rejection"):
        failures.append("build_context_not_current")
    omissions = _strings(issue.get("validator_decision_critical_omissions"))
    if omissions:
        failures.append("decision_critical_omissions:" + ",".join(omissions))
    missing = normalize_missing_fact_kinds(
        issue.get("missing_fact_kinds")
        or _mapping(issue.get("decision_fact_slice")).get("missing_fact_kinds")
        or []
    )
    if missing:
        failures.append("missing_required_facts:" + ",".join(sorted(missing)))

    fact_slice = _mapping(issue.get("decision_fact_slice"))
    if not fact_slice.get("fact_uids"):
        failures.append("decision_fact_slice_empty")
    if not fact_slice.get("dependency_code_hashes"):
        failures.append("dependency_code_hash_missing")

    cited_refs, catalog_failures = _catalog_checks(issue, val_data)
    failures.extend(catalog_failures)

    present_roles = _role_presence(issue)
    required_roles = set(binding.profile.required_roles if binding is not None else ())
    missing_roles = sorted(required_roles - present_roles)
    if missing_roles:
        failures.append("required_roles_not_replayable:" + ",".join(missing_roles))

    rule_id = str(issue.get("rule_id") or issue.get("rule") or "")
    required_positive_facts = _RULE_POSITIVE_FACT_REQUIREMENTS.get(rule_id, set())
    missing_positive_facts = sorted(required_positive_facts - _fact_kinds(issue))
    if missing_positive_facts:
        failures.append("rule_positive_facts_not_replayable:" + ",".join(missing_positive_facts))

    if str(val_data.get("pass") or "") == "investigation_synthesis":
        closure = _mapping(issue.get("v3_evidence_closure"))
        if closure.get("complete") is not True or not closure.get("fact_uids"):
            failures.append("investigation_evidence_closure_incomplete")

    # Preserve stable order for report/replay comparisons.
    unique_failures = tuple(dict.fromkeys(failures))
    return ClaimReplayResult(
        accepted=not unique_failures,
        claim_kind="positive",
        checker=checker,
        cited_refs=cited_refs,
        replayed_roles=tuple(sorted(required_roles & present_roles)),
        failures=unique_failures,
    )


def replay_semantic_counter_claim(
    issue: Mapping[str, Any], val_data: Mapping[str, Any]
) -> ClaimReplayResult:
    """Admit a bounded semantic refutation, separately from a program proof.

    Only runtime-admitted, cited investigation facts can support it. Universal
    absence claims remain with the coverage/proof path; a model cannot turn a
    partial source read into an exhaustive scope receipt.
    """
    failures = _identity_checks(issue, val_data)
    refs, catalog_failures = _catalog_checks(issue, val_data)
    failures.extend(catalog_failures)
    if binding_for_issue(issue) is None:
        failures.append("validation_obligation_profile_missing")
    if issue.get("validation_mode") not in {"balanced", "deep"}:
        failures.append("autonomous_validation_disabled")
    if val_data.get("schema_version") != VALIDATOR_RESULT_VERSION:
        failures.append("validator_protocol_not_current")
    if validation_verdict(dict(val_data)) != "rejected":
        failures.append("validator_verdict_not_rejected")
    if val_data.get("pass") != "investigation_synthesis":
        failures.append("not_autonomous_investigation")
    if val_data.get("stop_reason") not in {"decision_complete", "investigation_complete"}:
        failures.append("investigation_not_complete")
    if val_data.get("missing_fact_request") is not None:
        failures.append("validator_still_requests_fact")
    if not _strings(val_data.get("negative_evidence")):
        failures.append("counter_claim_missing")
    contract = _mapping(_mapping(issue.get("evidence_pack")).get("hierarchical_contract"))
    if _mapping(contract.get("hypothesis")).get("assumptions"):
        failures.append("unresolved_semantic_hypothesis_assumptions")
    if issue.get("evidence_conflict") or issue.get("build_scope_rejection"):
        failures.append("evidence_conflict_or_stale_build")
    if issue.get("validator_decision_critical_omissions"):
        failures.append("decision_critical_omissions")
    closure = _mapping(issue.get("v3_evidence_closure"))
    admitted = set(closure.get("fact_uids") or [])
    if closure.get("complete") is not True:
        failures.append("investigation_evidence_closure_incomplete")
    facts = [f for f in issue.get("v3_investigation_facts") or [] if isinstance(f, Mapping)]
    counters = [f for f in facts if f.get("fact_kind") == "counterexample"
                and f.get("fact_uid") in refs and f.get("fact_uid") in admitted
                and f.get("producer_engine") == "validator_readonly_tool_session"]
    subject = str(_mapping(issue.get("security_obligation")).get("subject_uid")
                  or issue.get("resource_identity") or issue.get("source_identity") or "")
    if not subject or any(f.get("subject_uid") != subject or
                          f.get("build_context_id") != issue_build_context_id(issue) for f in counters):
        failures.append("counterclaim_object_or_build_mismatch")
    if not counters or any(f.get("claim_scope") != "candidate_premise" for f in counters):
        failures.append("concrete_candidate_refutation_missing_or_universal_scope")
    return ClaimReplayResult(
        accepted=not failures, claim_kind="semantic_counter",
        checker="evidence_grounded_llm.v1", cited_refs=refs,
        replayed_roles=("candidate_premise",) if counters else (),
        failures=tuple(dict.fromkeys(failures)),
    )


def replay_counter_claim(
    issue: Mapping[str, Any],
    val_data: Mapping[str, Any],
    *,
    deterministic_counterfact_replayed: bool = False,
) -> ClaimReplayResult:
    """Replay a cited counter-claim through the deterministic proof checker."""

    binding = binding_for_issue(issue)
    failures: list[str] = []
    checker = binding.profile.rejection_checker if binding is not None else "unbound"
    if binding is None:
        failures.append("validation_obligation_profile_missing")
    failures.extend(_identity_checks(issue, val_data))
    if str(val_data.get("schema_version") or "") != VALIDATOR_RESULT_VERSION:
        failures.append("validator_protocol_not_current")
    if validation_verdict(dict(val_data)) != "rejected":
        failures.append("validator_verdict_not_rejected")
    if not _strings(val_data.get("negative_evidence")):
        failures.append("counter_claim_missing")
    cited_refs, catalog_failures = _catalog_checks(issue, val_data)
    failures.extend(catalog_failures)
    # A model statement and readable citations are not a counter-proof.  The
    # current fact graph must reproduce one of the governed guard,
    # reachability, cleanup, lock/HB, object-identity, or API-identity proof
    # shapes.  Keeping this in the replay result prevents telemetry from
    # calling an unproven rejection "accepted" even though policy correctly
    # leaves it in needs_review.
    from .proofs import deterministic_decision_proof

    proof = deterministic_decision_proof(dict(issue), outcome="reject")
    if proof is None and not deterministic_counterfact_replayed:
        failures.append("deterministic_counterfact_not_replayed")
    unique_failures = tuple(dict.fromkeys(failures))
    return ClaimReplayResult(
        accepted=not unique_failures,
        claim_kind="counter",
        checker=checker,
        cited_refs=cited_refs,
        replayed_roles=(
            (proof.proof_kind,)
            if proof is not None
            else (("external_deterministic_checker",) if deterministic_counterfact_replayed else ())
        ),
        failures=unique_failures,
    )
