"""Structured deterministic proof extraction for validation decisions.

The validator may explain a decision, but it is not a proof authority.  This
module accepts only facts attached by deterministic analysis (or an explicitly
versioned proof record), and turns them into small auditable decision proofs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, cast


@dataclass(frozen=True)
class DecisionProof:
    outcome: str
    proof_kind: str
    producer_engine: str
    fact_ids: tuple[str, ...]
    code_hash: str
    assumptions: tuple[str, ...]
    contradiction_or_obligation: str
    scope: str
    completeness: str
    proof_version: str = "zscope.decision-proof.v4"
    subject_identity: str = ""
    cfg_nodes: tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return cast(Mapping[str, Any], value) if isinstance(value, Mapping) else {}


_REJECTION_REQUIREMENTS = {
    "guard_dominates_sink": {"guard_dominates_sink"},
    "sanitizer_dominates_sink": {"sanitizer_dominates_sink"},
    "lock_dominates_access": {"lock_dominates_access", "all_accesses_guarded"},
    "happens_before_orders_access": {"happens_before_proved"},
    "ownership_cleanup_complete": {"cleanup_all_paths"},
    "release_after_last_use": {"release_after_last_use"},
    "sink_unreachable": {"sink_unreachable"},
    "error_path_returns_before_sink": {"error_path_returns_before_sink"},
    "contract_precondition_enforced": {"contract_precondition_enforced"},
    "distinct_object_identity": {"distinct_object_identity"},
    "branch_paths_mutually_exclusive": {"branch_paths_mutually_exclusive"},
    # Evidence-completion providers use these narrower facts for common
    # ownership, allocation and bounds obligations.  They are all derived
    # from a complete local AST/CFG path and have their own proof kind, so a
    # model verdict can never turn them into a rejection by itself.
    "failed_acquisition_exit": {"fd_failure_guard", "failure_return"},
    "return_value_ownership_transfer": {"descriptor_returned_to_caller"},
    "durable_global_owner_transfer": {"ownership_transfer_complete"},
    "output_parameter_ownership_transfer": {"ownership_transfer_complete"},
    "returned_parent_ownership_transfer": {"ownership_transfer_complete"},
    "terminating_allocation_upper_bound": {
        "explicit_upper_bound",
        "terminating_guard",
        "guard_dominates_allocation",
    },
    "array_sink_identity_mismatch": {
        "fixed_array_identity",
        "write_identity_mismatch",
    },
    "dynamic_array_not_fixed_storage": {
        "pointer_declaration",
        "dynamic_array_storage",
    },
    "array_bound_guard_dominates_loop": {
        "fixed_array_bound",
        "terminating_upper_bound_guard",
        "guard_dominates_loop",
    },
    "balanced_lock_return_paths": {"all_return_paths_unlocked"},
    "matching_lock_dominates_unlock": {"matching_lock_dominates_unlock"},
    "allocation_capacity_dominates_copy": {
        "allocation_capacity_exceeds_copy",
        "same_length_symbol",
    },
    "failed_member_acquisition_cleanup": {
        "member_acquisition_failed",
        "parent_cleanup_on_failure_only",
    },
    "pointer_offset_not_data_pointer": {
        "pointer_derived_from_pointer_base",
        "not_data_integer_cast",
    },
    "cursor_progress_dominates_iteration": {"cursor_advances_before_iteration"},
    "not_signal_handler_reachable": {"ordinary_call_context"},
    "constant_contract_makes_sink_irrelevant": {"constant_contract_precondition"},
    "all_reachable_callers_bound_allocation": {
        "all_reachable_callers_bounded",
        "guard_dominates_allocation",
    },
    "allocation_capacity_covers_sink": {
        "allocation_capacity_covers_sink",
        "signedness_safe",
    },
    "fixed_array_index_proved_in_range": {
        "all_paths_index_in_range",
        "fixed_array_capacity",
    },
    "ownership_transferred_on_all_exits": {
        "same_field_sensitive_object",
        "all_exits_release_or_transfer",
    },
    "single_shared_access_not_race": {"single_shared_access_event"},
    "exact_allocation_length_covers_copy": {
        "same_field_sensitive_object",
        "allocation_length_equals_copy_length",
    },
    "matching_release_precedes_reported_exit": {
        "same_field_sensitive_object",
        "release_dominates_reported_exit",
    },
    "zero_initialized_member_failed_before_parent_release": {
        "zero_initialized_parent",
        "member_acquisition_failed",
        "parent_cleanup_on_failure_only",
    },
    "caller_owned_field_transfer": {
        "field_sensitive_object",
        "caller_owned_parent",
        "successful_return_transfers_responsibility",
    },
    # Source-level unsynchronized-write refutation (Phase 1.2/1.3): the
    # reported global's write set is dominated by one lock inside the
    # function body.  Read-shaped claims are never refuted here.
    "source_lockset_dominates_access": {
        "lock_dominates_access",
        "all_writes_guarded",
    },
    # Interprocedural lock-protocol refutation (Phase 1.2 "调用方持锁"):
    # every recorded caller holds the same mutex at the call site.
    "caller_lock_context_dominates": {
        "caller_lock_held_at_every_call_site",
    },
}

_CONFIRMATION_REQUIREMENTS = {
    "unguarded_source_to_sink": {"source_to_sink_complete", "missing_guard"},
    "out_of_range_value_reaches_sink": {"source_to_sink_complete", "out_of_range_value"},
    "use_after_free_path": {"free_before_use", "source_to_sink_complete"},
    "double_release_path": {"first_release", "second_release", "same_object_path"},
    "missing_cleanup_path": {"allocation_reachable", "cleanup_missing"},
    "race_without_happens_before": {"conflicting_accesses", "no_happens_before"},
    "contract_violation_path": {"caller_contract_violated", "source_to_sink_complete"},
    "deterministic_cfg_obligation_path": {
        "source_to_sink_complete",
        "event_path_complete",
    },
    "ordered_publication_before_initialization": {
        "allocation_before_publication",
        "publication_before_initialization",
    },
    "same_function_owned_member_cleanup_gap": {
        "same_function_helper_contract",
        "owned_member_not_released",
    },
    "async_stack_address_escape": {
        "stack_object_address_escapes",
        "async_lifetime_unbounded",
    },
    "container_unlink_without_release": {
        "container_owner_unlinked",
        "ownership_not_transferred_or_released",
    },
    "lock_held_on_failure_return": {
        "lock_acquired_before_failure",
        "failure_returns_with_lock_held",
    },
    "incomplete_owner_cleanup": {
        "multiple_owned_members_initialized",
        "owned_member_not_released",
    },
    "owned_member_left_live_when_parent_released": {
        "field_sensitive_owned_member",
        "parent_release",
        "member_not_released",
    },
    "external_value_controls_unbounded_allocation": {
        "external_source_to_allocation",
        "allocation_path_complete",
        "no_upper_bound_guard",
    },
    "allocation_arithmetic_overflow_reaches_sink": {
        "overflow_value_reachable",
        "arithmetic_precedes_guard",
        "allocation_sink_reached",
    },
    "registered_signal_path_calls_unsafe_operation": {
        "signal_context_reachable",
        "async_signal_unsafe_operation",
    },
    "entry_parameter_reaches_system_sink": {
        "scanned_entry_parameter_source",
        "nonliteral_system_sink",
        "entry_to_sink_path_complete",
        "no_structured_command_sanitizer",
    },
    "external_callback_invoked_under_lock": {
        "entry_parameter_callback_source",
        "callback_assignment_under_lock",
        "callback_invoked_before_matching_unlock",
        "entry_to_callback_path_complete",
    },
    "reachable_self_link_without_cycle_guard": {
        "self_link_assignment",
        "container_traversal_reachable",
        "cycle_guard_missing",
    },
    "exact_acquisition_exit_leak": {
        "successful_acquisition",
        "reachable_exit_without_release",
        "ownership_not_transferred",
    },
    # Source-level twin of the CFG event leak proof (Phase 1.2/1.3):
    # lifecycle facts re-derived from the validator's function source when
    # the engine supplied no CFG events.  The fact set pins the
    # path-independent negative existential exactly; no model text can mint
    # these facts.
    "source_lifecycle_acquire_without_release": {
        "event:acquire",
        "event:exit",
        "no_intraprocedural_release",
        "no_ownership_transfer",
    },
}


def deterministic_decision_proof(
    issue: Mapping[str, Any],
    *,
    outcome: str,
) -> Optional[DecisionProof]:
    """Return a complete proof from deterministic facts or ``None``.

    Proof records must originate in the issue/evidence pack, never in the LLM
    response.  This keeps a model from self-attesting that a guard or lock is
    complete merely by describing it in prose.
    """

    expected = str(outcome or "").lower()
    if issue.get("analysis_scope") == "conditional_source_branch":
        return None
    if expected == "reject" and issue.get("review_checked_proofs_enabled") is True:
        from .review_checks import checked_receipt

        receipt = checked_receipt(dict(issue))
        if receipt is None:
            return None
        return DecisionProof(
            outcome="reject", proof_kind="compiler_checked_review_claim",
            producer_engine=str(receipt["checker_version"]),
            fact_ids=(str(receipt["fact_store_id"]),),
            code_hash=str(receipt["candidate_binding"]),
            assumptions=("bound compiler configuration",),
            contradiction_or_obligation=str(receipt["reason"]),
            scope="candidate_obligation_in_current_build", completeness="complete",
            subject_identity=str(issue.get("candidate_uid") or ""),
        )
    requirements = _REJECTION_REQUIREMENTS if expected == "reject" else _CONFIRMATION_REQUIREMENTS
    for proof in _proof_records(issue):
        proof_outcome = str(proof.get("outcome") or proof.get("decision") or "").lower()
        if proof_outcome not in {expected, "rejected" if expected == "reject" else "confirmed"}:
            continue
        kind = str(proof.get("proof_kind") or proof.get("kind") or "").lower()
        required = requirements.get(kind)
        if not required:
            continue
        # M2 guard: the source_lifecycle acquire-without-release proof loses
        # its confirm authority when the demotion flag rides on the issue
        # (measured 0TP/1FP on the frozen balanced run).  The record stays
        # attached for diagnostics; it simply cannot decide a confirmation.
        if (
            expected == "confirm"
            and kind == "source_lifecycle_acquire_without_release"
            and issue.get("demote_source_lifecycle_confirm") is True
        ):
            continue
        facts = _fact_names(proof)
        if not required.issubset(facts):
            continue
        if not _complete(proof) or not _has_fact_ids(proof) or not _has_code_hash(proof, issue):
            continue
        engine = str(proof.get("producer_engine") or proof.get("engine") or "").lower()
        if not engine or engine in {"llm", "validator", "model"}:
            continue
        return DecisionProof(
            outcome=expected,
            proof_kind=kind,
            producer_engine=engine,
            fact_ids=tuple(
                sorted(_string_values(proof.get("fact_ids") or proof.get("evidence_refs")))
            ),
            code_hash=str(proof.get("code_hash") or _code_hash(issue)),
            assumptions=tuple(sorted(_string_values(proof.get("assumptions")))),
            contradiction_or_obligation=str(
                proof.get("contradiction_or_obligation")
                or proof.get("summary")
                or proof.get("reason")
                or kind
            ),
            scope=str(proof.get("scope") or "candidate"),
            completeness="complete",
            proof_version=str(proof.get("proof_version") or "zscope.decision-proof.v4"),
            subject_identity=str(
                proof.get("subject_identity")
                or issue.get("resource_identity")
                or issue.get("source_identity")
                or ""
            ),
            cfg_nodes=tuple(
                sorted(_string_values(proof.get("cfg_nodes") or proof.get("fact_ids")))
            ),
        )
    return None


def _proof_records(issue: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    pack = _as_mapping(issue.get("evidence_pack"))
    sources = (
        issue.get("deterministic_proofs"),
        issue.get("decision_proofs"),
        issue.get("proofs"),
        pack.get("deterministic_proofs"),
        pack.get("decision_proofs"),
        pack.get("proofs"),
    )
    for source in sources:
        if isinstance(source, Mapping):
            # A keyed collection may contain multiple proof objects.
            if "proof_kind" in source or "kind" in source:
                yield source
            else:
                for value in source.values():
                    if isinstance(value, Mapping):
                        yield value
        elif isinstance(source, (list, tuple)):
            for value in source:
                if isinstance(value, Mapping):
                    yield value


def _fact_names(proof: Mapping[str, Any]) -> set[str]:
    raw = proof.get("facts") or proof.get("fact_kinds") or proof.get("fact_names") or []
    result = {str(value).strip().lower() for value in _string_values(raw)}
    for key, value in proof.items():
        if value is True:
            result.add(str(key).strip().lower())
    return result


def _complete(proof: Mapping[str, Any]) -> bool:
    return str(proof.get("completeness") or "").lower() == "complete" or bool(
        proof.get("complete") is True
    )


def _has_fact_ids(proof: Mapping[str, Any]) -> bool:
    return bool(_string_values(proof.get("fact_ids") or proof.get("evidence_refs")))


def _code_hash(issue: Mapping[str, Any]) -> str:
    pack = _as_mapping(issue.get("evidence_pack"))
    return str(
        issue.get("dependency_code_hash")
        or issue.get("code_hash")
        or issue.get("source_fingerprint")
        or pack.get("dependency_code_hash")
        or pack.get("code_hash")
        or pack.get("source_fingerprint")
        or ""
    )


def _has_code_hash(proof: Mapping[str, Any], issue: Mapping[str, Any]) -> bool:
    return bool(str(proof.get("code_hash") or _code_hash(issue)).strip())


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if str(item).strip()]
    return []
