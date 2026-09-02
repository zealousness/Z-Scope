from __future__ import annotations

import pytest

from zscope.core.validation.audit_eligibility import (
    AUDIT_ELIGIBILITY_VERSION,
    AUDIT_ONLY_DISPOSITION,
    evaluate_audit_eligibility,
    has_exact_v4_producer_occurrence_binding,
    revalidate_v4_producer_occurrence_binding,
)


def _issue(**overrides):
    issue = {
        "candidate_source": "hypothesis_hunter",
        "candidate_uid": "CAND_1",
        "validation_cluster_uid": "VAL_1",
        "file": "src/demo.c",
        "line": 10,
        "function": "parse",
        "category": "integer_overflow",
        "source_identity": "wire_len",
        "security_obligation": {
            "obligation_uid": "OBL_1",
            "defect_family": "integer_overflow",
            "subject_uid": "wire_len",
            "required_fact_kinds": ["value_range", "guard_dominance"],
        },
        "missing_fact_kinds": ["value_range"],
        "validator_evidence_actions": [
            {
                "action_id": "ACTION_1",
                "fact_kind": "value_range",
                "provider_id": "path-and-guard-provider",
                "verifier_id": "proof-checker",
            }
        ],
        "validator_pass_history": [{"pass": "initial"}],
        "proof_closure_evaluation": {"status": "open", "conflicting_clauses": []},
    }
    issue.update(overrides)
    return issue


def _native_v4_issue(
    *,
    candidate_source: str = "llm",
    include_unrelated_event: bool = False,
    **overrides,
):
    from zscope.core.validation.fact_capabilities import FunctionIRFactService
    from zscope.core.validation.function_ir import FunctionIRGraph
    from zscope.core.validation.proof_kernel import ProofKernelEngine
    from zscope.orchestration.candidate_envelope import annotate_issue_identity

    external_malloc_call = {
        "callee": "malloc",
        "line": 4,
        "callee_decl_identity": (
            '{"kind":"FunctionDecl","name":"malloc",' '"type":"void *(size_t)"}'
        ),
        "callee_binding_complete": True,
        "callee_decl_origin": "external_declaration",
        "callee_project_definition": False,
        "result_type": "void *",
        "arg_count": 1,
        "argument_kinds": ["IntegerLiteral"],
        "argument_types": ["int"],
        "argument_refs": [[]],
        "argument_ref_types": [{}],
        "first_argument_refs": [],
    }
    unrelated_malloc_call = {
        **external_malloc_call,
        "line": 5,
    }
    call_exprs = [external_malloc_call]
    call_assignments = [{**external_malloc_call, "target": "p"}]
    statements = ["p = malloc(8)"]
    var_decls = [
        {
            "name": "p",
            "type": "void *",
            "line": 4,
            "storage_class": "",
        }
    ]
    if include_unrelated_event:
        call_exprs.append(unrelated_malloc_call)
        call_assignments.append({**unrelated_malloc_call, "target": "q"})
        statements.append("q = malloc(8)")
        var_decls.append(
            {
                "name": "q",
                "type": "void *",
                "line": 5,
                "storage_class": "",
            }
        )
    graph = FunctionIRGraph.from_clang_evidence(
        {
            "clang_path": "clang",
            "code_snapshot_sha256": "d" * 64,
            "cfg_dump": {
                "summary": {
                    "parse_ok": True,
                    "function": "resource_target",
                    "function_section_unique": True,
                    "entry_blocks": ["B1"],
                    "exit_blocks": ["B0"],
                    "blocks": [
                        {
                            "id": "B1",
                            "label": "(ENTRY)",
                            "successors": ["B0"],
                            "predecessors": [],
                            "statements": statements,
                        },
                        {
                            "id": "B0",
                            "label": "(EXIT)",
                            "successors": [],
                            "predecessors": ["B1"],
                            "statements": [],
                        },
                    ],
                }
            },
            "ast_dump": {
                "summary": {
                    "parse_ok": True,
                    "target_function": {
                        "call_exprs": call_exprs,
                        "call_assignments": call_assignments,
                        "var_decls": var_decls,
                        "value_fact_coverage_complete": True,
                    },
                }
            },
        },
        function="resource_target",
        file="src/resource.c",
    )
    assert graph is not None and graph.coverage_complete is True
    issue = _issue(
        candidate_source=candidate_source,
        file="src/resource.c",
        line=4,
        location="src/resource.c:4",
        function="resource_target",
        category="memory_leak",
        defect_class="memory_leak",
        source={
            "kind": "resource_acquire",
            "function": "resource_target",
            "file": "src/resource.c",
            "line": 4,
            "operation": "malloc",
            "resource": "p",
        },
        sink={
            "kind": "exit",
            "function": "resource_target",
            "file": "src/resource.c",
            "line": 4,
            "resource": "p",
        },
        resource="p",
        function_ir_graph=graph.to_dict(),
        decision_fact_graph_v1=True,
        decision_context_v31=True,
        decision_context_v32=True,
        decision_context_v33=True,
        security_obligation_v1=True,
        missing_fact_kinds=[],
        validator_evidence_actions=[],
    )
    annotate_issue_identity(
        issue,
        project_id="p6-audit-test",
        revision="rev-p6-audit-test",
    )
    assert issue["security_obligation"]["decision_fact_slice"] == issue["decision_fact_slice"]
    frozen = FunctionIRFactService(None, enabled=False).build_composite_proof_input(issue, {})
    assert frozen is not None
    complete_selection = tuple(map(str, frozen["selected_action_uids"]))
    assert len(complete_selection) >= 2
    # Freeze a genuinely actionable incomplete obligation: the omitted action
    # is still present in the reducer-owned catalog, so its missing clause has
    # a concrete deterministic proof plan without trusting model-authored
    # ``missing_fact_kinds`` or action descriptors.
    selected = complete_selection[:-1]
    frozen = {**frozen, "selected_action_uids": list(selected)}
    evaluation = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=frozen["proof_ir"],
        obligation=frozen["proof_obligation"],
        selected_action_uids=selected,
    )
    assert evaluation.closure_evaluation.complete is False
    issue["proof_kernel_input"] = frozen
    issue["proof_kernel_input_origin"] = "product_composite_obligation_v4"
    issue["proof_kernel_checker_results"] = [dict(value) for value in evaluation.check_results]
    issue["proof_kernel_live_selected_action_uids"] = list(selected)
    evaluation.apply_to_issue(issue)
    issue.update(overrides)
    return issue


def _native_hunter_v4_issue():
    from scripts.qualify_p6_proof_promotion import _freeze_reduce
    from zscope.core.validation.proof_kernel import ProofKernelEngine
    from zscope.orchestration.hypothesis_hunter.models import build_hypothesis_offer
    from zscope.orchestration.hypothesis_hunter.qualification import (
        load_builtin_qualification,
    )

    replay = next(
        value
        for value in load_builtin_qualification()["frozen_replays"]
        if value["expected_shadow_decision"] == "needs_review"
    )
    state, closure, authority_input = _freeze_reduce(
        proof_ir=replay["program_proof_ir"],
        obligation=replay["proof_obligation"],
        actions=[replay["evidence_action"]],
        check_results=replay["checker_results"],
    )
    hypothesis = replay["security_hypothesis"]
    location = hypothesis["location"]
    summary = replay["program_proof_ir"]["functions"][0]
    catalog = ProofKernelEngine().action_catalog(
        proof_ir=replay["program_proof_ir"],
        obligation=replay["proof_obligation"],
    )
    offer = build_hypothesis_offer(
        audit_unit_uid=hypothesis["audit_unit_uid"],
        defect_family=hypothesis["defect_family"],
        subject_uid=hypothesis["subject_uid"],
        decision_region_uid=hypothesis["decision_region_uid"],
        location=location,
        source_ref=hypothesis.get("source_ref"),
        sink_ref=hypothesis.get("sink_ref"),
        resource_ref=hypothesis.get("resource_ref"),
        proof_ir=replay["program_proof_ir"],
        proof_obligation=replay["proof_obligation"],
        evidence_actions=catalog,
        supporting_fact_refs=hypothesis["supporting_fact_refs"],
        opposing_fact_refs=hypothesis["opposing_fact_refs"],
        unknown_fact_refs=hypothesis["unknown_fact_refs"],
        evidence_refs=hypothesis["evidence_refs"],
        dependency_hashes=hypothesis["dependency_hashes"],
    )
    assert offer["offer_uid"] == hypothesis["offer_uid"]
    return _issue(
        candidate_source="hypothesis_hunter",
        file=location["file"],
        line=location["start_line"],
        function=summary["function_uid"],
        location=dict(location),
        source_identity=hypothesis["subject_uid"],
        hypothesis_offer=offer,
        security_hypothesis=hypothesis,
        attribution={
            "schema_version": "zscope.finding-attribution.v2",
            "discovered_by": ["hypothesis_hunter"],
            "discovery_details": [
                {
                    "kind": "hypothesis_hunter",
                    "source_id": hypothesis["offer_uid"],
                }
            ],
            "decided_by": "unresolved",
            "decision_level": "none",
            "decision_details": {},
        },
        missing_fact_kinds=[],
        validator_evidence_actions=[],
        security_obligation={
            "obligation_uid": state.obligation_uid,
            "defect_family": hypothesis["defect_family"],
            "subject_uid": state.subject_uid,
        },
        proof_kernel_input=authority_input,
        proof_kernel_checker_results=replay["checker_results"],
        proof_kernel_frozen_state=state.to_dict(),
        proof_kernel_closure_evaluation=closure.to_dict(),
        proof_kernel_live_selected_action_uids=[replay["evidence_action"]["action_uid"]],
    )


def _rebind_hunter_authority(
    issue: dict,
    *,
    proof_ir: dict,
    obligation: dict,
) -> None:
    """Coordinate a hostile proof/hypothesis reseal but keep the producer offer frozen."""

    from zscope.core.validation.proof_kernel import ProofKernelEngine
    from zscope.orchestration.hypothesis_hunter.models import (
        build_hypothesis_offer,
        materialize_security_hypothesis,
    )

    original_offer = issue["hypothesis_offer"]
    original_hypothesis = issue["security_hypothesis"]
    catalog = ProofKernelEngine().action_catalog(
        proof_ir=proof_ir,
        obligation=obligation,
    )
    assert catalog
    selected = [str(value["action_uid"]) for value in catalog]
    replacement_offer = build_hypothesis_offer(
        audit_unit_uid=original_offer["audit_unit_uid"],
        defect_family=original_offer["defect_family"],
        subject_uid=original_offer["subject_uid"],
        decision_region_uid=original_offer["decision_region_uid"],
        location=original_offer["location"],
        source_ref=original_offer.get("source_ref"),
        sink_ref=original_offer.get("sink_ref"),
        resource_ref=original_offer.get("resource_ref"),
        proof_ir=proof_ir,
        proof_obligation=obligation,
        evidence_actions=catalog,
        supporting_fact_refs=original_offer["supporting_fact_refs"],
        opposing_fact_refs=original_offer["opposing_fact_refs"],
        unknown_fact_refs=original_offer["unknown_fact_refs"],
        evidence_refs=original_offer["evidence_refs"],
        dependency_hashes=original_offer["dependency_hashes"],
    )
    replacement_hypothesis = materialize_security_hypothesis(
        offer=replacement_offer,
        selection={
            "offer_uid": replacement_offer["offer_uid"],
            "evidence_action_uids": selected,
            "supporting_fact_refs": original_hypothesis["supporting_fact_refs"],
            "opposing_fact_refs": original_hypothesis["opposing_fact_refs"],
            "unknown_fact_refs": original_hypothesis["unknown_fact_refs"],
            "evidence_refs": original_hypothesis["evidence_refs"],
        },
    )
    authority_input = {
        "schema_version": "zscope.proof-kernel-authority-input.v1",
        "proof_ir": proof_ir,
        "proof_obligation": obligation,
        "selected_action_uids": selected,
    }
    evaluation = ProofKernelEngine().reevaluate_authority_input(authority_input)
    assert evaluation.closure_evaluation.disposition == "needs_review"
    issue["security_hypothesis"] = replacement_hypothesis
    issue["proof_kernel_input"] = authority_input
    issue["proof_kernel_checker_results"] = [dict(value) for value in evaluation.check_results]
    issue["proof_kernel_live_selected_action_uids"] = selected
    evaluation.apply_to_issue(issue)


def _product_v4_binding(issue) -> str:
    import zscope.core.validation.audit_eligibility as module

    authority_input = issue["proof_kernel_input"]
    return module._product_candidate_binding(
        issue,
        proof_ir=authority_input["proof_ir"],
        proof_obligation=authority_input["proof_obligation"],
        selected_action_uids=authority_input["selected_action_uids"],
    )


@pytest.mark.parametrize("factory", [_native_v4_issue, _native_hunter_v4_issue])
def test_shared_v4_producer_occurrence_binding_rebuilds_and_compares_exactly(factory) -> None:
    issue = factory()

    producer_binding, occurrence_binding = revalidate_v4_producer_occurrence_binding(issue)

    assert len(producer_binding) == 64
    assert len(occurrence_binding) == 64
    issue["proof_kernel_producer_binding_sha256"] = producer_binding
    issue["proof_kernel_occurrence_binding_sha256"] = occurrence_binding
    assert has_exact_v4_producer_occurrence_binding(issue) is True
    issue["proof_kernel_occurrence_binding_sha256"] = "f" * 64
    assert has_exact_v4_producer_occurrence_binding(issue) is False


def _coordinated_candidate_reseal_with_untrusted_fact_slice(issue) -> None:
    """Model the old trusted-identity shortcut after a fact-slice rewrite."""

    from types import MappingProxyType

    from zscope.orchestration.candidate_envelope import CandidateEnvelope

    projected = {
        "candidate_schema_version",
        "candidate_uid",
        "occurrence_uid",
        "history_key",
        "evidence_hash",
        "decision_evidence_hash",
        "provenance_hash",
        "validation_cluster_uid",
        "run_issue_uid",
        "context_signature",
        "obligation_uid",
        "obligation_shape",
        "decision_fact_version",
        "decision_context_version",
        "project_id",
        "revision",
        "defect_class",
        "source_identity",
        "sink_identity",
        "resource_identity",
        "evidence_models",
        "evidence_sources",
        "entry_paths",
        "record_role",
        "candidate_disposition",
        "evidence_completeness",
    }
    attack_input = {key: value for key, value in issue.items() if key not in projected}
    # The attacker hashes the rewritten projection without invoking the
    # governed DecisionFactGraph producer.  This is exactly the coordinated
    # re-seal that the product authority must independently reject.
    attack_input["decision_fact_graph_v1"] = False
    envelope = CandidateEnvelope.from_issue(
        MappingProxyType(attack_input),
        project_id=issue["project_id"],
        revision=issue["revision"],
        default_disposition="needs_review",
    )
    field_map = {
        "candidate_schema_version": "schema_version",
        "candidate_uid": "candidate_uid",
        "occurrence_uid": "occurrence_uid",
        "history_key": "history_key",
        "evidence_hash": "evidence_hash",
        "decision_evidence_hash": "decision_evidence_hash",
        "provenance_hash": "provenance_hash",
        "validation_cluster_uid": "validation_cluster_uid",
        "run_issue_uid": "run_issue_uid",
        "context_signature": "context_signature",
        "obligation_uid": "obligation_uid",
        "obligation_shape": "obligation_shape",
        "decision_fact_version": "decision_fact_version",
        "decision_context_version": "decision_context_version",
        "project_id": "project_id",
        "revision": "revision",
        "defect_class": "defect_class",
        "source_identity": "source_identity",
        "sink_identity": "sink_identity",
        "resource_identity": "resource_identity",
    }
    sealed = envelope.to_dict()
    for issue_key, envelope_key in field_map.items():
        issue[issue_key] = sealed[envelope_key]
    issue["decision_fact_graph_v1"] = True


def test_specific_qualified_unresolved_obligation_stays_needs_review(monkeypatch) -> None:
    import zscope.core.validation.audit_eligibility as module

    monkeypatch.setattr(module, "_v4_qualification_binding", lambda _issue: "a" * 64)
    monkeypatch.setattr(
        module,
        "_recomputed_executable_fact_kinds",
        lambda _issue, _open: {"value_range"},
    )
    result = evaluate_audit_eligibility(_issue())
    assert result.schema_version == AUDIT_ELIGIBILITY_VERSION
    assert result.needs_review_eligible is True
    assert result.disposition == "needs_review"
    assert result.reason_codes == ()
    assert result.qualification_binding_sha256 == "a" * 64
    assert len(result.input_sha256) == 64


def test_broad_hint_without_anchor_or_obligation_is_audit_only() -> None:
    result = evaluate_audit_eligibility(
        {
            "candidate_source": "hypothesis_hunter",
            "category": "potential_issue",
            "validator_pass_history": [{"pass": "initial"}],
        }
    )
    assert result.needs_review_eligible is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION
    assert "AUDIT_CONCRETE_ANCHOR_MISSING" in result.reason_codes
    assert "AUDIT_FALSIFIABLE_OBLIGATION_MISSING" in result.reason_codes


def test_non_executable_caller_contract_does_not_enter_actionable_view() -> None:
    issue = _issue(
        security_obligation={
            "obligation_uid": "OBL_CALLER",
            "defect_family": "api_contract_violation",
            "subject_uid": "public_api",
            "required_fact_kinds": ["caller_contract"],
        },
        missing_fact_kinds=["caller_contract"],
        validator_evidence_actions=[],
        fact_capabilities=[
            {
                "fact_kind": "caller_contract",
                "supported": True,
                "executable_for_subject_region": False,
            }
        ],
    )
    result = evaluate_audit_eligibility(issue)
    assert result.needs_review_eligible is False
    assert "AUDIT_EXECUTABLE_PROOF_PLAN_MISSING" in result.reason_codes


def test_counterproof_never_remains_needs_review() -> None:
    result = evaluate_audit_eligibility(
        _issue(
            proof_closure_evaluation={
                "status": "conflicting",
                "conflicting_clauses": ["value_range"],
            }
        )
    )
    assert result.needs_review_eligible is False
    assert result.unrefuted is False


def test_exact_rule_qualification_cannot_replace_v4_proof_authority(monkeypatch) -> None:
    import zscope.core.validation.audit_eligibility as module

    monkeypatch.setattr(
        module,
        "_qualified_rule_bindings",
        lambda: {("RULE_OK", 2): "b" * 64},
    )
    monkeypatch.setattr(
        module,
        "_deterministic_rule_producer_binding",
        lambda _issue, *, rule_id, revision: (
            "c" * 64 if (rule_id, revision) == ("RULE_OK", 2) else ""
        ),
    )
    monkeypatch.setattr(
        module,
        "_recomputed_executable_fact_kinds",
        lambda _issue, _open: {"value_range"},
    )
    pending = evaluate_audit_eligibility(
        _issue(rule_id="RULE_PENDING", rule_revision=1, candidate_source="clang_ast_cfg")
    )
    qualified_rule_only = evaluate_audit_eligibility(
        _issue(rule_id="RULE_OK", rule_revision=2, candidate_source="clang_ast_cfg")
    )
    assert pending.qualification_backed is False
    assert pending.disposition == AUDIT_ONLY_DISPOSITION
    assert qualified_rule_only.qualification_backed is False
    assert qualified_rule_only.qualification_binding_sha256 == ""
    assert qualified_rule_only.disposition == AUDIT_ONLY_DISPOSITION


def test_model_authored_action_and_capability_projections_do_not_grant_eligibility(
    monkeypatch,
) -> None:
    import zscope.core.validation.audit_eligibility as module

    monkeypatch.setattr(module, "_v4_qualification_binding", lambda _issue: "a" * 64)
    result = evaluate_audit_eligibility(
        _issue(
            function_ir_graph={},
            fact_capabilities=[
                {
                    "fact_kind": "value_range",
                    "supported": True,
                    "executable_for_subject_region": True,
                }
            ],
            proof_clause_action_plan={"value_range": {"executable": True}},
        )
    )

    assert result.qualification_backed is True
    assert result.executable_proof_plan is False
    assert result.needs_review_eligible is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_llm_cannot_borrow_a_qualified_deterministic_rule_identity(monkeypatch) -> None:
    import zscope.core.validation.audit_eligibility as module

    rule_id, revision = "RULE_QUALIFIED_ONLY_FOR_DETERMINISTIC_PRODUCER", 7
    monkeypatch.setattr(
        module,
        "_qualified_rule_bindings",
        lambda: {(rule_id, revision): "b" * 64},
    )
    result = evaluate_audit_eligibility(
        _issue(
            candidate_source="llm",
            native_rule_id=rule_id,
            rule_id=rule_id,
            rule_revision=revision,
            attribution={
                "discovered_by": ["deterministic_rule"],
                "discovery_details": [{"kind": "deterministic_rule", "source_id": rule_id}],
            },
        )
    )

    assert result.qualification_backed is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_source_name_and_validator_history_do_not_self_qualify() -> None:
    for source in ("hypothesis_hunter", "llm", "semantic", "backend_signal"):
        result = evaluate_audit_eligibility(
            _issue(candidate_source=source, validator_invocation_count=3)
        )
        assert result.qualification_backed is False
        assert result.qualification_binding_sha256 == ""
        assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_classification_input_is_answer_free() -> None:
    base = evaluate_audit_eligibility(_issue())
    contaminated = evaluate_audit_eligibility(
        _issue(
            truth_id="RANGE_V16_001",
            expected="confirmed",
            benchmark_score={"matched": True},
        )
    )
    assert contaminated == base


def test_native_v4_frozen_state_proves_falsifiable_executable_open_clause() -> None:
    issue = _native_v4_issue()
    result = evaluate_audit_eligibility(issue)
    assert result.falsifiable_obligation is True
    assert result.executable_proof_plan is True
    assert result.qualification_backed is True
    assert len(result.qualification_binding_sha256) == 64
    assert result.needs_review_eligible is True


def test_unqualified_rule_label_cannot_mask_verified_v4_successor() -> None:
    issue = _native_v4_issue(
        rule_id="RULE_NOT_IN_QUALIFICATION_REGISTRY",
        rule_revision=1,
        candidate_source="clang_ast_cfg",
    )
    result = evaluate_audit_eligibility(issue)
    assert result.qualification_backed is True
    assert len(result.qualification_binding_sha256) == 64
    assert result.needs_review_eligible is True


def test_rule_and_v4_qualification_are_jointly_bound(monkeypatch) -> None:
    import zscope.core.validation.audit_eligibility as module

    monkeypatch.setattr(
        module,
        "_qualified_rule_bindings",
        lambda: {("RULE_OK", 2): "b" * 64},
    )
    monkeypatch.setattr(
        module,
        "_deterministic_rule_producer_binding",
        lambda _issue, *, rule_id, revision: (
            "c" * 64 if (rule_id, revision) == ("RULE_OK", 2) else ""
        ),
    )
    monkeypatch.setattr(module, "_v4_qualification_binding", lambda _issue: "a" * 64)
    v4_only = evaluate_audit_eligibility(_native_v4_issue())
    jointly_bound = evaluate_audit_eligibility(
        _native_v4_issue(
            rule_id="RULE_OK",
            rule_revision=2,
            candidate_source="clang_ast_cfg",
        )
    )
    assert jointly_bound.qualification_backed is True
    assert jointly_bound.qualification_binding_sha256 != v4_only.qualification_binding_sha256


def test_hunter_v4_envelope_still_requires_sealed_hypothesis() -> None:
    result = evaluate_audit_eligibility(_native_v4_issue(candidate_source="hypothesis_hunter"))
    assert result.qualification_backed is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_hunter_with_sealed_hypothesis_and_v4_successor_remains_actionable(
    monkeypatch,
) -> None:
    import zscope.core.validation.audit_eligibility as module

    monkeypatch.setattr(
        module,
        "_successor_runtime_binding",
        lambda: ("a" * 64, "b" * 64, "candidate_registration_only"),
    )
    result = evaluate_audit_eligibility(_native_hunter_v4_issue())
    assert result.qualification_backed is True
    assert len(result.qualification_binding_sha256) == 64
    assert result.needs_review_eligible is True


def test_tampered_v4_closure_is_not_qualification_backed() -> None:
    issue = _issue(
        candidate_source="llm",
        proof_kernel_input={},
        proof_kernel_frozen_state={"schema_version": "zscope.frozen-proof-state.v1"},
        proof_kernel_closure_evaluation={"schema_version": "zscope.proof-closure-evaluation.v1"},
    )
    result = evaluate_audit_eligibility(issue)
    assert result.qualification_backed is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_v4_authority_selection_must_exactly_equal_frozen_selection() -> None:
    issue = _native_v4_issue()
    issue["proof_kernel_input"]["selected_action_uids"] = []

    result = evaluate_audit_eligibility(issue)

    assert result.qualification_backed is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_v4_checker_result_array_rejects_malformed_entries_instead_of_filtering() -> None:
    issue = _native_v4_issue()
    issue["proof_kernel_checker_results"].append("not-a-checker-result")

    result = evaluate_audit_eligibility(issue)

    assert result.qualification_backed is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_v4_checker_result_array_rejects_duplicate_results() -> None:
    issue = _native_v4_issue()
    issue["proof_kernel_checker_results"].append(dict(issue["proof_kernel_checker_results"][0]))

    result = evaluate_audit_eligibility(issue)

    assert result.qualification_backed is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_partial_v4_requires_every_executable_counterproof_to_be_checked(
    monkeypatch,
) -> None:
    import zscope.core.validation.audit_eligibility as module
    from zscope.core.validation.fact_capabilities import FunctionIRFactService
    from zscope.core.validation.proof_kernel import ProofKernelEngine
    from zscope.core.validation.proof_kernel.models import (
        build_proof_clause,
        build_proof_obligation,
    )
    from zscope.core.validation.proof_kernel.registry import PREDICATE_REGISTRY

    issue = _native_v4_issue()
    authority_input = issue["proof_kernel_input"]
    proof_ir = authority_input["proof_ir"]
    base_obligation = authority_input["proof_obligation"]
    base_catalog = ProofKernelEngine().action_catalog(
        proof_ir=proof_ir,
        obligation=base_obligation,
    )
    parameters = dict(base_catalog[0]["fixed_parameters"])
    spec = PREDICATE_REGISTRY["qualified_leak_cleanup_complete"]
    counterproof = build_proof_clause(
        role="counterproof",
        provider_family=spec.provider_family,
        predicate_id=spec.predicate_id,
        fact_kind=spec.fact_kind,
        quantifier=spec.quantifier,
        expected_value={"cleanup_complete": True},
        parameters=parameters,
    )
    obligation = build_proof_obligation(
        validation_cluster_uid=base_obligation["validation_cluster_uid"],
        defect_family=base_obligation["defect_family"],
        subject_uid=base_obligation["subject_uid"],
        decision_region_uid=base_obligation["decision_region_uid"],
        confirmation_clauses=base_obligation["confirmation_clauses"],
        counterproof_clauses=(counterproof,),
        dependency_hashes=proof_ir["dependency_hashes"],
    )
    engine = ProofKernelEngine()
    catalog = engine.action_catalog(proof_ir=proof_ir, obligation=obligation)
    confirmation_action = next(
        value
        for value in catalog
        if value["clause_uid"]
        in {item["clause_uid"] for item in obligation["confirmation_clauses"]}
    )
    counterproof_action = next(
        value for value in catalog if value["clause_uid"] == counterproof["clause_uid"]
    )

    monkeypatch.setattr(
        module,
        "_successor_runtime_binding",
        lambda: ("a" * 64, "", "candidate_registration_only"),
    )
    complete_composite = {
        "schema_version": authority_input["schema_version"],
        "proof_ir": proof_ir,
        "proof_obligation": obligation,
        "selected_action_uids": [str(value["action_uid"]) for value in catalog],
    }
    monkeypatch.setattr(
        FunctionIRFactService,
        "build_composite_proof_input",
        lambda *_a, **_k: complete_composite,
    )
    monkeypatch.setattr(module, "_v4_occurrence_binding", lambda *_a, **_k: "c" * 64)

    def apply_selection(action_uids: list[str]) -> None:
        current_input = {
            "schema_version": authority_input["schema_version"],
            "proof_ir": proof_ir,
            "proof_obligation": obligation,
            "selected_action_uids": action_uids,
        }
        evaluation = engine.reevaluate_authority_input(current_input)
        assert evaluation.closure_evaluation.complete is False
        assert evaluation.closure_evaluation.integrity_status == "verified"
        issue["proof_kernel_input"] = current_input
        issue["proof_kernel_checker_results"] = [dict(value) for value in evaluation.check_results]
        evaluation.apply_to_issue(issue)

    apply_selection([confirmation_action["action_uid"]])
    assert counterproof_action["action_uid"] not in issue["proof_kernel_live_selected_action_uids"]
    assert module._v4_qualification_binding(issue) == ""
    assert evaluate_audit_eligibility(issue).disposition == AUDIT_ONLY_DISPOSITION

    # Counterproof status need not prove or refute the vulnerability, but the
    # executable action must have been run and checked before the remaining
    # confirmation work is exposed as actionable needs_review.
    apply_selection([confirmation_action["action_uid"], counterproof_action["action_uid"]])
    assert _product_v4_binding(issue)
    assert module._v4_qualification_binding(issue)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("file", "src/unrelated.c"),
        ("function", "unrelated_function"),
        ("line", 999),
    ],
)
def test_v4_occurrence_must_match_sealed_function_ir_anchor(
    field: str,
    replacement: object,
) -> None:
    issue = _native_v4_issue()
    issue[field] = replacement

    result = evaluate_audit_eligibility(issue)

    assert result.qualification_backed is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_v4_occurrence_rejects_unrelated_event_on_same_function_line() -> None:
    issue = _native_v4_issue(include_unrelated_event=True, line=5)
    proof_ir = issue["proof_kernel_input"]["proof_ir"]
    assert any(
        event["attributes"]["source_line"] == 5 for event in proof_ir["functions"][0]["events"]
    )

    result = evaluate_audit_eligibility(issue)

    assert result.qualification_backed is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("candidate_uid", "CAND_REBOUND"),
        ("validation_cluster_uid", "VAL_REBOUND"),
        ("obligation_uid", "OBL_REBOUND"),
        ("decision_evidence_hash", "f" * 64),
        ("source_identity", "rebound-source"),
        ("sink_identity", "rebound-sink"),
        ("resource_identity", "q"),
    ],
)
def test_v4_product_candidate_identity_cannot_be_rebound(
    field: str,
    replacement: object,
) -> None:
    issue = _native_v4_issue()
    issue[field] = replacement

    result = evaluate_audit_eligibility(issue)

    assert result.qualification_backed is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_v4_security_obligation_projection_cannot_be_rebound() -> None:
    issue = _native_v4_issue()
    issue["security_obligation"] = {
        **issue["security_obligation"],
        "subject_uid": "q",
    }

    result = evaluate_audit_eligibility(issue)

    assert result.qualification_backed is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_hunter_issue_location_must_exactly_equal_sealed_hypothesis_location() -> None:
    issue = _native_hunter_v4_issue()
    issue["location"] = {**issue["location"], "statement_uid": "STATEMENT_OTHER"}

    result = evaluate_audit_eligibility(issue)

    assert result.qualification_backed is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_hunter_v4_requires_the_system_attached_full_offer(monkeypatch) -> None:
    import zscope.core.validation.audit_eligibility as module

    monkeypatch.setattr(
        module,
        "_successor_runtime_binding",
        lambda: ("a" * 64, "b" * 64, "candidate_registration_only"),
    )
    issue = _native_hunter_v4_issue()
    issue.pop("hypothesis_offer")

    result = evaluate_audit_eligibility(issue)

    assert result.qualification_backed is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_hunter_self_sealed_hypothesis_cannot_replace_producer_obligation(
    monkeypatch,
) -> None:
    from zscope.core.validation.proof_kernel import (
        build_proof_clause,
        build_proof_obligation,
    )
    import zscope.core.validation.audit_eligibility as module

    monkeypatch.setattr(
        module,
        "_successor_runtime_binding",
        lambda: ("a" * 64, "b" * 64, "candidate_registration_only"),
    )
    issue = _native_hunter_v4_issue()
    raw = issue["proof_kernel_input"]
    original = raw["proof_obligation"]
    clause = original["confirmation_clauses"][0]
    parameters = dict(clause["parameters"])
    parameter_name = sorted(parameters)[0]
    parameters[parameter_name] = "HUNTER_RESEALED_PARAMETER"
    replacement_clause = build_proof_clause(
        role="confirmation",
        provider_family=clause["provider_family"],
        predicate_id=clause["predicate_id"],
        fact_kind=clause["fact_kind"],
        quantifier=clause["quantifier"],
        expected_value=clause["expected_value"],
        parameters=parameters,
        required=clause["required"],
    )
    replacement = build_proof_obligation(
        validation_cluster_uid=original["validation_cluster_uid"],
        defect_family=original["defect_family"],
        subject_uid=original["subject_uid"],
        decision_region_uid=original["decision_region_uid"],
        confirmation_clauses=(replacement_clause,),
        counterproof_clauses=original["counterproof_clauses"],
        open_clauses=original["open_clauses"],
        dependency_hashes=original["dependency_hashes"],
    )
    _rebind_hunter_authority(
        issue,
        proof_ir=raw["proof_ir"],
        obligation=replacement,
    )

    result = evaluate_audit_eligibility(issue)

    assert result.qualification_backed is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_hunter_resealed_proof_ir_cannot_replace_producer_offer(monkeypatch) -> None:
    from zscope.core.validation.proof_kernel.canonical import seal_mapping
    import zscope.core.validation.audit_eligibility as module

    monkeypatch.setattr(
        module,
        "_successor_runtime_binding",
        lambda: ("a" * 64, "b" * 64, "candidate_registration_only"),
    )
    issue = _native_hunter_v4_issue()
    raw = issue["proof_kernel_input"]
    original_ir = raw["proof_ir"]
    summary_body = dict(original_ir["functions"][0])
    summary_body.pop("summary_uid")
    summary_body.pop("content_sha256")
    summary_body["signature"] = str(summary_body["signature"]) + " resealed"
    replacement_summary = seal_mapping(
        summary_body,
        uid_field="summary_uid",
        prefix="FUNSUM_",
    )
    ir_body = dict(original_ir)
    ir_body.pop("proof_ir_uid")
    ir_body.pop("content_sha256")
    ir_body["functions"] = [replacement_summary]
    replacement_ir = seal_mapping(
        ir_body,
        uid_field="proof_ir_uid",
        prefix="PROOFIR_",
    )
    _rebind_hunter_authority(
        issue,
        proof_ir=replacement_ir,
        obligation=raw["proof_obligation"],
    )

    result = evaluate_audit_eligibility(issue)

    assert result.qualification_backed is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_product_v4_binding_rebuilds_current_function_ir() -> None:
    issue = _native_v4_issue()
    assert _product_v4_binding(issue)

    issue["function_ir_graph"] = {
        **issue["function_ir_graph"],
        "code_snapshot_sha256": "e" * 64,
    }

    assert _product_v4_binding(issue) == ""


def test_product_v4_binding_rebuilds_decision_fact_slice_after_coordinated_reseal() -> None:
    issue = _native_v4_issue()
    assert _product_v4_binding(issue)

    tampered_slice = {
        **issue["decision_fact_slice"],
        "coverage": "complete",
        "missing_fact_kinds": [],
    }
    issue["decision_fact_slice"] = tampered_slice
    issue["security_obligation"] = {
        **issue["security_obligation"],
        "decision_fact_slice": tampered_slice,
    }
    _coordinated_candidate_reseal_with_untrusted_fact_slice(issue)

    assert _product_v4_binding(issue) == ""


def test_product_v4_binding_rejects_trimmed_compound_obligation_after_reseal() -> None:
    from zscope.core.validation.proof_kernel import ProofKernelEngine
    from zscope.core.validation.proof_kernel.models import build_proof_obligation

    issue = _native_v4_issue()
    assert _product_v4_binding(issue)
    authority_input = issue["proof_kernel_input"]
    original = authority_input["proof_obligation"]
    confirmation = list(original["confirmation_clauses"])
    assert len(confirmation) >= 3
    trimmed = build_proof_obligation(
        validation_cluster_uid=original["validation_cluster_uid"],
        defect_family=original["defect_family"],
        subject_uid=original["subject_uid"],
        decision_region_uid=original["decision_region_uid"],
        confirmation_clauses=confirmation[:-1],
        counterproof_clauses=original["counterproof_clauses"],
        open_clauses=original["open_clauses"],
        dependency_hashes=original["dependency_hashes"],
    )
    catalog = ProofKernelEngine().action_catalog(
        proof_ir=authority_input["proof_ir"],
        obligation=trimmed,
    )
    selected = (str(catalog[0]["action_uid"]),)
    evaluation = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=authority_input["proof_ir"],
        obligation=trimmed,
        selected_action_uids=selected,
    )
    issue["proof_kernel_input"] = {
        **authority_input,
        "proof_obligation": trimmed,
        "selected_action_uids": list(selected),
    }
    issue["proof_kernel_checker_results"] = [dict(value) for value in evaluation.check_results]
    evaluation.apply_to_issue(issue)

    assert _product_v4_binding(issue) == ""
