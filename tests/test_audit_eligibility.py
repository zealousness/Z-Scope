from __future__ import annotations

from zscope.core.validation.audit_eligibility import (
    AUDIT_ELIGIBILITY_VERSION,
    AUDIT_ONLY_DISPOSITION,
    evaluate_audit_eligibility,
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


def _native_v4_issue(*, candidate_source: str = "llm"):
    from scripts.p2_proof_corpus import build_corpus
    from scripts.qualify_p6_proof_promotion import _freeze_reduce

    for case in build_corpus()["cases"]:
        state, closure, authority_input = _freeze_reduce(
            proof_ir=case["program_proof_ir"],
            obligation=case["proof_obligation"],
            actions=[case["evidence_action"]],
            check_results=[case["proof_check_result"]],
        )
        if (
            closure.complete is False
            and closure.integrity_status == "verified"
            and closure.failure_codes == ()
        ):
            return _issue(
                candidate_source=candidate_source,
                missing_fact_kinds=[],
                validator_evidence_actions=[],
                security_obligation={
                    "obligation_uid": state.obligation_uid,
                    "defect_family": str(case["proof_obligation"]["defect_family"]),
                    "subject_uid": state.subject_uid,
                },
                proof_kernel_input=authority_input,
                proof_kernel_checker_results=[case["proof_check_result"]],
                proof_kernel_frozen_state=state.to_dict(),
                proof_kernel_closure_evaluation=closure.to_dict(),
                proof_kernel_live_selected_action_uids=[case["evidence_action"]["action_uid"]],
            )
    raise AssertionError("P2 corpus did not produce a clean incomplete v4 case")


def _native_hunter_v4_issue():
    from scripts.qualify_p6_proof_promotion import _freeze_reduce
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
    return _issue(
        candidate_source="hypothesis_hunter",
        file=location["file"],
        line=location["start_line"],
        function=location["function_uid"],
        source_identity=hypothesis["subject_uid"],
        security_hypothesis=hypothesis,
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


def test_specific_qualified_unresolved_obligation_stays_needs_review(monkeypatch) -> None:
    import zscope.core.validation.audit_eligibility as module

    monkeypatch.setattr(module, "_v4_qualification_binding", lambda _issue: "a" * 64)
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


def test_exact_rule_requires_verified_qualification(monkeypatch) -> None:
    import zscope.core.validation.audit_eligibility as module

    monkeypatch.setattr(
        module,
        "_qualified_rule_bindings",
        lambda: {("RULE_OK", 2): "b" * 64},
    )
    pending = evaluate_audit_eligibility(
        _issue(rule_id="RULE_PENDING", rule_revision=1, candidate_source="clang_ast_cfg")
    )
    qualified = evaluate_audit_eligibility(
        _issue(rule_id="RULE_OK", rule_revision=2, candidate_source="clang_ast_cfg")
    )
    assert pending.qualification_backed is False
    assert pending.disposition == AUDIT_ONLY_DISPOSITION
    assert qualified.qualification_backed is True
    assert qualified.qualification_binding_sha256 == "b" * 64
    assert qualified.disposition == "needs_review"


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


def test_hunter_v4_envelope_still_requires_sealed_hypothesis() -> None:
    result = evaluate_audit_eligibility(_native_v4_issue(candidate_source="hypothesis_hunter"))
    assert result.qualification_backed is False
    assert result.disposition == AUDIT_ONLY_DISPOSITION


def test_hunter_with_sealed_hypothesis_and_v4_successor_remains_actionable() -> None:
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
