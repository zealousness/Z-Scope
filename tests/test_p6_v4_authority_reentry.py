from types import SimpleNamespace

from scripts.p2_proof_corpus import build_corpus
from zscope.common.validator_protocol import ValidatorResultV3
from zscope.core.validation.authority import TerminalAuthorityEvaluator
from zscope.core.validation.proof_kernel import (
    PROOF_KERNEL_AUTHORITY_INPUT_VERSION,
    ProofKernelEngine,
)
from zscope.core.validation.runner import ValidationRunner


def _runner_without_runtime() -> ValidationRunner:
    runner = object.__new__(ValidationRunner)
    runner._terminal_authority = TerminalAuthorityEvaluator()
    return runner


def _open_corpus_issue() -> tuple[dict, str]:
    case = build_corpus()["cases"][0]
    proof_ir = case["program_proof_ir"]
    obligation = case["proof_obligation"]
    action_uid = str(
        ProofKernelEngine()
        .action_catalog(proof_ir=proof_ir, obligation=obligation)[0]["action_uid"]
    )
    return (
        {
            "proof_kernel_input": {
                "schema_version": PROOF_KERNEL_AUTHORITY_INPUT_VERSION,
                "proof_ir": proof_ir,
                "proof_obligation": obligation,
                "selected_action_uids": [],
            },
            "proof_kernel_live_selected_action_uids": [],
        },
        action_uid,
    )


def test_v3_reentry_reduces_the_same_frozen_obligation() -> None:
    runner = _runner_without_runtime()
    issue, action_uid = _open_corpus_issue()
    original_input = issue["proof_kernel_input"]
    original_obligation = original_input["proof_obligation"]
    original_proof_ir = original_input["proof_ir"]
    original_obligation_uid = original_obligation["obligation_uid"]
    original_proof_ir_uid = original_proof_ir["proof_ir_uid"]

    assert runner._reenter_frozen_proof_obligation(issue, action_uid=action_uid)
    authority = runner._terminal_authority.evaluate(issue, operation="live")
    assert runner._mark_terminal_transition(issue, "V3", authority)

    assert issue["proof_kernel_input"]["proof_ir"] == original_proof_ir
    assert issue["proof_kernel_input"]["proof_obligation"] == original_obligation
    assert issue["proof_kernel_input"]["selected_action_uids"] == [action_uid]
    assert issue["proof_kernel_live_selected_action_uids"] == [action_uid]
    assert issue["proof_kernel_frozen_state"]["obligation_uid"] == original_obligation_uid
    assert issue["proof_kernel_frozen_state"]["proof_ir_uid"] == original_proof_ir_uid
    assert issue["proof_kernel_v3_reentry_status"] == "reduced_original_obligation"
    assert issue["terminal_transition_level"] == "V3"
    assert authority.disposition in {"confirmed", "rejected_with_proof"}


def test_terminal_authority_stops_post_terminal_v3_work() -> None:
    runner = _runner_without_runtime()
    issue, action_uid = _open_corpus_issue()
    assert runner._reenter_frozen_proof_obligation(issue, action_uid=action_uid)
    item = SimpleNamespace(raw_issue=issue)

    class ForbiddenAgent:
        def run(self, _value):  # pragma: no cover - this must never execute
            raise AssertionError("model ran after terminal authority")

    prior = ValidatorResultV3(
        candidate_uid="CAND_V3_STOP",
        validation_cluster_uid="VAL_V3_STOP",
        validation_pass="investigation_synthesis",
        verdict="uncertain",
        reasoning="already reduced",
        positive_evidence=(),
        negative_evidence=(),
        evidence_refs=(),
        blocking_negative_evidence=False,
        missing_fact_request={
            "fact_kind": "value_range",
            "subject_uid": "subject",
            "function_uid": "sink",
            "reason": "one final fact remains",
        },
        stop_reason="missing_fact",
    ).to_dict()

    revised = runner._reconcile_v3_missing_fact(item, ForbiddenAgent(), prior, {})

    assert revised["stop_reason"] == "decision_complete"
    assert issue["validator_v3_post_resolution"]["status"] == "skipped_terminal_authority"
    assert issue["terminal_transition_level"] == "V3"


def test_fact_plan_completion_does_not_authorize_promotion() -> None:
    issue = {
        "missing_fact_kinds": ["value_range"],
        "obligation_required_fact_kinds": ["value_range"],
        "v3_investigation_facts": [
            {
                "fact_uid": "FACT_GUARD",
                "satisfies_fact_kinds": ["value_range"],
                "dependency_code_hash": "a" * 64,
            }
        ],
    }

    added = ValidationRunner._apply_v3_investigation_facts(issue, {}, {})

    assert added == 0
    assert issue["fact_plan_complete"] is True
    assert issue["v3_evidence_closure"]["reason"] == "fact_plan_complete"
    assert issue["candidate_promotion_eligible"] is False
    assert issue["candidate_promotion_reason"] == (
        "fact_plan_complete_requires_proof_closure"
    )


def test_terminal_transition_records_only_the_first_true_terminal() -> None:
    issue: dict = {}
    open_authority = TerminalAuthorityEvaluator().evaluate({}, operation="live")
    closed_issue, action_uid = _open_corpus_issue()
    runner = _runner_without_runtime()
    assert runner._reenter_frozen_proof_obligation(closed_issue, action_uid=action_uid)
    closed_authority = runner._terminal_authority.evaluate(closed_issue, operation="live")

    assert ValidationRunner._mark_terminal_transition(issue, "V1", open_authority) is False
    assert ValidationRunner._mark_terminal_transition(issue, "V3", closed_authority) is True
    assert ValidationRunner._mark_terminal_transition(issue, "V2", closed_authority) is False
    assert issue["terminal_transition_level"] == "V3"
