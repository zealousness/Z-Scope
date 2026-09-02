from types import SimpleNamespace

import pytest

from scripts.p2_proof_corpus import build_corpus
import zscope.core.validation.runner as validation_runner_module
import zscope.orchestration.decision_trace as decision_trace_module
from zscope.common.validator_protocol import ValidatorResultV3
from zscope.core.validation.authority import TerminalAuthorityEvaluator
from zscope.core.validation.proof_kernel import (
    PROOF_KERNEL_AUTHORITY_INPUT_VERSION,
    ProofKernelEngine,
)
from zscope.core.validation.runner import ValidationRunner
from zscope.orchestration.decision_trace import DecisionTraceStore


@pytest.fixture(autouse=True)
def _trust_p2_corpus_producer_boundary(monkeypatch) -> None:
    """Keep these reducer mechanics tests independent of product provenance."""

    verifier = lambda _candidate: True
    monkeypatch.setattr(
        validation_runner_module,
        "has_exact_v4_producer_occurrence_binding",
        verifier,
    )
    monkeypatch.setattr(
        decision_trace_module,
        "_has_exact_v4_producer_occurrence_binding",
        verifier,
    )


def _runner_without_runtime(tmp_path) -> ValidationRunner:
    runner = object.__new__(ValidationRunner)
    runner._terminal_authority = TerminalAuthorityEvaluator()
    runner._decision_trace_store = DecisionTraceStore(tmp_path)
    return runner


def _open_corpus_issue() -> tuple[dict, str]:
    case = build_corpus()["cases"][0]
    proof_ir = case["program_proof_ir"]
    obligation = case["proof_obligation"]
    action_uid = str(
        ProofKernelEngine().action_catalog(proof_ir=proof_ir, obligation=obligation)[0][
            "action_uid"
        ]
    )
    return (
        {
            "validation_cluster_uid": "VAL_P6_V4_REENTRY",
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


def test_v3_reentry_reduces_the_same_frozen_obligation(tmp_path) -> None:
    runner = _runner_without_runtime(tmp_path)
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


def test_terminal_authority_stops_post_terminal_v3_work(tmp_path) -> None:
    runner = _runner_without_runtime(tmp_path)
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
    assert issue["candidate_promotion_reason"] == ("fact_plan_complete_requires_proof_closure")


def test_terminal_transition_records_only_the_first_true_terminal(tmp_path) -> None:
    issue: dict = {}
    open_authority = TerminalAuthorityEvaluator().evaluate({}, operation="live")
    issue, action_uid = _open_corpus_issue()
    runner = _runner_without_runtime(tmp_path)
    assert runner._reenter_frozen_proof_obligation(issue, action_uid=action_uid)
    closed_authority = runner._terminal_authority.evaluate(issue, operation="live")

    assert runner._mark_terminal_transition(issue, "V1", open_authority) is False
    assert runner._mark_terminal_transition(issue, "V3", closed_authority) is True
    assert runner._mark_terminal_transition(issue, "V3", closed_authority) is False
    assert issue["terminal_transition_level"] == "V3"


@pytest.mark.parametrize(
    "persistence_marker",
    (
        "validator_cache_hit",
        "resume_checkpoint_id",
        "policy_replay_source",
        "evidence_extension_checkpoint",
    ),
)
def test_persisted_authority_marker_cannot_replace_live_producer_rebuild(
    tmp_path,
    persistence_marker,
) -> None:
    runner = _runner_without_runtime(tmp_path)
    issue, action_uid = _open_corpus_issue()
    assert runner._reenter_frozen_proof_obligation(issue, action_uid=action_uid)
    stale_authority = runner._terminal_authority.evaluate(issue, operation="live")
    assert stale_authority.terminal is True
    issue["proof_kernel_terminal_authority_decision"] = stale_authority.to_dict()
    issue["terminal_authority_decision"] = stale_authority.to_dict()
    issue["terminal_transition_level"] = "V0"
    issue[persistence_marker] = "PERSISTED_STALE_RECEIPT"

    rebuilt = runner._rebuild_live_proof_input(issue, {})

    assert rebuilt is False
    assert issue["proof_kernel_input_rebuild_status"] == "legacy_or_unknown_candidate"
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["validation_status"] == "needs_review"
    assert "proof_kernel_input" not in issue
    assert "proof_kernel_promotion_certificate" not in issue
    assert "proof_kernel_terminal_authority_decision" not in issue
    assert "terminal_authority_decision" not in issue
    assert "terminal_transition_level" not in issue


def test_v2_v3_foreign_action_cannot_extend_frozen_obligation(tmp_path) -> None:
    runner = _runner_without_runtime(tmp_path)
    issue, action_uid = _open_corpus_issue()
    original_input = issue["proof_kernel_input"]

    assert not runner._reenter_frozen_proof_obligation(
        issue,
        action_uid="EVACTION_FOREIGN_OR_STALE",
    )
    assert issue["proof_kernel_input"] == original_input
    assert issue["proof_kernel_v3_reentry_status"] == "proof_kernel_reentry_failed"
    assert "proof_kernel_promotion_certificate" not in issue
    foreign_authority = runner._terminal_authority.evaluate(issue, operation="live")
    assert foreign_authority.disposition == "needs_review"
    assert foreign_authority.promotion_certificate is None

    assert runner._reenter_frozen_proof_obligation(issue, action_uid=action_uid)
    assert issue["proof_kernel_input"]["selected_action_uids"] == [action_uid]
    assert runner._terminal_authority.evaluate(issue, operation="live").terminal is True
