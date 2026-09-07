import json
from copy import deepcopy
from types import SimpleNamespace
from pathlib import Path
import runpy

import pytest

from zscope.agents.validator_agent.agent import ValidatorAgent
from zscope.common.validator_protocol import ValidatorResultV3, parse_validator_result_v3
from zscope.core.validation.review_protocol import (
    REVIEW_VERSION,
    adjudicate_review,
    parse_review_result,
)
from zscope.core.validation.review_checkpoint import ReviewCheckpointStore, RelatedCandidateRegistry
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.benchmarking.review_experiment import (
    freeze_audit,
    load_audit,
    compare_paired_replays,
    arm_flags,
)
from zscope.orchestration.candidates import CandidateLedger, CandidateRegistrar


def test_replay_snippets_cannot_read_labels_or_escape_source_root(tmp_path):
    module = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/replay_review_experiment.py")
    )
    project = tmp_path / "project"
    project.mkdir()
    index = SimpleNamespace(
        project_root=project,
        resolve_existing_file=lambda name: project / name,
        get_file_snippet=lambda path, start, end: str(path),
    )
    guarded = module["ReplaySourceIndex"](index)
    assert guarded.get_file_snippet("source.c", 1, 2)
    assert guarded.get_file_snippet("labels.json", 1, 2) is None
    assert guarded.get_file_snippet("../outside.c", 1, 2) is None


def envelope(*, complete=False, assessment="scope_refuted", refs=None):
    refs = refs or ["TOOLFACT_1"]
    decision = ValidatorResultV3(
        candidate_uid="C_1",
        validation_cluster_uid="V_1",
        validation_pass="v2b_adjudication",
        verdict="verified",
        reasoning="具体路径",
        positive_evidence=("无界可行路径",),
        negative_evidence=(),
        evidence_refs=tuple(refs),
        blocking_negative_evidence=False,
        missing_fact_request=None,
        stop_reason="decision_complete",
    ).to_dict()
    return {
        "schema_version": REVIEW_VERSION,
        "decision": decision,
        "prior_rejection": {
            "assessment": assessment,
            "reason": "局部守卫不能覆盖整个候选",
            "evidence_refs": refs,
        },
        "defect_case": {
            "status": "supported" if complete else "incomplete",
            "subject": "buffer",
            "source": "external size",
            "sink": "malloc(size)",
            "path": "entry → malloc",
            "trigger": "unbounded size",
            "guard_analysis": "no guard",
            "evidence_refs": refs,
            "missing_conditions": [] if complete else ["path feasibility"],
        },
    }


def test_refuting_rejection_is_not_positive_evidence_and_v3_remains_compatible():
    value = envelope()
    parsed = parse_review_result(
        value,
        candidate_uid="C_1",
        cluster_uid="V_1",
        expected_pass="v2b_adjudication",
        allowed_refs=["TOOLFACT_1"],
        rejection_expected=True,
    )
    assert parsed
    decision, reason = adjudicate_review(parsed, backed_refs=["TOOLFACT_1"])
    assert decision["verdict"] == "uncertain" and reason == "rejection_refuted_unconfirmed"
    assert parse_validator_result_v3(decision)
    assert decision["stop_reason"] != reason
    item = {
        "function": "f",
        "category": "bounds",
        "location": "a.c:1",
        "review_disposition_reason": reason,
    }
    pipeline = ValidationPipeline(SimpleNamespace(), uncertain_confirm_threshold=0.95)
    result = pipeline.apply_validator_result(
        item,
        {**decision, "confidence_score": 1.0},
        verdict="uncertain",
        score_data={"final_score": 1.0},
    )
    assert (
        result.report_bucket == "observations" and item["candidate_disposition"] == "needs_review"
    )


def test_safe_malloc_like_real_positive_case_is_not_filtered_by_truth_or_old_fact_validity():
    value = envelope(complete=True, assessment="supported")
    # There is deliberately no truth input in this protocol.
    result, reason = adjudicate_review(value, backed_refs=["TOOLFACT_1"])
    assert result["verdict"] == "verified" and reason == "positive_case_submitted_for_validation"
    unbacked, _ = adjudicate_review(value, backed_refs=[])
    assert unbacked["verdict"] == "uncertain"


def test_rejection_expected_and_scope_are_validated():
    value = envelope()
    assert (
        parse_review_result(
            value,
            candidate_uid="OTHER",
            cluster_uid="V_1",
            expected_pass="v2b_adjudication",
            allowed_refs=["TOOLFACT_1"],
            rejection_expected=True,
        )
        is None
    )
    value["prior_rejection"]["assessment"] = "not_applicable"
    assert parse_review_result(
        value,
        candidate_uid="C_1",
        cluster_uid="V_1",
        expected_pass="v2b_adjudication",
        allowed_refs=["TOOLFACT_1"],
        rejection_expected=False,
    )


def test_agent_terminal_wrapper_is_enforced_and_raw_results_are_preserved():
    agent = ValidatorAgent(SimpleNamespace(models=["test"]), [])
    captured = {}

    def conversation(messages, **kwargs):
        captured.update(kwargs)
        schemas = kwargs["additional_tools_schema"]
        final = next(s for s in schemas if s["function"]["name"] == "emit_validator_result_v3")
        assert final["function"]["parameters"]["properties"]["schema_version"]["enum"] == [
            REVIEW_VERSION
        ]
        result = kwargs["tool_executor"]("read", {"func_name": "f"})
        ref = result["evidence_ref"]
        accepted = kwargs["terminal_tool_handler"](envelope(refs=[ref]))
        assert accepted["valid"] and accepted["payload"]["verdict"] == "uncertain"
        return {"conversation": [], "content": "", "iterations": 1}

    agent._run_tool_conversation = conversation
    agent._tool_executor = lambda *_: {
        "success": True,
        "data": {"function": "f", "code": "malloc(n);"},
    }
    response = agent.investigate(
        {
            "finding_uid": "C_1",
            "validation_cluster_uid": "V_1",
            "review_protocol_enabled": True,
            "review_rejection_expected": True,
            "evidence_slice": {
                "obligation": {"candidate_uid": "C_1", "validation_cluster_uid": "V_1"}
            },
        },
        pass_kind="v2b_adjudication",
    )
    assert response.data["verdict"] == "uncertain"
    assert response.metadata["review_disposition_reason"] == "rejection_refuted_unconfirmed"
    assert response.metadata["review_tool_results"][0]["result"]["data"]["code"] == "malloc(n);"


def test_checkpoint_integrity_answer_isolation_and_proposal_recovery(tmp_path):
    store = ReviewCheckpointStore(tmp_path)
    proposal = {
        "file": "a.c",
        "line": 8,
        "function": "f",
        "category": "race",
        "source": "value",
        "sink": "unlocked return",
        "analysis_scope": "current_build",
        "trigger_condition": "two threads",
    }
    parent = {
        "candidate_uid": "C_1",
        "review_related_proposals": [proposal],
        "review_checked_proof": {"signature": "old"},
    }
    uid = store.save(parent, stage="interrupted", facts={"complete": False}, runtime={})
    restored = store.load(uid)["candidate"]
    assert "review_checked_proof" not in restored
    children = RelatedCandidateRegistry([restored, {**restored, "candidate_uid": "C_2"}]).freeze()
    assert len(children) == 1 and children[0]["parent_candidate_uids"] == ["C_1", "C_2"]
    assert (
        RelatedCandidateRegistry([{**children[0], "review_related_proposals": [proposal]}]).freeze()
        == []
    )
    with pytest.raises(ValueError, match="offline"):
        store.save({"audit_label": "TP"}, stage="invalid", facts={}, runtime={})
    path = tmp_path / f"{uid}.json"
    raw = json.loads(path.read_text())
    raw["stage"] = "tampered"
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="integrity"):
        store.load(uid)


def test_frozen_main_ledger_keeps_related_outcomes_in_final_projection():
    main = CandidateLedger()
    main.freeze()
    child = {
        "id": "child",
        "function": "f",
        "file": "a.c",
        "line": 8,
        "location": "a.c:8",
        "category": "race",
        "description": "unlocked access",
        "source": "value",
        "sink": "return",
        "parent_candidate_uid": "parent",
        "related_generation": 1,
        "candidate_kind": "llm_observation",
    }
    appendix = CandidateLedger()
    CandidateRegistrar(appendix).register_issues(
        [child], source="validator_related_discovery", force_unconfirmed=True
    )
    appendix.freeze()
    main.attach_review_appendix(appendix)
    appendix.mark_issue_terminal(child, disposition="needs_review", status="needs_review")
    assert main._frozen and not main._records
    snapshot = main.lifecycle_snapshot()
    assert snapshot["outcomes"][0]["issue"]["parent_candidate_uid"] == "parent"
    assert snapshot["outcomes"][0]["terminal_disposition"] == "needs_review"


def test_acceptance_counts_new_related_fp_and_requires_all_truth_coverage(tmp_path):
    labels = [
        {
            "candidate_uid": uid,
            "classification": label,
            "auditor": "independent",
            "rationale": "code reviewed",
        }
        for uid, label in [
            ("fp1", "provable_fp"),
            ("fp2", "provable_fp"),
            ("tp", "true_defect"),
            ("child", "provable_fp"),
        ]
    ]
    audit_path = freeze_audit(labels, tmp_path)
    audit = load_audit(audit_path)
    base = {
        "outcomes": [
            {"candidate_uid": uid, "candidate_disposition": "needs_review"}
            for uid in ("fp1", "fp2", "tp")
        ],
        "confirmed_truth_ids": ["TRUTH_0"],
        "review_truth_ids": ["TRUTH_1"],
        "audit_commitment": audit_path.stem,
        "checkpoint_manifest_hash": "frozen",
        "model": ["same"],
        "investigation_limits": {"v3": 50, "v2b": 12},
    }
    improved = {**deepcopy(base), "pair_id": "1", "arm": "facts"}
    improved["outcomes"][0]["candidate_disposition"] = "rejected_with_proof"
    runs = [{**deepcopy(improved), "pair_id": str(i)} for i in range(5)]
    result = compare_paired_replays(base, runs, audit, replay_proof=lambda _: True)
    assert result["status"] == "passed" and result["review_true_fp_reduction"] == 0.5
    runs[0]["confirmed_truth_ids"] = []
    assert (
        compare_paired_replays(base, runs, audit, replay_proof=lambda _: True)["status"]
        == "experimental"
    )
    for run in runs:
        run["confirmed_truth_ids"] = ["TRUTH_0"]
        run["outcomes"].append({"candidate_uid": "child", "candidate_disposition": "needs_review"})
    assert (
        compare_paired_replays(base, runs, audit, replay_proof=lambda _: True)[
            "review_true_fp_reduction"
        ]
        == 0
    )
    assert (
        compare_paired_replays(base, runs, audit, replay_proof=lambda _: False)["status"]
        == "experimental"
    )
    assert (
        arm_flags("positive")["validation_positive_case"]
        and not arm_flags("neutral")["validation_positive_case"]
    )
    assert arm_flags("baseline")["validation_v2b_adjudication"]
    assert {
        k: v for k, v in arm_flags("baseline").items() if k != "validation_review_protocol"
    } == {k: v for k, v in arm_flags("protocol").items() if k != "validation_review_protocol"}
