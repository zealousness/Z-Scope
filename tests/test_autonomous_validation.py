from copy import deepcopy

import pytest

from test_validation_claims import _issue, _rejected, _Config
from zscope.core.validation.claims import replay_semantic_counter_claim
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.core.validation.runner import ValidationRunner
from zscope.orchestration.candidate_envelope import infer_candidate_disposition


def case():
    issue = _issue()
    issue["validation_mode"] = "balanced"
    issue["source_identity"] = "base-object"
    issue["missing_fact_kinds"] = []
    fact = {
        "fact_uid": "FACT_COUNTER",
        "fact_kind": "counterexample",
        "summary": "The deallocation consumes the allocation root, not an interior pointer.",
        "claim_scope": "candidate_premise",
        "evidence_refs": ["TOOL_ROOT"],
        "subject_uid": "base-object",
        "build_context_id": "build-current",
        "producer_engine": "validator_readonly_tool_session",
        "dependency_code_hash": "current",
        "locations": [{"file": "current.c", "line": 5}],
    }
    data = {
        **_rejected(),
        "pass": "investigation_synthesis",
        "evidence_refs": ["FACT_SOURCE", "FACT_SINK", "FACT_COUNTER"],
        "blocking_negative_evidence": True,
    }
    metadata = {
        "validator_investigation_facts": [fact],
        "validator_tool_fact_catalog": {
            "TOOL_ROOT": {
                "dependency_code_hash": "current",
                "location": {"file": "current.c", "line": 5},
            }
        },
    }
    ValidationRunner._apply_v3_investigation_facts(issue, data, metadata)
    return issue, data


def test_grounded_llm_rejection_is_terminal_but_never_a_deterministic_proof():
    issue, data = case()
    assert replay_semantic_counter_claim(issue, data).accepted
    outcome = ValidationPipeline(_Config()).apply_validator_result(
        issue, data, verdict="rejected", score_data={"final_score": 0.1}
    )
    assert outcome.memory_status == "rejected"
    assert infer_candidate_disposition(issue) == "rejected_with_evidence"
    assert issue["deterministic_rejection"] is False
    assert issue["decision_basis"] == "llm_evidence"
    assert not issue.get("decision_proof")


@pytest.mark.parametrize("source_present", [False, True])
def test_real_source_read_controls_counterclaim_admission(tmp_path, source_present):
    import json

    from zscope.agents.validator_agent.agent import ValidatorAgent
    from zscope.tools.read_code import ReadCodeTool
    from zscope.tools.source_access import ProjectSourceAccess

    if source_present:
        (tmp_path / "current.c").write_text("void release(void *base) { free(base); }\n")
    issue = _issue()
    issue.update(validation_mode="balanced", source_identity="base-object")

    class CounterclaimLLM:
        def run_conversation_with_tools(self, **kwargs):
            executor = kwargs["tool_executor"]
            read = executor("read_code", {"file_path": "current.c", "start_line": 1})
            assert read["validator_new_evidence"] is source_present
            recorded = executor(
                executor.fact_tool_name,
                {
                    "fact_kind": "counterexample",
                    "summary": "The deallocation consumes the allocation root.",
                    "claim_scope": "candidate_premise",
                    "subject_uid": "base-object",
                    "evidence_refs": [read.get("evidence_ref", "TOOLFACT_NOT_READ")],
                },
            )
            assert recorded["success"] is source_present
            payload = {
                **_rejected(),
                "pass": "investigation_synthesis",
                "blocking_negative_evidence": True,
                "evidence_refs": [
                    "FACT_SOURCE",
                    "FACT_SINK",
                    recorded.get("fact", {}).get("fact_uid", "FACT_NOT_RECORDED"),
                ],
            }
            accepted = kwargs["terminal_tool_handler"](payload)
            assert accepted["valid"] is source_present
            return {
                "content": json.dumps(payload),
                "iterations": 1,
                "terminal_tool_valid": accepted["valid"],
            }

    tool = ReadCodeTool(None, None, source_access=ProjectSourceAccess(tmp_path))
    response = ValidatorAgent(CounterclaimLLM(), [tool]).investigate(
        {
            "autonomous_validation": True,
            "candidate_subject_uid": "base-object",
            "candidate_build_context_id": "build-current",
            "evidence_slice": {
                "obligation": {"candidate_uid": "CAND_1", "validation_cluster_uid": "VAL_1"},
                "evidence_ref_catalog": issue["validator_evidence_ref_catalog"],
                "allowed_missing_fact_kinds": [],
            },
        }
    )
    ValidationRunner._apply_v3_investigation_facts(issue, response.data, response.metadata)
    outcome = ValidationPipeline(_Config()).apply_validator_result(
        issue,
        response.data,
        verdict=response.data["verdict"],
        score_data={"final_score": 0.1},
    )
    assert outcome.memory_status == ("rejected" if source_present else "needs_review")
    assert infer_candidate_disposition(issue) == (
        "rejected_with_evidence" if source_present else "needs_review"
    )


@pytest.mark.parametrize(
    "mutation",
    ["fast", "universal", "stale", "conflict", "missing", "forged_ref", "wrong_candidate"],
)
def test_semantic_rejection_fails_closed(mutation):
    issue, data = case()
    if mutation == "fast":
        issue["validation_mode"] = "fast"
    elif mutation == "universal":
        issue["v3_investigation_facts"][0]["claim_scope"] = "all_paths"
    elif mutation == "stale":
        issue["build_scope_rejection"] = "source_changed"
    elif mutation == "conflict":
        issue["evidence_conflict"] = True
    elif mutation == "missing":
        issue["v3_evidence_closure"]["complete"] = False
    elif mutation == "forged_ref":
        data["evidence_refs"] = ["NOT_READ"]
    else:
        data["candidate_uid"] = "foreign_candidate"
    assert not replay_semantic_counter_claim(issue, data).accepted
    outcome = ValidationPipeline(_Config()).apply_validator_result(
        issue, data, verdict="rejected", score_data={"final_score": 1.0}
    )
    assert outcome.memory_status == "needs_review"
