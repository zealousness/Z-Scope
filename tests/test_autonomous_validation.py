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
