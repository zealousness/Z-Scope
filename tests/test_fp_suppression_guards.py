"""FP-suppression guards (M1/M2/M3') — deterministic unit tests.

M1: replay escalation from uncertain to verified is held for review.
M2: source_lifecycle_acquire_without_release loses confirm authority.
M3': a cfg-obligation confirm whose body frees the obligation object is
     self-contradictory and is not produced.
"""

from __future__ import annotations

from test_validation_pipeline import _score
from test_validation_runner import FakeUserConfig

from zscope.core.validation.evidence_completion import EvidenceCompletionQueue
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.core.validation.proofs import _code_hash, deterministic_decision_proof


def _lifecycle_issue(**overrides):
    issue = {
        "id": "SVF_VALUE_FLOW_2fb63c353a1e",
        "sink": "Memory Leak",
        "code_hash": "abc123",
        "deterministic_proofs": [
            {
                "outcome": "confirm",
                "proof_kind": "source_lifecycle_acquire_without_release",
                "producer_engine": "source_lifecycle_event_facts_v12",
                "code_hash": "abc123",
                "fact_ids": ["code:191:event:acquire", "code:207:event:exit"],
                "facts": [
                    "event:acquire",
                    "event:exit",
                    "no_intraprocedural_release",
                    "no_ownership_transfer",
                ],
                "completeness": "complete",
                "scope": "function body",
                "summary": "acquire without release",
            }
        ],
    }
    issue.update(overrides)
    return issue


def test_m2_source_lifecycle_confirm_demoted_by_flag() -> None:
    issue = _lifecycle_issue()
    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.proof_kind == "source_lifecycle_acquire_without_release"

    demoted = _lifecycle_issue(demote_source_lifecycle_confirm=True)
    assert deterministic_decision_proof(demoted, outcome="confirm") is None


def test_m2_other_kinds_unaffected_by_demotion_flag() -> None:
    issue = _lifecycle_issue(
        demote_source_lifecycle_confirm=True,
        deterministic_proofs=[
            {
                "outcome": "confirm",
                "proof_kind": "external_value_controls_unbounded_allocation",
                "producer_engine": "clang_ast_cfg_obligation_prover",
                "code_hash": "abc123",
                "fact_ids": ["cfg:20:a", "cfg:21:b", "cfg:22:c"],
                "facts": [
                    "external_source_to_allocation",
                    "allocation_path_complete",
                    "no_upper_bound_guard",
                ],
                "completeness": "complete",
                "scope": "function body",
                "summary": "unbounded allocation",
            }
        ],
    )
    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.proof_kind == "external_value_controls_unbounded_allocation"


def test_m3_infunction_release_contradiction_helper() -> None:
    # 注意：仅裸 free(...) 属于工具规则识别范围；SAFE_FREE 等项目专属
    # wrapper 宏的识别由语义建模暴露（语义建模方向：工具规则不做硬编码）。
    body = (
        "int _runtime_release_reader_channel(const char* key, int role) {\n"
        "    ServiceNode* node = _service_alloc_node(key, \"reader\");\n"
        "    if (!node) { return -1; }\n"
        "    node->role = role;\n"
        "    if (node->role == 1) {\n"
        "        _service_release_by_role(node, 0);\n"
        "        free(node);\n"
        "        return 0;\n"
        "    }\n"
        "    _service_release_by_role(node, 0);\n"
        "    free(node);\n"
        "    return 0;\n"
        "}\n"
    )
    guard = EvidenceCompletionQueue._infunction_release_contradiction
    assert guard("_service_release_by_role(node, 0);", body) is True
    # callee identifiers never count as the freed object
    assert guard("_service_release_by_role(service_release_by_role);", body) is False
    # a store-shaped sink names its assigned value as the object
    assert guard("plugin->context = context;", "free(other);") is False
    assert guard("", body) is False
    assert guard("_service_release_by_role(node, 0);", "") is False


def test_m1_uncertain_confirm_hold_forces_review() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "R3_UNCERTAIN_1",
        "category": "memory_leak",
        "review_disposition_reason": "uncertain_confirm_hold",
    }
    outcome = pipeline.apply_validator_result(
        issue,
        {
            "reasoning": "positive case witness constructed",
            "positive_evidence": ["witness:1"],
            "blocking_negative_evidence": False,
        },
        verdict="verified",
        score_data=_score(0.9),
    )
    assert outcome.report_bucket == "observations"
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["review_disposition_reason"] == "uncertain_confirm_hold"


def test_m1_hold_marker_absent_keeps_standard_routing() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {"id": "NORMAL_1", "category": "memory_leak"}
    outcome = pipeline.apply_validator_result(
        issue,
        {
            "reasoning": "confirmed",
            "positive_evidence": ["witness:1"],
            "blocking_negative_evidence": False,
        },
        verdict="verified",
        score_data=_score(0.9),
    )
    assert outcome.report_bucket == "issues"
    assert issue["candidate_disposition"] == "confirmed"


def test_m2_fixture_code_hash_matches_helper() -> None:
    issue = _lifecycle_issue()
    assert _code_hash(issue) == "abc123"
