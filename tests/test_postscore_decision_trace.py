import hashlib
import json
from functools import lru_cache
from pathlib import Path

from scripts.p2_proof_corpus import build_case
from zscope.benchmarking.postscore_trace import build_postscore_decision_trace
from zscope.core.validation.authority import TerminalAuthorityEvaluator
from zscope.core.validation.proof_kernel import ProofKernelEngine
from zscope.orchestration.decision_trace import DecisionTraceStore


@lru_cache(maxsize=1)
def _confirmed_v4_bundle() -> dict:
    case = build_case("concurrency", 0)
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=case["program_proof_ir"],
        obligation=case["proof_obligation"],
    )
    carrier = {}
    evaluation.apply_to_issue(carrier)
    authority = TerminalAuthorityEvaluator().evaluate(carrier, operation="live").to_dict()
    carrier["proof_kernel_terminal_authority_decision"] = authority
    carrier["terminal_authority_decision"] = authority
    return carrier


def _needs_review_v4_bundle() -> dict:
    authority = TerminalAuthorityEvaluator().evaluate({}, operation="live").to_dict()
    return {
        "proof_kernel_terminal_authority_decision": authority,
        "terminal_authority_decision": authority,
    }


def test_postscore_trace_joins_review_tp_and_fn_without_mutating_product_trace(
    tmp_path: Path,
) -> None:
    store = DecisionTraceStore(tmp_path)
    review_issue = {
        "candidate_uid": "CAND_REVIEW",
        "validation_cluster_uid": "VAL_REVIEW",
        "candidate_disposition": "needs_review",
        **_needs_review_v4_bundle(),
        "missing_fact_kinds": ["lockset"],
        "location": {"file": "src/demo.c", "function": "unsafe_lock", "line": 10},
    }
    store.finalize_issue(review_issue, view_memberships=("with_needs_review",))
    store.record_coverage_event(
        "AUDIT_MISSING",
        reason_code="PRODUCER_NO_SIGNAL",
        producer="candidate_blind_discovery",
        details={"file": "src/missing.c", "functions": ["missing_sink"]},
    )
    manifest = store.snapshot()
    report = {
        "report_views": {
            "default": {"issues": []},
            "with_needs_review": {"issues": [review_issue]},
        },
        "run_manifest": {
            "decision_trace": {
                "schema_version": manifest["schema_version"],
                "manifest_sha256": manifest["manifest_sha256"],
            }
        },
    }
    truth = {
        "vulnerabilities": [
            {
                "id": "T_REVIEW",
                "file": "src/demo.c",
                "function": "unsafe_lock",
                "category": "race_condition",
            },
            {
                "id": "T_MISSING",
                "file": "src/missing.c",
                "function": "missing_sink",
                "category": "resource_leak",
            },
        ]
    }
    score_views = {
        "default": {
            "true_positives": 0,
            "false_negatives": 2,
            "false_positives_raw": 0,
            "matched_pairs": [],
            "unmatched_issue_classifications": [],
            "scoring_contract": {"matcher_version": "zscope.truth-matcher.v2"},
        },
        "with_needs_review": {
            "true_positives": 1,
            "matched_pairs": [
                {
                    "truth_id": "T_REVIEW",
                    "issue_index": 0,
                    "issue_identity": "review-issue",
                    "match": {"anchor": "primary"},
                }
            ],
        },
    }
    trace_path = tmp_path / review_issue["decision_trace_ref"]
    before = hashlib.sha256(trace_path.read_bytes()).hexdigest()

    result = build_postscore_decision_trace(
        report=report,
        truth=truth,
        score_views=score_views,
        snapshot_dir=tmp_path,
    )

    assert result["answer_material_present"] is True
    assert result["product_trace_mutated"] is False
    records = {record["truth_id"]: record for record in result["truth_records"]}
    assert records["T_REVIEW"]["view"] == "with_needs_review_only"
    assert records["T_REVIEW"]["first_divergence"] == "provider_or_verifier_open_clauses"
    assert records["T_MISSING"]["first_divergence"] == "producer_no_signal"
    assert records["T_MISSING"]["coverage_matches"][0]["audit_unit_uid"] == "AUDIT_MISSING"
    assert hashlib.sha256(trace_path.read_bytes()).hexdigest() == before


def test_postscore_fp_is_diagnostic_and_does_not_assert_product_error(tmp_path: Path) -> None:
    store = DecisionTraceStore(tmp_path)
    issue = {
        "candidate_uid": "CAND_FP",
        "validation_cluster_uid": "VAL_FP",
        "candidate_disposition": "confirmed",
        "proof_coverage": "complete",
        "decision_proof": {"coverage": "complete", "polarity": "positive"},
        **_confirmed_v4_bundle(),
    }
    store.record_terminal_transition(
        issue,
        level="V1",
        authority=issue["terminal_authority_decision"],
    )
    store.finalize_issue(issue, view_memberships=("default", "with_needs_review"))
    report = {
        "report_views": {"default": {"issues": [issue]}, "with_needs_review": {"issues": [issue]}},
        "run_manifest": {"decision_trace": store.snapshot()},
    }
    scores = {
        "default": {
            "true_positives": 0,
            "false_negatives": 0,
            "false_positives_raw": 1,
            "matched_pairs": [],
            "unmatched_issue_classifications": [
                {
                    "issue_index": 0,
                    "issue_identity": "fp-1",
                    "classification": "false_positive",
                }
            ],
            "scoring_contract": {"matcher_version": "zscope.truth-matcher.v2"},
        },
        "with_needs_review": {"true_positives": 0, "matched_pairs": []},
    }

    result = build_postscore_decision_trace(
        report=report,
        truth={"vulnerabilities": []},
        score_views=scores,
        snapshot_dir=tmp_path,
    )

    record = result["false_positive_records"][0]
    assert record["diagnostic_only"] is True
    assert record["first_possible_divergence"] == (
        "candidate_or_truth_contract_requires_independent_review"
    )
    json.dumps(result, allow_nan=False)
