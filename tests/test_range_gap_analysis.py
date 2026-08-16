from __future__ import annotations

import hashlib
import json

import pytest

from zscope.benchmarking.gap_analysis import analyze_range_gaps
from zscope.benchmarking.truth_contract import summarize_truth_contract


def test_gap_analysis_classifies_hidden_counterproof_and_open_fact_once() -> None:
    truth = {
        "version": "v15",
        "vulnerabilities": [
            {
                "id": "BUG-FACT",
                "category": "memory_leak",
                "file": "src/demo.c",
                "function": "leaky",
                "line": 10,
            },
            {
                "id": "BUG-LOCK",
                "category": "unlock_without_lock",
                "cwe": "CWE-832",
                "file": "src/demo.c",
                "function": "abort_batch",
                "line": 30,
            },
        ],
    }
    review_issue = {
        "category": "memory_leak",
        "file": "src/demo.c",
        "function": "leaky",
        "line": 10,
        "location": "src/demo.c:10",
        "candidate_uid": "CAND_FACT",
        "validation_cluster_uid": "VAL_FACT",
        "evidence_completion_status": "exhausted",
    }
    hidden = {
        "category": "lock_protocol_violation",
        "cwe": "CWE-832",
        "file": "src/demo.c",
        "function": "abort_batch",
        "line": 30,
        "location": "src/demo.c:30",
        "candidate_uid": "CAND_LOCK",
        "validation_cluster_uid": "VAL_LOCK",
        "policy_disposition": "rejected_with_proof",
        "deterministic_proofs": [
            {
                "outcome": "reject",
                "proof_kind": "matching_lock_dominates_unlock",
                "completeness": "complete",
                "fact_ids": ["cfg:1", "cfg:2"],
            }
        ],
    }
    report = {
        "issues_with_needs_review": [review_issue],
        "candidate_terminal_states": [hidden],
    }
    score = {
        "scoring_contract": {"matcher_version": "zscope.truth-matcher.v2"},
        "report_views": {
            "default": {"matched": [], "false_negatives": 2},
            "with_needs_review": {
                "matched": ["BUG-FACT"],
                "matched_pairs": [{"truth_id": "BUG-FACT", "issue_index": 0}],
                "true_positives": 1,
            },
        },
    }

    result = analyze_range_gaps(
        report=report,
        score=score,
        truth=truth,
        source_hashes={"report_sha256": "a" * 64},
    )

    assert result["false_negative_count"] == 2
    assert result["cause_counts"]["fact_resolution_exhausted"] == 1
    assert result["cause_counts"]["incorrect_deterministic_counterproof"] == 1
    assert {row["truth_id"] for row in result["entries"]} == {"BUG-FACT", "BUG-LOCK"}


def _v16_truth() -> dict:
    records = []
    vulnerabilities = []
    for truth_id, kind, status in (
        ("BUG-CONCRETE", "concrete_trigger", "accepted"),
        ("BUG-CONTRACT", "public_api_contract", "corrected"),
        ("BUG-PATTERN", "pattern_model", "accepted"),
        ("BUG-RETIRED", "retired", "retired"),
    ):
        contract = {
            "kind": kind,
            "adjudication_status": status,
            "threat_assumptions": ["public API is caller reachable"],
            "required_evidence": ["coherent source/path/sink"],
            "adjudication_artifact_sha256": truth_id.lower().replace("-", "")[:1] * 64,
        }
        vulnerabilities.append({"id": truth_id, "verification_contract": contract})
        records.append(
            {
                "truth_id": truth_id,
                "kind": kind,
                "adjudication_status": status,
                "threat_assumptions": contract["threat_assumptions"],
                "required_evidence": contract["required_evidence"],
                "adjudication_artifact_sha256": contract["adjudication_artifact_sha256"],
            }
        )
    manifest_sha = hashlib.sha256(
        json.dumps(
            records,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "version": "v16",
        "truth_contract": {
            "schema_version": "zscope.range-truth-contract.v1",
            "manifest_sha256": manifest_sha,
            "attestation_sha256": "f" * 64,
            "independent_review_complete": True,
            "review_protocol": "two reviewers and independent arbitration",
        },
        "vulnerabilities": vulnerabilities,
    }


def test_v15_truth_is_descriptive_and_v16_threshold_is_dynamic() -> None:
    historical = summarize_truth_contract(
        {"version": "v15", "vulnerabilities": [{"id": "A"}, {"id": "B"}]}
    )
    formal = summarize_truth_contract(_v16_truth())

    assert historical["formal_eligible"] is False
    assert historical["required_confirmed_tp"] == 2
    assert formal["formal_eligible"] is True
    assert formal["confirmable_truth_count"] == 2
    assert formal["pattern_model_count"] == 1
    assert formal["retired_count"] == 1
    assert formal["required_confirmed_tp"] == 2


def test_v16_truth_contract_fails_closed_on_tampered_manifest() -> None:
    truth = _v16_truth()
    truth["vulnerabilities"][0]["verification_contract"]["kind"] = "pattern_model"

    with pytest.raises(ValueError, match="manifest hash"):
        summarize_truth_contract(truth)
