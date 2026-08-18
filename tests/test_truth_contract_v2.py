from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest

from zscope.benchmarking.truth_contract import (
    TRUTH_CONTRACT_V2_SCHEMA_VERSION,
    summarize_truth_contract,
)


def _record(truth_id: str, kind: str, line: int) -> dict:
    contract = {
        "schema_version": "zscope.range-truth-record.v2",
        "kind": kind,
        "adjudication_status": "retired" if kind == "retired" else "accepted",
        "defect_taxonomy_id": "memory_leak",
        "structured_anchors": [
            {
                "kind": "primary",
                "file": "src/demo.c",
                "function": f"f_{line}",
                "start_line": line,
                "end_line": line + 1,
            }
        ],
        "trigger": {
            "summary": "A concrete resource path.",
            "evidence_refs": [f"src/demo.c:{line}"],
        },
        "threat_assumptions": ["The entry is callable."],
        "required_evidence_clauses": [
            {"clause_id": "path", "predicate": "source_sink", "evidence_refs": []}
        ],
        "review_artifacts": {
            "fable_sha256": "1" * 64,
            "deepseek_sha256": "2" * 64,
            "normalized_sha256": "3" * 64,
        },
        "safe_pair": (
            {
                "pair_uid": f"pair:{truth_id}",
                "manifest_sha256": "4" * 64,
                "vulnerable_sha256": "5" * 64,
                "fixed_or_near_miss_sha256": "6" * 64,
            }
            if kind in {"concrete_trigger", "public_api_contract"}
            else {}
        ),
        "fixture_sha256": "7" * 64,
    }
    return {
        "id": truth_id,
        "category": "memory_leak",
        "cwe": "CWE-401",
        "file": "src/demo.c",
        "function": f"f_{line}",
        "line": line,
        "verification_contract": contract,
    }


def truth_v16() -> dict:
    records = [
        _record("T-1", "concrete_trigger", 10),
        _record("T-2", "public_api_contract", 20),
        _record("T-3", "pattern_model", 30),
        _record("T-4", "retired", 40),
    ]
    canonical = [
        {"truth_id": record["id"], **record["verification_contract"]} for record in records
    ]
    digest = hashlib.sha256(
        json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "version": "v16",
        "benchmark": "unit",
        "suite": "unit",
        "truth_contract": {
            "schema_version": TRUTH_CONTRACT_V2_SCHEMA_VERSION,
            "manifest_sha256": digest,
            "review_bundle_sha256": "8" * 64,
            "taxonomy_sha256": "9" * 64,
            "independent_review_complete": True,
            "review_protocol": "fable+deepseek; opus disagreements and mandatory disputed set",
            "safe_unit_count": 2,
        },
        "vulnerabilities": records,
    }


def test_truth_contract_v2_uses_dynamic_confirmable_denominator() -> None:
    summary = summarize_truth_contract(truth_v16())
    assert summary["schema_version"] == TRUTH_CONTRACT_V2_SCHEMA_VERSION
    assert summary["confirmable_truth_count"] == 2
    assert summary["pattern_model_count"] == 1
    assert summary["retired_count"] == 1
    assert summary["required_confirmed_tp"] == 2
    assert summary["safe_unit_count"] == 2


def test_truth_contract_v2_rejects_missing_pair_and_manifest_tampering() -> None:
    truth = truth_v16()
    truth["vulnerabilities"][0]["verification_contract"]["safe_pair"] = {}
    with pytest.raises(ValueError, match="requires a safe pair"):
        summarize_truth_contract(truth)

    tampered = deepcopy(truth_v16())
    tampered["vulnerabilities"][0]["verification_contract"]["trigger"]["summary"] = "changed"
    with pytest.raises(ValueError, match="manifest hash"):
        summarize_truth_contract(tampered)


def test_truth_contract_v2_rejects_unknown_fields() -> None:
    truth = truth_v16()
    truth["vulnerabilities"][0]["verification_contract"]["benchmark_hint"] = "do not allow"
    with pytest.raises(ValueError, match="fields are invalid"):
        summarize_truth_contract(truth)


def test_truth_contract_v2_rejects_incoherent_anchor_and_clause() -> None:
    truth = truth_v16()
    truth["vulnerabilities"][0]["function"] = "other"
    with pytest.raises(ValueError, match="primary anchor projection"):
        summarize_truth_contract(truth)

    truth = truth_v16()
    clause = truth["vulnerabilities"][0]["verification_contract"]["required_evidence_clauses"][0]
    truth["vulnerabilities"][0]["verification_contract"]["required_evidence_clauses"].append(
        deepcopy(clause)
    )
    with pytest.raises(ValueError, match="clause identity"):
        summarize_truth_contract(truth)
