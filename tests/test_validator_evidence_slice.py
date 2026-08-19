import json

from zscope.core.validation.evidence import build_validator_evidence_slice_v3


def _issue(alias_count: int) -> dict:
    aliases = [f"OCC_{index:04d}" for index in range(alias_count)]
    return {
        "candidate_uid": "CAND_primary",
        "validation_cluster_uid": "VAL_primary",
        "occurrence_uid": "OCC_primary",
        "occurrence_uids": ["OCC_primary", *aliases],
        "alias_occurrence_uids": aliases,
        "occurrence_count": alias_count + 1,
        "function": "sink",
        "location": "src/demo.c:10",
        "category": "bounds",
        "source": "wire_len",
        "sink": "copy(dst, src, wire_len)",
        "decision_fact_version": "zscope.decision-facts.v1.2",
        "decision_fact_slice": {
            "coverage": "partial",
            "fact_uids": ["FACT_1"],
            "edge_uids": [],
            "dependency_code_hashes": ["CODE_1"],
            "missing_fact_kinds": ["value_range"],
        },
        "entry_paths": [["entry", "sink"]],
    }


def test_alias_growth_does_not_copy_alias_uids_into_validator_payload() -> None:
    small = build_validator_evidence_slice_v3(
        _issue(1), {"function_context": {"code": "void sink(void) {}"}}, ""
    )
    large = build_validator_evidence_slice_v3(
        _issue(500), {"function_context": {"code": "void sink(void) {}"}}, ""
    )

    assert "alias_uid_refs" not in small["alias_summary"]
    assert "alias_uid_refs" not in large["alias_summary"]
    assert len(large["alias_summary"]["alias_uid_set_hash"]) == 64
    # Only the numeric counts change; no occurrence, code or path is copied.
    small["alias_summary"]["occurrence_count"] = 0
    small["alias_summary"]["alias_count"] = 0
    large["alias_summary"]["occurrence_count"] = 0
    large["alias_summary"]["alias_count"] = 0
    small["alias_summary"]["alias_uid_set_hash"] = "HASH"
    large["alias_summary"]["alias_uid_set_hash"] = "HASH"
    assert small == large


def test_evidence_slice_keeps_one_representative_path_and_compact_code() -> None:
    issue = _issue(20)
    issue["entry_paths"] = [["entry", "wrapper", "sink"], ["other", "sink"]]
    evidence = {"function_context": {"code": "\n".join(f"line_{line};" for line in range(200))}}

    result = build_validator_evidence_slice_v3(issue, evidence, "")

    assert result["canonical_occurrence"]["representative_call_path"] == [
        "entry",
        "wrapper",
        "sink",
    ]
    assert "other" not in json.dumps(result, ensure_ascii=False)
    assert len(result["code"]["function_context"].splitlines()) <= 111


def test_v3_evidence_slice_projects_canonical_subject_and_decision_region() -> None:
    issue = _issue(0)
    issue["security_obligation"] = {
        "obligation_uid": "OBL_CANONICAL",
        "defect_family": "bounds",
        "obligation_shape": "source_sink_path",
        "subject_uid": "SUBJECT_CANONICAL",
        "source_uid": "SOURCE_CANONICAL",
        "sink_uid": "SINK_CANONICAL",
        "decision_region_uid": "REGION_CANONICAL",
    }

    result = build_validator_evidence_slice_v3(issue, {}, "")

    assert result["obligation"]["obligation_uid"] == "OBL_CANONICAL"
    assert result["obligation"]["subject_uid"] == "SUBJECT_CANONICAL"
    assert result["obligation"]["decision_region_uid"] == "REGION_CANONICAL"
