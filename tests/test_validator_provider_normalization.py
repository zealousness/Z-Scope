from __future__ import annotations

import json

from zscope.common.validator_protocol import (
    normalize_validator_provider_payload_v3,
    parse_validator_result_v3,
)


def _dsml_payload() -> dict:
    fields = {
        "candidate_uid": "CAND_REAL_023",
        "validation_cluster_uid": "VAL_REAL_023",
        "pass": "initial",
        "verdict": "verified",
        "reasoning": "加锁后存在直接早退，路径上没有解锁。",
        "positive_evidence": ["FACT_LOCK", "FACT_RETURN"],
        "negative_evidence": [],
        "evidence_refs": ["FACT_LOCK", "FACT_RETURN"],
        "blocking_negative_evidence": False,
        "missing_fact_request": None,
        "stop_reason": "decision_complete",
    }
    encoded = "zscope.validator-result.v3</parameter>"
    for name, value in fields.items():
        is_string = isinstance(value, str)
        rendered = value if is_string else json.dumps(value, ensure_ascii=False)
        encoded += (
            f'<｜DSML｜    parameter name="{name}" '
            f'string="{str(is_string).lower()}">{rendered}</parameter>'
        )
    encoded += "<｜DSML｜  invoke>"
    return {"schema_version": encoded}


def test_exact_terminal_tool_dsml_framing_is_strictly_normalized() -> None:
    normalized = normalize_validator_provider_payload_v3(_dsml_payload())

    assert normalized is not None
    parsed = parse_validator_result_v3(
        normalized,
        candidate_uid="CAND_REAL_023",
        validation_cluster_uid="VAL_REAL_023",
        expected_pass="initial",
        allowed_evidence_refs={"FACT_LOCK", "FACT_RETURN"},
    )
    assert parsed is not None
    assert parsed.verdict == "verified"


def test_dsml_normalizer_rejects_unknown_fields_and_nonterminal_markup() -> None:
    payload = _dsml_payload()
    encoded = payload["schema_version"]
    payload["schema_version"] = encoded.replace(
        "<｜DSML｜  invoke>",
        '<｜DSML｜ parameter name="extra" string="true">x</parameter><｜DSML｜  invoke>',
    )
    assert normalize_validator_provider_payload_v3(payload) is None

    payload = _dsml_payload()
    payload["schema_version"] = payload["schema_version"].replace("<｜DSML｜  invoke>", "")
    assert normalize_validator_provider_payload_v3(payload) is None
