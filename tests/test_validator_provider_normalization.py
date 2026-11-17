from __future__ import annotations

import json

import pytest

from zscope.agents.validator_agent.agent import ValidatorAgent
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


@pytest.mark.parametrize(
    "fragment",
    [
        '{"fact_kind":"lockset","fact_kind":"value_range","reason":"Need the bound"}',
        '{"fact_kind":NaN,"fact_kind":"value_range","reason":"Need the bound"}',
        '{"fact_kind":1e999,"reason":"Need the bound"}',
        "[" * 10000 + "0" + "]" * 10000,
    ],
)
def test_dsml_fragments_obey_public_json_rules_without_escaping_exceptions(fragment):
    payload = _dsml_payload()
    payload["schema_version"] = (
        payload["schema_version"]
        .replace('string="true">verified</parameter>', 'string="true">uncertain</parameter>')
        .replace("decision_complete</parameter>", "missing_fact</parameter>")
        .replace(
            'name="missing_fact_request" string="false">null',
            'name="missing_fact_request" string="false">' + fragment,
        )
    )
    assert normalize_validator_provider_payload_v3(payload) is None
    result = {"content": json.dumps(payload)}
    agent = ValidatorAgent.__new__(ValidatorAgent)
    parsed, audit = agent._read_v3_response(
        result,
        {
            "candidate_uid": "CAND_REAL_023",
            "validation_cluster_uid": "VAL_REAL_023",
            "expected_pass": "initial",
            "allowed_evidence_refs": ["FACT_LOCK", "FACT_RETURN"],
            "allowed_missing_fact_kinds": {"value_range"},
        },
    )
    assert parsed is None
    assert not audit["provider_payload_normalized"]


def test_dsml_normalizer_accepts_whitespace_between_complete_parameters():
    payload = _dsml_payload()
    payload["schema_version"] = payload["schema_version"].replace(
        "</parameter>", "</parameter>\n\t"
    )
    normalized = normalize_validator_provider_payload_v3(payload)
    assert parse_validator_result_v3(normalized) is not None


def test_dsml_malformed_open_tags_do_not_produce_a_partial_result():
    payload = {
        "schema_version": "zscope.validator-result.v3</parameter>"
        + '<｜DSML｜ parameter name="candidate_uid" string="true">' * 1000
    }
    assert normalize_validator_provider_payload_v3(payload) is None
