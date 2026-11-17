"""A model chooses a decision; the invocation owns its result envelope."""

import pytest

from zscope.common.validator_protocol import (
    bind_validator_decision,
    parse_validator_result_v3,
    validator_decision_schema_v3,
    validator_result_provider_schema_v3,
)
from zscope.framework.base import validate_function_arguments


def _decision(**changes):
    return {
        "verdict": "verified",
        "reasoning": "当前路径存在无保护访问。",
        "positive_evidence": ["FACT_1 描述具体访问路径。"],
        "negative_evidence": [],
        "evidence_refs": ["FACT_1"],
        "blocking_negative_evidence": False,
        "missing_fact_request": None,
        **changes,
    }


def _bind(value, **changes):
    options = dict(
        candidate_uid="CAND_1",
        validation_cluster_uid="VAL_1",
        expected_pass="initial",
        allowed_evidence_refs=["FACT_1"],
        allowed_missing_fact_kinds=["value_range"],
        subject_uid="OBJECT_1",
        function_uid="FUNCTION_1",
    )
    return bind_validator_decision(value, **(options | changes))


def _request(**changes):
    return {"fact_kind": "value_range", "reason": "缺少可达值的准确上限。", **changes}


def test_model_schema_has_only_decisions_and_preserves_provider_restrictions():
    schema = validator_decision_schema_v3(
        allowed_missing_fact_kinds=["value_range"], allowed_evidence_refs=["FACT_1"]
    )
    assert set(schema["properties"]) == set(schema["required"]) == set(_decision())
    assert schema["additionalProperties"] is False
    assert schema["properties"]["evidence_refs"]["items"]["enum"] == ["FACT_1"]
    request = schema["properties"]["missing_fact_request"]["anyOf"][1]
    assert set(request["properties"]) == set(request["required"]) == {"fact_kind", "reason"}
    assert request["properties"]["fact_kind"]["enum"] == ["value_range"]
    historical = validator_result_provider_schema_v3()
    assert "pass" in historical["properties"]
    assert (
        "subject_uid" in historical["properties"]["missing_fact_request"]["anyOf"][1]["properties"]
    )
    closed = validator_decision_schema_v3(allowed_missing_fact_kinds=[], allowed_evidence_refs=[])
    assert closed["properties"]["missing_fact_request"]["type"] == "null"
    assert closed["properties"]["evidence_refs"]["maxItems"] == 0


@pytest.mark.parametrize("field", tuple(_decision()))
def test_every_decision_field_is_required(field):
    value = _decision()
    del value[field]
    assert validate_function_arguments(validator_decision_schema_v3(), value) is not None
    assert _bind(value) is None


@pytest.mark.parametrize(
    "verdict,fact_request,stop",
    [
        ("verified", None, "decision_complete"),
        ("rejected", None, "decision_complete"),
        ("uncertain", None, "no_evidence_gain"),
        ("uncertain", _request(), "missing_fact"),
    ],
)
def test_program_binds_identity_request_target_and_stop_state(verdict, fact_request, stop):
    value = _decision(verdict=verdict, missing_fact_request=fact_request)
    result = _bind(value)
    assert result is not None
    exported = result.to_dict()
    assert (exported["candidate_uid"], exported["validation_cluster_uid"], exported["pass"]) == (
        "CAND_1",
        "VAL_1",
        "initial",
    )
    assert exported["schema_version"] == "zscope.validator-result.v3"
    assert result.stop_reason == stop
    assert parse_validator_result_v3(exported) == result
    assert _bind(exported) == result
    if fact_request is not None:
        assert result.missing_fact_request == {
            **fact_request,
            "subject_uid": "OBJECT_1",
            "function_uid": "FUNCTION_1",
        }
        assert set(value["missing_fact_request"]) == {"fact_kind", "reason"}


@pytest.mark.parametrize("field", ["subject_uid", "function_uid"])
def test_model_cannot_supply_missing_fact_target(field):
    value = _decision(verdict="uncertain", missing_fact_request=_request(**{field: "MODEL_TARGET"}))
    assert validate_function_arguments(validator_decision_schema_v3(), value) is not None
    assert _bind(value) is None


@pytest.mark.parametrize(
    "metadata,value",
    [
        ("schema_version", "zscope.validator-result.v0"),
        ("candidate_uid", "CAND_OTHER"),
        ("validation_cluster_uid", "VAL_OTHER"),
        ("pass", "evidence_recheck"),
    ],
)
def test_historical_metadata_is_checked_and_never_replaced(metadata, value):
    result = _bind(_decision()).to_dict()
    result[metadata] = value
    assert _bind(result) is None


@pytest.mark.parametrize(
    "field", ["schema_version", "candidate_uid", "validation_cluster_uid", "pass", "stop_reason"]
)
def test_partial_old_and_new_shapes_are_not_mixed(field):
    result = _bind(_decision()).to_dict()
    assert _bind(_decision(**{field: result[field]})) is None


@pytest.mark.parametrize("verdict", ["verified", "rejected"])
def test_completed_decision_cannot_request_a_fact(verdict):
    assert _bind(_decision(verdict=verdict, missing_fact_request=_request())) is None


def test_historical_stop_reason_and_request_targets_are_preserved():
    result = _bind(_decision(verdict="uncertain", missing_fact_request=_request())).to_dict()
    result["missing_fact_request"]["subject_uid"] = "HISTORICAL_TARGET"
    assert _bind(result).missing_fact_request["subject_uid"] == "HISTORICAL_TARGET"
    result.update(missing_fact_request=None, stop_reason="fact_timeout")
    assert _bind(result).stop_reason == "fact_timeout"


def test_fact_and_evidence_allowlists_apply_to_both_wire_formats():
    decision = _decision(verdict="uncertain", missing_fact_request=_request())
    historical = _bind(decision).to_dict()
    for value in (decision, historical):
        assert _bind(value, allowed_missing_fact_kinds=[]) is None
        assert _bind(value, allowed_evidence_refs=[]) is None
    assert _bind(decision, allowed_missing_fact_kinds=iter(["value_range"])) is not None


@pytest.mark.parametrize(
    "changes",
    [
        {"reasoning": " "},
        {"verdict": " verified"},
        {"evidence_refs": ("FACT_1",)},
        {"blocking_negative_evidence": 1},
        {"positive_evidence": ["x" * 1001]},
        {"missing_fact_request": []},
    ],
)
def test_compact_payload_keeps_full_result_validation(changes):
    assert _bind(_decision(**changes)) is None


@pytest.mark.parametrize(
    "changes", [{"candidate_uid": ""}, {"validation_cluster_uid": " "}, {"expected_pass": ""}]
)
def test_binding_requires_a_real_invocation_scope(changes):
    assert _bind(_decision(), **changes) is None
    assert _bind(_bind(_decision()).to_dict(), **changes) is None
