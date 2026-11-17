"""Contract boundaries shared by model schemas and immutable runtime results."""

from dataclasses import dataclass, fields

import pytest

from zscope.common.validator_protocol import (
    DynamicReproductionRequest,
    DynamicReproductionResult,
    parse_validator_result_v3,
    validator_result_provider_schema_v3,
    validator_result_schema_v3,
)
from zscope.framework.base import validate_function_arguments


def _payload(**changes):
    return {
        "schema_version": "zscope.validator-result.v3",
        "candidate_uid": "CAND_1",
        "validation_cluster_uid": "VAL_1",
        "pass": "initial",
        "verdict": "uncertain",
        "reasoning": "需要核对对象边界。",
        "positive_evidence": ["当前路径包含一次访问。"],
        "negative_evidence": [],
        "evidence_refs": ["FACT_1"],
        "blocking_negative_evidence": False,
        "missing_fact_request": {"fact_kind": "value_range", "reason": "缺少准确上限。"},
        "stop_reason": "missing_fact",
        **changes,
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"candidate_uid": " \t"},
        {"validation_cluster_uid": "\n"},
        {"reasoning": "  "},
        {"positive_evidence": [" \n"]},
        {"negative_evidence": ["\t"]},
        {"evidence_refs": [" "]},
        {"pass": " initial"},
        {"verdict": "uncertain "},
        {"stop_reason": " missing_fact"},
        {"missing_fact_request": {"fact_kind": " value_range", "reason": "缺少上限。"}},
        {"missing_fact_request": {"fact_kind": "value_range", "reason": " "}},
    ],
)
def test_schema_and_parser_reject_blank_content_and_enum_aliases(changes):
    payload = _payload(**changes)
    assert validate_function_arguments(validator_result_schema_v3(), payload) is not None
    assert parse_validator_result_v3(payload) is None


def test_runtime_result_owns_immutable_request_and_exports_independent_data():
    payload = _payload()
    result = parse_validator_result_v3(payload)
    assert result is not None
    payload["missing_fact_request"]["fact_kind"] = "lockset"
    payload["positive_evidence"].clear()
    assert result.missing_fact_request["fact_kind"] == "value_range"
    assert result.positive_evidence == ("当前路径包含一次访问。",)
    with pytest.raises(TypeError):
        result.missing_fact_request["fact_kind"] = "lockset"
    exported = result.to_dict()
    exported["missing_fact_request"]["fact_kind"] = "lockset"
    assert parse_validator_result_v3(result.to_dict()) == result


def test_evidence_identity_is_preserved_and_never_coerced_or_trimmed():
    schema = validator_result_provider_schema_v3(allowed_evidence_refs=[" FACT_1 ", 7])
    refs = schema["properties"]["evidence_refs"]["items"]["enum"]
    assert refs == [" FACT_1 "]
    payload = _payload(evidence_refs=[" FACT_1 "])
    result = parse_validator_result_v3(payload, allowed_evidence_refs=refs)
    assert result is not None and result.evidence_refs == (" FACT_1 ",)
    assert parse_validator_result_v3(payload, allowed_evidence_refs=["FACT_1"]) is None
    assert (
        parse_validator_result_v3(_payload(evidence_refs=["7"]), allowed_evidence_refs=[7]) is None
    )


@pytest.mark.parametrize("number", [True, -1, 1.5, "30", None])
def test_dynamic_contract_limits_require_nonnegative_integers(number):
    with pytest.raises(ValueError):
        DynamicReproductionRequest("R", "C", "V", "asan", "target", timeout_seconds=number)
    with pytest.raises(ValueError):
        DynamicReproductionResult("R", "inconclusive", "未完成。", duration_ms=number)


@pytest.mark.parametrize(
    "changes",
    [
        {"target": " "},
        {"evidence_refs": ["FACT"]},
        {"evidence_refs": (None,)},
        {"reproduction_kind": []},
    ],
)
def test_dynamic_request_validates_identity_and_immutable_reference_shape(changes):
    fields = dict(
        request_id="R",
        candidate_uid="C",
        validation_cluster_uid="V",
        reproduction_kind="asan",
        target="target",
    )
    with pytest.raises(ValueError):
        DynamicReproductionRequest(**(fields | changes))


@pytest.mark.parametrize(
    "value",
    [
        parse_validator_result_v3(_payload()),
        DynamicReproductionRequest("R", "C", "V", "asan", "target", ("FACT_1",)),
        DynamicReproductionResult("R", "inconclusive", "未完成。", ("FACT_1",), ("ARTIFACT_1",)),
    ],
)
def test_wire_projection_excludes_subclass_fields_and_detaches_reference_arrays(value):
    @dataclass(frozen=True)
    class Extended(type(value)):
        private_note: str = "internal-only"

    extended = Extended(**{field.name: getattr(value, field.name) for field in fields(value)})
    exported = extended.to_dict()
    assert exported == value.to_dict()
    assert "private_note" not in exported
    exported["evidence_refs"].append("OTHER_FACT")
    assert value.evidence_refs == ("FACT_1",)
