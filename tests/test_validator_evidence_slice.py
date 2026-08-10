import json

from zscope.agents.validator_agent.agent import ValidatorAgent
from zscope.core.validation.evidence import build_validator_evidence_slice_v2


class _UnusedLLM:
    models = ["unit-model"]


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
    small = build_validator_evidence_slice_v2(
        _issue(1), {"function_context": {"code": "void sink(void) {}"}}, ""
    )
    large = build_validator_evidence_slice_v2(
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
    evidence = {
        "function_context": {"code": "\n".join(f"line_{line};" for line in range(200))}
    }

    result = build_validator_evidence_slice_v2(issue, evidence, "")

    assert result["canonical_occurrence"]["representative_call_path"] == [
        "entry",
        "wrapper",
        "sink",
    ]
    assert "other" not in json.dumps(result, ensure_ascii=False)
    assert len(result["code"]["function_context"].splitlines()) <= 111


def test_validator_v2_protocol_accepts_one_response_without_tools(monkeypatch) -> None:
    agent = ValidatorAgent(_UnusedLLM(), [])
    calls = []
    payload = {
        "type": "validation_result",
        "issue_id": "CAND_primary",
        "verdict": "uncertain",
        "finding_kind": "audit_observation",
        "is_valid": False,
        "confidence_score": 0.5,
        "reasoning": "one deterministic value range is missing",
        "positive_evidence": [],
        "negative_evidence": [],
        "blocking_negative_evidence": False,
        "missing_context": ["value_range"],
        "missing_fact_request": {"fact_kind": "value_range", "subject_uid": "wire_len"},
    }

    def run(messages, **kwargs):
        calls.append((messages, kwargs))
        return {
            "content": json.dumps(payload),
            "conversation": [{"role": "assistant", "content": json.dumps(payload)}],
            "iterations": 1,
            "tool_call_count": 0,
            "cumulative_prompt_tokens": 20,
            "cumulative_completion_tokens": 10,
            "cumulative_total_tokens": 30,
        }

    monkeypatch.setattr(agent, "_run_tool_conversation", run)
    response = agent.run(
        {
            "finding_uid": "CAND_primary",
            "evidence_slice": {"schema_version": "zscope.validator-evidence-slice.v2"},
            "evidence_slice_token_count": 12,
        }
    )

    assert response.success is True
    assert response.data["missing_fact_request"]["fact_kind"] == "value_range"
    assert len(calls) == 1
    assert calls[0][1]["max_iterations"] == 1
    assert response.metadata["validator_session_count"] == 1
    assert response.metadata["validator_api_call_count"] == 1
    assert response.metadata["multi_turn_outlier_count"] == 0


def test_validator_v2_invalid_output_closes_as_review_not_engine_failure(monkeypatch) -> None:
    agent = ValidatorAgent(_UnusedLLM(), [])
    monkeypatch.setattr(
        agent,
        "_run_tool_conversation",
        lambda *args, **kwargs: {
            "content": "not json",
            "conversation": [{"role": "assistant", "content": "not json"}],
            "iterations": 1,
            "tool_call_count": 0,
        },
    )
    monkeypatch.setattr(agent, "_run_json_repair", lambda *args, **kwargs: None)

    response = agent.run(
        {
            "finding_uid": "CAND_primary",
            "evidence_slice": {"schema_version": "zscope.validator-evidence-slice.v2"},
        }
    )

    assert response.success is True
    assert response.data["verdict"] == "uncertain"
    assert response.data["protocol_exhausted"] is True
    assert response.metadata["validator_api_call_count"] == 1


def test_validator_json_candidate_counter_accepts_repair_output_spec() -> None:
    agent = ValidatorAgent(_UnusedLLM(), [])
    payload = {
        "type": "validation_result",
        "verdict": "uncertain",
        "reasoning": "one fact is missing",
        "blocking_negative_evidence": False,
    }
    result = {
        "message": {
            "role": "assistant",
            "tool_calls": [
                {
                    "type": "function",
                    "function": {
                        "name": "emit_validation_result",
                        "arguments": json.dumps(payload),
                    },
                }
            ],
        }
    }

    count = agent._json_candidate_count(
        "",
        result,
        [],
        json_output_spec=agent._validation_json_output_spec(),
    )

    assert count == 1
