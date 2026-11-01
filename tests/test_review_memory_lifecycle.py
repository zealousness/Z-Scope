import json

import pytest

from zscope.review_memory.extractor import extract_with_llm, proposal_from_record
from zscope.review_memory.matcher import match_patterns


class FakeLLM:
    models = ["fake"]

    def __init__(self, payload):
        self.payload = payload

    def chat_completion(self, *_args, **_kwargs):
        return {"choices": [{"message": {"content": json.dumps(self.payload)}}]}


class CapturingLLM(FakeLLM):
    def __init__(self, payload):
        super().__init__(payload)
        self.messages = []

    def chat_completion(self, messages, **kwargs):
        self.messages.append(messages)
        return super().chat_completion(messages, **kwargs)


def _record():
    return {
        "schema_version": "zscope.review-record.v1",
        "review_id": "r1",
        "project_id": "p1",
        "finding": {"rule": "R", "category": "C", "stable_fingerprint": "fp"},
        "user_rebuttal": "reason",
        "evidence_refs": ["e1"],
        "status": "pending_extraction",
    }


def test_review_memory_user_content_is_final_tool_only():
    llm = CapturingLLM({
        "false_positive_reason": "调用点缺少当前证据",
        "required_checks": ["重新检查当前源码"],
        "counter_conditions": ["存在已证明的外部可控输入"],
        "trigger_features": [],
    })
    extract_with_llm(_record(), llm)
    user_content = llm.messages[0][1]["content"]
    assert "FINAL TOOL ONLY" in user_content
    assert "emit_review_pattern" in user_content
    assert "Do not emit" in user_content
    assert "Do not put any final JSON outside the tool call" in user_content
    assert '"review_id"' in user_content


def test_llm_cannot_create_new_matchable_feature():
    proposal = extract_with_llm(_record(), FakeLLM({
        "false_positive_reason": "需要复核当前证据",
        "counter_conditions": [],
        "trigger_features": [
            {"kind": "fingerprint", "value": "other", "matchable": True},
        ],
        "required_checks": ["recheck"],
    }))
    assert proposal["trigger_features"][0]["matchable"] is False


def test_source_drift_does_not_match_advisory_pattern():
    pattern = proposal_from_record(_record())
    pattern.update({"status": "advisory", "required_checks": ["recheck"]})
    assert match_patterns({"rule": "R", "category": "C", "stable_fingerprint": "changed"}, [pattern], project_id="p1") == []


def test_same_finding_revisions_share_one_proposal_identity():
    first = _record()
    second = dict(first, review_id="r2", user_rebuttal="later explanation")
    assert proposal_from_record(first)["pattern_id"] == proposal_from_record(second)["pattern_id"]


def test_candidate_function_predicate_matches_across_issue_ids():
    finding = {"rule": "R", "category": "C", "function": "_safe_calloc", "candidate_uid": "uid-1"}
    pattern = proposal_from_record({**_record(), "finding": finding})
    pattern.update({"status": "advisory", "required_checks": ["recheck"]})
    current = {"candidate_id": "new-id", "issue_id": "new-issue", **finding, "candidate_uid": "uid-other", "file": "other.c", "line": 99}
    matches = match_patterns(current, [pattern], project_id="p1")
    assert matches and "function" in matches[0]["match_basis"]


def test_candidate_semantic_group_matches_different_function():
    finding = {"rule": "R", "category": "C", "function": "first", "root_cause_key": "unchecked-allocation", "source_identity": "allocator", "sink_identity": "copy"}
    pattern = proposal_from_record({**_record(), "finding": finding})
    pattern.update({"status": "advisory", "required_checks": ["recheck"]})
    current = {**finding, "function": "second", "candidate_uid": "different", "candidate_id": "different"}
    assert match_patterns(current, [pattern], project_id="p1")


def test_candidate_rule_revision_is_strictly_isolated():
    finding = {"rule": "R", "rule_revision": "2", "category": "C", "function": "same"}
    pattern = proposal_from_record({**_record(), "finding": finding})
    pattern.update({"status": "advisory", "required_checks": ["recheck"]})
    assert match_patterns({**finding, "rule_revision": "3"}, [pattern], project_id="p1") == []
