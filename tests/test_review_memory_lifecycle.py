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


def test_llm_cannot_create_new_matchable_feature():
    proposal = extract_with_llm(_record(), FakeLLM({
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
