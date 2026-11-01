import json
from pathlib import Path

import pytest

from zscope.review_memory.extractor import extract_with_llm, proposal_from_record
from zscope.review_memory.lifecycle import qualify_and_activate
from zscope.review_memory.matcher import match_patterns
from zscope.review_memory.projector import project_hints
from zscope.review_memory.store import ReviewMemoryStore


class FakeLLM:
    models = ["fake-model"]

    def __init__(self, content: str):
        self.content = content

    def chat_completion(self, messages, **kwargs):
        return {"choices": [{"message": {"content": self.content}}]}


def record():
    return {
        "schema_version": "zscope.review-record.v1",
        "review_id": "review-1",
        "project_id": "project-1",
        "finding": {"rule": "R1", "category": "C1", "stable_fingerprint": "fp-1"},
        "user_rebuttal": "historically unreachable",
        "evidence_refs": ["review-evidence-1"],
        "status": "pending_extraction",
    }


def test_llm_extractor_preserves_program_owned_identity(monkeypatch):
    from zscope.agents.review_memory.agent import ReviewMemoryAgent
    from zscope.framework.base import AgentResponse

    # A compromised/custom Agent must still not overwrite program identities.
    monkeypatch.setattr(ReviewMemoryAgent, "run", lambda self, _input: AgentResponse(
        success=True, data=json.loads(self.llm_client.content)
    ))
    proposal = extract_with_llm(
        record(),
        FakeLLM(json.dumps({
            "pattern_id": "forged",
            "project_id": "other",
            "false_positive_reason": "unreachable branch",
            "required_checks": ["check CFG"],
            "counter_conditions": ["external caller"],
            "trigger_features": [{"kind": "fingerprint", "value": "fp-1", "matchable": True}],
        })),
    )
    assert proposal["project_id"] == "project-1"
    assert proposal["pattern_id"] != "forged"
    assert proposal["false_positive_reason"] == "unreachable branch"


def test_qualification_requires_matchable_feature_and_guard():
    proposal = proposal_from_record(record())
    with pytest.raises(ValueError):
        qualify_and_activate(proposal)
    proposal["required_checks"] = ["check CFG"]
    assert qualify_and_activate(proposal)["status"] == "advisory"


def test_store_round_trip_and_digest(tmp_path: Path):
    store = ReviewMemoryStore(tmp_path)
    store.save_record(record())
    proposal = proposal_from_record(record())
    proposal["status"] = "advisory"
    proposal["required_checks"] = ["check CFG"]
    store.save_proposal(proposal)
    assert store.get_record("review-1")["review_id"] == "review-1"
    assert store.get_proposal(proposal["pattern_id"])["status"] == "advisory"
    assert store.proposal_digest("project-1")
    assert store.export_json()["schema_version"] == "zscope.review-memory-export.v1"


def test_matcher_is_project_rule_category_scoped():
    pattern = proposal_from_record(record())
    pattern.update({"status": "advisory", "required_checks": ["check CFG"]})
    assert match_patterns(record()["finding"], [pattern], project_id="project-1")
    assert not match_patterns(record()["finding"], [pattern], project_id="other")
    assert not match_patterns({**record()["finding"], "rule": "R2"}, [pattern], project_id="project-1")


def test_projection_is_bounded_and_advisory():
    result = project_hints([{"pattern_id": str(i)} for i in range(5)])
    assert result["authority"] == "advisory"
    assert result["selection"]["selected_count"] == 3
    assert result["selection"]["omitted_count"] == 2


def test_projection_respects_token_budget():
    result = project_hints([{"pattern_id": "one", "summary": "x" * 100}], token_budget=1)
    assert result["hints"] == []
