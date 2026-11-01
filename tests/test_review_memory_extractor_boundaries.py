import json

import pytest

from zscope.review_memory.extractor import extract_with_llm


class FakeLLM:
    models = ["fake"]

    def __init__(self, payload):
        self.payload = payload

    def chat_completion(self, *_args, **_kwargs):
        return {"choices": [{"message": {"content": json.dumps(self.payload)}}]}


def test_llm_cannot_add_evidence_reference(monkeypatch):
    from zscope.agents.review_memory.agent import ReviewMemoryAgent
    from zscope.framework.base import AgentResponse

    # Exercise the extractor's independent defense after the Agent boundary.
    monkeypatch.setattr(ReviewMemoryAgent, "run", lambda *_: AgentResponse(
        success=True, data={"evidence_refs": ["forged"]}
    ))
    record = {
        "review_id": "r",
        "project_id": "p",
        "finding": {"stable_fingerprint": "fp"},
        "evidence_refs": ["known"],
        "user_rebuttal": "reason",
    }
    with pytest.raises(ValueError, match="evidence"):
        extract_with_llm(record, FakeLLM({"evidence_refs": ["forged"]}))
