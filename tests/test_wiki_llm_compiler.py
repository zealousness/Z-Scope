from __future__ import annotations

import json
from pathlib import Path

import pytest

from zscope.framework.llm_client import LLMClient
from zscope.orchestration.specs import SpecRegistry
from zscope.wiki.compiler.llm_compiler import (
    FINAL_TOOL_NAME,
    LLMWikiCompilerProvider,
    MAX_ATTEMPTS,
)
from zscope.wiki.compiler.workset import build_ingest_workset
from zscope.wiki.source_index import SourceIndex
from zscope.wiki.source_manifest import build_source_manifest

FIXTURE = Path(__file__).parent / "fixtures" / "wiki_project"


class FakeLLM:
    supports_structured_output = False
    models = ["fake-wiki-model"]

    def __init__(self):
        self.messages = None
        self.kwargs = None

    @staticmethod
    def _payload(workset):
        return {
            "schema_version": "zscope.wiki-changeset.v1",
            "workset_id": workset["workset_id"],
            "base_revision_id": workset["base_revision_id"],
            "outcome": "background_only",
            "source_results": [
                {
                    "source_ref": workset["added_source_ids"][0],
                    "extraction_status": "no_constraints_found",
                    "source_refs_used": [],
                    "constraint_ids": [],
                    "reason": "background",
                }
            ],
            "page_changes": [],
            "constraint_proposals": [],
            "edge_proposals": [],
            "retire_proposals": [],
            "unresolved_conflicts": [],
            "summary": "background only",
        }

    def run_conversation_with_tools(self, messages, **kwargs):
        self.messages = messages
        self.kwargs = kwargs
        workset = json.loads(messages[-1]["content"])
        payload = self._payload(workset)
        payload["compiler"] = {
            "kind": "llm",
            "identity": "model-controlled",
            "prompt_version": "forged",
            "model": "forged-model",
        }
        validation = kwargs["terminal_tool_handler"](payload)
        return {
            "terminal_tool_valid": validation["valid"],
            "terminal_tool_payload": validation.get("payload"),
        }


def _build_workset(tmp_path: Path):
    manifest = build_source_manifest(
        FIXTURE,
        project_id="fixture",
        created_at="2026-01-01T00:00:00Z",
    )
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(FIXTURE, manifest=manifest)
    return index, build_ingest_workset(manifest, source_index=index)


def _tool_response(payload, call_index):
    return {
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": f"wiki_{call_index}",
                            "type": "function",
                            "function": {
                                "name": FINAL_TOOL_NAME,
                                "arguments": json.dumps(payload),
                            },
                        }
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


def test_llm_provider_validates_structured_changeset_without_network(tmp_path: Path) -> None:
    index, workset = _build_workset(tmp_path)
    llm = FakeLLM()
    result = LLMWikiCompilerProvider(llm)(workset)
    assert result["outcome"] == "background_only"
    assert result["constraint_proposals"] == []
    assert result["compiler"] == {
        "kind": "llm",
        "identity": "zscope.wiki.openai-compatible.v1",
        "prompt_version": "zscope.wiki-compiler.agent.v1",
        "model": "fake-wiki-model",
    }
    assert llm.messages[0]["content"] == SpecRegistry().get_agent("wiki_compiler").to_prompt_block()
    assert "[[page_id|中文标题]]" in llm.messages[0]["content"]
    assert FINAL_TOOL_NAME in llm.messages[0]["content"]
    assert "max_tokens" not in llm.kwargs
    assert llm.kwargs["max_iterations"] == MAX_ATTEMPTS == 5
    assert llm.kwargs["temperature"] == 0.0
    assert llm.kwargs["terminal_tool_name"] == FINAL_TOOL_NAME
    assert llm.kwargs["terminal_tool_required"] is True
    tool_schema = llm.kwargs["tools_schema"][0]
    assert tool_schema["function"]["name"] == FINAL_TOOL_NAME
    assert "$ref" not in json.dumps(tool_schema)
    assert workset["limits"] == {
        "max_pages": None,
        "max_source_chars": None,
        "max_output_chars": None,
        "max_wall_seconds": None,
    }
    index.close()


def test_llm_provider_applies_explicit_compiler_completion_limit(tmp_path: Path) -> None:
    index, workset = _build_workset(tmp_path)
    llm = FakeLLM()

    LLMWikiCompilerProvider(llm, max_tokens=6000)(workset)

    assert llm.kwargs["max_tokens"] == 6000
    index.close()


def test_llm_provider_accepts_valid_final_tool_after_two_repairs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    index, workset = _build_workset(tmp_path)
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid/v1",
        models=["fake-wiki-model"],
    )
    calls = []
    valid_payload = FakeLLM._payload(workset)

    def fake_chat_completion(messages, **kwargs):
        calls.append((list(messages), kwargs))
        payload = {"schema_version": "invalid"} if len(calls) < 3 else valid_payload
        return _tool_response(payload, len(calls))

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)
    result = LLMWikiCompilerProvider(client, max_tokens=6000)(workset)

    assert result["outcome"] == "background_only"
    assert len(calls) == 3
    assert all(call_kwargs["max_tokens"] == 6000 for _, call_kwargs in calls)
    assert all(call_kwargs["temperature"] == 0.0 for _, call_kwargs in calls)
    assert any(
        message.get("terminal_tool_result") for message in calls[1][0] if isinstance(message, dict)
    )
    assert any(
        message.get("terminal_tool_result") for message in calls[2][0] if isinstance(message, dict)
    )
    index.close()


def test_llm_provider_stops_after_configured_failed_attempts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    index, workset = _build_workset(tmp_path)
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid/v1",
        models=["fake-wiki-model"],
    )
    calls = []

    def fake_chat_completion(messages, **kwargs):
        calls.append((list(messages), kwargs))
        return _tool_response({"schema_version": "invalid"}, len(calls))

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)

    with pytest.raises(ValueError, match="did not submit a valid final tool payload"):
        LLMWikiCompilerProvider(client)(workset)

    assert len(calls) == MAX_ATTEMPTS == 5
    index.close()
