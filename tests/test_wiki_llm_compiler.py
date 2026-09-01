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
from zscope.wiki.compiler.workset import (
    build_ingest_workset,
    build_llm_input_projection,
    split_workset_by_document,
)
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
            "constraint_proposals": [],
        }

    def run_conversation_with_tools(self, messages, **kwargs):
        self.messages = messages
        self.kwargs = kwargs
        workset = json.loads(messages[-1]["content"])
        payload = self._payload(workset)
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
    workset = split_workset_by_document(workset)[0]
    llm = FakeLLM()
    result = LLMWikiCompilerProvider(llm)(workset)
    assert result["outcome"] == "background_only"
    assert result["constraint_proposals"] == []
    assert result["compiler"] == {
        "kind": "llm",
        "identity": "zscope.wiki.openai-compatible.v1",
        "prompt_version": "zscope.constraint-compiler.agent.v3",
        "model": "fake-wiki-model",
    }
    assert llm.messages[0]["content"] == SpecRegistry().get_agent("wiki_compiler").to_prompt_block()
    assert "emit_project_constraints" in llm.messages[0]["content"]
    assert "normalized_value" in llm.messages[0]["content"]
    assert "max_tokens" not in llm.kwargs
    assert llm.kwargs["max_iterations"] == MAX_ATTEMPTS == 5
    assert llm.kwargs["temperature"] == 0.0
    assert llm.kwargs["terminal_tool_name"] == FINAL_TOOL_NAME
    assert llm.kwargs["terminal_tool_required"] is True
    projection = json.loads(llm.messages[-1]["content"])
    assert set(projection) == {"file_path", "title", "change", "sections"}
    assert projection["file_path"] == "docs/api-limits-legacy.md"
    assert projection["title"] == workset["project_id"]
    assert projection["change"] == "initial"
    assert len(projection["sections"]) == len(workset["source_sections"])
    assert all(
        set(section)
        == {
            "ref_id",
            "heading_path",
            "start_line",
            "end_line",
            "text",
        }
        for section in projection["sections"]
    )
    assert [section["start_line"] for section in projection["sections"]] == [1, 3]
    for forbidden in (
        "allowed_source_refs",
        "allowed_subject_ids",
        "source_ref_catalog",
        "source_sections",
        "workset_id",
        "base_revision_id",
        "source_manifest_digest",
        "limits",
    ):
        assert forbidden not in projection
    assert all(
        not any(forbidden in section for forbidden in (
            "allowed_source_refs",
            "allowed_subject_ids",
            "source_ref_catalog",
            "source_sections",
            "workset_id",
            "base_revision_id",
            "source_manifest_digest",
            "limits",
        ))
        for section in projection["sections"]
    )
    tool_schema = llm.kwargs["tools_schema"][0]
    assert tool_schema["function"]["name"] == FINAL_TOOL_NAME
    assert "$ref" not in json.dumps(tool_schema)
    assert tool_schema["function"]["parameters"]["required"] == ["constraint_proposals"]
    assert "workset_id" not in tool_schema["function"]["parameters"]["properties"]
    assert "summary" not in tool_schema["function"]["parameters"]["properties"]
    proposal_schema = tool_schema["function"]["parameters"]["properties"]["constraint_proposals"]["items"]
    assert "schema_version" not in proposal_schema["properties"]
    assert "schema_version" not in proposal_schema["required"]
    assert "subject_kind" in proposal_schema["properties"]
    assert proposal_schema["properties"]["subject_kind"]["enum"] == [
        "project", "module", "api", "symbol", "resource", "lock", "type", "configuration", "topic"
    ]
    tool_text = json.dumps(tool_schema)
    for forbidden in ("page_changes", "edge_proposals", "normalized_value", "page_refs", "status", "authority", "allowed_subject_kinds"):
        assert forbidden not in tool_text
    assert workset["limits"] == {"max_constraints": None, "max_wall_seconds": None}
    index.close()


def test_terminal_handler_adds_program_owned_proposal_schema_version(tmp_path: Path) -> None:
    index, workset = _build_workset(tmp_path)
    workset = split_workset_by_document(workset)[0]
    ref_id = workset["allowed_source_refs"][0]
    payload = {
        "constraint_proposals": [
            {
                "subject_id": "api:parse_byte",
                "subject_kind": "api",
                "kind": "input_range",
                "statement": "parse_byte accepts values from 0 to 255.",
                "normativity": "required",
                "source_refs": [ref_id],
            }
        ]
    }
    validation = LLMWikiCompilerProvider._changeset_from_terminal_payload(payload, workset)
    assert validation["constraint_proposals"][0]["schema_version"] == "zscope.project-constraint-proposal.v1"
    index.close()


def test_llm_input_projection_derives_incremental_change_and_section_refs(
    tmp_path: Path,
) -> None:
    index, workset = _build_workset(tmp_path)
    source_id = workset["added_source_ids"][0]
    incremental = dict(workset)
    incremental["base_revision_id"] = "wikirev_existing"
    incremental["added_source_ids"] = []
    incremental["changed_source_ids"] = [source_id]
    incremental["source_sections"] = [
        item for item in workset["source_sections"] if item["source_id"] == source_id
    ]
    incremental["source_ref_catalog"] = [
        item for item in workset["source_ref_catalog"] if item["source_id"] == source_id
    ]
    projection = build_llm_input_projection(incremental)

    assert projection["change"] == "incremental"
    assert projection["sections"]
    assert all(section["ref_id"].startswith("docref_") for section in projection["sections"])
    index.close()


def test_llm_input_projection_rejects_removed_sources(
    tmp_path: Path,
) -> None:
    index, workset = _build_workset(tmp_path)
    removed_source_id = workset["added_source_ids"][0]
    active_source_id = workset["added_source_ids"][1]
    projection_input = dict(workset)
    projection_input["base_revision_id"] = "wikirev_existing"
    projection_input["added_source_ids"] = []
    projection_input["changed_source_ids"] = []
    projection_input["removed_source_ids"] = [removed_source_id]
    projection_input["source_sections"] = [
        item
        for item in workset["source_sections"]
        if item["source_id"] == active_source_id
    ]
    projection_input["source_ref_catalog"] = [
        item
        for item in workset["source_ref_catalog"]
        if item["source_id"] == active_source_id
    ]
    with pytest.raises(ValueError, match="removed sources"):
        build_llm_input_projection(projection_input)
    index.close()


def test_llm_provider_applies_explicit_compiler_completion_limit(tmp_path: Path) -> None:
    index, workset = _build_workset(tmp_path)
    workset = split_workset_by_document(workset)[0]
    llm = FakeLLM()

    LLMWikiCompilerProvider(llm, max_tokens=6000)(workset)

    assert llm.kwargs["max_tokens"] == 6000
    index.close()


def test_final_tool_rejects_model_summary_and_program_generates_one(tmp_path: Path) -> None:
    index, workset = _build_workset(tmp_path)
    workset = split_workset_by_document(workset)[0]
    llm = FakeLLM()
    provider = LLMWikiCompilerProvider(llm)

    invalid = provider._validate_terminal_payload(
        {"constraint_proposals": [], "summary": "model-authored text"},
        workset,
    )
    assert invalid["valid"] is False
    assert "unknown" in invalid["error"]

    result = provider(workset)
    assert result["summary"] == "No documented constraints found."
    index.close()


def test_llm_provider_accepts_valid_final_tool_after_two_repairs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    index, workset = _build_workset(tmp_path)
    workset = split_workset_by_document(workset)[0]
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
    assert result["summary"] == "No documented constraints found."
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
    workset = split_workset_by_document(workset)[0]
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
