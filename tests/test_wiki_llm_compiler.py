from __future__ import annotations

import json
from pathlib import Path

from zscope.wiki.compiler.llm_compiler import LLMWikiCompilerProvider
from zscope.wiki.compiler.workset import build_ingest_workset
from zscope.wiki.source_index import SourceIndex
from zscope.wiki.source_manifest import build_source_manifest


FIXTURE = Path(__file__).parent / "fixtures" / "wiki_project"


class FakeLLM:
    supports_structured_output = False
    models = ["fake-wiki-model"]

    def __init__(self):
        self.messages = None

    def chat_completion(self, messages, **kwargs):
        self.messages = messages
        workset = json.loads(messages[-1]["content"])
        return {"choices": [{"message": {"content": json.dumps({
            "schema_version": "zscope.wiki-changeset.v1",
            "workset_id": workset["workset_id"],
            "base_revision_id": workset["base_revision_id"],
            "outcome": "background_only",
            "source_results": [{"source_ref": workset["added_source_ids"][0], "extraction_status": "no_constraints_found", "source_refs_used": [], "constraint_ids": [], "reason": "background"}],
            "page_changes": [], "constraint_proposals": [], "edge_proposals": [], "retire_proposals": [], "unresolved_conflicts": [], "summary": "background only",
        })}}]}


def test_llm_provider_validates_structured_changeset_without_network(tmp_path: Path) -> None:
    manifest = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(FIXTURE, manifest=manifest)
    workset = build_ingest_workset(manifest, source_index=index)
    llm = FakeLLM()
    result = LLMWikiCompilerProvider(llm)(workset)
    assert result["outcome"] == "background_only"
    assert result["constraint_proposals"] == []
    assert result["compiler"] == {
        "kind": "llm",
        "identity": "zscope.wiki.openai-compatible.v1",
        "prompt_version": "zscope.wiki-compiler.prompt.v2",
        "model": "fake-wiki-model",
    }
    assert "[[page_id|中文标题]]" in llm.messages[0]["content"]
    index.close()
