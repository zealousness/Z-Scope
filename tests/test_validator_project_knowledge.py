from __future__ import annotations

from zscope.core.validation.evidence import build_validator_evidence_slice_v3


def _issue() -> dict:
    return {
        "id": "candidate-1",
        "candidate_uid": "candidate-1",
        "function": "parse_byte",
        "location": "src/parser.c:10",
        "category": "input",
        "missing_fact_kinds": ["value_range"],
        "decision_fact_slice": {"fact_uids": [], "edge_uids": [], "facts": []},
    }


def test_project_knowledge_is_auxiliary_and_refs_enter_catalog() -> None:
    knowledge = {
        "schema_version": "zscope.validator-project-knowledge.v1",
        "resolution_mode": "source_fallback",
        "project_id": "fixture",
        "wiki_revision_id": None,
        "source_manifest_digest": "sha256:" + "1" * 64,
        "context_digest": "sha256:" + "2" * 64,
        "target": {"module_ids": [], "subject_ids": ["parse_byte"], "obligation_kind": "input_range", "candidate_file": "src/parser.c"},
        "constraints": [],
        "page_excerpts": [],
        "source_excerpts": [{"ref_id": "docref_readme", "relative_path": "README.md", "heading_path": ["API contract"], "start_line": 3, "end_line": 6, "text": "0..255", "match_reasons": ["exact_symbol"], "score": 100}],
        "conflicts": [],
        "unknowns": [],
        "selection": {"max_tokens": 2000, "estimated_tokens": 2, "selected_constraint_ids": [], "omitted_constraint_count": 0, "selected_page_ids": [], "selected_source_ref_ids": ["docref_readme"], "ranking_version": "source-index.v1", "fallback_reason": "compiler_unavailable"},
    }
    result = build_validator_evidence_slice_v3(_issue(), {"project_knowledge": knowledge}, "int value = 0;", validation_pass="initial")
    assert result["project_knowledge"]["resolution_mode"] == "source_fallback"
    assert result["evidence_ref_catalog"]["docref_readme"]["kind"] == "project_document_ref"
    assert result["project_knowledge"]["constraints"] == []
