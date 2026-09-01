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
        "target": {"module_ids": [], "subject_ids": ["parse_byte"], "obligation_kinds": ["input_range"], "candidate_file": "src/parser.c"},
        "constraints": [],
        "source_excerpts": [{"ref_id": "docref_readme", "relative_path": "README.md", "heading_path": ["API contract"], "start_line": 3, "end_line": 6, "text": "0..255", "match_reasons": ["exact_symbol"], "score": 100}],
        "conflicts": [],
        "unknowns": [],
        "selection": {"max_tokens": 2000, "estimated_tokens": 2, "selected_constraint_ids": [], "omitted_constraint_count": 0, "omitted_source_excerpt_count": 4, "selected_source_ref_ids": ["docref_readme"], "ranking_version": "source-index.v1", "fallback_reason": "compiler_unavailable"},
    }
    result = build_validator_evidence_slice_v3(_issue(), {"project_knowledge": knowledge}, "int value = 0;", validation_pass="initial")
    assert result["project_knowledge"]["resolution_mode"] == "source_fallback"
    assert result["evidence_ref_catalog"]["docref_readme"]["kind"] == "project_document_ref"
    assert result["project_knowledge"]["constraints"] == []
    assert result["project_knowledge"]["omitted_source_excerpt_count"] == 4


def test_validator_project_knowledge_projection_is_compact_and_repairs_candidate_file() -> None:
    knowledge = {
        "schema_version": "zscope.validator-project-knowledge.v1",
        "resolution_mode": "wiki",
        "project_id": "fixture",
        "wiki_revision_id": "wikirev_abc",
        "source_manifest_digest": "sha256:" + "1" * 64,
        "context_digest": "sha256:" + "2" * 64,
        "target": {"module_ids": [], "subject_ids": ["api:parse_byte"], "obligation_kinds": ["input_range"], "candidate_file": "unknown.md", "function_id": "parse_byte"},
        "constraints": [{"constraint_id": "constraint_abc", "kind": "input_range", "subject_id": "parse_byte", "subject": {"kind": "api", "canonical_id": "parse_byte"}, "statement": "0..255", "authority": "documented_contract", "normativity": "required", "status": "active", "source_refs": ["docref_readme"]}],
        "source_excerpts": [], "conflicts": [], "unknowns": [],
        "selection": {"max_tokens": None, "estimated_tokens": 2, "selected_constraint_ids": ["constraint_abc"], "omitted_constraint_count": 0, "omitted_source_excerpt_count": 0, "selected_source_ref_ids": ["docref_readme"], "ranking_version": "v1", "fallback_reason": None},
    }
    issue = {"function": "parse_byte", "location": "src/parser.c:10"}
    result = build_validator_evidence_slice_v3(issue, {"project_knowledge": knowledge}, "int x;", validation_pass="initial")
    projection = result["project_knowledge"]
    assert set(projection) == {"resolution_mode", "wiki_revision_id", "target", "constraints", "source_excerpts", "conflicts", "omitted_constraint_count", "omitted_source_excerpt_count", "fallback_reason"}
    assert projection["target"]["candidate_file"] == "src/parser.c"
    assert projection["target"]["function_name"] == "parse_byte"
    assert projection["target"]["obligation_kinds"] == []
    assert projection["target"]["subject_ids"] == []
    assert projection["constraints"][0]["subject_kind"] == "api"
    assert projection["constraints"][0]["subject_id"] == "parse_byte"
    assert projection["omitted_source_excerpt_count"] == 0
