from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

import pytest

from zscope.wiki.service import ProjectKnowledgeService, validate_project_knowledge
from zscope.wiki.identity import stable_id
from zscope.wiki.source_index import SourceIndex
from zscope.wiki.source_manifest import build_source_manifest
from zscope.wiki.store.revision_store import WikiStore


FIXTURE = Path(__file__).parent / "fixtures" / "wiki_project"


def test_shadow_service_returns_direct_source_context_without_llm(tmp_path: Path) -> None:
    manifest = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(FIXTURE, manifest=manifest)
    try:
        service = ProjectKnowledgeService(source_index=index, source_manifest_digest=manifest.source_manifest_digest, mode="shadow")
        context = service.resolve_for_candidate({"project_id": "fixture", "subject_id": "parse_byte", "fact_kind": "value_range", "relative_file": "src/parser.c"})
        assert context["schema_version"] == "zscope.validator-project-knowledge.v1"
        assert context["resolution_mode"] == "source_fallback"
        assert context["wiki_revision_id"] is None
        assert context["constraints"] == []
        assert context["source_excerpts"][0]["relative_path"] == "README.md"
        assert context["selection"]["selected_source_ref_ids"]
        assert context["context_digest"].startswith("sha256:")
    finally:
        index.close()


def test_service_target_uses_candidate_location_when_file_is_unknown(tmp_path: Path) -> None:
    manifest = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(FIXTURE, manifest=manifest)
    try:
        service = ProjectKnowledgeService(source_index=index, source_manifest_digest=manifest.source_manifest_digest, mode="shadow")
        context = service.resolve_for_candidate(
            {
                "project_id": "fixture",
                "function": "parse_byte",
                "location": "src/parser.c:10",
                "target": {"candidate_file": "unknown.md"},
            }
        )
        assert context["target"]["candidate_file"] == "src/parser.c"
    finally:
        index.close()


def test_service_uses_shared_default_context_token_budget(tmp_path: Path) -> None:
    manifest = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(FIXTURE, manifest=manifest)
    try:
        unlimited = ProjectKnowledgeService(
            source_index=index,
            source_manifest_digest=manifest.source_manifest_digest,
            mode="shadow",
        ).resolve_for_candidate({"project_id": "fixture", "subject_id": "parse_byte", "fact_kind": "value_range"})
        assert unlimited["selection"]["max_tokens"] == 4096
        assert unlimited["selection"]["estimated_tokens"] <= 4096
    finally:
        index.close()


def test_direct_fallback_defers_result_cap_to_project_knowledge(tmp_path: Path) -> None:
    manifest = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(FIXTURE, manifest=manifest)
    calls = []
    original_search = index.search

    def search(obligation, **kwargs):
        calls.append(kwargs)
        return original_search(obligation, **kwargs)

    index.search = search
    try:
        service = ProjectKnowledgeService(
            source_index=index,
            source_manifest_digest=manifest.source_manifest_digest,
            mode="shadow",
        )
        service.resolve_for_candidate(
            {"project_id": "fixture", "subject_id": "parse_byte", "fact_kind": "value_range"}
        )
        assert calls[0]["max_results"] is None
        assert calls[0]["max_documents"] is None
        assert calls[0]["max_tokens"] is None
    finally:
        index.close()


def test_direct_fallback_truncates_results_and_reports_omissions(tmp_path: Path) -> None:
    manifest = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(FIXTURE, manifest=manifest)
    rows = [
        {
            "ref_id": f"docref_excerpt_{i}",
            "relative_path": "README.md",
            "heading_path": ["API contract"],
            "start_line": i + 1,
            "end_line": i + 1,
            "text": f"parse_byte contract excerpt {i}",
            "match_reasons": ["exact_symbol"],
            "score": 100 - i,
        }
        for i in range(25)
    ]
    index.search = lambda _obligation, **_kwargs: rows
    try:
        service = ProjectKnowledgeService(
            source_index=index,
            source_manifest_digest=manifest.source_manifest_digest,
            mode="shadow",
        )
        context = service.resolve_for_candidate(
            {"project_id": "fixture", "subject_id": "parse_byte", "fact_kind": "value_range"}
        )
        assert context["resolution_mode"] == "source_fallback"
        assert len(context["source_excerpts"]) == 20
        assert context["selection"]["omitted_source_excerpt_count"] == 5
        assert context["selection"]["omitted_constraint_count"] == 0
    finally:
        index.close()


def test_project_knowledge_rejects_token_budget_above_shared_cap(tmp_path: Path) -> None:
    manifest = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(FIXTURE, manifest=manifest)
    try:
        service = ProjectKnowledgeService(
            source_index=index,
            source_manifest_digest=manifest.source_manifest_digest,
            mode="shadow",
        )
        with pytest.raises(ValueError, match="must not exceed 4096"):
            service.resolve_for_candidate(
                {"project_id": "fixture", "subject_id": "parse_byte", "fact_kind": "value_range"},
                max_tokens=4097,
            )
    finally:
        index.close()


def test_active_wiki_selects_at_most_twenty_and_reports_omissions(tmp_path: Path) -> None:
    manifest = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(FIXTURE, manifest=manifest)
    ref_id = index.connection.execute("SELECT section_id, source_id FROM sections ORDER BY source_id, start_line LIMIT 1").fetchone()
    source_ref = stable_id("docref", ref_id["source_id"], ref_id["section_id"])
    try:
        service = ProjectKnowledgeService(
            source_index=index,
            source_manifest_digest=manifest.source_manifest_digest,
            mode="active",
            compiler_available=True,
        )
        service._pinned_revision_id = "wikirev_test"
        service._pinned_refs = {source_ref: {"resolvable": True}}
        service._pinned_constraints = tuple(
            {
                "constraint_id": f"constraint_{i}",
                "kind": "input_range",
                "subject": {"canonical_id": "api:parse_byte", "kind": "api"},
                "statement": f"parse_byte contract {i}",
                "authority": "documented_contract",
                "normativity": "required",
                "status": "active",
                "source_refs": [source_ref],
            }
            for i in range(25)
        )
        context = service.resolve_for_candidate(
            {"project_id": "fixture", "subject_id": "parse_byte", "fact_kind": "input_range"}
        )
        assert context["resolution_mode"] == "wiki"
        assert len(context["constraints"]) == 20
        assert context["selection"]["omitted_constraint_count"] == 5
        assert context["selection"]["max_tokens"] == 4096
    finally:
        index.close()


def test_active_wiki_injects_conflicted_constraints_with_conflict_summary(tmp_path: Path) -> None:
    manifest = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(FIXTURE, manifest=manifest)
    ref_id = "docref_fixture:readme"
    try:
        service = ProjectKnowledgeService(
            source_index=index,
            source_manifest_digest=manifest.source_manifest_digest,
            mode="active",
            compiler_available=True,
        )
        service._pinned_revision_id = "wikirev_conflict"
        service._pinned_refs = {ref_id: {"resolvable": True}}
        service._pinned_constraints = (
            {
                "constraint_id": "constraint_range_a",
                "kind": "input_range",
                "subject": {"canonical_id": "parse_byte", "kind": "api"},
                "statement": "parse_byte accepts 0..127",
                "authority": "documented_contract",
                "normativity": "required",
                "status": "conflicted",
                "source_refs": [ref_id],
                "conflicts_with": ["constraint_range_b"],
            },
            {
                "constraint_id": "constraint_range_b",
                "kind": "input_range",
                "subject": {"canonical_id": "parse_byte", "kind": "api"},
                "statement": "parse_byte accepts 0..255",
                "authority": "documented_contract",
                "normativity": "required",
                "status": "conflicted",
                "source_refs": [ref_id],
                "conflicts_with": ["constraint_range_a"],
            },
        )

        context = service.resolve_for_candidate(
            {
                "project_id": "fixture",
                "subject_id": "parse_byte",
                "fact_kind": "input_range",
                "relative_file": "src/parser.c",
            }
        )

        assert context["resolution_mode"] == "wiki"
        assert [item["status"] for item in context["constraints"]] == ["conflicted", "conflicted"]
        assert context["constraints"][0]["conflicts_with"]
        assert context["conflicts"] == [{
            "subject_id": "parse_byte",
            "constraint_ids": ["constraint_range_a", "constraint_range_b"],
            "reason": "Conflicting documented constraints; resolve against source and code evidence.",
            "source_refs": [ref_id],
        }]
        assert validate_project_knowledge(context)["conflicts"] == context["conflicts"]
    finally:
        index.close()


def test_active_skeleton_without_constraints_falls_back_to_source(tmp_path: Path) -> None:
    manifest = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(FIXTURE, manifest=manifest)
    state = tmp_path / "wiki"
    with WikiStore(state) as store:
        store.build_skeleton(FIXTURE, manifest)
        service = ProjectKnowledgeService(source_index=index, wiki_store=store, source_manifest_digest=manifest.source_manifest_digest, mode="active")
        context = service.resolve_for_candidate({"project_id": "fixture", "subject_id": "parse_byte", "fact_kind": "value_range", "relative_file": "src/parser.c"}, compiler_available=True)
        assert context["resolution_mode"] == "source_fallback"
        assert context["wiki_revision_id"] is None
        assert context["source_excerpts"]
        assert context["constraints"] == []


def test_service_pins_one_revision_across_pointer_changes_and_worker_threads(
    tmp_path: Path,
) -> None:
    manifest = build_source_manifest(
        FIXTURE,
        project_id="fixture",
        created_at="2026-01-01T00:00:00Z",
    )
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(FIXTURE, manifest=manifest)
    state = tmp_path / "wiki"
    try:
        with WikiStore(state) as store:
            first = store.build_skeleton(
                FIXTURE,
                manifest,
                revision_id="wikirev_scan_a",
            )
            service = ProjectKnowledgeService(
                source_index=index,
                wiki_store=store,
                source_manifest_digest=manifest.source_manifest_digest,
                mode="active",
                compiler_available=True,
            )
            second = store.build_skeleton(
                FIXTURE,
                manifest,
                revision_id="wikirev_scan_b",
            )
            assert first.revision_id != second.revision_id
            assert store.active_revision()["revision_id"] == second.revision_id

            def resolve(_index: int) -> dict:
                return service.resolve_for_candidate(
                    {
                        "project_id": "fixture",
                        "subject_id": "parse_byte",
                        "fact_kind": "value_range",
                        "relative_file": "src/parser.c",
                    }
                )

            with ThreadPoolExecutor(max_workers=4) as executor:
                contexts = list(executor.map(resolve, range(12)))

            assert {item["wiki_revision_id"] for item in contexts} == {None}
            assert all(item["resolution_mode"] == "source_fallback" for item in contexts)
            assert service.telemetry_snapshot()["resolution_count"] == 12
    finally:
        index.close()


def test_stale_wiki_pages_are_not_available_to_validator(tmp_path: Path) -> None:
    manifest = build_source_manifest(
        FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z"
    )
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(FIXTURE, manifest=manifest)
    state = tmp_path / "wiki"
    try:
        with WikiStore(state) as store:
            store.build_skeleton(FIXTURE, manifest)
            revision_id = store.active_revision()["revision_id"]
            rows = store.connection.execute(
                "SELECT page_id, frontmatter_json FROM pages WHERE revision_id=?",
                (revision_id,),
            ).fetchall()
            assert rows == []

            service = ProjectKnowledgeService(
                source_index=index,
                wiki_store=store,
                source_manifest_digest=manifest.source_manifest_digest,
                mode="active",
                compiler_available=True,
            )
            context = service.resolve_for_candidate(
                {
                    "project_id": "fixture",
                    "subject_id": "parse_byte",
                    "fact_kind": "value_range",
                    "relative_file": "src/parser.c",
                }
            )
            assert context["resolution_mode"] == "source_fallback"
            assert context["constraints"] == []
    finally:
        index.close()


def test_service_telemetry_proves_active_injection_only_with_incremental_facts(tmp_path: Path) -> None:
    manifest = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(FIXTURE, manifest=manifest)
    state = tmp_path / "wiki"
    with WikiStore(state) as store:
        store.build_skeleton(FIXTURE, manifest)
        service = ProjectKnowledgeService(
            source_index=index,
            wiki_store=store,
            source_manifest_digest=manifest.source_manifest_digest,
            mode="active",
            compiler_available=True,
        )
        service.resolve_for_candidate({"project_id": "fixture", "subject_id": "parse_byte", "fact_kind": "value_range", "relative_file": "src/parser.c"})
        telemetry = service.telemetry_snapshot()
        assert telemetry["active_effective_mode"] is True
        assert telemetry["wiki_context_injected"] is False
        assert telemetry["incremental_fact_count"] == 0
        assert telemetry["knowledge_context_tokens"] > 0
    index.close()
