from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from zscope.wiki.service import ProjectKnowledgeService
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


def test_active_wiki_page_context_is_pinned_to_manifest(tmp_path: Path) -> None:
    manifest = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(FIXTURE, manifest=manifest)
    state = tmp_path / "wiki"
    with WikiStore(state) as store:
        store.build_skeleton(FIXTURE, manifest)
        service = ProjectKnowledgeService(source_index=index, wiki_store=store, source_manifest_digest=manifest.source_manifest_digest, mode="active")
        context = service.resolve_for_candidate({"project_id": "fixture", "subject_id": "parse_byte", "fact_kind": "value_range", "relative_file": "src/parser.c"}, compiler_available=True)
        assert context["resolution_mode"] == "wiki"
        assert context["wiki_revision_id"]
        assert context["source_excerpts"] == []
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

            assert {item["wiki_revision_id"] for item in contexts} == {
                first.revision_id
            }
            assert all(item["resolution_mode"] == "wiki" for item in contexts)
            assert service.telemetry_snapshot()["resolution_count"] == 12
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
