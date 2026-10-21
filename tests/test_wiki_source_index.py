from __future__ import annotations

from pathlib import Path

from zscope.wiki.context.direct_documents import DirectDocumentResolver
from zscope.wiki.context.obligation import ConstraintObligation
from zscope.wiki.source_index import SourceIndex
from zscope.wiki.source_manifest import build_source_manifest

FIXTURE = Path(__file__).parent / "fixtures" / "wiki_project"


def _index(tmp_path: Path) -> SourceIndex:
    index = SourceIndex(tmp_path / "source-index.db")
    result = index.rebuild(FIXTURE, project_id="fixture", max_excerpt_chars=8192)
    assert result.project_id == "fixture"
    expected_count = 5 + int(not (FIXTURE / "docs" / "outside.md").is_symlink())
    assert result.document_count == expected_count
    assert result.section_count > 0
    return index


def test_readme_value_range_is_returned_without_llm(tmp_path: Path) -> None:
    index = _index(tmp_path)
    try:
        obligation = ConstraintObligation(
            project_id="fixture",
            subject_ids=("parse_byte",),
            obligation_kind="input_range",
            candidate_file="src/parser.c",
        )
        resolution = DirectDocumentResolver(index).resolve(
            obligation,
            max_results=4,
            fallback_reason="compiler_unavailable",
        )
        assert resolution.resolution_mode == "source_fallback"
        assert resolution.fallback_reason == "compiler_unavailable"
        assert resolution.source_excerpts
        first = resolution.source_excerpts[0]
        assert first.relative_path == "README.md"
        assert "API contract" in first.heading_path
        assert first.start_line <= first.end_line
        assert "0..255" in first.text
        assert "exact_symbol" in first.match_reasons
        assert "fact_kind" in first.match_reasons
        assert first.score > 0
        assert first.ref_id.startswith("docref_")
    finally:
        index.close()


def test_validator_value_range_alias_is_accepted(tmp_path: Path) -> None:
    index = _index(tmp_path)
    try:
        resolution = DirectDocumentResolver(index).resolve(
            ConstraintObligation.from_mapping(
                {
                    "target": {
                        "subject_id": "parse_byte",
                        "fact_kind": "value_range",
                        "relative_file": "src/parser.c",
                    }
                }
            ),
            max_results=1,
        )
        assert resolution.resolution_mode == "source_fallback"
        assert resolution.source_excerpts[0].relative_path == "README.md"
        assert "fact_kind" in resolution.source_excerpts[0].match_reasons
    finally:
        index.close()


def test_no_hit_returns_none_and_does_not_fill_budget(tmp_path: Path) -> None:
    index = _index(tmp_path)
    try:
        obligation = ConstraintObligation(
            project_id="fixture",
            subject_ids=("totally_unknown_api",),
            obligation_kind="input_range",
            candidate_file="src/unknown.c",
        )
        resolution = DirectDocumentResolver(index).resolve(obligation, max_results=4)
        assert resolution.resolution_mode == "none"
        assert resolution.source_excerpts == ()
        assert resolution.fallback_reason == "no_relevant_project_constraint"
        assert index.search(obligation, max_results=4) == []
    finally:
        index.close()


def test_search_none_max_results_returns_all_ranked_hits(tmp_path: Path) -> None:
    index = _index(tmp_path)
    try:
        obligation = ConstraintObligation(
            project_id="fixture",
            subject_ids=("parse_byte",),
            obligation_kind="input_range",
            candidate_file="src/parser.c",
        )
        bounded = index.search(obligation, max_results=1, max_documents=None)
        unbounded = index.search(obligation, max_results=None, max_documents=None)
        assert len(bounded) == 1
        assert len(unbounded) >= len(bounded)
    finally:
        index.close()


def test_schema_tables_and_rebuild_are_stable(tmp_path: Path) -> None:
    path = tmp_path / "source-index.db"
    index = SourceIndex(path)
    try:
        first = index.rebuild(FIXTURE, project_id="fixture", max_excerpt_chars=8192)
        rows = index.connection.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        names = {row[0] for row in rows if not row[0].startswith("sections_fts_")}
        expected = {"documents", "sections", "links", "classification_events"}
        if index.fts_enabled:
            expected.add("sections_fts")
        assert names == expected
        second = index.rebuild(FIXTURE, project_id="fixture", max_excerpt_chars=8192)
        assert first.source_manifest_digest == second.source_manifest_digest
        assert first.section_count == second.section_count
        assert (
            index.connection.execute("SELECT COUNT(*) FROM sections").fetchone()[0]
            == first.section_count
        )
    finally:
        index.close()


def test_manifest_overrides_are_preserved_in_source_index_events(tmp_path: Path) -> None:
    overrides = {"exclude": ["docs/api-limits-legacy.md"]}
    manifest = build_source_manifest(
        FIXTURE,
        project_id="fixture",
        overrides=overrides,
        created_at="2026-01-01T00:00:00Z",
    )
    index = SourceIndex(tmp_path / "source-index.db")
    try:
        index.rebuild(FIXTURE, manifest=manifest, overrides=overrides)
        event = index.connection.execute(
            "SELECT classification, reason FROM classification_events WHERE relative_path=?",
            ("docs/api-limits-legacy.md",),
        ).fetchone()
        assert event is not None
        assert event["classification"] == "unknown"
        assert event["reason"] == "user_excluded_path"
        assert not index.connection.execute(
            "SELECT 1 FROM documents WHERE relative_path=?",
            ("docs/api-limits-legacy.md",),
        ).fetchone()
    finally:
        index.close()


def test_direct_rebuild_prunes_dynamic_state_tree(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "README.md").write_text(
        "# Contract\n\nparse_byte must accept values from 0 to 255.\n",
        encoding="utf-8",
    )
    generated_page = project / "var" / "wiki" / "pages" / "project.md"
    generated_page.parent.mkdir(parents=True)
    generated_page.write_text("# Generated Wiki page\n", encoding="utf-8")

    index = SourceIndex(tmp_path / "source-index.db")
    try:
        result = index.rebuild(
            project,
            project_id="fixture",
            prune_paths=("var/wiki",),
        )
        paths = {
            row["relative_path"]
            for row in index.connection.execute("SELECT relative_path FROM documents")
        }
        assert result.document_count == 1
        assert paths == {"README.md"}
    finally:
        index.close()
