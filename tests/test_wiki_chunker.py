from __future__ import annotations

from pathlib import Path

from zscope.wiki.compiler.chunker import build_chunk_workset, plan_compiler_chunks
from zscope.wiki.compiler.workset import build_ingest_workset
from zscope.wiki.markdown_parser import parse_markdown
from zscope.wiki.source_index import SourceIndex
from zscope.wiki.source_manifest import build_source_manifest


def _workset(tmp_path: Path, text: str):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text(text, encoding="utf-8")
    manifest = build_source_manifest(root, project_id="chunk-fixture")
    index = SourceIndex(tmp_path / "source.db")
    index.rebuild(root, manifest=manifest)
    workset = build_ingest_workset(
        manifest,
        source_index=index,
        added_source_ids=[manifest.accepted[0].source_id],
    )
    return index, workset


def test_chunk_planner_covers_refs_without_overlap(tmp_path: Path) -> None:
    text = "\n".join(
        f"## Section {i}\n\nThe API must accept value {i}. " + ("x" * 160)
        for i in range(8)
    )
    index, workset = _workset(tmp_path, text)
    try:
        chunks = plan_compiler_chunks(workset, context_tokens=600, completion_tokens=256)
        assert len(chunks) > 1
        refs = [ref for chunk in chunks for ref in chunk.primary_ref_ids]
        assert len(refs) == len(set(refs)) == len(workset["allowed_source_refs"])
        assert [chunk.ordinal for chunk in chunks] == list(range(len(chunks)))
        child = build_chunk_workset(workset, chunks[0])
        assert set(child["allowed_source_refs"]) == set(chunks[0].primary_ref_ids)
        assert set(child["allowed_source_refs"]) < set(workset["allowed_source_refs"])
    finally:
        index.close()


def test_parser_preserves_long_line_as_fragments(tmp_path: Path) -> None:
    text = "# Contract\n\n" + ("x" * 20_000) + "\n"
    parsed = parse_markdown(text, source_id="docsrc_long", max_excerpt_chars=8192)
    fragments = [item for item in parsed.sections if item.fragment_count]
    assert len(fragments) >= 3
    assert "".join(item.excerpt for item in fragments[1:]) == "x" * 20_000
    assert all(item.fragment_count == len(fragments) for item in fragments)
    assert [item.fragment_index for item in fragments] == list(range(len(fragments)))
    assert fragments[0].char_start == 0
    assert fragments[-1].char_end == len(text.rstrip("\n"))
