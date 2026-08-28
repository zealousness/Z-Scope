from __future__ import annotations

from pathlib import Path

import pytest

from zscope.wiki.classification import classify_document
from zscope.wiki.discovery import discover_markdown
from zscope.wiki.markdown_parser import parse_markdown
from zscope.wiki.source_manifest import build_source_manifest, write_source_manifest


FIXTURE = Path(__file__).parent / "fixtures" / "wiki_project"


def test_discovery_prunes_wiki_state_and_is_sorted() -> None:
    result = discover_markdown(FIXTURE)
    paths = [item.relative_path for item in result.files]
    assert paths == sorted(paths)
    assert not any(path.startswith(".zscope_knowledge/") for path in paths)
    assert "README.md" in paths
    assert result.unsupported_extensions == {}


def test_discovery_prunes_validated_dynamic_state_root(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Contract\n", encoding="utf-8")
    state_document = tmp_path / "var" / "wiki" / "pages" / "project.md"
    state_document.parent.mkdir(parents=True)
    state_document.write_text("# Generated Wiki\n", encoding="utf-8")

    result = discover_markdown(tmp_path, prune_paths=("var/wiki",))
    manifest = build_source_manifest(
        tmp_path,
        project_id="fixture",
        created_at="2026-01-01T00:00:00Z",
        prune_paths=("var/wiki",),
    )

    assert [item.relative_path for item in result.files] == ["README.md"]
    assert [item.relative_path for item in manifest.accepted] == ["README.md"]


@pytest.mark.parametrize("prune_path", ["", ".", "../wiki", "/tmp/wiki", "C:\\\\wiki"])
def test_discovery_rejects_unsafe_dynamic_prune_root(
    tmp_path: Path,
    prune_path: str,
) -> None:
    with pytest.raises(ValueError, match="prune path"):
        discover_markdown(tmp_path, prune_paths=(prune_path,))


def test_manifest_classification_and_digest_are_stable() -> None:
    first = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    second = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-02-01T00:00:00Z")
    assert first.source_manifest_digest == second.source_manifest_digest
    assert [item.relative_path for item in first.accepted] == [
        "README.md",
        "docs/api-limits-legacy.md",
        "docs/api-limits.md",
        "docs/background.md",
        "docs/module.md",
    ]
    excluded = {item.relative_path: item.classification for item in first.excluded}
    assert excluded["AGENTS.md"] == "runtime_instruction"
    assert excluded["GROUND_TRUTH.md"] == "benchmark_truth"
    assert excluded["artifacts/scan-report.md"] == "generated_artifact"
    assert excluded["docs/secrets.md"] == "sensitive_rejected"


def test_non_markdown_files_do_not_change_manifest_digests(tmp_path: Path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text("# Contract\n\nThe API must return zero.\n", encoding="utf-8")
    first = build_source_manifest(
        tmp_path,
        project_id="fixture",
        created_at="2026-01-01T00:00:00Z",
    )

    (tmp_path / "scan.log").write_text("first run\n", encoding="utf-8")
    (tmp_path / "report.json").write_text('{"status":"complete"}\n', encoding="utf-8")
    (tmp_path / "source.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    second = build_source_manifest(
        tmp_path,
        project_id="fixture",
        created_at="2026-02-01T00:00:00Z",
    )

    assert first.project_root_digest == second.project_root_digest
    assert first.source_manifest_digest == second.source_manifest_digest
    assert second.unsupported_extensions == {".c": 1, ".json": 1, ".log": 1}

    (tmp_path / "scan.log").write_text("changed run\n", encoding="utf-8")
    (tmp_path / "another.log").write_text("another run\n", encoding="utf-8")
    third = build_source_manifest(
        tmp_path,
        project_id="fixture",
        created_at="2026-03-01T00:00:00Z",
    )

    assert second.project_root_digest == third.project_root_digest
    assert second.source_manifest_digest == third.source_manifest_digest
    assert third.unsupported_extensions == {".c": 1, ".json": 1, ".log": 2}

    readme.write_text("# Contract\n\nThe API must return one.\n", encoding="utf-8")
    changed_markdown = build_source_manifest(
        tmp_path,
        project_id="fixture",
        created_at="2026-04-01T00:00:00Z",
    )
    assert changed_markdown.project_root_digest != third.project_root_digest
    assert changed_markdown.source_manifest_digest != third.source_manifest_digest


def test_parser_keeps_heading_locations_features_and_links() -> None:
    result = discover_markdown(FIXTURE)
    readme = next(item for item in result.files if item.relative_path == "README.md")
    parsed = parse_markdown(readme, source_id="docsrc_fixture_readme")
    assert parsed.input_language == "en"
    assert parsed.sections
    api = next(item for item in parsed.sections if "API contract" in item.heading_path)
    assert api.start_line <= api.end_line
    assert "range" in api.normative_terms
    assert "docs/module.md" in api.link_targets
    assert any("parse_byte" in symbol for symbol in api.symbols)


def test_unknown_can_be_reclassified_but_mandatory_cannot(tmp_path: Path) -> None:
    unknown = tmp_path / "notes.md"
    unknown.write_text("A personal note.\n", encoding="utf-8")
    runtime = tmp_path / "AGENTS.md"
    runtime.write_text("runtime", encoding="utf-8")
    result = discover_markdown(tmp_path)
    note = next(item for item in result.files if item.relative_path == "notes.md")
    agents = next(item for item in result.files if item.relative_path == "AGENTS.md")
    assert classify_document(note).classification == "unknown"
    assert classify_document(note, overrides={"explanatory": ["notes.md"]}).reason == "explanatory_override"
    assert classify_document(agents, overrides={"explanatory": ["AGENTS.md"]}).classification == "runtime_instruction"


def test_public_exclusion_filters_explanatory_docs_and_changes_manifest_identity(
    tmp_path: Path,
) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    kept = docs / "kept.md"
    kept.write_text("# Kept\n\nThe API must return zero.\n", encoding="utf-8")
    excluded = docs / "legacy.md"
    excluded.write_text("# Legacy\n\nThe API must return one.\n", encoding="utf-8")

    baseline = build_source_manifest(
        tmp_path,
        project_id="fixture",
        created_at="2026-01-01T00:00:00Z",
    )
    filtered = build_source_manifest(
        tmp_path,
        project_id="fixture",
        overrides={"exclude": ["docs/legacy.md"]},
        created_at="2026-01-01T00:00:00Z",
    )

    assert {item.relative_path for item in baseline.accepted} == {
        "docs/kept.md",
        "docs/legacy.md",
    }
    assert [item.relative_path for item in filtered.accepted] == ["docs/kept.md"]
    descriptor = next(
        item for item in filtered.excluded if item.relative_path == "docs/legacy.md"
    )
    assert descriptor.classification == "unknown"
    assert descriptor.reason == "user_excluded_path"
    assert filtered.override_digest is not None
    assert filtered.source_manifest_digest != baseline.source_manifest_digest


def test_public_exclusion_content_does_not_change_manifest_digest(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        "# Contract\n\nThe API must return zero.\n",
        encoding="utf-8",
    )
    conversations = tmp_path / ".zscope_conversations" / "run_1"
    conversations.mkdir(parents=True)
    transcript = conversations / "validator.md"
    transcript.write_text("# First transcript\n", encoding="utf-8")
    trace = conversations / "validator.jsonl"
    trace.write_text('{"event":"first"}\n', encoding="utf-8")
    invalid = conversations / "invalid.md"
    invalid.write_bytes(b"\xff")
    overrides = {"exclude": [".zscope_conversations/**"]}

    first = build_source_manifest(
        tmp_path,
        project_id="fixture",
        overrides=overrides,
        created_at="2026-01-01T00:00:00Z",
    )

    transcript.write_text("# Changed transcript\n", encoding="utf-8")
    trace.write_text('{"event":"changed"}\n', encoding="utf-8")
    invalid.write_bytes(b"\xfe")
    (conversations / "new-validator.md").write_text(
        "# New transcript\n",
        encoding="utf-8",
    )
    (conversations / "new-validator.jsonl").write_text(
        '{"event":"new"}\n',
        encoding="utf-8",
    )
    second = build_source_manifest(
        tmp_path,
        project_id="fixture",
        overrides=overrides,
        created_at="2026-02-01T00:00:00Z",
    )

    assert first.project_root_digest == second.project_root_digest
    assert first.source_manifest_digest == second.source_manifest_digest
    assert first.unsupported_extensions == second.unsupported_extensions == {}
    assert any(item.reason == "user_excluded_path" for item in second.excluded)

    (tmp_path / "README.md").write_text(
        "# Contract\n\nThe API must return one.\n",
        encoding="utf-8",
    )
    changed_source = build_source_manifest(
        tmp_path,
        project_id="fixture",
        overrides=overrides,
        created_at="2026-03-01T00:00:00Z",
    )
    assert changed_source.source_manifest_digest != second.source_manifest_digest


def test_public_exclusion_cannot_mask_mandatory_or_sensitive_classification(
    tmp_path: Path,
) -> None:
    (tmp_path / "AGENTS.md").write_text("runtime instructions\n", encoding="utf-8")
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "secret.md").write_text(
        "Authorization: Bearer fixture-token\n",
        encoding="utf-8",
    )

    manifest = build_source_manifest(
        tmp_path,
        project_id="fixture",
        overrides={"exclude": ["**/*.md", "AGENTS.md"]},
    )
    excluded = {item.relative_path: item.classification for item in manifest.excluded}

    assert excluded["AGENTS.md"] == "runtime_instruction"
    assert excluded["docs/secret.md"] == "sensitive_rejected"


@pytest.mark.parametrize("project_id", ["x" * 161, "project\nforged"])
def test_manifest_rejects_unbounded_or_control_project_id(
    tmp_path: Path,
    project_id: str,
) -> None:
    (tmp_path / "README.md").write_text(
        "# Contract\n\nThe API must return zero.\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="project_id"):
        build_source_manifest(tmp_path, project_id=project_id)


def test_manifest_atomic_replace_failure_preserves_previous_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "README.md").write_text(
        "# Contract\n\nThe API must return zero.\n",
        encoding="utf-8",
    )
    manifest = build_source_manifest(project, project_id="fixture")
    target = tmp_path / "state" / "source-manifest.json"
    target.parent.mkdir()
    target.write_text("previous-manifest\n", encoding="utf-8")

    def fail_replace(_source, _target):
        raise OSError("injected replace failure")

    monkeypatch.setattr("zscope.wiki.source_manifest.os.replace", fail_replace)
    with pytest.raises(OSError, match="replace failure"):
        write_source_manifest(manifest, target)

    assert target.read_text(encoding="utf-8") == "previous-manifest\n"
    assert list(target.parent.glob(".source-manifest.json.*.tmp")) == []


def test_invalid_utf8_external_symlink_and_size_are_rejected(tmp_path: Path) -> None:
    (tmp_path / "bad.md").write_bytes(b"\xff\xfe")
    outside = tmp_path.parent / "wiki-outside.md"
    outside.write_text("outside", encoding="utf-8")
    link = tmp_path / "outside.md"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    (tmp_path / "large.md").write_text("x" * 32, encoding="utf-8")
    result = discover_markdown(tmp_path, max_file_bytes=16)
    issues = {item.relative_path: item.reason for item in result.issues}
    assert issues["bad.md"] == "invalid_utf8"
    assert issues["outside.md"] == "symlink_outside_project_root"
    assert issues["large.md"] == "max_file_bytes_exceeded"
