from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from zscope.wiki.control import wiki_query, wiki_status
from zscope.wiki.source_manifest import build_source_manifest
from zscope.wiki.store.revision_store import WikiStore


FIXTURE = Path(__file__).parent / "fixtures" / "wiki_project"


def test_wiki_status_is_readonly_when_state_is_absent(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()

    status = wiki_status(project)

    assert status["available"] is False
    assert status["active"] is None
    assert status["schema_version"] == "zscope.wiki-status.v1"
    assert "project_root" not in status
    assert "state_root" not in status
    assert not (project / ".zscope_knowledge").exists()


def test_wiki_query_returns_valid_direct_document_context() -> None:
    context = wiki_query(
        FIXTURE,
        subjects=["parse_byte"],
        fact_kind="input_range",
        candidate_file="src/parser.c",
        max_tokens=512,
        project_id="fixture",
    )

    assert context["schema_version"] == "zscope.validator-project-knowledge.v1"
    assert context["resolution_mode"] == "source_fallback"
    assert context["source_excerpts"][0]["relative_path"] == "README.md"
    assert context["selection"]["max_tokens"] == 512


def test_wiki_query_prunes_custom_state_tree_from_manifest(tmp_path: Path) -> None:
    project = tmp_path / "project"
    shutil.copytree(FIXTURE, project)
    state_dir = "var/wiki"
    manifest = build_source_manifest(
        project,
        project_id="fixture",
        prune_paths=(state_dir,),
    )
    with WikiStore(project / state_dir) as store:
        store.build_skeleton(project, manifest)

    context = wiki_query(
        project,
        subjects=["parse_byte"],
        fact_kind="input_range",
        candidate_file="src/parser.c",
        max_tokens=512,
        project_id="fixture",
        state_dir=state_dir,
    )

    assert context["resolution_mode"] == "source_fallback"
    assert context["selection"]["fallback_reason"] == "compiler_unavailable"
    assert context["source_excerpts"][0]["relative_path"] == "README.md"


@pytest.mark.parametrize("state_dir", ["../wiki", "/tmp/wiki"])
def test_wiki_control_rejects_state_outside_project(state_dir: str) -> None:
    with pytest.raises(ValueError, match="state_dir"):
        wiki_status(FIXTURE, state_dir=state_dir)


def test_wiki_status_returns_bounded_projection_without_absolute_paths(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    shutil.copytree(FIXTURE, project)
    state = project / ".zscope_knowledge" / "wiki"
    manifest = build_source_manifest(project, project_id="fixture")
    with WikiStore(state) as store:
        built = store.build_skeleton(project, manifest)

    status = wiki_status(project)

    assert status["available"] is True
    assert status["active"]["revision_id"] == built.revision_id
    assert status["revision"]["compiler"]["kind"] == "deterministic"
    serialized = json.dumps(status, ensure_ascii=False)
    assert str(project) not in serialized
    assert len(serialized) < 5000


def test_wiki_status_rejects_traversal_pointer_without_reading_outside_revision(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    state = project / ".zscope_knowledge" / "wiki"
    state.mkdir(parents=True, exist_ok=True)
    outside = project / "secret" / "revision.json"
    outside.parent.mkdir()
    outside.write_text('{"secret":"must-not-leak"}\n', encoding="utf-8")
    (state / "active.json").write_text(
        json.dumps(
            {
                "schema_version": "zscope.wiki-active.v1",
                "revision_id": "../../secret",
                "source_manifest_digest": "sha256:" + "1" * 64,
                "updated_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    status = wiki_status(project)

    assert status["available"] is False
    assert status["error"]["code"] == "invalid_active_pointer"
    assert "must-not-leak" not in json.dumps(status)


def test_wiki_query_falls_back_to_source_when_active_pointer_is_invalid(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    shutil.copytree(FIXTURE, project)
    state = project / ".zscope_knowledge" / "wiki"
    state.mkdir(parents=True, exist_ok=True)
    (state / "active.json").write_text("{" + "x" * 100, encoding="utf-8")

    context = wiki_query(
        project,
        subjects=["parse_byte"],
        fact_kind="input_range",
        candidate_file="src/parser.c",
        max_tokens=512,
        project_id="fixture",
    )

    assert context["resolution_mode"] == "source_fallback"
    assert context["wiki_revision_id"] is None
    assert context["selection"]["fallback_reason"] == "invalid_revision"
    assert context["source_excerpts"][0]["relative_path"] == "README.md"


def test_wiki_query_rejects_unsafe_input_before_manifest_discovery(
    monkeypatch,
) -> None:
    called = False

    def fail_if_called(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("manifest discovery must not run")

    monkeypatch.setattr("zscope.wiki.control.build_source_manifest", fail_if_called)

    with pytest.raises(ValueError, match="candidate_file"):
        wiki_query(
            FIXTURE,
            subjects=["parse_byte"],
            candidate_file="../secret.md",
        )
    assert called is False


def test_wiki_control_rejects_symlinked_state_directory(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    state_parent = project / ".zscope_knowledge"
    state_parent.mkdir()
    outside = tmp_path / "outside-state"
    outside.mkdir()
    try:
        (state_parent / "wiki").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(ValueError, match="symlink"):
        wiki_status(project)
    assert list(outside.iterdir()) == []


def test_wiki_query_discards_tampered_page_projection_and_uses_source(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    shutil.copytree(FIXTURE, project)
    state = project / ".zscope_knowledge" / "wiki"
    manifest = build_source_manifest(project, project_id="fixture")
    with WikiStore(state) as store:
        result = store.build_skeleton(project, manifest)
        page = next((store.revisions_root / result.revision_id / "pages").rglob("*.md"))
        page.write_text(page.read_text(encoding="utf-8") + "\n篡改。\n", encoding="utf-8")

    context = wiki_query(
        project,
        subjects=["parse_byte"],
        fact_kind="input_range",
        candidate_file="src/parser.c",
        max_tokens=512,
        project_id="fixture",
    )

    assert context["resolution_mode"] == "source_fallback"
    assert context["selection"]["fallback_reason"] == "invalid_revision"
    assert context["source_excerpts"][0]["relative_path"] == "README.md"


def test_wiki_query_discards_projection_that_exceeds_runtime_lint_limits(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "project"
    shutil.copytree(FIXTURE, project)
    state = project / ".zscope_knowledge" / "wiki"
    manifest = build_source_manifest(project, project_id="fixture")
    with WikiStore(state) as store:
        store.build_skeleton(project, manifest)
    monkeypatch.setattr("zscope.wiki.lint.LINT_MAX_OBJECT_ROWS", 1)

    context = wiki_query(
        project,
        subjects=["parse_byte"],
        fact_kind="input_range",
        candidate_file="src/parser.c",
        max_tokens=512,
        project_id="fixture",
    )

    assert context["resolution_mode"] == "source_fallback"
    assert context["selection"]["fallback_reason"] == "invalid_revision"
