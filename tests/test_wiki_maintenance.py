from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from zscope.core.analysis.analyzer import Analyzer
from zscope.wiki.maintenance import (
    WikiWriterLock,
    compare_manifests,
    dirty_page_closure,
    merge_constraint_proposals,
    propagate_stale,
)
from zscope.wiki.source_manifest import build_source_manifest
from zscope.wiki.compiler.compiler import WikiCompiler
from zscope.wiki.compiler.workset import build_ingest_workset
from zscope.wiki.identity import slugify, stable_id
from zscope.wiki.source_index import SourceIndex
from zscope.wiki.store.revision_store import WikiStore

FIXTURE = Path(__file__).parent / "fixtures" / "wiki_project"


def _analyzer(
    project_root: Path,
    *,
    mode: str,
    auto_maintain: bool,
    compiler_enabled: bool,
    document_exclude=(),
    state_dir=".zscope_knowledge/wiki",
) -> Analyzer:
    wiki = SimpleNamespace(
        mode=mode,
        auto_maintain=auto_maintain,
        state_dir=state_dir,
        compiler_enabled=compiler_enabled,
        document_exclude=list(document_exclude),
        explanatory_overrides=[],
        generated_overrides=[],
        max_file_bytes=10 * 1024 * 1024,
        max_files=10_000,
        max_total_bytes=100 * 1024 * 1024,
        max_wall_seconds=600,
        max_constraints=None,
        compiler_max_tokens=4000,
    )
    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(
            project_root=project_root,
            project_id="fixture",
            wiki=wiki,
        )
    )
    analyzer.llm_clients = {}
    return analyzer


def _close_service(service) -> None:
    if service is None:
        return
    service.source_index.close()
    if service.wiki_store is not None:
        service.wiki_store.close()


def test_manifest_delta_and_dirty_closure(tmp_path: Path) -> None:
    before = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    changed = tmp_path / "project"
    import shutil

    shutil.copytree(FIXTURE, changed)
    (changed / "README.md").write_text(
        (changed / "README.md").read_text() + "\nNew note.\n", encoding="utf-8"
    )
    after = build_source_manifest(changed, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    delta = compare_manifests(before, after)
    assert len(delta.changed_source_ids) == 1
    project_page_id = stable_id("page", "fixture", "project")
    closure = dirty_page_closure(
        delta,
        source_to_pages={delta.changed_source_ids[0]: ["page_readme"]},
        project_page_id=project_page_id,
        page_dependencies={
            project_page_id: ["page_readme"],
            "page_dependent": [project_page_id],
        },
    )
    assert closure == tuple(sorted(("page_dependent", project_page_id, "page_readme")))


def test_default_workset_has_no_page_targets(tmp_path: Path) -> None:
    manifest = build_source_manifest(
        FIXTURE,
        project_id="fixture",
        created_at="2026-01-01T00:00:00Z",
    )
    with SourceIndex(tmp_path / "source.db") as index:
        index.rebuild(FIXTURE, manifest=manifest)
        workset = build_ingest_workset(manifest, source_index=index)

    assert "target_page_ids" not in workset
    assert "allowed_existing_pages" not in workset
    assert workset["limits"] == {"max_constraints": None, "max_wall_seconds": None}


def test_slugify_matches_the_wiki_page_slug_contract() -> None:
    assert slugify("page_project") == "page-project"
    assert slugify("Modules/API_Limits") == "modules/api-limits"


def test_equal_values_merge_refs_and_conflicting_values_remain_conflicted() -> None:
    base = {
        "constraint_id": "constraint_a",
        "subject": {"canonical_id": "api:parse"},
        "kind": "input_range",
        "scope": {},
        "statement": "parse accepts 0..255",
        "source_refs": ["docref_a"],
        "status": "active",
    }
    equal = dict(base, constraint_id="constraint_b", source_refs=["docref_b"])
    merged = merge_constraint_proposals([base], [equal])
    assert len(merged) == 1 and merged[0]["source_refs"] == ["docref_a", "docref_b"]
    conflict = dict(base, constraint_id="constraint_c", statement="parse accepts 1..254")
    merged = merge_constraint_proposals([base], [conflict])
    assert len(merged) == 2 and all(item["status"] == "conflicted" for item in merged)


def test_removed_source_marks_supporting_constraint_stale() -> None:
    item = {
        "constraint_id": "constraint_a",
        "source_refs": ["docsrc_removed:section"],
        "status": "active",
    }
    assert propagate_stale([item], ["docsrc_removed"])[0]["status"] == "stale"


def test_writer_lock_is_exclusive(tmp_path: Path) -> None:
    path = tmp_path / "wiki.lock"
    with WikiWriterLock(path):
        with pytest.raises(TimeoutError):
            with WikiWriterLock(path):
                pass
    assert not path.exists()


def test_writer_lock_recovers_only_a_dead_pid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "wiki.lock"
    path.write_text(
        json.dumps(
            {
                "schema_version": "zscope.wiki-writer-lock.v1",
                "pid": 999999,
                "token": "a" * 32,
                "created_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(WikiWriterLock, "_pid_alive", staticmethod(lambda pid: False))

    with WikiWriterLock(path):
        owner = json.loads(path.read_text(encoding="utf-8"))
        assert owner["pid"] == os.getpid()
        assert owner["token"] != "a" * 32
    assert not path.exists()


@pytest.mark.parametrize("content", ["not json", "{}"])
def test_writer_lock_rejects_malformed_owner(tmp_path: Path, content: str) -> None:
    path = tmp_path / "wiki.lock"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(RuntimeError, match="lock"):
        with WikiWriterLock(path):
            pass
    assert path.exists()


def test_writer_lock_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.lock"
    target.write_text("do not touch", encoding="utf-8")
    path = tmp_path / "wiki.lock"
    path.symlink_to(target)

    with pytest.raises(RuntimeError, match="symlink"):
        with WikiWriterLock(path):
            pass
    assert target.read_text(encoding="utf-8") == "do not touch"


def test_writer_lock_exit_does_not_delete_a_new_owner(tmp_path: Path) -> None:
    path = tmp_path / "wiki.lock"
    replacement = {
        "schema_version": "zscope.wiki-writer-lock.v1",
        "pid": os.getpid(),
        "token": "b" * 32,
        "created_at": "2026-01-01T00:00:00Z",
    }
    with WikiWriterLock(path):
        path.write_text(json.dumps(replacement), encoding="utf-8")
    assert json.loads(path.read_text(encoding="utf-8"))["token"] == "b" * 32


def test_manifest_delta_refresh_keeps_revision_and_marks_changed_constraint_stale(
    tmp_path: Path,
) -> None:
    before_root = tmp_path / "before"
    import shutil

    shutil.copytree(FIXTURE, before_root)
    after_root = tmp_path / "after"
    shutil.copytree(before_root, after_root)
    before = build_source_manifest(
        before_root, project_id="fixture", created_at="2026-01-01T00:00:00Z"
    )
    (after_root / "README.md").write_text(
        (after_root / "README.md").read_text(encoding="utf-8") + "\nAdditional contract note.\n",
        encoding="utf-8",
    )
    after = build_source_manifest(
        after_root, project_id="fixture", created_at="2026-01-01T00:00:00Z"
    )
    delta = compare_manifests(before, after)
    assert len(delta.changed_source_ids) == 1
    state = tmp_path / "wiki"
    with (
        SourceIndex(tmp_path / "before.db") as old_index,
        SourceIndex(tmp_path / "after.db") as new_index,
        WikiStore(state) as store,
    ):
        old_index.rebuild(before_root, manifest=before)
        first = store.build_skeleton(before_root, before)
        source_id = delta.changed_source_ids[0]
        ref_id = store.connection.execute(
            "SELECT ref_id FROM document_refs WHERE revision_id=? ORDER BY ref_id LIMIT 1",
            (first.revision_id,),
        ).fetchone()["ref_id"]
        seed_workset = build_ingest_workset(
            before,
            source_index=old_index,
            base_revision_id=first.revision_id,
            changed_source_ids=[source_id],
        )
        # Seed one active constraint so a changed supporting document has a
        # concrete freshness transition to assert.
        seed_constraint = {
            "schema_version": "zscope.wiki-changeset.v1",
            "workset_id": seed_workset["workset_id"],
            "base_revision_id": first.revision_id,
            "outcome": "changed",
            "source_results": [
                {
                    "source_ref": source_id,
                    "extraction_status": "constraints_found",
                    "source_refs_used": [ref_id],
                    "reason": "seed",
                }
            ],
            "constraint_proposals": [
                {
                    "schema_version": "zscope.project-constraint-proposal.v1",
                    "subject_id": "api:parse_byte",
                    "subject_kind": "api",
                    "kind": "input_range",
                    "statement": "0..255",
                    "normativity": "required",
                    "source_refs": [ref_id],
                }
            ],
            "summary": "seed",
        }
        seeded = store.apply_changeset(before_root, before, seed_workset, seed_constraint)
        # Simulate a pruned revision projection while retaining the SQLite
        # rows.  The maintenance path must still recover the old source
        # digest so a changed document invalidates its constraints.
        (state / "revisions" / seeded.revision_id / "source-manifest.json").unlink()
        recovered = store.revision_manifest(seeded.revision_id)
        assert recovered is not None
        assert recovered["accepted"]
        new_index.rebuild(after_root, manifest=after)
        workset = build_ingest_workset(
            after,
            source_index=new_index,
            base_revision_id=seeded.revision_id,
            changed_source_ids=[source_id],
        )
        refreshed = store.compile_and_apply(after_root, after, workset, WikiCompiler())
        assert refreshed.revision_id != seeded.revision_id
        row = store.connection.execute(
            "SELECT constraint_json FROM constraints WHERE revision_id=?",
            (refreshed.revision_id,),
        ).fetchone()
        assert row is not None
        assert __import__("json").loads(row["constraint_json"])["status"] == "stale"
        assert (
            store.revision_manifest(refreshed.revision_id)["source_manifest_digest"]
            == after.source_manifest_digest
        )


def test_maintenance_revision_preserves_parent_llm_compiler_identity(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    shutil.copytree(FIXTURE, project)
    before = build_source_manifest(project, project_id="fixture")
    state = tmp_path / "wiki"
    with SourceIndex(tmp_path / "source.db") as index, WikiStore(state) as store:
        index.rebuild(project, manifest=before)
        skeleton = store.build_skeleton(project, before)
        source_id = before.accepted[0].source_id
        workset = build_ingest_workset(
            before,
            source_index=index,
            base_revision_id=skeleton.revision_id,
            added_source_ids=[source_id],
            initial=True,
        )
        ref_id = next(
            item["ref_id"]
            for item in workset["source_ref_catalog"]
            if item["source_id"] == source_id
        )
        llm_changeset = {
            "schema_version": "zscope.wiki-changeset.v1",
            "workset_id": workset["workset_id"],
            "base_revision_id": skeleton.revision_id,
            "outcome": "changed",
            "source_results": [{
                "source_ref": source_id,
                "extraction_status": "constraints_found",
                "source_refs_used": [ref_id],
                "reason": "seed",
            }],
            "constraint_proposals": [{
                "schema_version": "zscope.project-constraint-proposal.v1",
                "subject_id": "api:parse_byte",
                "subject_kind": "api",
                "kind": "input_range",
                "statement": "parse_byte accepts 0..255",
                "normativity": "required",
                "source_refs": [ref_id],
            }],
            "summary": "seed",
            "compiler": {
                "kind": "llm",
                "identity": "zscope.wiki.openai-compatible.v1",
                "prompt_version": "test",
                "model": "test-model",
            },
        }
        seeded = store.apply_changeset(project, before, workset, llm_changeset)
        (project / "README.md").write_text(
            (project / "README.md").read_text(encoding="utf-8") + "\nChanged.\n",
            encoding="utf-8",
        )
        after = build_source_manifest(project, project_id="fixture")
        index.rebuild(project, manifest=after)
        delta = compare_manifests(before, after)
        refresh_workset = build_ingest_workset(
            after,
            source_index=index,
            base_revision_id=seeded.revision_id,
            changed_source_ids=delta.changed_source_ids,
        )
        refreshed = store.compile_and_apply(
            project,
            after,
            refresh_workset,
            WikiCompiler(max_workers=1),
        )
        metadata = store.revision_metadata(refreshed.revision_id)
        assert metadata["compiler"]["kind"] == "llm"
        assert metadata["compiler"]["identity"] == "zscope.wiki.openai-compatible.v1"


def test_analyzer_build_only_publishes_changed_manifest_revision(tmp_path: Path) -> None:
    project = tmp_path / "project"
    shutil.copytree(FIXTURE, project)
    state = project / ".zscope_knowledge" / "wiki"
    before = build_source_manifest(project, project_id="fixture")
    with WikiStore(state) as store:
        first = store.build_skeleton(project, before)
    (project / "README.md").write_text(
        (project / "README.md").read_text(encoding="utf-8") + "\nChanged contract.\n",
        encoding="utf-8",
    )

    analyzer = _analyzer(
        project,
        mode="build_only",
        auto_maintain=False,
        compiler_enabled=False,
    )
    assert analyzer._build_project_knowledge_service() is None

    current = build_source_manifest(project, project_id="fixture")
    with WikiStore(state) as store:
        active = store.active_revision()
        assert active is not None
        assert active["revision_id"] != first.revision_id
        assert active["source_manifest_digest"] == current.source_manifest_digest


def test_analyzer_reuses_existing_wiki_when_only_nonaccepted_delta_changed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Refresh the pin without invoking LLM for an empty accepted delta."""

    project = tmp_path / "project"
    shutil.copytree(FIXTURE, project)
    state = project / ".zscope_knowledge" / "wiki"
    before = build_source_manifest(project, project_id="fixture")

    with SourceIndex(tmp_path / "source.db") as index, WikiStore(state) as store:
        index.rebuild(project, manifest=before)
        skeleton = store.build_skeleton(project, before)
        readme = next(
            item for item in before.accepted if item.relative_path == "README.md"
        )
        workset = build_ingest_workset(
            before,
            source_index=index,
            base_revision_id=skeleton.revision_id,
            added_source_ids=[readme.source_id],
            initial=True,
        )
        ref_id = next(
            item["ref_id"]
            for item in workset["source_ref_catalog"]
            if item["relative_path"] == "README.md"
        )
        seeded = store.apply_changeset(
            project,
            before,
            workset,
            {
                "schema_version": "zscope.wiki-changeset.v1",
                "workset_id": workset["workset_id"],
                "base_revision_id": skeleton.revision_id,
                "outcome": "changed",
                "source_results": [
                    {
                        "source_ref": readme.source_id,
                        "extraction_status": "constraints_found",
                        "source_refs_used": [ref_id],
                        "reason": "seed",
                    }
                ],
                "constraint_proposals": [
                    {
                        "schema_version": "zscope.project-constraint-proposal.v1",
                        "subject_id": "parse_byte",
                        "subject_kind": "api",
                        "kind": "input_range",
                        "statement": "parse_byte accepts 0..255",
                        "normativity": "required",
                        "source_refs": [ref_id],
                    }
                ],
                "summary": "seed",
            },
        )

    # This generated Markdown is not an accepted source.  Its removal changes
    # the broad manifest digest but leaves the accepted Markdown delta empty.
    (project / "artifacts" / "scan-report.md").unlink()
    current = build_source_manifest(project, project_id="fixture")
    assert current.source_manifest_digest != before.source_manifest_digest
    assert not compare_manifests(before, current).added_source_ids
    assert not compare_manifests(before, current).changed_source_ids
    assert not compare_manifests(before, current).removed_source_ids

    calls = []

    class FailingProvider:
        def __init__(self, *_args, **_kwargs):
            calls.append("constructed")
            raise AssertionError(
                "empty accepted delta must not construct an LLM provider"
            )

    monkeypatch.setattr(
        "zscope.core.analysis.analyzer.LLMWikiCompilerProvider",
        FailingProvider,
    )
    analyzer = _analyzer(
        project,
        mode="active",
        auto_maintain=False,
        compiler_enabled=True,
    )
    analyzer.llm_clients = {"wiki_compiler": object()}

    service = analyzer._build_project_knowledge_service()
    _close_service(service)

    with WikiStore(state) as store:
        active = store.active_revision()
        assert active is not None
        assert active["revision_id"] != seeded.revision_id
        assert active["source_manifest_digest"] == current.source_manifest_digest
        refreshed = store.connection.execute(
            "SELECT constraint_json FROM constraints WHERE revision_id=?",
            (active["revision_id"],),
        ).fetchone()
        assert refreshed is not None
        assert (
            json.loads(refreshed["constraint_json"])["statement"]
            == "parse_byte accepts 0..255"
        )
    assert calls == []


def test_analyzer_applies_document_exclusions_to_manifest_and_source_index(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    shutil.copytree(FIXTURE, project)
    analyzer = _analyzer(
        project,
        mode="shadow",
        auto_maintain=False,
        compiler_enabled=False,
        document_exclude=("docs/api-limits-legacy.md",),
    )

    service = analyzer._build_project_knowledge_service()
    try:
        assert service is not None
        paths = {
            row["relative_path"]
            for row in service.source_index.connection.execute(
                "SELECT relative_path FROM documents"
            )
        }
        event = service.source_index.connection.execute(
            "SELECT classification, reason FROM classification_events WHERE relative_path=?",
            ("docs/api-limits-legacy.md",),
        ).fetchone()
        assert "docs/api-limits-legacy.md" not in paths
        assert event is not None
        assert event["classification"] == "unknown"
        assert event["reason"] == "user_excluded_path"
    finally:
        _close_service(service)


def test_analyzer_prunes_custom_state_tree_from_later_manifest(tmp_path: Path) -> None:
    project = tmp_path / "project"
    shutil.copytree(FIXTURE, project)
    analyzer = _analyzer(
        project,
        mode="shadow",
        auto_maintain=False,
        compiler_enabled=False,
        state_dir="var/wiki",
    )

    first = analyzer._build_project_knowledge_service()
    try:
        assert first is not None
        assert first.wiki_store is not None
        first_active = first.wiki_store.active_revision()
        assert first_active is not None
    finally:
        _close_service(first)

    second = analyzer._build_project_knowledge_service()
    try:
        assert second is not None
        assert second.wiki_store is not None
        active = second.wiki_store.active_revision()
        expected = build_source_manifest(
            project,
            project_id="fixture",
            prune_paths=("var/wiki",),
        )
        paths = {
            row["relative_path"]
            for row in second.source_index.connection.execute("SELECT relative_path FROM documents")
        }
        assert active is not None
        assert active["revision_id"] == first_active["revision_id"]
        assert active["source_manifest_digest"] == expected.source_manifest_digest
        assert not any(path.startswith("var/wiki/") for path in paths)
    finally:
        _close_service(second)


def test_analyzer_keeps_direct_source_fallback_when_wiki_pointer_is_invalid(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    shutil.copytree(FIXTURE, project)
    state = project / ".zscope_knowledge" / "wiki"
    state.mkdir(parents=True, exist_ok=True)
    (state / "active.json").write_text("not-json\n", encoding="utf-8")
    analyzer = _analyzer(
        project,
        mode="active",
        auto_maintain=False,
        compiler_enabled=False,
    )

    service = analyzer._build_project_knowledge_service()
    try:
        assert service is not None
        assert service.wiki_store is None
        context = service.resolve_for_candidate(
            {
                "project_id": "fixture",
                "subject_id": "parse_byte",
                "fact_kind": "value_range",
                "relative_file": "src/parser.c",
            },
            fallback_reason="invalid_revision",
        )
        assert context["resolution_mode"] == "source_fallback"
        assert context["selection"]["fallback_reason"] == "invalid_revision"
        assert context["source_excerpts"][0]["relative_path"] == "README.md"
    finally:
        _close_service(service)


def test_analyzer_uses_in_memory_source_fallback_for_symlinked_state_dir(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "README.md").write_text(
        "# API contract\n\nparse_byte must accept values from 0 to 255.\n",
        encoding="utf-8",
    )
    state_parent = project / ".zscope_knowledge"
    state_parent.mkdir()
    outside = tmp_path / "outside-state"
    outside.mkdir()
    try:
        (state_parent / "wiki").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    analyzer = _analyzer(
        project,
        mode="active",
        auto_maintain=False,
        compiler_enabled=False,
    )

    service = analyzer._build_project_knowledge_service()
    try:
        assert service is not None
        assert service.wiki_store is None
        assert service.source_index.path == ":memory:"
        context = service.resolve_for_candidate(
            {
                "project_id": "fixture",
                "subject_id": "parse_byte",
                "fact_kind": "value_range",
                "relative_file": "src/parser.c",
            },
            fallback_reason="invalid_revision",
        )
        assert context["resolution_mode"] == "source_fallback"
        assert context["source_excerpts"][0]["relative_path"] == "README.md"
        assert list(outside.iterdir()) == []
    finally:
        _close_service(service)


def test_analyzer_auto_maintain_enriches_once_without_revision_churn(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "project"
    shutil.copytree(FIXTURE, project)
    state = project / ".zscope_knowledge" / "wiki"
    manifest = build_source_manifest(project, project_id="fixture")
    with WikiStore(state) as store:
        skeleton = store.build_skeleton(project, manifest)

    calls = []

    class FakeProvider:
        def __init__(self, _client, *, max_tokens):
            self.max_tokens = max_tokens

        def __call__(self, workset):
            calls.append(dict(workset))
            source_ids = (
                list(workset["added_source_ids"])
                + list(workset["changed_source_ids"])
                + list(workset["removed_source_ids"])
            )
            return {
                "schema_version": "zscope.wiki-changeset.v1",
                "workset_id": workset["workset_id"],
                "base_revision_id": workset["base_revision_id"],
                "outcome": "background_only",
                "source_results": [
                        {
                            "source_ref": source_id,
                            "extraction_status": "no_constraints_found",
                            "source_refs_used": [],
                            "reason": "no_constraints_found",
                        }
                    for source_id in source_ids
                ],
                    "constraint_proposals": [],
                    "summary": "background only",
            }

    monkeypatch.setattr(
        "zscope.core.analysis.analyzer.LLMWikiCompilerProvider",
        FakeProvider,
    )
    analyzer = _analyzer(
        project,
        mode="shadow",
        auto_maintain=True,
        compiler_enabled=True,
    )
    analyzer.llm_clients = {"wiki_compiler": object()}

    first_service = analyzer._build_project_knowledge_service()
    _close_service(first_service)
    with WikiStore(state) as store:
        enriched = store.active_revision()
        assert enriched is not None
        assert enriched["revision_id"] != skeleton.revision_id
        revision = json.loads(
            (store.revisions_root / enriched["revision_id"] / "revision.json").read_text(
                encoding="utf-8"
            )
        )
        assert revision["compiler"]["kind"] == "llm"

    second_service = analyzer._build_project_knowledge_service()
    _close_service(second_service)
    with WikiStore(state) as store:
        assert store.active_revision()["revision_id"] == enriched["revision_id"]
    assert len(calls) == len(manifest.accepted)
    assert all(
        len(call["added_source_ids"] + call["changed_source_ids"]) == 1
        for call in calls
    )
    assert all(call["removed_source_ids"] == [] for call in calls)
    assert all(call["initial"] is True for call in calls)
    assert all("target_page_ids" not in call for call in calls)


@pytest.mark.parametrize("delta_kind", ("added", "changed", "removed"))
def test_analyzer_bootstraps_all_sources_when_parent_has_no_materialized_wiki(
    tmp_path: Path,
    monkeypatch,
    delta_kind: str,
) -> None:
    project = tmp_path / "project"
    shutil.copytree(FIXTURE, project)
    state = project / ".zscope_knowledge" / "wiki"
    before = build_source_manifest(project, project_id="fixture")
    before_ids = {item.source_id for item in before.accepted}
    with WikiStore(state) as store:
        skeleton = store.build_skeleton(project, before)
        assert skeleton.page_count == 0

    if delta_kind == "added":
        shutil.copyfile(project / "docs" / "api-limits-legacy.md", project / "docs" / "new-api.md")
    elif delta_kind == "changed":
        readme = project / "README.md"
        readme.write_text(readme.read_text(encoding="utf-8") + "\nNew contract note.\n", encoding="utf-8")
    else:
        (project / "docs" / "api-limits-legacy.md").unlink()
    current = build_source_manifest(project, project_id="fixture")
    current_ids = {item.source_id for item in current.accepted}
    removed_ids = before_ids - current_ids

    calls = []

    class FakeProvider:
        def __init__(self, _client, *, max_tokens):
            self.max_tokens = max_tokens

        def __call__(self, workset):
            calls.append(dict(workset))
            source_ids = (
                list(workset["added_source_ids"])
                + list(workset["changed_source_ids"])
                + list(workset["removed_source_ids"])
            )
            return {
                "schema_version": "zscope.wiki-changeset.v1",
                "workset_id": workset["workset_id"],
                "base_revision_id": workset["base_revision_id"],
                "outcome": "background_only",
                "source_results": [
                        {
                            "source_ref": source_id,
                            "extraction_status": "no_constraints_found",
                            "source_refs_used": [],
                            "reason": "bootstrap test",
                        }
                    for source_id in source_ids
                ],
                "constraint_proposals": [],
                "summary": "bootstrap test",
            }

    monkeypatch.setattr(
        "zscope.core.analysis.analyzer.LLMWikiCompilerProvider",
        FakeProvider,
    )
    analyzer = _analyzer(
        project,
        mode="shadow",
        auto_maintain=False,
        compiler_enabled=True,
    )
    analyzer.llm_clients = {"wiki_compiler": object()}

    service = analyzer._build_project_knowledge_service()
    _close_service(service)

    assert len(calls) == len(current_ids)
    assert {
        source_id
        for workset in calls
        for source_id in workset["added_source_ids"]
    } == current_ids
    assert all(workset["changed_source_ids"] == [] for workset in calls)
    assert all(workset["removed_source_ids"] == [] for workset in calls)
    assert all(workset["initial"] is True for workset in calls)
    assert all("target_page_ids" not in workset for workset in calls)
    assert removed_ids.isdisjoint(
        {
            source_id
            for workset in calls
            for source_id in workset["added_source_ids"] + workset["changed_source_ids"]
        }
    )
