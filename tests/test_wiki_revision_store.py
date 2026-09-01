from __future__ import annotations

import json
from pathlib import Path

import pytest

from zscope.wiki.source_manifest import build_source_manifest
from zscope.wiki.compiler.compiler import WikiCompiler
from zscope.wiki.compiler.workset import build_ingest_workset
from zscope.wiki.events import replay_audit_events
from zscope.wiki.lint import LintResult, lint_revision
from zscope.wiki.source_index import SourceIndex
from zscope.wiki.store.revision_store import HEADINGS, WikiStore
from zscope.wiki.service import ProjectKnowledgeService, validate_project_knowledge

FIXTURE = Path(__file__).parent / "fixtures" / "wiki_project"


def _linked_page(page_id: str, target_id: str, ref_id: str) -> str:
    values = {
        "摘要": f"中文页面 {page_id}。[[{target_id}|相关页面]]",
        "适用范围和模块边界": "适用于当前项目。",
        "已声明约束": "本次只维护背景页面。",
        "限定条件、例外和常见误报模式": "背景说明不是漏洞证明。",
        "冲突与未决问题": "暂无。",
        "来源索引": f"- [{ref_id}] README.md",
    }
    return "\n".join(f"## {heading}\n\n{values[heading]}\n" for heading in HEADINGS)


def test_deterministic_skeleton_publishes_refs_without_generated_pages(tmp_path: Path) -> None:
    manifest = build_source_manifest(
        FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z"
    )
    state = tmp_path / ".zscope_knowledge" / "wiki"
    with WikiStore(state) as store:
        result = store.build_skeleton(FIXTURE, manifest)
        assert result.outcome == "background_only"
        assert result.constraints_created == 0
        assert result.page_count == 0
        assert result.document_ref_count > 0
        active = store.active_revision()
        assert active and active["revision_id"] == result.revision_id
        revision = json.loads(
            (state / "revisions" / result.revision_id / "revision.json").read_text()
        )
        assert revision["compiler"]["kind"] == "deterministic"
        assert revision["lint"] == {"status": "passed", "errors": 0, "warnings": 0}
        pages = list((state / "revisions" / result.revision_id / "pages").rglob("*.md"))
        assert pages == []
        assert (state / "revisions" / result.revision_id / "index.md").is_file()
        refs = json.loads((state / "revisions" / result.revision_id / "refs.json").read_text())
        assert refs and all(ref["ref_id"].startswith("docref_") for ref in refs)
        log_text = (state / "log.md").read_text(encoding="utf-8")
        assert "event=1 type=publish status=succeeded" in log_text
        assert f"revision={result.revision_id}" in log_text
        events = [
            json.loads(line)
            for line in (state / "audit-events.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        assert events[0]["schema_version"] == "zscope.wiki-event.v1"
        assert events[0]["event_type"] == "publish"
        assert events[0]["previous_event_digest"] is None


def test_removed_only_update_publishes_stale_projection_without_llm_content(
    tmp_path: Path,
) -> None:
    before_root = tmp_path / "before"
    after_root = tmp_path / "after"
    import shutil

    shutil.copytree(FIXTURE, before_root)
    shutil.copytree(before_root, after_root)
    before = build_source_manifest(
        before_root, project_id="fixture", created_at="2026-01-01T00:00:00Z"
    )
    removed_source_id = next(
        item.source_id
        for item in before.accepted
        if item.relative_path == "docs/api-limits-legacy.md"
    )
    (after_root / "docs/api-limits-legacy.md").unlink()
    after = build_source_manifest(
        after_root, project_id="fixture", created_at="2026-01-01T00:00:00Z"
    )
    assert removed_source_id not in {item.source_id for item in after.accepted}

    with (
        SourceIndex(tmp_path / "before.db") as old_index,
        SourceIndex(tmp_path / "after.db") as new_index,
        WikiStore(tmp_path / "wiki") as store,
    ):
        old_index.rebuild(before_root, manifest=before)
        first = store.build_skeleton(before_root, before)
        removed_ref_id = store.connection.execute(
            "SELECT ref_id FROM document_refs WHERE revision_id=? AND source_id=? LIMIT 1",
            (first.revision_id, removed_source_id),
        ).fetchone()["ref_id"]

        # Seed one active documented constraint so the removal path proves
        # deterministic stale propagation without using the LLM.
        seed_workset = build_ingest_workset(
            before,
            source_index=old_index,
            base_revision_id=first.revision_id,
            changed_source_ids=[removed_source_id],
        )
        seed_constraint = {
            "schema_version": "zscope.wiki-changeset.v1",
            "workset_id": seed_workset["workset_id"],
            "base_revision_id": first.revision_id,
            "outcome": "changed",
            "source_results": [
                {
                    "source_ref": removed_source_id,
                    "extraction_status": "constraints_found",
                    "source_refs_used": [removed_ref_id],
                    "reason": "seed",
                }
            ],
            "constraint_proposals": [
                {
                    "schema_version": "zscope.project-constraint-proposal.v1",
                    "subject_id": "api:parse_byte",
                    "subject_kind": "api",
                    "kind": "input_range",
                    "statement": "parse_byte accepts 0..255",
                    "normativity": "required",
                    "source_refs": [removed_ref_id],
                }
            ],
            "summary": "seed",
        }
        seeded = store.apply_changeset(before_root, before, seed_workset, seed_constraint)

        new_index.rebuild(after_root, manifest=after)
        workset = build_ingest_workset(
            after,
            source_index=new_index,
            base_revision_id=seeded.revision_id,
            removed_source_ids=[removed_source_id],
        )
        calls = []

        def provider(_workset):
            calls.append(True)
            raise AssertionError("removed-only update must not invoke the LLM")

        result = store.compile_and_apply(
            after_root,
            after,
            workset,
            WikiCompiler(provider),
        )

        assert calls == []
        assert result.revision_id != seeded.revision_id
        assert result.outcome == "background_only"
        assert store.active_revision()["revision_id"] == result.revision_id
        assert store.active_revision()["source_manifest_digest"] == after.source_manifest_digest
        assert result.constraints_created == 0
        ref = store.connection.execute(
            "SELECT ref_json FROM document_refs WHERE revision_id=? AND ref_id=?",
            (result.revision_id, removed_ref_id),
        ).fetchone()
        assert ref is not None
        assert json.loads(ref["ref_json"])["resolvable"] is False
        constraint = store.connection.execute(
            "SELECT constraint_id, constraint_json FROM constraints WHERE revision_id=?",
            (result.revision_id,),
        ).fetchone()
        assert constraint is not None
        assert constraint["constraint_id"].startswith("constraint_")
        assert json.loads(constraint["constraint_json"])["status"] == "stale"
        assert store.connection.execute(
            "SELECT COUNT(*) AS count FROM pages WHERE revision_id=?",
            (result.revision_id,),
        ).fetchone()["count"] == 0


def test_rollback_switches_active_pointer_without_rebuilding(tmp_path: Path) -> None:
    manifest = build_source_manifest(
        FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z"
    )
    state = tmp_path / "wiki"
    with WikiStore(state) as store:
        first = store.build_skeleton(FIXTURE, manifest, revision_id="wikirev_first")
        second = store.build_skeleton(FIXTURE, manifest, revision_id="wikirev_second")
        assert store.active_revision()["revision_id"] == second.revision_id
        restored = store.rollback(first.revision_id)
        assert restored["revision_id"] == first.revision_id
        assert (state / "revisions" / first.revision_id).is_dir()
        events = [
            json.loads(line)
            for line in (state / "audit-events.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        assert events[-1]["event_type"] == "rollback"
        assert events[-1]["previous_event_digest"] == events[-2]["event_digest"]
        replay = replay_audit_events(state / "audit-events.jsonl")
        assert replay.passed
        assert replay.active_revision_id == first.revision_id
        (state / "log.md").write_text("tampered\n", encoding="utf-8")
        rebuilt = store.rebuild_log_from_events()
        assert rebuilt["active_revision_id"] == first.revision_id
        assert "type=rollback status=rolled_back" in (state / "log.md").read_text(encoding="utf-8")


def test_validated_changeset_is_merged_into_new_revision(tmp_path: Path) -> None:
    manifest = build_source_manifest(
        FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z"
    )
    state = tmp_path / "wiki"
    with SourceIndex(tmp_path / "source.db") as index, WikiStore(state) as store:
        index.rebuild(FIXTURE, manifest=manifest)
        first = store.build_skeleton(FIXTURE, manifest)
        ref_id = store.connection.execute(
            "SELECT ref_id FROM document_refs WHERE revision_id=? ORDER BY ref_id LIMIT 1",
            (first.revision_id,),
        ).fetchone()["ref_id"]
        source_id = manifest.accepted[0].source_id
        workset = build_ingest_workset(
            manifest,
            source_index=index,
            base_revision_id=first.revision_id,
            changed_source_ids=[source_id],
        )
        changeset = {
            "schema_version": "zscope.wiki-changeset.v1",
            "workset_id": workset["workset_id"],
            "base_revision_id": first.revision_id,
            "outcome": "changed",
            "source_results": [
                {
                    "source_ref": source_id,
                    "extraction_status": "constraints_found",
                    "source_refs_used": [ref_id],
                    "reason": "provider",
                }
            ],
            "constraint_proposals": [
                    {
                        "schema_version": "zscope.project-constraint-proposal.v1",
                        "subject_id": "api:parse_byte",
                        "subject_kind": "api",
                    "kind": "input_range",
                    "statement": "parse_byte accepts 0..255",
                    "normativity": "required",
                    "source_refs": [ref_id],
                }
            ],
            "summary": "provider result",
        }
        result = store.apply_changeset(FIXTURE, manifest, workset, changeset)
        assert result.outcome == "changed"
        assert result.constraint_count == 1
        assert store.active_revision()["revision_id"] == result.revision_id
        rows = store.connection.execute(
            "SELECT constraint_id, constraint_json FROM constraints WHERE revision_id=?",
            (result.revision_id,),
        ).fetchall()
        assert len(rows) == 1
        materialized = json.loads(rows[0]["constraint_json"])
        assert rows[0]["constraint_id"].startswith("constraint_")
        assert materialized["status"] == "active"
        assert materialized["authority"] == "documented_contract"
        assert "normalized_value" not in materialized
        assert "page_refs" not in materialized
        service = ProjectKnowledgeService(
            source_index=index,
            wiki_store=store,
            source_manifest_digest=manifest.source_manifest_digest,
            mode="active",
        )
        context = service.resolve_for_candidate(
            {
                "project_id": "fixture",
                "subject_id": "parse_byte",
                "fact_kind": "value_range",
                "relative_file": "src/parser.c",
            }
        )
        assert context["resolution_mode"] == "wiki"
        assert context["constraints"][0]["constraint_id"] == rows[0]["constraint_id"]
        assert validate_project_knowledge(context)["context_digest"].startswith("sha256:")


def test_constraint_only_changeset_does_not_publish_pages(tmp_path: Path) -> None:
    manifest = build_source_manifest(
        FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z"
    )
    state = tmp_path / "wiki"
    with SourceIndex(tmp_path / "source.db") as index, WikiStore(state) as store:
        index.rebuild(FIXTURE, manifest=manifest)
        first = store.build_skeleton(FIXTURE, manifest)
        source_id = manifest.accepted[0].source_id
        workset = build_ingest_workset(
            manifest,
            source_index=index,
            base_revision_id=first.revision_id,
            changed_source_ids=[source_id],
        )
        ref_id = workset["allowed_source_refs"][0]
        changeset = {
            "schema_version": "zscope.wiki-changeset.v1",
            "workset_id": workset["workset_id"],
            "base_revision_id": first.revision_id,
            "outcome": "changed",
            "source_results": [
                {
                    "source_ref": source_id,
                    "extraction_status": "constraints_found",
                    "source_refs_used": [ref_id],
                    "reason": "one documented constraint",
                }
            ],
            "constraint_proposals": [
                    {
                        "schema_version": "zscope.project-constraint-proposal.v1",
                        "subject_id": "api:parse_byte",
                        "subject_kind": "api",
                    "kind": "input_range",
                    "statement": "parse_byte accepts 0..255",
                    "normativity": "required",
                    "source_refs": [ref_id],
                }
            ],
            "summary": "one documented constraint",
        }
        result = store.compile_and_apply(
            FIXTURE,
            manifest,
            workset,
            WikiCompiler(lambda _workset: changeset),
        )

        assert result.constraint_count == 1
        published = store.connection.execute(
            "SELECT COUNT(*) AS count FROM pages WHERE revision_id=?",
            (result.revision_id,),
        ).fetchone()
        assert published["count"] == 0
        assert 'schema_version: "zscope.wiki-index.v1"' in (
            store.revisions_root / result.revision_id / "index.md"
        ).read_text(encoding="utf-8")


def test_failed_changeset_keeps_previous_active_revision(tmp_path: Path) -> None:
    manifest = build_source_manifest(
        FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z"
    )
    with WikiStore(tmp_path / "wiki") as store:
        first = store.build_skeleton(FIXTURE, manifest)
        failed = {
            "schema_version": "zscope.wiki-changeset.v1",
            "workset_id": "workset_failed",
            "base_revision_id": first.revision_id,
            "outcome": "extraction_failed",
            "source_results": [
                {
                    "source_ref": "docsrc_none",
                    "extraction_status": "extraction_failed",
                    "source_refs_used": [],
                    "reason": "provider unavailable",
                }
            ],
            "constraint_proposals": [],
            "summary": "failed",
        }
        # The workset identity is checked before publishing; a failed provider
        # therefore cannot move the active pointer or create a revision.
        import pytest
        from zscope.wiki.store.revision_store import WikiChangeSetApplyError

        with pytest.raises(WikiChangeSetApplyError):
            store.apply_changeset(
                FIXTURE,
                manifest,
                {
                    "workset_id": "workset_other",
                    "base_revision_id": first.revision_id,
                    "target_page_ids": [],
                    "allowed_source_refs": [],
                },
                failed,
            )
        assert store.active_revision()["revision_id"] == first.revision_id


def test_new_page_slug_is_safe_when_page_id_contains_underscores(tmp_path: Path) -> None:
    manifest = build_source_manifest(
        FIXTURE,
        project_id="fixture",
        created_at="2026-01-01T00:00:00Z",
    )
    with SourceIndex(tmp_path / "source.db") as index, WikiStore(tmp_path / "wiki") as store:
        index.rebuild(FIXTURE, manifest=manifest)
        first = store.build_skeleton(FIXTURE, manifest)
        ref_id = store.connection.execute(
            "SELECT ref_id FROM document_refs WHERE revision_id=? ORDER BY ref_id LIMIT 1",
            (first.revision_id,),
        ).fetchone()["ref_id"]
        source_id = manifest.accepted[0].source_id
        workset = build_ingest_workset(
            manifest,
            source_index=index,
            base_revision_id=first.revision_id,
            changed_source_ids=[source_id],
            target_page_ids=["page_project"],
        )
        changeset = {
            "schema_version": "zscope.wiki-changeset.v1",
            "workset_id": workset["workset_id"],
            "base_revision_id": first.revision_id,
            "outcome": "background_only",
            "source_results": [
                {
                    "source_ref": source_id,
                    "extraction_status": "no_constraints_found",
                    "source_refs_used": [ref_id],
                    "reason": "background updated",
                }
            ],
            "constraint_proposals": [],
            "summary": "background only",
        }

        result = store.apply_changeset(FIXTURE, manifest, workset, changeset)
        assert store.connection.execute(
            "SELECT COUNT(*) AS count FROM pages WHERE revision_id=?",
            (result.revision_id,),
        ).fetchone()["count"] == 0
        assert lint_revision(store, result.revision_id).passed


def test_program_summary_does_not_change_revision_identity(tmp_path: Path) -> None:
    manifest = build_source_manifest(
        FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z"
    )
    with SourceIndex(tmp_path / "source.db") as index:
        index.rebuild(FIXTURE, manifest=manifest)
        with WikiStore(tmp_path / "wiki-a") as store_a, WikiStore(tmp_path / "wiki-b") as store_b:
            first_a = store_a.build_skeleton(FIXTURE, manifest)
            first_b = store_b.build_skeleton(FIXTURE, manifest)
            assert first_a.revision_id == first_b.revision_id
            source_id = manifest.accepted[0].source_id
            workset = build_ingest_workset(
                manifest,
                source_index=index,
                base_revision_id=first_a.revision_id,
                changed_source_ids=[source_id],
            )
            ref_id = workset["allowed_source_refs"][0]

            def changeset(summary: str) -> dict:
                return {
                    "schema_version": "zscope.wiki-changeset.v1",
                    "workset_id": workset["workset_id"],
                    "base_revision_id": first_a.revision_id,
                    "outcome": "changed",
                    "source_results": [
                        {
                            "source_ref": source_id,
                            "extraction_status": "constraints_found",
                            "source_refs_used": [ref_id],
                            "reason": "provider",
                        }
                    ],
                    "constraint_proposals": [
                        {
                            "schema_version": "zscope.project-constraint-proposal.v1",
                            "subject_id": "api:parse_byte",
                            "subject_kind": "api",
                            "kind": "input_range",
                            "statement": "parse_byte accepts 0..255",
                            "normativity": "required",
                            "source_refs": [ref_id],
                        }
                    ],
                    "summary": summary,
                }

            result_a = store_a.apply_changeset(
                FIXTURE, manifest, workset, changeset("first deterministic summary")
            )
            result_b = store_b.apply_changeset(
                FIXTURE, manifest, workset, changeset("different wording")
            )
            assert result_a.revision_id == result_b.revision_id


def test_candidate_lint_failure_keeps_previous_active_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = build_source_manifest(
        FIXTURE,
        project_id="fixture",
        created_at="2026-01-01T00:00:00Z",
    )
    with SourceIndex(tmp_path / "source.db") as index, WikiStore(tmp_path / "wiki") as store:
        index.rebuild(FIXTURE, manifest=manifest)
        first = store.build_skeleton(FIXTURE, manifest)
        source_id = manifest.accepted[0].source_id
        workset = build_ingest_workset(
            manifest,
            source_index=index,
            base_revision_id=first.revision_id,
            changed_source_ids=[source_id],
        )
        changeset = WikiCompiler().compile(workset)
        monkeypatch.setattr(
            "zscope.wiki.lint.lint_revision",
            lambda _store, _revision_id=None: LintResult(
                "failed",
                ("injected_candidate_failure",),
                (),
            ),
        )

        with pytest.raises(Exception, match="candidate revision lint failed"):
            store.apply_changeset(FIXTURE, manifest, workset, changeset)

        assert store.active_revision()["revision_id"] == first.revision_id
        failed_revisions = [
            path for path in store.revisions_root.iterdir() if path.name != first.revision_id
        ]
        assert len(failed_revisions) == 1
        failed = json.loads((failed_revisions[0] / "revision.json").read_text(encoding="utf-8"))
        assert failed["active"] is False
        assert failed["lint"]["status"] == "failed"
        replay = replay_audit_events(store.audit_events_path)
        assert replay.passed
        assert replay.active_revision_id == first.revision_id
        assert "status=failed" in store.log_path.read_text(encoding="utf-8")


def test_active_pointer_failpoint_keeps_old_pointer_and_marks_new_revision_failed(
    tmp_path: Path, monkeypatch
) -> None:
    manifest = build_source_manifest(
        FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z"
    )
    with WikiStore(tmp_path / "wiki") as store:
        first = store.build_skeleton(FIXTURE, manifest)
        original = store._publish_active

        def fail_once(*args, **kwargs):
            raise OSError("injected active pointer failure")

        monkeypatch.setattr(store, "_publish_active", fail_once)
        with pytest.raises(Exception, match="active pointer publish failed"):
            store.build_skeleton(FIXTURE, manifest, revision_id="wikirev_failpoint")
        assert store.active_revision()["revision_id"] == first.revision_id
        failed = json.loads(
            (tmp_path / "wiki" / "revisions" / "wikirev_failpoint" / "revision.json").read_text(
                encoding="utf-8"
            )
        )
        assert failed["active"] is False
        assert failed["lint"]["status"] == "failed"
        monkeypatch.setattr(store, "_publish_active", original)


def test_store_rejects_untrusted_revision_ids_before_path_access(tmp_path: Path) -> None:
    manifest = build_source_manifest(
        FIXTURE,
        project_id="fixture",
        created_at="2026-01-01T00:00:00Z",
    )
    state = tmp_path / "wiki"
    with WikiStore(state) as store:
        with pytest.raises(ValueError, match="revision id"):
            store.build_skeleton(
                FIXTURE,
                manifest,
                revision_id="../../outside",
            )
        with pytest.raises(ValueError, match="revision id"):
            store.rollback("../../outside")

    assert not (tmp_path / "outside.tmp").exists()


def test_store_enforces_max_constraints_as_revision_total(tmp_path: Path) -> None:
    manifest = build_source_manifest(
        FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z"
    )
    with SourceIndex(tmp_path / "source.db") as index, WikiStore(tmp_path / "wiki") as store:
        index.rebuild(FIXTURE, manifest=manifest)
        first = store.build_skeleton(FIXTURE, manifest)
        source_id = manifest.accepted[0].source_id
        workset = build_ingest_workset(
            manifest,
            source_index=index,
            base_revision_id=first.revision_id,
            changed_source_ids=[source_id],
            max_constraints=1,
        )
        ref_id = workset["allowed_source_refs"][0]
        proposals = [
            {
                "schema_version": "zscope.project-constraint-proposal.v1",
                "subject_id": "api:parse_byte",
                "subject_kind": "api",
                "kind": kind,
                "statement": statement,
                "normativity": "required",
                "source_refs": [ref_id],
            }
            for kind, statement in (
                ("input_range", "parse_byte accepts 0..255"),
                ("size_contract", "parse_byte output is bounded"),
            )
        ]
        changeset = {
            "schema_version": "zscope.wiki-changeset.v1",
            "workset_id": workset["workset_id"],
            "base_revision_id": first.revision_id,
            "outcome": "changed",
            "source_results": [
                {
                    "source_ref": source_id,
                    "extraction_status": "constraints_found",
                    "source_refs_used": [ref_id],
                    "reason": "test",
                }
            ],
            "constraint_proposals": proposals,
            "summary": "test",
        }
        with pytest.raises(Exception, match="max_constraints"):
            store.apply_changeset(FIXTURE, manifest, workset, changeset)
