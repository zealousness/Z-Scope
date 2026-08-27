from __future__ import annotations

import json
from pathlib import Path

import pytest

from zscope.wiki.events import AUDIT_EVENT_MAX_LINE_BYTES, replay_audit_events
from zscope.wiki.identity import digest_json
from zscope.wiki.lint import lint_revision
from zscope.wiki.source_manifest import build_source_manifest
from zscope.wiki.store.revision_store import WikiStore


FIXTURE = Path(__file__).parent / "fixtures" / "wiki_project"


def test_revision_lint_passes_and_detects_unresolved_ref(tmp_path: Path) -> None:
    manifest = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    with WikiStore(tmp_path / "wiki") as store:
        result = store.build_skeleton(FIXTURE, manifest)
        assert lint_revision(store, result.revision_id).passed
        row = store.connection.execute("SELECT page_id, markdown FROM pages WHERE revision_id=? LIMIT 1", (result.revision_id,)).fetchone()
        broken = str(row["markdown"]) + "\n- [docref_missing]\n"
        store.connection.execute("UPDATE pages SET markdown=? WHERE revision_id=? AND page_id=?", (broken, result.revision_id, row["page_id"]))
        store.connection.commit()
        linted = lint_revision(store, result.revision_id)
        assert not linted.passed
        assert "unresolved_ref:docref_missing" in linted.errors


def test_revision_lint_detects_audit_event_chain_tampering(tmp_path: Path) -> None:
    manifest = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    with WikiStore(tmp_path / "wiki") as store:
        result = store.build_skeleton(FIXTURE, manifest)
        event = json.loads(store.audit_events_path.read_text(encoding="utf-8"))
        event["event_digest"] = "sha256:" + "0" * 64
        store.audit_events_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
        linted = lint_revision(store, result.revision_id)
        assert "audit_event_digest:1" in linted.errors


def test_revision_lint_validates_index_and_log_projection(tmp_path: Path) -> None:
    manifest = build_source_manifest(FIXTURE, project_id="fixture", created_at="2026-01-01T00:00:00Z")
    with WikiStore(tmp_path / "wiki") as store:
        result = store.build_skeleton(FIXTURE, manifest)
        index_path = store.revisions_root / result.revision_id / "index.md"
        index_text = index_path.read_text(encoding="utf-8")
        assert "schema_version: \"zscope.wiki-index.v1\"" in index_text
        assert "## 维护信息" in index_text
        assert "(pages/" in index_text
        store.log_path.write_text("tampered\n", encoding="utf-8")
        linted = lint_revision(store, result.revision_id)
        assert "log_projection_mismatch" in linted.errors


def test_revision_lint_rejects_untrusted_revision_id_before_path_access(
    tmp_path: Path,
) -> None:
    with WikiStore(tmp_path / "wiki") as store:
        linted = lint_revision(store, "../../outside")

    assert linted.errors == ("invalid_revision_id",)


def test_revision_lint_rejects_index_symlink_and_unsafe_db_slug(
    tmp_path: Path,
) -> None:
    manifest = build_source_manifest(
        FIXTURE,
        project_id="fixture",
        created_at="2026-01-01T00:00:00Z",
    )
    with WikiStore(tmp_path / "wiki") as store:
        result = store.build_skeleton(FIXTURE, manifest)
        index_path = store.revisions_root / result.revision_id / "index.md"
        outside = tmp_path / "outside-index.md"
        outside.write_text("secret projection\n", encoding="utf-8")
        index_path.unlink()
        try:
            index_path.symlink_to(outside)
        except OSError:
            pytest.skip("symlink creation is unavailable")
        row = store.connection.execute(
            "SELECT page_id FROM pages WHERE revision_id=? ORDER BY page_id LIMIT 1",
            (result.revision_id,),
        ).fetchone()
        store.connection.execute(
            "UPDATE pages SET canonical_slug=? WHERE revision_id=? AND page_id=?",
            ("../../outside", result.revision_id, row["page_id"]),
        )
        store.connection.commit()

        linted = lint_revision(store, result.revision_id)

    assert "index_unsafe" in linted.errors
    assert f"page_slug_unsafe:{row['page_id']}" in linted.errors


def test_audit_replay_rejects_control_text_long_lines_and_chain_reset(
    tmp_path: Path,
) -> None:
    manifest = build_source_manifest(
        FIXTURE,
        project_id="fixture",
        created_at="2026-01-01T00:00:00Z",
    )
    with WikiStore(tmp_path / "wiki") as store:
        store.build_skeleton(FIXTURE, manifest)
        event = json.loads(store.audit_events_path.read_text(encoding="utf-8"))
        event["occurred_at"] = "2026-01-01T00:00:00Z\nforged"
        event["event_digest"] = digest_json(
            {key: value for key, value in event.items() if key != "event_digest"}
        )
        store.audit_events_path.write_text(
            json.dumps(event, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        replay = replay_audit_events(store.audit_events_path)
        assert "audit_event_invalid:1" in replay.errors
        with pytest.raises(ValueError, match="invalid Wiki audit event chain"):
            store._append_audit_event(
                event_type="lint",
                project_id="fixture",
                status="failed",
                payload={"reason": "tampered"},
            )

        store.audit_events_path.write_bytes(b"x" * (AUDIT_EVENT_MAX_LINE_BYTES + 1))
        replay = replay_audit_events(store.audit_events_path)
        assert "audit_event_line_limit:1" in replay.errors
