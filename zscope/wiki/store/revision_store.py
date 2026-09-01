"""Deterministic Wiki skeleton, revision publication and rollback.

The store owns identities, references, revision metadata, SQLite projections,
the active pointer and the append-only Markdown event log.  No LLM is called
here; the skeleton is intentionally background-only until a later compiler
stage proposes constraints through a validated WikiChangeSet.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

from ..identity import digest_json, slugify, stable_id
from ..events import render_log_markdown, replay_audit_events
from ..maintenance import merge_constraint_proposals, propagate_stale
from ..models import SourceManifest
from ..page_format import (
    HEADINGS,
    INDEX_HEADINGS,
    body_from_markdown,
    markdown_links_for_pages,
    page_markdown_errors,
)
from ..schema import SchemaValidationError, validate_instance
from ..source_index import SourceIndex

ACTIVE_POINTER_MAX_BYTES = 64 * 1024
REVISION_METADATA_MAX_BYTES = 1024 * 1024
SOURCE_MANIFEST_MAX_BYTES = 64 * 1024 * 1024
_REVISION_ID_PATTERN = re.compile(r"^wikirev_[a-z0-9_:-]+$")
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def validate_revision_id(revision_id: str) -> str:
    value = str(revision_id or "")
    if not _REVISION_ID_PATTERN.fullmatch(value):
        raise ValueError("invalid Wiki revision id")
    return value


def resolve_project_state_root(
    project_root: Union[Path, str],
    state_dir: Union[Path, str],
) -> Path:
    root = Path(project_root).expanduser().resolve()
    relative = Path(str(state_dir or "").strip())
    if not str(relative) or relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Wiki state_dir must be project-root relative")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Wiki state_dir must not traverse symlinks")
    resolved = current.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("Wiki state_dir resolves outside project root") from exc
    return resolved


def resolve_state_child(
    state_root: Union[Path, str],
    *relative_parts: Union[Path, str],
) -> Path:
    root = Path(state_root).resolve()
    current = root
    for raw_part in relative_parts:
        relative = Path(str(raw_part))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("unsafe Wiki state-relative path")
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError("Wiki state-relative path must not traverse symlinks")
    resolved = current.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("Wiki state-relative path resolves outside state root") from exc
    return current


def _read_bounded_json_object(path: Path, *, max_bytes: int, label: str) -> Dict[str, Any]:
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if size > max_bytes:
        raise ValueError(f"{label} exceeds size limit")
    try:
        value = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def read_active_pointer(state_root: Union[Path, str]) -> Optional[Dict[str, Any]]:
    path = Path(state_root) / "active.json"
    if not path.exists():
        return None
    value = _read_bounded_json_object(
        path,
        max_bytes=ACTIVE_POINTER_MAX_BYTES,
        label="Wiki active pointer",
    )
    if value.get("schema_version") != "zscope.wiki-active.v1":
        raise ValueError("unsupported Wiki active pointer schema")
    if set(value) != {
        "schema_version",
        "revision_id",
        "source_manifest_digest",
        "updated_at",
    }:
        raise ValueError("invalid Wiki active pointer fields")
    validate_revision_id(str(value.get("revision_id") or ""))
    if not _DIGEST_PATTERN.fullmatch(str(value.get("source_manifest_digest") or "")):
        raise ValueError("invalid Wiki active pointer manifest digest")
    updated_at = str(value.get("updated_at") or "")
    if not updated_at or len(updated_at) > 80 or _CONTROL_CHARS.search(updated_at):
        raise ValueError("invalid Wiki active pointer timestamp")
    return value


def read_revision_metadata(
    state_root: Union[Path, str],
    revision_id: str,
) -> Dict[str, Any]:
    rid = validate_revision_id(revision_id)
    path = resolve_state_child(state_root, "revisions", rid, "revision.json")
    value = _read_bounded_json_object(
        path,
        max_bytes=REVISION_METADATA_MAX_BYTES,
        label="Wiki revision metadata",
    )
    if value.get("schema_version") != "zscope.wiki-revision.v1":
        raise ValueError("unsupported Wiki revision schema")
    if value.get("revision_id") != rid:
        raise ValueError("Wiki revision metadata identity mismatch")
    if not _DIGEST_PATTERN.fullmatch(str(value.get("source_manifest_digest") or "")):
        raise ValueError("invalid Wiki revision manifest digest")
    from ..schema import SchemaValidationError, validate_instance

    try:
        validate_instance(value, "zscope.wiki-revision.v1")
    except SchemaValidationError as exc:
        raise ValueError("invalid Wiki revision metadata schema") from exc
    return value


DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS revisions (
  revision_id TEXT PRIMARY KEY,
  parent_revision_id TEXT,
  project_id TEXT NOT NULL,
  source_manifest_digest TEXT NOT NULL,
  revision_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pages (
  revision_id TEXT NOT NULL,
  page_id TEXT NOT NULL,
  canonical_slug TEXT NOT NULL,
  frontmatter_json TEXT NOT NULL,
  markdown TEXT NOT NULL,
  content_digest TEXT NOT NULL,
  PRIMARY KEY (revision_id, page_id)
);
CREATE TABLE IF NOT EXISTS document_refs (
  revision_id TEXT NOT NULL,
  ref_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  ref_json TEXT NOT NULL,
  PRIMARY KEY (revision_id, ref_id)
);
CREATE TABLE IF NOT EXISTS constraints (
  revision_id TEXT NOT NULL,
  constraint_id TEXT NOT NULL,
  constraint_json TEXT NOT NULL,
  PRIMARY KEY (revision_id, constraint_id)
);
CREATE TABLE IF NOT EXISTS edges (
  revision_id TEXT NOT NULL,
  edge_id TEXT NOT NULL,
  edge_json TEXT NOT NULL,
  PRIMARY KEY (revision_id, edge_id)
);
CREATE TABLE IF NOT EXISTS wiki_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  revision_id TEXT,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  occurred_at TEXT NOT NULL
);
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def _frontmatter_text(frontmatter: Mapping[str, Any]) -> str:
    lines = ["---"]
    for key in sorted(frontmatter):
        value = frontmatter[key]
        if isinstance(value, list):
            lines.append(f"{key}:")
            lines.extend(f"  - {_yaml_scalar(item)}" for item in value)
        else:
            lines.append(f"{key}: {_yaml_scalar(value)}")
    lines.extend(["---", ""])
    return "\n".join(lines)


def _body(summary: str, scope: str, refs: Sequence[str]) -> str:
    sections = {
        "摘要": summary,
        "适用范围和模块边界": scope,
        "已声明约束": "本骨架阶段未从背景文档创建结构化约束。",
        "限定条件、例外和常见误报模式": "页面内容来自说明性 Markdown；它不是当前代码路径的漏洞证明。",
        "冲突与未决问题": "暂无程序裁决；后续冲突必须显式保留。",
        "来源索引": "\n".join(f"- [{ref}]" for ref in refs) or "- 暂无来源引用",
    }
    return "\n".join(f"## {heading}\n\n{sections[heading]}\n" for heading in HEADINGS)


def _render_index(
    project_id: str,
    revision_id: str,
    source_manifest_digest: str,
    pages: Sequence[Dict[str, Any]],
) -> str:
    sections = {
        "项目概览": markdown_links_for_pages(pages, kinds=("project_overview",)),
        "模块": markdown_links_for_pages(pages, kinds=("module",)),
        "API 与协议": markdown_links_for_pages(
            pages,
            kinds=("api_contract", "configuration", "topic", "source"),
        ),
        "资源与锁": markdown_links_for_pages(
            pages,
            kinds=("resource_protocol", "lock_protocol"),
        ),
        "冲突与过期": markdown_links_for_pages(
            pages,
            statuses=("stale", "conflicted", "retired", "quarantined"),
        ),
        "维护信息": (
            f"- revision: `{revision_id}`\n" f"- source manifest: `{source_manifest_digest}`"
        ),
    }
    body = "\n".join(f"## {heading}\n\n{sections[heading]}\n" for heading in INDEX_HEADINGS)
    import hashlib

    frontmatter = {
        "schema_version": "zscope.wiki-index.v1",
        "project_id": project_id,
        "revision_id": revision_id,
        "source_manifest_digest": source_manifest_digest,
        "generated_language": "zh-CN",
        "content_digest": "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest(),
    }
    return _frontmatter_text(frontmatter) + body


@dataclass(frozen=True)
class WikiBuildResult:
    revision_id: str
    parent_revision_id: Optional[str]
    source_manifest_digest: str
    page_count: int
    document_ref_count: int
    constraint_count: int
    active_path: Path
    outcome: str = "background_only"
    constraints_created: int = 0


class WikiChangeSetApplyError(ValueError):
    """Raised when a validated ChangeSet cannot be safely published."""


class WikiStore:
    def __init__(self, state_root: Union[Path, str], *, read_only: bool = False) -> None:
        self.state_root = Path(state_root).resolve()
        self.read_only = bool(read_only)
        if self.read_only:
            if not self.state_root.is_dir():
                raise ValueError("Wiki state directory is unavailable")
        else:
            self.state_root.mkdir(parents=True, exist_ok=True)
        self.revisions_root = self.state_root / "revisions"
        self.staging_root = self.state_root / "staging"
        self.quarantine_root = self.state_root / "quarantine"
        for path in (self.revisions_root, self.staging_root, self.quarantine_root):
            if path.is_symlink():
                raise ValueError("Wiki state directories must not be symlinks")
            if self.read_only:
                if not path.is_dir():
                    raise ValueError("Wiki state projection is incomplete")
            else:
                path.mkdir(parents=True, exist_ok=True)
        self.active_path = self.state_root / "active.json"
        self.log_path = self.state_root / "log.md"
        self.audit_events_path = self.state_root / "audit-events.jsonl"
        self.db_path = resolve_state_child(self.state_root, "wiki.db")
        if self.read_only:
            if not self.db_path.is_file():
                raise ValueError("Wiki database is unavailable")
            self.connection = sqlite3.connect(
                self.db_path.as_uri() + "?mode=ro",
                uri=True,
            )
        else:
            self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        if not self.read_only:
            self.connection.executescript(DB_SCHEMA)
            self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "WikiStore":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def active_revision(self) -> Optional[Dict[str, Any]]:
        return read_active_pointer(self.state_root)

    def revision_metadata(self, revision_id: str) -> Dict[str, Any]:
        return read_revision_metadata(self.state_root, revision_id)

    def revision_manifest(self, revision_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Load the exact accepted/excluded manifest pinned by a revision."""

        rid = revision_id or str((self.active_revision() or {}).get("revision_id") or "")
        if not rid:
            return None
        rid = validate_revision_id(rid)
        try:
            path = resolve_state_child(
                self.state_root,
                "revisions",
                rid,
                "source-manifest.json",
            )
        except ValueError:
            return None
        if not path.is_file():
            return None
        try:
            value = _read_bounded_json_object(
                path,
                max_bytes=SOURCE_MANIFEST_MAX_BYTES,
                label="Wiki revision source manifest",
            )
        except ValueError:
            return None
        return value

    def _publish_active(
        self, revision_id: str, source_manifest_digest: str, updated_at: str
    ) -> None:
        """Atomically switch the pointer after projection commit."""

        revision_id = validate_revision_id(revision_id)
        if not _DIGEST_PATTERN.fullmatch(str(source_manifest_digest or "")):
            raise ValueError("invalid Wiki source manifest digest")
        payload = {
            "schema_version": "zscope.wiki-active.v1",
            "revision_id": revision_id,
            "source_manifest_digest": source_manifest_digest,
            "updated_at": updated_at,
        }
        fd, temp_name = tempfile.mkstemp(prefix="active.", suffix=".json", dir=str(self.state_root))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.active_path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def _mark_revision_failed(self, revision_id: str, reason: str) -> None:
        path = self.revisions_root / revision_id / "revision.json"
        if path.is_file():
            try:
                revision = json.loads(path.read_text(encoding="utf-8"))
                revision["active"] = False
                revision["lint"] = {"status": "failed", "errors": 1, "warnings": 0}
                path.write_text(
                    json.dumps(revision, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                with self.connection:
                    self.connection.execute(
                        "UPDATE revisions SET revision_json=? WHERE revision_id=?",
                        (json.dumps(revision, ensure_ascii=False, sort_keys=True), revision_id),
                    )
                    self.connection.execute(
                        "INSERT INTO wiki_events(revision_id,event_type,status,payload_json,occurred_at) VALUES (?, ?, ?, ?, ?)",
                        (
                            revision_id,
                            "publish",
                            "failed",
                            json.dumps({"reason": str(reason)[:1000]}, sort_keys=True),
                            _utc_now(),
                        ),
                    )
                self._append_audit_event(
                    event_type="publish",
                    project_id=str(revision.get("project_id") or "project"),
                    status="failed",
                    payload={"reason": str(reason)[:1000]},
                    revision_id=revision_id,
                )
            except Exception:
                pass

    def _append_audit_event(
        self,
        *,
        event_type: str,
        project_id: str,
        status: str,
        payload: Mapping[str, Any],
        revision_id: Optional[str] = None,
        workset_id: Optional[str] = None,
        fallback_reason: Optional[str] = None,
        actor: str = "program",
    ) -> Dict[str, Any]:
        """Append one schema-valid hash-chained audit event."""

        previous: Optional[Dict[str, Any]] = None
        if self.audit_events_path.is_symlink():
            raise ValueError("Wiki audit event path must not be a symlink")
        if self.audit_events_path.exists():
            replay = replay_audit_events(self.audit_events_path)
            if not replay.passed:
                raise ValueError(
                    "cannot append to invalid Wiki audit event chain: " + ", ".join(replay.errors)
                )
            previous = dict(replay.events[-1]) if replay.events else None
        normalized_project_id = str(project_id or "")
        if (
            not normalized_project_id
            or len(normalized_project_id) > 160
            or _CONTROL_CHARS.search(normalized_project_id)
        ):
            raise ValueError("invalid Wiki audit project_id")
        event: Dict[str, Any] = {
            "schema_version": "zscope.wiki-event.v1",
            "event_id": int(previous.get("event_id", 0) if previous else 0) + 1,
            "event_type": event_type,
            "project_id": normalized_project_id,
            "occurred_at": _utc_now(),
            "actor": actor,
            "status": status,
            "payload_digest": digest_json(dict(payload)),
            "previous_event_digest": previous.get("event_digest") if previous else None,
            "event_digest": "",
        }
        if revision_id is not None:
            event["revision_id"] = revision_id
        if workset_id is not None:
            event["workset_id"] = workset_id
        if fallback_reason is not None:
            event["fallback_reason"] = fallback_reason
        event["event_digest"] = digest_json(
            {key: value for key, value in event.items() if key != "event_digest"}
        )
        from ..schema import validate_instance

        validate_instance(event, "zscope.wiki-event.v1")
        with self.audit_events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self.rebuild_log_from_events()
        return event

    def _manifest(self, manifest: Union[SourceManifest, Mapping[str, Any]]) -> SourceManifest:
        if isinstance(manifest, SourceManifest):
            return manifest
        # Reuse SourceIndex's strict mapping conversion without duplicating all
        # schema coercion rules.
        return SourceIndex._manifest(manifest)  # type: ignore[arg-type]

    def _load_sections(
        self, project_root: Path, manifest: SourceManifest
    ) -> Tuple[Dict[str, Any], ...]:
        index = SourceIndex(":memory:")
        try:
            index.rebuild(project_root, manifest=manifest)
            rows = index.connection.execute(
                "SELECT s.*, d.relative_path, d.content_digest AS source_digest "
                "FROM sections s JOIN documents d ON d.source_id=s.source_id "
                "ORDER BY d.relative_path, s.start_line, s.section_id"
            ).fetchall()
            return tuple(dict(row) for row in rows)
        finally:
            index.close()

    def _source_ref(self, row: Mapping[str, Any]) -> Dict[str, Any]:
        import hashlib

        heading_path = json.loads(row["heading_path_json"])
        excerpt = str(row["excerpt"])
        ref_id = stable_id("docref", row["source_id"], row["section_id"])
        return {
            "schema_version": "zscope.document-ref.v1",
            "ref_id": ref_id,
            "source_id": row["source_id"],
            "relative_path": row["relative_path"],
            "heading_path": heading_path,
            "start_line": int(row["start_line"]),
            "end_line": int(row["end_line"]),
            "source_digest": row["source_digest"],
            "excerpt_digest": "sha256:" + hashlib.sha256(excerpt.encode("utf-8")).hexdigest(),
            "resolvable": True,
            "excerpt": excerpt,
        }

    def _make_page(
        self,
        project_id: str,
        revision_id: str,
        page_kind: str,
        slug: str,
        title: str,
        source_ids: Sequence[str],
        ref_ids: Sequence[str],
        summary: str,
        scope: str,
    ) -> Tuple[Dict[str, Any], str]:
        page_id = stable_id("page", project_id, slug)
        frontmatter: Dict[str, Any] = {
            "schema_version": "zscope.wiki-page-frontmatter.v1",
            "page_id": page_id,
            "page_kind": page_kind,
            "canonical_slug": slug,
            "title": title,
            "project_id": project_id,
            "module_ids": [],
            "subject_ids": [],
            "status": "active",
            "source_ids": list(dict.fromkeys(source_ids)),
            "constraint_ids": [],
            "depends_on": [],
            "generated_language": "zh-CN",
            "compiler_revision": revision_id,
            "content_digest": "",
        }
        ref_links = [f"docref_{ref_id.removeprefix('docref_')}" for ref_id in ref_ids]
        body = _body(summary, scope, ref_links)
        import hashlib

        # The digest covers the human-readable body, avoiding a self-referential
        # frontmatter digest while still allowing the page writer to verify it.
        frontmatter["content_digest"] = "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()
        markdown = _frontmatter_text(frontmatter) + body
        return frontmatter, markdown

    def build_skeleton(
        self,
        project_root: Union[Path, str],
        manifest: Union[SourceManifest, Mapping[str, Any]],
        *,
        revision_id: Optional[str] = None,
    ) -> WikiBuildResult:
        manifest_obj = self._manifest(manifest)
        project_root_path = Path(project_root).resolve()
        parent = (self.active_revision() or {}).get("revision_id")
        rid = validate_revision_id(
            revision_id
            or stable_id(
                "wikirev",
                manifest_obj.project_id,
                manifest_obj.source_manifest_digest,
            )
        )
        rows = self._load_sections(project_root_path, manifest_obj)
        refs = [self._source_ref(row) for row in rows]
        module_sources: Dict[str, List[str]] = {}
        for source in manifest_obj.accepted:
            for module in source.module_hints:
                module_sources.setdefault(module, []).append(source.source_id)

        # Constraint-only revisions retain refs and structured constraints;
        # generated Markdown pages are no longer part of the runtime Wiki.
        # Keep the pages directory and index projection for old readers, but
        # publish no newly generated page rows.
        pages = []

        revision_dir = self.staging_root / f"{rid}.tmp"
        if revision_dir.exists():
            import shutil

            shutil.rmtree(revision_dir)
        (revision_dir / "pages").mkdir(parents=True, exist_ok=True)
        page_meta = []
        for frontmatter, markdown, slug in pages:
            path = revision_dir / "pages" / f"{slug}.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(markdown, encoding="utf-8")
            page_meta.append(
                {
                    "page_id": frontmatter["page_id"],
                    "canonical_slug": slug,
                    "content_digest": frontmatter["content_digest"],
                }
            )
        index_pages = [
            {
                "page_id": frontmatter["page_id"],
                "canonical_slug": slug,
                "frontmatter": frontmatter,
            }
            for frontmatter, _markdown, slug in pages
        ]
        index_text = _render_index(
            manifest_obj.project_id,
            rid,
            manifest_obj.source_manifest_digest,
            index_pages,
        )
        (revision_dir / "index.md").write_text(index_text, encoding="utf-8")
        revision = {
            "schema_version": "zscope.wiki-revision.v1",
            "revision_id": rid,
            "parent_revision_id": parent,
            "project_id": manifest_obj.project_id,
            "source_manifest_digest": manifest_obj.source_manifest_digest,
            "compiler": {
                "kind": "deterministic",
                "identity": "zscope.wiki.skeleton.v1",
                "prompt_version": None,
                "model": None,
            },
            "pages_digest": digest_json(page_meta),
            "constraints_digest": digest_json([]),
            "edges_digest": digest_json([]),
            "lint": {"status": "passed", "errors": 0, "warnings": 0},
            "dirty_modules": sorted(module_sources),
            "created_at": _utc_now(),
            "active": True,
        }
        (revision_dir / "refs.json").write_text(
            json.dumps(refs, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (revision_dir / "source-manifest.json").write_text(
            json.dumps(manifest_obj.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (revision_dir / "constraints.json").write_text("[]\n", encoding="utf-8")
        (revision_dir / "edges.json").write_text("[]\n", encoding="utf-8")
        (revision_dir / "revision.json").write_text(
            json.dumps(revision, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        final_dir = self.revisions_root / rid
        if final_dir.exists():
            import shutil

            shutil.rmtree(final_dir)
        os.replace(revision_dir, final_dir)
        with self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO revisions VALUES (?, ?, ?, ?, ?)",
                (
                    rid,
                    parent,
                    manifest_obj.project_id,
                    manifest_obj.source_manifest_digest,
                    json.dumps(revision, ensure_ascii=False, sort_keys=True),
                ),
            )
            self.connection.execute("DELETE FROM pages WHERE revision_id=?", (rid,))
            self.connection.execute("DELETE FROM document_refs WHERE revision_id=?", (rid,))
            self.connection.execute("DELETE FROM constraints WHERE revision_id=?", (rid,))
            self.connection.execute("DELETE FROM edges WHERE revision_id=?", (rid,))
            for frontmatter, markdown, slug in pages:
                self.connection.execute(
                    "INSERT INTO pages VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        rid,
                        frontmatter["page_id"],
                        slug,
                        json.dumps(frontmatter, ensure_ascii=False, sort_keys=True),
                        markdown,
                        frontmatter["content_digest"],
                    ),
                )
            for ref in refs:
                self.connection.execute(
                    "INSERT INTO document_refs VALUES (?, ?, ?, ?)",
                    (
                        rid,
                        ref["ref_id"],
                        ref["source_id"],
                        json.dumps(ref, ensure_ascii=False, sort_keys=True),
                    ),
                )
            self.connection.execute(
                "INSERT INTO wiki_events(revision_id,event_type,status,payload_json,occurred_at) VALUES (?, ?, ?, ?, ?)",
                (
                    rid,
                    "publish",
                    "succeeded",
                    json.dumps(
                        {"outcome": "background_only", "constraints_created": 0}, sort_keys=True
                    ),
                    revision["created_at"],
                ),
            )
        try:
            self._publish_active(rid, manifest_obj.source_manifest_digest, revision["created_at"])
        except Exception as exc:
            self._mark_revision_failed(rid, str(exc))
            raise WikiChangeSetApplyError("active pointer publish failed") from exc
        self._append_audit_event(
            event_type="publish",
            project_id=manifest_obj.project_id,
            status="succeeded",
            payload={
                "outcome": "background_only",
                "pages": len(pages),
                "refs": len(refs),
                "constraints_created": 0,
            },
            revision_id=rid,
        )
        self._append_log(revision, len(pages), len(refs))
        return WikiBuildResult(
            rid,
            parent,
            manifest_obj.source_manifest_digest,
            len(pages),
            len(refs),
            0,
            self.active_path,
        )

    build = build_skeleton

    @staticmethod
    def _body_from_markdown(markdown: str) -> str:
        """Return Markdown body after an optional YAML-like frontmatter block."""

        return body_from_markdown(markdown)

    @staticmethod
    def _frontmatter_hint(markdown: str) -> Dict[str, Any]:
        """Read only scalar/list hints from Compiler Markdown frontmatter.

        The Compiler is not trusted with identity.  This intentionally parses a
        small YAML-compatible subset and lets the program overwrite all
        program-owned fields before publication.
        """

        hints: Dict[str, Any] = {}
        text = str(markdown)
        if not (text.startswith("---\n") or text.startswith("---\r\n")):
            return hints
        lines = text.splitlines()
        if len(lines) < 2:
            return hints
        end = next((i for i, line in enumerate(lines[1:], 1) if line.strip() == "---"), None)
        if end is None:
            return hints
        current_list: Optional[str] = None
        for line in lines[1:end]:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if line.startswith("  - ") and current_list:
                hints.setdefault(current_list, []).append(line[4:].strip().strip("\"'"))
                continue
            if ":" not in line:
                continue
            key, raw = line.split(":", 1)
            key = key.strip()
            raw = raw.strip()
            if not raw:
                hints[key] = []
                current_list = key
            else:
                current_list = None
                hints[key] = raw.strip("\"'")
        return hints

    @staticmethod
    def _required_body(markdown: str) -> str:
        body = body_from_markdown(markdown).strip()
        errors = page_markdown_errors(markdown)
        if errors:
            raise WikiChangeSetApplyError("invalid Wiki page body: " + ", ".join(errors))
        return body + "\n"

    def _revision_rows(self, revision_id: Optional[str]) -> Tuple[
        Dict[str, Dict[str, Any]],
        Dict[str, Dict[str, Any]],
        Dict[str, Dict[str, Any]],
        Dict[str, Dict[str, Any]],
    ]:
        if not revision_id:
            return {}, {}, {}, {}
        pages: Dict[str, Dict[str, Any]] = {}
        for row in self.connection.execute(
            "SELECT * FROM pages WHERE revision_id=?", (revision_id,)
        ).fetchall():
            item = dict(row)
            try:
                item["frontmatter"] = json.loads(item.pop("frontmatter_json"))
            except Exception:
                item["frontmatter"] = {}
            pages[str(item["page_id"])] = item
        refs: Dict[str, Dict[str, Any]] = {}
        for row in self.connection.execute(
            "SELECT ref_id, ref_json FROM document_refs WHERE revision_id=?", (revision_id,)
        ).fetchall():
            try:
                refs[str(row["ref_id"])] = json.loads(row["ref_json"])
            except Exception:
                continue
        constraints: Dict[str, Dict[str, Any]] = {}
        for row in self.connection.execute(
            "SELECT constraint_id, constraint_json FROM constraints WHERE revision_id=?",
            (revision_id,),
        ).fetchall():
            try:
                constraints[str(row["constraint_id"])] = json.loads(row["constraint_json"])
            except Exception:
                continue
        edges: Dict[str, Dict[str, Any]] = {}
        for row in self.connection.execute(
            "SELECT edge_id, edge_json FROM edges WHERE revision_id=?", (revision_id,)
        ).fetchall():
            try:
                edges[str(row["edge_id"])] = json.loads(row["edge_json"])
            except Exception:
                continue
        return pages, refs, constraints, edges

    def _current_refs(
        self, project_root: Optional[Union[Path, str]], manifest: SourceManifest
    ) -> Dict[str, Dict[str, Any]]:
        if project_root is None:
            return {}
        rows = self._load_sections(Path(project_root).resolve(), manifest)
        return {str(ref["ref_id"]): ref for ref in (self._source_ref(row) for row in rows)}

    @classmethod
    def _materialize_constraint_proposal(
        cls,
        raw: Mapping[str, Any],
        manifest: SourceManifest,
        workset: Mapping[str, Any],
        revision_id: str,
    ) -> Dict[str, Any]:
        subject_id = str(raw.get("subject_id", "")).strip()
        subject_kind = str(raw.get("subject_kind", "")).strip()
        kind = str(raw.get("kind", "")).strip()
        normativity = str(raw.get("normativity", "unknown")).strip()
        statement = " ".join(str(raw.get("statement", "")).split())
        source_refs = sorted(set(str(ref) for ref in raw.get("source_refs", ())))
        ref_sources = {
            str(item.get("ref_id")): str(item.get("source_id"))
            for item in workset.get("source_ref_catalog", ())
            if isinstance(item, Mapping)
        }
        source_ids = {ref_sources.get(ref, "") for ref in source_refs}
        module_ids = sorted(
            {
                str(module)
                for source in manifest.accepted
                if source.source_id in source_ids
                for module in source.module_hints
            }
        )
        constraint_id = stable_id(
            "constraint",
            manifest.project_id,
            subject_kind,
            subject_id.casefold(),
            kind,
            normativity,
            statement.casefold(),
        )
        return {
            "schema_version": "zscope.project-constraint.v1",
            "constraint_id": constraint_id,
            "subject": {
                "kind": subject_kind,
                "canonical_id": subject_id,
            },
            "scope": {
                "project_id": manifest.project_id,
                "module_ids": module_ids,
                "path_globs": [],
            },
            "kind": kind,
            "statement": statement,
            "authority": "documented_contract",
            "normativity": normativity,
            "status": "active",
            "source_refs": source_refs,
            "conflicts_with": [],
            "source_manifest_digest": manifest.source_manifest_digest,
            "created_revision_id": revision_id,
        }

    def apply_changeset(
        self,
        project_root: Optional[Union[Path, str]],
        manifest: Union[SourceManifest, Mapping[str, Any]],
        workset: Mapping[str, Any],
        changeset: Mapping[str, Any],
        *,
        revision_id: Optional[str] = None,
        dirty_modules: Sequence[str] = (),
    ) -> WikiBuildResult:
        """Apply a validated WikiChangeSet and publish one atomic revision.

        The method performs all validation and projection in memory first.  A
        failed extraction/rejected source leaves the active pointer untouched;
        a successful ChangeSet writes an immutable revision and only then swaps
        ``active.json``.
        """

        from ..compiler.changeset import ChangeSetValidationError, validate_changeset

        manifest_obj = self._manifest(manifest)
        try:
            validated = validate_changeset(changeset, workset)
        except Exception as exc:
            raise WikiChangeSetApplyError(str(exc)) from exc
        active = self.active_revision() or {}
        parent_id = active.get("revision_id")
        base_id = workset.get("base_revision_id")
        if base_id != parent_id:
            raise WikiChangeSetApplyError(
                "ChangeSet base_revision_id does not match active revision"
            )
        outcome = str(validated["outcome"])
        if outcome in {"extraction_failed", "source_rejected"}:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO wiki_events(revision_id,event_type,status,payload_json,occurred_at) VALUES (?, ?, ?, ?, ?)",
                    (
                        parent_id,
                        "ingest",
                        "quarantined",
                        json.dumps(
                            {"outcome": outcome, "workset_id": workset.get("workset_id")},
                            sort_keys=True,
                        ),
                        _utc_now(),
                    ),
                )
            self._append_audit_event(
                event_type="ingest",
                project_id=manifest_obj.project_id,
                status="quarantined",
                payload={"outcome": outcome},
                revision_id=str(parent_id) if parent_id else None,
                workset_id=str(workset.get("workset_id")) if workset.get("workset_id") else None,
                fallback_reason="compiler_unavailable" if outcome == "extraction_failed" else None,
            )
            return WikiBuildResult(
                str(parent_id or ""),
                parent_id,
                manifest_obj.source_manifest_digest,
                0,
                0,
                0,
                self.active_path,
                outcome=outcome,
                constraints_created=0,
            )

        _old_pages, old_refs, old_constraints, _old_edges = self._revision_rows(parent_id)
        current_refs = self._current_refs(project_root, manifest_obj)
        refs = dict(old_refs)
        refs.update(current_refs)
        changed_sources = set(workset.get("changed_source_ids", ())) | set(
            workset.get("removed_source_ids", ())
        )
        for ref_id, ref in refs.items():
            source_id = str(ref.get("source_id", ""))
            if source_id in changed_sources and ref_id not in current_refs:
                ref["resolvable"] = False
        source_ref_to_source = {
            ref_id: str(ref.get("source_id", "")) for ref_id, ref in refs.items()
        }
        stale = propagate_stale(
            list(old_constraints.values()),
            changed_sources,
            source_ref_to_source=source_ref_to_source,
        )
        stale_by_id = {str(item["constraint_id"]): item for item in stale}

        # ``summary`` is a program-generated human/audit convenience field,
        # not semantic Wiki content.  Exclude it from revision identity so a
        # wording-only change cannot create revision churn.
        revision_identity = dict(validated)
        revision_identity.pop("summary", None)
        rid = validate_revision_id(
            revision_id
            or stable_id(
                "wikirev",
                manifest_obj.project_id,
                manifest_obj.source_manifest_digest,
                parent_id or "none",
                digest_json(revision_identity),
            )
        )
        proposals: List[Dict[str, Any]] = []
        for raw in validated.get("constraint_proposals", ()):
            item = self._materialize_constraint_proposal(raw, manifest_obj, workset, rid)
            item["source_manifest_digest"] = manifest_obj.source_manifest_digest
            item["created_revision_id"] = rid
            item["source_refs"] = sorted(set(str(ref) for ref in item.get("source_refs", ())))
            item["conflicts_with"] = sorted(set(str(ref) for ref in item.get("conflicts_with", ())))
            proposals.append(item)
        proposal_ids = {str(item["constraint_id"]) for item in proposals}
        historical = [
            item
            for item in stale_by_id.values()
            if item.get("status") not in {"active", "conflicted"}
            and str(item.get("constraint_id")) not in proposal_ids
        ]
        merge_base = [
            item for item in stale_by_id.values() if item.get("status") in {"active", "conflicted"}
        ]
        constraints = merge_constraint_proposals(merge_base, proposals)
        constraints.extend(historical)
        constraint_by_id = {str(item["constraint_id"]): item for item in constraints}

        # Constraint-only revisions intentionally drop historical page and
        # edge projections.  They remain readable in their original revision,
        # but no new page/edge data is copied into the current projection.
        edges: Dict[str, Dict[str, Any]] = {}
        pages_list: List[Dict[str, Any]] = []
        changed_page_ids: Set[str] = set()

        # A constraint projection belongs to this revision even when equal
        # values were merged from its parent.  Refresh the program-owned pin
        # while retaining its stable identity and provenance refs.
        for item in constraint_by_id.values():
            item.pop("normalized_value", None)
            item.pop("page_refs", None)
            item["source_manifest_digest"] = manifest_obj.source_manifest_digest
            item["created_revision_id"] = rid

        constraints = sorted(constraint_by_id.values(), key=lambda item: str(item["constraint_id"]))
        max_constraints = (
            workset.get("limits", {}).get("max_constraints")
            if isinstance(workset.get("limits"), Mapping)
            else None
        )
        if max_constraints is not None and len(constraints) > int(max_constraints):
            raise WikiChangeSetApplyError(
                "project Wiki constraints exceed max_constraints storage limit"
            )
        edges_list = sorted(edges.values(), key=lambda item: str(item["edge_id"]))
        page_meta = [
            {
                "page_id": item["page_id"],
                "canonical_slug": item["canonical_slug"],
                "content_digest": item["content_digest"],
            }
            for item in pages_list
        ]
        revision = {
            "schema_version": "zscope.wiki-revision.v1",
            "revision_id": rid,
            "parent_revision_id": parent_id,
            "project_id": manifest_obj.project_id,
            "source_manifest_digest": manifest_obj.source_manifest_digest,
            "compiler": dict(
                validated.get(
                    "compiler",
                    {
                        "kind": "mixed",
                        "identity": "zscope.wiki.changeset.v1",
                        "prompt_version": None,
                    },
                )
            ),
            "pages_digest": digest_json(page_meta),
            "constraints_digest": digest_json(constraints),
            "edges_digest": digest_json(edges_list),
            "lint": {"status": "passed", "errors": 0, "warnings": 0},
            "dirty_modules": sorted(set(str(item) for item in dirty_modules)),
            "created_at": _utc_now(),
            "active": True,
        }
        revision_dir = self.staging_root / f"{rid}.tmp"
        if revision_dir.exists():
            import shutil

            shutil.rmtree(revision_dir)
        (revision_dir / "pages").mkdir(parents=True, exist_ok=True)
        for item in pages_list:
            path = revision_dir / "pages" / f"{item['canonical_slug']}.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(str(item["markdown"]), encoding="utf-8")
        index_text = _render_index(
            manifest_obj.project_id,
            rid,
            manifest_obj.source_manifest_digest,
            pages_list,
        )
        (revision_dir / "index.md").write_text(index_text, encoding="utf-8")
        (revision_dir / "refs.json").write_text(
            json.dumps(
                sorted(refs.values(), key=lambda item: str(item["ref_id"])),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (revision_dir / "source-manifest.json").write_text(
            json.dumps(manifest_obj.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (revision_dir / "constraints.json").write_text(
            json.dumps(constraints, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (revision_dir / "edges.json").write_text(
            json.dumps(edges_list, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (revision_dir / "revision.json").write_text(
            json.dumps(revision, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        final_dir = self.revisions_root / rid
        if final_dir.exists():
            import shutil

            shutil.rmtree(final_dir)
        os.replace(revision_dir, final_dir)
        with self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO revisions VALUES (?, ?, ?, ?, ?)",
                (
                    rid,
                    parent_id,
                    manifest_obj.project_id,
                    manifest_obj.source_manifest_digest,
                    json.dumps(revision, ensure_ascii=False, sort_keys=True),
                ),
            )
            for table in ("pages", "document_refs", "constraints", "edges"):
                self.connection.execute(f"DELETE FROM {table} WHERE revision_id=?", (rid,))
            for item in pages_list:
                self.connection.execute(
                    "INSERT INTO pages VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        rid,
                        item["page_id"],
                        item["canonical_slug"],
                        json.dumps(item["frontmatter"], ensure_ascii=False, sort_keys=True),
                        item["markdown"],
                        item["content_digest"],
                    ),
                )
            for item in refs.values():
                self.connection.execute(
                    "INSERT INTO document_refs VALUES (?, ?, ?, ?)",
                    (
                        rid,
                        item["ref_id"],
                        item["source_id"],
                        json.dumps(item, ensure_ascii=False, sort_keys=True),
                    ),
                )
            for item in constraints:
                self.connection.execute(
                    "INSERT INTO constraints VALUES (?, ?, ?)",
                    (
                        rid,
                        item["constraint_id"],
                        json.dumps(item, ensure_ascii=False, sort_keys=True),
                    ),
                )
            for item in edges_list:
                self.connection.execute(
                    "INSERT INTO edges VALUES (?, ?, ?)",
                    (rid, item["edge_id"], json.dumps(item, ensure_ascii=False, sort_keys=True)),
                )

        from ..lint import lint_revision

        linted = lint_revision(self, rid)
        if not linted.passed:
            reason = "candidate revision lint failed: " + ", ".join(linted.errors[:8])
            self._mark_revision_failed(rid, reason)
            self._append_log(
                revision,
                len(pages_list),
                len(refs),
                outcome=outcome,
                constraints_created=len(proposals),
            )
            raise WikiChangeSetApplyError(reason)

        revision["lint"] = {
            "status": "passed",
            "errors": 0,
            "warnings": len(linted.warnings),
        }
        revision_path = final_dir / "revision.json"
        revision_path.write_text(
            json.dumps(revision, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.connection:
            self.connection.execute(
                "UPDATE revisions SET revision_json=? WHERE revision_id=?",
                (json.dumps(revision, ensure_ascii=False, sort_keys=True), rid),
            )
            self.connection.execute(
                "INSERT INTO wiki_events(revision_id,event_type,status,payload_json,occurred_at) VALUES (?, ?, ?, ?, ?)",
                (
                    rid,
                    "publish",
                    "succeeded",
                    json.dumps(
                        {
                            "outcome": outcome,
                            "workset_id": workset.get("workset_id"),
                            "changed_pages": len(changed_page_ids),
                            "constraints_created": len(proposals),
                        },
                        sort_keys=True,
                    ),
                    revision["created_at"],
                ),
            )
        try:
            self._publish_active(rid, manifest_obj.source_manifest_digest, revision["created_at"])
        except Exception as exc:
            self._mark_revision_failed(rid, str(exc))
            self._append_log(
                revision,
                len(pages_list),
                len(refs),
                outcome=outcome,
                constraints_created=len(proposals),
            )
            raise WikiChangeSetApplyError("active pointer publish failed") from exc
        self._append_audit_event(
            event_type="publish",
            project_id=manifest_obj.project_id,
            status="succeeded",
            payload={
                "outcome": outcome,
                "changed_pages": len(changed_page_ids),
                "constraints_created": len(proposals),
            },
            revision_id=rid,
            workset_id=str(workset.get("workset_id")) if workset.get("workset_id") else None,
        )
        self._append_log(
            revision,
            len(pages_list),
            len(refs),
            outcome=outcome,
            constraints_created=len(proposals),
        )
        return WikiBuildResult(
            rid,
            parent_id,
            manifest_obj.source_manifest_digest,
            len(pages_list),
            len(refs),
            len(constraints),
            self.active_path,
            outcome=outcome,
            constraints_created=len(proposals),
        )

    def compile_and_apply(
        self,
        project_root: Optional[Union[Path, str]],
        manifest: Union[SourceManifest, Mapping[str, Any]],
        workset: Mapping[str, Any],
        compiler: Any,
        *,
        revision_id: Optional[str] = None,
        dirty_modules: Sequence[str] = (),
    ) -> WikiBuildResult:
        """Run a bounded Compiler and publish its validated ChangeSet.

        ``compiler`` is deliberately duck-typed so deterministic and
        OpenAI-compatible adapters share exactly one store boundary.  The
        adapter may return ``extraction_failed``; that result is audited while
        leaving the active revision unchanged.
        """

        changeset = compiler.compile(workset)
        return self.apply_changeset(
            project_root,
            manifest,
            workset,
            changeset,
            revision_id=revision_id,
            dirty_modules=dirty_modules,
        )

    def rebuild_log_from_events(self) -> Dict[str, Any]:
        replay = replay_audit_events(self.audit_events_path)
        if not replay.passed:
            raise ValueError("invalid Wiki audit event chain: " + ", ".join(replay.errors))
        text = render_log_markdown(replay)
        fd, temp_name = tempfile.mkstemp(prefix="log.", suffix=".md", dir=str(self.state_root))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.log_path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        return replay.to_dict()

    def _append_log(
        self,
        revision: Mapping[str, Any],
        page_count: int,
        ref_count: int,
        *,
        outcome: str = "background_only",
        constraints_created: int = 0,
    ) -> None:
        # Compatibility shim for existing publication call sites.  log.md is
        # always rebuilt from the hash-chained program events.
        self.rebuild_log_from_events()

    def rollback(self, revision_id: str) -> Dict[str, Any]:
        revision_id = validate_revision_id(revision_id)
        try:
            revision = self.revision_metadata(revision_id)
        except ValueError as exc:
            raise ValueError(f"unknown Wiki revision: {revision_id}") from exc
        revision["active"] = True
        revision["created_at"] = _utc_now()
        self._publish_active(
            revision_id, revision["source_manifest_digest"], revision["created_at"]
        )
        self._append_audit_event(
            event_type="rollback",
            project_id=str(revision.get("project_id") or "project"),
            status="rolled_back",
            payload={"target_revision_id": revision_id},
            revision_id=revision_id,
        )
        self._append_log(revision, 0, 0)
        return self.active_revision() or {}


__all__ = [
    "WikiStore",
    "WikiBuildResult",
    "WikiChangeSetApplyError",
    "HEADINGS",
    "DB_SCHEMA",
    "ACTIVE_POINTER_MAX_BYTES",
    "REVISION_METADATA_MAX_BYTES",
    "SOURCE_MANIFEST_MAX_BYTES",
    "validate_revision_id",
    "resolve_project_state_root",
    "resolve_state_child",
    "read_active_pointer",
    "read_revision_metadata",
]
