"""Program-owned Wiki revision lint independent of optional JSON-schema libs."""

from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .events import render_log_markdown, replay_audit_events
from .page_format import INDEX_HEADINGS, body_from_markdown, page_markdown_errors, wikilink_targets
from .store.revision_store import (
    WikiStore,
    resolve_state_child,
    validate_revision_id,
)
from .schema import SchemaValidationError, validate_instance


LINT_MAX_OBJECT_ROWS = 10_000
LINT_MAX_JSON_CHARS = 1024 * 1024
LINT_MAX_MARKDOWN_CHARS = 2 * 1024 * 1024
LINT_MAX_INDEX_BYTES = 4 * 1024 * 1024
LINT_MAX_LOG_BYTES = 64 * 1024 * 1024
LINT_MAX_ERRORS = 512
_SLUG_PATTERN = re.compile(r"^(?!/)(?!.*\.\.)(?:[a-z0-9-]+/)*[a-z0-9-]+$")


def _read_bounded_text(path: Path, *, max_bytes: int) -> Tuple[Optional[str], Optional[str]]:
    if path.is_symlink():
        return None, "symlink"
    try:
        if path.stat().st_size > max_bytes:
            return None, "size_limit"
        return path.read_bytes().decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "invalid_utf8"
    except OSError:
        return None, "unavailable"


def _bounded_rows(
    store: WikiStore,
    query: str,
    params: Sequence[Any],
) -> Tuple[List[Any], bool]:
    rows = store.connection.execute(
        query + f" LIMIT {LINT_MAX_OBJECT_ROWS + 1}",
        tuple(params),
    ).fetchall()
    return list(rows[:LINT_MAX_OBJECT_ROWS]), len(rows) > LINT_MAX_OBJECT_ROWS


def _bounded_errors(errors: Sequence[str]) -> Tuple[str, ...]:
    unique = sorted(set(errors))
    if len(unique) <= LINT_MAX_ERRORS:
        return tuple(unique)
    return tuple(unique[: LINT_MAX_ERRORS - 1] + ["lint_error_limit_exceeded"])


@dataclass(frozen=True)
class LintResult:
    status: str
    errors: Tuple[str, ...]
    warnings: Tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.status == "passed"

    def to_dict(self) -> Dict[str, Any]:
        return {"status": self.status, "errors": list(self.errors), "warnings": list(self.warnings)}


def lint_revision(store: WikiStore, revision_id: Optional[str] = None) -> LintResult:
    try:
        active = store.active_revision() or {}
    except ValueError:
        active = {}
    rid = revision_id or active.get("revision_id")
    if not rid:
        return LintResult("failed", ("no_active_revision",), ())
    try:
        rid = validate_revision_id(str(rid))
    except ValueError:
        return LintResult("failed", ("invalid_revision_id",), ())
    try:
        revision = store.revision_metadata(rid)
    except ValueError:
        return LintResult("failed", ("revision_missing",), ())
    errors: List[str] = []
    warnings: List[str] = []
    replay = replay_audit_events(store.audit_events_path)
    errors.extend(replay.errors)
    if replay.passed:
        if active.get("revision_id") != replay.active_revision_id:
            errors.append("audit_active_projection_mismatch")
        expected_log = render_log_markdown(replay)
        if not store.log_path.is_file():
            errors.append("log_projection_missing")
        else:
            actual_log, log_error = _read_bounded_text(
                store.log_path,
                max_bytes=LINT_MAX_LOG_BYTES,
            )
            if log_error:
                errors.append(f"log_projection_{log_error}")
            elif actual_log != expected_log:
                errors.append("log_projection_mismatch")
    try:
        validate_instance(revision, "zscope.wiki-revision.v1")
    except SchemaValidationError as exc:
        errors.extend(f"revision_schema:{item}" for item in exc.errors)
    try:
        pages_root = resolve_state_child(store.state_root, "revisions", rid, "pages")
    except ValueError:
        return LintResult("failed", ("pages_root_unsafe",), ())
    page_rows, pages_limited = _bounded_rows(
        store,
        "SELECT page_id, canonical_slug, frontmatter_json, markdown, content_digest FROM pages WHERE revision_id=? ORDER BY page_id",
        (rid,),
    )
    ref_rows, refs_limited = _bounded_rows(
        store,
        "SELECT ref_id, ref_json FROM document_refs WHERE revision_id=? ORDER BY ref_id",
        (rid,),
    )
    constraint_rows, constraints_limited = _bounded_rows(
        store,
        "SELECT constraint_id, constraint_json FROM constraints WHERE revision_id=? ORDER BY constraint_id",
        (rid,),
    )
    edge_rows, edges_limited = _bounded_rows(
        store,
        "SELECT edge_id, edge_json FROM edges WHERE revision_id=? ORDER BY edge_id",
        (rid,),
    )
    for name, limited in (
        ("pages", pages_limited),
        ("refs", refs_limited),
        ("constraints", constraints_limited),
        ("edges", edges_limited),
    ):
        if limited:
            errors.append(f"{name}_projection_limit")
    refs: Dict[str, Dict[str, Any]] = {}
    constraints: Dict[str, Dict[str, Any]] = {}
    edges: Dict[str, Dict[str, Any]] = {}
    for rows, id_key, json_key, target, error_prefix in (
        (ref_rows, "ref_id", "ref_json", refs, "ref"),
        (constraint_rows, "constraint_id", "constraint_json", constraints, "constraint"),
        (edge_rows, "edge_id", "edge_json", edges, "edge"),
    ):
        for row in rows:
            object_id = str(row[id_key])
            raw_json = str(row[json_key])
            if len(raw_json) > LINT_MAX_JSON_CHARS:
                errors.append(f"{error_prefix}_json_size:{object_id}")
                continue
            try:
                value = json.loads(raw_json)
            except ValueError:
                errors.append(f"{error_prefix}_json_invalid:{object_id}")
                continue
            if not isinstance(value, dict):
                errors.append(f"{error_prefix}_json_object:{object_id}")
                continue
            target[object_id] = value
    page_ids = {str(row["page_id"]) for row in page_rows}
    for ref_id, ref in refs.items():
        try:
            validate_instance(ref, "zscope.document-ref.v1")
        except SchemaValidationError as exc:
            errors.extend(f"ref_schema:{ref_id}:{item}" for item in exc.errors)
    for constraint_id, constraint in constraints.items():
        # Older revisions may contain page/normalized projections.  They are
        # ignored during compatibility lint and never enter new projections.
        lint_constraint = dict(constraint)
        lint_constraint.pop("normalized_value", None)
        lint_constraint.pop("page_refs", None)
        try:
            validate_instance(lint_constraint, "zscope.project-constraint.v1")
        except SchemaValidationError as exc:
            errors.extend(f"constraint_schema:{constraint_id}:{item}" for item in exc.errors)
        source_refs = [str(ref) for ref in constraint.get("source_refs", ())]
        missing_refs = [ref for ref in source_refs if ref not in refs]
        if missing_refs:
            errors.append(f"constraint_unresolved_ref:{constraint_id}")
        if constraint.get("status") == "active" and any(not bool(refs.get(ref, {}).get("resolvable")) for ref in source_refs):
            errors.append(f"active_constraint_unresolvable:{constraint_id}")
    for edge_id, edge in edges.items():
        try:
            validate_instance(edge, "zscope.wiki-edge.v1")
        except SchemaValidationError as exc:
            errors.extend(f"edge_schema:{edge_id}:{item}" for item in exc.errors)
        if any(str(ref) not in refs for ref in edge.get("source_refs", ())):
            errors.append(f"edge_unresolved_ref:{edge_id}")
    for row in page_rows:
        raw_frontmatter = str(row["frontmatter_json"])
        if len(raw_frontmatter) > LINT_MAX_JSON_CHARS:
            errors.append(f"invalid_frontmatter_size:{row['page_id']}")
            continue
        try:
            frontmatter = json.loads(raw_frontmatter)
        except Exception:
            errors.append(f"invalid_frontmatter:{row['page_id']}")
            continue
        if not isinstance(frontmatter, dict):
            errors.append(f"invalid_frontmatter_object:{row['page_id']}")
            continue
        if frontmatter.get("page_id") != row["page_id"]:
            errors.append(f"page_id_mismatch:{row['page_id']}")
        try:
            validate_instance(frontmatter, "zscope.wiki-page-frontmatter.v1")
        except SchemaValidationError as exc:
            errors.extend(f"page_schema:{row['page_id']}:{item}" for item in exc.errors)
        if frontmatter.get("compiler_revision") != rid:
            errors.append(f"page_revision_mismatch:{row['page_id']}")
        if any(str(value) not in constraints for value in frontmatter.get("constraint_ids", ())):
            errors.append(f"page_unresolved_constraint:{row['page_id']}")
        if any(str(value) not in page_ids for value in frontmatter.get("depends_on", ())):
            errors.append(f"page_unresolved_dependency:{row['page_id']}")
        markdown = str(row["markdown"])
        if len(markdown) > LINT_MAX_MARKDOWN_CHARS:
            errors.append(f"page_markdown_size:{row['page_id']}")
            continue
        for error in page_markdown_errors(markdown):
            errors.append(f"page_markdown:{row['page_id']}:{error}")
        body = body_from_markdown(markdown).strip() + "\n"
        body_digest = "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()
        if frontmatter.get("content_digest") != body_digest or row["content_digest"] != body_digest:
            errors.append(f"page_content_digest:{row['page_id']}")
        for link_target in wikilink_targets(markdown):
            if link_target not in page_ids:
                errors.append(f"unresolved_wikilink:{link_target}")
        canonical_slug = str(row["canonical_slug"])
        if frontmatter.get("canonical_slug") != canonical_slug:
            errors.append(f"page_slug_mismatch:{row['page_id']}")
        if not _SLUG_PATTERN.fullmatch(canonical_slug):
            errors.append(f"page_slug_unsafe:{row['page_id']}")
            continue
        try:
            page_file = resolve_state_child(
                store.state_root,
                "revisions",
                rid,
                "pages",
                f"{canonical_slug}.md",
            )
        except ValueError:
            errors.append(f"page_file_unsafe:{row['page_id']}")
            continue
        if not page_file.is_file():
            errors.append(f"page_file_missing:{row['canonical_slug']}")
        else:
            page_text, page_error = _read_bounded_text(
                page_file,
                max_bytes=LINT_MAX_MARKDOWN_CHARS * 4,
            )
            if page_error:
                errors.append(f"page_file_{page_error}:{row['page_id']}")
            elif page_text != markdown:
                errors.append(f"page_file_projection:{row['page_id']}")
        for ref in re.findall(r"\[(docref_[a-z0-9_:-]+)\]", markdown):
            if ref not in refs:
                errors.append(f"unresolved_ref:{ref}")
    try:
        index_path = resolve_state_child(
            store.state_root,
            "revisions",
            rid,
            "index.md",
        )
    except ValueError:
        index_path = None
        errors.append("index_unsafe")
    if index_path is None or not index_path.is_file():
        errors.append("index_missing")
    else:
        index_markdown, index_error = _read_bounded_text(
            index_path,
            max_bytes=LINT_MAX_INDEX_BYTES,
        )
        if index_error:
            errors.append(f"index_{index_error}")
            index_markdown = None
        if index_markdown is None:
            index_markdown = ""
        index_frontmatter = store._frontmatter_hint(index_markdown)
        try:
            validate_instance(index_frontmatter, "zscope.wiki-index.v1")
        except SchemaValidationError as exc:
            errors.extend(f"index_schema:{item}" for item in exc.errors)
        index_body = body_from_markdown(index_markdown)
        index_headings = tuple(
            match.group(1).strip()
            for match in re.finditer(r"^##[ \t]+(.+?)[ \t]*$", index_body, re.MULTILINE)
        )
        if index_headings != INDEX_HEADINGS:
            errors.append("index_heading_sequence")
        index_digest = "sha256:" + hashlib.sha256(index_body.encode("utf-8")).hexdigest()
        if index_frontmatter.get("content_digest") != index_digest:
            errors.append("index_content_digest")
        page_slugs = {str(row["canonical_slug"]) for row in page_rows}
        for slug in re.findall(r"\]\(pages/([^\)]+)\.md\)", index_body):
            if slug not in page_slugs:
                errors.append(f"index_unresolved_page:{slug}")
    if active and active.get("revision_id") == rid and active.get("source_manifest_digest") != revision.get("source_manifest_digest"):
        errors.append("active_manifest_mismatch")
    manifest = store.revision_manifest(str(rid))
    if manifest is None:
        errors.append("revision_manifest_missing")
    elif manifest.get("source_manifest_digest") != revision.get("source_manifest_digest"):
        errors.append("revision_manifest_mismatch")
    else:
        try:
            validate_instance(manifest, "zscope.document-source-manifest.v1")
        except SchemaValidationError as exc:
            errors.extend(f"manifest_schema:{item}" for item in exc.errors)
    if revision.get("lint", {}).get("status") == "failed":
        errors.append("revision_marked_failed")
    bounded = _bounded_errors(errors)
    return LintResult(
        "passed" if not bounded else "failed",
        bounded,
        tuple(sorted(set(warnings))),
    )


__all__ = ["LintResult", "lint_revision"]
