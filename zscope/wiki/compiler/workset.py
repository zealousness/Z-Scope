"""Program-owned bounded IngestWorkset construction."""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple, Union

from ..identity import stable_id
from ..models import SourceManifest
from ..source_index import SourceIndex


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _manifest(value: Union[SourceManifest, Mapping[str, Any]]) -> SourceManifest:
    if isinstance(value, SourceManifest):
        return value
    return SourceIndex._manifest(value)  # type: ignore[arg-type]


def _refs_for_sources(index: SourceIndex, source_ids: Sequence[str]) -> Tuple[str, ...]:
    if not source_ids:
        return ()
    placeholders = ",".join("?" for _ in source_ids)
    rows = index.connection.execute(
        f"SELECT section_id, source_id FROM sections WHERE source_id IN ({placeholders}) ORDER BY source_id, start_line, section_id",
        tuple(source_ids),
    ).fetchall()
    return tuple(stable_id("docref", row["source_id"], row["section_id"]) for row in rows)


def _ref_catalog_for_sources(index: SourceIndex, source_ids: Sequence[str]) -> Tuple[Dict[str, Any], ...]:
    if not source_ids:
        return ()
    placeholders = ",".join("?" for _ in source_ids)
    rows = index.connection.execute(
        f"SELECT s.section_id, s.source_id, s.heading_path_json, s.start_line, s.end_line, s.excerpt, d.relative_path, d.content_digest "
        f"FROM sections s JOIN documents d ON d.source_id=s.source_id WHERE s.source_id IN ({placeholders}) "
        "ORDER BY s.source_id, s.start_line, s.section_id",
        tuple(source_ids),
    ).fetchall()
    return tuple({
        "schema_version": "zscope.document-ref.v1",
        "ref_id": stable_id("docref", row["source_id"], row["section_id"]),
        "source_id": row["source_id"],
        "relative_path": row["relative_path"],
        "heading_path": json.loads(row["heading_path_json"]),
        "start_line": int(row["start_line"]),
        "end_line": int(row["end_line"]),
        "source_digest": row["content_digest"],
        "excerpt_digest": "sha256:" + hashlib.sha256(str(row["excerpt"]).encode("utf-8")).hexdigest(),
        "resolvable": True,
        "excerpt": str(row["excerpt"]),
    } for row in rows)


def _allowed_subject_ids(project_id: str, sections: Sequence[Mapping[str, Any]]) -> Tuple[str, ...]:
    values = {f"project:{project_id}", project_id}
    for section in sections:
        values.update(str(item) for item in section.get("module_hints", ()) if str(item))
        for raw in section.get("symbols", ()):
            symbol = str(raw).strip().strip("`")
            if not symbol:
                continue
            values.add(symbol)
            name = symbol.split("(", 1)[0].strip()
            if name:
                values.update({name, f"api:{name}", f"symbol:{name}"})
            if "/" in symbol or symbol.endswith((".c", ".cc", ".cpp", ".h", ".hpp")):
                values.add(f"path:{symbol}")
    return tuple(sorted(values))


def _sections_for_sources(index: SourceIndex, source_ids: Sequence[str], max_source_chars: Optional[int]) -> Tuple[Dict[str, Any], ...]:
    """Project bounded source sections into the Compiler input envelope."""

    if not source_ids or (max_source_chars is not None and max_source_chars <= 0):
        return ()
    placeholders = ",".join("?" for _ in source_ids)
    rows = index.connection.execute(
        f"SELECT * FROM sections WHERE source_id IN ({placeholders}) ORDER BY source_id, start_line, section_id",
        tuple(source_ids),
    ).fetchall()
    links: Dict[str, list] = {}
    for row in index.connection.execute(
        f"SELECT source_id, target FROM links WHERE source_id IN ({placeholders}) ORDER BY source_id, target",
        tuple(source_ids),
    ).fetchall():
        links.setdefault(str(row["source_id"]), []).append(str(row["target"]))
    selected = []
    used = 0
    for row in rows:
        excerpt = str(row["excerpt"])
        # Keep whole sections only; truncating text would invalidate its
        # source digest and make later DocumentRef resolution ambiguous.
        cost = len(excerpt)
        if max_source_chars is not None and selected and used + cost > max_source_chars:
            break
        if max_source_chars is not None and not selected and cost > max_source_chars:
            excerpt = excerpt[:max_source_chars]
            cost = len(excerpt)
        selected.append({
            "schema_version": "zscope.document-section.v1",
            "section_id": row["section_id"],
            "source_id": row["source_id"],
            "heading_path": json.loads(row["heading_path_json"]),
            "heading_level": int(row["heading_level"]),
            "start_line": int(row["start_line"]),
            "end_line": int(row["end_line"]),
            "text_digest": row["text_digest"],
            "excerpt": excerpt,
            "symbols": json.loads(row["symbols_json"]),
            "module_hints": json.loads(row["module_hints_json"]),
            "normative_terms": json.loads(row["normative_terms_json"]),
            "link_targets": links.get(str(row["source_id"]), []),
        })
        used += cost
    return tuple(selected)


def build_ingest_workset(
    manifest: Union[SourceManifest, Mapping[str, Any]],
    *,
    source_index: SourceIndex,
    base_revision_id: Optional[str] = None,
    added_source_ids: Sequence[str] = (),
    changed_source_ids: Sequence[str] = (),
    removed_source_ids: Sequence[str] = (),
    target_page_ids: Sequence[str] = ("page_project",),
    allowed_existing_pages: Sequence[str] = (),
    max_pages: Optional[int] = None,
    max_source_chars: Optional[int] = None,
    max_output_chars: Optional[int] = None,
    max_wall_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """Create a fixed-schema workset from accepted source IDs only."""

    source_manifest = _manifest(manifest)
    accepted = {item.source_id for item in source_manifest.accepted}
    added = tuple(dict.fromkeys(str(item) for item in added_source_ids))
    changed = tuple(dict.fromkeys(str(item) for item in changed_source_ids))
    removed = tuple(dict.fromkeys(str(item) for item in removed_source_ids))
    all_changed = set(added) | set(changed) | set(removed)
    if not all_changed:
        all_changed = accepted
        added = tuple(sorted(accepted))
    # Added/changed sources must be present in the current accepted manifest.
    # Removed IDs intentionally come from the previous manifest and therefore
    # are absent from the current one; retaining them in the workset is what
    # lets the store mark their refs/constraints stale.
    if (set(added) | set(changed)) - accepted:
        unknown = sorted((set(added) | set(changed)) - accepted)
        raise ValueError(f"workset source IDs are not accepted by manifest: {unknown}")
    if set(added) & set(changed) or set(added) & set(removed) or set(changed) & set(removed):
        raise ValueError("added_source_ids, changed_source_ids and removed_source_ids must be disjoint")
    page_ids = tuple(dict.fromkeys(str(item) for item in target_page_ids if str(item)))
    if not page_ids:
        raise ValueError("target_page_ids must not be empty")
    active_source_ids = tuple(sorted(set(added) | set(changed)))
    refs = _refs_for_sources(source_index, active_source_ids)
    source_sections = _sections_for_sources(source_index, active_source_ids, max_source_chars)
    ref_catalog = _ref_catalog_for_sources(source_index, active_source_ids)
    allowed_subject_ids = _allowed_subject_ids(source_manifest.project_id, source_sections)
    result = {
        "schema_version": "zscope.wiki-ingest-workset.v1",
        "workset_id": stable_id("workset", source_manifest.project_id, source_manifest.source_manifest_digest, base_revision_id or "none", *sorted(all_changed)),
        "project_id": source_manifest.project_id,
        "base_revision_id": base_revision_id,
        "source_manifest_digest": source_manifest.source_manifest_digest,
        "added_source_ids": list(added),
        "changed_source_ids": list(changed),
        "removed_source_ids": list(removed),
        "target_page_ids": list(page_ids),
        "allowed_source_refs": list(refs),
        "source_ref_catalog": list(ref_catalog),
        "source_sections": list(source_sections),
        "allowed_subject_ids": list(allowed_subject_ids),
        "allowed_existing_pages": list(dict.fromkeys(str(item) for item in allowed_existing_pages)),
        "limits": {
            "max_pages": max_pages,
            "max_source_chars": max_source_chars,
            "max_output_chars": max_output_chars,
            "max_wall_seconds": max_wall_seconds,
        },
        "created_at": _now(),
    }
    from ..schema import SchemaValidationError, validate_instance

    try:
        validate_instance(result, "zscope.wiki-ingest-workset.v1")
    except SchemaValidationError as exc:
        raise ValueError("invalid IngestWorkset: " + "; ".join(exc.errors)) from exc
    return result
