"""Program-owned bounded IngestWorkset construction."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
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


def _ref_catalog_for_sources(
    index: SourceIndex, source_ids: Sequence[str]
) -> Tuple[Dict[str, Any], ...]:
    if not source_ids:
        return ()
    placeholders = ",".join("?" for _ in source_ids)
    rows = index.connection.execute(
        f"SELECT s.section_id, s.source_id, s.heading_path_json, s.start_line, s.end_line, s.excerpt, "
        f"s.fragment_index, s.fragment_count, s.char_start, s.char_end, d.relative_path, d.content_digest "
        f"FROM sections s JOIN documents d ON d.source_id=s.source_id WHERE s.source_id IN ({placeholders}) "
        "ORDER BY s.source_id, s.start_line, s.section_id",
        tuple(source_ids),
    ).fetchall()
    result = []
    for row in rows:
        item = {
            "schema_version": "zscope.document-ref.v1",
            "ref_id": stable_id("docref", row["source_id"], row["section_id"]),
            "source_id": row["source_id"],
            "relative_path": row["relative_path"],
            "heading_path": json.loads(row["heading_path_json"]),
            "start_line": int(row["start_line"]),
            "end_line": int(row["end_line"]),
            "source_digest": row["content_digest"],
            "excerpt_digest": "sha256:"
            + hashlib.sha256(str(row["excerpt"]).encode("utf-8")).hexdigest(),
            "resolvable": True,
            "excerpt": str(row["excerpt"]),
        }
        for name in ("fragment_index", "fragment_count", "char_start", "char_end"):
            if row[name] is not None:
                item[name] = int(row[name])
        result.append(item)
    return tuple(result)


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


def _sections_for_sources(index: SourceIndex, source_ids: Sequence[str]) -> Tuple[Dict[str, Any], ...]:
    """Project bounded source sections into the Compiler input envelope."""

    if not source_ids:
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
    for row in rows:
        excerpt = str(row["excerpt"])
        # Keep whole sections only; truncating text would invalidate its
        # source digest and make later DocumentRef resolution ambiguous.
        item = {
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
            }
        for name in ("fragment_index", "fragment_count", "char_start", "char_end"):
            if row[name] is not None:
                item[name] = int(row[name])
        selected.append(item)
    return tuple(selected)


def build_ingest_workset(
    manifest: Union[SourceManifest, Mapping[str, Any]],
    *,
    source_index: SourceIndex,
    base_revision_id: Optional[str] = None,
    added_source_ids: Sequence[str] = (),
    changed_source_ids: Sequence[str] = (),
    removed_source_ids: Sequence[str] = (),
    target_page_ids: Optional[Sequence[str]] = None,
    allowed_existing_pages: Sequence[str] = (),
    max_constraints: Optional[int] = None,
    max_wall_seconds: Optional[int] = None,
    initial: Optional[bool] = None,
) -> Dict[str, Any]:
    """Create a fixed-schema workset from accepted source IDs only."""

    source_manifest = _manifest(manifest)
    accepted = {item.source_id for item in source_manifest.accepted}
    added = tuple(dict.fromkeys(str(item) for item in added_source_ids))
    changed = tuple(dict.fromkeys(str(item) for item in changed_source_ids))
    removed = tuple(dict.fromkeys(str(item) for item in removed_source_ids))
    all_changed = set(added) | set(changed) | set(removed)
    # An explicitly supplied ``initial=False`` empty delta is a real no-op:
    # callers use it for a manifest-only freshness refresh when accepted
    # Markdown did not change.  Preserve the empty sets so the deterministic
    # compiler can publish the existing Wiki content without invoking an LLM.
    # The historical default (no delta and no explicit initial marker) still
    # bootstraps all accepted sources for standalone initial worksets.
    explicit_noop = not all_changed and initial is False
    if not all_changed and not explicit_noop:
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
        raise ValueError(
            "added_source_ids, changed_source_ids and removed_source_ids must be disjoint"
        )
    # Page-target arguments remain accepted for configuration/API compatibility
    # but are intentionally absent from the constraint-only compiler envelope.
    _ = (target_page_ids, allowed_existing_pages)
    active_source_ids = tuple(sorted(set(added) | set(changed)))
    refs = _refs_for_sources(source_index, active_source_ids)
    source_sections = _sections_for_sources(source_index, active_source_ids)
    ref_catalog = _ref_catalog_for_sources(source_index, active_source_ids)
    allowed_subject_ids = _allowed_subject_ids(source_manifest.project_id, source_sections)
    result = {
        "schema_version": "zscope.wiki-ingest-workset.v1",
        "workset_id": stable_id(
            "workset",
            source_manifest.project_id,
            source_manifest.source_manifest_digest,
            base_revision_id or "none",
            *sorted(all_changed),
        ),
        "project_id": source_manifest.project_id,
        "base_revision_id": base_revision_id,
        "source_manifest_digest": source_manifest.source_manifest_digest,
        "added_source_ids": list(added),
        "changed_source_ids": list(changed),
        "removed_source_ids": list(removed),
        "allowed_source_refs": list(refs),
        "source_ref_catalog": list(ref_catalog),
        "source_sections": list(source_sections),
        "allowed_subject_ids": list(allowed_subject_ids),
        "limits": {
            "max_constraints": max_constraints,
            "max_wall_seconds": max_wall_seconds,
        },
        "created_at": _now(),
    }
    if initial is not None:
        result["initial"] = bool(initial)
    from ..schema import SchemaValidationError, validate_instance

    try:
        validate_instance(result, "zscope.wiki-ingest-workset.v1")
    except SchemaValidationError as exc:
        raise ValueError("invalid IngestWorkset: " + "; ".join(exc.errors)) from exc
    return result


def build_llm_input_projection(workset: Mapping[str, Any]) -> Dict[str, Any]:
    """Project one document Workset into the model-facing input.

    Compiler calls are intentionally document-scoped.  The full Workset is an
    orchestration and validation envelope; it must never be serialized to the
    model.  A projection contains only the relative document path, a stable
    human title, the deterministic change kind and source excerpts.  Identity,
    allowlists and limits remain program-owned and are checked against the
    original Workset when the terminal tool is submitted.
    """

    if not isinstance(workset, Mapping):
        raise TypeError("workset must be a mapping")

    def _ids(name: str) -> list[str]:
        value = workset.get(name, ())
        if isinstance(value, str):
            value = (value,)
        if not isinstance(value, (list, tuple, set)):
            return []
        if isinstance(value, set):
            value = sorted(value, key=str)
        return list(dict.fromkeys(str(item) for item in value if str(item)))

    added = _ids("added_source_ids")
    changed = _ids("changed_source_ids")
    removed = _ids("removed_source_ids")

    active_source_ids = tuple(dict.fromkeys((*added, *changed)))
    if not active_source_ids:
        if removed:
            raise ValueError("removed sources do not enter the Wiki Compiler")
        raise ValueError("noop Worksets do not enter the Wiki Compiler")
    if len(active_source_ids) != 1:
        raise ValueError("build_llm_input_projection requires exactly one Markdown document")
    source_id = active_source_ids[0]

    # The analyzer may explicitly mark a bootstrap compilation (for example,
    # when the parent revision is only a deterministic skeleton).  Standalone
    # callers retain the base-revision fallback for compatibility.
    initial_marker = workset.get("initial")
    if initial_marker is True or (
        initial_marker is not False
        and added
        and not changed
        and not workset.get("base_revision_id")
    ):
        change = "initial"
    elif added or changed or removed:
        change = "incremental"
    else:
        change = "noop"

    catalog = {
        str(item.get("ref_id")): item
        for item in workset.get("source_ref_catalog", ())
        if isinstance(item, Mapping) and str(item.get("ref_id", ""))
    }
    sections = []
    active_source_set = {source_id}
    for raw in workset.get("source_sections", ()):
        if not isinstance(raw, Mapping):
            raise ValueError("source section must be an object")
        section_source_id = str(raw.get("source_id", ""))
        section_id = str(raw.get("section_id", ""))
        if not section_source_id or not section_id:
            raise ValueError("source section lacks source_id or section_id")
        if section_source_id not in active_source_set:
            raise ValueError(
                f"source section source_id is outside active delta: {section_source_id}"
            )
        ref_id = stable_id("docref", section_source_id, section_id)
        ref = catalog.get(ref_id)
        if ref is None:
            raise ValueError(f"source section ref is missing from catalog: {ref_id}")
        if str(ref.get("source_id", "")) != section_source_id:
            raise ValueError(f"source ref source_id mismatch: {ref_id}")
        if not str(ref.get("relative_path", "")):
            raise ValueError(f"source ref lacks relative_path: {ref_id}")
        section_projection = {
                "ref_id": ref_id,
                "heading_path": [str(item) for item in raw.get("heading_path", ())],
                "start_line": int(raw.get("start_line", 0)),
                "end_line": int(raw.get("end_line", 0)),
                "text": str(raw.get("excerpt", "")),
            }
        for name in ("fragment_index", "fragment_count", "char_start", "char_end"):
            if raw.get(name) is not None:
                section_projection[name] = int(raw[name])
        sections.append(section_projection)

    sections.sort(
        key=lambda item: (
            item["start_line"],
            item["end_line"],
            item["ref_id"],
        )
    )
    ref = next(
        (
            item
            for item in workset.get("source_ref_catalog", ())
            if isinstance(item, Mapping) and str(item.get("source_id", "")) == source_id
        ),
        None,
    )
    if ref is None:
        raise ValueError(f"source document is missing from ref catalog: {source_id}")
    file_path = str(ref.get("relative_path", "")).strip()
    if not file_path:
        raise ValueError(f"source document has no relative path: {source_id}")
    normalized_path = file_path.replace("\\", "/")
    path_obj = PurePosixPath(normalized_path)
    if (
        path_obj.is_absolute()
        or re.match(r"^[A-Za-z]:/", normalized_path)
        or ".." in path_obj.parts
        or re.search(r"[\x00-\x1f\x7f]", normalized_path)
    ):
        raise ValueError(f"source document path is not project-relative: {file_path}")
    file_path = normalized_path
    while file_path.startswith("./"):
        file_path = file_path[2:]
    if not file_path:
        raise ValueError(f"source document path is invalid: {source_id}")
    # The project title is intentionally program-owned.  Callers may provide a
    # display title in a private Workset field; project_id is the stable
    # fallback used by the normal ingestion path.
    title = str(
        workset.get("title")
        or workset.get("project_title")
        or workset.get("project_id")
        or file_path
    ).strip()
    if not title:
        title = file_path
    if len(title) > 240 or re.search(r"[\x00-\x1f\x7f]", title):
        raise ValueError("source document title is invalid")
    return {
        "file_path": file_path,
        "title": title,
        "change": change,
        "sections": sections,
    }


def split_workset_by_document(workset: Mapping[str, Any]) -> Tuple[Dict[str, Any], ...]:
    """Return one validation Workset per added/changed Markdown document.

    The parent Workset remains the publication boundary.  Child Worksets only
    narrow source/ref/subject allowlists so an individual model call cannot
    cite another document.  ``removed_source_ids`` are deliberately omitted;
    removed-only changes are handled deterministically by ``WikiCompiler``.
    """

    if not isinstance(workset, Mapping):
        raise TypeError("workset must be a mapping")

    def _ids(name: str) -> Tuple[str, ...]:
        value = workset.get(name, ())
        if isinstance(value, str):
            value = (value,)
        if not isinstance(value, (list, tuple, set)):
            return ()
        return tuple(dict.fromkeys(str(item) for item in value if str(item)))

    added = _ids("added_source_ids")
    changed = _ids("changed_source_ids")
    active = tuple(dict.fromkeys((*added, *changed)))
    if not active:
        return ()
    catalog = {
        str(item.get("ref_id")): item
        for item in workset.get("source_ref_catalog", ())
        if isinstance(item, Mapping) and str(item.get("ref_id", ""))
    }
    children = []
    from ..schema import SchemaValidationError, validate_instance

    for source_id in sorted(active):
        child = dict(workset)
        child["workset_id"] = stable_id("workset", str(workset.get("workset_id", "")), source_id)
        child["added_source_ids"] = [source_id] if source_id in added else []
        child["changed_source_ids"] = [source_id] if source_id in changed else []
        child["removed_source_ids"] = []
        refs = {
            str(ref.get("ref_id"))
            for ref in catalog.values()
            if str(ref.get("source_id", "")) == source_id
        }
        child["allowed_source_refs"] = sorted(refs)
        child["source_ref_catalog"] = [
            ref
            for ref in workset.get("source_ref_catalog", ())
            if isinstance(ref, Mapping) and str(ref.get("ref_id", "")) in refs
        ]
        child["source_sections"] = [
            section
            for section in workset.get("source_sections", ())
            if isinstance(section, Mapping) and str(section.get("source_id", "")) == source_id
        ]
        child["allowed_subject_ids"] = list(
            _allowed_subject_ids(str(workset.get("project_id", "")), child["source_sections"])
        )
        try:
            validate_instance(child, "zscope.wiki-ingest-workset.v1")
        except SchemaValidationError as exc:
            raise ValueError("invalid document Workset: " + "; ".join(exc.errors)) from exc
        children.append(child)
    return tuple(children)


# Descriptive alias for callers that prefer a builder-style API.
build_document_worksets = split_workset_by_document
