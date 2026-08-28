"""Cross-field validation for WikiChangeSet model output."""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Optional, Set

from ..page_format import page_markdown_errors, wikilink_targets


class ChangeSetValidationError(ValueError):
    pass


_OUTCOMES = {"changed", "background_only", "conflict_only", "extraction_failed", "source_rejected"}
_STATUSES = {
    "constraints_found",
    "no_constraints_found",
    "background_page_updated",
    "conflict_detected",
    "extraction_failed",
    "source_rejected",
}
_TOP = {
    "schema_version",
    "workset_id",
    "base_revision_id",
    "outcome",
    "source_results",
    "page_changes",
    "constraint_proposals",
    "edge_proposals",
    "retire_proposals",
    "unresolved_conflicts",
    "summary",
    "compiler",
}


def _ensure(condition: bool, message: str) -> None:
    if not condition:
        raise ChangeSetValidationError(message)


def _ids(values: Any) -> Set[str]:
    return {str(value) for value in values or ()}


def validate_changeset(value: Mapping[str, Any], workset: Mapping[str, Any]) -> dict:
    """Validate fields and all outcome-specific invariants; return a copy."""

    _ensure(isinstance(value, Mapping), "WikiChangeSet must be an object")
    # Validate the materialized Draft 2020-12 contract first.  The local
    # registry has a dependency-free subset validator, so compiler output is
    # rejected consistently even when ``jsonschema`` is not installed.
    from ..schema import SchemaValidationError, validate_instance

    try:
        validate_instance(value, "zscope.wiki-changeset.v1")
    except SchemaValidationError as exc:
        raise ChangeSetValidationError(
            "WikiChangeSet schema validation failed: " + "; ".join(exc.errors)
        ) from exc
    _ensure(set(value) <= _TOP, "WikiChangeSet contains unknown fields")
    for key in _TOP - {"compiler"}:
        _ensure(key in value, f"WikiChangeSet missing {key}")
    _ensure(
        value["schema_version"] == "zscope.wiki-changeset.v1", "invalid ChangeSet schema_version"
    )
    _ensure(value["workset_id"] == workset.get("workset_id"), "workset_id mismatch")
    _ensure(
        value["base_revision_id"] == workset.get("base_revision_id"), "base_revision_id mismatch"
    )
    if "compiler" in value:
        compiler = value["compiler"]
        _ensure(isinstance(compiler, Mapping), "compiler metadata must be an object")
        _ensure(
            str(compiler.get("kind")) in {"deterministic", "llm", "mixed"}, "invalid compiler kind"
        )
        _ensure(bool(str(compiler.get("identity", "")).strip()), "compiler identity is required")
    outcome = value["outcome"]
    _ensure(outcome in _OUTCOMES, f"invalid ChangeSet outcome: {outcome}")
    _ensure(
        isinstance(value["source_results"], list) and value["source_results"],
        "source_results must be non-empty",
    )
    allowed_refs = _ids(workset.get("allowed_source_refs"))
    allowed_pages = _ids(workset.get("target_page_ids")) | _ids(
        workset.get("allowed_existing_pages")
    )
    changed_sources = (
        _ids(workset.get("added_source_ids"))
        | _ids(workset.get("changed_source_ids"))
        | _ids(workset.get("removed_source_ids"))
    )
    allowed_subject_ids = _ids(workset.get("allowed_subject_ids"))
    for result in value["source_results"]:
        _ensure(
            set(result)
            <= {"source_ref", "extraction_status", "source_refs_used", "constraint_ids", "reason"},
            "unknown source_result field",
        )
        for key in (
            "source_ref",
            "extraction_status",
            "source_refs_used",
            "constraint_ids",
            "reason",
        ):
            _ensure(key in result, f"source_result missing {key}")
        _ensure(result["extraction_status"] in _STATUSES, "invalid extraction_status")
        source_ref = str(result["source_ref"])
        if source_ref.startswith("docsrc_") and source_ref != "docsrc_none":
            _ensure(source_ref in changed_sources, "source_result source_ref is outside workset")
        used = _ids(result["source_refs_used"])
        _ensure(used <= allowed_refs, "source_refs_used escapes workset allowlist")
        if outcome == "source_rejected":
            _ensure(
                str(result["source_ref"]).startswith("docdesc_"),
                "source_rejected requires docdesc source_ref",
            )
            _ensure(not used, "source_rejected cannot use accepted source refs")
        else:
            _ensure(
                not str(result["source_ref"]).startswith("docdesc_"),
                "docdesc source_ref is only valid for source_rejected",
            )
    pages = value["page_changes"]
    _ensure(isinstance(pages, list), "page_changes must be a list")
    limits = workset.get("limits") if isinstance(workset.get("limits"), Mapping) else {}
    max_pages = limits.get("max_pages")
    _ensure(
        max_pages is None or len(pages) <= int(max_pages), "page_changes exceed workset max_pages"
    )
    page_ids = [str(change.get("page_id")) for change in pages]
    _ensure(len(page_ids) == len(set(page_ids)), "page_changes contain duplicate page_id")
    output_chars = sum(len(str(change.get("markdown") or "")) for change in pages)
    max_output_chars = limits.get("max_output_chars")
    _ensure(
        max_output_chars is None or output_chars <= int(max_output_chars),
        "page_changes exceed workset max_output_chars",
    )
    upsert_links = {}
    for change in pages:
        _ensure(
            str(change.get("page_id")) in allowed_pages,
            "page change escapes workset page allowlist",
        )
        _ensure(change.get("operation") in {"upsert", "retire"}, "invalid page operation")
        _ensure(str(change.get("page_id", "")).startswith("page_"), "invalid page_id")
        _ensure(
            not (_ids(change.get("source_refs_used")) - allowed_refs),
            "page source refs escape workset",
        )
        if change["operation"] == "upsert":
            _ensure(
                isinstance(change.get("markdown"), str) and bool(change["markdown"].strip()),
                "upsert requires markdown",
            )
            markdown = str(change["markdown"])
            errors = page_markdown_errors(markdown)
            _ensure(not errors, "invalid page markdown: " + ", ".join(errors))
            markdown_refs = set(re.findall(r"\[(docref_[a-z0-9_:-]+)\]", markdown))
            _ensure(markdown_refs <= allowed_refs, "page markdown refs escape workset")
            _ensure(
                _ids(change.get("source_refs_used")) <= markdown_refs,
                "page source_refs_used must appear in 来源索引",
            )
            targets = set(wikilink_targets(markdown))
            _ensure(targets <= allowed_pages, "page wikilink escapes workset page allowlist")
            upsert_links[str(change["page_id"])] = targets
        else:
            _ensure("markdown" not in change, "retire must not include markdown")
    if len(upsert_links) > 1:
        upsert_ids = set(upsert_links)
        for page_id, targets in upsert_links.items():
            _ensure(
                bool(targets & (upsert_ids - {page_id})),
                "multi-page upsert pages must link to another changed page",
            )
    proposals = value["constraint_proposals"]
    edges = value["edge_proposals"]
    retires = value["retire_proposals"]
    conflicts = value["unresolved_conflicts"]
    _ensure(all(isinstance(item, Mapping) for item in proposals), "invalid constraint proposal")
    _ensure(all(isinstance(item, Mapping) for item in edges), "invalid edge proposal")
    for proposal in proposals:
        _ensure(
            str(proposal.get("schema_version")) == "zscope.project-constraint.v1",
            "invalid constraint schema_version",
        )
        _ensure(
            str(proposal.get("authority")) == "documented_contract",
            "constraint authority must be documented_contract",
        )
        _ensure(
            str(proposal.get("constraint_id", "")).startswith("constraint_"),
            "invalid constraint_id",
        )
        _ensure(
            _ids(proposal.get("source_refs")) <= allowed_refs,
            "constraint source_refs escape workset",
        )
        _ensure(
            _ids(proposal.get("page_refs")) <= allowed_pages, "constraint page_refs escape workset"
        )
        subject = proposal.get("subject") if isinstance(proposal.get("subject"), Mapping) else {}
        _ensure(
            str(subject.get("canonical_id", "")) in allowed_subject_ids,
            "constraint subject escapes workset",
        )
    proposed_constraint_ids = {
        str(proposal.get("constraint_id", "")) for proposal in proposals
    }
    allowed_edge_endpoint_ids = (
        allowed_subject_ids | allowed_pages | proposed_constraint_ids
    )
    for edge in edges:
        _ensure(
            str(edge.get("schema_version")) == "zscope.wiki-edge.v1", "invalid edge schema_version"
        )
        _ensure(str(edge.get("edge_id", "")).startswith("wikiedge_"), "invalid edge_id")
        _ensure(_ids(edge.get("source_refs")) <= allowed_refs, "edge source_refs escape workset")
        _ensure(
            str(edge.get("from_id", "")) in allowed_edge_endpoint_ids,
            "edge from_id escapes workset",
        )
        _ensure(
            str(edge.get("to_id", "")) in allowed_edge_endpoint_ids,
            "edge to_id escapes workset",
        )
    if outcome == "background_only":
        _ensure(not proposals, "background_only cannot create constraints")
        _ensure(
            all(
                item["extraction_status"] in {"no_constraints_found", "background_page_updated"}
                for item in value["source_results"]
            ),
            "background_only source_results must use no_constraints_found or background_page_updated",
        )
        _ensure(not edges and not retires, "background_only cannot mutate graph")
    elif outcome == "changed":
        _ensure(bool(pages or proposals or edges or retires), "changed must contain a change")
        _ensure(
            any(
                item["extraction_status"] in {"constraints_found", "background_page_updated"}
                for item in value["source_results"]
            ),
            "changed requires a successful extraction",
        )
    elif outcome == "conflict_only":
        _ensure(bool(conflicts), "conflict_only requires unresolved_conflicts")
        _ensure(
            all(item.get("status") == "conflicted" for item in proposals),
            "conflict proposals must be conflicted",
        )
    elif outcome == "extraction_failed":
        _ensure(
            not pages and not proposals and not edges and not retires,
            "extraction_failed cannot publish content",
        )
        _ensure(
            any(
                item["extraction_status"] == "extraction_failed" for item in value["source_results"]
            ),
            "extraction_failed requires failed source result",
        )
    elif outcome == "source_rejected":
        _ensure(
            not pages and not proposals and not edges and not retires,
            "source_rejected cannot publish content",
        )
        _ensure(
            all(str(item["source_ref"]).startswith("docdesc_") for item in value["source_results"]),
            "source_rejected sources must be docdesc",
        )
    for retire in retires:
        _ensure(isinstance(retire, Mapping), "invalid retire proposal")
        object_type = str(retire.get("object_type", ""))
        object_id = str(retire.get("object_id", ""))
        _ensure(object_type in {"page", "constraint", "edge"}, "invalid retire object_type")
        if object_type == "page":
            _ensure(object_id in allowed_pages, "retired page escapes workset")
        elif object_type == "constraint":
            _ensure(object_id.startswith("constraint_"), "invalid retired constraint")
        else:
            _ensure(object_id.startswith("wikiedge_"), "invalid retired edge")
    for conflict in conflicts:
        _ensure(isinstance(conflict, Mapping), "invalid unresolved conflict")
        _ensure(
            len(_ids(conflict.get("constraint_ids"))) >= 2,
            "unresolved conflict needs two constraints",
        )
    return dict(value)
