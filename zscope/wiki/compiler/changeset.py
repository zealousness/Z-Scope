"""Cross-field validation for constraint-only WikiChangeSet output."""

from __future__ import annotations

from typing import Any, Mapping, Set


class ChangeSetValidationError(ValueError):
    pass


_OUTCOMES = {"changed", "background_only", "extraction_failed", "source_rejected"}
_STATUSES = {
    "constraints_found",
    "no_constraints_found",
    "extraction_failed",
    "source_rejected",
}
_TOP = {
    "schema_version",
    "workset_id",
    "base_revision_id",
    "outcome",
    "source_results",
    "constraint_proposals",
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
    raw_source_results = value["source_results"]
    _ensure(
        isinstance(raw_source_results, list) and bool(raw_source_results),
        "source_results must be non-empty",
    )
    allowed_refs = _ids(workset.get("allowed_source_refs"))
    changed_sources = (
        _ids(workset.get("added_source_ids"))
        | _ids(workset.get("changed_source_ids"))
        | _ids(workset.get("removed_source_ids"))
    )
    allowed_subject_ids = _ids(workset.get("allowed_subject_ids"))
    for result in value["source_results"]:
        _ensure(
            set(result)
            <= {"source_ref", "extraction_status", "source_refs_used", "reason"},
            "unknown source_result field",
        )
        for key in (
            "source_ref",
            "extraction_status",
            "source_refs_used",
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
    limits_value = workset.get("limits")
    limits: Mapping[str, Any] = limits_value if isinstance(limits_value, Mapping) else {}
    proposals = value["constraint_proposals"]
    _ensure(all(isinstance(item, Mapping) for item in proposals), "invalid constraint proposal")
    max_constraints = limits.get("max_constraints")
    _ensure(
        max_constraints is None or len(proposals) <= int(max_constraints),
        "constraint proposals exceed workset max_constraints",
    )
    for proposal in proposals:
        _ensure(
            str(proposal.get("schema_version")) == "zscope.project-constraint-proposal.v1",
            "invalid constraint schema_version",
        )
        _ensure(
            str(proposal.get("subject_kind", ""))
            in {"project", "module", "api", "symbol", "resource", "lock", "type", "configuration", "topic"},
            "invalid constraint subject_kind",
        )
        _ensure(
            _ids(proposal.get("source_refs")) <= allowed_refs,
            "constraint source_refs escape workset",
        )
        _ensure(
            str(proposal.get("subject_id", "")) in allowed_subject_ids,
            "constraint subject escapes workset",
        )
    if outcome == "background_only":
        _ensure(not proposals, "background_only cannot create constraints")
        _ensure(
            all(item["extraction_status"] == "no_constraints_found" for item in value["source_results"]),
            "background_only source_results must use no_constraints_found",
        )
    elif outcome == "changed":
        _ensure(bool(proposals), "changed must contain constraint proposals")
        _ensure(
            any(item["extraction_status"] == "constraints_found" for item in value["source_results"]),
            "changed requires a successful extraction",
        )
    elif outcome == "extraction_failed":
        _ensure(not proposals, "extraction_failed cannot publish content")
        _ensure(
            any(
                item["extraction_status"] == "extraction_failed" for item in value["source_results"]
            ),
            "extraction_failed requires failed source result",
        )
    elif outcome == "source_rejected":
        _ensure(not proposals, "source_rejected cannot publish content")
        _ensure(
            all(str(item["source_ref"]).startswith("docdesc_") for item in value["source_results"]),
            "source_rejected sources must be docdesc",
        )
    return dict(value)
