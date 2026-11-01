"""Structural finding-root projection for canonical validation outcomes.

This module never deletes a validation outcome.  It selects one display
primary for proof-equivalent security obligations and turns the remaining
outcomes into auditable ``deduplicated_alias`` terminal records.  Text
similarity, detector names and LLM prose are deliberately excluded.
"""

from __future__ import annotations

from ..common.issue_identity import issue_build_context_id

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple


FINDING_ROOT_VERSION = "zscope.finding-root.v1"
_DISPLAY_DISPOSITIONS = frozenset({"confirmed", "needs_review"})
_CLEANUP_FAMILIES = frozenset(
    {
        "memory_leak",
        "resource_leak",
        "fd_leak",
        "file_descriptor_leak",
        "cleanup",
    }
)
_COMPOSITE_PROOF_KINDS = frozenset(
    {
        "missing_cleanup_path",
        "same_function_owned_member_cleanup_gap",
        "incomplete_owner_cleanup",
        "owned_member_left_live_when_parent_released",
    }
)
_REGION_SCOPED_FAMILIES = frozenset({"file_type_validation"})
_EXACT_SINK_ROOT_PROOF_KINDS = {
    # Publication detectors commonly describe the allocation object with
    # detector-local provenance (for example ``function:line:variable`` versus
    # the bare variable).  Once one complete deterministic proof establishes
    # publication-before-initialization at an exact CFG sink, another confirmed
    # observation of that same statement is provenance for the same repair
    # responsibility, not a second actionable root.
    "object_publication": frozenset({"ordered_publication_before_initialization"}),
}


@dataclass(frozen=True)
class FindingRootProjection:
    outcomes: Tuple[Dict[str, Any], ...]
    finding_root_count: int
    finding_root_alias_count: int


def project_finding_roots(
    outcomes: Sequence[Mapping[str, Any]],
) -> FindingRootProjection:
    """Return deterministic primary/alias outcomes without losing evidence."""

    copied = [deepcopy(dict(item)) for item in outcomes]
    conditional = [item for item in copied if item.get("analysis_scope") == "conditional_source_branch"]
    copied = [item for item in copied if item.get("analysis_scope") != "conditional_source_branch"]
    attachment_buckets: Dict[str, List[Dict[str, Any]]] = {}
    for item in copied:
        signature = _attachment_signature(item)
        if signature:
            attachment_buckets.setdefault(signature, []).append(item)
    attached_to_primary: Dict[str, List[Dict[str, Any]]] = {}
    attached_ids: set[int] = set()
    for group in attachment_buckets.values():
        confirmed = [
            item
            for item in group
            if str(item.get("candidate_disposition") or "").lower() == "confirmed"
            and isinstance(item.get("decision_proof"), Mapping)
            and str(item["decision_proof"].get("completeness") or "").lower() == "complete"
        ]
        review = [
            item
            for item in group
            if str(item.get("candidate_disposition") or "").lower() == "needs_review"
        ]
        if not confirmed or not review:
            continue
        primary = sorted(confirmed, key=_primary_sort_key)[0]
        key = str(primary.get("candidate_uid") or primary.get("validation_cluster_uid") or "")
        if not key:
            continue
        attached_to_primary.setdefault(key, []).extend(review)
        attached_ids.update(id(item) for item in review)

    buckets: Dict[str, List[Dict[str, Any]]] = {}
    passthrough: List[Dict[str, Any]] = []
    exact_sink_buckets: Dict[str, List[Dict[str, Any]]] = {}
    for item in copied:
        if id(item) in attached_ids:
            continue
        signature = _exact_sink_root_signature(item)
        if signature:
            exact_sink_buckets.setdefault(signature, []).append(item)
    exact_sink_groups = {
        signature: group
        for signature, group in exact_sink_buckets.items()
        if len(group) > 1 and any(_has_exact_sink_anchor_proof(item) for item in group)
    }
    exact_sink_item_ids = {id(item) for group in exact_sink_groups.values() for item in group}
    for signature, group in exact_sink_groups.items():
        buckets[f"exact-sink:{signature}"] = group
    for item in copied:
        if id(item) in attached_ids:
            continue
        if id(item) in exact_sink_item_ids:
            continue
        disposition = str(item.get("candidate_disposition") or "").lower()
        if disposition not in _DISPLAY_DISPOSITIONS:
            passthrough.append(item)
            continue
        signature = _root_signature(item)
        if not signature:
            passthrough.append(item)
            continue
        buckets.setdefault(signature, []).append(item)

    projected: List[Dict[str, Any]] = list(passthrough) + conditional
    alias_count = 0
    for signature in sorted(buckets):
        group = sorted(buckets[signature], key=_primary_sort_key)
        primary = group[0]
        root_uid = (
            "ROOT_"
            + hashlib.sha256(f"{FINDING_ROOT_VERSION}|{signature}".encode("utf-8")).hexdigest()[:32]
        )
        subjects = sorted(
            {subject for subject in (_subject_identity(item) for item in group) if subject}
        )
        primary["finding_root_version"] = FINDING_ROOT_VERSION
        primary["finding_root_uid"] = root_uid
        primary["affected_subjects"] = subjects
        primary["finding_root_alias_uids"] = sorted(
            str(item.get("candidate_uid") or item.get("validation_cluster_uid") or "")
            for item in group[1:]
            if item.get("candidate_uid") or item.get("validation_cluster_uid")
        )
        primary["finding_root_alias_count"] = len(group) - 1
        primary["alias_occurrence_uids"] = _unique_strings(
            list(primary.get("alias_occurrence_uids") or [])
            + [occurrence for item in group[1:] for occurrence in _occurrence_uids(item)]
        )
        primary["occurrence_uids"] = _unique_strings(
            [occurrence for item in group for occurrence in _occurrence_uids(item)]
        )
        primary["occurrence_count"] = len(primary["occurrence_uids"])
        projected.append(primary)

        for item in group[1:]:
            alias = item
            alias["candidate_disposition"] = "deduplicated_alias"
            alias["status"] = "deduplicated_alias"
            alias["validation_status"] = "deduplicated_alias"
            alias["finding_root_version"] = FINDING_ROOT_VERSION
            alias["finding_root_uid"] = root_uid
            alias["finding_root_primary_candidate_uid"] = str(primary.get("candidate_uid") or "")
            alias["finding_root_primary_validation_cluster_uid"] = str(
                primary.get("validation_cluster_uid") or ""
            )
            alias["affected_subjects"] = subjects
            projected.append(alias)
            alias_count += 1

    projected_by_candidate = {
        str(item.get("candidate_uid") or item.get("validation_cluster_uid") or ""): item
        for item in projected
    }
    for primary_key, aliases in attached_to_primary.items():
        attached_primary = projected_by_candidate.get(primary_key)
        if attached_primary is None:
            continue
        root_uid = str(attached_primary.get("finding_root_uid") or "")
        if not root_uid:
            root_uid = (
                "ROOT_"
                + hashlib.sha256(
                    f"{FINDING_ROOT_VERSION}|attachment|{primary_key}".encode("utf-8")
                ).hexdigest()[:32]
            )
            attached_primary["finding_root_version"] = FINDING_ROOT_VERSION
            attached_primary["finding_root_uid"] = root_uid
        subjects = sorted(
            {
                value
                for value in [
                    *list(attached_primary.get("affected_subjects") or []),
                    *[_subject_identity(alias) for alias in aliases],
                ]
                if value
            }
        )
        attached_primary["affected_subjects"] = subjects
        attached_primary["finding_root_alias_uids"] = _unique_strings(
            list(attached_primary.get("finding_root_alias_uids") or [])
            + [
                str(alias.get("candidate_uid") or alias.get("validation_cluster_uid") or "")
                for alias in aliases
            ]
        )
        attached_primary["finding_root_alias_count"] = int(
            attached_primary.get("finding_root_alias_count") or 0
        ) + len(aliases)
        attached_primary["occurrence_uids"] = _unique_strings(
            list(attached_primary.get("occurrence_uids") or [])
            + [occurrence for alias in aliases for occurrence in _occurrence_uids(alias)]
        )
        attached_primary["occurrence_count"] = len(attached_primary["occurrence_uids"])
        for item in aliases:
            alias = item
            alias["candidate_disposition"] = "deduplicated_alias"
            alias["status"] = "deduplicated_alias"
            alias["validation_status"] = "deduplicated_alias"
            alias["finding_root_version"] = FINDING_ROOT_VERSION
            alias["finding_root_uid"] = root_uid
            alias["finding_root_primary_candidate_uid"] = str(
                attached_primary.get("candidate_uid") or ""
            )
            alias["finding_root_primary_validation_cluster_uid"] = str(
                attached_primary.get("validation_cluster_uid") or ""
            )
            alias["affected_subjects"] = subjects
            projected.append(alias)
            alias_count += 1

    projected.sort(
        key=lambda item: (
            str(item.get("finding_root_uid") or ""),
            str(item.get("candidate_disposition") or ""),
            str(item.get("validation_cluster_uid") or ""),
            str(item.get("candidate_uid") or ""),
        )
    )
    root_count = sum(
        1
        for item in projected
        if str(item.get("candidate_disposition") or "").lower() in _DISPLAY_DISPOSITIONS
    )
    return FindingRootProjection(tuple(projected), root_count, alias_count)


def _attachment_signature(item: Mapping[str, Any]) -> str:
    disposition = str(item.get("candidate_disposition") or "").lower()
    if disposition not in _DISPLAY_DISPOSITIONS:
        return ""
    obligation = item.get("security_obligation")
    obligation = obligation if isinstance(obligation, Mapping) else {}
    family = str(
        obligation.get("defect_family")
        or item.get("defect_family")
        or item.get("defect_class")
        or item.get("category")
        or ""
    ).lower()
    region = _decision_region(item)
    subject = _canonical_subject(_subject_identity(item))
    file_path = _posix_path(str(item.get("file_path") or ""))
    function = str(item.get("function") or item.get("function_name") or "")
    if subject and not subject.startswith("{"):
        subject = json.dumps(
            {"expression": subject, "file": file_path},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    if not all((family, region.startswith("REGION_"), subject, file_path, function)):
        return ""
    region_key = subject if family in _REGION_SCOPED_FAMILIES else region
    return json.dumps(
        {
            "version": FINDING_ROOT_VERSION,
            "build_context_id": issue_build_context_id(item),
            "family": family,
            "region": region_key,
            "subject": subject,
            "file": file_path,
            "function": function,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _root_signature(item: Mapping[str, Any]) -> str:
    proof = item.get("decision_proof")
    proof = proof if isinstance(proof, Mapping) else {}
    family = (
        str(item.get("defect_family") or item.get("defect_class") or item.get("category") or "")
        .strip()
        .lower()
    )
    file_path = _posix_path(str(item.get("file_path") or ""))
    function = str(item.get("function") or item.get("function_name") or "")
    fact_slice = item.get("decision_fact_slice")
    fact_slice = fact_slice if isinstance(fact_slice, Mapping) else {}
    if not fact_slice:
        obligation = item.get("security_obligation")
        obligation = obligation if isinstance(obligation, Mapping) else {}
        fact_slice = obligation.get("decision_fact_slice")
        fact_slice = fact_slice if isinstance(fact_slice, Mapping) else {}
    dependency_hashes = sorted(_strings(fact_slice.get("dependency_code_hashes")))
    code_hash = str(
        proof.get("code_hash")
        or item.get("dependency_code_hash")
        or item.get("code_hash")
        or (dependency_hashes[0] if len(dependency_hashes) == 1 else "")
        or ""
    )
    region = _decision_region(item)
    if not family or not file_path or not function or not code_hash or not region:
        return ""

    proof_kind = str(proof.get("proof_kind") or "").lower()
    proof_complete = str(proof.get("completeness") or "").lower() == "complete"
    composite = (
        family in _CLEANUP_FAMILIES and proof_complete and proof_kind in _COMPOSITE_PROOF_KINDS
    )
    canonical_subject = _canonical_subject(_subject_identity(item))
    subject = "" if composite or family in _REGION_SCOPED_FAMILIES else canonical_subject
    root_region = (
        canonical_subject if family in _REGION_SCOPED_FAMILIES and canonical_subject else region
    )
    # Review roots have no decision proof.  Requiring the complete decision
    # evidence hash prevents nearby lines or similarly worded descriptions
    # from being merged merely because their detector family matches.
    if not proof_complete:
        # A versioned decision region is produced from CFG reachability and
        # decision constraints.  Within that region, equal field-sensitive
        # subjects and equal fact obligations represent one actionable root
        # even when several sink statements are attached as occurrences.
        if not region.startswith("REGION_") or (
            not subject and family not in _REGION_SCOPED_FAMILIES
        ):
            return ""
        proof_signature: Any = {
            "required": sorted(_strings(item.get("obligation_required_fact_kinds"))),
            "missing": sorted(_strings(item.get("missing_fact_kinds"))),
            "blocking_negative_evidence": bool(item.get("blocking_negative_evidence")),
        }
    else:
        proof_signature = {
            "kind": proof_kind,
            "version": str(proof.get("proof_version") or ""),
            "engine": str(proof.get("producer_engine") or ""),
            "scope": str(proof.get("scope") or ""),
            "code_hash": code_hash,
        }
    payload = {
        "version": FINDING_ROOT_VERSION,
        "build_context_id": issue_build_context_id(item),
        "disposition": str(item.get("candidate_disposition") or "").lower(),
        "family": family,
        "file": file_path,
        "function": function,
        "obligation_shape": str(item.get("obligation_shape") or ""),
        "region": root_region,
        "subject": subject,
        "proof": proof_signature,
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _exact_sink_root_signature(item: Mapping[str, Any]) -> str:
    """Identify a narrowly contracted exact-sink root across proof producers.

    This is intentionally stricter than ordinary candidate clustering.  It is
    used only after validation, only for confirmed outcomes, and only for
    defect families whose repair responsibility is the exact sink statement.
    An eligible group is projected only when one member also carries a complete
    deterministic proof accepted by :func:`_has_exact_sink_anchor_proof`.
    """

    if str(item.get("candidate_disposition") or "").lower() != "confirmed":
        return ""
    if bool(item.get("blocking_negative_evidence")):
        return ""
    obligation = item.get("security_obligation")
    obligation = obligation if isinstance(obligation, Mapping) else {}
    pack = item.get("evidence_pack")
    pack = pack if isinstance(pack, Mapping) else {}
    nested = pack.get("security_obligation")
    nested = nested if isinstance(nested, Mapping) else {}
    family = (
        str(
            obligation.get("defect_family")
            or nested.get("defect_family")
            or item.get("defect_family")
            or item.get("defect_class")
            or item.get("category")
            or ""
        )
        .strip()
        .lower()
    )
    if family not in _EXACT_SINK_ROOT_PROOF_KINDS:
        return ""
    shape = (
        str(
            obligation.get("obligation_shape")
            or nested.get("obligation_shape")
            or item.get("obligation_shape")
            or ""
        )
        .strip()
        .lower()
    )
    if shape != "sink_sensitive":
        return ""
    sink = obligation.get("sink_uid") or nested.get("sink_uid") or item.get("sink_identity")
    sink_anchor = _structured_sink_anchor(sink)
    if not sink_anchor:
        return ""
    file_path = _posix_path(str(item.get("file_path") or item.get("file") or ""))
    function = str(item.get("function") or item.get("function_name") or "")
    code_slice = _canonical_code_slice(str(item.get("code_snippet") or ""))
    if not file_path or not function or not code_slice:
        return ""
    if sink_anchor["file"] != file_path:
        return ""
    return json.dumps(
        {
            "version": FINDING_ROOT_VERSION,
            "contract": "exact_sink_with_deterministic_anchor",
            "build_context_id": issue_build_context_id(item),
            "family": family,
            "file": file_path,
            "function": function,
            "shape": shape,
            "sink": sink_anchor,
            "code_slice_hash": hashlib.sha256(code_slice.encode("utf-8")).hexdigest(),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _has_exact_sink_anchor_proof(item: Mapping[str, Any]) -> bool:
    proof = item.get("decision_proof")
    proof = proof if isinstance(proof, Mapping) else {}
    obligation = item.get("security_obligation")
    obligation = obligation if isinstance(obligation, Mapping) else {}
    family = (
        str(
            obligation.get("defect_family")
            or item.get("defect_family")
            or item.get("defect_class")
            or item.get("category")
            or ""
        )
        .strip()
        .lower()
    )
    return (
        str(proof.get("outcome") or "").lower() == "confirm"
        and str(proof.get("completeness") or "").lower() == "complete"
        and str(proof.get("proof_kind") or "").lower()
        in _EXACT_SINK_ROOT_PROOF_KINDS.get(family, frozenset())
        and bool(proof.get("fact_ids"))
        and bool(proof.get("code_hash"))
    )


def _structured_sink_anchor(value: Any) -> Dict[str, Any]:
    if isinstance(value, Mapping):
        parsed = value
    else:
        try:
            candidate = json.loads(str(value or ""))
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
        if not isinstance(candidate, Mapping):
            return {}
        parsed = candidate
    file_path = _posix_path(str(parsed.get("file") or ""))
    operation = re.sub(r"\s+", "", str(parsed.get("operation") or "")).lower()
    try:
        line = int(parsed.get("line") or 0)
    except (TypeError, ValueError):
        return {}
    if not file_path or line <= 0 or not operation:
        return {}
    return {"file": file_path, "line": line, "operation": operation}


def _canonical_code_slice(value: str) -> str:
    statements: List[str] = []
    for raw_line in str(value or "").splitlines():
        numbered = re.match(r"\s*\d+\s*\|\s*(.*)$", raw_line)
        statement = numbered.group(1) if numbered is not None else raw_line
        statement = re.sub(r"\s+", "", statement).lower()
        if statement:
            statements.append(statement)
    return "\n".join(statements)


def _decision_region(item: Mapping[str, Any]) -> str:
    obligation = item.get("security_obligation")
    obligation = obligation if isinstance(obligation, Mapping) else {}
    pack = item.get("evidence_pack")
    pack = pack if isinstance(pack, Mapping) else {}
    nested_obligation = pack.get("security_obligation")
    nested_obligation = nested_obligation if isinstance(nested_obligation, Mapping) else {}
    sink = pack.get("sink")
    if isinstance(sink, Mapping):
        sink_value = sink.get("cfg_node_uid") or sink.get("line") or sink.get("statement")
    else:
        sink_value = sink
    return str(
        obligation.get("decision_region_uid")
        or nested_obligation.get("decision_region_uid")
        or item.get("decision_region_uid")
        or sink_value
        or item.get("location")
        or item.get("line")
        or ""
    )


def _subject_identity(item: Mapping[str, Any]) -> str:
    proof = item.get("decision_proof")
    proof = proof if isinstance(proof, Mapping) else {}
    obligation = item.get("security_obligation")
    obligation = obligation if isinstance(obligation, Mapping) else {}
    pack = item.get("evidence_pack")
    pack = pack if isinstance(pack, Mapping) else {}
    nested = pack.get("security_obligation")
    nested = nested if isinstance(nested, Mapping) else {}
    return str(
        proof.get("subject_identity")
        or obligation.get("subject_uid")
        or nested.get("subject_uid")
        or item.get("resource_identity")
        or item.get("source_identity")
        or item.get("resource")
        or ""
    )


def _canonical_subject(value: str) -> str:
    """Normalize a structured subject without erasing field identity."""

    text = str(value or "")
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        parsed = None
    if isinstance(parsed, Mapping):
        expression = str(parsed.get("expression") or parsed.get("access_path") or "")
        # Detector locations are occurrence provenance.  The versioned
        # decision region already carries the CFG responsibility.
        expression = re.sub(
            r"(?<![A-Za-z0-9_])(?:size_t|ssize_t|uint(?:8|16|32|64)_t|int(?:8|16|32|64)_t|unsigned|signed|const|struct)",
            "",
            expression,
            flags=re.IGNORECASE,
        )
        expression = re.sub(r"\s+", "", expression).lower()
        return json.dumps(
            {
                "expression": expression,
                "file": _posix_path(str(parsed.get("file") or "")),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    return re.sub(r"\s+", "", text.replace("->", ".")).lower()


def _occurrence_uids(item: Mapping[str, Any]) -> List[str]:
    return _unique_strings(
        [str(item.get("occurrence_uid") or "")]
        + list(item.get("occurrence_uids") or [])
        + list(item.get("alias_occurrence_uids") or [])
    )


def _primary_sort_key(item: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        "0" if _has_exact_sink_anchor_proof(item) else "1",
        str(item.get("validation_cluster_uid") or ""),
        str(item.get("candidate_uid") or ""),
    )


def _strings(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, Iterable):
        return [str(item) for item in value if str(item)]
    return []


def _unique_strings(values: Iterable[Any]) -> List[str]:
    return sorted({str(value) for value in values if str(value)})


def _posix_path(value: str) -> str:
    return str(PurePosixPath(value.replace("\\", "/")))
