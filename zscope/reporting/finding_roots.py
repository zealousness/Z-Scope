"""Deterministic, non-destructive finding-root projection.

Validation clusters remain the authority for evidence and disposition.  This
module only chooses one display primary for structurally identical roots and
turns every other member into an auditable ``deduplicated_alias`` terminal
record.  Detector names, benchmark truth, free-form prose and LLM similarity
never participate in a root identity.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


FINDING_ROOT_VERSION = "zscope.finding-root.v2"
_DISPLAY_DISPOSITIONS = frozenset({"confirmed", "needs_review"})


@dataclass(frozen=True)
class FindingRootProjection:
    outcomes: Tuple[Dict[str, Any], ...]
    finding_root_count: int
    finding_root_alias_count: int
    summary: Dict[str, Any] = field(default_factory=dict)


def project_finding_roots(
    outcomes: Sequence[Mapping[str, Any]],
) -> FindingRootProjection:
    """Return display primaries plus preserved alias terminal records.

    All inputs are assumed to come from one frozen scan-level Candidate
    Ledger.  Evidence dependency hashes are deliberately not root identity:
    V2/V3 fact completion commonly adds several candidate-specific dependency
    hashes to one otherwise identical repair responsibility.
    """

    copied = [deepcopy(dict(item)) for item in outcomes]
    display_indices = [
        index for index, item in enumerate(copied) if _disposition(item) in _DISPLAY_DISPOSITIONS
    ]
    parent = {index: index for index in display_indices}

    def find(index: int) -> int:
        root = index
        while parent[root] != root:
            root = parent[root]
        while parent[index] != index:
            next_index = parent[index]
            parent[index] = root
            index = next_index
        return root

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root == right_root:
            return
        parent[right_root] = left_root

    key_builders = (
        ("same_candidate_uid", _candidate_merge_key),
        ("same_structured_sink", _structured_sink_merge_key),
        ("same_decision_region_subject", _decision_region_merge_key),
    )
    for _contract, key_builder in key_builders:
        buckets: Dict[str, List[int]] = defaultdict(list)
        for index in display_indices:
            key = key_builder(copied[index], include_disposition=True)
            if key:
                buckets[key].append(index)
        for indices in buckets.values():
            for index in indices[1:]:
                union(indices[0], index)

    grouped_indices: Dict[int, List[int]] = defaultdict(list)
    for index in display_indices:
        grouped_indices[find(index)].append(index)
    groups = [sorted(indices) for indices in grouped_indices.values()]

    # Attach an unresolved display group to a proved confirmed root only when
    # both describe the same structural root and the review group has no
    # counterproof/conflict.  This is intentionally stricter than grouping two
    # outcomes with the same disposition.
    confirmed_by_attachment_key: Dict[str, int] = {}
    for group_index, indices in enumerate(groups):
        members = [copied[index] for index in indices]
        if not any(_disposition(item) == "confirmed" for item in members):
            continue
        if not any(_has_complete_deterministic_proof(item) for item in members):
            continue
        for item in members:
            for key in _attachment_keys(item):
                confirmed_by_attachment_key.setdefault(key, group_index)

    attached_group_to_primary: Dict[int, int] = {}
    for group_index, indices in enumerate(groups):
        members = [copied[index] for index in indices]
        if not members or any(_disposition(item) != "needs_review" for item in members):
            continue
        if any(_merge_block_reason(item) for item in members):
            continue
        matching_confirmed = {
            confirmed_by_attachment_key[key]
            for item in members
            for key in _attachment_keys(item)
            if key in confirmed_by_attachment_key
        }
        if len(matching_confirmed) == 1:
            attached_group_to_primary[group_index] = next(iter(matching_confirmed))

    for review_group, primary_group in sorted(attached_group_to_primary.items()):
        groups[primary_group].extend(groups[review_group])
        groups[primary_group] = sorted(set(groups[primary_group]))
    active_groups = [
        indices
        for group_index, indices in enumerate(groups)
        if group_index not in attached_group_to_primary
    ]

    projected: List[Dict[str, Any]] = [
        item for index, item in enumerate(copied) if index not in display_indices
    ]
    alias_count = 0
    merge_counts: Counter[str] = Counter()
    unprojectable: Counter[str] = Counter()

    for indices in active_groups:
        group = [copied[index] for index in indices]
        group.sort(key=_primary_sort_key)
        primary = group[0]
        contract = _group_merge_contract(group)
        signature = _group_root_signature(group, contract)
        if not signature:
            reason = _projection_skip_reason(primary)
            primary["finding_root_projection_skip_reason"] = reason
            unprojectable[reason] += 1
            projected.extend(group)
            continue

        root_uid = (
            "ROOT_"
            + hashlib.sha256(f"{FINDING_ROOT_VERSION}|{signature}".encode("utf-8")).hexdigest()[:32]
        )
        candidate_uids = _unique_strings(item.get("candidate_uid") for item in group)
        cluster_uids = _unique_strings(item.get("validation_cluster_uid") for item in group)
        occurrence_uids = _unique_strings(
            occurrence for item in group for occurrence in _occurrence_uids(item)
        )
        subjects = _unique_strings(_subject_identity(item) for item in group)
        member_attributions = [
            {
                "candidate_uid": str(item.get("candidate_uid") or ""),
                "validation_cluster_uid": str(item.get("validation_cluster_uid") or ""),
                "attribution": deepcopy(item.get("attribution") or {}),
            }
            for item in group
        ]
        merge_contracts = _group_merge_contracts(group)
        if any(_disposition(item) == "needs_review" for item in group) and any(
            _disposition(item) == "confirmed" for item in group
        ):
            merge_contracts = _unique_strings([*merge_contracts, "confirmed_review_attachment"])
        primary.update(
            {
                "finding_root_version": FINDING_ROOT_VERSION,
                "finding_root_uid": root_uid,
                "finding_root_merge_contract": contract,
                "finding_root_merge_contracts": merge_contracts,
                "member_candidate_uids": candidate_uids,
                "member_validation_cluster_uids": cluster_uids,
                "finding_root_alias_uids": _unique_strings(
                    _root_alias_uid(item, primary) for item in group[1:]
                ),
                "finding_root_alias_count": len(group) - 1,
                "occurrence_uids": occurrence_uids,
                "occurrence_count": len(occurrence_uids),
                "affected_subjects": subjects,
                "finding_root_member_attributions": member_attributions,
                "finding_root_merge_evidence": _merge_evidence(primary, contract),
            }
        )
        projected.append(primary)
        if len(group) > 1:
            merge_counts[contract] += len(group) - 1

        for item in group[1:]:
            original_disposition = _disposition(item)
            item.update(
                {
                    "candidate_disposition": "deduplicated_alias",
                    "status": "deduplicated_alias",
                    "validation_status": "deduplicated_alias",
                    "finding_root_original_disposition": original_disposition,
                    "finding_root_version": FINDING_ROOT_VERSION,
                    "finding_root_uid": root_uid,
                    "finding_root_merge_contract": contract,
                    "finding_root_merge_contracts": merge_contracts,
                    "finding_root_primary_candidate_uid": str(primary.get("candidate_uid") or ""),
                    "finding_root_primary_validation_cluster_uid": str(
                        primary.get("validation_cluster_uid") or ""
                    ),
                    "member_candidate_uids": candidate_uids,
                    "member_validation_cluster_uids": cluster_uids,
                    "affected_subjects": subjects,
                }
            )
            projected.append(item)
            alias_count += 1

    projected.sort(
        key=lambda item: (
            str(item.get("finding_root_uid") or ""),
            str(item.get("candidate_disposition") or ""),
            str(item.get("validation_cluster_uid") or ""),
            str(item.get("candidate_uid") or ""),
        )
    )
    root_count = sum(1 for item in projected if _disposition(item) in _DISPLAY_DISPOSITIONS)
    summary = {
        "schema_version": FINDING_ROOT_VERSION,
        "input_outcome_count": len(copied),
        "display_input_count": len(display_indices),
        "finding_root_count": root_count,
        "finding_root_alias_count": alias_count,
        "counts_by_merge_contract": dict(sorted(merge_counts.items())),
        "unprojectable_count": sum(unprojectable.values()),
        "unprojectable_by_reason": dict(sorted(unprojectable.items())),
    }
    return FindingRootProjection(tuple(projected), root_count, alias_count, summary)


def _disposition(item: Mapping[str, Any]) -> str:
    return (
        str(
            item.get("candidate_disposition")
            or item.get("terminal_disposition")
            or item.get("status")
            or ""
        )
        .strip()
        .lower()
    )


def _obligation(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("security_obligation")
    if isinstance(value, Mapping):
        return value
    pack = item.get("evidence_pack")
    nested = pack.get("security_obligation") if isinstance(pack, Mapping) else None
    if isinstance(nested, Mapping):
        return nested
    return {}


def _family(item: Mapping[str, Any]) -> str:
    obligation = _obligation(item)
    return (
        str(
            obligation.get("defect_family")
            or item.get("defect_family")
            or item.get("defect_class")
            or item.get("category")
            or ""
        )
        .strip()
        .lower()
        .replace("-", "_")
    )


def _shape(item: Mapping[str, Any]) -> str:
    return (
        str(item.get("obligation_shape") or _obligation(item).get("obligation_shape") or "")
        .strip()
        .lower()
    )


def _file_path(item: Mapping[str, Any]) -> str:
    value = str(item.get("file_path") or item.get("file") or "")
    if re.match(r"^[^:]+:\d+(?::\d+)?$", value):
        value = value.split(":", 1)[0]
    return _posix_path(value).lower() if value else ""


def _function(item: Mapping[str, Any]) -> str:
    return str(item.get("function") or item.get("function_name") or "").strip().lower()


def _base_structural_identity(item: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    family = _family(item)
    file_path = _file_path(item)
    function = _function(item)
    shape = _shape(item)
    # Root merging is stricter than display normalization.  Keep the
    # structured subject's source line so two detector-local subjects that
    # merely normalize to the same expression are not silently coalesced.
    subject = _merge_subject_identity(_subject_identity(item))
    if not all((family, file_path, function, shape, subject)):
        return None
    return {
        "family": family,
        "file": file_path,
        "function": function,
        "shape": shape,
        "subject": subject,
    }


def _candidate_merge_key(item: Mapping[str, Any], *, include_disposition: bool) -> str:
    if _merge_block_reason(item):
        return ""
    candidate_uid = str(item.get("candidate_uid") or "")
    family = _family(item)
    file_path = _file_path(item)
    function = _function(item)
    shape = _shape(item)
    if not all((candidate_uid, family, file_path, function, shape)):
        return ""
    payload: Dict[str, Any] = {
        "contract": "same_candidate_uid",
        "candidate_uid": candidate_uid,
        "family": family,
        "file": file_path,
        "function": function,
        "shape": shape,
    }
    _add_disposition_contract(payload, item, include_disposition=include_disposition)
    return _stable_json(payload)


def _structured_sink_merge_key(item: Mapping[str, Any], *, include_disposition: bool) -> str:
    if _merge_block_reason(item):
        return ""
    base = _base_structural_identity(item)
    sink = _structured_sink_anchor(_obligation(item).get("sink_uid"))
    if base is None or not sink:
        return ""
    payload: Dict[str, Any] = {
        "contract": "same_structured_sink",
        **base,
        "sink": sink,
    }
    _add_disposition_contract(payload, item, include_disposition=include_disposition)
    return _stable_json(payload)


def _decision_region_merge_key(item: Mapping[str, Any], *, include_disposition: bool) -> str:
    if _merge_block_reason(item):
        return ""
    base = _base_structural_identity(item)
    region = _decision_region(item)
    if base is None or not region.startswith("REGION_"):
        return ""
    payload: Dict[str, Any] = {
        "contract": "same_decision_region_subject",
        **base,
        "region": region,
    }
    _add_disposition_contract(payload, item, include_disposition=include_disposition)
    return _stable_json(payload)


def _add_disposition_contract(
    payload: Dict[str, Any], item: Mapping[str, Any], *, include_disposition: bool
) -> None:
    if not include_disposition:
        return
    disposition = _disposition(item)
    payload["disposition"] = disposition
    if disposition == "needs_review":
        payload["unresolved_contract"] = _unresolved_contract(item)


def _unresolved_contract(item: Mapping[str, Any]) -> Dict[str, Any]:
    obligation = _obligation(item)
    fact_slice = item.get("decision_fact_slice")
    fact_slice = fact_slice if isinstance(fact_slice, Mapping) else {}
    required = item.get("obligation_required_fact_kinds") or obligation.get("required_fact_kinds")
    missing = item.get("missing_fact_kinds") or fact_slice.get("missing_fact_kinds")
    return {
        "required": sorted(_strings(required)),
        "missing": sorted(_strings(missing)),
        "blocking_negative_evidence": bool(item.get("blocking_negative_evidence")),
        "model_verdict": str(item.get("model_verdict") or "").lower(),
        "promotion_reason": str(item.get("candidate_promotion_reason") or ""),
        "stop_reason": str(item.get("stop_reason") or item.get("validation_stop_reason") or ""),
        "decision_context_version": str(item.get("decision_context_version") or ""),
    }


def _attachment_keys(item: Mapping[str, Any]) -> List[str]:
    return _unique_strings(
        key_builder(item, include_disposition=False)
        for key_builder in (
            _candidate_merge_key,
            _structured_sink_merge_key,
            _decision_region_merge_key,
        )
    )


def _merge_block_reason(item: Mapping[str, Any]) -> str:
    if bool(item.get("blocking_negative_evidence")):
        return "blocking_negative_evidence"
    for key in (
        "deterministic_counterproof",
        "has_deterministic_counterproof",
        "fact_conflicts",
        "evidence_conflicts",
    ):
        if item.get(key):
            return key
    proof = item.get("decision_proof")
    proof = proof if isinstance(proof, Mapping) else {}
    if str(proof.get("outcome") or "").lower() in {"reject", "rejected", "counterproof"}:
        return "deterministic_counterproof"
    fact_slice = item.get("decision_fact_slice")
    fact_slice = fact_slice if isinstance(fact_slice, Mapping) else {}
    if fact_slice.get("conflicts"):
        return "fact_conflicts"
    return ""


def _has_complete_deterministic_proof(item: Mapping[str, Any]) -> bool:
    proof = item.get("decision_proof")
    proof = proof if isinstance(proof, Mapping) else {}
    return (
        str(proof.get("outcome") or "").lower() in {"confirm", "confirmed", "verified"}
        and str(proof.get("completeness") or "").lower() == "complete"
        and bool(proof.get("producer_engine"))
        and bool(proof.get("fact_ids"))
    )


def _group_merge_contract(group: Sequence[Mapping[str, Any]]) -> str:
    if len(group) <= 1:
        return "singleton"
    for contract, builder in (
        ("same_candidate_uid", _candidate_merge_key),
        ("same_structured_sink", _structured_sink_merge_key),
        ("same_decision_region_subject", _decision_region_merge_key),
    ):
        keys = {builder(item, include_disposition=False) for item in group}
        keys.discard("")
        if len(keys) == 1:
            return contract
    return "confirmed_review_attachment"


def _group_merge_contracts(group: Sequence[Mapping[str, Any]]) -> List[str]:
    contracts: List[str] = []
    if len(group) <= 1:
        return ["singleton"]
    for contract, builder in (
        ("same_candidate_uid", _candidate_merge_key),
        ("same_structured_sink", _structured_sink_merge_key),
        ("same_decision_region_subject", _decision_region_merge_key),
    ):
        keys = {builder(item, include_disposition=False) for item in group}
        keys.discard("")
        if len(keys) == 1:
            contracts.append(contract)
    return contracts or ["confirmed_review_attachment"]


def _group_root_signature(group: Sequence[Mapping[str, Any]], contract: str) -> str:
    primary = group[0]
    if contract == "same_candidate_uid":
        structural = _candidate_merge_key(primary, include_disposition=False)
    elif contract == "same_structured_sink":
        structural = _structured_sink_merge_key(primary, include_disposition=False)
    elif contract == "same_decision_region_subject":
        structural = _decision_region_merge_key(primary, include_disposition=False)
    elif contract == "confirmed_review_attachment":
        keys = _attachment_keys(primary)
        structural = keys[0] if keys else ""
    else:
        candidate_uid = str(
            primary.get("candidate_uid") or primary.get("validation_cluster_uid") or ""
        )
        base = _base_structural_identity(primary)
        structural = (
            _stable_json(
                {
                    "contract": "singleton",
                    "candidate_uid": candidate_uid,
                    "base": base,
                }
            )
            if candidate_uid and base is not None
            else ""
        )
    if not structural:
        return ""
    return _stable_json(
        {
            "version": FINDING_ROOT_VERSION,
            "contract": contract,
            "disposition": _disposition(primary),
            "structural": structural,
        }
    )


def _projection_skip_reason(item: Mapping[str, Any]) -> str:
    if not item.get("candidate_uid") and not item.get("validation_cluster_uid"):
        return "missing_candidate_identity"
    missing: List[str] = []
    base = _base_structural_identity(item)
    if base is None:
        if not _family(item):
            missing.append("family")
        if not _file_path(item):
            missing.append("file")
        if not _function(item):
            missing.append("function")
        if not _shape(item):
            missing.append("obligation_shape")
        if not _subject_identity(item):
            missing.append("subject")
    return "missing_root_fields:" + ",".join(missing) if missing else "unkeyed_root"


def _merge_evidence(item: Mapping[str, Any], contract: str) -> Dict[str, Any]:
    obligation = _obligation(item)
    return {
        "contract": contract,
        "defect_family": _family(item),
        "file": _file_path(item),
        "function": _function(item),
        "obligation_shape": _shape(item),
        "subject_uid": _merge_subject_identity(_subject_identity(item)),
        "sink": _structured_sink_anchor(obligation.get("sink_uid")),
        "decision_region_uid": _decision_region(item),
    }


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
    file_path = _posix_path(str(parsed.get("file") or "")).lower()
    operation = re.sub(r"\s+", "", str(parsed.get("operation") or "")).lower()
    try:
        line = int(parsed.get("line") or 0)
    except (TypeError, ValueError):
        return {}
    if not file_path or line <= 0 or not operation:
        return {}
    return {"file": file_path, "line": line, "operation": operation}


def _decision_region(item: Mapping[str, Any]) -> str:
    obligation = _obligation(item)
    pack = item.get("evidence_pack")
    pack = pack if isinstance(pack, Mapping) else {}
    sink = pack.get("sink")
    if isinstance(sink, Mapping):
        sink_value = sink.get("cfg_node_uid") or sink.get("line") or sink.get("statement")
    else:
        sink_value = sink
    return str(
        obligation.get("decision_region_uid")
        or item.get("decision_region_uid")
        or sink_value
        or item.get("location")
        or item.get("line")
        or ""
    )


def _subject_identity(item: Mapping[str, Any]) -> str:
    proof = item.get("decision_proof")
    proof = proof if isinstance(proof, Mapping) else {}
    obligation = _obligation(item)
    return str(
        proof.get("subject_identity")
        or obligation.get("subject_uid")
        or item.get("resource_identity")
        or item.get("source_identity")
        or item.get("resource")
        or ""
    )


def _merge_subject_identity(value: str) -> str:
    """Return a field- and location-sensitive subject for root merging."""

    text = str(value or "")
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        parsed = None
    if not isinstance(parsed, Mapping):
        return re.sub(r"\s+", "", text.replace("->", ".")).lower()
    expression = str(parsed.get("expression") or parsed.get("access_path") or "")
    expression = re.sub(r"\s+", "", expression.replace("->", ".")).lower()
    try:
        line = int(parsed.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    return _stable_json(
        {
            "expression": expression,
            "file": _posix_path(str(parsed.get("file") or "")).lower(),
            "line": line,
        }
    )


def _occurrence_uids(item: Mapping[str, Any]) -> List[str]:
    return _unique_strings(
        [str(item.get("occurrence_uid") or "")]
        + list(item.get("occurrence_uids") or [])
        + list(item.get("alias_occurrence_uids") or [])
    )


def _primary_sort_key(item: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        "0" if _has_complete_deterministic_proof(item) else "1",
        "0" if _disposition(item) == "confirmed" else "1",
        str(item.get("validation_cluster_uid") or ""),
        str(item.get("candidate_uid") or ""),
    )


def _root_alias_uid(item: Mapping[str, Any], primary: Mapping[str, Any]) -> str:
    candidate_uid = str(item.get("candidate_uid") or "")
    primary_candidate_uid = str(primary.get("candidate_uid") or "")
    if candidate_uid and candidate_uid != primary_candidate_uid:
        return candidate_uid
    return str(item.get("validation_cluster_uid") or candidate_uid)


def _strings(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, Iterable):
        return [str(item) for item in value if str(item)]
    return []


def _unique_strings(values: Iterable[Any]) -> List[str]:
    return sorted({str(value) for value in values if str(value)})


def _stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _posix_path(value: str) -> str:
    return str(PurePosixPath(value.replace("\\", "/")))
