"""Same-site aggregation for canonical validation outcomes.

This module folds issues that describe the same repair site — one defect
family, one function, one structured sink anchor within a small line
tolerance — into a single display primary, unioning their CWE and category
labels so the aggregated issue keeps the full classification of every
member.  It runs after :mod:`zscope.reporting.finding_roots` and follows the
same philosophy: nothing is deleted, folded members become auditable
``deduplicated_alias`` terminal records, and text similarity or LLM prose is
never consulted.  Call chains deliberately stay out of the key: two findings
that reach the same sink statement through different entries describe the
same site responsibility.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from ..common.defect_cwe_map import merge_cwes
from ..common.issue_identity import semantic_category_family
from .finding_roots import _occurrence_uids, _structured_sink_anchor, _unique_strings

ISSUE_AGGREGATION_VERSION = "zscope.issue-aggregation.v1"
_AGGREGATION_DISPOSITIONS = frozenset({"confirmed", "needs_review"})
# Consecutive sink-line gap that still counts as the same site; mirrors the
# ±8 same-defect-site tolerance used by issue identity deduplication.
SINK_LINE_TOLERANCE = 8
_SEVERITY_RANK = {"critical": "0", "high": "1", "medium": "2", "low": "3", "info": "4"}


@dataclass(frozen=True)
class AggregationProjection:
    items: Tuple[Dict[str, Any], ...]
    aggregation_count: int
    aggregation_alias_count: int


def project_issue_aggregation(
    outcomes: Sequence[Mapping[str, Any]],
) -> AggregationProjection:
    """Fold same-site outcomes into labeled primaries without losing records."""

    copied = [deepcopy(dict(item)) for item in outcomes]
    conditional = [
        item for item in copied if item.get("analysis_scope") == "conditional_source_branch"
    ]
    copied = [item for item in copied if item.get("analysis_scope") != "conditional_source_branch"]

    buckets: Dict[Tuple[str, str, str, str, str], List[Dict[str, Any]]] = {}
    passthrough: List[Dict[str, Any]] = []
    for item in copied:
        if str(item.get("candidate_disposition") or "").lower() not in _AGGREGATION_DISPOSITIONS:
            passthrough.append(item)
            continue
        key = _site_bucket_key(item)
        if key is None:
            passthrough.append(item)
            continue
        buckets.setdefault(key, []).append(item)

    projected: List[Dict[str, Any]] = list(passthrough) + conditional
    alias_count = 0
    for key in sorted(buckets):
        for group in _cluster_by_sink_line(buckets[key]):
            if len(group) < 2:
                projected.extend(group)
                continue
            ordered = sorted(group, key=_aggregation_sort_key)
            primary = ordered[0]
            signature = json.dumps(
                {
                    "version": ISSUE_AGGREGATION_VERSION,
                    "family": key[0],
                    "file": key[1],
                    "function": key[2],
                    "sink_file": key[3],
                    "operation": key[4],
                    "sink_line": _sink_anchor(ordered[0])["line"],
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            aggregation_uid = "AGG_" + hashlib.sha256(signature.encode("utf-8")).hexdigest()[:32]
            _apply_primary_labels(primary, ordered[1:], aggregation_uid)
            projected.append(primary)
            for alias in ordered[1:]:
                alias["candidate_disposition"] = "deduplicated_alias"
                alias["status"] = "deduplicated_alias"
                alias["validation_status"] = "deduplicated_alias"
                alias["aggregation_version"] = ISSUE_AGGREGATION_VERSION
                alias["aggregation_uid"] = aggregation_uid
                alias["aggregation_primary_candidate_uid"] = str(primary.get("candidate_uid") or "")
                projected.append(alias)
                alias_count += 1

    projected.sort(
        key=lambda item: (
            str(item.get("aggregation_uid") or ""),
            str(item.get("candidate_disposition") or ""),
            str(item.get("validation_cluster_uid") or ""),
            str(item.get("candidate_uid") or ""),
        )
    )
    aggregation_count = sum(
        1
        for item in projected
        if str(item.get("candidate_disposition") or "").lower() in _AGGREGATION_DISPOSITIONS
    )
    return AggregationProjection(tuple(projected), aggregation_count, alias_count)


def _sink_anchor(item: Mapping[str, Any]) -> Dict[str, Any]:
    obligation = item.get("security_obligation")
    obligation = obligation if isinstance(obligation, Mapping) else {}
    pack = item.get("evidence_pack")
    pack = pack if isinstance(pack, Mapping) else {}
    nested = pack.get("security_obligation")
    nested = nested if isinstance(nested, Mapping) else {}
    sink = (
        obligation.get("sink_uid")
        or nested.get("sink_uid")
        or item.get("sink_identity")
        or (pack.get("sink") if isinstance(pack.get("sink"), Mapping) else None)
    )
    return _structured_sink_anchor(sink)


def _site_bucket_key(item: Mapping[str, Any]) -> Tuple[str, str, str, str, str] | None:
    """Bucket by family, file, function, sink file, and sink operation.

    The sink line joins later through tolerance clustering, so drift of a few
    lines between detectors does not split one site into two groups.
    """

    family_source = (
        item.get("defect_family")
        or item.get("defect_class")
        or item.get("category")
        or item.get("subcategory")
        or ""
    )
    family = semantic_category_family(str(family_source))
    file_path = _posix_path(str(item.get("file_path") or item.get("file") or ""))
    function = str(item.get("function") or item.get("function_name") or "")
    sink_anchor = _sink_anchor(item)
    if not family or not file_path or not function or not sink_anchor:
        return None
    return (
        family,
        file_path,
        function,
        sink_anchor["file"],
        sink_anchor["operation"],
    )


def _cluster_by_sink_line(
    items: List[Dict[str, Any]],
) -> List[List[Dict[str, Any]]]:
    """Chain-cluster bucket members by consecutive sink-line gaps."""

    ordered = sorted(
        items, key=lambda item: (_sink_anchor(item)["line"], _aggregation_sort_key(item))
    )
    clusters: List[List[Dict[str, Any]]] = []
    for item in ordered:
        if clusters:
            previous_line = _sink_anchor(clusters[-1][-1])["line"]
            if _sink_anchor(item)["line"] - previous_line <= SINK_LINE_TOLERANCE:
                clusters[-1].append(item)
                continue
        clusters.append([item])
    return clusters


def _aggregation_sort_key(item: Mapping[str, Any]) -> Tuple[str, str, str, str]:
    proof = item.get("decision_proof")
    proof_complete = (
        "0"
        if isinstance(proof, Mapping) and str(proof.get("completeness") or "").lower() == "complete"
        else "1"
    )
    severity = str(item.get("impact_level") or item.get("default_severity") or "medium").lower()
    return (
        proof_complete,
        _SEVERITY_RANK.get(severity, "9"),
        str(item.get("validation_cluster_uid") or ""),
        str(item.get("candidate_uid") or ""),
    )


def _category_tokens(item: Mapping[str, Any]) -> List[str]:
    tokens: List[str] = []
    for value in (
        item.get("defect_class"),
        item.get("category"),
        item.get("subcategory"),
        item.get("defect_family"),
    ):
        token = str(value or "").strip().lower()
        if token and token not in tokens:
            tokens.append(token)
    return tokens


def _apply_primary_labels(
    primary: Dict[str, Any],
    aliases: Sequence[Mapping[str, Any]],
    aggregation_uid: str,
) -> None:
    """Union member labels, occurrences, and provenance onto the primary."""

    members = [primary, *aliases]
    primary["aggregation_version"] = ISSUE_AGGREGATION_VERSION
    primary["aggregation_uid"] = aggregation_uid
    primary["aggregation_alias_uids"] = _unique_strings(
        [
            str(item.get("candidate_uid") or item.get("validation_cluster_uid") or "")
            for item in aliases
        ]
    )
    primary["aggregation_alias_count"] = len(aliases)
    primary["occurrence_uids"] = _unique_strings(
        [occurrence for item in members for occurrence in _occurrence_uids(item)]
    )
    primary["occurrence_count"] = len(primary["occurrence_uids"])
    primary["alias_occurrence_uids"] = _unique_strings(
        list(primary.get("alias_occurrence_uids") or [])
        + [occurrence for item in aliases for occurrence in _occurrence_uids(item)]
    )

    # CWE union: the primary's own CWE stays first so ``cwe == cwes[0]``.
    cwe_groups: List[Any] = [primary.get("cwe"), primary.get("cwes")]
    for item in aliases:
        cwe_groups.extend((item.get("cwe"), item.get("cwes")))
    primary["cwes"] = merge_cwes(*cwe_groups)
    if not primary.get("cwe") and primary["cwes"]:
        primary["cwe"] = primary["cwes"][0]

    # Category union keeps the primary's class first and records every
    # member's defect class so downstream matching sees the full set.
    categories: List[str] = list(primary.get("categories") or [])
    for item in members:
        for token in _category_tokens(item):
            if token not in categories:
                categories.append(token)
    if categories:
        primary["categories"] = categories

    primary["entry_paths"] = _unique_path_lists(
        list(primary.get("entry_paths") or [])
        + [path for item in aliases for path in (item.get("entry_paths") or [])]
    )
    primary["duplicate_sources"] = _unique_records(
        list(primary.get("duplicate_sources") or [])
        + [record for item in aliases for record in (item.get("duplicate_sources") or [])]
    )

    pack = primary.get("evidence_pack")
    if isinstance(pack, dict):
        pack["cwes"] = list(primary["cwes"])
        if categories:
            pack["categories"] = list(categories)


def _unique_path_lists(paths: Sequence[Any]) -> List[List[str]]:
    seen: set[str] = set()
    result: List[List[str]] = []
    for path in paths:
        if not isinstance(path, (list, tuple)):
            continue
        key = json.dumps([str(item) for item in path], ensure_ascii=False)
        if key in seen:
            continue
        seen.add(key)
        result.append([str(item) for item in path])
    return result


def _unique_records(records: Sequence[Any]) -> List[Dict[str, Any]]:
    seen: set[str] = set()
    result: List[Dict[str, Any]] = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        key = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        result.append(dict(record))
    return result


def _posix_path(value: str) -> str:
    return str(PurePosixPath(value.replace("\\", "/")))
