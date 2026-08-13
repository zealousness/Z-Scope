"""Answer-free validator replay bundles for benchmark and policy experiments."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence


REPLAY_BUNDLE_SCHEMA_VERSION = "zscope.validator-replay-bundle.v1"
_INITIAL_FACT_KEYS = (
    "facts",
    "decision_facts",
    "decision_fact_graph",
    "fact_graph",
)
_FACT_RESERVOIR_KEYS = (
    "frozen_fact_catalog",
    "fact_reservoir",
    "frozen_fact_reservoir",
)
_FACT_PARTITION_CONTRACT = {
    "initial_keys": list(_INITIAL_FACT_KEYS),
    "reservoir_keys": list(_FACT_RESERVOIR_KEYS),
    "overlap_policy": "fail_closed_by_record_sha256_or_fact_uid",
}
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "source_identity",
        "group_count",
        "canonical_groups",
        "answer_material_present",
        "contract",
        "bundle_sha256",
    }
)
_GROUP_FIELDS = frozenset(
    {
        "validation_cluster_uid",
        "candidate_uid",
        "candidate_uids",
        "occurrence_uids",
        "entries",
        "candidate",
        "evidence",
        "facts",
        "hashes",
        "group_sha256",
    }
)
_CANDIDATE_FIELDS = (
    "candidate_id",
    "candidate_uid",
    "obligation_uid",
    "candidate_schema_version",
    "candidate_kind",
    "candidate_source",
    "sources",
    "signal_source",
    "native_rule_id",
    "rule",
    "rule_id",
    "rule_engine",
    "rule_revision",
    "rule_source",
    "skill",
    "category",
    "subcategory",
    "defect_class",
    "cwe",
    "impact_level",
    "severity",
    "risk_score",
    "priority_score",
    "externally_reachable",
    "reachable_from_entry",
    "function",
    "function_name",
    "entry_function",
    "entry_identity",
    "file",
    "file_path",
    "line",
    "line_number",
    "location",
    "source",
    "sink",
    "call_path",
    "call_paths",
    "entry_paths",
    "description",
    "root_cause",
    "code_snippet",
)
_HASH_FIELDS = (
    "evidence_hash",
    "decision_evidence_hash",
    "provenance_hash",
    "provenance_hashes",
    "evidence_hashes",
    "context_signature",
    "validation_contexts",
    "decision_context_version",
    "decision_fact_version",
    "candidate_sha256",
    "candidate_uids_sha256",
    "occurrence_uids_sha256",
    "entries_sha256",
    "evidence_sha256",
    "facts_sha256",
)
_REQUIRED_CONTENT_HASH_FIELDS = frozenset(
    {
        "candidate_sha256",
        "candidate_uids_sha256",
        "occurrence_uids_sha256",
        "entries_sha256",
        "evidence_sha256",
        "facts_sha256",
    }
)
_SOURCE_IDENTITY_FIELDS = (
    "source_revision",
    "source_tree_hash",
    "config_hash",
    "model_manifest_hash",
    "effective_rules_sha256",
    "candidate_schema_version",
    "knowledge_db_version",
    "identity_sha256",
)
_FORBIDDEN_KEY_FRAGMENTS = (
    "ground_truth",
    "truth_id",
    "truth_label",
    "oracle",
    "expected_label",
    "matched_truth",
    "verdict",
    "disposition",
    "validation_status",
    "terminal_status",
    "terminal_issue",
    "decision_proof",
    "rejection_proof",
    "validator_result",
    "old_decision",
    "old_status",
    "false_positive",
    "true_positive",
)
_FORBIDDEN_EXACT_KEYS = frozenset(
    {
        "status",
        "finding_status",
        "engine_status",
        "validation_attempt_count",
        "validator_avoided",
        "deterministic_prevalidation_decision",
        "proof_provider",
        "promotion_reason",
        "candidate_promotion_eligible",
        "confidence",
        "final_score",
        "score_components",
    }
)
_FORBIDDEN_VALUE_RE = re.compile(
    r"(?i)(?:^|[/\\])(?:ground[_ -]?truth|truth[_ -]?set)(?:\.(?:json|md|ya?ml))?(?:$|[/\\])"
)


class ReplayBundleError(ValueError):
    """Raised when a replay bundle leaks answers or violates canonical hashes."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_payload(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def canonical_json_sha256(value: Any) -> str:
    """Return the cross-platform canonical SHA-256 used by replay artifacts."""

    return _sha256_payload(value)


def _is_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _forbidden_key(key: Any) -> bool:
    normalized = str(key or "").strip().lower()
    return normalized in _FORBIDDEN_EXACT_KEYS or any(
        fragment in normalized for fragment in _FORBIDDEN_KEY_FRAGMENTS
    )


def _answer_free(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: Dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReplayBundleError("replay input object keys must be strings")
            normalized_key = unicodedata.normalize("NFC", key)
            if _forbidden_key(normalized_key):
                continue
            result[normalized_key] = _answer_free(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_answer_free(item) for item in value]
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, float) and not math.isfinite(value):
        raise ReplayBundleError("replay input contains a non-finite number")
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return str(value)


def _cluster_uid(raw: Mapping[str, Any]) -> str:
    raw_issue = raw.get("issue")
    issue: Mapping[str, Any] = raw_issue if isinstance(raw_issue, Mapping) else raw
    return str(
        raw.get("validation_cluster_uid")
        or issue.get("validation_cluster_uid")
        or raw.get("candidate_uid")
        or issue.get("candidate_uid")
        or raw.get("candidate_id")
        or issue.get("candidate_id")
        or ""
    ).strip()


def _candidate_uid(raw: Mapping[str, Any]) -> str:
    raw_issue = raw.get("issue")
    issue: Mapping[str, Any] = raw_issue if isinstance(raw_issue, Mapping) else raw
    return str(
        raw.get("candidate_uid")
        or issue.get("candidate_uid")
        or raw.get("candidate_id")
        or issue.get("candidate_id")
        or ""
    ).strip()


def _canonical_group_records(
    report: Mapping[str, Any],
) -> Iterable[tuple[Mapping[str, Any], ...]]:
    records = report.get("candidate_terminal_states")
    if not isinstance(records, list):
        metadata = report.get("metadata")
        records = metadata.get("candidate_terminal_states") if isinstance(metadata, Mapping) else []
    if not isinstance(records, list) or not records:
        records = report.get("issues_with_needs_review") or report.get("issues") or []
    candidates: list[Mapping[str, Any]] = []
    for raw in records:
        if not isinstance(raw, Mapping):
            continue
        # Engine/phase completeness records are report governance, not
        # validation candidates.  They intentionally carry no source
        # evidence and must remain visible in the scan report without being
        # projected into an answer-free Validator replay bundle.
        raw_candidate_issue = raw.get("issue")
        candidate_issue: Mapping[str, Any] = (
            raw_candidate_issue if isinstance(raw_candidate_issue, Mapping) else raw
        )
        if str(
            raw.get("record_role") or candidate_issue.get("record_role") or ""
        ).strip() == "operational_obligation":
            continue
        cluster = _cluster_uid(raw)
        candidate_uid = _candidate_uid(raw)
        if not cluster or not candidate_uid:
            raise ReplayBundleError(
                "every replay candidate must have a validation cluster and candidate identity"
            )
        candidates.append(raw)

    # A lifecycle alias can carry a stale producer cluster while reusing the
    # canonical candidate or occurrence identity.  Replay must therefore
    # freeze connected obligations, not merely group by the producer's cluster
    # string.  Otherwise the same evidence is replayed twice and the bundle's
    # global identity invariant fails after an otherwise successful scan.
    parents = list(range(len(candidates)))

    def root(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = root(left)
        right_root = root(right)
        if left_root != right_root:
            parents[max(left_root, right_root)] = min(left_root, right_root)

    identity_owner: Dict[str, int] = {}
    for index, raw in enumerate(candidates):
        raw_issue = raw.get("issue")
        issue: Mapping[str, Any] = raw_issue if isinstance(raw_issue, Mapping) else raw
        identities = {
            f"cluster:{_cluster_uid(raw)}",
            f"candidate:{_candidate_uid(raw)}",
            *{
                f"occurrence:{value}"
                for value in _list_values(
                    raw.get("occurrence_uids"),
                    issue.get("occurrence_uids"),
                    raw.get("alias_occurrence_uids"),
                    issue.get("alias_occurrence_uids"),
                    raw.get("primary_occurrence_uid"),
                    raw.get("occurrence_uid"),
                    issue.get("occurrence_uid"),
                )
            },
        }
        for identity in sorted(identities):
            owner = identity_owner.setdefault(identity, index)
            union(index, owner)

    grouped: Dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    for index, raw in enumerate(candidates):
        grouped[root(index)].append(raw)
    ordered = sorted(
        grouped.values(),
        key=lambda group: min(_cluster_uid(item) for item in group),
    )
    for group in ordered:
        yield tuple(
            sorted(
                group,
                key=lambda item: (
                    _cluster_uid(item),
                    _candidate_uid(item),
                    _sha256_payload(_answer_free(item)),
                ),
            )
        )


def _list_values(*values: Any) -> list[str]:
    result: set[str] = set()
    for value in values:
        if isinstance(value, (list, tuple, set)):
            result.update(
                unicodedata.normalize("NFC", str(item)) for item in value if str(item).strip()
            )
        elif value not in (None, ""):
            result.add(unicodedata.normalize("NFC", str(value)))
    return sorted(result)


def _stable_union(left: Any, right: Any) -> Any:
    """Recursively retain every answer-free alias value without row-order bias."""

    if left in (None, "", [], {}):
        return _answer_free(right)
    if right in (None, "", [], {}):
        return _answer_free(left)
    left = _answer_free(left)
    right = _answer_free(right)
    if left == right:
        return left
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return {
            key: _stable_union(left.get(key), right.get(key))
            for key in sorted(set(left) | set(right))
        }
    left_values = left if isinstance(left, list) else [left]
    right_values = right if isinstance(right, list) else [right]
    unique = {_canonical_bytes(item): item for item in [*left_values, *right_values]}
    return [unique[key] for key in sorted(unique)]


def _candidate_projection(raw: Mapping[str, Any]) -> Dict[str, Any]:
    raw_issue = raw.get("issue")
    issue: Mapping[str, Any] = raw_issue if isinstance(raw_issue, Mapping) else raw
    return {
        key: _answer_free(
            issue.get(key) if issue.get(key) not in (None, "", [], {}) else raw.get(key)
        )
        for key in _CANDIDATE_FIELDS
        if (issue.get(key) if issue.get(key) not in (None, "", [], {}) else raw.get(key))
        not in (None, "", [], {})
    }


def _nested_fact_records(value: Any) -> list[Mapping[str, Any]]:
    records: list[Mapping[str, Any]] = []
    if isinstance(value, Mapping):
        if str(value.get("fact_kind") or value.get("kind") or "").strip():
            records.append(value)
        for item in value.values():
            records.extend(_nested_fact_records(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            records.extend(_nested_fact_records(item))
    return records


def _nested_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            keys.add(str(key))
            keys.update(_nested_keys(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            keys.update(_nested_keys(item))
    return keys


def _validate_fact_partition(facts: Mapping[str, Any], *, label: str) -> None:
    unknown = set(facts) - set(_INITIAL_FACT_KEYS) - set(_FACT_RESERVOIR_KEYS)
    if unknown:
        raise ReplayBundleError(f"{label} contains unknown fact partition keys")

    # A reservoir nested under an initial container has no unambiguous replay
    # boundary: V1 would either leak future evidence or V2 would silently lose
    # it.  Require the exporter to place every resolvable fact in a dedicated
    # top-level reservoir key.
    initial_values = [facts[key] for key in _INITIAL_FACT_KEYS if key in facts]
    if any(set(_FACT_RESERVOIR_KEYS).intersection(_nested_keys(value)) for value in initial_values):
        raise ReplayBundleError(
            f"{label} nests a frozen fact reservoir inside the initial fact partition"
        )

    reservoir_values = [facts[key] for key in _FACT_RESERVOIR_KEYS if key in facts]
    initial_records = [record for value in initial_values for record in _nested_fact_records(value)]
    reservoir_records = [
        record for value in reservoir_values for record in _nested_fact_records(value)
    ]
    initial_hashes = {_sha256_payload(record) for record in initial_records}
    reservoir_hashes = {_sha256_payload(record) for record in reservoir_records}
    if initial_hashes.intersection(reservoir_hashes):
        raise ReplayBundleError(
            f"{label} reuses a fact record in both initial evidence and the frozen reservoir"
        )

    def fact_uids(records: Sequence[Mapping[str, Any]]) -> set[str]:
        return {
            str(record.get("fact_uid") or record.get("uid") or "").strip()
            for record in records
            if str(record.get("fact_uid") or record.get("uid") or "").strip()
        }

    if fact_uids(initial_records).intersection(fact_uids(reservoir_records)):
        raise ReplayBundleError(
            f"{label} reuses a fact UID in both initial evidence and the frozen reservoir"
        )


def _without_fact_reservoir(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _without_fact_reservoir(item)
            for key, item in value.items()
            if str(key) not in _FACT_RESERVOIR_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_without_fact_reservoir(item) for item in value]
    return value


def _evidence_projection(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    raw_issue = raw.get("issue")
    issue: Mapping[str, Any] = raw_issue if isinstance(raw_issue, Mapping) else raw
    raw_ticket = raw.get("ticket")
    ticket: Mapping[str, Any] = raw_ticket if isinstance(raw_ticket, Mapping) else {}
    raw_ticket_evidence = ticket.get("evidence")
    ticket_evidence: Mapping[str, Any] = (
        raw_ticket_evidence if isinstance(raw_ticket_evidence, Mapping) else {}
    )
    evidence = issue.get("evidence_pack")
    return evidence if isinstance(evidence, Mapping) else ticket_evidence


def _build_group(records: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    if not records:
        raise ReplayBundleError("cannot build an empty canonical replay group")
    cluster = min(_cluster_uid(raw) for raw in records)
    candidate_uids = sorted({_candidate_uid(raw) for raw in records})
    if not cluster or not candidate_uids or any(not value for value in candidate_uids):
        raise ReplayBundleError("canonical replay group identities are incomplete")
    candidate_uid = candidate_uids[0]
    primary = next(raw for raw in records if _candidate_uid(raw) == candidate_uid)
    candidate = _candidate_projection(primary)
    candidate["candidate_uid"] = candidate_uid

    evidence: Any = {}
    facts: Dict[str, Any] = {}
    hashes: Dict[str, Any] = {}
    occurrence_values: list[Any] = []
    entry_values: list[Any] = []
    for raw in records:
        raw_issue = raw.get("issue")
        issue: Mapping[str, Any] = raw_issue if isinstance(raw_issue, Mapping) else raw
        raw_ticket = raw.get("ticket")
        ticket: Mapping[str, Any] = raw_ticket if isinstance(raw_ticket, Mapping) else {}
        raw_ticket_evidence = ticket.get("evidence")
        ticket_evidence: Mapping[str, Any] = (
            raw_ticket_evidence if isinstance(raw_ticket_evidence, Mapping) else {}
        )
        current_evidence = _evidence_projection(raw)
        evidence = _stable_union(evidence, current_evidence)
        for owner in (raw, issue, current_evidence, ticket_evidence):
            if not isinstance(owner, Mapping):
                continue
            for key in (*_INITIAL_FACT_KEYS, *_FACT_RESERVOIR_KEYS):
                value = owner.get(key)
                if value not in (None, "", [], {}):
                    facts[key] = _stable_union(facts.get(key), value)
            for key in _HASH_FIELDS:
                if key in _REQUIRED_CONTENT_HASH_FIELDS:
                    continue
                value = owner.get(key)
                if value not in (None, "", [], {}):
                    hashes[key] = _stable_union(hashes.get(key), value)
        occurrence_values.extend(
            [
                raw.get("occurrence_uids"),
                issue.get("occurrence_uids"),
                raw.get("alias_occurrence_uids"),
                issue.get("alias_occurrence_uids"),
                raw.get("primary_occurrence_uid"),
                raw.get("occurrence_uid"),
                issue.get("occurrence_uid"),
            ]
        )
        entry_values.extend(
            [
                raw.get("entries"),
                issue.get("entries"),
                issue.get("entry_identity"),
                issue.get("entry_function"),
                issue.get("function"),
                issue.get("function_name"),
            ]
        )
    occurrence_uids = _list_values(*occurrence_values) or list(candidate_uids)
    entries = _list_values(*entry_values)
    _validate_fact_partition(facts, label=f"canonical group {cluster}")
    # Reservoir facts live in exactly one explicit bundle partition.  Keeping
    # another copy inside evidence_pack would make it possible for V1 to see
    # the same payload that FACT_RESOLUTION later presents as a V2 delta.
    evidence = _without_fact_reservoir(evidence)
    hashes.update(
        {
            "candidate_sha256": _sha256_payload(candidate),
            "candidate_uids_sha256": _sha256_payload(candidate_uids),
            "occurrence_uids_sha256": _sha256_payload(occurrence_uids),
            "entries_sha256": _sha256_payload(entries),
            "evidence_sha256": _sha256_payload(evidence),
            "facts_sha256": _sha256_payload(facts),
        }
    )
    group = {
        "validation_cluster_uid": cluster,
        "candidate_uid": candidate_uid,
        "candidate_uids": candidate_uids,
        "occurrence_uids": occurrence_uids,
        "entries": entries,
        "candidate": candidate,
        "evidence": _answer_free(evidence),
        "facts": facts,
        "hashes": hashes,
    }
    group["group_sha256"] = _sha256_payload(group)
    return group


def build_validator_replay_bundle(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Export canonical validation inputs without truth or prior outcomes."""

    manifest = report.get("run_manifest")
    if not isinstance(manifest, Mapping):
        manifest = {}
    metadata = report.get("metadata")
    if not isinstance(metadata, Mapping):
        metadata = {}
    source_identity: Dict[str, Any] = {
        key: _answer_free(
            manifest.get(key) if manifest.get(key) not in (None, "", [], {}) else metadata.get(key)
        )
        for key in _SOURCE_IDENTITY_FIELDS
        if key != "identity_sha256"
        if (manifest.get(key) if manifest.get(key) not in (None, "", [], {}) else metadata.get(key))
        not in (None, "", [], {})
    }
    if not source_identity:
        raise ReplayBundleError("replay bundle requires a non-empty source identity")
    source_identity["identity_sha256"] = _sha256_payload(source_identity)
    groups = sorted(
        (_build_group(raw_group) for raw_group in _canonical_group_records(report)),
        key=lambda item: item["validation_cluster_uid"],
    )
    payload: Dict[str, Any] = {
        "schema_version": REPLAY_BUNDLE_SCHEMA_VERSION,
        "source_identity": source_identity,
        "group_count": len(groups),
        "canonical_groups": groups,
        "answer_material_present": False,
        "contract": {
            "group_unit": "canonical_validation_cluster",
            "answers_excluded": True,
            "fact_partition": _answer_free(_FACT_PARTITION_CONTRACT),
            "excluded_material": [
                "benchmark_truth",
                "prior_validator_verdict",
                "prior_terminal_disposition",
                "prior_decision_proof",
            ],
        },
    }
    payload["bundle_sha256"] = _sha256_payload(payload)
    validate_validator_replay_bundle(payload)
    return payload


def _find_forbidden_keys(value: Any, *, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = f"{path}.{key}"
            if _forbidden_key(key):
                found.append(child)
            found.extend(_find_forbidden_keys(item, path=child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_find_forbidden_keys(item, path=f"{path}[{index}]"))
    return found


def _find_forbidden_values(value: Any, *, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            found.extend(_find_forbidden_values(item, path=f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_find_forbidden_values(item, path=f"{path}[{index}]"))
    elif isinstance(value, str) and _FORBIDDEN_VALUE_RE.search(value.replace("\\", "/")):
        found.append(path)
    return found


def validate_validator_replay_bundle(bundle: Mapping[str, Any]) -> None:
    """Fail closed on schema drift, answer leakage, ordering, or hash mismatch."""

    if set(bundle) != _TOP_LEVEL_FIELDS:
        raise ReplayBundleError("replay bundle has missing or unknown top-level fields")
    if bundle.get("schema_version") != REPLAY_BUNDLE_SCHEMA_VERSION:
        raise ReplayBundleError("replay bundle schema_version is invalid")
    if bundle.get("answer_material_present") is not False:
        raise ReplayBundleError("replay bundle declares answer material")
    source_identity = bundle.get("source_identity")
    if not isinstance(source_identity, Mapping) or not set(source_identity).issubset(
        _SOURCE_IDENTITY_FIELDS
    ):
        raise ReplayBundleError("replay bundle source_identity has invalid fields")
    if set(source_identity) == {"identity_sha256"}:
        raise ReplayBundleError("replay bundle source_identity has no replay identity fields")
    source_identity_without_hash = {
        key: value for key, value in source_identity.items() if key != "identity_sha256"
    }
    if source_identity.get("identity_sha256") != _sha256_payload(source_identity_without_hash):
        raise ReplayBundleError("replay bundle source identity hash mismatch")
    for key, value in source_identity_without_hash.items():
        if (key.endswith("_hash") or key.endswith("_sha256")) and not _is_sha256(value):
            raise ReplayBundleError(f"replay bundle source_identity.{key} is not SHA-256")
    source_forbidden = _find_forbidden_keys(source_identity, path="$.source_identity")
    if source_forbidden:
        raise ReplayBundleError(
            "replay bundle source_identity contains answer fields: " + ", ".join(source_forbidden)
        )
    contract = bundle.get("contract")
    if not isinstance(contract, Mapping) or set(contract) != {
        "group_unit",
        "answers_excluded",
        "fact_partition",
        "excluded_material",
    }:
        raise ReplayBundleError("replay bundle contract is invalid")
    if (
        contract.get("group_unit") != "canonical_validation_cluster"
        or contract.get("answers_excluded") is not True
        or contract.get("fact_partition") != _FACT_PARTITION_CONTRACT
        or contract.get("excluded_material")
        != [
            "benchmark_truth",
            "prior_validator_verdict",
            "prior_terminal_disposition",
            "prior_decision_proof",
        ]
    ):
        raise ReplayBundleError("replay bundle is not declared answer-free")
    groups = bundle.get("canonical_groups")
    if not isinstance(groups, list) or bundle.get("group_count") != len(groups):
        raise ReplayBundleError("replay bundle group_count does not match canonical_groups")
    identities: list[str] = []
    seen_candidate_uids: set[str] = set()
    seen_occurrence_uids: set[str] = set()
    for index, raw in enumerate(groups):
        if not isinstance(raw, Mapping) or set(raw) != _GROUP_FIELDS:
            raise ReplayBundleError(f"canonical_groups[{index}] has invalid fields")
        cluster = str(raw.get("validation_cluster_uid") or "")
        if not cluster:
            raise ReplayBundleError(f"canonical_groups[{index}] has no validation cluster")
        candidate = raw.get("candidate")
        hashes = raw.get("hashes")
        if not isinstance(candidate, Mapping) or not set(candidate).issubset(_CANDIDATE_FIELDS):
            raise ReplayBundleError(f"canonical_groups[{index}].candidate has invalid fields")
        if not isinstance(hashes, Mapping) or not set(hashes).issubset(_HASH_FIELDS):
            raise ReplayBundleError(f"canonical_groups[{index}].hashes has invalid fields")
        candidate_uid = str(raw.get("candidate_uid") or "")
        candidate_uids = raw.get("candidate_uids")
        if (
            not candidate_uid
            or not isinstance(candidate_uids, list)
            or candidate_uids != sorted(set(candidate_uids))
            or candidate_uid not in candidate_uids
            or candidate_uid != min(candidate_uids)
            or candidate.get("candidate_uid") != candidate_uid
        ):
            raise ReplayBundleError(f"canonical_groups[{index}] candidate identities are invalid")
        for name in ("occurrence_uids", "entries"):
            values = raw.get(name)
            if (
                not isinstance(values, list)
                or any(not isinstance(value, str) or not value for value in values)
                or values != sorted(set(values))
            ):
                raise ReplayBundleError(f"canonical_groups[{index}].{name} is not canonical")
        if not raw.get("occurrence_uids"):
            raise ReplayBundleError(f"canonical_groups[{index}] has no occurrence identity")
        duplicate_candidates = seen_candidate_uids.intersection(candidate_uids)
        duplicate_occurrences = seen_occurrence_uids.intersection(raw["occurrence_uids"])
        if duplicate_candidates or duplicate_occurrences:
            raise ReplayBundleError(
                f"canonical_groups[{index}] reuses candidate or occurrence identities"
            )
        seen_candidate_uids.update(candidate_uids)
        seen_occurrence_uids.update(raw["occurrence_uids"])
        if not isinstance(raw.get("evidence"), Mapping) or not isinstance(
            raw.get("facts"), Mapping
        ):
            raise ReplayBundleError(f"canonical_groups[{index}] evidence and facts must be objects")
        if set(_FACT_RESERVOIR_KEYS).intersection(_nested_keys(raw["evidence"])):
            raise ReplayBundleError(
                f"canonical_groups[{index}] stores frozen reservoir facts outside the fact partition"
            )
        _validate_fact_partition(raw["facts"], label=f"canonical_groups[{index}].facts")
        if (
            not raw.get("evidence")
            and not raw.get("facts")
            and not any(
                candidate.get(key)
                for key in (
                    "location",
                    "file_path",
                    "source",
                    "sink",
                    "description",
                    "code_snippet",
                )
            )
        ):
            raise ReplayBundleError(f"canonical_groups[{index}] has no replayable evidence")
        if not _REQUIRED_CONTENT_HASH_FIELDS.issubset(hashes):
            raise ReplayBundleError(f"canonical_groups[{index}] content hashes are incomplete")
        expected_content_hashes = {
            "candidate_sha256": _sha256_payload(candidate),
            "candidate_uids_sha256": _sha256_payload(candidate_uids),
            "occurrence_uids_sha256": _sha256_payload(raw.get("occurrence_uids")),
            "entries_sha256": _sha256_payload(raw.get("entries")),
            "evidence_sha256": _sha256_payload(raw.get("evidence")),
            "facts_sha256": _sha256_payload(raw.get("facts")),
        }
        if any(hashes.get(key) != value for key, value in expected_content_hashes.items()):
            raise ReplayBundleError(f"canonical_groups[{index}] content hash mismatch")
        identities.append(cluster)
        expected_group_sha = _sha256_payload(
            {key: value for key, value in raw.items() if key != "group_sha256"}
        )
        if raw.get("group_sha256") != expected_group_sha:
            raise ReplayBundleError(f"canonical_groups[{index}] hash mismatch")
        forbidden = _find_forbidden_keys(raw)
        if forbidden:
            raise ReplayBundleError(
                f"canonical_groups[{index}] contains answer fields: {', '.join(forbidden)}"
            )
        forbidden_values = _find_forbidden_values(raw)
        if forbidden_values:
            raise ReplayBundleError(
                f"canonical_groups[{index}] contains answer paths: " + ", ".join(forbidden_values)
            )
    if identities != sorted(identities) or len(identities) != len(set(identities)):
        raise ReplayBundleError("canonical validation groups must be unique and sorted")
    expected_bundle_sha = _sha256_payload(
        {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    )
    if bundle.get("bundle_sha256") != expected_bundle_sha:
        raise ReplayBundleError("replay bundle hash mismatch")


def write_validator_replay_bundle(path: Path, report: Mapping[str, Any]) -> Dict[str, Any]:
    bundle = build_validator_replay_bundle(report)
    Path(path).write_text(
        json.dumps(bundle, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return bundle


def load_validator_replay_bundle(path: Path) -> Dict[str, Any]:
    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReplayBundleError(f"duplicate JSON key in replay bundle: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ReplayBundleError(f"non-finite JSON value in replay bundle: {value}")

    try:
        payload = json.loads(
            Path(path).read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReplayBundleError(f"invalid replay bundle: {path}") from exc
    if not isinstance(payload, dict):
        raise ReplayBundleError("replay bundle must be an object")
    validate_validator_replay_bundle(payload)
    return payload
