"""Deterministic, truth-free execution of versioned Validator replay arms."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Protocol, Sequence, Union

from ..common.validator_protocol import parse_validator_result_v3, validator_result_schema_v3
from ..core.validation.evidence import build_validator_evidence_slice_v3
from .replay_bundle import (
    REPLAY_BUNDLE_SCHEMA_VERSION,
    ReplayBundleError,
    canonical_json_sha256,
    validate_validator_replay_bundle,
)


ARM_CATALOG_SCHEMA_VERSION = "zscope.validator-arm-catalog.v1"
REPLAY_RUN_SCHEMA_VERSION = "zscope.validator-replay-run.v1"
DEFAULT_ARM_CATALOG_FILE = "validator_arms.v1.json"
LEGACY_UPPER_BOUND_EXPECTED_TOTAL_TOKENS = 17_000_000
VALIDATOR_ARM_CATALOG_REVISION = 2
FROZEN_QUERY_SCHEMA_VERSION = "zscope.validator-replay-query.v1"
FROZEN_ACTION_SCHEMA_VERSION = "zscope.validator-replay-action.v1"
_CATALOG_FIELDS = frozenset(
    {
        "schema_version",
        "catalog_revision",
        "replay_schema_version",
        "evidence_slice_schema_version",
        "validator_protocol_version",
        "result_schema_version",
        "arms",
        "catalog_sha256",
    }
)
_ARM_FIELDS = frozenset(
    {
        "arm_id",
        "revision",
        "baseline",
        "description",
        "protocol_mode",
        "decision_policy",
        "limits",
        "arm_spec_sha256",
    }
)
_DECISION_POLICY_FIELDS = frozenset(
    {
        "initial_direct_calls",
        "max_mechanical_repair_calls",
        "fact_recheck_enabled",
        "max_fact_requests",
        "require_new_fact_delta",
        "investigation_enabled",
        "investigation_gate",
        "investigation_trajectories",
        "max_tool_queries_per_trajectory",
        "tool_source",
        "executor_usage_scope",
        "investigation_depth",
        "investigation_eligible_severities",
        "investigation_risk_threshold",
        "investigation_max_cluster_percent",
    }
)
_LIMIT_FIELDS = frozenset(
    {
        "max_calls_per_group",
        "max_input_tokens",
        "max_output_tokens",
        "repair_output_tokens",
        "expected_group_tokens",
        "deadline_seconds",
        "concurrency",
        "expected_investigation_tokens",
    }
)
_EXECUTION_IDENTITY_FIELDS = frozenset({"executor_sha256", "model_spec_sha256", "prompt_sha256"})
_EXECUTOR_TRUST_FIELDS = frozenset({"mode", "oci_evidence_sha256"})
_USAGE_FIELDS = frozenset(
    {
        "prompt_tokens",
        "cached_prompt_tokens",
        "completion_tokens",
        "reasoning_tokens",
        "total_tokens",
        "tool_call_count",
        "api_attempt_count",
        "provider_reported",
    }
)
_RUN_FIELDS = frozenset(
    {
        "schema_version",
        "bundle_schema_version",
        "bundle_sha256",
        "source_identity_sha256",
        "arm_catalog_sha256",
        "arm_id",
        "arm_revision",
        "arm_spec_sha256",
        "trial_index",
        "execution_identity",
        "executor_trust",
        "expected_total_tokens",
        "cost_expectation_met",
        "planned_group_count",
        "group_count",
        "groups",
        "usage",
        "answer_material_present",
        "contract",
        "complete",
        "run_sha256",
    }
)
_GROUP_RUN_FIELDS = frozenset(
    {
        "validation_cluster_uid",
        "candidate_uid",
        "group_sha256",
        "slice_sha256",
        "calls",
        "terminal_result",
        "terminal_result_sha256",
        "usage",
        "protocol_errors",
        "protocol_valid",
        "execution_status",
        "group_run_sha256",
    }
)
_CALL_RUN_FIELDS = frozenset(
    {
        "call_index",
        "call_kind",
        "validation_pass",
        "request_sha256",
        "input_sha256",
        "slice_sha256",
        "raw_result_sha256",
        "result",
        "result_sha256",
        "usage",
        "protocol_errors",
    }
)
_CONTRACT_FIELDS = frozenset(
    {
        "truth_access",
        "truth_scoring",
        "group_order",
        "tool_source",
        "cost_evaluation",
        "executor_usage_scope",
        "executor_invocation_scope",
        "legacy_upper_bound_expected_tokens",
        "executor_formal_eligible",
        "executor_trust_mode",
        "trusted_executor_oci_evidence_sha256",
        "investigation_depth",
    }
)


class ValidatorReplayError(ValueError):
    """Raised when a replay arm, call, or result violates the frozen contract."""


@dataclass(frozen=True)
class ReplayCall:
    arm_id: str
    arm_spec_sha256: str
    protocol_mode: str
    trial_index: int
    call_index: int
    call_kind: str
    validation_pass: str
    validation_cluster_uid: str
    candidate_uid: str
    group_sha256: str
    input_sha256: str
    validator_input: Mapping[str, Any]
    decision_policy: Mapping[str, Any]
    limits: Mapping[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "arm_id": self.arm_id,
            "arm_spec_sha256": self.arm_spec_sha256,
            "protocol_mode": self.protocol_mode,
            "trial_index": self.trial_index,
            "call_index": self.call_index,
            "call_kind": self.call_kind,
            "validation_pass": self.validation_pass,
            "validation_cluster_uid": self.validation_cluster_uid,
            "candidate_uid": self.candidate_uid,
            "group_sha256": self.group_sha256,
            "input_sha256": self.input_sha256,
            "validator_input": copy.deepcopy(dict(self.validator_input)),
            "decision_policy": dict(self.decision_policy),
            "limits": dict(self.limits),
        }


class ReplayCallExecutor(Protocol):
    def execute(self, call: ReplayCall) -> Mapping[str, Any]: ...


ReplayExecutor = Union[ReplayCallExecutor, Callable[[ReplayCall], Mapping[str, Any]]]


def _is_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _strict_json_object(path: Path) -> Dict[str, Any]:
    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValidatorReplayError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValidatorReplayError(f"non-finite JSON value: {value}")

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidatorReplayError(f"cannot load replay JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ValidatorReplayError(f"replay JSON must be an object: {path}")
    return value


def _without_hash(value: Mapping[str, Any], field: str) -> Dict[str, Any]:
    return {key: item for key, item in value.items() if key != field}


def validate_validator_arm_catalog(catalog: Mapping[str, Any]) -> None:
    if set(catalog) != _CATALOG_FIELDS:
        raise ValidatorReplayError("validator arm catalog has missing or unknown fields")
    if catalog.get("schema_version") != ARM_CATALOG_SCHEMA_VERSION:
        raise ValidatorReplayError("validator arm catalog schema_version is invalid")
    if catalog.get("catalog_revision") != VALIDATOR_ARM_CATALOG_REVISION:
        raise ValidatorReplayError(
            f"validator arm catalog_revision must be {VALIDATOR_ARM_CATALOG_REVISION}"
        )
    expected_versions = {
        "replay_schema_version": REPLAY_BUNDLE_SCHEMA_VERSION,
        "evidence_slice_schema_version": "zscope.validator-evidence-slice.v3",
        "validator_protocol_version": "zscope.validator-protocol.v3",
        "result_schema_version": "zscope.validator-result.v3",
    }
    for field, expected in expected_versions.items():
        if catalog.get(field) != expected:
            raise ValidatorReplayError(f"validator arm catalog {field} is invalid")
    arms = catalog.get("arms")
    if not isinstance(arms, list) or len(arms) != 5:
        raise ValidatorReplayError("validator arm catalog must contain A-E exactly once")
    identifiers: list[str] = []
    baseline_count = 0
    for index, raw in enumerate(arms):
        if not isinstance(raw, Mapping) or set(raw) != _ARM_FIELDS:
            raise ValidatorReplayError(f"arms[{index}] has missing or unknown fields")
        arm_id = str(raw.get("arm_id") or "")
        identifiers.append(arm_id)
        if (
            isinstance(raw.get("revision"), bool)
            or not isinstance(raw.get("revision"), int)
            or int(raw["revision"]) <= 0
            or not str(raw.get("description") or "")
        ):
            raise ValidatorReplayError(f"arms[{index}] identity is invalid")
        if not isinstance(raw.get("baseline"), bool):
            raise ValidatorReplayError(f"arms[{index}].baseline must be boolean")
        baseline_count += int(raw.get("baseline") is True)
        if raw.get("protocol_mode") not in {
            "legacy_single_turn_bridge",
            "legacy_multi_turn_upper_bound",
            "v3_direct",
            "v3_fact_recheck",
            "v3_bounded_investigation",
        }:
            raise ValidatorReplayError(f"arms[{index}].protocol_mode is invalid")
        policy = raw.get("decision_policy")
        limits = raw.get("limits")
        if not isinstance(policy, Mapping) or set(policy) != _DECISION_POLICY_FIELDS:
            raise ValidatorReplayError(f"arms[{index}].decision_policy is invalid")
        if not isinstance(limits, Mapping) or set(limits) != _LIMIT_FIELDS:
            raise ValidatorReplayError(f"arms[{index}].limits is invalid")
        integer_policy = (
            "initial_direct_calls",
            "max_mechanical_repair_calls",
            "max_fact_requests",
            "investigation_trajectories",
            "max_tool_queries_per_trajectory",
        )
        if any(
            isinstance(policy.get(name), bool)
            or not isinstance(policy.get(name), int)
            or int(policy[name]) < 0
            for name in integer_policy
        ):
            raise ValidatorReplayError(f"arms[{index}] has invalid decision limits")
        if policy.get("initial_direct_calls") != 1:
            raise ValidatorReplayError(f"arms[{index}] must have one initial direct call")
        for name in ("fact_recheck_enabled", "require_new_fact_delta", "investigation_enabled"):
            if not isinstance(policy.get(name), bool):
                raise ValidatorReplayError(f"arms[{index}].{name} must be boolean")
        if policy.get("tool_source") != "frozen_replay_bundle_only":
            raise ValidatorReplayError(f"arms[{index}] permits non-frozen tool data")
        usage_scope = policy.get("executor_usage_scope")
        if usage_scope not in {
            "single_http_attempt",
            "aggregate_all_http_attempts_in_legacy_session",
        }:
            raise ValidatorReplayError(f"arms[{index}] executor usage scope is invalid")
        if policy.get("fact_recheck_enabled") is not (int(policy["max_fact_requests"]) > 0):
            raise ValidatorReplayError(f"arms[{index}] fact recheck settings disagree")
        if policy.get("investigation_enabled") is not (
            int(policy["investigation_trajectories"]) > 0
        ):
            raise ValidatorReplayError(f"arms[{index}] investigation settings disagree")
        investigation_depth = policy.get("investigation_depth")
        eligible_severities = policy.get("investigation_eligible_severities")
        risk_threshold = policy.get("investigation_risk_threshold")
        max_cluster_percent = policy.get("investigation_max_cluster_percent")
        if investigation_depth not in {"disabled", "balanced", "deep"}:
            raise ValidatorReplayError(f"arms[{index}] investigation depth is invalid")
        if (
            not isinstance(eligible_severities, list)
            or eligible_severities != sorted(set(eligible_severities))
            or any(value not in {"critical", "high"} for value in eligible_severities)
            or isinstance(risk_threshold, bool)
            or not isinstance(risk_threshold, int)
            or isinstance(max_cluster_percent, bool)
            or not isinstance(max_cluster_percent, int)
        ):
            raise ValidatorReplayError(f"arms[{index}] investigation gate is invalid")
        expected_gate = {
            "disabled": ([], 0, 0, 0, 0, 0),
            "balanced": (["critical", "high"], 80, 5, 1, 2, 80_000),
            "deep": (["critical", "high"], 60, 20, 2, 3, 160_000),
        }[str(investigation_depth)]
        observed_gate = (
            eligible_severities,
            risk_threshold,
            max_cluster_percent,
            policy.get("investigation_trajectories"),
            policy.get("max_tool_queries_per_trajectory"),
            limits.get("expected_investigation_tokens"),
        )
        if observed_gate != expected_gate:
            raise ValidatorReplayError(f"arms[{index}] investigation gate disagrees")
        for name, value in limits.items():
            if name == "expected_investigation_tokens":
                continue
            if isinstance(value, bool) or not isinstance(value, int) or int(value) <= 0:
                raise ValidatorReplayError(f"arms[{index}].limits.{name} must be positive")
        if (
            isinstance(limits.get("expected_investigation_tokens"), bool)
            or not isinstance(limits.get("expected_investigation_tokens"), int)
            or int(limits["expected_investigation_tokens"]) < 0
        ):
            raise ValidatorReplayError(
                f"arms[{index}].limits.expected_investigation_tokens is invalid"
            )
        if limits.get("concurrency") != 1:
            raise ValidatorReplayError(f"arms[{index}] replay concurrency must be 1")
        legacy_mode = raw.get("protocol_mode") == "legacy_multi_turn_upper_bound"
        if legacy_mode != (arm_id == "E"):
            raise ValidatorReplayError(
                "legacy multi-turn upper-bound protocol must be used by Arm E only"
            )
        expected_usage_scope = (
            "aggregate_all_http_attempts_in_legacy_session"
            if legacy_mode
            else "single_http_attempt"
        )
        if usage_scope != expected_usage_scope:
            raise ValidatorReplayError(f"arms[{index}] executor usage scope disagrees")
        if legacy_mode and (
            policy.get("max_mechanical_repair_calls") != 0
            or policy.get("fact_recheck_enabled") is not False
            or policy.get("investigation_enabled") is not False
            or limits.get("max_calls_per_group") != 1
            or limits.get("expected_group_tokens")
            != LEGACY_UPPER_BOUND_EXPECTED_TOTAL_TOKENS
        ):
            raise ValidatorReplayError(
                "Arm E must delegate one complete legacy session to one executor invocation"
            )
        if not _is_sha256(raw.get("arm_spec_sha256")) or raw.get(
            "arm_spec_sha256"
        ) != canonical_json_sha256(_without_hash(raw, "arm_spec_sha256")):
            raise ValidatorReplayError(f"arms[{index}] arm_spec_sha256 mismatch")
    if identifiers != list("ABCDE") or baseline_count != 1 or arms[0].get("baseline") is not True:
        raise ValidatorReplayError("validator arms must be ordered A-E with A as sole baseline")
    if not _is_sha256(catalog.get("catalog_sha256")) or catalog.get(
        "catalog_sha256"
    ) != canonical_json_sha256(_without_hash(catalog, "catalog_sha256")):
        raise ValidatorReplayError("validator arm catalog_sha256 mismatch")


def load_validator_arm_catalog(path: Optional[Path] = None) -> Dict[str, Any]:
    if path is None:
        resource = files(__package__).joinpath(DEFAULT_ARM_CATALOG_FILE)
        try:
            loaded = json.loads(resource.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidatorReplayError("cannot load packaged validator arm catalog") from exc
        if not isinstance(loaded, dict):
            raise ValidatorReplayError("packaged validator arm catalog must be an object")
        value: Dict[str, Any] = dict(loaded)
    else:
        value = _strict_json_object(Path(path))
    validate_validator_arm_catalog(value)
    return dict(value)


def validator_arm(catalog: Mapping[str, Any], arm_id: str) -> Dict[str, Any]:
    validate_validator_arm_catalog(catalog)
    for raw in catalog["arms"]:
        if raw["arm_id"] == str(arm_id).upper():
            return dict(raw)
    raise ValidatorReplayError(f"unknown validator replay arm: {arm_id}")


def _group_to_validator_input(
    group: Mapping[str, Any],
    *,
    validation_pass: str,
    evidence_delta: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    issue = copy.deepcopy(dict(group["candidate"]))
    issue.update(
        {
            "candidate_uid": group["candidate_uid"],
            "validation_cluster_uid": group["validation_cluster_uid"],
            "occurrence_uids": list(group["occurrence_uids"]),
            "alias_occurrence_uids": list(group["occurrence_uids"])[1:],
            "occurrence_count": len(group["occurrence_uids"]),
            "entries": list(group["entries"]),
        }
    )
    # V1 retains facts that were present in the original evidence pack, while
    # the explicitly named frozen reservoir remains hidden until one typed
    # FACT_RESOLUTION lookup.  The exporter rejects overlap between these two
    # partitions, so the same fact cannot be both V1 evidence and a V2 delta.
    issue = _strip_fact_reservoir(issue)
    evidence_pack = _strip_fact_reservoir(copy.deepcopy(dict(group["evidence"])))
    raw_facts = group.get("facts")
    facts = raw_facts if isinstance(raw_facts, Mapping) else {}
    initial_facts: Dict[str, Any] = {
        key: copy.deepcopy(facts[key])
        for key in ("facts", "decision_facts", "decision_fact_graph", "fact_graph")
        if key in facts
    }
    if initial_facts:
        evidence_pack.setdefault(
            "decision_facts",
            initial_facts.get("decision_facts") or initial_facts.get("facts") or initial_facts,
        )
    function_context = evidence_pack.get("function_context")
    context_code = function_context.get("code") if isinstance(function_context, Mapping) else ""
    issue_code = str(issue.get("code_snippet") or evidence_pack.get("code") or context_code or "")
    evidence_slice = build_validator_evidence_slice_v3(
        issue,
        evidence_pack,
        issue_code,
        validation_pass=validation_pass,
        evidence_delta=evidence_delta,
    )
    return {
        "finding_uid": group["candidate_uid"],
        "candidate_uid": group["candidate_uid"],
        "validation_cluster_uid": group["validation_cluster_uid"],
        "validation_pass": validation_pass,
        "evidence_slice": evidence_slice,
    }


_FACT_RESERVOIR_KEYS = frozenset(
    {
        "frozen_fact_catalog",
        "fact_reservoir",
        "frozen_fact_reservoir",
    }
)


def _strip_fact_reservoir(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _strip_fact_reservoir(item)
            for key, item in value.items()
            if str(key) not in _FACT_RESERVOIR_KEYS
        }
    if isinstance(value, list):
        return [_strip_fact_reservoir(item) for item in value]
    return copy.deepcopy(value)


def _nested_fact_records(value: Any) -> list[Dict[str, Any]]:
    records: list[Dict[str, Any]] = []
    if isinstance(value, Mapping):
        kind = str(value.get("fact_kind") or value.get("kind") or "")
        if kind:
            records.append(copy.deepcopy(dict(value)))
        for item in value.values():
            records.extend(_nested_fact_records(item))
    elif isinstance(value, list):
        for item in value:
            records.extend(_nested_fact_records(item))
    return records


def _fact_record_sha256s(value: Any) -> set[str]:
    return {canonical_json_sha256(item) for item in _nested_fact_records(value)}


def _nested_value_sha256s(value: Any) -> set[str]:
    """Commit every JSON subtree already visible to an investigation turn."""

    result = {canonical_json_sha256(value)}
    if isinstance(value, Mapping):
        for item in value.values():
            result.update(_nested_value_sha256s(item))
    elif isinstance(value, list):
        for item in value:
            result.update(_nested_value_sha256s(item))
    return result


def _fact_uid(value: Mapping[str, Any]) -> str:
    return str(value.get("fact_uid") or value.get("uid") or value.get("id") or "")


def _fact_kind(value: Mapping[str, Any]) -> str:
    return str(value.get("fact_kind") or value.get("kind") or "")


def _fact_reservoir_tiers(group: Mapping[str, Any]) -> list[list[Dict[str, Any]]]:
    raw_facts = group.get("facts")
    facts = raw_facts if isinstance(raw_facts, Mapping) else {}
    preferred: list[Dict[str, Any]] = []
    for key in ("frozen_fact_catalog", "fact_reservoir", "frozen_fact_reservoir"):
        preferred.extend(_nested_fact_records(facts.get(key)))
    return [preferred]


def _all_frozen_fact_tiers(group: Mapping[str, Any]) -> list[list[Dict[str, Any]]]:
    raw_facts = group.get("facts")
    facts = raw_facts if isinstance(raw_facts, Mapping) else {}
    initial: list[Dict[str, Any]] = []
    for key in ("facts", "decision_facts", "decision_fact_graph", "fact_graph"):
        initial.extend(_nested_fact_records(facts.get(key)))
    return [*_fact_reservoir_tiers(group), initial]


def _frozen_fact_delta(
    group: Mapping[str, Any],
    request: Optional[Mapping[str, Any]],
    *,
    initial_fact_sha256s: Optional[set[str]] = None,
) -> Optional[Dict[str, Any]]:
    if not isinstance(request, Mapping):
        return None
    fact_kind = str(request.get("fact_kind") or "")
    already_present = initial_fact_sha256s or set()
    matches: list[Dict[str, Any]] = []
    # FACT_RESOLUTION may only reveal facts from the explicit provider-
    # resolvable reservoir.  Initial facts stay in V1 and can never be replayed
    # as a synthetic delta.
    for tier in _fact_reservoir_tiers(group):
        matches = [
            item
            for item in tier
            if _fact_kind(item) == fact_kind and canonical_json_sha256(item) not in already_present
        ]
        if matches:
            break
    if not matches:
        return None
    unique = {canonical_json_sha256(item): item for item in matches}
    facts = [unique[key] for key in sorted(unique)]
    refs = sorted(
        {
            _fact_uid(item)
            for item in facts
            if str(item.get("fact_uid") or item.get("uid") or item.get("id") or "")
        }
    )
    return {
        "fact_kind": fact_kind,
        "facts": facts,
        "evidence_refs": refs,
        "frozen_source": "validator_replay_bundle.v1",
        "initial_evidence_fact_sha256s": sorted(already_present),
    }


def _frozen_tool_catalog(group: Mapping[str, Any]) -> Dict[str, Any]:
    unique: Dict[str, Dict[str, Any]] = {}
    for tier in _all_frozen_fact_tiers(group):
        for item in tier:
            unique.setdefault(canonical_json_sha256(item), item)
    evidence = group.get("evidence")
    evidence_refs = sorted(
        {str(key) for key in (evidence if isinstance(evidence, Mapping) else {}) if str(key)}
    )
    return {
        "query_schema_version": FROZEN_QUERY_SCHEMA_VERSION,
        "allowed_query_kinds": ["fact_by_kind", "fact_by_uid", "evidence_by_key"],
        "fact_kinds": sorted({_fact_kind(item) for item in unique.values() if _fact_kind(item)}),
        "fact_uids": sorted({_fact_uid(item) for item in unique.values() if _fact_uid(item)}),
        "evidence_keys": evidence_refs,
    }


def _parse_frozen_query(value: Any) -> Optional[Dict[str, str]]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "query_kind",
        "key",
        "reason",
    }:
        return None
    query_kind = value.get("query_kind")
    key = value.get("key")
    reason = value.get("reason")
    if (
        value.get("schema_version") != FROZEN_QUERY_SCHEMA_VERSION
        or query_kind not in {"fact_by_kind", "fact_by_uid", "evidence_by_key"}
        or not isinstance(key, str)
        or not key.strip()
        or len(key) > 512
        or not isinstance(reason, str)
        or not reason.strip()
        or len(reason) > 1000
    ):
        return None
    return {
        "schema_version": FROZEN_QUERY_SCHEMA_VERSION,
        "query_kind": str(query_kind),
        "key": key.strip(),
        "reason": reason.strip(),
    }


def _resolve_frozen_query(group: Mapping[str, Any], query: Mapping[str, str]) -> Dict[str, Any]:
    kind = query["query_kind"]
    key = query["key"]
    values: list[Any] = []
    if kind in {"fact_by_kind", "fact_by_uid"}:
        seen: set[str] = set()
        for tier in _all_frozen_fact_tiers(group):
            for item in tier:
                matches = (
                    _fact_kind(item) == key if kind == "fact_by_kind" else _fact_uid(item) == key
                )
                digest = canonical_json_sha256(item)
                if matches and digest not in seen:
                    seen.add(digest)
                    values.append(copy.deepcopy(item))
            if values:
                break
    else:
        evidence = group.get("evidence")
        if isinstance(evidence, Mapping) and key in evidence:
            values.append(copy.deepcopy(evidence[key]))
    return {
        "query_sha256": canonical_json_sha256(query),
        "query_kind": kind,
        "key": key,
        "values": values,
        "value_sha256s": sorted({canonical_json_sha256(item) for item in values}),
        "frozen_source": "validator_replay_bundle.v1",
    }


def _no_gain_result(
    prior: Mapping[str, Any], *, reasoning: str, validation_pass: Optional[str] = None
) -> Dict[str, Any]:
    return {
        "schema_version": "zscope.validator-result.v3",
        "candidate_uid": str(prior["candidate_uid"]),
        "validation_cluster_uid": str(prior["validation_cluster_uid"]),
        "pass": str(validation_pass or prior["pass"]),
        "verdict": "uncertain",
        "reasoning": reasoning,
        "positive_evidence": list(prior.get("positive_evidence") or []),
        "negative_evidence": list(prior.get("negative_evidence") or []),
        "evidence_refs": list(prior.get("evidence_refs") or []),
        "blocking_negative_evidence": bool(prior.get("blocking_negative_evidence")),
        "missing_fact_request": None,
        "stop_reason": "no_evidence_gain",
    }


def _parse_investigation_action(
    value: Any,
    *,
    candidate_uid: str,
    validation_cluster_uid: str,
    allowed_evidence_refs: Sequence[str],
) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "action",
        "query",
        "result",
    }:
        return None
    action = value.get("action")
    if value.get("schema_version") != FROZEN_ACTION_SCHEMA_VERSION or action not in {
        "query",
        "terminal",
    }:
        return None
    if action == "query":
        query = _parse_frozen_query(value.get("query"))
        if query is None or value.get("result") is not None:
            return None
        return {
            "schema_version": FROZEN_ACTION_SCHEMA_VERSION,
            "action": "query",
            "query": query,
            "result": None,
        }
    parsed = parse_validator_result_v3(
        value.get("result"),
        candidate_uid=candidate_uid,
        validation_cluster_uid=validation_cluster_uid,
        expected_pass="investigation_synthesis",
        allowed_evidence_refs=allowed_evidence_refs,
    )
    if parsed is None or value.get("query") is not None:
        return None
    return {
        "schema_version": FROZEN_ACTION_SCHEMA_VERSION,
        "action": "terminal",
        "query": None,
        "result": parsed.to_dict(),
    }


def _group_risk_score(group: Mapping[str, Any]) -> int:
    candidate = group.get("candidate")
    candidate = candidate if isinstance(candidate, Mapping) else {}
    try:
        explicit = int(candidate.get("risk_score") or candidate.get("priority_score") or 0)
    except (TypeError, ValueError):
        explicit = 0
    severity = str(candidate.get("impact_level") or candidate.get("severity") or "").lower()
    return max(explicit, {"critical": 100, "high": 80, "medium": 60}.get(severity, 0))


def _group_severity(group: Mapping[str, Any]) -> str:
    candidate = group.get("candidate")
    candidate = candidate if isinstance(candidate, Mapping) else {}
    return str(candidate.get("impact_level") or candidate.get("severity") or "").lower()


def _group_externally_reachable(group: Mapping[str, Any]) -> bool:
    candidate = group.get("candidate")
    candidate = candidate if isinstance(candidate, Mapping) else {}
    evidence = group.get("evidence")
    evidence = evidence if isinstance(evidence, Mapping) else {}
    entry = evidence.get("entry_context")
    entry = entry if isinstance(entry, Mapping) else {}
    return bool(
        candidate.get("externally_reachable")
        or candidate.get("reachable_from_entry")
        or entry.get("entry_is_external_root")
        or entry.get("reachable_from_entry")
    )


def _selected_investigation_clusters(
    groups: Sequence[Mapping[str, Any]], policy: Mapping[str, Any]
) -> set[str]:
    if policy.get("investigation_enabled") is not True:
        return set()
    severities = set(str(value) for value in policy["investigation_eligible_severities"])
    threshold = int(policy["investigation_risk_threshold"])
    eligible = [
        group
        for group in groups
        if _group_severity(group) in severities
        and _group_risk_score(group) >= threshold
        and _group_externally_reachable(group)
    ]
    eligible.sort(
        key=lambda group: (
            -_group_risk_score(group),
            str(group.get("validation_cluster_uid") or ""),
        )
    )
    percent = int(policy["investigation_max_cluster_percent"])
    cap = max(1, (len(groups) * percent + 99) // 100) if percent else 0
    return {str(group["validation_cluster_uid"]) for group in eligible[:cap]}


def _validate_execution_identity(value: Mapping[str, Any]) -> Dict[str, str]:
    if set(value) != _EXECUTION_IDENTITY_FIELDS or any(
        not _is_sha256(value.get(field)) for field in _EXECUTION_IDENTITY_FIELDS
    ):
        raise ValidatorReplayError(
            "execution_identity must contain executor/model/prompt SHA-256 bindings"
        )
    return {field: str(value[field]) for field in sorted(_EXECUTION_IDENTITY_FIELDS)}


def _validate_executor_trust(value: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    raw: Mapping[str, Any] = value or {
        "mode": "untrusted_external",
        "oci_evidence_sha256": "",
    }
    if set(raw) != _EXECUTOR_TRUST_FIELDS:
        raise ValidatorReplayError("executor_trust has missing or unknown fields")
    mode = str(raw.get("mode") or "")
    evidence = str(raw.get("oci_evidence_sha256") or "")
    if mode not in {"builtin_provider", "trusted_oci_external", "untrusted_external"}:
        raise ValidatorReplayError("executor_trust mode is invalid")
    if mode == "trusted_oci_external":
        if not _is_sha256(evidence):
            raise ValidatorReplayError("trusted external executor requires OCI evidence SHA-256")
    elif evidence:
        raise ValidatorReplayError("OCI evidence is only valid for a trusted external executor")
    return {"mode": mode, "oci_evidence_sha256": evidence}


def _normalized_usage(value: Any) -> tuple[Dict[str, Any], list[str]]:
    errors: list[str] = []
    raw = value if isinstance(value, Mapping) else {}
    if set(raw) != _USAGE_FIELDS:
        errors.append("executor usage has missing or unknown fields")
    result: Dict[str, Any] = {}
    for field in _USAGE_FIELDS - {"provider_reported"}:
        item = raw.get(field, 0)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            errors.append(f"usage.{field} must be a non-negative integer")
            item = 0
        result[field] = item
    result["provider_reported"] = raw.get("provider_reported") is True
    if raw.get("provider_reported") is not True:
        errors.append("usage is not provider-reported")
    if result["total_tokens"] != result["prompt_tokens"] + result["completion_tokens"]:
        errors.append("usage total_tokens does not equal prompt+completion")
    if result["cached_prompt_tokens"] > result["prompt_tokens"]:
        errors.append("usage cached_prompt_tokens exceeds prompt_tokens")
    if result["reasoning_tokens"] > result["completion_tokens"]:
        errors.append("usage reasoning_tokens exceeds completion_tokens")
    if result["total_tokens"] > 0 and result["api_attempt_count"] <= 0:
        errors.append("usage api_attempt_count must cover every charged HTTP attempt")
    return result, errors


def _forfeited_usage(
    *,
    estimated_input_tokens: int,
    effective_output_limit: int,
    legacy_session_expected_tokens: int,
) -> Dict[str, Any]:
    """Charge an admitted attempt whose provider usage is unknown.

    Unknown provider usage is conservatively measured from the admitted
    request projection.  The benchmark cost expectation never changes which
    calls are executed.
    """

    del legacy_session_expected_tokens
    prompt_tokens = estimated_input_tokens
    completion_tokens = effective_output_limit
    return {
        "prompt_tokens": prompt_tokens,
        "cached_prompt_tokens": 0,
        "completion_tokens": completion_tokens,
        "reasoning_tokens": 0,
        "total_tokens": prompt_tokens + completion_tokens,
        "tool_call_count": 0,
        "api_attempt_count": 1,
        "provider_reported": False,
    }


def _invoke_executor(executor: ReplayExecutor, call: ReplayCall) -> Mapping[str, Any]:
    method = getattr(executor, "execute", None)
    value = method(call) if callable(method) else executor(call)  # type: ignore[misc,operator]
    if not isinstance(value, Mapping):
        raise ValidatorReplayError("replay executor must return an object")
    return value


def _sum_usage(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    numeric = _USAGE_FIELDS - {"provider_reported"}
    return {
        **{field: sum(int(row.get(field) or 0) for row in rows) for field in sorted(numeric)},
        "provider_reported_call_count": sum(row.get("provider_reported") is True for row in rows),
        "call_count": len(rows),
    }


def _conservative_request_input_tokens(
    validator_input: Mapping[str, Any],
    *,
    protocol_mode: str,
    call_kind: str,
) -> int:
    """Reserve complete prompt/schema framing without provider-specific tokenizer claims."""

    framing = {
        "system_prompt_revision": 2,
        "protocol_mode": protocol_mode,
        "call_kind": call_kind,
        "validator_input": validator_input,
        "validator_result_schema": validator_result_schema_v3(),
        "frozen_action_schema_version": FROZEN_ACTION_SCHEMA_VERSION,
        "frozen_query_schema_version": FROZEN_QUERY_SCHEMA_VERSION,
        "forced_final_terminal_bridge": (call_kind == "legacy_forced_final"),
        "response_schema_and_terminal_tool_framing": True,
    }
    byte_count = len(
        json.dumps(
            framing,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    )
    # bytes/3 plus a fixed envelope is deliberately more conservative than
    # the product estimator's bytes/4 approximation.
    return (byte_count + 2) // 3 + 1024


def run_validator_replay(
    bundle: Mapping[str, Any],
    arm: Mapping[str, Any],
    *,
    executor: ReplayExecutor,
    execution_identity: Mapping[str, Any],
    expected_bundle_sha256: str,
    arm_catalog_sha256: str,
    trial_index: int = 1,
    expected_total_tokens: Optional[int] = None,
    executor_trust: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute one arm without accepting a truth path, truth object, or repository handle."""

    validate_validator_replay_bundle(bundle)
    if bundle.get("bundle_sha256") != expected_bundle_sha256 or not _is_sha256(
        expected_bundle_sha256
    ):
        raise ValidatorReplayError("replay bundle does not match the externally expected SHA-256")
    if not _is_sha256(arm_catalog_sha256):
        raise ValidatorReplayError("arm catalog SHA-256 binding is invalid")
    identity = _validate_execution_identity(execution_identity)
    trust = _validate_executor_trust(executor_trust)
    if not isinstance(trial_index, int) or isinstance(trial_index, bool) or trial_index <= 0:
        raise ValidatorReplayError("trial_index must be a positive integer")
    if expected_total_tokens is not None and (
        isinstance(expected_total_tokens, bool)
        or not isinstance(expected_total_tokens, int)
        or expected_total_tokens <= 0
    ):
        raise ValidatorReplayError("expected_total_tokens must be a positive integer")
    if not isinstance(arm, Mapping) or set(arm) != _ARM_FIELDS:
        raise ValidatorReplayError("validator arm spec has invalid fields")
    if arm.get("arm_spec_sha256") != canonical_json_sha256(_without_hash(arm, "arm_spec_sha256")):
        raise ValidatorReplayError("validator arm spec hash mismatch")

    policy = arm["decision_policy"]
    limits = arm["limits"]
    legacy_session_mode = arm.get("protocol_mode") == "legacy_multi_turn_upper_bound"
    expected_usage_scope = (
        "aggregate_all_http_attempts_in_legacy_session"
        if legacy_session_mode
        else "single_http_attempt"
    )
    if policy.get("executor_usage_scope") != expected_usage_scope:
        raise ValidatorReplayError("arm executor usage scope disagrees with protocol mode")
    if legacy_session_mode and (
        arm.get("arm_id") != "E"
        or policy.get("max_mechanical_repair_calls") != 0
        or policy.get("fact_recheck_enabled") is not False
        or policy.get("investigation_enabled") is not False
        or limits.get("max_calls_per_group") != 1
        or limits.get("expected_group_tokens") != LEGACY_UPPER_BOUND_EXPECTED_TOTAL_TOKENS
    ):
        raise ValidatorReplayError("Arm E legacy session contract is invalid")

    frozen_bundle_sha = canonical_json_sha256(_without_hash(bundle, "bundle_sha256"))
    group_rows: list[Dict[str, Any]] = []
    all_usage: list[Mapping[str, Any]] = []
    investigation_clusters = _selected_investigation_clusters(
        list(bundle["canonical_groups"]), policy
    )

    for group in bundle["canonical_groups"]:
        calls: list[Dict[str, Any]] = []
        terminal: Optional[Dict[str, Any]] = None
        group_errors: list[str] = []
        group_usage: list[Mapping[str, Any]] = []
        call_index = 0
        initial_fact_sha256s: set[str] = set()
        initial_evidence_slice: Dict[str, Any] = {}
        resolved_evidence_sha256s: set[str] = set()
        v2_completed = False

        def run_call(
            call_kind: str,
            validation_pass: str,
            evidence_delta: Optional[Mapping[str, Any]] = None,
            repair_of_sha256: str = "",
            validator_input_override: Optional[Mapping[str, Any]] = None,
            investigation_call: bool = False,
        ) -> Optional[Dict[str, Any]]:
            nonlocal call_index
            nonlocal initial_fact_sha256s, initial_evidence_slice
            nonlocal resolved_evidence_sha256s
            call_index += 1
            if call_index > int(limits["max_calls_per_group"]):
                group_errors.append("arm max_calls_per_group exceeded")
                return None
            validator_input = (
                copy.deepcopy(dict(validator_input_override))
                if validator_input_override is not None
                else _group_to_validator_input(
                    group,
                    validation_pass=validation_pass,
                    evidence_delta=evidence_delta,
                )
            )
            if repair_of_sha256:
                validator_input["repair_of_sha256"] = repair_of_sha256
            input_sha = canonical_json_sha256(validator_input)
            slice_sha = canonical_json_sha256(validator_input["evidence_slice"])
            estimated_input_tokens = _conservative_request_input_tokens(
                validator_input,
                protocol_mode=str(arm["protocol_mode"]),
                call_kind=call_kind,
            )
            if estimated_input_tokens > int(limits["max_input_tokens"]):
                raise ValidatorReplayError(
                    "replay evidence slice exceeds the arm max_input_tokens limit"
                )
            effective_output_limit = int(
                limits["repair_output_tokens"]
                if call_kind == "format_repair"
                else limits["max_output_tokens"]
            )
            projected_tokens = estimated_input_tokens + effective_output_limit
            call = ReplayCall(
                arm_id=str(arm["arm_id"]),
                arm_spec_sha256=str(arm["arm_spec_sha256"]),
                protocol_mode=str(arm["protocol_mode"]),
                trial_index=trial_index,
                call_index=call_index,
                call_kind=call_kind,
                validation_pass=validation_pass,
                validation_cluster_uid=str(group["validation_cluster_uid"]),
                candidate_uid=str(group["candidate_uid"]),
                group_sha256=str(group["group_sha256"]),
                input_sha256=input_sha,
                validator_input=copy.deepcopy(validator_input),
                decision_policy=dict(policy),
                limits={
                    **dict(limits),
                    "effective_max_output_tokens": effective_output_limit,
                    "run_expected_total_tokens": int(expected_total_tokens or 0),
                    "projected_tokens_for_call": projected_tokens,
                    "executor_usage_scope": policy["executor_usage_scope"],
                    "legacy_session_expected_tokens": (
                        int(limits["expected_group_tokens"]) if legacy_session_mode else 0
                    ),
                    "investigation_trajectories": int(policy["investigation_trajectories"]),
                    "max_tool_queries_per_trajectory": int(
                        policy["max_tool_queries_per_trajectory"]
                    ),
                    "tool_source": policy["tool_source"],
                },
            )
            if call_kind in {"direct", "legacy_forced_final"} and validation_pass == "initial":
                initial_evidence_slice = copy.deepcopy(
                    dict(validator_input.get("evidence_slice") or {})
                )
                initial_fact_sha256s = _fact_record_sha256s(initial_evidence_slice)
                resolved_evidence_sha256s = _nested_value_sha256s(initial_evidence_slice)
            request_sha = canonical_json_sha256(call.as_dict())
            call_errors: list[str] = []
            raw_result: Any = None
            raw_result_sha = ""
            usage: Dict[str, Any] = {field: 0 for field in _USAGE_FIELDS - {"provider_reported"}}
            usage["provider_reported"] = False
            try:
                response = _invoke_executor(executor, call)
                if set(response) != {"result", "usage", "execution_identity"}:
                    call_errors.append("executor response has missing or unknown fields")
                try:
                    observed_identity = _validate_execution_identity(
                        response.get("execution_identity")  # type: ignore[arg-type]
                        if isinstance(response.get("execution_identity"), Mapping)
                        else {}
                    )
                    if observed_identity != identity:
                        call_errors.append(
                            "executor execution_identity does not match the run binding"
                        )
                except ValidatorReplayError as exc:
                    call_errors.append(str(exc))
                usage, usage_errors = _normalized_usage(response.get("usage"))
                call_errors.extend(usage_errors)
                if usage_errors:
                    usage = _forfeited_usage(
                        estimated_input_tokens=estimated_input_tokens,
                        effective_output_limit=effective_output_limit,
                        legacy_session_expected_tokens=int(
                            call.limits["legacy_session_expected_tokens"]
                        ),
                    )
                    call_errors.append("unknown provider usage forfeited full reservation")
                raw_result = response.get("result")
                try:
                    raw_result_sha = canonical_json_sha256(raw_result)
                except (TypeError, ValueError):
                    call_errors.append("executor result is not canonical JSON")
            except Exception as exc:
                call_errors.append(f"executor failure: {type(exc).__name__}")
                # A connection failure after admission has unknown provider
                # usage.  Conservatively charge the complete reservation so a
                # repair or later cluster cannot spend the same budget again.
                usage = _forfeited_usage(
                    estimated_input_tokens=estimated_input_tokens,
                    effective_output_limit=effective_output_limit,
                    legacy_session_expected_tokens=int(
                        call.limits["legacy_session_expected_tokens"]
                    ),
                )
                call_errors.append("unknown provider usage forfeited full reservation")
            group_usage.append(usage)
            all_usage.append(usage)
            if int(usage.get("completion_tokens") or 0) > effective_output_limit:
                attempt_count = max(1, int(usage.get("api_attempt_count") or 0))
                if (
                    not legacy_session_mode
                    or int(usage.get("completion_tokens") or 0)
                    > effective_output_limit * attempt_count
                ):
                    call_errors.append("executor exceeded the arm output-token limit")
            if not legacy_session_mode and int(usage.get("api_attempt_count") or 0) != 1:
                call_errors.append(
                    "non-legacy executor invocation must represent exactly one HTTP attempt"
                )
            if canonical_json_sha256(call.validator_input) != input_sha:
                call_errors.append("executor mutated the replay call input")
            if canonical_json_sha256(call.as_dict()) != request_sha:
                call_errors.append("executor mutated the replay call contract")
            if canonical_json_sha256(_without_hash(bundle, "bundle_sha256")) != frozen_bundle_sha:
                raise ValidatorReplayError("executor mutated the replay bundle")
            catalog = call.validator_input["evidence_slice"].get("evidence_ref_catalog") or {}
            parsed_result: Optional[Dict[str, Any]]
            if investigation_call:
                action = _parse_investigation_action(
                    raw_result,
                    candidate_uid=str(group["candidate_uid"]),
                    validation_cluster_uid=str(group["validation_cluster_uid"]),
                    allowed_evidence_refs=list(catalog),
                )
                if action is None:
                    call_errors.append("executor result violates frozen investigation action")
                    parsed_result = None
                else:
                    parsed_result = action
            else:
                parsed = parse_validator_result_v3(
                    raw_result,
                    candidate_uid=str(group["candidate_uid"]),
                    validation_cluster_uid=str(group["validation_cluster_uid"]),
                    expected_pass=validation_pass,
                    allowed_evidence_refs=catalog,
                )
                if parsed is None:
                    call_errors.append("executor result violates ValidatorResult v3")
                parsed_result = parsed.to_dict() if parsed is not None else None
            record = {
                "call_index": call_index,
                "call_kind": call_kind,
                "validation_pass": validation_pass,
                "request_sha256": request_sha,
                "input_sha256": input_sha,
                "slice_sha256": slice_sha,
                "raw_result_sha256": raw_result_sha,
                "result": parsed_result,
                "result_sha256": (
                    canonical_json_sha256(parsed_result) if parsed_result is not None else ""
                ),
                "usage": usage,
                "protocol_errors": call_errors,
            }
            calls.append(record)
            group_errors.extend(call_errors)
            return parsed_result

        def call_with_repair(
            call_kind: str,
            validation_pass: str,
            evidence_delta: Optional[Mapping[str, Any]] = None,
        ) -> Optional[Dict[str, Any]]:
            result = run_call(call_kind, validation_pass, evidence_delta)
            if (
                result is not None
                or int(policy["max_mechanical_repair_calls"]) <= 0
            ):
                return result
            repair_hash = calls[-1]["raw_result_sha256"] if calls else ""
            return run_call(
                "format_repair",
                validation_pass,
                evidence_delta,
                repair_of_sha256=repair_hash,
            )

        def run_bounded_investigation(prior: Mapping[str, Any]) -> Dict[str, Any]:
            evidence_slice = copy.deepcopy(initial_evidence_slice)
            evidence_slice["validation_pass"] = "investigation_synthesis"
            evidence_slice["frozen_tool_catalog"] = _frozen_tool_catalog(group)
            transcript: list[Dict[str, Any]] = []
            # Query results must add evidence that was absent from both V1 and
            # the typed V2 delta. Re-reading a known fact consumes one query
            # and triggers the production no-gain stop rule.
            seen_value_sha256s: set[str] = set(resolved_evidence_sha256s)
            for query_index in range(int(policy["max_tool_queries_per_trajectory"]) + 1):
                investigation_input = {
                    "finding_uid": group["candidate_uid"],
                    "candidate_uid": group["candidate_uid"],
                    "validation_cluster_uid": group["validation_cluster_uid"],
                    "validation_pass": "investigation_synthesis",
                    "evidence_slice": {
                        **copy.deepcopy(evidence_slice),
                        "investigation_transcript": copy.deepcopy(transcript),
                    },
                }
                action = run_call(
                    "bounded_investigation_turn",
                    "investigation_synthesis",
                    validator_input_override=investigation_input,
                    investigation_call=True,
                )
                if action is None:
                    return _no_gain_result(
                        prior,
                        validation_pass="investigation_synthesis",
                        reasoning=(
                            "The frozen investigation session ended without a valid bounded action."
                        ),
                    )
                if action.get("action") == "terminal":
                    result = action.get("result")
                    if isinstance(result, Mapping):
                        return dict(result)
                    break
                if query_index >= int(policy["max_tool_queries_per_trajectory"]):
                    group_errors.append("frozen investigation exceeded query limit")
                    break
                query = action.get("query")
                if not isinstance(query, Mapping):
                    group_errors.append("frozen investigation query is invalid")
                    break
                resolved = _resolve_frozen_query(group, query)  # type: ignore[arg-type]
                value_hashes = set(str(value) for value in resolved["value_sha256s"])
                new_hashes = value_hashes - seen_value_sha256s
                ref_catalog = evidence_slice.get("evidence_ref_catalog")
                if not isinstance(ref_catalog, dict):
                    ref_catalog = {}
                    evidence_slice["evidence_ref_catalog"] = ref_catalog
                for value in resolved["values"]:
                    if not isinstance(value, Mapping):
                        continue
                    uid = _fact_uid(value)
                    if uid:
                        ref_catalog[uid] = copy.deepcopy(dict(value))
                transcript.append(
                    {
                        "query": copy.deepcopy(dict(query)),
                        "result": resolved,
                        "new_evidence_sha256s": sorted(new_hashes),
                    }
                )
                if not new_hashes:
                    return _no_gain_result(
                        prior,
                        validation_pass="investigation_synthesis",
                        reasoning=(
                            "A bounded frozen query added no new evidence; investigation stopped."
                        ),
                    )
                seen_value_sha256s.update(new_hashes)
            return _no_gain_result(
                prior,
                validation_pass="investigation_synthesis",
                reasoning="The bounded frozen investigation query limit was exhausted.",
            )

        if legacy_session_mode:
            terminal = run_call("legacy_multi_turn_session", "initial")
        else:
            initial_kind = (
                "legacy_forced_final"
                if arm.get("protocol_mode") == "legacy_single_turn_bridge"
                else "direct"
            )
            terminal = call_with_repair(initial_kind, "initial")
        if (
            terminal is not None
            and terminal.get("verdict") == "uncertain"
            and policy["fact_recheck_enabled"] is True
            and terminal.get("missing_fact_request") is not None
        ):
            delta = _frozen_fact_delta(
                group,
                terminal.get("missing_fact_request"),
                initial_fact_sha256s=initial_fact_sha256s,
            )
            if delta is not None:
                delta_sha = canonical_json_sha256(delta)
                if not policy["require_new_fact_delta"] or delta_sha != canonical_json_sha256({}):
                    resolved_evidence_sha256s.update(_nested_value_sha256s(delta))
                    terminal = call_with_repair("fact_recheck", "evidence_recheck", delta)
                    v2_completed = terminal is not None
            else:
                terminal = _no_gain_result(
                    terminal,
                    reasoning=(
                        "FACT_RESOLUTION found no frozen fact absent from the initial V1 slice."
                    ),
                )
        if (
            terminal is not None
            and terminal.get("verdict") == "uncertain"
            and policy["investigation_enabled"] is True
            and v2_completed
            and str(group["validation_cluster_uid"]) in investigation_clusters
        ):
            terminal = run_bounded_investigation(terminal)

        total_usage = _sum_usage(group_usage)
        non_blocking_errors = {
            "executor result violates ValidatorResult v3",
        }
        blocking_errors = [error for error in group_errors if error not in non_blocking_errors]
        execution_status = "complete" if terminal is not None and not blocking_errors else "invalid"
        group_row: Dict[str, Any] = {
            "validation_cluster_uid": group["validation_cluster_uid"],
            "candidate_uid": group["candidate_uid"],
            "group_sha256": group["group_sha256"],
            "slice_sha256": calls[0]["slice_sha256"] if calls else "",
            "calls": calls,
            "terminal_result": terminal,
            "terminal_result_sha256": (
                canonical_json_sha256(terminal) if terminal is not None else ""
            ),
            "usage": total_usage,
            "protocol_errors": list(dict.fromkeys(group_errors)),
            "protocol_valid": not group_errors,
            "execution_status": execution_status,
        }
        group_row["group_run_sha256"] = canonical_json_sha256(group_row)
        group_rows.append(group_row)

    usage = _sum_usage(all_usage)
    planned_group_count = len(bundle["canonical_groups"])
    cost_expectation_met = bool(
        expected_total_tokens is None or usage["total_tokens"] <= expected_total_tokens
    )
    result: Dict[str, Any] = {
        "schema_version": REPLAY_RUN_SCHEMA_VERSION,
        "bundle_schema_version": bundle["schema_version"],
        "bundle_sha256": bundle["bundle_sha256"],
        "source_identity_sha256": bundle["source_identity"]["identity_sha256"],
        "arm_catalog_sha256": arm_catalog_sha256,
        "arm_id": arm["arm_id"],
        "arm_revision": arm["revision"],
        "arm_spec_sha256": arm["arm_spec_sha256"],
        "trial_index": trial_index,
        "execution_identity": identity,
        "executor_trust": trust,
        "expected_total_tokens": int(expected_total_tokens or 0),
        "cost_expectation_met": cost_expectation_met,
        "planned_group_count": planned_group_count,
        "group_count": len(group_rows),
        "groups": group_rows,
        "usage": usage,
        "answer_material_present": False,
        "contract": {
            "truth_access": "forbidden",
            "truth_scoring": "independent_after_replay",
            "group_order": "validation_cluster_uid_ascending",
            "tool_source": "frozen_replay_bundle_only",
            "cost_evaluation": "after_complete_replay_no_runtime_token_admission",
            "executor_usage_scope": policy["executor_usage_scope"],
            "executor_invocation_scope": (
                "one_complete_legacy_multi_turn_session_per_validation_cluster"
                if legacy_session_mode
                else "one_http_attempt"
            ),
            "legacy_upper_bound_expected_tokens": (
                LEGACY_UPPER_BOUND_EXPECTED_TOTAL_TOKENS if legacy_session_mode else 0
            ),
            "executor_formal_eligible": trust["mode"]
            in {
                "builtin_provider",
                "trusted_oci_external",
            },
            "executor_trust_mode": trust["mode"],
            "trusted_executor_oci_evidence_sha256": trust["oci_evidence_sha256"],
            "investigation_depth": str(policy["investigation_depth"]),
        },
        "complete": len(group_rows) == planned_group_count
        and all(row["execution_status"] == "complete" for row in group_rows),
    }
    result["run_sha256"] = canonical_json_sha256(result)
    validate_validator_replay_run(result)
    return result


def validate_validator_replay_run(result: Mapping[str, Any]) -> None:
    """Validate the answer-free result ledger and its complete hash chain."""

    if set(result) != _RUN_FIELDS or result.get("schema_version") != REPLAY_RUN_SCHEMA_VERSION:
        raise ValidatorReplayError("validator replay run has an invalid top-level schema")
    if result.get("bundle_schema_version") != REPLAY_BUNDLE_SCHEMA_VERSION:
        raise ValidatorReplayError("validator replay run bundle schema binding is invalid")
    for field in (
        "bundle_sha256",
        "source_identity_sha256",
        "arm_catalog_sha256",
        "arm_spec_sha256",
    ):
        if not _is_sha256(result.get(field)):
            raise ValidatorReplayError(f"validator replay run {field} is not SHA-256")
    if result.get("answer_material_present") is not False:
        raise ValidatorReplayError("validator replay run declares answer material")
    contract = result.get("contract")
    if not isinstance(contract, Mapping) or set(contract) != _CONTRACT_FIELDS:
        raise ValidatorReplayError("validator replay run contract is invalid")
    if (
        contract.get("truth_access") != "forbidden"
        or contract.get("truth_scoring") != "independent_after_replay"
    ):
        raise ValidatorReplayError("validator replay run truth contract is invalid")
    if contract.get("tool_source") != "frozen_replay_bundle_only":
        raise ValidatorReplayError("validator replay run tool source is invalid")
    usage_scope = contract.get("executor_usage_scope")
    if usage_scope not in {
        "single_http_attempt",
        "aggregate_all_http_attempts_in_legacy_session",
    }:
        raise ValidatorReplayError("validator replay run executor usage scope is invalid")
    legacy_contract = usage_scope == "aggregate_all_http_attempts_in_legacy_session"
    if legacy_contract != (result.get("arm_id") == "E"):
        raise ValidatorReplayError("validator replay run Arm E usage contract disagrees")
    if contract.get("executor_invocation_scope") != (
        "one_complete_legacy_multi_turn_session_per_validation_cluster"
        if legacy_contract
        else "one_http_attempt"
    ):
        raise ValidatorReplayError("validator replay run executor invocation scope disagrees")
    if contract.get("cost_evaluation") != "after_complete_replay_no_runtime_token_admission":
        raise ValidatorReplayError("validator replay cost evaluation contract is invalid")
    if contract.get("legacy_upper_bound_expected_tokens") != (
        LEGACY_UPPER_BOUND_EXPECTED_TOTAL_TOKENS if legacy_contract else 0
    ):
        raise ValidatorReplayError("validator replay run legacy upper-bound contract disagrees")
    raw_execution_identity = result.get("execution_identity")
    execution_identity: Mapping[str, Any] = (
        raw_execution_identity if isinstance(raw_execution_identity, Mapping) else {}
    )
    _validate_execution_identity(execution_identity)
    raw_executor_trust = result.get("executor_trust")
    executor_trust = _validate_executor_trust(
        raw_executor_trust if isinstance(raw_executor_trust, Mapping) else None
    )
    if (
        contract.get("executor_trust_mode") != executor_trust["mode"]
        or contract.get("trusted_executor_oci_evidence_sha256")
        != executor_trust["oci_evidence_sha256"]
        or contract.get("executor_formal_eligible")
        is not (executor_trust["mode"] in {"builtin_provider", "trusted_oci_external"})
    ):
        raise ValidatorReplayError("validator replay executor trust contract disagrees")
    expected_depth = "balanced" if result.get("arm_id") == "D" else "disabled"
    if contract.get("investigation_depth") != expected_depth:
        raise ValidatorReplayError("validator replay investigation depth contract disagrees")
    groups = result.get("groups")
    if not isinstance(groups, list) or result.get("group_count") != len(groups):
        raise ValidatorReplayError("validator replay run group_count mismatch")
    expected_total_tokens = result.get("expected_total_tokens")
    if (
        isinstance(expected_total_tokens, bool)
        or not isinstance(expected_total_tokens, int)
        or expected_total_tokens < 0
    ):
        raise ValidatorReplayError("validator replay run expected_total_tokens is invalid")
    planned_group_count = result.get("planned_group_count")
    if (
        isinstance(planned_group_count, bool)
        or not isinstance(planned_group_count, int)
        or planned_group_count != len(groups)
    ):
        raise ValidatorReplayError("validator replay run planned group count disagrees")
    if not isinstance(result.get("cost_expectation_met"), bool):
        raise ValidatorReplayError("validator replay cost expectation status is invalid")
    group_usage_rows: list[Mapping[str, Any]] = []
    for group_index, group in enumerate(groups):
        if not isinstance(group, Mapping) or set(group) != _GROUP_RUN_FIELDS:
            raise ValidatorReplayError(f"validator replay groups[{group_index}] schema is invalid")
        expected_group_run_sha = canonical_json_sha256(_without_hash(group, "group_run_sha256"))
        if group.get("group_run_sha256") != expected_group_run_sha:
            raise ValidatorReplayError(f"validator replay groups[{group_index}] hash mismatch")
        calls = group.get("calls")
        if not isinstance(calls, list) or not calls:
            raise ValidatorReplayError(f"validator replay groups[{group_index}] has no calls")
        call_usage_rows: list[Mapping[str, Any]] = []
        for call_index, call in enumerate(calls, start=1):
            if not isinstance(call, Mapping) or set(call) != _CALL_RUN_FIELDS:
                raise ValidatorReplayError(
                    f"validator replay groups[{group_index}].calls[{call_index - 1}] schema is invalid"
                )
            if call.get("call_index") != call_index:
                raise ValidatorReplayError("validator replay call indexes are not contiguous")
            parsed = call.get("result")
            if parsed is not None and call.get("result_sha256") != canonical_json_sha256(parsed):
                raise ValidatorReplayError("validator replay call result hash mismatch")
            usage, errors = _normalized_usage(call.get("usage"))
            if errors:
                # Invalid usage remains audit-visible in an incomplete ledger;
                # its normalized counters must nevertheless conserve.
                usage = dict(call.get("usage") or {})
            call_usage_rows.append(usage)
        expected_group_usage = _sum_usage(call_usage_rows)
        if group.get("usage") != expected_group_usage:
            raise ValidatorReplayError("validator replay group usage does not conserve")
        terminal = group.get("terminal_result")
        expected_terminal_sha = canonical_json_sha256(terminal) if terminal is not None else ""
        if group.get("terminal_result_sha256") != expected_terminal_sha:
            raise ValidatorReplayError("validator replay terminal result hash mismatch")
        group_usage_rows.extend(call_usage_rows)
    if result.get("usage") != _sum_usage(group_usage_rows):
        raise ValidatorReplayError("validator replay run usage does not conserve")
    total_tokens = int(_sum_usage(group_usage_rows)["total_tokens"])
    expected_cost_status = bool(
        not expected_total_tokens or total_tokens <= expected_total_tokens
    )
    if result.get("cost_expectation_met") is not expected_cost_status:
        raise ValidatorReplayError("validator replay cost expectation status disagrees")
    expected_complete = all(group.get("execution_status") == "complete" for group in groups)
    if result.get("complete") is not expected_complete:
        raise ValidatorReplayError("validator replay complete status disagrees")
    if result.get("run_sha256") != canonical_json_sha256(_without_hash(result, "run_sha256")):
        raise ValidatorReplayError("validator replay run hash mismatch")


def write_validator_replay_run(path: Path, result: Mapping[str, Any]) -> None:
    validate_validator_replay_run(result)
    Path(path).write_text(
        json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def load_validator_replay_run(path: Path) -> Dict[str, Any]:
    result = _strict_json_object(Path(path))
    validate_validator_replay_run(result)
    return result
