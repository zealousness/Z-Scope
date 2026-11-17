"""Content-bound reuse of one closed, structured initial Validator call.

These records are model responses, never proof receipts or policy decisions.
The caller still builds current evidence and runs the current validation policy.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from ...common.validator_protocol import parse_validator_result_v3

INITIAL_REUSE_PROTOCOL = "zscope.validator-initial-cache.v1"
INITIAL_REUSE_RECORD = "zscope.validator-initial-record.v1"
INITIAL_CANDIDATE = "CAND_INITIAL_REQUEST"
INITIAL_CLUSTER = "VAL_INITIAL_REQUEST"


def initial_request_view(input_data: dict[str, Any]) -> dict[str, Any]:
    """Use request-local envelope IDs on both cold and reused model calls.

    Native subjects, fact/edge refs, code, paths, coverage and all unknown
    fields remain exact. Only the known revision-bound display envelope is
    rebound; the Ledger and report keep their original identities.
    """
    view = deepcopy(input_data)
    view["_initial_trace_identity"] = {
        "candidate_uid": input_data.get("finding_uid"),
        "validation_cluster_uid": input_data.get("validation_cluster_uid"),
    }
    view["finding_uid"] = INITIAL_CANDIDATE
    view["validation_cluster_uid"] = INITIAL_CLUSTER
    evidence = view["evidence_slice"]
    obligation = evidence.setdefault("obligation", {})
    obligation["candidate_uid"] = INITIAL_CANDIDATE
    obligation["validation_cluster_uid"] = INITIAL_CLUSTER
    if "obligation_uid" in obligation:
        obligation["obligation_uid"] = "OBL_INITIAL_REQUEST"
    occurrence = evidence.get("canonical_occurrence")
    if isinstance(occurrence, dict) and "occurrence_uid" in occurrence:
        occurrence["occurrence_uid"] = "OCC_INITIAL_REQUEST"
    # This commitment is report provenance, not decision evidence. Its raw
    # occurrence IDs contain the commit even when all decision inputs agree.
    aliases = evidence.get("alias_summary")
    if isinstance(aliases, dict):
        aliases.pop("alias_uid_set_hash", None)
    return view


def parse_initial_response(value: Any, request_view: Mapping[str, Any]) -> dict[str, Any] | None:
    evidence = request_view["evidence_slice"]
    parsed = parse_validator_result_v3(
        value,
        candidate_uid=INITIAL_CANDIDATE,
        validation_cluster_uid=INITIAL_CLUSTER,
        expected_pass="initial",
        allowed_evidence_refs=list(evidence.get("evidence_ref_catalog") or {}),
    )
    if parsed is None:
        return None
    return parsed.to_dict()


def reusable_initial_response(value: Any, request_view: Mapping[str, Any]) -> bool:
    parsed = parse_initial_response(value, request_view)
    return bool(
        parsed
        and parsed["verdict"] in {"verified", "rejected"}
        and parsed["stop_reason"] == "decision_complete"
        and parsed["missing_fact_request"] is None
    )


def rebind_initial_response(value: Any, input_data: Mapping[str, Any]) -> Any:
    """Bind protocol/audit identity values without rewriting free text."""
    obligation = input_data["evidence_slice"].get("obligation") or {}
    bindings = {
        INITIAL_CANDIDATE: input_data.get("finding_uid") or obligation.get("candidate_uid"),
        INITIAL_CLUSTER: input_data.get("validation_cluster_uid")
        or obligation.get("validation_cluster_uid"),
    }

    def rebound(item: Any) -> Any:
        if isinstance(item, dict):
            return {key: rebound(nested) for key, nested in item.items()}
        if isinstance(item, list):
            return [rebound(nested) for nested in item]
        if isinstance(item, str):
            return bindings.get(item, item)
        return item

    return rebound(value)


def initial_reuse_metrics() -> dict[str, Any]:
    return {
        "queries": 0,
        "hits": 0,
        "misses": 0,
        "writes": 0,
        "bypassed": 0,
        "model_tasks": 0,
        "tokens": 0,
        "miss_reasons": {},
        "bypass_reasons": {},
        "write_skip_reasons": {},
    }


def merge_initial_reuse_metrics(target: dict[str, Any], source: Mapping[str, Any]) -> None:
    for key in initial_reuse_metrics():
        value = source.get(key)
        if isinstance(value, dict):
            counts = target.setdefault(key, {})
            for reason, count in value.items():
                counts[reason] = int(counts.get(reason, 0)) + int(count)
        elif value is not None:
            target[key] = int(target.get(key, 0)) + int(value)
