#!/usr/bin/env python3
"""Run a non-formal, answer-free V3 EvidenceAction model canary.

The command consumes only a hash-verified action preflight plus its frozen
decision traces and current source snapshot.  It never accepts a truth file or
score report.  Each selected cluster gets one fresh Validator V3 session with
the same finite actions used by the product runtime.  The result is diagnostic
and can authorize a cold pilot only when the separate trace-integrity and
benchmark gates also pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.prepare_v3_action_canary import (
    _canonical,
    _endpoint,
    _inside,
    _json,
    _location,
    _model_input,
    _select_currently_eligible,
    _sha,
    _v3_records,
)
from zscope.agents.validator_agent.agent import ValidatorAgent
from zscope.config.config import ConfigLoader
from zscope.core.validation.fact_capabilities import (
    EvidenceAction,
    FunctionIRFactService,
)
from zscope.framework.llm_client import LLMClient
from zscope.framework.llm_usage import llm_usage_attribution_scope
from zscope.orchestration.decision_trace import DecisionTraceError


def _verify_preflight(path: Path, expected_sha256: str) -> Dict[str, Any]:
    preflight = _json(path)
    supplied = str(preflight.get("artifact_sha256") or "")
    if supplied != expected_sha256:
        raise DecisionTraceError("preflight SHA does not match the external binding")
    body = dict(preflight)
    body.pop("artifact_sha256", None)
    if supplied != _sha(body):
        raise DecisionTraceError("preflight artifact hash mismatch")
    if preflight.get("ready_for_model_canary") is not True:
        raise DecisionTraceError("action preflight did not pass its model-canary gate")
    if preflight.get("model_calls") != 0:
        raise DecisionTraceError("action preflight unexpectedly contains model calls")
    if preflight.get("truth_inputs") != 0:
        raise DecisionTraceError("action preflight is not answer-free")
    return preflight


def _v3_token_delta(trace: Mapping[str, Any]) -> int:
    return sum(
        int(event.get("token_delta") or 0)
        for event in trace.get("events") or []
        if isinstance(event, Mapping) and event.get("stage") == "V3"
    )


def _runtime_rows(
    *,
    trace_root: Path,
    source_root: Path,
    service: FunctionIRFactService,
    limit: int,
) -> list[Dict[str, Any]]:
    historical: list[Dict[str, Any]] = []
    for cluster_uid, trace, entered in _v3_records(trace_root):
        structured = _model_input(trace_root, trace)
        raw_slice = structured.get("evidence_slice")
        evidence_slice = deepcopy(dict(raw_slice)) if isinstance(raw_slice, Mapping) else {}
        obligation = evidence_slice.get("obligation")
        if not isinstance(obligation, Mapping):
            raise DecisionTraceError(f"{cluster_uid} has no structured obligation")
        relative_file, line = _location(obligation)
        source_file = _inside(source_root, relative_file)
        details = entered.get("details")
        details = details if isinstance(details, Mapping) else {}
        required = tuple(
            sorted(
                {
                    str(value).strip().lower()
                    for value in details.get("required_fact_kinds") or []
                    if str(value).strip()
                }
            )
        )
        candidate_uid = str(obligation.get("candidate_uid") or "")
        decision_facts = evidence_slice.get("decision_facts")
        decision_facts = (
            deepcopy(dict(decision_facts)) if isinstance(decision_facts, Mapping) else {}
        )
        decision_facts["missing_fact_kinds"] = list(required)
        evidence_slice["decision_facts"] = decision_facts
        evidence_slice["obligation"] = {
            **dict(obligation),
            "required_fact_kinds": list(required),
        }
        issue: Dict[str, Any] = {
            "candidate_uid": candidate_uid,
            "validation_cluster_uid": cluster_uid,
            "function": str(obligation.get("function") or ""),
            "file": str(source_file),
            "line": line,
            "category": str(obligation.get("category") or ""),
            "defect_family": str(obligation.get("defect_family") or ""),
            "source": _endpoint(obligation.get("source_uid")),
            "sink": _endpoint(obligation.get("sink_uid")),
            "security_obligation": dict(evidence_slice["obligation"]),
            "decision_fact_slice": decision_facts,
            "missing_fact_kinds": list(required),
        }
        actions = service.actions(issue, evidence_slice, required)
        historical.append(
            {
                "validation_cluster_uid": cluster_uid,
                "candidate_uid": candidate_uid,
                "required_fact_kinds": list(required),
                "actions": [value.to_dict() for value in actions],
                "issue": issue,
                "evidence_slice": evidence_slice,
                "historical_v3_tokens": _v3_token_delta(trace),
            }
        )
    selected, _excluded = _select_currently_eligible(historical, limit=limit)
    return selected


def _client(config: Any) -> tuple[LLMClient, Any, str]:
    profile = str(getattr(config.scan.llm_profiles, "validation", "") or "default")
    llm_cfg = config.llms.get(profile) or config.llms.get("default")
    if llm_cfg is None:
        raise DecisionTraceError("validation LLM profile is unavailable")
    client = LLMClient(
        api_key=llm_cfg.api_key,
        base_url=getattr(llm_cfg, "base_urls", None) or llm_cfg.base_url,
        models=llm_cfg.models,
        timeout=llm_cfg.timeout,
        max_retries=llm_cfg.max_retries,
        retry_until_available=getattr(llm_cfg, "retry_until_available", False),
        max_tokens=llm_cfg.max_tokens,
        base_url_rate_limit_per_minute=getattr(
            llm_cfg,
            "base_url_rate_limit_per_minute",
            0,
        ),
        base_url_max_concurrent_requests=getattr(
            llm_cfg,
            "base_url_max_concurrent_requests",
            0,
        ),
        global_max_concurrent_requests=config.concurrency.llm_max_inflight,
        supports_structured_output=getattr(llm_cfg, "supports_structured_output", False),
        token_usage_ledger=config.scan_token_usage_ledger,
        llm_ref=profile,
    )
    return client, config.scan_token_usage_ledger, profile


def _action_from_mapping(raw: Mapping[str, Any]) -> EvidenceAction:
    return EvidenceAction(
        action_id=str(raw.get("action_id") or ""),
        fact_kind=str(raw.get("fact_kind") or ""),
        provider_id=str(raw.get("provider_id") or ""),
        verifier_id=str(raw.get("verifier_id") or ""),
        subject_uid=str(raw.get("subject_uid") or ""),
        decision_region_uid=str(raw.get("decision_region_uid") or ""),
        fixed_parameters=dict(raw.get("fixed_parameters") or {}),
        description=str(raw.get("description") or ""),
        cost_class=str(raw.get("cost_class") or "local_cfg"),
        schema_version=str(raw.get("schema_version") or "zscope.evidence-action.v1"),
    )


def run_canary(
    *,
    preflight_path: Path,
    expected_preflight_sha256: str,
    trace_root: Path,
    source_root: Path,
    compile_commands_path: Path,
    config_path: Path,
    limit: int,
) -> Dict[str, Any]:
    preflight = _verify_preflight(preflight_path, expected_preflight_sha256)
    trace_root = trace_root.resolve()
    source_root = source_root.resolve()
    compile_commands_path = compile_commands_path.resolve()
    config = ConfigLoader.load(str(config_path.resolve()), scan_depth="balanced")
    service = FunctionIRFactService(compile_commands_path, enabled=True)
    rows = _runtime_rows(
        trace_root=trace_root,
        source_root=source_root,
        service=service,
        limit=limit,
    )
    selected_ids = [str(value["validation_cluster_uid"]) for value in rows]
    preflight_ids = [
        str(value.get("validation_cluster_uid") or "")
        for value in preflight.get("clusters") or []
        if isinstance(value, Mapping)
    ]
    if selected_ids != preflight_ids:
        raise DecisionTraceError("current eligible cluster set differs from the preflight")
    preflight_action_ids = {
        str(value.get("validation_cluster_uid") or ""): [
            str(action.get("action_id") or "")
            for action in value.get("actions") or []
            if isinstance(action, Mapping)
        ]
        for value in preflight.get("clusters") or []
        if isinstance(value, Mapping)
    }
    current_action_ids = {
        str(value["validation_cluster_uid"]): [
            str(action.get("action_id") or "")
            for action in value["actions"]
            if isinstance(action, Mapping)
        ]
        for value in rows
    }
    if current_action_ids != preflight_action_ids:
        raise DecisionTraceError("current evidence actions differ from the preflight")
    if hashlib.sha256(compile_commands_path.read_bytes()).hexdigest() != str(
        preflight.get("compile_commands_sha256") or ""
    ):
        raise DecisionTraceError("compile database changed after preflight")
    source_hashes = preflight.get("source_file_sha256")
    source_hashes = source_hashes if isinstance(source_hashes, Mapping) else {}
    for relative, expected in source_hashes.items():
        source_file = _inside(source_root, str(relative))
        if hashlib.sha256(source_file.read_bytes()).hexdigest() != str(expected):
            raise DecisionTraceError(f"source file changed after preflight: {relative}")

    client, usage_ledger, profile = _client(config)
    results: list[Dict[str, Any]] = []
    protocol_error_count = 0
    print(
        f"V3 action canary: {len(rows)} eligible cluster(s), profile={profile}",
        file=sys.stderr,
        flush=True,
    )
    try:
        for row_index, row in enumerate(rows, start=1):
            cluster_uid = str(row["validation_cluster_uid"])
            candidate_uid = str(row["candidate_uid"])
            issue = deepcopy(dict(row["issue"]))
            evidence_slice = deepcopy(dict(row["evidence_slice"]))
            action_values = [
                _action_from_mapping(value)
                for value in row["actions"]
                if isinstance(value, Mapping)
            ]
            action_by_id = {value.action_id: value for value in action_values}
            remaining = set(str(value) for value in row["required_fact_kinds"])
            closed: set[str] = set()
            certificate_sha256: list[str] = []

            def execute(action_id: str) -> Dict[str, Any]:
                action = action_by_id.get(str(action_id or ""))
                if action is None:
                    return {
                        "status": "unknown",
                        "reason_code": "unknown_evidence_action",
                        "verified_fact": None,
                    }
                if action.fact_kind not in remaining:
                    return {
                        "status": "unknown",
                        "reason_code": "evidence_action_clause_already_closed",
                        "verified_fact": None,
                        "terminal_authority": {
                            "terminal": not bool(service.actions(issue, evidence_slice, remaining)),
                            "disposition": "needs_review",
                        },
                    }
                outcome = service.execute(action, issue, evidence_slice)
                fact = outcome.fact
                if isinstance(fact, Mapping):
                    satisfies = {
                        str(value) for value in fact.get("satisfies_fact_kinds") or [] if str(value)
                    }
                    newly_closed = remaining & satisfies
                    closed.update(newly_closed)
                    remaining.difference_update(newly_closed)
                certificate_hash = str(outcome.certificate.get("certificate_sha256") or "")
                if certificate_hash:
                    certificate_sha256.append(certificate_hash)
                proof = fact.get("deterministic_proof") if isinstance(fact, Mapping) else None
                proof = proof if isinstance(proof, Mapping) else {}
                proof_outcome = str(proof.get("outcome") or "")
                if proof_outcome == "confirm":
                    terminal = {"terminal": True, "disposition": "confirmed"}
                elif proof_outcome == "reject":
                    terminal = {
                        "terminal": True,
                        "disposition": "rejected_with_proof",
                    }
                else:
                    has_action = bool(service.actions(issue, evidence_slice, remaining))
                    terminal = {
                        "terminal": not has_action,
                        "disposition": "needs_review",
                    }
                payload = outcome.to_dict()
                payload["terminal_authority"] = terminal
                return payload

            input_data = {
                "finding_uid": candidate_uid,
                "validation_cluster_uid": cluster_uid,
                "validation_pass": "investigation_synthesis",
                "evidence_slice": evidence_slice,
            }
            with llm_usage_attribution_scope(
                agent="validator_agent",
                stage="validation",
                call_kind="targeted_investigation",
                candidate_uid=candidate_uid,
                validation_cluster_uid=cluster_uid,
            ):
                response = ValidatorAgent(client, []).investigate(
                    input_data,
                    max_iterations=50,
                    evidence_actions=[value.to_dict() for value in action_values],
                    evidence_action_executor=execute,
                )
            metadata = dict(response.metadata or {})
            response_data = dict(response.data or {}) if isinstance(response.data, Mapping) else {}
            diagnostic_text = _canonical(
                {
                    "error": response.error,
                    "response": response_data,
                    "metadata": metadata,
                }
            )
            protocol_errors = sorted(
                value
                for value in (
                    "unknown_evidence_ref",
                    "claim_arguments_not_replayed",
                    "provider_semantic_mismatch",
                )
                if value in diagnostic_text
            )
            protocol_error_count += len(protocol_errors)
            cluster_result = {
                "validation_cluster_uid": cluster_uid,
                "candidate_uid": candidate_uid,
                "required_fact_kinds": list(row["required_fact_kinds"]),
                "closed_fact_kinds": sorted(closed),
                "remaining_fact_kinds": sorted(remaining),
                "action_count": len(action_values),
                "certificate_sha256": sorted(set(certificate_sha256)),
                "model_success": response.success is True,
                "verdict": str(response_data.get("verdict") or ""),
                "stop_reason": str(response_data.get("stop_reason") or ""),
                "model_iterations": int(metadata.get("iterations") or 0),
                "tool_call_count": int(metadata.get("tool_call_count") or 0),
                "new_fact_count": int(metadata.get("new_fact_count") or 0),
                "prompt_tokens": int(metadata.get("cumulative_prompt_tokens") or 0),
                "completion_tokens": int(metadata.get("cumulative_completion_tokens") or 0),
                "total_tokens": int(metadata.get("cumulative_total_tokens") or 0),
                "historical_v3_tokens": int(row["historical_v3_tokens"]),
                "protocol_errors": protocol_errors,
            }
            results.append(cluster_result)
            closed_label = ",".join(sorted(closed)) or "-"
            print(
                "V3 action canary "
                f"[{row_index}/{len(rows)}] {cluster_uid}: "
                f"calls={cluster_result['model_iterations']} "
                f"tokens={cluster_result['total_tokens']} "
                f"closed={closed_label}",
                file=sys.stderr,
                flush=True,
            )
    finally:
        client.close()

    provider_usage = client.usage_snapshot()
    usage_snapshot = usage_ledger.snapshot(include_events=False)
    current_tokens = sum(int(value["total_tokens"]) for value in results)
    comparable_rows = [value for value in results if int(value["historical_v3_tokens"]) > 0]
    historical_tokens = sum(int(value["historical_v3_tokens"]) for value in comparable_rows)
    comparable_current_tokens = sum(int(value["total_tokens"]) for value in comparable_rows)
    closing = sum(bool(value["closed_fact_kinds"]) for value in results)
    comparable_reduction = (
        1.0 - (comparable_current_tokens / historical_tokens) if historical_tokens else None
    )
    passed = bool(
        len(results) >= 3
        and closing >= 3
        and protocol_error_count == 0
        and float(provider_usage.get("provider_usage_coverage") or 0.0) == 1.0
        and comparable_reduction is not None
        and comparable_reduction >= 0.5
    )
    body: Dict[str, Any] = {
        "schema_version": "zscope.v3-action-model-canary.v1",
        "formal_eligible": False,
        "answer_material_present": False,
        "preflight_artifact_sha256": expected_preflight_sha256,
        "trace_manifest_sha256": str(preflight.get("trace_manifest_sha256") or ""),
        "trace_manifest_complete": preflight.get("trace_manifest_complete") is True,
        "validation_llm_profile": profile,
        "selected_cluster_count": len(results),
        "clusters_closing_at_least_one_clause": closing,
        "protocol_error_count": protocol_error_count,
        "historical_comparable_v3_tokens": historical_tokens,
        "comparable_cluster_count": len(comparable_rows),
        "current_comparable_v3_tokens": comparable_current_tokens,
        "current_v3_tokens": current_tokens,
        "comparable_token_reduction": comparable_reduction,
        "provider_usage": provider_usage,
        "usage_ledger": usage_snapshot,
        "model_canary_passed": passed,
        "truth_inputs": 0,
        "clusters": results,
    }
    body["artifact_sha256"] = _sha(body)
    return body


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the answer-free finite-action Validator V3 model canary"
    )
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--expected-preflight-sha256", required=True)
    parser.add_argument("--trace-root", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--compile-commands", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.limit < 1 or args.limit > 12:
        parser.error("--limit must be between 1 and 12")
    result = run_canary(
        preflight_path=args.preflight,
        expected_preflight_sha256=str(args.expected_preflight_sha256),
        trace_root=args.trace_root,
        source_root=args.source_root,
        compile_commands_path=args.compile_commands,
        config_path=args.config,
        limit=args.limit,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0 if result["model_canary_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
