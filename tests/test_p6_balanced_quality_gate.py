from __future__ import annotations

import copy
import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

from scripts.p6_balanced_quality_gate import (
    FAILURE_AGGREGATE_SCHEMA_VERSION,
    MAX_BALANCED_TOKENS,
    P6BalancedQualityGateError,
    P6BalancedQualityGateFailure,
    SCHEMA_VERSION,
    build_quality_gate,
    load_quality_gate,
    main,
    validate_quality_failure_aggregate,
)
from zscope.benchmarking.provider_runtime import P6_PROVIDER_MODEL, P6_PROVIDER_RESPONSE_MODEL
from zscope.benchmarking.p6_sidecar_evidence import build_trace_sidecar_evidence
from zscope.core.validation.audit_eligibility import (
    revalidate_v4_producer_occurrence_binding,
)
from zscope.core.validation.authority import TerminalAuthorityEvaluator
from zscope.core.validation.fact_capabilities import FunctionIRFactService
from zscope.core.validation.function_ir import FunctionIRGraph
from zscope.core.validation.proof_kernel import ProofKernelEngine
from zscope.orchestration.candidate_envelope import annotate_issue_identity
from zscope.reporting.finding_roots import _has_complete_deterministic_proof


REPO_ROOT = Path(__file__).resolve().parents[1]


@lru_cache(maxsize=1)
def _confirmed_v4() -> dict[str, Any]:
    call = {
        "callee": "malloc",
        "line": 4,
        "callee_decl_identity": (
            '{"kind":"FunctionDecl","name":"malloc",' '"type":"void *(size_t)"}'
        ),
        "callee_binding_complete": True,
        "callee_decl_origin": "external_declaration",
        "callee_project_definition": False,
        "result_type": "void *",
        "arg_count": 1,
        "argument_kinds": ["IntegerLiteral"],
        "argument_types": ["int"],
        "argument_refs": [[]],
        "argument_ref_types": [{}],
        "first_argument_refs": [],
    }
    graph = FunctionIRGraph.from_clang_evidence(
        {
            "clang_path": "clang",
            "code_snapshot_sha256": "d" * 64,
            "cfg_dump": {
                "summary": {
                    "parse_ok": True,
                    "function": "resource_target",
                    "function_section_unique": True,
                    "entry_blocks": ["B1"],
                    "exit_blocks": ["B0"],
                    "blocks": [
                        {
                            "id": "B1",
                            "label": "(ENTRY)",
                            "successors": ["B0"],
                            "predecessors": [],
                            "statements": ["p = malloc(8)"],
                        },
                        {
                            "id": "B0",
                            "label": "(EXIT)",
                            "successors": [],
                            "predecessors": ["B1"],
                            "statements": [],
                        },
                    ],
                }
            },
            "ast_dump": {
                "summary": {
                    "parse_ok": True,
                    "target_function": {
                        "call_exprs": [call],
                        "call_assignments": [{**call, "target": "p"}],
                        "var_decls": [
                            {
                                "name": "p",
                                "type": "void *",
                                "line": 4,
                                "storage_class": "",
                            }
                        ],
                        "value_fact_coverage_complete": True,
                    },
                }
            },
        },
        function="resource_target",
        file="src/resource.c",
    )
    assert graph is not None and graph.coverage_complete is True
    carrier: dict[str, Any] = {
        "candidate_source": "llm",
        "candidate_disposition": "confirmed",
        "status": "confirmed",
        "file": "src/resource.c",
        "line": 4,
        "location": "src/resource.c:4",
        "function": "resource_target",
        "category": "memory_leak",
        "defect_class": "memory_leak",
        "source": {
            "kind": "resource_acquire",
            "function": "resource_target",
            "file": "src/resource.c",
            "line": 4,
            "operation": "malloc",
            "resource": "p",
        },
        "sink": {
            "kind": "exit",
            "function": "resource_target",
            "file": "src/resource.c",
            "line": 4,
            "resource": "p",
        },
        "resource": "p",
        "function_ir_graph": graph.to_dict(),
        "decision_fact_graph_v1": True,
        "decision_context_v31": True,
        "decision_context_v32": True,
        "decision_context_v33": True,
        "security_obligation_v1": True,
        "missing_fact_kinds": [],
        "validator_evidence_actions": [],
    }
    annotate_issue_identity(
        carrier,
        project_id="p6-balanced-quality-test",
        revision="rev-p6-balanced-quality-test",
    )
    frozen = FunctionIRFactService(None, enabled=False).build_composite_proof_input(
        carrier,
        {},
    )
    assert frozen is not None
    selected_action_uids = tuple(map(str, frozen["selected_action_uids"]))
    evaluation = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=frozen["proof_ir"],
        obligation=frozen["proof_obligation"],
        selected_action_uids=selected_action_uids,
    )
    assert evaluation.closure_evaluation.complete is True
    carrier["proof_kernel_input"] = frozen
    carrier["proof_kernel_input_origin"] = "product_composite_obligation_v4"
    carrier["proof_kernel_checker_results"] = [dict(value) for value in evaluation.check_results]
    carrier["proof_kernel_live_selected_action_uids"] = list(selected_action_uids)
    evaluation.apply_to_issue(carrier)
    producer_binding, occurrence_binding = revalidate_v4_producer_occurrence_binding(carrier)
    assert producer_binding and occurrence_binding
    carrier["proof_kernel_producer_binding_sha256"] = producer_binding
    carrier["proof_kernel_occurrence_binding_sha256"] = occurrence_binding
    authority = TerminalAuthorityEvaluator().evaluate(carrier, operation="live").to_dict()
    assert authority["terminal"] is True
    assert authority["disposition"] == "confirmed"
    carrier["proof_kernel_terminal_authority_decision"] = authority
    carrier["terminal_authority_decision"] = authority
    return carrier


def _view(truth_count: int, tp: int, fp: int, *, prefix: str) -> dict:
    return {
        "ground_truth_count": truth_count,
        "true_positives": tp,
        "false_negatives": truth_count - tp,
        "false_positives_raw": fp,
        "matched": [f"{prefix}-{index:03d}" for index in range(tp)],
    }


def _truth_id_commitment(truth_id: str) -> str:
    return hashlib.sha256(
        json.dumps(
            {"truth_id": truth_id},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _partition_commitments(product_ids: list[str], design_ids: list[str]) -> dict[str, Any]:
    def partition(member_ids: list[str]) -> dict[str, Any]:
        members = sorted(_truth_id_commitment(value) for value in member_ids)
        return {
            "member_count": len(members),
            "member_commitments": members,
            "member_commitments_sha256": hashlib.sha256(
                json.dumps(members, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
        }

    product = partition(product_ids)
    design = partition(design_ids)
    union = sorted(set(product["member_commitments"]) | set(design["member_commitments"]))
    value = {
        "schema_version": "zscope.p6-truth-partition-projection.v1",
        "truth_sha256": "3" * 64,
        "product": product,
        "design_risk": design,
        "partitions_disjoint": True,
        "union_member_count": len(union),
        "union_member_commitments_sha256": hashlib.sha256(
            json.dumps(union, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "answer_material_present": False,
    }
    value["content_sha256"] = hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    return value


def _trace_sidecar_evidence() -> dict[str, Any]:
    manifest = {
        "trace_count": 0,
        "coverage_trace_count": 0,
        "evidence_object_count": 0,
        "model_event_count": 0,
        "traces": {},
        "coverage_traces": {},
        "evidence_object_sha256": [],
        "model_event_sha256": [],
        "complete": True,
    }
    return build_trace_sidecar_evidence(
        manifest_path="decision_trace_manifest.json",
        manifest_payload=json.dumps(manifest, sort_keys=True).encode("utf-8"),
        sidecar_payloads={},
    )


def test_confirmed_product_v4_binds_distinct_registrar_and_proof_obligations() -> None:
    carrier = copy.deepcopy(_confirmed_v4())
    registrar_obligation = carrier["security_obligation"]
    proof_obligation = carrier["proof_kernel_input"]["proof_obligation"]

    assert registrar_obligation["obligation_uid"].startswith("OBL_")
    assert proof_obligation["obligation_uid"].startswith("POBL_")
    assert registrar_obligation["obligation_uid"] != proof_obligation["obligation_uid"]
    assert _has_complete_deterministic_proof(carrier) is True

    tampered = copy.deepcopy(carrier)
    tampered["proof_kernel_input"]["proof_obligation"]["obligation_uid"] = "POBL_tampered"
    assert _has_complete_deterministic_proof(tampered) is False


def _producer_projection() -> dict:
    calls = 8
    usage = {
        "physical_call_count": calls,
        "provider_reported_call_count": calls,
        "estimated_call_count": 0,
        "provider_usage_coverage": 1.0,
        "requested_model": "deepseek-v4-flash",
        "requested_model_coverage": 1.0,
        "response_model": "deepseek-v4-flash-ga-260731",
        "response_model_coverage": 1.0,
        "queue_empty": True,
        "dimensions": {
            name: {"numerator": calls, "denominator": calls, "conserved": True}
            for name in ("token", "tool", "trace", "finding", "terminal")
        },
    }
    return {
        "schema_version": "zscope.p6-depth-projection.v1",
        "scan_depth": "balanced",
        "control_plane_commit": "c" * 40,
        "producer_attempt_id": "p6-balanced-local-1",
        "artifact_sha256": "d" * 64,
        "git_sha": "1" * 40,
        "git_tree": "2" * 40,
        "provider_identity_sha256": "4" * 64,
        "call_count": calls,
        "provider_usage_coverage": 1.0,
        "provider_response_model_coverage": 1.0,
        "estimated_provider_call_count": 0,
        "queue_empty": True,
        "token_conservation_passed": True,
        "telemetry_complete_rate": 1.0,
        "eligible_count": 8,
        "entered_count": 8,
        "usage_conservation": usage,
        "toolchain_evidence_sha256": "e" * 64,
        "oci_image_ref": "python:3.13@sha256:" + "7" * 64,
        "oci_image_digest": "sha256:" + "7" * 64,
        "oci_image_id": "sha256:" + "f" * 64,
        "runtime_source_sha256": "5" * 64,
        "toolchain_oci_execution_sha256": "a" * 64,
        "oci_execution_sha256": "b" * 64,
        "cache_identity_sha256": "8" * 64,
        "cache_empty_at_start": True,
        "cache_reused": False,
        "formal_benchmark": False,
        "release_eligible": False,
    }


def _inputs() -> tuple[dict, dict, dict, dict, dict, dict, dict, dict]:
    confirmed = copy.deepcopy(_confirmed_v4())
    review = {
        "candidate_disposition": "needs_review",
        "validation_cluster_uid": "VAL_review",
        "status": "needs_review",
        "obligation_uid": "OBL_review",
    }
    report = {
        "answer_material_present": False,
        "run_manifest": {"validation_queue_drained": True},
        "metadata": {"audit_observation_count": 0, "audit_observations": []},
        "issues": [confirmed],
        "candidate_terminal_states": [confirmed, review],
        "report_views": {
            "default": {"issues": [confirmed]},
            "with_needs_review": {"issues": [confirmed, review]},
        },
    }
    legacy = {
        "p6_frozen_report_sha256": "9" * 64,
        "tokens": MAX_BALANCED_TOKENS,
        "queue_empty": True,
        "token_conservation_passed": True,
        "provider_response_model_missing_count": 0,
        "provider_response_model_mismatch_count": 0,
        "requested_model_mismatch_count": 0,
        "provider_usage_coverage": 1.0,
        "provider_response_model_coverage": 1.0,
        "provider_response_model_successful_call_count": 8,
        "provider_response_model_counts": {
            P6_PROVIDER_MODEL: 0,
            P6_PROVIDER_RESPONSE_MODEL: 8,
        },
        "provider_response_model_counts_conserved": True,
        "estimated_provider_call_count": 0,
        "failed_or_unknown_call_count": 0,
        "budget_violation_count": 0,
        "telemetry_complete_rate": 1.0,
        "protocol_anomaly_count": 0,
        "usage_accounting": {
            "complete": True,
            "conservation_passed": True,
            "provider_usage_coverage": 1.0,
            "totals": {
                "total_tokens": MAX_BALANCED_TOKENS,
                "estimated_or_conservative_calls": 0,
            },
        },
        "p6_conservation": {
            "physical_call_count": 8,
            "provider_reported_call_count": 8,
            "estimated_call_count": 0,
            "queue_empty": True,
            "dimensions": {
                name: {"numerator": 8, "denominator": 8, "conserved": True}
                for name in ("token", "tool", "trace", "finding", "terminal")
            },
        },
        "p6_admission_conservation": {
            "enabled": True,
            "request_count": 8,
            "admitted_request_count": 8,
            "denied_request_count": 0,
            "denied_reasons": {},
            "request_conservation_passed": True,
            "zero_call_denial_conservation_passed": True,
        },
        "p6_retry_conservation": {
            "maximum_transport_retries": 1,
            "maximum_contract_regenerations": 1,
            "logical_call_chain_count": 8,
            "physical_attempt_count": 8,
            "pre_model_rejection_count": 0,
            "transport_retry_count": 0,
            "maximum_observed_attempt_index": 1,
            "contract_regeneration_operation_count": 0,
            "maximum_observed_contract_regenerations": 0,
            "call_chain_conservation_passed": True,
            "contract_regeneration_conservation_passed": True,
            "passed": True,
        },
        "p6_terminal_authority": {
            "terminal_trace_count": 2,
            "confirmed_terminal_count": 1,
            "confirmed_v4_report_count": 1,
            "confirmed_v4_trace_count": 1,
            "post_terminal_model_call_count": 0,
            "post_terminal_tool_call_count": 0,
            "call_trace_conservation_passed": True,
            "tool_trace_conservation_passed": True,
            "model_event_trace_conservation_passed": True,
            "passed": True,
        },
        "report_views": {
            "default": _view(136, 96, 10, prefix="legacy"),
            "with_needs_review": _view(136, 125, 100, prefix="legacy"),
        },
    }
    # Ensure default is a subset while retaining the exact review TP count.
    legacy["report_views"]["with_needs_review"]["matched"] = [
        *legacy["report_views"]["default"]["matched"],
        *[f"legacy-extra-{index:03d}" for index in range(29)],
    ]
    v16 = {
        "p6_frozen_report_sha256": "9" * 64,
        "product": {
            "default": _view(61, 43, 4, prefix="v16"),
            "with_needs_review": _view(61, 61, 40, prefix="v16"),
        },
        "design_risk": {
            "default": {
                "truth_count": 75,
                "true_positives": 4,
                "matched": [f"risk-{index}" for index in range(4)],
            },
            "with_needs_review": {
                "truth_count": 75,
                "true_positives": 8,
                "matched": [f"risk-{index}" for index in range(8)],
            },
        },
    }
    v16["product"]["with_needs_review"]["matched"] = [
        *v16["product"]["default"]["matched"],
        *[f"v16-extra-{index:03d}" for index in range(18)],
    ]
    v16["p6_truth_partition_projection"] = _partition_commitments(
        list(v16["product"]["with_needs_review"]["matched"]),
        [f"risk-{index}" for index in range(75)],
    )
    bindings = {
        "git_commit": "1" * 40,
        "git_tree": "2" * 40,
        "candidate_sha256": hashlib.sha256(("1" * 40).encode("utf-8")).hexdigest(),
        "provider_identity_sha256": "4" * 64,
        "runtime_sha256": "5" * 64,
        "config_sha256": "6" * 64,
        "oci_image_digest": "sha256:" + "7" * 64,
        "cold_cache_identity": "8" * 64,
        "selected_attempt_id": "p6-balanced-local-1",
    }
    projection = _producer_projection()
    artifacts = {
        "bindings": "e" * 64,
        "frozen_manifest": "f" * 64,
        "report": "9" * 64,
        "legacy_score": "a" * 64,
        "v16_score": "b" * 64,
        "v16_truth_partitions": "2" * 64,
        "producer_projection": "c" * 64,
        "trace_sidecars": "1" * 64,
        "usage_events": "0" * 64,
        "usage_evidence": "d" * 64,
    }
    frozen_manifest = {
        "schema_version": "zscope.p6-balanced-frozen-scan.v3",
        "workflow_run_id": "33260000001",
        "workflow_run_attempt": 1,
        "control_plane_commit": "c" * 40,
        "candidate_git_sha": bindings["git_commit"],
        "candidate_git_tree": bindings["git_tree"],
        "attempt_id": bindings["selected_attempt_id"],
        "llm_usage_events_sha256": "0" * 64,
        "llm_usage_events_call_count": 8,
        "trace_sidecars_sha256": artifacts["trace_sidecars"],
        "trace_sidecar_member_count": 1,
        "trace_count": 0,
        "coverage_trace_count": 0,
        "evidence_object_count": 0,
        "model_event_count": 0,
        "report_sha256": artifacts["report"],
        "bindings_sha256": artifacts["bindings"],
        "usage_evidence_sha256": "d" * 64,
        "projection_sha256": artifacts["producer_projection"],
        "answer_material_present": False,
        "formal_benchmark": False,
        "release_eligible": False,
    }
    frozen_manifest["content_sha256"] = hashlib.sha256(
        json.dumps(
            frozen_manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    usage_evidence = {
        "schema_version": "zscope.p6-balanced-usage-evidence.v3",
        "workflow_run_id": frozen_manifest["workflow_run_id"],
        "workflow_run_attempt": frozen_manifest["workflow_run_attempt"],
        "attempt_id": frozen_manifest["attempt_id"],
        "llm_usage_events_sha256": frozen_manifest["llm_usage_events_sha256"],
        "llm_usage_events_call_count": frozen_manifest["llm_usage_events_call_count"],
        "trace_sidecars_sha256": frozen_manifest["trace_sidecars_sha256"],
        "trace_sidecar_member_count": frozen_manifest["trace_sidecar_member_count"],
        "trace_count": frozen_manifest["trace_count"],
        "coverage_trace_count": frozen_manifest["coverage_trace_count"],
        "evidence_object_count": frozen_manifest["evidence_object_count"],
        "model_event_count": frozen_manifest["model_event_count"],
        "score_fields": {
            name: copy.deepcopy(legacy[name])
            for name in (
                "tokens",
                "queue_empty",
                "token_conservation_passed",
                "provider_response_model_missing_count",
                "provider_response_model_mismatch_count",
                "requested_model_mismatch_count",
                "provider_usage_coverage",
                "provider_response_model_coverage",
                "provider_response_model_successful_call_count",
                "provider_response_model_counts",
                "provider_response_model_counts_conserved",
                "estimated_provider_call_count",
                "failed_or_unknown_call_count",
                "budget_violation_count",
                "telemetry_complete_rate",
                "protocol_anomaly_count",
                "usage_accounting",
                "p6_conservation",
                "p6_admission_conservation",
                "p6_retry_conservation",
                "p6_terminal_authority",
            )
        },
        "answer_material_present": False,
        "formal_benchmark": False,
        "release_eligible": False,
    }
    usage_evidence["content_sha256"] = hashlib.sha256(
        json.dumps(
            usage_evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    return (
        report,
        legacy,
        v16,
        projection,
        bindings,
        frozen_manifest,
        usage_evidence,
        artifacts,
    )


def _build(parts: tuple[dict, dict, dict, dict, dict, dict, dict, dict]) -> dict:
    report, legacy, v16, projection, bindings, frozen_manifest, usage, artifacts = parts
    return build_quality_gate(
        report=report,
        legacy_score=legacy,
        v16_score=v16,
        v16_truth_partitions=v16["p6_truth_partition_projection"],
        producer_projection=projection,
        bindings=bindings,
        frozen_manifest=frozen_manifest,
        usage_evidence=usage,
        usage_events_call_count=8,
        trace_sidecars=_trace_sidecar_evidence(),
        artifact_sha256s=artifacts,
    )


def test_quality_gate_uses_integer_cross_products_and_keeps_design_risk_separate() -> None:
    result = _build(_inputs())
    assert result["schema_version"] == SCHEMA_VERSION
    assert result["hard_gate_passed"] is True
    assert result["challenge_passed"] is False
    assert result["legacy_v15"]["default"]["hard"]["passed"] is True
    assert result["truth_v16"]["product"]["with_needs_review"]["hard"]["passed"] is True
    assert result["truth_v16"]["design_risk"]["default"]["truth_count"] == 75
    assert result["truth_v16"]["design_risk"]["default"]["counting_contract"] == (
        "separate_from_product_quality_gates"
    )
    assert result["cross_view"]["truth_v16_design_risk"] is True
    assert result["balanced_scan_usage"]["total_tokens"] == MAX_BALANCED_TOKENS
    assert result["formal_benchmark"] is False
    assert result["release_eligible"] is False
    assert len(result["content_sha256"]) == 64


@pytest.mark.parametrize(
    ("view_path", "tp", "fp"),
    [
        (("legacy", "default"), 82, 21),
        (("legacy", "review"), 125, 126),
        (("v16", "default"), 37, 10),
        (("v16", "review"), 60, 1),
    ],
)
def test_each_hard_boundary_fails_closed(view_path: tuple[str, str], tp: int, fp: int) -> None:
    parts = _inputs()
    report, legacy, v16, projection, bindings, frozen_manifest, usage, artifacts = copy.deepcopy(
        parts
    )
    if view_path == ("legacy", "default"):
        legacy["report_views"]["default"] = _view(136, tp, fp, prefix="legacy")
    elif view_path == ("legacy", "review"):
        legacy["report_views"]["with_needs_review"] = _view(136, tp, fp, prefix="legacy")
    elif view_path == ("v16", "default"):
        v16["product"]["default"] = _view(61, tp, fp, prefix="v16")
    else:
        v16["product"]["with_needs_review"].update(
            {
                "true_positives": tp,
                "false_negatives": 61 - tp,
                "false_positives_raw": fp,
                "matched": v16["product"]["with_needs_review"]["matched"][:tp],
            }
        )
    with pytest.raises(P6BalancedQualityGateError, match="hard quality gate"):
        _build(
            (
                report,
                legacy,
                v16,
                projection,
                bindings,
                frozen_manifest,
                usage,
                artifacts,
            )
        )


def test_hard_gate_miss_exposes_only_closed_answer_free_aggregate_counts() -> None:
    parts = list(_inputs())
    legacy = copy.deepcopy(parts[1])
    legacy["report_views"]["default"] = _view(136, 81, 0, prefix="private-case")
    parts[1] = legacy

    with pytest.raises(P6BalancedQualityGateFailure) as raised:
        _build(tuple(parts))

    aggregate = raised.value.aggregate
    validate_quality_failure_aggregate(aggregate)
    assert aggregate["schema_version"] == FAILURE_AGGREGATE_SCHEMA_VERSION
    assert aggregate["legacy_v15"]["default"] == {
        "truth_count": 136,
        "true_positives": 81,
        "false_negatives": 55,
        "false_positives_raw": 0,
        "hard_passed": False,
        "challenge_passed": False,
    }
    encoded = json.dumps(aggregate, sort_keys=True)
    for forbidden in (
        "matched",
        "private-case",
        "source",
        "location",
        "expected",
        "ground_truth",
        "prompt",
    ):
        assert forbidden not in encoded.lower()


def test_quality_failure_aggregate_schema_is_closed() -> None:
    schema = json.loads(
        (REPO_ROOT / "zscope/benchmarking/p6_balanced_quality_aggregate.schema.json").read_text(
            "utf-8"
        )
    )
    open_objects: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object" and value.get("additionalProperties") is not False:
                open_objects.append(path)
            for name, child in value.items():
                visit(child, f"{path}.{name}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(schema, "$")
    assert open_objects == []


def test_default_must_be_subset_of_with_needs_review() -> None:
    parts = list(_inputs())
    legacy = copy.deepcopy(parts[1])
    legacy["report_views"]["with_needs_review"]["matched"][0] = "different"
    parts[1] = legacy
    with pytest.raises(P6BalancedQualityGateError, match="hard quality gate"):
        _build(tuple(parts))


def test_design_risk_default_must_be_subset_of_with_needs_review() -> None:
    parts = list(_inputs())
    v16 = copy.deepcopy(parts[2])
    v16["design_risk"]["with_needs_review"]["matched"] = [f"risk-{index}" for index in range(8, 16)]
    parts[2] = v16

    with pytest.raises(P6BalancedQualityGateError, match="hard quality gate"):
        _build(tuple(parts))


@pytest.mark.parametrize(
    "mutation",
    (
        "token_overflow",
        "estimated_usage",
        "missing_usage",
        "model_mismatch",
        "queue_not_drained",
        "terminal_not_conserved",
        "retry_bound_tamper",
    ),
)
def test_usage_and_conservation_boundaries_fail_closed(mutation: str) -> None:
    parts = list(_inputs())
    legacy = copy.deepcopy(parts[1])
    if mutation == "token_overflow":
        legacy["tokens"] = MAX_BALANCED_TOKENS + 1
        legacy["usage_accounting"]["totals"]["total_tokens"] = MAX_BALANCED_TOKENS + 1
    elif mutation == "estimated_usage":
        legacy["p6_conservation"]["estimated_call_count"] = 1
    elif mutation == "missing_usage":
        legacy["usage_accounting"]["provider_usage_coverage"] = 0.999
    elif mutation == "model_mismatch":
        legacy["provider_response_model_mismatch_count"] = 1
    elif mutation == "queue_not_drained":
        legacy["queue_empty"] = False
    elif mutation == "terminal_not_conserved":
        legacy["p6_conservation"]["dimensions"]["terminal"]["conserved"] = False
    else:
        legacy["p6_retry_conservation"]["maximum_observed_attempt_index"] = 3
        legacy["p6_retry_conservation"]["passed"] = False
    parts[1] = legacy
    usage = copy.deepcopy(parts[6])
    usage["score_fields"] = {name: copy.deepcopy(legacy[name]) for name in usage["score_fields"]}
    usage.pop("content_sha256")
    usage["content_sha256"] = hashlib.sha256(
        json.dumps(usage, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    parts[6] = usage
    with pytest.raises(P6BalancedQualityGateError, match="hard quality gate"):
        _build(tuple(parts))


def test_conserved_zero_call_hard_limit_denial_is_not_an_overshoot() -> None:
    parts = list(_inputs())
    legacy = copy.deepcopy(parts[1])
    legacy["p6_admission_conservation"].update(
        {
            "request_count": 9,
            "admitted_request_count": 8,
            "denied_request_count": 1,
            "denied_reasons": {"p6_token_hard_limit": 1},
            "request_conservation_passed": True,
            "zero_call_denial_conservation_passed": True,
        }
    )
    parts[1] = legacy
    usage = copy.deepcopy(parts[6])
    usage["score_fields"] = {name: copy.deepcopy(legacy[name]) for name in usage["score_fields"]}
    usage.pop("content_sha256")
    usage["content_sha256"] = hashlib.sha256(
        json.dumps(usage, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    parts[6] = usage

    gate = _build(tuple(parts))

    assert gate["hard_gate_passed"] is True
    assert gate["balanced_scan_usage"]["hard_limit_denied_count"] == 1
    assert gate["balanced_scan_usage"]["gates"]["hard_limit_denials_zero_call_conserved"] is True
    assert gate["balanced_scan_usage"]["total_tokens"] == MAX_BALANCED_TOKENS


@pytest.mark.parametrize(
    "mutation",
    ("not_zero_call", "reason_count_mismatch", "budget_violation"),
)
def test_hard_limit_denial_still_requires_zero_call_conservation(
    mutation: str,
) -> None:
    parts = list(_inputs())
    legacy = copy.deepcopy(parts[1])
    legacy["p6_admission_conservation"].update(
        {
            "request_count": 9,
            "admitted_request_count": 8,
            "denied_request_count": 1,
            "denied_reasons": {"p6_token_hard_limit": 1},
            "request_conservation_passed": True,
            "zero_call_denial_conservation_passed": True,
        }
    )
    if mutation == "not_zero_call":
        legacy["p6_admission_conservation"]["zero_call_denial_conservation_passed"] = False
    elif mutation == "reason_count_mismatch":
        legacy["p6_admission_conservation"]["denied_reasons"]["p6_token_hard_limit"] = 2
    else:
        legacy["budget_violation_count"] = 1
    parts[1] = legacy
    usage = copy.deepcopy(parts[6])
    usage["score_fields"] = {name: copy.deepcopy(legacy[name]) for name in usage["score_fields"]}
    usage.pop("content_sha256")
    usage["content_sha256"] = hashlib.sha256(
        json.dumps(usage, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    parts[6] = usage

    with pytest.raises(P6BalancedQualityGateError, match="hard quality gate"):
        _build(tuple(parts))


def test_frozen_report_actual_views_must_match_terminal_membership() -> None:
    parts = list(_inputs())
    report = copy.deepcopy(parts[0])
    report["report_views"]["with_needs_review"]["issues"].append(
        {
            "candidate_disposition": "shadow_observation",
            "validation_cluster_uid": "VAL_audit",
            "status": "shadow_observation",
        }
    )
    parts[0] = report
    with pytest.raises(P6BalancedQualityGateError, match="hard quality gate"):
        _build(tuple(parts))


def test_confirmed_terminal_requires_recomputed_v4_authority() -> None:
    parts = list(_inputs())
    report = copy.deepcopy(parts[0])
    for collection in (
        report["issues"],
        report["candidate_terminal_states"],
        report["report_views"]["default"]["issues"],
        report["report_views"]["with_needs_review"]["issues"],
    ):
        for item in collection:
            if item.get("candidate_disposition") == "confirmed":
                item.pop("proof_kernel_promotion_certificate", None)
    parts[0] = report
    with pytest.raises(P6BalancedQualityGateError, match="hard quality gate"):
        _build(tuple(parts))


def test_post_terminal_calls_fail_even_when_usage_projection_claims_passed() -> None:
    parts = list(_inputs())
    legacy = copy.deepcopy(parts[1])
    legacy["p6_terminal_authority"]["post_terminal_model_call_count"] = 1
    legacy["p6_terminal_authority"]["passed"] = True
    parts[1] = legacy
    usage = copy.deepcopy(parts[6])
    usage["score_fields"] = {name: copy.deepcopy(legacy[name]) for name in usage["score_fields"]}
    usage.pop("content_sha256")
    usage["content_sha256"] = hashlib.sha256(
        json.dumps(usage, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    parts[6] = usage
    with pytest.raises(P6BalancedQualityGateError, match="hard quality gate"):
        _build(tuple(parts))


@pytest.mark.parametrize("collection", ("terminal", "default_view", "audit"))
def test_report_non_objects_and_audit_metadata_fail_closed(collection: str) -> None:
    parts = list(_inputs())
    report = copy.deepcopy(parts[0])
    if collection == "terminal":
        report["candidate_terminal_states"].append("not-an-object")
    elif collection == "default_view":
        report["report_views"]["default"]["issues"].append("not-an-object")
    else:
        report["metadata"]["audit_observation_count"] = 1
    parts[0] = report
    with pytest.raises(P6BalancedQualityGateError):
        _build(tuple(parts))


@pytest.mark.parametrize("mutation", ("unexpected_identity", "nonconserved_count"))
def test_response_model_counts_are_exact_and_conserved(mutation: str) -> None:
    parts = list(_inputs())
    legacy = copy.deepcopy(parts[1])
    if mutation == "unexpected_identity":
        legacy["provider_response_model_counts"]["provider-alias"] = 0
    else:
        legacy["provider_response_model_counts"][P6_PROVIDER_RESPONSE_MODEL] -= 1
    parts[1] = legacy
    usage = copy.deepcopy(parts[6])
    usage["score_fields"] = {name: copy.deepcopy(legacy[name]) for name in usage["score_fields"]}
    usage.pop("content_sha256")
    usage["content_sha256"] = hashlib.sha256(
        json.dumps(usage, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    parts[6] = usage
    with pytest.raises(P6BalancedQualityGateError):
        _build(tuple(parts))


def test_matched_counts_and_design_risk_denominator_are_strict() -> None:
    parts = list(_inputs())
    v16 = copy.deepcopy(parts[2])
    v16["product"]["default"]["matched"].pop()
    parts[2] = v16
    with pytest.raises(P6BalancedQualityGateError, match="one unique ID per TP"):
        _build(tuple(parts))

    parts = list(_inputs())
    v16 = copy.deepcopy(parts[2])
    v16["design_risk"]["default"]["truth_count"] = 74
    parts[2] = v16
    with pytest.raises(P6BalancedQualityGateError, match="must be 75"):
        _build(tuple(parts))


def _reseal_partition_projection(projection: dict[str, Any]) -> None:
    for name in ("product", "design_risk"):
        members = projection[name]["member_commitments"]
        projection[name]["member_count"] = len(members)
        projection[name]["member_commitments_sha256"] = hashlib.sha256(
            json.dumps(sorted(members), separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    union = sorted(
        set(projection["product"]["member_commitments"])
        | set(projection["design_risk"]["member_commitments"])
    )
    projection["union_member_count"] = len(union)
    projection["union_member_commitments_sha256"] = hashlib.sha256(
        json.dumps(union, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    projection.pop("content_sha256", None)
    projection["content_sha256"] = hashlib.sha256(
        json.dumps(
            projection, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


@pytest.mark.parametrize(
    "mutation",
    (
        "product_matched_from_design_partition",
        "design_matched_from_product_partition",
        "unknown_product_matched_id",
        "unknown_design_matched_id",
        "duplicate_product_matched_id",
        "overlapping_partition_commitment",
        "duplicate_partition_commitment",
    ),
)
def test_v16_partition_membership_overlap_duplicates_and_unknowns_fail_closed(
    mutation: str,
) -> None:
    parts = list(_inputs())
    v16 = copy.deepcopy(parts[2])
    commitments = v16["p6_truth_partition_projection"]
    if mutation == "product_matched_from_design_partition":
        v16["product"]["default"]["matched"][0] = "risk-74"
        v16["product"]["with_needs_review"]["matched"][0] = "risk-74"
    elif mutation == "design_matched_from_product_partition":
        v16["design_risk"]["default"]["matched"][0] = "v16-000"
        v16["design_risk"]["with_needs_review"]["matched"][0] = "v16-000"
    elif mutation == "unknown_product_matched_id":
        v16["product"]["default"]["matched"][0] = "unknown-product"
        v16["product"]["with_needs_review"]["matched"][0] = "unknown-product"
    elif mutation == "unknown_design_matched_id":
        v16["design_risk"]["default"]["matched"][0] = "unknown-design"
        v16["design_risk"]["with_needs_review"]["matched"][0] = "unknown-design"
    elif mutation == "duplicate_product_matched_id":
        v16["product"]["default"]["matched"][-1] = v16["product"]["default"]["matched"][0]
    elif mutation == "overlapping_partition_commitment":
        commitments["design_risk"]["member_commitments"][0] = commitments["product"][
            "member_commitments"
        ][0]
        _reseal_partition_projection(commitments)
    else:
        commitments["design_risk"]["member_commitments"][-1] = commitments["design_risk"][
            "member_commitments"
        ][0]
        _reseal_partition_projection(commitments)
    parts[2] = v16

    with pytest.raises(P6BalancedQualityGateError):
        _build(tuple(parts))


@pytest.mark.parametrize("score_index", (1, 2))
def test_each_score_must_bind_the_exact_frozen_report(score_index: int) -> None:
    parts = list(_inputs())
    score = copy.deepcopy(parts[score_index])
    score["p6_frozen_report_sha256"] = "0" * 64
    parts[score_index] = score
    with pytest.raises(P6BalancedQualityGateError, match="exact frozen report"):
        _build(tuple(parts))


def test_usage_evidence_must_bind_the_frozen_attempt_sidecar() -> None:
    parts = list(_inputs())
    usage = copy.deepcopy(parts[6])
    usage["llm_usage_events_sha256"] = "f" * 64
    unsigned = dict(usage)
    unsigned.pop("content_sha256", None)
    usage["content_sha256"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    parts[6] = usage

    with pytest.raises(P6BalancedQualityGateError, match="usage evidence binding"):
        _build(tuple(parts))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("formal_benchmark", True),
        ("release_eligible", True),
        ("git_sha", "0" * 40),
        ("runtime_source_sha256", "0" * 64),
        ("cache_identity_sha256", "0" * 64),
        ("producer_attempt_id", "p6-other-attempt"),
    ),
)
def test_producer_projection_tampering_fails_closed(field: str, value: object) -> None:
    parts = list(_inputs())
    projection = copy.deepcopy(parts[3])
    projection[field] = value
    parts[3] = projection
    with pytest.raises(P6BalancedQualityGateError, match="producer projection"):
        _build(tuple(parts))


def _write_gate(path: Path, gate: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(gate, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _reseal(gate: dict[str, Any]) -> None:
    unsigned = copy.deepcopy(gate)
    unsigned.pop("content_sha256", None)
    gate["content_sha256"] = hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def test_strict_schema_and_load_reject_top_level_nested_and_content_tamper(
    tmp_path: Path,
) -> None:
    schema = json.loads(
        (REPO_ROOT / "zscope/benchmarking/p6_balanced_quality_gate.schema.json").read_text(
            encoding="utf-8"
        )
    )
    open_objects: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object" and value.get("additionalProperties") is not False:
                open_objects.append(path)
            for name, child in value.items():
                visit(child, f"{path}.{name}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(schema, "$")
    assert open_objects == []

    path = tmp_path / "gate.json"
    gate = _build(_inputs())
    _write_gate(path, gate)
    assert load_quality_gate(path) == gate

    top_extra = copy.deepcopy(gate)
    top_extra["unexpected"] = True
    _reseal(top_extra)
    _write_gate(path, top_extra)
    with pytest.raises(P6BalancedQualityGateError, match="v1 schema"):
        load_quality_gate(path)

    nested_extra = copy.deepcopy(gate)
    nested_extra["bindings"]["unexpected"] = "forbidden"
    _reseal(nested_extra)
    _write_gate(path, nested_extra)
    with pytest.raises(P6BalancedQualityGateError, match="binding fields"):
        load_quality_gate(path)

    content_tamper = copy.deepcopy(gate)
    content_tamper["challenge_passed"] = not content_tamper["challenge_passed"]
    _write_gate(path, content_tamper)
    with pytest.raises(P6BalancedQualityGateError, match="content SHA-256"):
        load_quality_gate(path)


def test_resealed_gate_cannot_forge_view_thresholds_or_root_decisions(tmp_path: Path) -> None:
    path = tmp_path / "gate.json"
    gate = _build(_inputs())

    forged = copy.deepcopy(gate)
    view = forged["legacy_v15"]["default"]
    view.update(
        {
            "true_positives": 1,
            "false_negatives": 135,
            "false_positives_raw": 100,
            "actionable_denominator": 101,
        }
    )
    for decision in ("hard", "challenge"):
        view[decision] = {
            "tp": True,
            "actionable_precision_cross_product": True,
            "passed": True,
        }
    _reseal(forged)
    _write_gate(path, forged)
    with pytest.raises(P6BalancedQualityGateError, match="fixed integer threshold"):
        load_quality_gate(path)

    forged = copy.deepcopy(gate)
    forged["challenge_passed"] = not gate["challenge_passed"]
    _reseal(forged)
    _write_gate(path, forged)
    with pytest.raises(P6BalancedQualityGateError, match="challenge decision"):
        load_quality_gate(path)

    forged = copy.deepcopy(gate)
    forged["hard_gate_passed"] = False
    _reseal(forged)
    _write_gate(path, forged)
    with pytest.raises(P6BalancedQualityGateError, match="hard decision"):
        load_quality_gate(path)


def test_quality_gate_cli_failure_is_fixed_and_answer_free(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "private-score-details-do-not-print.json"
    failure_aggregate = tmp_path / "failure-aggregate.json"
    result = main(
        [
            "--report",
            str(missing),
            "--legacy-score",
            str(missing),
            "--v16-score",
            str(missing),
            "--v16-truth-partitions",
            str(missing),
            "--producer-projection",
            str(missing),
            "--bindings",
            str(missing),
            "--frozen-manifest",
            str(missing),
            "--usage-evidence",
            str(missing),
            "--usage-events",
            str(missing),
            "--trace-sidecars",
            str(missing),
            "--output",
            str(tmp_path / "output.json"),
            "--failure-aggregate",
            str(failure_aggregate),
        ]
    )

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == (
        "stage=report_finding; class=quality_no_progress_gate_failed:1; count=1\n"
    )
    assert "Traceback" not in captured.err
    assert missing.name not in captured.err
    assert not failure_aggregate.exists()
