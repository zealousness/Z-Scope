from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from scripts.p2_proof_corpus import build_case
from scripts import run_p6_synthetic_replay as replay_cli
import zscope.benchmarking.p6_synthetic_replay as replay_module
from zscope.benchmarking.p6_synthetic_replay import (
    REPLAY_MAX_CONTRACT_REGENERATIONS,
    REPLAY_MAX_INFLIGHT,
    REPLAY_MAX_TRANSPORT_RETRIES,
    SyntheticScenario,
    SyntheticReplayError,
    assert_answer_free_payload,
    compile_synthetic_project,
    execute_scanner,
    failure_result,
    install_replay_call_guards,
    materialize_replay_workspace,
    synthetic_scenarios,
    validate_replay_report,
)
from zscope.benchmarking.provider_runtime import (
    P6_PROVIDER_BASE_URL,
    P6_PROVIDER_MODEL,
    P6_PROVIDER_RESPONSE_MODEL,
)
from zscope.core.validation.authority import TerminalAuthorityEvaluator
from zscope.core.validation.function_ir import FunctionIRGraph
from zscope.core.validation.proof_kernel import (
    PREDICATE_REGISTRY,
    ProofKernelEngine,
    build_cross_thread_function_ir,
    build_proof_clause,
    build_proof_obligation,
    program_proof_ir_from_graph,
)
from zscope.core.validation.proof_kernel.canonical import seal_mapping
from zscope.core.validation.proof_kernel.registry import (
    function_ir_compound_wrappers,
    qualified_bounds_options,
    qualified_race_options,
    qualified_resource_leak_options,
)
from zscope.framework.llm_client import LLMClient
from zscope.config.config import ConfigLoader
from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.orchestration.candidate_envelope import (
    DECISION_CONTEXT_VERSION,
    annotate_issue_identity,
    context_signature_for,
    occurrence_uid_for,
    validation_cluster_uid_for,
)


def _provider_config(path: Path) -> Path:
    value = {
        "config_version": 2,
        "llms": {
            "default": {
                "base_urls": [P6_PROVIDER_BASE_URL],
                "models": [P6_PROVIDER_MODEL],
                "response_model_map": {
                    P6_PROVIDER_MODEL: P6_PROVIDER_RESPONSE_MODEL,
                },
                "api_key": "${Z_SCOPE_API_KEY}",
                "base_url_max_concurrent_requests": 8,
                "max_tokens": 8192,
                "max_retries": 1,
                "retry_until_available": False,
                "supports_structured_output": False,
                "require_exact_response_model": True,
                "timeout": 120,
            }
        },
        "project": {
            "id": "neutral-provider-config",
            "root": ".",
            "source_root": ".",
            "language": "c_cpp",
        },
        "scan": {
            "task": "",
            "llm_profiles": {
                "modeling": "default",
                "analysis": "default",
                "validation": "default",
            },
        },
        "indexing": {
            "backend": "unified",
            "svf": {
                "scope": "auto",
                "entry_depth": 4,
                "max_selected_tus": 32,
                "fallback": "full",
                "groups_file": "",
                "always_include": [],
                "exclusive_pools": [],
                "shared_pools": [],
                "heap_limit_mb": 4096,
                "timeout_seconds": 120,
            },
            "tools": {
                "clangd": "clangd",
                "gclang": "gclang",
                "get_bc": "get-bc",
                "llvm_link": "llvm-link",
            },
        },
        "concurrency": {
            "entry_workers": 8,
            "validator_workers": 8,
            "investigator_workers": 1,
            "evidence_completion_workers": 2,
            "index_workers": 4,
            "svf_workers": 2,
            "llm_max_inflight": 8,
        },
    }
    path.write_text(yaml.safe_dump(value, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return path.resolve()


def _workspace(tmp_path: Path):
    return materialize_replay_workspace(
        root=(tmp_path / "work").resolve(),
        source_config_path=_provider_config(tmp_path / "provider.yaml"),
    )


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


@lru_cache(maxsize=40)
def _real_confirmed_v4_bundle(
    proof_family: str,
    proof_index: int,
    validation_cluster_uid: str,
    proof_function_uid: str,
) -> dict[str, Any]:
    """Build an origin-bound fixture through the real provider/Checker/reducer."""

    case = build_case(proof_family, proof_index)
    original_ir = case["program_proof_ir"]
    original_summary = original_ir["functions"][0]
    summary_body = {
        key: copy.deepcopy(value)
        for key, value in original_summary.items()
        if key not in {"summary_uid", "content_sha256"}
    }
    summary_body["function_uid"] = proof_function_uid
    summary_body["signature"] = f"int {proof_function_uid}(void)"
    bound_summary = seal_mapping(
        summary_body,
        uid_field="summary_uid",
        prefix="FUNSUM_",
    )
    proof_ir_body = {
        key: copy.deepcopy(value)
        for key, value in original_ir.items()
        if key not in {"proof_ir_uid", "content_sha256"}
    }
    proof_ir_body["functions"] = [bound_summary]
    proof_ir = seal_mapping(
        proof_ir_body,
        uid_field="proof_ir_uid",
        prefix="PROOFIR_",
    )
    original = case["proof_obligation"]
    obligation = build_proof_obligation(
        validation_cluster_uid=validation_cluster_uid,
        defect_family=original["defect_family"],
        subject_uid=original["subject_uid"],
        decision_region_uid=original["decision_region_uid"],
        confirmation_clauses=tuple(original["confirmation_clauses"]),
        counterproof_clauses=tuple(original["counterproof_clauses"]),
        open_clauses=tuple(original["open_clauses"]),
        dependency_hashes=tuple(original["dependency_hashes"]),
    )
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=proof_ir,
        obligation=obligation,
    )
    assert evaluation.promotion_certificate is not None
    carrier: dict[str, Any] = {
        "candidate_disposition": "confirmed",
        "validation_cluster_uid": validation_cluster_uid,
    }
    evaluation.apply_to_issue(carrier)
    authority = TerminalAuthorityEvaluator().evaluate(carrier, operation="live").to_dict()
    carrier["proof_kernel_terminal_authority_decision"] = authority
    carrier["terminal_authority_decision"] = authority
    return carrier


def _origin_test_graph(
    function: str,
    statements: list[str],
    calls: list[dict[str, Any]],
    *,
    code_sha256: str,
) -> FunctionIRGraph:
    evidence = {
        "code_snapshot_sha256": code_sha256,
        "cfg_dump": {
            "summary": {
                "parse_ok": True,
                "function": function,
                "function_section_unique": True,
                "entry_blocks": ["B1"],
                "exit_blocks": ["B0"],
                "blocks": [
                    {
                        "id": "B1",
                        "label": "(ENTRY)",
                        "successors": ["B0"],
                        "predecessors": [],
                        "statements": statements,
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
                    "call_exprs": calls,
                    "value_fact_coverage_complete": True,
                },
            }
        },
    }
    graph = FunctionIRGraph.from_clang_evidence(
        evidence,
        function=function,
        file=f"src/{function}.c",
    )
    assert graph is not None
    return graph


@lru_cache(maxsize=4)
def _real_cross_thread_v4_bundle(validation_cluster_uid: str) -> dict[str, Any]:
    creator = _origin_test_graph(
        "synthetic_creator",
        [
            "pthread_create(&left_thread, 0, synthetic_worker_left, 0)",
            "pthread_create(&right_thread, 0, synthetic_worker_right, 0)",
        ],
        [
            {"callee": "pthread_create", "line": 4},
            {"callee": "pthread_create", "line": 5},
        ],
        code_sha256="1" * 64,
    )
    left = _origin_test_graph(
        "synthetic_worker_left",
        ["synthetic_counter++"],
        [],
        code_sha256="2" * 64,
    )
    right = _origin_test_graph(
        "synthetic_worker_right",
        ["int snapshot = synthetic_counter"],
        [],
        code_sha256="3" * 64,
    )
    cross_thread = build_cross_thread_function_ir(
        candidate_graph=left,
        creator_graph=creator,
        worker_graphs=(left, right),
        object_uid="synthetic_counter",
        declaration_uid="GLOBAL:synthetic_counter",
        declaration_file="src/synthetic_shared.c",
        declaration_line=2,
        project_revision_sha256="4" * 64,
    )
    proof_ir = program_proof_ir_from_graph(
        left,
        project_uid="P6_SYNTHETIC_ORIGIN_TEST",
        revision_uid="REV_P6_SYNTHETIC_ORIGIN_TEST",
        wrapper_summaries=function_ir_compound_wrappers(
            left,
            cross_thread_function_ir=cross_thread,
        ),
    )
    options = qualified_race_options(proof_ir["functions"][0])
    assert len(options) == 1
    fixed_parameters = options[0]["fixed_parameters"]
    expected_by_predicate = {
        "qualified_race_shared_object_identity": {"shared_object_identity": True},
        "qualified_race_conflicting_accesses": {"conflicting_accesses": True},
        "qualified_race_cross_thread_reachability": {"cross_thread_reachable": True},
        "qualified_race_empty_locksets": {"must_hold_locks": []},
        "qualified_race_no_happens_before": {"happens_before": False},
    }
    clauses = []
    for predicate_id, expected in expected_by_predicate.items():
        spec = PREDICATE_REGISTRY[predicate_id]
        clauses.append(
            build_proof_clause(
                role="confirmation",
                provider_family=spec.provider_family,
                predicate_id=predicate_id,
                fact_kind=spec.fact_kind,
                quantifier=spec.quantifier,
                expected_value=expected,
                parameters=fixed_parameters,
            )
        )
    obligation = build_proof_obligation(
        validation_cluster_uid=validation_cluster_uid,
        defect_family="data_race",
        subject_uid="synthetic_counter",
        decision_region_uid="synthetic_creator->synthetic_worker_left",
        confirmation_clauses=clauses,
        counterproof_clauses=(),
        dependency_hashes=proof_ir["dependency_hashes"],
    )
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=proof_ir,
        obligation=obligation,
    )
    assert evaluation.promotion_certificate is not None
    carrier: dict[str, Any] = {
        "candidate_disposition": "confirmed",
        "validation_cluster_uid": validation_cluster_uid,
    }
    evaluation.apply_to_issue(carrier)
    authority = TerminalAuthorityEvaluator().evaluate(carrier, operation="live").to_dict()
    carrier["proof_kernel_terminal_authority_decision"] = authority
    carrier["terminal_authority_decision"] = authority
    return carrier


def _scenario_proof_bundle(
    workspace,
    scenario: SyntheticScenario,
    validation_cluster_uid: str,
) -> tuple[dict[str, Any], str]:
    file_path = (workspace.project_root / scenario.source_name).resolve()
    code_sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
    expected_by_predicate: dict[str, Any]

    if scenario.proof_family == "leak":
        graph = replay_module._extract_scenario_function_graph(
            workspace,
            scenario,
            scenario.vulnerable_entry,
        )
        assert graph is not None
        proof_ir = program_proof_ir_from_graph(
            graph,
            project_uid="P6_SYNTHETIC_SCENARIO",
            revision_uid="REV_" + code_sha256[:32],
            wrapper_summaries=function_ir_compound_wrappers(graph),
        )
        options = [
            value
            for value in qualified_resource_leak_options(proof_ir["functions"][0])
            if value["fixed_parameters"].get("resource_uid") == scenario.subject_uid
            and value["actual"].get("outstanding_on_reachable_exit") is True
            and value["actual"].get("ownership_transfer_excluded") is True
        ]
        assert len(options) == 1
        fixed_parameters = options[0]["fixed_parameters"]
        expected_by_predicate = {
            "qualified_leak_acquisition_identity": {"exact_acquisition_identity": True},
            "qualified_leak_exit_outstanding": {"outstanding_on_reachable_exit": True},
            "qualified_leak_transfer_excluded": {"ownership_transfer_excluded": True},
        }
        defect_family = "memory_leak"
        occurrence_tail = scenario.vulnerable_entry
    elif scenario.proof_family == "bounds":
        graph = replay_module._extract_scenario_function_graph(
            workspace,
            scenario,
            scenario.vulnerable_entry,
        )
        assert graph is not None
        proof_ir = program_proof_ir_from_graph(
            graph,
            project_uid="P6_SYNTHETIC_SCENARIO",
            revision_uid="REV_" + code_sha256[:32],
            wrapper_summaries=function_ir_compound_wrappers(graph),
        )
        options = [
            value
            for value in qualified_bounds_options(proof_ir["functions"][0])
            if value.get("value_uid") == scenario.subject_uid
        ]
        assert len(options) == 1
        fixed_parameters = options[0]
        expected_by_predicate = {
            "qualified_bounds_source_controllable": {"source_controllable": True},
            "qualified_bounds_path_complete": {"path_exists": True},
            "qualified_bounds_sink_contract": {"dangerous_sink_contract": True},
            "qualified_bounds_range_violation": {"range_violation": True},
        }
        defect_family = "integer_bounds"
        occurrence_tail = scenario.vulnerable_entry
    else:
        creator = replay_module._extract_scenario_function_graph(
            workspace,
            scenario,
            scenario.creator_function_uid,
        )
        assert creator is not None
        workers = tuple(
            replay_module._extract_scenario_function_graph(
                workspace,
                scenario,
                function,
            )
            for function in scenario.worker_function_uids
        )
        assert all(value is not None for value in workers)
        workers = tuple(value for value in workers if value is not None)
        candidate_graph = workers[0]
        cross_thread = build_cross_thread_function_ir(
            candidate_graph=candidate_graph,
            creator_graph=creator,
            worker_graphs=workers,
            object_uid=scenario.subject_uid,
            declaration_uid="GLOBAL:" + scenario.subject_uid,
            declaration_file=file_path.as_posix(),
            declaration_line=3,
            project_revision_sha256=code_sha256,
        )
        proof_ir = program_proof_ir_from_graph(
            candidate_graph,
            project_uid="P6_SYNTHETIC_SCENARIO",
            revision_uid="REV_" + code_sha256[:32],
            wrapper_summaries=function_ir_compound_wrappers(
                candidate_graph,
                cross_thread_function_ir=cross_thread,
            ),
        )
        options = qualified_race_options(proof_ir["functions"][0])
        assert len(options) == 1
        fixed_parameters = options[0]["fixed_parameters"]
        expected_by_predicate = {
            "qualified_race_shared_object_identity": {"shared_object_identity": True},
            "qualified_race_conflicting_accesses": {"conflicting_accesses": True},
            "qualified_race_cross_thread_reachability": {"cross_thread_reachable": True},
            "qualified_race_empty_locksets": {"must_hold_locks": []},
            "qualified_race_no_happens_before": {"happens_before": False},
        }
        defect_family = "data_race"
        occurrence_tail = candidate_graph.function

    clauses = []
    for predicate_id, expected_value in expected_by_predicate.items():
        spec = PREDICATE_REGISTRY[predicate_id]
        clauses.append(
            build_proof_clause(
                role="confirmation",
                provider_family=spec.provider_family,
                predicate_id=predicate_id,
                fact_kind=spec.fact_kind,
                quantifier=spec.quantifier,
                expected_value=expected_value,
                parameters=fixed_parameters,
            )
        )
    obligation = build_proof_obligation(
        validation_cluster_uid=validation_cluster_uid,
        defect_family=defect_family,
        subject_uid=scenario.subject_uid,
        decision_region_uid=f"{scenario.vulnerable_entry}->{occurrence_tail}",
        confirmation_clauses=clauses,
        counterproof_clauses=(),
        dependency_hashes=proof_ir["dependency_hashes"],
    )
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=proof_ir,
        obligation=obligation,
    )
    assert evaluation.promotion_certificate is not None
    carrier: dict[str, Any] = {
        "candidate_disposition": "confirmed",
        "validation_cluster_uid": validation_cluster_uid,
    }
    evaluation.apply_to_issue(carrier)
    authority = TerminalAuthorityEvaluator().evaluate(carrier, operation="live").to_dict()
    carrier["proof_kernel_terminal_authority_decision"] = authority
    carrier["terminal_authority_decision"] = authority
    return carrier, occurrence_tail


def _confirmed_scenario_state(workspace, scenario: SyntheticScenario, index: int) -> dict[str, Any]:
    candidate_uid = f"candidate-{index}"
    obligation_uid = f"p6-synthetic-obligation-{index}"
    decision_evidence_hash = hashlib.sha256(
        f"p6-synthetic:{index}:{scenario.vulnerable_entry}".encode("utf-8")
    ).hexdigest()
    validator_contract = {"protocol": "p6-synthetic-replay-v1"}
    validation_cluster_uid = validation_cluster_uid_for(
        candidate_uid,
        decision_evidence_hash=decision_evidence_hash,
        validator_contract=validator_contract,
        obligation_uid=obligation_uid,
        decision_context_version=DECISION_CONTEXT_VERSION,
    )
    state, occurrence_tail = _scenario_proof_bundle(
        workspace,
        scenario,
        validation_cluster_uid,
    )
    call_paths = [[scenario.vulnerable_entry]]
    if occurrence_tail != scenario.vulnerable_entry:
        call_paths = [[scenario.vulnerable_entry, occurrence_tail]]
    occurrence_uid = occurrence_uid_for(
        candidate_uid,
        entry=scenario.vulnerable_entry,
        entry_paths=call_paths,
    )
    state.update(
        {
            "candidate_uid": candidate_uid,
            "obligation_uid": obligation_uid,
            "decision_evidence_hash": decision_evidence_hash,
            "decision_context_version": DECISION_CONTEXT_VERSION,
            "validator_contract": validator_contract,
            "occurrence_uid": occurrence_uid,
            "occurrence_uids": [occurrence_uid],
            "alias_occurrence_uids": [],
            "occurrences": [
                {
                    "occurrence_uid": occurrence_uid,
                    "entry_identity": scenario.vulnerable_entry,
                    "call_paths": call_paths,
                    "context_signature": context_signature_for(
                        entry=scenario.vulnerable_entry,
                        entry_paths=call_paths,
                    ),
                }
            ],
            "occurrence_count": 1,
            "entry_count": 1,
            "entries": [scenario.vulnerable_entry],
            "entry_paths": call_paths,
            "reported_from_entry": scenario.vulnerable_entry,
        }
    )
    return state


def _confirmed_state(entry: str, index: int) -> dict[str, Any]:
    ordinal = max(0, index - 1)
    proof_families = ("concurrency", "resource", "path_guard", "contract_type")
    proof_family = proof_families[(ordinal // 10) % len(proof_families)]
    proof_index = ordinal % 10
    candidate_uid = f"candidate-{index}"
    obligation_uid = f"p6-synthetic-obligation-{index}"
    decision_evidence_hash = hashlib.sha256(
        f"p6-synthetic:{index}:{entry}".encode("utf-8")
    ).hexdigest()
    validator_contract = {"protocol": "p6-synthetic-replay-v1"}
    validation_cluster_uid = validation_cluster_uid_for(
        candidate_uid,
        decision_evidence_hash=decision_evidence_hash,
        validator_contract=validator_contract,
        obligation_uid=obligation_uid,
        decision_context_version=DECISION_CONTEXT_VERSION,
    )
    state = copy.deepcopy(
        _real_confirmed_v4_bundle(
            proof_family,
            proof_index,
            validation_cluster_uid,
            entry,
        )
    )
    call_paths = [[entry]]
    occurrence_uid = occurrence_uid_for(
        candidate_uid,
        entry=entry,
        entry_paths=call_paths,
    )
    state.update(
        {
            "candidate_uid": candidate_uid,
            "obligation_uid": obligation_uid,
            "decision_evidence_hash": decision_evidence_hash,
            "decision_context_version": DECISION_CONTEXT_VERSION,
            "validator_contract": validator_contract,
            "occurrence_uid": occurrence_uid,
            "occurrence_uids": [occurrence_uid],
            "alias_occurrence_uids": [],
            "occurrences": [
                {
                    "occurrence_uid": occurrence_uid,
                    "entry_identity": entry,
                    "call_paths": call_paths,
                    "context_signature": context_signature_for(
                        entry=entry,
                        entry_paths=call_paths,
                    ),
                }
            ],
            "occurrence_count": 1,
            "entry_count": 1,
            "entries": [entry],
            "entry_paths": call_paths,
            "reported_from_entry": entry,
        }
    )
    return state


def _trace_event(
    *,
    sequence: int,
    previous: dict[str, Any] | None,
    stage: str,
    actor: str,
    reason_code: str,
    call_ids: list[str],
    tool_call_ids: list[str],
    token_delta: int,
    output_refs: list[str],
    disposition_after: str = "",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = {
        "schema_version": "zscope.decision-event.v3",
        "sequence": sequence,
        "recorded_at": f"2026-01-01T00:00:{sequence:02d}+00:00",
        "stage": stage,
        "actor": actor,
        "reason_code": reason_code,
        "parent_event_uids": [previous["event_uid"]] if previous else [],
        "previous_event_hash": previous["event_hash"] if previous else "",
        "input_state_hash": _canonical_sha256({}),
        "output_state_hash": _canonical_sha256({}),
        "input_refs": [],
        "output_refs": sorted(output_refs),
        "disposition_before": "",
        "disposition_after": disposition_after,
        "call_ids": sorted(call_ids),
        "tool_call_ids": sorted(tool_call_ids),
        "token_delta": token_delta,
        "closed_clause_ids": [],
        "open_clause_ids": [],
        "details": details or {},
        "dedupe_key": f"test:{sequence}:{reason_code}",
    }
    digest = _canonical_sha256(body)
    return {
        **body,
        "event_uid": f"EVENT_{digest[:32]}",
        "event_hash": digest,
    }


def _trace_identity(workspace) -> dict[str, str]:
    return {
        "project_id": "p6-synthetic-replay",
        "scan_depth": "balanced",
        "runtime_config_sha256": workspace.runtime_config_sha256,
    }


def _write_state_trace(
    trace_root: Path,
    state: dict[str, Any],
    identity: dict[str, str],
    usage_events: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    cluster_uid = state["validation_cluster_uid"]
    relative_path = f"decision_traces/{cluster_uid}.json"
    trace_events: list[dict[str, Any]] = []
    model_digests: list[str] = []
    (trace_root / "model_events").mkdir(exist_ok=True)
    for usage in usage_events or []:
        call_id = str(usage["call_id"])
        tool_ids = [
            f"tool-{call_id}-{index}" for index in range(int(usage.get("tool_call_count") or 0))
        ]
        model_body = {
            "schema_version": "zscope.model-event.v1",
            "call_identity": call_id,
            "stage": "verifier",
            "validation_cluster_uid": cluster_uid,
            "structured_input": {},
            "structured_output": {},
            "call_ids": [call_id],
            "tool_call_ids": tool_ids,
            "prompt_revision": "p6-synthetic-test",
            "prompt_hash": "",
        }
        model_digest = _canonical_sha256(model_body)
        model_digests.append(model_digest)
        (trace_root / "model_events" / f"{model_digest}.json").write_text(
            json.dumps({**model_body, "sha256": model_digest}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        trace_events.append(
            _trace_event(
                sequence=len(trace_events) + 1,
                previous=trace_events[-1] if trace_events else None,
                stage="verifier",
                actor="llm_usage_ledger_binding",
                reason_code="LLM_USAGE_BOUND",
                call_ids=[call_id],
                tool_call_ids=tool_ids,
                token_delta=int(usage["total_tokens"]),
                output_refs=[f"model_events/{model_digest}.json"],
            )
        )
    authority = state["terminal_authority_decision"]
    authority_sha256 = _canonical_sha256(authority)
    terminal_event = _trace_event(
        sequence=len(trace_events) + 1,
        previous=trace_events[-1] if trace_events else None,
        stage="policy",
        actor="terminal_authority_evaluator",
        reason_code=str(authority["reason_code"]),
        call_ids=[],
        tool_call_ids=[],
        token_delta=0,
        output_refs=[],
        disposition_after="confirmed",
        details={
            "terminal_transition_level": "V1",
            "terminal_authority_sha256": authority_sha256,
        },
    )
    trace_events.append(terminal_event)
    state.update(
        {
            "terminal_event_uid": terminal_event["event_uid"],
            "terminal_authority": authority["reason_code"],
            "terminal_reason_codes": [authority["reason_code"]],
            "terminal_transition_event_uid": terminal_event["event_uid"],
            "terminal_transition_event_hash": terminal_event["event_hash"],
            "terminal_transition_authority_sha256": authority_sha256,
            "terminal_transition_level": "V1",
            "terminal_transition_disposition": "confirmed",
        }
    )
    trace_body = {
        "schema_version": "zscope.issue-decision-trace.v3",
        "scan_uid": "p6-synthetic-test-scan",
        "validation_cluster_uid": cluster_uid,
        "candidate_uids": [state["candidate_uid"]],
        "occurrence_uids": list(state["occurrence_uids"]),
        "identity": identity,
        "events": trace_events,
        "terminal_disposition": "confirmed",
        "terminal_event_uid": terminal_event["event_uid"],
        "terminal_authority": authority["reason_code"],
        "terminal_reason_codes": [authority["reason_code"]],
        "terminal_transition_event_uid": terminal_event["event_uid"],
        "terminal_transition_event_hash": terminal_event["event_hash"],
        "terminal_transition_authority_sha256": authority_sha256,
        "terminal_transition_level": "V1",
        "terminal_transition_disposition": "confirmed",
        "view_memberships": [],
        "finding_root": {},
        "trace_root_sha256": terminal_event["event_hash"],
    }
    document_sha256 = _canonical_sha256(trace_body)
    trace_document = {**trace_body, "document_sha256": document_sha256}
    (trace_root / relative_path).write_text(
        json.dumps(trace_document, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    state["decision_trace_ref"] = relative_path
    state["decision_trace_sha256"] = document_sha256
    return (
        {
            "path": relative_path,
            "trace_root_sha256": terminal_event["event_hash"],
            "document_sha256": document_sha256,
            "event_count": len(trace_events),
            "terminal_disposition": "confirmed",
        },
        model_digests,
    )


def _write_success_artifacts(workspace, *, call_count: int = 10) -> tuple[dict, list[dict]]:
    states = [
        _confirmed_scenario_state(workspace, scenario, index)
        for index, scenario in enumerate(workspace.scenarios, start=1)
    ]
    functions = [
        {
            "function": entry,
            "entry_key": entry,
            "entry_identity": entry,
            "entry_file_path": scenario.source_name,
            "entry_signature": entry,
            "verdict": "completed",
            "issue_count": int(entry == scenario.vulnerable_entry),
            "audit_observation_count": 0,
            "duration_seconds": 0.0,
            "entry_budget_seconds": 0.0,
            "entry_budget_exceeded": False,
            "entry_budget_overrun_seconds": 0.0,
            "budget_exhaustion_policy": "none",
            "context_tokens": 0,
            "cumulative_prompt_tokens": 0,
            "cumulative_completion_tokens": 0,
            "cumulative_total_tokens": 0,
            "validation_performance": {},
            "error": "",
        }
        for scenario in workspace.scenarios
        for entry in (scenario.vulnerable_entry, scenario.protected_entry)
    ]
    events: list[dict[str, Any]] = []
    for sequence in range(1, call_count + 1):
        state = states[(sequence - 1) % len(states)]
        total_tokens = 110 + sequence
        attribution = {
            "schema_version": "zscope.llm-usage-attribution.v1",
            "stage": "validation",
            "agent": "proof_engine",
            "skill": "",
            "entry_identity": state["reported_from_entry"],
            "audit_unit_uid": "",
            "candidate_uid": state["candidate_uid"],
            "finding_uid": "",
            "validation_cluster_uid": state["validation_cluster_uid"],
            "llm_ref": "default",
            "call_kind": "initial",
        }
        events.append(
            {
                "schema_version": "zscope.llm-usage-event.v3",
                "sequence": sequence,
                "call_id": f"call-{sequence}",
                "reservation_id": f"call-{sequence}",
                "agent": attribution["agent"],
                "stage": "validation",
                "candidate_uid": attribution["candidate_uid"],
                "audit_unit_uid": "",
                "validation_cluster_uid": attribution["validation_cluster_uid"],
                "llm_ref": attribution["llm_ref"],
                "call_kind": attribution["call_kind"],
                "outcome": "success",
                "prompt_tokens": 100 + sequence,
                "completion_tokens": 10,
                "total_tokens": total_tokens,
                "reserved_total_tokens": total_tokens,
                "provider_reported": True,
                "conservative_charge": False,
                "budget_violation": False,
                "attribution": attribution,
                "budget_stage": "validation",
                "model": P6_PROVIDER_MODEL,
                "requested_model": P6_PROVIDER_MODEL,
                "provider_response_model": P6_PROVIDER_RESPONSE_MODEL,
                "call_chain_id": f"call-chain-{sequence}",
                "attempt_index": 1,
                "logical_operation_id": f"logical-operation-{sequence}",
                "reason": "",
                "finish_reason": "stop",
                "cached_prompt_tokens": 0,
                "reasoning_tokens": 0,
                "retry": False,
                "repair": False,
                "tool_call_count": sequence % 2,
                "new_fact_count": 0,
                "duration_ms": 1,
            }
        )
    prompt_tokens = sum(row["prompt_tokens"] for row in events)
    completion_tokens = sum(row["completion_tokens"] for row in events)
    total_tokens = sum(row["total_tokens"] for row in events)
    tool_calls = sum(row["tool_call_count"] for row in events)
    snapshots = workspace.project_root / ".zscope_snapshots"
    snapshots.mkdir(parents=True)
    events_path = snapshots / "llm_usage_events_local.jsonl"
    events_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in events),
        encoding="utf-8",
    )
    trace_root = snapshots
    trace_documents = trace_root / "decision_traces"
    trace_documents.mkdir()
    trace_path = trace_root / "decision_trace_manifest.json"
    trace_projections: dict[str, dict[str, Any]] = {}
    model_digests: list[str] = []
    for index, state in enumerate(states):
        state_usage = [
            value for value in events if (int(value["sequence"]) - 1) % len(states) == index
        ]
        projection, state_model_digests = _write_state_trace(
            trace_root,
            state,
            _trace_identity(workspace),
            state_usage,
        )
        trace_projections[state["validation_cluster_uid"]] = projection
        model_digests.extend(state_model_digests)
    trace_manifest_body = {
        "schema_version": "zscope.decision-trace-manifest.v3",
        "scan_uid": "p6-synthetic-test-scan",
        "identity": _trace_identity(workspace),
        "trace_count": len(trace_projections),
        "coverage_trace_count": 0,
        "evidence_object_count": 0,
        "model_event_count": len(model_digests),
        "traces": trace_projections,
        "coverage_traces": {},
        "evidence_object_sha256": [],
        "model_event_sha256": sorted(model_digests),
        "complete": True,
        "errors": [],
        "error_counts": {},
        "llm_usage_events": {
            "available": True,
            "schema_version": "zscope.llm-usage-ledger.v2",
            "path": events_path.relative_to(trace_root).as_posix(),
            "file_sha256": hashlib.sha256(events_path.read_bytes()).hexdigest(),
            "event_count": call_count,
            "referenced_call_count": call_count,
            "referenced_call_ids": sorted(str(value["call_id"]) for value in events),
            "trace_token_total": total_tokens,
            "usage_token_total": total_tokens,
            "missing_call_ids": [],
            "unreferenced_call_ids": [],
            "duplicate_call_ids": [],
            "provider_usage_coverage": 1.0,
            "conservation_valid": True,
        },
    }
    trace_sha = _canonical_sha256(trace_manifest_body)
    trace_manifest = {**trace_manifest_body, "manifest_sha256": trace_sha}
    trace_path.write_text(json.dumps(trace_manifest, sort_keys=True) + "\n", encoding="utf-8")
    totals = {
        "request_count": call_count,
        "successful_calls": call_count,
        "provider_reported_calls": call_count,
        "estimated_or_conservative_calls": 0,
        "failed_or_unknown_calls": 0,
        "budget_violation_count": 0,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "tool_call_count": tool_calls,
    }
    report = {
        "summary": {
            "functions_completed": len(functions),
            "functions_failed": 0,
            "total_issues": len(states),
            "llm_usage": {
                "scan_token_usage": {
                    "depth": "balanced",
                    "telemetry_complete": True,
                    "active_reservation_count": 0,
                    "reserved_tokens": 0,
                    "usage_attribution": {
                        "provider_usage_coverage": 1.0,
                        "totals": totals,
                    },
                }
            },
        },
        "function_results": functions,
        "issues": copy.deepcopy(states),
        "candidate_terminal_states": states,
        "run_manifest": {
            "validation_queue_drained": True,
            "terminal_outcome_count": len(states),
            "report_invariant_status": {"valid": True},
            "decision_trace": {
                "schema_version": trace_manifest["schema_version"],
                "manifest_path": str(trace_path.resolve()),
                "manifest_sha256": trace_sha,
                "trace_count": trace_manifest["trace_count"],
                "coverage_trace_count": trace_manifest["coverage_trace_count"],
                "evidence_object_count": trace_manifest["evidence_object_count"],
                "model_event_count": trace_manifest["model_event_count"],
                "complete": True,
                "errors": [],
            },
        },
    }
    workspace.report_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
    return report, events


def _rewrite_report(workspace, report: dict[str, Any]) -> None:
    workspace.report_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")


def _sync_report_issue(report: dict[str, Any], state: dict[str, Any]) -> None:
    terminal_issue = state.get("issue") if isinstance(state.get("issue"), dict) else state
    cluster_uid = terminal_issue["validation_cluster_uid"]
    for index, raw in enumerate(report["issues"]):
        issue = (
            raw.get("issue")
            if isinstance(raw, dict) and isinstance(raw.get("issue"), dict)
            else raw
        )
        if isinstance(issue, dict) and issue.get("validation_cluster_uid") == cluster_uid:
            report["issues"][index] = copy.deepcopy(terminal_issue)
            return
    raise AssertionError("terminal issue projection is missing")


def _rewrite_events(workspace, events: list[dict[str, Any]]) -> None:
    path = next((workspace.project_root / ".zscope_snapshots").glob("llm_usage_events_*.jsonl"))
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in events),
        encoding="utf-8",
    )


def _resign_usage_file_binding(workspace) -> None:
    report = json.loads(workspace.report_path.read_text(encoding="utf-8"))
    manifest_path = Path(report["run_manifest"]["decision_trace"]["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("manifest_sha256", None)
    usage_path = next(
        (workspace.project_root / ".zscope_snapshots").glob("llm_usage_events_*.jsonl")
    )
    manifest["llm_usage_events"]["file_sha256"] = hashlib.sha256(
        usage_path.read_bytes()
    ).hexdigest()
    manifest_sha256 = _canonical_sha256(manifest)
    manifest["manifest_sha256"] = manifest_sha256
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report["run_manifest"]["decision_trace"]["manifest_sha256"] = manifest_sha256
    _rewrite_report(workspace, report)


def _resign_trace_manifest(report: dict[str, Any]) -> None:
    manifest_path = Path(report["run_manifest"]["decision_trace"]["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("manifest_sha256", None)
    manifest_sha256 = _canonical_sha256(manifest)
    manifest["manifest_sha256"] = manifest_sha256
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report["run_manifest"]["decision_trace"]["manifest_sha256"] = manifest_sha256


def _resign_state_trace(workspace, report: dict[str, Any], state: dict[str, Any]) -> None:
    cluster_uid = state["validation_cluster_uid"]
    manifest_path = Path(report["run_manifest"]["decision_trace"]["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("manifest_sha256", None)
    projection = manifest["traces"][cluster_uid]
    trace_path = manifest_path.parent / projection["path"]
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace.pop("document_sha256", None)
    document_sha256 = _canonical_sha256(trace)
    trace["document_sha256"] = document_sha256
    trace_path.write_text(json.dumps(trace, sort_keys=True) + "\n", encoding="utf-8")
    projection["document_sha256"] = document_sha256
    projection["event_count"] = len(trace["events"])
    projection["trace_root_sha256"] = trace["trace_root_sha256"]
    state["decision_trace_sha256"] = document_sha256
    _sync_report_issue(report, state)
    manifest_sha256 = _canonical_sha256(manifest)
    manifest["manifest_sha256"] = manifest_sha256
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report["run_manifest"]["decision_trace"]["manifest_sha256"] = manifest_sha256


def _resign_occurrence_trace_binding(
    workspace,
    report: dict[str, Any],
    state: dict[str, Any],
) -> None:
    cluster_uid = state["validation_cluster_uid"]
    issue = next(
        value for value in report["issues"] if value["validation_cluster_uid"] == cluster_uid
    )
    for key in (
        "occurrence_uid",
        "occurrence_uids",
        "alias_occurrence_uids",
        "occurrences",
        "entries",
        "entry_paths",
        "reported_from_entry",
    ):
        issue[key] = copy.deepcopy(state[key])

    manifest_path = Path(report["run_manifest"]["decision_trace"]["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("manifest_sha256", None)
    projection = manifest["traces"][cluster_uid]
    trace_path = manifest_path.parent / projection["path"]
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace.pop("document_sha256", None)
    trace["occurrence_uids"] = list(state["occurrence_uids"])
    document_sha256 = _canonical_sha256(trace)
    trace["document_sha256"] = document_sha256
    trace_path.write_text(json.dumps(trace, sort_keys=True) + "\n", encoding="utf-8")
    projection["document_sha256"] = document_sha256
    state["decision_trace_sha256"] = document_sha256
    issue["decision_trace_sha256"] = document_sha256
    manifest_sha256 = _canonical_sha256(manifest)
    manifest["manifest_sha256"] = manifest_sha256
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report["run_manifest"]["decision_trace"]["manifest_sha256"] = manifest_sha256


def _append_confirmed_state(
    workspace,
    report: dict[str, Any],
    *,
    entry: str,
    index: int,
) -> dict[str, Any]:
    state = _confirmed_state(entry, index)
    trace_path = Path(report["run_manifest"]["decision_trace"]["manifest_path"])
    trace_manifest = json.loads(trace_path.read_text(encoding="utf-8"))
    trace_manifest.pop("manifest_sha256", None)
    projection, model_digests = _write_state_trace(
        trace_path.parent,
        state,
        _trace_identity(workspace),
    )
    assert model_digests == []
    trace_manifest["traces"][state["validation_cluster_uid"]] = projection
    trace_manifest["trace_count"] = len(trace_manifest["traces"])
    trace_sha256 = _canonical_sha256(trace_manifest)
    trace_manifest["manifest_sha256"] = trace_sha256
    trace_path.write_text(
        json.dumps(trace_manifest, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report["run_manifest"]["decision_trace"]["manifest_sha256"] = trace_sha256
    report["run_manifest"]["decision_trace"]["trace_count"] = trace_manifest["trace_count"]
    report["candidate_terminal_states"].append(state)
    report["issues"].append(copy.deepcopy(state))
    report["summary"]["total_issues"] += 1
    report["run_manifest"]["terminal_outcome_count"] += 1
    return state


def test_public_suite_has_five_neutral_pairs() -> None:
    scenarios = synthetic_scenarios()
    assert len(scenarios) == 5
    assert len({scenario.scenario_id for scenario in scenarios}) == 5
    assert all(scenario.vulnerable_entry != scenario.protected_entry for scenario in scenarios)
    packet = [scenario.model_input() for scenario in scenarios]
    assert_answer_free_payload(packet)
    serialized = json.dumps(packet, sort_keys=True).casefold().replace("\\", "/")
    markers = (
        "ground" + "_" + "tr" + "uth",
        "tr" + "uth",
        "expect" + "ed",
        "scor" + "er",
        "test" + "/" + "range",
        "range" + "-",
        "range" + "_",
        "fix" + "ture",
    )
    assert not any(marker in serialized for marker in markers)
    sources = "\n".join(scenario.source for scenario in scenarios)
    for token in ("malloc", "memcpy", "calloc", "pthread_create", "write(output_fd"):
        assert token in sources


def test_public_compound_scenarios_match_the_qualified_contract_shapes() -> None:
    scenarios = {value.scenario_id: value for value in synthetic_scenarios()}

    memcpy_pair = scenarios["syn-02"].source
    assert "ssize_t received = recv(" in memcpy_pair
    assert "memcpy(dst, received_bytes, received);" in memcpy_pair
    assert memcpy_pair.count("if (received < 0 || (size_t)received > dst_capacity) return -1;") == 1
    vulnerable_memcpy = memcpy_pair.index("memcpy(dst, received_bytes, received);")
    combined_guard = memcpy_pair.index(
        "if (received < 0 || (size_t)received > dst_capacity) return -1;"
    )
    protected_memcpy = memcpy_pair.rindex("memcpy(dst, received_bytes, received);")
    assert vulnerable_memcpy < combined_guard < protected_memcpy

    write_pair = scenarios["syn-05"].source
    assert "ssize_t received = read(" in write_pair
    assert "write(output_fd, buffer, received)" in write_pair
    assert write_pair.count("if (received < 0) return -1;") == 1
    assert write_pair.index("if (received < 0) return -1;") < write_pair.rindex(
        "write(output_fd, buffer, received)"
    )

    race_pair = scenarios["syn-04"].source
    assert "pthread_join" not in race_pair
    for worker in (
        "s04_worker_a_left",
        "s04_worker_a_right",
        "s04_worker_b_left",
        "s04_worker_b_right",
    ):
        assert race_pair.count(worker) == 2
    assert race_pair.count("g_s04_counter_a++;") == 2
    assert race_pair.count("g_s04_counter_b++;") == 2
    assert race_pair.count("pthread_mutex_lock(&s04_lock);") == 2
    assert race_pair.count("pthread_mutex_unlock(&s04_lock);") == 2


def test_public_race_candidates_bind_the_exact_shared_object_subject() -> None:
    race_pair = next(
        value.source for value in synthetic_scenarios() if value.scenario_id == "syn-04"
    )
    issues = RegexCandidateGenerator().generate_issues(
        "p6_s04_pair",
        race_pair,
        "unit_04.c",
    )
    by_object = {
        str(issue.get("source") or ""): issue
        for issue in issues
        if issue.get("rule") == "unsynchronized_shared_flag_or_counter"
    }
    assert set(by_object) == {"g_s04_counter_a", "g_s04_counter_b"}

    for subject_uid, issue in by_object.items():
        issue["decision_fact_graph_v1"] = True
        issue["security_obligation_v1"] = True
        annotate_issue_identity(
            issue,
            project_id="p6-synthetic-shape",
            project_root=".",
            revision="p6-synthetic-shape",
            entry_function="p6_s04_pair",
        )
        assert issue["thread_object"] == subject_uid
        assert issue["evidence_pack"]["thread_object"] == subject_uid
        assert issue["security_obligation"]["subject_uid"] == subject_uid


def test_public_compound_scenario_headers_match_the_entry_definitions(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    header = (workspace.project_root / "api.h").read_text(encoding="utf-8")
    assert "int p6_s02_a(int fd, unsigned char *dst);" in header
    assert "int p6_s02_b(int fd, unsigned char *dst, size_t dst_capacity);" in header
    assert "int p6_s05_a(int input_fd, int output_fd);" in header
    assert "int p6_s05_b(int input_fd, int output_fd);" in header


@pytest.mark.parametrize(
    "marker",
    (
        "ground" + "_" + "tr" + "uth",
        "tr" + "uth",
        "expect" + "ed",
        "scor" + "er",
        "test" + "/" + "range",
        "range" + "-" + "001",
        "range" + "_" + "001",
        "fix" + "ture",
    ),
)
def test_recursive_canary_rejects_each_answer_marker(marker: str) -> None:
    with pytest.raises(SyntheticReplayError) as caught:
        assert_answer_free_payload({"outer": [{"inner": marker}]})
    assert caught.value.failure_class == "input_binding_failure"


def test_runtime_is_frozen_to_one_call_in_flight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path)
    runtime = yaml.safe_load(workspace.config_path.read_text(encoding="utf-8"))
    profile = runtime["llms"]["default"]
    assert profile["models"] == [P6_PROVIDER_MODEL]
    assert profile["base_urls"] == [P6_PROVIDER_BASE_URL]
    assert profile["base_url_max_concurrent_requests"] == REPLAY_MAX_INFLIGHT == 1
    assert profile["max_retries"] == REPLAY_MAX_TRANSPORT_RETRIES == 1
    assert profile["retry_until_available"] is False
    assert runtime["concurrency"] == {
        "entry_workers": 1,
        "validator_workers": 1,
        "investigator_workers": 1,
        "evidence_completion_workers": 1,
        "index_workers": 1,
        "svf_workers": 1,
        "llm_max_inflight": 1,
    }
    assert runtime["project"]["entry_discovery"] == {
        "enabled": False,
        "interface_files": ["api.h"],
        "max_entries": 10,
        "max_functions": 64,
    }
    assert_answer_free_payload(runtime)
    monkeypatch.setenv("Z_SCOPE_API_KEY", "private-value")
    effective = ConfigLoader.load(str(workspace.config_path), scan_depth="balanced")
    assert effective.llm.models == [P6_PROVIDER_MODEL]
    assert effective.concurrency.llm_max_inflight == 1
    assert effective.project.entry_discovery.enabled is False


def test_replay_requires_a_fresh_work_root(tmp_path: Path) -> None:
    occupied = (tmp_path / "occupied").resolve()
    occupied.mkdir()
    (occupied / "old.txt").write_text("old", encoding="utf-8")
    with pytest.raises(SyntheticReplayError) as caught:
        materialize_replay_workspace(
            root=occupied,
            source_config_path=_provider_config(tmp_path / "provider.yaml"),
        )
    assert caught.value.failure_class == "input_binding_failure"


def test_compiler_contract_is_strict_and_complete(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    calls: list[list[str]] = []

    def runner(arguments, **kwargs):
        calls.append(list(arguments))
        assert kwargs["cwd"] == workspace.project_root
        assert kwargs["stdout"] is subprocess.DEVNULL
        assert kwargs["stderr"] is subprocess.DEVNULL
        return subprocess.CompletedProcess(arguments, 0)

    compile_synthetic_project(workspace, runner=runner)
    assert len(calls) == 5
    for arguments in calls:
        assert arguments[:6] == ["cc", "-std=c11", "-Werror", "-Wall", "-Wextra", "-pthread"]
        assert "-c" in arguments


def test_recursive_canary_stops_before_scanner(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    marker = "ground" + "_" + "tr" + "uth"
    first = workspace.project_root / workspace.scenarios[0].source_name
    first.write_text(first.read_text(encoding="utf-8") + f"\n/* {marker} */\n", encoding="utf-8")
    called = False

    def runner(*args, **kwargs):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(args[0], 0)

    with pytest.raises(SyntheticReplayError) as caught:
        execute_scanner(workspace, api_key="private-value", runner=runner)
    assert caught.value.failure_class == "input_binding_failure"
    assert called is False


def test_scanner_boundary_passes_key_only_in_child_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path)
    workspace.report_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.delenv("Z_SCOPE_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("Z_SCOPE_LLM_MODEL", raising=False)
    captured: dict[str, Any] = {}

    def runner(command, **kwargs):
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        assert kwargs["stdout"] is subprocess.DEVNULL
        assert kwargs["stderr"] is subprocess.DEVNULL
        return subprocess.CompletedProcess(command, 0)

    execute_scanner(workspace, api_key="private-value", runner=runner)
    assert captured["environment"]["Z_SCOPE_API_KEY"] == "private-value"
    assert "private-value" not in json.dumps(captured["command"])
    assert "--scan-depth" in captured["command"]
    assert "balanced" in captured["command"]
    assert "--p6-pilot" in captured["command"]
    bootstrap = captured["command"][2]
    assert "install_replay_call_guards" in bootstrap


def test_pre_call_guard_enforces_retry_and_regeneration_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def original(self, *args, **kwargs):
        calls.append(str(kwargs.get("trace_label") or ""))
        return {"ok": True}

    monkeypatch.setattr(LLMClient, "chat_completion", original)
    monkeypatch.setattr(
        LLMClient,
        "TRANSIENT_AUTH_RETRY_LIMIT",
        LLMClient.TRANSIENT_AUTH_RETRY_LIMIT,
    )
    monkeypatch.setattr(
        LLMClient,
        "TRANSIENT_CLIENT_RESPONSE_RETRY_LIMIT",
        LLMClient.TRANSIENT_CLIENT_RESPONSE_RETRY_LIMIT,
    )
    install_replay_call_guards()
    client = object.__new__(LLMClient)
    client.max_retries = 1
    client.retry_until_available = False
    client.models = [P6_PROVIDER_MODEL]
    client._base_url_states = [SimpleNamespace(url=P6_PROVIDER_BASE_URL)]
    label = (
        "proof_engine_v3; call_kind=contract_regeneration; " "validation_cluster_uid=cluster-one"
    )
    assert client.chat_completion([], trace_label=label) == {"ok": True}
    with pytest.raises(RuntimeError):
        client.chat_completion([], trace_label=label)
    assert len(calls) == 1
    client.max_retries = 2
    with pytest.raises(RuntimeError):
        client.chat_completion([], trace_label="call_kind=initial")
    assert len(calls) == 1
    assert LLMClient.TRANSIENT_AUTH_RETRY_LIMIT == 0
    assert LLMClient.TRANSIENT_CLIENT_RESPONSE_RETRY_LIMIT == 0


def test_success_validates_model_usage_and_six_way_conservation(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    _write_success_artifacts(workspace)
    result = validate_replay_report(workspace)
    assert result["passed"] is True
    assert result["formal_evidence"] is False
    assert result["release_eligible"] is False
    assert result["provider"]["model"] == P6_PROVIDER_MODEL
    assert result["runtime"] == {
        "llm_max_inflight": 1,
        "base_url_max_concurrent_requests": 1,
        "max_transport_retries": 1,
        "max_contract_regenerations": 1,
        "source_config_sha256": workspace.source_config_sha256,
        "runtime_config_sha256": workspace.runtime_config_sha256,
    }
    assert set(result["usage"]["conservation"]) == {
        "call",
        "token",
        "tool",
        "trace",
        "finding",
        "terminal",
    }
    assert all(row["conserved"] is True for row in result["usage"]["conservation"].values())
    assert all(row["entries_scanned"] == 2 for row in result["scenarios"])
    assert all(row["protected_confirmation_count"] == 0 for row in result["scenarios"])
    assert_answer_free_payload(result)


def test_generic_sealed_proof_cannot_satisfy_a_scenario_contract(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    scenario = workspace.scenarios[0]
    generic = _append_confirmed_state(
        workspace,
        report,
        entry=scenario.vulnerable_entry,
        index=91,
    )
    _rewrite_report(workspace, report)
    manifest_path = Path(report["run_manifest"]["decision_trace"]["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert (
        replay_module._complete_v4_confirmation(
            workspace,
            generic,
            trace_manifest_path=manifest_path,
            trace_manifest=manifest,
            scenario=scenario,
        )
        is False
    )


def test_scenario_specific_proof_cannot_be_swapped_between_contracts(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    manifest_path = Path(report["run_manifest"]["decision_trace"]["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    for index, state in enumerate(report["candidate_terminal_states"]):
        wrong_scenario = workspace.scenarios[(index + 1) % len(workspace.scenarios)]
        assert (
            replay_module._complete_v4_confirmation(
                workspace,
                state,
                trace_manifest_path=manifest_path,
                trace_manifest=manifest,
                scenario=wrong_scenario,
            )
            is False
        )


def test_scenario_summary_must_equal_real_clang_reextraction(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    scenario = workspace.scenarios[0]
    graph = replay_module._extract_scenario_function_graph(
        workspace,
        scenario,
        scenario.vulnerable_entry,
    )
    assert graph is not None
    acquisition_index = next(
        index for index, event in enumerate(graph.events) if event.callee == scenario.source_callee
    )
    forged_events = list(graph.events)
    forged_events[acquisition_index] = replace(
        forged_events[acquisition_index],
        source_line=forged_events[acquisition_index].source_line + 100,
    )
    forged_graph = replace(
        graph,
        events=tuple(forged_events),
        ir_sha256="f" * 64,
    )
    proof_ir = program_proof_ir_from_graph(
        forged_graph,
        project_uid="P6_FORGED_TEST",
        revision_uid="REV_P6_FORGED_TEST",
        wrapper_summaries=function_ir_compound_wrappers(forged_graph),
    )

    assert (
        replay_module._fresh_summary_matches(
            workspace,
            scenario,
            proof_ir["functions"][0],
        )
        is None
    )


def test_race_embedded_graph_requires_the_exact_clang_projection(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    scenario = workspace.scenarios[3]
    state = report["candidate_terminal_states"][3]
    summary = state["proof_kernel_input"]["proof_ir"]["functions"][0]
    wrapper = next(
        value
        for value in summary["wrapper_summaries"]
        if value.get("summary_kind") == "cross_thread_function_ir"
    )
    wrapper["creator_graph"]["unrecognized_graph_field"] = "forged"
    wrapper_body = dict(wrapper)
    wrapper_body.pop("content_sha256")
    wrapper["content_sha256"] = _canonical_sha256(wrapper_body)
    summary_body = {
        key: copy.deepcopy(value)
        for key, value in summary.items()
        if key not in {"summary_uid", "content_sha256"}
    }
    state["proof_kernel_input"]["proof_ir"]["functions"][0] = seal_mapping(
        summary_body,
        uid_field="summary_uid",
        prefix="FUNSUM_",
    )

    assert replay_module._proof_binds_scenario(workspace, state, scenario) is False


def test_trace_manifest_requires_its_external_digest_binding(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    manifest_path = Path(report["run_manifest"]["decision_trace"]["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("manifest_sha256")
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "conservation"
    assert caught.value.failure_class == "accounting_conservation_failure"


@pytest.mark.parametrize(
    "malformed_line",
    (
        '{"sequence":1,"sequence":2}',
        '{"sequence":NaN}',
        '{"sequence":Infinity}',
    ),
)
def test_usage_json_rejects_duplicate_keys_and_nonfinite_numbers(
    tmp_path: Path,
    malformed_line: str,
) -> None:
    workspace = _workspace(tmp_path)
    _write_success_artifacts(workspace)
    usage_path = next(
        (workspace.project_root / ".zscope_snapshots").glob("llm_usage_events_*.jsonl")
    )
    usage_path.write_text(malformed_line + "\n", encoding="utf-8")

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "usage"
    assert caught.value.failure_class == "provider_usage_unverifiable"


def test_unrelated_issue_row_cannot_be_hidden_by_self_reported_totals(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    unrelated = copy.deepcopy(report["issues"][0])
    unrelated["candidate_uid"] = "unrelated-candidate"
    report["issues"].append(unrelated)
    report["summary"]["total_issues"] += 1
    _rewrite_report(workspace, report)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "conservation"
    assert caught.value.failure_class == "accounting_conservation_failure"


def test_success_states_use_a_distinct_sealed_proof_for_every_entry(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    proof_input_hashes = {
        _canonical_sha256(state["proof_kernel_input"])
        for state in report["candidate_terminal_states"]
    }

    assert len(proof_input_hashes) == len(workspace.scenarios)
    assert [
        state["proof_kernel_input"]["proof_ir"]["functions"][0]["function_uid"]
        for state in report["candidate_terminal_states"]
    ] == [
        (
            scenario.worker_function_uids[0]
            if scenario.proof_family == "race"
            else scenario.vulnerable_entry
        )
        for scenario in workspace.scenarios
    ]


def test_sealed_proof_origin_cannot_be_swapped_between_entries(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    state = report["candidate_terminal_states"][0]
    foreign = copy.deepcopy(
        _real_confirmed_v4_bundle(
            "concurrency",
            0,
            state["validation_cluster_uid"],
            workspace.scenarios[0].protected_entry,
        )
    )
    for key in (
        "proof_kernel_input",
        "proof_kernel_frozen_state",
        "proof_kernel_closure_evaluation",
        "proof_kernel_promotion_certificate",
        "proof_kernel_terminal_authority_decision",
        "terminal_authority_decision",
    ):
        state[key] = foreign[key]
    _sync_report_issue(report, state)
    _rewrite_report(workspace, report)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "proof"
    assert caught.value.failure_class == "terminal_state_inconsistent"


def test_cross_thread_proof_origin_requires_creator_to_worker_direction() -> None:
    carrier = copy.deepcopy(_real_cross_thread_v4_bundle("cross-thread-origin-cluster"))
    audited = TerminalAuthorityEvaluator().evaluate(carrier, operation="audit").to_dict()
    assert audited == carrier["terminal_authority_decision"]
    correct = replay_module._ValidatedOccurrenceBinding(
        candidate_uid="candidate-cross-thread",
        validation_cluster_uid="cross-thread-origin-cluster",
        occurrence_uids=("occurrence-cross-thread",),
        entries=("synthetic_creator",),
        occurrences=(
            (
                "synthetic_creator",
                (("synthetic_creator", "synthetic_worker_left"),),
            ),
        ),
    )
    reversed_path = replay_module._ValidatedOccurrenceBinding(
        candidate_uid=correct.candidate_uid,
        validation_cluster_uid=correct.validation_cluster_uid,
        occurrence_uids=correct.occurrence_uids,
        entries=correct.entries,
        occurrences=(
            (
                "synthetic_creator",
                (("synthetic_worker_left", "synthetic_creator"),),
            ),
        ),
    )
    wrong_entry = replay_module._ValidatedOccurrenceBinding(
        candidate_uid=correct.candidate_uid,
        validation_cluster_uid=correct.validation_cluster_uid,
        occurrence_uids=correct.occurrence_uids,
        entries=("synthetic_worker_left",),
        occurrences=(
            (
                "synthetic_worker_left",
                (("synthetic_worker_left",),),
            ),
        ),
    )

    assert replay_module._proof_origin_binds_occurrences(carrier, correct) is True
    assert replay_module._proof_origin_binds_occurrences(carrier, reversed_path) is False
    assert replay_module._proof_origin_binds_occurrences(carrier, wrong_entry) is False


def test_canonical_entries_occurrences_and_entry_paths_are_attributed_exactly(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    first, second, third = report["candidate_terminal_states"][:3]
    first.pop("reported_from_entry")
    third.pop("reported_from_entry")
    report["candidate_terminal_states"][1] = {
        "candidate_disposition": "confirmed",
        "validation_cluster_uid": second["validation_cluster_uid"],
        "primary_occurrence_uid": second["occurrence_uid"],
        "occurrence_uids": list(second["occurrence_uids"]),
        "alias_occurrence_uids": list(second["alias_occurrence_uids"]),
        "issue": second,
    }
    for state in report["candidate_terminal_states"][:3]:
        _sync_report_issue(report, state)
    report["function_results"][0]["function"] = "unit_01.c::int p6_s01_a(size_t n)"
    _rewrite_report(workspace, report)

    assert validate_replay_report(workspace)["passed"] is True


def test_similar_function_and_non_entry_path_node_are_not_misattributed(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    first = report["candidate_terminal_states"][0]
    first.pop("reported_from_entry")
    first["entries"] = ["unit_01.c::int p6_s01_a_extra(size_t n)"]
    first["entry_paths"] = [["unit_01.c::int p6_s01_a_extra(size_t n)", "p6_s01_a"]]
    _sync_report_issue(report, first)
    _rewrite_report(workspace, report)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "proof"
    assert caught.value.failure_class == "terminal_state_inconsistent"


def test_rewritten_occurrence_cannot_borrow_another_entries_sealed_proof(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    state = report["candidate_terminal_states"][0]
    replacement_entry = workspace.scenarios[0].protected_entry
    replacement_paths = [[replacement_entry]]
    replacement_uid = occurrence_uid_for(
        state["candidate_uid"],
        entry=replacement_entry,
        entry_paths=replacement_paths,
    )
    state.update(
        {
            "occurrence_uid": replacement_uid,
            "occurrence_uids": [replacement_uid],
            "alias_occurrence_uids": [],
            "occurrences": [
                {
                    "occurrence_uid": replacement_uid,
                    "entry_identity": replacement_entry,
                    "call_paths": replacement_paths,
                    "context_signature": context_signature_for(
                        entry=replacement_entry,
                        entry_paths=replacement_paths,
                    ),
                }
            ],
            "entries": [replacement_entry],
            "entry_paths": replacement_paths,
            "reported_from_entry": replacement_entry,
        }
    )
    _resign_occurrence_trace_binding(workspace, report, state)
    _rewrite_report(workspace, report)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "proof"
    assert caught.value.failure_class == "terminal_state_inconsistent"


def test_protected_confirmation_fails_semantic_gate(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    _append_confirmed_state(
        workspace,
        report,
        entry=workspace.scenarios[0].protected_entry,
        index=99,
    )
    _rewrite_report(workspace, report)
    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "semantic"
    assert caught.value.failure_class == "anonymous_qualification_failed"


def test_incomplete_certificate_fails_closed(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    del report["candidate_terminal_states"][0]["proof_kernel_promotion_certificate"]
    _sync_report_issue(report, report["candidate_terminal_states"][0])
    _rewrite_report(workspace, report)
    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "proof"
    assert caught.value.failure_class == "terminal_state_inconsistent"


def test_confirmed_state_replays_original_proof_input_not_just_sealed_outputs(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    proof_input = report["candidate_terminal_states"][0]["proof_kernel_input"]
    proof_input["selected_action_uids"] = []
    _sync_report_issue(report, report["candidate_terminal_states"][0])
    _rewrite_report(workspace, report)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "proof"
    assert caught.value.failure_class == "terminal_state_inconsistent"


def test_confirmed_state_requires_both_exact_materialized_authority_projections(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    report["candidate_terminal_states"][0]["terminal_authority_decision"] = copy.deepcopy(
        report["candidate_terminal_states"][0]["terminal_authority_decision"]
    )
    report["candidate_terminal_states"][0]["terminal_authority_decision"][
        "reason_code"
    ] = "CONFIRMED_BUT_NOT_REPLAYED"
    _sync_report_issue(report, report["candidate_terminal_states"][0])
    _rewrite_report(workspace, report)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "proof"
    assert caught.value.failure_class == "terminal_state_inconsistent"


@pytest.mark.parametrize("response_model", [P6_PROVIDER_MODEL, P6_PROVIDER_RESPONSE_MODEL])
def test_response_identity_accepts_the_frozen_contract_aliases(
    tmp_path: Path,
    response_model: str,
) -> None:
    workspace = _workspace(tmp_path)
    _, events = _write_success_artifacts(workspace)
    events[0]["provider_response_model"] = response_model
    _rewrite_events(workspace, events)
    _resign_usage_file_binding(workspace)
    assert validate_replay_report(workspace)["passed"] is True


def test_response_identity_mismatch_fails_closed(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    _, events = _write_success_artifacts(workspace)
    events[0]["provider_response_model"] = "unbound-response-model"
    _rewrite_events(workspace, events)
    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.failure_class == "provider_identity_mismatch"


def test_provider_identity_is_validated_before_semantic_interpretation(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, events = _write_success_artifacts(workspace)
    _append_confirmed_state(
        workspace,
        report,
        entry=workspace.scenarios[0].protected_entry,
        index=99,
    )
    events[0]["provider_response_model"] = "unbound-response-model"
    _rewrite_report(workspace, report)
    _rewrite_events(workspace, events)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "provider"
    assert caught.value.failure_class == "provider_identity_mismatch"


def test_usage_coverage_is_validated_before_semantic_interpretation(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    _append_confirmed_state(
        workspace,
        report,
        entry=workspace.scenarios[0].protected_entry,
        index=99,
    )
    report["summary"]["llm_usage"]["scan_token_usage"]["usage_attribution"][
        "provider_usage_coverage"
    ] = 0.9
    _rewrite_report(workspace, report)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "usage"
    assert caught.value.failure_class == "provider_usage_unverifiable"


def test_trace_conservation_is_validated_before_semantic_interpretation(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    _append_confirmed_state(
        workspace,
        report,
        entry=workspace.scenarios[0].protected_entry,
        index=99,
    )
    trace_path = Path(report["run_manifest"]["decision_trace"]["manifest_path"])
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace["llm_usage_events"]["trace_token_total"] += 1
    trace_path.write_text(json.dumps(trace, sort_keys=True) + "\n", encoding="utf-8")
    _rewrite_report(workspace, report)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "conservation"
    assert caught.value.failure_class == "accounting_conservation_failure"


def test_token_mismatch_fails_conservation(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    report["summary"]["llm_usage"]["scan_token_usage"]["usage_attribution"]["totals"][
        "total_tokens"
    ] += 1
    _rewrite_report(workspace, report)
    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.failure_class == "accounting_conservation_failure"


def test_duplicate_physical_call_identity_is_not_counted_as_usage(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    _, events = _write_success_artifacts(workspace)
    events[1]["call_id"] = events[0]["call_id"]
    _rewrite_events(workspace, events)
    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "usage"
    assert caught.value.failure_class == "provider_usage_unverifiable"


@pytest.mark.parametrize("attribution_kind", ["foreign_cluster", "audit"])
def test_usage_call_cannot_be_attributed_to_a_different_trace_cluster(
    tmp_path: Path,
    attribution_kind: str,
) -> None:
    workspace = _workspace(tmp_path)
    _, events = _write_success_artifacts(workspace)
    if attribution_kind == "foreign_cluster":
        foreign_cluster = events[1]["validation_cluster_uid"]
        events[0]["validation_cluster_uid"] = foreign_cluster
        events[0]["attribution"]["validation_cluster_uid"] = foreign_cluster
    else:
        events[0]["validation_cluster_uid"] = ""
        events[0]["attribution"]["validation_cluster_uid"] = ""
        events[0]["audit_unit_uid"] = "audit-unit-foreign"
        events[0]["attribution"]["audit_unit_uid"] = "audit-unit-foreign"
    _rewrite_events(workspace, events)
    _resign_usage_file_binding(workspace)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "conservation"
    assert caught.value.failure_class == "accounting_conservation_failure"


def test_retry_chain_cannot_cross_cluster_or_restart_attempt_number(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    _, events = _write_success_artifacts(workspace)
    events[1]["call_chain_id"] = events[0]["call_chain_id"]
    events[1]["logical_operation_id"] = events[0]["logical_operation_id"]
    events[1]["attempt_index"] = 2
    events[1]["retry"] = True
    _rewrite_events(workspace, events)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "provider"
    assert caught.value.failure_class == "provider_transport_exhausted"


def test_report_issue_must_be_the_full_terminal_projection(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    report["issues"][0]["proof_kernel_input"] = copy.deepcopy(
        report["issues"][0]["proof_kernel_input"]
    )
    report["issues"][0]["proof_kernel_input"]["selected_action_uids"] = []
    _rewrite_report(workspace, report)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "conservation"
    assert caught.value.failure_class == "accounting_conservation_failure"


@pytest.mark.parametrize("mutation", ["scan_uid", "identity", "root"])
def test_trace_scan_identity_and_root_are_bound_to_the_manifest(
    tmp_path: Path,
    mutation: str,
) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    state = report["candidate_terminal_states"][0]
    manifest_path = Path(report["run_manifest"]["decision_trace"]["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    trace_path = manifest_path.parent / manifest["traces"][state["validation_cluster_uid"]]["path"]
    if mutation in {"scan_uid", "identity"}:
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        if mutation == "scan_uid":
            trace["scan_uid"] = "foreign-scan"
        else:
            trace["identity"] = {
                **trace["identity"],
                "runtime_config_sha256": "0" * 64,
            }
        trace_path.write_text(json.dumps(trace, sort_keys=True) + "\n", encoding="utf-8")
        _resign_state_trace(workspace, report, state)
    else:
        manifest.pop("manifest_sha256")
        manifest["traces"][state["validation_cluster_uid"]]["trace_root_sha256"] = "0" * 64
        manifest_sha256 = _canonical_sha256(manifest)
        manifest["manifest_sha256"] = manifest_sha256
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        report["run_manifest"]["decision_trace"]["manifest_sha256"] = manifest_sha256
    _rewrite_report(workspace, report)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "conservation"
    assert caught.value.failure_class == "accounting_conservation_failure"


def test_trace_projection_rejects_unreported_alias_candidate(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    state = report["candidate_terminal_states"][0]
    manifest_path = Path(report["run_manifest"]["decision_trace"]["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    trace_path = manifest_path.parent / manifest["traces"][state["validation_cluster_uid"]]["path"]
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace["candidate_uids"] = sorted([state["candidate_uid"], "candidate-unreported-alias"])
    trace_path.write_text(json.dumps(trace, sort_keys=True) + "\n", encoding="utf-8")
    _resign_state_trace(workspace, report, state)
    _rewrite_report(workspace, report)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "conservation"
    assert caught.value.failure_class == "accounting_conservation_failure"


def test_post_proof_call_fails_even_when_trace_hashes_are_recomputed(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, events = _write_success_artifacts(workspace)
    state = report["candidate_terminal_states"][0]
    manifest_path = Path(report["run_manifest"]["decision_trace"]["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    trace_path = manifest_path.parent / manifest["traces"][state["validation_cluster_uid"]]["path"]
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace.pop("document_sha256")
    trace["events"].append(
        _trace_event(
            sequence=len(trace["events"]) + 1,
            previous=trace["events"][-1],
            stage="verifier",
            actor="llm_usage_ledger_binding",
            reason_code="LLM_USAGE_BOUND",
            call_ids=[events[0]["call_id"]],
            tool_call_ids=[],
            token_delta=events[0]["total_tokens"],
            output_refs=[],
        )
    )
    trace["trace_root_sha256"] = trace["events"][-1]["event_hash"]
    trace_path.write_text(json.dumps(trace, sort_keys=True) + "\n", encoding="utf-8")
    _resign_state_trace(workspace, report, state)
    _rewrite_report(workspace, report)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "conservation"
    assert caught.value.failure_class == "accounting_conservation_failure"


@pytest.mark.parametrize("artifact_kind", ["evidence", "model"])
def test_manifest_rejects_unreferenced_content_addressed_artifacts(
    tmp_path: Path,
    artifact_kind: str,
) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    manifest_path = Path(report["run_manifest"]["decision_trace"]["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("manifest_sha256")
    if artifact_kind == "evidence":
        body = {
            "schema_version": "zscope.evidence-object.v1",
            "kind": "synthetic",
            "producer": "test",
            "dependency_hashes": [],
            "locations": [],
            "payload": {},
        }
        directory = manifest_path.parent / "evidence_objects"
        list_key = "evidence_object_sha256"
        count_key = "evidence_object_count"
    else:
        cluster_uid = report["candidate_terminal_states"][0]["validation_cluster_uid"]
        body = {
            "schema_version": "zscope.model-event.v1",
            "call_identity": "unreferenced-model-call",
            "stage": "verifier",
            "validation_cluster_uid": cluster_uid,
            "structured_input": {},
            "structured_output": {},
            "call_ids": [],
            "tool_call_ids": [],
            "prompt_revision": "p6-synthetic-test",
            "prompt_hash": "",
        }
        directory = manifest_path.parent / "model_events"
        list_key = "model_event_sha256"
        count_key = "model_event_count"
    digest = _canonical_sha256(body)
    directory.mkdir(exist_ok=True)
    (directory / f"{digest}.json").write_text(
        json.dumps({**body, "sha256": digest}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest[list_key] = sorted([*manifest[list_key], digest])
    manifest[count_key] += 1
    manifest_sha256 = _canonical_sha256(manifest)
    manifest["manifest_sha256"] = manifest_sha256
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    report["run_manifest"]["decision_trace"]["manifest_sha256"] = manifest_sha256
    report["run_manifest"]["decision_trace"][count_key] = manifest[count_key]
    _rewrite_report(workspace, report)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "conservation"
    assert caught.value.failure_class == "accounting_conservation_failure"


def test_trace_path_rejects_a_symlinked_lexical_directory(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    snapshots = workspace.project_root / ".zscope_snapshots"
    trace_dir = snapshots / "decision_traces"
    real_dir = snapshots / "decision_traces-real"
    trace_dir.rename(real_dir)
    trace_dir.symlink_to(real_dir.name, target_is_directory=True)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "conservation"
    assert caught.value.failure_class == "accounting_conservation_failure"


@pytest.mark.parametrize(
    ("field", "value"),
    [("unexpected", "field"), ("total_tokens", True)],
)
def test_usage_event_schema_and_field_types_are_exact(
    tmp_path: Path,
    field: str,
    value: Any,
) -> None:
    workspace = _workspace(tmp_path)
    _, events = _write_success_artifacts(workspace)
    events[0][field] = value
    _rewrite_events(workspace, events)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "usage"
    assert caught.value.failure_class == "provider_usage_unverifiable"


def test_function_result_set_rejects_duplicate_entry_with_fixed_cardinality(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report, _ = _write_success_artifacts(workspace)
    report["function_results"][-1] = copy.deepcopy(report["function_results"][0])
    _rewrite_report(workspace, report)

    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.stage == "scan"
    assert caught.value.failure_class == "anonymous_qualification_failed"


@pytest.mark.parametrize(
    ("field", "value", "failure_class"),
    [
        ("retry", True, "provider_transport_exhausted"),
        ("call_kind", "contract_regeneration", "provider_protocol_incompatible"),
    ],
)
def test_retry_and_regeneration_are_bounded_per_call_chain(
    tmp_path: Path,
    field: str,
    value: Any,
    failure_class: str,
) -> None:
    workspace = _workspace(tmp_path)
    _, events = _write_success_artifacts(workspace)
    events[0][field] = value
    events[1][field] = value
    events[1]["validation_cluster_uid"] = events[0]["validation_cluster_uid"]
    events[1]["attribution"]["validation_cluster_uid"] = events[0]["validation_cluster_uid"]
    if field == "call_kind":
        events[0]["attribution"]["call_kind"] = value
        events[1]["attribution"]["call_kind"] = value
        events[1]["logical_operation_id"] = events[0]["logical_operation_id"]
    _rewrite_events(workspace, events)
    with pytest.raises(SyntheticReplayError) as caught:
        validate_replay_report(workspace)
    assert caught.value.failure_class == failure_class
    assert REPLAY_MAX_CONTRACT_REGENERATIONS == 1


def test_failure_projection_and_cli_never_expose_exception_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    error = SyntheticReplayError("provider", "provider_transport_exhausted", 2)
    error.__cause__ = RuntimeError("provider body and private response must stay hidden")
    projection = failure_result(error)
    assert projection["failure"] == {
        "stage": "provider",
        "failure_class": "provider_transport_exhausted",
        "failure_count": 2,
    }
    assert_answer_free_payload(projection)

    def fail(**kwargs):
        raise error

    monkeypatch.setattr(replay_cli, "run_synthetic_replay", fail)
    output = (tmp_path / "result.json").resolve()
    code = replay_cli.main(
        [
            "--config",
            str((tmp_path / "provider.yaml").resolve()),
            "--api-key-file",
            str((tmp_path / "secret.env").resolve()),
            "--work-root",
            str((tmp_path / "work").resolve()),
            "--output",
            str(output),
        ]
    )
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert captured.err == "stage=provider; class=provider_transport_exhausted:2; count=2\n"
    assert "private response" not in captured.err
    assert json.loads(output.read_text(encoding="utf-8")) == projection


def test_p6_docs_freeze_synthetic_replay_before_cold_balanced() -> None:
    root = Path(__file__).resolve().parents[1]
    protocol = (root / "docs" / "range-benchmark.md").read_text(encoding="utf-8")
    phase = (
        root
        / "docs"
        / "design"
        / "zscope-2.0-security-architecture"
        / "phases"
        / "P6-pilot-validation.md"
    ).read_text(encoding="utf-8")
    interfaces = (root / "docs" / "modules" / "interfaces-reporting.md").read_text(encoding="utf-8")

    replay_offset = protocol.index("scripts/run_p6_synthetic_replay.py")
    balanced_offset = protocol.index("完成一次 cold balanced", replay_offset)
    assert replay_offset < balanced_offset
    assert "--api-key-file /tmp/zscope-p6-key.env" in protocol
    assert "llm_max_inflight=1" in protocol
    assert "真实网络调用加入零网络 pytest" in protocol
    assert "deepseek-v4-flash-ga-260731" in phase
    assert "11,999,999" in phase
    assert "TP >= 82/136" in phase and "TP = 61/61" in phase
    assert "Claude Code `2.1.233`" in phase
    assert "DSH `0.1.0-rc.6`" in phase
    assert "Codex CLI `0.144.4`" in phase
    assert "`audit_observations` 是独立、守恒的 shadow-observation 集合" in interfaces
