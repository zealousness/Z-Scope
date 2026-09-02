import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from scripts.p2_proof_corpus import build_corpus
import zscope.core.validation.runner as validation_runner_module
import zscope.orchestration.decision_trace as decision_trace_module
from zscope.common.cancellation import (
    CancellationError,
    CancellationToken,
    bind_cancellation_token,
)
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.core.validation.runner import ValidationResultCache, ValidationRunner
from zscope.core.validation.audit_eligibility import (
    has_exact_v4_producer_occurrence_binding,
)
from zscope.core.validation.fact_capabilities import EvidenceAction
from zscope.core.validation.function_ir import FunctionIRGraph
from zscope.core.validation.proof_kernel import (
    PREDICATE_REGISTRY,
    PROOF_KERNEL_AUTHORITY_INPUT_VERSION,
    ProofKernelEngine,
    build_proof_clause,
    build_proof_obligation,
    program_proof_ir_from_graph,
)
from zscope.framework.base import AgentResponse
from zscope.framework.llm_client import ProviderFailureError
from zscope.framework.llm_usage import (
    P6BalancedTokenAdmissionError,
    ScanTokenUsageLedger,
)
from zscope.orchestration.candidates import CandidateLedger, CandidateRegistrar
from zscope.orchestration.decision_trace import DecisionTraceError, DecisionTraceStore
from zscope.orchestration.scheduler import ScanScheduler


class FakeUserConfig:
    def __init__(self):
        self.baseline = None

    def is_false_positive(self, func_name, location, category):
        return False

    def get_finding_baseline_for_issue(self, issue, dedup_key):
        return self.baseline

    def get_finding_baseline(self, dedup_key):
        return self.baseline


def _trust_test_producer_occurrence_binding(monkeypatch, issue: dict) -> None:
    issue["proof_kernel_producer_binding_sha256"] = "a" * 64
    issue["proof_kernel_occurrence_binding_sha256"] = "b" * 64
    verifier = lambda _candidate: True
    monkeypatch.setattr(
        validation_runner_module,
        "has_exact_v4_producer_occurrence_binding",
        verifier,
    )
    monkeypatch.setattr(
        decision_trace_module,
        "_has_exact_v4_producer_occurrence_binding",
        verifier,
    )


class FakeCodeIndex:
    def get_file_snippet(self, file_path, start, end):
        return "snippet"

    def get_callers(self, func_name, limit=8):
        return []

    def get_callees(self, func_name, limit=12):
        return []

    def get_function_impl(self, func_name):
        return {"code": "void sink_func(void) {}"}


class FakeSnapshotStore:
    def load_snapshot(self, func_name):
        return None


class FakeValidatorAgent:
    def __init__(self, responses):
        self.responses = list(responses)
        self.inputs = []

    def run(self, input_data):
        self.inputs.append(input_data)
        return self.responses.pop(0)


def _runner(
    agent,
    *,
    enabled=True,
    memory=None,
    analysis=None,
    code_index=None,
    proof_engine_agent_factory=None,
    result_cache=None,
    scheduler=None,
    get_tools=None,
    concurrency=None,
    scan=None,
    attach_agent_contract=None,
):
    memory = memory if memory is not None else []
    config = SimpleNamespace(
        analysis=analysis,
        # Tests that exercise the Proof Engine adapter use the model-capable
        # balanced profile unless they explicitly select fast.  P5 fast is a
        # hard zero-model path.
        scan=scan or SimpleNamespace(depth="balanced"),
        concurrency=concurrency
        or SimpleNamespace(
            validator_workers=2,
            evidence_completion_workers=2,
        ),
        project=SimpleNamespace(
            agents=[SimpleNamespace(name="proof_engine", enabled=enabled, llm_ref="default")]
        ),
    )
    return ValidationRunner(
        config=config,
        llm_clients={"default": object()},
        validation_pipeline=ValidationPipeline(FakeUserConfig()),
        code_index=code_index or FakeCodeIndex(),
        snapshot_store=FakeSnapshotStore(),
        get_tools=get_tools or (lambda agent_name: []),
        tool_policy_for_agent=lambda agent_name: None,
        attach_agent_contract=attach_agent_contract
        or (lambda context, agent_name: context.update({"agent_contract": agent_name})),
        remember_validation_result=lambda issue, status: memory.append((issue["id"], status)),
        proof_engine_agent_factory=proof_engine_agent_factory or (lambda *args, **kwargs: agent),
        result_cache=result_cache,
        scheduler=scheduler,
    )


def _state(issue):
    return {
        "pending_new_issues": [issue],
        "agent_context": {
            "func_name": "api_entry",
            "code": "void api_entry(void) { sink_func(); }",
            "entry_custom_prompt": "Public API declared in header file",
        },
        "entry_func": "api_entry",
        "issues": [],
        "observations": [],
        "notes": [],
    }


def _issue(**overrides):
    issue = {
        "id": "ISSUE_1",
        "function": "sink_func",
        "entry_function": "api_entry",
        "location": "src/demo.c:10",
        "category": "memory_leak",
        "confidence": 1.0,
        "rule_confidence": 1.0,
        "source": "arg",
        "sink": "free",
        "evidence_pack": {"path": {"complete": True, "complete_to_entry": True}},
    }
    issue.update(overrides)
    return issue


def _validator_v3_result(
    *,
    verdict="uncertain",
    validation_pass="initial",
    missing_fact_request=None,
    stop_reason="decision_complete",
):
    return {
        "schema_version": "zscope.validator-result.v3",
        "candidate_uid": "CAND_V3",
        "validation_cluster_uid": "VAL_V3",
        "pass": validation_pass,
        "verdict": verdict,
        "reasoning": "bounded validator decision",
        "positive_evidence": ["structured path"],
        "negative_evidence": [],
        "evidence_refs": [],
        "blocking_negative_evidence": False,
        "missing_fact_request": missing_fact_request,
        "stop_reason": stop_reason,
    }


def _closed_v4_issue(**overrides):
    case = build_corpus()["cases"][0]
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=case["program_proof_ir"],
        obligation=case["proof_obligation"],
    )
    issue = _issue(**overrides)
    evaluation.apply_to_issue(issue)
    selected_action_uids = [str(value["action_uid"]) for value in evaluation.actions]
    issue.update(
        {
            "proof_kernel_input": evaluation.authority_inputs()["proof_kernel_input"],
            "proof_kernel_live_selected_action_uids": selected_action_uids,
            "proof_kernel_checker_results": [dict(value) for value in evaluation.check_results],
            "proof_kernel_artifact_refs": list(evaluation.artifact_refs),
            "proof_kernel_checker_result_refs": list(evaluation.checker_result_refs),
            "proof_kernel_root_manifest_sha256": evaluation.root_manifest_sha256,
        }
    )
    return issue


def _function_ir_graph(*, duplicate_sink: bool = False, as_object: bool = False):
    blocks = [
        {
            "id": "B4",
            "label": "(ENTRY)",
            "successors": ["B3"],
            "predecessors": [],
            "statements": [],
        },
        {
            "id": "B3",
            "label": "",
            "successors": ["B2", "B1"],
            "predecessors": ["B4"],
            "statements": ["wire_len = read_input()", "if (wire_len)"],
        },
        {
            "id": "B2",
            "label": "",
            "successors": ["B0"],
            "predecessors": ["B3"],
            "statements": ["sink(wire_len)"],
        },
        {
            "id": "B1",
            "label": "",
            "successors": ["B0"],
            "predecessors": ["B3"],
            "statements": ["sink(wire_len)" if duplicate_sink else "observe(wire_len)"],
        },
        {
            "id": "B0",
            "label": "(EXIT)",
            "successors": [],
            "predecessors": ["B2", "B1"],
            "statements": [],
        },
    ]
    call_exprs = [
        {"callee": "read_input", "line": 5},
        {"callee": "sink", "line": 10},
    ]
    if duplicate_sink:
        call_exprs.append({"callee": "sink", "line": 20})
    graph = FunctionIRGraph.from_clang_evidence(
        {
            "clang_path": "clang",
            "code_snapshot_sha256": "c" * 64,
            "cfg_dump": {
                "summary": {
                    "parse_ok": True,
                    "function": "sink_func",
                    "function_section_unique": True,
                    "entry_blocks": ["B4"],
                    "exit_blocks": ["B0"],
                    "blocks": blocks,
                }
            },
            "ast_dump": {"summary": {"target_function": {"call_exprs": call_exprs}}},
        },
        function="sink_func",
        file="src/demo.c",
    )
    assert graph is not None
    return graph if as_object else graph.to_dict()


def _executable_path_issue(**overrides):
    issue = _issue(
        function_ir_graph=_function_ir_graph(duplicate_sink=True),
        source={"callee": "read_input", "line": 5},
        sink={"callee": "sink"},
        security_obligation={
            "obligation_uid": "OBL_PATH",
            "subject_uid": "wire_len",
            "decision_region_uid": "REGION_PATH",
            "required_fact_kinds": ["source_sink_reachability"],
        },
        obligation_required_fact_kinds=["source_sink_reachability"],
        missing_fact_kinds=["source_sink_reachability"],
    )
    issue.update(overrides)
    return issue


def _resource_function_ir_graph(*, cleanup: bool) -> dict:
    statements = ["p = malloc(8)"]
    calls = [{"callee": "malloc", "line": 4}]
    if cleanup:
        statements.append("free(p)")
        calls.append({"callee": "free", "line": 5})
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
    assert graph is not None
    return graph.to_dict()


def _resource_proof_issue(*, cleanup: bool) -> dict:
    return _issue(
        id="ISSUE_RESOURCE_PROOF",
        candidate_uid="CAND_RESOURCE_PROOF",
        validation_cluster_uid="VAL_RESOURCE_PROOF",
        function="resource_target",
        file="src/resource.c",
        location="src/resource.c:4",
        category="memory_leak",
        resource_identity="p",
        function_ir_graph=_resource_function_ir_graph(cleanup=cleanup),
        security_obligation={
            "obligation_uid": "OBL_RESOURCE_PROOF",
            "defect_family": "resource_leak",
            "subject_uid": "p",
            "decision_region_uid": "REGION_RESOURCE_PROOF",
            "required_fact_kinds": ["event:acquire", "event:exit"],
        },
        obligation_required_fact_kinds=["event:acquire", "event:exit"],
        decision_fact_slice={
            "fact_uids": ["FACT_ACQUIRE", "FACT_EXIT"],
            "dependency_code_hashes": ["resource-code-sha"],
            "missing_fact_kinds": [],
            "coverage": "complete",
            "facts": [],
        },
        decision_fact_coverage="complete",
        missing_fact_kinds=[],
    )


def test_validation_runner_cache_key_uses_stable_evidence_fingerprint_without_candidate_id() -> (
    None
):
    runner = _runner(None)
    issue = _issue(
        id="ISSUE_VOLATILE",
        candidate_id="",
        category="resource_allocation_without_limits",
        defect_class="resource_allocation_without_limits",
        function="demo",
        source="segment_count",
        sink="_safe_calloc(segment_count, sizeof(int))",
        evidence_pack={
            "resource": "segment_count",
            "source": {"expression": "segment_count"},
            "sink": {"operation": "_safe_calloc(segment_count, sizeof(int))"},
        },
    )
    item = SimpleNamespace(raw_issue=issue, issue_func="demo")

    key = runner._validator_cache_key(item)

    assert key


def test_fact_first_missing_cleanup_is_shadow_only_before_v1() -> None:
    agent = FakeValidatorAgent([AgentResponse(success=True, data=_validator_v3_result())])
    issue = _resource_proof_issue(cleanup=False)
    state = _state(issue)

    _runner(agent).run(state)

    assert len(agent.inputs) == 1
    assert agent.inputs[0]["evidence_slice"]["decision_facts"]["facts"] == []
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["proof_kernel_fact_first"]["proof_engine"]["disposition"] == "confirmed"
    assert "proof_kernel_checker_results" not in issue


def test_fact_first_complete_cleanup_counterproof_is_shadow_only_before_v1() -> None:
    agent = FakeValidatorAgent([AgentResponse(success=True, data=_validator_v3_result())])
    issue = _resource_proof_issue(cleanup=True)
    state = _state(issue)

    _runner(agent).run(state)

    assert len(agent.inputs) == 1
    assert agent.inputs[0]["evidence_slice"]["decision_facts"]["facts"] == []
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["proof_kernel_fact_first"]["proof_engine"]["disposition"] == (
        "rejected_with_proof"
    )
    assert "proof_kernel_checker_results" not in issue


def test_governed_validator_candidate_freezes_composite_v4_after_evidence_pack() -> None:
    issue = _resource_proof_issue(cleanup=False)
    issue.update(
        {
            "line": 4,
            "resource": "p",
            "source": {
                "file": "src/resource.c",
                "function": "resource_target",
                "line": 4,
                "resource": "p",
                "expression": "malloc",
            },
            "sink": {
                "file": "src/resource.c",
                "function": "resource_target",
                "line": 4,
                "resource": "p",
                "operation": "exit",
            },
            "candidate_source": "clang_ast_cfg",
        }
    )
    CandidateRegistrar(
        CandidateLedger(project_id="PROJECT_TEST", revision="REV_TEST")
    ).register_issues(
        [issue],
        source="clang_ast_cfg",
        default_entry_identity="api_entry",
    )
    runner = _runner(FakeValidatorAgent([]))

    prepared = runner._prepare_issue_for_validation(_state(issue), issue, 0)

    assert prepared is None
    assert issue["proof_kernel_input_origin"] == "product_composite_obligation_v4"
    assert issue["proof_kernel_composite_family"] == "leak"
    assert issue["proof_kernel_composite_status"] == "frozen"
    assert issue["proof_kernel_frozen_state"]["schema_version"] == ("zscope.frozen-proof-state.v1")
    assert issue["proof_kernel_closure_evaluation"]["complete"] is True
    assert issue["proof_kernel_promotion_certificate"]["schema_version"] == (
        "zscope.promotion-certificate.v1"
    )
    assert issue["proof_kernel_terminal_authority_decision"]["disposition"] == "confirmed"
    assert len(issue["proof_kernel_producer_binding_sha256"]) == 64
    assert len(issue["proof_kernel_occurrence_binding_sha256"]) == 64
    assert has_exact_v4_producer_occurrence_binding(issue) is True
    obligation = issue["proof_kernel_input"]["proof_obligation"]
    assert obligation["open_clauses"] == []
    assert {value["fact_kind"] for value in obligation["confirmation_clauses"]} == {
        "object_identity",
        "cleanup_coverage",
        "ownership_transfer",
    }


def test_live_entry_discards_self_sealed_input_and_all_stale_terminal_projections() -> None:
    stale = _closed_v4_issue(
        candidate_disposition="confirmed",
        validation_status="validated",
        policy_disposition="confirmed",
        finding_kind="confirmed",
        terminal_transition_level="V0",
        terminal_transition_disposition="confirmed",
        terminal_transition_event_uid="EVENT_STALE",
        terminal_transition_event_hash="a" * 64,
        terminal_transition_authority_sha256="b" * 64,
    )
    stale_authority = {
        "schema_version": "zscope.terminal-authority-decision.v4",
        "terminal": True,
        "disposition": "confirmed",
    }
    stale["proof_kernel_terminal_authority_decision"] = dict(stale_authority)
    stale["terminal_authority_decision"] = dict(stale_authority)
    stale["proof_kernel_evaluation"] = {"decision": "confirmed"}
    stale["candidate_promotion_eligible"] = True
    stale["candidate_promotion_reason"] = "stale"
    stale["candidate_promotion_terminal_status"] = "confirmed"
    runner = _runner(FakeValidatorAgent([]))

    prepared = runner._prepare_issue_for_validation(_state(stale), stale, 0)

    assert prepared is not None
    assert stale["proof_kernel_input_rebuild_status"] == "legacy_or_unknown_candidate"
    assert stale["candidate_disposition"] == "needs_review"
    assert stale["validation_status"] == "needs_review"
    for key in (
        "proof_kernel_input",
        "proof_kernel_frozen_state",
        "proof_kernel_closure_evaluation",
        "proof_kernel_promotion_certificate",
        "proof_kernel_evaluation",
        "proof_kernel_terminal_authority_decision",
        "terminal_authority_decision",
        "terminal_transition_level",
        "terminal_transition_disposition",
        "terminal_transition_event_uid",
        "terminal_transition_event_hash",
        "terminal_transition_authority_sha256",
        "candidate_promotion_eligible",
        "candidate_promotion_reason",
        "candidate_promotion_terminal_status",
    ):
        assert key not in stale


def test_midflight_self_sealed_foreign_proof_cannot_authorize_live_terminal() -> None:
    issue = _closed_v4_issue(
        candidate_uid="CAND_FOREIGN_TARGET",
        validation_cluster_uid="VAL_FOREIGN_TARGET",
    )
    issue["proof_kernel_producer_binding_sha256"] = "a" * 64
    issue["proof_kernel_occurrence_binding_sha256"] = "b" * 64
    runner = _runner(FakeValidatorAgent([]))

    assert runner._terminal_authority.evaluate(issue, operation="live").disposition == "confirmed"
    authority = runner._evaluate_bound_terminal_authority(issue, operation="live")

    assert authority.disposition == "needs_review"
    assert authority.reason_code == "NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE"


def test_disabled_validator_cannot_preserve_self_sealed_v0_authority() -> None:
    issue = _closed_v4_issue(
        candidate_disposition="confirmed",
        validation_status="validated",
        terminal_transition_level="V0",
    )
    state = _state(issue)

    _runner(FakeValidatorAgent([]), enabled=False).run(state)

    assert issue["candidate_disposition"] == "needs_review"
    assert issue["validation_status"] == "needs_review"
    assert issue["proof_kernel_input_rebuild_status"] == "legacy_or_unknown_candidate"
    assert "proof_kernel_input" not in issue
    assert "proof_kernel_promotion_certificate" not in issue
    assert "terminal_transition_level" not in issue
    assert issue["terminal_authority_decision"]["disposition"] == "needs_review"
    assert state["issues"] == []


def test_live_product_rebuild_replaces_stale_cross_obligation_authority() -> None:
    issue = _resource_proof_issue(cleanup=True)
    issue.update(
        {
            "line": 4,
            "resource": "p",
            "source": {
                "file": "src/resource.c",
                "function": "resource_target",
                "line": 4,
                "resource": "p",
                "expression": "malloc",
            },
            "sink": {
                "file": "src/resource.c",
                "function": "resource_target",
                "line": 4,
                "resource": "p",
                "operation": "exit",
            },
            "candidate_source": "clang_ast_cfg",
        }
    )
    CandidateRegistrar(
        CandidateLedger(project_id="PROJECT_TEST", revision="REV_TEST")
    ).register_issues(
        [issue],
        source="clang_ast_cfg",
        default_entry_identity="api_entry",
    )
    stale = _closed_v4_issue()
    stale_input = stale["proof_kernel_input"]
    for key, value in stale.items():
        if key.startswith("proof_kernel_") or key.startswith("terminal_"):
            issue[key] = value
    runner = _runner(FakeValidatorAgent([]))

    prepared = runner._prepare_issue_for_validation(_state(issue), issue, 0)

    assert prepared is None
    assert issue["proof_kernel_input"] != stale_input
    assert issue["proof_kernel_input_origin"] == "product_composite_obligation_v4"
    assert issue["proof_kernel_input"]["proof_obligation"]["counterproof_clauses"]
    assert issue["proof_kernel_terminal_authority_decision"]["disposition"] == (
        "rejected_with_proof"
    )
    assert issue["candidate_disposition"] == "rejected_with_proof"
    assert issue["terminal_transition_level"] == "V0"


def test_v4_reverification_failure_is_answer_safe(monkeypatch) -> None:
    secret = "PRIVATE_PROMPT_AND_SOURCE_MUST_NOT_LEAK"

    class ExplodingProofKernel:
        def evaluate(self, **_kwargs):
            raise ValueError(secret)

    monkeypatch.setattr(
        "zscope.core.validation.runner.ProofKernelEngine",
        ExplodingProofKernel,
    )
    issue = {
        "proof_kernel_input": {
            "schema_version": PROOF_KERNEL_AUTHORITY_INPUT_VERSION,
            "proof_ir": {},
            "proof_obligation": {},
            "selected_action_uids": [],
        }
    }

    _runner(None)._reverify_attached_proof_kernel_input(issue)

    serialized = json.dumps(issue, ensure_ascii=False, sort_keys=True)
    assert secret not in serialized
    assert "ValueError" not in serialized
    assert issue["proof_kernel_decision"]["failure_class"] == ("proof_kernel_reverification_failed")


def test_validation_worker_failure_and_trace_failure_are_answer_safe(caplog) -> None:
    secret = "PRIVATE_VALIDATOR_EXCEPTION_BODY_MUST_NOT_LEAK"
    captured = []

    class CapturingTrace:
        def append_event(self, *_args, **kwargs):
            captured.append(kwargs)

    issue = _issue(
        candidate_uid="CAND_FAILURE_SAFE",
        validation_cluster_uid="VAL_FAILURE_SAFE",
    )
    state = _state(issue)
    runner = _runner(None)
    runner._decision_trace_store = CapturingTrace()
    caplog.set_level(logging.WARNING, logger="zscope.core.validation.runner")

    runner._handle_validation_failure(
        state,
        issue,
        "sink_func",
        ValueError(secret),
    )

    serialized = json.dumps({"issue": issue, "trace": captured}, ensure_ascii=False)
    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert secret not in serialized
    assert secret not in messages
    assert "ValueError" not in serialized
    assert issue["validation_error"] == "validation_worker_failure"
    assert captured[-1]["details"] == {"failure_class": "validation_worker_failure"}

    class FailingTrace:
        def append_event(self, *_args, **_kwargs):
            raise RuntimeError(secret)

    runner._decision_trace_store = FailingTrace()
    runner._trace_event(
        issue,
        stage="policy",
        actor="unit-test",
        reason_code="NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE",
    )
    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert secret not in messages
    assert "RuntimeError" not in messages
    assert "class=decision_trace_append_failed" in messages

    class FailingCacheStore:
        def load_validation_result(self, *_args, **_kwargs):
            raise OSError(secret)

        def save_validation_result(self, *_args, **_kwargs):
            raise OSError(secret)

    runner.snapshot_store = FailingCacheStore()
    assert runner._validator_cache_get("CACHE_FAILURE_SAFE") is None
    assert runner._validator_cache_put("CACHE_FAILURE_SAFE", _validator_v3_result()) is True
    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert secret not in messages
    assert "OSError" not in messages
    assert "class=validation_cache_read_failed; count=1" in messages
    assert "class=validation_cache_write_failed; count=1" in messages


def test_balanced_validation_order_is_answer_free_and_not_priority_score_only() -> None:
    runner = _runner(None, scan=SimpleNamespace(depth="balanced"))

    def item(index, identifier, **issue_values):
        issue = _issue(id=identifier, priority_score=999 - index, **issue_values)
        return SimpleNamespace(index=index, raw_issue=issue)

    low = item(0, "LOW", confidence=0.1, positive_evidence=[])
    standard = item(1, "STANDARD", confidence=0.8, positive_evidence=["anchor"])
    counterproof = item(2, "COUNTER", confidence=0.8, negative_evidence=["guard"])
    near = item(
        3,
        "NEAR",
        confidence=0.8,
        proof_kernel_closure_evaluation={
            "checked_clause_uids": ["CLAUSE_1"],
            "missing_clause_uids": ["CLAUSE_2"],
        },
    )

    ordered = runner._order_balanced_validation_work([low, standard, counterproof, near])

    assert [value.raw_issue["id"] for value in ordered] == [
        "NEAR",
        "COUNTER",
        "STANDARD",
        "LOW",
    ]
    assert [value.raw_issue["balanced_validation_priority"]["class"] for value in ordered] == [
        "near_closure",
        "high_value_counterproof",
        "standard",
        "low_value_audit",
    ]
    assert all(
        value.raw_issue["balanced_validation_priority"]["basis"]["truth_fields_consulted"] is False
        for value in ordered
    )


def test_p6_soft_watermark_stage_applies_only_to_low_value_balanced_work() -> None:
    runner = _runner(None, scan=SimpleNamespace(depth="balanced"))
    ledger = ScanTokenUsageLedger(depth="balanced")
    ledger.enable_p6_balanced_admission()
    runner.config.scan_token_usage_ledger = ledger
    low = SimpleNamespace(
        raw_issue={
            "balanced_validation_priority": {"class": "low_value_audit"},
        }
    )
    strong = SimpleNamespace(
        raw_issue={
            "balanced_validation_priority": {"class": "near_closure"},
        }
    )

    assert runner._validation_usage_stage(low) == "active_discovery"
    assert runner._validation_usage_stage(strong) == "validation"
    assert runner._validation_usage_call_kind(low) == "p6_low_value_audit"
    assert runner._validation_usage_call_kind(strong) == ""

    ordinary = _runner(None, scan=SimpleNamespace(depth="balanced"))
    ordinary.config.scan_token_usage_ledger = ScanTokenUsageLedger(depth="balanced")
    assert ordinary._validation_usage_stage(low) == "validation"
    assert ordinary._validation_usage_call_kind(low) == ""


def test_p6_soft_watermark_drains_eight_workers_as_zero_call_audit() -> None:
    barrier = threading.Barrier(8)
    lock = threading.Lock()
    active = 0
    max_active = 0

    class SoftDeniedValidator:
        def run(self, _input_data):
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
            try:
                barrier.wait(timeout=5)
                raise P6BalancedTokenAdmissionError("p6_token_soft_watermark")
            finally:
                with lock:
                    active -= 1

    issues = [
        _issue(
            id=f"ISSUE_SOFT_TOKEN_{index}",
            candidate_uid=f"CAND_SOFT_TOKEN_{index}",
            validation_cluster_uid=f"VAL_SOFT_TOKEN_{index}",
            dedup_key=f"soft-token-{index}",
            confidence=0.1,
            rule_confidence=0.1,
            positive_evidence=[],
            audit_status="audit_only",
            category="potential_issue",
        )
        for index in range(8)
    ]
    state = _state(issues[0])
    state["pending_new_issues"] = issues
    runner = _runner(
        None,
        concurrency=SimpleNamespace(
            validator_workers=8,
            evidence_completion_workers=8,
        ),
        proof_engine_agent_factory=lambda *_args, **_kwargs: SoftDeniedValidator(),
    )
    ledger = ScanTokenUsageLedger(depth="balanced")
    ledger.enable_p6_balanced_admission()
    runner.config.scan_token_usage_ledger = ledger

    runner.run(state)

    assert max_active == 8
    assert state["validation_queue_drained"] is True
    assert state["pending_new_issues"] == []
    assert state["observations"] == []
    assert len(state["audit_observations"]) == 8
    assert state["p6_token_admission_counts"] == {"p6_token_soft_watermark": 8}
    assert state["p6_token_admission_denied_request_counts"] == {"p6_token_soft_watermark": 8}
    assert all(issue["candidate_disposition"] == "shadow_observation" for issue in issues)
    assert all(issue["p6_token_provider_calls"] == 0 for issue in issues)
    assert all("validation_error" not in issue for issue in issues)


def test_p6_soft_watermark_uses_audit_eligibility_and_preserves_actionable_review(
    monkeypatch,
) -> None:
    from zscope.core.validation import runner as runner_module

    calls = []

    class Eligible:
        needs_review_eligible = True
        reason_codes = ()

        def to_dict(self):
            return {
                "schema_version": "zscope.audit-eligibility.v1",
                "needs_review_eligible": True,
                "reason_codes": [],
                "disposition": "needs_review",
            }

    def classify(issue):
        calls.append(issue["id"])
        return Eligible()

    monkeypatch.setattr(runner_module, "evaluate_audit_eligibility", classify)

    class SoftDeniedValidator:
        def run(self, _input_data):
            raise P6BalancedTokenAdmissionError("p6_token_soft_watermark")

    issue = _issue(
        id="ISSUE_SOFT_ELIGIBLE",
        candidate_uid="CAND_SOFT_ELIGIBLE",
        validation_cluster_uid="VAL_SOFT_ELIGIBLE",
        dedup_key="soft-eligible",
        confidence=0.1,
        rule_confidence=0.1,
        positive_evidence=[],
        audit_status="audit_only",
        category="potential_issue",
    )
    state = _state(issue)
    memory = []
    runner = _runner(
        None,
        memory=memory,
        proof_engine_agent_factory=lambda *_args, **_kwargs: SoftDeniedValidator(),
    )
    ledger = ScanTokenUsageLedger(depth="balanced")
    ledger.enable_p6_balanced_admission()
    runner.config.scan_token_usage_ledger = ledger

    runner.run(state)

    assert calls == ["ISSUE_SOFT_ELIGIBLE"]
    assert state["validation_queue_drained"] is True
    assert state["observations"] == [issue]
    assert state.get("audit_observations", []) == []
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["audit_eligibility"]["needs_review_eligible"] is True
    assert issue["p6_token_provider_calls"] == 0
    assert memory == [("ISSUE_SOFT_ELIGIBLE", "needs_review")]


def test_p6_hard_limit_drains_as_canonical_needs_review_without_engine_failure() -> None:
    class HardDeniedValidator:
        def run(self, _input_data):
            raise P6BalancedTokenAdmissionError("p6_token_hard_limit")

    issue = _issue(
        id="ISSUE_HARD_TOKEN",
        candidate_uid="CAND_HARD_TOKEN",
        validation_cluster_uid="VAL_HARD_TOKEN",
        dedup_key="hard-token",
    )
    state = _state(issue)
    memory = []
    runner = _runner(
        None,
        memory=memory,
        proof_engine_agent_factory=lambda *_args, **_kwargs: HardDeniedValidator(),
    )

    runner.run(state)

    assert state["validation_queue_drained"] is True
    assert state["observations"] == [issue]
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["validation_status"] == "needs_review"
    assert issue["p6_token_admission_reason"] == "p6_token_hard_limit"
    assert issue["p6_token_admission_request_denied"] is True
    assert issue["p6_token_provider_calls"] == 0
    assert issue["terminal_reason_codes"] == ["NEEDS_REVIEW_OPEN_CLAUSES"]
    assert "validation_error" not in issue
    assert memory == [("ISSUE_HARD_TOKEN", "needs_review")]


def test_p6_hard_limit_collects_current_eight_and_never_starts_next_batch() -> None:
    barrier = threading.Barrier(8)
    lock = threading.Lock()
    calls = 0

    class OneHardDeniedValidator:
        def run(self, _input_data):
            nonlocal calls
            with lock:
                calls += 1
                ordinal = calls
            barrier.wait(timeout=5)
            if ordinal == 1:
                raise P6BalancedTokenAdmissionError("p6_token_hard_limit")
            return AgentResponse(
                success=True,
                data=_validator_v3_result(
                    verdict="uncertain",
                    stop_reason="decision_complete",
                ),
            )

    issues = [
        _issue(
            id=f"ISSUE_HARD_BATCH_{index}",
            candidate_uid=f"CAND_HARD_BATCH_{index}",
            validation_cluster_uid=f"VAL_HARD_BATCH_{index}",
            dedup_key=f"hard-batch-{index}",
        )
        for index in range(16)
    ]
    state = _state(issues[0])
    state["pending_new_issues"] = issues
    shared = OneHardDeniedValidator()
    runner = _runner(
        None,
        concurrency=SimpleNamespace(
            validator_workers=8,
            evidence_completion_workers=8,
        ),
        proof_engine_agent_factory=lambda *_args, **_kwargs: shared,
    )

    runner.run(state)

    assert calls == 8
    assert state["validation_queue_drained"] is True
    assert state["pending_new_issues"] == []
    assert state["p6_token_admission_denied_request_counts"] == {"p6_token_hard_limit": 1}
    assert state["p6_token_admission_counts"] == {"p6_token_hard_limit": 9}
    budget_closed = [
        issue for issue in issues if issue.get("p6_token_admission_reason") == "p6_token_hard_limit"
    ]
    assert len(budget_closed) == 9
    assert sum(issue.get("p6_token_admission_request_denied") is True for issue in issues) == 1
    assert all(issue.get("p6_token_provider_calls") == 0 for issue in budget_closed)
    assert all("validation_error" not in issue for issue in issues)


def test_validation_runner_cache_key_rejects_weak_fingerprint_without_candidate_id() -> None:
    runner = _runner(None)
    issue = _issue(id="ISSUE_WEAK", candidate_id="", source="", sink="", evidence_pack={})
    item = SimpleNamespace(raw_issue=issue, issue_func="demo")

    assert runner._validator_cache_key(item) == ""


def test_validation_runner_cache_is_scoped_to_runner_instance() -> None:
    first = _runner(None)
    second = _runner(None)
    cached = _validator_v3_result()

    first._validator_cache_put("same-candidate", cached)

    assert first._validator_cache_get("same-candidate") == cached
    assert second._validator_cache_get("same-candidate") is None


@pytest.mark.parametrize(
    "changed_field",
    (
        "successor_implementation_root_sha256",
        "successor_qualification_sha256",
        "successor_review_status",
        "successor_review_status_content_sha256",
        "successor_review_set_sha256",
    ),
)
def test_validation_persistent_cache_protocol_binds_complete_successor_projection(
    monkeypatch: pytest.MonkeyPatch,
    changed_field: str,
) -> None:
    base = {
        "successor_implementation_root_sha256": "1" * 64,
        "successor_qualification_sha256": "2" * 64,
        "successor_review_status": "in_progress",
        "successor_review_status_content_sha256": "3" * 64,
        "successor_review_set_sha256": "",
    }
    changed = dict(base)
    changed[changed_field] = "reviewed" if changed_field == "successor_review_status" else "4" * 64

    class ProtocolStore:
        def __init__(self) -> None:
            self.values: dict[tuple[str, str, str, str], dict] = {}

        def save_validation_result(
            self,
            cache_key,
            result,
            *,
            protocol,
            candidate_schema_version,
            environment_fingerprint,
            **_kwargs,
        ) -> None:
            self.values[
                (
                    cache_key,
                    protocol,
                    candidate_schema_version,
                    environment_fingerprint,
                )
            ] = dict(result)

        def load_validation_result(
            self,
            cache_key,
            *,
            protocol,
            candidate_schema_version,
            environment_fingerprint,
        ):
            return self.values.get(
                (
                    cache_key,
                    protocol,
                    candidate_schema_version,
                    environment_fingerprint,
                )
            )

    store = ProtocolStore()

    def install(binding: dict[str, str]) -> None:
        monkeypatch.setattr(
            validation_runner_module,
            "load_successor_qualification",
            lambda: {
                "implementation_root_sha256": binding["successor_implementation_root_sha256"],
                "content_sha256": binding["successor_qualification_sha256"],
            },
        )
        monkeypatch.setattr(
            validation_runner_module,
            "SUCCESSOR_RUNTIME_REVIEW_MANIFEST",
            {
                "status": binding["successor_review_status"],
                "content_sha256": binding["successor_review_status_content_sha256"],
                "review_set_sha256": binding["successor_review_set_sha256"],
            },
        )
        monkeypatch.setattr(
            validation_runner_module,
            "validate_successor_runtime_review_status",
            lambda *_args, **_kwargs: (True, "valid"),
        )
        monkeypatch.setattr(
            validation_runner_module,
            "validate_current_successor_runtime_review_status",
            lambda *_args, **_kwargs: (
                (True, "current_successor_reviewed")
                if binding["successor_review_status"] == "reviewed"
                else (False, "successor_review_in_progress")
            ),
        )

    install(base)
    first = _runner(None)
    first.snapshot_store = store
    assert first._validator_cache_put("same-candidate", _validator_v3_result()) is True

    install(changed)
    second = _runner(None)
    second.snapshot_store = store

    assert first._validation_persistent_cache_enabled is True
    assert second._validation_persistent_cache_enabled is True
    assert first._validation_cache_successor_binding == base
    assert second._validation_cache_successor_binding == changed
    assert first._validation_cache_protocol != second._validation_cache_protocol
    assert second._validator_cache_get("same-candidate") is None


def test_stale_successor_disables_persistent_validation_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def stale() -> dict:
        raise ValueError("successor_qualification_source_stale")

    monkeypatch.setattr(validation_runner_module, "load_successor_qualification", stale)
    runner = _runner(None)
    calls: list[str] = []

    class Store:
        def load_validation_result(self, *_args, **_kwargs):
            calls.append("load")
            return _validator_v3_result()

        def save_validation_result(self, *_args, **_kwargs):
            calls.append("save")

    runner.snapshot_store = Store()
    runner._validator_cache_get("stale-successor")
    runner._validator_cache_put("stale-successor", _validator_v3_result())

    assert runner._validation_persistent_cache_enabled is False
    assert calls == []


def test_unavailable_successor_review_status_disables_persistent_validation_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        validation_runner_module,
        "load_successor_qualification",
        lambda: {
            "implementation_root_sha256": "1" * 64,
            "content_sha256": "2" * 64,
        },
    )
    monkeypatch.setattr(
        validation_runner_module,
        "SUCCESSOR_RUNTIME_REVIEW_MANIFEST",
        {},
    )
    monkeypatch.setattr(
        validation_runner_module,
        "validate_successor_runtime_review_status",
        lambda *_args, **_kwargs: (False, "successor_review_status_unavailable"),
    )

    runner = _runner(None)

    assert runner._validation_persistent_cache_enabled is False
    assert runner._validation_cache_successor_binding == {}


def test_reviewed_successor_without_physical_evidence_disables_persistent_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        validation_runner_module,
        "load_successor_qualification",
        lambda: {
            "implementation_root_sha256": "1" * 64,
            "content_sha256": "2" * 64,
        },
    )
    monkeypatch.setattr(
        validation_runner_module,
        "SUCCESSOR_RUNTIME_REVIEW_MANIFEST",
        {
            "status": "reviewed",
            "content_sha256": "3" * 64,
            "review_set_sha256": "4" * 64,
        },
    )
    monkeypatch.setattr(
        validation_runner_module,
        "validate_successor_runtime_review_status",
        lambda *_args, **_kwargs: (True, "valid"),
    )
    monkeypatch.setattr(
        validation_runner_module,
        "validate_current_successor_runtime_review_status",
        lambda *_args, **_kwargs: (False, "successor_review_evidence_unavailable"),
    )

    runner = _runner(None)

    assert runner._validation_persistent_cache_enabled is False
    assert runner._validation_cache_successor_binding == {}


def test_in_progress_successor_with_physical_evidence_disables_persistent_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        validation_runner_module,
        "load_successor_qualification",
        lambda: {
            "implementation_root_sha256": "1" * 64,
            "content_sha256": "2" * 64,
        },
    )
    monkeypatch.setattr(
        validation_runner_module,
        "SUCCESSOR_RUNTIME_REVIEW_MANIFEST",
        {
            "status": "in_progress",
            "content_sha256": "3" * 64,
            "review_set_sha256": "",
        },
    )
    monkeypatch.setattr(
        validation_runner_module,
        "validate_successor_runtime_review_status",
        lambda *_args, **_kwargs: (True, "valid"),
    )
    monkeypatch.setattr(
        validation_runner_module,
        "validate_current_successor_runtime_review_status",
        lambda *_args, **_kwargs: (
            False,
            "successor_review_in_progress_contains_review_evidence",
        ),
    )

    runner = _runner(None)

    assert runner._validation_persistent_cache_enabled is False
    assert runner._validation_cache_successor_binding == {}


def test_cache_hit_occurs_only_after_persisted_v4_authority_is_discarded() -> None:
    candidate_uid = "CAND_CACHE_STALE_AUTHORITY"
    cluster_uid = "VAL_CACHE_STALE_AUTHORITY"
    cached_result = _validator_v3_result()
    cached_result.update(
        {
            "candidate_uid": candidate_uid,
            "validation_cluster_uid": cluster_uid,
        }
    )
    agent = FakeValidatorAgent([AgentResponse(success=True, data=cached_result)])
    runner = _runner(agent, result_cache=ValidationResultCache(max_entries=8))

    def persisted_attempt():
        return _closed_v4_issue(
            id="ISSUE_CACHE_STALE_AUTHORITY",
            candidate_uid=candidate_uid,
            validation_cluster_uid=cluster_uid,
            candidate_disposition="confirmed",
            validation_status="validated",
            terminal_transition_level="V0",
            validator_cache_hit=1,
            resume_checkpoint_id="CHECKPOINT_STALE",
            policy_replay_source="RUN_STALE",
        )

    first_issue = persisted_attempt()
    first_state = _state(first_issue)
    runner.run(first_state)
    second_issue = persisted_attempt()
    second_state = _state(second_issue)
    runner.run(second_state)

    assert len(agent.inputs) == 1
    assert second_state["validator_cache_hit"] == 1
    for issue in (first_issue, second_issue):
        assert issue["candidate_disposition"] == "needs_review"
        assert issue["proof_kernel_input_rebuild_status"] == "legacy_or_unknown_candidate"
        assert "proof_kernel_input" not in issue
        assert "proof_kernel_promotion_certificate" not in issue
        assert "terminal_transition_level" not in issue


@pytest.mark.parametrize(
    "mutation",
    (
        "missing_schema",
        "wrong_schema",
        "cross_candidate",
        "cross_occurrence_cluster",
        "wrong_pass",
        "unbound_evidence_ref",
    ),
)
def test_validation_cache_hit_is_reparsed_against_current_exact_input(mutation) -> None:
    runner = _runner(None)
    issue = _issue(
        candidate_uid="CAND_CACHE_CURRENT",
        validation_cluster_uid="VAL_CACHE_CURRENT",
    )
    validator_input = runner._validator_input(
        issue,
        "void sink_func(void) { free(arg); }",
        issue["evidence_pack"],
    )
    value = _validator_v3_result()
    value.update(
        {
            "candidate_uid": "CAND_CACHE_CURRENT",
            "validation_cluster_uid": "VAL_CACHE_CURRENT",
        }
    )
    if mutation == "missing_schema":
        value.pop("schema_version")
    elif mutation == "wrong_schema":
        value["schema_version"] = "zscope.validator-result.v2"
    elif mutation == "cross_candidate":
        value["candidate_uid"] = "CAND_CACHE_OTHER"
    elif mutation == "cross_occurrence_cluster":
        value["validation_cluster_uid"] = "VAL_CACHE_OTHER_OCCURRENCE"
    elif mutation == "wrong_pass":
        value["pass"] = "evidence_recheck"
    else:
        value["evidence_refs"] = ["evidence:outside-current-catalog"]

    runner._validator_result_cache.put("poisoned", value)

    assert runner._validator_cache_get("poisoned", validator_input=validator_input) is None


def test_validation_cache_store_requires_exact_current_input() -> None:
    runner = _runner(None)
    issue = _issue(
        candidate_uid="CAND_CACHE_STORE",
        validation_cluster_uid="VAL_CACHE_STORE",
    )
    validator_input = runner._validator_input(
        issue,
        "void sink_func(void) { free(arg); }",
        issue["evidence_pack"],
    )
    wrong = _validator_v3_result()
    wrong.update(
        {
            "candidate_uid": "CAND_CACHE_OTHER",
            "validation_cluster_uid": "VAL_CACHE_STORE",
        }
    )

    assert (
        runner._validator_cache_put(
            "wrong-current-input",
            wrong,
            validator_input=validator_input,
        )
        is False
    )
    assert runner._validator_cache_get("wrong-current-input") is None


def test_validation_cache_binds_rendered_prompt_and_project_override() -> None:
    def contract(text):
        return lambda context, _agent_name: context.update(
            {
                "agent_contract": text,
                "skill_contracts": "fixed proof skill",
            }
        )

    built_in = _runner(
        None,
        attach_agent_contract=contract("built-in proof engine contract"),
    )
    project_override = _runner(
        None,
        attach_agent_contract=contract("project override proof engine contract"),
    )
    item = SimpleNamespace(
        raw_issue=_issue(candidate_id="CAND_PROMPT_BINDING"),
        issue_func="sink_func",
        issue_code="void sink_func(void) { free(arg); }",
        evidence_pack={"candidate_id": "CAND_PROMPT_BINDING", "path": {"complete": True}},
    )

    assert built_in._validation_prompt_contract["system_prompt"].startswith(
        "built-in proof engine contract"
    )
    assert project_override._validation_prompt_contract["system_prompt"].startswith(
        "project override proof engine contract"
    )
    assert (
        built_in._validation_prompt_contract_sha256
        != project_override._validation_prompt_contract_sha256
    )
    assert built_in._validator_cache_key(item) != project_override._validator_cache_key(item)


def test_validation_cache_binds_actual_response_schema(monkeypatch) -> None:
    from zscope.core.validation import runner as runner_module

    baseline = _runner(None)
    original = runner_module.validator_result_schema_v3

    def revised_schema(**kwargs):
        schema = original(**kwargs)
        return {**schema, "$comment": "proof-schema-revision"}

    monkeypatch.setattr(runner_module, "validator_result_schema_v3", revised_schema)
    revised = _runner(None)
    item = SimpleNamespace(
        raw_issue=_issue(candidate_id="CAND_SCHEMA_BINDING"),
        issue_func="sink_func",
        issue_code="void sink_func(void) { free(arg); }",
        evidence_pack={"candidate_id": "CAND_SCHEMA_BINDING", "path": {"complete": True}},
    )

    assert baseline._validation_prompt_contract_sha256 != revised._validation_prompt_contract_sha256
    assert baseline._validator_cache_key(item) != revised._validator_cache_key(item)


def test_model_trace_uses_per_call_rendered_prompt_and_schema_hash() -> None:
    runner = _runner(None)
    issue = _issue(
        candidate_uid="CAND_TRACE_PROMPT",
        validation_cluster_uid="VAL_TRACE_PROMPT",
    )
    structured_input = runner._validator_input(
        issue,
        "void sink_func(void) { free(arg); }",
        {"path": {"complete": True}},
    )
    captured = {}
    runner._decision_trace_store = SimpleNamespace(
        put_model_event=lambda **kwargs: captured.update(kwargs) or "model_events/fixed.json",
        bound_call_ids=lambda _cluster_uid: (),
        bound_tool_call_ids=lambda _cluster_uid: (),
    )
    runner._trace_event = lambda *_args, **_kwargs: None

    runner._record_model_trace(
        issue,
        stage="V1",
        structured_input=structured_input,
        structured_output={"verdict": "uncertain"},
        usage_start=0,
        reason_code="V1_COMPLETED",
    )

    assert captured["prompt_hash"] == runner._rendered_validation_prompt_schema_sha256(
        structured_input
    )
    assert captured["prompt_hash"] != runner._validation_prompt_contract_sha256


@pytest.mark.parametrize(
    "stop_reason",
    [
        "fact_timeout",
        "malformed_output",
        "output_truncated",
    ],
)
def test_validation_runner_does_not_cache_transient_v3_results(stop_reason) -> None:
    runner = _runner(None)
    value = _validator_v3_result(stop_reason=stop_reason)

    assert runner._validator_cache_put("transient", value) is False
    assert runner._validator_cache_get("transient") is None


def test_zero_sized_validation_cache_is_really_disabled() -> None:
    cache = ValidationResultCache(max_entries=0)

    assert cache.max_entries == 0
    assert not cache.enabled
    assert cache.reserve("same-candidate")
    assert cache.reserve("same-candidate")
    cache.put("same-candidate", {"verdict": "verified"})
    assert cache.get("same-candidate") is None

    runner = _runner(
        None,
        analysis=SimpleNamespace(
            validation_cache_entries=0,
            validation_deadline_seconds=None,
        ),
    )
    assert runner._validator_result_cache_size == 0
    assert not runner._validator_result_cache.enabled
    assert runner._validation_cache_wait_seconds() is None


def test_validation_runner_cache_key_ignores_occurrence_only_entry_context() -> None:
    runner = _runner(None)
    base = _issue(candidate_id="CAND_STABLE", call_path=["api_entry", "sink_func"])
    first = SimpleNamespace(
        raw_issue=base,
        issue_func="sink_func",
        issue_code="void sink_func(void) { free(arg); }",
        evidence_pack={"candidate_id": "CAND_STABLE", "path": {"complete": True}},
    )
    changed_code = SimpleNamespace(
        raw_issue=dict(base),
        issue_func="sink_func",
        issue_code="void sink_func(void) { if (arg) free(arg); }",
        evidence_pack=dict(first.evidence_pack),
    )
    changed_evidence = SimpleNamespace(
        raw_issue=dict(base),
        issue_func="sink_func",
        issue_code=first.issue_code,
        evidence_pack={"candidate_id": "CAND_STABLE", "path": {"complete": False}},
    )
    changed_entry = SimpleNamespace(
        raw_issue={**base, "entry_function": "other_entry"},
        issue_func="sink_func",
        issue_code=first.issue_code,
        evidence_pack=dict(first.evidence_pack),
    )

    keys = {
        runner._validator_cache_key(first),
        runner._validator_cache_key(changed_code),
        runner._validator_cache_key(changed_evidence),
        runner._validator_cache_key(changed_entry),
    }

    assert len(keys) == 3
    assert runner._validator_cache_key(first) == runner._validator_cache_key(changed_entry)


def test_validation_runner_cluster_cache_key_ignores_occurrence_payload() -> None:
    runner = _runner(None)
    first = SimpleNamespace(
        raw_issue=_issue(
            validation_cluster_uid="VAL_SHARED",
            function="wrapper_a",
            location="src/a.c:10",
            source="entry_a_arg",
            sink="shared_sink",
        ),
        issue_func="wrapper_a",
        issue_code="void wrapper_a(void) { shared_sink(); }",
        evidence_pack={"validation_cluster_uid": "VAL_SHARED"},
    )
    second = SimpleNamespace(
        raw_issue=_issue(
            validation_cluster_uid="VAL_SHARED",
            function="wrapper_b",
            location="src/b.c:99",
            source="entry_b_arg",
            sink="shared_sink",
        ),
        issue_func="wrapper_b",
        issue_code="void wrapper_b(void) { shared_sink(); }",
        evidence_pack={"validation_cluster_uid": "VAL_SHARED"},
    )

    assert runner._validator_cache_key(first) == runner._validator_cache_key(second)


def test_validation_runner_selects_one_representative_per_validation_cluster() -> None:
    runner = _runner(None)
    issues = [
        _issue(
            id=f"ISSUE_{index}",
            validation_cluster_uid="VAL_SHARED",
            occurrence_uid=f"OCC_{index}",
            provenance_hash=f"PROV_{index}",
            evidence_hash=f"EVIDENCE_{index}",
            evidence_completeness="complete" if index == 1 else "partial",
        )
        for index in range(4)
    ]

    grouped = runner._coalesce_validation_groups(issues)

    assert len(grouped) == 1
    assert grouped[0]["id"] == "ISSUE_1"
    assert grouped[0]["grouped_candidate_count"] == 4
    assert len(grouped[0]["occurrence_uids"]) == 4
    assert len(grouped[0]["provenance_hashes"]) == 4


def test_validation_runner_coalesces_identical_inflight_work_across_entry_runners() -> None:
    cache = ValidationResultCache(max_entries=16)
    calls = []
    calls_lock = threading.Lock()

    class SlowValidator:
        def run(self, input_data):
            with calls_lock:
                calls.append(threading.current_thread().name)
            time.sleep(0.05)
            return AgentResponse(
                success=True,
                data={
                    "schema_version": "zscope.validator-result.v3",
                    "candidate_uid": input_data["finding_uid"],
                    "validation_cluster_uid": input_data["validation_cluster_uid"],
                    "pass": input_data["validation_pass"],
                    "verdict": "verified",
                    "reasoning": "same immutable evidence",
                    "positive_evidence": ["same immutable evidence"],
                    "negative_evidence": [],
                    "evidence_refs": [],
                    "blocking_negative_evidence": False,
                    "missing_fact_request": None,
                    "stop_reason": "decision_complete",
                },
            )

    first = _runner(SlowValidator(), result_cache=cache)
    second = _runner(SlowValidator(), result_cache=cache)
    first_state = _state(_issue(candidate_uid="CAND_SHARED", validation_cluster_uid="VAL_SHARED"))
    second_state = _state(_issue(candidate_uid="CAND_SHARED", validation_cluster_uid="VAL_SHARED"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(
            pool.map(
                lambda pair: pair[0].run(pair[1]), [(first, first_state), (second, second_state)]
            )
        )

    assert len(calls) == 1
    assert len(first_state["observations"]) == 1
    assert len(second_state["observations"]) == 1
    cache_hits = int(first_state.get("validator_cache_hit", 0)) + int(
        second_state.get("validator_cache_hit", 0)
    )
    assert cache_hits == 1


def test_validation_runner_validates_issue_and_remembers_outcome() -> None:
    memory = []
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data={
                    "verdict": "verified",
                    "reasoning": "reachable public API path",
                    "confidence_score": 1.0,
                    "source": "arg",
                    "sink": "free",
                },
            )
        ]
    )
    state = _state(_issue())

    _runner(agent, memory=memory).run(state)

    assert state["pending_new_issues"] == []
    assert state["issues"] == []
    assert len(state["observations"]) == 1
    assert state["observations"][0]["validation_status"] == "needs_review"
    assert state["observations"][0]["validator_verdict"] == "verified"
    assert state["observations"][0]["model_verdict"] == "verified"
    assert state["observations"][0]["policy_disposition"] == "needs_review"
    assert state["observations"][0]["attribution"]["discovered_by"] == []
    assert state["observations"][0]["attribution"]["decided_by"] == "unresolved"
    assert state["observations"][0]["attribution"]["decision_level"] == "none"
    assert memory == [("ISSUE_1", "needs_review")]
    assert agent.inputs[0]["agent_contract"] == "proof_engine"


def test_validation_runner_v2_recheck_sees_all_required_typed_fact_deltas_once() -> None:
    request = {
        "fact_kind": "source_controllability",
        "subject_uid": "wire_len",
        "function_uid": "sink_func",
        "reason": "the exposed entry contract is missing",
    }
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data=_validator_v3_result(
                    missing_fact_request=request,
                    stop_reason="missing_fact",
                ),
            ),
            AgentResponse(
                success=True,
                data=_validator_v3_result(
                    verdict="verified",
                    validation_pass="evidence_recheck",
                ),
            ),
        ]
    )
    issue = _issue(
        candidate_uid="CAND_V3",
        validation_cluster_uid="VAL_V3",
        severity="medium",
        impact_level="medium",
        reachable_from_entry=True,
        entry_context={"entry_is_external_root": True},
        function_ir_graph=_function_ir_graph(),
        source={"callee": "read_input", "line": 5},
        sink={"callee": "sink", "line": 10},
        security_obligation={
            "obligation_uid": "OBL_RANGE",
            "subject_uid": "wire_len",
            "decision_region_uid": "REGION_PATH",
            "required_fact_kinds": ["source_sink_reachability"],
        },
        obligation_required_fact_kinds=["source_sink_reachability"],
        missing_fact_kinds=["source_sink_reachability"],
    )
    state = _state(issue)

    _runner(agent, scan=SimpleNamespace(depth="balanced")).run(state)

    assert len(agent.inputs) == 2
    assert agent.inputs[1]["validation_pass"] == "evidence_recheck"
    delta = agent.inputs[1]["evidence_slice"]["evidence_delta"]
    assert delta["fact_kinds"] == ["source_controllability"]
    assert delta["facts"][0]["verification_certificate"]["schema_version"] == (
        "zscope.evidence-certificate.v2"
    )
    v1_fact_kinds = {
        fact["fact_kind"] for fact in agent.inputs[0]["evidence_slice"]["decision_facts"]["facts"]
    }
    assert "source_sink_reachability" not in v1_fact_kinds
    assert issue["proof_kernel_fact_first"]["decision_fact_slice"]["facts"]
    assert issue["proof_kernel_mode"] == "authoritative"
    assert issue["validator_fact_resolution"]["status"] == "completed_partial"
    assert issue["validator_pass_history"][-1]["pass"] == "evidence_recheck"
    assert issue["evidence_completion_attempt_count"] == 1


def test_validation_runner_does_not_recheck_without_evidence_delta() -> None:
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data=_validator_v3_result(
                    missing_fact_request={
                        "fact_kind": "value_range",
                        "subject_uid": "wire_len",
                        "function_uid": "sink_func",
                        "reason": "the caller bound is missing",
                    },
                    stop_reason="missing_fact",
                ),
            )
        ]
    )
    issue = _issue(candidate_uid="CAND_V3", validation_cluster_uid="VAL_V3")
    state = _state(issue)

    _runner(agent).run(state)

    assert len(agent.inputs) == 1
    assert issue["validator_fact_resolution"]["status"] == "exhausted"
    assert issue["validator_stop_reason"] == "missing_fact"
    assert issue["validator_v2_stop_reason"] == "no_evidence_gain"


def test_v2_exact_parameterized_duplicate_is_zero_provider_and_model_calls(monkeypatch) -> None:
    agent = FakeValidatorAgent([])
    runner = _runner(agent)
    issue = _issue(candidate_uid="CAND_V3", validation_cluster_uid="VAL_V3")
    issue["validator_evidence_snapshot_sha256_by_pass"] = {"initial": "a" * 64}
    item = SimpleNamespace(
        raw_issue=issue,
        issue_func="sink_func",
        issue_code="void sink_func(void) {}",
        evidence_pack={"path": {"complete": True}},
    )
    request = {
        "fact_kind": "value_range",
        "subject_uid": "wire_len",
        "function_uid": "sink_func",
        "reason": "a bound is required",
    }
    val_data = _validator_v3_result(
        missing_fact_request=request,
        stop_reason="missing_fact",
    )
    provider_calls = []

    def resolve(*_args, **_kwargs):
        provider_calls.append(1)
        return SimpleNamespace(
            resolutions=[
                SimpleNamespace(
                    fact_kind="value_range",
                    terminal_status="no_match",
                    status="no_match",
                    miss_reason="no qualified local fact",
                )
            ],
            evidence_delta={},
            evidence_delta_hash="",
            proof_added=False,
            has_evidence_delta=False,
        )

    monkeypatch.setattr(runner._evidence_completion_queue, "resolve_required_facts", resolve)

    runner._run_v3_evidence_recheck(item, agent, val_data, {})
    runner._run_v3_evidence_recheck(item, agent, val_data, {})

    assert len(provider_calls) == 1
    assert agent.inputs == []
    assert issue["validator_fact_resolution"]["status"] == "exact_duplicate_request"
    assert len(issue["validator_fact_request_attempts"]) == 1


def test_v2_no_match_does_not_exhaust_refined_same_kind_request(monkeypatch) -> None:
    agent = FakeValidatorAgent([])
    runner = _runner(agent)
    issue = _issue(candidate_uid="CAND_V3", validation_cluster_uid="VAL_V3")
    issue["validator_evidence_snapshot_sha256_by_pass"] = {"initial": "a" * 64}
    item = SimpleNamespace(
        raw_issue=issue,
        issue_func="sink_func",
        issue_code="void sink_func(void) {}",
        evidence_pack={"path": {"complete": True}},
    )
    provider_calls = []

    def resolve(*_args, **_kwargs):
        provider_calls.append(1)
        return SimpleNamespace(
            resolutions=[
                SimpleNamespace(
                    fact_kind="value_range",
                    terminal_status="no_match",
                    status="no_match",
                    miss_reason="no qualified local fact",
                )
            ],
            evidence_delta={},
            evidence_delta_hash="",
            proof_added=False,
            has_evidence_delta=False,
        )

    monkeypatch.setattr(runner._evidence_completion_queue, "resolve_required_facts", resolve)
    first = _validator_v3_result(
        missing_fact_request={
            "fact_kind": "value_range",
            "subject_uid": "wire_len",
            "function_uid": "sink_func",
            "reason": "the first bound is required",
        },
        stop_reason="missing_fact",
    )
    refined = _validator_v3_result(
        missing_fact_request={
            "fact_kind": "value_range",
            "subject_uid": "payload_len",
            "function_uid": "sink_func",
            "reason": "a refined object bound is required",
        },
        stop_reason="missing_fact",
    )

    runner._run_v3_evidence_recheck(item, agent, first, {})
    runner._run_v3_evidence_recheck(item, agent, refined, {})

    assert len(provider_calls) == 2
    assert agent.inputs == []
    attempts = issue["validator_fact_request_attempts"]
    assert len(attempts) == 2
    assert {entry["subject_uid"] for entry in attempts} == {"wire_len", "payload_len"}
    assert {entry["status"] for entry in attempts} == {"no_match"}


def test_v2_same_scope_rechecks_after_real_fact_delta_then_exact_duplicate_is_zero_call() -> None:
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data=_validator_v3_result(
                    verdict="uncertain",
                    validation_pass="evidence_recheck",
                    stop_reason="missing_fact",
                ),
            )
        ]
    )
    runner = _runner(agent, scan=SimpleNamespace(depth="balanced"))
    issue = _issue(
        candidate_uid="CAND_V3",
        validation_cluster_uid="VAL_V3",
        severity="medium",
        impact_level="medium",
        reachable_from_entry=True,
        entry_context={"entry_is_external_root": True},
        function_ir_graph=_function_ir_graph(),
        source={"callee": "read_input", "line": 5},
        sink={"callee": "sink", "line": 10},
        security_obligation={
            "obligation_uid": "OBL_RANGE",
            "subject_uid": "wire_len",
            "decision_region_uid": "REGION_PATH",
            "required_fact_kinds": ["source_controllability"],
        },
        obligation_required_fact_kinds=["source_controllability"],
        missing_fact_kinds=["source_controllability"],
    )
    item = SimpleNamespace(
        raw_issue=issue,
        issue_func="sink_func",
        issue_code="void sink_func(void) {}",
        evidence_pack={},
    )
    request = _validator_v3_result(
        missing_fact_request={
            "fact_kind": "source_controllability",
            "subject_uid": "wire_len",
            "function_uid": "sink_func",
            "reason": "the externally controlled source fact is required",
        },
        stop_reason="missing_fact",
    )
    runner._validator_input(issue, item.issue_code, item.evidence_pack)
    _, before = runner._v2_request_identity(item, request["missing_fact_request"])

    runner._run_v3_evidence_recheck(item, agent, request, {})
    _, after_delta = runner._v2_request_identity(item, request["missing_fact_request"])
    assert after_delta["evidence_snapshot_sha256"] != before["evidence_snapshot_sha256"]
    assert issue["decision_fact_slice"]["facts"]

    # The changed material snapshot authorizes one bounded provider recheck.
    # It returns the same fact delta, so it must not trigger another model call.
    runner._run_v3_evidence_recheck(item, agent, request, {})
    _, after_duplicate_delta = runner._v2_request_identity(item, request["missing_fact_request"])
    assert after_duplicate_delta == after_delta

    # With neither a new fact nor a new re-entry, the exact third request is
    # rejected before the deterministic provider and the model.
    provider_attempts = issue["evidence_completion_attempt_count"]
    runner._run_v3_evidence_recheck(item, agent, request, {})

    assert issue["evidence_completion_attempt_count"] == provider_attempts == 2
    assert len(issue["validator_fact_request_attempts"]) == 2
    assert len(agent.inputs) == 1
    assert len(issue.get("evidence_completion_request_hashes") or []) <= 1


def test_v2_fact_first_exact_scope_is_zero_call_but_each_refinement_runs(monkeypatch) -> None:
    agent = FakeValidatorAgent([])
    runner = _runner(agent)
    issue = _issue(
        candidate_uid="CAND_FACT_FIRST",
        validation_cluster_uid="VAL_FACT_FIRST",
        function="entry",
    )
    issue["validator_evidence_snapshot_sha256_by_pass"] = {"initial": "a" * 64}
    issue["proof_kernel_fact_first"] = {
        "status": "exhausted",
        "attempted_fact_kinds": ["caller_contract"],
        "parameterized_request_scopes": [
            {
                "fact_kind": "caller_contract",
                "subject_uid": "entry",
                "function_uid": "entry",
                "fixed_parameters": [],
            }
        ],
    }
    item = SimpleNamespace(
        raw_issue=issue,
        issue_func="entry",
        issue_code="void entry(void) {}",
        evidence_pack={},
    )
    provider_calls = []

    def resolve(*_args, **_kwargs):
        provider_calls.append(1)
        return SimpleNamespace(
            resolutions=[
                SimpleNamespace(
                    fact_kind="caller_contract",
                    terminal_status="no_match",
                    status="no_match",
                    miss_reason="no qualified closed-world contract",
                )
            ],
            evidence_delta={},
            evidence_delta_hash="",
            proof_added=False,
            has_evidence_delta=False,
        )

    monkeypatch.setattr(runner._evidence_completion_queue, "resolve_required_facts", resolve)

    def request(
        *,
        subject: str = "entry",
        function: str = "entry",
        fixed_parameters=None,
    ):
        missing = {
            "fact_kind": "caller_contract",
            "subject_uid": subject,
            "function_uid": function,
            "reason": "the caller contract is missing",
        }
        if fixed_parameters is not None:
            missing["fixed_parameters"] = fixed_parameters
        return _validator_v3_result(
            missing_fact_request=missing,
            stop_reason="missing_fact",
        )

    runner._run_v3_evidence_recheck(item, agent, request(), {})
    assert provider_calls == []
    assert issue["validator_fact_resolution"]["status"] == ("no_new_parameterized_request")

    runner._run_v3_evidence_recheck(item, agent, request(subject="other"), {})
    runner._run_v3_evidence_recheck(item, agent, request(function="other"), {})
    runner._run_v3_evidence_recheck(
        item,
        agent,
        request(fixed_parameters={"contract_scope": "closed_world"}),
        {},
    )
    issue["validator_evidence_snapshot_sha256_by_pass"]["initial"] = "b" * 64
    runner._run_v3_evidence_recheck(item, agent, request(), {})

    # Mutating the historical V1 snapshot is not a material evidence delta.
    # Only the three genuinely refined scopes may reach the provider.
    assert len(provider_calls) == 3
    assert len(issue["validator_fact_request_attempts"]) == 4
    assert issue["validator_evidence_snapshot_sha256_by_pass"]["v2_initial_snapshot_drift"] is True
    assert agent.inputs == []


def test_validation_runner_maps_fact_provider_timeout_to_canonical_stop(monkeypatch) -> None:
    request = {
        "fact_kind": "value_range",
        "subject_uid": "wire_len",
        "function_uid": "sink_func",
        "reason": "the caller bound is missing",
    }
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data=_validator_v3_result(
                    missing_fact_request=request,
                    stop_reason="missing_fact",
                ),
            )
        ]
    )
    runner = _runner(agent)
    runner._evidence_completion_queue.fact_timeout_seconds = 0.01

    def slow_provider(*_args):
        time.sleep(0.05)
        return []

    monkeypatch.setattr(
        runner._evidence_completion_queue,
        "_requested_completion_proofs",
        slow_provider,
    )
    issue = _issue(candidate_uid="CAND_V3", validation_cluster_uid="VAL_V3")
    state = _state(issue)

    runner.run(state)

    assert state["validation_queue_drained"] is True
    assert issue["validator_fact_resolution"]["status"] == "timeout"
    assert issue["validator_stop_reason"] == "missing_fact"
    assert issue["validator_v2_stop_reason"] == "fact_timeout"
    assert issue["candidate_disposition"] == "needs_review"


def test_v3_terminal_authority_skips_post_terminal_provider_and_model_calls(monkeypatch) -> None:
    agent = FakeValidatorAgent([])
    runner = _runner(agent)
    issue = _closed_v4_issue(candidate_uid="CAND_V3", validation_cluster_uid="VAL_V3")
    _trust_test_producer_occurrence_binding(monkeypatch, issue)
    item = SimpleNamespace(
        raw_issue=issue,
        issue_func="sink_func",
        issue_code="void sink_func(void) {}",
        evidence_pack={},
    )
    monkeypatch.setattr(
        runner._evidence_completion_queue,
        "resolve_required_facts",
        lambda *_args, **_kwargs: pytest.fail("provider ran after terminal authority"),
    )
    prior = _validator_v3_result(
        missing_fact_request={
            "fact_kind": "value_range",
            "subject_uid": "wire_len",
            "function_uid": "sink_func",
            "reason": "must not execute after terminal",
        },
        validation_pass="investigation_synthesis",
        stop_reason="missing_fact",
    )

    revised = runner._reconcile_v3_missing_fact(item, agent, prior, {})

    assert agent.inputs == []
    assert revised["stop_reason"] == "decision_complete"
    assert issue["terminal_transition_level"] == "V3"
    assert issue["validator_v3_post_resolution"]["status"] == "skipped_terminal_authority"


@pytest.mark.parametrize("bad_response", ("failure", "malformed"))
def test_v3_persists_programmatic_closure_even_when_response_is_bad(
    tmp_path,
    monkeypatch,
    bad_response: str,
) -> None:
    issue = _executable_path_issue(
        candidate_uid="CAND_V3_PENDING",
        validation_cluster_uid="VAL_V3_PENDING",
        severity="high",
        reachable_from_entry=True,
    )
    _trust_test_producer_occurrence_binding(monkeypatch, issue)

    class ClosingThenBadValidator(FakeValidatorAgent):
        def __init__(self):
            super().__init__([AgentResponse(success=True, data=_validator_v3_result())])

        def investigate(
            self,
            _input_data,
            *,
            max_iterations=50,
            evidence_actions=None,
            evidence_action_executor=None,
        ):
            assert max_iterations == 50
            closed = _closed_v4_issue(
                candidate_uid="CAND_V3_PENDING",
                validation_cluster_uid="VAL_V3_PENDING",
            )
            issue.update(
                {key: value for key, value in closed.items() if key.startswith("proof_kernel_")}
            )
            actions = evidence_actions
            assert callable(evidence_action_executor)
            outcome = evidence_action_executor(actions[0]["action_id"])
            assert outcome["reason_code"] == "terminal_authority_already_closed"
            if bad_response == "failure":
                return AgentResponse(success=False, data={}, error="fixed failure")
            return AgentResponse(success=True, data={"schema_version": "invalid"})

    runner = _runner(ClosingThenBadValidator(), scan=SimpleNamespace(depth="balanced"))
    runner._decision_trace_store = DecisionTraceStore(tmp_path)

    runner.run(_state(issue))

    assert issue["candidate_disposition"] == "confirmed"
    assert issue["terminal_transition_level"] == "V3"
    trace = runner._decision_trace_store.trace("VAL_V3_PENDING")
    stages = [event["stage"] for event in trace["events"]]
    transition_index = next(
        index
        for index, event in enumerate(trace["events"])
        if event["event_uid"] == issue["terminal_transition_event_uid"]
    )
    assert stages[transition_index] == "policy"
    assert any(event["stage"] == "V3" for event in trace["events"][:transition_index])
    assert all(event["stage"] == "report" for event in trace["events"][transition_index + 1 :])


def test_v3_rejects_a_second_action_after_programmatic_closure(tmp_path, monkeypatch) -> None:
    issue = _executable_path_issue(
        candidate_uid="CAND_V3_POST_PROOF",
        validation_cluster_uid="VAL_V3_POST_PROOF",
        severity="high",
        reachable_from_entry=True,
    )
    _trust_test_producer_occurrence_binding(monkeypatch, issue)

    class PostProofValidator(FakeValidatorAgent):
        def __init__(self):
            super().__init__([AgentResponse(success=True, data=_validator_v3_result())])

        def investigate(
            self,
            _input_data,
            *,
            max_iterations=50,
            evidence_actions=None,
            evidence_action_executor=None,
        ):
            assert max_iterations == 50
            closed = _closed_v4_issue(
                candidate_uid="CAND_V3_POST_PROOF",
                validation_cluster_uid="VAL_V3_POST_PROOF",
            )
            issue.update(
                {key: value for key, value in closed.items() if key.startswith("proof_kernel_")}
            )
            assert callable(evidence_action_executor)
            first = evidence_action_executor(evidence_actions[0]["action_id"])
            second = evidence_action_executor(evidence_actions[0]["action_id"])
            assert first["reason_code"] == "terminal_authority_already_closed"
            assert second["reason_code"] == "post_terminal_action_forbidden"
            return AgentResponse(
                success=True,
                data=_validator_v3_result(validation_pass="investigation_synthesis"),
            )

    runner = _runner(PostProofValidator(), scan=SimpleNamespace(depth="balanced"))
    runner._decision_trace_store = DecisionTraceStore(tmp_path)

    with pytest.raises(DecisionTraceError, match="post_proof_call_detected"):
        runner.run(_state(issue))

    assert not issue.get("terminal_transition_event_uid")


def test_v3_reenters_the_original_composite_obligation_and_closes_at_v3(monkeypatch) -> None:
    graph = _function_ir_graph(duplicate_sink=True, as_object=True)
    proof_ir = program_proof_ir_from_graph(
        graph,
        project_uid="PROJECT_RUNNER_REENTRY",
        revision_uid="REV_RUNNER_REENTRY",
    )
    spec = PREDICATE_REGISTRY["source_sink_path_exists"]
    clauses = tuple(
        build_proof_clause(
            role="confirmation",
            provider_family=spec.provider_family,
            predicate_id=spec.predicate_id,
            fact_kind=spec.fact_kind,
            quantifier=spec.quantifier,
            expected_value={"path_exists": True},
            parameters={"source_node_uid": "B3", "sink_node_uid": sink},
        )
        for sink in ("B2", "B1")
    )
    obligation = build_proof_obligation(
        validation_cluster_uid="VAL_V3_REENTRY",
        defect_family="dataflow",
        subject_uid="wire_len",
        decision_region_uid="REGION_V3_REENTRY",
        confirmation_clauses=clauses,
        counterproof_clauses=(),
        dependency_hashes=proof_ir["dependency_hashes"],
    )
    engine = ProofKernelEngine()
    catalog = engine.action_catalog(proof_ir=proof_ir, obligation=obligation)
    issue = _issue(
        validation_cluster_uid="VAL_V3_REENTRY",
        proof_kernel_input={
            "schema_version": PROOF_KERNEL_AUTHORITY_INPUT_VERSION,
            "proof_ir": proof_ir,
            "proof_obligation": obligation,
            "selected_action_uids": [catalog[0]["action_uid"]],
        },
    )
    runner = _runner(FakeValidatorAgent([]))

    runner._reverify_attached_proof_kernel_input(issue)
    _trust_test_producer_occurrence_binding(monkeypatch, issue)

    item = SimpleNamespace(
        raw_issue=issue,
        issue_func="sink_func",
        issue_code="void sink_func(void) {}",
        evidence_pack={},
    )
    snapshot_request = {
        "fact_kind": str(catalog[1]["fact_kind"]),
        "subject_uid": str(catalog[1]["subject_uid"]),
        "function_uid": "sink_func",
        "fixed_parameters": dict(catalog[1]["fixed_parameters"]),
    }
    runner._validator_input(issue, item.issue_code, item.evidence_pack)
    _, identity_before_reentry = runner._v2_request_identity(item, snapshot_request)

    assert issue["proof_kernel_closure_evaluation"]["complete"] is False
    assert "proof_kernel_promotion_certificate" not in issue
    fact_action = EvidenceAction(
        action_id="FACT_ACTION_V3",
        fact_kind=str(catalog[1]["fact_kind"]),
        provider_id=str(catalog[1]["provider_id"]),
        verifier_id=str(catalog[1]["verifier_id"]),
        subject_uid=str(catalog[1]["subject_uid"]),
        decision_region_uid=str(catalog[1]["decision_region_uid"]),
        fixed_parameters=dict(catalog[1]["fixed_parameters"]),
        description="exact frozen action mapping",
    )
    frozen_action_uid = runner._matching_frozen_proof_action_uid(issue, fact_action)

    assert frozen_action_uid == catalog[1]["action_uid"]
    assert runner._reenter_frozen_proof_obligation(
        issue,
        action_uid=frozen_action_uid,
    )
    _, identity_after_reentry = runner._v2_request_identity(item, snapshot_request)
    authority = runner._terminal_authority.evaluate(issue, operation="live")
    runner._mark_terminal_transition(issue, "V3", authority)

    assert authority.disposition == "confirmed"
    assert issue["terminal_transition_level"] == "V3"
    assert issue["proof_kernel_v3_reentry_status"] == "reduced_original_obligation"
    assert issue["proof_kernel_frozen_state"]["obligation_uid"] == obligation["obligation_uid"]
    assert issue["proof_kernel_frozen_state"]["proof_ir_uid"] == proof_ir["proof_ir_uid"]
    assert issue["proof_kernel_input"]["selected_action_uids"] == [
        catalog[0]["action_uid"],
        catalog[1]["action_uid"],
    ]
    assert issue["proof_kernel_live_selected_action_uids"] == [
        catalog[0]["action_uid"],
        catalog[1]["action_uid"],
    ]
    assert (
        identity_after_reentry["evidence_snapshot_sha256"]
        != identity_before_reentry["evidence_snapshot_sha256"]
    )
    assert issue["proof_kernel_terminal_authority_decision"]["schema_version"] == (
        "zscope.terminal-authority-decision.v4"
    )


def test_v2_fact_reenters_the_same_frozen_obligation_before_terminal_authority(
    monkeypatch,
) -> None:
    graph = _function_ir_graph(duplicate_sink=True, as_object=True)
    proof_ir = program_proof_ir_from_graph(
        graph,
        project_uid="PROJECT_RUNNER_V2_REENTRY",
        revision_uid="REV_RUNNER_V2_REENTRY",
    )
    spec = PREDICATE_REGISTRY["source_sink_path_exists"]
    clauses = tuple(
        build_proof_clause(
            role="confirmation",
            provider_family=spec.provider_family,
            predicate_id=spec.predicate_id,
            fact_kind=spec.fact_kind,
            quantifier=spec.quantifier,
            expected_value={"path_exists": True},
            parameters={"source_node_uid": "B3", "sink_node_uid": sink},
        )
        for sink in ("B2", "B1")
    )
    obligation = build_proof_obligation(
        validation_cluster_uid="VAL_V2_REENTRY",
        defect_family="dataflow",
        subject_uid="wire_len",
        decision_region_uid="REGION_V2_REENTRY",
        confirmation_clauses=clauses,
        counterproof_clauses=(),
        dependency_hashes=proof_ir["dependency_hashes"],
    )
    engine = ProofKernelEngine()
    catalog = engine.action_catalog(proof_ir=proof_ir, obligation=obligation)
    issue = _issue(
        candidate_uid="CAND_V2_REENTRY",
        validation_cluster_uid="VAL_V2_REENTRY",
        proof_kernel_input={
            "schema_version": PROOF_KERNEL_AUTHORITY_INPUT_VERSION,
            "proof_ir": proof_ir,
            "proof_obligation": obligation,
            "selected_action_uids": [catalog[0]["action_uid"]],
        },
    )
    runner = _runner(FakeValidatorAgent([]))
    runner._reverify_attached_proof_kernel_input(issue)
    _trust_test_producer_occurrence_binding(monkeypatch, issue)
    item = SimpleNamespace(
        raw_issue=issue,
        issue_func="sink_func",
        issue_code="void sink_func(void) {}",
        evidence_pack={},
    )
    resolved = SimpleNamespace(
        fact_kind=str(catalog[1]["fact_kind"]),
        terminal_status="resolved",
        status="completed_partial",
        miss_reason="",
    )
    batch = SimpleNamespace(
        resolutions=[resolved],
        evidence_delta={
            "fact_kinds": [str(catalog[1]["fact_kind"])],
            "facts": [
                {
                    "fact_uid": "FACT_V2_REENTRY",
                    "fact_kind": str(catalog[1]["fact_kind"]),
                    "certificate_authoritative": True,
                    "satisfies_fact_kinds": [str(catalog[1]["fact_kind"])],
                }
            ],
        },
        evidence_delta_hash="d" * 64,
        proof_added=False,
        has_evidence_delta=True,
    )
    monkeypatch.setattr(
        runner._evidence_completion_queue,
        "resolve_required_facts",
        lambda *_args, **_kwargs: batch,
    )
    request = _validator_v3_result(
        missing_fact_request={
            "fact_kind": str(catalog[1]["fact_kind"]),
            "subject_uid": str(catalog[1]["subject_uid"]),
            "function_uid": "sink_func",
            "fixed_parameters": dict(catalog[1]["fixed_parameters"]),
            "reason": "close the remaining exact path clause",
        },
        stop_reason="missing_fact",
    )

    result = runner._run_v3_evidence_recheck(item, FakeValidatorAgent([]), request, {})

    assert result["stop_reason"] == "decision_complete"
    assert issue["proof_kernel_v2_reentry_status"] == "reduced_original_obligation"
    assert issue["proof_kernel_frozen_state"]["obligation_uid"] == obligation["obligation_uid"]
    assert issue["proof_kernel_live_selected_action_uids"] == [
        catalog[0]["action_uid"],
        catalog[1]["action_uid"],
    ]
    assert issue["proof_kernel_closure_evaluation"]["complete"] is True
    assert issue["terminal_transition_level"] == "V2"


def test_untrusted_explicit_v4_input_is_cleared_and_remains_needs_review() -> None:
    graph = _function_ir_graph(duplicate_sink=True, as_object=True)
    proof_ir = program_proof_ir_from_graph(
        graph,
        project_uid="PROJECT_AUDIT_CLASSIFICATION",
        revision_uid="REV_AUDIT_CLASSIFICATION",
    )
    spec = PREDICATE_REGISTRY["source_sink_path_exists"]
    clauses = tuple(
        build_proof_clause(
            role="confirmation",
            provider_family=spec.provider_family,
            predicate_id=spec.predicate_id,
            fact_kind=spec.fact_kind,
            quantifier=spec.quantifier,
            expected_value={"path_exists": True},
            parameters={"source_node_uid": "B3", "sink_node_uid": sink},
        )
        for sink in ("B2", "B1")
    )
    obligation = build_proof_obligation(
        validation_cluster_uid="VAL_AUDIT_CLASSIFICATION",
        defect_family="dataflow",
        subject_uid="wire_len",
        decision_region_uid="REGION_AUDIT_CLASSIFICATION",
        confirmation_clauses=clauses,
        counterproof_clauses=(),
        dependency_hashes=proof_ir["dependency_hashes"],
    )
    catalog = ProofKernelEngine().action_catalog(proof_ir=proof_ir, obligation=obligation)

    class Ledger:
        def __init__(self):
            self.terminal = []

        def mark_validation_running(self, _issue):
            return None

        def mark_issue_terminal(self, terminal_issue, *, disposition, status):
            self.terminal.append((terminal_issue, disposition, status))

    ledger = Ledger()
    issue = _issue(
        location="",
        file="",
        line=None,
        source_identity="wire_len",
        candidate_source="llm",
        proof_kernel_input={
            "schema_version": PROOF_KERNEL_AUTHORITY_INPUT_VERSION,
            "proof_ir": proof_ir,
            "proof_obligation": obligation,
            "selected_action_uids": [catalog[0]["action_uid"]],
        },
    )
    state = _state(issue)
    state["candidate_ledger"] = ledger

    _runner(FakeValidatorAgent([AgentResponse(success=True, data=_validator_v3_result())])).run(
        state
    )

    assert issue["candidate_disposition"] == "needs_review"
    assert issue["validation_status"] == "needs_review"
    assert issue["proof_kernel_input_rebuild_status"] == "legacy_or_unknown_candidate"
    assert "proof_kernel_input" not in issue
    assert "audit_eligibility" not in issue
    assert state["observations"] == [issue]
    assert state.get("audit_observations", []) == []
    assert ledger.terminal == [(issue, "needs_review", "needs_review")]


def test_legacy_review_without_v4_envelope_remains_canonical_needs_review() -> None:
    issue = _issue(candidate_disposition="needs_review", validation_status="needs_review")
    state = _state(issue)
    outcome = SimpleNamespace(
        report_bucket="observations",
        memory_status="needs_review",
        verdict="needs_review",
        final_score=0.0,
    )

    classified = _runner(None)._classify_final_needs_review(state, issue, outcome)

    assert classified is outcome
    assert issue["candidate_disposition"] == "needs_review"
    assert "audit_eligibility" not in issue


@pytest.mark.parametrize(
    "proof_fields",
    [
        {},
        {
            "proof_kernel_frozen_state": "malformed",
            "proof_kernel_closure_evaluation": [],
        },
    ],
    ids=("missing-v4", "invalid-v4"),
)
def test_p6_review_without_valid_v4_envelope_becomes_audit_only(proof_fields) -> None:
    issue = _issue(
        candidate_disposition="needs_review",
        validation_status="needs_review",
        **proof_fields,
    )
    state = _state(issue)
    outcome = SimpleNamespace(
        report_bucket="observations",
        memory_status="needs_review",
        verdict="needs_review",
        final_score=0.0,
    )
    runner = _runner(None)
    ledger = ScanTokenUsageLedger(depth="balanced")
    ledger.enable_p6_balanced_admission()
    runner.config.scan_token_usage_ledger = ledger

    classified = runner._classify_final_needs_review(state, issue, outcome)

    assert classified.report_bucket is None
    assert classified.memory_status is None
    assert classified.verdict == "uncertain"
    assert issue["candidate_disposition"] == "shadow_observation"
    assert issue["validation_status"] == "uncertain"
    assert issue["audit_status"] == "audit_only"
    assert issue["audit_eligibility"]["needs_review_eligible"] is False
    assert "AUDIT_QUALIFICATION_BACKED_MISSING" in issue["audit_reason_codes"]
    assert state["observations"] == []
    assert state["audit_observations"] == [issue]
    assert state["audit_observation_count"] == 1


def test_validator_attribution_uses_actual_terminal_transition_level() -> None:
    issue = _issue(
        candidate_disposition="confirmed",
        terminal_transition_level="V3",
        terminal_authority_decision={
            "terminal": True,
            "authority": "zscope.proof-checker",
        },
    )
    outcome = SimpleNamespace(memory_status="validated")

    ValidationRunner._record_validator_attribution(
        issue,
        _validator_v3_result(
            verdict="verified",
            validation_pass="investigation_synthesis",
        ),
        outcome,
    )

    assert issue["attribution"]["decision_level"] == "V3"
    assert issue["validator_policy_outcome"]["decision_level"] == "V3"


def test_balanced_runs_long_v3_for_high_risk_external_candidate() -> None:
    class InvestigatingValidator(FakeValidatorAgent):
        def __init__(self):
            super().__init__(
                [
                    AgentResponse(
                        success=True,
                        data=_validator_v3_result(),
                    ),
                ]
            )
            self.investigations = []

        def investigate(
            self,
            input_data,
            *,
            max_iterations=50,
            evidence_actions=None,
            evidence_action_executor=None,
        ):
            self.investigations.append(
                (
                    input_data,
                    {
                        "max_iterations": max_iterations,
                        "evidence_actions": evidence_actions,
                        "evidence_action_executor": evidence_action_executor,
                    },
                )
            )
            return AgentResponse(
                success=True,
                data=_validator_v3_result(
                    verdict="verified",
                    validation_pass="investigation_synthesis",
                    stop_reason="investigation_complete",
                ),
            )

    agent = InvestigatingValidator()
    issue = _executable_path_issue(
        candidate_uid="CAND_V3",
        validation_cluster_uid="VAL_V3",
        severity="high",
        reachable_from_entry=True,
    )
    state = _state(issue)

    _runner(agent, scan=SimpleNamespace(depth="balanced")).run(state)

    assert len(agent.investigations) == 1
    kwargs = agent.investigations[0][1]
    assert kwargs["max_iterations"] == 50
    assert len(kwargs["evidence_actions"]) == 2
    assert callable(kwargs["evidence_action_executor"])
    assert issue["validator_pass_history"][-1]["pass"] == "investigation_synthesis"
    assert issue["attribution"]["decision_level"] == "none"
    assert issue["validator_policy_outcome"]["attempt_level"] == "V3"
    assert issue["validator_policy_outcome"]["terminal_transition_level"] == ""


def test_v3_rejects_another_action_after_its_clause_was_closed() -> None:
    class InvestigatingValidator(FakeValidatorAgent):
        def __init__(self):
            super().__init__([AgentResponse(success=True, data=_validator_v3_result())])
            self.action_results = []

        def investigate(
            self,
            _input_data,
            *,
            max_iterations=50,
            evidence_actions=None,
            evidence_action_executor=None,
        ):
            assert max_iterations == 50
            actions = evidence_actions
            execute = evidence_action_executor
            assert callable(execute)
            assert len(actions) == 2
            self.action_results.append(execute(actions[0]["action_id"]))
            self.action_results.append(execute(actions[1]["action_id"]))
            return AgentResponse(
                success=True,
                data=_validator_v3_result(
                    validation_pass="investigation_synthesis",
                    stop_reason="investigation_exhausted",
                ),
            )

    agent = InvestigatingValidator()
    issue = _executable_path_issue(
        candidate_uid="CAND_V3",
        validation_cluster_uid="VAL_V3",
        severity="high",
        reachable_from_entry=True,
    )

    _runner(agent, scan=SimpleNamespace(depth="balanced")).run(_state(issue))

    assert agent.action_results[0]["status"] == "verified_true"
    assert agent.action_results[0]["newly_accepted"] is True
    assert agent.action_results[1]["status"] == "unknown"
    assert agent.action_results[1]["reason_code"] == "evidence_action_clause_already_closed"


def test_balanced_does_not_run_v3_when_no_executable_certificate_provider_exists() -> None:
    class InvestigatingValidator(FakeValidatorAgent):
        def __init__(self):
            super().__init__([AgentResponse(success=True, data=_validator_v3_result())])
            self.calls = []

        def investigate(self, input_data, **kwargs):
            self.calls.append((input_data, kwargs))
            return AgentResponse(
                success=True,
                data=_validator_v3_result(
                    validation_pass="investigation_synthesis",
                    stop_reason="investigation_exhausted",
                ),
            )

    agent = InvestigatingValidator()
    state = _state(
        _issue(
            candidate_uid="CAND_V3",
            validation_cluster_uid="VAL_V3",
            severity="critical",
            reachable_from_entry=True,
            evidence_pack={"path": {"complete": False, "complete_to_entry": False}},
            security_obligation={
                "obligation_uid": "OBL_CALLER",
                "subject_uid": "sink_func",
                "required_fact_kinds": ["caller_contract"],
            },
            obligation_required_fact_kinds=["caller_contract"],
            missing_fact_kinds=["caller_contract"],
        )
    )

    _runner(agent, scan=SimpleNamespace(depth="balanced")).run(state)

    assert agent.calls == []
    issue = state["observations"][0]
    assert issue["validator_v3_eligibility"]["reason"] == "no_readonly_closable_gap"
    assert [entry["pass"] for entry in issue["validator_pass_history"]] == ["initial"]


def test_balanced_does_not_run_v3_for_medium_risk_candidate() -> None:
    class InvestigatingValidator(FakeValidatorAgent):
        def __init__(self):
            super().__init__([AgentResponse(success=True, data=_validator_v3_result())])
            self.called = False

        def investigate(self, input_data, **kwargs):
            self.called = True
            raise AssertionError("medium-risk candidate must not enter V3")

    agent = InvestigatingValidator()
    state = _state(
        _issue(
            candidate_uid="CAND_V3",
            validation_cluster_uid="VAL_V3",
            severity="medium",
            impact_level="medium",
            reachable_from_entry=False,
            entry_function="",
            evidence_pack={"path": {"complete": True, "complete_to_entry": False}},
            security_obligation={
                "obligation_uid": "OBL_RANGE",
                "subject_uid": "wire_len",
                "required_fact_kinds": ["value_range"],
            },
            obligation_required_fact_kinds=["value_range"],
            missing_fact_kinds=["value_range"],
        )
    )
    state["agent_context"]["entry_custom_prompt"] = "Internal repository helper"

    _runner(agent, scan=SimpleNamespace(depth="balanced")).run(state)

    assert agent.called is False


def test_balanced_runs_v3_for_medium_candidate_when_explicitly_external() -> None:
    class InvestigatingValidator(FakeValidatorAgent):
        def __init__(self):
            super().__init__([AgentResponse(success=True, data=_validator_v3_result())])
            self.calls = 0

        def investigate(self, input_data, **kwargs):
            self.calls += 1
            assert kwargs == {"max_iterations": 50}
            return AgentResponse(
                success=True,
                data=_validator_v3_result(
                    validation_pass="investigation_synthesis",
                    stop_reason="investigation_exhausted",
                ),
            )

    agent = InvestigatingValidator()
    issue = _executable_path_issue(
        candidate_uid="CAND_V3",
        validation_cluster_uid="VAL_V3",
        severity="medium",
        impact_level="medium",
        externally_reachable=True,
    )

    _runner(agent, scan=SimpleNamespace(depth="balanced")).run(_state(issue))

    assert agent.calls == 1


@pytest.mark.parametrize(
    ("error", "failure_class"),
    [
        (
            "malformed JSON output PRIVATE_SOURCE_AND_MODEL_OUTPUT_MUST_NOT_LEAK",
            "validator_v1_malformed_output",
        ),
        ("provider output truncated", "validator_v1_output_truncated"),
    ],
)
def test_balanced_recoverable_v1_failure_enters_v3(error, failure_class) -> None:
    class RecoveringValidator(FakeValidatorAgent):
        def __init__(self):
            super().__init__([AgentResponse(success=False, data={}, error=error)])
            self.calls = 0

        def investigate(self, input_data, **kwargs):
            self.calls += 1
            return AgentResponse(
                success=True,
                data=_validator_v3_result(
                    validation_pass="investigation_synthesis",
                    stop_reason="investigation_exhausted",
                ),
            )

    agent = RecoveringValidator()
    issue = _executable_path_issue(
        candidate_uid="CAND_V3",
        validation_cluster_uid="VAL_V3",
        severity="high",
        impact_level="high",
        externally_reachable=True,
    )

    _runner(agent, scan=SimpleNamespace(depth="balanced")).run(_state(issue))

    assert agent.calls == 1
    assert issue["validator_result_pass"] == "investigation_synthesis"
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["validator_v1_recoverable_failure_class"] == failure_class
    assert issue["validator_v1_recoverable_failure_count"] == 1
    serialized = json.dumps(issue, ensure_ascii=False, sort_keys=True)
    assert "PRIVATE_SOURCE_AND_MODEL_OUTPUT_MUST_NOT_LEAK" not in serialized
    assert "validator_v1_recoverable_error" not in issue


@pytest.mark.parametrize("verdict", ["rejected", "verified"])
def test_balanced_escalates_unclosed_model_verdicts_to_v3(verdict) -> None:
    class InvestigatingValidator(FakeValidatorAgent):
        def __init__(self):
            super().__init__(
                [
                    AgentResponse(
                        success=True,
                        data=_validator_v3_result(
                            verdict=verdict,
                            stop_reason="decision_complete",
                        ),
                    ),
                    AgentResponse(
                        success=True,
                        data=_validator_v3_result(
                            validation_pass="evidence_recheck",
                            stop_reason="decision_complete",
                        ),
                    ),
                ]
            )
            self.calls = []

        def investigate(self, input_data, **kwargs):
            self.calls.append((input_data, kwargs))
            return AgentResponse(
                success=True,
                data=_validator_v3_result(
                    validation_pass="investigation_synthesis",
                    stop_reason="investigation_exhausted",
                ),
            )

    agent = InvestigatingValidator()
    issue = _executable_path_issue(
        candidate_uid="CAND_V3",
        validation_cluster_uid="VAL_V3",
        severity="high",
        impact_level="high",
        reachable_from_entry=True,
        externally_reachable=True,
        confidence=0.1,
        rule_confidence=0.1,
        evidence_pack={"path": {"complete": False, "complete_to_entry": True}},
    )

    _runner(agent, scan=SimpleNamespace(depth="balanced")).run(_state(issue))

    assert len(agent.calls) == 1
    assert agent.calls[0][1] == {"max_iterations": 50}
    assert issue["validator_result_pass"] == "investigation_synthesis"
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["validator_v3_eligibility"]["risk_basis"]["truth_fields_consulted"] is False


def test_v3_is_not_started_for_external_contract_without_program_provider() -> None:
    holder = {}

    class ClosingAfterProviderValidator(FakeValidatorAgent):
        def __init__(self):
            super().__init__(
                [
                    AgentResponse(success=True, data=_validator_v3_result()),
                    AgentResponse(
                        success=True,
                        data=_validator_v3_result(
                            verdict="verified",
                            validation_pass="investigation_synthesis",
                            stop_reason="decision_complete",
                        ),
                    ),
                ]
            )
            self.investigation_calls = 0

        def investigate(self, input_data, **kwargs):
            self.investigation_calls += 1
            holder["issue"]["fact_completion_by_kind"] = {
                "caller_contract": [
                    {
                        "value": "public caller reaches sink_func",
                        "dependency_code_hash": "caller-contract-sha",
                    }
                ]
            }
            return AgentResponse(
                success=True,
                data=_validator_v3_result(
                    verdict="verified",
                    validation_pass="investigation_synthesis",
                    missing_fact_request={
                        "fact_kind": "caller_contract",
                        "subject_uid": "sink_func",
                        "function_uid": "sink_func",
                        "reason": "the public caller contract must be closed",
                    },
                    stop_reason="missing_fact",
                ),
            )

    agent = ClosingAfterProviderValidator()
    issue = _issue(
        candidate_uid="CAND_V3",
        validation_cluster_uid="VAL_V3",
        severity="high",
        impact_level="high",
        externally_reachable=False,
        evidence_pack={"path": {"complete": False, "complete_to_entry": False}},
        decision_context_version="zscope.decision-context.v3.1",
        source_identity="public_input",
        sink_identity="sink_func",
        security_obligation={
            "obligation_uid": "OBL_CALLER",
            "subject_uid": "sink_func",
            "required_fact_kinds": ["caller_contract"],
        },
        obligation_required_fact_kinds=["caller_contract"],
        missing_fact_kinds=["caller_contract"],
        decision_fact_slice={
            "fact_uids": ["FACT_BASE"],
            "dependency_code_hashes": ["base-code-sha"],
            "missing_fact_kinds": ["caller_contract"],
            "coverage": "partial",
        },
        decision_fact_coverage="partial",
    )
    holder["issue"] = issue

    _runner(agent, scan=SimpleNamespace(depth="balanced")).run(_state(issue))

    assert agent.investigation_calls == 0
    assert len(agent.inputs) == 1
    assert issue["decision_fact_coverage"] == "partial"
    assert issue["missing_fact_kinds"] == ["caller_contract"]
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["validator_v3_eligibility"]["reason"] == "no_readonly_closable_gap"


def test_v3_rejects_unbacked_fact_uid_from_default_promotion() -> None:
    class ForgingValidator(FakeValidatorAgent):
        def __init__(self):
            super().__init__([AgentResponse(success=True, data=_validator_v3_result())])

        def investigate(self, input_data, **kwargs):
            return AgentResponse(
                success=True,
                data=_validator_v3_result(
                    verdict="verified",
                    validation_pass="investigation_synthesis",
                    stop_reason="investigation_complete",
                )
                | {"evidence_refs": ["FACT_V3_FORGED"]},
                metadata={
                    "validator_investigation_facts": [
                        {
                            "fact_uid": "FACT_V3_FORGED",
                            "fact_kind": "value_range",
                            "summary": "invented bound",
                            "evidence_refs": ["TOOLFACT_MISSING"],
                            "producer_engine": "validator_readonly_tool_session",
                            "dependency_code_hash": "invented-code-sha",
                            "locations": [{"file": "src/demo.c", "start_line": 10}],
                        }
                    ]
                },
            )

    issue = _executable_path_issue(
        candidate_uid="CAND_V3",
        validation_cluster_uid="VAL_V3",
        severity="high",
        impact_level="high",
        externally_reachable=True,
        decision_context_version="zscope.decision-context.v3.1",
        source_identity="wire_len",
        subject_uid="wire_len",
        obligation_uid="OBL_MULTI",
        sink_identity="memcpy",
        decision_fact_slice={
            "fact_uids": ["FACT_BASE"],
            "dependency_code_hashes": ["base-code-sha"],
            "missing_fact_kinds": ["source_sink_reachability"],
            "coverage": "partial",
        },
        decision_fact_coverage="partial",
    )

    _runner(ForgingValidator(), scan=SimpleNamespace(depth="balanced")).run(_state(issue))

    assert issue["candidate_disposition"] == "needs_review"
    assert issue["v3_evidence_closure"]["complete"] is False
    assert issue["v3_investigation_cited_fact_count"] == 0


def test_deep_runs_v3_for_every_unclosed_non_shadow_candidate() -> None:
    class InvestigatingValidator(FakeValidatorAgent):
        def __init__(self):
            super().__init__(
                [
                    AgentResponse(
                        success=True,
                        data=_validator_v3_result(),
                    ),
                ]
            )
            self.called = False

        def investigate(self, input_data, **kwargs):
            self.called = True
            self.kwargs = kwargs
            return AgentResponse(
                success=True,
                data=_validator_v3_result(
                    validation_pass="investigation_synthesis",
                    stop_reason="investigation_exhausted",
                ),
            )

    agent = InvestigatingValidator()
    issue = _executable_path_issue(
        candidate_uid="CAND_V3",
        validation_cluster_uid="VAL_V3",
        severity="medium",
        risk_score=1,
        reachable_from_entry=False,
    )

    _runner(agent, scan=SimpleNamespace(depth="deep")).run(_state(issue))

    assert agent.called is True
    assert agent.kwargs == {"max_iterations": 50}
    assert issue["validator_result_pass"] == "investigation_synthesis"


def test_legacy_prevalidation_proof_cannot_close_p5_candidate() -> None:
    agent = FakeValidatorAgent(
        [AgentResponse(success=True, data=_validator_v3_result(verdict="verified"))]
    )
    runner = _runner(agent)
    issue = _issue(
        deterministic_proofs=[
            {
                "outcome": "confirm",
                "proof_kind": "deterministic_cfg_obligation_path",
                "producer_engine": "clang_ast_cfg_obligation_prover",
                "fact_ids": ["cfg:10", "cfg:14"],
                "code_hash": "body-v1",
                "facts": ["source_to_sink_complete", "event_path_complete"],
                "completeness": "complete",
            }
        ]
    )
    state = _state(issue)

    runner.run(state)

    assert len(agent.inputs) == 1
    assert state["issues"] == []
    assert state["observations"] == [issue]
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["terminal_authority"] == "terminal_authority_evaluator"


def test_legacy_completion_proof_cannot_close_p5_candidate() -> None:
    agent = FakeValidatorAgent(
        [AgentResponse(success=True, data=_validator_v3_result(verdict="verified"))]
    )
    runner = _runner(agent)
    issue = _issue(
        evidence_completion_proofs=[
            {
                "outcome": "confirm",
                "proof_kind": "deterministic_cfg_obligation_path",
                "producer_engine": "generic_cfg_obligation_provider",
                "fact_ids": ["cfg:entry", "cfg:sink"],
                "code_hash": "anonymous-body-v1",
                "facts": ["source_to_sink_complete", "event_path_complete"],
                "completeness": "complete",
            }
        ]
    )
    state = _state(issue)

    runner.run(state)

    assert len(agent.inputs) == 1
    assert state["issues"] == []
    assert state["observations"] == [issue]
    assert issue["candidate_disposition"] == "needs_review"


def test_model_verdict_cannot_upgrade_authoritative_open_proof() -> None:
    agent = FakeValidatorAgent(
        [AgentResponse(success=True, data=_validator_v3_result(verdict="verified"))]
    )
    issue = _issue(
        candidate_uid="CAND_V3",
        validation_cluster_uid="VAL_V3",
        decision_context_version="zscope.decision-context.v3.3",
        decision_fact_slice={
            "fact_uids": ["FACT_BASE"],
            "dependency_code_hashes": ["anonymous-code-v1"],
            "coverage": "partial",
            "missing_fact_kinds": ["caller_contract"],
        },
        decision_fact_coverage="partial",
        source_identity="public_argument",
        sink_identity="free",
    )
    state = _state(issue)

    _runner(agent, scan=SimpleNamespace(depth="fast")).run(state)

    assert agent.inputs == []
    assert state["issues"] == []
    assert state["observations"] == [issue]
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["terminal_authority"] == "terminal_authority_evaluator"
    assert issue["proof_kernel_mode"] == "authoritative"


def test_stable_validator_evidence_slice_disables_open_ended_tools() -> None:
    captured = {}

    def factory(client, tools, **kwargs):
        captured["tools"] = tools
        return FakeValidatorAgent([])

    runner = _runner(
        FakeValidatorAgent([]),
        proof_engine_agent_factory=factory,
        get_tools=lambda _agent_name: ["broad_code_browser"],
        scan=SimpleNamespace(depth="fast"),
    )

    runner._build_proof_engine_agent()

    assert captured["tools"] == []


def test_balanced_validator_receives_readonly_v3_tools_but_v1_remains_direct() -> None:
    captured = {}
    readonly_tools = [object(), object()]

    def factory(client, tools, **kwargs):
        captured["tools"] = tools
        return FakeValidatorAgent([])

    runner = _runner(
        FakeValidatorAgent([]),
        proof_engine_agent_factory=factory,
        get_tools=lambda _agent_name: readonly_tools,
        scan=SimpleNamespace(depth="balanced"),
    )

    runner._build_proof_engine_agent()

    assert captured["tools"] == readonly_tools


def test_validation_runner_logs_needs_review_without_validated_label(caplog) -> None:
    caplog.set_level(logging.INFO, logger="zscope.core.validation.runner")

    ValidationRunner._log_validation_outcome(
        {"id": "ISSUE_NR", "validation_status": "needs_review", "confidence": 0.95},
        {"confidence_score": 0.95},
        "verified",
        0.75,
    )

    message = "\n".join(record.getMessage() for record in caplog.records)
    assert "Issue ISSUE_NR kept as NEEDS_REVIEW by Validator" in message
    assert "report_bucket=observations" in message
    assert "final_score=0.75" in message
    assert "VALIDATED" not in message


def test_validation_runner_compacts_large_validator_payloads() -> None:
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data={
                    "verdict": "verified",
                    "reasoning": "reachable public API path",
                    "confidence_score": 1.0,
                },
            )
        ]
    )
    large_payload = "RAW_PAYLOAD_SHOULD_NOT_SURVIVE" * 200
    state = _state(
        _issue(
            raw_metadata={"huge": large_payload},
            irrelevant_large_blob=large_payload,
            evidence_pack={
                "path": {"complete": True, "complete_to_entry": True},
                "raw_evidence": large_payload,
                "raw_reports": [{"dump": large_payload}],
                "positive_evidence": ["entry reaches sink"],
            },
        )
    )

    _runner(agent).run(state)

    validator_input = agent.inputs[0]
    serialized_slice = json.dumps(validator_input["evidence_slice"])
    assert "RAW_PAYLOAD_SHOULD_NOT_SURVIVE" not in serialized_slice
    assert "irrelevant_large_blob" not in serialized_slice
    assert validator_input["evidence_slice"]["evidence"]["positive"] == ["entry reaches sink"]
    assert validator_input["validator_protocol"] == "zscope.validator-protocol.v3"


def test_validation_runner_keeps_entry_root_rejection_without_proof_for_review() -> None:
    memory = []
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data={"verdict": "rejected", "reasoning": "No callers, dead code."},
            ),
            AgentResponse(
                success=True,
                data={"verdict": "rejected", "reasoning": "Still no callers above main."},
            ),
        ]
    )
    state = _state(_issue(id="ISSUE_2"))

    _runner(agent, memory=memory).run(state)

    assert len(agent.inputs) == 1
    assert state["issues"] == []
    assert len(state["observations"]) == 1
    assert state["observations"][0]["validation_status"] == "needs_review"
    assert state["observations"][0]["attribution"]["decided_by"] == "unresolved"
    assert state["observations"][0]["attribution"]["decision_level"] == "none"
    assert memory == [("ISSUE_2", "needs_review")]


def test_validation_runner_keeps_contract_scope_rejection_without_proof_for_review() -> None:
    memory = []
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data={
                    "verdict": "rejected",
                    "reasoning": "The current callback is empty and only local.",
                },
            )
        ]
    )
    state = _state(
        _issue(
            id="ISSUE_3",
            defect_class="held_lock_callback",
            evidence_refs=["src/demo.c:10: callback invoked under lock"],
        )
    )

    _runner(agent, memory=memory).run(state)

    assert state["issues"] == []
    assert len(state["observations"]) == 1
    assert state["observations"][0]["validation_status"] == "needs_review"
    assert memory == [("ISSUE_3", "needs_review")]


def test_validation_runner_keeps_structured_reachable_rejection_for_review() -> None:
    memory = []
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data={
                    "verdict": "rejected",
                    "reasoning": (
                        "The current direct caller uses a local buffer, so the input is not "
                        "caller controllable and this is only by design."
                    ),
                },
            )
        ]
    )
    state = _state(
        _issue(
            id="ISSUE_5",
            category="alignment",
            defect_class="alignment",
            evidence_checker="clang_ast_cfg",
            positive_evidence=["packet + 1 is cast to uint32_t *"],
            source="public packet bytes",
            sink="unaligned uint32_t load",
        )
    )

    _runner(agent, memory=memory).run(state)

    assert state["issues"] == []
    assert len(state["observations"]) == 1
    assert state["observations"][0]["validation_status"] == "needs_review"
    assert memory == [("ISSUE_5", "needs_review")]


def test_validation_runner_recovers_uncertain_observation_location_from_evidence_pack() -> None:
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data={"verdict": "uncertain", "reasoning": "Plausible, needs source review."},
            )
        ]
    )
    issue = _issue(
        id="ISSUE_4",
        location="",
        file="",
        line=None,
        start_line=None,
        evidence_pack={
            "path": {"complete": True, "complete_to_entry": True},
            "finding_summary": {
                "function": "sink_func",
                "location": "src/recovered.c:77-79",
            },
            "source_loc": "src/recovered.c:70",
        },
    )
    state = _state(issue)

    _runner(agent).run(state)

    assert state["issues"] == []
    assert len(state["observations"]) == 1
    observation = state["observations"][0]
    assert observation["validation_status"] == "needs_review"
    assert observation["location"] == "src/recovered.c:77-79"
    assert observation["file"] == "src/recovered.c"
    assert observation["line"] == 77
    assert observation["start_line"] == 77
    assert observation["end_line"] == 79
    assert observation["source_loc"] == "src/recovered.c:70"


def test_validation_runner_parallel_workers_preserve_order_and_token_totals() -> None:
    calls = []

    class PerIssueValidatorAgent:
        def run(self, input_data):
            issue_id = input_data["finding_uid"]
            calls.append((threading.current_thread().name, issue_id))
            return AgentResponse(
                success=True,
                data={
                    "verdict": "verified",
                    "reasoning": f"{issue_id} reachable",
                    "confidence_score": 1.0,
                    "source": "arg",
                    "sink": "free",
                },
                metadata={
                    "context_tokens": 10,
                    "cumulative_prompt_tokens": 20,
                    "cumulative_completion_tokens": 5,
                    "cumulative_total_tokens": 25,
                },
            )

    issues = [
        _issue(
            id=f"ISSUE_{idx}",
            location=f"src/demo_{idx}.c:{10 + idx}",
            dedup_key=f"parallel-validation-{idx}",
        )
        for idx in range(1, 4)
    ]
    state = _state(issues[0])
    state["pending_new_issues"] = issues

    runner = _runner(
        None,
        proof_engine_agent_factory=lambda *args, **kwargs: PerIssueValidatorAgent(),
    )
    runner.run(state)

    assert [issue["id"] for issue in state["observations"]] == [
        "ISSUE_1",
        "ISSUE_2",
        "ISSUE_3",
    ]
    assert state["total_context_tokens"] == 30
    assert state["total_cumulative_prompt_tokens"] == 60
    assert state["total_cumulative_completion_tokens"] == 15
    assert state["total_cumulative_total_tokens"] == 75
    assert all(thread_name.startswith("zscope-validator") for thread_name, _issue_id in calls)


def test_parallel_validation_propagates_typed_systemic_provider_failure() -> None:
    class FailingProviderValidator:
        def run(self, _input_data):
            raise ProviderFailureError("provider_protocol_incompatible")

    issues = [
        _issue(
            id=f"ISSUE_PROVIDER_{index}",
            location=f"src/provider_{index}.c:{index + 1}",
            dedup_key=f"provider-validation-{index}",
        )
        for index in range(2)
    ]
    state = _state(issues[0])
    state["pending_new_issues"] = issues
    runner = _runner(
        None,
        proof_engine_agent_factory=lambda *args, **kwargs: FailingProviderValidator(),
    )

    with pytest.raises(ProviderFailureError) as raised:
        runner.run(state)

    assert raised.value.failure_class == "provider_protocol_incompatible"
    assert state["pending_new_issues"] == issues
    assert state["validation_provider_failure_counts"] == {"provider_protocol_incompatible": 2}
    assert state["validation_provider_failure_batch_admitted_count"] == 2
    assert state["validation_provider_failure_batch_settled_count"] == 2
    assert state["validation_provider_failure_unstarted_count"] == 0


def test_parallel_provider_failure_settles_batch_and_resume_runs_only_missing() -> None:
    barrier = threading.Barrier(8)
    lock = threading.Lock()
    calls = []
    active = 0
    max_active = 0
    failure_emitted = False

    class OneFailureValidator:
        def run(self, input_data):
            nonlocal active, max_active, failure_emitted
            candidate_uid = str(input_data["finding_uid"])
            with lock:
                ordinal = len(calls)
                calls.append(candidate_uid)
                active += 1
                max_active = max(max_active, active)
            try:
                if ordinal < 8:
                    barrier.wait(timeout=5)
                if candidate_uid == "CAND_00" and not failure_emitted:
                    with lock:
                        failure_emitted = True
                    raise ProviderFailureError("provider_transport_exhausted")
                return AgentResponse(
                    success=True,
                    data={
                        "schema_version": "zscope.validator-result.v3",
                        "candidate_uid": candidate_uid,
                        "validation_cluster_uid": input_data["validation_cluster_uid"],
                        "pass": input_data["validation_pass"],
                        "verdict": "verified",
                        "reasoning": "bounded validation result",
                        "positive_evidence": ["structured evidence"],
                        "negative_evidence": [],
                        "evidence_refs": [],
                        "blocking_negative_evidence": False,
                        "missing_fact_request": None,
                        "stop_reason": "decision_complete",
                    },
                )
            finally:
                with lock:
                    active -= 1

    issues = [
        _issue(
            id=f"ISSUE_{index:02d}",
            candidate_uid=f"CAND_{index:02d}",
            validation_cluster_uid=f"VAL_{index:02d}",
            location=f"src/provider_batch_{index}.c:{index + 1}",
            dedup_key=f"provider-batch-validation-{index}",
        )
        for index in range(16)
    ]
    state = _state(issues[0])
    state["pending_new_issues"] = issues
    runner = _runner(
        None,
        concurrency=SimpleNamespace(
            validator_workers=8,
            evidence_completion_workers=2,
        ),
        proof_engine_agent_factory=lambda *args, **kwargs: OneFailureValidator(),
    )

    with pytest.raises(ProviderFailureError) as raised:
        runner.run(state)

    assert raised.value.failure_class == "provider_transport_exhausted"
    assert max_active == 8
    assert set(calls) == {f"CAND_{index:02d}" for index in range(8)}
    assert state["validation_provider_failure_counts"] == {"provider_transport_exhausted": 1}
    assert state["validation_provider_failure_batch_admitted_count"] == 8
    assert state["validation_provider_failure_batch_settled_count"] == 8
    assert state["validation_provider_failure_unstarted_count"] == 8
    assert state["validation_queue_drained"] is False
    assert [item["candidate_uid"] for item in state["pending_new_issues"]] == [
        "CAND_00",
        *[f"CAND_{index:02d}" for index in range(8, 16)],
    ]
    assert {item["candidate_uid"] for item in state["observations"]} == {
        f"CAND_{index:02d}" for index in range(1, 8)
    }
    assert issues[0]["validation_provider_failure_class"] == ("provider_transport_exhausted")
    assert all("validation_provider_failure_class" not in issue for issue in issues[1:])

    runner.run(state)

    assert state["pending_new_issues"] == []
    assert state["validation_queue_drained"] is True
    assert len(state["observations"]) == 16
    assert calls.count("CAND_00") == 2
    assert all(calls.count(f"CAND_{index:02d}") == 1 for index in range(1, 16))


def test_validation_deadline_is_a_soft_budget_and_retains_late_result() -> None:
    class SlowSuccessfulValidator:
        def run(self, _input_data):
            time.sleep(0.03)
            return AgentResponse(
                success=True,
                data={
                    "verdict": "verified",
                    "reasoning": "late but complete validation",
                    "confidence_score": 1.0,
                    "source": "arg",
                    "sink": "free",
                },
            )

    issue = _issue(id="ISSUE_SOFT_BUDGET")
    state = _state(issue)
    runner = _runner(
        SlowSuccessfulValidator(),
        analysis=SimpleNamespace(validation_deadline_seconds=0.005),
    )

    runner.run(state)

    assert [item["id"] for item in state["observations"]] == ["ISSUE_SOFT_BUDGET"]
    assert issue["validation_status"] == "needs_review"
    assert issue["validation_soft_budget_overrun"] is True
    assert issue["validation_soft_budget_overrun_seconds"] > 0
    assert issue["validation_duration_seconds"] >= 0.02
    assert state["validation_soft_budget_overrun_count"] == 1
    assert state["validation_soft_budget_overrun_seconds"] > 0


def test_parent_cancellation_cancels_unstarted_validation_futures_without_draining() -> None:
    release = threading.Event()
    first_started = threading.Event()
    calls = []
    calls_lock = threading.Lock()

    class BlockingValidator:
        def run(self, _input_data):
            with calls_lock:
                calls.append(threading.current_thread().name)
                first_started.set()
            release.wait(timeout=2.0)
            return AgentResponse(
                success=True,
                data={
                    "verdict": "verified",
                    "reasoning": "should be discarded after parent cancellation",
                    "confidence_score": 1.0,
                },
            )

    issues = [
        _issue(
            id=f"ISSUE_CANCEL_{index}",
            location=f"src/cancel_{index}.c:{index + 1}",
            dedup_key=f"cancel-validation-{index}",
        )
        for index in range(8)
    ]
    state = _state(issues[0])
    state["pending_new_issues"] = issues
    runner = _runner(
        None,
        analysis=SimpleNamespace(
            validation_deadline_seconds=0.001,
        ),
        proof_engine_agent_factory=lambda *args, **kwargs: BlockingValidator(),
    )
    parent = CancellationToken()

    def cancel_parent() -> None:
        assert first_started.wait(timeout=1.0)
        parent.cancel("entry_cancelled")

    cancel_thread = threading.Thread(target=cancel_parent, daemon=True)
    cancel_thread.start()
    started = time.monotonic()
    try:
        with bind_cancellation_token(parent):
            with pytest.raises(CancellationError, match="entry_cancelled"):
                runner.run(state)
        elapsed = time.monotonic() - started
    finally:
        release.set()
        cancel_thread.join(timeout=1.0)

    time.sleep(0.05)
    assert elapsed < 0.5
    assert len(calls) <= 2
    assert state["pending_new_issues"] == issues


def test_parent_deadline_is_a_hard_cutoff_for_parallel_validation_batch() -> None:
    release = threading.Event()
    calls = []
    calls_lock = threading.Lock()

    class BlockingValidator:
        def run(self, _input_data):
            with calls_lock:
                calls.append(threading.current_thread().name)
            release.wait(timeout=2.0)
            return AgentResponse(
                success=True,
                data={
                    "verdict": "verified",
                    "reasoning": "should be discarded after parent deadline",
                    "confidence_score": 1.0,
                },
            )

    issues = [
        _issue(
            id=f"ISSUE_DEADLINE_{index}",
            location=f"src/deadline_{index}.c:{index + 1}",
            dedup_key=f"deadline-validation-{index}",
        )
        for index in range(8)
    ]
    state = _state(issues[0])
    state["pending_new_issues"] = issues
    runner = _runner(
        None,
        analysis=SimpleNamespace(
            validation_deadline_seconds=0.001,
        ),
        proof_engine_agent_factory=lambda *args, **kwargs: BlockingValidator(),
    )
    parent = CancellationToken(timeout_seconds=0.05)

    started = time.monotonic()
    try:
        with bind_cancellation_token(parent):
            with pytest.raises(CancellationError, match="deadline_exceeded"):
                runner.run(state)
        elapsed = time.monotonic() - started
    finally:
        release.set()

    time.sleep(0.05)
    assert elapsed < 0.5
    assert len(calls) <= 2
    assert state["pending_new_issues"] == issues


def test_parent_cancellation_cancels_queued_scan_scheduler_validations() -> None:
    release = threading.Event()
    first_started = threading.Event()
    calls = []

    class BlockingValidator:
        def run(self, _input_data):
            calls.append(threading.current_thread().name)
            first_started.set()
            release.wait(timeout=2.0)
            return AgentResponse(
                success=True,
                data={
                    "verdict": "verified",
                    "reasoning": "scheduler work should stop with its parent",
                    "confidence_score": 1.0,
                },
            )

    issues = [
        _issue(
            id=f"ISSUE_SCHEDULER_CANCEL_{index}",
            location=f"src/scheduler_cancel_{index}.c:{index + 1}",
            dedup_key=f"scheduler-cancel-validation-{index}",
        )
        for index in range(6)
    ]
    state = _state(issues[0])
    state["pending_new_issues"] = issues
    parent = CancellationToken()
    scheduler = ScanScheduler(
        entry_workers=1,
        validator_workers=1,
        investigator_workers=1,
    )
    runner = _runner(
        None,
        analysis=SimpleNamespace(
            validation_deadline_seconds=0.001,
        ),
        proof_engine_agent_factory=lambda *args, **kwargs: BlockingValidator(),
        scheduler=scheduler,
    )

    def cancel_parent() -> None:
        assert first_started.wait(timeout=1.0)
        parent.cancel("scan_cancelled")

    cancel_thread = threading.Thread(target=cancel_parent, daemon=True)
    cancel_thread.start()
    try:
        with bind_cancellation_token(parent):
            with pytest.raises(CancellationError, match="scan_cancelled"):
                runner.run(state)
    finally:
        release.set()
        cancel_thread.join(timeout=1.0)
        scheduler.shutdown(wait=True, cancel_futures=True)

    assert calls == ["zscope-validator-0"]
    assert state["pending_new_issues"] == issues


def test_validation_runner_uses_explicit_concurrency_validator_workers() -> None:
    runner = _runner(
        None,
        concurrency=SimpleNamespace(
            validator_workers=3,
            evidence_completion_workers=2,
        ),
    )

    assert runner._validation_worker_count(5) == 3


def test_validation_runner_normalizes_external_api_function_to_entry_function() -> None:
    class MissingExternalApiCodeIndex(FakeCodeIndex):
        def get_function_impl(self, func_name, *args, **kwargs):
            if func_name == "pthread_create":
                return None
            if func_name == "api_entry":
                return {"code": "void api_entry(void) { pthread_create(0, 0, worker, 0); }"}
            return super().get_function_impl(func_name)

    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data={
                    "verdict": "uncertain",
                    "reasoning": "Need worker lifetime details.",
                    "missing_context": ["worker ownership contract"],
                },
            )
        ]
    )
    issue = _issue(
        id="ISSUE_PTHREAD",
        function="pthread_create",
        entry_function="api_entry",
        sink="pthread_create",
    )
    state = _state(issue)

    _runner(agent, code_index=MissingExternalApiCodeIndex()).run(state)

    evidence_slice = agent.inputs[0]["evidence_slice"]
    assert evidence_slice["obligation"]["function"] == "api_entry"
    assert evidence_slice["evidence"]["sink"] == "pthread_create"
    assert issue["validation_function_normalized_from"] == "pthread_create"
    assert (
        issue["validation_function_normalization_reason"]
        == "external_api_function_without_indexed_body"
    )
