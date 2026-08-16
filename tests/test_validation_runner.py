import json
import hashlib
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from zscope.common.cancellation import (
    CancellationError,
    CancellationToken,
    bind_cancellation_token,
)
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.core.validation.runner import ValidationResultCache, ValidationRunner
from zscope.core.validation.claim_verifier import (
    EvidenceClaimRequest,
    EvidenceClaimVerifier,
    verify_evidence_certificate,
)
from zscope.core.validation.function_ir import FunctionIRGraph
from zscope.framework.base import AgentResponse
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
    validator_agent_factory=None,
    result_cache=None,
    scheduler=None,
    get_tools=None,
    concurrency=None,
    scan=None,
):
    memory = memory if memory is not None else []
    config = SimpleNamespace(
        analysis=analysis,
        scan=scan,
        concurrency=concurrency
        or SimpleNamespace(
            validator_workers=2,
            evidence_completion_workers=2,
        ),
        project=SimpleNamespace(
            agents=[SimpleNamespace(name="validator_agent", enabled=enabled, llm_ref="default")]
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
        attach_agent_contract=lambda context, agent_name: context.update(
            {"agent_contract": agent_name}
        ),
        remember_validation_result=lambda issue, status: memory.append((issue["id"], status)),
        validator_agent_factory=validator_agent_factory or (lambda *args, **kwargs: agent),
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


def _verified_v3_fact(*, fact_kind="value_range", subject_uid="wire_len", ref="TOOLFACT_RANGE"):
    predicate = {
        "value_range": "value_range_is_proved",
        "lockset": "lock_must_hold_at_access",
    }[fact_kind]
    true_key = {
        "value_range": "value_range_proved",
        "lockset": "lock_must_hold",
    }[fact_kind]
    result_payload = {
        "success": True,
        "data": {true_key: True, "analysis_complete": True},
    }
    result_hash = hashlib.sha256(
        json.dumps(
            result_payload,
            ensure_ascii=False,
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    catalog = {
        ref: {
            "evidence_ref": ref,
            "tool_name": "get_data_flow",
            "arguments": {"query": fact_kind},
            "arguments_hash": "a" * 64,
            "result_hash": result_hash,
            "result_payload": result_payload,
            "dependency_code_hash": result_hash,
            "location": {
                "file": "src/demo.c",
                "function": "sink_func",
                "start_line": 10,
                "end_line": 14,
            },
        }
    }
    claim = EvidenceClaimRequest.from_mapping(
        {
            "obligation_uid": "OBL_TEST",
            "fact_kind": fact_kind,
            "predicate": predicate,
            "polarity": "supports",
            "subject_uid": subject_uid,
            "decision_region_uid": "",
            "arguments": {"query": fact_kind},
            "cited_evidence_refs": [ref],
        }
    )
    verification = EvidenceClaimVerifier().verify(
        claim,
        issue={},
        tool_catalog=catalog,
    )
    assert verification.verified_fact is not None
    return verification.verified_fact, catalog


def _function_ir_graph(*, duplicate_sink: bool = False) -> dict:
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
    return graph.to_dict()


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


def test_validation_runner_cache_key_rejects_weak_fingerprint_without_candidate_id() -> None:
    runner = _runner(None)
    issue = _issue(id="ISSUE_WEAK", candidate_id="", source="", sink="", evidence_pack={})
    item = SimpleNamespace(raw_issue=issue, issue_func="demo")

    assert runner._validator_cache_key(item) == ""


def test_validation_runner_cache_is_scoped_to_runner_instance() -> None:
    first = _runner(None)
    second = _runner(None)

    first._validator_cache_put("same-candidate", {"verdict": "verified"})

    assert first._validator_cache_get("same-candidate") == {"verdict": "verified"}
    assert second._validator_cache_get("same-candidate") is None


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
        def run(self, _input_data):
            with calls_lock:
                calls.append(threading.current_thread().name)
            time.sleep(0.05)
            return AgentResponse(
                success=True,
                data={
                    "verdict": "verified",
                    "reasoning": "same immutable evidence",
                    "confidence_score": 1.0,
                },
            )

    first = _runner(SlowValidator(), result_cache=cache)
    second = _runner(SlowValidator(), result_cache=cache)
    first_state = _state(_issue(candidate_id="CAND_SHARED"))
    second_state = _state(_issue(candidate_id="CAND_SHARED"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(
            pool.map(
                lambda pair: pair[0].run(pair[1]), [(first, first_state), (second, second_state)]
            )
        )

    assert len(calls) == 1
    assert len(first_state["issues"]) == 1
    assert len(second_state["issues"]) == 1
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
    assert len(state["issues"]) == 1
    assert state["issues"][0]["validation_status"] == "validated"
    assert state["issues"][0]["validator_verdict"] == "verified"
    assert state["issues"][0]["model_verdict"] == "verified"
    assert state["issues"][0]["policy_disposition"] == "confirmed"
    assert state["issues"][0]["attribution"]["discovered_by"] == []
    assert state["issues"][0]["attribution"]["decided_by"] == "validator_llm"
    assert memory == [("ISSUE_1", "validated")]
    assert agent.inputs[0]["agent_contract"] == "validator_agent"


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
        fact["fact_kind"]
        for fact in agent.inputs[0]["evidence_slice"]["decision_facts"]["facts"]
    }
    assert "source_sink_reachability" in v1_fact_kinds
    assert issue["validator_fact_resolution"]["status"] == "completed_partial"
    assert issue["validator_pass_history"][-1]["pass"] == "evidence_recheck"
    assert issue["evidence_completion_attempt_count"] == 2


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
    assert issue["attribution"]["decision_level"] == "V3"


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
    assert (
        agent.action_results[1]["reason_code"]
        == "evidence_action_clause_already_closed"
    )


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


@pytest.mark.parametrize("error", ["malformed JSON output", "provider output truncated"])
def test_balanced_recoverable_v1_failure_enters_v3(error) -> None:
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


def test_v3_legacy_generic_tool_fact_cannot_reenter_live_promotion_policy() -> None:
    class ClosingValidator(FakeValidatorAgent):
        def __init__(self):
            super().__init__([AgentResponse(success=True, data=_validator_v3_result())])
            self.calls = 0

        def investigate(self, input_data, **kwargs):
            self.calls += 1
            fact, catalog = _verified_v3_fact()
            fact_uid = fact["fact_uid"]
            return AgentResponse(
                success=True,
                data=_validator_v3_result(
                    verdict="verified",
                    validation_pass="investigation_synthesis",
                    stop_reason="investigation_complete",
                )
                | {"evidence_refs": [fact_uid]},
                metadata={
                    "iterations": 4,
                    "tool_call_count": 3,
                    "validator_tool_fact_catalog": catalog,
                    "validator_investigation_facts": [fact],
                },
            )

    agent = ClosingValidator()
    issue = _executable_path_issue(
        candidate_uid="CAND_V3",
        validation_cluster_uid="VAL_V3",
        severity="high",
        impact_level="high",
        reachable_from_entry=True,
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
    state = _state(issue)

    _runner(agent, scan=SimpleNamespace(depth="balanced")).run(state)

    assert agent.calls == 1
    assert state["issues"] == []
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["v3_evidence_closure"]["complete"] is False
    assert issue["decision_fact_coverage"] == "partial"
    assert issue["v3_tool_fact_catalog"]["TOOLFACT_RANGE"]["tool_name"] == "get_data_flow"


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
                    ],
                    "validator_tool_fact_catalog": {},
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


def test_v3_closure_normalizes_obligation_event_aliases() -> None:
    issue = {
        "allow_legacy_v3_claim_replay": True,
        "missing_fact_kinds": ["event:shared_state_access", "lockset"],
        "decision_fact_slice": {
            "fact_uids": ["FACT_BASE"],
            "dependency_code_hashes": ["base-code-sha"],
            "missing_fact_kinds": ["event:shared_state_access", "lockset"],
            "coverage": "partial",
        },
    }
    fact, catalog = _verified_v3_fact(
        fact_kind="lockset",
        subject_uid="shared_state",
        ref="TOOLFACT_LOCKSET",
    )

    ValidationRunner._apply_v3_investigation_facts(
        issue,
        {"evidence_refs": [fact["fact_uid"]]},
        {
            "validator_investigation_facts": [fact],
            "validator_tool_fact_catalog": catalog,
        },
    )

    assert issue["v3_evidence_closure"]["complete"] is True
    assert issue["v3_evidence_closure"]["resolved_fact_kinds"] == ["lockset"]
    assert issue["missing_fact_kinds"] == []


def test_v3_legacy_claim_is_not_accepted_by_live_strict_verifier() -> None:
    class ClaimingValidator(FakeValidatorAgent):
        def __init__(self):
            super().__init__(
                [
                    AgentResponse(success=True, data=_validator_v3_result()),
                    AgentResponse(
                        success=True,
                        data=_validator_v3_result(validation_pass="evidence_recheck"),
                    ),
                ]
            )

        def investigate(self, input_data, *, max_iterations=50, claim_verifier=None):
            _, catalog = _verified_v3_fact()
            assert max_iterations == 50
            assert claim_verifier is not None
            verification = claim_verifier(
                {
                    "obligation_uid": "OBL_PATH",
                    "fact_kind": "value_range",
                    "predicate": "value_range_is_proved",
                    "polarity": "supports",
                    "subject_uid": "wire_len",
                    "decision_region_uid": "REGION_PATH",
                    "arguments": {"query": "value_range"},
                    "cited_evidence_refs": ["TOOLFACT_RANGE"],
                },
                catalog,
            )
            assert verification["status"] == "unknown"
            assert verification["reason_code"] == "claim_protocol_invalid"
            assert verification.get("accepted_into_decision_slice") is not True
            return AgentResponse(
                success=True,
                data=_validator_v3_result(
                    verdict="uncertain",
                    validation_pass="investigation_synthesis",
                    stop_reason="investigation_exhausted",
                ),
                metadata={
                    "iterations": 5,
                    "tool_call_count": 2,
                    "validator_tool_fact_catalog": catalog,
                    "validator_investigation_facts": [verification["verified_fact"]],
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

    _runner(ClaimingValidator(), scan=SimpleNamespace(depth="balanced")).run(_state(issue))

    assert issue["candidate_disposition"] == "needs_review"
    assert "value_range" not in issue["evidence_closure_state"]["resolved_fact_kinds"]
    assert issue["validator_pass_history"][-1]["new_fact_count"] == 0


def test_v3_invalid_claim_is_unknown_and_persisted_in_trace(tmp_path) -> None:
    runner = _runner(
        None,
        analysis=SimpleNamespace(snapshot_dir=str(tmp_path)),
    )
    issue = _issue(
        candidate_uid="CAND_V3",
        validation_cluster_uid="VAL_V3_INVALID_CLAIM",
        obligation_uid="OBL_TEST",
        subject_uid="wire_len",
        decision_region_uid="REGION_1",
    )

    verification = runner._verify_v3_claim(
        issue,
        {
            "fact_kind": "value_range",
            # A model may pick two independently valid enum members that do
            # not form a valid fact/predicate pair.  This must be traceable,
            # not swallowed by the Agent tool loop.
            "predicate": "caller_contract_holds",
            "polarity": "supports",
            "subject_uid": "wire_len",
            "decision_region_uid": "REGION_1",
            "arguments": {"query": "value_range"},
            "cited_evidence_refs": ["TOOLFACT_RANGE"],
        },
        {},
    )

    assert verification["status"] == "unknown"
    assert verification["reason_code"] == "claim_protocol_invalid"
    trace = runner._decision_trace_store.trace("VAL_V3_INVALID_CLAIM")
    verifier_events = [event for event in trace["events"] if event["stage"] == "verifier"]
    assert len(verifier_events) == 1
    assert verifier_events[0]["reason_code"] == "FACT_UNKNOWN"
    assert verifier_events[0]["details"]["verification_reason"] == "claim_protocol_invalid"
    assert verifier_events[0]["input_refs"]
    assert verifier_events[0]["output_refs"]
    certificate_object = json.loads(
        (tmp_path / verifier_events[0]["output_refs"][0]).read_text(encoding="utf-8")
    )
    assert verify_evidence_certificate(certificate_object["payload"]) == (True, "ok")


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


def test_validation_runner_always_skips_validator_for_prevalidation_proof() -> None:
    agent = FakeValidatorAgent([])
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

    assert agent.inputs == []
    assert state["issues"] == [issue]
    assert state["validator_avoided_count"] == 1
    assert state["deterministic_prevalidation_confirmed_count"] == 1
    assert issue["attribution"]["decided_by"] == "deterministic_proof"
    assert issue["attribution"]["decision_level"] == "V0"


def test_stable_validator_evidence_slice_disables_open_ended_tools() -> None:
    captured = {}

    def factory(client, tools, **kwargs):
        captured["tools"] = tools
        return FakeValidatorAgent([])

    runner = _runner(
        FakeValidatorAgent([]),
        validator_agent_factory=factory,
        get_tools=lambda _agent_name: ["broad_code_browser"],
    )

    runner._build_validator_agent()

    assert captured["tools"] == []


def test_balanced_validator_receives_readonly_v3_tools_but_v1_remains_direct() -> None:
    captured = {}
    readonly_tools = [object(), object()]

    def factory(client, tools, **kwargs):
        captured["tools"] = tools
        return FakeValidatorAgent([])

    runner = _runner(
        FakeValidatorAgent([]),
        validator_agent_factory=factory,
        get_tools=lambda _agent_name: readonly_tools,
        scan=SimpleNamespace(depth="balanced"),
    )

    runner._build_validator_agent()

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
        validator_agent_factory=lambda *args, **kwargs: PerIssueValidatorAgent(),
    )
    runner.run(state)

    assert [issue["id"] for issue in state["issues"]] == ["ISSUE_1", "ISSUE_2", "ISSUE_3"]
    assert state["total_context_tokens"] == 30
    assert state["total_cumulative_prompt_tokens"] == 60
    assert state["total_cumulative_completion_tokens"] == 15
    assert state["total_cumulative_total_tokens"] == 75
    assert all(thread_name.startswith("zscope-validator") for thread_name, _issue_id in calls)


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

    assert [item["id"] for item in state["issues"]] == ["ISSUE_SOFT_BUDGET"]
    assert issue["validation_status"] == "validated"
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
        validator_agent_factory=lambda *args, **kwargs: BlockingValidator(),
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
        validator_agent_factory=lambda *args, **kwargs: BlockingValidator(),
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
        validator_agent_factory=lambda *args, **kwargs: BlockingValidator(),
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
