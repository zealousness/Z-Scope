import json
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
):
    memory = memory if memory is not None else []
    config = SimpleNamespace(
        analysis=analysis,
        project=SimpleNamespace(
            agents=[SimpleNamespace(name="validator_agent", enabled=enabled, llm_ref="default")]
        )
    )
    return ValidationRunner(
        config=config,
        llm_clients={"default": object()},
        validation_pipeline=ValidationPipeline(FakeUserConfig()),
        code_index=code_index or FakeCodeIndex(),
        snapshot_store=FakeSnapshotStore(),
        get_tools=lambda agent_name: [],
        tool_policy_for_agent=lambda agent_name: None,
        attach_agent_contract=lambda context, agent_name: context.update({"agent_contract": agent_name}),
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


def test_validation_runner_cache_key_uses_stable_evidence_fingerprint_without_candidate_id() -> None:
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
    assert runner._validator_cache_key(first) == runner._validator_cache_key(
        changed_entry
    )


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
        list(pool.map(lambda pair: pair[0].run(pair[1]), [(first, first_state), (second, second_state)]))

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
    assert memory == [("ISSUE_1", "validated")]
    assert agent.inputs[0]["agent_contract"] == "validator_agent"


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
    assert "RAW_PAYLOAD_SHOULD_NOT_SURVIVE" not in validator_input["finding"]
    assert "irrelevant_large_blob" not in validator_input["finding"]
    candidate_evidence = validator_input["evidence_pack"]["candidate_evidence"]
    assert "raw_evidence" not in candidate_evidence
    assert "raw_reports" not in candidate_evidence
    assert candidate_evidence["path"]["complete_to_entry"] is True
    assert candidate_evidence["positive_evidence"] == ["entry reaches sink"]
    assert candidate_evidence["compaction_metadata"]["omitted_large_payload_keys"] == [
        "raw_evidence",
        "raw_reports",
    ]


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

    assert len(agent.inputs) == 2
    assert agent.inputs[1]["evidence_pack"]["mode"] == "tri_state_exploitability_validation_entry_root_retry"
    assert state["issues"] == []
    assert len(state["observations"]) == 1
    assert state["observations"][0]["validation_status"] == "needs_review"
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
            finding = json.loads(input_data["finding"])
            issue_id = finding["id"]
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
        analysis=SimpleNamespace(parallel_workers=12, validation_parallel_workers=2),
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
            validation_parallel_workers=2,
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
            validation_parallel_workers=2,
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
            validator_workers=1,
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


def test_validation_runner_prefers_role_specific_validator_workers() -> None:
    runner = _runner(
        None,
        analysis=SimpleNamespace(
            entry_workers=8,
            parallel_workers=2,
            validator_workers=3,
            validation_parallel_workers=1,
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

    compact_finding = json.loads(agent.inputs[0]["finding"])
    assert compact_finding["function"] == "api_entry"
    assert compact_finding["sink_function"] == "pthread_create"
    assert issue["validation_function_normalized_from"] == "pthread_create"
    assert issue["validation_function_normalization_reason"] == "external_api_function_without_indexed_body"
