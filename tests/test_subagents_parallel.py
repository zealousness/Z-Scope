import threading
import time

import pytest

from zscope.common.cancellation import (
    CancellationError,
    CancellationToken,
    bind_cancellation_token,
    current_cancellation_token,
)
from zscope.framework.base import AgentResponse
from zscope.orchestration.scheduler import ScanScheduler
from zscope.orchestration.subagents import SubAgentOrchestrator, SubAgentTicket
from zscope.orchestration.specs import SpecRegistry


class FakeDeepWorker:
    sleep_seconds = 0.0
    seen_inputs = []
    seen_models = []

    def __init__(self, llm_client, tools, tool_policy=None):
        models = getattr(llm_client, "models", []) or []
        self.model = models[0] if models else ""

    def run(self, input_data):
        self.seen_inputs.append(input_data)
        self.seen_models.append(self.model)
        if self.sleep_seconds:
            time.sleep(self.sleep_seconds)
        ticket = input_data["ticket"]
        return AgentResponse(
            success=True,
            data={
                "type": "worker_report",
                "ticket_id": ticket["id"],
                "issues_found": [],
                "conclusion": "ok",
            },
            metadata={"context_tokens": 1, "tool_call_count": 2, "iterations": 3},
        )


def _tickets(count: int) -> list[SubAgentTicket]:
    return [
        SubAgentTicket(
            id=f"ticket-{idx}",
            skill="stack_escape",
            task="check stack escape",
            trigger="return &local",
            line=idx + 1,
            context_slice="int demo(void) { return 0; }",
        )
        for idx in range(count)
    ]


def test_run_tickets_parallel_keeps_stable_report_order(monkeypatch) -> None:
    monkeypatch.setattr("zscope.orchestration.subagents.DeepWorkerAgent", FakeDeepWorker)
    FakeDeepWorker.sleep_seconds = 0.05
    FakeDeepWorker.seen_inputs = []
    FakeDeepWorker.seen_models = []
    orchestrator = SubAgentOrchestrator(SpecRegistry(), tools=[])
    tickets = _tickets(4)

    started = time.perf_counter()
    reports = orchestrator.run_tickets(
        llm_client=object(),
        tickets=tickets,
        max_workers=4,
    )
    elapsed = time.perf_counter() - started

    assert [report["ticket"]["id"] for report in reports] == [ticket.id for ticket in tickets]
    assert all(report["status"] == "completed" for report in reports)
    assert all("duration_ms" in report["metadata"] for report in reports)
    assert all(report["metadata"]["tool_call_count"] == 2 for report in reports)
    assert all(report["metadata"]["iterations"] == 3 for report in reports)
    assert elapsed < 0.18


def test_legacy_cancel_policy_does_not_kill_available_worker(monkeypatch) -> None:
    monkeypatch.setattr("zscope.orchestration.subagents.DeepWorkerAgent", FakeDeepWorker)
    FakeDeepWorker.sleep_seconds = 0.2
    FakeDeepWorker.seen_inputs = []
    FakeDeepWorker.seen_models = []
    orchestrator = SubAgentOrchestrator(SpecRegistry(), tools=[])

    started = time.perf_counter()
    reports = orchestrator.run_tickets(
        llm_client=object(),
        tickets=_tickets(2),
        max_workers=2,
        max_iterations=6,
        ticket_timeout=0.01,
        budget_exhaustion_policy="cancel",
    )
    elapsed = time.perf_counter() - started

    assert len(reports) == 2
    assert elapsed >= 0.18
    assert all(report["status"] == "completed" for report in reports)
    assert all(report["metadata"]["ticket_budget_exceeded"] for report in reports)
    assert all(
        report["metadata"]["budget_exhaustion_policy"] == "observe"
        for report in reports
    )
    assert {report["metadata"]["worker_index"] for report in reports} == {0, 1}
    assert all(report["metadata"]["max_turns"] == 6 for report in reports)


def test_ticket_timeout_starts_when_each_queued_worker_starts(monkeypatch) -> None:
    monkeypatch.setattr("zscope.orchestration.subagents.DeepWorkerAgent", FakeDeepWorker)
    FakeDeepWorker.sleep_seconds = 0.08
    FakeDeepWorker.seen_inputs = []
    FakeDeepWorker.seen_models = []
    scheduler = ScanScheduler(
        entry_workers=1,
        validator_workers=1,
        investigator_workers=1,
    )
    orchestrator = SubAgentOrchestrator(
        SpecRegistry(),
        tools=[],
        scheduler=scheduler,
    )
    try:
        reports = orchestrator.run_tickets(
            llm_client=object(),
            tickets=_tickets(2),
            max_workers=1,
            ticket_timeout=0.12,
            budget_exhaustion_policy="cancel",
        )
    finally:
        scheduler.shutdown(wait=True, cancel_futures=True)

    assert [report["status"] for report in reports] == ["completed", "completed"]


def test_run_tickets_default_budget_is_observe_only(monkeypatch) -> None:
    observed_remaining = []

    class DeadlineRecordingWorker(FakeDeepWorker):
        def run(self, input_data):
            token = current_cancellation_token()
            assert token is not None
            observed_remaining.append(token.remaining_seconds())
            return super().run(input_data)

    monkeypatch.setattr(
        "zscope.orchestration.subagents.DeepWorkerAgent",
        DeadlineRecordingWorker,
    )
    FakeDeepWorker.sleep_seconds = 0.0
    orchestrator = SubAgentOrchestrator(SpecRegistry(), tools=[])

    reports = orchestrator.run_tickets(
        llm_client=object(),
        tickets=_tickets(1),
        max_workers=1,
    )

    assert reports[0]["status"] == "completed"
    assert observed_remaining[0] is None
    assert reports[0]["metadata"]["ticket_budget_seconds"] == 300.0
    assert reports[0]["metadata"]["budget_exhaustion_policy"] == "observe"


def test_run_tickets_retains_result_after_soft_budget_overrun(monkeypatch) -> None:
    monkeypatch.setattr("zscope.orchestration.subagents.DeepWorkerAgent", FakeDeepWorker)
    FakeDeepWorker.sleep_seconds = 0.03
    orchestrator = SubAgentOrchestrator(SpecRegistry(), tools=[])

    reports = orchestrator.run_tickets(
        llm_client=object(),
        tickets=_tickets(1),
        max_workers=1,
        ticket_timeout=0.005,
    )

    assert reports[0]["status"] == "completed"
    assert reports[0]["success"] is True
    assert reports[0]["metadata"]["ticket_budget_exceeded"] is True
    assert reports[0]["metadata"]["ticket_budget_overrun_seconds"] > 0
    assert reports[0]["metadata"]["budget_exhaustion_policy"] == "observe"


def test_parent_cancellation_propagates_out_of_ticket_batch(monkeypatch) -> None:
    worker_started = threading.Event()

    class CancellationAwareWorker(FakeDeepWorker):
        def run(self, input_data):
            token = current_cancellation_token()
            assert token is not None
            worker_started.set()
            while not token.wait(0.005):
                pass
            token.raise_if_cancelled()
            raise AssertionError("unreachable")

    monkeypatch.setattr(
        "zscope.orchestration.subagents.DeepWorkerAgent",
        CancellationAwareWorker,
    )
    parent = CancellationToken()
    orchestrator = SubAgentOrchestrator(SpecRegistry(), tools=[])

    def cancel_parent() -> None:
        assert worker_started.wait(timeout=1.0)
        parent.cancel("scan_interrupted")

    canceller = threading.Thread(target=cancel_parent)
    canceller.start()
    try:
        with bind_cancellation_token(parent):
            with pytest.raises(CancellationError, match="scan_interrupted"):
                orchestrator.run_tickets(
                    llm_client=object(),
                    tickets=_tickets(2),
                    max_workers=1,
                )
    finally:
        canceller.join(timeout=1.0)


def test_run_tickets_sequential_path_still_reports_metadata(monkeypatch) -> None:
    monkeypatch.setattr("zscope.orchestration.subagents.DeepWorkerAgent", FakeDeepWorker)
    FakeDeepWorker.sleep_seconds = 0.0
    FakeDeepWorker.seen_inputs = []
    FakeDeepWorker.seen_models = []
    orchestrator = SubAgentOrchestrator(SpecRegistry(), tools=[])

    reports = orchestrator.run_tickets(
        llm_client=object(),
        tickets=_tickets(1),
        max_workers=1,
        max_iterations=7,
    )

    assert reports[0]["status"] == "completed"
    assert reports[0]["metadata"]["max_iterations"] == 7
    assert reports[0]["metadata"]["max_turns"] == 7
    assert reports[0]["metadata"]["worker_index"] == 0


def test_run_tickets_rejects_agent_type_not_in_spawn_allowlist() -> None:
    orchestrator = SubAgentOrchestrator(SpecRegistry(), tools=[])

    reports = orchestrator.run_tickets(
        llm_client=object(),
        tickets=_tickets(1),
        agent_type="general_agent",
        spawn_allowlist=["deep_worker"],
    )

    assert reports[0]["status"] == "failed"
    assert reports[0]["metadata"]["failure_kind"] == "spawn_denied"
    assert reports[0]["metadata"]["needs_human_review"] is True


def test_run_tickets_records_model_policy_and_read_only_isolation(monkeypatch) -> None:
    monkeypatch.setattr("zscope.orchestration.subagents.DeepWorkerAgent", FakeDeepWorker)
    FakeDeepWorker.sleep_seconds = 0.0
    FakeDeepWorker.seen_inputs = []
    FakeDeepWorker.seen_models = []
    orchestrator = SubAgentOrchestrator(SpecRegistry(), tools=[])

    class FakeClient:
        def __init__(self, model):
            self.models = [model]

    tickets = _tickets(1)
    reports = orchestrator.run_tickets(
        llm_client=FakeClient("default-model"),
        tickets=tickets,
        max_workers=1,
        max_iterations=5,
        llm_client_resolver=lambda ticket: FakeClient("high-risk-model"),
        execution_policy_resolver=lambda ticket: {
            "llm_ref": "high_risk",
            "reasoning_effort": "high",
        },
        worktree_isolation={"mode": "read_only", "snapshot_writes": False},
    )

    metadata = reports[0]["metadata"]
    assert FakeDeepWorker.seen_models == ["high-risk-model"]
    assert metadata["execution_policy"]["llm_ref"] == "high_risk"
    assert metadata["execution_policy"]["model"] == "high-risk-model"
    assert metadata["execution_policy"]["reasoning_effort"] == "high"
    assert metadata["worktree_isolation"]["mode"] == "read_only"
    assert metadata["nested_spawn_allowed"] is False
    assert metadata["subagent_can_spawn"] is False
    assert FakeDeepWorker.seen_inputs[0]["worktree_isolation"]["snapshot_writes"] is False
