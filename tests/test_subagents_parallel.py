import time

from zscope.framework.base import AgentResponse
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


def test_run_tickets_timeout_marks_pending_reports(monkeypatch) -> None:
    monkeypatch.setattr("zscope.orchestration.subagents.DeepWorkerAgent", FakeDeepWorker)
    FakeDeepWorker.sleep_seconds = 0.2
    FakeDeepWorker.seen_inputs = []
    FakeDeepWorker.seen_models = []
    orchestrator = SubAgentOrchestrator(SpecRegistry(), tools=[])

    reports = orchestrator.run_tickets(
        llm_client=object(),
        tickets=_tickets(2),
        max_workers=2,
        max_iterations=6,
        ticket_timeout=0.01,
    )

    assert len(reports) == 2
    assert all(report["status"] == "killed" for report in reports)
    assert all(report["metadata"]["failure_kind"] == "timeout" for report in reports)
    assert {report["metadata"]["worker_index"] for report in reports} == {0, 1}
    assert all(report["metadata"]["max_turns"] == 6 for report in reports)


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
