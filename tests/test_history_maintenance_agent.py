from zscope.agents.history_maintenance.agent import HistoryMaintenanceAgent
from zscope.framework.base import AgentResponse


def test_history_maintenance_rejects_non_verify_modes() -> None:
    agent = HistoryMaintenanceAgent(object())  # type: ignore[arg-type]

    response = agent.run({"mode": "deduplicate"})

    assert response.success is False
    assert "verify_fix only" in str(response.error)


def test_history_maintenance_returns_advisory_verify_result(monkeypatch) -> None:
    agent = HistoryMaintenanceAgent(object())  # type: ignore[arg-type]
    captured = {}

    def fake_run(messages, **kwargs):
        captured["messages"] = messages
        captured["kwargs"] = kwargs
        return AgentResponse(
            success=True,
            data={
                "still_exists": False,
                "new_location": None,
                "reasoning": "The changed branch no longer contains the operation.",
            },
        )

    monkeypatch.setattr(agent, "_run_json_conversation", fake_run)
    response = agent.run(
        {
            "mode": "verify_fix",
            "historical_issue": {"id": "H1", "root_cause": "unchecked copy"},
            "new_code": "void f(void) {}",
        }
    )

    assert response.success is True
    assert response.data["still_exists"] is False
    assert captured["kwargs"]["trace_label"] == "history_maintenance_verify_fix"
    assert "advisory maintenance evidence" in captured["messages"][-1]["content"]
