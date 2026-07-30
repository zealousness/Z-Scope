from zscope.orchestration.history_reconciler import HistoryReconciler


class FakeResponse:
    def __init__(self, success, data=None):
        self.success = success
        self.data = data or {}


def test_history_reconciler_partitions_active_and_user_rejected() -> None:
    valid, user_rejected = HistoryReconciler.partition_issues(
        [
            {"id": "validated", "validation_status": "validated"},
            {"id": "pending", "validation_status": "pending"},
            {"id": "user-rejected", "validation_status": "rejected", "rejection_source": "user"},
            {"id": "validator-rejected", "validation_status": "rejected"},
        ]
    )

    assert [issue["id"] for issue in valid] == ["validated", "pending"]
    assert [issue["id"] for issue in user_rejected] == ["user-rejected"]


def test_history_reconciler_keeps_failed_reconciliation_as_needs_review() -> None:
    result = HistoryReconciler.reconcile_issue(
        {"id": "old-1", "location": "src/demo.c:42", "validation_status": "validated"},
        FakeResponse(False),
    )

    assert result.keep is True
    assert result.reason == "reconciliation_failed"
    assert result.issue["validation_status"] == "needs_review"
    assert "不能自动判定为已修复" in result.issue["validation_reasoning"]


def test_history_reconciler_updates_location_when_issue_still_exists() -> None:
    result = HistoryReconciler.reconcile_issue(
        {"id": "old-1", "location": "src/demo.c:42", "validation_status": "validated"},
        FakeResponse(True, {"still_exists": True, "new_location": "src/demo.c:57"}),
    )

    assert result.keep is True
    assert result.reason == "still_exists"
    assert result.issue["location"] == "src/demo.c:57"


def test_history_reconciler_keeps_llm_fix_suggestion_for_review() -> None:
    result = HistoryReconciler.reconcile_issue(
        {"id": "old-1", "location": "src/demo.c:42", "validation_status": "validated"},
        FakeResponse(
            True,
            {
                "still_exists": False,
                "reasoning": "A new guard appears before the sink.",
            },
        ),
    )

    assert result.keep is True
    assert result.reason == "fix_suggested_needs_review"
    assert result.issue["validation_status"] == "needs_review"
    assert result.issue["candidate_disposition"] == "needs_review"
    assert result.issue["historical_fix_suggestion"]["advisory_only"] is True
