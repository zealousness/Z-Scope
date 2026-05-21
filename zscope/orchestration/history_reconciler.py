"""History loading and issue reconciliation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


ACTIVE_HISTORICAL_STATUSES = {"validated", "pending"}


@dataclass
class ReconciledHistoricalIssue:
    """Result of checking one historical issue against changed code."""

    keep: bool
    issue: Optional[Dict[str, Any]] = None
    reason: str = ""


class HistoryReconciler:
    """Owns snapshot history partitioning and reconciliation semantics."""

    def __init__(self, snapshot_store: Any = None, force_ignore_history: bool = False):
        self.snapshot_store = snapshot_store
        self.force_ignore_history = force_ignore_history

    def load_state(self, entry_func: str, impl_result: Dict[str, Any]) -> Dict[str, Any]:
        historical_report = None
        if self.snapshot_store and not self.force_ignore_history:
            historical_report = self.snapshot_store.load_final_report(entry_func, impl_result["file"])

        hist_issues = historical_report.get("issues", []) if historical_report else []
        valid_hist_issues, user_rejected_hist_issues = self.partition_issues(hist_issues)

        needs_refresh = True
        reason = "no_snapshot"
        if self.snapshot_store and not self.force_ignore_history:
            needs_refresh, reason_value = self.snapshot_store.needs_refresh(
                entry_func,
                impl_result["code"],
                impl_result["file"],
            )
            reason = str(reason_value)

        return {
            "historical_report": historical_report,
            "valid_hist_issues": valid_hist_issues,
            "user_rejected_hist_issues": user_rejected_hist_issues,
            "needs_refresh": needs_refresh,
            "refresh_reason": reason,
            "is_code_unchanged": (not needs_refresh and reason != "no_snapshot"),
            "history_loaded": True,
        }

    @staticmethod
    def partition_issues(
        hist_issues: List[Dict[str, Any]],
    ) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        valid_hist_issues = [
            issue
            for issue in hist_issues
            if issue.get("validation_status") in ACTIVE_HISTORICAL_STATUSES
        ]
        user_rejected_hist_issues = [
            issue
            for issue in hist_issues
            if issue.get("validation_status") == "rejected"
            and issue.get("rejection_source") == "user"
        ]
        return valid_hist_issues, user_rejected_hist_issues

    @staticmethod
    def reconcile_issue(
        hist_issue: Dict[str, Any],
        response: Any,
    ) -> ReconciledHistoricalIssue:
        if response.success and response.data.get("still_exists"):
            updated = dict(hist_issue)
            updated["location"] = response.data.get("new_location", updated.get("location"))
            return ReconciledHistoricalIssue(keep=True, issue=updated, reason="still_exists")
        if not response.success:
            updated = dict(hist_issue)
            updated["validation_status"] = "needs_review"
            updated["validation_reasoning"] = (
                "历史问题复核失败，不能自动判定为已修复；请人工复核。"
            )
            return ReconciledHistoricalIssue(
                keep=True,
                issue=updated,
                reason="reconciliation_failed",
            )
        return ReconciledHistoricalIssue(keep=False, reason="fixed")
