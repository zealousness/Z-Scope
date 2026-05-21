"""Final report assembly and persistence helpers."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, cast

from ..reporting.report import FinalReport, Issue, ReportGenerator
from ..reporting.views import build_report_views, report_view_summary
from ..snapshots.store import SnapshotStore


IssueResolver = Callable[[List[Dict[str, Any]]], None]
ObservationDeduper = Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]]
MetadataFactory = Callable[[Dict[str, Any]], Dict[str, Any]]


class ReportAssembler:
    """Build and persist final reports from workflow state."""

    def __init__(
        self,
        report_generator: ReportGenerator,
        snapshot_store: Optional[SnapshotStore],
        *,
        resolve_issue_locations: IssueResolver,
        deduplicate_observations: ObservationDeduper,
        metadata_factory: MetadataFactory,
    ) -> None:
        self.report_generator = report_generator
        self.snapshot_store = snapshot_store
        self.resolve_issue_locations = resolve_issue_locations
        self.deduplicate_observations = deduplicate_observations
        self.metadata_factory = metadata_factory

    def build(self, state: Dict[str, Any]) -> FinalReport:
        all_issues = state.get("issues", []) + state.get("verified_hist_issues", [])
        self.resolve_issue_locations(all_issues)
        observations = state.get("observations", [])
        self.resolve_issue_locations(observations)
        if observations:
            state["observations"] = self.deduplicate_observations(observations)
        if state.get("observations"):
            state["notes"].append(
                f"Kept {len(state.get('observations', []))} non-reportable candidate(s) "
                "as audit observations; they are excluded from the default vulnerability report."
            )

        verdict = self._overall_verdict(state, all_issues)
        final_report = FinalReport(
            entry_function=state["entry_func"],
            overall_verdict=verdict,
            issues=self._issue_objects(all_issues, state["entry_func"]),
            notes=state["notes"],
        )
        self.refresh(final_report, state)
        state["final_report"] = final_report
        return final_report

    def refresh(self, final_report: FinalReport, state: Dict[str, Any]) -> None:
        final_report.metadata = self.metadata_factory(state)
        if not final_report.report_views:
            final_report.report_views = build_report_views(
                state.get("issues", []) + state.get("verified_hist_issues", []),
                state.get("observations", []),
            )
        final_report.metadata["report_view_summary"] = report_view_summary(final_report.to_dict())

    def persist(self, state: Dict[str, Any]) -> Dict[str, Any]:
        final_report = state["final_report"]
        self.refresh(final_report, state)
        self.report_generator.save_json_report(final_report)
        self.report_generator.save_markdown_report(final_report)

        report_dict = cast(Dict[str, Any], final_report.to_dict())
        if self.snapshot_store:
            self.snapshot_store.save_final_report(
                state["entry_func"],
                report_dict,
                state["agent_context"]["location"],
            )
        return report_dict

    def finalize_returned_report(self, state: Dict[str, Any]) -> Dict[str, Any]:
        report_dict = dict(state["final_report_dict"])
        metadata = dict(report_dict.get("metadata") or {})
        metadata.update(self.metadata_factory(state))
        report_dict["metadata"] = metadata
        return report_dict

    @staticmethod
    def _overall_verdict(state: Dict[str, Any], all_issues: List[Any]) -> str:
        if state.get("any_failure") and not all_issues:
            state["notes"].append(
                f"Analysis incomplete due to agent failure: {state.get('failure_msg', '')}"
            )
            return "error"
        return "issues_found" if all_issues else "no_issue_found"

    @staticmethod
    def _issue_objects(all_issues: List[Any], entry_func: str) -> List[Issue]:
        issues = [
            Issue.from_dict(issue, context_function=entry_func, issue_index=idx + 1)
            for idx, issue in enumerate(all_issues)
            if isinstance(issue, dict)
        ]
        return issues or [issue for issue in all_issues if isinstance(issue, Issue)]
