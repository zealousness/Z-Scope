"""Final report assembly and persistence helpers."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable, Dict, List, Optional, cast

from ..core.validation.pipeline import preserve_issue_location
from ..orchestration.candidate_envelope import annotate_issue_collection
from ..reporting.report import FinalReport, Issue, ReportGenerator
from ..reporting.schema import (
    REPORT_SCHEMA_VERSION,
    build_run_manifest,
    coalesce_terminal_candidates,
    completeness_status,
    engine_failure_terminal_states,
    finding_status,
    needs_review_count,
    scan_outcome,
    terminal_candidate_identity,
)
from ..reporting.views import (
    build_report_views,
    report_view_summary,
    review_governance_summary,
)
from ..snapshots.store import SnapshotStore


IssueResolver = Callable[[List[Dict[str, Any]]], None]
ObservationDeduper = Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]]
ReportIssueDeduper = Callable[[List[Dict[str, Any]], Dict[str, Any]], List[Dict[str, Any]]]
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
        deduplicate_report_issues: Optional[ReportIssueDeduper] = None,
        metadata_factory: MetadataFactory,
    ) -> None:
        self.report_generator = report_generator
        self.snapshot_store = snapshot_store
        self.resolve_issue_locations = resolve_issue_locations
        self.deduplicate_observations = deduplicate_observations
        self.deduplicate_report_issues = deduplicate_report_issues
        self.metadata_factory = metadata_factory

    def build(self, state: Dict[str, Any]) -> FinalReport:
        metadata = self.metadata_factory(state)
        all_issues = state.get("issues", []) + state.get("verified_hist_issues", [])
        observations = list(state.get("observations", []))
        observations.extend(
            self._unresolved_candidate_observations(
                state,
                list(all_issues) + observations,
            )
        )
        state["observations"] = observations
        identity_kwargs = {
            "project_id": str(
                metadata.get("project_id")
                or metadata.get("repo")
                or metadata.get("project_root")
                or ""
            ),
            "project_root": str(
                metadata.get("repo") or metadata.get("project_root") or ""
            ),
            "revision": str(metadata.get("commit_sha") or metadata.get("source_revision") or ""),
            "entry_function": str(
                state.get("entry_identity")
                or state.get("entry_func")
                or ""
            ),
            "run_id": str(state.get("run_id") or metadata.get("run_id") or ""),
        }
        annotate_issue_collection(
            [issue for issue in all_issues if isinstance(issue, dict)],
            default_disposition="confirmed",
            **identity_kwargs,
        )
        annotate_issue_collection(
            [issue for issue in observations if isinstance(issue, dict)],
            default_disposition="needs_review",
            **identity_kwargs,
        )
        self.resolve_issue_locations(all_issues)
        if self.deduplicate_report_issues:
            all_issues = self.deduplicate_report_issues(all_issues, state)
            state["_deduped_report_issues"] = all_issues
        self.resolve_issue_locations(observations)
        for observation in observations:
            preserve_issue_location(observation)
        if observations:
            state["observations"] = self.deduplicate_observations(observations)
        if state.get("observations"):
            state["notes"].append(
                f"Kept {len(state.get('observations', []))} non-reportable candidate(s) "
                "as audit observations; they are excluded from the default vulnerability report."
            )

        verdict = self._overall_verdict(state, all_issues)
        finding = finding_status(all_issues, state.get("observations", []))
        terminal_states = self._candidate_terminal_states(
            state,
            all_issues,
            state.get("observations", []),
        )
        for item in engine_failure_terminal_states(
            state.get("engine_capabilities") or {},
            scope=str(state.get("entry_identity") or state.get("entry_func") or ""),
        ):
            identity = str(item.get("occurrence_uid") or item.get("candidate_uid") or "")
            if not identity or not any(
                identity
                == str(
                    existing.get("occurrence_uid")
                    or existing.get("candidate_uid")
                    or ""
                )
                for existing in terminal_states
            ):
                terminal_states.append(item)
        if finding == "clean" and any(
            str(item.get("candidate_disposition") or "").lower()
            == "needs_review"
            for item in terminal_states
        ):
            finding = "needs_review"
        completeness = completeness_status(
            state,
            list(all_issues) + list(state.get("observations", [])) + terminal_states,
        )
        review_count = needs_review_count(
            state.get("observations", []),
            terminal_states,
        )
        governance = review_governance_summary(
            list(state.get("observations", [])) + terminal_states,
        )
        final_report = FinalReport(
            entry_function=state["entry_func"],
            overall_verdict=verdict,
            issues=self._issue_objects(all_issues, state["entry_func"]),
            notes=state["notes"],
            schema_version=REPORT_SCHEMA_VERSION,
            finding_status=finding,
            completeness=completeness,
            scan_outcome=scan_outcome(finding, completeness),
            run_manifest=build_run_manifest(
                metadata,
                entry_function=str(state.get("entry_func") or ""),
                finding=finding,
                completeness=completeness,
                issue_count=len(all_issues),
                needs_review_count=review_count,
                review_governance=governance,
            ),
            candidate_terminal_states=terminal_states,
            needs_review_governance=governance,
        )
        final_report.metadata = metadata
        self.refresh(final_report, state)
        state["final_report"] = final_report
        return final_report

    def refresh(self, final_report: FinalReport, state: Dict[str, Any]) -> None:
        final_report.metadata = self.metadata_factory(state)
        if not final_report.report_views:
            final_report.report_views = build_report_views(
                state.get("_deduped_report_issues")
                or (state.get("issues", []) + state.get("verified_hist_issues", [])),
                state.get("observations", []),
            )
        with_review = final_report.report_views.get("with_needs_review", {})
        governance = (
            with_review.get("needs_review_governance")
            if isinstance(with_review, dict)
            else None
        )
        if isinstance(governance, dict):
            governance = dict(governance)
            governance["operational_obligation_count"] = max(
                int(governance.get("operational_obligation_count") or 0),
                int(
                    final_report.needs_review_governance.get(
                        "operational_obligation_count"
                    )
                    or 0
                ),
            )
            final_report.needs_review_governance = governance
            final_report.run_manifest.update(
                {
                    key: governance.get(key, 0)
                    for key in (
                        "raw_occurrence_count",
                        "raw_projection_count",
                        "unique_security_obligation_count",
                        "operational_obligation_count",
                        "displayed_review_count",
                        "grouped_alias_count",
                        "attached_to_confirmed_count",
                        "validation_not_completed_count",
                        "pending_validation_count",
                    )
                }
            )
            final_report.run_manifest["needs_review_count"] = int(
                governance.get("displayed_review_count") or 0
            )
            final_report.run_manifest["unresolved_obligation_count"] = int(
                governance.get("displayed_review_count") or 0
            ) + int(governance.get("operational_obligation_count") or 0)
        final_report.metadata["report_view_summary"] = report_view_summary(final_report.to_dict())

    def persist(self, state: Dict[str, Any], *, write_root_reports: bool = True) -> Dict[str, Any]:
        final_report = state["final_report"]
        self.refresh(final_report, state)
        if write_root_reports:
            self.report_generator.save_json_report(final_report)
            self.report_generator.save_markdown_report(final_report)

        report_dict = cast(Dict[str, Any], final_report.to_dict())
        if self.snapshot_store:
            self.snapshot_store.save_final_report(
                state["entry_index_name"],
                report_dict,
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

    @staticmethod
    def _candidate_terminal_states(
        state: Dict[str, Any],
        issues: List[Any],
        observations: List[Any],
    ) -> List[Dict[str, Any]]:
        terminal: List[Dict[str, Any]] = []

        def append_item(item: Dict[str, Any]) -> None:
            if str(item.get("record_role") or "") == "triage_lead":
                return
            normalized = ReportAssembler._terminalize_candidate_item(item)
            terminal.append(
                {
                    key: normalized.get(key)
                    for key in (
                        "candidate_schema_version",
                        "candidate_uid",
                        "occurrence_uid",
                        "history_key",
                        "evidence_hash",
                        "decision_evidence_hash",
                        "provenance_hash",
                        "provenance_hashes",
                        "evidence_hashes",
                        "validation_cluster_uid",
                        "context_signature",
                        "validation_contexts",
                        "occurrence_uids",
                        "alias_occurrence_uids",
                        "occurrences",
                        "occurrence_count",
                        "grouped_alias_count",
                        "entry_count",
                        "entries",
                        "entry_paths",
                        "record_role",
                        "candidate_id",
                        "dedup_key",
                        "candidate_disposition",
                        "status",
                        "function_name",
                        "entry_identity",
                        "file_path",
                        "signature",
                        "deferred_reason",
                        "reason",
                        "engine",
                        "parent",
                        "sources",
                        "call_paths",
                        "duplicate_count",
                        "engine_status",
                        "function",
                        "location",
                        "line",
                        "category",
                        "subcategory",
                        "defect_class",
                        "description",
                        "root_cause",
                        "impact_level",
                        "confidence",
                        "validation_status",
                        "evidence_pack",
                        "evidence_refs",
                    )
                    if normalized.get(key) not in (None, "", [], {})
                }
            )

        for item in list(issues) + list(observations):
            if isinstance(item, dict):
                append_item(item)
        for item in state.get("deferred_deterministic_work", []):
            if isinstance(item, dict):
                append_item(item)

        snapshot = state.get("candidate_lifecycle_snapshot")
        if isinstance(snapshot, dict):
            for value in snapshot.get("records", []):
                if isinstance(value, dict):
                    append_item(value)
        return [
            dict(item)
            for item in coalesce_terminal_candidates(terminal)
            if isinstance(item, dict)
        ]

    @staticmethod
    def _terminalize_candidate_item(item: Dict[str, Any]) -> Dict[str, Any]:
        value = dict(item)
        disposition = str(
            value.get("candidate_disposition")
            or value.get("disposition")
            or ""
        ).lower()
        status = str(value.get("status") or "").lower()
        terminal_statuses = {
            "confirmed",
            "rejected_with_proof",
            "needs_review",
            "deferred_budget",
            "engine_failed",
            "interrupted",
            "deduplicated_alias",
        }
        if disposition not in terminal_statuses:
            disposition = (
                status if status in terminal_statuses else "needs_review"
            )
        if status not in terminal_statuses:
            prior_status = status
            status = disposition
            if prior_status:
                value.setdefault("reason", f"nonterminal_status:{prior_status}")
            elif disposition == "needs_review":
                value.setdefault("reason", "validation_not_completed")
        value["candidate_disposition"] = disposition
        value["status"] = status
        if disposition == "needs_review":
            value.setdefault("validation_status", "needs_review")
        elif disposition in {"deferred_budget", "engine_failed", "interrupted"}:
            value.setdefault("validation_status", "operational")
            value.setdefault("record_role", "operational_obligation")
        return value

    @staticmethod
    def _unresolved_candidate_observations(
        state: Dict[str, Any],
        represented_items: List[Any],
    ) -> List[Dict[str, Any]]:
        """Route every unresolved ledger record into an actionable review view."""

        represented: set[str] = set()
        for item in represented_items:
            if not isinstance(item, dict):
                continue
            identity = terminal_candidate_identity(item)
            if identity:
                represented.add(identity)

        observations: List[Dict[str, Any]] = []
        snapshot = state.get("candidate_lifecycle_snapshot")
        if not isinstance(snapshot, dict):
            return observations

        for raw in snapshot.get("records", []):
            if not isinstance(raw, dict):
                continue
            if str(raw.get("record_role") or "") != "validation_obligation":
                continue
            terminal = ReportAssembler._terminalize_candidate_item(raw)
            disposition = str(
                terminal.get("candidate_disposition") or ""
            ).lower()
            if disposition != "needs_review":
                continue
            identity = terminal_candidate_identity(terminal)
            if identity and identity in represented:
                continue

            ticket = raw.get("ticket") if isinstance(raw.get("ticket"), dict) else {}
            evidence = (
                ticket.get("evidence")
                if isinstance(ticket.get("evidence"), dict)
                else {}
            )
            payload = (
                evidence.get("candidate_payload")
                if isinstance(evidence.get("candidate_payload"), dict)
                else {}
            )
            observation = deepcopy(payload)
            for key in (
                "candidate_schema_version",
                "candidate_uid",
                "history_key",
                "evidence_hash",
                "decision_evidence_hash",
                "provenance_hash",
                "provenance_hashes",
                "evidence_hashes",
                "validation_cluster_uid",
                "context_signature",
                "validation_contexts",
                "occurrence_uids",
                "alias_occurrence_uids",
                "occurrences",
                "occurrence_count",
                "grouped_alias_count",
                "entry_count",
                "entries",
                "entry_paths",
                "record_role",
                "candidate_id",
                "dedup_key",
                "sources",
                "call_paths",
                "duplicate_count",
            ):
                if terminal.get(key) not in (None, "", [], {}):
                    observation[key] = deepcopy(terminal[key])
            occurrence_uids = observation.get("occurrence_uids")
            if (
                not observation.get("occurrence_uid")
                and isinstance(occurrence_uids, list)
                and len(occurrence_uids) == 1
            ):
                observation["occurrence_uid"] = occurrence_uids[0]

            function_name = str(
                observation.get("function")
                or evidence.get("function")
                or ((evidence.get("path") or {}).get("function")
                    if isinstance(evidence.get("path"), dict)
                    else "")
                or ""
            )
            if not function_name:
                call_paths = terminal.get("call_paths")
                if (
                    isinstance(call_paths, list)
                    and call_paths
                    and isinstance(call_paths[0], list)
                    and call_paths[0]
                ):
                    function_name = str(call_paths[0][-1])
            if function_name:
                observation.setdefault("function", function_name)

            line = int(observation.get("line") or ticket.get("line") or 0)
            file_path = str(
                observation.get("file_path")
                or observation.get("file")
                or ""
            )
            if not file_path:
                for endpoint in ("sink", "source"):
                    endpoint_value = evidence.get(endpoint)
                    if isinstance(endpoint_value, dict) and endpoint_value.get("file"):
                        file_path = str(endpoint_value["file"])
                        line = int(endpoint_value.get("line") or line or 0)
                        break
            if file_path:
                observation.setdefault("file_path", file_path)
                observation.setdefault(
                    "location",
                    f"{file_path}:{line}" if line else file_path,
                )
            if line:
                observation.setdefault("line", line)

            defect_class = str(
                observation.get("defect_class")
                or terminal.get("defect_class")
                or evidence.get("defect_class")
                or ticket.get("skill")
                or "security_review"
            )
            observation.setdefault("category", defect_class)
            observation.setdefault("subcategory", defect_class)
            observation.setdefault("defect_class", defect_class)
            observation.setdefault(
                "description",
                str(ticket.get("task") or "Candidate requires review."),
            )
            observation.setdefault(
                "root_cause",
                str(ticket.get("trigger") or "Validation did not reach a proof."),
            )
            priority = int(ticket.get("priority_score") or 0)
            observation.setdefault(
                "impact_level",
                "critical"
                if priority >= 90
                else "high"
                if priority >= 75
                else "medium"
                if priority >= 45
                else "low",
            )
            observation.setdefault(
                "confidence",
                round(max(0, min(100, priority)) / 100.0, 4),
            )
            observation["candidate_disposition"] = disposition
            observation["status"] = disposition
            observation["validation_status"] = "needs_review"
            observation.setdefault("finding_kind", "needs_review")
            observation["_ledger_projection"] = True
            observation.setdefault(
                "reason",
                terminal.get("reason") or "validation_not_completed",
            )
            compact_evidence = {
                key: deepcopy(value)
                for key, value in evidence.items()
                if key != "candidate_payload"
            }
            if compact_evidence:
                observation.setdefault("evidence_pack", compact_evidence)
            observation.setdefault(
                "id",
                str(
                    observation.get("candidate_id")
                    or observation.get("candidate_uid")
                    or "NEEDS_REVIEW"
                ),
            )
            if identity:
                represented.add(identity)
            observations.append(observation)
        return observations
