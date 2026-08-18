"""Final report assembly and persistence helpers."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Callable, Dict, List, Optional, cast

from ..core.validation.pipeline import preserve_issue_location
from ..orchestration.candidate_envelope import annotate_issue_collection
from ..reporting.report import FinalReport, Issue, ReportGenerator
from ..reporting.finding_roots import project_finding_roots
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


def _as_dict(value: Any) -> Dict[str, Any]:
    return cast(Dict[str, Any], value) if isinstance(value, dict) else {}


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
        trace_store = state.get("decision_trace_store")
        update_trace_identity = getattr(trace_store, "update_identity", None)
        if callable(update_trace_identity):
            update_trace_identity(
                {
                    "source_revision": str(
                        metadata.get("commit_sha") or metadata.get("source_revision") or ""
                    ),
                    "source_tree_hash": str(metadata.get("source_tree_hash") or ""),
                    "config_hash": str(metadata.get("config_hash") or ""),
                    "model_manifest_hash": str(metadata.get("model_manifest_hash") or ""),
                    "effective_rules_sha256": str(metadata.get("effective_rules_sha256") or ""),
                }
            )
        all_issues = state.get("issues", []) + state.get("verified_hist_issues", [])
        observations = list(state.get("observations", []))
        identity_kwargs = {
            "project_id": str(
                metadata.get("project_id")
                or metadata.get("repo")
                or metadata.get("project_root")
                or ""
            ),
            "project_root": str(metadata.get("repo") or metadata.get("project_root") or ""),
            "revision": str(metadata.get("commit_sha") or metadata.get("source_revision") or ""),
            "entry_function": str(state.get("entry_identity") or state.get("entry_func") or ""),
            "run_id": str(state.get("run_id") or metadata.get("run_id") or ""),
        }
        annotate_issue_collection(
            [issue for issue in all_issues if isinstance(issue, dict)],
            default_disposition="confirmed",
            project_id=identity_kwargs["project_id"],
            project_root=identity_kwargs["project_root"],
            revision=identity_kwargs["revision"],
            entry_function=identity_kwargs["entry_function"],
            run_id=identity_kwargs["run_id"],
        )
        canonical_outcomes = (
            self._canonical_outcome_items(state)
            if bool(state.get("canonical_outcome_projection_enabled", True))
            else None
        )
        if canonical_outcomes is not None:
            # A frozen group outcome, not an entry-local report, is the sole
            # authority for final security dispositions.  Keep raw projections
            # for diagnostics, but never let them add or override findings.
            state["raw_observations"] = list(observations)
            all_issues = [
                item
                for item in canonical_outcomes
                if str(item.get("candidate_disposition") or "").lower() == "confirmed"
            ]
            observations = [
                item
                for item in canonical_outcomes
                if str(item.get("candidate_disposition") or "").lower() == "needs_review"
            ]
            state["_canonical_report_issues"] = list(all_issues)
            state["_canonical_review_observations"] = list(observations)
            lifecycle = state.get("candidate_lifecycle_snapshot")
            lifecycle_summary = lifecycle.get("summary") if isinstance(lifecycle, dict) else {}
            if int((lifecycle_summary or {}).get("nonterminal_validation_count") or 0):
                state["completeness"] = "degraded"
                state["notes"].append(
                    "Validation lifecycle did not close; nonterminal groups were excluded from security findings."
                )
        else:
            observations.extend(
                self._unresolved_candidate_observations(
                    state,
                    list(all_issues) + observations,
                )
            )
        state["observations"] = observations
        annotate_issue_collection(
            [issue for issue in observations if isinstance(issue, dict)],
            default_disposition="needs_review",
            project_id=identity_kwargs["project_id"],
            project_root=identity_kwargs["project_root"],
            revision=identity_kwargs["revision"],
            entry_function=identity_kwargs["entry_function"],
            run_id=identity_kwargs["run_id"],
        )
        self.resolve_issue_locations(all_issues)
        if canonical_outcomes is None and self.deduplicate_report_issues:
            all_issues = self.deduplicate_report_issues(all_issues, state)
            state["_deduped_report_issues"] = all_issues
        elif canonical_outcomes is not None:
            # Each item is already the immutable projection of one validation
            # group.  Report-time semantic de-duplication is not allowed to
            # erase a distinct decision context.
            state["semantic_dedup_summary"] = {
                "enabled": False,
                "canonical_projection": True,
                "input_issue_count": len(all_issues),
                "output_issue_count": len(all_issues),
            }
        self.resolve_issue_locations(observations)
        for observation in observations:
            preserve_issue_location(observation)
        if observations and canonical_outcomes is None:
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
                == str(existing.get("occurrence_uid") or existing.get("candidate_uid") or "")
                for existing in terminal_states
            ):
                terminal_states.append(item)
        finalize_trace = getattr(trace_store, "finalize_issue", None)
        if callable(finalize_trace):
            for item in terminal_states:
                if item.get("decision_trace_ref"):
                    continue
                if not item.get("validation_cluster_uid"):
                    stable = terminal_candidate_identity(item) or str(item)
                    item["validation_cluster_uid"] = (
                        "VAL_ENGINE_" + hashlib.sha256(stable.encode("utf-8")).hexdigest()[:32]
                    )
                finalize_trace(item, view_memberships=("excluded",))
            snapshot_trace = getattr(trace_store, "snapshot", None)
            if callable(snapshot_trace):
                state["decision_trace_manifest"] = snapshot_trace()
        if finding == "clean" and any(
            str(item.get("candidate_disposition") or "").lower() == "needs_review"
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
        operational_terminal = [
            item
            for item in terminal_states
            if str(item.get("record_role") or "") == "operational_obligation"
            or str(item.get("candidate_disposition") or "").lower()
            in {"deferred_budget", "engine_failed", "interrupted"}
        ]
        governance = review_governance_summary(
            list(state.get("observations", [])) + operational_terminal,
            canonical_review=[
                item for item in state.get("observations", []) if isinstance(item, dict)
            ],
        )
        invariant_status = self._report_invariant_status(
            all_issues,
            state.get("observations", []),
            terminal_states,
            canonical_outcomes is not None,
        )
        if "validation_queue_drained" in state and not bool(state.get("validation_queue_drained")):
            invariant_status["valid"] = False
            invariant_status["validation_queue_drained"] = False
        else:
            invariant_status["validation_queue_drained"] = True
        state["report_invariant_status"] = invariant_status
        if not invariant_status["valid"]:
            state["completeness"] = "degraded"
            completeness = "degraded"
            state["notes"].append(
                "Report lifecycle invariants failed; scan is incomplete and diagnostic data was retained."
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
        final_report.run_manifest["canonical_validation_group_count"] = int(
            invariant_status["canonical_validation_group_count"]
        )
        final_report.run_manifest.update(
            {
                key: int(invariant_status.get(key) or 0)
                for key in (
                    "validation_group_alias_count",
                    "validator_invocation_count",
                    "rejected_with_proof_count",
                    "cluster_fragmentation_count",
                )
            }
        )
        final_report.run_manifest["report_invariant_status"] = invariant_status
        final_report.run_manifest["finding_root_count"] = int(
            state.get("finding_root_count", 0) or 0
        )
        final_report.run_manifest["finding_root_alias_count"] = int(
            state.get("finding_root_alias_count", 0) or 0
        )
        final_report.run_manifest["finding_root_projection"] = dict(
            state.get("finding_root_projection_summary") or {}
        )
        trace_manifest = state.get("decision_trace_manifest")
        if isinstance(trace_manifest, dict):
            final_report.run_manifest["decision_trace"] = {
                key: deepcopy(trace_manifest.get(key))
                for key in (
                    "schema_version",
                    "manifest_path",
                    "manifest_sha256",
                    "trace_count",
                    "coverage_trace_count",
                    "evidence_object_count",
                    "model_event_count",
                    "complete",
                    "errors",
                )
            }
        final_report.run_manifest.update(self._release_observability(state))
        self.refresh(final_report, state)
        state["final_report"] = final_report
        return final_report

    def refresh(self, final_report: FinalReport, state: Dict[str, Any]) -> None:
        final_report.metadata = self.metadata_factory(state)
        if not final_report.report_views:
            canonical_issues = state.get("_canonical_report_issues")
            canonical_observations = state.get("_canonical_review_observations")
            final_report.report_views = build_report_views(
                (
                    canonical_issues
                    if isinstance(canonical_issues, list)
                    else state.get("_deduped_report_issues")
                    or (state.get("issues", []) + state.get("verified_hist_issues", []))
                ),
                (
                    canonical_observations
                    if isinstance(canonical_observations, list)
                    else state.get("observations", [])
                ),
                canonical_projection=(
                    isinstance(canonical_issues, list) and isinstance(canonical_observations, list)
                ),
            )
        with_review = final_report.report_views.get("with_needs_review", {})
        governance = (
            with_review.get("needs_review_governance") if isinstance(with_review, dict) else None
        )
        if isinstance(governance, dict):
            governance = dict(governance)
            governance["operational_obligation_count"] = max(
                int(governance.get("operational_obligation_count") or 0),
                int(final_report.needs_review_governance.get("operational_obligation_count") or 0),
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
        # Keep the lifecycle funnel in the product artifact as well as the
        # benchmark score.  The local import avoids making reporting module
        # import-time initialization depend on the benchmark package.
        from ..benchmarking.protocol import candidate_funnel

        final_report.metadata["candidate_funnel"] = candidate_funnel(final_report.to_dict())

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
    def _release_observability(state: Dict[str, Any]) -> Dict[str, Any]:
        drained = bool(state.get("validation_queue_drained", False))
        invariant = state.get("report_invariant_status")
        invariant = invariant if isinstance(invariant, dict) else {}
        blockers: List[str] = []
        if not drained:
            blockers.append("validation_queue_not_drained")
        if invariant and not invariant.get("valid", False):
            blockers.append("report_invariant_failed")
        if str(state.get("budget_exhaustion_policy") or "observe") != "observe":
            blockers.append("budget_policy_not_observe_only")
        llm_usage = state.get("llm_usage")
        return {
            "validator_session_count": int(state.get("validator_session_count", 0) or 0),
            "validator_api_call_count": int(state.get("validator_api_call_count", 0) or 0),
            "validator_turn_distribution": dict(state.get("validator_turn_distribution") or {}),
            "validator_prompt_tokens_by_stage": dict(
                state.get("validator_prompt_tokens_by_stage") or {}
            ),
            "evidence_slice_token_count": int(state.get("evidence_slice_token_count", 0) or 0),
            "multi_turn_outlier_count": int(state.get("multi_turn_outlier_count", 0) or 0),
            "snapshot_model_call_count": int(state.get("snapshot_model_call_count", 0) or 0),
            "fact_query_cache_hit_count": int(state.get("fact_query_cache_hit_count", 0) or 0),
            "budget_exhaustion_policy": str(state.get("budget_exhaustion_policy") or "observe"),
            "validation_queue_drained": drained,
            "llm_usage": dict(llm_usage) if isinstance(llm_usage, dict) else {},
            "release_gate_status": {
                "runtime_valid": not blockers,
                "quality_evaluation_pending": True,
                "blockers": blockers,
            },
        }

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
        canonical = ReportAssembler._canonical_outcome_items(state)
        if canonical is not None:
            return [deepcopy(item) for item in canonical]

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
                        "obligation_uid",
                        "obligation_shape",
                        "decision_context_version",
                        "decision_fact_version",
                        "decision_fact_coverage",
                        "missing_fact_kinds",
                        "candidate_promotion_eligible",
                        "candidate_promotion_reason",
                        "candidate_promotion_terminal_status",
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
                        "candidate_kind",
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
                        "rule",
                        "rule_id",
                        "rule_engine",
                        "rule_revision",
                        "rule_source",
                        "rule_status",
                        "rule_catalog_version",
                        "rule_catalog_sha256",
                        "skill",
                        "signal_source",
                        "native_rule_id",
                        "parent",
                        "sources",
                        "call_paths",
                        "duplicate_count",
                        "engine_status",
                        "decision_proof",
                        "promotion_reason",
                        "proof_provider",
                        "proof_coverage",
                        "blocking_negative_evidence",
                        "deterministic_prevalidation_decision",
                        "validator_avoided",
                        "evidence_completion_status",
                        "evidence_completion_terminal_status",
                        "validation_group_alias_count",
                        "validator_invocation_count",
                        "rejected_with_proof_count",
                        "cluster_fragmentation_count",
                        "attribution",
                        "model_verdict",
                        "policy_disposition",
                        "validator_result_pass",
                        "validator_pass_history",
                        "validator_policy_outcome",
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
            dict(item) for item in coalesce_terminal_candidates(terminal) if isinstance(item, dict)
        ]

    @staticmethod
    def _terminalize_candidate_item(item: Dict[str, Any]) -> Dict[str, Any]:
        value = dict(item)
        disposition = str(
            value.get("candidate_disposition") or value.get("disposition") or ""
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
            "shadow_observation",
        }
        if disposition not in terminal_statuses:
            disposition = status if status in terminal_statuses else "needs_review"
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
    def _canonical_outcome_items(state: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        """Return canonical group outcomes when the lifecycle snapshot supports them."""

        snapshot = state.get("candidate_lifecycle_snapshot")
        if not isinstance(snapshot, dict) or "outcomes" not in snapshot:
            return None
        result: List[Dict[str, Any]] = []
        for raw in snapshot.get("outcomes") or []:
            if not isinstance(raw, dict):
                continue
            disposition = str(
                raw.get("terminal_disposition") or raw.get("candidate_disposition") or ""
            ).lower()
            if not disposition:
                continue
            issue = _as_dict(raw.get("issue"))
            value = deepcopy(issue)
            value.update(
                {
                    key: deepcopy(item)
                    for key, item in raw.items()
                    if key != "issue" and item not in (None, "", [], {})
                }
            )
            value["candidate_disposition"] = disposition
            value["status"] = str(value.get("status") or disposition)
            if disposition == "confirmed":
                value["validation_status"] = "validated"
            elif disposition == "needs_review":
                value["validation_status"] = "needs_review"
            elif disposition in {"engine_failed", "interrupted", "deferred_budget"}:
                value["record_role"] = "operational_obligation"
                value["validation_status"] = "operational"
            result.append(value)
        result.sort(key=lambda item: str(item.get("validation_cluster_uid") or ""))
        if bool(
            state.get(
                "finding_root_projection_enabled",
                state.get("finding_root_v1_enabled", False),
            )
        ):
            projection = project_finding_roots(result)
            state["finding_root_count"] = projection.finding_root_count
            state["finding_root_alias_count"] = projection.finding_root_alias_count
            state["finding_root_projection_summary"] = dict(projection.summary)
            result = list(projection.outcomes)
        trace_store = state.get("decision_trace_store")
        finalize_issue = getattr(trace_store, "finalize_issue", None)
        if callable(finalize_issue):
            for item in result:
                disposition = str(item.get("candidate_disposition") or "").lower()
                memberships: List[str] = []
                if disposition == "confirmed":
                    memberships = ["default", "with_needs_review"]
                elif disposition == "needs_review":
                    memberships = ["with_needs_review"]
                else:
                    memberships = ["excluded"]
                finalize_issue(item, view_memberships=memberships)
            snapshot = getattr(trace_store, "snapshot", None)
            if callable(snapshot):
                state["decision_trace_manifest"] = snapshot()
        return result

    @staticmethod
    def _report_invariant_status(
        issues: List[Any],
        observations: List[Any],
        terminal_states: List[Dict[str, Any]],
        canonical_enabled: bool,
    ) -> Dict[str, Any]:
        default_count = sum(1 for item in issues if isinstance(item, dict))
        review_count = sum(
            1
            for item in observations
            if isinstance(item, dict)
            and str(item.get("candidate_disposition") or "").lower() == "needs_review"
        )
        terminal_confirmed = sum(
            1
            for item in terminal_states
            if str(item.get("candidate_disposition") or "").lower() == "confirmed"
        )
        terminal_review = sum(
            1
            for item in terminal_states
            if str(item.get("candidate_disposition") or "").lower() == "needs_review"
        )
        reportable_terminal_states = [
            item
            for item in terminal_states
            if str(item.get("candidate_disposition") or "").lower() != "shadow_observation"
        ]
        clusters = {
            str(item.get("validation_cluster_uid") or "")
            for item in reportable_terminal_states
            if item.get("validation_cluster_uid")
        }
        security_terminal_count = sum(
            1
            for item in reportable_terminal_states
            if str(item.get("record_role") or "") != "operational_obligation"
        )
        terminal_items = [item for item in terminal_states if isinstance(item, dict)]
        open_completion_count = sum(
            1
            for item in terminal_items
            if str(item.get("evidence_completion_status") or "").lower()
            in {"requested", "running", "queued"}
            or str(item.get("evidence_completion_terminal_status") or "").lower()
            in {"requested", "running", "queued"}
        )
        open_validation_count = sum(
            1
            for item in terminal_items
            if str(item.get("status") or "").lower() in {"pending", "queued", "planned", "running"}
        )
        obligation_uids = {
            str(item.get("obligation_uid") or item.get("candidate_uid") or "")
            for item in reportable_terminal_states
            if str(item.get("record_role") or "") != "operational_obligation"
        }
        valid = not canonical_enabled or (
            default_count == terminal_confirmed
            and review_count == terminal_review
            and len(clusters) == security_terminal_count
            and open_completion_count == 0
            and open_validation_count == 0
        )
        return {
            "valid": valid,
            "canonical_projection": canonical_enabled,
            "default_confirmed_count": default_count,
            "terminal_confirmed_count": terminal_confirmed,
            "displayed_review_count": review_count,
            "terminal_review_count": terminal_review,
            "shadow_observation_count": sum(
                1
                for item in terminal_states
                if str(item.get("candidate_disposition") or "").lower() == "shadow_observation"
            ),
            "canonical_validation_group_count": len(clusters),
            "validation_group_alias_count": sum(
                len(item.get("alias_occurrence_uids") or []) for item in terminal_items
            ),
            "validator_invocation_count": sum(
                int(item.get("validation_attempt_count") or 0) for item in terminal_items
            ),
            "rejected_with_proof_count": sum(
                1
                for item in terminal_items
                if str(item.get("candidate_disposition") or "").lower() == "rejected_with_proof"
            ),
            "cluster_fragmentation_count": max(0, len(clusters) - len(obligation_uids)),
            "open_evidence_completion_count": open_completion_count,
            "open_validation_group_count": open_validation_count,
        }

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
            disposition = str(terminal.get("candidate_disposition") or "").lower()
            if disposition != "needs_review":
                continue
            identity = terminal_candidate_identity(terminal)
            if identity and identity in represented:
                continue

            ticket = _as_dict(raw.get("ticket"))
            evidence = _as_dict(ticket.get("evidence"))
            payload = _as_dict(evidence.get("candidate_payload"))
            observation = deepcopy(payload)
            for key in (
                "candidate_schema_version",
                "candidate_uid",
                "obligation_uid",
                "obligation_shape",
                "decision_context_version",
                "decision_fact_version",
                "decision_fact_coverage",
                "missing_fact_kinds",
                "candidate_promotion_eligible",
                "candidate_promotion_reason",
                "candidate_promotion_terminal_status",
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
                "decision_proof",
                "promotion_reason",
                "proof_provider",
                "proof_coverage",
                "blocking_negative_evidence",
                "deterministic_prevalidation_decision",
                "validator_avoided",
                "evidence_completion_status",
                "evidence_completion_terminal_status",
                "validation_group_alias_count",
                "validator_invocation_count",
                "rejected_with_proof_count",
                "cluster_fragmentation_count",
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

            evidence_path = _as_dict(evidence.get("path"))
            function_name = str(
                observation.get("function")
                or evidence.get("function")
                or evidence_path.get("function")
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
            file_path = str(observation.get("file_path") or observation.get("file") or "")
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
                (
                    "critical"
                    if priority >= 90
                    else "high" if priority >= 75 else "medium" if priority >= 45 else "low"
                ),
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
