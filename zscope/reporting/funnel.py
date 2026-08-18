"""Product-owned Candidate Ledger funnel projection.

Benchmark scoring may consume this projection, but product reporting never imports
benchmark, truth, or scorer code.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from .attribution import FindingAttribution, finding_attribution_mapping_errors

CANDIDATE_FUNNEL_SCHEMA_VERSION = "zscope.candidate-funnel.v1"


def _as_dict(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def report_issues(report: Mapping[str, Any], view: str = "default") -> List[Dict[str, Any]]:
    views = report.get("report_views")
    if isinstance(views, Mapping):
        selected = views.get(view)
        if isinstance(selected, Mapping) and isinstance(selected.get("issues"), list):
            return [dict(item) for item in selected["issues"] if isinstance(item, Mapping)]
    raw = report.get("issues")
    return (
        [dict(item) for item in raw if isinstance(item, Mapping)] if isinstance(raw, list) else []
    )


def finding_attribution(issue: Mapping[str, Any]) -> Dict[str, Any]:
    explicit = issue.get("attribution") or issue.get("finding_attribution")
    if isinstance(explicit, Mapping):
        parsed = FindingAttribution.from_mapping(explicit)
        errors = finding_attribution_mapping_errors(explicit)
        return {
            "schema_version": parsed.to_dict()["schema_version"],
            "discovered_by": list(parsed.discovered_by) or ["unknown"],
            "decided_by": parsed.decided_by,
            "decision_level": parsed.decision_level,
            "attribution_inferred": False,
            "inferred": False,
            "valid": not errors,
            "errors": errors,
        }
    values = {
        str(value).strip().lower()
        for value in (
            issue.get("candidate_source"),
            issue.get("candidate_kind"),
            issue.get("finding_kind"),
        )
        if value
    }
    discovered = set()
    if any("hypothesis" in value for value in values):
        discovered.add("hypothesis_hunter")
    if any("backend" in value or value.startswith(("svf", "saber", "joern")) for value in values):
        discovered.add("backend_signal")
    if issue.get("rule") or issue.get("rule_id") or any("rule" in value for value in values):
        discovered.add("deterministic_rule")
    terminal = issue.get("terminal_authority_decision")
    decided = "proof_engine" if isinstance(terminal, Mapping) else "unresolved"
    return {
        "schema_version": "zscope.finding-attribution.v2",
        "discovered_by": sorted(discovered) or ["unknown"],
        "decided_by": decided,
        "decision_level": "V0" if decided == "proof_engine" else "none",
        "attribution_inferred": True,
        "inferred": True,
        "valid": True,
        "errors": [],
    }


def candidate_funnel(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Summarize candidate flow while keeping occurrence/group/finding units explicit."""

    manifest = _as_dict(report.get("run_manifest"))
    summary = _as_dict(report.get("summary"))
    validation_performance = _as_dict(summary.get("validation_performance"))
    governance = _as_dict(report.get("needs_review_governance"))
    raw_terminal = report.get("candidate_terminal_states")
    terminal = (
        [item for item in raw_terminal or [] if isinstance(item, dict)]
        if isinstance(raw_terminal, list)
        else []
    )
    issues = report_issues(dict(report), view="default")
    views = report.get("report_views")
    review_view = _as_dict(views.get("with_needs_review")) if isinstance(views, dict) else {}
    review_issues = review_view.get("issues")
    review_issues = (
        [item for item in review_issues if isinstance(item, dict)]
        if isinstance(review_issues, list)
        else []
    )

    def first_numeric(*sources: tuple[Mapping[str, Any], str]) -> tuple[Optional[int], str]:
        for owner, key in sources:
            value = owner.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return int(value), key
        return None, "unavailable"

    raw_occurrences, raw_source = first_numeric(
        (summary, "scan_level_raw_occurrence_count"),
        (manifest, "raw_occurrence_count"),
        (governance, "raw_occurrence_count"),
    )
    candidate_ids = {
        str(item.get("candidate_uid") or _as_dict(item.get("issue")).get("candidate_uid") or "")
        for item in terminal
        if str(item.get("candidate_uid") or _as_dict(item.get("issue")).get("candidate_uid") or "")
    }
    group_ids = {
        str(item.get("validation_cluster_uid") or "")
        for item in terminal
        if str(item.get("validation_cluster_uid") or "")
    }
    manifest_groups, manifest_group_source = first_numeric(
        (manifest, "canonical_validation_group_count"),
        (manifest, "unique_security_obligation_count"),
        (summary, "validation_group_count"),
    )
    canonical_groups = len(group_ids) if group_ids else manifest_groups
    canonical_source = "candidate_terminal_states" if group_ids else manifest_group_source

    by_decision: Dict[str, int] = {}
    by_decision_level: Dict[str, int] = {}
    by_discovery: Dict[str, int] = {}
    exclusive_by_discovery: Dict[str, int] = {}
    intersections: Dict[str, int] = {}
    reached_by_level: Dict[str, int] = {f"V{level}": 0 for level in range(5)}
    transition_counts: Dict[str, int] = {}
    drop_reasons: Dict[str, int] = {}
    v3_counts = {"eligible": 0, "entered": 0, "confirmed": 0}
    v3_by_source_terminal: Dict[str, int] = {}
    v3_by_risk_layer: Dict[str, Dict[str, int]] = {}
    v3_by_fact_kind: Dict[str, Dict[str, int]] = {}
    invoked_groups: set[str] = set()
    for index, item in enumerate(terminal):
        issue = {
            **_as_dict(item.get("issue")),
            **{key: value for key, value in item.items() if key != "issue"},
        }
        attribution = finding_attribution(issue)
        decision = str(attribution["decided_by"])
        by_decision[decision] = by_decision.get(decision, 0) + 1
        level = str(attribution["decision_level"])
        by_decision_level[level] = by_decision_level.get(level, 0) + 1
        history = issue.get("validator_pass_history")
        history = history if isinstance(history, list) else []
        history_passes = {
            str(entry.get("pass") or "") for entry in history if isinstance(entry, Mapping)
        }
        disposition = str(
            item.get("candidate_disposition")
            or issue.get("candidate_disposition")
            or item.get("status")
            or ""
        ).lower()
        schema_version = str(item.get("candidate_schema_version") or "").lower()
        reached: set[str] = set()
        if not (
            schema_version == "zscope.entry-candidate.v1"
            or (
                disposition in {"engine_failed", "interrupted", "deferred_budget"}
                and not issue.get("deterministic_prevalidation_decision")
                and not issue.get("validator_pass_history")
                and int(item.get("validation_attempt_count") or 0) == 0
            )
        ):
            reached.add("V0")
        if (
            int(
                item.get("validation_attempt_count") or issue.get("validator_invocation_count") or 0
            )
            > 0
            or decision == "validator_llm"
            or level in {"V1", "V2", "V3", "V4"}
            or "initial" in history_passes
        ):
            reached.add("V1")
        # V3 may follow V1 directly when deterministic fact resolution adds no
        # evidence delta.  A terminal V3 attribution therefore does not prove
        # that the stateless V2 model pass was reached.
        if level == "V2" or "evidence_recheck" in history_passes:
            reached.add("V2")
        if level in {"V3", "V4"} or "investigation_synthesis" in history_passes:
            reached.add("V3")
        if level == "V4" or str(issue.get("dynamic_reproduction_status") or ""):
            reached.add("V4")
        for reached_level in reached:
            reached_by_level[reached_level] += 1
        for current, following in zip(("V0", "V1", "V2", "V3"), ("V1", "V2", "V3", "V4")):
            if current in reached and following in reached:
                key = f"{current}->{following}"
                transition_counts[key] = transition_counts.get(key, 0) + 1
        if "V1" in reached and "V3" in reached and "V2" not in reached:
            transition_counts["V1->V3"] = transition_counts.get("V1->V3", 0) + 1
        terminal_level = (
            max(reached, key=lambda value: int(value[1:])) if reached else "pre_validation"
        )
        terminal_reason = str(
            issue.get("stop_reason")
            or _as_dict(issue.get("validator_policy_outcome")).get("stop_reason")
            or item.get("candidate_disposition")
            or decision
            or "unknown"
        )
        terminal_transition = f"{terminal_level}->terminal:{terminal_reason}"
        transition_counts[terminal_transition] = transition_counts.get(terminal_transition, 0) + 1
        drop_reasons[terminal_reason] = drop_reasons.get(terminal_reason, 0) + 1
        cluster = str(item.get("validation_cluster_uid") or f"terminal:{index}")
        if int(item.get("validation_attempt_count") or 0) > 0 or decision == "validator_llm":
            invoked_groups.add(cluster)
        for source in attribution["discovered_by"]:
            by_discovery[source] = by_discovery.get(source, 0) + 1
            key = f"{source}|{decision}"
            intersections[key] = intersections.get(key, 0) + 1
        if len(attribution["discovered_by"]) == 1:
            source = attribution["discovered_by"][0]
            exclusive_by_discovery[source] = exclusive_by_discovery.get(source, 0) + 1

        v3_eligibility = _as_dict(issue.get("validator_v3_eligibility"))
        v3_eligible = v3_eligibility.get("eligible") is True
        v3_entered = issue.get("validator_v3_entered") is True or "V3" in reached
        v3_confirmed = bool(
            v3_entered
            and (
                issue.get("validator_v3_confirmed") is True
                or disposition in {"confirmed", "validated"}
            )
        )
        if v3_eligible:
            v3_counts["eligible"] += 1
        if v3_entered:
            v3_counts["entered"] += 1
        if v3_confirmed:
            v3_counts["confirmed"] += 1
        if v3_entered:
            sources = attribution["discovered_by"] or ["unknown"]
            for source in sources:
                key = f"{source}|{disposition or 'unknown'}"
                v3_by_source_terminal[key] = v3_by_source_terminal.get(key, 0) + 1
        risk_layer = str(v3_eligibility.get("severity") or "unknown")
        risk_counts = v3_by_risk_layer.setdefault(
            risk_layer,
            {"eligible": 0, "entered": 0, "confirmed": 0},
        )
        if v3_eligible:
            risk_counts["eligible"] += 1
        if v3_entered:
            risk_counts["entered"] += 1
        if v3_confirmed:
            risk_counts["confirmed"] += 1
        raw_fact_kinds = v3_eligibility.get("required_fact_kinds")
        if not isinstance(raw_fact_kinds, list):
            closure = _as_dict(issue.get("v3_evidence_closure"))
            raw_fact_kinds = closure.get("resolved_fact_kinds")
        fact_kinds = (
            sorted({str(value) for value in raw_fact_kinds if str(value)})
            if isinstance(raw_fact_kinds, list)
            else []
        )
        for fact_kind in fact_kinds:
            fact_counts = v3_by_fact_kind.setdefault(
                fact_kind,
                {"eligible": 0, "entered": 0, "confirmed": 0},
            )
            if v3_eligible:
                fact_counts["eligible"] += 1
            if v3_entered:
                fact_counts["entered"] += 1
            if v3_confirmed:
                fact_counts["confirmed"] += 1

    unique_count: Optional[int] = len(candidate_ids) if candidate_ids else None
    if unique_count is None:
        unique_count, unique_source = first_numeric(
            (summary, "unique_candidate_count"),
            (manifest, "unique_security_obligation_count"),
        )
    else:
        unique_source = "candidate_terminal_states"

    def stage(count: Optional[int], *, unit: str, source: str) -> Dict[str, Any]:
        return {
            "count": count,
            "available": count is not None,
            "unit": unit,
            "source": source,
        }

    prevalidation = _as_dict(summary.get("deterministic_prevalidation"))
    v0_decision_count, v0_decision_source = first_numeric(
        (summary, "deterministic_prevalidation_total"),
        (prevalidation, "total"),
        (prevalidation, "candidate_count"),
        (validation_performance, "deterministic_prevalidation_decision_count"),
    )
    v0_count = reached_by_level.get("V0") if terminal else None
    v0_source = "candidate_terminal_states.lifecycle" if terminal else "unavailable"
    v1_count = len(invoked_groups) if terminal else None
    v2_count = reached_by_level.get("V2") if terminal else None
    v3_count = reached_by_level.get("V3") if terminal else None
    v4_count = reached_by_level.get("V4") if terminal else None

    return {
        "schema_version": CANDIDATE_FUNNEL_SCHEMA_VERSION,
        "stages": {
            "raw_occurrences": stage(
                raw_occurrences,
                unit="occurrence",
                source=raw_source,
            ),
            "unique_candidates": stage(
                unique_count,
                unit="candidate",
                source=unique_source,
            ),
            "canonical_validation_groups": stage(
                canonical_groups,
                unit="validation_group",
                source=canonical_source,
            ),
            "v0_prevalidation": stage(
                v0_count,
                unit="validation_group",
                source=v0_source,
            ),
            "v0_deterministic_decisions": stage(
                v0_decision_count,
                unit="validation_group",
                source=v0_decision_source,
            ),
            "v1_initial_decision": stage(
                v1_count,
                unit="validation_group",
                source="candidate_terminal_states.validator_pass_history",
            ),
            "v2_evidence_recheck": stage(
                v2_count,
                unit="validation_group",
                source="candidate_terminal_states.validator_pass_history",
            ),
            "v3_targeted_investigation": stage(
                v3_count,
                unit="validation_group",
                source="candidate_terminal_states.validator_pass_history",
            ),
            "v4_dynamic_reproduction": stage(
                v4_count,
                unit="validation_group",
                source="reserved_not_implemented",
            ),
            "validator_invoked_groups": stage(
                len(invoked_groups) if terminal else None,
                unit="validation_group",
                source="candidate_terminal_states.validation_attempt_count",
            ),
            "reported_findings": stage(
                len(issues),
                unit="finding",
                source="default_report_view",
            ),
            "reported_with_review": stage(
                len(review_issues) if review_view else None,
                unit="finding",
                source="with_needs_review_report_view",
            ),
        },
        "canonical_group_attribution": {
            "by_discovery": dict(sorted(by_discovery.items())),
            "exclusive_by_discovery": dict(sorted(exclusive_by_discovery.items())),
            "by_decision": dict(sorted(by_decision.items())),
            "by_decision_level": dict(sorted(by_decision_level.items())),
            "reached_by_level": dict(sorted(reached_by_level.items())),
            "transition_counts": dict(sorted(transition_counts.items())),
            "drop_reason": dict(sorted(drop_reasons.items())),
            "by_discovery_and_decision": dict(sorted(intersections.items())),
            "counting_contract": (
                "discovery counts overlap; decision counts are terminal and exclusive"
            ),
        },
        "v3_investigation": {
            **v3_counts,
            "by_source_terminal": dict(sorted(v3_by_source_terminal.items())),
            "by_risk_layer": {key: dict(value) for key, value in sorted(v3_by_risk_layer.items())},
            "by_fact_kind": {key: dict(value) for key, value in sorted(v3_by_fact_kind.items())},
            "unit": "validation_group",
        },
        "contract": {
            "linear_conversion_rates_valid": False,
            "reason": (
                "stages intentionally use occurrence, candidate, validation-group, and "
                "finding units; compare like units only"
            ),
        },
    }
