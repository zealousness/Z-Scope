"""Answer-free metric reducers used by the isolated P6 cold producer.

This module intentionally contains no Truth matcher, scorer entry point, review
decision reader, or post-score quality logic.  The host-side cold producer can
therefore compute its usage ledger and lifecycle counters from the frozen scan
report while the scorer implementation is physically absent from its source
tree.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Sequence


USAGE_LEDGER_SCHEMA_VERSION = "zscope.llm-usage-ledger.v1"
CANDIDATE_FUNNEL_SCHEMA_VERSION = "zscope.candidate-funnel.v1"


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def aggregate_p6_producer_usage_ledger(
    report: Mapping[str, Any],
    *,
    usage_spans: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Aggregate response-boundary usage without importing the Truth scorer."""

    raw_spans = list(usage_spans)
    errors: list[str] = []
    seen: set[str] = set()
    totals = {
        "prompt_tokens": 0,
        "cached_prompt_tokens": 0,
        "completion_tokens": 0,
        "reasoning_tokens": 0,
        "total_tokens": 0,
        "tool_call_count": 0,
        "new_fact_count": 0,
    }
    by_agent: Dict[str, Dict[str, int]] = {}
    by_stage: Dict[str, Dict[str, int]] = {}
    provider_reported = 0
    finish_reasons: Dict[str, int] = {}

    def normalized_values(span: Mapping[str, Any], *, index: int) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for key in totals:
            value = span.get(key, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                errors.append(f"span[{index}].{key} must be a non-negative integer")
                value = 0
            result[key] = value
        return result

    def add(target: Dict[str, int], values: Mapping[str, int]) -> None:
        for key, value in values.items():
            target[key] = target.get(key, 0) + value

    for index, raw in enumerate(raw_spans):
        if not isinstance(raw, dict):
            errors.append(f"span[{index}] is not an object")
            continue
        call_id = str(raw.get("call_id") or "")
        if not call_id:
            errors.append(f"span[{index}] has no call_id")
            continue
        if call_id in seen:
            errors.append(f"duplicate call_id: {call_id}")
            continue
        seen.add(call_id)
        values = normalized_values(raw, index=index)
        for required_key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            if required_key not in raw:
                errors.append(f"span[{index}] has no {required_key}")
        add(totals, values)
        agent = str(raw.get("agent") or "")
        stage = str(raw.get("stage") or "")
        if not agent:
            errors.append(f"span[{index}] has no agent")
            agent = "unknown"
        if not stage:
            errors.append(f"span[{index}] has no stage")
            stage = "unknown"
        add(by_agent.setdefault(agent, {}), values)
        add(by_stage.setdefault(stage, {}), values)
        provider_reported += int(
            raw.get("provider_reported") is True or raw.get("estimated") is False
        )
        if raw.get("provider_reported") is not True and raw.get("estimated") is not False:
            errors.append(f"span[{index}] is not provider-reported")
        finish = str(raw.get("finish_reason") or "")
        if not finish:
            errors.append(f"span[{index}] has no finish_reason")
            finish = "unknown"
        finish_reasons[finish] = finish_reasons.get(finish, 0) + 1
        expected_total = values["prompt_tokens"] + values["completion_tokens"]
        if values["total_tokens"] != expected_total:
            errors.append(f"span[{index}] total_tokens does not equal prompt+completion")
        if values["cached_prompt_tokens"] > values["prompt_tokens"]:
            errors.append(f"span[{index}] cached_prompt_tokens exceeds prompt_tokens")

    conservation = all(
        totals[key]
        == sum(row.get(key, 0) for row in by_agent.values())
        == sum(row.get(key, 0) for row in by_stage.values())
        for key in totals
    )
    if not conservation:
        errors.append("usage aggregation does not conserve totals")
    call_count = len(seen)
    return {
        "schema_version": USAGE_LEDGER_SCHEMA_VERSION,
        "source": "response_usage_spans",
        "present": bool(raw_spans),
        "complete": bool(raw_spans) and not errors and provider_reported == call_count,
        "call_count": call_count,
        "provider_reported_call_count": provider_reported,
        "provider_usage_coverage": round(
            provider_reported / call_count if call_count else 0.0,
            4,
        ),
        "totals": totals,
        "by_agent": by_agent,
        "by_stage": by_stage,
        "finish_reasons": finish_reasons,
        "conservation_passed": conservation,
        "telemetry_complete": bool(raw_spans) and not errors,
        "errors": list(dict.fromkeys(errors)),
    }


def p6_producer_candidate_funnel(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Project only answer-free lifecycle counts needed by P6 freeze.

    The post-freeze scorer retains the richer cross-Truth funnel.  This
    projection deliberately uses only terminal lifecycle telemetry already in
    the product report.
    """

    raw_terminal = report.get("candidate_terminal_states")
    terminal = (
        [item for item in raw_terminal if isinstance(item, dict)]
        if isinstance(raw_terminal, list)
        else []
    )
    views = report.get("report_views")
    default_view = _as_dict(views.get("default")) if isinstance(views, dict) else {}
    review_view = _as_dict(views.get("with_needs_review")) if isinstance(views, dict) else {}
    default_issues = default_view.get("issues")
    review_issues = review_view.get("issues")
    counts = {"eligible": 0, "entered": 0, "confirmed": 0}
    by_fact_kind: Dict[str, Dict[str, int]] = {}
    for item in terminal:
        issue = {
            **_as_dict(item.get("issue")),
            **{key: value for key, value in item.items() if key != "issue"},
        }
        eligibility = _as_dict(issue.get("validator_v3_eligibility"))
        history = issue.get("validator_pass_history")
        history_passes = {
            str(entry.get("pass") or "") for entry in history or [] if isinstance(entry, Mapping)
        }
        decision_level = str(
            _as_dict(issue.get("attribution") or issue.get("finding_attribution")).get(
                "decision_level"
            )
            or ""
        )
        disposition = str(
            item.get("candidate_disposition")
            or issue.get("candidate_disposition")
            or item.get("status")
            or ""
        ).lower()
        eligible = eligibility.get("eligible") is True
        entered = bool(
            issue.get("validator_v3_entered") is True
            or "investigation_synthesis" in history_passes
            or decision_level in {"V3", "V4"}
        )
        confirmed = bool(
            entered
            and (
                issue.get("validator_v3_confirmed") is True
                or disposition in {"confirmed", "validated"}
            )
        )
        counts["eligible"] += int(eligible)
        counts["entered"] += int(entered)
        counts["confirmed"] += int(confirmed)
        raw_fact_kinds = eligibility.get("required_fact_kinds")
        if not isinstance(raw_fact_kinds, list):
            raw_fact_kinds = _as_dict(issue.get("v3_evidence_closure")).get("resolved_fact_kinds")
        fact_kinds = (
            sorted({str(value) for value in raw_fact_kinds if str(value)})
            if isinstance(raw_fact_kinds, list)
            else []
        )
        for fact_kind in fact_kinds:
            row = by_fact_kind.setdefault(
                fact_kind,
                {"eligible": 0, "entered": 0, "confirmed": 0},
            )
            row["eligible"] += int(eligible)
            row["entered"] += int(entered)
            row["confirmed"] += int(confirmed)

    return {
        "schema_version": CANDIDATE_FUNNEL_SCHEMA_VERSION,
        "stages": {
            "canonical_validation_groups": {
                "count": len(terminal),
                "available": bool(terminal),
                "unit": "validation_group",
                "source": "candidate_terminal_states",
            },
            "reported_findings": {
                "count": len(default_issues) if isinstance(default_issues, list) else 0,
                "available": isinstance(default_issues, list),
                "unit": "finding",
                "source": "default_report_view",
            },
            "reported_with_review": {
                "count": len(review_issues) if isinstance(review_issues, list) else 0,
                "available": isinstance(review_issues, list),
                "unit": "finding",
                "source": "with_needs_review_report_view",
            },
        },
        "v3_investigation": {
            **counts,
            "by_fact_kind": {key: dict(value) for key, value in sorted(by_fact_kind.items())},
            "unit": "validation_group",
        },
        "contract": {
            "answer_free": True,
            "truth_matcher_loaded": False,
        },
    }


__all__ = [
    "aggregate_p6_producer_usage_ledger",
    "p6_producer_candidate_funnel",
]
