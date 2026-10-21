"""Exact-scope business declarations; neither defect verdicts nor suppressions."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .contracts import digest

ANSWER_SCHEMA = "zscope.business-answer.v1"
FACTS = {
    "event:business_release_requirement",
    "event:responsibility_endpoint",
    "event:nonconcurrent_reference_count",
    "event:serial_handle_namespace",
}


def assumption_subject(assumption: Mapping[str, Any]) -> dict[str, Any]:
    scope, basis = assumption.get("scope"), assumption.get("basis")
    if (
        assumption.get("fact_kind") not in FACTS
        or not isinstance(assumption.get("statement"), str)
        or not assumption["statement"].strip()
        or not isinstance(scope, dict)
        or not all(scope.get(k) for k in ("build_context_id", "entry_usr", "object_ref"))
        or not isinstance(basis, dict)
        or not all(basis.get(k) for k in ("dependency_hash", "observation_kind"))
    ):
        raise ValueError("业务前提缺少对象、源码依赖或适用范围，请重新扫描")
    return {
        "schema": ANSWER_SCHEMA,
        "fact_kind": assumption["fact_kind"],
        "statement": assumption["statement"],
        "scope": scope,
        "basis": basis,
    }


def assumption_key(assumption: Mapping[str, Any]) -> str:
    return "BUSINESS_" + digest(assumption_subject(assumption))


def report_assessments(report: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    """Walk only report containers, never arbitrary native evidence trees."""
    stack: list[Any] = [report]
    seen: set[int] = set()
    while stack:
        item = stack.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, (list, tuple)):
            stack.extend(item)
        elif isinstance(item, Mapping):
            assessment = item.get("protocol_assessment")
            if isinstance(assessment, Mapping):
                yield assessment
            for key in (
                "issues",
                "observations",
                "audit_observations",
                "candidate_terminal_states",
                "metadata",
                "reports",
                "results",
                "report_views",
                "default",
                "with_needs_review",
            ):
                child = item.get(key)
                if isinstance(child, (Mapping, list, tuple)):
                    stack.append(child)


def feedback_reuse_problem(report: Mapping[str, Any], store: Any) -> str:
    expected: dict[str, int] = {}
    for assessment in report_assessments(report):
        revisions = assessment.get("feedback_revisions")
        if not isinstance(revisions, Mapping):
            # An old, unconfirmed assessment already blocks normal reuse.
            continue
        for key, value in revisions.items():
            if type(value) is not int or value < 0 or (key in expected and expected[key] != value):
                return "business_feedback_dependency_conflict"
            expected[str(key)] = value
    if not expected:
        return ""
    reader = getattr(store, "protocol_answer_revisions", None)
    if not callable(reader):
        return "business_feedback_unavailable"
    try:
        return "" if reader(list(expected)) == expected else "business_feedback_changed"
    except Exception:
        return "business_feedback_unavailable"
