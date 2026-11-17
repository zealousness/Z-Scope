"""Reusable read-only query plans, never reusable verdicts or proof authority.

Every subscribed query is executed again. Stored observations only tell the
current investigator whether its answer changed, including empty results.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterable, Mapping

PROTOCOL = "zscope.validator-query-plan.v2"
ENABLED = True  # Internal experiment control; no user configuration is required.
MAX_PREFETCH_QUERIES = 8
READ_QUERIES = frozenset(
    {
        "search_code",
        "read_code",
        "get_file_snippet",
        "get_function_info",
        "get_callers",
        "list_known_functions",
        "find_function_pointers",
        "query_pointer_alias",
        "query_code_graph",
    }
)
COUNTERS = (
    "queries",
    "hits",
    "writes",
    "replayed_queries",
    "changed_results",
    "unchanged_results",
    "failed_queries",
    "bypassed",
    "model_tasks",
    "tokens",
    "condition_rows",
    "ready_conditions",
    "reconfirmed_conditions",
    "reopened_conditions",
    "remaining_tasks",
    "scope_subscriptions",
    "scope_added",
    "scope_removed",
    "scope_incomplete",
)


def metrics() -> dict[str, Any]:
    return {**{key: 0 for key in COUNTERS}, "reasons": {}}


def merge_metrics(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    total = metrics()
    for row in rows:
        for key in COUNTERS:
            total[key] += int(row.get(key, 0))
        for reason, count in row.get("reasons", {}).items():
            total["reasons"][reason] = total["reasons"].get(reason, 0) + int(count)
    return total


def supported_query(name: str, arguments: Any) -> bool:
    if name not in READ_QUERIES or not isinstance(arguments, dict):
        return False
    # Public zs1 symbol locators are resolved by the current tool catalog.
    # Build/fact IDs instead name historical instances and are not replayed.
    return not any(
        value and (key.endswith("_uid") or key in {"build_context_id", "evidence_refs", "view_id"})
        for key, value in arguments.items()
    )


def query_succeeded(result: Mapping[str, Any]) -> bool:
    return (
        result.get("success") is not False
        and result.get("status")
        not in {
            "error",
            "failed",
            "forbidden",
            "invalid_request",
            "unsupported",
            "unavailable",
        }
        and not result.get("error")
    )


def remember_query(
    steps: list[dict[str, Any]], name: str, arguments: Any, result: Mapping[str, Any]
) -> None:
    if not supported_query(name, arguments) or not query_succeeded(result):
        return
    if len(steps) >= MAX_PREFETCH_QUERIES:
        return
    if any(step["name"] == name and step["arguments"] == arguments for step in steps):
        return
    steps.append({"name": name, "arguments": deepcopy(arguments), "observation": deepcopy(result)})


def load_steps(record: Any) -> list[dict[str, Any]]:
    if not isinstance(record, dict) or record.get("schema_version") != PROTOCOL:
        return []
    steps = record.get("queries")
    if not isinstance(steps, list):
        return []
    return [
        step
        for step in steps[:MAX_PREFETCH_QUERIES]
        if isinstance(step, dict)
        and supported_query(str(step.get("name") or ""), step.get("arguments"))
        and isinstance(step.get("observation"), dict)
    ]
