#!/usr/bin/env python3
"""Score reproducible LLM tool-use traces against the six-tool contract.

The evaluator is provider-neutral: a runner presents each suite prompt together
with the current Agent tool schemas and records one JSON object per scenario.
This script validates those captured calls locally, so schema and interpretation
gates do not depend on trusting the model's final prose.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import sys
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from zscope.framework.llm_client import LLMClient
from zscope.tools.registry import build_tool_registry

DEFAULT_SUITE = ROOT / "tests" / "fixtures" / "tool_use_eval_v1.json"
LEGACY_SCHEMA_TOKENS = 2168
LEGACY_TOOLS = {
    "get_function_impl",
    "get_function_info",
    "get_function_snapshot",
    "get_security_semantics",
    "list_functions",
    "get_file_snippet",
    "get_callers",
    "get_type_info",
    "get_call_graph",
    "get_data_flow",
    "find_function_pointers",
    "query_pointer_alias",
    "verify_taint_reachability",
    "get_deep_call_context",
}
THRESHOLDS = {
    "first_tool_accuracy": 0.95,
    "first_arguments_valid": 0.98,
    "recovery_accuracy": 1.0,
    "legacy_call_rate": 0.0,
    "coverage_semantics_accuracy": 0.95,
    "schema_token_ratio": 0.70,
    "bounded_discovery_accuracy": 1.0,
}

EVAL_SYMBOL_ID = "zs1:function:111111111111111111111111"
EVAL_TYPE_ID = "zs1:type:222222222222222222222222"
FIRST_TOOL_SYSTEM_PROMPT = """You are a Z-SCOPE code-analysis agent.
Choose and call exactly one best first tool for the user's request. Do not answer
in prose and do not call a second tool. Use only the supplied tools. When an
exact symbol_id is supplied, pass it unchanged and do not search for it again;
never invent a symbol_id. Partial, unsupported, and unavailable coverage do not
prove absence. A may-flow or unvalidated finding is only an investigation lead.
Route source reading to read_code; snapshots, contracts, claims, audit units, and
map summaries to get_semantic_context; calls, references, callbacks, and indirect
targets to query_code_graph; value propagation to trace_data_flow; and existing
analysis records to query_static_findings. Use search_code only to find an
unknown symbol.
"""


def load_suite(path: Path = DEFAULT_SUITE) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) < 40:
        raise ValueError("tool-use suite must contain at least 40 scenarios")
    ids = [str(item.get("id") or "") for item in scenarios]
    if any(not item for item in ids) or len(ids) != len(set(ids)):
        raise ValueError("tool-use scenario ids must be non-empty and unique")
    return payload


def load_traces(path: Path) -> dict[str, dict[str, Any]]:
    traces: dict[str, dict[str, Any]] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        item = json.loads(raw)
        scenario_id = str(item.get("scenario_id") or "")
        if not scenario_id:
            raise ValueError(f"trace line {line_number} has no scenario_id")
        if scenario_id in traces:
            raise ValueError(f"duplicate trace for scenario {scenario_id}")
        traces[scenario_id] = item
    return traces


def schema_budget() -> dict[str, Any]:
    registry = build_tool_registry(None, None)
    schemas = [tool.get_schema() for tool in registry.values()]
    encoded = json.dumps(schemas, ensure_ascii=False, separators=(",", ":"))
    current = LLMClient.estimate_tokens([{"role": "system", "content": encoded}])
    ratio = current / LEGACY_SCHEMA_TOKENS
    return {
        "estimator": "LLMClient.estimate_tokens",
        "legacy_tokens": LEGACY_SCHEMA_TOKENS,
        "current_tokens": current,
        "ratio": ratio,
        "limit": THRESHOLDS["schema_token_ratio"],
        "passed": ratio <= THRESHOLDS["schema_token_ratio"],
    }


def _first_tool_scenario_prompt(scenario: dict[str, Any]) -> str:
    """Make otherwise implicit fixture state explicit without naming a tool."""

    prompt = str(scenario["prompt"]).strip()
    scenario_id = str(scenario["id"])
    context: list[str] = []
    explicit_context = scenario.get("context")
    if isinstance(explicit_context, str) and explicit_context.strip():
        return prompt + "\n\nKnown evaluation context:\n" + explicit_context.strip()
    semantic_map_query = scenario_id.startswith("java.semantic.") and not scenario_id.endswith(
        ("snapshot", "contract")
    )
    if "zs1:" not in prompt and scenario_id.split(".", 2)[1] != "search" and not semantic_map_query:
        symbol_id = EVAL_TYPE_ID if "reference" in scenario_id else EVAL_SYMBOL_ID
        context.append(f"The exact subject symbol_id is {symbol_id}.")
    if scenario_id in {
        "c.coverage.unsupported_flow",
        "cpp.flow.may",
        "cpp.recovery.invalid_selector",
        "java.flow.source_unsupported",
    }:
        context.append(
            "When the request refers to an omitted or corrected flow selector, use "
            'source={"kind":"parameter","name":"input"} and '
            'sink={"kind":"return"}.'
        )
    if not context:
        return prompt
    return prompt + "\n\nKnown evaluation context:\n" + "\n".join(context)


def _normalize_tool_calls(response: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    choices = response.get("choices")
    first_choice = choices[0] if isinstance(choices, list) and choices else {}
    first_choice = first_choice if isinstance(first_choice, dict) else {}
    message = first_choice.get("message")
    message = message if isinstance(message, dict) else {}
    raw_calls = message.get("tool_calls")
    raw_calls = raw_calls if isinstance(raw_calls, list) else []
    calls: list[dict[str, Any]] = []
    for raw_call in raw_calls:
        if not isinstance(raw_call, dict):
            continue
        function = raw_call.get("function")
        function = function if isinstance(function, dict) else {}
        raw_arguments = function.get("arguments")
        arguments: Any = raw_arguments
        parse_error: str | None = None
        if isinstance(raw_arguments, str):
            try:
                arguments = json.loads(raw_arguments)
            except json.JSONDecodeError as exc:
                parse_error = f"invalid JSON arguments: {exc.msg}"
        call = {
            "name": str(function.get("name") or raw_call.get("name") or ""),
            "arguments": arguments,
        }
        if parse_error:
            call["parse_error"] = parse_error
        calls.append(call)
    metadata = {
        "finish_reason": first_choice.get("finish_reason"),
        "model": response.get("model"),
        "usage": response.get("usage") if isinstance(response.get("usage"), dict) else {},
        "assistant_content": message.get("content"),
    }
    return calls, metadata


def run_first_tool_eval(
    suite: dict[str, Any],
    client: LLMClient,
    *,
    trace_output: Path,
    max_workers: int = 4,
) -> dict[str, dict[str, Any]]:
    """Capture one real first-tool decision for every scenario."""

    registry = build_tool_registry(None, None)
    tools = [tool.get_schema() for tool in registry.values()]
    scenarios = list(suite["scenarios"])

    def invoke(scenario: dict[str, Any]) -> dict[str, Any]:
        scenario_id = str(scenario["id"])
        presented_prompt = _first_tool_scenario_prompt(scenario)
        row: dict[str, Any] = {
            "scenario_id": scenario_id,
            "language": scenario["language"],
            "prompt": scenario["prompt"],
            "presented_prompt": presented_prompt,
            "tool_calls": [],
            "coverage_judgment": None,
            "flow_judgment": None,
            "evidence_refs": [],
        }
        try:
            response = client.chat_completion(
                messages=[
                    {"role": "system", "content": FIRST_TOOL_SYSTEM_PROMPT},
                    {"role": "user", "content": presented_prompt},
                ],
                tools=tools,
                tool_choice="required",
                temperature=0.0,
                max_tokens=800,
                trace_agent="tool_use_eval",
                trace_label=scenario_id,
            )
            calls, metadata = _normalize_tool_calls(response)
            row["tool_calls"] = calls[:1]
            row["response"] = metadata
        except Exception as exc:  # keep the complete run auditable
            row["error"] = {"type": type(exc).__name__, "message": str(exc)}
        return row

    indexed_results: dict[int, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        futures = {
            executor.submit(invoke, scenario): index for index, scenario in enumerate(scenarios)
        }
        for future in as_completed(futures):
            indexed_results[futures[future]] = future.result()

    ordered = [indexed_results[index] for index in range(len(scenarios))]
    trace_output.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(json.dumps(row, ensure_ascii=False) for row in ordered) + "\n"
    trace_output.write_text(text, encoding="utf-8", newline="\n")
    return {str(row["scenario_id"]): row for row in ordered}


def _split_env_values(value: str) -> list[str]:
    stripped = value.strip()
    if stripped.startswith("["):
        decoded = json.loads(stripped)
        if not isinstance(decoded, list) or not all(isinstance(item, str) for item in decoded):
            raise ValueError("LLM endpoint/model environment value must be a string list")
        return [item.strip() for item in decoded if item.strip()]
    return [item.strip() for item in stripped.split(",") if item.strip()]


def llm_client_from_env(*, timeout: float, max_retries: int, max_workers: int) -> LLMClient:
    api_key = os.environ.get("Z_SCOPE_API_KEY", "").strip()
    raw_base_urls = (
        os.environ.get("Z_SCOPE_LLM_BASE_URLS", "").strip()
        or os.environ.get("Z_SCOPE_LLM_BASE_URL", "").strip()
    )
    raw_models = (
        os.environ.get("Z_SCOPE_LLM_MODELS", "").strip()
        or os.environ.get("Z_SCOPE_LLM_MODEL", "").strip()
    )
    missing = [
        name
        for name, value in (
            ("Z_SCOPE_API_KEY", api_key),
            ("Z_SCOPE_LLM_BASE_URL", raw_base_urls),
            ("Z_SCOPE_LLM_MODEL", raw_models),
        )
        if not value
    ]
    if missing:
        raise ValueError("missing required LLM environment variables: " + ", ".join(missing))
    return LLMClient(
        api_key=api_key,
        base_url=_split_env_values(raw_base_urls),
        models=_split_env_values(raw_models),
        timeout=timeout,
        max_retries=max_retries,
        max_tokens=800,
        global_max_concurrent_requests=max(1, max_workers),
        base_url_max_concurrent_requests=max(1, max_workers),
        supports_structured_output=os.environ.get("Z_SCOPE_LLM_SUPPORTS_STRUCTURED_OUTPUT", "")
        .strip()
        .lower()
        in {"1", "true", "yes", "on"},
        llm_ref="tool_use_eval",
    )


def _ratio(matches: int, total: int) -> float:
    return matches / total if total else 1.0


def score_first_tool(suite: dict[str, Any], traces: dict[str, dict[str, Any]]) -> dict[str, Any]:
    registry = build_tool_registry(None, None)
    scenarios = suite["scenarios"]
    first_tool_ok = 0
    first_args_ok = 0
    legacy_calls = 0
    total_calls = 0
    details: list[dict[str, Any]] = []
    for scenario in scenarios:
        scenario_id = str(scenario["id"])
        trace = traces.get(scenario_id) or {}
        calls = trace.get("tool_calls")
        calls = calls if isinstance(calls, list) else []
        first = calls[0] if calls and isinstance(calls[0], dict) else {}
        first_name = str(first.get("name") or "")
        choice_ok = first_name == scenario["expected"]["first_tool"]
        first_tool_ok += int(choice_ok)
        tool = registry.get(first_name)
        argument_error = (
            tool.validate_arguments(first.get("arguments"))
            if tool is not None
            else {"error": "unknown tool"}
        )
        arguments_ok = argument_error is None
        first_args_ok += int(arguments_ok)
        for call in calls:
            if not isinstance(call, dict):
                continue
            total_calls += 1
            legacy_calls += int(str(call.get("name") or "") in LEGACY_TOOLS)
        details.append(
            {
                "scenario_id": scenario_id,
                "expected_tool": scenario["expected"]["first_tool"],
                "actual_tool": first_name or None,
                "first_tool_ok": choice_ok,
                "first_arguments_ok": arguments_ok,
                "argument_error": argument_error,
                "runtime_error": trace.get("error"),
            }
        )

    metrics = {
        "first_tool_accuracy": _ratio(first_tool_ok, len(scenarios)),
        "first_arguments_valid": _ratio(first_args_ok, len(scenarios)),
        "legacy_call_rate": _ratio(legacy_calls, total_calls),
    }
    thresholds = {name: THRESHOLDS[name] for name in metrics}
    gates = {
        name: value <= thresholds[name] if name == "legacy_call_rate" else value >= thresholds[name]
        for name, value in metrics.items()
    }
    return {
        "schema_version": "zscope.tool-use-eval.first-tool-result.v1",
        "suite": suite["schema_version"],
        "scenario_count": len(scenarios),
        "trace_count": len(traces),
        "metrics": metrics,
        "thresholds": thresholds,
        "gates": gates,
        "passed": all(gates.values()) and len(traces) == len(scenarios),
        "schema_budget": schema_budget(),
        "scenarios": details,
    }


def score(suite: dict[str, Any], traces: dict[str, dict[str, Any]]) -> dict[str, Any]:
    registry = build_tool_registry(None, None)
    scenarios = suite["scenarios"]
    first_tool_ok = 0
    first_args_ok = 0
    recovery_ok = 0
    recovery_total = 0
    coverage_ok = 0
    coverage_total = 0
    bounded_ok = 0
    bounded_total = 0
    legacy_calls = 0
    total_calls = 0
    details: list[dict[str, Any]] = []

    for scenario in scenarios:
        scenario_id = str(scenario["id"])
        expected = scenario["expected"]
        trace = traces.get(scenario_id) or {}
        calls = trace.get("tool_calls")
        calls = calls if isinstance(calls, list) else []
        first = calls[0] if calls and isinstance(calls[0], dict) else {}
        first_name = str(first.get("name") or "")
        choice_ok = first_name == expected["first_tool"]
        first_tool_ok += int(choice_ok)

        tool = registry.get(first_name)
        arguments = first.get("arguments")
        argument_error = (
            tool.validate_arguments(arguments) if tool is not None else {"error": "unknown tool"}
        )
        arguments_ok = argument_error is None
        first_args_ok += int(arguments_ok)

        for call in calls:
            if not isinstance(call, dict):
                continue
            total_calls += 1
            if str(call.get("name") or "") in LEGACY_TOOLS:
                legacy_calls += 1

        expected_recovery = expected.get("recovery_tool")
        recovered: bool | None = None
        if expected_recovery:
            recovery_total += 1
            recovered = len(calls) >= 2 and str(calls[1].get("name") or "") == expected_recovery
            recovery_ok += int(recovered)

        expected_judgment = expected.get("coverage_judgment")
        judgment_ok: bool | None = None
        if expected_judgment:
            coverage_total += 1
            judgment_ok = trace.get("coverage_judgment") == expected_judgment
            coverage_ok += int(judgment_ok)
        expected_flow = expected.get("flow_judgment")
        if expected_flow:
            coverage_total += 1
            flow_ok = trace.get("flow_judgment") == expected_flow
            coverage_ok += int(flow_ok)
            judgment_ok = bool(judgment_ok is not False and flow_ok)

        max_calls = expected.get("max_calls")
        bounded: bool | None = None
        if isinstance(max_calls, int):
            bounded_total += 1
            bounded = bool(calls) and len(calls) <= max_calls
            bounded_ok += int(bounded)

        details.append(
            {
                "scenario_id": scenario_id,
                "first_tool_ok": choice_ok,
                "first_arguments_ok": arguments_ok,
                "argument_error": argument_error,
                "recovery_ok": recovered,
                "interpretation_ok": judgment_ok,
                "bounded_calls_ok": bounded,
                "evidence_refs": trace.get("evidence_refs") or [],
            }
        )

    budget = schema_budget()
    metrics = {
        "first_tool_accuracy": _ratio(first_tool_ok, len(scenarios)),
        "first_arguments_valid": _ratio(first_args_ok, len(scenarios)),
        "recovery_accuracy": _ratio(recovery_ok, recovery_total),
        "legacy_call_rate": _ratio(legacy_calls, total_calls),
        "coverage_semantics_accuracy": _ratio(coverage_ok, coverage_total),
        "schema_token_ratio": budget["ratio"],
        "bounded_discovery_accuracy": _ratio(bounded_ok, bounded_total),
    }
    gates = {
        name: (
            value <= threshold
            if name in {"legacy_call_rate", "schema_token_ratio"}
            else value >= threshold
        )
        for name, threshold in THRESHOLDS.items()
        for value in [metrics[name]]
    }
    return {
        "schema_version": "zscope.tool-use-eval.result.v1",
        "suite": suite["schema_version"],
        "scenario_count": len(scenarios),
        "trace_count": len(traces),
        "metrics": metrics,
        "thresholds": THRESHOLDS,
        "gates": gates,
        "passed": all(gates.values()) and len(traces) == len(scenarios),
        "schema_budget": budget,
        "scenarios": details,
    }


def template_rows(suite: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for scenario in suite["scenarios"]:
        yield {
            "scenario_id": scenario["id"],
            "language": scenario["language"],
            "prompt": scenario["prompt"],
            "tool_calls": [],
            "coverage_judgment": None,
            "flow_judgment": None,
            "evidence_refs": [],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    parser.add_argument("--traces", type=Path)
    parser.add_argument("--emit-template", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--schema-only", action="store_true")
    parser.add_argument("--first-tool-only", action="store_true")
    parser.add_argument("--run-llm", action="store_true")
    parser.add_argument("--trace-output", type=Path)
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--max-retries", type=int, default=1)
    args = parser.parse_args()

    suite = load_suite(args.suite)
    if args.emit_template:
        text = "\n".join(json.dumps(row, ensure_ascii=False) for row in template_rows(suite)) + "\n"
        args.emit_template.write_text(text, encoding="utf-8", newline="\n")
    if args.run_llm and not args.trace_output:
        parser.error("--run-llm requires --trace-output")
    if args.run_llm and args.traces:
        parser.error("--run-llm and --traces are mutually exclusive")
    if args.max_workers < 1:
        parser.error("--max-workers must be at least 1")

    if args.run_llm:
        client = llm_client_from_env(
            timeout=args.timeout,
            max_retries=args.max_retries,
            max_workers=args.max_workers,
        )
        try:
            traces = run_first_tool_eval(
                suite,
                client,
                trace_output=args.trace_output,
                max_workers=args.max_workers,
            )
        finally:
            client.close()
        result = score_first_tool(suite, traces)
    elif args.schema_only:
        result: dict[str, Any] = schema_budget()
    elif args.traces:
        traces = load_traces(args.traces)
        result = score_first_tool(suite, traces) if args.first_tool_only else score(suite, traces)
    else:
        result = {
            "schema_version": suite["schema_version"],
            "scenario_count": len(suite["scenarios"]),
            "schema_budget": schema_budget(),
        }

    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    else:
        print(encoded, end="")
    return 0 if bool(result.get("passed", result.get("schema_budget", result)["passed"])) else 1


if __name__ == "__main__":
    raise SystemExit(main())
