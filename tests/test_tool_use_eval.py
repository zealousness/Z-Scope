from __future__ import annotations

from scripts.evaluate_tool_use import (
    DEFAULT_SUITE,
    _first_tool_scenario_prompt,
    load_suite,
    run_first_tool_eval,
    schema_budget,
    score,
    score_first_tool,
)

SYMBOL_ID = "zs1:function:111111111111111111111111"


def _arguments(tool_name: str) -> dict:
    return {
        "search_code": {"query": "parse"},
        "read_code": {"symbol_id": SYMBOL_ID},
        "get_semantic_context": {"kind": "summary"},
        "query_code_graph": {"symbol_id": SYMBOL_ID, "relation": "call"},
        "trace_data_flow": {
            "symbol_id": SYMBOL_ID,
            "source": {"kind": "parameter", "name": "input"},
            "sink": {"kind": "call", "query": "sink"},
        },
        "query_static_findings": {},
    }[tool_name]


def _passing_traces(suite: dict) -> dict[str, dict]:
    traces = {}
    for scenario in suite["scenarios"]:
        expected = scenario["expected"]
        first_name = expected["first_tool"]
        calls = [
            {
                "name": first_name,
                "arguments": scenario.get("example_arguments", _arguments(first_name)),
            }
        ]
        recovery_name = expected.get("recovery_tool")
        if recovery_name:
            calls.append({"name": recovery_name, "arguments": _arguments(recovery_name)})
        traces[scenario["id"]] = {
            "scenario_id": scenario["id"],
            "tool_calls": calls,
            "coverage_judgment": expected.get("coverage_judgment"),
            "flow_judgment": expected.get("flow_judgment"),
            "evidence_refs": [{"kind": "source", "file": "src/example.c", "line": 1}],
        }
    return traces


def test_tool_use_suite_has_language_coverage_and_at_least_40_scenarios() -> None:
    suite = load_suite(DEFAULT_SUITE)

    assert len(suite["scenarios"]) >= 40
    assert {item["language"] for item in suite["scenarios"]} == {"c", "cpp", "java"}


def test_tool_use_golden_trace_passes_all_release_gates() -> None:
    suite = load_suite(DEFAULT_SUITE)
    result = score(suite, _passing_traces(suite))

    assert result["passed"] is True
    assert all(result["gates"].values())
    assert result["trace_count"] == result["scenario_count"]


def test_tool_definition_budget_is_at_most_70_percent_of_legacy() -> None:
    budget = schema_budget()

    assert budget["passed"] is True
    assert budget["ratio"] <= 0.70


def test_tool_use_eval_rejects_legacy_call_and_unsafe_partial_interpretation() -> None:
    suite = load_suite(DEFAULT_SUITE)
    traces = _passing_traces(suite)
    traces["c.search.function"]["tool_calls"][0]["name"] = "get_function_impl"
    traces["c.coverage.partial_graph"]["coverage_judgment"] = "safe"

    result = score(suite, traces)

    assert result["passed"] is False
    assert result["metrics"]["legacy_call_rate"] > 0
    assert result["metrics"]["coverage_semantics_accuracy"] < 1


def test_first_tool_score_does_not_require_later_interpretation_fields() -> None:
    suite = load_suite(DEFAULT_SUITE)
    traces = _passing_traces(suite)
    for trace in traces.values():
        trace["tool_calls"] = trace["tool_calls"][:1]
        trace["coverage_judgment"] = None
        trace["flow_judgment"] = None

    result = score_first_tool(suite, traces)

    assert result["passed"] is True
    assert result["metrics"]["first_tool_accuracy"] == 1.0


def test_live_first_tool_runner_captures_normalized_calls(tmp_path) -> None:
    suite = load_suite(DEFAULT_SUITE)

    class FakeClient:
        def chat_completion(self, *, messages, **kwargs):
            del kwargs
            user_prompt = messages[-1]["content"]
            name = "read_code" if "supplied symbol_id" in user_prompt else "search_code"
            arguments = {"symbol_id": SYMBOL_ID} if name == "read_code" else {"query": "parse"}
            return {
                "model": "fake-model",
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": name,
                                        "arguments": __import__("json").dumps(arguments),
                                    }
                                }
                            ],
                        },
                    }
                ],
            }

    small_suite = {**suite, "scenarios": suite["scenarios"][:4]}
    output = tmp_path / "traces.jsonl"
    traces = run_first_tool_eval(small_suite, FakeClient(), trace_output=output, max_workers=2)

    assert list(traces) == [item["id"] for item in small_suite["scenarios"]]
    assert traces["c.read.known_symbol"]["tool_calls"] == [
        {"name": "read_code", "arguments": {"symbol_id": SYMBOL_ID}}
    ]
    assert SYMBOL_ID in traces["c.read.known_symbol"]["presented_prompt"]
    assert len(output.read_text(encoding="utf-8").splitlines()) == 4


def test_cross_function_flow_eval_cases_have_expressible_selectors() -> None:
    suite = load_suite(DEFAULT_SUITE)
    scenarios = {item["id"]: item for item in suite["scenarios"]}

    cpp_prompt = _first_tool_scenario_prompt(scenarios["cpp.flow.return"])
    java_prompt = _first_tool_scenario_prompt(scenarios["java.flow.joern"])

    assert 'source={"kind":"variable","name":"result"}' in cpp_prompt
    assert 'sink={"kind":"call","query":"send"' in cpp_prompt
    assert 'source={"kind":"parameter","name":"input"}' in java_prompt
    assert 'sink={"kind":"call","query":"executeQuery"' in java_prompt
