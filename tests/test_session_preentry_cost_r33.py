"""Actual Session/native builder handoff with offline response accounting only."""

from types import SimpleNamespace
import pytest
from test_instance_analysis import native_variants, _native_config, _native_index
from zscope.config.function_entry import FunctionEntry
from zscope.core.analysis.analyzer import Analyzer
from zscope.orchestration.entry_instances import plan_entry_instances
from zscope.orchestration.scan_session import ScanSessionRunner


@pytest.mark.parametrize("preentry", [True, False])
def test_real_instance_builder_retains_current_preentry_cost_and_service(
    native_variants, monkeypatch, preentry
):
    backend, root, cdb = native_variants
    index = _native_index(backend, root, cdb)
    config = _native_config(root, cdb, root)
    config.llm.api_key = "offline-session-accounting-fixture"
    config.llm.base_urls = ["http://example.invalid"]
    config.llm.models = ["offline-session-accounting-fixture"]
    config.llms = {"default": config.llm}
    config.project.wiki.mode = "active" if preentry else "off"
    entries = [FunctionEntry("f", file_path="unit.c")]
    plan = plan_entry_instances(index, entries)
    assert plan.status == "planned" and len(plan.instances) == 2
    runner = ScanSessionRunner(config)
    state = dict(code_index=index, entries=entries, entry_instance_plan=plan)
    # An unrelated project-wide model must not enter this exact-instance path.
    state["semantic_result"] = object()
    service = SimpleNamespace(source_index=None, wiki_store=None)
    calls = []

    def controlled_wiki_stage(_config, clients):
        calls.append(clients)
        if preentry and len(calls) == 1:
            client = next(iter(clients.values()))
            client._record_successful_usage(
                dict(prompt_tokens=11, completion_tokens=13, total_tokens=24, estimated=False),
                duration_seconds=2.0,
            )
        return service if preentry else None

    monkeypatch.setattr(
        Analyzer, "build_project_knowledge_service", staticmethod(controlled_wiki_stage)
    )
    assert runner._handle_wiki_compile(state, SimpleNamespace(id="wiki_compile")) is False
    analyzer = None
    try:
        analyzer = runner._build_instance_analyzer(state)
        assert not analyzer._instance_semantics_context.unavailable
        analyzer.require_current_instance_inputs()
        assert analyzer._shared_local_pattern_semantics is None
        assert analyzer._shared_semantic_overlay is None
        report = analyzer.generate_combined_report({})
        usage = report["summary"]["llm_usage"]
        expected = 24 if preentry else 0
        assert usage["total_tokens"] == expected, (usage, len(calls))
        assert report["summary"]["total_cumulative_total_tokens"] == expected
        if preentry:
            assert analyzer._shared_llm_clients is state["llm_clients"]
            assert analyzer.project_knowledge_service is state["project_knowledge_service"]
            assert calls == [state["llm_clients"]]
            assert usage["successful_calls"] == 1
    finally:
        if analyzer is not None:
            analyzer.close()
        if state.get("llm_clients"):
            runner._close_llm_clients(state["llm_clients"])
