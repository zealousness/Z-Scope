"""Synthetic boundary probe only: foreign navigation must not become scoped evidence."""

from zscope.retrieval.instance_index import InstanceScope, ScopedCodeIndex

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import threading


def test_unscoped_navigation_cannot_return_another_build_as_usable_data():
    class NavigationIndex:
        def get_callees(self, name):
            return ["callee_from_another_compilation_variant"]

    scope = InstanceScope(build_context_id="ctx-a", usr="usr-a", identity="ctx-a/usr-a",
                          source="unit.c", function_names=("f",))
    index = ScopedCodeIndex(NavigationIndex(), scope)
    result = index.get_callees("f")
    assert not result, "An unsupported unscoped navigation result must stay a gap"
    assert index.scope_report()["scope_gaps"]


def test_close_waits_for_an_active_instance_analysis(tmp_path, monkeypatch):
    # A controlled scheduling body isolates the public lifetime contract;
    # this is not native/analyzer-effect acceptance.
    from zscope.orchestration.parallel_analyzer import ParallelAnalyzer

    analyzer = ParallelAnalyzer.__new__(ParallelAnalyzer)
    analyzer.base_config = SimpleNamespace(project=SimpleNamespace(language="c_cpp", project_root=tmp_path))
    analyzer._candidate_ledger = SimpleNamespace(lifecycle_snapshot=lambda: {})
    # The public entry point now freezes semantics and resolves the entry
    # owners before scheduling.  Those steps are not what this test measures
    # (it isolates the close() lifetime contract), and a bare __new__ façade
    # has none of the __init__ state they read, so stub them explicitly.
    analyzer.freeze_instance_semantics = lambda plan: None
    analyzer._current_instance_entries = lambda plan: []
    analyzer._current_instance_owner_aliases = lambda batch: {}
    instance = SimpleNamespace(build_context_id="ctx-a", usr="usr-a", identity="ctx-a/usr-a",
                               source="unit.c", function_names=("f",), selected_by="test")
    plan = SimpleNamespace(instances=[instance], gaps=[], status="planned")
    entered, release, close_started, cleaned = (threading.Event() for _ in range(4))

    def scheduling_body(*args, **kwargs):
        entered.set()
        assert release.wait(timeout=10)
        return {}

    def close():
        close_started.set()
        analyzer.close()

    monkeypatch.setattr(analyzer, "_analyze_function_entries", scheduling_body)
    monkeypatch.setattr(analyzer, "_close_owned_resources", cleaned.set)
    with ThreadPoolExecutor(max_workers=2) as pool:
        running = pool.submit(analyzer.analyze_entry_instances, plan)
        assert entered.wait(timeout=10)
        closing = pool.submit(close)
        assert close_started.wait(timeout=10)
        try:
            assert not cleaned.wait(timeout=0.2), "close() freed resources during active instance analysis"
        finally:
            release.set()
            running.result(timeout=10)
            closing.result(timeout=10)
