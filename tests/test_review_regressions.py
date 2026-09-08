"""Behavioral regressions for the September correctness/concurrency review."""

from concurrent.futures import ThreadPoolExecutor
import json
import multiprocessing
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.cpp_domains.source_events import source_events
from zscope.core.candidates.cpp_domains.typed_resources import MISMATCH_RULE, LEAK_RULE
from zscope.core.candidates.graph import GraphCandidateGenerator, FunctionView, LockOrderEdge
from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.core.analysis.analyzer import Analyzer
from zscope.core.validation.context_budget import fit_evidence
from zscope.core.validation.evidence import build_validator_evidence_slice_v3
from zscope.core.validation.runner import ValidationRunner
from zscope.framework.llm_client import LLMClient
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer
from zscope.retrieval.analysis_facts import AnalysisFactCache
from zscope.retrieval.code_index import CodeIndex
from zscope.retrieval.knowledge_db import KnowledgeDB
from zscope.rules.catalog import RuleCatalog, EffectiveRuleSet
from zscope.snapshots.store import SnapshotStore


def snapshot(summary="one"):
    return dict(
        index_name="f@a.c:1-2",
        func_name="f",
        file_path="a.c",
        start_line=1,
        end_line=2,
        referenced_globals=[],
        referenced_macros=[],
        referenced_types=[],
        summary=summary,
    )


def _process_save(directory, barrier, summary):
    store = SnapshotStore(Path(directory))
    barrier.wait(timeout=10)
    value = snapshot(summary)
    store.save_snapshot(value["index_name"], value, summary)


def test_cross_process_snapshot_commit_and_cross_store_cache(tmp_path):
    store = SnapshotStore(tmp_path)
    name = snapshot()["index_name"]
    store.save_snapshot(name, snapshot(), "one")
    assert store.load_snapshot(name)["summary"] == "one"
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(2)
    processes = [
        ctx.Process(target=_process_save, args=(str(tmp_path), barrier, value))
        for value in ("two", "three")
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    current, generation = store.load_snapshot_versioned(name)
    assert current["summary"] in {"two", "three"}
    assert json.loads((tmp_path / generation).read_text())["summary"] == current["summary"]
    assert len(list(tmp_path.glob("*.json"))) == 1
    assert not list(tmp_path.glob("*.tmp"))


def test_stale_report_cannot_attach_to_new_snapshot(tmp_path):
    first, second = SnapshotStore(tmp_path), SnapshotStore(tmp_path)
    name = snapshot()["index_name"]
    old = first.save_snapshot(name, snapshot(), "one")
    new = second.save_snapshot(name, snapshot("two"), "two")
    assert not first.save_final_report(name, {"old": True}, expected_generation=old)
    assert second.save_final_report(name, {"new": True}, expected_generation=new)
    assert first.load_final_report(name) == {"new": True}
    assert len(list((tmp_path / "conflicts").glob("*.json"))) == 1


def test_reader_retries_when_committed_version_is_retired(tmp_path, monkeypatch):
    first, second = SnapshotStore(tmp_path), SnapshotStore(tmp_path)
    name = snapshot()["index_name"]
    old = first.save_snapshot(name, snapshot(), "one")
    reader = SnapshotStore(tmp_path)
    read_text = Path.read_text

    def interleaved_read(path, *args, **kwargs):
        if path == tmp_path / old:
            second.save_snapshot(name, snapshot("two"), "two")
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", interleaved_read)
    value, generation = reader.load_snapshot_versioned(name)
    assert value["summary"] == "two" and generation != old


def test_deleted_snapshot_rejects_late_report_and_retires_files(tmp_path):
    store = SnapshotStore(tmp_path)
    name = snapshot()["index_name"]
    version = store.save_snapshot(name, snapshot(), "one")
    assert store.save_final_report(name, {"issues": []}, expected_generation=version)
    store.delete_snapshot(name)
    assert not store.save_final_report(name, {"late": True}, expected_generation=version)
    assert store.load_snapshot(name) is None and store.load_final_report(name) is None
    assert not list(tmp_path.glob("*.json"))


def test_snapshot_failed_write_leaves_committed_version(tmp_path, monkeypatch):
    store = SnapshotStore(tmp_path)
    name = snapshot()["index_name"]
    version = store.save_snapshot(name, snapshot(), "one")
    original = store._connect

    def fail():
        raise RuntimeError("commit unavailable")

    monkeypatch.setattr(store, "_connect", fail)
    with pytest.raises(RuntimeError):
        store.save_snapshot(name, snapshot("two"), "two")
    monkeypatch.setattr(store, "_connect", original)
    assert store.load_snapshot_versioned(name)[1] == version
    assert len(list(tmp_path.glob("*.json"))) == 1


def test_snapshot_sqlite_commit_failure_rolls_back_pointer_and_file(tmp_path, monkeypatch):
    store = SnapshotStore(tmp_path)
    name = snapshot()["index_name"]
    version = store.save_snapshot(name, snapshot(), "one")
    connect = store._connect

    class FailedCommit:
        def __init__(self):
            self.connection = connect()

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def commit(self):
            raise RuntimeError("injected commit failure")

    monkeypatch.setattr(store, "_connect", FailedCommit)
    with pytest.raises(RuntimeError, match="commit failure"):
        store.save_snapshot(name, snapshot("two"), "two")
    monkeypatch.setattr(store, "_connect", connect)
    assert store.load_snapshot_versioned(name)[1] == version
    assert len(list(tmp_path.glob("*.json"))) == 1


def test_live_capacity_owners_and_drain():
    url = "http://review-quota.invalid/v1"
    low = LLMClient(
        "test",
        url,
        ["test"],
        global_max_concurrent_requests=1,
        base_url_max_concurrent_requests=1,
        base_url_rate_limit_per_minute=1,
    )
    high = LLMClient(
        "test",
        url,
        ["test"],
        global_max_concurrent_requests=16,
        base_url_max_concurrent_requests=16,
        base_url_rate_limit_per_minute=120,
    )
    try:
        request = low._select_base_url()
        session = low.session
        low.close()
        assert session in low._sessions
        state = high.endpoint_capacity_snapshot()[url]
        assert state["hard_max_concurrent_requests"] == 16
        assert state["rate_limit_per_minute"] == 120
        assert state["in_flight"] == 1
        with pytest.raises(RuntimeError, match="closed"):
            low._select_base_url()
        low._release_base_url(request)
        assert not low._sessions
        assert high.endpoint_capacity_snapshot()[url]["in_flight"] == 0
    finally:
        low.close()
        high.close()


def test_borrowed_client_not_closed_by_parallel_facade():
    calls = []
    client = SimpleNamespace(close=lambda: calls.append("closed"))
    analyzer = ParallelAnalyzer.__new__(ParallelAnalyzer)
    analyzer._owns_llm_clients = False
    analyzer._shared_llm_clients = {"default": client}
    analyzer.close()
    analyzer.close()
    assert not calls


def test_parallel_close_waits_for_admitted_batch_and_closes_once():
    entered, release, requested = threading.Event(), threading.Event(), threading.Event()
    closed = []
    analyzer = ParallelAnalyzer.__new__(ParallelAnalyzer)
    analyzer._owns_llm_clients = True
    analyzer._shared_llm_clients = {"default": SimpleNamespace(close=lambda: closed.append(True))}

    def batch(*args):
        entered.set()
        assert release.wait(5)
        return {}

    analyzer._analyze_function_entries = batch

    def close():
        requested.set()
        analyzer.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        work = pool.submit(analyzer.analyze_function_entries, [])
        assert entered.wait(5)
        cleanup = pool.submit(close)
        assert requested.wait(5)
        # Synchronize on the close request, not a timing-dependent sleep.
        with analyzer._lifecycle_condition():
            while not getattr(analyzer, "_closed", False):
                analyzer._lifecycle_condition().wait(0.01)
        assert not cleanup.done() and not closed
        with pytest.raises(RuntimeError, match="closed"):
            analyzer.analyze_function_entries([])
        release.set()
        work.result(timeout=5)
        cleanup.result(timeout=5)
    analyzer.close()
    assert closed == [True]


def test_owner_removal_preserves_overload_state_and_request_history():
    url = "http://review-adaptive.invalid/v1"
    low = LLMClient(
        "test", url, ["test"], base_url_max_concurrent_requests=1, base_url_rate_limit_per_minute=1
    )
    high = LLMClient(
        "test",
        url,
        ["test"],
        global_max_concurrent_requests=16,
        base_url_max_concurrent_requests=16,
        base_url_rate_limit_per_minute=120,
    )
    try:
        request = low._select_base_url()
        low._record_endpoint_overload(request, reason="test overload")
        low._release_base_url(request)
        low.close()
        current = high.endpoint_capacity_snapshot()[url]
        assert current["max_concurrent_requests"] == 1
        assert current["hard_max_concurrent_requests"] == 16
        assert current["recent_requests"] == 1
    finally:
        low.close()
        high.close()


def test_token_first_evidence_keeps_middle_guard():
    lines = [";" for _ in range(240)]
    lines[119], lines[189] = "if (size > capacity) return;", "memcpy(dst, src, size);"
    value = fit_evidence({"code": {"function_context": "\n".join(lines)}}, max_tokens=12_000)
    assert "if (size > capacity)" in value["code"]["function_context"]
    assert not value["slice_truncated"]


def test_token_budget_marks_omissions_and_preserves_relevant_guards():
    lines = ["/* padding */" * 40 for _ in range(1500)]
    lines[700], lines[900] = "if (size > capacity) return;", "memcpy(dst, src, size);"
    value = fit_evidence(
        {
            "code": {"function_context": "\n".join(lines)},
            "evidence": {"sink": "memcpy(dst, src, size)"},
        },
        max_tokens=2000,
    )
    assert value["slice_truncated"] and value["context_requires_retrieval"]
    assert value["code"]["omitted_line_intervals"]
    assert "if (size > capacity)" in value["code"]["function_context"]
    assert value["slice_estimated_tokens"] <= 2000


def test_upstream_evidence_compaction_cannot_be_labelled_complete():
    issue = {
        "function": "demo",
        "location": "a.c:1",
        "positive_evidence": [str(i) * 2000 for i in range(40)],
    }
    projected = build_validator_evidence_slice_v3(issue, {}, "void demo() {}")
    assert projected["slice_truncated"] and projected["upstream_omissions"]
    assert projected["context_requires_retrieval"]


def test_incomplete_context_verdict_requires_decision_evidence_not_just_one_completed_query():
    issue = {
        "validator_context_requires_retrieval": True,
        "evidence_completion_status": "completed",
    }
    value = ValidationRunner._context_checked_result(issue, {"verdict": "confirmed"})
    assert value["verdict"] == "uncertain"
    issue["decision_fact_coverage"] = "complete"
    assert (
        ValidationRunner._context_checked_result(issue, {"verdict": "confirmed"})["verdict"]
        == "confirmed"
    )


@pytest.mark.parametrize("line_count", [50, 550, 1500])
def test_full_function_source_and_graph_are_not_model_limited(tmp_path, line_count):
    body = "void demo(char *p) {\n" + "\n" * line_count + "free(p);\nfree(p);\n}\n"
    (tmp_path / "a.c").write_text(body)
    index = CodeIndex(tmp_path, source_root=tmp_path)
    try:
        impl = GraphCandidateGenerator(index)._impl_for("demo")
        assert impl and not impl.get("truncated")
        issues = ClangAstCfgCandidateGenerator().generate_issues("demo", impl["code"], "a.c")
        assert any(i["rule"] == "clang_cfg_same_object_released_twice" for i in issues)
    finally:
        index.close()


@pytest.mark.parametrize("line_count", [50, 550, 1500])
def test_entry_workflow_java_and_provider_receive_full_source(tmp_path, monkeypatch, line_count):
    import zscope.core.analysis.analyzer as module

    code = (
        "void demo(String input) {\n" + "\n" * line_count + "Runtime.getRuntime().exec(input);\n}\n"
    )
    identity = dict(
        index_name="demo@Demo.java:1-1600", func_name="demo", file_path="Demo.java", code=code
    )

    class Index:
        language = "java"

        def get_function_impl(self, name, *, max_lines, file_path):
            assert max_lines is None
            return {"code": code, "file": file_path, "start_line": 1, "truncated": False}

    analyzer = Analyzer.__new__(Analyzer)
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(entry_function="demo", language="java", project_root=tmp_path),
        analysis=SimpleNamespace(max_function_lines=500),
        rules=SimpleNamespace(packs=["test"], providers=[]),
    )
    analyzer.code_index, analyzer.snapshot_store = Index(), object()
    analyzer.user_config = SimpleNamespace(clear_config_warnings=lambda: None)
    analyzer.candidate_ledger = None
    monkeypatch.setattr(
        module, "build_semantic_model_input", lambda *args, **kwargs: dict(identity)
    )
    monkeypatch.setattr(module, "hydrate_project_callee_summaries", lambda value, *args: value)
    monkeypatch.setattr(module, "relevant_user_config_context", lambda *args: {})
    monkeypatch.setattr(analyzer, "_refresh_effective_budget", lambda *args: None)
    monkeypatch.setattr(analyzer, "_engine_capabilities", lambda: {})
    monkeypatch.setattr(analyzer, "_candidate_backend_profile", lambda: "joern")
    monkeypatch.setattr(
        analyzer,
        "_direct_callee_rule_scan_budget",
        lambda state: {"limit": 0, "max_depth": 0, "total_limit": 0},
    )
    monkeypatch.setattr(
        analyzer, "_detect_direct_callee_rule_candidates", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        analyzer, "_detect_java_project_file_rule_candidates", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(analyzer, "_annotate_candidate_issues", lambda issues, **kwargs: issues)
    seen = []
    analyzer._extension_rule_registry = SimpleNamespace(
        evaluate=lambda context: seen.append(context.code) or []
    )
    state = analyzer._create_workflow_state()
    assert state["impl_result"]["code"] == code
    assert len(state["agent_context"]["code"].splitlines()) <= 500
    assert state["agent_context"]["code_truncated"] == (line_count > 500)
    issues = analyzer._detect_local_rule_candidates(state)
    assert any(issue["defect_class"] == "command_injection" for issue in issues)
    assert seen == [code]


def test_partial_source_records_unfinished_detection():
    analyzer = Analyzer.__new__(Analyzer)
    analyzer.config = SimpleNamespace(project=SimpleNamespace(language="c_cpp"))
    state = {"entry_func": "demo", "impl_result": {"code": "void demo() {", "truncated": True}}
    assert analyzer._detect_local_rule_candidates(state) == []
    assert state["deferred_deterministic_work"][0]["reason"] == "source_truncated"
    assert (
        analyzer._runtime_engine_capabilities["deterministic_local_rules"]["status"] != "complete"
    )


@pytest.mark.parametrize("generator", [ClangAstCfgCandidateGenerator, RegexCandidateGenerator])
def test_same_line_operations_and_null_reset(generator):
    unsafe = generator().generate_issues("demo", "void demo(char *p) { free(p); free(p); }", "a.c")
    safe = generator().generate_issues(
        "demo", "void demo(char *p) { free(p); p = NULL; free(p); }", "a.c"
    )
    assert any(i["defect_class"] == "double_free" for i in unsafe)
    assert not any(i["defect_class"] == "double_free" for i in safe)


def test_lexer_ignores_macro_string_and_for_semicolons():
    code = '#define RELEASE(p) free(p); free(p)\nvoid f() { const char *s = R"(free(p);)"; for (int i=0;i<2;i++) use(i); }'
    events = source_events(code)
    assert len([e for e in events if "for (" in e.text]) == 1
    assert not any(e.text.startswith("free(p)") for e in events)
    for generator in (RegexCandidateGenerator(), ClangAstCfgCandidateGenerator()):
        issues = generator.generate_issues(
            "demo", 'void demo(char *p) { puts("free(p)"); free(p); }', "a.c"
        )
        assert not any(i["defect_class"] == "double_free" for i in issues)


def test_fallback_event_columns_and_offsets_use_utf8_bytes():
    prefix = "void demo(char *p) { /* 中文 */ "
    events = source_events(prefix + "free(p); free(p); }")
    releases = [event for event in events if event.text.startswith("free")]
    assert releases[0].column == len(prefix.encode("utf-8")) + 1
    assert releases[0].offset == len(prefix.encode("utf-8"))
    assert releases[1].ordinal > releases[0].ordinal


@pytest.mark.parametrize(
    "unsafe,safe,rule",
    [
        ("int *p = new int[4]; delete p;", "int *p = new int[4]; delete[] p;", MISMATCH_RULE),
        (
            "int *p = new int; delete p; delete p;",
            "int *p = new int; delete p;",
            "clang_cfg_same_object_released_twice",
        ),
        (
            "int *p = new int[4];",
            "int *p = new int[4]; delete[] p;",
            "clang_cfg_acquire_without_release_on_exit",
        ),
        ('FILE *p = fopen("a", "r");', 'FILE *p = fopen("a", "r"); fclose(p);', LEAK_RULE),
        ('DIR *p = opendir(".");', 'DIR *p = opendir("."); closedir(p);', LEAK_RULE),
    ],
)
def test_typed_lifetimes_have_positive_and_fixed_pair(unsafe, safe, rule):
    generator = ClangAstCfgCandidateGenerator()
    detected = generator.generate_issues("demo", "void demo() {" + unsafe + "}", "a.cpp")
    fixed = generator.generate_issues("demo", "void demo() {" + safe + "}", "a.cpp")
    assert rule in {i["rule"] for i in detected}
    assert rule not in {i["rule"] for i in fixed}


@pytest.mark.parametrize("name", ["g_counter", "shared_value", "renamed_total"])
def test_shared_candidate_is_invariant_under_renaming(name):
    generator = ClangAstCfgCandidateGenerator()
    issues = generator.generate_issues("demo", f"void demo() {{\n {name}++;\n}}", "a.c")
    assert any(i["rule"] == "clang_cfg_unsynchronized_shared_flag_or_counter" for i in issues)
    fixed = generator.generate_issues(
        "demo", f"void demo() {{\nint {name} = 0;\n{name}++;\n}}", "a.c"
    )
    assert not any(i["rule"] == "clang_cfg_unsynchronized_shared_flag_or_counter" for i in fixed)


@pytest.mark.parametrize(
    "body",
    [
        "int private_value = 0; private_value++;",
        "thread_local int private_value = 0; private_value++;",
        "std::atomic<int> value; value++;",
        "pthread_mutex_lock(&mu); shared_value++; pthread_mutex_unlock(&mu);",
    ],
)
def test_shared_access_near_misses_under_single_line_formatting(body):
    for generator in (RegexCandidateGenerator(), ClangAstCfgCandidateGenerator()):
        issues = generator.generate_issues("demo", "void demo() {" + body + "}", "a.cpp")
        assert not any(
            issue["rule"]
            in {
                "unsynchronized_shared_flag_or_counter",
                "clang_cfg_unsynchronized_shared_flag_or_counter",
            }
            for issue in issues
        )


def test_ir_keeps_identical_same_line_events(tmp_path):
    db = KnowledgeDB(str(tmp_path / "facts.db"))
    try:
        first = db.upsert_ir_statement(
            "a.c", 1, "demo", normalized_code="free(p)", column_number=1, event_ordinal=1
        )
        second = db.upsert_ir_statement(
            "a.c", 1, "demo", normalized_code="free(p)", column_number=10, event_ordinal=2
        )
        assert first != second
    finally:
        db.close()


def test_literal_null_deallocation_is_safe():
    issues = ClangAstCfgCandidateGenerator().generate_issues(
        "demo", "void demo() { free(NULL); free(NULL); delete nullptr; delete nullptr; }", "a.cpp"
    )
    assert not any(i["defect_class"] == "double_free" for i in issues)


@pytest.mark.parametrize(
    "body",
    [
        "int *p = new int; std::unique_ptr<int> owner(p);",
        "int *p = new int; return p;",
        'FILE *p = fopen("x", "r"); if (!p) return; fclose(p);',
        'DIR *p = opendir("."); if (bad) { closedir(p); return; } closedir(p);',
        'FILE *p = fopen("x", "r"); p = freopen("y", "r", p); fclose(p);',
    ],
)
def test_typed_resource_ownership_and_terminal_cleanup_near_misses(body):
    issues = ClangAstCfgCandidateGenerator().generate_issues(
        "demo", "void demo() {" + body + "}", "a.cpp"
    )
    assert not any(
        i["rule"]
        in {
            LEAK_RULE,
            "clang_cfg_same_object_released_twice",
            "clang_cfg_acquire_without_release_on_exit",
        }
        for i in issues
    )


def test_typed_resource_wrappers_and_exception_exit():
    overlay = {
        "resource_models": [
            {
                "name": "read_handle",
                "kind": "io_acquire",
                "description": "resource_family=file resource_output=return",
            },
            {
                "name": "finish_handle",
                "kind": "io_release",
                "description": "resource_family=file resource_input=arg1",
            },
        ]
    }
    generator = ClangAstCfgCandidateGenerator(semantic_overlay=overlay)
    unsafe = generator.generate_issues("demo", "void demo() {auto p = read_handle();}", "a.cpp")
    safe = generator.generate_issues(
        "demo", "void demo() {auto p = read_handle(); finish_handle(p);}", "a.cpp"
    )
    assert any(i["rule"] == LEAK_RULE for i in unsafe)
    assert not any(i["rule"] == LEAK_RULE for i in safe)
    throws = generator.generate_issues(
        "demo", "void demo() {int *p = new int; if (bad) throw 1; delete p;}", "a.cpp"
    )
    assert any(i["rule"] == "clang_cfg_acquire_without_release_on_exit" for i in throws)


def test_custom_allocation_requests_ownership_evidence():
    issues = ClangAstCfgCandidateGenerator().generate_issues(
        "demo", "void demo() {int *p = new (arena) int; delete p;}", "a.cpp"
    )
    assert any(
        i.get("audit_observation_reason") == "custom_allocation_ownership_unresolved"
        and i["validation_required"]
        for i in issues
    )


@pytest.mark.parametrize("separator", ["\n", " "])
def test_exclusive_release_paths_never_get_confirmation_proof(tmp_path, separator):
    from zscope.core.validation.pipeline import ValidationPipeline
    from zscope.core.validation.proofs import deterministic_decision_proof
    from zscope.orchestration.candidates import CandidateLedger, CandidateRegistrar

    code = separator.join(
        [
            "void demo(char *p, int flag) {",
            "if (flag) {",
            "free(p);",
            "} else {",
            "free(p);",
            "}",
            "}",
        ]
    )
    issues = ClangAstCfgCandidateGenerator().generate_issues("demo", code, "a.c")
    ledger = CandidateLedger(project_id="review", project_root=str(tmp_path), revision="test")
    CandidateRegistrar(ledger, run_id="review").register_issues(
        issues, source="clang_ast_cfg", default_entry_identity="demo"
    )
    for issue in issues:
        if issue["defect_class"] != "double_free":
            continue
        assert deterministic_decision_proof(issue, outcome="confirm") is None
        outcome = ValidationPipeline(None).apply_deterministic_prevalidation(
            issue, {"final_score": 0.8}
        )
        assert outcome is None or outcome.verdict not in {"verified", "confirmed"}


@pytest.mark.parametrize(
    "declaration,operation",
    [
        ("FILE *p", "fclose(p)"),
        ("DIR *p", "closedir(p)"),
    ],
)
def test_typed_parameter_double_release(declaration, operation):
    issues = ClangAstCfgCandidateGenerator().generate_issues(
        "demo", f"void demo({declaration}) {{{operation}; {operation};}}", "a.cpp"
    )
    assert any(i["defect_class"] == "double_free" for i in issues)


def test_fact_cache_single_producer_and_bounded_storage():
    cache = AnalysisFactCache(max_bytes=4096)
    entered, release = threading.Event(), threading.Event()

    def produce():
        entered.set()
        assert release.wait(5)
        return {"fact": [1, 2]}

    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(cache.compute, "same", produce)
        assert entered.wait(5)
        two = pool.submit(cache.compute, "same", produce)
        release.set()
        assert one.result() == two.result()
    assert cache.computations == 1
    for i in range(30):
        cache.compute(i, lambda: "x" * 1000)
    assert cache._bytes <= cache.max_bytes


def test_unique_lock_pairs_do_not_do_quadratic_comparisons(monkeypatch):
    generator = GraphCandidateGenerator(SimpleNamespace())
    edges = [LockOrderEdge(f"f{i}", "a.c", f"a{i}", f"b{i}", 1, 2) for i in range(8000)]
    monkeypatch.setattr(generator, "_lock_order_edges", lambda views: edges)
    calls = []
    monkeypatch.setattr(generator, "_locks_may_match", lambda a, b: calls.append((a, b)) or a == b)
    generator._rule_lock_order_inversion([], [])
    assert not calls


def test_unqualified_changed_rules_are_not_default_enabled():
    effective = EffectiveRuleSet.build(RuleCatalog.builtin(), language="c_cpp", backend="unified")
    assert MISMATCH_RULE not in effective.enabled_ids
    assert LEAK_RULE not in effective.enabled_ids
    assert "clang_cfg_unsynchronized_shared_flag_or_counter" not in effective.enabled_ids


@pytest.mark.parametrize("generator", [RegexCandidateGenerator, ClangAstCfgCandidateGenerator])
def test_timed_wait_requires_predicate_loop(generator):
    unsafe = generator().generate_issues(
        "demo", "void demo() {\nif (!ready) {\npthread_cond_timedwait(&cv, &mu, &ts);\n}\n}", "a.c"
    )
    safe = generator().generate_issues(
        "demo",
        "void demo() {\nwhile (!ready) {\npthread_cond_timedwait(&cv, &mu, &ts);\n}\n}",
        "a.c",
    )
    assert any(i["defect_class"] == "lost_wakeup" for i in unsafe)
    assert not any(i["defect_class"] == "lost_wakeup" for i in safe)


def test_graph_fact_cache_reuses_overlapping_entries_and_separates_source_changes():
    class Index:
        _index_epoch = 1
        calls = 0

        def get_function_impl(self, name, max_lines=500, warn_missing=False):
            assert max_lines is None
            self.calls += 1
            return {"code": "void leaf() {}", "file": "a.c", "callees": []}

    index = Index()
    first, second = GraphCandidateGenerator(index), GraphCandidateGenerator(index)
    assert first._view_for("leaf") == second._view_for("leaf")
    assert index.calls == 1
    index._index_epoch = 2
    third = GraphCandidateGenerator(index)
    third._view_for("leaf")
    assert index.calls == 2


def test_graph_cache_separates_compilation_context(tmp_path):
    path = tmp_path / "compile_commands.json"
    path.write_text("[]")

    class Index:
        compile_commands_path = path
        calls = 0

        def get_function_impl(self, *args, **kwargs):
            self.calls += 1
            return {"code": "void leaf() {}", "file": "a.c"}

    index = Index()
    GraphCandidateGenerator(index)._view_for("leaf")
    GraphCandidateGenerator(index)._view_for("leaf")
    assert index.calls == 1
    path.write_text('[{"command":"cc -DOTHER"}]')
    GraphCandidateGenerator(index)._view_for("leaf")
    assert index.calls == 2


@pytest.mark.parametrize("compiler_complete", [False, True])
def test_shared_access_index_reads_function_and_access_facts_once(compiler_complete):
    from zscope.core.candidates.cpp_domains.shared_access import SharedAccessIndex

    class CountedList(list):
        iterations = 0

        def __iter__(self):
            self.iterations += 1
            return super().__iter__()

    lines = CountedList(
        SimpleNamespace(number=i + 1, index=i, text="shared_value++;") for i in range(2000)
    )
    accesses = CountedList(
        {"location": {"line": i + 1}, "target": {"name": "shared_value"}} for i in range(2000)
    )
    index = SharedAccessIndex(
        lines, {"complete": compiler_complete, "accesses": accesses}, set(), set()
    )
    assert all(index.match(line)["global"] == "shared_value" for line in lines)
    assert accesses.iterations == 1
    # A declaration pass (fallback only), a lock-prefix pass, and the queries.
    assert lines.iterations <= 3


@pytest.mark.parametrize("generator", [RegexCandidateGenerator, ClangAstCfgCandidateGenerator])
def test_detectors_prepare_shared_access_index_once_per_function(generator, monkeypatch):
    from zscope.core.candidates.cpp_domains.shared_access import SharedAccessIndex

    original = SharedAccessIndex.__init__
    builds = []

    def record(self, lines, *args, **kwargs):
        builds.append(len(lines))
        original(self, lines, *args, **kwargs)

    monkeypatch.setattr(SharedAccessIndex, "__init__", record)
    detector = generator()
    for name in ("first", "second"):
        detector.generate_issues(
            name, f"void {name}() {{\nshared_value++;\nshared_value++;\n}}", "a.c"
        )
    assert len(builds) == 2
