import threading
from pathlib import Path

import pytest

from zscope.config.config import (
    AgentConfig,
    AnalysisConfig,
    IndexingConfig,
    LLMConfig,
    ProjectConfig,
    ZScopeConfig,
)
from zscope.config.function_entry import FunctionEntry
from zscope.core.analysis import analyzer as analyzer_module
from zscope.orchestration import parallel_analyzer as parallel_module
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer
from zscope.orchestration.subagents import SubAgentTicket
from zscope.semantics.models import LocalPatternSemantics


class FakeCodeIndex:
    pass


def _config(tmp_path: Path) -> ZScopeConfig:
    llm = LLMConfig(api_key="test", base_url="http://localhost", models=["test"])
    return ZScopeConfig(
        llm=llm,
        llms={"default": llm},
        indexing=IndexingConfig(),
        analysis=AnalysisConfig(
            snapshot_dir=str(tmp_path / "snapshots"),
            user_config_db=str(tmp_path / "user-config"),
            parallel_workers=3,
        ),
        project=ProjectConfig(
            project_root=tmp_path,
            source_root=tmp_path,
            agents=[AgentConfig(name="vulnerability_analyzer", task="audit")],
        ),
    )


def test_parallel_analyzer_builds_shared_semantics_once_per_batch(monkeypatch, tmp_path) -> None:
    counts = {"build": 0, "compile": 0}
    seen_semantics = []
    seen_overlays = []
    seen_lock = threading.Lock()

    class CountingLocalPatternSemanticBuilder:
        def __init__(self, *args, **kwargs):
            pass

        def build(self) -> LocalPatternSemantics:
            counts["build"] += 1
            semantics = LocalPatternSemantics()
            semantics.add_api("allocator", "shared_alloc", "test-builder")
            return semantics

    class CountingSemanticOverlayCompiler:
        def __init__(self, *args, **kwargs):
            pass

        def compile(self):
            counts["compile"] += 1
            return {"pointer_targets": [{"name": "shared_pointer_target"}]}

    def fake_run(self):
        semantics = self._get_local_pattern_semantics()
        overlay = self._get_semantic_overlay()
        assert "shared_alloc" in semantics.allocators
        assert overlay["pointer_targets"][0]["name"] == "shared_pointer_target"

        semantics.add_api(
            "allocator",
            f"{self.config.project.entry_function}_alloc",
            "test-run",
        )
        overlay.setdefault("mutated_entries", []).append(self.config.project.entry_function)

        with seen_lock:
            seen_semantics.append(semantics)
            seen_overlays.append(overlay)

        return {
            "overall_verdict": "clean",
            "issues": [],
            "metadata": {"audit_observations": [], "context_tokens": 1},
        }

    monkeypatch.setattr(
        parallel_module,
        "LocalPatternSemanticBuilder",
        CountingLocalPatternSemanticBuilder,
    )
    monkeypatch.setattr(
        analyzer_module,
        "LocalPatternSemanticBuilder",
        CountingLocalPatternSemanticBuilder,
    )
    monkeypatch.setattr(
        parallel_module,
        "SemanticOverlayCompiler",
        CountingSemanticOverlayCompiler,
    )
    monkeypatch.setattr(
        analyzer_module,
        "SemanticOverlayCompiler",
        CountingSemanticOverlayCompiler,
    )
    monkeypatch.setattr(analyzer_module.Analyzer, "run", fake_run)

    parallel = ParallelAnalyzer(_config(tmp_path), code_index=FakeCodeIndex())
    results = parallel.analyze_function_entries(
        [
            FunctionEntry("alpha"),
            FunctionEntry("beta"),
            FunctionEntry("gamma"),
        ]
    )

    assert counts == {"build": 1, "compile": 1}
    assert set(results) == {"alpha", "beta", "gamma"}
    assert {result.verdict for result in results.values()} == {"clean"}

    assert len(seen_semantics) == 3
    assert len({id(semantics) for semantics in seen_semantics}) == 3
    assert "alpha_alloc" not in parallel._shared_local_pattern_semantics.allocators
    assert "beta_alloc" not in parallel._shared_local_pattern_semantics.allocators
    assert "gamma_alloc" not in parallel._shared_local_pattern_semantics.allocators

    assert len(seen_overlays) == 3
    assert len({id(overlay) for overlay in seen_overlays}) == 3
    assert "mutated_entries" not in parallel._shared_semantic_overlay


def test_parallel_analyzer_runs_global_model_before_entries(monkeypatch, tmp_path) -> None:
    events = []

    class CountingLocalPatternSemanticBuilder:
        def __init__(self, *args, **kwargs):
            pass

        def build(self) -> LocalPatternSemantics:
            return LocalPatternSemantics()

    class CountingSemanticOverlayCompiler:
        def __init__(self, *args, **kwargs):
            pass

        def compile(self):
            return {}

    class FakeStats:
        reachable_functions = 1
        modeled_functions = 1
        cache_hit_functions = 0
        deterministic_snapshot_count = 0
        llm_snapshot_count = 1
        failed_functions = 0
        unresolved_entry_functions = 0
        reconciled_functions = 1
        reconciliation_failures = 0
        stage_complete = True

        def to_dict(self):
            return {"reachable_functions": 1, "modeled_functions": 1}

    class FakeGlobalModeler:
        def run(self, entries):
            events.append(("global", [entry.function_name for entry in entries]))
            return FakeStats()

    def fake_from_helpers(*args, **kwargs):
        return FakeGlobalModeler()

    def fake_run(self):
        events.append(("entry", self.config.project.entry_function))
        return {
            "overall_verdict": "clean",
            "issues": [],
            "metadata": {"audit_observations": [], "context_tokens": 1},
        }

    monkeypatch.setattr(
        parallel_module,
        "LocalPatternSemanticBuilder",
        CountingLocalPatternSemanticBuilder,
    )
    monkeypatch.setattr(
        analyzer_module,
        "LocalPatternSemanticBuilder",
        CountingLocalPatternSemanticBuilder,
    )
    monkeypatch.setattr(
        parallel_module,
        "SemanticOverlayCompiler",
        CountingSemanticOverlayCompiler,
    )
    monkeypatch.setattr(
        analyzer_module,
        "SemanticOverlayCompiler",
        CountingSemanticOverlayCompiler,
    )
    monkeypatch.setattr(parallel_module.GlobalModeler, "from_analyzer_helpers", fake_from_helpers)
    monkeypatch.setattr(analyzer_module.Analyzer, "run", fake_run)

    config = _config(tmp_path)
    config.analysis.enable_global_model = True
    parallel = ParallelAnalyzer(config, code_index=FakeCodeIndex())
    results = parallel.analyze_function_entries([FunctionEntry("alpha")])

    assert list(results) == ["alpha"]
    assert events == [("global", ["alpha"]), ("entry", "alpha")]
    assert parallel._last_global_model_stats == {
        "reachable_functions": 1,
        "modeled_functions": 1,
    }


def test_parallel_analyzer_stops_when_global_model_fails(monkeypatch, tmp_path) -> None:
    observed_flags = []

    class CountingLocalPatternSemanticBuilder:
        def __init__(self, *args, **kwargs):
            pass

        def build(self) -> LocalPatternSemantics:
            return LocalPatternSemantics()

    class CountingSemanticOverlayCompiler:
        def __init__(self, *args, **kwargs):
            pass

        def compile(self):
            return {}

    class IncompleteStats:
        reachable_functions = 1
        modeled_functions = 0
        cache_hit_functions = 0
        deterministic_snapshot_count = 0
        llm_snapshot_count = 0
        failed_functions = 1
        unresolved_entry_functions = 0
        reconciled_functions = 0
        reconciliation_failures = 0
        stage_complete = False

        def to_dict(self):
            return {"failed_functions": 1, "stage_complete": False}

    class IncompleteGlobalModeler:
        def run(self, entries):
            return IncompleteStats()

    def incomplete_global_model(*args, **kwargs):
        return IncompleteGlobalModeler()

    def fake_run(self):
        observed_flags.append(self.config.analysis.enable_global_model)
        return {
            "overall_verdict": "clean",
            "issues": [],
            "metadata": {"audit_observations": [], "context_tokens": 1},
        }

    monkeypatch.setattr(
        parallel_module,
        "LocalPatternSemanticBuilder",
        CountingLocalPatternSemanticBuilder,
    )
    monkeypatch.setattr(
        analyzer_module,
        "LocalPatternSemanticBuilder",
        CountingLocalPatternSemanticBuilder,
    )
    monkeypatch.setattr(
        parallel_module,
        "SemanticOverlayCompiler",
        CountingSemanticOverlayCompiler,
    )
    monkeypatch.setattr(
        analyzer_module,
        "SemanticOverlayCompiler",
        CountingSemanticOverlayCompiler,
    )
    monkeypatch.setattr(
        parallel_module.GlobalModeler,
        "from_analyzer_helpers",
        incomplete_global_model,
    )
    monkeypatch.setattr(analyzer_module.Analyzer, "run", fake_run)

    config = _config(tmp_path)
    config.analysis.enable_global_model = True
    parallel = ParallelAnalyzer(config, code_index=FakeCodeIndex())
    with pytest.raises(RuntimeError, match="Global semantic modeling did not complete"):
        parallel.analyze_function_entries([FunctionEntry("alpha")])

    assert observed_flags == []
    assert parallel._last_global_model_stats == {
        "failed_functions": 1,
        "stage_complete": False,
    }


def test_scan_validation_queue_validates_one_shared_ledger_group(tmp_path) -> None:
    """Wrapper occurrences are merged before any validator work is scheduled."""

    parallel = ParallelAnalyzer(_config(tmp_path), code_index=FakeCodeIndex())
    ticket = SubAgentTicket(
        id="RULE_1",
        skill="bounds",
        task="validate one structured bounds obligation",
        trigger="copy",
        line=12,
        context_slice="copy(dst, src, count);",
        priority_score=90,
        origin="src/demo.c:10",
        sink="src/demo.c:12",
        resource_kind="buffer",
        evidence={
            "candidate_uid": "CAND_SHARED",
            "evidence_hash": "evidence",
            "decision_evidence_hash": "decision",
            "validation_cluster_uid": "VAL_SHARED",
            "context_signature": "context",
            "candidate_payload": {
                "id": "RULE_1",
                "category": "bounds",
                "defect_class": "bounds",
                "function": "sink",
                "source": "count",
                "sink": "copy(dst, src, count)",
                "location": "src/demo.c:12",
            },
        },
    )
    parallel._candidate_ledger.add(
        ticket,
        source="clang_ast_cfg",
        call_path=["entry_a", "sink"],
        record_role="validation_obligation",
        entry_identity="entry_a",
    )
    parallel._candidate_ledger.add(
        ticket,
        source="graph_rule",
        call_path=["entry_b", "sink"],
        record_role="validation_obligation",
        entry_identity="entry_b",
    )

    parallel._run_scan_validation_queue()

    assert parallel._global_validation_state["validation_group_count"] == 1
    assert parallel._global_validation_state["scan_level_raw_occurrence_count"] == 2
    snapshot = parallel._candidate_ledger.lifecycle_snapshot()
    assert snapshot["summary"]["validation_group_count"] == 1
    assert snapshot["summary"]["raw_occurrence_count"] == 2
    assert snapshot["outcomes"][0]["candidate_disposition"] == "needs_review"
    # This fixture deliberately has no Validator agent, so the runner closes
    # the one queued obligation as review without issuing an LLM attempt.
    # ``test_validation_runner_selects_one_representative_per_validation_cluster``
    # covers the corresponding one-validator-call coalescing behavior.
    assert snapshot["outcomes"][0]["validation_attempt_count"] == 0


def test_project_deterministic_fact_pass_collects_reachable_function_once(tmp_path) -> None:
    class ReachableCodeIndex:
        def get_function_impl(self, name, **_kwargs):
            code = {
                "entry_a": """
int entry_a(void) {
    return worker();
}
""",
                "entry_b": """
int entry_b(void) {
    return worker();
}
""",
                "worker": """
int worker(void) {
    Job job;
    pthread_create(&tid, NULL, thread_main, &job);
    pthread_detach(tid);
    return 0;
}
""",
            }.get(name)
            if code is None:
                return None
            return {
                "name": name,
                "index_name": f"{name}@src/demo.c",
                "file": "src/demo.c",
                "code": code,
            }

        def get_callees(self, name, limit=0):
            del limit
            return [{"name": "worker", "file": "src/demo.c"}] if name.startswith("entry_") else []

    config = _config(tmp_path)
    config.analysis.project_deterministic_fact_pass_v1 = True
    config.analysis.decision_fact_graph_v1 = True
    config.analysis.decision_context_v32 = True
    parallel = ParallelAnalyzer(config, code_index=ReachableCodeIndex())
    parallel._shared_local_pattern_semantics = LocalPatternSemantics()
    parallel._shared_semantic_overlay = {}

    parallel._run_project_deterministic_fact_pass(
        [FunctionEntry("entry_a"), FunctionEntry("entry_b")]
    )

    state = parallel._project_fact_pass_state
    assert state["status"] == "complete"
    assert state["reachable_functions"] == 3
    records = parallel._candidate_ledger.records()
    stack_records = [record for record in records if record.defect_class == "stack_escape"]
    assert len(stack_records) == 1
    assert len(stack_records[0].occurrence_uids) == 2
