import threading
from pathlib import Path

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
