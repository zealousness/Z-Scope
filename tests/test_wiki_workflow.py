from pathlib import Path
from types import SimpleNamespace

from zscope.config.config import (
    AnalysisConfig,
    IndexingConfig,
    LLMConfig,
    ProjectConfig,
    ZScopeConfig,
)
from zscope.config.function_entry import FunctionEntry
from zscope.core.analysis.analyzer import Analyzer
from zscope.orchestration import parallel_analyzer as parallel_module
from zscope.orchestration import scan_session as scan_session_module
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer
from zscope.orchestration.scan_session import ScanSessionResult, ScanSessionRunner
from zscope.orchestration.specs import WorkflowSpec
from zscope.rules.extensions import preflight_rules


def _config(tmp_path: Path) -> ZScopeConfig:
    config = ZScopeConfig(
        llm=LLMConfig(),
        llms={"default": LLMConfig()},
        indexing=IndexingConfig(backend="unified"),
        analysis=AnalysisConfig(snapshot_dir=str(tmp_path / ".zscope_snapshots")),
        project=ProjectConfig(
            project_root=tmp_path,
            source_root=tmp_path,
            compile_commands_path=tmp_path / "compile_commands.json",
            entry_function="main",
        ),
    )
    preflight_rules(config)
    return config


def test_builtin_workflows_compile_wiki_before_entry_steps() -> None:
    workflow_root = Path(scan_session_module.__file__).parents[1] / "workflows"

    for name in ("default", "resume", "maintain"):
        workflow = WorkflowSpec.from_yaml(workflow_root / f"{name}.yaml")
        wiki_index = next(
            index for index, step in enumerate(workflow.steps) if step.id == "wiki_compile"
        )
        first_entry_index = next(
            index for index, step in enumerate(workflow.steps) if step.scope == "entry"
        )
        assert workflow.steps[wiki_index].scope == "session"
        assert wiki_index < first_entry_index


def test_scan_session_finishes_wiki_compile_before_analysis(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _config(tmp_path)
    config.project.wiki.mode = "active"
    events = []

    class Resource:
        def __init__(self, name: str) -> None:
            self.name = name

        def close(self) -> None:
            events.append(f"{self.name}_close")

    class CompilerClient:
        def close(self) -> None:
            events.append("compiler_client_close")

    service = SimpleNamespace(
        source_index=Resource("source_index"),
        wiki_store=Resource("wiki_store"),
    )

    monkeypatch.setattr(
        ParallelAnalyzer,
        "_build_shared_llm_clients",
        staticmethod(lambda _config: {"default": CompilerClient()}),
    )

    def build_service(_config, _clients):
        events.append("wiki_compile")
        return service

    monkeypatch.setattr(
        Analyzer,
        "build_project_knowledge_service",
        staticmethod(build_service),
    )

    runner = ScanSessionRunner(config)

    def run_single(state):
        assert state["project_knowledge_service"] is service
        events.append("analysis")
        return ScanSessionResult(is_batch=False, exit_code=0)

    monkeypatch.setattr(runner, "_run_single", run_single)

    runner.run()

    assert events == [
        "wiki_compile",
        "analysis",
        "source_index_close",
        "wiki_store_close",
        "compiler_client_close",
    ]


def test_parallel_entries_receive_one_pinned_project_knowledge_service(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _config(tmp_path)
    service = object()
    seen_services = []

    class FakeCodeIndex:
        pass

    parallel = ParallelAnalyzer(
        config,
        code_index=FakeCodeIndex(),
        maintain_mode=True,
        project_knowledge_service=service,
    )

    class FakeAnalyzer:
        def __init__(self, *args, **kwargs) -> None:
            seen_services.append(kwargs.get("project_knowledge_service"))

        def run(self):
            return {
                "overall_verdict": "clean",
                "issues": [],
                "candidate_terminal_states": [],
                "metadata": {},
            }

    monkeypatch.setattr(parallel_module, "Analyzer", FakeAnalyzer)

    result = parallel._analyze_single_entry(FunctionEntry("main"))

    assert result.verdict == "clean"
    assert seen_services == [service]


def test_analyzer_closes_only_owned_project_knowledge_service() -> None:
    closed = []

    class Resource:
        def close(self) -> None:
            closed.append("closed")

    service = SimpleNamespace(source_index=Resource(), wiki_store=Resource())
    analyzer = object.__new__(Analyzer)
    analyzer.project_knowledge_service = service
    analyzer._owns_llm_clients = False

    analyzer._owns_project_knowledge_service = False
    analyzer.close()
    assert closed == []

    analyzer._owns_project_knowledge_service = True
    analyzer.close()
    assert closed == ["closed", "closed"]
