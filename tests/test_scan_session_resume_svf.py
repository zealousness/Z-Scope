from pathlib import Path

from zscope.config.config import (
    AnalysisConfig,
    IndexingConfig,
    LLMConfig,
    ProjectConfig,
    ZScopeConfig,
)
from zscope.config.function_entry import FunctionEntry
from zscope.orchestration import scan_session as scan_session_module
from zscope.orchestration.scan_session import ScanSessionRunner


def _config(tmp_path: Path) -> ZScopeConfig:
    return ZScopeConfig(
        llm=LLMConfig(),
        llms={"default": LLMConfig()},
        indexing=IndexingConfig(backend="unified"),
        analysis=AnalysisConfig(snapshot_dir=str(tmp_path / ".zscope_snapshots")),
        project=ProjectConfig(
            project_root=tmp_path,
            source_root=tmp_path,
            compile_commands_path=tmp_path / "compile_commands.json",
        ),
    )


def test_diff_repo_root_defaults_to_source_root(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    source_root = project_root / "src"
    source_root.mkdir(parents=True)
    cfg = ZScopeConfig(
        llm=LLMConfig(),
        llms={"default": LLMConfig()},
        indexing=IndexingConfig(),
        analysis=AnalysisConfig(snapshot_dir=str(project_root / ".zscope_snapshots")),
        project=ProjectConfig(
            project_root=project_root,
            source_root=source_root,
        ),
    )

    runner = ScanSessionRunner(cfg, diff_base="base")

    assert runner.diff_repo_root == source_root.resolve()


def test_resume_svf_scope_uses_original_entry_list(tmp_path: Path) -> None:
    runner = ScanSessionRunner(_config(tmp_path), resume=True)
    captured = {}

    class FakeCodeIndex:
        def run_svf(self, entries):
            captured["entries"] = [entry.function_name for entry in entries]

    state = {
        "code_index": FakeCodeIndex(),
        "all_entries": [
            FunctionEntry("api_a"),
            FunctionEntry("api_b"),
            FunctionEntry("api_c"),
        ],
    }

    runner._ensure_svf_for_entries(state, [FunctionEntry("api_c")])

    assert captured["entries"] == ["api_a", "api_b", "api_c"]


def test_default_svf_scope_uses_active_entries(tmp_path: Path) -> None:
    runner = ScanSessionRunner(_config(tmp_path), resume=False)
    captured = {}

    class FakeCodeIndex:
        def run_svf(self, entries):
            captured["entries"] = [entry.function_name for entry in entries]

    state = {
        "code_index": FakeCodeIndex(),
        "all_entries": [
            FunctionEntry("api_a"),
            FunctionEntry("api_b"),
        ],
    }

    runner._ensure_svf_for_entries(state, [FunctionEntry("api_b")])

    assert captured["entries"] == ["api_b"]


def test_resume_with_no_remaining_entries_defers_svf_initialization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    captured = {}

    class FakeCodeIndex:
        def __init__(self, *args, **kwargs):
            captured["svf_entry_functions"] = [
                entry.function_name for entry in kwargs.get("svf_entry_functions", [])
            ]
            captured["defer_svf"] = kwargs.get("defer_svf")

        def close(self):
            pass

    class FakeParallelAnalyzer:
        def __init__(self, *args, **kwargs):
            pass

        def analyze_function_entries(self, entries):
            captured["analyzed_entries"] = list(entries)
            return {}

        def generate_combined_report(self, results, output_path=None):
            if output_path:
                output_path.write_text("{}", encoding="utf-8")
            return {
                "summary": {
                    "total_issues": 0,
                    "functions_analyzed": len(results),
                    "needs_review_issues": 0,
                }
            }

        def generate_combined_markdown_report(self, results, output_path):
            output_path.write_text("# report\n", encoding="utf-8")
            return "# report\n"

    monkeypatch.setattr(scan_session_module, "CodeIndex", FakeCodeIndex)
    monkeypatch.setattr(scan_session_module, "ParallelAnalyzer", FakeParallelAnalyzer)

    runner = ScanSessionRunner(_config(tmp_path), resume=True)
    runner.batch_executor = type(
        "NoopBatchExecutor",
        (),
        {"execute": lambda self, state, steps: None},
    )()
    state = runner._create_state()
    state["batch_mode"] = True
    state["entries"] = []
    state["all_entries"] = [FunctionEntry("api_a"), FunctionEntry("api_b")]
    state["skipped_entries"] = list(state["all_entries"])

    runner._run_batch(state, [])

    assert captured["svf_entry_functions"] == ["api_a", "api_b"]
    assert captured["defer_svf"] is True
    assert captured["analyzed_entries"] == []
