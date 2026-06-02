from pathlib import Path

import pytest

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


def test_diff_repo_root_can_be_overridden(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    git_root = tmp_path / "repo"
    git_root.mkdir()

    runner = ScanSessionRunner(cfg, diff_base="base", diff_repo_root=git_root)

    assert runner.diff_repo_root == git_root.resolve()


def test_diff_paths_are_passed_to_diff_impact_planner(tmp_path: Path, monkeypatch) -> None:
    captured = {}

    class FakeCodeIndex:
        pass

    class FakePlan:
        changed_functions = [object()]
        entries = [FunctionEntry("api")]

        def to_entry_functions_payload(self):
            return {"diff_impact": {"entry_count": 1}, "functions": [{"function_name": "api"}]}

    class FakePlanner:
        def __init__(self, *args, **kwargs):
            captured["diff_paths"] = kwargs.get("diff_paths")

        def plan(self):
            return FakePlan()

        def write_entry_functions_file(self, path, plan):
            path.write_text('{"functions":[{"function_name":"api"}]}', encoding="utf-8")
            captured["entry_list_path"] = path
            return path

    monkeypatch.setattr(scan_session_module, "DiffImpactPlanner", FakePlanner)
    runner = ScanSessionRunner(
        _config(tmp_path),
        diff_base="base",
        diff_paths=["src/net", "src/fs"],
    )
    state = runner._create_state()
    state["code_index"] = FakeCodeIndex()

    runner._plan_diff_impact_entries(state)

    assert captured["diff_paths"] == ["src/net", "src/fs"]
    assert captured["entry_list_path"].exists()
    assert state["discovered_entry_functions_list"] == str(captured["entry_list_path"])


def test_empty_diff_path_result_stops_before_single_entry_fallback(tmp_path: Path, monkeypatch) -> None:
    captured = {}

    class FakeCodeIndex:
        pass

    class FakePlan:
        changed_functions = []
        entries = []

        def to_entry_functions_payload(self):
            return {"diff_impact": {"entry_count": 0}, "functions": []}

    class FakePlanner:
        def __init__(self, *args, **kwargs):
            pass

        def plan(self):
            return FakePlan()

        def write_entry_functions_file(self, path, plan):
            path.write_text('{"diff_impact":{"entry_count":0},"functions":[]}', encoding="utf-8")
            captured["entry_list_path"] = path
            return path

    monkeypatch.setattr(scan_session_module, "DiffImpactPlanner", FakePlanner)
    runner = ScanSessionRunner(
        _config(tmp_path),
        diff_base="base",
        diff_paths=["src/no-match"],
    )
    state = runner._create_state()
    state["code_index"] = FakeCodeIndex()

    with pytest.raises(RuntimeError, match="produced no scan entries"):
        runner._plan_diff_impact_entries(state)

    assert captured["entry_list_path"].exists()
    assert runner.config.project.entry_functions_list == captured["entry_list_path"]


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


def test_interrupted_entry_names_are_missing_result_entries(tmp_path: Path) -> None:
    runner = ScanSessionRunner(_config(tmp_path), resume=False)
    entries = [
        FunctionEntry("api_a"),
        FunctionEntry("api_b"),
        FunctionEntry("api_c", file_path="src/api.c"),
    ]

    missing = runner._interrupted_entry_names(entries, {"api_a": object()})

    assert missing == ["api_b", "api_c"]


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
