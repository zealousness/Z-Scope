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
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer
from zscope.orchestration.scan_session import ScanSessionRunner
from zscope.snapshots.store import SnapshotStore


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


def test_review_counts_separate_visible_findings_from_manifest_obligations() -> None:
    report = {
        "summary": {"needs_review_issues": 30},
        "report_views": {
            "with_needs_review": {"included_needs_review_count": 29}
        },
        "run_manifest": {"needs_review_count": 951},
    }

    assert ScanSessionRunner._needs_review_count_from_report(report) == 30
    assert ScanSessionRunner._unresolved_obligations_count_from_report(report) == 951


def test_unresolved_obligations_fall_back_to_terminal_candidate_ledger() -> None:
    report = {
        "report_views": {
            "with_needs_review": {"included_needs_review_count": 1}
        },
        "candidate_terminal_states": [
            {
                "candidate_uid": "candidate-visible",
                "candidate_disposition": "needs_review",
            },
            {
                "candidate_uid": "candidate-deferred",
                "candidate_disposition": "deferred_budget",
            },
            {
                "candidate_uid": "candidate-confirmed",
                "candidate_disposition": "confirmed",
            },
        ],
    }

    assert ScanSessionRunner._needs_review_count_from_report(report) == 1
    assert ScanSessionRunner._unresolved_obligations_count_from_report(report) == 2


class _ResumeCodeIndex:
    def __init__(self, indexes, referenced_macros=None, referenced_types=None):
        self.indexes = dict(indexes)
        self.referenced_macros = dict(referenced_macros or {})
        self.referenced_types = dict(referenced_types or {})

    def find_function_infos(self, func_name: str, file_path: str = ""):
        index_name = self.indexes.get(file_path)
        if not index_name:
            return []
        start_end = index_name.rsplit(":", 1)[-1].split("-", 1)
        return [
            {
                "function_name": func_name.split("@", 1)[0],
                "index_name": index_name,
                "file_path": file_path,
                "start_line": int(start_end[0]),
                "end_line": int(start_end[-1]),
                "signature": "int handle_request(void)",
                "is_static": False,
                "is_macro": False,
                "callees": [],
                "referenced_globals": [],
                "referenced_macros": list(self.referenced_macros.get(file_path) or []),
                "referenced_types": list(self.referenced_types.get(file_path) or []),
            }
        ]

    def get_function_impl(self, func_name: str, **kwargs):
        file_path = str(kwargs.get("file_path") or "")
        index_name = self.indexes.get(file_path)
        if not index_name:
            for candidate_file, candidate_index in self.indexes.items():
                if func_name == candidate_index:
                    file_path = candidate_file
                    index_name = candidate_index
                    break
        if not index_name:
            return None
        start_end = index_name.rsplit(":", 1)[-1].split("-", 1)
        return {
            "func_name": "handle_request",
            "index_name": index_name,
            "file": file_path,
            "start_line": int(start_end[0]),
            "end_line": int(start_end[-1]),
            "code": "int handle_request(void) { return 0; }\n",
        }


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


def test_resume_does_not_skip_entry_when_only_other_path_has_final_report(
    tmp_path: Path,
) -> None:
    cfg = _config(tmp_path)
    store = SnapshotStore(Path(cfg.analysis.snapshot_dir))
    left_index = "handle_request@src/a.c:10-10"
    right_index = "handle_request@src/b.c:20-20"
    store.save_snapshot(
        left_index,
        {
            "func_name": "handle_request",
            "index_name": left_index,
            "file_path": "src/a.c",
            "start_line": 10,
            "end_line": 10,
            "summary": "a",
            "referenced_globals": [],
            "referenced_macros": [],
            "referenced_types": [],
        },
        "int handle_request(void) { return 1; }\n",
    )
    store.save_snapshot(
        right_index,
        {
            "func_name": "handle_request",
            "index_name": right_index,
            "file_path": "src/b.c",
            "start_line": 20,
            "end_line": 20,
            "summary": "b",
            "referenced_globals": [],
            "referenced_macros": [],
            "referenced_types": [],
        },
        "int handle_request(void) { return 2; }\n",
    )
    store.save_final_report(
        left_index,
        {"overall_verdict": "no_issue_found", "issues": []},
    )

    runner = ScanSessionRunner(cfg, resume=True)
    entry = FunctionEntry("handle_request", file_path="src/b.c")
    state = {
        "entries_loaded": True,
        "batch_mode": True,
        "entries": [entry],
        "code_index": _ResumeCodeIndex(
            {
                "src/a.c": left_index,
                "src/b.c": right_index,
            }
        ),
    }

    runner._handle_plan_resume_entries(state, None)  # type: ignore[arg-type]

    assert state["entries"] == [entry]
    assert state["skipped_entries"] == []


def test_resume_merges_duplicate_function_reports_by_entry_path(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    store = SnapshotStore(Path(cfg.analysis.snapshot_dir))
    reports = {
        "src/a.c": {
            "schema_version": 2,
            "overall_verdict": "issues_found",
            "finding_status": "confirmed",
            "completeness": "complete",
                "run_manifest": {
                    "valid": True,
                    "candidate_schema_version": "zscope.candidate.v3.3",
                },
            "issues": [{"source": "a"}],
        },
        "src/b.c": {
            "schema_version": 2,
            "overall_verdict": "no_issue_found",
            "finding_status": "clean",
            "completeness": "complete",
                "run_manifest": {
                    "valid": True,
                    "candidate_schema_version": "zscope.candidate.v3.3",
                },
            "issues": [{"source": "b"}],
        },
    }
    for file_path, report in reports.items():
        index_name = f"handle_request@{file_path}:10-10"
        store.save_snapshot(
            index_name,
            {
                "func_name": "handle_request",
                "index_name": index_name,
                "file_path": file_path,
                "start_line": 10,
                "end_line": 10,
                "summary": file_path,
                "referenced_globals": [],
                "referenced_macros": [],
                "referenced_types": [],
            },
            "int handle_request(void) { return 0; }\n",
        )
        store.save_final_report(index_name, report)

    entries = [
        FunctionEntry("handle_request", file_path="src/a.c"),
        FunctionEntry("handle_request", file_path="src/b.c"),
    ]
    runner = ScanSessionRunner(cfg, resume=True)
    state = {
        "entries_loaded": True,
        "batch_mode": True,
        "entries": list(entries),
        "code_index": _ResumeCodeIndex(
            {
                "src/a.c": "handle_request@src/a.c:10-10",
                "src/b.c": "handle_request@src/b.c:10-10",
            }
        ),
    }

    runner._handle_plan_resume_entries(state, None)  # type: ignore[arg-type]
    state["results"] = {}
    runner._handle_merge_skipped_reports(state, None)  # type: ignore[arg-type]

    expected_keys = {ParallelAnalyzer._entry_result_key(entry) for entry in entries}
    assert state["entries"] == []
    assert set(state["results"]) == expected_keys
    assert state["results"]["default:handle_request@src/a.c"].issues == [{"source": "a"}]
    assert state["results"]["default:handle_request@src/b.c"].issues == [{"source": "b"}]


def test_resume_does_not_skip_when_symbol_context_changed(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    store = SnapshotStore(Path(cfg.analysis.snapshot_dir))
    file_path = "src/a.c"
    index_name = "handle_request@src/a.c:10-10"
    old_macro = {
        "macro_index_name": "LIMIT@include/limits.h:3-3",
        "definition": "3 | #define LIMIT 8\n",
        "is_function_like": False,
        "reference_lines": [10],
    }
    store.save_snapshot(
        index_name,
        {
            "func_name": "handle_request",
            "index_name": index_name,
            "file_path": file_path,
            "start_line": 10,
            "end_line": 10,
            "summary": "old",
            "referenced_globals": [],
            "referenced_macros": [old_macro],
            "referenced_types": [],
        },
        "int handle_request(void) { return 0; }\n",
    )
    store.save_final_report(
        index_name,
        {"overall_verdict": "no_issue_found", "issues": []},
    )
    current_macro = {**old_macro, "definition": "3 | #define LIMIT 16\n"}
    runner = ScanSessionRunner(cfg, resume=True)
    entry = FunctionEntry("handle_request", file_path=file_path)
    state = {
        "entries_loaded": True,
        "batch_mode": True,
        "entries": [entry],
        "code_index": _ResumeCodeIndex(
            {file_path: index_name},
            referenced_macros={file_path: [current_macro]},
        ),
    }

    runner._handle_plan_resume_entries(state, None)  # type: ignore[arg-type]

    assert state["entries"] == [entry]
    assert state["skipped_entries"] == []


def test_resume_does_not_skip_when_type_context_changed(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    store = SnapshotStore(Path(cfg.analysis.snapshot_dir))
    file_path = "src/a.c"
    index_name = "handle_request@src/a.c:10-10"
    old_type = {
        "type_index_name": "Context@include/context.h:1-3",
        "kind": "struct",
        "full_definition": "1 | typedef struct { int value; } Context;\n",
        "reference_kinds": ["parameter"],
        "reference_lines": [10],
    }
    store.save_snapshot(
        index_name,
        {
            "func_name": "handle_request",
            "index_name": index_name,
            "file_path": file_path,
            "start_line": 10,
            "end_line": 10,
            "summary": "old",
            "referenced_globals": [],
            "referenced_macros": [],
            "referenced_types": [old_type],
        },
        "int handle_request(void) { return 0; }\n",
    )
    store.save_final_report(
        index_name,
        {"overall_verdict": "no_issue_found", "issues": []},
    )
    current_type = {
        **old_type,
        "full_definition": "typedef struct { long value; } Context;",
    }
    runner = ScanSessionRunner(cfg, resume=True)
    entry = FunctionEntry("handle_request", file_path=file_path)
    state = {
        "entries_loaded": True,
        "batch_mode": True,
        "entries": [entry],
        "code_index": _ResumeCodeIndex(
            {file_path: index_name},
            referenced_types={file_path: [current_type]},
        ),
    }

    runner._handle_plan_resume_entries(state, None)  # type: ignore[arg-type]

    assert state["entries"] == [entry]
    assert state["skipped_entries"] == []


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
