"""The ordinary ScanSession must execute the precise EntryInstancePlan.

A C/C++ scan that has verifiable compile instances runs one real Analyzer per
``(BuildContext, USR)`` instance and never builds the project-wide semantic
model; a C/C++ scan with no verifiable instance reports the explicit coverage
gap instead of falling back to a name-only analysis of an unknown build.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

from zscope.config.function_entry import FunctionEntry
from zscope.orchestration.scan_session import ScanSessionRunner

DOUBLE_FREE_SOURCE = (
    "#include <stdlib.h>\n"
    "void f(void) {\n"
    "  char *p = malloc(4);\n"
    "  if (!p) { return; }\n"
    "  RELEASE(p);\n"
    "}\n"
)
RELEASE_BASE = "-DRELEASE(p)=free(p)"
RELEASE_ALT = "-DRELEASE(p)=do { free(p); free(p); } while (0)"


def _write_project(tmp_path: Path, *, variants: bool = True) -> Path:
    if variants:
        (tmp_path / "unit.c").write_text(DOUBLE_FREE_SOURCE, encoding="utf-8")
    rows: List[Dict[str, Any]] = []
    if variants:
        for macro in (RELEASE_BASE, RELEASE_ALT):
            rows.append(
                {
                    "directory": str(tmp_path),
                    "file": str(tmp_path / "unit.c"),
                    "arguments": ["clang", "-c", str(tmp_path / "unit.c"), macro],
                }
            )
    else:
        # A real index, but no compilation instance contains the scan entry.
        (tmp_path / "other.c").write_text("void g(void) { }\n", encoding="utf-8")
        rows.append(
            {
                "directory": str(tmp_path),
                "file": str(tmp_path / "other.c"),
                "arguments": ["clang", "-c", str(tmp_path / "other.c")],
            }
        )
    (tmp_path / "compile_commands.json").write_text(json.dumps(rows), encoding="utf-8")
    return tmp_path


def _config(tmp_path: Path, *, single: bool = True, entry_list: bool = False):
    from zscope.config.config import (
        AgentConfig,
        AnalysisConfig,
        ConcurrencyConfig,
        IndexingConfig,
        LLMConfig,
        ProjectConfig,
        RulesConfig,
        ZScopeConfig,
    )
    from zscope.rules.extensions import preflight_rules

    entry_file = tmp_path / "entry_functions_list.json"
    if entry_list:
        entry_file.write_text(
            json.dumps({"functions": [{"function_name": "f", "file_path": "unit.c"}]}),
            encoding="utf-8",
        )
    config = ZScopeConfig(
        llm=LLMConfig(),
        llms={},
        indexing=IndexingConfig(
            backend="clang",
            clang_frontend="batch",
            clang_indexer_path=str(os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER") or ""),
            max_clangd_threads=2,
        ),
        analysis=AnalysisConfig(
            snapshot_dir=str(tmp_path / ".zscope_snapshots"),
            user_config_db=str(tmp_path / ".zscope_user_config"),
        ),
        project=ProjectConfig(
            project_root=tmp_path,
            source_root=tmp_path,
            language="c_cpp",
            include_paths=[str(tmp_path)],
            compile_commands_path=tmp_path / "compile_commands.json",
            agents=[AgentConfig(name="vulnerability_analyzer", task="audit")],
            entry_function="f" if single else None,
            entry_file_path="unit.c" if single else None,
            entry_functions_list=entry_file if entry_list else None,
        ),
        concurrency=ConcurrencyConfig(entry_workers=2),
        rules=RulesConfig(enabled_ids=["clang_cfg_same_object_released_twice"]),
    )
    preflight_rules(config)
    return config


@pytest.fixture
def native_symbol_project(tmp_path, monkeypatch):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("scan session instance tests require Z_SCOPE_TEST_CLANG_INDEXER")
    monkeypatch.setenv("Z_SCOPE_TEST_CLANG_INDEXER", executable)
    _write_project(tmp_path)
    return tmp_path


def _forbid_global_modeling(monkeypatch) -> None:
    from zscope.orchestration.global_modeler import GlobalModeler

    def _fail(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("the instance scan must not build the project-wide semantic model")

    monkeypatch.setattr(GlobalModeler, "from_analyzer_helpers", staticmethod(_fail))


def _read_report(path: Path) -> Dict[str, Any]:
    from zscope.reporting.json_io import read_report

    return read_report(path)


def _instance_analysis(report: Dict[str, Any]) -> Dict[str, Any]:
    plan = (report.get("metadata") or {}).get("entry_instances") or {}
    return plan.get("instance_analysis") or {}


def test_single_entry_session_runs_exact_instances(native_symbol_project, monkeypatch) -> None:
    _forbid_global_modeling(monkeypatch)
    root = native_symbol_project
    config = _config(root)
    runner = ScanSessionRunner(config, task_id="inst/scan")
    result = runner.run()

    assert result.is_batch is False
    report = _read_report(root / "report.json")
    plan = report["metadata"]["entry_instances"]
    assert plan["status"] == "planned"
    assert plan["scheduled_instances"] == 2
    analysis = _instance_analysis(report)
    assert analysis["analyzed_instances"] == 2
    assert analysis["instance_scope_complete"] is True
    assert analysis["scan_coverage_complete"] is False

    per_instance = analysis["instances"]
    assert len(per_instance) == 2
    counts = sorted(item["candidate_count"] for item in per_instance)
    assert counts == [0, 1], per_instance
    with_candidate = next(item for item in per_instance if item["candidate_count"])
    assert [candidate["defect_class"] for candidate in with_candidate["candidates"]] == [
        "double_free"
    ]
    for item in with_candidate["candidates"]:
        assert item["build_context_id"] == with_candidate["build_context_id"]


def test_batch_session_runs_exact_instances(native_symbol_project, monkeypatch) -> None:
    _forbid_global_modeling(monkeypatch)
    root = native_symbol_project
    config = _config(root, single=False, entry_list=True)
    runner = ScanSessionRunner(config, task_id="inst/batch")
    result = runner.run()

    assert result.is_batch is True
    report = _read_report(root / "zscope_batch_report_inst_batch.json")
    plan = report["metadata"]["entry_instances"]
    assert plan["scheduled_instances"] == 2
    analysis = _instance_analysis(report)
    assert analysis["analyzed_instances"] == 2
    counts = sorted(item["candidate_count"] for item in analysis["instances"])
    assert counts == [0, 1]


def test_no_verifiable_instance_does_not_fall_back_to_name_only(tmp_path, monkeypatch) -> None:
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("scan session instance tests require Z_SCOPE_TEST_CLANG_INDEXER")
    _write_project(tmp_path, variants=False)  # compile database with no command
    config = _config(tmp_path)

    from zscope.orchestration import parallel_analyzer as parallel_module

    def _forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("a scan with no verifiable instance must not analyze by name")

    monkeypatch.setattr(parallel_module.ParallelAnalyzer, "analyze_function_entries", _forbidden)

    runner = ScanSessionRunner(config, task_id="inst/gap")
    result = runner.run()

    report = _read_report(tmp_path / "report.json")
    assert report["completeness"] == "incomplete"
    assert report["summary"]["total_issues"] == 0
    plan = report["metadata"]["entry_instances"]
    assert plan["status"] == "planned"
    assert plan["planned_instances"] == 0
    assert plan["gaps"]
    assert plan["scheduled_instances"] is None
    assert report["metadata"]["instance_execution"]["mode"] == "gap"
    assert result.exit_code == 2


def test_java_scan_keeps_its_own_execution_path(tmp_path, monkeypatch) -> None:
    from zscope.orchestration.scan_session import ScanSessionRunner as _Runner

    config = _config(tmp_path)
    config.project.language = "java"
    config.project.compile_commands_path = None
    runner = _Runner(config)
    state = runner._create_state()
    state["entries"] = [FunctionEntry("F", file_path="A.java")]
    runner._plan_entry_instances(state)
    assert runner._instance_execution_mode(state) == "legacy"


@pytest.mark.parametrize("batch", [False, True])
def test_cpp_resume_runs_exact_instances_without_global_semantics(
    native_symbol_project, monkeypatch, batch
) -> None:
    """The real ``resume`` workflow must not borrow global/name-only evidence.

    Both the single-entry and the batch resume must run the precise current
    instance plan and report every variant, never skipping an entry from a
    name-only saved report nor building the project-wide semantic model.
    """

    root = native_symbol_project
    _forbid_global_modeling(monkeypatch)
    config = _config(root, single=not batch, entry_list=batch)
    config.analysis.workflow_name = "resume"
    runner = ScanSessionRunner(config, resume=True, task_id="inst/resume")

    def _forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("precise instance resume must not use the unscoped semantic phase")

    monkeypatch.setattr(runner, "_ensure_semantic_phase", _forbidden)
    monkeypatch.setattr(runner, "_load_current_saved_report", _forbidden)

    runner.run()

    report_path = root / "zscope_batch_report_inst_resume.json" if batch else root / "report.json"
    report = _read_report(report_path)
    plan = report["metadata"]["entry_instances"]
    assert plan["planned_instances"] == 2
    assert plan["scheduled_instances"] == 2
    analysis = _instance_analysis(report)
    assert analysis["analyzed_instances"] == 2
    assert analysis["instance_scope_complete"] is True
    counts = sorted(item["candidate_count"] for item in analysis["instances"])
    assert counts == [0, 1], analysis["instances"]
    with_candidate = next(item for item in analysis["instances"] if item["candidate_count"])
    assert [c["defect_class"] for c in with_candidate["candidates"]] == ["double_free"]
    for item in analysis["instances"]:
        for candidate in item["candidates"]:
            assert candidate["build_context_id"] == item["build_context_id"]


def test_java_resume_keeps_its_semantic_phase(tmp_path, monkeypatch) -> None:
    """Java has no compilation instances, so its own resume path stays."""

    config = _config(tmp_path)
    config.project.language = "java"
    config.project.compile_commands_path = None
    runner = ScanSessionRunner(config, resume=True)
    state = runner._create_state()

    semantic_calls: List[str] = []
    monkeypatch.setattr(runner, "_ensure_batch_entries", lambda _state: None)
    monkeypatch.setattr(
        runner, "_ensure_semantic_phase", lambda _state: semantic_calls.append("semantic")
    )

    handled = runner._handle_plan_resume_entries(state, None)  # type: ignore[arg-type]

    assert semantic_calls == ["semantic"]
    assert handled is False
