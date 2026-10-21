"""Native job publication must reject revoked emitting inputs before writes."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3

import pytest

from test_job_runtime_footprint_r34 import project
from test_scan_session_instances import _config, _instance_analysis, _read_report
from test_scan_session_jobs import _completed_by_kind, _run_dir
from zscope.orchestration.jobs.models import JobError
from zscope.orchestration.scan_session import ScanSessionRunner
from zscope.retrieval.build_context import context_input_status


def _identity(path: Path):
    observed = path.stat()
    return {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": observed.st_size,
        "mtime_ns": observed.st_mtime_ns,
        "ctime_ns": observed.st_ctime_ns,
        "device": observed.st_dev,
        "inode": observed.st_ino,
        "mode": observed.st_mode,
        "links": observed.st_nlink,
    }


def _store_observation(monkeypatch, store, observed):
    original_connect = sqlite3.connect

    def connect(database, *args, **kwargs):
        matches = Path(os.fsdecode(database)).resolve() == store.db_path.resolve()
        row = None
        if matches:
            row = {
                "native_plan_finished": bool(observed["native_plans"]),
                "physical_database": str(store.db_path.resolve()),
                "sidecars_before": {
                    suffix: Path(str(store.db_path) + suffix).exists()
                    for suffix in ("-wal", "-shm", "-journal")
                },
            }
            observed["store_connects"].append(row)
        # Forward the actual factory and every argument unchanged. No fake
        # connection, SQL result, generation, lock or currentness is supplied.
        connection = original_connect(database, *args, **kwargs)
        if row is not None:
            row["connect_returned"] = True
            row["sidecars_on_return"] = {
                suffix: Path(str(store.db_path) + suffix).exists()
                for suffix in ("-wal", "-shm", "-journal")
            }
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)


def _plan_observation(monkeypatch, observed, after_plan=None):
    original = ScanSessionRunner._build_entry_instance_plan

    def build(runner, state):
        plan = original(runner, state)
        assert plan.boundary_coverage_complete is True
        assert len(plan.instances) == 2
        index = runner._ensure_code_index(state, defer_svf=True)
        contexts = index.get_build_contexts()
        assert len(contexts) == 2
        assert all(context_input_status(context) == "current" for context in contexts)
        assert all(
            context["tool"]["capability"]["include_lookup_version"] == 1 for context in contexts
        )
        assert all(context["include_lookups"]["complete"] is True for context in contexts)
        observed["native_plans"].append(
            {
                "instances": len(plan.instances),
                "current_contexts": len(contexts),
                "build_context_ids": sorted(context["build_context_id"] for context in contexts),
                "tool_sha256": sorted(
                    {context["tool"]["binary"]["sha256"] for context in contexts}
                ),
            }
        )
        if after_plan is not None:
            after_plan(contexts)
        return plan

    monkeypatch.setattr(ScanSessionRunner, "_build_entry_instance_plan", build)


@pytest.mark.parametrize("batch", [False, True])
def test_prewrite_probe_native_job_positive_closes_queue(project, batch, record_property):
    root, _store = project
    result = ScanSessionRunner(
        _config(root, single=not batch, entry_list=batch), task_id="prewrite/positive"
    ).run()
    report = _read_report(
        root / ("zscope_batch_report_prewrite_positive.json" if batch else "report.json")
    )
    analysis = _instance_analysis(report)
    assert result.is_batch is batch
    assert analysis["analyzed_instances"] == 2
    assert analysis["instance_scope_complete"] is True
    assert report["metadata"]["job"]["checkpointed"] is True
    assert report["metadata"]["job"]["remaining_count"] == 0
    assert _completed_by_kind(root) == {
        "instance_analysis": 2,
        "instance_validation": 1,
        "instance_checkpoint": 1,
    }
    record_property(
        "positive_job", json.dumps({"batch": batch, "analyzed": 2, "checkpointed": True})
    )


@pytest.mark.parametrize("link_kind", ["hardlink", "symlink"])
@pytest.mark.parametrize("input_kind", ["source", "header"])
def test_batch_backup_link_to_actual_input_is_refused_before_copy(
    project, monkeypatch, record_property, link_kind, input_kind
):
    from zscope.orchestration import scan_session
    from zscope.retrieval.code_index import _JobRuntimeOutputs

    root, store = project
    header = root / "prewrite-input.h"
    header.write_text("#define PREWRITE_INPUT_VALUE 7\n", encoding="utf-8")
    source = root / "unit.c"
    source.write_text(
        '#include "prewrite-input.h"\n' + source.read_text(encoding="utf-8"), encoding="utf-8"
    )
    actual_input = source if input_kind == "source" else header
    report_path = root / "zscope_batch_report_prewrite_backup.json"
    report_path.write_text('{"existing_report":true}\n', encoding="utf-8")
    backup_dir = root / ".zscope_knowledge" / "backups"
    backup_dir.mkdir(parents=True)
    backup_path = backup_dir / "zscope_batch_report_20400102_030405.json"
    if link_kind == "hardlink":
        os.link(actual_input, backup_path)
    else:
        backup_path.symlink_to(actual_input)
    before = _identity(actual_input)
    original_time = scan_session.time

    class TimeObservation:
        def __getattr__(self, name):
            return getattr(original_time, name)

        def strftime(self, pattern, *args):
            if pattern == "%Y%m%d_%H%M%S":
                return "20400102_030405"
            return original_time.strftime(pattern, *args)

    monkeypatch.setattr(scan_session, "time", TimeObservation())
    observed = {
        "native_plans": [],
        "store_connects": [],
        "dangerous_copy_calls": [],
        "backup_method_calls": [],
        "exact_target_gates": [],
    }

    def prove_input(contexts):
        assert all(
            context["dependencies"].get(str(actual_input.resolve())) == before["sha256"]
            for context in contexts
        )

    _plan_observation(monkeypatch, observed, prove_input)
    _store_observation(monkeypatch, store, observed)
    original_copy = shutil.copy2
    original_backup = ScanSessionRunner._backup_existing_batch_report
    original_declare = _JobRuntimeOutputs._declare

    def backup(runner, report, *args, **kwargs):
        row = {"report_path": str(report), "expected_exact_target": str(backup_path)}
        observed["backup_method_calls"].append(row)
        try:
            result = original_backup(runner, report, *args, **kwargs)
        except BaseException as error:
            row["exception_type"] = type(error).__name__
            raise
        else:
            row["returned"] = True
            return result

    def declare(scope, path, *args, **kwargs):
        row = None
        if Path(path) == backup_path:
            row = {
                "exact_target": str(path),
                "directory": kwargs.get("directory", False),
                "current_native_contexts": len(scope._contexts),
                "target_is_link_to_actual_input": Path(path).exists()
                and Path(path).samefile(actual_input),
                "actual_input_identity_before": _identity(actual_input),
            }
            observed["exact_target_gates"].append(row)
        try:
            result = original_declare(scope, path, *args, **kwargs)
        except BaseException as error:
            if row is not None:
                row["rejected"] = True
                row["exception_type"] = type(error).__name__
                row["exception_message"] = str(error)
            raise
        else:
            if row is not None:
                row["rejected"] = False
            return result

    def copy(source_path, destination, *args, **kwargs):
        destination_path = Path(destination)
        if destination_path.exists() and destination_path.samefile(actual_input):
            observed["dangerous_copy_calls"].append(
                {
                    "destination": str(destination_path),
                    "actual_input_identity_before": _identity(actual_input),
                }
            )
        return original_copy(source_path, destination, *args, **kwargs)

    monkeypatch.setattr(scan_session.shutil, "copy2", copy)
    monkeypatch.setattr(ScanSessionRunner, "_backup_existing_batch_report", backup)
    monkeypatch.setattr(_JobRuntimeOutputs, "_declare", declare)
    caught = None
    try:
        try:
            ScanSessionRunner(
                _config(root, single=False, entry_list=True), task_id="prewrite/backup"
            ).run()
        except (ValueError, JobError) as error:
            caught = error
    finally:
        observed["actual_input_before"] = before
        observed["actual_input_after"] = _identity(actual_input)
        observed["exception_type"] = type(caught).__name__ if caught is not None else None
        observed["exception_message"] = str(caught) if caught is not None else None
        observed["risk_gate_reached"] = bool(
            observed["dangerous_copy_calls"] or observed["exact_target_gates"]
        )
        observed["causal_classification"] = (
            "actual_copy_or_exact_target_gate_reached"
            if observed["risk_gate_reached"]
            else "inconclusive_target_not_reached"
        )
        record_property("prewrite_observation", json.dumps(observed, sort_keys=True))
    assert (
        len(observed["native_plans"]) == 1
    ), "the real exact two-variant native plan must precede the gate"
    assert observed[
        "risk_gate_reached"
    ], "inconclusive probe: neither the actual dangerous copy nor the exact target gate executed"
    assert (
        observed["dangerous_copy_calls"] == []
    ), "the real copy operation must never follow a link to an input"
    assert (
        _identity(actual_input) == before
    ), "input bytes, mtime and physical identity must remain exact"
    assert any(
        row.get("rejected") is True
        and row["directory"] is False
        and row["current_native_contexts"] == 2
        and row["target_is_link_to_actual_input"] is True
        and row["actual_input_identity_before"] == before
        and "job_runtime_output" in row.get("exception_message", "")
        for row in observed["exact_target_gates"]
    ), "the live factory must explicitly reject this precise linked target before copying"
    assert caught is not None and "job_runtime_output" in str(caught)


def test_revoked_real_tool_copy_is_refused_before_first_store_connection(
    project, monkeypatch, tmp_path, record_property
):
    from zscope.orchestration import instance_semantics_context

    root, store = project
    actual_tool = Path(os.environ["Z_SCOPE_TEST_CLANG_INDEXER"])
    controlled_directory = root.parent / (root.name + "-controlled-tool")
    controlled_directory.mkdir()
    controlled_tool = controlled_directory / "zscope-clang-indexer"
    shutil.copy2(actual_tool, controlled_tool)
    monkeypatch.setenv("Z_SCOPE_TEST_CLANG_INDEXER", str(controlled_tool))
    before_inputs = {
        str(path): _identity(path) for path in (root / "unit.c", root / "compile_commands.json")
    }
    observed = {
        "native_plans": [],
        "store_connects": [],
        "native_tool_gates": [],
        "tool_before": _identity(controlled_tool),
        "inputs_before_native_preparation": before_inputs,
    }
    original_native_current = instance_semantics_context._native_inputs_current

    def native_current(context):
        binary = context.get("tool", {}).get("binary", {})
        matches = binary.get("path") == str(controlled_tool)
        row = None
        if matches:
            row = {
                "recorded_tool_sha256": binary.get("sha256"),
                "actual_tool_sha256": _identity(controlled_tool)["sha256"],
                "store_connects_before_gate": len(observed["store_connects"]),
            }
            observed["native_tool_gates"].append(row)
        try:
            result = original_native_current(context)
        except BaseException as error:
            if row is not None:
                row["exception_type"] = type(error).__name__
            raise
        if row is not None:
            row["actual_current_result"] = result
        return result

    monkeypatch.setattr(instance_semantics_context, "_native_inputs_current", native_current)

    def revoke(contexts):
        assert all(
            Path(context["tool"]["binary"]["path"]) == controlled_tool for context in contexts
        )
        assert all(
            context["tool"]["binary"]["sha256"] == observed["tool_before"]["sha256"]
            for context in contexts
        )
        observed["inputs_at_revoke"] = {
            str(path): _identity(path) for path in (root / "unit.c", root / "compile_commands.json")
        }
        stamp = controlled_tool.stat()
        # A controlled, still-executable ELF copy changes only after its real
        # native extraction. This is an offline provenance-withdrawal probe.
        with controlled_tool.open("ab") as stream:
            stream.write(b"\nprewrite-controlled-tool-revoked\n")
        os.utime(controlled_tool, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        observed["tool_revoked"] = _identity(controlled_tool)
        assert observed["tool_revoked"]["sha256"] != observed["tool_before"]["sha256"]
        assert observed["tool_revoked"]["mtime_ns"] == observed["tool_before"]["mtime_ns"]

    _plan_observation(monkeypatch, observed, revoke)
    _store_observation(monkeypatch, store, observed)
    caught = None
    try:
        try:
            ScanSessionRunner(_config(root), task_id="prewrite/tool-revoked").run()
        except (ValueError, JobError) as error:
            caught = error
    finally:
        observed["exception_type"] = type(caught).__name__ if caught is not None else None
        observed["exception_message"] = str(caught) if caught is not None else None
        observed["risk_gate_reached"] = any(
            row.get("actual_current_result") is False
            and row["recorded_tool_sha256"] != row["actual_tool_sha256"]
            for row in observed["native_tool_gates"]
        )
        observed["causal_classification"] = (
            "actual_revoked_tool_verifier_reached"
            if observed["risk_gate_reached"]
            else "inconclusive_target_not_reached"
        )
        record_property("prewrite_observation", json.dumps(observed, sort_keys=True))
    assert len(observed["native_plans"]) == 1
    assert any(
        row["recorded_tool_sha256"] == observed["tool_before"]["sha256"]
        and row["actual_tool_sha256"] == observed["tool_revoked"]["sha256"]
        and row.get("actual_current_result") is False
        and row["store_connects_before_gate"] == 0
        for row in observed["native_tool_gates"]
    ), "the real emitting-byte verifier must observe the revoked tool before any Store connection"
    assert (
        observed["store_connects"] == []
    ), "withdrawn native authority must precede even a WAL-capable Store connection"
    assert {
        str(path): _identity(path) for path in (root / "unit.c", root / "compile_commands.json")
    } == observed["inputs_at_revoke"]
    assert not _run_dir(root).exists()
    assert caught is not None and "job_runtime_output" in str(
        caught
    ), "the pure native-input preflight must refuse the revoked tool"


def _add_unselected_tu(root: Path, header_name: str) -> Path:
    """Add a third indexed TU that includes ``header_name`` from the run dir."""

    run_dir = _run_dir(root)
    run_dir.mkdir(parents=True, exist_ok=True)
    header = run_dir / header_name
    header.write_text("#define THIRD_TU_VALUE 41\n", encoding="utf-8")
    other = root / "other.c"
    other.write_text(
        f'#include "{header_name}"\nint other_tu(void) {{ return THIRD_TU_VALUE; }}\n',
        encoding="utf-8",
    )
    database = root / "compile_commands.json"
    rows = json.loads(database.read_text(encoding="utf-8"))
    rows.append(
        {
            "directory": str(root),
            "file": str(other),
            "arguments": ["clang", "-c", str(other), "-I", str(run_dir)],
        }
    )
    database.write_text(json.dumps(rows), encoding="utf-8")
    return header


def test_unselected_indexed_tu_input_is_refused_before_any_runtime_write(
    project, monkeypatch, record_property
):
    """A job output may not overwrite a header an unselected TU already read."""

    root, _store = project
    header = _add_unselected_tu(root, "pending.json")
    before = _identity(header)
    observed: dict = {"replace_calls": [], "plan_contexts": None}

    original_replace = os.replace

    def replace(source, destination, *args, **kwargs):
        observed["replace_calls"].append([str(source), str(destination)])
        return original_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "replace", replace)

    original_plan = ScanSessionRunner._build_entry_instance_plan

    def build(runner, state):
        plan = original_plan(runner, state)
        index = runner._ensure_code_index(state, defer_svf=True)
        contexts = index.get_build_contexts()
        observed["plan_contexts"] = len(contexts)
        observed["unselected_sources"] = sorted(
            {
                str(context.get("source") or "")
                for context in contexts
                if str(context.get("build_context_id") or "")
                not in {item.build_context_id for item in plan.instances}
            }
        )
        return plan

    monkeypatch.setattr(ScanSessionRunner, "_build_entry_instance_plan", build)

    caught = None
    try:
        ScanSessionRunner(_config(root), task_id="prewrite/third-tu").run()
    except (ValueError, JobError) as error:
        caught = error
    finally:
        record_property(
            "third_tu_observation",
            json.dumps(
                {
                    "exception": None if caught is None else str(caught),
                    "plan_contexts": observed["plan_contexts"],
                    "unselected_sources": observed.get("unselected_sources"),
                    "replace_calls": observed["replace_calls"],
                },
                sort_keys=True,
            ),
        )

    # The index really enumerated a third, unselected instance.
    assert observed["plan_contexts"] == 3
    assert len(observed["unselected_sources"] or []) == 1
    assert observed["unselected_sources"][0].endswith("other.c")
    # The precise file is refused by the runtime-output factory, before any
    # publish, and the real header bytes are untouched.
    assert caught is not None, "the collision must be refused, not overwritten"
    assert "job_runtime_output_input_overlap" in str(caught)
    # Compile-command preparation legitimately replaces its own cache files;
    # the guarded header must never be a replace destination.
    assert [row for row in observed["replace_calls"] if row[1] == str(header)] == []
    assert _identity(header) == before
    assert header.read_text(encoding="utf-8") == "#define THIRD_TU_VALUE 41\n"


def test_unselected_tu_with_ordinary_header_keeps_the_job_drained(project, record_property):
    """The same shape with a non-output header must still complete normally."""

    root, _store = project
    header = _add_unselected_tu(root, "ordinary-other.h")
    before = _identity(header)
    result = ScanSessionRunner(_config(root), task_id="prewrite/third-tu-control").run()
    report = _read_report(root / "report.json")
    analysis = _instance_analysis(report)
    assert result.is_batch is False
    assert analysis["analyzed_instances"] == 2
    assert analysis["instance_scope_complete"] is True
    assert report["metadata"]["job"]["checkpointed"] is True
    assert report["metadata"]["job"]["remaining_count"] == 0
    assert _completed_by_kind(root) == {
        "instance_analysis": 2,
        "instance_validation": 1,
        "instance_checkpoint": 1,
    }
    assert _identity(header) == before
    record_property(
        "third_tu_control",
        json.dumps({"analyzed": 2, "unselected_header_untouched": True}, sort_keys=True),
    )
