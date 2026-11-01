"""Batch log volume is bounded without dropping diagnostics or liveness."""

import errno
import json
import logging
import sys
import threading
from pathlib import Path

import pytest

from zscope.retrieval import clang_batch
from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.clang_batch import BatchExtractionError, BatchIndexer
from zscope.retrieval.indexing_runtime import MeasuredProcess, heartbeat, run_process
from zscope.retrieval.knowledge_db import KnowledgeDB


@pytest.fixture
def indexer(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    source = root / "a.c"
    source.write_text("int f(void) {return 0;}\n", encoding="utf-8")
    build = tmp_path / "build"
    build.mkdir()
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "directory": str(build),
                    "file": str(source),
                    "arguments": ["clang", "-Irelative-include", "-c", str(source)],
                }
            ]
        ),
        encoding="utf-8",
    )
    backend = ClangBackend(frontend="batch", max_threads=4)
    backend._source_path = root
    backend._compile_commands_path = str(cdb)
    backend._db = KnowledgeDB(str(tmp_path / "knowledge" / "code.db"))
    monkeypatch.setattr(clang_batch, "admitted_workers", lambda requested, count, memory: 4)
    try:
        yield BatchIndexer(backend, sys.executable, {})
    finally:
        backend.close()


def failed_run(indexer):
    with pytest.raises(RuntimeError, match="strict batch extraction incomplete"):
        indexer.run()
    return json.loads((indexer.cache / "latest_run.json").read_text(encoding="utf-8"))


def test_cli_report_outputs_are_exact_native_input_exclusions(indexer):
    from zscope.retrieval.indexing_identity import search_directories_snapshot

    excluded = set(indexer.validation_excludes)
    reports = {
        indexer.root / "report.json",
        indexer.root / "report.md",
        indexer.root / "zscope_batch_report.json",
        indexer.root / "zscope_batch_report.md",
    }
    assert reports <= excluded
    assert indexer.root / "zscope_batch_report_custom.json" not in excluded
    before = search_directories_snapshot([indexer.root], exclude_paths=excluded)
    for path in reports:
        path.write_text("generated\n", encoding="utf-8")
    assert search_directories_snapshot([indexer.root], exclude_paths=excluded) == before

    custom = indexer.root / "zscope_batch_report_custom.json"
    custom.write_text("not a declared output\n", encoding="utf-8")
    assert search_directories_snapshot([indexer.root], exclude_paths=excluded) != before


def test_many_failures_have_bounded_info_and_samples_but_complete_report(
    indexer, monkeypatch, caplog
):
    caplog.set_level(logging.INFO)
    original = indexer._jobs()[0]
    jobs = [
        {**original, "key": str(i), "source": str(indexer.root / f"tu{i}.c")} for i in range(300)
    ]
    indexer.stats["selected_compile_contexts"] = len(jobs)
    monkeypatch.setattr(indexer, "_jobs", lambda: jobs)

    def fail(job):
        raise BatchExtractionError(
            "process_exit", f"fatal error in {job['source']}", {"exit_code": 1}
        )

    monkeypatch.setattr(indexer, "_extract", fail)
    report = failed_run(indexer)
    failures = [r for r in caplog.records if "[clang-batch-failed]" in r.message]
    assert len(failures) == 3
    assert all("fatal error" in r.message and "report=" in r.message for r in failures)
    assert len(report["failed_tus"]) == 300
    assert report["failure_reasons"] == {"process_exit": 300}
    assert report["failure_logs_suppressed"] == 297
    assert report["completed_tus"] == 300 and report["remaining_tus"] == 0
    assert not report["complete"]
    # Fast completion does not emit one INFO for every TU; the final total is visible.
    progress = [r for r in caplog.records if r.message.startswith("[clang-batch]")]
    assert len(progress) == 5
    assert "done=300/300" in progress[-1].message


def test_different_failure_reason_is_visible_after_sample_budget(indexer, caplog):
    caplog.set_level(logging.DEBUG)
    job = indexer._jobs()[0]
    for _ in range(5):
        indexer._report_failure(job, BatchExtractionError("process_exit", "fatal error"))
    indexer._report_failure(job, BatchExtractionError("timed_out", "native timeout"))
    failures = [r for r in caplog.records if "[clang-batch-failed]" in r.message]
    assert len(failures) == 6  # DEBUG retains all per-TU details.
    warnings = [r for r in failures if r.levelno == logging.WARNING]
    assert len(warnings) == 4 and "reason=timed_out" in warnings[-1].message


def test_heartbeat_reports_while_no_tu_has_completed(indexer, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    received = threading.Event()

    class Listener(logging.Handler):
        def emit(self, record):
            if "[indexing-heartbeat] phase=clang-batch" in record.getMessage():
                received.set()

    runtime_logger = logging.getLogger("zscope.retrieval.indexing_runtime")
    handler = Listener()
    runtime_logger.addHandler(handler)
    monkeypatch.setattr(
        clang_batch, "heartbeat", lambda phase, state: heartbeat(phase, state, interval=0.01)
    )

    def wait_for_heartbeat(job):
        if not received.wait(5):
            pytest.fail("heartbeat stopped while waiting for TU completion")
        raise BatchExtractionError("timed_out", "native timeout")

    monkeypatch.setattr(indexer, "_extract", wait_for_heartbeat)
    try:
        failed_run(indexer)
    finally:
        runtime_logger.removeHandler(handler)
    reports = [
        r.message for r in caplog.records if "[indexing-heartbeat] phase=clang-batch" in r.message
    ]
    assert reports and "'completed_tus': 0" in reports[0]


def test_missing_leaf_directory_fails_before_spawn_with_clear_reason(indexer, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    job = indexer._jobs()[0]
    leaf = Path(job["directory"]) / "removed" / "module"
    job["directory"] = str(leaf)
    monkeypatch.setattr(indexer, "_jobs", lambda: [job])
    monkeypatch.setattr(
        clang_batch, "run_process", lambda *a, **kw: pytest.fail("unexpected process")
    )
    report = failed_run(indexer)
    failure = report["failed_tus"][0]
    assert failure["code"] == "compile_directory_missing"
    assert failure["metrics"]["errno"] == errno.ENOENT
    assert repr(str(leaf)) in failure["reason"] and str(leaf) in caplog.text
    assert not leaf.exists()
    assert json.loads(Path(failure["job_path"]).read_text())["arguments"] == job["arguments"]


@pytest.mark.parametrize(
    "returncode, flags, expected",
    [
        (1, {}, "process_exit"),
        (-9, {}, "process_signal"),
        (-9, {"timed_out": True}, "timed_out"),
        (-9, {"memory_exceeded": True}, "memory_exceeded"),
        (-9, {"cancelled": True}, "cancelled"),
    ],
)
def test_native_failure_reports_preserve_metrics_and_full_stderr(
    indexer, monkeypatch, caplog, returncode, flags, expected
):
    caplog.set_level(logging.INFO)
    stderr = "fatal error: missing header\n" + "detail\n" * 1000 + "last diagnostic"

    def run(command, **kwargs):
        # A valid build directory outside the source root reaches the process unchanged.
        assert kwargs["cwd"].parent == indexer.root.parent
        assert kwargs["cwd"] != indexer.root
        assert kwargs["log_level"] == logging.DEBUG
        stderr_path = kwargs["output_prefix"].with_suffix(".stderr.log")
        stderr_path.write_text(stderr, encoding="utf-8")
        return MeasuredProcess(
            returncode,
            stderr=stderr,
            metrics={
                **flags,
                "stderr_path": str(stderr_path),
                "exit_code": returncode,
            },
        )

    monkeypatch.setattr(clang_batch, "run_process", run)
    failure = failed_run(indexer)["failed_tus"][0]
    assert failure["code"] == expected
    assert failure["metrics"]["exit_code"] == returncode
    assert Path(failure["stderr_path"]).read_text(encoding="utf-8") == stderr
    assert "fatal error: missing header" in caplog.text and "last diagnostic" in caplog.text
    assert len(failure["reason"]) < 2100


@pytest.mark.parametrize("level, visible", [(logging.DEBUG, False), (logging.INFO, True)])
def test_process_log_level_changes_output_not_metrics(tmp_path, caplog, level, visible):
    caplog.set_level(logging.INFO)
    result = run_process(
        [sys.executable, "-c", "print('ok')"],
        cwd=tmp_path,
        output_prefix=tmp_path / "native",
        log_level=level,
    )
    assert result.returncode == 0 and result.stdout.strip() == "ok"
    assert result.metrics["exit_code"] == 0
    assert Path(result.metrics["stdout_path"]).is_file()
    assert ("[indexing-process]" in caplog.text) == visible


def test_success_exit_with_error_diagnostics_is_not_published(indexer, monkeypatch):
    policy = {
        "policy_version": clang_batch.ARGUMENT_POLICY_VERSION,
        "policy_digest": clang_batch.POLICY_DIGEST,
        "attempts": [{"number": 1, "error_count": 1}],
    }

    def run(command, **kwargs):
        Path(command[-1]).write_text(
            json.dumps({"kind": "header", "protocol": clang_batch.PROTOCOL})
            + "\n"
            + json.dumps({"kind": "complete", "success": True, "argument_adjustments": policy})
            + "\n",
            encoding="utf-8",
        )
        return MeasuredProcess(0, stderr="error: driver error that did not affect exit status")

    monkeypatch.setattr(clang_batch, "run_process", run)
    report = failed_run(indexer)
    assert report["compiled_tus"] == 0
    failure = report["failed_tus"][0]
    assert failure["code"] == "artifact_invalid"
    assert failure["argument_adjustments"] == policy
    assert "error-free footer" in failure["reason"]
