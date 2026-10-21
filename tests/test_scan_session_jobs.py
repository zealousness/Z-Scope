"""The ordinary ScanSession drains a job's persistent instance work queue.

A C/C++ scan started by a job owner consumes the owner-passed ``ZSCOPE_JOB_*``
identity and runs its exact per-instance analysis, the scan-level validation and
the completion checkpoint as real work items on the persistent SQLite queue
(reached through the real ``SessionWorkScheduler`` and the real Analyzer /
Validator chain -- only the model boundary stays unexercised here).  The report
is only ``complete`` once that checkpoint is durably persisted; a same-input
restart reuses the checkpoint instead of re-analyzing, a changed input revokes
the old completion, and a cancel reports the real partial coverage.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

from test_scan_session_instances import (
    _config,
    _forbid_global_modeling,
    _instance_analysis,
    _read_report,
    _write_project,
)
from zscope.orchestration.jobs.models import JobError, utc_now_iso
from zscope.orchestration.jobs.scan_work import CHECKPOINT_FILENAME, CHECKPOINT_SCHEMA
from zscope.orchestration.jobs.session_scheduler import WORK_QUEUE_FILENAME
from zscope.orchestration.jobs.store import JobStore
from zscope.orchestration.jobs.work_queue import WorkQueue
from zscope.orchestration.scan_session import ScanSessionRunner

JOB_ID = "job_inst"
RUN_ID = "run_inst"
OWNER_TOKEN = "owner-token"
INPUT_REVISION = "rev-a"
CHECKPOINT_NAME = "instance-checkpoint.json"


def _job_dir(root: Path) -> Path:
    return root / JOB_ID


def _run_dir(root: Path) -> Path:
    return _job_dir(root) / RUN_ID


def _job_store(root: Path, *, input_revision: str = INPUT_REVISION) -> JobStore:
    store = JobStore(root / "jobs.db")
    store.initialize()
    now = utc_now_iso()
    store.create_job(
        {
            "job_id": JOB_ID,
            "run_id": RUN_ID,
            "revision": 1,
            "input_revision": input_revision,
            "status": "running",
            "created_at": now,
            "updated_at": now,
            "config_path": str(root / "zscope.yaml"),
            "config_sha256": "dummy",
            "project_root": str(root),
            "project_id": "dummy",
            "working_directory": str(root),
            "run_dir": str(_run_dir(root)),
            "owner_token": OWNER_TOKEN,
        }
    )
    store.record_attempt(
        {
            "job_id": JOB_ID,
            "run_id": RUN_ID,
            "attempt_no": store.next_attempt_no(JOB_ID),
            "status": "running",
            "input_revision": input_revision,
            "started_at": now,
        }
    )
    assert store.attempt_for(JOB_ID, RUN_ID)["input_revision"] == input_revision
    return store


def _bind_job_env(monkeypatch, root: Path, store: JobStore) -> None:
    monkeypatch.setenv("ZSCOPE_JOB_STORE", str(store.db_path))
    monkeypatch.setenv("ZSCOPE_JOB_ID", JOB_ID)
    monkeypatch.setenv("ZSCOPE_JOB_RUN_ID", RUN_ID)
    monkeypatch.setenv("ZSCOPE_JOB_OWNER_TOKEN", OWNER_TOKEN)
    monkeypatch.setenv("ZSCOPE_JOB_RUN_DIR", str(_run_dir(root)))


def _set_job_field(store: JobStore, updates: Dict[str, Any]) -> None:
    # While the owner is running it keeps bumping the revision, so this
    # read-modify-write must re-read on a lost race instead of failing.
    for attempt in range(50):
        row = store.get_job(JOB_ID)
        assert row is not None
        try:
            store.update_job(JOB_ID, expected_revision=int(row["revision"]), updates=updates)
            break
        except JobError as exc:
            if exc.code != "revision_conflict" or attempt == 49:
                raise
            time.sleep(0.05)
    if "input_revision" in updates:
        # This controlled fixture explicitly rebinds its synthetic attempt;
        # production resume uses a new run and the real owner's attempt write.
        attempt = store.attempt_for(JOB_ID, RUN_ID)
        assert attempt is not None
        store.record_attempt({**attempt, "input_revision": updates["input_revision"]})


def _completed_by_kind(root: Path) -> Dict[str, int]:
    """Direct SQLite read of every real queue this job attempted."""

    counts: Dict[str, int] = {}
    for db in sorted(_job_dir(root).rglob("work-queue.db*")):
        if not db.is_file() or db.name.endswith(("-wal", "-shm", "-journal")):
            continue
        connection = sqlite3.connect(str(db))
        try:
            for kind, total in connection.execute(
                "SELECT kind, COUNT(*) FROM items WHERE status = 'completed' GROUP BY kind"
            ):
                counts[str(kind)] = counts.get(str(kind), 0) + int(total)
        except sqlite3.DatabaseError:
            continue
        finally:
            connection.close()
    return counts


@pytest.fixture
def native_job_project(tmp_path, monkeypatch):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("job scan tests require Z_SCOPE_TEST_CLANG_INDEXER")
    monkeypatch.setenv("Z_SCOPE_TEST_CLANG_INDEXER", executable)
    _forbid_global_modeling(monkeypatch)
    _write_project(tmp_path)
    store = _job_store(tmp_path)
    _bind_job_env(monkeypatch, tmp_path, store)
    return tmp_path, store


def test_job_scan_runs_exact_instances_on_the_queue(native_job_project) -> None:
    root, store = native_job_project
    ScanSessionRunner(_config(root), task_id="job/scan").run()

    report = _read_report(root / "report.json")
    analysis = _instance_analysis(report)
    assert analysis["analyzed_instances"] == 2
    assert analysis["instance_scope_complete"] is True
    assert analysis["scan_coverage_complete"] is False
    counts = sorted(item["candidate_count"] for item in analysis["instances"])
    assert counts == [0, 1], analysis["instances"]
    with_candidate = next(item for item in analysis["instances"] if item["candidate_count"])
    assert [c["defect_class"] for c in with_candidate["candidates"]] == ["double_free"]
    for candidate in with_candidate["candidates"]:
        assert candidate["build_context_id"] == with_candidate["build_context_id"]

    job = report["metadata"]["job"]
    assert job["status"] == "drained"
    assert job["checkpointed"] is True
    assert job["remaining_count"] == 0

    # The real queue settles two analyses, one validation and one checkpoint.
    assert _completed_by_kind(root) == {
        "instance_analysis": 2,
        "instance_validation": 1,
        "instance_checkpoint": 1,
    }
    assert (_run_dir(root) / CHECKPOINT_NAME).is_file()


def test_batch_job_scan_runs_instances_on_the_queue(native_job_project) -> None:
    root, store = native_job_project
    result = ScanSessionRunner(
        _config(root, single=False, entry_list=True), task_id="job/batch"
    ).run()

    assert result.is_batch is True
    report = _read_report(root / "zscope_batch_report_job_batch.json")
    analysis = _instance_analysis(report)
    assert analysis["analyzed_instances"] == 2
    assert sorted(item["candidate_count"] for item in analysis["instances"]) == [0, 1]
    assert report["metadata"]["job"]["checkpointed"] is True


def test_same_input_restart_reuses_the_checkpoint(native_job_project, monkeypatch) -> None:
    root, store = native_job_project
    ScanSessionRunner(_config(root), task_id="job/scan").run()

    from zscope.orchestration import parallel_analyzer as parallel_module

    def _forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a checkpointed instance must not be re-analyzed")

    monkeypatch.setattr(parallel_module.ParallelAnalyzer, "run_instance_batch", _forbidden)
    monkeypatch.setattr(parallel_module.ParallelAnalyzer, "analyze_entry_instances", _forbidden)

    ScanSessionRunner(_config(root), task_id="job/scan").run()

    report = _read_report(root / "report.json")
    analysis = _instance_analysis(report)
    assert analysis["analyzed_instances"] == 2
    assert sorted(item["candidate_count"] for item in analysis["instances"]) == [0, 1]
    assert report["metadata"]["job"]["checkpointed"] is True
    assert report["metadata"]["job"]["status"] == "drained"
    assert (root / "report.md").is_file()


def test_changed_input_revokes_the_old_checkpoint(native_job_project, monkeypatch) -> None:
    root, store = native_job_project
    ScanSessionRunner(_config(root), task_id="job/scan").run()
    assert (_run_dir(root) / CHECKPOINT_NAME).is_file()

    # A real source/header/config edit re-fingerprints the job row's input.
    _set_job_field(store, {"input_revision": "rev-b"})

    from zscope.orchestration import parallel_analyzer as parallel_module

    analyzed: List[str] = []
    original = parallel_module.ParallelAnalyzer.run_instance_batch

    def _spy(self: Any, batch: Any, identities: Any) -> Any:
        analyzed.extend(str(value) for value in identities)
        return original(self, batch, identities)

    monkeypatch.setattr(parallel_module.ParallelAnalyzer, "run_instance_batch", _spy)

    ScanSessionRunner(_config(root), task_id="job/scan").run()

    assert len(analyzed) == 2, "a changed input must re-analyze every instance"
    report = _read_report(root / "report.json")
    assert report["metadata"]["job"]["checkpointed"] is True


def test_cancel_stops_new_claims_and_reports_partial(native_job_project) -> None:
    root, store = native_job_project
    _set_job_field(store, {"cancel_requested_at": utc_now_iso()})

    ScanSessionRunner(_config(root), task_id="job/scan").run()

    report = _read_report(root / "report.json")
    assert report["completeness"] == "incomplete"
    assert report["scan_outcome"] == "partial"
    job = report["metadata"]["job"]
    assert job["checkpointed"] is False
    assert job["cancel_observed"] is True
    assert not (_run_dir(root) / CHECKPOINT_NAME).exists()

    pending = json.loads((_run_dir(root) / "pending.json").read_text(encoding="utf-8"))
    assert pending["count"] == 2
    assert {row["kind"] for row in pending["items"]} == {"instance_analysis"}


def test_unpersisted_checkpoint_is_not_reported_complete(native_job_project, monkeypatch) -> None:
    root, store = native_job_project
    from zscope.orchestration.jobs import scan_work

    monkeypatch.setattr(scan_work, "persist_checkpoint", lambda *args, **kwargs: None)

    ScanSessionRunner(_config(root), task_id="job/scan").run()

    report = _read_report(root / "report.json")
    assert report["completeness"] == "incomplete"
    assert report["scan_outcome"] == "partial"
    assert report["metadata"]["job"]["checkpointed"] is False
    assert not (_run_dir(root) / CHECKPOINT_NAME).exists()
    # No durable completion: the checkpoint item never settles as completed.
    assert _completed_by_kind(root).get("instance_checkpoint", 0) == 0


def test_foreign_owner_token_does_not_bind(native_job_project, monkeypatch) -> None:
    root, store = native_job_project
    monkeypatch.setenv("ZSCOPE_JOB_OWNER_TOKEN", "foreign-token")

    with pytest.raises(JobError):
        ScanSessionRunner(_config(root), task_id="job/scan").run()

    assert not (_run_dir(root) / CHECKPOINT_NAME).exists()


def test_foreign_checkpoint_json_is_rejected(native_job_project) -> None:
    """A JSON naming another job/run never authorizes skipping the real queue."""

    root, store = native_job_project
    row = store.get_job(JOB_ID)
    assert row is not None
    forged = {
        "schema": CHECKPOINT_SCHEMA,
        "job_id": "foreign-job",
        "run_id": "foreign-run",
        "input_revision": row["input_revision"],
        "instance_analysis": {"instances": []},
        "report": {
            "completeness": "complete",
            "summary": {"total_issues": 0, "functions_analyzed": 0},
            "metadata": {},
        },
    }
    (_run_dir(root) / CHECKPOINT_FILENAME).parent.mkdir(parents=True, exist_ok=True)
    (_run_dir(root) / CHECKPOINT_FILENAME).write_text(json.dumps(forged), encoding="utf-8")

    ScanSessionRunner(_config(root), task_id="job/scan").run()

    report = _read_report(root / "report.json")
    analysis = _instance_analysis(report)
    assert len(analysis["instances"]) == 2, "a foreign checkpoint skipped the real analysis"
    assert sorted(item["candidate_count"] for item in analysis["instances"]) == [0, 1]


def test_checkpoint_whose_bytes_do_not_match_its_receipt_is_rejected(
    native_job_project, monkeypatch
) -> None:
    """A tampered receipt must not be trusted just because it parses."""

    root, store = native_job_project
    ScanSessionRunner(_config(root), task_id="job/scan").run()
    checkpoint = _run_dir(root) / CHECKPOINT_FILENAME
    assert checkpoint.is_file()
    receipts = sorted((_run_dir(root) / "instance-results").glob("*.json"))
    assert receipts, "per-instance receipts are the resume authority"

    # The whole-run checkpoint is no longer the authority: claiming coverage in
    # it changes nothing on its own.
    tampered = json.loads(checkpoint.read_text(encoding="utf-8"))
    tampered["scan_coverage_complete"] = True
    checkpoint.write_text(json.dumps(tampered), encoding="utf-8")

    # The per-instance receipt is: its bytes must match the recorded hash.
    receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
    receipt["candidate_count"] = int(receipt.get("candidate_count") or 0) + 7
    receipts[0].write_text(json.dumps(receipt), encoding="utf-8")

    from zscope.orchestration import parallel_analyzer as parallel_module

    analyzed: List[str] = []
    original = parallel_module.ParallelAnalyzer.run_instance_batch

    def _spy(self: Any, batch: Any, identities: Any) -> Any:
        analyzed.extend(str(value) for value in identities)
        return original(self, batch, identities)

    monkeypatch.setattr(parallel_module.ParallelAnalyzer, "run_instance_batch", _spy)

    ScanSessionRunner(_config(root), task_id="job/scan").run()

    assert len(analyzed) == 1, "a tampered instance receipt was trusted without a matching hash"
    job = _read_report(root / "report.json")["metadata"]["job"]
    assert job["executed_instances"] == 1
    assert job["restored_instances"] == 1, "only the untrusted instance may be redone"
    assert job["analyzed_instances"] == 2


def _blocking_analyzer(monkeypatch) -> Dict[str, Any]:
    """Replace ``Analyzer.run`` only with a token-aware model-boundary wait."""

    from zscope.core.analysis.analyzer import Analyzer

    observed: Dict[str, Any] = {}
    started = threading.Event()
    original_run = Analyzer.run

    def blocking_run(self: Any) -> Any:
        token = getattr(self, "cancellation_token", None)
        observed["token_present"] = token is not None
        started.set()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if token is not None and token.is_cancelled():
                observed["reason"] = token.reason
                token.raise_if_cancelled()
            time.sleep(0.02)
        observed["expired"] = True
        return original_run(self)

    monkeypatch.setattr(Analyzer, "run", blocking_run)
    observed["started"] = started
    return observed


def _run_in_background(config: Any) -> Dict[str, Any]:
    box: Dict[str, Any] = {}

    def _scan() -> None:
        box["result"] = ScanSessionRunner(config, task_id="job/scan").run()

    worker = threading.Thread(target=_scan, daemon=True)
    worker.start()
    box["thread"] = worker
    return box


def _read_pending(root: Path) -> Dict[str, Any]:
    return json.loads((_run_dir(root) / "pending.json").read_text(encoding="utf-8"))


def test_inflight_analysis_observes_job_cancel(native_job_project, monkeypatch) -> None:
    """The real in-flight analyzer must stop before the owner watchdog."""

    root, store = native_job_project
    observed = _blocking_analyzer(monkeypatch)
    box = _run_in_background(_config(root))

    assert observed["started"].wait(timeout=90), "the real analyzer never started"
    _set_job_field(store, {"cancel_requested_at": utc_now_iso()})
    box["thread"].join(timeout=90)

    assert not box["thread"].is_alive(), "the scan did not stop cooperatively"
    assert observed.get("reason"), "the in-flight analyzer never observed the job cancel"
    assert not observed.get("expired")

    report = _read_report(root / "report.json")
    assert report["completeness"] == "incomplete"
    assert report["scan_outcome"] == "partial"
    assert report["metadata"]["job"]["cancel_observed"] is True
    pending = _read_pending(root)
    assert pending["count"] >= 1 and pending["items"]


def test_inflight_analysis_observes_job_deadline(native_job_project, monkeypatch) -> None:
    """A real deadline that lands mid-analysis stops the same cooperative way."""

    root, store = native_job_project
    observed = _blocking_analyzer(monkeypatch)
    box = _run_in_background(_config(root))

    assert observed["started"].wait(timeout=90), "the real analyzer never started"
    _set_job_field(store, {"stop_at_epoch": time.time() + 1.0})
    box["thread"].join(timeout=90)

    assert not box["thread"].is_alive(), "the scan did not stop at its deadline"
    assert observed.get("reason"), "the in-flight analyzer never observed the deadline"
    assert not observed.get("expired")

    report = _read_report(root / "report.json")
    assert report["completeness"] == "incomplete"
    assert report["scan_outcome"] == "partial"
    assert report["metadata"]["job"]["window_closed"] is True
    pending = _read_pending(root)
    assert pending["count"] >= 1 and pending["items"]


def test_foreign_owner_never_touches_a_bound_instance_queue(
    native_job_project, monkeypatch
) -> None:
    """An invalid binding is a hard stop, never a licence to reset the queue."""

    root, store = native_job_project
    row = store.get_job(JOB_ID)
    assert row is not None
    queue_path = _job_dir(root) / WORK_QUEUE_FILENAME
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    queue = WorkQueue(queue_path, job_id=JOB_ID, input_revision=row["input_revision"])
    queue.enqueue(
        [{"kind": "instance_analysis", "scope_key": "legit", "build": "legit-build"}],
        batch_no=1,
    )
    before = (
        hashlib.sha256(queue_path.read_bytes()).hexdigest(),
        queue_path.stat().st_ino,
    )

    monkeypatch.setenv("ZSCOPE_JOB_OWNER_TOKEN", "foreign-token")
    with pytest.raises(JobError):
        ScanSessionRunner(_config(root), task_id="job/scan").run()

    assert queue_path.is_file(), "a foreign owner removed the bound queue"
    assert (
        hashlib.sha256(queue_path.read_bytes()).hexdigest(),
        queue_path.stat().st_ino,
    ) == before
    assert queue.snapshot()["counts"]["pending"] == 1
