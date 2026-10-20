"""Real SQLite probes: a completed parent cannot lose its discovered work."""
import multiprocessing
import os
import sqlite3
from contextlib import contextmanager

from test_scheduler_guard_probes import bound_scheduler, item
from zscope.orchestration.jobs.session_scheduler import WorkComplete
from zscope.orchestration.jobs.work_queue import WorkQueue


def test_batch_bound_keeps_unaccepted_discovery_as_remaining(tmp_path):
    _, scheduler = bound_scheduler(tmp_path, max_batches=1)
    scheduler.submit([item("parent")])
    scheduler.register_handler("entry", lambda work: WorkComplete(discoveries=[item("child")]))
    summary = scheduler.run()
    snapshot = scheduler.snapshot()
    assert snapshot["unresolved_count"] > 0, (
        "batch bound must retain a durable unresolved obligation; drained with no remaining loses the child"
    )


def _crash_before_child_submission(directory):
    _, scheduler = bound_scheduler(directory)
    scheduler.submit([item("parent")])
    scheduler.register_handler("entry", lambda work: WorkComplete(discoveries=[item("child")]))
    original_write = scheduler._queue._write

    @contextmanager
    def crash_after_parent_commit():
        with original_write() as connection:
            yield connection
        # Crash after the real durable verdict transaction commits. An atomic
        # implementation must already contain the child at this same point.
        with sqlite3.connect(scheduler.work_queue_path) as connection:
            parent = connection.execute(
                "SELECT status FROM items WHERE scope_key = 'parent'"
            ).fetchone()
        if parent and parent[0] == "completed":
            os._exit(73)

    scheduler._queue._write = crash_after_parent_commit
    scheduler.run()


def test_process_exit_between_parent_and_child_keeps_recoverable_work(tmp_path):
    process = multiprocessing.get_context("fork").Process(
        target=_crash_before_child_submission, args=(tmp_path,)
    )
    process.start()
    process.join(10)
    if process.is_alive():
        process.terminate()
        process.join(5)
    assert process.exitcode == 73
    reopened = WorkQueue(tmp_path / "job_test/work-queue.db", job_id="job_test", input_revision="fp0")
    snapshot = reopened.snapshot()
    assert snapshot["unresolved_count"] > 0, (
        "the durable parent verdict must commit its children or remain recoverable after process exit"
    )
