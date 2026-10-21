"""Real-SQLite and real-process tests for the session work scheduler (S08).

Every in-process test drives a real SQLite job store and work queue under
``tmp_path`` through the public scheduler API with controlled (but real)
work callbacks; nothing about the job, the database or the owner is mocked.
The subprocess tests spawn the real detached owner
(``python -m zscope.orchestration.jobs``) through ``ScanJobService`` and a
real scanner child that binds to the owner-passed ``ZSCOPE_JOB_*``
environment and drains the queue through this scheduler.

The three counterexamples from the coordinator's independent probe
(``followups-r6/test_scheduler_guard_probes.py``) are covered here as
regressions: a stale claim must not enqueue discoveries, and a callback
whose input revision or owner token changed mid-flight must lose both its
verdict and its discovered children.

Scope note (explicit non-wiring): this scheduler is a standalone consumer.
It is not wired into ``scan_session``/``ParallelAnalyzer``; passing this
file does not close JOB04/JOB06/S08 for the shared session.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from test_scan_jobs import make_project, make_service, start_job, store_for
from zscope.orchestration.jobs import identity
from zscope.orchestration.jobs.models import TERMINAL_STATUSES, JobError, utc_now_iso
from zscope.orchestration.jobs.scheduler_hook import (
    JOB_ENV_JOB_ID,
    JOB_ENV_OWNER_TOKEN,
    JOB_ENV_RUN_DIR,
    JOB_ENV_RUN_ID,
    JOB_ENV_STORE,
    JobWindowHook,
    job_window_hook_from_environment,
    session_job_context_from_env,
)
from zscope.orchestration.jobs.service import STORE_DIR_NAME, ScanJobService
from zscope.orchestration.jobs.store import JobStore
from zscope.orchestration.jobs.work_queue import WorkQueue
from zscope.orchestration.jobs.session_scheduler import (
    DEFER_REASON_HANDLER_MISSING,
    PENDING_SOURCE_BLOCKED,
    PENDING_SOURCE_CANCEL,
    PENDING_SOURCE_WINDOW,
    SESSION_SCHEDULER_SCHEMA,
    SessionWorkScheduler,
    WorkComplete,
    WorkDefer,
)

needs_proc = pytest.mark.skipif(
    not identity.proc_available(),
    reason="detached owner tests require Linux /proc process identity",
)

SCHEDULER_SCHEMA = SESSION_SCHEDULER_SCHEMA


def item(name: str, *, kind: str = "entry", build: Optional[str] = "exact-build") -> Dict[str, Any]:
    return {"kind": kind, "scope_key": name, "build": build, "payload": {"name": name}}


def set_job_field(store, job_id: str, updates: Dict[str, Any]) -> None:
    """Update the job row with revision retry (real concurrent store)."""

    last: Optional[JobError] = None
    for _ in range(10):
        current = store.get_job(job_id)
        assert current is not None
        try:
            store.update_job(job_id, expected_revision=int(current["revision"]), updates=updates)
            return
        except JobError as exc:
            if exc.code != "revision_conflict":
                raise
            last = exc
            time.sleep(0.05)
    raise AssertionError(f"could not update job row: {last}")


def events_of(store, job_id: str) -> List[Dict[str, Any]]:
    events, _ = store.list_events(job_id, after_seq=0, limit=500)
    return events


def event_kinds(store, job_id: str) -> List[str]:
    return [event["kind"] for event in events_of(store, job_id)]


def queue_rows(queue_path: Path) -> tuple[Dict[str, str], List[Dict[str, Any]]]:
    """Direct real-SQLite read of the queue (binding-free observation)."""

    connection = sqlite3.connect(str(queue_path))
    connection.row_factory = sqlite3.Row
    try:
        meta = {
            str(row["key"]): str(row["value"])
            for row in connection.execute("SELECT key, value FROM meta")
        }
        rows = [
            dict(row)
            for row in connection.execute(
                "SELECT item_id, kind, scope_key, build_key, status, attempts, "
                "total_attempts, batch_no, claim_expires_at, next_eligible_at, "
                "last_defer_reason, revoked_from_status FROM items"
            )
        ]
    finally:
        connection.close()
    return meta, rows


def queue_claim_token(queue_path: Path) -> Optional[str]:
    connection = sqlite3.connect(str(queue_path))
    try:
        row = connection.execute(
            "SELECT claim_token FROM items WHERE claim_token IS NOT NULL LIMIT 1"
        ).fetchone()
    finally:
        connection.close()
    return str(row[0]) if row else None


def wait_for(predicate, *, timeout: float = 30.0, interval: float = 0.1, description: str):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {description}; last={last!r}")


@pytest.fixture
def session_env(tmp_path: Path):
    """A real project, job store and job row bound to one attempt."""

    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-session-sched")
    store = store_for(project)
    row = store.get_job(job["job_id"])
    assert row is not None
    queue_path = tmp_path / "queue.db"

    def factory(**overrides: Any) -> SessionWorkScheduler:
        kwargs: Dict[str, Any] = dict(
            store_path=store.db_path,
            job_id=job["job_id"],
            run_id=job["run_id"],
            owner_token=row["owner_token"],
            run_dir=Path(row["run_dir"]),
            work_queue_path=queue_path,
            worker_count=1,
            lease_seconds=600.0,
            defer_base_seconds=0.05,
            defer_max_seconds=0.2,
            idle_poll_seconds=0.01,
            progress_interval_seconds=0.2,
            finalize_grace_seconds=2.0,
            cancel_grace_seconds=1.0,
            max_attempts=3,
            max_batches=8,
        )
        kwargs.update(overrides)
        return SessionWorkScheduler(**kwargs)

    return SimpleNamespace(
        project=project,
        service=service,
        store=store,
        job=job,
        row=row,
        queue_path=queue_path,
        factory=factory,
        tmp_path=tmp_path,
    )


# ---------------------------------------------------------------------------
# construction / binding guards


def test_constructor_verifies_attempt_binding(session_env):
    env = session_env
    with pytest.raises(JobError) as excinfo:
        env.factory(run_id="run_other")
    assert excinfo.value.code == "attempt_superseded"

    with pytest.raises(JobError) as excinfo:
        env.factory(owner_token="foreign-token")
    assert excinfo.value.code == "owner_token_mismatch"

    with pytest.raises(JobError) as excinfo:
        env.factory(job_id="job_missing")
    assert excinfo.value.code == "job_not_found"

    set_job_field(env.store, env.job["job_id"], {"status": "failed"})
    with pytest.raises(JobError) as excinfo:
        env.factory()
    assert excinfo.value.code == "job_terminal"

    # A fresh, non-terminal job binds and persists the input revision.
    project2 = make_project(env.tmp_path, name="project2")
    service2 = make_service(project2)
    job2 = start_job(service2, request_id="req-bind-2")
    store2 = store_for(project2)
    row2 = store2.get_job(job2["job_id"])
    scheduler = SessionWorkScheduler(
        store_path=store2.db_path,
        job_id=job2["job_id"],
        run_id=job2["run_id"],
        owner_token=row2["owner_token"],
        run_dir=Path(row2["run_dir"]),
        work_queue_path=env.tmp_path / "q2.db",
    )
    assert scheduler.input_revision == row2["input_revision"]
    assert scheduler.work_queue_path.is_file()

    with pytest.raises(JobError):
        scheduler.register_handler("", lambda work: WorkComplete())
    with pytest.raises(JobError):
        scheduler.register_handler("entry", "not-callable")  # type: ignore[arg-type]

    scheduler.register_handler("entry", lambda work: WorkComplete())
    scheduler.submit([item("only")])
    assert scheduler.run()["status"] == "drained"
    with pytest.raises(JobError) as excinfo:
        scheduler.run()
    assert excinfo.value.code == "invalid_state"


def test_env_contract_full_set_required(session_env):
    full = {
        JOB_ENV_STORE: "/tmp/jobs.db",
        JOB_ENV_JOB_ID: "job_1",
        JOB_ENV_RUN_ID: "run_1",
        JOB_ENV_OWNER_TOKEN: "tok",
        JOB_ENV_RUN_DIR: "/tmp/run",
    }
    context = session_job_context_from_env(full)
    assert context is not None
    assert context.store_path == "/tmp/jobs.db"
    assert context.job_id == "job_1"
    assert context.run_id == "run_1"
    assert context.owner_token == "tok"
    assert context.run_dir == "/tmp/run"
    hook = job_window_hook_from_environment(full)
    assert isinstance(hook, JobWindowHook)

    for missing in (JOB_ENV_STORE, JOB_ENV_JOB_ID, JOB_ENV_RUN_ID, JOB_ENV_OWNER_TOKEN):
        partial = dict(full)
        del partial[missing]
        assert session_job_context_from_env(partial) is None
        assert job_window_hook_from_environment(partial) is None
    blank = dict(full)
    blank[JOB_ENV_RUN_DIR] = "   "
    assert session_job_context_from_env(blank) is None
    assert job_window_hook_from_environment({}) is None


# ---------------------------------------------------------------------------
# normal drain, progress honesty and token secrecy


def test_run_drains_reports_measured_progress_and_hides_tokens(session_env):
    env = session_env
    executed: List[str] = []

    def handler(work):
        assert not hasattr(work, "claim_token"), "handler must never see the claim token"
        executed.append(work.scope_key)
        return WorkComplete(detail={"scope": work.scope_key})

    scheduler = env.factory()
    scheduler.register_handler("entry", handler)
    scheduler.submit([item("a"), item("b"), item("c"), item("d")])
    summary = scheduler.run()

    assert summary["schema"] == SCHEDULER_SCHEMA
    assert summary["status"] == "drained"
    assert summary["counts"]["completed"] == 4
    assert summary["completed_this_run"] == 4
    assert summary["remaining_count"] == 0
    assert sorted(executed) == ["a", "b", "c", "d"]

    # Measured progress only: 4 of 4 real items.
    row = env.store.get_job(env.job["job_id"])
    assert row["progress_json"]["completed"] == 4
    assert row["progress_json"]["total"] == 4
    assert row["progress_json"]["unit"] == "work_items"
    assert row["phase"] is None or isinstance(row["phase"], str)

    pending = json.loads(Path(summary["pending_path"]).read_text(encoding="utf-8"))
    assert pending["count"] == 0
    assert pending["job_id"] == env.job["job_id"]
    assert pending["run_id"] == env.job["run_id"]

    kinds = event_kinds(env.store, env.job["job_id"])
    assert "session_scheduler_started" in kinds
    assert "session_scheduler_finished" in kinds
    assert kinds.count("work_completed") == 4

    # No token ever reaches events, the summary or the persisted pending file.
    dump = json.dumps(
        {
            "events": events_of(env.store, env.job["job_id"]),
            "summary": summary,
            "pending": pending,
        }
    )
    assert env.row["owner_token"] not in dump


def test_progress_stays_unknown_without_measured_denominator(session_env):
    env = session_env
    scheduler = env.factory()
    scheduler.register_handler("entry", lambda work: WorkComplete())
    summary = scheduler.run()

    assert summary["status"] == "drained"
    assert summary["counts"]["completed"] == 0
    row = env.store.get_job(env.job["job_id"])
    for key in ("completed", "total", "active", "deferred"):
        assert row["progress_json"][key] is None
    assert Path(summary["pending_path"]).read_text(encoding="utf-8").count('"count": 0')


# ---------------------------------------------------------------------------
# window: stop new claims, bounded finalization, honest interruption


def test_deadline_already_past_claims_nothing(session_env):
    env = session_env
    scheduler = env.factory()
    scheduler.register_handler("entry", lambda work: WorkComplete())
    scheduler.submit([item("a"), item("b")])
    set_job_field(env.store, env.job["job_id"], {"stop_at_epoch": time.time() - 1.0})

    summary = scheduler.run()
    assert summary["status"] == "window_closed"
    assert summary["completed_this_run"] == 0
    assert summary["counts"]["pending"] == 2
    pending = json.loads(Path(summary["pending_path"]).read_text(encoding="utf-8"))
    assert pending["source"] == PENDING_SOURCE_WINDOW
    assert pending["count"] == 2
    assert {entry["scope_key"] for entry in pending["items"]} == {"a", "b"}


def test_claimed_work_finishes_bounded_after_deadline(session_env):
    env = session_env
    scheduler = env.factory(finalize_grace_seconds=2.0)

    def handler(work):
        time.sleep(0.6)  # crosses the deadline mid-flight; finishes bounded
        return WorkComplete()

    scheduler.register_handler("entry", handler)
    scheduler.submit([item("a"), item("b")])
    set_job_field(env.store, env.job["job_id"], {"stop_at_epoch": time.time() + 0.5})

    summary = scheduler.run()
    assert summary["status"] == "window_closed"
    # The in-flight item completed after the deadline; the unclaimed one stays.
    assert summary["counts"]["completed"] == 1
    assert summary["counts"]["pending"] == 1
    pending = json.loads(Path(summary["pending_path"]).read_text(encoding="utf-8"))
    assert [entry["scope_key"] for entry in pending["items"]] == ["b"]


def test_interrupted_inflight_work_defers_with_honest_reason(session_env):
    env = session_env
    scheduler = env.factory(finalize_grace_seconds=0.3)

    def handler(work):
        for _ in range(200):  # ~4s of cooperative token polling
            work.cancellation.raise_if_cancelled()
            time.sleep(0.02)
        return WorkComplete()

    scheduler.register_handler("entry", handler)
    scheduler.submit([item("a")])
    set_job_field(env.store, env.job["job_id"], {"stop_at_epoch": time.time() + 0.4})

    summary = scheduler.run()
    assert summary["status"] == "window_closed"
    assert summary["counts"]["completed"] == 0
    assert summary["counts"]["deferred"] == 1
    assert summary["deferred_this_run"] == 1
    _, rows = queue_rows(env.queue_path)
    assert rows[0]["last_defer_reason"].startswith("session_interrupted:")
    pending = json.loads(Path(summary["pending_path"]).read_text(encoding="utf-8"))
    assert pending["items"][0]["scope_key"] == "a"


# ---------------------------------------------------------------------------
# cancel: interrupt in-flight, persist remaining, never touch job status


def test_cancel_interrupts_inflight_and_persists_remaining(session_env):
    env = session_env

    def handler(work):
        for _ in range(500):  # ~10s of cooperative token polling
            work.cancellation.raise_if_cancelled()
            time.sleep(0.02)
        return WorkComplete()

    scheduler = env.factory(cancel_grace_seconds=1.5)
    scheduler.register_handler("entry", handler)
    scheduler.submit([item("a"), item("b"), item("c")])

    results: List[Dict[str, Any]] = []
    thread = threading.Thread(target=lambda: results.append(scheduler.run()), daemon=True)
    thread.start()
    wait_for(
        lambda: queue_rows(env.queue_path)[1]
        and any(row["status"] == "active" for row in queue_rows(env.queue_path)[1]),
        description="first claimed item active",
    )
    set_job_field(env.store, env.job["job_id"], {"cancel_requested_at": utc_now_iso()})
    thread.join(timeout=15.0)
    assert not thread.is_alive(), "scheduler did not finish after cancel"

    summary = results[0]
    assert summary["status"] == "cancelled"
    assert summary["cancel_observed"] is True
    assert summary["counts"]["completed"] == 0
    assert summary["remaining_count"] == 3
    pending = json.loads(Path(summary["pending_path"]).read_text(encoding="utf-8"))
    assert pending["source"] == PENDING_SOURCE_CANCEL
    assert pending["count"] == 3

    # The scheduler never writes the job's own status; only the request flag.
    row = env.store.get_job(env.job["job_id"])
    assert row["status"] == "queued"
    assert row["cancel_requested_at"] is not None


# ---------------------------------------------------------------------------
# the coordinator's three counterexamples (regressions)


def test_stale_claim_verdict_rejected_and_children_never_enqueued(session_env):
    """Counterexample 1: a rejected stale claim must not enqueue discoveries.

    Two real schedulers share one queue.  The first claimant's lease expires
    mid-execution (driven by an injected clock, immune to wall-clock jumps);
    the second re-claims the item and holds it active.  The first claimant's
    late verdict is rejected with ``stale_claim`` and its discovered child
    never enters the queue.
    """

    env = session_env
    clock = {"now": 1000.0}

    def slow_handler(work):
        time.sleep(1.2)  # its lease (10 clock-seconds) expires while this runs
        return WorkComplete(discoveries=[item("stale-child")])

    def reclaiming_handler(work):
        time.sleep(2.0)  # keeps the re-claimed item active past the old verdict
        return WorkComplete()

    first = env.factory(lease_seconds=10.0, now_fn=lambda: clock["now"])
    first.register_handler("entry", slow_handler)
    first.submit([item("parent")])

    results: List[Dict[str, Any]] = []
    thread = threading.Thread(target=lambda: results.append(first.run()), daemon=True)
    thread.start()
    token = wait_for(
        lambda: queue_claim_token(env.queue_path),
        description="parent claimed by the first scheduler",
    )
    # The claim is active under the injected clock; advance past its lease.
    clock["now"] = 1020.0

    second = env.factory(lease_seconds=10.0, now_fn=lambda: clock["now"])
    second.register_handler("entry", reclaiming_handler)
    second_results: List[Dict[str, Any]] = []
    second_thread = threading.Thread(
        target=lambda: second_results.append(second.run()), daemon=True
    )
    second_thread.start()
    wait_for(
        lambda: queue_rows(env.queue_path)[1][0]["attempts"] == 2,
        description="the second scheduler re-claimed the expired lease",
    )

    thread.join(timeout=15.0)
    assert not thread.is_alive()
    second_thread.join(timeout=15.0)
    assert not second_thread.is_alive()
    first_summary = results[0]
    second_summary = second_results[0]

    assert second_summary["counts"]["completed"] == 1
    assert second_summary["completed_this_run"] == 1
    assert first_summary["rejected_verdicts"] == 1
    assert first_summary["completed_this_run"] == 0
    assert first_summary["discoveries_enqueued"] == 0

    meta, rows = queue_rows(env.queue_path)
    assert len(rows) == 1, "the stale child must never be enqueued"
    assert rows[0]["scope_key"] == "parent"
    assert rows[0]["status"] == "completed"
    assert rows[0]["attempts"] == 2 and rows[0]["total_attempts"] == 2

    rejections = [
        event
        for event in events_of(env.store, env.job["job_id"])
        if event["kind"] == "work_verdict_rejected"
    ]
    assert rejections and rejections[0]["data"]["code"] == "stale_claim"

    # The live claim token never leaked into events, summaries or pending.
    dump = json.dumps(
        {
            "events": events_of(env.store, env.job["job_id"]),
            "first": first_summary,
            "second": second_summary,
        }
    )
    assert token not in dump


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"input_revision": "fp1"}, "input_revision_changed"),
        ({"owner_token": "new-owner"}, "owner_token_mismatch"),
    ],
)
def test_callback_binding_change_revokes_result_and_discoveries(session_env, change, reason):
    """Counterexamples 2 and 3: a callback that loses the binding mid-flight.

    The handler mutates the real job row (input revision or owner token)
    while its own item is in flight, then returns a completion with a
    discovered child.  The verdict, the question-free completion and the
    child are all rejected: nothing completes and the queue does not grow.
    """

    env = session_env

    def handler(work):
        current = env.store.get_job(env.job["job_id"])
        env.store.update_job(
            env.job["job_id"], expected_revision=int(current["revision"]), updates=change
        )
        return WorkComplete(discoveries=[item("stale-child")])

    scheduler = env.factory()
    scheduler.register_handler("entry", handler)
    scheduler.submit([item("parent")])
    summary = scheduler.run()

    assert summary["status"] == "stood_down"
    assert summary["stood_down_reason"] == reason
    # Either the settle-time guard rejected the late verdict, or the next
    # loop-top guard stood down before the result was settled; both leave
    # the parent uncommitted under its claim with no discovered children.
    assert summary["rejected_verdicts"] in (0, 1)
    assert summary["completed_this_run"] == 0

    snapshot = scheduler.snapshot()
    assert snapshot["counts"]["completed"] == 0
    assert {row["scope_key"] for row in snapshot["remaining"]} == {"parent"}

    if summary["rejected_verdicts"]:
        rejections = [
            event
            for event in events_of(env.store, env.job["job_id"])
            if event["kind"] == "work_verdict_rejected"
        ]
        assert rejections and rejections[0]["data"]["code"] == "binding_changed"
        assert rejections[0]["data"]["reason"] == reason
    # No new batch beyond the initial backlog, no business question, no
    # further submissions from the revoked result.
    all_events = events_of(env.store, env.job["job_id"])
    assert [event for event in all_events if event["kind"] == "work_question"] == []
    submitted = [event for event in all_events if event["kind"] == "work_submitted"]
    assert len(submitted) == 1 and submitted[0]["data"]["batch_no"] == 1


def test_unreadable_binding_stops_consuming_and_keeps_gap(session_env):
    """An unreadable job row is not authorization to keep consuming."""

    env = session_env

    def handler(work):
        time.sleep(0.4)
        return WorkComplete()

    scheduler = env.factory()
    scheduler.register_handler("entry", handler)
    scheduler.submit([item("a"), item("b")])

    results: List[Dict[str, Any]] = []
    thread = threading.Thread(target=lambda: results.append(scheduler.run()), daemon=True)
    thread.start()
    wait_for(
        lambda: any(row["status"] == "active" for row in queue_rows(env.queue_path)[1]),
        description="first claimed item active",
    )
    env.store.db_path.unlink()  # the binding can no longer be verified

    thread.join(timeout=15.0)
    assert not thread.is_alive()
    summary = results[0]
    assert summary["status"] == "stood_down"
    assert summary["stood_down_reason"] == "store_unreadable"
    assert summary["pending_path"] is None

    _, rows = queue_rows(env.queue_path)
    statuses = {row["scope_key"]: row["status"] for row in rows}
    assert statuses == {"a": "active", "b": "pending"}
    assert not (Path(env.row["run_dir"]) / "pending.json").exists()


def test_superseded_run_stands_down_without_consuming(session_env):
    env = session_env
    scheduler = env.factory()
    scheduler.register_handler("entry", lambda work: WorkComplete())
    scheduler.submit([item("a"), item("b")])
    set_job_field(env.store, env.job["job_id"], {"run_id": "run_newer"})

    summary = scheduler.run()
    assert summary["status"] == "stood_down"
    assert summary["stood_down_reason"] == "run_superseded"
    assert summary["completed_this_run"] == 0
    assert summary["counts"] is None  # no queue snapshot is taken for a dead run
    _, rows = queue_rows(env.queue_path)
    assert {row["status"] for row in rows} == {"pending"}
    assert not (Path(env.row["run_dir"]) / "pending.json").exists()


# ---------------------------------------------------------------------------
# resume: only remaining work reruns; a real input change recovers the queue


def test_resume_same_input_runs_only_remaining_then_recovery_reruns_all(session_env):
    env = session_env
    executed: List[str] = []

    def handler(work):
        executed.append(work.scope_key)
        time.sleep(0.3)
        return WorkComplete()

    def windowed() -> SessionWorkScheduler:
        scheduler = env.factory()
        scheduler.register_handler("entry", handler)
        return scheduler

    first = windowed()
    first.submit([item("a"), item("b"), item("c"), item("d")])
    set_job_field(env.store, env.job["job_id"], {"stop_at_epoch": time.time() + 0.75})
    first_summary = first.run()
    assert first_summary["status"] == "window_closed"
    _, rows = queue_rows(env.queue_path)
    done_first = {row["scope_key"] for row in rows if row["status"] == "completed"}
    remaining_first = {row["scope_key"] for row in rows if row["status"] != "completed"}
    assert done_first and done_first | remaining_first == {"a", "b", "c", "d"}

    # Same input revision: a new scheduler keeps valid completions and runs
    # only the real remaining work.  Windows are per-attempt (the resume
    # path clears them); the new scheduler starts without one.
    executed.clear()
    set_job_field(env.store, env.job["job_id"], {"stop_at_epoch": None})
    second = windowed()
    second_summary = second.run()
    assert second_summary["status"] == "drained"
    assert set(executed) == remaining_first, "resume must not re-scan completed identities"
    assert not (set(executed) & done_first)
    meta, rows = queue_rows(env.queue_path)
    assert meta["input_revision"] == env.row["input_revision"]
    assert meta["recovery_count"] == "0"
    assert all(row["status"] == "completed" for row in rows)

    # A real input change re-binds the queue: every old verdict is revoked
    # and re-verified, not granted.
    executed.clear()
    set_job_field(env.store, env.job["job_id"], {"stop_at_epoch": None, "input_revision": "fp1"})
    third = windowed()
    third_summary = third.run()
    assert third_summary["status"] == "drained"
    assert set(executed) == {"a", "b", "c", "d"}, "changed input must re-verify all items"
    meta, rows = queue_rows(env.queue_path)
    assert meta["input_revision"] == "fp1"
    assert meta["recovery_count"] == "1"
    revoked = {row["scope_key"]: row["revoked_from_status"] for row in rows}
    assert revoked == {"a": "completed", "b": "completed", "c": "completed", "d": "completed"}
    kinds = event_kinds(env.store, env.job["job_id"])
    assert "queue_recovered" in kinds


# ---------------------------------------------------------------------------
# callbacks: current-process registration, bounded failures, business unknowns


def test_unregistered_kind_defers_bounded_then_fails_without_execution(session_env):
    env = session_env
    executed: List[str] = []

    # No handler is registered for "entry": the queue holds persisted items
    # but this process restored no callback from it.
    scheduler = env.factory(max_attempts=2)
    scheduler.submit([item("a"), item("b")])
    summary = scheduler.run()

    assert summary["status"] == "drained"
    assert executed == []
    assert summary["counts"]["failed"] == 2
    assert summary["counts"]["completed"] == 0
    _, rows = queue_rows(env.queue_path)
    for row in rows:
        assert row["status"] == "failed"
        assert row["attempts"] == 2
    deferred = [
        event
        for event in events_of(env.store, env.job["job_id"])
        if event["kind"] == "work_deferred"
    ]
    assert deferred and all(
        event["data"]["reason"] == DEFER_REASON_HANDLER_MISSING for event in deferred
    )
    # Bounded: every unregistered item reaches a terminal failed state.
    assert summary["counts"]["pending"] == 0 and summary["counts"]["deferred"] == 0


def test_handler_exception_defers_bounded(session_env):
    env = session_env

    def handler(work):
        if work.attempts == 1:
            raise RuntimeError("backend temporarily unavailable")
        return WorkComplete()

    scheduler = env.factory()
    scheduler.register_handler("entry", handler)
    scheduler.submit([item("a")])
    summary = scheduler.run()
    assert summary["status"] == "drained"
    assert summary["counts"]["completed"] == 1
    assert summary["deferred_this_run"] == 1
    deferred = [
        event
        for event in events_of(env.store, env.job["job_id"])
        if event["kind"] == "work_deferred"
    ]
    assert deferred and deferred[0]["data"]["reason"].startswith("handler_error:RuntimeError")


def test_business_unknown_records_question_and_defers_not_waiting_user(session_env):
    env = session_env

    def handler(work):
        if work.scope_key == "a" and work.deferred_count == 0:
            return WorkDefer(
                reason="business_unknown:ownership",
                retry_after_seconds=0.05,
                question={
                    "id": "q-own",
                    "question": "Who owns the pooled object?",
                    "affected_scope": work.scope_key,
                },
            )
        return WorkComplete()

    scheduler = env.factory()
    scheduler.register_handler("entry", handler)
    scheduler.submit([item("a"), item("b")])
    summary = scheduler.run()

    assert summary["status"] == "drained"
    assert summary["counts"]["completed"] == 2
    assert summary["questions_recorded"] == 1
    questions = [
        event
        for event in events_of(env.store, env.job["job_id"])
        if event["kind"] == "work_question"
    ]
    assert questions and questions[0]["data"]["question"]["id"] == "q-own"

    # JOB02: no waiting_user state anywhere.
    dump = json.dumps(
        {
            "events": events_of(env.store, env.job["job_id"]),
            "summary": summary,
            "job_row": env.store.get_job(env.job["job_id"]),
        }
    )
    assert "waiting_user" not in dump


# ---------------------------------------------------------------------------
# fairness: next batch for discoveries, dedup, long-pending rotation


def test_discoveries_next_batch_dedup_and_long_pending_rotation(session_env):
    env = session_env
    clock = {"now": 1000.0}
    completed_order: List[str] = []

    def handler(work):
        if work.scope_key == "old":
            if work.deferred_count == 0:
                return WorkDefer(reason="hard", retry_after_seconds=10.0)
            completed_order.append(work.scope_key)
            return WorkComplete()
        if work.scope_key == "gate":
            # Old's backoff elapses while this result settles, so the next
            # claim must serve the long-pending batch-1 item before the
            # newly discovered batch-2 child.
            clock["now"] += 20.0
            completed_order.append(work.scope_key)
            return WorkComplete(discoveries=[item("child"), item("old")])  # old is a duplicate
        completed_order.append(work.scope_key)
        return WorkComplete()

    scheduler = env.factory(now_fn=lambda: clock["now"])
    scheduler.register_handler("entry", handler)
    scheduler.submit([item("old"), item("gate")])
    summary = scheduler.run()

    assert summary["status"] == "drained"
    # The deferred long-pending item rotates back before the newer batch-2
    # discovery; the duplicate discovery is reported, never re-enqueued.
    assert completed_order == ["gate", "old", "child"]
    assert summary["duplicates"] == 1
    assert summary["discoveries_enqueued"] == 1
    meta, rows = queue_rows(env.queue_path)
    assert meta["frontier_batch"] == "2"
    assert {row["scope_key"] for row in rows} == {"old", "gate", "child"}
    child_batch = {row["scope_key"]: row["batch_no"] for row in rows}
    assert child_batch["child"] == 2 and child_batch["old"] == 1
    assert all(row["status"] == "completed" for row in rows)
    kinds = event_kinds(env.store, env.job["job_id"])
    assert "work_discoveries_deduplicated" in kinds


# ---------------------------------------------------------------------------
# real owner + scanner subprocess integration (env contract, window, watchdog)


SCANNER_SCRIPT = """\
import json
import sys
import time
from pathlib import Path

mode = sys.argv[1]
project_root = Path(sys.argv[2])
control_dir = Path(sys.argv[3])
control_dir.mkdir(parents=True, exist_ok=True)

from zscope.orchestration.jobs.scheduler_hook import session_job_context_from_env
from zscope.orchestration.jobs.session_scheduler import (
    SessionWorkScheduler,
    WorkComplete,
    WorkDefer,
)

ctx = session_job_context_from_env()
if ctx is None:
    (control_dir / "env_missing.txt").write_text(
        "ZSCOPE_JOB_* identifiers absent\\n", encoding="utf-8"
    )
    sys.exit(3)

exec_log = control_dir / "executed.jsonl"

CONFIG = {
    "drain": {"items": 6, "work": 0.05, "workers": 2, "lease": 30.0, "finalize": 3.0},
    "drain4": {"items": 4, "work": 0.05, "workers": 2, "lease": 30.0, "finalize": 3.0},
    "slow": {"items": 8, "work": 1.2, "workers": 2, "lease": 30.0, "finalize": 3.0},
    "slow4": {"items": 4, "work": 1.0, "workers": 1, "lease": 30.0, "finalize": 3.0},
    "hang": {"items": 3, "work": 300.0, "workers": 1, "lease": 2.0, "finalize": 60.0},
    "poll": {"items": 6, "work": 1.5, "workers": 2, "lease": 30.0, "finalize": 3.0},
    "hold4": {"items": 4, "work": 0.05, "workers": 1, "lease": 30.0, "finalize": 3.0},
    "release4": {"items": 4, "work": 0.05, "workers": 2, "lease": 30.0, "finalize": 3.0},
}
cfg = CONFIG[mode]


def log_exec(work):
    with exec_log.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps({"run_id": ctx.run_id, "scope": work.scope_key, "at": time.time()})
            + "\\n"
        )


def handler(work):
    log_exec(work)
    if mode == "hold4" and work.scope_key in ("s3", "s4"):
        if (control_dir / "hold.flag").exists():
            # Deterministic split: hold s3/s4 back with a backoff that
            # outlives the first run's window, keeping real remaining work.
            return WorkDefer(reason="controlled-hold", retry_after_seconds=12.0)
    if mode == "poll":
        deadline = time.monotonic() + cfg["work"]
        while time.monotonic() < deadline:
            work.cancellation.raise_if_cancelled()
            time.sleep(0.05)
        return WorkComplete(detail={"scope": work.scope_key})
    time.sleep(cfg["work"])
    return WorkComplete(detail={"scope": work.scope_key})


scheduler = SessionWorkScheduler(
    store_path=ctx.store_path,
    job_id=ctx.job_id,
    run_id=ctx.run_id,
    owner_token=ctx.owner_token,
    run_dir=ctx.run_dir,
    worker_count=cfg["workers"],
    lease_seconds=cfg["lease"],
    finalize_grace_seconds=cfg["finalize"],
    cancel_grace_seconds=2.0,
    defer_base_seconds=0.05,
    defer_max_seconds=0.2,
    idle_poll_seconds=0.02,
    progress_interval_seconds=0.5,
    max_attempts=3,
    max_batches=8,
)
scheduler.register_handler("entry", handler)
scheduler.submit(
    [
        {"kind": "entry", "scope_key": "s%d" % i, "build": "b1", "payload": {"i": i}}
        for i in range(1, cfg["items"] + 1)
    ]
)
summary = scheduler.run()
(control_dir / ("summary-" + ctx.run_id + ".json")).write_text(
    json.dumps(summary, indent=2), encoding="utf-8"
)
sys.exit(0)
"""


def scanner_service(project: Path, scanner: Path, mode_box: List[str], control_dir: Path):
    def builder(config_path, scan_depth, python_executable):
        return [python_executable, str(scanner), mode_box[0], str(project), str(control_dir)]

    return ScanJobService(
        project / "zscope.yaml",
        scan_command_builder=builder,
        spawn_owner=True,
        terminate_grace=2.0,
    )


def wait_terminal(service: ScanJobService, job_id: str, *, timeout: float = 60.0) -> Dict[str, Any]:
    def probe():
        response = service.detail(job_id)
        assert response.status_code == 200, response.payload
        job = response.payload["job"]
        return job if job["status"] in TERMINAL_STATUSES else None

    return wait_for(probe, timeout=timeout, description=f"terminal state of {job_id}")


def wait_running(service: ScanJobService, job_id: str) -> Dict[str, Any]:
    def probe():
        job = service.detail(job_id).payload["job"]
        if job["status"] == "running":
            store = store_for(Path(service.config_path).parent)
            row = store.get_job(job_id)
            if row and row["scanner_pid"]:
                return row
        return None

    return wait_for(probe, description=f"running scanner of {job_id}")


def job_queue_path(project: Path, job_id: str) -> Path:
    return project / STORE_DIR_NAME / job_id / "work-queue.db"


def exec_lines(control_dir: Path, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
    log = control_dir / "executed.jsonl"
    if not log.is_file():
        return []
    lines = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
    if run_id is None:
        return lines
    return [line for line in lines if line["run_id"] == run_id]


@needs_proc
def test_owner_passes_env_and_session_drains_queue(tmp_path: Path):
    project = make_project(tmp_path)
    scanner = tmp_path / "scanner.py"
    scanner.write_text(SCANNER_SCRIPT, encoding="utf-8")
    control = tmp_path / "control"
    mode_box = ["drain"]
    service = scanner_service(project, scanner, mode_box, control)
    job = start_job(service, request_id="req-env-drain")

    terminal = wait_terminal(service, job["job_id"])
    assert terminal["status"] == "completed"
    assert not (control / "env_missing.txt").exists(), "owner must pass ZSCOPE_JOB_* identifiers"

    summary_path = control / f"summary-{terminal['run_id']}.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["status"] == "drained"
    assert summary["counts"]["completed"] == 6

    assert len(exec_lines(control)) == 6
    meta, rows = queue_rows(job_queue_path(project, job["job_id"]))
    assert meta["job_id"] == job["job_id"]
    assert all(row["status"] == "completed" for row in rows)

    # Measured progress from the real session reached the job row.
    row = store_for(project).get_job(job["job_id"])
    assert row["progress_json"]["completed"] == 6
    assert row["progress_json"]["total"] == 6
    assert row["progress_json"]["unit"] == "work_items"
    assert row["owner_token"] not in summary_path.read_text(encoding="utf-8")


@needs_proc
def test_cooperative_window_exit_preserves_real_pending(tmp_path: Path):
    project = make_project(tmp_path)
    scanner = tmp_path / "scanner.py"
    scanner.write_text(SCANNER_SCRIPT, encoding="utf-8")
    control = tmp_path / "control"
    mode_box = ["slow"]
    service = scanner_service(project, scanner, mode_box, control)
    stop_at = (datetime.now(timezone.utc) + timedelta(seconds=2.5)).isoformat()
    job = start_job(service, stop_at=stop_at, request_id="req-window-coop")
    running = wait_running(service, job["job_id"])

    terminal = wait_terminal(service, job["job_id"], timeout=60.0)
    assert terminal["status"] == "partial"
    assert terminal["error"]["code"] == "stop_window_reached"

    kinds = [event["kind"] for event in service.events(job["job_id"], 0).payload["events"]]
    assert "stop_window_reached" in kinds
    assert "window_cooperative_exit" in kinds
    assert "pending_preserved" in kinds
    assert "window_watchdog" not in kinds
    assert "scan_terminated" not in kinds

    # The real remaining queue survives; the owner placeholder never ran.
    run_dir = Path(running["run_dir"])
    pending = json.loads((run_dir / "pending.json").read_text(encoding="utf-8"))
    assert pending["source"] == PENDING_SOURCE_WINDOW
    assert pending["job_id"] == job["job_id"]
    assert pending["run_id"] == terminal["run_id"]

    meta, rows = queue_rows(job_queue_path(project, job["job_id"]))
    by_scope = {row["scope_key"]: row["status"] for row in rows}
    completed = {scope for scope, status in by_scope.items() if status == "completed"}
    remaining = {scope for scope, status in by_scope.items() if status != "completed"}
    assert len(rows) == 8
    assert 2 <= len(completed) < 8, "the window must stop new claims before the queue drains"
    assert {entry["scope_key"] for entry in pending["items"]} == remaining
    executed = {line["scope"] for line in exec_lines(control)}
    assert executed == completed, "only completed items were executed"


@needs_proc
def test_watchdog_kills_session_that_ignores_the_window(tmp_path: Path):
    project = make_project(tmp_path)
    scanner = tmp_path / "scanner.py"
    scanner.write_text(SCANNER_SCRIPT, encoding="utf-8")
    control = tmp_path / "control"
    mode_box = ["hang"]
    service = scanner_service(project, scanner, mode_box, control)
    stop_at = (datetime.now(timezone.utc) + timedelta(seconds=2.0)).isoformat()
    job = start_job(service, stop_at=stop_at, request_id="req-watchdog")
    running = wait_running(service, job["job_id"])
    scanner_pid = int(running["scanner_pid"])

    terminal = wait_terminal(service, job["job_id"], timeout=60.0)
    assert terminal["status"] == "partial"
    assert (
        identity.probe_process(scanner_pid, expected_start_ticks=running["scanner_start_ticks"])
        is not True
    ), "the watchdog must have torn the scanner down"

    events = service.events(job["job_id"], 0).payload["events"]
    kinds = [event["kind"] for event in events]
    assert "stop_window_reached" in kinds
    assert "window_watchdog" in kinds
    terminated = [event for event in events if event["kind"] == "scan_terminated"]
    assert terminated and terminated[0]["data"]["reason"] == "stop_window"
    assert terminated[0]["data"]["outcome"] in {"terminated", "killed"}

    # The scanner never finalized, so the honest owner placeholder remains.
    run_dir = Path(running["run_dir"])
    pending = json.loads((run_dir / "pending.json").read_text(encoding="utf-8"))
    assert pending["source"] == "owner_window_stop"
    assert pending["count"] == 0

    # In-flight work stays active under its expired lease; the rest pending.
    _, rows = queue_rows(job_queue_path(project, job["job_id"]))
    statuses = {row["scope_key"]: row["status"] for row in rows}
    assert statuses == {"s1": "active", "s2": "pending", "s3": "pending"}
    active = rows[0]
    assert active["claim_expires_at"] is not None and active["claim_expires_at"] <= time.time()


@needs_proc
def test_cancel_persists_real_remaining_from_session(tmp_path: Path):
    project = make_project(tmp_path)
    scanner = tmp_path / "scanner.py"
    scanner.write_text(SCANNER_SCRIPT, encoding="utf-8")
    control = tmp_path / "control"
    mode_box = ["poll"]
    service = scanner_service(project, scanner, mode_box, control)
    job = start_job(service, request_id="req-cancel-session")
    running = wait_running(service, job["job_id"])

    wait_for(
        lambda: exec_lines(control) or None,
        description="scanner executing its first item",
    )
    current = service.detail(job["job_id"]).payload["job"]
    response = service.cancel(
        job["job_id"], base_revision=current["revision"], request_id="req-cancel-session-op"
    )
    assert response.status_code == 200

    terminal = wait_terminal(service, job["job_id"], timeout=40.0)
    assert terminal["status"] == "cancelled"
    assert terminal["error"]["code"] == "cancelled"

    events = service.events(job["job_id"], 0).payload["events"]
    terminated = [event for event in events if event["kind"] == "scan_terminated"]
    assert terminated and terminated[0]["data"]["reason"] == "cancel"

    # The session persisted the real remaining queue before it exited.
    run_dir = Path(running["run_dir"])
    pending = json.loads((run_dir / "pending.json").read_text(encoding="utf-8"))
    assert pending["source"] == PENDING_SOURCE_CANCEL
    _, rows = queue_rows(job_queue_path(project, job["job_id"]))
    by_scope = {row["scope_key"]: row["status"] for row in rows}
    completed = {scope for scope, status in by_scope.items() if status == "completed"}
    deferred = {scope for scope, status in by_scope.items() if status == "deferred"}
    assert len(rows) == 6
    assert deferred, "interrupted in-flight work defers with an honest reason"
    assert {entry["scope_key"] for entry in pending["items"]} == set(by_scope) - completed


@needs_proc
def test_resume_same_input_runs_only_real_remaining(tmp_path: Path):
    """Deterministic split: the first attempt completes s1/s2 and holds s3/s4.

    The hold is a control-file-gated deferral whose backoff outlives the
    first window, so the partial run keeps a real, non-empty remaining queue
    without relying on wall-clock luck; the resumed attempt releases the
    held items and runs exactly those.
    """

    project = make_project(tmp_path)
    scanner = tmp_path / "scanner.py"
    scanner.write_text(SCANNER_SCRIPT, encoding="utf-8")
    control = tmp_path / "control"
    control.mkdir(parents=True, exist_ok=True)
    hold = control / "hold.flag"
    hold.write_text("hold\n", encoding="utf-8")
    mode_box = ["hold4"]
    service = scanner_service(project, scanner, mode_box, control)
    stop_at = (datetime.now(timezone.utc) + timedelta(seconds=6.0)).isoformat()
    job = start_job(service, stop_at=stop_at, request_id="req-resume-same")
    first = wait_terminal(service, job["job_id"], timeout=90.0)
    assert first["status"] == "partial"

    _, rows = queue_rows(job_queue_path(project, job["job_id"]))
    done_first = {row["scope_key"] for row in rows if row["status"] == "completed"}
    remaining_first = {row["scope_key"] for row in rows if row["status"] == "deferred"}
    assert done_first == {"s1", "s2"}, "the first attempt must complete exactly the released part"
    assert remaining_first == {"s3", "s4"}, "the held part must stay real remaining work"
    executed_first = [line["scope"] for line in exec_lines(control, first["run_id"])]
    assert set(executed_first) == {"s1", "s2", "s3", "s4"}
    # Each held item ran exactly once to decide the hold: no busy retry loop.
    assert executed_first.count("s3") == 1 and executed_first.count("s4") == 1

    # Resume with unchanged inputs: only the real remaining work runs.
    hold.unlink()
    mode_box[0] = "release4"
    response = service.resume(
        job["job_id"], base_revision=first["revision"], request_id="req-resume-same-op"
    )
    assert response.status_code == 202
    second_run = response.payload["job"]["run_id"]
    assert second_run != first["run_id"]

    terminal = wait_terminal(service, job["job_id"], timeout=90.0)
    assert terminal["status"] == "completed"
    executed_second = {line["scope"] for line in exec_lines(control, second_run)}
    assert executed_second == remaining_first, "resume must run only the remaining identities"
    assert not (executed_second & done_first)

    meta, rows = queue_rows(job_queue_path(project, job["job_id"]))
    assert meta["recovery_count"] == "0"
    assert all(row["status"] == "completed" for row in rows)


@needs_proc
def test_resume_changed_input_recovers_and_reruns_all(tmp_path: Path):
    """Same deterministic hold/release split, then a real source change.

    The resumed attempt must revoke both the old completions and the old
    deferrals and re-verify every item under the new input revision.
    """

    project = make_project(tmp_path)
    scanner = tmp_path / "scanner.py"
    scanner.write_text(SCANNER_SCRIPT, encoding="utf-8")
    control = tmp_path / "control"
    control.mkdir(parents=True, exist_ok=True)
    hold = control / "hold.flag"
    hold.write_text("hold\n", encoding="utf-8")
    mode_box = ["hold4"]
    service = scanner_service(project, scanner, mode_box, control)
    stop_at = (datetime.now(timezone.utc) + timedelta(seconds=6.0)).isoformat()
    job = start_job(service, stop_at=stop_at, request_id="req-resume-changed")
    first = wait_terminal(service, job["job_id"], timeout=90.0)
    assert first["status"] == "partial"
    _, rows = queue_rows(job_queue_path(project, job["job_id"]))
    done_first = {row["scope_key"] for row in rows if row["status"] == "completed"}
    held_first = {row["scope_key"] for row in rows if row["status"] == "deferred"}
    assert done_first == {"s1", "s2"}
    assert held_first == {"s3", "s4"}

    # A real source change: the next attempt's fingerprint differs.
    (project / "src" / "main.c").write_text("int main(void) { return 1; }\n", encoding="utf-8")
    hold.unlink()
    mode_box[0] = "release4"
    response = service.resume(
        job["job_id"], base_revision=first["revision"], request_id="req-resume-changed-op"
    )
    assert response.status_code == 202
    second_run = response.payload["job"]["run_id"]

    terminal = wait_terminal(service, job["job_id"], timeout=90.0)
    assert terminal["status"] == "completed"
    executed_second = {line["scope"] for line in exec_lines(control, second_run)}
    assert executed_second == {
        "s1",
        "s2",
        "s3",
        "s4",
    }, "changed input must revoke old completions and re-verify every item"

    meta, rows = queue_rows(job_queue_path(project, job["job_id"]))
    assert meta["recovery_count"] == "1"
    connection = sqlite3.connect(str(job_queue_path(project, job["job_id"])))
    connection.row_factory = sqlite3.Row
    try:
        recoveries = [
            dict(row)
            for row in connection.execute("SELECT * FROM recoveries ORDER BY seq DESC LIMIT 1")
        ]
    finally:
        connection.close()
    # Both the completed part and the held part were non-pending: the
    # recovery revoked and re-pended all four verdicts.
    assert recoveries and recoveries[0]["re_pended"] == 4
    revoked = {row["scope_key"]: row["revoked_from_status"] for row in rows}
    assert revoked == {
        "s1": "completed",
        "s2": "completed",
        "s3": "deferred",
        "s4": "deferred",
    }
    assert all(row["status"] == "completed" for row in rows)
    kinds = [event["kind"] for event in service.events(job["job_id"], 0).payload["events"]]
    # The service revoked the stale input binding when arming the resume; the
    # session scheduler then recovered the per-job queue (queue_recovered).
    assert "input_revoked" in kinds
    assert "queue_recovered" in kinds


# ---------------------------------------------------------------------------
# R2 regressions: discovery durability, bounds and the binding/queue race


def test_batch_limit_keeps_blocked_parent_as_explicit_pending(session_env):
    """A discovery that hits max_batches must not vanish inside a drained run.

    The parent's verdict is replaced by an explicit deferral, the round
    stops claiming and the real remaining queue keeps the obligation.
    """

    env = session_env
    scheduler = env.factory(max_batches=1)
    scheduler.register_handler("entry", lambda work: WorkComplete(discoveries=[item("child")]))
    scheduler.submit([item("parent")])
    summary = scheduler.run()

    assert summary["status"] == "discovery_blocked"
    assert summary["discovery_blocked"] == "batch_limit"
    assert summary["discoveries_dropped"] == 1
    assert summary["discoveries_enqueued"] == 0
    assert summary["completed_this_run"] == 0

    snapshot = scheduler.snapshot()
    assert snapshot["unresolved_count"] == 1
    blocked = snapshot["remaining"][0]
    assert blocked["scope_key"] == "parent"
    assert blocked["status"] == "deferred"
    assert blocked["reason"] == "discovery_batch_limit"

    pending = json.loads(Path(summary["pending_path"]).read_text(encoding="utf-8"))
    assert pending["source"] == PENDING_SOURCE_BLOCKED
    assert [entry["scope_key"] for entry in pending["items"]] == ["parent"]
    assert "discovery_blocked" in event_kinds(env.store, env.job["job_id"])


def _make_bound_job_store(directory: Path) -> JobStore:
    store = JobStore(directory / "jobs.db")
    store.initialize()
    now = utc_now_iso()
    store.create_job(
        {
            "job_id": "job_probe",
            "run_id": "run_probe",
            "revision": 1,
            "input_revision": "fp0",
            "status": "running",
            "created_at": now,
            "updated_at": now,
            "config_path": str(directory / "zscope.yaml"),
            "config_sha256": "dummy",
            "project_root": str(directory),
            "project_id": "dummy",
            "working_directory": str(directory),
            "run_dir": str(directory / "job_probe" / "run_probe"),
            "owner_token": "tok",
        }
    )
    return store


def _crash_after_parent_commit(directory: Path) -> None:
    store = _make_bound_job_store(directory)
    scheduler = SessionWorkScheduler(
        store_path=store.db_path,
        job_id="job_probe",
        run_id="run_probe",
        owner_token="tok",
        run_dir=directory / "job_probe" / "run_probe",
    )
    scheduler.register_handler("entry", lambda work: WorkComplete(discoveries=[item("child")]))
    scheduler.submit([item("parent")])
    original_write = scheduler._queue._write

    @contextmanager
    def crash_after_commit():
        with original_write() as connection:
            yield connection
        # Real process exit right after the verdict transaction commits: an
        # atomic settlement must already contain the child at this point.
        with sqlite3.connect(str(scheduler.work_queue_path)) as connection:
            parent = connection.execute(
                "SELECT status FROM items WHERE scope_key = 'parent'"
            ).fetchone()
        if parent and parent[0] == "completed":
            os._exit(73)

    scheduler._queue._write = crash_after_commit
    scheduler.run()


@needs_proc
def test_process_exit_after_verdict_commit_keeps_child_durable(tmp_path: Path):
    process = multiprocessing.get_context("fork").Process(
        target=_crash_after_parent_commit, args=(tmp_path,)
    )
    process.start()
    process.join(15)
    if process.is_alive():
        process.terminate()
        process.join(5)
    assert process.exitcode == 73, "the crash must fire at the committed verdict"

    reopened = WorkQueue(
        tmp_path / "job_probe" / "work-queue.db", job_id="job_probe", input_revision="fp0"
    )
    snapshot = reopened.snapshot()
    assert snapshot["counts"]["completed"] == 1, "the parent verdict committed"
    assert snapshot["unresolved_count"] == 1, "its child must be durable with it"
    statuses = {row["scope_key"]: row["status"] for row in snapshot["remaining"]}
    assert statuses == {"child": "pending"}


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"owner_token": "new-owner"}, "owner_token_mismatch"),
        ({"input_revision": "fp1"}, "input_revision_changed"),
    ],
)
def test_concurrent_binding_flip_during_inflight_work(session_env, change, reason):
    """Another thread flips the binding while an item is in flight.

    The in-flight verdict and its discovered child are rejected wholesale;
    work finished before the flip stays completed and the queue does not
    grow under the dead binding.
    """

    env = session_env
    flip_done = threading.Event()

    def handler(work):
        if work.scope_key == "pivot":
            assert flip_done.wait(timeout=10), "racer never flipped the binding"
            return WorkComplete(discoveries=[item("pivot-child")])
        return WorkComplete()

    scheduler = env.factory()
    scheduler.register_handler("entry", handler)
    scheduler.submit([item("warmup"), item("pivot")])

    def racer():
        wait_for(
            lambda: any(
                row["status"] == "active" and row["scope_key"] == "pivot"
                for row in queue_rows(env.queue_path)[1]
            ),
            description="pivot claimed",
        )
        set_job_field(env.store, env.job["job_id"], change)
        flip_done.set()

    results: List[Dict[str, Any]] = []
    worker = threading.Thread(target=lambda: results.append(scheduler.run()), daemon=True)
    racer_thread = threading.Thread(target=racer, daemon=True)
    worker.start()
    racer_thread.start()
    worker.join(timeout=20.0)
    racer_thread.join(timeout=10.0)
    assert not worker.is_alive(), "scheduler did not finish after the flip"

    summary = results[0]
    assert summary["status"] == "stood_down"
    assert summary["stood_down_reason"] == reason
    # Either the settle-time guard rejected the late verdict outright, or the
    # loop-top guard stood the run down first and the result was never
    # settled; both leave the pivot uncommitted under its claim.
    assert summary["rejected_verdicts"] in (0, 1)
    assert summary["discoveries_enqueued"] == 0
    if summary["rejected_verdicts"]:
        assert summary["discoveries_dropped"] == 1

    snapshot = scheduler.snapshot()
    assert snapshot["counts"]["completed"] == 1  # warmup finished before the flip
    assert {row["scope_key"] for row in snapshot["remaining"]} == {"pivot"}
    if summary["rejected_verdicts"]:
        rejections = [
            event
            for event in events_of(env.store, env.job["job_id"])
            if event["kind"] == "work_verdict_rejected"
        ]
        assert rejections and rejections[-1]["data"]["code"] == "binding_changed"


def test_bound_attempt_holds_binding_lock_through_queue_write(session_env):
    """The store lock is held until the queue transaction has committed.

    A concurrent binding flip blocks on the lock while the settlement
    commits under the verified binding, and is rejected afterwards.
    """

    env = session_env
    scheduler = env.factory()
    scheduler.register_handler("entry", lambda work: WorkComplete())
    scheduler.submit([item("pivot")])
    claimed = scheduler._queue.claim_batch(1, now=time.time())["claimed"][0]
    assert claimed["scope_key"] == "pivot"

    flipped: Dict[str, Any] = {}

    def racer():
        set_job_field(env.store, env.job["job_id"], {"input_revision": "fp1"})
        flipped["done"] = True

    racer_thread = threading.Thread(target=racer, daemon=True)
    with env.store.bound_attempt(
        job_id=env.job["job_id"],
        run_id=env.job["run_id"],
        owner_token=env.row["owner_token"],
        expected_input_revision=env.row["input_revision"],
    ):
        racer_thread.start()
        time.sleep(0.5)
        assert not flipped, "the flip must not commit while the attempt lock is held"
        result = scheduler._queue.settle(
            claimed["item_id"],
            action="complete",
            claim_token=claimed["claim_token"],
            discoveries=[item("child")],
            now=time.time(),
        )
        assert result["status"] == "completed"
    racer_thread.join(timeout=10.0)
    assert flipped.get("done") is True

    # After the flip, binding under the old input revision is rejected.
    with pytest.raises(JobError) as excinfo:
        with env.store.bound_attempt(
            job_id=env.job["job_id"],
            run_id=env.job["run_id"],
            owner_token=env.row["owner_token"],
            expected_input_revision=env.row["input_revision"],
        ):
            pass
    assert excinfo.value.code == "input_revision_changed"

    snapshot = scheduler.snapshot()
    assert snapshot["counts"]["completed"] == 1
    assert snapshot["counts"]["pending"] == 1  # the atomic child


def test_queue_commit_failure_aborts_run_and_keeps_parent_recoverable(session_env):
    """A real queue-commit failure rolls the verdict back and stops the run."""

    env = session_env
    scheduler = env.factory(lease_seconds=1.0)
    queue = scheduler._queue
    original_write = queue._write

    @contextmanager
    def failing_write():
        with original_write() as connection:
            yield connection
            raise sqlite3.OperationalError("injected pre-commit I/O failure")

    def handler(work):
        # Patch from inside the handler: the claim already committed, the
        # settlement's commit fails for real.
        queue._write = failing_write
        return WorkComplete(discoveries=[item("child")])

    scheduler.register_handler("entry", handler)
    scheduler.submit([item("parent")])
    summary = scheduler.run()
    queue.__dict__.pop("_write", None)

    assert summary["status"] == "aborted"
    assert summary["error"]["code"] == "queue_unavailable"
    _, rows = queue_rows(env.queue_path)
    statuses = {row["scope_key"]: row["status"] for row in rows}
    assert statuses == {"parent": "active"}, "no completion, no child, no loss"

    # The rolled-back parent stays recoverable: after the lease expires a
    # later run settles it normally.
    time.sleep(1.2)
    second = env.factory()
    second.register_handler("entry", lambda work: WorkComplete())
    second_summary = second.run()
    assert second_summary["status"] == "drained"
    assert second_summary["counts"]["completed"] == 1


# ---------------------------------------------------------------------------
# R3 regressions: in-result duplicate children and parked discovery bounds


def test_duplicate_children_inside_one_result_are_deduplicated(session_env):
    """Two identical children in one handler result deduplicate atomically.

    The UNIQUE constraint must never turn a legitimate duplicate into a
    queue-wide failure; the second copy is reported as a duplicate of the
    first copy enqueued by the same transaction.
    """

    env = session_env

    def handler(work):
        if work.scope_key != "parent":
            return WorkComplete()
        return WorkComplete(discoveries=[item("child"), item("child"), item("child")])

    scheduler = env.factory()
    scheduler.register_handler("entry", handler)
    scheduler.submit([item("parent")])
    summary = scheduler.run()

    assert summary["status"] == "drained"
    assert summary["discoveries_enqueued"] == 1
    assert summary["duplicates"] == 2
    assert summary["discoveries_dropped"] == 0
    # The single deduplicated child is then claimed and completed normally.
    snapshot = scheduler.snapshot()
    assert snapshot["counts"]["completed"] == 2
    assert snapshot["unresolved_count"] == 0


def test_parked_discovery_survives_same_input_resume_without_retries(session_env):
    """A parked discovery bound survives a same-input resume as real remaining.

    The resumed round does not drain the obligation, does not fail it by
    attempt accounting and does not re-run the handler (no busy loop); only
    a real input change re-pends and re-verifies it.
    """

    env = session_env
    first_calls: List[str] = []
    second_calls: List[str] = []
    third_calls: List[str] = []

    def first_handler(work):
        first_calls.append(work.scope_key)
        return WorkComplete(discoveries=[item("child")])

    def second_handler(work):
        second_calls.append(work.scope_key)
        return WorkComplete(discoveries=[item("child")])

    def third_handler(work):
        third_calls.append(work.scope_key)
        return WorkComplete(discoveries=[item("child")])

    scheduler = env.factory(max_batches=1, max_attempts=1)
    scheduler.register_handler("entry", first_handler)
    scheduler.submit([item("parent")])
    first = scheduler.run()
    assert first["status"] == "discovery_blocked"
    assert first["remaining_count"] == 1
    assert first["counts"]["failed"] == 0
    first_snapshot = scheduler.snapshot()
    assert first_snapshot["counts"]["deferred"] == 1
    assert first_snapshot["discovery_blocked_count"] == 1

    # Same-input resume: the parked parent is neither claimable nor failed;
    # the resumed round stops on it without re-running the handler.
    resumed = env.factory(max_batches=1, max_attempts=1)
    resumed.register_handler("entry", second_handler)
    second = resumed.run()
    assert second["status"] == "discovery_blocked"
    assert second["remaining_count"] == 1
    assert second["counts"]["failed"] == 0
    assert second["completed_this_run"] == 0
    assert second_calls == [], "a parked obligation must not re-run its handler"
    snapshot = resumed.snapshot()
    assert snapshot["counts"]["deferred"] == 1
    assert snapshot["discovery_blocked_count"] == 1
    parked = snapshot["remaining"][0]
    assert parked["scope_key"] == "parent"
    assert parked["reason"] == "discovery_batch_limit"

    # A real input change revokes the parked premise and re-verifies it:
    # recovery re-pends the item, the handler runs once more and parks again
    # under the same persisted bound.
    set_job_field(env.store, env.job["job_id"], {"input_revision": "fp1"})
    verified = env.factory(max_batches=1, max_attempts=1)
    verified.register_handler("entry", third_handler)
    third = verified.run()
    assert third["status"] == "discovery_blocked"
    assert third_calls == ["parent"], "recovery must actually re-verify the parked item"
    meta, rows = queue_rows(env.queue_path)
    assert meta["recovery_count"] == "1"
    assert meta["input_revision"] == "fp1"
    assert {row["scope_key"]: row["revoked_from_status"] for row in rows} == {"parent": "deferred"}
    assert {row["scope_key"]: row["status"] for row in rows} == {"parent": "deferred"}
