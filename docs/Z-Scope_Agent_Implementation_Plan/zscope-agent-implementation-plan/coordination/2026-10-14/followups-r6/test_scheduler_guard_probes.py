"""Independent real-SQLite probes of callback-result invalidation boundaries."""

import pytest

from zscope.orchestration.jobs.models import utc_now_iso
from zscope.orchestration.jobs.session_scheduler import SessionWorkScheduler, WorkComplete
from zscope.orchestration.jobs.store import JobStore


def bound_scheduler(tmp_path, **kwargs):
    store = JobStore(tmp_path / "jobs.db")
    store.initialize()
    now = utc_now_iso()
    run_dir = tmp_path / "job_test" / "run_test"
    store.create_job({
        "job_id": "job_test", "run_id": "run_test", "revision": 1,
        "input_revision": "fp0", "status": "running", "created_at": now,
        "updated_at": now, "config_path": str(tmp_path / "zscope.yaml"),
        "config_sha256": "dummy", "project_root": str(tmp_path), "project_id": "dummy",
        "working_directory": str(tmp_path), "run_dir": str(run_dir), "owner_token": "tok",
    })
    scheduler = SessionWorkScheduler(store_path=store.db_path, job_id="job_test",
                                     run_id="run_test", owner_token="tok", run_dir=run_dir,
                                     **kwargs)
    return store, scheduler


def item(name):
    return {"kind": "entry", "scope_key": name, "build": "exact-build", "payload": {}}


def test_rejected_stale_claim_cannot_enqueue_discoveries(tmp_path):
    _, scheduler = bound_scheduler(tmp_path, lease_seconds=1, now_fn=lambda: 1002.0)
    scheduler.submit([item("parent")])
    old = scheduler._queue.claim_batch(1, now=1000.0)["claimed"][0]
    fresh = scheduler._queue.claim_batch(1, now=1002.0)["claimed"][0]
    assert old["claim_token"] != fresh["claim_token"]
    scheduler._settle(old, WorkComplete(discoveries=[item("stale-child")]))
    snapshot = scheduler.snapshot()
    assert scheduler._rejected == 1
    assert {row["scope_key"] for row in snapshot["remaining"]} == {"parent"}


@pytest.mark.parametrize("change", [{"input_revision": "fp1"}, {"owner_token": "new-owner"}])
def test_running_callback_change_revokes_its_result_and_discoveries(tmp_path, change):
    store, scheduler = bound_scheduler(tmp_path)
    scheduler.submit([item("parent")])

    def handler(work):
        if work.scope_key == "parent":
            current = store.get_job("job_test")
            store.update_job("job_test", expected_revision=current["revision"], updates=change)
            return WorkComplete(discoveries=[item("stale-child")])
        return WorkComplete()

    scheduler.register_handler("entry", handler)
    scheduler.run()
    snapshot = scheduler.snapshot()
    assert snapshot["counts"]["completed"] == 0
    assert {row["scope_key"] for row in snapshot["remaining"]} == {"parent"}
