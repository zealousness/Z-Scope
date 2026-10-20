"""Real persisted queue settlement edges beyond the original five probes."""
from test_scheduler_guard_probes import bound_scheduler, item
from zscope.orchestration.jobs.session_scheduler import WorkComplete


def test_duplicate_children_inside_one_result_are_deduplicated(tmp_path):
    _, scheduler = bound_scheduler(tmp_path)
    scheduler.submit([item("parent")])
    claimed = scheduler._queue.claim_batch(1)["claimed"][0]
    settled = scheduler._queue.settle(
        claimed["item_id"], action="complete", claim_token=claimed["claim_token"],
        discoveries=[item("child"), item("child")], expected_input_revision="fp0",
    )
    assert len(settled["enqueued"]) == 1
    assert len(settled["duplicates"]) == 1
    assert scheduler.snapshot()["unresolved_count"] == 1


def test_resume_preserves_batch_blocked_parent_at_attempt_bound(tmp_path):
    _, scheduler = bound_scheduler(tmp_path, max_batches=1, max_attempts=1, now_fn=lambda: 1000.0)
    scheduler.submit([item("parent")])
    scheduler.register_handler("entry", lambda work: WorkComplete(discoveries=[item("child")]))
    first = scheduler.run()
    assert first["status"] == "discovery_blocked"
    assert scheduler.snapshot()["unresolved_count"] == 1
    reopened = type(scheduler)(store_path=scheduler._store.db_path, job_id="job_test", run_id="run_test",
        owner_token="tok", run_dir=tmp_path/"job_test/run_test", max_batches=1, max_attempts=1,
        now_fn=lambda: 1002.0)
    reopened.register_handler("entry", lambda work: WorkComplete(discoveries=[item("child")]))
    reopened.run()
    assert reopened.snapshot()["unresolved_count"] == 1, (
        "a persisted discovery bound cannot turn into exhausted/drained on same-input resume"
    )
