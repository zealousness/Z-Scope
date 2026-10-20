"""Real-SQLite tests for the persistent scan job work queue (S08 queue core).

Every test drives a real SQLite database under ``tmp_path`` through the
public queue API with an injectable clock; the database is never mocked.
The "controlled worker" tests run a bounded claim/complete/defer/discover
loop shaped like the session wiring the coordinator will add later.

Scope note (explicit non-wiring): this slice is an independent queue module.
It is not wired into ``scan_session``/``ParallelAnalyzer``, and it does not
start, cancel or kill any scanner or LLM work; JOB04/JOB06 stay undelivered
at the shared-session level until the coordinator wires this queue in.
"""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import pytest

from zscope.orchestration.jobs.models import JobError
from zscope.orchestration.jobs.work_queue import WorkQueue

QUEUE_SCHEMA = "zscope.scan-job-work-queue.v1"


def make_queue(path: Path | str, **overrides: Any) -> WorkQueue:
    kwargs: Dict[str, Any] = {"job_id": "job-1", "input_revision": "rev-1"}
    kwargs.update(overrides)
    return WorkQueue(path, **kwargs)


def item(
    scope: str,
    *,
    kind: str = "entry",
    build: Optional[str] = "b1",
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "kind": kind,
        "scope_key": scope,
        "build": build,
        "payload": payload if payload is not None else {},
    }


def test_enqueue_claim_complete_roundtrip(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    result = queue.enqueue(
        [item("main", payload={"functions": ["main"], "nested": {"a": 1}}), item("helper")],
        batch_no=1,
    )
    assert [entry["scope_key"] for entry in result["enqueued"]] == ["main", "helper"]
    assert result["duplicates"] == []
    assert result["frontier_batch"] == 0

    claimed = queue.claim_batch(2, now=1000.0)["claimed"]
    assert len(claimed) == 2
    first = claimed[0]
    assert first["kind"] == "entry" and first["scope_key"] == "main"
    assert first["build"] == "b1" and first["batch_no"] == 1
    assert first["attempts"] == 1 and first["total_attempts"] == 1
    assert first["payload"] == {"functions": ["main"], "nested": {"a": 1}}
    assert first["claim_token"] and first["claim_expires_at"] > 1000.0

    done = queue.complete(first["item_id"], claim_token=first["claim_token"], now=1001.0)
    assert done["status"] == "completed" and done["scope_key"] == "main"
    done_second = queue.complete(
        claimed[1]["item_id"], claim_token=claimed[1]["claim_token"], now=1001.5
    )
    assert done_second["status"] == "completed"

    snap = queue.snapshot(now=1002.0)
    assert snap["counts"] == {
        "pending": 0,
        "active": 0,
        "deferred": 0,
        "failed": 0,
        "completed": 2,
    }
    assert snap["frontier_batch"] == 1


def test_snapshot_machine_payload_shape(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    queue.enqueue([item("i1"), item("i2"), item("i3")], batch_no=1)
    claim = queue.claim_batch(3, now=1000.0)["claimed"]
    by_scope = {entry["scope_key"]: entry for entry in claim}
    queue.complete(by_scope["i1"]["item_id"], claim_token=by_scope["i1"]["claim_token"], now=1000.5)
    queue.defer(
        by_scope["i2"]["item_id"],
        "model temporarily unavailable",
        claim_token=by_scope["i2"]["claim_token"],
        retry_after_seconds=60.0,
        now=1000.5,
    )

    snap = queue.snapshot(now=1000.6)
    assert snap["schema"] == QUEUE_SCHEMA
    assert snap["job_id"] == "job-1" and snap["input_revision"] == "rev-1"
    assert snap["counts"] == {
        "pending": 0,
        "active": 1,
        "deferred": 1,
        "failed": 0,
        "completed": 1,
    }
    assert snap["unresolved_count"] == 2
    assert snap["deferred_eligible_count"] == 0
    assert snap["lease_expired_active_count"] == 0
    remaining = {entry["scope_key"]: entry for entry in snap["remaining"]}
    assert remaining["i2"]["status"] == "deferred"
    assert remaining["i2"]["reason"] == "model temporarily unavailable"
    assert remaining["i2"]["deferred_eligible"] is False
    assert remaining["i2"]["next_eligible_at"] == 1060.5
    assert remaining["i3"]["status"] == "active"
    assert remaining["i3"]["lease_expired"] is False
    assert snap["completed"][0]["scope_key"] == "i1"
    assert snap["failed"] == [] and snap["recoveries"] == []
    assert snap["remaining_truncated"] is False


def test_enqueue_dedup_by_kind_scope_and_exact_build(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    first = queue.enqueue([item("main", build="b1"), item("main", build="b2")], batch_no=1)
    assert len(first["enqueued"]) == 2

    again = queue.enqueue([item("main", build="b1")], batch_no=1)
    assert again["enqueued"] == []
    assert len(again["duplicates"]) == 1
    duplicate = again["duplicates"][0]
    assert duplicate["existing_item_id"] == first["enqueued"][0]["item_id"]
    assert duplicate["existing_status"] == "pending"

    # unknown build is a slot of its own: separate from any concrete build,
    # deduplicated among itself, never a cross-build wildcard
    unknown = queue.enqueue([item("main", build=None), item("other", build=None)], batch_no=1)
    assert len(unknown["enqueued"]) == 2
    reunknown = queue.enqueue([item("main", build=None)], batch_no=1)
    assert reunknown["enqueued"] == []
    assert reunknown["duplicates"][0]["existing_item_id"] == unknown["enqueued"][0]["item_id"]

    kind_differs = queue.enqueue([item("main", kind="validation", build="b1")], batch_no=1)
    assert len(kind_differs["enqueued"]) == 1

    assert queue.snapshot()["counts"]["pending"] == 5


def test_completed_identity_is_not_retried_without_new_input(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    queue.enqueue([item("main")], batch_no=1)
    claim = queue.claim_batch(1, now=1000.0)["claimed"][0]
    queue.complete(claim["item_id"], claim_token=claim["claim_token"], now=1000.5)

    retry = queue.enqueue([item("main")], batch_no=2)
    assert retry["enqueued"] == []
    assert retry["duplicates"][0]["existing_status"] == "completed"
    snap = queue.snapshot()
    assert snap["counts"]["completed"] == 1 and snap["counts"]["pending"] == 0
    assert queue.claim_batch(1, now=1001.0)["claimed"] == []


def test_enqueue_batch_rules_next_batch_only_and_limit(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db", max_batches=2)

    with pytest.raises(JobError) as exc:
        queue.enqueue([item("x")], batch_no=0)
    assert exc.value.code == "invalid_request"
    with pytest.raises(JobError) as exc:
        queue.enqueue([item("x")], batch_no=2)
    assert exc.value.code == "invalid_request"

    assert len(queue.enqueue([item("a")], batch_no=1)["enqueued"]) == 1
    assert len(queue.enqueue([item("b")], batch_no=1)["enqueued"]) == 1  # seed top-up
    assert queue.claim_batch(2, now=1000.0)["claimed"]  # frontier -> 1
    assert len(queue.enqueue([item("c")], batch_no=2)["enqueued"]) == 1
    with pytest.raises(JobError) as exc:
        queue.enqueue([item("d")], batch_no=3)
    assert exc.value.code == "batch_limit_exceeded"

    assert queue.claim_batch(1, now=1000.5)["claimed"]  # frontier -> 2
    with pytest.raises(JobError) as exc:
        queue.enqueue([item("d")], batch_no=3)
    assert exc.value.code == "batch_limit_exceeded"
    assert queue.snapshot()["max_batch_enqueued"] == 2


def test_claim_window_closed_at_deadline_and_active_work_finishes(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    queue.enqueue([item("a"), item("b")], batch_no=1)

    closed = queue.claim_batch(2, now=100.0, stop_time=100.0)
    assert closed == {"claimed": [], "window_closed": True, "failed_exhausted": []}
    assert queue.snapshot(now=100.0)["counts"]["pending"] == 2

    granted = queue.claim_batch(2, now=99.0, stop_time=100.0)
    assert granted["window_closed"] is False and len(granted["claimed"]) == 2

    # already claimed work finishes bounded after the window closed
    for entry in granted["claimed"]:
        queue.complete(entry["item_id"], claim_token=entry["claim_token"], now=200.0)
    snap = queue.snapshot(now=200.0)
    assert snap["counts"]["completed"] == 2

    post = queue.claim_batch(1, now=200.0, stop_time=100.0)
    assert post["window_closed"] is True and post["claimed"] == []


def test_claim_serves_earlier_batches_before_new_discoveries(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    queue.enqueue([item("a"), item("b")], batch_no=1)

    first = queue.claim_batch(1, now=1000.0)["claimed"]
    assert first[0]["scope_key"] == "a"

    # a root discovered during batch 1 can only enter batch 2 ...
    discovery = queue.enqueue([item("new_root")], batch_no=2)
    assert discovery["batch_no"] == 2
    # ... and it is never claimed while batch 1 still has eligible work
    second = queue.claim_batch(1, now=1000.5)["claimed"]
    assert second[0]["scope_key"] == "b"
    third = queue.claim_batch(1, now=1000.6)["claimed"]
    assert third[0]["scope_key"] == "new_root" and third[0]["batch_no"] == 2


def test_deferred_item_is_not_starved_by_later_batches(tmp_path: Path) -> None:
    queue = make_queue(
        tmp_path / "queue.db",
        max_attempts=5,
        defer_base_seconds=1.0,
        defer_max_seconds=10.0,
    )
    queue.enqueue([item("hard"), item("easy1")], batch_no=1)
    claim = queue.claim_batch(2, now=1000.0)["claimed"]
    by_scope = {entry["scope_key"]: entry for entry in claim}
    queue.complete(
        by_scope["easy1"]["item_id"], claim_token=by_scope["easy1"]["claim_token"], now=1000.5
    )
    queue.defer(
        by_scope["hard"]["item_id"],
        "needs more evidence",
        claim_token=by_scope["hard"]["claim_token"],
        now=1000.5,
    )

    # while "hard" is in backoff, later batches proceed
    queue.enqueue([item("easy2")], batch_no=2)
    got = queue.claim_batch(1, now=1000.6)["claimed"]
    assert got[0]["scope_key"] == "easy2"
    queue.complete(got[0]["item_id"], claim_token=got[0]["claim_token"], now=1000.7)
    queue.enqueue([item("easy3")], batch_no=3)
    got = queue.claim_batch(1, now=1000.8)["claimed"]
    assert got[0]["scope_key"] == "easy3"
    queue.complete(got[0]["item_id"], claim_token=got[0]["claim_token"], now=1000.9)
    queue.enqueue([item("easy4")], batch_no=4)

    # once the backoff elapsed, the aged batch-1 item beats batch 4
    recovered = queue.claim_batch(1, now=1001.6)["claimed"]
    assert recovered[0]["scope_key"] == "hard"
    queue.complete(recovered[0]["item_id"], claim_token=recovered[0]["claim_token"], now=1001.7)

    final = queue.claim_batch(1, now=1001.8)["claimed"]
    assert final[0]["scope_key"] == "easy4"
    queue.complete(final[0]["item_id"], claim_token=final[0]["claim_token"], now=1001.9)

    snap = queue.snapshot(now=1002.0)
    assert snap["counts"] == {
        "pending": 0,
        "active": 0,
        "deferred": 0,
        "failed": 0,
        "completed": 5,
    }
    hard_done = [entry for entry in snap["completed"] if entry["scope_key"] == "hard"][0]
    assert hard_done["attempts"] == 2 and hard_done["deferred_count"] == 1


def test_defer_backoff_grows_exponentially_and_is_capped(tmp_path: Path) -> None:
    queue = make_queue(
        tmp_path / "queue.db",
        max_attempts=10,
        defer_base_seconds=1.0,
        defer_max_seconds=4.0,
    )
    queue.enqueue([item("x")], batch_no=1)
    now = 1000.0
    for expected_backoff in (1.0, 2.0, 4.0, 4.0):
        claim = queue.claim_batch(1, now=now)["claimed"]
        assert claim[0]["attempts"] >= 1
        result = queue.defer(
            claim[0]["item_id"], "again", claim_token=claim[0]["claim_token"], now=now
        )
        assert result["status"] == "deferred"
        assert result["next_eligible_at"] == now + expected_backoff
        now = result["next_eligible_at"]
    snap = queue.snapshot(now=now)
    assert snap["counts"]["deferred"] == 1
    assert snap["deferred_eligible_count"] == 1
    assert snap["remaining"][0]["deferred_eligible"] is True


def test_defer_at_exhausted_attempts_transitions_to_failed(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db", max_attempts=2)
    queue.enqueue([item("x")], batch_no=1)

    first = queue.claim_batch(1, now=1000.0)["claimed"][0]
    deferred = queue.defer(
        first["item_id"],
        "first",
        claim_token=first["claim_token"],
        retry_after_seconds=0.0,
        now=1000.5,
    )
    assert deferred["status"] == "deferred"

    second = queue.claim_batch(1, now=1001.0)["claimed"][0]
    assert second["attempts"] == 2
    failed = queue.defer(
        second["item_id"],
        "second",
        claim_token=second["claim_token"],
        retry_after_seconds=0.0,
        now=1001.5,
    )
    assert failed["status"] == "failed"
    assert failed["reason"] == "max_attempts_exhausted"

    assert queue.claim_batch(1, now=1002.0)["claimed"] == []
    snap = queue.snapshot(now=1002.0)
    assert snap["counts"]["failed"] == 1
    failed_item = snap["failed"][0]
    assert failed_item["fail_reason"] == "max_attempts_exhausted"
    assert failed_item["attempts"] == 2 and failed_item["total_attempts"] == 2


def test_lease_expiry_reclaims_and_old_token_is_rejected(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db", lease_seconds=5.0)
    queue.enqueue([item("x")], batch_no=1)

    first = queue.claim_batch(1, now=100.0)["claimed"][0]
    assert first["claim_expires_at"] == 105.0
    assert queue.snapshot(now=104.0)["remaining"][0]["lease_expired"] is False

    second = queue.claim_batch(1, now=106.0)["claimed"]
    assert len(second) == 1
    assert second[0]["item_id"] == first["item_id"]
    assert second[0]["attempts"] == 2
    assert second[0]["claim_token"] != first["claim_token"]

    with pytest.raises(JobError) as exc:
        queue.complete(first["item_id"], claim_token=first["claim_token"], now=107.0)
    assert exc.value.code == "stale_claim"
    done = queue.complete(second[0]["item_id"], claim_token=second[0]["claim_token"], now=107.0)
    assert done["status"] == "completed"


def test_lease_expired_item_with_exhausted_attempts_fails(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db", max_attempts=1, lease_seconds=5.0)
    queue.enqueue([item("x"), item("y")], batch_no=1)

    first = queue.claim_batch(1, now=100.0)["claimed"][0]
    result = queue.claim_batch(1, now=106.0)
    assert result["failed_exhausted"] == [first["item_id"]]
    assert [entry["scope_key"] for entry in result["claimed"]] == ["y"]

    snap = queue.snapshot(now=106.0)
    assert snap["counts"]["failed"] == 1
    assert snap["failed"][0]["fail_reason"] == "max_attempts_exhausted"


def test_claim_token_required_and_reassignment_rebinds_current_claim(tmp_path: Path) -> None:
    """Producer-review repair: omitted tokens must not bypass a re-assigned lease."""

    queue = make_queue(tmp_path / "queue.db", lease_seconds=1.0)
    queue.enqueue([item("x"), item("y"), item("z")], batch_no=1)
    current = {entry["scope_key"]: entry for entry in queue.claim_batch(3, now=100.0)["claimed"]}

    # omission is not a callable bypass: the current claim token is a
    # required argument, so no token-less compatibility path exists
    with pytest.raises(TypeError):
        queue.complete(current["x"]["item_id"], now=100.5)
    with pytest.raises(TypeError):
        queue.defer(current["y"]["item_id"], "reason", now=100.5)

    # empty or unknown tokens cannot finish the current claim either
    with pytest.raises(JobError) as exc:
        queue.complete(current["x"]["item_id"], claim_token="", now=100.5)
    assert exc.value.code == "invalid_request"
    with pytest.raises(JobError) as exc:
        queue.defer(current["y"]["item_id"], "reason", claim_token="unknown-token", now=100.5)
    assert exc.value.code == "stale_claim"

    # the current claimant can complete and defer
    done = queue.complete(
        current["x"]["item_id"], claim_token=current["x"]["claim_token"], now=100.6
    )
    assert done["status"] == "completed"
    held = queue.defer(
        current["y"]["item_id"],
        "still working",
        claim_token=current["y"]["claim_token"],
        retry_after_seconds=0.0,
        now=100.6,
    )
    assert held["status"] == "deferred"

    # "z" keeps its claim until the lease expires; at 102 the queue re-assigns it
    reassigned = queue.claim_batch(1, now=102.0)["claimed"][0]
    assert reassigned["item_id"] == current["z"]["item_id"]
    assert reassigned["claim_token"] != current["z"]["claim_token"]

    # the stale claimant cannot finish the re-assigned work, with or without its token
    with pytest.raises(TypeError):
        queue.complete(current["z"]["item_id"], now=102.5)
    with pytest.raises(JobError) as exc:
        queue.complete(current["z"]["item_id"], claim_token=current["z"]["claim_token"], now=102.5)
    assert exc.value.code == "stale_claim"
    with pytest.raises(JobError) as exc:
        queue.defer(
            current["z"]["item_id"], "reason", claim_token=current["z"]["claim_token"], now=102.5
        )
    assert exc.value.code == "stale_claim"

    # only the current claim finishes the re-assigned work
    done = queue.complete(reassigned["item_id"], claim_token=reassigned["claim_token"], now=103.0)
    assert done["status"] == "completed"


def test_stale_claim_rejected_across_reopen_and_input_recovery(tmp_path: Path) -> None:
    path = tmp_path / "queue.db"
    queue = make_queue(path, lease_seconds=1.0)
    queue.enqueue([item("x")], batch_no=1)
    first = queue.claim_batch(1, now=100.0)["claimed"][0]
    reassigned = queue.claim_batch(1, now=102.0)["claimed"][0]
    assert reassigned["claim_token"] != first["claim_token"]

    # a reopened instance enforces the same binding against the stored lease
    reopened = make_queue(path)
    with pytest.raises(JobError) as exc:
        reopened.complete(first["item_id"], claim_token=first["claim_token"], now=103.0)
    assert exc.value.code == "stale_claim"
    with pytest.raises(JobError) as exc:
        reopened.defer(first["item_id"], "reason", claim_token=first["claim_token"], now=103.0)
    assert exc.value.code == "stale_claim"
    with pytest.raises(TypeError):
        reopened.complete(first["item_id"], now=103.0)

    # an input change re-pends the item: no claim remains to complete against
    queue.recover("rev-2", now=104.0)
    with pytest.raises(JobError) as exc:
        queue.complete(reassigned["item_id"], claim_token=reassigned["claim_token"], now=105.0)
    assert exc.value.code == "invalid_state"
    with pytest.raises(JobError) as exc:
        queue.defer(
            reassigned["item_id"], "reason", claim_token=reassigned["claim_token"], now=105.0
        )
    assert exc.value.code == "invalid_state"
    snap = queue.snapshot(now=105.0)
    assert snap["counts"] == {
        "pending": 1,
        "active": 0,
        "deferred": 0,
        "failed": 0,
        "completed": 0,
    }


def test_owner_crash_never_fakes_completion(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db", lease_seconds=600.0)
    queue.enqueue([item("x")], batch_no=1)

    claim = queue.claim_batch(1, now=100.0)["claimed"][0]
    # the owner crashes: nobody calls complete, only real queue state may speak
    snap = queue.snapshot(now=5000.0)
    assert snap["counts"] == {
        "pending": 0,
        "active": 1,
        "deferred": 0,
        "failed": 0,
        "completed": 0,
    }
    assert snap["remaining"][0]["lease_expired"] is True
    assert snap["lease_expired_active_count"] == 1

    reclaimed = queue.claim_batch(1, now=5001.0)["claimed"][0]
    assert reclaimed["item_id"] == claim["item_id"]
    assert reclaimed["attempts"] == 2
    queue.complete(reclaimed["item_id"], claim_token=reclaimed["claim_token"], now=5002.0)
    assert queue.snapshot(now=5002.0)["counts"]["completed"] == 1


def test_reopen_preserves_state_leases_and_persisted_bounds(tmp_path: Path) -> None:
    path = tmp_path / "queue.db"
    first = make_queue(path)
    first.enqueue([item("i1"), item("i2"), item("i3")], batch_no=1)
    claim = first.claim_batch(2, now=1000.0)["claimed"]
    first.complete(claim[0]["item_id"], claim_token=claim[0]["claim_token"], now=1000.5)
    before = first.snapshot(now=1000.6)

    reopened = make_queue(path)
    after = reopened.snapshot(now=1000.6)
    assert after["counts"] == before["counts"]
    assert after["counts"] == {
        "pending": 1,
        "active": 1,
        "deferred": 0,
        "failed": 0,
        "completed": 1,
    }

    # the stored lease survives reopen; the original token still finishes it
    done = reopened.complete(claim[1]["item_id"], claim_token=claim[1]["claim_token"], now=1001.0)
    assert done["status"] == "completed"

    with pytest.raises(JobError) as exc:
        make_queue(path, max_attempts=9)
    assert exc.value.code == "queue_bounds_mismatch"
    with pytest.raises(JobError) as exc:
        make_queue(path, job_id="job-2")
    assert exc.value.code == "job_scope_mismatch"
    with pytest.raises(JobError) as exc:
        make_queue(path, input_revision="rev-2")
    assert exc.value.code == "input_revision_mismatch"
    assert exc.value.details["recorded_input_revision"] == "rev-1"


def test_concurrent_claims_from_separate_workers_are_disjoint(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db", lease_seconds=600.0)
    queue.enqueue([item(f"i{n}") for n in range(20)], batch_no=1)

    def drain(worker_index: int) -> List[int]:
        local = make_queue(queue.db_path)
        taken: List[int] = []
        for _ in range(50):  # bounded worker loop, no waiting on the DB
            result = local.claim_batch(1)
            if not result["claimed"]:
                break
            entry = result["claimed"][0]
            taken.append(entry["item_id"])
            local.complete(entry["item_id"], claim_token=entry["claim_token"])
        return taken

    with ThreadPoolExecutor(max_workers=4) as pool:
        per_worker = list(pool.map(drain, range(4)))
    all_ids = [item_id for ids in per_worker for item_id in ids]
    assert len(all_ids) == 20
    assert len(set(all_ids)) == 20  # no item claimed twice

    snap = queue.snapshot()
    assert snap["counts"] == {
        "pending": 0,
        "active": 0,
        "deferred": 0,
        "failed": 0,
        "completed": 20,
    }
    assert all(entry["attempts"] == 1 for entry in snap["completed"])


def test_recover_re_pends_instead_of_granting_old_completion(tmp_path: Path) -> None:
    path = tmp_path / "queue.db"
    queue = make_queue(path)
    queue.enqueue([item("done1"), item("done2"), item("later"), item("stuck")], batch_no=1)
    claim = queue.claim_batch(4, now=1000.0)["claimed"]
    by_scope = {entry["scope_key"]: entry for entry in claim}
    queue.complete(
        by_scope["done1"]["item_id"], claim_token=by_scope["done1"]["claim_token"], now=1000.5
    )
    queue.complete(
        by_scope["done2"]["item_id"], claim_token=by_scope["done2"]["claim_token"], now=1000.6
    )
    queue.defer(
        by_scope["later"]["item_id"],
        "waiting for evidence",
        claim_token=by_scope["later"]["claim_token"],
        retry_after_seconds=500.0,
        now=1000.7,
    )
    # "stuck" stays active: its owner crashed mid-claim

    with pytest.raises(JobError) as exc:
        queue.recover("rev-1")
    assert exc.value.code == "invalid_request"

    summary = queue.recover("rev-2", now=1010.0)
    assert summary["from_input_revision"] == "rev-1"
    assert summary["to_input_revision"] == "rev-2"
    assert summary["re_pended"] == 4
    assert summary["by_previous_status"] == {"completed": 2, "deferred": 1, "active": 1}

    snap = queue.snapshot(now=1010.0)
    assert snap["input_revision"] == "rev-2"
    assert snap["counts"] == {
        "pending": 4,
        "active": 0,
        "deferred": 0,
        "failed": 0,
        "completed": 0,
    }
    remaining = {entry["scope_key"]: entry for entry in snap["remaining"]}
    assert remaining["done1"]["revoked_from_status"] == "completed"
    assert remaining["done1"]["attempts"] == 0
    assert remaining["done1"]["total_attempts"] == 1  # cumulative audit kept
    assert remaining["stuck"]["revoked_from_status"] == "active"
    assert len(snap["recoveries"]) == 1 and snap["recovery_count"] == 1

    # the crashed owner cannot inject its stale completion afterwards
    with pytest.raises(JobError) as exc:
        queue.complete(
            by_scope["stuck"]["item_id"], claim_token=by_scope["stuck"]["claim_token"], now=1011.0
        )
    assert exc.value.code == "invalid_state"

    # the same identity is still deduplicated, not re-enqueued as new work
    duplicate = queue.enqueue([item("done1")], batch_no=2)
    assert duplicate["enqueued"] == []
    assert duplicate["duplicates"][0]["existing_status"] == "pending"

    # a fresh completion requires a real re-verification through a new claim
    reclaimed = queue.claim_batch(1, now=1012.0)["claimed"][0]
    assert reclaimed["scope_key"] == "done1" and reclaimed["attempts"] == 1
    queue.complete(reclaimed["item_id"], claim_token=reclaimed["claim_token"], now=1012.5)
    snap = queue.snapshot(now=1012.5)
    assert snap["counts"]["completed"] == 1 and snap["counts"]["pending"] == 3


def test_open_for_recovery_restart_flow(tmp_path: Path) -> None:
    path = tmp_path / "queue.db"
    queue = make_queue(path)
    queue.enqueue([item("x")], batch_no=1)
    claim = queue.claim_batch(1, now=1000.0)["claimed"][0]
    queue.complete(claim["item_id"], claim_token=claim["claim_token"], now=1000.5)

    # a restarted process cannot open the queue under the new revision ...
    with pytest.raises(JobError) as exc:
        make_queue(path, input_revision="rev-2")
    assert exc.value.code == "input_revision_mismatch"

    # ... it must recover explicitly
    recovered = WorkQueue.open_for_recovery(path, job_id="job-1", new_input_revision="rev-2")
    assert isinstance(recovered, WorkQueue)
    snap = recovered.snapshot()
    assert snap["input_revision"] == "rev-2"
    assert snap["counts"] == {
        "pending": 1,
        "active": 0,
        "deferred": 0,
        "failed": 0,
        "completed": 0,
    }
    assert snap["remaining"][0]["revoked_from_status"] == "completed"

    with pytest.raises(JobError) as exc:
        WorkQueue.open_for_recovery(path, job_id="job-1", new_input_revision="rev-2")
    assert exc.value.code == "invalid_request"
    with pytest.raises(JobError) as exc:
        WorkQueue.open_for_recovery(path, job_id="job-9", new_input_revision="rev-3")
    assert exc.value.code == "job_scope_mismatch"
    with pytest.raises(JobError) as exc:
        WorkQueue.open_for_recovery(
            tmp_path / "missing.db", job_id="job-1", new_input_revision="rev-9"
        )
    assert exc.value.code == "queue_not_found"


def test_validation_rejects_malformed_requests_without_writing(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    cases = [
        (lambda: queue.enqueue([], batch_no=1), "invalid_request"),
        (lambda: queue.enqueue("nope", batch_no=1), "invalid_request"),
        (lambda: queue.enqueue([{"scope_key": "s"}], batch_no=1), "invalid_request"),
        (
            lambda: queue.enqueue(
                [{"kind": "k", "scope_key": "s", "argv": ["run", "anything"]}], batch_no=1
            ),
            "invalid_request",
        ),
        (
            lambda: queue.enqueue([{"kind": "k", "scope_key": "s", "payload": "text"}], batch_no=1),
            "invalid_request",
        ),
        (
            lambda: queue.enqueue(
                [{"kind": "k", "scope_key": "s", "payload": {"v": float("nan")}}], batch_no=1
            ),
            "invalid_request",
        ),
        (
            lambda: queue.enqueue(
                [{"kind": "k", "scope_key": "s", "payload": {"blob": "x" * 9000}}], batch_no=1
            ),
            "invalid_request",
        ),
        (
            lambda: queue.enqueue([{"kind": "k", "scope_key": "s", "build": 5}], batch_no=1),
            "invalid_request",
        ),
        (lambda: queue.enqueue([item("x")], batch_no=2), "invalid_request"),
        (lambda: queue.claim_batch(0), "invalid_request"),
        (lambda: queue.claim_batch(True), "invalid_request"),
        (lambda: queue.claim_batch(1001), "invalid_request"),
        (lambda: queue.complete(999, claim_token="tok"), "item_not_found"),
        (lambda: queue.defer(999, "reason", claim_token="tok"), "item_not_found"),
    ]
    for call, code in cases:
        with pytest.raises(JobError) as exc:
            call()
        assert exc.value.code == code
    assert queue.snapshot()["counts"]["pending"] == 0  # nothing was written

    with pytest.raises(JobError):
        WorkQueue(tmp_path / "q2.db", job_id="", input_revision="rev-1")
    with pytest.raises(JobError):
        make_queue(tmp_path / "q3.db", defer_base_seconds=10.0, defer_max_seconds=1.0)

    assert len(queue.enqueue([item("x")], batch_no=1)["enqueued"]) == 1
    with pytest.raises(JobError) as exc:
        queue.complete(1, claim_token="tok")  # pending, not active
    assert exc.value.code == "invalid_state"
    claim = queue.claim_batch(1, now=1000.0)["claimed"][0]
    queue.complete(claim["item_id"], claim_token=claim["claim_token"], now=1000.5)
    with pytest.raises(JobError) as exc:
        queue.defer(claim["item_id"], "done already", claim_token=claim["claim_token"])
    assert exc.value.code == "invalid_state"
    with pytest.raises(JobError) as exc:
        queue.defer(claim["item_id"], "", claim_token=claim["claim_token"])
    assert exc.value.code == "invalid_request"


def test_snapshot_truncates_large_remaining_lists(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    queue.enqueue([item(f"i{n}") for n in range(2001)], batch_no=1)
    snap = queue.snapshot()
    assert snap["counts"]["pending"] == 2001
    assert len(snap["remaining"]) == 2000
    assert snap["remaining_truncated"] is True


def test_controlled_worker_drains_bounded_with_dynamic_roots(tmp_path: Path) -> None:
    """Bounded controlled worker: real claims, real defers, real discoveries.

    The worker loop mirrors how the coordinator will drive the queue inside a
    scan session: claim a batch, complete or defer each item, and enqueue any
    newly discovered root into the *next* batch only.  The loop is bounded by
    construction, so a runaway discovery chain cannot spin forever.
    """

    queue = make_queue(
        tmp_path / "queue.db",
        max_attempts=4,
        max_batches=6,
        lease_seconds=60.0,
        defer_base_seconds=1.0,
        defer_max_seconds=4.0,
    )
    assert len(queue.enqueue([item("main"), item("helper")], batch_no=1)["enqueued"]) == 2

    clock = 1000.0
    discovered_batches: List[int] = []
    discoveries = 0
    completed_scopes = set()
    rounds = 0
    while rounds < 60:
        rounds += 1
        result = queue.claim_batch(4, now=clock)
        if result["window_closed"] or not result["claimed"]:
            break
        for claimed_item in result["claimed"]:
            token = claimed_item["claim_token"]
            scope = claimed_item["scope_key"]
            if scope in {"main", "root1"} and discoveries < 2:
                # dynamic new root discovered while processing: next batch only
                # (root1 itself discovers root2 when it gets its turn)
                discoveries += 1
                frontier = queue.snapshot(now=clock)["frontier_batch"]
                discovered_batches.append(
                    queue.enqueue([item(f"root{discoveries}")], batch_no=frontier + 1)["batch_no"]
                )
                queue.complete(claimed_item["item_id"], claim_token=token, now=clock)
                completed_scopes.add(scope)
            elif scope == "helper" and claimed_item["attempts"] < 2:
                queue.defer(
                    claimed_item["item_id"],
                    "model temporarily unavailable",
                    claim_token=token,
                    now=clock,
                )
            else:
                queue.complete(claimed_item["item_id"], claim_token=token, now=clock)
                completed_scopes.add(scope)
        clock += 5.0  # advance past the deferral backoff between rounds

    assert rounds < 60  # the loop terminated by draining, not by the bound
    assert discovered_batches == [2, 3]
    snap = queue.snapshot(now=clock)
    assert snap["counts"] == {
        "pending": 0,
        "active": 0,
        "deferred": 0,
        "failed": 0,
        "completed": 4,
    }
    assert completed_scopes == {"main", "helper", "root1", "root2"}
    helper_done = [entry for entry in snap["completed"] if entry["scope_key"] == "helper"][0]
    assert helper_done["attempts"] == 2 and helper_done["deferred_count"] == 1
    assert snap["frontier_batch"] == 3


# ---------------------------------------------------------------------------
# settle: one atomic transaction for the parent verdict and its children


def _claim_one(queue: WorkQueue, *, now: float = 1000.0) -> Dict[str, Any]:
    claimed = queue.claim_batch(1, now=now)["claimed"]
    assert len(claimed) == 1
    return claimed[0]


def test_settle_commits_verdict_and_children_in_one_transaction(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    queue.enqueue([item("parent")], batch_no=1)
    claimed = _claim_one(queue)

    result = queue.settle(
        claimed["item_id"],
        action="complete",
        claim_token=claimed["claim_token"],
        discoveries=[item("child-a"), item("child-b")],
        now=1001.0,
    )
    assert result["status"] == "completed"
    assert result["discovery_blocked"] is None
    assert result["duplicates"] == []
    assert [entry["scope_key"] for entry in result["enqueued"]] == ["child-a", "child-b"]

    snap = queue.snapshot(now=1002.0)
    assert snap["counts"] == {
        "pending": 2,
        "active": 0,
        "deferred": 0,
        "failed": 0,
        "completed": 1,
    }
    children = {entry["scope_key"]: entry["batch_no"] for entry in snap["remaining"]}
    assert children == {"child-a": 2, "child-b": 2}
    assert snap["frontier_batch"] == 1


def test_settle_defer_action_persists_children_and_reason(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    queue.enqueue([item("parent")], batch_no=1)
    claimed = _claim_one(queue)

    result = queue.settle(
        claimed["item_id"],
        action="defer",
        reason="model temporarily unavailable",
        claim_token=claimed["claim_token"],
        retry_after_seconds=30.0,
        discoveries=[item("child")],
        now=1001.0,
    )
    assert result["status"] == "deferred"
    assert result["reason"] == "model temporarily unavailable"
    assert result["next_eligible_at"] == 1031.0
    assert [entry["scope_key"] for entry in result["enqueued"]] == ["child"]

    snap = queue.snapshot(now=1002.0)
    assert snap["counts"]["deferred"] == 1 and snap["counts"]["pending"] == 1


def test_settle_reports_duplicates_without_reenqueue(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    queue.enqueue([item("parent"), item("known")], batch_no=1)
    claimed = _claim_one(queue)  # claims "parent" first

    result = queue.settle(
        claimed["item_id"],
        action="complete",
        claim_token=claimed["claim_token"],
        discoveries=[item("known"), item("fresh")],
        now=1001.0,
    )
    assert result["status"] == "completed"
    assert [entry["scope_key"] for entry in result["enqueued"]] == ["fresh"]
    assert [entry["scope_key"] for entry in result["duplicates"]] == ["known"]
    assert result["duplicates"][0]["existing_status"] == "pending"

    snap = queue.snapshot(now=1002.0)
    assert snap["counts"] == {
        "pending": 2,
        "active": 0,
        "deferred": 0,
        "failed": 0,
        "completed": 1,
    }


def test_settle_rejects_stale_claim_without_verdict_or_children(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db", lease_seconds=1.0)
    queue.enqueue([item("parent")], batch_no=1)
    old = _claim_one(queue, now=1000.0)
    fresh = _claim_one(queue, now=1002.0)  # lease expired; re-claimed
    assert old["claim_token"] != fresh["claim_token"]

    with pytest.raises(JobError) as excinfo:
        queue.settle(
            old["item_id"],
            action="complete",
            claim_token=old["claim_token"],
            discoveries=[item("stale-child")],
            now=1003.0,
        )
    assert excinfo.value.code == "stale_claim"

    snap = queue.snapshot(now=1004.0)
    assert snap["counts"] == {
        "pending": 0,
        "active": 1,
        "deferred": 0,
        "failed": 0,
        "completed": 0,
    }
    assert [entry["scope_key"] for entry in snap["remaining"]] == ["parent"]


def test_settle_rejects_input_revision_mismatch_without_writing(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    queue.enqueue([item("parent")], batch_no=1)
    claimed = _claim_one(queue)

    with pytest.raises(JobError) as excinfo:
        queue.settle(
            claimed["item_id"],
            action="complete",
            claim_token=claimed["claim_token"],
            discoveries=[item("child")],
            expected_input_revision="other-rev",
            now=1001.0,
        )
    assert excinfo.value.code == "input_revision_mismatch"
    assert excinfo.value.details["recorded_input_revision"] == "rev-1"

    snap = queue.snapshot(now=1002.0)
    assert snap["counts"] == {
        "pending": 0,
        "active": 1,
        "deferred": 0,
        "failed": 0,
        "completed": 0,
    }


def test_settle_validates_request_shape(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    queue.enqueue([item("parent")], batch_no=1)
    claimed = _claim_one(queue)
    token = claimed["claim_token"]

    with pytest.raises(JobError) as excinfo:
        queue.settle(claimed["item_id"], action="finish", claim_token=token)
    assert excinfo.value.code == "invalid_request"
    with pytest.raises(JobError) as excinfo:
        queue.settle(
            claimed["item_id"], action="complete", claim_token=token, reason="not-for-complete"
        )
    assert excinfo.value.code == "invalid_request"
    with pytest.raises(JobError) as excinfo:
        queue.settle(claimed["item_id"], action="defer", claim_token=token, reason="")
    assert excinfo.value.code == "invalid_request"
    snap = queue.snapshot(now=1002.0)
    assert snap["counts"]["active"] == 1  # nothing was written by the rejected shapes


def test_settle_batch_limit_keeps_parent_explicit_pending(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db", max_batches=1)
    queue.enqueue([item("parent")], batch_no=1)
    claimed = _claim_one(queue)  # frontier is now 1 == max_batches

    result = queue.settle(
        claimed["item_id"],
        action="complete",
        claim_token=claimed["claim_token"],
        discoveries=[item("child")],
        now=1001.0,
    )
    # The verdict was replaced by an explicit deferral: the obligation stays
    # durable unresolved work, never a completed parent with a lost child.
    assert result["status"] == "deferred"
    assert result["discovery_blocked"] == "batch_limit"
    assert result["reason"] == "discovery_batch_limit"
    assert result["enqueued"] == []

    snap = queue.snapshot(now=1002.0)
    assert snap["counts"] == {
        "pending": 0,
        "active": 0,
        "deferred": 1,
        "failed": 0,
        "completed": 0,
    }
    blocked = snap["remaining"][0]
    assert blocked["scope_key"] == "parent"
    assert blocked["reason"] == "discovery_batch_limit"


def test_settle_queue_capacity_limit_keeps_parent_explicit_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("zscope.orchestration.jobs.work_queue._MAX_QUEUE_ITEMS", 3)
    queue = make_queue(tmp_path / "queue.db")
    queue.enqueue([item("a"), item("b"), item("c")], batch_no=1)
    claimed = _claim_one(queue)

    result = queue.settle(
        claimed["item_id"],
        action="complete",
        claim_token=claimed["claim_token"],
        discoveries=[item("child")],
        now=1001.0,
    )
    assert result["status"] == "deferred"
    assert result["discovery_blocked"] == "queue_limit"
    assert result["reason"] == "discovery_queue_limit"

    snap = queue.snapshot(now=1002.0)
    assert snap["counts"]["deferred"] == 1 and snap["counts"]["completed"] == 0
    assert snap["counts"]["pending"] == 2  # b and c stay untouched


def test_settle_invalid_discovery_rolls_back_the_parent_verdict(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    queue.enqueue([item("parent")], batch_no=1)
    claimed = _claim_one(queue)
    malformed = {"kind": "entry", "scope_key": "bad", "build": "b1", "payload": {}, "extra": 1}

    with pytest.raises(JobError) as excinfo:
        queue.settle(
            claimed["item_id"],
            action="complete",
            claim_token=claimed["claim_token"],
            discoveries=[malformed],
            now=1001.0,
        )
    assert excinfo.value.code == "discovery_invalid"

    snap = queue.snapshot(now=1002.0)
    assert snap["counts"] == {
        "pending": 0,
        "active": 1,
        "deferred": 0,
        "failed": 0,
        "completed": 0,
    }

    # The parent is still settleable once the handler produces valid children.
    result = queue.settle(
        claimed["item_id"],
        action="complete",
        claim_token=claimed["claim_token"],
        discoveries=[item("child")],
        now=1003.0,
    )
    assert result["status"] == "completed"
    assert [entry["scope_key"] for entry in result["enqueued"]] == ["child"]


def test_settle_commit_failure_rolls_back_verdict_and_children(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    queue.enqueue([item("parent")], batch_no=1)
    claimed = _claim_one(queue)
    original_write = queue._write

    @contextmanager
    def write_failing_before_commit() -> Iterator[sqlite3.Connection]:
        with original_write() as connection:
            yield connection
            # A real transaction rollback: the commit itself fails, so the
            # parent verdict and every child insertion are undone together.
            raise sqlite3.OperationalError("injected pre-commit I/O failure")

    queue._write = write_failing_before_commit  # type: ignore[assignment]
    try:
        with pytest.raises(JobError) as excinfo:
            queue.settle(
                claimed["item_id"],
                action="complete",
                claim_token=claimed["claim_token"],
                discoveries=[item("child")],
                now=1001.0,
            )
        assert excinfo.value.code == "queue_unavailable"
    finally:
        del queue._write  # type: ignore[attr-defined]

    snap = queue.snapshot(now=1002.0)
    assert snap["counts"] == {
        "pending": 0,
        "active": 1,
        "deferred": 0,
        "failed": 0,
        "completed": 0,
    }
    # The rolled-back parent is re-settleable once the failure clears.
    result = queue.settle(
        claimed["item_id"],
        action="complete",
        claim_token=claimed["claim_token"],
        discoveries=[item("child")],
        now=1003.0,
    )
    assert result["status"] == "completed"


# ---------------------------------------------------------------------------
# settle edges: in-result duplicates and parked discovery bounds


def test_settle_deduplicates_identical_children_within_one_result(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db")
    queue.enqueue([item("parent")], batch_no=1)
    claimed = _claim_one(queue)

    result = queue.settle(
        claimed["item_id"],
        action="complete",
        claim_token=claimed["claim_token"],
        discoveries=[item("child"), item("child"), item("child")],
        now=1001.0,
    )
    # The second and third copy are duplicates of the first copy enqueued by
    # this same transaction; the UNIQUE constraint must never reject the
    # whole legitimate result.
    assert result["status"] == "completed"
    assert len(result["enqueued"]) == 1
    assert len(result["duplicates"]) == 2
    assert all(entry["existing_item_id"] is None for entry in result["duplicates"])

    snap = queue.snapshot(now=1002.0)
    assert snap["counts"] == {
        "pending": 1,
        "active": 0,
        "deferred": 0,
        "failed": 0,
        "completed": 1,
    }


def test_parked_discovery_deferral_is_not_claimable_or_attempt_failed(tmp_path: Path) -> None:
    queue = make_queue(tmp_path / "queue.db", max_batches=1, max_attempts=1)
    queue.enqueue([item("parent")], batch_no=1)
    claimed = _claim_one(queue, now=1000.0)

    result = queue.settle(
        claimed["item_id"],
        action="complete",
        claim_token=claimed["claim_token"],
        discoveries=[item("child")],
        now=1001.0,
    )
    assert result["discovery_blocked"] == "batch_limit"
    assert result["status"] == "deferred"

    # Attempts sit at the bound and the backoff has long elapsed, yet the
    # parked obligation is neither claimable nor failed by attempt
    # accounting: it stays real remaining work.
    later = queue.claim_batch(5, now=1100.0)
    assert later["claimed"] == []
    assert later["failed_exhausted"] == []
    snap = queue.snapshot(now=1101.0)
    assert snap["counts"]["deferred"] == 1
    assert snap["counts"]["failed"] == 0
    assert snap["discovery_blocked_count"] == 1
    assert snap["deferred_eligible_count"] == 0
    parked = snap["remaining"][0]
    assert parked["scope_key"] == "parent"
    assert parked["reason"] == "discovery_batch_limit"

    # A real input change re-pends the parked obligation for re-verification.
    recovered = queue.recover("rev-2", now=1200.0)
    assert recovered["re_pended"] == 1
    snap = queue.snapshot(now=1201.0)
    assert snap["counts"]["pending"] == 1
    assert snap["discovery_blocked_count"] == 0
    revived = queue.claim_batch(1, now=1202.0)["claimed"]
    assert [entry["scope_key"] for entry in revived] == ["parent"]
