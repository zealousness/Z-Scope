import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from zscope.retrieval import clang_type_state as state
from zscope.retrieval.clang_type_scheduler import FunctionTypeScheduler
from zscope.retrieval.clang_type_scheduler import acquire_scheduler, release_scheduler
from zscope.retrieval.clang_type_worker import TypeCollectionCancelled
from zscope.retrieval.knowledge_db import KnowledgeDB


@pytest.fixture
def indexed(tmp_path):
    db = KnowledgeDB(str(tmp_path / "facts.db"))
    for name, line in [("first", 1), ("second", 3), ("third", 5)]:
        db._conn.execute(
            "INSERT INTO functions(name,file_path,start_line,end_line,signature) VALUES (?,?,?,?,?)",
            (name, "a.c", line, line, "int " + name + "(void)"),
        )
    db.commit()
    state.initialize_states(db, "generation", {"a.c": "command"})
    db.commit()
    backend = SimpleNamespace(_db=db)
    yield backend
    db.close()


class Collector:
    cache = None
    reusable = True
    epoch = "epoch"

    def __init__(self, backend, run):
        self.run = run
        self.cancelled = threading.Event()
        self.closed = False

    def prepare(self):
        pass

    def check_inputs(self, record, *, verify: bool = False):
        pass

    def pump(self):
        pass

    def collect(self, record, checkpoint):
        return self.run(self, record, checkpoint)

    def interrupt(self):
        self.cancelled.set()

    def close(self):
        self.closed = True


def record(backend, name):
    return state.function_record(backend._db, name, "a.c", 0)


def scheduler(backend, run):
    return FunctionTypeScheduler(backend, collector_factory=lambda b: Collector(b, run))


def until(predicate, timeout=3):
    end = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < end, "condition was not reached"
        time.sleep(0.005)


def test_scope_empty_results_and_cas(indexed):
    db = indexed._db
    first, second = record(indexed, "first"), record(indexed, "second")
    assert state.read_current(db, "first", "a.c", 1, "generation") is None
    assert state.claim(db, first["id"], "generation", "one")
    assert not state.claim(db, first["id"], "generation", "two")
    row = (first["id"], None, "", "Missing", "a.c", 1, "parameter", "unmapped")
    with pytest.raises(ValueError):
        state.finish(db, first["id"], "generation", "one", [(second["id"], *row[1:])])
    assert state.finish(db, first["id"], "generation", "one", [row])
    assert state.claim(db, second["id"], "generation", "two")
    assert state.finish(db, second["id"], "generation", "two", [])
    assert state.read_current(db, "second", "a.c", 3, "generation") == {"referenced_types": []}
    assert db._conn.execute("SELECT COUNT(*) FROM function_type_refs").fetchone()[0] == 1
    assert not state.finish(db, first["id"], "generation", "one", [])
    assert db.get_derived_index_state("function_type_refs")["status"] == "dirty"


def test_background_promoted_and_concurrent_waiters_share_one_task(indexed):
    started, allow = threading.Event(), threading.Event()
    calls = []

    def run(engine, row, checkpoint):
        calls.append(row["name"])
        if row["name"] == "first":
            started.set()
            assert allow.wait(3)
        checkpoint()
        return []

    service = scheduler(indexed, run)
    try:
        assert started.wait(3)
        with ThreadPoolExecutor(4) as pool:
            futures = [pool.submit(service.ensure, record(indexed, "first")) for _ in range(4)]
            until(lambda: service.snapshot()["joined"] >= 4)
            allow.set()
            for future in futures:
                future.result(3)
        until(lambda: state.counts(indexed._db)["current"] == 3)
        service.ensure(record(indexed, "first"))
        assert calls.count("first") == 1
        assert indexed._db.get_derived_index_state("function_type_refs")["status"] == "current"
    finally:
        allow.set()
        service.close()


def test_background_drain_forms_stable_native_fact_barrier(indexed):
    calls = []

    def run(engine, row, checkpoint):
        calls.append(row["name"])
        checkpoint()
        return []

    service = scheduler(indexed, run)
    try:
        report = service.drain_background(timeout_seconds=3)
        assert report["functions"] == {
            "pending": 0,
            "in_progress": 0,
            "current": 3,
            "failed": 0,
        }
        assert sorted(calls) == ["first", "second", "third"]
    finally:
        service.close()


def test_other_function_preempts_at_rpc_boundary_and_resumes(indexed):
    started, rpc_done = threading.Event(), threading.Event()
    order = []

    def run(engine, row, checkpoint):
        if row["name"] == "first":
            order.append("first-rpc")
            started.set()
            assert rpc_done.wait(3)
            checkpoint()
            order.append("first-resume")
        else:
            order.append(row["name"])
        return []

    service = scheduler(indexed, run)
    try:
        assert started.wait(3)
        with ThreadPoolExecutor(1) as pool:
            second = pool.submit(service.ensure, record(indexed, "second"))
            until(lambda: service.snapshot()["foreground"] == 1)
            assert not second.done()
            rpc_done.set()
            second.result(3)
        until(lambda: "first-resume" in order)
        assert order.index("second") < order.index("first-resume")
        assert order.count("first-rpc") == 1
    finally:
        rpc_done.set()
        service.close()


def test_timeout_detaches_only_its_waiter(indexed):
    started, allow = threading.Event(), threading.Event()

    def run(engine, row, checkpoint):
        if row["name"] == "first":
            started.set()
            assert allow.wait(3)
        checkpoint()
        return []

    service = scheduler(indexed, run)
    try:
        assert started.wait(3)
        with ThreadPoolExecutor(1) as pool:
            other = pool.submit(service.ensure, record(indexed, "first"))
            with pytest.raises(state.TypeContextUnavailable, match="300 seconds"):
                service.ensure(record(indexed, "first"), deadline=time.monotonic() + 0.05)
            assert not other.done()
            assert not service.engine.cancelled.is_set()
            allow.set()
            other.result(3)
    finally:
        allow.set()
        service.close()


def test_pause_releases_process_and_does_not_cancel_waiter(indexed):
    started = threading.Event()
    first_attempt = True

    def run(engine, row, checkpoint):
        nonlocal first_attempt
        if row["name"] == "first" and first_attempt:
            first_attempt = False
            started.set()
            engine.cancelled.wait(3)
            checkpoint()
        return []

    service = scheduler(indexed, run)
    try:
        assert started.wait(3)
        with ThreadPoolExecutor(1) as pool:
            waiter = pool.submit(service.ensure, record(indexed, "first"))
            until(lambda: service.snapshot()["foreground"] == 1)
            with service.paused():
                assert service.engine is None
                assert not waiter.done()
                assert record(indexed, "first")["type_status"] == "pending"
            waiter.result(3)
    finally:
        service.close()


def test_close_checkpoints_instead_of_draining_background(indexed):
    started = threading.Event()

    def run(engine, row, checkpoint):
        started.set()
        engine.cancelled.wait(3)
        checkpoint()
        return []

    service = scheduler(indexed, run)
    assert started.wait(3)
    service.close()
    assert state.counts(indexed._db)["pending"] == 3
    assert state.counts(indexed._db)["current"] == 0


def test_old_generation_cannot_publish(indexed):
    db = indexed._db
    first = record(indexed, "first")
    assert state.claim(db, first["id"], "generation", "one")
    db.mark_derived_indexes_dirty()
    assert db.get_metadata(state.GENERATION_KEY) != "generation"
    assert not state.finish(db, first["id"], "generation", "one", [])


def test_failed_job_does_not_become_empty_success(indexed):
    def run(engine, row, checkpoint):
        raise state.TypeContextUnavailable("rpc_failed")

    service = scheduler(indexed, run)
    try:
        with pytest.raises(state.TypeContextUnavailable, match="rpc_failed"):
            service.ensure(record(indexed, "first"))
        assert record(indexed, "first")["type_status"] == "failed"
        assert state.read_current(indexed._db, "first", "a.c", 1, "generation") is None
    finally:
        service.close()


def test_registry_owns_connection_and_survives_first_backend_release(indexed):
    started, allow = threading.Event(), threading.Event()

    def run(engine, row, checkpoint):
        started.set()
        assert allow.wait(3)
        checkpoint()
        return []

    second_db = KnowledgeDB(str(indexed._db._db_path))
    second_backend = SimpleNamespace(_db=second_db)
    one = acquire_scheduler(indexed, collector_factory=lambda b: Collector(b, run))
    two = acquire_scheduler(
        second_backend, collector_factory=lambda b: pytest.fail("duplicate scheduler")
    )
    try:
        assert one is two
        assert one.db is not indexed._db and one.db is not second_db
        assert started.wait(3)
        release_scheduler(one)
        with ThreadPoolExecutor(1) as pool:
            result = pool.submit(two.ensure, record(second_backend, "first"))
            allow.set()
            result.result(3)
    finally:
        allow.set()
        release_scheduler(two)
        second_db.close()


def test_failed_publication_rolls_back_old_rows(indexed):
    db = indexed._db
    first = record(indexed, "first")
    old_row = (first["id"], None, "", "Old", "a.c", 1, "parameter", "unmapped")
    assert state.claim(db, first["id"], "generation", "old")
    assert state.finish(db, first["id"], "generation", "old", [old_row])
    db._conn.execute(
        "UPDATE function_type_ref_state SET status='pending' WHERE function_id=?", (first["id"],)
    )
    db._conn.execute(
        "CREATE TRIGGER reject_type_publish BEFORE INSERT ON function_type_refs "
        "BEGIN SELECT RAISE(ABORT, 'injected publication failure'); END"
    )
    db.commit()
    assert state.claim(db, first["id"], "generation", "new")
    with pytest.raises(Exception, match="injected publication failure"):
        state.finish(db, first["id"], "generation", "new", [old_row])
    assert db._conn.execute("SELECT referenced_name FROM function_type_refs").fetchone()[0] == "Old"
    assert record(indexed, "first")["type_status"] == "in_progress"


def test_purging_tu_removes_function_tasks_and_rejects_late_result(indexed):
    db = indexed._db
    first = record(indexed, "first")
    db._conn.execute("INSERT INTO translation_units(id,file_path) VALUES (1,'a.c')")
    db._conn.execute("UPDATE functions SET tu_id=1 WHERE id=?", (first["id"],))
    db.commit()
    assert state.claim(db, first["id"], "generation", "old")
    db.purge_tu_data(1)
    assert (
        db._conn.execute(
            "SELECT 1 FROM function_type_ref_state WHERE function_id=?", (first["id"],)
        ).fetchone()
        is None
    )
    assert not state.finish(db, first["id"], "generation", "old", [])
    assert record(indexed, "second") is not None


def test_volatile_rpc_errors_are_retried_but_successes_are_retained(tmp_path):
    from zscope.retrieval.clang_derived_cache import DerivedCache

    cache = DerivedCache(tmp_path / "cache.db", epoch="same", max_bytes=100000)
    try:
        cache.put("symbolInfo", "ok", {"items": ["USR"], "_volatile": False})
        cache.put("symbolInfo", "retry", {"items": [], "_volatile": True})
        cache.discard_volatile()
        assert cache.get("symbolInfo", "retry") is None
        assert cache.get("symbolInfo", "ok")["items"] == ["USR"]
    finally:
        cache.close()


def test_all_waiters_timeout_then_background_finishes_without_restart(indexed):
    started, allow = threading.Event(), threading.Event()
    calls = []

    def run(engine, row, checkpoint):
        calls.append(row["name"])
        if row["name"] == "first":
            started.set()
            assert allow.wait(3)
        checkpoint()
        return []

    service = scheduler(indexed, run)
    try:
        assert started.wait(3)
        with pytest.raises(state.TypeContextUnavailable):
            service.ensure(record(indexed, "first"), deadline=time.monotonic() + 0.05)
        until(lambda: service.snapshot()["foreground"] == 0)
        assert not service.engine.cancelled.is_set()
        allow.set()
        until(lambda: state.counts(indexed._db)["current"] == 3)
        assert calls.count("first") == 1
    finally:
        allow.set()
        service.close()


def test_foreground_tasks_round_robin_between_checkpoints(indexed):
    started, allow = threading.Event(), threading.Event()
    order = []

    def run(engine, row, checkpoint):
        if row["name"] == "first":
            started.set()
            assert allow.wait(3)
        for step in range(3):
            checkpoint()
            order.append(row["name"])
        return []

    service = scheduler(indexed, run)
    try:
        assert started.wait(3)
        with ThreadPoolExecutor(2) as pool:
            futures = [
                pool.submit(service.ensure, record(indexed, name)) for name in ("second", "third")
            ]
            until(lambda: service.snapshot()["foreground"] == 2)
            allow.set()
            for future in futures:
                future.result(3)
        foreground = [name for name in order if name != "first"]
        assert len(foreground) == 6
        assert all(left != right for left, right in zip(foreground, foreground[1:]))
    finally:
        allow.set()
        service.close()


def test_shutdown_interrupts_preparation_and_wakes_queued_consumer(indexed):
    started = threading.Event()

    class PreparingCollector(Collector):
        def prepare(self):
            started.set()
            assert self.cancelled.wait(3)
            raise TypeCollectionCancelled()

    service = FunctionTypeScheduler(
        indexed, collector_factory=lambda b: PreparingCollector(b, lambda *_: [])
    )
    try:
        assert started.wait(3)
        with ThreadPoolExecutor(1) as pool:
            result = pool.submit(service.ensure, record(indexed, "first"))
            until(lambda: not service._events.empty())
            service.close()
            with pytest.raises(state.TypeContextUnavailable, match="backend_closed"):
                result.result(3)
        assert state.counts(indexed._db)["current"] == 0
    finally:
        service.close()


def test_global_tool_failure_pauses_queue_until_new_demand(indexed):
    attempts = []

    class UnavailableCollector(Collector):
        def prepare(self):
            attempts.append(1)
            raise state.TypeContextUnavailable("clangd_unavailable")

    service = FunctionTypeScheduler(
        indexed, collector_factory=lambda b: UnavailableCollector(b, lambda *_: [])
    )
    try:
        until(lambda: service.snapshot()["error"] == "clangd_unavailable")
        assert len(attempts) == 1
        assert state.counts(indexed._db)["pending"] == 3
        with pytest.raises(state.TypeContextUnavailable, match="clangd_unavailable"):
            service.ensure(record(indexed, "first"))
        assert len(attempts) == 2
        assert state.counts(indexed._db)["pending"] == 3
    finally:
        service.close()


def test_wait_budget_includes_admission_lock_contention(indexed):
    started, allow = threading.Event(), threading.Event()

    def run(engine, row, checkpoint):
        started.set()
        assert allow.wait(3)
        checkpoint()
        return []

    service = scheduler(indexed, run)
    try:
        assert started.wait(3)
        first = record(indexed, "first")
        with ThreadPoolExecutor(1) as pool, service._condition:
            result = pool.submit(service.ensure, first, deadline=time.monotonic() + 0.05)
            with pytest.raises(state.TypeContextUnavailable, match="300 seconds"):
                result.result(1)
    finally:
        allow.set()
        service.close()
