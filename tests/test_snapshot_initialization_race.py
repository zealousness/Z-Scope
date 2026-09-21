"""Store startup must complete before independent modeling requests can join."""

from concurrent.futures import ThreadPoolExecutor
import sqlite3
import threading
import time

from zscope.snapshots.store import SnapshotStore


def test_concurrent_first_open_creates_the_schema_once(tmp_path, monkeypatch):
    entered = threading.Event()
    second_started = threading.Event()
    calls = []
    original = SnapshotStore._create_schema

    def create(connection, table_name="snapshots"):
        calls.append(table_name)
        entered.set()
        assert second_started.wait(5)
        time.sleep(0.05)  # Expose the old inspect-then-create race.
        original(connection, table_name)

    monkeypatch.setattr(SnapshotStore, "_create_schema", staticmethod(create))
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(SnapshotStore, tmp_path)
        assert entered.wait(5)

        def open_second():
            second_started.set()
            return SnapshotStore(tmp_path / ".")

        second = pool.submit(open_second)
        stores = [first.result(timeout=10), second.result(timeout=10)]
    assert calls == ["snapshots"]
    assert stores[0].db_path.resolve() == stores[1].db_path.resolve()
    with sqlite3.connect(stores[0].db_path) as connection:
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"


def test_unrelated_database_initializations_overlap(tmp_path, monkeypatch):
    barrier = threading.Barrier(2)
    original = SnapshotStore._create_schema

    def create(connection, table_name="snapshots"):
        barrier.wait(5)
        original(connection, table_name)

    monkeypatch.setattr(SnapshotStore, "_create_schema", staticmethod(create))
    with ThreadPoolExecutor(2) as pool:
        stores = list(pool.map(SnapshotStore, [tmp_path / "one", tmp_path / "two"]))
    assert stores[0].db_path != stores[1].db_path
