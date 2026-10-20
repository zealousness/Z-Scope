"""Real SQLite transaction reuse and fail-closed private Store scope (R35)."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import threading
import time

import pytest

from test_job_bound_completion import binding, counts, payload
from test_job_bound_instance_results import (
    queue_status,
    settle,
    settled_context,
    trusted,
)
from zscope.orchestration.jobs.models import JobError
from zscope.orchestration.jobs.store import JobStore


def arguments(job, **updates):
    value = {
        "job_id": job["job_id"],
        "run_id": job["run_id"],
        "owner_token": job["owner_token"],
        "expected_input_revision": job["input_revision"],
    }
    value.update(updates)
    return value


def accessor(store):
    method = getattr(store, "_active_transaction_connection", None)
    assert callable(method), "FEATURE_MISSING: private actual transaction accessor"
    return method


@contextmanager
def owner(store, job, kind):
    if kind == "write":
        with store._write() as connection:
            yield connection
    else:
        with store.bound_attempt(**arguments(job)):
            yield accessor(store)()


@pytest.fixture
def observe_sql(monkeypatch, record_property):
    """Subclass the supplied real factory and fully forward every operation."""
    original = sqlite3.connect
    events = []
    observer = {"before_finish": None, "post_forward_fault": None, "before_begin": None}

    def connect(*args, **kwargs):
        base = kwargs.get("factory", sqlite3.Connection)
        database = str(args[0])

        class ObservedConnection(base):
            def execute(self, sql, parameters=()):
                event = [database, id(self), "execute", sql, "entered"]
                events.append(event)
                if sql == "BEGIN IMMEDIATE" and observer["before_begin"] is not None:
                    observer["before_begin"](self)
                try:
                    result = super().execute(sql, parameters)
                except BaseException as error:
                    event[-1] = type(error).__name__
                    raise
                event[-1] = "returned"
                return result

            def _finish(self, name, original_operation):
                events.append([database, id(self), name, "", "entered"])
                callback = observer["before_finish"]
                if callback is not None:
                    callback(self, name)
                result = original_operation()
                events[-1][-1] = "returned"
                if observer["post_forward_fault"] == name:
                    observer["post_forward_fault"] = None
                    raise sqlite3.OperationalError("controlled post-forward " + name)
                return result

            def commit(self):
                return self._finish("commit", super().commit)

            def rollback(self):
                return self._finish("rollback", super().rollback)

            def close(self):
                return self._finish("close", super().close)

        kwargs["factory"] = ObservedConnection
        connection = original(*args, **kwargs)
        events.append([database, id(connection), "connect", "", "returned"])
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)
    started = time.monotonic()
    yield events, observer
    record_property("actual_sqlite_operations", json.dumps(events))
    record_property("elapsed_seconds", time.monotonic() - started)


def store_events(events, store):
    return [event for event in events if event[0] == str(store.db_path)]


def begins(events, store):
    return [
        event
        for event in store_events(events, store)
        if event[2:4] == ["execute", "BEGIN IMMEDIATE"]
    ]


@pytest.mark.parametrize("outer", ["write", "bound"])
def test_actual_same_thread_nested_bound_does_not_begin_twice(binding, observe_sql, outer):
    """Existing bug red: the original real second BEGIN waits its full timeout."""
    _, store, job = binding
    events, _ = observe_sql
    if outer == "write":
        outer_scope = store._write()
    else:
        # Do not ask for the new feature before the actual legacy nested BEGIN.
        outer_scope = store.bound_attempt(**arguments(job))
    with outer_scope:
        with store.bound_attempt(**arguments(job)) as row:
            assert row["run_id"] == job["run_id"]
            assert row["input_revision"] == job["input_revision"]
        assert len(begins(events, store)) == 1
        assert len({event[1] for event in store_events(events, store)}) == 1
    assert all(event[-1] == "returned" for event in begins(events, store))
    assert any(event[3] == "PRAGMA busy_timeout = 30000" for event in events)


@pytest.mark.parametrize("outer", ["write", "bound"])
def test_actual_accessor_is_identical_and_revoked_after_owner(binding, observe_sql, outer):
    _, store, job = binding
    active = accessor(store)
    events, _ = observe_sql
    with owner(store, job, outer) as connection:
        assert isinstance(connection, sqlite3.Connection)
        assert active() is connection and connection.in_transaction
        with store.bound_attempt(**arguments(job)):
            assert active() is connection
        assert active() is connection
        assert len(begins(events, store)) == 1
    with pytest.raises(JobError):
        active()


@pytest.mark.parametrize("manual_begin", [False, True])
def test_read_connection_and_arbitrary_in_transaction_cannot_issue(binding, manual_begin):
    _, store, _ = binding
    active = accessor(store)
    with store._read() as connection:
        if manual_begin:
            connection.execute("BEGIN IMMEDIATE")
            assert connection.in_transaction
        with pytest.raises(JobError):
            active()


@pytest.mark.parametrize("forgery", ["boolean", "JSON", "callable", "connection"])
def test_caller_attributes_do_not_mint_a_private_write_frame(binding, forgery):
    _, store, _ = binding
    active = accessor(store)
    with store._read() as connection:
        connection.execute("BEGIN IMMEDIATE")
        value = {
            "boolean": True,
            "JSON": {"active": True, "connection": connection, "store": store},
            "callable": lambda: connection,
            "connection": connection,
        }[forgery]
        store._active_transaction = value
        store._write_frame = value
        with pytest.raises(JobError):
            active()


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("job_id", "missing-job", "job_missing"),
        ("run_id", "foreign-run", "run_superseded"),
        ("owner_token", "foreign-owner", "owner_token_mismatch"),
        ("expected_input_revision", "foreign-input", "input_revision_changed"),
        ("terminal", "completed", "job_terminal"),
    ],
)
def test_borrow_repeats_original_actual_SQL_binding_checks(
    binding, observe_sql, field, value, expected
):
    _, store, job = binding
    active = accessor(store)
    events, _ = observe_sql
    with store._write() as connection:
        kwargs = arguments(job)
        if field == "terminal":
            connection.execute("UPDATE jobs SET status=? WHERE job_id=?", (value, job["job_id"]))
        else:
            kwargs[field] = value
        with pytest.raises(JobError) as error:
            with store.bound_attempt(**kwargs):
                pytest.fail("foreign binding must not yield")
        assert error.value.code == expected
        assert active() is connection and connection.in_transaction
        assert len(begins(events, store)) == 1
        assert not [
            event
            for event in store_events(events, store)
            if event[2] in {"commit", "rollback", "close"}
        ]


def test_legacy_optional_input_revision_remains_optional(binding):
    _, store, job = binding
    active = accessor(store)
    with store._write() as connection:
        connection.execute(
            "UPDATE jobs SET input_revision=? WHERE job_id=?", ("changed", job["job_id"])
        )
        with store.bound_attempt(**arguments(job, expected_input_revision=None)) as row:
            assert row["input_revision"] == "changed"
            assert active() is connection


def test_same_path_wrapper_borrows_the_identical_actual_transaction(binding, observe_sql):
    _, store, job = binding
    other = JobStore(store.db_path)
    active = accessor(store)
    other_active = accessor(other)
    events, _ = observe_sql
    with store._write() as connection:
        assert other_active() is connection
        with other.bound_attempt(**arguments(job)) as row:
            assert row["run_id"] == job["run_id"]
            assert active() is other_active() is connection
        assert len(begins(events, store)) == 1
        assert len({event[1] for event in store_events(events, store)}) == 1
    with pytest.raises(JobError):
        other_active()


@pytest.mark.parametrize("foreign", ["other_path", "hardlink"])
def test_foreign_Store_does_not_borrow_or_open_another_connection(
    binding, observe_sql, tmp_path, foreign
):
    _, store, job = binding
    active = accessor(store)
    if foreign == "other_path":
        other = JobStore(tmp_path / "other.sqlite")
        other.initialize()
    else:
        alias = tmp_path / "hardlink.sqlite"
        os.link(store.db_path, alias)
        other = JobStore(alias)
    events, _ = observe_sql
    events.clear()
    with store._write() as connection:
        count = len(events)
        with pytest.raises(JobError):
            with other.bound_attempt(**arguments(job)):
                pytest.fail("foreign Store must refuse")
        assert len(events) == count
        assert active() is connection


def test_foreign_thread_cannot_access_the_current_private_frame(binding, observe_sql):
    _, store, job = binding
    active = accessor(store)
    events, _ = observe_sql
    outcome = []
    finished = threading.Event()

    def other_thread():
        try:
            active()
        except BaseException as error:
            outcome.append(error)
        finally:
            finished.set()

    with store._write():
        thread = threading.Thread(target=other_thread)
        thread.start()
        completed_while_outer_active = finished.wait(2.0)
    thread.join(40.0)
    assert not thread.is_alive()
    assert completed_while_outer_active
    assert len(outcome) == 1 and isinstance(outcome[0], JobError)
    assert len(begins(events, store)) == 1


def test_foreign_thread_real_independent_BEGIN_waits_then_checks_binding(binding, observe_sql):
    _, store, job = binding
    active = accessor(store)
    other = JobStore(store.db_path)
    events, observer = observe_sql
    entering = threading.Event()
    finished = threading.Event()
    outcomes = []
    main_thread = threading.get_ident()

    def before_begin(connection):
        if threading.get_ident() != main_thread:
            entering.set()

    observer["before_begin"] = before_begin

    def independent_writer():
        try:
            with other.bound_attempt(**arguments(job)) as row:
                connection = accessor(other)()
                assert row["run_id"] == job["run_id"]
                outcomes.append(id(connection))
                assert connection.in_transaction
        except BaseException as error:
            outcomes.append(error)
        finally:
            finished.set()

    with store._write() as connection:
        assert active() is connection
        owner_identity = id(connection)
        thread = threading.Thread(target=independent_writer)
        thread.start()
        began = entering.wait(5.0)
        completed_before_release = finished.is_set()
    thread.join(40.0)
    assert not thread.is_alive() and began
    assert not completed_before_release
    assert len(outcomes) == 1 and isinstance(outcomes[0], int)
    assert outcomes[0] != owner_identity
    assert len(begins(events, store)) == 2
    assert all(event[-1] == "returned" for event in begins(events, store))


@pytest.mark.parametrize(
    "operation",
    [
        "commit",
        "rollback",
        "executescript",
        "comment_commit",
        "cursor_commit",
        "cursor_executescript",
        "context_commit",
        "context_rollback",
    ],
)
@pytest.mark.parametrize("begin_again", [False, True])
def test_ended_transaction_generation_cannot_be_resurrected(binding, operation, begin_again):
    _, store, _ = binding
    active = accessor(store)
    with store._write() as connection:
        assert active() is connection
        if operation == "commit":
            connection.commit()
        elif operation == "rollback":
            connection.rollback()
        elif operation == "executescript":
            connection.executescript("SELECT 1;")
        elif operation == "comment_commit":
            connection.execute("/* actual SQL control */ COMMIT")
        elif operation == "cursor_commit":
            connection.cursor().execute("-- actual cursor control\nEND")
        elif operation == "cursor_executescript":
            connection.cursor().executescript("SELECT 1;")
        elif operation == "context_commit":
            with connection:
                connection.execute("SELECT 1")
        else:
            with pytest.raises(RuntimeError):
                with connection:
                    raise RuntimeError("real connection context rollback")
        if begin_again:
            connection.execute("BEGIN IMMEDIATE")
            assert connection.in_transaction
        with pytest.raises(JobError):
            active()


@pytest.mark.parametrize("callback", ["disabled", "replaced"])
@pytest.mark.parametrize("finish", ["commit", "cursor_commit"])
def test_user_trace_changes_preserve_observation_and_never_resurrect(
    binding, callback, finish, record_property
):
    _, store, _ = binding
    active = accessor(store)
    traces = []
    with store._write() as connection:
        connection.set_trace_callback(traces.append)
        connection.execute("SELECT 701")
        assert traces.count("SELECT 701") == 1
        connection.set_trace_callback(None if callback == "disabled" else traces.append)
        assert active() is connection
        connection.execute("SELECT 702")
        assert traces.count("SELECT 702") == (0 if callback == "disabled" else 1)
        if finish == "commit":
            connection.commit()
        else:
            connection.cursor().execute("/* cursor, after trace change */ COMMIT")
        connection.execute("BEGIN IMMEDIATE")
        assert connection.in_transaction
        with pytest.raises(JobError):
            active()
    record_property("actual_user_trace_statements", json.dumps(traces))


def test_closed_connection_cannot_supply_an_active_frame(binding):
    _, store, _ = binding
    active = accessor(store)
    with pytest.raises(sqlite3.ProgrammingError):
        with store._write() as connection:
            assert active() is connection
            connection.close()
            with pytest.raises(JobError):
                active()


@pytest.mark.parametrize("outer", ["write", "bound"])
@pytest.mark.parametrize("exit_kind", ["normal", "Exception", "BaseException"])
def test_revocation_precedes_original_owner_finish(binding, observe_sql, outer, exit_kind):
    _, store, job = binding
    active = accessor(store)
    events, observer = observe_sql
    observations = []

    def before_finish(connection, name):
        with pytest.raises(JobError):
            active()
        observations.append(name)

    observer["before_finish"] = before_finish

    def execute():
        with owner(store, job, outer) as connection:
            assert active() is connection
            if exit_kind == "Exception":
                raise RuntimeError("actual callback exception")
            if exit_kind == "BaseException":
                raise KeyboardInterrupt("actual callback BaseException")

    if exit_kind == "normal":
        execute()
        assert observations == ["commit", "close"]
    else:
        with pytest.raises(RuntimeError if exit_kind == "Exception" else KeyboardInterrupt):
            execute()
        expected = (
            ["close"]
            if outer == "write" and exit_kind == "BaseException"
            else ["rollback", "close"]
        )
        assert observations == expected
    assert len(begins(events, store)) == 1
    with pytest.raises(JobError):
        active()


@pytest.mark.parametrize("finish", ["commit", "rollback", "close"])
@pytest.mark.parametrize("outer", ["write", "bound"])
def test_post_forward_finish_failure_never_leaves_authority(binding, observe_sql, finish, outer):
    """Fault injection is after the real operation, never a fabricated SQL result."""
    _, store, job = binding
    active = accessor(store)
    _, observer = observe_sql
    observer["post_forward_fault"] = finish
    observations = []

    def before_finish(connection, name):
        with pytest.raises(JobError):
            active()
        observations.append(name)

    observer["before_finish"] = before_finish
    expected_error = JobError if finish == "commit" and outer == "bound" else sqlite3.Error
    if finish == "rollback":
        expected_error = RuntimeError if outer == "bound" else sqlite3.Error
    with pytest.raises(expected_error):
        with owner(store, job, outer):
            if finish == "rollback":
                raise RuntimeError("trigger original rollback")
    assert finish in observations and "close" in observations
    with pytest.raises(JobError):
        active()


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_borrower_failure_keeps_the_genuine_outer_transaction(binding, observe_sql, failure):
    _, store, job = binding
    active = accessor(store)
    events, _ = observe_sql
    with store._write() as connection:
        with pytest.raises(failure):
            with store.bound_attempt(**arguments(job)):
                assert active() is connection
                raise failure("nested borrower")
        assert active() is connection and connection.in_transaction
        assert len(begins(events, store)) == 1
        assert not [
            event
            for event in store_events(events, store)
            if event[2] in {"commit", "rollback", "close"}
        ]


def test_absent_main_initializes_without_issuing_then_real_write_can_issue(tmp_path):
    store = JobStore(tmp_path / "initially-absent.sqlite")
    active = accessor(store)
    assert not store.db_path.exists()
    with store._write() as connection:
        connection.execute("CREATE TABLE actual_values(value INTEGER)")
        connection.execute("INSERT INTO actual_values VALUES(7)")
        with pytest.raises(JobError):
            active()
    with store._write() as connection:
        assert active() is connection
        assert connection.execute("SELECT value FROM actual_values").fetchone()[0] == 7
    with pytest.raises(JobError):
        active()


def test_memory_main_does_not_issue_a_physical_database_capability():
    store = JobStore(":memory:")
    active = accessor(store)
    with store._write() as connection:
        connection.execute("CREATE TABLE actual_values(value INTEGER)")
        assert connection.execute("PRAGMA database_list").fetchone()[2] == ""
        with pytest.raises(JobError):
            active()


def test_attached_database_is_not_mistaken_for_main(binding, tmp_path):
    _, store, _ = binding
    active = accessor(store)
    with store._write() as connection:
        connection.execute("ATTACH DATABASE ? AS foreign_db", (str(tmp_path / "attached.sqlite"),))
        assert active() is connection
        main = next(row for row in connection.execute("PRAGMA database_list") if row[1] == "main")
        assert Path(main[2]).resolve() == store.db_path.resolve()


def replacement_database(source, destination):
    with sqlite3.connect(str(source)) as original, sqlite3.connect(str(destination)) as replacement:
        original.backup(replacement)


def test_replaced_main_path_cannot_refresh_an_old_open_connection(binding, tmp_path):
    _, store, job = binding
    active = accessor(store)
    replacement = tmp_path / "replacement.sqlite"
    replacement_database(store.db_path, replacement)
    with store._write() as connection:
        assert active() is connection
        old_inode = store.db_path.stat().st_ino
        parked = tmp_path / "parked.sqlite"
        store.db_path.rename(parked)
        replacement.replace(store.db_path)
        assert store.db_path.stat().st_ino != old_inode
        assert (
            connection.execute(
                "SELECT run_id FROM jobs WHERE job_id=?", (job["job_id"],)
            ).fetchone()[0]
            == job["run_id"]
        )
        with pytest.raises(JobError):
            active()
        with pytest.raises(JobError):
            with store.bound_attempt(**arguments(job)):
                pytest.fail("old open handle must not borrow the replacement identity")


def test_replacement_between_real_open_and_BEGIN_issues_no_authority(
    binding, tmp_path, monkeypatch
):
    _, store, _ = binding
    active = accessor(store)
    replacement = tmp_path / "replacement-before-begin.sqlite"
    replacement_database(store.db_path, replacement)
    original_connect = store._connect

    def open_then_replace():
        connection = original_connect()
        store.db_path.rename(tmp_path / "old-open.sqlite")
        replacement.replace(store.db_path)
        return connection

    monkeypatch.setattr(store, "_connect", open_then_replace)
    with store._write() as connection:
        assert connection.in_transaction
        with pytest.raises(JobError):
            active()


@pytest.mark.parametrize("alias", ["symlink", "hardlink"])
def test_lexical_alias_drift_does_not_keep_the_old_frame(binding, tmp_path, alias):
    _, store, _ = binding
    active = accessor(store)
    original_path = store.db_path
    other_path = tmp_path / (alias + ".sqlite")
    if alias == "symlink":
        other_path.symlink_to(original_path)
    else:
        os.link(original_path, other_path)
    with store._write() as connection:
        assert active() is connection
        store.db_path = other_path
        try:
            with pytest.raises(JobError):
                active()
        finally:
            store.db_path = original_path


def test_original_checkpoint_callback_borrows_the_actual_owner(binding, observe_sql):
    _, store, job = binding
    active = accessor(store)
    events, _ = observe_sql
    observed = []
    before = counts(store)
    events.clear()

    def guard():
        connection = active()
        wrapper = JobStore(store.db_path)
        with wrapper.bound_attempt(**arguments(job)):
            assert active() is accessor(wrapper)() is connection
            observed.append(id(connection))

    event = store.append_bound_event(
        job["job_id"],
        run_id=job["run_id"],
        owner_token=job["owner_token"],
        expected_input_revision=job["input_revision"],
        kind="instance_checkpoint_persisted",
        message="actual nested currentness guard",
        data=payload(job),
        input_current_guard=guard,
    )
    with store._read() as connection:
        row = connection.execute(
            "SELECT e.kind,e.job_id,e.run_id,r.input_revision "
            "FROM events e JOIN bound_event_receipts r ON r.event_seq=e.seq "
            "WHERE e.seq=? AND r.job_id=e.job_id AND r.run_id=e.run_id",
            (event["seq"],),
        ).fetchone()
        assert row is not None
        assert tuple(row) == (
            "instance_checkpoint_persisted",
            job["job_id"],
            job["run_id"],
            job["input_revision"],
        )
    assert event["job_id"] == job["job_id"]
    assert event["run_id"] == job["run_id"]
    assert event["input_revision"] == job["input_revision"]
    assert len(observed) == 1 and len(begins(events, store)) == 1
    assert counts(store) == (before[0] + 1, before[1] + 1)


def test_original_settlement_callbacks_borrow_and_commit_actual_queue_receipt(
    settled_context, observe_sql
):
    store = settled_context[1]
    job = settled_context[2]
    active = accessor(store)
    events, _ = observe_sql
    observed = []

    def guard():
        connection = active()
        wrapper = JobStore(store.db_path)
        with wrapper.bound_attempt(**arguments(job)):
            assert active() is accessor(wrapper)() is connection
            observed.append(id(connection))

    ack = settle(settled_context, input_current_guard=guard)
    assert ack.committed
    assert len(observed) == 3 and len(set(observed)) == 1
    assert len(begins(events, store)) == 1
    assert queue_status(settled_context[7], settled_context[8]) == "completed"
    assert len(trusted(settled_context)) == 1
