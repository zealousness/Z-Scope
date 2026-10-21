"""Additional causal probe; original Store65 test bytes and Counter stay fixed."""

import json

import pytest

from zscope.orchestration.jobs.models import JobError
from zscope.orchestration.jobs import store as store_module
from zscope.orchestration.jobs.store import JobStore


@pytest.mark.parametrize(
    "route", ["connection_sql", "cursor_sql", "commit_api", "rollback_api", "normal_trace"]
)
def test_real_user_trace_callback_cannot_resurrect_issued_generation(
    tmp_path, record_property, route
):
    store = JobStore(tmp_path / "actual-main.sqlite")
    store.initialize()
    statements = []
    operations = []
    fired = False
    error = None
    returned = None
    with store._write() as connection:
        active = store._active_transaction_connection
        assert active() is connection and connection.in_transaction
        original_frame = store_module._WRITE_SCOPES.current.frame
        original_generation = original_frame.generation
        original_connection_id = id(connection)

        def trace(sql):
            nonlocal fired
            statements.append(sql)
            if sql != "PRAGMA database_list" or fired:
                return
            fired = True
            if route == "normal_trace":
                return
            operations.append(["before_end", connection.in_transaction])
            if route in {"connection_sql", "cursor_sql"}:
                target = connection if route == "connection_sql" else connection.cursor()
                target.execute("/* user callback actual control */ COMMIT")
            elif route == "commit_api":
                connection.commit()
            else:
                connection.rollback()
            operations.append(["after_actual_end", connection.in_transaction])
            connection.execute("BEGIN IMMEDIATE")
            operations.append(["after_actual_BEGIN", connection.in_transaction])

        connection.set_trace_callback(trace)
        try:
            returned = active()
        except JobError as caught:
            error = caught
        observation = store_module._CONNECTION_OBSERVATIONS[connection]
        record_property("actual_trace_SQL", json.dumps(statements))
        record_property("actual_callback_SQL_operations", json.dumps(operations))
        record_property("original_connection_id", original_connection_id)
        record_property("original_frame_generation_id", id(original_generation))
        record_property("current_observed_generation_id", id(observation.generation))
        record_property(
            "public_accessor_outcome", error.code if error else "returned_real_connection"
        )
        assert fired
        if route == "normal_trace":
            assert returned is connection and error is None
            assert not operations and connection.in_transaction
        else:
            assert operations == [
                ["before_end", True],
                ["after_actual_end", False],
                ["after_actual_BEGIN", True],
            ]
            assert isinstance(
                error, JobError
            ), "ended/restarted generation was accepted after real callback SQL: " + json.dumps(
                statements
            )
            assert returned is None
