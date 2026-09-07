"""Function-scoped type materialization. Only the owning coordinator writes."""

from __future__ import annotations

import json
import time
from contextlib import contextmanager
from typing import Any, Iterator

from .clang_derived_cache import cache_key

GENERATION_KEY = "clang_type_refs_generation"
FALLBACK_KEY = "clang_type_refs_fallback"
VERSION = "7"


class TypeContextUnavailable(RuntimeError):
    def __init__(self, reason: str, message: str = ""):
        self.reason = reason
        if not message and reason == "type_context_timeout":
            message = "Function type context wait exceeded 300 seconds"
        super().__init__(message or reason)


@contextmanager
def transaction(db: Any) -> Iterator[None]:
    with db._derived_index_lock:
        connection = db._conn
        connection.execute("SAVEPOINT function_type_materialization")
        try:
            yield
        except BaseException:
            connection.execute("ROLLBACK TO function_type_materialization")
            connection.execute("RELEASE function_type_materialization")
            raise
        else:
            connection.execute("RELEASE function_type_materialization")


def initialize_states(db: Any, generation: str, contexts: dict[str, str]) -> None:
    """Called in the unpublished batch database after all base rows exist."""
    with transaction(db):
        db._conn.execute("DELETE FROM function_type_ref_state")
        rows = []
        for function in db._conn.execute("SELECT * FROM functions WHERE is_declaration=0"):
            file = str(function["file_path"])
            context = contexts.get(file, "native")
            identity = cache_key(
                [
                    file,
                    function["name"],
                    function["start_line"],
                    function["end_line"],
                    function["signature"],
                    context,
                ]
            )
            rows.append(
                (
                    function["id"],
                    identity,
                    context,
                    file,
                    function["start_line"],
                    generation,
                    "pending" if file in contexts else "current",
                )
            )
            if len(rows) == 1000:
                db._conn.executemany(
                    "INSERT INTO function_type_ref_state "
                    "(function_id,identity,context,file_path,start_line,generation,status) VALUES (?,?,?,?,?,?,?)",
                    rows,
                )
                rows.clear()
        db._conn.executemany(
            "INSERT INTO function_type_ref_state "
            "(function_id,identity,context,file_path,start_line,generation,status) VALUES (?,?,?,?,?,?,?)",
            rows,
        )
        db._set_metadata_uncommitted(GENERATION_KEY, generation)
        db._set_metadata_uncommitted(FALLBACK_KEY, json.dumps(contexts, sort_keys=True))
        update_aggregate(db)


def counts(db: Any) -> dict[str, int]:
    result = dict(pending=0, in_progress=0, current=0, failed=0)
    for row in db._conn.execute(
        "SELECT status,COUNT(*) FROM function_type_ref_state WHERE generation=? GROUP BY status",
        (db.get_metadata(GENERATION_KEY),),
    ):
        result[str(row[0])] = int(row[1])
    return result


def update_aggregate(db: Any) -> None:
    incomplete = bool(
        db._conn.execute(
            "SELECT 1 FROM function_type_ref_state WHERE generation=? "
            "AND status IN ('pending','in_progress','failed') LIMIT 1",
            (db.get_metadata(GENERATION_KEY),),
        ).fetchone()
    )
    state = db.get_derived_index_state("function_type_refs")
    state.update(
        status="dirty" if incomplete else "current",
        target_version=VERSION,
        applied_version=VERSION if not incomplete else state.get("applied_version", ""),
        dirty_reason="deferred_type_refs" if incomplete else "",
        last_stats={"complete": not incomplete},
    )
    db._write_derived_index_state_uncommitted("function_type_refs", state)


def claim(db: Any, function_id: int, generation: str, attempt: str) -> bool:
    with transaction(db):
        if db.get_metadata(GENERATION_KEY) != generation:
            return False
        return bool(
            db._conn.execute(
                "UPDATE function_type_ref_state SET status='in_progress',attempt=?,reason='' "
                "WHERE function_id=? AND generation=? AND status IN ('pending','failed')",
                (attempt, function_id, generation),
            ).rowcount
        )


def finish(
    db: Any,
    function_id: int,
    generation: str,
    attempt: str,
    rows: list[tuple[Any, ...]] | None,
    reason: str = "",
) -> bool:
    """CAS the attempt and publish rows + readiness in one transaction."""
    with transaction(db):
        state = db._conn.execute(
            "SELECT s.status,s.attempt FROM function_type_ref_state s "
            "JOIN functions f ON f.id=s.function_id "
            "WHERE s.function_id=? AND s.generation=?",
            (function_id, generation),
        ).fetchone()
        if (
            db.get_metadata(GENERATION_KEY) != generation
            or not state
            or state[0] != "in_progress"
            or state[1] != attempt
        ):
            return False
        if rows is not None:
            if any(int(row[0]) != function_id for row in rows):
                raise ValueError("function materialization contains another function")
            db._conn.execute("DELETE FROM function_type_refs WHERE function_id=?", (function_id,))
            db._conn.executemany(
                "INSERT OR REPLACE INTO function_type_refs "
                "(function_id,type_id,type_index_name,referenced_name,reference_file,"
                "reference_line,reference_kind,resolution_reason) VALUES (?,?,?,?,?,?,?,?)",
                rows,
            )
        db._conn.execute(
            "UPDATE function_type_ref_state SET status=?,reason=? WHERE function_id=?",
            ("current" if rows is not None else "failed", reason, function_id),
        )
        if rows is None:
            retries = int(
                db._conn.execute(
                    "SELECT retry_count FROM function_type_ref_state WHERE function_id=?",
                    (function_id,),
                ).fetchone()[0]
            )
            delay = (30, 120, 600)[min(retries, 2)]
            db._conn.execute(
                "UPDATE function_type_ref_state SET retry_count=retry_count+1,retry_after=? "
                "WHERE function_id=?",
                (time.time() + delay, function_id),
            )
        update_aggregate(db)
        return True


def release(db: Any, function_id: int, generation: str, attempt: str) -> None:
    with transaction(db):
        db._conn.execute(
            "UPDATE function_type_ref_state SET status='pending',attempt='' "
            "WHERE function_id=? AND generation=? AND attempt=? AND status='in_progress'",
            (function_id, generation, attempt),
        )


def invalidate_inputs(db: Any, generation: str, reason: str) -> None:
    with transaction(db):
        if db.get_metadata(GENERATION_KEY) != generation:
            return
        db._conn.execute(
            "UPDATE function_type_ref_state SET status='pending',attempt='',reason=? "
            "WHERE generation=? AND context<>'native'",
            (reason, generation),
        )
        aggregate = db.get_derived_index_state("function_type_refs")
        aggregate.update(
            status="dirty", dirty_reason=reason, last_error=reason, last_stats={"complete": False}
        )
        db._write_derived_index_state_uncommitted("function_type_refs", aggregate)


def reset_unfinished(db: Any, generation: str, *, invalidate: bool = False) -> None:
    contexts = json.loads(db.get_metadata(FALLBACK_KEY) or "{}")
    with transaction(db):
        for file in contexts:
            db._conn.execute(
                "UPDATE function_type_ref_state SET status='pending',attempt='',reason='' "
                + (",retry_count=0,retry_after=0 " if invalidate else "")
                + "WHERE generation=? AND function_id IN (SELECT id FROM functions WHERE file_path=?)"
                + ("" if invalidate else " AND status='in_progress'"),
                (generation, file),
            )
        update_aggregate(db)


def function_record(db: Any, name: str, file: str, line: int) -> dict[str, Any] | None:
    matches = [
        dict(row)
        for row in db._conn.execute(
            "SELECT f.*,s.identity,s.context,s.generation,s.status AS type_status,s.reason "
            "FROM functions f LEFT JOIN function_type_ref_state s ON s.function_id=f.id "
            "WHERE f.name=? AND f.is_declaration=0",
            (name,),
        )
        if (not file or db._paths_match_hint(str(row["file_path"]), file))
        and (not line or int(row["start_line"]) == line)
    ]
    return matches[0] if len(matches) == 1 else None


def read_current(
    db: Any, name: str, file: str, line: int, generation: str
) -> dict[str, Any] | None:
    # A read transaction, not the writer mutex: never wait for the scheduler here.
    connection = db._conn
    connection.execute("SAVEPOINT read_function_types")
    try:
        record = function_record(db, name, file, line)
        if (
            not record
            or record["type_status"] != "current"
            or record["generation"] != generation
            or db.get_metadata(GENERATION_KEY) != generation
        ):
            return None
        return dict(db.get_function_type_context(name, file, line))
    finally:
        connection.execute("RELEASE read_function_types")
