"""Unit/store-level tests for the persistent scan job slice (S08).

These tests cover the SQLite single source of truth, the contract-aligned
service envelope, input fingerprinting, process identity probing and the
scheduler hook contract.  Real detached-owner process behaviour lives in
``test_scan_job_execution.py``; nothing in this file spawns an owner.
"""

import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from zscope.orchestration.jobs import identity
from zscope.orchestration.jobs.fingerprint import compute_input_fingerprint, diff_components
from zscope.orchestration.jobs.models import (
    MAX_EVENT_DATA_CHARS,
    SCHEMA_VERSION,
    JobError,
    bounded_event_data,
    deduce_owner_state,
    error_envelope,
    extract_questions,
    job_capabilities,
    merge_coverage,
    null_progress,
    parse_stop_at,
    resolve_stop_time,
    utc_now_iso,
    validate_after_seq,
    validate_base_revision,
    validate_request_id,
    validate_scan_depth,
)
from zscope.orchestration.jobs.owner import Owner
from zscope.orchestration.jobs.runner import build_cli_command, write_launch_file
from zscope.orchestration.jobs.scheduler_hook import JobWindowHook
from zscope.orchestration.jobs.service import STORE_DB_NAME, STORE_DIR_NAME, ScanJobService
from zscope.orchestration.jobs.store import JobStore
from zscope.reporting.json_io import read_report, write_report_atomic

CONFIG_TEMPLATE = """\
config_version: 2
llms:
  default:
    base_urls: ["http://127.0.0.1:9/"]
    models: ["dummy-model"]
    api_key: "dummy-key"
project:
  language: c_cpp
  root: "{root}"
  source_root: src
scan:
  depth: fast
indexing:
  backend: regex
concurrency:
  entry_workers: 1
  validator_workers: 1
  investigator_workers: 1
  evidence_completion_workers: 1
  index_workers: 1
  svf_workers: 1
  llm_max_inflight: 1
"""

needs_proc = pytest.mark.skipif(
    not identity.proc_available(), reason="process identity requires Linux /proc"
)


def make_project(tmp_path: Path, *, name: str = "project") -> Path:
    """Create a minimal real project with a valid saved config."""

    project = tmp_path / name
    (project / "src").mkdir(parents=True)
    (project / "src" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    config_text = CONFIG_TEMPLATE.replace("{root}", str(project))
    (project / "zscope.yaml").write_text(config_text, encoding="utf-8")
    return project


def make_build_project(tmp_path: Path, *, name: str = "buildproject") -> Path:
    """Like :func:`make_project` but with a compile_commands build input."""

    project = make_project(tmp_path, name=name)
    config = project / "zscope.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "  source_root: src\n",
            "  source_root: src\n  compile_commands_path: build/compile_commands.json\n",
        ),
        encoding="utf-8",
    )
    (project / "build").mkdir()
    (project / "build" / "compile_commands.json").write_text("[]\n", encoding="utf-8")
    return project


SHARED_REPORT = {
    "completeness": "incomplete",
    "issues": [{"id": "iss-1", "rule": "demo_rule"}],
    "metadata": {
        "build_coverage": {"selected_tus": 2, "total_tus": 3},
        "coverage_gaps": [{"kind": "tu_missing", "path": "src/extra.c"}],
        "deferred_count": 4,
        "business_questions": [
            {
                "id": "q9",
                "question": "Who owns the pooled object?",
                "affected_scope": "src/main.c",
                "current_assumption": "caller-owned",
                "impact": "high",
                "answer_revision": 0,
            }
        ],
    },
}


def _corrupt_shared_json_graph(path: Path) -> None:
    """Break an object digest inside a real shared-json.v1 envelope."""

    envelope = json.loads(path.read_text(encoding="utf-8"))
    assert envelope.get("storage_schema") == "zscope.shared-json.v1"
    uid = next(iter(envelope["objects"]))
    envelope["objects"][uid] = ["value", "tampered-object-digest"]
    path.write_text(json.dumps(envelope), encoding="utf-8")


@needs_proc
def _spawn_zombie() -> "subprocess.Popen[bytes]":
    """Exit a real child without reaping it, so it stays a zombie."""

    child = subprocess.Popen([sys.executable, "-c", "pass"])
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        stat = identity.read_process_stat(child.pid)
        if stat is not None and stat[1] == "Z":
            return child
        time.sleep(0.05)
    child.wait()
    pytest.fail("child did not become an unreaped zombie")


def make_service(project: Path, **kwargs) -> ScanJobService:
    kwargs.setdefault("spawn_owner", False)
    return ScanJobService(project / "zscope.yaml", **kwargs)


def store_for(project: Path) -> JobStore:
    return JobStore(project / STORE_DIR_NAME / STORE_DB_NAME)


def create_row(
    store: JobStore,
    *,
    job_id: str = "job_test",
    run_id: str = "run_test",
    status: str = "queued",
) -> dict:
    now = utc_now_iso()
    return store.create_job(
        {
            "job_id": job_id,
            "run_id": run_id,
            "revision": 1,
            "input_revision": "fp0",
            "status": status,
            "phase": None,
            "created_at": now,
            "updated_at": now,
            "requested_stop_at": None,
            "resolved_stop_time": None,
            "stop_at_epoch": None,
            "scan_depth": None,
            "config_path": "/tmp/x/zscope.yaml",
            "config_sha256": "x",
            "project_root": "/tmp/x",
            "project_id": "x",
            "working_directory": "/tmp/x",
            "run_dir": "/tmp/x/.zscope_jobs/job_test/run_test",
            "owner_pid": None,
            "owner_token": "tok",
            "owner_start_ticks": None,
            "owner_boot_id": None,
            "owner_heartbeat_at": None,
            "scanner_pid": None,
            "scanner_start_ticks": None,
            "cancel_requested_at": None,
            "input_components_json": {},
            "progress_json": {},
            "coverage_json": {},
            "questions_json": [],
            "pending_count": None,
            "report_json": {},
            "artifacts_json": [],
            "error_code": None,
            "error_message": None,
        }
    )


def force_status(store: JobStore, job_id: str, status: str) -> dict:
    job = store.get_job(job_id)
    assert job is not None
    return store.update_job(
        job_id, expected_revision=int(job["revision"]), updates={"status": status}
    )


def start_job(service: ScanJobService, **kwargs) -> dict:
    response = service.start(**kwargs)
    assert response.status_code == 202, response.payload
    return response.payload["job"]


# ---------------------------------------------------------------------------
# models: validation helpers and pure projections


def test_validate_scan_depth_accepts_case_insensitive_and_none():
    assert validate_scan_depth(None) is None
    assert validate_scan_depth("FAST") == "fast"
    assert validate_scan_depth(" balanced ") == "balanced"
    with pytest.raises(JobError) as excinfo:
        validate_scan_depth("nightly")
    assert excinfo.value.status_code == 400
    assert excinfo.value.code == "invalid_request"


def test_parse_stop_at_requires_explicit_timezone():
    with pytest.raises(JobError) as excinfo:
        parse_stop_at("2026-10-14T22:00:00")
    assert excinfo.value.status_code == 400
    with pytest.raises(JobError):
        parse_stop_at("not-a-time")
    with pytest.raises(JobError):
        parse_stop_at(123)
    resolved, epoch = resolve_stop_time("2026-10-14T22:00:00+08:00")
    assert resolved is not None and epoch is not None
    assert resolved == "2026-10-14T14:00:00+00:00"
    expected = datetime(2026, 10, 14, 22, 0, 0, tzinfo=timezone(timedelta(hours=8)))
    assert epoch == expected.timestamp()
    assert resolve_stop_time(None) == (None, None)


def test_validate_request_id_bounds():
    assert validate_request_id(" req-1 ") == "req-1"
    for bad in (None, "", "   ", 42):
        with pytest.raises(JobError):
            validate_request_id(bad)
    with pytest.raises(JobError):
        validate_request_id("x" * 200)


def test_validate_base_revision_and_after_seq():
    assert validate_base_revision(3) == 3
    for bad in (0, -1, True, "1", None):
        with pytest.raises(JobError):
            validate_base_revision(bad)
    assert validate_after_seq(0) == 0
    assert validate_after_seq(17) == 17
    for bad in (-1, True, "0", None):
        with pytest.raises(JobError):
            validate_after_seq(bad)


def test_error_envelope_shape_and_codes():
    exc = JobError("some_code", "message", status_code=409, details={"k": "v"})
    assert error_envelope(exc) == {"error": "message", "code": "some_code", "details": {"k": "v"}}
    assert error_envelope(JobError("c", "m")) == {"error": "m", "code": "c"}


def test_job_capabilities_per_status():
    running = job_capabilities("running")
    assert running["cancel"] is True and running["resume"] is False
    assert any(r["code"] == "job_active" for r in running["reasons"])
    stopping = job_capabilities("stopping")
    assert stopping["cancel"] is False
    assert any(r["code"] == "cancel_in_progress" for r in stopping["reasons"])
    completed = job_capabilities("completed")
    assert completed["cancel"] is False and completed["resume"] is False
    assert any(r["code"] == "already_completed" for r in completed["reasons"])
    cancelled = job_capabilities("cancelled")
    assert cancelled["resume"] is True and cancelled["cancel"] is False
    assert any(r["code"] == "terminal_state" for r in cancelled["reasons"])


def test_deduce_owner_state_mapping():
    assert deduce_owner_state(probe_result=True, job_status="running") == "alive"
    assert deduce_owner_state(probe_result=False, job_status="running") == "lost"
    assert deduce_owner_state(probe_result=False, job_status="completed") == "exited"
    assert deduce_owner_state(probe_result=None, job_status="running") == "unknown"


def test_bounded_event_data_truncates_oversized_payloads():
    small = {"k": "v"}
    assert bounded_event_data(small) == small
    big = {"blob": "x" * (MAX_EVENT_DATA_CHARS * 2)}
    bounded = bounded_event_data(big)
    assert bounded["_truncated"] is True
    assert len(json.dumps(bounded)) < MAX_EVENT_DATA_CHARS
    assert bounded_event_data(None) == {}


def test_bounded_event_data_output_is_finite_json_without_default_encoder():
    # Event rows are persisted with a plain json.dumps (no ``default``), so
    # whatever bounded_event_data returns must already be finite JSON.
    class Odd:
        def __str__(self) -> str:
            return "odd-object"

    payload = {"obj": Odd(), "nested": {"keep": True}}
    bounded = bounded_event_data(payload)
    encoded = json.dumps(bounded, ensure_ascii=False)
    assert len(encoded) <= MAX_EVENT_DATA_CHARS
    decoded = json.loads(encoded)
    assert decoded["obj"] == "odd-object"
    assert decoded["nested"] == {"keep": True}


def test_merge_coverage_and_extract_questions():
    assert merge_coverage(None) == {
        "completeness": None,
        "build_coverage": None,
        "gaps": [],
        "deferred_count": None,
    }
    report = {
        "completeness": "incomplete",
        "metadata": {
            "build_coverage": {"selected": 1},
            "coverage_gaps": [{"kind": "tu_missing"}],
            "deferred_count": 2,
            "business_questions": [
                {"id": "q1", "question": "Is this owned?", "impact": "high"},
                {"question": ""},
                "not-a-dict",
            ],
        },
    }
    coverage = merge_coverage(report)
    assert coverage["completeness"] == "incomplete"
    assert coverage["build_coverage"] == {"selected": 1}
    assert coverage["gaps"] == [{"kind": "tu_missing"}]
    assert coverage["deferred_count"] == 2
    questions = extract_questions(report)
    assert len(questions) == 1
    assert questions[0]["id"] == "q1"
    assert questions[0]["question"] == "Is this owned?"


def test_owner_status_from_exit_mapping():
    assert Owner._status_from_exit(0, report_bound=False) == "completed"
    assert Owner._status_from_exit(1, report_bound=False) == "completed"
    assert Owner._status_from_exit(2, report_bound=True) == "partial"
    assert Owner._status_from_exit(2, report_bound=False) == "failed"
    assert Owner._status_from_exit(3, report_bound=True) == "failed"


# ---------------------------------------------------------------------------
# store: single source of truth


def test_store_initialize_is_idempotent_and_records_schema(tmp_path):
    store = JobStore(tmp_path / "nested" / "jobs.db")
    store.initialize()
    store.initialize()
    store.check_available()
    row = create_row(store)
    assert row["revision"] == 1
    assert row["status"] == "queued"
    fresh = JobStore(tmp_path / "nested" / "jobs.db")
    assert fresh.get_job("job_test") is not None


def test_store_rejects_read_of_uninitialized_db(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    with pytest.raises(JobError) as excinfo:
        store.check_available()
    assert excinfo.value.code == "store_unavailable"
    assert excinfo.value.status_code == 503


def test_store_create_job_enforces_single_active_job(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    store.initialize()
    create_row(store, job_id="job_a", run_id="run_a")
    with pytest.raises(JobError) as excinfo:
        create_row(store, job_id="job_b", run_id="run_b")
    assert excinfo.value.code == "project_scan_active"
    assert excinfo.value.status_code == 409
    assert excinfo.value.details["active_job_id"] == "job_a"
    force_status(store, "job_a", "cancelled")
    created = create_row(store, job_id="job_b", run_id="run_b")
    assert created["job_id"] == "job_b"


@pytest.mark.parametrize("status", ["completed", "partial", "cancelled", "failed", "lost"])
def test_terminal_job_and_attempt_are_visible_in_one_commit(tmp_path, monkeypatch, status):
    from zscope.orchestration.jobs import store as store_module

    store = JobStore(tmp_path / "jobs.sqlite")
    store.initialize()
    job = create_row(store, status="running")
    store.record_attempt(
        {
            "job_id": job["job_id"],
            "run_id": job["run_id"],
            "attempt_no": 1,
            "status": "running",
            "input_revision": job["input_revision"],
        }
    )
    reader = JobStore(store.db_path)
    finish = store_module._finish_attempt_on
    observations = []

    def observe_before_attempt_write(connection, job_id, run_id, fields):
        # An independent SQLite reader must not see the job's terminal status
        # while its attempt is still running, even at this forced write boundary.
        observations.append(
            (reader.get_job(job_id)["status"], reader.attempt_for(job_id, run_id)["status"])
        )
        finish(connection, job_id, run_id, fields)

    monkeypatch.setattr(store_module, "_finish_attempt_on", observe_before_attempt_write)
    updated = store.update_job(
        job["job_id"],
        expected_revision=job["revision"],
        updates={"status": status},
        attempt_fields={"status": status, "ended_at": utc_now_iso(), "exit_code": 3},
    )
    assert observations == [("running", "running")]
    assert updated["status"] == reader.get_job(job["job_id"])["status"] == status
    attempt = reader.attempt_for(job["job_id"], job["run_id"])
    assert attempt["status"] == status
    assert attempt["attempt_no"] == 1
    assert attempt["input_revision"] == job["input_revision"]
    assert attempt["exit_code"] == 3


def test_attempt_write_failure_rolls_back_terminal_job(tmp_path, monkeypatch):
    from zscope.orchestration.jobs import store as store_module

    store = JobStore(tmp_path / "jobs.sqlite")
    store.initialize()
    job = create_row(store, status="running")

    def fail_attempt_write(*args):
        raise RuntimeError("injected attempt persistence failure")

    monkeypatch.setattr(store_module, "_finish_attempt_on", fail_attempt_write)
    with pytest.raises(RuntimeError, match="attempt persistence failure"):
        store.update_job(
            job["job_id"],
            expected_revision=job["revision"],
            updates={"status": "failed"},
            attempt_fields={"status": "failed", "ended_at": utc_now_iso()},
        )
    reader = JobStore(store.db_path)
    assert reader.get_job(job["job_id"])["status"] == "running"
    assert reader.get_job(job["job_id"])["revision"] == job["revision"]
    assert reader.attempt_for(job["job_id"], job["run_id"]) is None


def test_store_update_job_optimistic_revision(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    store.initialize()
    job = create_row(store)
    updated = store.update_job(job["job_id"], expected_revision=1, updates={"phase": "scanning"})
    assert updated["revision"] == 2
    assert updated["phase"] == "scanning"
    with pytest.raises(JobError) as excinfo:
        store.update_job(job["job_id"], expected_revision=1, updates={"phase": "x"})
    assert excinfo.value.code == "revision_conflict"
    assert excinfo.value.status_code == 409
    with pytest.raises(ValueError):
        store.update_job(job["job_id"], expected_revision=2, updates={"job_id": "nope"})


def test_store_conditional_update_checks_status_atomically(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    store.initialize()
    job = create_row(store)
    with pytest.raises(JobError) as excinfo:
        store.conditional_update(
            job["job_id"],
            expected_revision=1,
            from_statuses=("running",),
            updates={"status": "stopping"},
        )
    assert excinfo.value.code == "invalid_state"
    assert excinfo.value.status_code == 409
    with pytest.raises(JobError) as excinfo:
        store.conditional_update(
            job["job_id"],
            expected_revision=99,
            from_statuses=("queued",),
            updates={"status": "stopping"},
        )
    assert excinfo.value.code == "revision_conflict"
    updated = store.conditional_update(
        job["job_id"],
        expected_revision=1,
        from_statuses=("queued", "running"),
        updates={"status": "running"},
    )
    assert updated["status"] == "running"
    assert updated["revision"] == 2


def test_store_heartbeat_is_token_guarded_and_revision_neutral(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    store.initialize()
    job = create_row(store)
    assert store.heartbeat(job["job_id"], owner_token="wrong", at=utc_now_iso()) is False
    assert store.heartbeat(job["job_id"], owner_token="tok", at=utc_now_iso()) is True
    reloaded = store.get_job(job["job_id"])
    assert reloaded["revision"] == job["revision"]
    assert reloaded["owner_heartbeat_at"] is not None


def test_store_events_are_ordered_and_paged(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    store.initialize()
    create_row(store)
    seqs = []
    for index in range(5):
        seqs.append(
            store.append_event(
                "job_test", run_id="run_test", kind="k", message=f"m{index}", data={"i": index}
            )
        )
    assert seqs == sorted(seqs)
    page, has_more = store.list_events("job_test", after_seq=0, limit=2)
    assert [event["seq"] for event in page] == seqs[:2]
    assert has_more is True
    page, has_more = store.list_events("job_test", after_seq=seqs[1], limit=10)
    assert [event["seq"] for event in page] == seqs[2:]
    assert has_more is False
    assert page[0]["data"] == {"i": 2}


def test_store_request_idempotency_records_conflicts(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    store.initialize()
    assert (
        store.record_request_if_new(
            request_id="r1", endpoint="start", payload_hash="h1", job_id="job_test"
        )
        is None
    )
    conflict = store.record_request_if_new(
        request_id="r1", endpoint="start", payload_hash="h1", job_id="job_test"
    )
    assert conflict is not None and conflict["job_id"] == "job_test"
    assert store.get_request("r1")["payload_hash"] == "h1"
    assert store.get_request("missing") is None


def test_store_create_job_with_request_reserves_atomically(tmp_path):
    # R5: the marker and the job row commit together in one transaction —
    # before any launch side effect — so duplicates replay, conflicts create
    # nothing, and the mutex holds in the same transaction.
    store = JobStore(tmp_path / "jobs.db")
    store.initialize()

    def fields_for(job_id: str, run_id: str) -> dict:
        now = utc_now_iso()
        return {
            "job_id": job_id,
            "run_id": run_id,
            "revision": 1,
            "input_revision": "fp0",
            "status": "queued",
            "phase": "queued",
            "created_at": now,
            "updated_at": now,
            "config_path": "/tmp/x/zscope.yaml",
            "config_sha256": "x",
            "project_root": "/tmp/x",
            "project_id": "x",
            "working_directory": "/tmp/x",
            "run_dir": f"/tmp/x/.zscope_jobs/{job_id}/{run_id}",
            "owner_token": "tok",
        }

    reservation = store.create_job_with_request(
        fields=fields_for("job_r5b", "run_r5b"),
        request_id="req-r5a",
        endpoint="start",
        payload_hash="h1",
    )
    assert reservation.created and reservation.job_id == "job_r5b"
    assert reservation.job is not None and reservation.job["status"] == "queued"
    assert store.get_request("req-r5a")["job_id"] == "job_r5b"
    # Same key + payload replays the reserved job (even from a reopened store).
    replay = JobStore(tmp_path / "jobs.db").create_job_with_request(
        fields=fields_for("job_r5c", "run_r5c"),
        request_id="req-r5a",
        endpoint="start",
        payload_hash="h1",
    )
    assert not replay.created and replay.job_id == "job_r5b"
    assert store.get_job("job_r5c") is None
    # Same key + different payload (or endpoint) conflicts without creating.
    for endpoint, payload_hash in (("start", "h2"), ("resume", "h1")):
        with pytest.raises(JobError) as excinfo:
            store.create_job_with_request(
                fields=fields_for("job_r5d", "run_r5d"),
                request_id="req-r5a",
                endpoint=endpoint,
                payload_hash=payload_hash,
            )
        assert excinfo.value.code == "request_id_conflict"
        assert excinfo.value.status_code == 409
    assert store.get_job("job_r5d") is None
    # The active-scan mutex is enforced inside the same transaction.
    with pytest.raises(JobError) as excinfo:
        store.create_job_with_request(
            fields=fields_for("job_r5e", "run_r5e"),
            request_id="req-r5b",
            endpoint="start",
            payload_hash="h1",
        )
    assert excinfo.value.code == "project_scan_active"
    assert excinfo.value.details["active_job_id"] == "job_r5b"
    # Once the first job is terminal, the duplicate still replays — never a
    # second job (the R5 defect).
    force_status(store, "job_r5b", "completed")
    replay_after_terminal = store.create_job_with_request(
        fields=fields_for("job_r5f", "run_r5f"),
        request_id="req-r5a",
        endpoint="start",
        payload_hash="h1",
    )
    assert not replay_after_terminal.created
    assert replay_after_terminal.job_id == "job_r5b"
    assert [row["job_id"] for row in store.list_jobs()] == ["job_r5b"]


def test_store_arm_attempt_with_request_guards_revision_and_status(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    store.initialize()
    create_row(store, job_id="job_r5g", run_id="run_r5g")
    force_status(store, "job_r5g", "cancelled")
    current = store.get_job("job_r5g")
    assert current is not None
    # A stale base_revision can never arm a second attempt.
    with pytest.raises(JobError) as excinfo:
        store.arm_attempt_with_request(
            job_id="job_r5g",
            expected_revision=int(current["revision"]) - 1,
            from_statuses=("cancelled",),
            updates={"run_id": "run_stale"},
            request_id="req-r5g-stale",
            endpoint="resume",
            payload_hash="h1",
        )
    assert excinfo.value.code == "revision_conflict"
    # Wrong status guard.
    with pytest.raises(JobError) as excinfo:
        store.arm_attempt_with_request(
            job_id="job_r5g",
            expected_revision=int(current["revision"]),
            from_statuses=("failed",),
            updates={"run_id": "run_wrong"},
            request_id="req-r5g-wrong",
            endpoint="resume",
            payload_hash="h1",
        )
    assert excinfo.value.code == "invalid_state"
    # Arming registers the marker in the same transaction; a duplicate with
    # the same payload replays instead of arming again.
    armed = store.arm_attempt_with_request(
        job_id="job_r5g",
        expected_revision=int(current["revision"]),
        from_statuses=("cancelled",),
        updates={"run_id": "run_r5g2", "status": "queued"},
        request_id="req-r5g",
        endpoint="resume",
        payload_hash="h2",
    )
    assert armed.created and armed.job is not None
    assert armed.job["run_id"] == "run_r5g2"
    duplicate = store.arm_attempt_with_request(
        job_id="job_r5g",
        expected_revision=int(current["revision"]),
        from_statuses=("cancelled",),
        updates={"run_id": "run_r5g3"},
        request_id="req-r5g",
        endpoint="resume",
        payload_hash="h2",
    )
    assert not duplicate.created and duplicate.job_id == "job_r5g"
    assert store.get_job("job_r5g")["run_id"] == "run_r5g2"


def test_store_cancel_with_request_finalizes_ownerless_queued_job(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    store.initialize()
    job = create_row(store, job_id="job_r5h", run_id="run_r5h")
    # Queued with no owner: the cancel transaction finalizes to cancelled and
    # keeps the attempt record bound to the input.
    reservation = store.cancel_with_request(
        job_id="job_r5h",
        expected_revision=int(job["revision"]),
        request_id="req-r5h",
        endpoint="cancel",
        payload_hash="h1",
    )
    assert reservation.created and reservation.job is not None
    assert reservation.job["status"] == "cancelled"
    assert reservation.job["error_code"] == "cancelled"
    attempt = store.attempt_for("job_r5h", "run_r5h")
    assert attempt is not None and attempt["status"] == "cancelled"
    assert attempt["input_revision"] == job["input_revision"]
    duplicate = store.cancel_with_request(
        job_id="job_r5h",
        expected_revision=int(job["revision"]),
        request_id="req-r5h",
        endpoint="cancel",
        payload_hash="h1",
    )
    assert not duplicate.created and duplicate.job_id == "job_r5h"


def test_store_attempts_lifecycle(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    store.initialize()
    create_row(store)
    assert store.next_attempt_no("job_test") == 1
    store.record_attempt(
        {
            "job_id": "job_test",
            "run_id": "run_test",
            "attempt_no": 1,
            "status": "running",
            "input_revision": "fp0",
            "started_at": utc_now_iso(),
        }
    )
    assert store.next_attempt_no("job_test") == 2
    store.finish_attempt(
        "job_test",
        "run_test",
        {"status": "completed", "ended_at": utc_now_iso(), "exit_code": 0},
    )
    attempt = store.attempt_for("job_test", "run_test")
    assert attempt["status"] == "completed"
    assert attempt["attempt_no"] == 1
    assert attempt["exit_code"] == 0
    assert len(store.list_attempts("job_test")) == 1


# ---------------------------------------------------------------------------
# fingerprint and identity


def test_fingerprint_tracks_config_and_source_changes(tmp_path):
    project = make_project(tmp_path)
    config_path = project / "zscope.yaml"
    first = compute_input_fingerprint(config_path, scan_depth=None)
    second = compute_input_fingerprint(config_path, scan_depth=None)
    assert first["sha256"] == second["sha256"]
    assert first["project_id"]
    (project / "src" / "util.c").write_text("int util(void) { return 1; }\n", encoding="utf-8")
    changed = compute_input_fingerprint(config_path, scan_depth=None)
    assert changed["sha256"] != first["sha256"]
    names = diff_components(first["components"], changed["components"])
    assert any(name.startswith("source_manifest") for name in names)


def test_fingerprint_missing_config_is_503(tmp_path):
    with pytest.raises(JobError) as excinfo:
        compute_input_fingerprint(tmp_path / "nope.yaml", scan_depth=None)
    assert excinfo.value.code == "config_unavailable"
    assert excinfo.value.status_code == 503


@needs_proc
def test_identity_probe_distinguishes_alive_dead_and_recycled():
    ticks = identity.self_start_ticks()
    assert isinstance(ticks, int) and ticks > 0
    assert identity.probe_process(os.getpid(), expected_start_ticks=ticks) is True
    assert identity.probe_process(os.getpid(), expected_start_ticks=ticks + 10_000_000) is False
    assert identity.probe_process(os.getpid(), expected_start_ticks=None) is None
    assert identity.probe_process(None, expected_start_ticks=ticks) is None
    assert identity.probe_process(2**30, expected_start_ticks=ticks) is False
    assert identity.system_boot_id()


# ---------------------------------------------------------------------------
# runner helpers


def test_build_cli_command_shape():
    command = build_cli_command(Path("/p/zscope.yaml"), None, "/usr/bin/python3")
    assert command == ["/usr/bin/python3", "-m", "zscope.cli.cli", "-c", "/p/zscope.yaml"]
    command = build_cli_command(Path("/p/zscope.yaml"), "deep", "/usr/bin/python3")
    assert command[-2:] == ["--scan-depth", "deep"]


def test_write_launch_file_roundtrip(tmp_path):
    target = tmp_path / "launch.json"
    # 2026-10-14T22:00:00+08:00 == 2026-10-14T14:00:00+00:00 -> epoch 1791986400.
    expected_epoch = datetime(
        2026, 10, 14, 22, 0, 0, tzinfo=timezone(timedelta(hours=8))
    ).timestamp()
    assert expected_epoch == 1791986400.0
    write_launch_file(
        target,
        job_id="job_x",
        run_id="run_x",
        owner_token="tok",
        argv=["python", "-c", "pass"],
        cwd="/tmp",
        report_candidates=["/tmp/report.json"],
        stop_at_epoch=expected_epoch,
        resolved_stop_time="2026-10-14T14:00:00+00:00",
    )
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["schema"] == "zscope.scan-job-launch.v1"
    assert payload["job_id"] == "job_x"
    assert payload["argv"] == ["python", "-c", "pass"]
    assert payload["stop_at_epoch"] == expected_epoch


# ---------------------------------------------------------------------------
# service: contract envelope (no owner spawning)


def test_start_creates_queued_job_with_contract_envelope(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-1")
    assert job["status"] == "queued"
    assert job["phase"] == "queued"
    assert job["revision"] == 1
    assert job["job_id"].startswith("job_")
    assert job["run_id"].startswith("run_")
    assert job["input_revision"]
    assert job["started_at"] is None
    assert job["resolved_stop_time"] is None
    assert job["progress"] == null_progress()
    assert job["coverage"]["completeness"] is None
    assert job["coverage"]["gaps"] == []
    assert job["pending_count"] is None
    assert job["questions"] == []
    assert job["report"] == {"available": False, "report_id": None, "path": None}
    assert job["owner"]["process_id"] is None
    assert job["capabilities"]["cancel"] is True
    assert job["capabilities"]["resume"] is False
    assert job["error"] is None


def test_start_with_stop_at_resolves_to_utc(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, stop_at="2026-10-14T22:00:00+08:00", request_id="req-stop")
    assert job["resolved_stop_time"] == "2026-10-14T14:00:00+00:00"
    stored = store_for(project).get_job(job["job_id"])
    expected = datetime(2026, 10, 14, 22, 0, 0, tzinfo=timezone(timedelta(hours=8)))
    assert stored["stop_at_epoch"] == expected.timestamp()
    assert stored["requested_stop_at"] == "2026-10-14T22:00:00+08:00"


def test_start_rejects_invalid_requests(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    response = service.start(scan_depth="nightly", request_id="req-x")
    assert response.status_code == 400
    assert response.payload["code"] == "invalid_request"
    response = service.start(request_id="")
    assert response.status_code == 400
    response = service.start(stop_at="2026-10-14T22:00:00", request_id="req-naive")
    assert response.status_code == 400
    assert "timezone" in response.payload["error"]
    assert service.list().payload["jobs"] == []


def test_start_replay_is_idempotent_and_conflict_detected(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    first = start_job(service, scan_depth="fast", request_id="req-idem")
    replay = service.start(scan_depth="fast", request_id="req-idem")
    assert replay.status_code == 202
    assert replay.payload["job"]["job_id"] == first["job_id"]
    assert replay.payload["job"]["run_id"] == first["run_id"]
    assert len(service.list().payload["jobs"]) == 1
    conflict = service.start(scan_depth="deep", request_id="req-idem")
    assert conflict.status_code == 409
    assert conflict.payload["code"] == "request_id_conflict"


def test_start_mutex_blocks_second_active_job(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    first = start_job(service, request_id="req-a")
    response = service.start(request_id="req-b")
    assert response.status_code == 409
    assert response.payload["code"] == "project_scan_active"
    assert response.payload["details"]["active_job_id"] == first["job_id"]
    listing = service.list().payload
    assert listing["capabilities"]["create"] is False
    assert listing["capabilities"]["reasons"][0]["code"] == "project_scan_active"
    assert listing["latest_job_id"] == first["job_id"]


def test_detail_unknown_and_malformed_ids(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    response = service.detail("job_nope")
    assert response.status_code == 404
    assert response.payload["code"] == "job_not_found"
    response = service.detail("  ")
    assert response.status_code == 400


def test_events_endpoint_pages_real_events(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-ev")
    response = service.events(job["job_id"], 0)
    assert response.status_code == 200
    payload = response.payload
    assert payload["schema"] == SCHEMA_VERSION
    assert payload["job_id"] == job["job_id"]
    kinds = [event["kind"] for event in payload["events"]]
    assert "job_created" in kinds
    assert payload["events"][0]["run_id"] == job["run_id"]
    assert payload["next_seq"] == payload["events"][-1]["seq"]
    assert payload["has_more"] is False
    follow_up = service.events(job["job_id"], payload["next_seq"])
    assert follow_up.payload["events"] == []
    assert follow_up.payload["next_seq"] == payload["next_seq"]
    assert service.events(job["job_id"], -1).status_code == 400
    assert service.events("job_nope", 0).status_code == 404


def test_cancel_validates_revision_and_state(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-c")
    response = service.cancel(job["job_id"], base_revision=99, request_id="req-cancel-1")
    assert response.status_code == 409
    assert response.payload["code"] == "revision_conflict"
    assert response.payload["details"]["current_revision"] == job["revision"]
    response = service.cancel(
        job["job_id"], base_revision=job["revision"], request_id="req-cancel-1"
    )
    assert response.status_code == 200
    # This queued job has no owner (spawn_owner=False): nothing could ever
    # observe a cancel flag, so the marker transaction finalizes it to the
    # honest cancelled terminal state instead of leaving it stuck.
    assert response.payload["job"]["status"] == "cancelled"
    stored = store_for(project).get_job(job["job_id"])
    assert stored["cancel_requested_at"] is not None
    events = service.events(job["job_id"], 0).payload["events"]
    assert any(event["kind"] == "cancel_requested" for event in events)
    # Replaying the same cancel request returns the recorded outcome again.
    replay = service.cancel(job["job_id"], base_revision=job["revision"], request_id="req-cancel-1")
    assert replay.status_code == 200
    # The same request id with a different revision is a conflict.
    conflict = service.cancel(
        job["job_id"], base_revision=job["revision"] + 1, request_id="req-cancel-1"
    )
    assert conflict.status_code == 409
    assert conflict.payload["code"] == "request_id_conflict"
    # A terminal job cannot be cancelled.
    terminal = force_status(store_for(project), job["job_id"], "completed")
    response = service.cancel(
        job["job_id"], base_revision=terminal["revision"], request_id="req-cancel-2"
    )
    assert response.status_code == 409
    assert response.payload["code"] == "invalid_state"


def test_resume_requires_resumable_state_and_matching_revision(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-r")
    response = service.resume(job["job_id"], base_revision=1, request_id="req-resume-1")
    assert response.status_code == 409
    assert response.payload["code"] == "invalid_state"
    cancelled = force_status(store_for(project), job["job_id"], "cancelled")
    response = service.resume(job["job_id"], base_revision=1, request_id="req-resume-2")
    assert response.status_code == 409
    assert response.payload["code"] == "revision_conflict"
    response = service.resume(
        job["job_id"], base_revision=cancelled["revision"], request_id="req-resume-2"
    )
    assert response.status_code == 202
    resumed = response.payload["job"]
    assert resumed["job_id"] == job["job_id"]
    assert resumed["run_id"] != job["run_id"]
    assert resumed["status"] == "queued"
    assert resumed["revision"] > cancelled["revision"]
    # Per-attempt windows are not carried over.
    assert resumed["resolved_stop_time"] is None
    replay = service.resume(
        job["job_id"], base_revision=cancelled["revision"], request_id="req-resume-2"
    )
    assert replay.status_code == 202
    assert replay.payload["job"]["run_id"] == resumed["run_id"]
    events = service.events(job["job_id"], 0).payload["events"]
    assert any(event["kind"] == "attempt_started" for event in events)


def test_resume_after_input_change_revokes_previous_binding(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-ic")
    cancelled = force_status(store_for(project), job["job_id"], "cancelled")
    (project / "src" / "main.c").write_text("int main(void) { return 42; }\n", encoding="utf-8")
    # A reconnecting client holds no in-process fingerprint cache.
    reconnected = make_service(project)
    response = reconnected.resume(
        job["job_id"], base_revision=cancelled["revision"], request_id="req-ic-resume"
    )
    assert response.status_code == 202
    resumed = response.payload["job"]
    assert resumed["input_revision"] != job["input_revision"]
    events = reconnected.events(job["job_id"], 0).payload["events"]
    revoked = [event for event in events if event["kind"] == "input_revoked"]
    assert revoked, "input change must be recorded before the new attempt starts"
    assert revoked[0]["data"]["previous"] == job["input_revision"]
    assert revoked[0]["data"]["current"] == resumed["input_revision"]
    assert any(name.startswith("source_manifest") for name in revoked[0]["data"]["components"])


def test_same_instance_resume_detects_source_change_without_scan_depth(tmp_path):
    # F4 regression: with scan_depth omitted the config stat does not change
    # when only sources are edited, yet the same service instance must bind
    # the fresh input on resume — a config-stat cache may never authorize a
    # new attempt's input binding.
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-f4-src")
    assert job["input_revision"]
    cancelled = force_status(store_for(project), job["job_id"], "cancelled")
    (project / "src" / "main.c").write_text("int main(void) { return 42; }\n", encoding="utf-8")
    response = service.resume(
        job["job_id"], base_revision=cancelled["revision"], request_id="req-f4-src-r"
    )
    assert response.status_code == 202
    resumed = response.payload["job"]
    assert resumed["input_revision"] != job["input_revision"]
    events = service.events(job["job_id"], 0).payload["events"]
    revoked = [event for event in events if event["kind"] == "input_revoked"]
    assert revoked
    assert revoked[0]["data"]["previous"] == job["input_revision"]
    assert revoked[0]["data"]["current"] == resumed["input_revision"]
    assert any(name.startswith("source_manifest") for name in revoked[0]["data"]["components"])


def test_same_instance_resume_detects_header_change(tmp_path):
    # Header files are part of the source manifest, not of the config stat.
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-f4-hdr")
    cancelled = force_status(store_for(project), job["job_id"], "cancelled")
    (project / "src" / "util.h").write_text("#define UTIL_LIMIT 8\n", encoding="utf-8")
    response = service.resume(
        job["job_id"], base_revision=cancelled["revision"], request_id="req-f4-hdr-r"
    )
    assert response.status_code == 202
    resumed = response.payload["job"]
    assert resumed["input_revision"] != job["input_revision"]


def test_same_instance_resume_detects_build_input_change(tmp_path):
    # compile_commands.json is a declared build input; changing its content
    # leaves the config bytes untouched but must revoke the old binding.
    project = make_build_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-f4-build")
    cancelled = force_status(store_for(project), job["job_id"], "cancelled")
    (project / "build" / "compile_commands.json").write_text(
        json.dumps(
            [{"directory": str(project), "command": "cc -c src/main.c", "file": "src/main.c"}]
        ),
        encoding="utf-8",
    )
    response = service.resume(
        job["job_id"], base_revision=cancelled["revision"], request_id="req-f4-build-r"
    )
    assert response.status_code == 202
    resumed = response.payload["job"]
    assert resumed["input_revision"] != job["input_revision"]
    events = service.events(job["job_id"], 0).payload["events"]
    revoked = [event for event in events if event["kind"] == "input_revoked"]
    assert revoked
    assert any(name.startswith("compile_commands") for name in revoked[0]["data"]["components"])


def test_same_instance_resume_without_input_change_is_idempotent(tmp_path):
    # Negative control: unchanged inputs keep the binding stable and emit no
    # input_revoked event, on the same instance and with scan_depth omitted.
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-f4-same")
    cancelled = force_status(store_for(project), job["job_id"], "cancelled")
    response = service.resume(
        job["job_id"], base_revision=cancelled["revision"], request_id="req-f4-same-r"
    )
    assert response.status_code == 202
    resumed = response.payload["job"]
    assert resumed["input_revision"] == job["input_revision"]
    events = service.events(job["job_id"], 0).payload["events"]
    assert not [event for event in events if event["kind"] == "input_revoked"]


def test_same_instance_start_after_source_change_binds_fresh_input(tmp_path):
    # The start path binds the fresh input even when scan_depth is omitted
    # and the config stat is unchanged (F4).
    project = make_project(tmp_path)
    service = make_service(project)
    first = start_job(service, request_id="req-f4-start-a")
    force_status(store_for(project), first["job_id"], "cancelled")
    (project / "src" / "main.c").write_text("int main(void) { return 7; }\n", encoding="utf-8")
    second = start_job(service, request_id="req-f4-start-b")
    assert second["input_revision"] != first["input_revision"]


def test_result_reports_reason_without_inventing_findings(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-res")
    response = service.result(job["job_id"])
    assert response.status_code == 200
    payload = response.payload
    assert payload["report_available"] is False
    assert payload["report_id"] is None
    assert payload["reason"] == "job_status:queued"
    assert payload["findings"] is None
    assert payload["coverage"]["completeness"] is None
    store = store_for(project)
    current = store.get_job(job["job_id"])
    store.update_job(
        job["job_id"],
        expected_revision=int(current["revision"]),
        updates={
            "status": "failed",
            "report_json": {"available": False, "reason": "report_not_produced"},
            "error_code": "scan_failed",
            "error_message": "scanner exited with code 3",
        },
    )
    payload = service.result(job["job_id"]).payload
    assert payload["reason"] == "report_not_produced"
    detail = service.detail(job["job_id"]).payload["job"]
    assert detail["error"] == {"code": "scan_failed", "message": "scanner exited with code 3"}


def test_result_revalidates_bound_report_bytes(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-tamper")
    store = store_for(project)
    report_path = project / "bound_report.json"
    report_payload = {"completeness": "complete", "metadata": {"build_coverage": {"a": 1}}}
    report_path.write_text(json.dumps(report_payload), encoding="utf-8")
    digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
    current = store.get_job(job["job_id"])
    store.update_job(
        job["job_id"],
        expected_revision=int(current["revision"]),
        updates={
            "status": "completed",
            "report_json": {
                "available": True,
                "report_id": digest,
                "path": str(report_path),
            },
        },
    )
    payload = service.result(job["job_id"]).payload
    assert payload["report_available"] is True
    assert payload["report_id"] == digest
    assert payload["reason"] is None
    loaded = service.load_bound_report(job["job_id"])
    assert loaded is not None
    parsed, bound_path = loaded
    assert bound_path == report_path
    assert parsed["completeness"] == "complete"
    # Tampered bytes revoke availability; the stale JSON never speaks for itself.
    report_path.write_text(json.dumps({"completeness": "tampered"}), encoding="utf-8")
    payload = service.result(job["job_id"]).payload
    assert payload["report_available"] is False
    assert payload["reason"] == "report_artifact_mismatch"
    assert service.load_bound_report(job["job_id"]) is None
    report_path.unlink()
    payload = service.result(job["job_id"]).payload
    assert payload["reason"] == "report_artifact_missing"


# ---------------------------------------------------------------------------
# report binding: real shared-json.v1 object graphs (write_report_atomic)


def _owner_for_binding(project: Path, job: dict, tmp_path: Path) -> tuple[Owner, JobStore]:
    store = store_for(project)
    run_dir = store.db_path.parent / job["job_id"] / job["run_id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    owner = Owner(
        store=store,
        job_id=job["job_id"],
        run_id=job["run_id"],
        run_dir=run_dir,
        launch_path=run_dir / "launch.json",
        token=store.get_job(job["job_id"])["owner_token"],
    )
    owner.launch = {"report_candidates": [str(tmp_path / "zscope_batch_report.json")]}
    return owner, store


def test_owner_binds_real_shared_json_report_and_extracts_projection(tmp_path):
    # The real writer always produces a zscope.shared-json.v1 object graph;
    # the owner must decode it (not read the storage envelope as the report)
    # and keep the artifact bytes untouched.
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-shared-bind")
    owner, store = _owner_for_binding(project, job, tmp_path)
    source = tmp_path / "zscope_batch_report.json"
    baseline = {str(source): None}  # no report existed when the attempt started
    write_report_atomic(source, SHARED_REPORT)
    info = owner._bind_report(baseline)
    assert info["available"] is True
    bound = Path(info["path"])
    assert bound == owner.run_dir / "report.json"
    raw = json.loads(bound.read_text(encoding="utf-8"))
    assert raw["storage_schema"] == "zscope.shared-json.v1"
    assert info["report_id"] == hashlib.sha256(bound.read_bytes()).hexdigest()
    # The decoded logical report drives the coverage/questions projection.
    parsed = info["_parsed"]
    assert parsed["completeness"] == "incomplete"
    coverage = merge_coverage(parsed)
    assert coverage["completeness"] == "incomplete"
    assert coverage["build_coverage"] == {"selected_tus": 2, "total_tus": 3}
    assert coverage["gaps"] == [{"kind": "tu_missing", "path": "src/extra.c"}]
    assert coverage["deferred_count"] == 4
    questions = extract_questions(parsed)
    assert [question["id"] for question in questions] == ["q9"]
    events = service.events(job["job_id"], 0).payload["events"]
    assert any(event["kind"] == "report_bound" for event in events)


def test_owner_rejects_corrupt_shared_json_graph(tmp_path):
    # A missing reference or a wrong object digest rejects the binding; the
    # corrupt artifact is never presented as this attempt's result.
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-shared-corrupt")
    owner, _ = _owner_for_binding(project, job, tmp_path)
    source = tmp_path / "zscope_batch_report.json"
    write_report_atomic(source, SHARED_REPORT)
    _corrupt_shared_json_graph(source)
    info = owner._bind_report({str(source): None})
    assert info["available"] is False
    assert info["report_id"] is None
    assert info["reason"] == "report_not_produced"
    events = service.events(job["job_id"], 0).payload["events"]
    unreadable = [event for event in events if event["kind"] == "report_unreadable"]
    assert unreadable


def test_load_bound_report_decodes_shared_json_and_preserves_fields(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-shared-load")
    store = store_for(project)
    run_dir = store.db_path.parent / job["job_id"] / job["run_id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    bound = run_dir / "report.json"
    write_report_atomic(bound, SHARED_REPORT)
    digest = hashlib.sha256(bound.read_bytes()).hexdigest()
    current = store.get_job(job["job_id"])
    store.update_job(
        job["job_id"],
        expected_revision=int(current["revision"]),
        updates={
            "status": "completed",
            "report_json": {"available": True, "report_id": digest, "path": str(bound)},
            # What the owner would have stored from the decoded report.
            "coverage_json": merge_coverage(read_report(bound)),
            "questions_json": extract_questions(read_report(bound)),
            "pending_count": 1,
        },
    )
    result = service.result(job["job_id"]).payload
    assert result["report_available"] is True
    assert result["report_id"] == digest
    assert result["reason"] is None
    assert result["coverage"]["completeness"] == "incomplete"
    assert result["coverage"]["build_coverage"] == {"selected_tus": 2, "total_tus": 3}
    assert result["coverage"]["gaps"] == [{"kind": "tu_missing", "path": "src/extra.c"}]
    assert result["coverage"]["deferred_count"] == 4
    assert [question["id"] for question in result["questions"]] == ["q9"]
    loaded = service.load_bound_report(job["job_id"])
    assert loaded is not None
    parsed, bound_path = loaded
    assert bound_path == bound
    assert parsed["completeness"] == "incomplete"
    assert parsed["issues"] == [{"id": "iss-1", "rule": "demo_rule"}]
    assert parsed["metadata"]["build_coverage"] == {"selected_tus": 2, "total_tus": 3}
    assert parsed["metadata"]["deferred_count"] == 4


def test_load_bound_report_rejects_corrupt_graph_with_intact_hash(tmp_path):
    # Byte-level integrity alone is not enough: a graph whose object digest
    # does not match its reference is rejected even when the recorded hash
    # matches the (corrupt) bytes.
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-shared-hashok")
    store = store_for(project)
    run_dir = store.db_path.parent / job["job_id"] / job["run_id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    bound = run_dir / "report.json"
    write_report_atomic(bound, SHARED_REPORT)
    _corrupt_shared_json_graph(bound)
    digest = hashlib.sha256(bound.read_bytes()).hexdigest()
    current = store.get_job(job["job_id"])
    store.update_job(
        job["job_id"],
        expected_revision=int(current["revision"]),
        updates={
            "status": "completed",
            "report_json": {"available": True, "report_id": digest, "path": str(bound)},
        },
    )
    result = service.result(job["job_id"]).payload
    assert result["report_available"] is False
    assert result["reason"] == "report_artifact_corrupt"
    assert service.load_bound_report(job["job_id"]) is None


def test_parallel_projects_have_independent_stores_and_mutexes(tmp_path):
    # DYN07: two projects scanned in parallel must not share job state.
    project_a = make_project(tmp_path, name="project_a")
    project_b = make_project(tmp_path, name="project_b")
    service_a = make_service(project_a)
    service_b = make_service(project_b)
    job_a = start_job(service_a, request_id="req-a")
    response_b = service_b.start(request_id="req-b")
    assert response_b.status_code == 202
    job_b = response_b.payload["job"]
    assert job_a["job_id"] != job_b["job_id"]
    assert [j["job_id"] for j in service_a.list().payload["jobs"]] == [job_a["job_id"]]
    assert [j["job_id"] for j in service_b.list().payload["jobs"]] == [job_b["job_id"]]
    assert store_for(project_a).db_path != store_for(project_b).db_path
    # A restarted service instance reconnects to the persisted state (JOB01).
    reconnected_a = make_service(project_a)
    assert [j["job_id"] for j in reconnected_a.list().payload["jobs"]] == [job_a["job_id"]]
    detail = reconnected_a.detail(job_a["job_id"]).payload["job"]
    assert detail["run_id"] == job_a["run_id"]


def test_reconcile_marks_job_lost_when_owner_verifiably_dead(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-lost")
    store = store_for(project)
    current = store.get_job(job["job_id"])
    store.update_job(
        job["job_id"],
        expected_revision=int(current["revision"]),
        updates={"owner_pid": 2**30, "status": "running", "phase": "scanning"},
    )
    # A mid-flight owner always recorded its attempt before vanishing.
    store.record_attempt(
        {
            "job_id": job["job_id"],
            "run_id": job["run_id"],
            "attempt_no": 1,
            "status": "running",
            "input_revision": job["input_revision"],
            "started_at": utc_now_iso(),
        }
    )
    detail = service.detail(job["job_id"]).payload["job"]
    assert detail["status"] == "lost"
    assert detail["error"]["code"] == "owner_lost"
    assert detail["owner"]["state"] == "exited"
    assert detail["capabilities"]["resume"] is True
    events = service.events(job["job_id"], 0).payload["events"]
    assert any(event["kind"] == "owner_lost" for event in events)
    attempts = store.list_attempts(job["job_id"])
    assert attempts and attempts[-1]["status"] == "lost"


@needs_proc
def test_reconcile_keeps_job_while_owner_identity_verified(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-alive")
    store = store_for(project)
    sleeper = os.spawnvp(os.P_NOWAIT, "/bin/sh", ["sh", "-c", "exec sleep 300"])
    try:
        time.sleep(0.3)
        ticks = identity.read_process_start_ticks(sleeper)
        assert ticks is not None
        current = store.get_job(job["job_id"])
        store.update_job(
            job["job_id"],
            expected_revision=int(current["revision"]),
            updates={"owner_pid": sleeper, "owner_start_ticks": ticks},
        )
        detail = service.detail(job["job_id"]).payload["job"]
        assert detail["status"] == "queued"
        assert detail["owner"] == {"state": "alive", "process_id": sleeper}
        # A live process whose start time does not match the recorded identity
        # is a recycled PID: it must not count as the owner (JOB05).
        store.record_attempt(
            {
                "job_id": job["job_id"],
                "run_id": job["run_id"],
                "attempt_no": 1,
                "status": "running",
                "input_revision": job["input_revision"],
                "started_at": utc_now_iso(),
            }
        )
        current = store.get_job(job["job_id"])
        store.update_job(
            job["job_id"],
            expected_revision=int(current["revision"]),
            updates={"owner_start_ticks": ticks + 10_000_000},
        )
        detail = service.detail(job["job_id"]).payload["job"]
        assert detail["status"] == "lost"
        assert detail["owner"]["state"] == "exited"
    finally:
        os.kill(sleeper, 9)
        os.waitpid(sleeper, 0)


def test_spawn_failure_marks_job_failed_instead_of_faking_success(tmp_path):
    project = make_project(tmp_path)
    service = ScanJobService(
        project / "zscope.yaml",
        spawn_owner=True,
        python_executable=str(tmp_path / "no-such-python"),
    )
    response = service.start(request_id="req-spawn")
    # Contract: an owner that cannot be spawned is a 503 owner_spawn_failed
    # envelope, never a 500 and never a fake success.  The job row keeps the
    # honest failed terminal state and an attempt row bound to the input.
    assert response.status_code == 503
    assert response.payload["code"] == "owner_spawn_failed"
    jobs = service.list().payload["jobs"]
    assert len(jobs) == 1
    assert jobs[0]["status"] == "failed"
    assert jobs[0]["error"]["code"] == "owner_spawn_failed"
    assert jobs[0]["owner"]["process_id"] is None
    assert jobs[0]["report"]["available"] is False
    attempts = store_for(project).list_attempts(jobs[0]["job_id"])
    assert attempts and attempts[-1]["status"] == "failed"
    assert attempts[-1]["input_revision"] == jobs[0]["input_revision"]
    assert attempts[-1]["error_code"] == "owner_spawn_failed"


def test_reconcile_lost_without_attempt_row_persists_honest_terminal(tmp_path):
    # The owner died before recording its attempt (killed between spawn and
    # its first store write): no attempt row exists.  Reconcile must persist
    # the honest lost terminal state — including an attempt row backfilled
    # from the job's input binding — instead of failing on the NOT NULL
    # attempts.input_revision column.
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-lost-noattempt")
    store = store_for(project)
    current = store.get_job(job["job_id"])
    store.update_job(
        job["job_id"],
        expected_revision=int(current["revision"]),
        updates={"owner_pid": 2**30, "status": "running", "phase": "scanning"},
    )
    detail = service.detail(job["job_id"]).payload["job"]
    assert detail["status"] == "lost"
    assert detail["error"]["code"] == "owner_lost"
    assert detail["capabilities"]["resume"] is True
    attempts = store.list_attempts(job["job_id"])
    assert attempts and attempts[-1]["status"] == "lost"
    assert attempts[-1]["input_revision"] == job["input_revision"]
    events = service.events(job["job_id"], 0).payload["events"]
    assert any(event["kind"] == "owner_lost" for event in events)


@needs_proc
def test_probe_treats_unreaped_zombie_as_gone():
    # A zombie's /proc/<pid>/stat stays readable until the parent reaps it;
    # the exit must still count as verifiably gone, not alive.
    child = _spawn_zombie()
    try:
        ticks = identity.read_process_start_ticks(child.pid)
        assert ticks is not None
        assert identity.probe_process(child.pid, expected_start_ticks=ticks) is False
        assert identity.probe_process(child.pid, expected_start_ticks=ticks + 10_000_000) is False
    finally:
        child.wait()


@needs_proc
def test_reconcile_marks_zombie_owner_lost_without_reaping(tmp_path):
    # F3: the service is alive but has not reaped its killed owner; the
    # zombie owner must still be recognized as gone while the job is active.
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-zombie-owner")
    store = store_for(project)
    zombie = _spawn_zombie()
    try:
        ticks = identity.read_process_start_ticks(zombie.pid)
        assert ticks is not None
        current = store.get_job(job["job_id"])
        store.update_job(
            job["job_id"],
            expected_revision=int(current["revision"]),
            updates={
                "owner_pid": zombie.pid,
                "owner_start_ticks": ticks,
                "status": "running",
                "phase": "scanning",
            },
        )
        detail = service.detail(job["job_id"]).payload["job"]
        assert detail["status"] == "lost"
        assert detail["error"]["code"] == "owner_lost"
        assert detail["owner"]["state"] == "exited"
        attempts = store.list_attempts(job["job_id"])
        assert attempts and attempts[-1]["status"] == "lost"
        assert attempts[-1]["input_revision"] == job["input_revision"]
    finally:
        zombie.wait()


@needs_proc
def test_spawn_owner_records_startup_identity_at_spawn(tmp_path):
    # The service records the precise (pid, start_ticks, boot_id) identity at
    # spawn time, so an owner that dies before publishing its own identity
    # is still verifiable by reconcile.
    project = make_project(tmp_path)
    store = store_for(project)
    store.initialize()
    job = create_row(store, job_id="job_spawnid", run_id="run_spawnid")
    run_dir = store.db_path.parent / "job_spawnid" / "run_spawnid"
    run_dir.mkdir(parents=True)
    launch = run_dir / "launch.json"
    write_launch_file(
        launch,
        job_id="job_spawnid",
        run_id="run_spawnid",
        owner_token="tok",
        argv=[sys.executable, "-c", "pass"],
        cwd=str(tmp_path),
        report_candidates=[],
        stop_at_epoch=None,
        resolved_stop_time=None,
    )
    sleeper = tmp_path / "sleeper.py"
    sleeper.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n", encoding="utf-8")
    sleeper.chmod(0o755)
    service = ScanJobService(
        project / "zscope.yaml",
        python_executable=str(sleeper),
        spawn_owner=True,
    )
    service._spawn_owner(store=store, job=job, run_dir=run_dir, launch_path=launch)
    row = store.get_job("job_spawnid")
    assert isinstance(row["owner_pid"], int)
    assert row["owner_start_ticks"] == identity.read_process_start_ticks(row["owner_pid"])
    assert row["owner_boot_id"] == identity.system_boot_id()
    os.kill(row["owner_pid"], signal.SIGKILL)
    os.waitpid(row["owner_pid"], 0)


# ---------------------------------------------------------------------------
# request reservation atomicity (R5): duplicates replay, never double-start


def test_concurrent_same_key_start_reserves_exactly_one_job(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    barrier = threading.Barrier(4)
    results: list = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        response = service.start(request_id="req-concurrent")
        with lock:
            results.append((response.status_code, response.payload["job"]["job_id"]))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert len(results) == 4
    assert {status for status, _ in results} == {202}
    assert len({job_id for _, job_id in results}) == 1
    assert len(service.list().payload["jobs"]) == 1


def test_start_conflicting_payload_creates_no_side_effects(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    first = start_job(service, scan_depth="fast", request_id="req-conflict")
    response = service.start(scan_depth="deep", request_id="req-conflict")
    assert response.status_code == 409
    assert response.payload["code"] == "request_id_conflict"
    jobs = service.list().payload["jobs"]
    assert len(jobs) == 1 and jobs[0]["job_id"] == first["job_id"]
    # No phantom launch side effects: only the first job's directory exists.
    store = store_for(project)
    job_dirs = [p.name for p in store.db_path.parent.iterdir() if p.is_dir()]
    assert job_dirs == [first["job_id"]]


def test_request_key_reused_across_endpoints_is_rejected(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-cross")
    resume = service.resume(job["job_id"], base_revision=job["revision"], request_id="req-cross")
    assert resume.status_code == 409 and resume.payload["code"] == "request_id_conflict"
    cancel = service.cancel(job["job_id"], base_revision=job["revision"], request_id="req-cross")
    assert cancel.status_code == 409 and cancel.payload["code"] == "request_id_conflict"
    stored = store_for(project).get_job(job["job_id"])
    assert stored is not None
    assert stored["cancel_requested_at"] is None
    assert stored["status"] == "queued"


def test_spawn_failure_resend_replays_failed_job(tmp_path):
    # A real spawn failure keeps identity and reason; resending the same
    # request replays the failed job instead of starting another attempt.
    project = make_project(tmp_path)
    service = ScanJobService(
        project / "zscope.yaml",
        spawn_owner=True,
        python_executable=str(tmp_path / "no-such-python"),
    )
    first = service.start(request_id="req-spawn-resend")
    assert first.status_code == 503
    assert first.payload["code"] == "owner_spawn_failed"
    resend = service.start(request_id="req-spawn-resend")
    assert resend.status_code == 202
    replayed = resend.payload["job"]
    jobs = service.list().payload["jobs"]
    assert len(jobs) == 1 and replayed["job_id"] == jobs[0]["job_id"]
    assert replayed["status"] == "failed"
    assert replayed["error"]["code"] == "owner_spawn_failed"
    assert "no-such-python" in replayed["error"]["message"]
    attempts = store_for(project).list_attempts(replayed["job_id"])
    assert len(attempts) == 1 and attempts[0]["status"] == "failed"
    kinds = [event["kind"] for event in service.events(replayed["job_id"], 0).payload["events"]]
    assert kinds.count("job_created") == 1
    assert any(kind == "request_replayed" for kind in kinds)


def test_cancel_finalizes_queued_job_without_owner_and_replays(tmp_path):
    # A queued job whose owner was never spawned has nothing to observe a
    # cancel flag: the marker transaction finalizes the honest cancelled
    # state, keeps the attempt bound to the input and frees the mutex.
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-qc")
    response = service.cancel(job["job_id"], base_revision=job["revision"], request_id="req-qc-op")
    assert response.status_code == 200
    cancelled = response.payload["job"]
    assert cancelled["status"] == "cancelled"
    assert cancelled["error"]["code"] == "cancelled"
    assert cancelled["capabilities"]["resume"] is True
    store = store_for(project)
    stored = store.get_job(job["job_id"])
    assert stored is not None and stored["cancel_requested_at"] is not None
    attempts = store.list_attempts(job["job_id"])
    assert attempts and attempts[-1]["status"] == "cancelled"
    assert attempts[-1]["input_revision"] == job["input_revision"]
    kinds = [event["kind"] for event in service.events(job["job_id"], 0).payload["events"]]
    assert "cancel_requested" in kinds and "job_terminal" in kinds
    # The mutex is free again: a fresh request starts a new job.
    second = start_job(service, request_id="req-qc-2")
    assert second["job_id"] != job["job_id"]
    # A duplicate cancel replays the recorded outcome.
    replay = service.cancel(job["job_id"], base_revision=job["revision"], request_id="req-qc-op")
    assert replay.status_code == 200
    assert replay.payload["job"]["job_id"] == job["job_id"]
    assert replay.payload["job"]["status"] == "cancelled"
    # And the replay started nothing new for the original job.
    assert len(store.list_attempts(job["job_id"])) == 1


def test_duplicate_resume_replays_armed_attempt_once(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-rd")
    cancelled = force_status(store_for(project), job["job_id"], "cancelled")
    first = service.resume(
        job["job_id"], base_revision=cancelled["revision"], request_id="req-rd-op"
    )
    assert first.status_code == 202
    armed = first.payload["job"]
    assert armed["run_id"] != job["run_id"]
    # A duplicate resume with the same key replays the armed attempt.
    replay = service.resume(
        job["job_id"], base_revision=cancelled["revision"], request_id="req-rd-op"
    )
    assert replay.status_code == 202
    assert replay.payload["job"]["run_id"] == armed["run_id"]
    events = service.events(job["job_id"], 0).payload["events"]
    assert len([event for event in events if event["kind"] == "attempt_started"]) == 1
    assert any(event["kind"] == "request_replayed" for event in events)
    # Same key, different payload conflicts; a stale base_revision with a
    # fresh key can never arm a second attempt either.
    conflict = service.resume(
        job["job_id"], base_revision=cancelled["revision"] + 1, request_id="req-rd-op"
    )
    assert conflict.status_code == 409
    assert conflict.payload["code"] == "request_id_conflict"
    stale = service.resume(
        job["job_id"], base_revision=cancelled["revision"], request_id="req-rd-op-2"
    )
    assert stale.status_code == 409
    assert stale.payload["code"] == "revision_conflict"


# ---------------------------------------------------------------------------
# scheduler hook contract (JOB04/06 wiring surface)


def _hook_for(project: Path, job: dict) -> JobWindowHook:
    store = store_for(project)
    run_dir = store.db_path.parent / job["job_id"] / job["run_id"]
    row = store.get_job(job["job_id"])
    # The hook is bound to the real attempt: a persisted pending file is
    # authorized by the job row's owner token, not by a placeholder.
    return JobWindowHook(
        store.db_path,
        job_id=job["job_id"],
        run_id=job["run_id"],
        owner_token=row["owner_token"],
        run_dir=run_dir,
        input_revision=job["input_revision"],
    )


def test_hook_stop_new_work_reflects_store_flags(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-hook")
    hook = _hook_for(project, job)
    assert hook.stop_new_work() is False
    assert hook.cancel_requested() is False
    assert hook.deadline_epoch() is None
    store = store_for(project)
    current = store.get_job(job["job_id"])
    store.update_job(
        job["job_id"],
        expected_revision=int(current["revision"]),
        updates={"stop_at_epoch": time.time() - 1.0},
    )
    hook._cached_flags = (0.0, False, None)
    assert hook.stop_new_work() is True
    assert hook.deadline_epoch() is not None
    current = store.get_job(job["job_id"])
    store.update_job(
        job["job_id"],
        expected_revision=int(current["revision"]),
        updates={"cancel_requested_at": utc_now_iso(), "stop_at_epoch": None},
    )
    hook._cached_flags = (0.0, False, None)
    assert hook.cancel_requested() is True
    assert hook.stop_new_work() is True


def test_hook_phase_and_progress_require_matching_run_id(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-hook2")
    hook = _hook_for(project, job)
    hook.note_phase("scanning")
    hook.note_progress(completed=3, total=None, active=1, deferred=None, unit="entries")
    stored = store_for(project).get_job(job["job_id"])
    assert stored["phase"] == "scanning"
    assert stored["progress_json"]["completed"] == 3
    # Unknown denominators stay null; no percentage is invented.
    assert stored["progress_json"]["total"] is None
    stale_hook = JobWindowHook(
        store_for(project).db_path,
        job_id=job["job_id"],
        run_id="run_stale",
        owner_token="tok",
        run_dir=store_for(project).db_path.parent,
    )
    stale_hook.note_phase("hijacked")
    stale_hook.note_progress(completed=99)
    stored = store_for(project).get_job(job["job_id"])
    assert stored["phase"] == "scanning"
    assert stored["progress_json"]["completed"] == 3


def test_hook_persist_pending_bounds_items_and_records_event(tmp_path, monkeypatch):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-hook3")
    hook = _hook_for(project, job)
    monkeypatch.setattr("zscope.orchestration.jobs.scheduler_hook._MAX_PENDING_ITEMS", 3)
    target = hook.persist_pending([{"entry": f"fn{i}"} for i in range(5)], source="test_queue")
    assert target is not None
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["schema"] == "zscope.scan-job-pending.v1"
    assert payload["job_id"] == job["job_id"]
    assert payload["run_id"] == job["run_id"]
    assert payload["capped"] is True
    assert payload["count"] == 3
    assert payload["source"] == "test_queue"
    events = service.events(job["job_id"], 0).payload["events"]
    assert any(event["kind"] == "pending_persisted" for event in events)


def test_job_runtime_output_identity_survives_a_file_vanishing_mid_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A SQLite side file can disappear between the existence check and the stat.

    ``declare()`` compares every declared output against the job's protected inputs
    with ``samefile()``. SQLite creates and removes ``-wal``/``-shm`` beside the job
    database while the scan runs, so the check used to raise
    ``FileNotFoundError: .../jobs.db-wal`` and abort the scan
    (``test_instance_coverage_native_owner_http`` caught it inside an 80-minute run).
    A vanished entry is simply not the same file as anything.
    """

    from zscope.retrieval import indexing_identity

    root = tmp_path / "run"
    root.mkdir()
    protected = root / "jobs.db"
    protected.write_text("db", encoding="utf-8")
    wal = root / "jobs.db-wal"
    wal.write_text("wal", encoding="utf-8")

    raw = {path: state for path, (state, _) in indexing_identity._search_membership([root]).items()}
    view = indexing_identity._RuntimeNamespaceView(raw, (), (protected,), ())

    # A real overlap is still refused before anything touches disk.
    with pytest.raises(ValueError, match="job_runtime_output_input_overlap"):
        view.declare(protected)

    real_samefile = Path.samefile

    def vanish(self: Path, other: Path, *, _real=real_samefile):
        if self.name.endswith("-wal") or self.name.endswith("-shm"):
            raise FileNotFoundError(self)
        return _real(self, other)

    monkeypatch.setattr(Path, "samefile", vanish)
    view.declare(wal)  # used to raise FileNotFoundError
    assert wal in view.files
    # ``current()`` walks the same comparison over every declared output and must
    # not raise either: the raw namespace is untouched, so the recorded proof holds.
    assert view.current(view.raw) is True
