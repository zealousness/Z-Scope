"""Calendar/control-plane tests use an explicit fake engine, never a paid scan."""

from __future__ import annotations

from datetime import datetime
from datetime import timedelta, timezone
import json
from pathlib import Path

import pytest

from zscope.orchestration.jobs.schedules import (
    ScanScheduleService,
    daily_window_at,
    validate_policy,
)
from zscope.orchestration.jobs.service import ServiceResponse


def epoch(value):
    return datetime.fromisoformat(value).timestamp()


class Engine:
    def __init__(self):
        self.fingerprint = "input-a"
        self.jobs = {}
        self.requests = {}
        self.calls = []
        self.busy = False

    def _fingerprint(self, **kwargs):
        return {"sha256": self.fingerprint}

    def require_semantics(self):
        # This explicit fake tests calendar state; real gates are exercised
        # by the shared service and native onboarding tests.
        return None

    def registered_job(self, request_id):
        return self.jobs.get(self.requests.get(request_id))

    def start(self, **kwargs):
        if self.busy:
            return ServiceResponse(409, {"code": "project_scan_active", "error": "busy"})
        self.calls.append(("start", kwargs))
        job = {
            "job_id": "job-a",
            "run_id": "run-1",
            "revision": 1,
            "status": "running",
            "input_revision": self.fingerprint,
        }
        self.jobs[job["job_id"]] = job
        self.requests[kwargs["request_id"]] = job["job_id"]
        return ServiceResponse(202, {"job": dict(job)})

    def resume(self, **kwargs):
        self.calls.append(("resume", kwargs))
        job = self.jobs[kwargs["job_id"]]
        job.update(run_id="run-2", revision=job["revision"] + 1, status="running")
        self.requests[kwargs["request_id"]] = job["job_id"]
        return ServiceResponse(202, {"job": dict(job)})

    def detail(self, job_id):
        return ServiceResponse(200, {"job": dict(self.jobs[job_id])})

    def cancel(self, job_id, **kwargs):
        kwargs["job_id"] = job_id
        self.calls.append(("cancel", kwargs))
        self.jobs[kwargs["job_id"]].update(status="stopping")
        return self.detail(kwargs["job_id"])


def service(tmp_path, now="2026-10-24T12:00:00+08:00"):
    clock = [epoch(now)]
    engine = Engine()
    value = ScanScheduleService(
        tmp_path / "zscope.yaml", engine=engine, spawn_daemon=False, clock=lambda: clock[0]
    )
    return value, engine, clock


def create(value, **kwargs):
    reply = value.create(
        request_id="schedule-test", scan_depth="balanced", end_mode="complete", **kwargs
    )
    assert reply.status_code == 202, reply.payload
    return reply.payload["schedule"]


def current(value):
    return value.list().payload["schedules"][0]


def test_future_start_is_durable_and_does_not_run_early(tmp_path):
    value, engine, clock = service(tmp_path)
    create(value, start_at="2026-10-24T20:00:00+08:00")
    value.tick()
    assert not engine.calls
    restarted = ScanScheduleService(
        value.config_path, engine=engine, spawn_daemon=False, clock=lambda: clock[0]
    )
    clock[0] = epoch("2026-10-24T20:00:00+08:00")
    restarted.tick()
    restarted.tick()
    assert [call[0] for call in engine.calls] == ["start"]
    assert engine.calls[0][1]["ignore_config_window"] is True
    assert engine.calls[0][1]["stop_at"] is None
    assert current(restarted)["status"] == "running"


def test_daily_overnight_resumes_same_job_with_fresh_next_window(tmp_path):
    value, engine, clock = service(tmp_path)
    create(value, daily_window={"timezone": "Asia/Taipei", "start": "23:00", "end": "08:00"})
    value.tick()
    assert not engine.calls
    clock[0] = epoch("2026-10-24T23:00:00+08:00")
    value.tick()
    assert engine.calls[0][1]["stop_at"] == "2026-10-25T00:00:00+00:00"
    engine.jobs["job-a"]["status"] = "partial"
    clock[0] = epoch("2026-10-25T08:00:00+08:00")
    value.tick()
    assert current(value)["status"] == "waiting"
    clock[0] = epoch("2026-10-25T23:00:00+08:00")
    value.tick()
    assert [x[0] for x in engine.calls] == ["start", "resume"]
    assert engine.calls[1][1]["stop_at"] == "2026-10-26T00:00:00+00:00"
    assert engine.calls[1][1]["expected_input_revision"] == "input-a"
    assert current(value)["run_id"] == "run-2"
    engine.jobs["job-a"]["status"] = "completed"
    value.tick()
    assert current(value)["status"] == "completed"


def test_input_change_blocks_launch_and_continuation(tmp_path):
    value, engine, clock = service(tmp_path)
    create(value)
    engine.fingerprint = "changed"
    value.tick()
    assert not engine.calls
    assert current(value)["error"]["code"] == "schedule_input_changed"


def test_retry_key_conflict_and_replay(tmp_path):
    value, engine, _ = service(tmp_path)
    first = create(value)
    assert create(value)["schedule_id"] == first["schedule_id"]
    reply = value.create(request_id="schedule-test", scan_depth="deep", end_mode="complete")
    assert reply.status_code == 409
    value.tick()
    assert len(engine.calls) == 1


@pytest.mark.parametrize("stop_running", [True, False])
def test_cancel_has_explicit_current_run_policy(tmp_path, stop_running):
    value, engine, _ = service(tmp_path)
    create(value)
    value.tick()
    row = current(value)
    reply = value.cancel(
        row["schedule_id"],
        base_revision=row["revision"],
        request_id="cancel-test",
        stop_running=stop_running,
    )
    assert reply.status_code == 200
    value.tick()
    assert current(value)["status"] == "cancelled"
    assert any(x[0] == "cancel" for x in engine.calls) is stop_running


def test_pending_action_crash_replays_without_second_launch(tmp_path):
    value, engine, _ = service(tmp_path)
    create(value)
    original = engine.start

    def crash(**kwargs):
        original(**kwargs)
        raise KeyboardInterrupt("coordinator dies after job reservation")

    engine.start = crash
    with pytest.raises(KeyboardInterrupt):
        value.tick()
    engine.start = original
    value.tick()
    assert len(engine.calls) == 1
    assert current(value)["job_id"] == "job-a"


def test_cancel_after_crash_finds_reserved_job_without_starting_new_one(tmp_path):
    value, engine, _ = service(tmp_path)
    create(value)
    original = engine.start

    def crash(**kwargs):
        original(**kwargs)
        raise KeyboardInterrupt()

    engine.start = crash
    with pytest.raises(KeyboardInterrupt):
        value.tick()
    row = current(value)
    value.cancel(row["schedule_id"], base_revision=row["revision"], request_id="cancel-crash")
    engine.start = original
    value.tick()
    assert [x[0] for x in engine.calls] == ["start", "cancel"]


def test_busy_project_does_not_launch_stale_window(tmp_path):
    value, engine, clock = service(tmp_path, "2026-10-24T23:00:00+08:00")
    create(value, daily_window={"timezone": "Asia/Taipei", "start": "23:00", "end": "08:00"})
    engine.busy = True
    value.tick()
    clock[0] = epoch("2026-10-25T09:00:00+08:00")
    engine.busy = False
    value.tick()
    value.tick()
    assert not engine.calls
    assert current(value)["status"] == "waiting"


@pytest.mark.parametrize(
    "update",
    [
        {"scan_depth": "quick"},
        {"start_at": "2026-10-24T23:00:00"},
        {"start_at": False},
        {"end_mode": []},
        {"end_mode": "deadline", "stop_at": "2020-01-01T00:00:00Z"},
        {"daily_window": {"timezone": "Asia/Taipei", "start": "08:00", "end": "08:00"}},
        {"daily_window": {"timezone": "invalid", "start": "23:00", "end": "08:00"}},
    ],
)
def test_invalid_schedule_parameters(tmp_path, update):
    value, engine, _ = service(tmp_path)
    reply = value.create(
        **{"request_id": "bad", "scan_depth": "fast", "end_mode": "complete", **update}
    )
    assert reply.status_code == 400, reply.payload
    assert not engine.calls


def test_window_end_is_exclusive_and_handles_dst():
    policy = {"timezone": "America/New_York", "start": "23:00", "end": "08:00"}
    start, end = daily_window_at(epoch("2026-11-01T01:30:00-04:00"), policy)
    assert end - start == 10 * 3600
    following, _ = daily_window_at(end, policy)
    assert following >= end


def real_service(tmp_path):
    """Real SQLite/job/launch path, with scanner launch explicitly disabled."""
    from zscope.orchestration.jobs.service import ScanJobService
    import time

    config = tmp_path / "zscope.yaml"
    config.write_text(
        """config_version: 3
llms:
  default:
    base_urls: [http://127.0.0.1:9/v1]
    models: [synthetic-not-called]
    api_key: synthetic-not-used
project:
  language: java
  targets:
    - id: java
scan:
  preset: fast
"""
    )
    (tmp_path / "Main.java").write_text("class Main {}\n")
    engine = ScanJobService(config, spawn_owner=False)
    clock = [time.time()]
    value = ScanScheduleService(config, engine=engine, spawn_daemon=False, clock=lambda: clock[0])
    return value, engine, clock


def test_real_job_window_rearm_preserves_identity_and_new_deadline(tmp_path):
    value, engine, clock = real_service(tmp_path)
    local = datetime.fromtimestamp(clock[0], timezone.utc)
    policy = {
        "timezone": "UTC",
        "start": (local - timedelta(minutes=5)).strftime("%H:%M"),
        "end": (local + timedelta(minutes=5)).strftime("%H:%M"),
    }
    response = value.create(
        request_id="real-daily", scan_depth="fast", end_mode="complete", daily_window=policy
    )
    assert response.status_code == 202, response.payload
    clock[0] += 0.01
    value.tick()
    row = current(value)
    assert row["job_id"]
    store = engine._locate_store()
    first = store.get_job(row["job_id"])
    first_launch = json.loads((Path(first["run_dir"]) / "launch.json").read_text())
    assert first_launch["stop_at_epoch"] > clock[0]
    (tmp_path / "zscope_batch_report.json").write_text("{}")
    store.update_job(
        first["job_id"], expected_revision=first["revision"], updates={"status": "partial"}
    )
    clock[0] += 24 * 3600
    value.tick()
    row = current(value)
    second = store.get_job(row["job_id"])
    second_launch = json.loads((Path(second["run_dir"]) / "launch.json").read_text())
    assert second["job_id"] == first["job_id"]
    assert second["run_id"] != first["run_id"]
    assert second["owner_token"] != first["owner_token"]
    assert second["input_revision"] == first["input_revision"]
    assert second_launch["stop_at_epoch"] == first_launch["stop_at_epoch"] + 24 * 3600
    assert second_launch["owner_token"] == second["owner_token"]


def test_real_schedule_complete_ignores_saved_window_and_changed_source_blocks(
    tmp_path, monkeypatch
):
    value, engine, clock = real_service(tmp_path)

    def forbidden():
        raise AssertionError("Schedule must not inherit saved-config stop window")

    monkeypatch.setattr(engine, "_config_stop_window", forbidden)
    reply = value.create(request_id="real-complete", scan_depth="fast", end_mode="complete")
    assert reply.status_code == 202
    clock[0] += 0.01
    value.tick()
    row = current(value)
    assert row["job_id"]
    store = engine._locate_store()
    job = store.get_job(row["job_id"])
    assert job["stop_at_epoch"] is None
    assert job["resolved_stop_time"] is None
    # A scheduled continuation cannot reuse an edited source version.
    store.update_job(
        job["job_id"], expected_revision=job["revision"], updates={"status": "partial"}
    )
    (tmp_path / "Main.java").write_text("class Main { int changed; }\n")
    refused = engine.resume(
        job["job_id"],
        base_revision=store.get_job(job["job_id"])["revision"],
        request_id="changed-source",
        stop_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        expected_input_revision=job["input_revision"],
    )
    assert refused.status_code == 409
    assert refused.payload["code"] == "schedule_input_changed"
    assert store.get_job(job["job_id"])["run_id"] == job["run_id"]


def test_deadline_marks_expired_instead_of_claiming_scan_complete(tmp_path):
    value, engine, clock = service(tmp_path)
    reply = value.create(
        request_id="deadline",
        scan_depth="fast",
        end_mode="deadline",
        stop_at="2026-10-24T13:00:00+08:00",
    )
    assert reply.status_code == 202
    clock[0] = epoch("2026-10-24T13:00:00+08:00")
    value.tick()
    assert current(value)["status"] == "expired"
    assert not engine.calls


def test_detached_coordinator_launches_real_owner_only_after_start(tmp_path):
    """Real coordinator+owner processes; child is a receipt-only fixture, not Z-SCOPE/LLM."""
    import subprocess
    import sys
    import time

    value, engine, _ = real_service(tmp_path)
    marker = value.root / "scanner-receipt"
    scanner = value.root / "safe-scanner.py"
    scanner.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('explicit safe worker fixture')\n"
    )
    wrapper = value.root / "test-coordinator.py"
    wrapper.write_text(
        """import sys
from zscope.orchestration.jobs import schedule_runner
from zscope.orchestration.jobs.schedules import ScanScheduleService
from zscope.orchestration.jobs.service import ScanJobService
config,scanner=sys.argv[1:]
engine=ScanJobService(config,scan_command_builder=lambda path,depth,python:[python,scanner])
schedule_runner.ScanScheduleService=lambda path,**kwargs:ScanScheduleService(path,engine=engine,spawn_daemon=False)
sys.argv=[sys.argv[0],"--config",config]
raise SystemExit(schedule_runner.main())
"""
    )
    start = (datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat()
    reply = value.create(
        request_id="detached-safe-fixture", scan_depth="fast", end_mode="complete", start_at=start
    )
    assert reply.status_code == 202
    process = subprocess.Popen(
        [sys.executable, str(wrapper), str(value.config_path), str(scanner)], start_new_session=True
    )
    try:
        time.sleep(1)
        assert not marker.exists(), "No scanner may start before the persisted boundary"
        # Reopen management while a separate coordinator survives independently.
        reopened = ScanScheduleService(value.config_path, engine=engine, spawn_daemon=False)
        assert current(reopened)["status"] == "waiting"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and current(reopened)["status"] != "completed":
            time.sleep(0.1)
        assert process.poll() is None
        assert marker.read_text() == "explicit safe worker fixture"
        row = current(reopened)
        assert row["status"] == "completed"
        actual = engine.detail(row["job_id"]).payload["job"]
        assert actual["run_id"] == row["run_id"]
        store = engine._locate_store()
        bound = store.get_job(row["job_id"])
        assert bound["owner_pid"] and bound["owner_start_ticks"] and bound["owner_boot_id"]
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)


def test_http_schedule_contract_is_strict_and_saved_config_scoped(tmp_path):
    from types import SimpleNamespace
    from zscope.web.scan_jobs_service import ScanJobsHttpService

    schedule, engine, _ = service(tmp_path)
    http = ScanJobsHttpService(tmp_path / "zscope.yaml", SimpleNamespace(), engine=engine)
    http._schedule_engine = schedule
    code, data = http.post(
        "/api/schedules",
        {
            "request_id": "http-schedule",
            "scan_depth": "fast",
            "start_at": None,
            "end_mode": "complete",
            "stop_at": None,
            "daily_window": None,
        },
    )
    assert code == 202
    row = data["schedule"]
    assert row["config_path"] == str((tmp_path / "zscope.yaml").resolve())
    assert http.get("/api/schedules", "")[1]["schedules"][0]["schedule_id"] == row["schedule_id"]
    assert http.get("/api/schedules", "config_path=/other/private.yaml")[0] == 400
    assert (
        http.post(
            "/api/schedules",
            {
                "request_id": "unknown",
                "scan_depth": "fast",
                "end_mode": "complete",
                "config_path": "/other.yaml",
            },
        )[0]
        == 400
    )
    assert (
        http.post(
            "/api/schedules/cancel",
            {
                "schedule_id": row["schedule_id"],
                "base_revision": row["revision"],
                "request_id": "http-cancel",
                "stop_running": False,
            },
        )[0]
        == 200
    )
    assert not engine.calls


def test_idle_ticks_do_not_churn_user_visible_revision(tmp_path):
    value, engine, _ = service(tmp_path)
    row = create(value, start_at="2026-10-25T23:00:00+08:00")
    value.tick()
    value.tick()
    assert current(value)["revision"] == row["revision"]


def test_manual_rearm_cannot_be_taken_over_or_cancelled(tmp_path):
    value, engine, _ = service(tmp_path)
    create(value)
    value.tick()
    engine.jobs["job-a"]["run_id"] = "outside-run"
    value.tick()
    assert current(value)["status"] == "blocked"
    assert current(value)["error"]["code"] == "schedule_job_changed"
    row = current(value)
    assert (
        value.cancel(
            row["schedule_id"], base_revision=row["revision"], request_id="do-not-stop-other"
        ).status_code
        == 200
    )
    value.tick()
    assert not any(call[0] == "cancel" for call in engine.calls)


def test_cancel_during_launch_wins_and_stops_only_returned_attempt(tmp_path):
    value, engine, _ = service(tmp_path)
    create(value)
    original = engine.start

    def concurrent_cancel(**kwargs):
        response = original(**kwargs)
        row = current(value)
        assert (
            value.cancel(
                row["schedule_id"], base_revision=row["revision"], request_id="concurrent-cancel"
            ).status_code
            == 200
        )
        return response

    engine.start = concurrent_cancel
    value.tick()
    value.tick()
    assert current(value)["status"] == "cancelled"
    assert [x[0] for x in engine.calls] == ["start", "cancel"]


def test_owner_rechecks_scheduled_input_before_launch_without_rebinding(tmp_path):
    from zscope.orchestration.jobs.owner import Owner, _OwnerFailure

    value, engine, clock = real_service(tmp_path)
    response = value.create(request_id="owner-input-fence", scan_depth="fast", end_mode="complete")
    assert response.status_code == 202
    clock[0] += 0.01
    value.tick()
    row = current(value)
    store = engine._locate_store()
    job = store.get_job(row["job_id"])
    launch = Path(job["run_dir"]) / "launch.json"
    owner = Owner(
        store=store,
        job_id=job["job_id"],
        run_id=job["run_id"],
        run_dir=job["run_dir"],
        launch_path=launch,
        token=job["owner_token"],
    )
    owner.job = job
    owner.launch = json.loads(launch.read_text())
    assert owner.launch["expected_input_revision"] == job["input_revision"]
    (tmp_path / "Main.java").write_text("class Main { int changed; }\n")
    with pytest.raises(_OwnerFailure) as failure:
        owner._bind_inputs()
    assert failure.value.code == "schedule_input_changed"
    assert store.get_job(job["job_id"])["input_revision"] == job["input_revision"]


def test_owner_does_not_spawn_scanner_after_delayed_start_misses_window(tmp_path, monkeypatch):
    from zscope.orchestration.jobs import owner as owner_module

    value, engine, _ = real_service(tmp_path)
    stop = datetime.now(timezone.utc) + timedelta(seconds=30)
    fingerprint = engine._fingerprint(scan_depth="fast")
    response = engine.start(
        request_id="delayed-window",
        scan_depth="fast",
        stop_at=stop.isoformat(),
        ignore_config_window=True,
        expected_input_revision=fingerprint["sha256"],
    )
    assert response.status_code == 202, response.payload
    job_id = response.payload["job"]["job_id"]
    store = engine._locate_store()
    job = store.get_job(job_id)
    owner = owner_module.Owner(
        store=store,
        job_id=job_id,
        run_id=job["run_id"],
        run_dir=job["run_dir"],
        launch_path=Path(job["run_dir"]) / "launch.json",
        token=job["owner_token"],
    )
    spawned = []
    monkeypatch.setattr(owner, "_spawn_scanner", lambda: spawned.append(True))
    monkeypatch.setattr(owner_module.time, "time", lambda: stop.timestamp() + 1)
    assert owner.run() == 0
    assert not spawned
    final = store.get_job(job_id)
    assert final["status"] == "partial"
    assert final["error_code"] == "stop_window_closed"


def test_saved_config_edit_cannot_hide_bound_job_from_cancellation(tmp_path):
    value, engine, clock = real_service(tmp_path)
    assert (
        value.create(
            request_id="editable-config", scan_depth="fast", end_mode="complete"
        ).status_code
        == 202
    )
    clock[0] += 0.01
    value.tick()
    row = current(value)
    assert row["job_id"]
    value.config_path.write_text("this is not a valid configuration")
    assert engine.detail(row["job_id"]).status_code == 200
    assert (
        value.cancel(
            row["schedule_id"], base_revision=row["revision"], request_id="cancel-invalid-config"
        ).status_code
        == 200
    )
    value.tick()
    assert current(value)["status"] == "cancelled"
    assert engine.detail(row["job_id"]).payload["job"]["status"] in {"cancelled", "stopping"}
