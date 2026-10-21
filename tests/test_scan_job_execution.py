"""Real Linux process tests for the persistent scan job slice (JOB01/JOB04/JOB05).

Every test here spawns real processes: the detached owner
(``python -m zscope.orchestration.jobs``) and a scanner child whose behaviour
is controlled per attempt (sleep, produce a report, exit codes).  No owner
behaviour is faked; store-level craft is limited to the PID-recycling
counterexample, which still uses a real unrelated process as the victim.
"""

import concurrent.futures
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

from test_scan_jobs import make_project, make_service, start_job, store_for
from zscope.orchestration.jobs import identity
from zscope.orchestration.jobs.models import TERMINAL_STATUSES
from zscope.orchestration.jobs.runner import write_launch_file
from zscope.orchestration.jobs.service import ScanJobService

pytestmark = pytest.mark.skipif(
    not identity.proc_available(),
    reason="detached owner tests require Linux /proc process identity",
)

SCANNER_SCRIPT = """\
import json
import sys
import time
from pathlib import Path

mode = sys.argv[1]
root = Path(sys.argv[2])
counter = Path(sys.argv[3]) if len(sys.argv) > 3 else None
report = root / "zscope_batch_report.json"

if counter is not None:
    with counter.open("a", encoding="utf-8") as handle:
        handle.write(f"scanner {mode}\\n")

REPORT = {
    "completeness": "complete",
    "metadata": {
        "build_coverage": {"selected_tus": 1, "total_tus": 1},
        "business_questions": [
            {
                "id": "q1",
                "question": "Is the buffer owned by the caller?",
                "affected_scope": "src/main.c",
                "current_assumption": "owned",
                "impact": "medium",
                "answer_revision": 0,
            }
        ],
    },
}

SHARED_REPORT = {
    "completeness": "incomplete",
    "issues": [{"id": "iss-1", "rule": "demo_rule"}],
    "metadata": {
        "build_coverage": {"selected_tus": 2, "total_tus": 3},
        "coverage_gaps": [{"kind": "tu_missing", "path": "src/extra.c"}],
        "deferred_count": 2,
        "business_questions": [
            {
                "id": "q1",
                "question": "Is the buffer owned by the caller?",
                "affected_scope": "src/main.c",
                "current_assumption": "owned",
                "impact": "high",
                "answer_revision": 0,
            }
        ],
    },
}


def corrupt_shared_graph(path):
    envelope = json.loads(path.read_text(encoding="utf-8"))
    assert envelope["storage_schema"] == "zscope.shared-json.v1"
    uid = next(iter(envelope["objects"]))
    envelope["objects"][uid] = ["value", "tampered-object-digest"]
    path.write_text(json.dumps(envelope))


if mode == "sleep":
    time.sleep(300)
elif mode == "slow_report":
    time.sleep(5)
    report.write_text(json.dumps(REPORT))
elif mode == "report":
    time.sleep(0.5)
    report.write_text(json.dumps(REPORT))
elif mode == "shared_report":
    from zscope.reporting.json_io import write_report_atomic

    time.sleep(0.5)
    write_report_atomic(report, SHARED_REPORT)
elif mode == "corrupt_shared":
    from zscope.reporting.json_io import write_report_atomic

    time.sleep(0.5)
    write_report_atomic(report, SHARED_REPORT)
    corrupt_shared_graph(report)
elif mode == "report_exit2":
    report.write_text(json.dumps(REPORT))
    sys.exit(2)
elif mode == "exit2_noreport":
    sys.exit(2)
elif mode == "stale_keep":
    time.sleep(0.5)
elif mode == "fail":
    sys.exit(3)
sys.exit(0)
"""

CLIENT_SCRIPT = """\
import sys
from pathlib import Path

config_path, scanner_path, project_root, mode, job_id_out = sys.argv[1:6]

from zscope.orchestration.jobs.service import ScanJobService


def builder(config, depth, python_executable):
    return [python_executable, scanner_path, mode, project_root]


service = ScanJobService(config_path, scan_command_builder=builder, terminate_grace=2.0)
response = service.start(request_id="req-disconnect")
if response.status_code != 202:
    print(response.payload, file=sys.stderr)
    sys.exit(1)
Path(job_id_out).write_text(response.payload["job"]["job_id"], encoding="utf-8")
"""

START_CLIENT_SCRIPT = """\
import sys
from pathlib import Path

config_path, scanner_path, project_root, counter_path, request_id, job_out = sys.argv[1:7]

from zscope.orchestration.jobs.service import ScanJobService


def builder(config, depth, python_executable):
    return [python_executable, scanner_path, "shared_report", project_root, counter_path]


service = ScanJobService(config_path, scan_command_builder=builder, terminate_grace=2.0)
response = service.start(request_id=request_id)
if response.status_code != 202:
    Path(job_out).write_text(f"ERROR:{response.status_code}:{response.payload}", encoding="utf-8")
    sys.exit(1)
Path(job_out).write_text(response.payload["job"]["job_id"], encoding="utf-8")
"""

# Labeled fault injection (the only pause): the client's first launch stalls
# after the durable reservation and before the owner process is spawned —
# exactly the R5 window, now reservation-first.
PAUSE_CLIENT_SCRIPT = """\
import sys
import time
from pathlib import Path

(
    config_path,
    scanner_path,
    project_root,
    counter_path,
    request_id,
    paused_flag,
    release_flag,
    job_out,
) = sys.argv[1:9]

from zscope.orchestration.jobs.service import ScanJobService


class PausedLaunchService(ScanJobService):
    def _spawn_owner(self, **kwargs):
        Path(paused_flag).write_text("paused", encoding="utf-8")
        deadline = time.monotonic() + 90
        while not Path(release_flag).exists():
            if time.monotonic() > deadline:
                raise RuntimeError("release timeout")
            time.sleep(0.05)
        return super()._spawn_owner(**kwargs)


def builder(config, depth, python_executable):
    return [python_executable, scanner_path, "shared_report", project_root, counter_path]


service = PausedLaunchService(config_path, scan_command_builder=builder, terminate_grace=2.0)
response = service.start(request_id=request_id)
if response.status_code != 202:
    Path(job_out).write_text(f"ERROR:{response.status_code}:{response.payload}", encoding="utf-8")
    sys.exit(1)
Path(job_out).write_text(response.payload["job"]["job_id"], encoding="utf-8")
"""


def wait_for(predicate, *, timeout: float = 30.0, interval: float = 0.2, description: str):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {description}; last={last!r}")


@pytest.fixture
def job_env(tmp_path):
    project = make_project(tmp_path)
    scanner = tmp_path / "scanner.py"
    scanner.write_text(SCANNER_SCRIPT, encoding="utf-8")
    mode_box = ["report"]

    def builder(config_path, scan_depth, python_executable):
        return [python_executable, str(scanner), mode_box[0], str(project)]

    def factory(**kwargs):
        kwargs.setdefault("scan_command_builder", builder)
        kwargs.setdefault("spawn_owner", True)
        kwargs.setdefault("terminate_grace", 2.0)
        return ScanJobService(project / "zscope.yaml", **kwargs)

    return {
        "project": project,
        "scanner": scanner,
        "mode_box": mode_box,
        "factory": factory,
        "tmp_path": tmp_path,
    }


def wait_terminal(service: ScanJobService, job_id: str, *, timeout: float = 180.0) -> dict:
    # A real two-instance native scan plus checkpoint publication measures
    # ~80 s here; a 60 s budget expired before the assertions ran.
    def probe():
        response = service.detail(job_id)
        assert response.status_code == 200, response.payload
        job = response.payload["job"]
        return job if job["status"] in TERMINAL_STATUSES else None

    return wait_for(probe, timeout=timeout, description=f"terminal state of {job_id}")


def wait_running(service: ScanJobService, job_id: str, *, timeout: float = 30.0) -> dict:
    def probe():
        job = service.detail(job_id).payload["job"]
        store_job = store_for(service.config_path.parent).get_job(job_id)
        if job["status"] == "running" and store_job and store_job["scanner_pid"]:
            return store_job
        return None

    return wait_for(probe, timeout=timeout, description=f"running scanner of {job_id}")


def event_kinds(service: ScanJobService, job_id: str) -> list:
    return [event["kind"] for event in service.events(job_id, 0).payload["events"]]


def assert_process_gone(pid: int) -> None:
    assert identity.read_process_start_ticks(pid) is None, f"process {pid} is still alive"


# ---------------------------------------------------------------------------
# owner entry point (__main__)


def test_owner_entry_rejects_unreadable_launch(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "zscope.orchestration.jobs",
            "--job-id",
            "job_x",
            "--run-id",
            "run_x",
            "--store",
            str(tmp_path / "jobs.db"),
            "--run-dir",
            str(tmp_path / "run"),
            "--launch",
            str(tmp_path / "missing-launch.json"),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "ZSCOPE_JOB_OWNER_TOKEN": "tok"},
    )
    assert result.returncode == 3
    assert "launch_invalid" in (result.stderr + result.stdout)


def test_owner_entry_stands_down_for_foreign_attempt(tmp_path):
    project = make_project(tmp_path)
    service = make_service(project)
    job = start_job(service, request_id="req-hijack")
    store = store_for(project)
    token = store.get_job(job["job_id"])["owner_token"]
    run_dir = tmp_path / "foreign_run"
    run_dir.mkdir()
    launch = run_dir / "launch.json"
    write_launch_file(
        launch,
        job_id=job["job_id"],
        run_id="run_other",
        owner_token=token,
        argv=[sys.executable, "-c", "pass"],
        cwd=str(tmp_path),
        report_candidates=[],
        stop_at_epoch=None,
        resolved_stop_time=None,
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "zscope.orchestration.jobs",
            "--job-id",
            job["job_id"],
            "--run-id",
            "run_other",
            "--store",
            str(store.db_path),
            "--run-dir",
            str(run_dir),
            "--launch",
            str(launch),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "ZSCOPE_JOB_OWNER_TOKEN": token},
    )
    assert result.returncode == 2
    assert "attempt_superseded" in (result.stderr + result.stdout)
    # The real attempt row is untouched: a stray owner must not mark failure.
    assert store.get_job(job["job_id"])["status"] == "queued"


# ---------------------------------------------------------------------------
# JOB01: UI/client disconnect; the owner keeps working


def test_detached_owner_survives_client_disconnect(job_env, tmp_path):
    project = job_env["project"]
    scanner = job_env["scanner"]
    client = tmp_path / "client.py"
    client.write_text(CLIENT_SCRIPT, encoding="utf-8")
    job_id_file = tmp_path / "job_id.txt"
    started = time.monotonic()
    result = subprocess.run(
        [
            sys.executable,
            str(client),
            str(project / "zscope.yaml"),
            str(scanner),
            str(project),
            "slow_report",
            str(job_id_file),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    client_pid_note = "client process exited; no parent remains for the owner"
    job_id = job_id_file.read_text(encoding="utf-8").strip()

    # Reconnect with a fresh service instance; the job state is real.
    service = job_env["factory"]()
    running = wait_running(service, job_id)
    owner_pid = int(running["owner_pid"])
    owner_ticks = running["owner_start_ticks"]
    assert (
        identity.probe_process(owner_pid, expected_start_ticks=owner_ticks) is True
    ), client_pid_note
    detail = service.detail(job_id).payload["job"]
    assert detail["owner"] == {"state": "alive", "process_id": owner_pid}

    terminal = wait_terminal(service, job_id)
    elapsed = time.monotonic() - started
    assert terminal["status"] == "completed"
    assert elapsed >= 5.0, "scanner slept 5s; a completed job proves the owner survived"
    assert terminal["report"]["available"] is True
    assert terminal["report"]["report_id"]
    # The owner writes the terminal state before it exits; init then reaps it.
    # Wait for the exit to be verifiable instead of racing the status write.
    wait_for(
        lambda: identity.probe_process(owner_pid, expected_start_ticks=owner_ticks) is not True
        or None,
        timeout=15.0,
        description=f"owner {owner_pid} exit after finalize",
    )
    detail = service.detail(job_id).payload["job"]
    assert detail["owner"]["state"] == "exited"
    kinds = event_kinds(service, job_id)
    for expected in (
        "job_created",
        "owner_spawned",
        "owner_started",
        "input_fingerprint",
        "scan_launched",
        "report_bound",
        "job_terminal",
    ):
        assert expected in kinds, kinds

    # The bound report belongs to this attempt's run directory.
    run_dir = Path(running["run_dir"])
    bound = run_dir / "report.json"
    assert terminal["report"]["path"] == str(bound)
    assert bound.is_file()
    assert terminal["report"]["report_id"] == hashlib.sha256(bound.read_bytes()).hexdigest()
    receipt = json.loads((run_dir / "owner.json").read_text(encoding="utf-8"))
    assert receipt["schema"] == "zscope.scan-job-owner.v1"
    assert receipt["pid"] == owner_pid
    assert receipt["run_id"] == terminal["run_id"]

    result_payload = service.result(job_id).payload
    assert result_payload["report_available"] is True
    assert result_payload["report_id"] == terminal["report"]["report_id"]
    assert result_payload["findings"] is None  # coordinator wires the projection
    assert result_payload["coverage"]["completeness"] == "complete"
    assert result_payload["coverage"]["build_coverage"] == {"selected_tus": 1, "total_tus": 1}
    assert len(result_payload["questions"]) == 1
    assert result_payload["questions"][0]["id"] == "q1"
    loaded = service.load_bound_report(job_id)
    assert loaded is not None and loaded[0]["completeness"] == "complete"
    attempts = store_for(project).list_attempts(job_id)
    assert len(attempts) == 1
    assert attempts[0]["status"] == "completed"
    assert attempts[0]["exit_code"] == 0


# ---------------------------------------------------------------------------
# JOB05: cancel, controller crash, PID reuse


def test_cancel_stops_owner_and_reaps_scanner_group(job_env):
    job_env["mode_box"][0] = "sleep"
    service = job_env["factory"]()
    job = start_job(service, request_id="req-cancel")
    job_id = job["job_id"]
    running = wait_running(service, job_id)
    scanner_pid = int(running["scanner_pid"])
    owner_pid = int(running["owner_pid"])

    current = service.detail(job_id).payload["job"]
    started = time.monotonic()
    response = service.cancel(job_id, base_revision=current["revision"], request_id="req-cancel-op")
    assert response.status_code == 200
    terminal = wait_terminal(service, job_id, timeout=30.0)
    elapsed = time.monotonic() - started
    assert terminal["status"] == "cancelled"
    assert terminal["error"]["code"] == "cancelled"
    assert elapsed < 20.0, "cancel teardown must be bounded"
    assert_process_gone(scanner_pid)
    # The owner writes the terminal state and then exits; as its parent the
    # test process must reap it before /proc stops showing the process.
    reap_deadline = time.monotonic() + 10.0
    while True:
        try:
            done, _ = os.waitpid(owner_pid, os.WNOHANG)
        except ChildProcessError:
            break
        if done == owner_pid:
            break
        assert time.monotonic() < reap_deadline, "owner did not exit within bound"
        time.sleep(0.1)
    assert_process_gone(owner_pid)
    kinds = event_kinds(service, job_id)
    assert "cancel_requested" in kinds
    assert "cancel_observed" in kinds
    terminated = [
        event
        for event in service.events(job_id, 0).payload["events"]
        if event["kind"] == "scan_terminated"
    ]
    assert terminated and terminated[0]["data"]["reason"] == "cancel"
    assert terminated[0]["data"]["outcome"] in {"terminated", "killed"}
    assert terminal["capabilities"]["resume"] is True
    attempts = store_for(job_env["project"]).list_attempts(job_id)
    assert attempts[-1]["status"] == "cancelled"
    assert attempts[-1]["exit_signal"] in (None, 9, 15)


def test_owner_crash_marks_lost_reaps_scanner_then_resume_recovers(job_env):
    job_env["mode_box"][0] = "sleep"
    service = job_env["factory"]()
    job = start_job(service, request_id="req-crash")
    job_id = job["job_id"]
    running = wait_running(service, job_id)
    owner_pid = int(running["owner_pid"])
    scanner_pid = int(running["scanner_pid"])

    # Controller crash: SIGKILL the owner.  The zombie is NOT reaped yet —
    # the exit must be recognized from the zombie state alone (F3), not only
    # after the parent happens to collect the body.
    os.kill(owner_pid, signal.SIGKILL)
    lost = wait_for(
        lambda: (
            service.detail(job_id).payload["job"]
            if service.detail(job_id).payload["job"]["status"] == "lost"
            else None
        ),
        description="lost verdict on the unreaped zombie owner",
    )
    assert lost["error"]["code"] == "owner_lost"
    assert lost["capabilities"]["resume"] is True
    os.waitpid(owner_pid, 0)  # reap only after the zombie-verdict assertion
    detail = service.detail(job_id).payload["job"]
    assert detail["status"] == "lost"
    # The orphaned scanner group was reaped only after identity verification.
    assert_process_gone(scanner_pid)
    events = service.events(job_id, 0).payload["events"]
    lost_events = [event for event in events if event["kind"] == "owner_lost"]
    assert lost_events and lost_events[0]["data"]["scanner"] == "reaped"

    # Resume starts a new attempt; the old one stays on record.
    job_env["mode_box"][0] = "report"
    response = service.resume(
        job_id, base_revision=detail["revision"], request_id="req-crash-resume"
    )
    assert response.status_code == 202
    assert response.payload["job"]["run_id"] != detail["run_id"]
    terminal = wait_terminal(service, job_id)
    assert terminal["status"] == "completed"
    assert terminal["report"]["available"] is True
    attempts = store_for(job_env["project"]).list_attempts(job_id)
    assert [attempt["status"] for attempt in attempts] == ["lost", "completed"]
    assert attempts[0]["ended_at"] is not None
    kinds = event_kinds(service, job_id)
    assert "attempt_started" in kinds


def test_reconcile_never_kills_process_with_mismatched_identity(job_env):
    # PID-reuse counterexample: a live process with a different start time
    # must not be treated as the recorded scanner (JOB05).
    project = job_env["project"]
    service = make_service(project)
    job = start_job(service, request_id="req-reuse")
    job_id = job["job_id"]
    store = store_for(project)
    victim = subprocess.Popen(["sleep", "300"], start_new_session=True)
    try:
        real_ticks = identity.read_process_start_ticks(victim.pid)
        assert real_ticks is not None
        current = store.get_job(job_id)
        store.update_job(
            job_id,
            expected_revision=int(current["revision"]),
            updates={
                "status": "running",
                "owner_pid": 2**30,  # verifiably dead owner
                "scanner_pid": victim.pid,
                "scanner_start_ticks": real_ticks + 10_000_000,  # recycled identity
            },
        )
        # A mid-flight attempt row always exists before an owner can vanish.
        store.record_attempt(
            {
                "job_id": job_id,
                "run_id": job["run_id"],
                "attempt_no": 1,
                "status": "running",
                "input_revision": job["input_revision"],
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        detail = service.detail(job_id).payload["job"]
        assert detail["status"] == "lost"
        # The innocent process is still alive: no signal was sent to it.
        assert victim.poll() is None
        events = service.events(job_id, 0).payload["events"]
        lost_events = [event for event in events if event["kind"] == "owner_lost"]
        assert lost_events and lost_events[0]["data"]["scanner"] == "not_running"
    finally:
        victim.kill()
        victim.wait()


# ---------------------------------------------------------------------------
# JOB04: stop window (owner-granularity enforcement; session hook is pending)


def test_stop_window_forces_partial_with_bounded_teardown(job_env):
    job_env["mode_box"][0] = "sleep"
    service = job_env["factory"]()
    stop_at = (datetime.now(timezone.utc) + timedelta(seconds=3)).isoformat()
    job = start_job(service, stop_at=stop_at, request_id="req-window")
    job_id = job["job_id"]
    running = wait_running(service, job_id)
    scanner_pid = int(running["scanner_pid"])

    terminal = wait_terminal(service, job_id, timeout=30.0)
    assert terminal["status"] == "partial"
    assert terminal["error"]["code"] == "stop_window_reached"
    assert terminal["resolved_stop_time"] is not None
    assert "cancel_requested_at" not in terminal
    assert_process_gone(scanner_pid)
    kinds = event_kinds(service, job_id)
    assert "stop_window_reached" in kinds
    assert "scan_terminated" in kinds

    # The owner persists an honest, empty backlog marker: session-level queue
    # introspection requires the scheduler hook wiring (JOB04 pending part).
    run_dir = Path(running["run_dir"])
    pending = json.loads((run_dir / "pending.json").read_text(encoding="utf-8"))
    assert pending["schema"] == "zscope.scan-job-pending.v1"
    assert pending["source"] == "owner_window_stop"
    assert pending["job_id"] == job_id
    assert pending["run_id"] == terminal["run_id"]
    assert terminal["capabilities"]["resume"] is True


# ---------------------------------------------------------------------------
# report binding: only the current attempt's output counts


def test_report_binds_only_when_this_attempt_updates_it(job_env):
    project = job_env["project"]
    service = job_env["factory"]()
    stale_report = project / "zscope_batch_report.json"
    stale_report.write_text(
        json.dumps({"completeness": "complete", "metadata": {}, "stale": True}),
        encoding="utf-8",
    )
    stale_mtime = stale_report.stat().st_mtime_ns

    # Attempt 1 leaves the pre-existing report untouched: no binding.
    job_env["mode_box"][0] = "stale_keep"
    job = start_job(service, request_id="req-stale")
    terminal = wait_terminal(service, job["job_id"])
    assert terminal["status"] == "completed"
    assert terminal["report"] == {"available": False, "report_id": None, "path": None}
    result_payload = service.result(job["job_id"]).payload
    assert result_payload["report_available"] is False
    assert result_payload["reason"] == "report_not_updated"
    assert result_payload["coverage"]["completeness"] is None
    assert stale_report.stat().st_mtime_ns == stale_mtime

    # Attempt 2 really produces the report: it is bound to the new attempt.
    job_env["mode_box"][0] = "report"
    job2 = start_job(service, request_id="req-fresh")
    terminal2 = wait_terminal(service, job2["job_id"])
    assert terminal2["status"] == "completed"
    assert terminal2["report"]["available"] is True
    assert terminal2["report"]["report_id"]
    bound = Path(terminal2["report"]["path"])
    assert bound.parent != project, "the bound copy lives in the run directory"
    parsed = json.loads(bound.read_text(encoding="utf-8"))
    assert parsed.get("stale") is not True
    assert parsed["completeness"] == "complete"
    result2 = service.result(job2["job_id"]).payload
    assert result2["report_available"] is True
    assert result2["coverage"]["completeness"] == "complete"
    assert result2["coverage"]["build_coverage"] == {"selected_tus": 1, "total_tus": 1}
    assert terminal2["pending_count"] is None  # questions are not measured queue work
    assert terminal2["questions"][0]["question"] == "Is the buffer owned by the caller?"


def test_exit2_is_partial_only_when_report_bound(job_env, tmp_path):
    service = job_env["factory"]()
    job_env["mode_box"][0] = "report_exit2"
    job = start_job(service, request_id="req-partial")
    terminal = wait_terminal(service, job["job_id"])
    assert terminal["status"] == "partial"
    assert terminal["report"]["available"] is True
    assert terminal["error"]["code"] == "scan_incomplete"
    assert terminal["capabilities"]["resume"] is True

    # A bare exit-2 (no report produced) is a failure, never a fake partial.
    project2 = make_project(tmp_path, name="project2")
    scanner2 = tmp_path / "scanner2.py"
    scanner2.write_text(SCANNER_SCRIPT, encoding="utf-8")
    mode_box2 = ["exit2_noreport"]

    def builder2(config_path, scan_depth, python_executable):
        return [python_executable, str(scanner2), mode_box2[0], str(project2)]

    service2 = ScanJobService(
        project2 / "zscope.yaml",
        scan_command_builder=builder2,
        terminate_grace=2.0,
    )
    job2 = start_job(service2, request_id="req-exit2")
    terminal2 = wait_terminal(service2, job2["job_id"])
    assert terminal2["status"] == "failed"
    assert terminal2["report"]["available"] is False
    assert terminal2["error"]["code"] == "scan_failed"
    result2 = service2.result(job2["job_id"]).payload
    assert result2["report_available"] is False
    assert result2["reason"] == "report_not_produced"


def test_failed_scanner_records_error_and_artifacts(job_env):
    job_env["mode_box"][0] = "fail"
    service = job_env["factory"]()
    job = start_job(service, request_id="req-fail")
    terminal = wait_terminal(service, job["job_id"])
    assert terminal["status"] == "failed"
    assert terminal["error"]["code"] == "scan_failed"
    assert terminal["report"]["available"] is False
    # The raw scanner log of this attempt is preserved and reachable.
    log_artifacts = [
        artifact for artifact in terminal["artifacts"] if artifact["kind"] == "scanner_log"
    ]
    assert log_artifacts and log_artifacts[0]["status"] == "available"
    assert Path(log_artifacts[0]["path"]).is_file()
    attempts = store_for(job_env["project"]).list_attempts(job["job_id"])
    assert attempts[-1]["status"] == "failed"
    assert attempts[-1]["exit_code"] == 3


# ---------------------------------------------------------------------------
# report binding through the real product format (zscope.shared-json.v1)


def test_shared_json_report_binds_and_projects_end_to_end(job_env):
    # The scanner writes through the real write_report_atomic: the bound
    # artifact is a shared-json.v1 storage envelope and the projections come
    # from the decoded logical report, never from the envelope bytes.
    job_env["mode_box"][0] = "shared_report"
    service = job_env["factory"]()
    job = start_job(service, request_id="req-shared-e2e")
    terminal = wait_terminal(service, job["job_id"])
    assert terminal["status"] == "completed"
    assert terminal["report"]["available"] is True
    bound = Path(terminal["report"]["path"])
    assert bound.parent != job_env["project"], "the bound copy lives in the run directory"
    raw = json.loads(bound.read_text(encoding="utf-8"))
    assert raw["storage_schema"] == "zscope.shared-json.v1"
    assert terminal["report"]["report_id"] == hashlib.sha256(bound.read_bytes()).hexdigest()
    result = service.result(job["job_id"]).payload
    assert result["report_available"] is True
    assert result["report_id"] == terminal["report"]["report_id"]
    assert result["coverage"]["completeness"] == "incomplete"
    assert result["coverage"]["build_coverage"] == {"selected_tus": 2, "total_tus": 3}
    assert result["coverage"]["gaps"] == [{"kind": "tu_missing", "path": "src/extra.c"}]
    assert result["coverage"]["deferred_count"] == 2
    assert [question["id"] for question in result["questions"]] == ["q1"]
    assert terminal["pending_count"] is None  # no queue was consumed by this scanner
    loaded = service.load_bound_report(job["job_id"])
    assert loaded is not None
    parsed, bound_path = loaded
    assert bound_path == bound
    assert parsed["completeness"] == "incomplete"
    assert parsed["issues"] == [{"id": "iss-1", "rule": "demo_rule"}]
    assert parsed["metadata"]["build_coverage"] == {"selected_tus": 2, "total_tus": 3}
    assert parsed["metadata"]["deferred_count"] == 2


def test_corrupt_shared_json_report_is_rejected_end_to_end(job_env):
    # A report whose object graph does not decode (wrong object digest) is
    # never bound, even though the scanner exited successfully.
    job_env["mode_box"][0] = "corrupt_shared"
    service = job_env["factory"]()
    job = start_job(service, request_id="req-corrupt-e2e")
    terminal = wait_terminal(service, job["job_id"])
    assert terminal["status"] == "completed"
    assert terminal["report"] == {"available": False, "report_id": None, "path": None}
    assert terminal["pending_count"] is None
    result = service.result(job["job_id"]).payload
    assert result["report_available"] is False
    assert result["report_id"] is None
    assert result["reason"] == "report_not_produced"
    kinds = event_kinds(service, job["job_id"])
    assert "report_unreadable" in kinds
    assert service.load_bound_report(job["job_id"]) is None


# ---------------------------------------------------------------------------
# request reservation atomicity (R5): duplicates replay, never double-start.
# The only fault injection is the labeled launch pause; every process, the
# SQLite store, the detached owner and the shared-json report writer are real.


class _PausedLaunchService(ScanJobService):
    """Stalls the first launch after the durable reservation, before spawn."""

    def __init__(self, *args, paused, release, **kwargs):
        super().__init__(*args, **kwargs)
        self._paused_event = paused
        self._release_event = release

    def _spawn_owner(self, **kwargs):
        if not self._paused_event.is_set():
            self._paused_event.set()
            if not self._release_event.wait(60):
                raise RuntimeError("test release timeout")
        return super()._spawn_owner(**kwargs)


def test_duplicate_start_during_paused_launch_replays_single_scanner(job_env, tmp_path):
    # R5 regression: the first handler stalls after the durable reservation
    # (before any process side effect); the duplicate from a second service
    # instance (reopen) must replay the reserved job, and the released
    # handler must return 202 — not start a second real owner/scanner and
    # not fail with a spurious 409.
    project = job_env["project"]
    counter = tmp_path / "scanner-count.txt"
    mode_box = ["shared_report"]

    def builder(config_path, scan_depth, python_executable):
        return [python_executable, str(job_env["scanner"]), mode_box[0], str(project), str(counter)]

    paused = threading.Event()
    release = threading.Event()
    service = _PausedLaunchService(
        project / "zscope.yaml",
        paused=paused,
        release=release,
        scan_command_builder=builder,
        terminate_grace=2.0,
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(service.start, request_id="same-create-key")
        assert paused.wait(15), "first handler did not reach the launch pause"
        # The reservation is durable and re-readable before any side effect.
        store = store_for(project)
        reserved = store.list_jobs()
        assert len(reserved) == 1 and reserved[0]["status"] == "queued"
        job_id = reserved[0]["job_id"]
        # A second service instance (reopen) duplicates the same key.
        other = ScanJobService(
            project / "zscope.yaml", scan_command_builder=builder, terminate_grace=2.0
        )
        duplicate = other.start(request_id="same-create-key")
        assert duplicate.status_code == 202, duplicate.payload
        assert duplicate.payload["job"]["job_id"] == job_id
        release.set()
        original = first.result(timeout=60)
        assert original.status_code == 202, original.payload
        assert original.payload["job"]["job_id"] == job_id
    terminal = wait_terminal(service, job_id)
    assert terminal["status"] == "completed"
    assert terminal["report"]["available"] is True
    jobs = service.list().payload["jobs"]
    assert len(jobs) == 1
    assert counter.read_text(encoding="utf-8").count("scanner") == 1
    kinds = event_kinds(service, job_id)
    assert kinds.count("job_created") == 1
    assert any(kind == "request_replayed" for kind in kinds)


def test_cross_process_duplicate_start_replays_reservation(job_env, tmp_path):
    # True cross-process concurrency: the paused first client is a separate
    # OS process; the duplicate arrives from this process's own service
    # instance.  The single SQLite reservation must serialize them.
    project = job_env["project"]
    counter = tmp_path / "scanner-count.txt"
    paused_flag = tmp_path / "paused.flag"
    release_flag = tmp_path / "release.flag"
    job_out = tmp_path / "job_id.txt"
    client = tmp_path / "pause_client.py"
    client.write_text(PAUSE_CLIENT_SCRIPT, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    process = subprocess.Popen(
        [
            sys.executable,
            str(client),
            str(project / "zscope.yaml"),
            str(job_env["scanner"]),
            str(project),
            str(counter),
            "same-create-key",
            str(paused_flag),
            str(release_flag),
            str(job_out),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_for(lambda: paused_flag.exists() or None, timeout=15, description="client pause flag")

        def builder(config_path, scan_depth, python_executable):
            return [
                python_executable,
                str(job_env["scanner"]),
                "shared_report",
                str(project),
                str(counter),
            ]

        local = ScanJobService(
            project / "zscope.yaml", scan_command_builder=builder, terminate_grace=2.0
        )
        duplicate = local.start(request_id="same-create-key")
        assert duplicate.status_code == 202, duplicate.payload
        jobs = local.list().payload["jobs"]
        assert len(jobs) == 1
        assert duplicate.payload["job"]["job_id"] == jobs[0]["job_id"]
        assert duplicate.payload["job"]["status"] in ("queued", "running")
        release_flag.write_text("release\n", encoding="utf-8")
        output, _ = process.communicate(timeout=90)
        assert process.returncode == 0, output
        assert job_out.read_text(encoding="utf-8").strip() == jobs[0]["job_id"]
        terminal = wait_terminal(local, jobs[0]["job_id"])
        assert terminal["status"] == "completed"
        assert counter.read_text(encoding="utf-8").count("scanner") == 1
        assert len(local.list().payload["jobs"]) == 1
    finally:
        if process.poll() is None:
            release_flag.write_text("release\n", encoding="utf-8")
            try:
                process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=15)


def test_resend_after_fast_terminal_replays_completed_job(job_env, tmp_path):
    # Handler disconnect + fast terminal + resend: the client process exits
    # right after starting; once the real owner completes, a resend with the
    # same key replays the completed job instead of starting a second scan.
    project = job_env["project"]
    counter = tmp_path / "scanner-count.txt"
    job_out = tmp_path / "job_id.txt"
    client = tmp_path / "start_client.py"
    client.write_text(START_CLIENT_SCRIPT, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    result = subprocess.run(
        [
            sys.executable,
            str(client),
            str(project / "zscope.yaml"),
            str(job_env["scanner"]),
            str(project),
            str(counter),
            "req-disconnect-retry",
            str(job_out),
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    job_id = job_out.read_text(encoding="utf-8").strip()

    def builder(config_path, scan_depth, python_executable):
        return [
            python_executable,
            str(job_env["scanner"]),
            "shared_report",
            str(project),
            str(counter),
        ]

    service = ScanJobService(
        project / "zscope.yaml", scan_command_builder=builder, terminate_grace=2.0
    )
    terminal = wait_terminal(service, job_id)
    assert terminal["status"] == "completed"
    assert terminal["report"]["available"] is True
    assert counter.read_text(encoding="utf-8").count("scanner") == 1
    resend = service.start(request_id="req-disconnect-retry")
    assert resend.status_code == 202
    replayed = resend.payload["job"]
    assert replayed["job_id"] == job_id
    assert replayed["run_id"] == terminal["run_id"]
    assert replayed["status"] == "completed"
    assert replayed["report"]["available"] is True
    assert len(service.list().payload["jobs"]) == 1
    # The replay started nothing: still exactly one scanner invocation.
    assert counter.read_text(encoding="utf-8").count("scanner") == 1
    kinds = event_kinds(service, job_id)
    assert any(kind == "request_replayed" for kind in kinds)
    assert kinds.count("job_created") == 1


def test_duplicate_cancel_on_running_job_replays_outcome(job_env):
    job_env["mode_box"][0] = "sleep"
    service = job_env["factory"]()
    job = start_job(service, request_id="req-dup-cancel")
    job_id = job["job_id"]
    wait_running(service, job_id)
    current = service.detail(job_id).payload["job"]
    first = service.cancel(
        job_id, base_revision=current["revision"], request_id="req-dup-cancel-op"
    )
    assert first.status_code == 200
    # The duplicate cancel (same key, same base revision) replays the
    # recorded outcome instead of failing with a revision conflict.
    duplicate = service.cancel(
        job_id, base_revision=current["revision"], request_id="req-dup-cancel-op"
    )
    assert duplicate.status_code == 200
    assert duplicate.payload["job"]["job_id"] == job_id
    terminal = wait_terminal(service, job_id)
    assert terminal["status"] == "cancelled"
    events = service.events(job_id, 0).payload["events"]
    assert len([event for event in events if event["kind"] == "cancel_requested"]) == 1
    assert any(event["kind"] == "request_replayed" for event in events)


def test_duplicate_resume_during_paused_launch_replays_single_attempt(job_env):
    # The same reservation-first guarantee for resume: while the first resume
    # handler is stalled mid-launch, a duplicate replays the armed attempt —
    # exactly one new attempt is ever launched.
    job_env["mode_box"][0] = "sleep"
    service = job_env["factory"]()
    job = start_job(service, request_id="req-dup-resume")
    job_id = job["job_id"]
    running = wait_running(service, job_id)
    owner_pid = int(running["owner_pid"])
    os.kill(owner_pid, signal.SIGKILL)
    os.waitpid(owner_pid, 0)
    lost = wait_for(
        lambda: (
            service.detail(job_id).payload["job"]
            if service.detail(job_id).payload["job"]["status"] == "lost"
            else None
        ),
        description=f"lost state of {job_id}",
    )
    job_env["mode_box"][0] = "shared_report"
    paused = threading.Event()
    release = threading.Event()
    paused_service = _PausedLaunchService(
        job_env["project"] / "zscope.yaml",
        paused=paused,
        release=release,
        scan_command_builder=lambda config_path, scan_depth, python_executable: [
            python_executable,
            str(job_env["scanner"]),
            "shared_report",
            str(job_env["project"]),
        ],
        terminate_grace=2.0,
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(
            paused_service.resume,
            job_id,
            base_revision=lost["revision"],
            request_id="req-dup-resume-op",
        )
        assert paused.wait(15), "resume handler did not reach the launch pause"
        duplicate = job_env["factory"]().resume(
            job_id, base_revision=lost["revision"], request_id="req-dup-resume-op"
        )
        assert duplicate.status_code == 202, duplicate.payload
        assert duplicate.payload["job"]["run_id"] != lost["run_id"]
        armed_run = duplicate.payload["job"]["run_id"]
        release.set()
        original = first.result(timeout=60)
        assert original.status_code == 202, original.payload
        assert original.payload["job"]["run_id"] == armed_run
    terminal = wait_terminal(paused_service, job_id)
    assert terminal["status"] == "completed"
    attempts = store_for(job_env["project"]).list_attempts(job_id)
    assert [attempt["status"] for attempt in attempts] == ["lost", "completed"]
    events = service.events(job_id, 0).payload["events"]
    assert len([event for event in events if event["kind"] == "attempt_started"]) == 1
    assert any(event["kind"] == "request_replayed" for event in events)
