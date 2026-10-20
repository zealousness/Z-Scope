"""Measured owner remaining over real SQLite and detached scanner processes.

The scanner's report and queue work are controlled inputs. This verifies job
accounting and terminal honesty, not actual static-analysis effectiveness.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from test_scan_jobs import make_project, start_job
from test_scan_job_execution import wait_terminal
from zscope.orchestration.jobs.service import ScanJobService
from zscope.orchestration.jobs.models import PENDING_SCHEMA_VERSION
from zscope.orchestration.jobs.work_queue import WorkQueue, read_bound_queue_counts

SCANNER = """
import json, os, sys
from pathlib import Path
from zscope.orchestration.jobs.store import JobStore
from zscope.orchestration.jobs.work_queue import WorkQueue

root, mode = Path(sys.argv[1]), sys.argv[2]
store = Path(os.environ['ZSCOPE_JOB_STORE'])
job_id = os.environ['ZSCOPE_JOB_ID']
row = JobStore(store).get_job(job_id)
path = store.parent / job_id / 'work-queue.db'
if mode == 'corrupt':
    path.write_text('not sqlite')
elif mode != 'no_queue':
    queue = WorkQueue(path, job_id='foreign' if mode == 'foreign_job' else job_id,
        input_revision='old-input' if mode == 'foreign_input' else row['input_revision'],
        max_attempts=1)
    queue.enqueue([{'kind':'controlled','scope_key':str(i),'build':'build-a'}
        for i in range(3)], batch_no=1)
    if mode in ('drained', 'failed'):
        items = queue.claim_batch(3)['claimed']
        for item in items:
            if mode == 'failed':
                queue.defer(item['item_id'], 'controlled_failure', claim_token=item['claim_token'])
            else:
                queue.complete(item['item_id'], claim_token=item['claim_token'])
(root / 'zscope_batch_report.json').write_text(json.dumps({
    'completeness':'complete',
    'metadata':{'business_questions':[{'id':'q-one','question':'Controlled question'}]}
}))
"""


@pytest.mark.parametrize(
    "mode,status,remaining",
    [
        ("no_queue", "completed", None),
        ("pending", "partial", 3),
        ("drained", "completed", 0),
        ("failed", "partial", 0),
        ("foreign_input", "completed", None),
        ("foreign_job", "completed", None),
        ("corrupt", "completed", None),
    ],
)
def test_owner_remaining_is_queue_measurement(tmp_path, mode, status, remaining):
    project = make_project(tmp_path)
    scanner = tmp_path / "controlled.py"
    scanner.write_text(SCANNER, encoding="utf-8")

    def builder(config_path, scan_depth, python_executable):
        return [python_executable, str(scanner), str(project), mode]

    service = ScanJobService(project / "zscope.yaml", scan_command_builder=builder)
    job = start_job(service, request_id="remaining-" + mode)
    terminal = wait_terminal(service, job["job_id"])
    assert terminal["status"] == status, terminal
    assert terminal["report"]["available"] is True, terminal
    assert len(terminal["questions"]) == 1
    assert terminal["pending_count"] == remaining
    if status == "partial":
        assert terminal["error"]["code"] == "scan_incomplete"
        assert terminal["capabilities"]["resume"] is True
    # Reconstruction reads the same durable numbers, not a client cache.
    rebuilt = ScanJobService(project / "zscope.yaml").detail(job["job_id"]).payload["job"]
    assert rebuilt["pending_count"] == remaining
    assert rebuilt["status"] == status


def test_count_reader_does_not_create_or_rebind_queue(tmp_path):
    path = tmp_path / "missing queue.db"
    assert read_bound_queue_counts(path, job_id="job", input_revision="input") is None
    assert not path.exists()
    queue = WorkQueue(path, job_id="job", input_revision="input")
    queue.enqueue([{"kind": "analysis", "scope_key": "entry", "build": "b"}], batch_no=1)
    before = hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns
    assert read_bound_queue_counts(path, job_id="other", input_revision="input") is None
    assert read_bound_queue_counts(path, job_id="job", input_revision="old") is None
    assert read_bound_queue_counts(path, job_id="job", input_revision="") is None
    assert read_bound_queue_counts(path, job_id="job", input_revision="input")["pending"] == 1
    assert (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns) == before


def test_real_session_remaining_survives_owner_finalization(tmp_path):
    """Persist a measured completed/deferred split through owner finalization.

    The shared hold4 scanner uses one worker and real WorkDefer outcomes.
    The unchanged slow8 scheduler test separately verifies that a window
    stops new claims with two workers.
    """
    from test_job_session_scheduler import (
        SCANNER_SCRIPT,
        PENDING_SOURCE_WINDOW,
        exec_lines,
        scanner_service,
        wait_running,
        queue_rows,
        job_queue_path,
    )

    project = make_project(tmp_path)
    scanner = tmp_path / "session.py"
    scanner.write_text(SCANNER_SCRIPT, encoding="utf-8")
    control = tmp_path / "control"
    control.mkdir()
    (control / "hold.flag").write_text("hold\n", encoding="utf-8")
    service = scanner_service(project, scanner, ["hold4"], control)
    stop_at = (datetime.now(timezone.utc) + timedelta(seconds=2.5)).isoformat()
    job = start_job(service, request_id="remaining-window", stop_at=stop_at)
    running = wait_running(service, job["job_id"])
    terminal = wait_terminal(service, job["job_id"])
    assert terminal["status"] == "partial"
    assert terminal["error"]["code"] == "stop_window_reached"
    pending = json.loads((Path(running["run_dir"]) / "pending.json").read_text(encoding="utf-8"))
    meta, rows = queue_rows(job_queue_path(project, job["job_id"]))
    assert meta["job_id"] == job["job_id"]
    assert meta["input_revision"] == terminal["input_revision"]
    assert len(rows) == 4
    assert {row["scope_key"] for row in rows if row["status"] == "completed"} == {"s1", "s2"}
    assert {row["scope_key"] for row in rows if row["status"] == "deferred"} == {"s3", "s4"}
    remaining = sum(row["status"] in {"pending", "active", "deferred"} for row in rows)
    assert remaining == 2
    assert all(row["total_attempts"] == 1 for row in rows)
    assert all(
        row["last_defer_reason"] == "controlled-hold" for row in rows if row["status"] == "deferred"
    )
    assert pending["schema"] == PENDING_SCHEMA_VERSION
    assert pending["capped"] is False
    assert len(pending["items"]) == 2
    assert pending["source"] == PENDING_SOURCE_WINDOW
    assert pending["job_id"] == job["job_id"]
    assert pending["run_id"] == terminal["run_id"]
    assert {item["scope_key"] for item in pending["items"]} == {"s3", "s4"}
    assert all(item["build"] == "b1" for item in pending["items"])
    assert terminal["pending_count"] == pending["count"] == remaining
    summary = json.loads(
        (control / f"summary-{terminal['run_id']}.json").read_text(encoding="utf-8")
    )
    assert summary["status"] == "window_closed"
    assert summary["counts"]["completed"] == 2
    assert summary["counts"]["deferred"] == summary["remaining_count"] == remaining
    executed = [line["scope"] for line in exec_lines(control, terminal["run_id"])]
    assert sorted(executed) == ["s1", "s2", "s3", "s4"]
    rebuilt = ScanJobService(project / "zscope.yaml").detail(job["job_id"]).payload["job"]
    assert rebuilt["status"] == "partial"
    assert rebuilt["run_id"] == terminal["run_id"]
    assert rebuilt["pending_count"] == remaining
    kinds = [event["kind"] for event in service.events(job["job_id"], 0).payload["events"]]
    assert "window_cooperative_exit" in kinds
    assert "pending_preserved" in kinds
    assert "window_watchdog" not in kinds
    assert "scan_terminated" not in kinds
