"""Owner reads the current scheduler's actual queue over real Linux processes.

Work bodies/report contents are controlled. SQLite, scheduler, detached owner,
window and accounting execute product code; this is accounting acceptance.
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from test_scan_jobs import make_project, start_job
from test_scan_job_execution import wait_terminal
from test_job_session_scheduler import SCANNER_SCRIPT, scanner_service, queue_rows


@pytest.mark.parametrize("mode", ["drain", "slow"])
def test_actual_attempt_queue_receipt_overrides_unused_canonical_queue(tmp_path, mode):
    project = make_project(tmp_path)
    scanner = tmp_path / "session.py"
    extra = """
from zscope.orchestration.jobs.store import JobStore
from zscope.orchestration.jobs.work_queue import WorkQueue
row = JobStore(ctx.store_path).get_job(ctx.job_id)
canonical = Path(ctx.store_path).parent / ctx.job_id / 'work-queue.db'
stale = WorkQueue(canonical,job_id=ctx.job_id,input_revision=row['input_revision'])
stale.enqueue([{'kind':'unused','scope_key':str(i),'build':'b'} for i in range(99)],batch_no=1)
actual_queue = Path(ctx.store_path).parent / ctx.job_id / ('work-queue.db.'+ctx.run_id)
"""
    script = SCANNER_SCRIPT.replace(
        "scheduler = SessionWorkScheduler(\n",
        extra + "\nscheduler = SessionWorkScheduler(\n    work_queue_path=actual_queue,\n",
    )
    assert script != SCANNER_SCRIPT
    scanner.write_text(script, encoding="utf-8")
    control = tmp_path / "control"
    service = scanner_service(project, scanner, [mode], control)
    options = (
        {"stop_at": (datetime.now(timezone.utc) + timedelta(seconds=2.5)).isoformat()}
        if mode == "slow"
        else {}
    )
    job = start_job(service, request_id="actual-queue-" + mode, **options)
    terminal = wait_terminal(service, job["job_id"])
    events = service.events(job["job_id"], 0).payload["events"]
    receipt = next(row for row in events if row["kind"] == "session_scheduler_started")
    assert receipt["run_id"] == terminal["run_id"]
    assert receipt["data"]["input_revision"] == terminal["input_revision"]
    actual = Path(receipt["data"]["work_queue"])
    _, rows = queue_rows(actual)
    remaining = sum(row["status"] in {"pending", "active", "deferred"} for row in rows)
    assert terminal["pending_count"] == remaining
    assert remaining != 99
    if mode == "drain":
        assert terminal["status"] == "completed" and remaining == 0
    else:
        assert terminal["status"] == "partial" and 0 < remaining < 8
        pending = json.loads(
            (actual.parent / terminal["run_id"] / "pending.json").read_text(encoding="utf-8")
        )
        assert pending["count"] == remaining
        assert "window_cooperative_exit" in {row["kind"] for row in events}


BAD_RECEIPT_SCANNER = r"""
import json,os,sys
from pathlib import Path
from zscope.orchestration.jobs.store import JobStore
from zscope.orchestration.jobs.work_queue import WorkQueue
root,mode = Path(sys.argv[1]),sys.argv[2]
store=JobStore(os.environ['ZSCOPE_JOB_STORE'])
job_id,run_id=os.environ['ZSCOPE_JOB_ID'],os.environ['ZSCOPE_JOB_RUN_ID']
row=store.get_job(job_id)
directory=Path(row['run_dir']).parent
canonical=directory/'work-queue.db'
unused=WorkQueue(canonical,job_id=job_id,input_revision=row['input_revision'])
unused.enqueue([{'kind':'unused','scope_key':'unused','build':'b'}],batch_no=1)
path=directory/'work-queue.db.receipt'
if mode in ('outside','symlink'):
    outside=root.parent/'work-queue.db.outside'
    queue=WorkQueue(outside,job_id=job_id,input_revision=row['input_revision'])
    if mode=='symlink':
        path.symlink_to(outside)
    else:
        path=outside
elif mode!='missing':
    queue=WorkQueue(path,job_id='foreign' if mode=='foreign_job' else job_id,input_revision=row['input_revision'])
data={'work_queue':str(path),'input_revision':'wrong' if mode=='foreign_input' else row['input_revision']}
if mode=='relative':
    data['work_queue']='work-queue.db.receipt'
store.append_event(job_id,run_id=run_id,kind='session_scheduler_started',message='Controlled damaged receipt',data=data)
(root/'zscope_batch_report.json').write_text(json.dumps({'completeness':'complete','issues':[]}))
"""


@pytest.mark.parametrize(
    "mode", ["foreign_input", "foreign_job", "outside", "symlink", "relative", "missing"]
)
def test_invalid_queue_receipt_stays_unknown_without_fallback_or_creation(tmp_path, mode):
    from zscope.orchestration.jobs.service import ScanJobService

    project = make_project(tmp_path)
    scanner = tmp_path / "damaged_receipt.py"
    scanner.write_text(BAD_RECEIPT_SCANNER, encoding="utf-8")

    def builder(config_path, scan_depth, python_executable):
        return [python_executable, str(scanner), str(project), mode]

    service = ScanJobService(project / "zscope.yaml", scan_command_builder=builder)
    job = start_job(service, request_id="invalid-queue-receipt-" + mode)
    terminal = wait_terminal(service, job["job_id"])
    assert terminal["status"] == "completed", terminal
    assert terminal["pending_count"] is None, terminal
    if mode == "missing":
        events = service.events(job["job_id"], 0).payload["events"]
        receipt = next(row for row in events if row["kind"] == "session_scheduler_started")
        assert not Path(receipt["data"]["work_queue"]).exists()
