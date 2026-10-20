"""Real owner/store/CLI/shared token; only the analysis body is controlled."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0,str(Path(os.environ["PYTHONPATH"])/"tests"))
from test_config_stop_at_consumers import _make_project, _store_for
from zscope.orchestration.jobs.service import ScanJobService

HELPER = '''import json, os, sys, time
from pathlib import Path
from zscope.orchestration.scan_session import ScanSessionRunner, ScanSessionResult
from zscope.orchestration.execution_profile import session_cancellation_token
def controlled_analysis(self):
    token = session_cancellation_token(self)
    out = Path(os.environ["ZSCOPE_JOB_RUN_DIR"]) / "cli-budget.json"
    out.write_text(json.dumps({"remaining": token.remaining_seconds(), "wall_epoch": time.time(), "reason": token.reason, "job_id": os.environ["ZSCOPE_JOB_ID"], "run_id": os.environ["ZSCOPE_JOB_RUN_ID"], "shared_token": token is self.session_executor.cancellation_token}), encoding="utf-8")
    # Exit1 is the product's successful finding outcome, so use an explicit
    # controlled runtime failure to make the first attempt legitimately resumable.
    raise SystemExit(91)
ScanSessionRunner.run = controlled_analysis
from zscope.cli.cli import main
main(args=["-c", sys.argv[1], "--discover-entries"], standalone_mode=False)
'''


def make_service(tmp_path, stop_at):
    project=_make_project(tmp_path,execution={"timezone":"UTC","stop_at":stop_at})
    helper=tmp_path/"cli-window-helper.py"
    helper.write_text(HELPER,encoding="utf-8")
    def command(config_path,scan_depth,python_executable):
        return [python_executable,str(helper),str(config_path)]
    return project,ScanJobService(project/"zscope.yaml",scan_command_builder=command,terminate_grace=1)


def terminal(service,job_id):
    end=time.monotonic()+45
    while time.monotonic()<end:
        response=service.detail(job_id)
        assert response.status_code==200,response.payload
        job=response.payload["job"]
        if job["status"] in {"completed","partial","cancelled","failed","lost"}:
            return job
        time.sleep(.1)
    raise AssertionError("real owner did not reach a terminal state")


def observation(project,job):
    path=project/".zscope_jobs"/job["job_id"]/job["run_id"]/"cli-budget.json"
    assert path.is_file(), "real CLI refused before controlled analysis; persisted job window must win over config"
    data=json.loads(path.read_text(encoding="utf-8"))
    assert data["shared_token"] and data["job_id"]==job["job_id"] and data["run_id"]==job["run_id"]
    return data


def test_real_owner_cli_uses_explicit_window_instead_of_config_window(tmp_path):
    now=datetime.now(timezone.utc)
    project,service=make_service(tmp_path,"00:00")
    explicit=now+timedelta(seconds=60)
    response=service.start(request_id="req-explicit-cli-window",stop_at=explicit.isoformat())
    assert response.status_code==202,response.payload
    job=terminal(service,response.payload["job"]["job_id"])
    assert datetime.fromisoformat(job["resolved_stop_time"])==explicit
    data=observation(project,job)
    assert data["remaining"] is not None and 0<data["remaining"]
    assert abs(data["remaining"]-(explicit.timestamp()-data["wall_epoch"]))<.5, "real shared budget must match the persisted explicit epoch"


def test_real_resumed_cli_does_not_reapply_cleared_config_window(tmp_path):
    stop=(datetime.now(timezone.utc)+timedelta(minutes=5)).strftime("%H:%M")
    project,service=make_service(tmp_path,stop)
    response=service.start(request_id="req-before-resume-cli-window")
    assert response.status_code==202,response.payload
    first=terminal(service,response.payload["job"]["job_id"])
    assert observation(project,first)["remaining"] is not None
    response=service.resume(first["job_id"],base_revision=first["revision"],request_id="req-resume-cli-window")
    assert response.status_code==202,response.payload
    resumed=terminal(service,first["job_id"])
    row=_store_for(project).get_job(first["job_id"])
    assert resumed["run_id"]!=first["run_id"] and row["stop_at_epoch"] is None
    assert observation(project,resumed)["remaining"] is None, "resume SQL cleared the window, but CLI silently armed config again"
