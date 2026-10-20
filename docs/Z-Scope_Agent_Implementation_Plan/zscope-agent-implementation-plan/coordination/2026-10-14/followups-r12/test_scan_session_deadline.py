"""Actual owner stop_at must reach an in-flight native ScanSession token."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import os
import time

import yaml
from test_scan_session_crash_resume import (
    make_project, native_saved_config, SCANNER, start_job, store_for, wait_terminal,
)
from zscope.orchestration.jobs.service import ScanJobService


def test_actual_owner_deadline_stops_inflight_analysis_cooperatively(tmp_path):
    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "actual native tool required"
    project = make_project(tmp_path)
    source = project / "unit.c"
    source.write_text('#include <stdlib.h>\nvoid f(void){char *p=malloc(4); if(!p)return; free(p);}\n', encoding="utf-8")
    database = project / "compile_commands.json"
    database.write_text(json.dumps([{"directory":str(project),"file":str(source),"arguments":["clang","-c",str(source),*flags]} for flags in ([],["-DALT=1"])]), encoding="utf-8")
    config_path = project / "zscope.yaml"
    config_path.write_text(yaml.safe_dump(native_saved_config(project),sort_keys=False), encoding="utf-8")
    scanner, control = tmp_path / "actual_scan.py", tmp_path / "control"
    scanner.write_text(SCANNER, encoding="utf-8")

    def builder(config_path, scan_depth, python_executable):
        return [python_executable,str(scanner),str(project),"blocking",str(control)]

    service = ScanJobService(config_path,scan_command_builder=builder,terminate_grace=2.0)
    stop_at = datetime.now(timezone.utc) + timedelta(seconds=15)
    job = start_job(service,stop_at=stop_at.isoformat(),request_id="actual-inflight-deadline")
    until = time.monotonic() + 60
    while not (control / "inflight.json").exists() and time.monotonic() < until:
        if service.detail(job["job_id"]).payload["job"]["status"] in {"failed","partial","cancelled","completed","lost"}:
            break
        time.sleep(.1)
    assert (control / "inflight.json").is_file(), service.detail(job["job_id"]).payload
    final = wait_terminal(service,job["job_id"])
    assert final["status"] == "partial", final
    assert final["error"]["code"] == "stop_window_reached", final
    observed = control / "cancel-observed.json"
    assert observed.is_file(), "actual Analyzer ignored the owner stop_at token"
    assert json.loads(observed.read_text(encoding="utf-8"))["reason"] == "job_deadline_exceeded"
    assert not (control / "wait-expired.json").exists()
    events = service.events(job["job_id"],after_seq=0).payload["events"]
    assert not {"cancel_watchdog","window_watchdog"} & {row["kind"] for row in events}, events
    assert "window_cooperative_exit" in {row["kind"] for row in events}, events
    teardown = [row for row in events if row["kind"] == "scan_terminated"]
    assert all(row["data"]["outcome"] == "already_exited" for row in teardown), teardown
    pending_path = Path(store_for(project).get_job(job["job_id"])["run_dir"]) / "pending.json"
    pending = json.loads(pending_path.read_text(encoding="utf-8"))
    assert pending["items"] and pending["count"] > 0, pending
