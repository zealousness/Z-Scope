"""Real detached owner/CLI identity rejection; only analysis and tampering controlled."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_job_cli_effective_window_boundary import HELPER, _make_project, terminal
from zscope.orchestration.jobs.service import ScanJobService


@pytest.mark.parametrize("tamper", [
    "os.environ.pop('ZSCOPE_JOB_RUN_ID')",
    "os.environ['ZSCOPE_JOB_RUN_ID']='foreign-run'",
    "os.environ['ZSCOPE_JOB_OWNER_TOKEN']='foreign-owner'",
    "os.environ['ZSCOPE_JOB_RUN_DIR']=str(Path(sys.argv[1]).parent/'foreign-run-dir')",
    "os.environ['ZSCOPE_JOB_STORE']=str(Path(sys.argv[1]).parent/'absent-store.db')",
    "import sqlite3; db=sqlite3.connect(os.environ['ZSCOPE_JOB_STORE']); db.execute('UPDATE jobs SET input_revision=? WHERE job_id=?', ('foreign-input',os.environ['ZSCOPE_JOB_ID'])); db.commit(); db.close()",
])
def test_real_cli_rejects_partial_or_foreign_job_binding(tmp_path, tamper):
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": "00:00"})
    helper = tmp_path / "identity-helper.py"
    prefix = "import os, sys\nfrom pathlib import Path\n" + tamper + "\n"
    marker = project / "analysis-entered.txt"
    (project / "foreign-run-dir").mkdir()
    assert HELPER.count("def controlled_analysis(self):\n") == 1
    observable = HELPER.replace("def controlled_analysis(self):\n", "def controlled_analysis(self):\n    Path(" + repr(str(marker)) + ").write_text('entered', encoding='utf-8')\n")
    helper.write_text(prefix + observable, encoding="utf-8")

    def command(config_path, scan_depth, python_executable):
        return [python_executable, str(helper), str(config_path)]

    service = ScanJobService(project / "zscope.yaml", scan_command_builder=command, terminate_grace=1)
    response = service.start(request_id="req-identity-window")
    assert response.status_code == 202, response.payload
    job = terminal(service, response.payload["job"]["job_id"])
    run_dir = project / ".zscope_jobs" / job["job_id"] / job["run_id"]
    assert not marker.exists(), "CLI entered analysis before rejecting the unverified job binding"
    assert not (run_dir / "cli-budget.json").exists(), "CLI analysis consumed an unverified job binding"
    assert not (project / "foreign-run-dir" / "cli-budget.json").exists(), "CLI wrote into a foreign attempt directory"
    assert job["status"] == "failed", job
    assert not (project / "absent-store.db").exists(), "read-only binding lookup created a missing store"
