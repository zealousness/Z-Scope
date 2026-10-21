"""Real HTTP rendering of controlled reports/configs, not a scan acceptance."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(sys.platform != "linux", reason="UI checks require Linux")
@pytest.mark.parametrize("case", ["incomplete", "explicit-unwired", "unknown"])
def test_capability_boundaries_real_http(tmp_path, monkeypatch, case):
    if not os.environ.get("ZSCOPE_UI_PLAYWRIGHT_MODULE"):
        pytest.skip("Linux Playwright required")
    from test_config_v3_preparation import _document, _materialize_project, _write
    from zscope.reporting.report import FinalReport
    from zscope.web import server, services
    from zscope.web.scan_jobs_service import ScanJobsHttpService

    project = _materialize_project(tmp_path / "capability boundaries")
    document = _document()
    if case == "unknown":
        document["execution"].pop("stop_at")
    config = _write(project, document)
    report = FinalReport(entry_function="main", overall_verdict="no_issue_found")
    if case != "unknown":
        report.metadata["entry_instances"] = {
            "schema": "zscope.entry-instances.v1",
            "planned_instances": 2,
            "scheduled_instances": 2,
            "scan_coverage_complete": False,
            "gaps": (
                [{"reason": "entry_instance_analysis_unwired", "detail": "producer evidence"}]
                if case == "explicit-unwired"
                else []
            ),
            "instance_analysis": {
                "schema": "zscope.instance-analysis.v1",
                "analyzed_instances": 2,
                "instance_scope_complete": True,
                "scan_coverage_complete": False,
            },
        }
    report_path = project / "report.json"
    report_path.write_text(json.dumps(report.to_dict()), encoding="utf-8")
    feedback = services.ReportFeedbackService(report_filename=str(report_path))
    monkeypatch.setattr(server, "_config_service", services.ConfigService(config))
    monkeypatch.setattr(server, "_report_feedback_service", feedback)
    monkeypatch.setattr(server, "_scan_jobs_http_service", ScanJobsHttpService(config, feedback))
    output = ROOT / os.environ["ZSCOPE_UX_BOUNDARY_EVIDENCE"] / case
    output.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.ZScopeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [shutil.which("node") or "node", "tests/fixtures/ux_capability_boundaries_ui.cjs"],
            cwd=ROOT,
            env=dict(
                os.environ,
                ZSCOPE_UI_BASE_URL=f"http://127.0.0.1:{httpd.server_port}",
                ZSCOPE_UX_BOUNDARY_CASE=case,
                ZSCOPE_UX_BOUNDARY_EVIDENCE=str(output),
            ),
            capture_output=True,
            text=True,
            timeout=120,
        )
        (output / "browser.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        assert result.returncode == 0, result.stdout + result.stderr
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
