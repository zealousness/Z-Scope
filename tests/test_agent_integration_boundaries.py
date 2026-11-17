"""Real HTTP preparation and conservative coverage integration boundaries."""

import http.server
import json
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from zscope.reporting.acceptance import acceptance_coverage
from zscope.web import server
from zscope.web.services import ConfigService
from zscope.web.services import ReportFeedbackService
from zscope.web.scan_jobs_service import ScanJobsHttpService


def test_v3_multiple_targets_prepare_over_actual_http(tmp_path, monkeypatch):
    document = {
        "config_version": 3,
        "llms": {
            "default": {
                "base_urls": ["http://localhost/v1"],
                "models": ["unit-model"],
                "api_key": "dummy-private-key",
            }
        },
        "project": {
            "language": "c_cpp",
            "platform": "linux_user",
            "targets": [
                {"id": "a", "compile_commands": "a.json"},
                {"id": "b", "compile_commands": "b.json"},
            ],
        },
        "scan": {"preset": "fast"},
    }
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(server, "_config_service", ConfigService(path))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), server.ZScopeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        with urlopen(
            f"http://127.0.0.1:{httpd.server_port}/api/scan/prepare", timeout=5
        ) as response:
            raw = response.read().decode()
        data = json.loads(raw)
        assert data["read_only"] is True
        assert [target["id"] for target in data["version3"]["targets"]] == ["a", "b"]
        assert data["build"]["status"] == "multi_target"
        assert data["version3"]["start_capability"]["startable"] is False
        assert "dummy-private-key" not in raw and "http://localhost/v1" not in raw
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_compile_planning_does_not_hide_analysis_coverage_gap():
    report = {
        "completeness": "complete",
        "metadata": {
            "entry_instances": {
                "scan_coverage_complete": False,
                "gaps": [{"reason": "entry_absent_in_variant", "detail": "variant b"}],
            }
        },
    }
    coverage = acceptance_coverage(report)
    kinds = {gap["kind"] for gap in coverage["gaps"]}
    assert "entry_instance_coverage_incomplete" in kinds
    assert "entry_instance_analysis_unwired" not in kinds
    assert {"kind": "entry_absent_in_variant", "detail": "variant b"} in coverage["gaps"]
    assert coverage["completeness"] == "complete"


def test_actual_job_engine_over_http_with_controlled_scanner(tmp_path, monkeypatch):
    """Real SQLite/owner/HTTP; scanner emits explicitly synthetic evidence."""
    from semantics_fixtures import reviewed_control_plane_project
    from test_config_options import _config, _write
    from zscope.orchestration.jobs.service import ScanJobService

    project = tmp_path / "real job HTTP with spaces"
    project.mkdir()
    (project / "unit.c").write_text("int main(void) { return 0; }\n")
    config = _write(project, _config(project))
    scanner = tmp_path / "controlled-scanner.py"
    scanner.write_text(
        "import sys\nfrom pathlib import Path\n"
        "from zscope.reporting.json_io import write_report_atomic\n"
        "write_report_atomic(Path(sys.argv[1])/'report.json', "
        "{'schema_version':2,'issues':[], 'completeness':'complete',"
        "'metadata':{'synthetic_only':True,'fixture_kind':'controlled-scanner'}})\n"
    )
    monkeypatch.setenv("PYTHONPATH", str(__import__("pathlib").Path(__file__).resolve().parents[1]))
    engine = ScanJobService(
        config,
        scan_command_builder=lambda path, depth, executable: [
            executable,
            str(scanner),
            str(project),
        ],
    )
    feedback = ReportFeedbackService(report_filename=str(project / "report.json"))
    monkeypatch.setattr(
        server, "_scan_jobs_http_service", ScanJobsHttpService(config, feedback, engine=engine)
    )
    # Exercise the explicitly bound single-project service, independently of
    # project-picker globals left by other HTTP tests.
    monkeypatch.setattr(server, "_project_library", None)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), server.ZScopeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    def call(path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        request = Request(
            f"http://127.0.0.1:{httpd.server_port}" + path,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            response = urlopen(request, timeout=10)
        except HTTPError as error:
            response = error
        with response:
            return response.status, json.loads(response.read())

    try:
        payload = {"request_id": "actual-http-create"}
        status, rejected = call("/api/jobs", payload)
        assert status == 409 and rejected["code"] == "project_semantics_not_ready"
        assert call("/api/jobs")[1]["jobs"] == []
        # Supply the current onboarding precondition instead of bypassing the
        # production gate. This receipt only tests the synthetic control plane.
        reviewed_control_plane_project(config)
        status, created = call("/api/jobs", payload)
        assert status == 202, created
        job_id = created["job"]["job_id"]
        assert call("/api/jobs", payload)[1]["job"]["job_id"] == job_id
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            job = call(f"/api/jobs/detail?job_id={job_id}")[1]["job"]
            if job["status"] in {"completed", "partial", "failed", "lost"}:
                break
            time.sleep(0.1)
        assert job["status"] == "completed", job
        assert len(call("/api/jobs")[1]["jobs"]) == 1
        events = call(f"/api/jobs/events?job_id={job_id}&after_seq=0")[1]
        assert events["events"]
        result = call(f"/api/jobs/result?job_id={job_id}")[1]
        assert result["report_available"] is True
        assert result["findings"]["findings"] == []
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
