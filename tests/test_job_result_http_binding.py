"""Real HTTP/SQLite/owner attempts; only scanner/report and race timing controlled."""

import http.server
import json
import threading
from urllib.request import urlopen

import pytest

from test_job_result_projection import SCANNER_SCRIPT, run_to_terminal
from test_scan_jobs import make_project
from test_scan_job_execution import wait_terminal
from zscope.orchestration.jobs.service import ScanJobService
from zscope.reporting.json_io import read_report
from zscope.web import server
from zscope.web.scan_jobs_service import ScanJobsHttpService
from zscope.web.services import ReportFeedbackService
from zscope.web.review_reports import report_identity


@pytest.fixture
def actual_http(tmp_path, monkeypatch):
    project = make_project(tmp_path)
    scanner = tmp_path / "scanner.py"
    scanner.write_text(
        SCANNER_SCRIPT.replace('elif mode == "shared":', 'elif mode == "shared_exit2":').replace(
            "write_report_atomic(report, REPORT)",
            "write_report_atomic(report, REPORT)\n    sys.exit(2)",
        ),
        encoding="utf-8",
    )
    servers = []

    def connect(service, current):
        http_service = ScanJobsHttpService(
            project / "zscope.yaml",
            ReportFeedbackService(report_filename=str(current)),
            engine=service,
        )
        monkeypatch.setattr(server, "_scan_jobs_http_service", http_service)
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), server.ZScopeHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        servers.append((httpd, thread))

        def result(job_id):
            with urlopen(
                f"http://127.0.0.1:{httpd.server_port}/api/jobs/result?job_id={job_id}", timeout=60
            ) as response:
                assert response.status == 200
                return json.loads(response.read())

        return result

    try:
        yield project, scanner, connect
    finally:
        for daemon, thread in servers:
            daemon.shutdown()
            daemon.server_close()
            thread.join(timeout=5)
            assert not thread.is_alive()


@pytest.mark.parametrize("mode", ["report_exit2", "shared_exit2"])
def test_actual_http_does_not_label_old_envelope_with_new_same_hash_run(actual_http, mode):
    project, scanner, connect = actual_http

    class MovingResult(ScanJobService):
        move = True
        current = None

        def result(self, job_id):
            response = super().result(job_id)
            if self.move:
                self.move = False
                old = self.detail(job_id).payload["job"]
                resumed = self.resume(
                    job_id, base_revision=old["revision"], request_id="http-same-hash-race-resume"
                )
                assert resumed.status_code == 202, resumed.payload
                self.current = wait_terminal(self, job_id)
                assert self.current["run_id"] != old["run_id"]
                assert self.current["report"]["report_id"] == old["report"]["report_id"]
            return response

    def builder(config_path, scan_depth, python_executable):
        return [python_executable, str(scanner), mode, str(project)]

    service = MovingResult(project / "zscope.yaml", scan_command_builder=builder)
    job, first = run_to_terminal(service, request_id="http-result-race-start")
    call = connect(service, project / "zscope_batch_report.json")
    result = call(job["job_id"])
    assert result["binding"]["run_id"] == service.current["run_id"]
    assert result["binding"]["run_id"] != first["run_id"]
    fresh = service.result(job["job_id"]).payload
    for field in ("report_id", "coverage", "questions", "artifacts"):
        assert result[field] == fresh[field]
    assert result["findings"]["findings"][0]["id"] == "iss-1"
    assert result["review_scope"]["shared_with_current"] is True


def test_actual_http_keeps_the_selected_single_report_review_scope(actual_http):
    project, scanner, connect = actual_http

    def builder(config_path, scan_depth, python_executable):
        return [python_executable, str(scanner), "report_exit2", str(project)]

    service = ScanJobService(project / "zscope.yaml", scan_command_builder=builder)
    job, terminal = run_to_terminal(service, request_id="http-selected-single-report")
    selected = project / "report.json"
    selected.write_bytes((project / "zscope_batch_report.json").read_bytes())
    call = connect(service, selected)
    result = call(job["job_id"])
    logical = read_report(selected)
    assert result["findings"]["report_id"] == report_identity(logical, str(selected))
    assert result["review_scope"]["shared_with_current"] is True
    selected.write_text(json.dumps({"issues": []}), encoding="utf-8")
    historical = call(job["job_id"])
    assert historical["findings"]["findings"][0]["id"] == "iss-1"
    assert historical["review_scope"]["shared_with_current"] is False
    assert historical["findings"]["report_id"] == report_identity(
        logical, terminal["report"]["path"]
    )
