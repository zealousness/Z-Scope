"""HTTP binding and snapshot projection tests; no scanner/owner is simulated as real."""

from __future__ import annotations

import hashlib
import http.server
import json
from pathlib import Path
from types import SimpleNamespace
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from zscope.web import server
from zscope.web.review_reports import report_identity
from zscope.web.scan_jobs_service import ScanJobsHttpService
from zscope.web.services import ReportFeedbackService


class ContractEngine:
    """Explicit contract fixture. Process execution has separate acceptance tests."""

    def __init__(self, snapshot: Path):
        self.snapshot = snapshot
        self.bound_hash = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        self.calls = []
        self.available = True

    def reply(self, **payload):
        return SimpleNamespace(
            status_code=200, payload={"schema": "zscope.scan-jobs.v1", **payload}
        )

    def list(self):
        self.calls.append(("list", {}))
        return self.reply(
            jobs=[], latest_job_id=None, capabilities={"create": False, "reasons": []}
        )

    def detail(self, job_id):
        self.calls.append(("detail", {"job_id": job_id}))
        return self.reply(
            job={
                "job_id": job_id,
                "status": "partial",
                "revision": 4,
                "run_id": "contract-run",
                "input_revision": "contract-input",
                "report": {"report_id": self.bound_hash, "path": str(self.snapshot)},
            }
        )

    def events(self, job_id, after_seq):
        self.calls.append(("events", {"job_id": job_id, "after_seq": after_seq}))
        return self.reply(job_id=job_id, events=[], next_seq=after_seq, has_more=False)

    def start(self, **payload):
        self.calls.append(("start", payload))
        response = self.reply(job={"job_id": "contract-job", "status": "queued", "revision": 1})
        response.status_code = 202
        return response

    def cancel(self, **payload):
        self.calls.append(("cancel", payload))
        return self.reply(job={"job_id": payload["job_id"], "status": "stopping", "revision": 5})

    def resume(self, **payload):
        self.calls.append(("resume", payload))
        response = self.reply(job={"job_id": payload["job_id"], "status": "queued", "revision": 6})
        response.status_code = 202
        return response

    def result(self, job_id):
        return self.reply(
            job_id=job_id,
            report_id=self.bound_hash,
            report_available=self.available,
            reason=None if self.available else "report_not_produced",
            findings=None,
            coverage={"completeness": "partial"},
            questions=[],
            artifacts=[],
        )

    def load_bound_report(self, job_id):
        return {}, self.snapshot


@pytest.fixture
def jobs_http(tmp_path, monkeypatch):
    report = {
        "run_manifest": {"run_id": "explicit-synthetic-run", "project_id": "synthetic-http-only"},
        "issues": [
            {
                "id": "pending-a",
                "function": "entry",
                "location": "sample.c:4",
                "category": "uaf",
                "validation_status": "needs_review",
                "description": "Synthetic projection fixture. " * 2000,
                "build_context_id": "build-a",
                "resource": "object-a",
            }
        ],
        "metadata": {"completeness": "partial"},
    }
    current = tmp_path / "report.json"
    snapshot = tmp_path / "attempt" / "report.json"
    snapshot.parent.mkdir()
    current.write_text(json.dumps(report), encoding="utf-8")
    snapshot.write_bytes(current.read_bytes())
    engine = ContractEngine(snapshot)
    feedback = ReportFeedbackService(report_filename=str(current))
    service = ScanJobsHttpService(tmp_path / "zscope.yaml", feedback, engine=engine)
    monkeypatch.setattr(server, "_scan_jobs_http_service", service)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), server.ZScopeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    def call(method, path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        request = Request(f"http://127.0.0.1:{httpd.server_port}" + path, data=body, method=method)
        request.add_header("Content-Type", "application/json")
        try:
            response = urlopen(request, timeout=5)
        except HTTPError as exc:
            response = exc
        with response:
            return response.status, json.loads(response.read())

    try:
        yield SimpleNamespace(
            call=call,
            engine=engine,
            feedback=feedback,
            report=report,
            current=current,
            snapshot=snapshot,
            service=service,
        )
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_http_routes_preserve_engine_envelopes_and_events_cursor(jobs_http):
    api = jobs_http
    assert api.call("GET", "/api/jobs")[1]["jobs"] == []
    assert api.call("GET", "/api/jobs/detail?job_id=contract-job")[1]["job"]["status"] == "partial"
    assert api.call("GET", "/api/jobs/events?job_id=contract-job&after_seq=4")[1]["next_seq"] == 4
    status, started = api.call("POST", "/api/jobs", {"request_id": "create", "scan_depth": "deep"})
    assert status == 202 and started["job"]["status"] == "queued"
    command = {"job_id": "contract-job", "base_revision": 4, "request_id": "cancel"}
    assert api.call("POST", "/api/jobs/cancel", command)[1]["job"]["status"] == "stopping"
    assert api.call("POST", "/api/jobs/resume", dict(command, request_id="resume"))[0] == 202
    assert api.engine.calls[-1] == ("resume", dict(command, request_id="resume"))


def test_http_rejects_argv_config_and_ambiguous_queries_before_engine(jobs_http):
    api = jobs_http
    for path in (
        "/api/jobs?config=/private",
        "/api/jobs/detail?job_id=a&job_id=b",
        "/api/jobs/events?job_id=a&after_seq=-1",
        "/api/jobs/events?job_id=a&after_seq=1.5",
    ):
        assert api.call("GET", path)[0] == 400
    for payload in (
        {"request_id": "x", "argv": ["arbitrary"]},
        {"request_id": "x", "config_path": "/private"},
        {"request_id": "x", "scan_depth": {}},
        {"request_id": "x", "stop_at": []},
    ):
        assert api.call("POST", "/api/jobs", payload)[0] == 400
    assert (
        api.call(
            "POST", "/api/jobs/cancel", {"job_id": "a", "base_revision": True, "request_id": "x"}
        )[0]
        == 400
    )
    assert api.engine.calls == []


def test_job_snapshot_reuses_real_projection_and_current_review_identity(jobs_http):
    api = jobs_http
    status, result = api.call("GET", "/api/jobs/result?job_id=contract-job")
    assert status == 200 and result["report_available"] is True
    payload = result["findings"]
    assert payload["report_id"] == report_identity(api.report, str(api.current))
    assert payload["findings"][0]["acceptance"]["state"] == "pending"
    assert payload["findings"][0]["acceptance"]["build_context_id"] == "build-a"
    assert len(json.dumps(payload)) < len(api.current.read_bytes()) / 2
    assert payload["coverage"]["build_coverage"] is None
    assert result["report_id"] == api.engine.bound_hash


def test_old_job_never_reads_findings_from_new_current_report(jobs_http):
    api = jobs_http
    changed = dict(api.report, issues=[])
    api.current.write_text(json.dumps(changed), encoding="utf-8")
    _, result = api.call("GET", "/api/jobs/result?job_id=contract-job")
    payload = result["findings"]
    assert len(payload["findings"]) == 1
    assert payload["report_id"] == report_identity(api.report, str(api.snapshot))
    assert payload["report_id"] != report_identity(changed, str(api.current))


def test_current_product_shared_report_storage_is_decoded_before_projection(jobs_http):
    from zscope.reporting.json_io import write_report_atomic

    api = jobs_http
    write_report_atomic(api.snapshot, api.report)
    write_report_atomic(api.current, api.report)
    api.engine.bound_hash = hashlib.sha256(api.snapshot.read_bytes()).hexdigest()
    _, result = api.call("GET", "/api/jobs/result?job_id=contract-job")
    assert result["report_available"] is True
    assert len(result["findings"]["findings"]) == 1
    assert result["findings"]["report_id"] == report_identity(api.report, str(api.current))
    assert result["findings"]["findings"][0]["acceptance"]["state"] == "pending"


def test_invalid_shared_report_graph_is_unavailable_not_empty_safe(jobs_http):
    from zscope.reporting.shared_objects import ObjectEncoder

    api = jobs_http
    storage = ObjectEncoder().envelope(api.report)
    storage["objects"] = {}
    api.snapshot.write_text(json.dumps(storage), encoding="utf-8")
    api.engine.bound_hash = hashlib.sha256(api.snapshot.read_bytes()).hexdigest()
    _, result = api.call("GET", "/api/jobs/result?job_id=contract-job")
    assert result["report_available"] is False
    assert result["findings"] is None
    assert result["reason"] == "report_artifact_invalid"


def test_tampered_or_missing_job_report_does_not_become_empty_complete_result(jobs_http):
    api = jobs_http
    api.snapshot.write_text("{}", encoding="utf-8")
    _, result = api.call("GET", "/api/jobs/result?job_id=contract-job")
    assert result["report_available"] is False and result["findings"] is None
    assert result["reason"] == "report_artifact_mismatch"
    api.engine.available = False
    _, result = api.call("GET", "/api/jobs/result?job_id=contract-job")
    assert result["findings"] is None and result["reason"] == "report_not_produced"


def test_unavailable_job_service_is_explicit_and_does_not_fall_back_to_scan(jobs_http, monkeypatch):
    monkeypatch.setattr(server, "_scan_jobs_http_service", None)
    assert jobs_http.call("GET", "/api/jobs")[0] == 503
    assert jobs_http.call("POST", "/api/jobs", {"request_id": "x"})[0] == 503
    assert jobs_http.engine.calls == []
