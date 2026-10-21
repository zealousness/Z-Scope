"""Real HTTP integration over synthetic, explicitly scoped report evidence."""

from __future__ import annotations

import copy
import http.server
import json
import threading
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pytest

from zscope.config.acceptance_feedback import AcceptanceFeedbackStore
from zscope.reporting.issue_markdown import issue_identity
from zscope.web import server
from zscope.web.acceptance_service import AcceptanceReviewService
from zscope.web.review_reports import report_identity
from zscope.web.services import ReportFeedbackService


@pytest.fixture
def api(tmp_path, monkeypatch):
    issue = {
        "id": "synthetic-http-finding",
        "function": "entry",
        "location": "sample.c:4",
        "defect_class": "double_free",
        "validation_status": "needs_review",
        "description": "Synthetic evidence for HTTP contract verification only",
        "build_context_id": "build-a",
        "resource": "object-a",
    }
    report = {
        "run_manifest": {"project_id": "synthetic-http", "run_id": "run-a"},
        "issues": [issue],
        "report_views": {"with_needs_review": {"issues": [copy.deepcopy(issue)]}},
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    feedback = ReportFeedbackService(report_filename=str(path))
    store = AcceptanceFeedbackStore(tmp_path / "state" / "dispositions.sqlite3")
    service = AcceptanceReviewService(feedback, store=store)
    monkeypatch.setattr(server, "_acceptance_review_service", service)
    monkeypatch.setattr(server, "_report_feedback_service", feedback)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), server.ZScopeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_port}"

    def call(method, suffix, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        request = Request(base + suffix, data=body, method=method)
        request.add_header("Content-Type", "application/json")
        try:
            response = urlopen(request, timeout=5)
        except HTTPError as exc:
            response = exc
        with response:
            return response.status, json.loads(response.read())

    rid, iid = report_identity(report, str(path)), issue_identity(issue)
    query = "/api/acceptance/dispositions?" + urlencode({"report_id": rid, "issue_id": iid})
    try:
        yield {
            "call": call,
            "query": query,
            "report": report,
            "path": path,
            "store": store,
            "service": service,
            "rid": rid,
            "iid": iid,
        }
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def command(api, current, request_id="http-command"):
    return {
        "report_id": api["rid"],
        "issue_id": api["iid"],
        "build_context_id": "build-a",
        "base_revision": current["revision"],
        "base_context_revision": current["context_revision"],
        "request_id": request_id,
        "type": "risk_accept",
        "reason": "Local test disposition",
    }


def test_http_disposition_round_trip_is_persistent_and_independent(api):
    before = api["path"].read_bytes()
    status, current = api["call"]("GET", api["query"])
    assert status == 200 and current["revision"] == 0 and current["writable"] is True
    assert len(current["context_revision"]) == 64
    status, saved = api["call"]("POST", "/api/acceptance/dispositions", command(api, current))
    assert status == 200 and saved["revision"] == 1
    assert saved["context_revision"] == current["context_revision"]
    status, replay = api["call"]("POST", "/api/acceptance/dispositions", command(api, current))
    assert status == 200 and replay == saved
    reopened = AcceptanceReviewService(
        ReportFeedbackService(report_filename=str(api["path"])),
        store=AcceptanceFeedbackStore(api["store"].db_path),
    )
    _, loaded = reopened.get(api["query"].partition("?")[2])
    assert loaded["revision"] == 1 and loaded["disposition"] == saved["disposition"]
    assert api["path"].read_bytes() == before


@pytest.mark.parametrize(
    "field,value", [("description", "Changed evidence"), ("resource", "object-b")]
)
def test_never_saved_stale_draft_zero_cannot_bind_changed_evidence(api, field, value):
    _, old = api["call"]("GET", api["query"])
    api["report"]["issues"][0][field] = value
    api["report"]["report_views"]["with_needs_review"]["issues"][0][field] = value
    api["path"].write_text(json.dumps(api["report"]), encoding="utf-8")
    _, fresh = api["call"]("GET", api["query"])
    assert old["revision"] == fresh["revision"] == 0
    assert old["context_revision"] != fresh["context_revision"]
    status, result = api["call"]("POST", "/api/acceptance/dispositions", command(api, old))
    assert status == 409 and result["code"] == "stale_scope"
    assert not api["store"].history(api["rid"], api["iid"])
    status, result = api["call"]("POST", "/api/acceptance/dispositions", command(api, fresh))
    assert status == 200 and result["revision"] == 1


def test_scope_revision_is_required_and_unknown_build_is_not_wildcard(api):
    _, current = api["call"]("GET", api["query"])
    payload = command(api, current)
    payload.pop("base_context_revision")
    assert api["call"]("POST", "/api/acceptance/dispositions", payload)[0] == 400
    payload = command(api, current)
    payload["build_context_id"] = None
    assert api["call"]("POST", "/api/acceptance/dispositions", payload)[0] == 409


def test_unavailable_and_ambiguous_query_have_explicit_status(api, monkeypatch):
    assert api["call"]("GET", api["query"] + "&issue_id=other")[0] == 400
    monkeypatch.setattr(server, "_acceptance_review_service", None)
    assert api["call"]("GET", api["query"])[0] == 503


def test_read_only_service_rejects_writes(api, monkeypatch):
    _, current = api["call"]("GET", api["query"])
    service = api["service"]._service()
    service.writable = False
    monkeypatch.setattr(api["service"], "_service", lambda: service)
    status, _ = api["call"]("POST", "/api/acceptance/dispositions", command(api, current))
    assert status == 503 and not api["store"].history(api["rid"], api["iid"])
