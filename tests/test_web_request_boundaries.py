"""Malformed HTTP input must be rejected before configuration mutations."""

from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
import threading

import pytest

from zscope.web.server import ZScopeHandler


@pytest.fixture(scope="module")
def dashboard_http_boundary():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), ZScopeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_port
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("method", ["POST", "DELETE"])
@pytest.mark.parametrize("length", ["invalid", "-1"])
def test_invalid_content_length_returns_400(dashboard_http_boundary, method, length):
    connection = HTTPConnection("127.0.0.1", dashboard_http_boundary, timeout=5)
    try:
        connection.request(method, "/api/config", headers={"Content-Length": length})
        response = connection.getresponse()
        assert response.status == 400
        assert json.loads(response.read())["error"] == "Invalid Content-Length"
    finally:
        connection.close()


@pytest.mark.parametrize("method", ["POST", "DELETE"])
@pytest.mark.parametrize("body", [b"[]", b"null", b"\xff", b"{"])
def test_non_object_or_invalid_json_returns_400(dashboard_http_boundary, method, body):
    connection = HTTPConnection("127.0.0.1", dashboard_http_boundary, timeout=5)
    try:
        connection.request(method, "/api/config", body=body)
        response = connection.getresponse()
        assert response.status == 400
        assert json.loads(response.read())["success"] is False
    finally:
        connection.close()
