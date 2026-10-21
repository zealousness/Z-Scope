"""Real HTTP acceptance of parser-only configuration editing and execution refusal."""

from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
import json
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
import yaml

from test_config_v3_preparation import _document, _materialize_project, _write
from zscope.config.config import ConfigLoader
from zscope.web import server
from zscope.web.services import ConfigService


@pytest.fixture
def config_http(tmp_path, monkeypatch):
    project = _materialize_project(tmp_path / "config editor with spaces")
    document = _document()
    document["llms"]["default"]["api_key"] = "${Z_SCOPE_HTTP_DUMMY_KEY}"
    document["llms"]["wiki_compiler"] = {
        "base_urls": ["http://dummy-wiki.invalid/v1"],
        "models": ["dummy-wiki"],
        "api_key": "${Z_SCOPE_HTTP_DUMMY_KEY}",
        "timeout": None,
    }
    document["project"]["targets"].append(
        {"id": "second", "compile_commands": "build/compile_commands.json"}
    )
    monkeypatch.setenv("Z_SCOPE_HTTP_DUMMY_KEY", "dummy-never-sent-to-a-model")
    config = _write(project, document)
    monkeypatch.setattr(server, "_config_service", ConfigService(config))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.ZScopeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_port}"

    def request(path, data=None):
        kwargs = {}
        if data is not None:
            kwargs = {
                "data": json.dumps(data).encode("utf-8"),
                "headers": {"Content-Type": "application/json"},
                "method": "POST",
            }
        try:
            # 15 s is enough on an idle machine, but the full acceptance suite
            # runs many native scans in parallel and a structured-config save
            # re-validates every target; the client budget must not be the thing
            # that decides whether the handler is correct.
            response = urlopen(Request(base + path, **kwargs), timeout=60)
        except HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response)

    try:
        yield config, document, request
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_multi_target_get_save_and_prepare_preserve_document_without_authorizing_execution(
    config_http,
):
    config, document, request = config_http
    status, loaded = request("/api/config/structured")
    assert status == 200
    assert loaded["config"] == document
    assert loaded["config_version"] == 3 and loaded["language"] == "c_cpp"
    document["project"]["targets"][1]["id"] = "second-edited"
    status, saved = request("/api/config/structured", {"config": document})
    assert status == 200 and saved["success"] is True
    assert saved["config"] == document
    assert yaml.safe_load(config.read_text(encoding="utf-8")) == document
    status, prepared = request("/api/scan/prepare")
    assert status == 200
    assert [target["id"] for target in prepared["version3"]["targets"]] == [
        "service",
        "second-edited",
    ]
    assert prepared["version3"]["start_capability"]["startable"] is False
    with pytest.raises(ValueError, match="exactly one"):
        ConfigLoader.load(str(config))


@pytest.mark.parametrize("change", ["unknown-key", "java-database", "empty-targets"])
def test_invalid_structured_save_keeps_original_bytes_and_no_candidates(config_http, change):
    config, document, request = config_http
    before = config.read_bytes()
    if change == "unknown-key":
        document["unexpected"] = True
    elif change == "java-database":
        document["project"]["language"] = "java"
        document["scan"]["preset"] = "quick"
    else:
        document["project"]["targets"] = []
    status, payload = request("/api/config/structured", {"config": document})
    assert status == 400 and payload["success"] is False
    assert config.read_bytes() == before
    assert not list(config.parent.glob(".*.tmp-*"))


def test_concurrent_real_http_writes_each_validate_a_complete_document(config_http):
    config, document, request = config_http
    choices = [json.loads(json.dumps(document)) for _ in range(2)]
    choices[0]["project"]["targets"][1]["id"] = "left"
    choices[1]["project"]["targets"][1]["id"] = "right"
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(request, "/api/config/structured", {"config": choice}) for choice in choices
        ]
        for future in futures:
            status, payload = future.result(timeout=20)
            assert status == 200 and payload["success"] is True
    # The current endpoint has no revision/CAS: the final complete valid write wins.
    assert yaml.safe_load(config.read_text(encoding="utf-8")) in choices
    assert not list(config.parent.glob(".*.tmp-*"))


def test_invalid_saved_document_is_not_projected_as_valid(config_http):
    config, _, request = config_http
    config.write_text("config_version: 3\nproject: []\n", encoding="utf-8")
    status, payload = request("/api/config/structured")
    assert status == 400 and payload["config"] == {} and payload["error"]
