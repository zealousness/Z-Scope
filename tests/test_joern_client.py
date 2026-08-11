from pathlib import Path
from subprocess import CompletedProcess
import asyncio
import sys
import threading
import types

import pytest

from zscope.common.joern_client import JoernClient, JoernQueryError
from zscope.retrieval.joern_backend import JoernBackend


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        ("val res7: Int = 81", 81),
        ("val res8: Long = 81L", 81),
        ("val res9: Double = 1.25", 1.25),
        ("val res10: Boolean = true", True),
    ],
)
def test_joern_server_stdout_parses_scala_scalars(stdout, expected) -> None:
    assert JoernClient._parse_server_stdout(stdout) == expected


def test_joern_cpg_ready_accepts_parsed_method_count(monkeypatch) -> None:
    client = JoernClient()
    monkeypatch.setattr(client, "query", lambda _text, **_kwargs: 81)

    assert client._wait_for_cpg_ready(timeout=1, poll_interval=0)


def test_joern_query_event_loop_is_explicitly_reused_and_closed() -> None:
    client = JoernClient()

    first = client._get_query_event_loop()
    second = client._get_query_event_loop()

    assert first is second
    assert not first.is_closed()
    client.stop_server()
    assert first.is_closed()
    assert client._query_event_loops == []


def test_joern_query_event_loops_are_isolated_by_thread() -> None:
    client = JoernClient()
    main_loop = client._get_query_event_loop()
    worker_loops = []

    worker = threading.Thread(target=lambda: worker_loops.append(client._get_query_event_loop()))
    worker.start()
    worker.join()

    assert worker_loops[0] is not main_loop
    client.stop_server()
    assert main_loop.is_closed()
    assert worker_loops[0].is_closed()


def test_joern_websocket_query_has_bounded_wait(monkeypatch, caplog) -> None:
    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {"uuid": "query-id"}

    class WebSocket:
        def __init__(self):
            self.calls = 0

        async def recv(self):
            self.calls += 1
            if self.calls == 1:
                return "connected"
            await asyncio.sleep(60)
            return "query-id"

    class Connection:
        async def __aenter__(self):
            return WebSocket()

        async def __aexit__(self, *_args):
            return None

    class Transport:
        @staticmethod
        def connect(_endpoint):
            return Connection()

        @staticmethod
        def post(_endpoint, **_kwargs):
            return Response()

        @staticmethod
        def get(_endpoint, **_kwargs):
            return Response()

    class FakeCPGQLSClient:
        CPGQLS_MSG_CONNECTED = "connected"

        def __init__(self, _endpoint, event_loop):
            self._transport = Transport()
            self._auth_creds = None
            self._event_loop = event_loop

        @staticmethod
        def connect_endpoint():
            return "connect"

        @staticmethod
        def post_query_endpoint():
            return "post"

        @staticmethod
        def get_result_endpoint(_target_uuid):
            return "get"

        async def _send_query(self, _query):
            raise AssertionError("Z-SCOPE timeout patch was not installed")

        def execute(self, query):
            return self._event_loop.run_until_complete(self._send_query(query))

    monkeypatch.setitem(
        sys.modules,
        "cpgqls_client",
        types.SimpleNamespace(CPGQLSClient=FakeCPGQLSClient),
    )
    client = JoernClient(query_timeout_seconds=0.01, query_max_attempts=1)

    assert client.query("cpg.method.size") is None
    assert "Joern query failed" in caplog.text
    client.stop_server()


@pytest.mark.parametrize(
    "kwargs",
    ({"query_timeout_seconds": 0}, {"query_max_attempts": 0}),
)
def test_joern_query_policy_rejects_non_positive_values(kwargs) -> None:
    with pytest.raises(ValueError):
        JoernClient(**kwargs)


def test_joern_cli_query_uses_loaded_cpg_and_marker_json(monkeypatch, tmp_path) -> None:
    cpg_path = tmp_path / "cpg.bin"
    cpg_path.write_bytes(b"")
    client = JoernClient(joern_path="joern")
    client._cli_mode = True
    client._cpg_path = str(cpg_path)
    calls = {}

    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        calls["cmd"] = cmd
        calls["script"] = Path(cmd[-1]).read_text(encoding="utf-8")
        return CompletedProcess(
            cmd,
            0,
            stdout='noise\n__ZSCOPE_JSON_BEGIN__\n[{"method":"api_recv"}]\n__ZSCOPE_JSON_END__\n',
            stderr="",
        )

    monkeypatch.setattr("zscope.common.joern_client.subprocess.run", fake_run)

    result = client.query('cpg.method.name("api_recv").l.toJson')

    assert result == [{"method": "api_recv"}]
    assert calls["cmd"][:2] == ["joern", "--nocolors"]
    assert "val __zscope_result" in calls["script"]
    assert "importCpg(" in calls["script"]
    assert str(cpg_path.resolve()).replace("\\", "\\\\") in calls["script"]
    assert 'cpg.method.name("api_recv").l.toJson' in calls["script"]


def test_joern_cli_import_reuses_existing_cpg(tmp_path) -> None:
    cpg_path = tmp_path / "cpg.bin"
    cpg_path.write_bytes(b"")
    client = JoernClient(joern_path="joern")
    client._cli_mode = True

    assert client.import_cpg(str(tmp_path))
    assert client.cpg_status == "ready"
    assert client._cpg_path == str(cpg_path)


def test_joern_windows_batch_launcher_prefers_cli_mode() -> None:
    client = JoernClient(joern_path=r"C:\tmp\joern\joern-cli\joern.bat")

    assert client.start_server()
    assert client._cli_mode


def test_joern_parse_path_follows_joern_binary_location() -> None:
    assert JoernClient(joern_path="joern")._joern_parse_path() == "joern-parse"
    assert (
        JoernClient(joern_path=r"C:\tmp\joern\joern-cli\joern.bat")
        ._joern_parse_path()
        .endswith("joern-parse.bat")
    )
    assert JoernClient(joern_path="/opt/joern/joern-cli/joern")._joern_parse_path() == (
        "/opt/joern/joern-cli/joern-parse"
    )


def test_joern_client_queries_direct_function_type_references(monkeypatch) -> None:
    client = JoernClient()
    captured = {}

    def query(text):
        captured["query"] = text
        return [
            {
                "typeFullName": "PluginRegistry*",
                "lineNumber": 32,
                "referenceKind": "parameter",
            }
        ]

    monkeypatch.setattr(client, "query", query)

    rows = client.get_function_type_references("_plugin_register", "src/plugin.c")

    assert rows[0]["typeFullName"] == "PluginRegistry*"
    assert 'nameExact("_plugin_register")' in captured["query"]
    assert 'endsWith("src/plugin.c")' in captured["query"]
    assert '"referenceKind" -> "return"' in captured["query"]
    assert '"referenceKind" -> "parameter"' in captured["query"]
    assert '"referenceKind" -> "local"' in captured["query"]


def test_failed_joern_fact_query_is_not_reported_as_empty(monkeypatch) -> None:
    client = JoernClient()
    monkeypatch.setattr(client, "query", lambda _text: None)

    with pytest.raises(JoernQueryError, match="get_method_callees"):
        client.get_method_callees("entry")


def test_failed_joern_index_query_is_not_reported_as_empty() -> None:
    class FailedJoern:
        def query(self, _text):
            return None

    backend = JoernBackend(joern_client=FailedJoern())

    with pytest.raises(JoernQueryError, match="build_function_index"):
        backend.build_function_index()


def test_joern_backend_builds_resolved_and_optional_unresolved_type_context() -> None:
    class FakeJoern:
        def get_function_type_references(self, name, file_path=""):
            return [
                {
                    "typeFullName": "PluginRegistry*",
                    "lineNumber": 32,
                    "referenceKind": "parameter",
                },
                {
                    "typeFullName": "MissingType*",
                    "lineNumber": 40,
                    "referenceKind": "local",
                },
            ]

        def get_type_decls(self, name):
            if name == "PluginRegistry":
                return [
                    {
                        "name": name,
                        "filename": "include/types.h",
                        "lineNumber": 110,
                        "lineNumberEnd": 115,
                        "full_definition": "typedef struct { void *plugins; } PluginRegistry;",
                    }
                ]
            return []

    backend = JoernBackend(joern_client=FakeJoern())

    context = backend.get_function_type_context("_plugin_register", "src/plugin.c", 32)

    assert context["referenced_types"][0]["type_index_name"] == (
        "PluginRegistry@include/types.h:110-115"
    )
    assert context["referenced_types"][0]["reference_kinds"] == ["parameter"]
    assert context["unresolved_referenced_types"] == [
        {
            "name": "MissingType",
            "reference_kinds": ["local"],
            "reference_lines": [40],
            "reason": "type_definition_not_found",
        }
    ]
