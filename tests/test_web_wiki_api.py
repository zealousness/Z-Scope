from __future__ import annotations

from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

from zscope.web import server
from zscope.web.services import WikiControlService


def _config(tmp_path: Path) -> SimpleNamespace:
    wiki = SimpleNamespace(
        state_dir=".zscope_knowledge/wiki",
        max_context_tokens=1200,
        document_exclude=["legacy/**"],
        explanatory_overrides=["docs/contracts/**/*.md"],
        generated_overrides=["artifacts/**"],
        max_file_bytes=1024,
        max_files=40,
        max_total_bytes=4096,
    )
    project = SimpleNamespace(
        project_root=tmp_path,
        project_id="fixture",
        wiki=wiki,
    )
    return SimpleNamespace(project=project)


def test_wiki_control_service_uses_configured_readonly_scope(tmp_path: Path, monkeypatch) -> None:
    config = _config(tmp_path)
    calls = []
    monkeypatch.setattr("zscope.web.services.ConfigLoader.load", lambda _path: config)
    monkeypatch.setattr(
        "zscope.web.services.wiki_status",
        lambda project_root, *, state_dir: calls.append(("status", project_root, state_dir))
        or {"available": False},
    )

    def fake_query(project_root, **kwargs):
        calls.append(("query", project_root, kwargs))
        return {"schema_version": "zscope.validator-project-knowledge.v1"}

    monkeypatch.setattr("zscope.web.services.wiki_query", fake_query)
    service = WikiControlService(tmp_path / "zscope.yaml")

    assert service.status_payload() == {"available": False}
    result = service.query_payload(
        "subject=parse_byte&subject=api%3Aparse_byte&fact_kind=input_range&candidate_file=src%2Fparser.c&max_tokens=512"
    )

    assert result["schema_version"] == "zscope.validator-project-knowledge.v1"
    assert calls[0] == ("status", tmp_path, ".zscope_knowledge/wiki")
    assert calls[1][2]["subjects"] == ["parse_byte", "api:parse_byte"]
    assert calls[1][2]["project_id"] == "fixture"
    assert calls[1][2]["max_file_bytes"] == 1024
    assert calls[1][2]["overrides"]["exclude"] == ["legacy/**"]


def test_wiki_control_service_rejects_scope_and_budget_overrides(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("zscope.web.services.ConfigLoader.load", lambda _path: _config(tmp_path))
    service = WikiControlService(tmp_path / "zscope.yaml")

    for query in (
        "project_root=%2Ftmp&subject=parse_byte",
        "subject=parse_byte&candidate_file=..%2Fsecret.md",
        "subject=parse_byte&max_tokens=1201",
    ):
        try:
            service.query_payload(query)
        except ValueError:
            continue
        raise AssertionError(f"unsafe query was accepted: {query}")


def test_web_wiki_routes_are_get_only(monkeypatch) -> None:
    monkeypatch.setattr(
        server,
        "_wiki_control_service",
        SimpleNamespace(
            status_payload=lambda: {"available": True},
            query_payload=lambda query: {"query": query},
        ),
    )
    handler = object.__new__(server.ZScopeHandler)
    sent = []
    handler._send_json = lambda payload, status=200: sent.append((status, payload))

    handler.path = "/api/wiki/status"
    handler.do_GET()
    handler.path = "/api/wiki/query?subject=parse_byte"
    handler.do_GET()

    assert sent == [
        (200, {"available": True}),
        (200, {"query": "subject=parse_byte"}),
    ]

    handler.path = "/api/wiki/query"
    handler.headers = {"Content-Length": "0"}
    handler.rfile = BytesIO()
    errors = []
    handler.send_error = lambda status: errors.append(status)
    handler.do_POST()
    assert errors == [404]


def test_web_wiki_routes_do_not_expose_internal_exception_text(monkeypatch) -> None:
    monkeypatch.setattr(
        server,
        "_wiki_control_service",
        SimpleNamespace(
            status_payload=lambda: (_ for _ in ()).throw(
                RuntimeError("secret /home/private/status")
            ),
            query_payload=lambda _query: (_ for _ in ()).throw(
                ValueError("secret /home/private/query")
            ),
        ),
    )
    handler = object.__new__(server.ZScopeHandler)
    sent = []
    handler._send_json = lambda payload, status=200: sent.append((status, payload))

    handler.path = "/api/wiki/status"
    handler.do_GET()
    handler.path = "/api/wiki/query?subject=parse_byte"
    handler.do_GET()

    assert sent == [
        (400, {"error": "Wiki status is unavailable.", "available": False}),
        (400, {"error": "Wiki query is unavailable."}),
    ]
