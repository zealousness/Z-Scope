from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

from zscope.framework.llm_usage import ScanTokenUsageLedger
from zscope.orchestration.scan_request import ScanRequestService
from zscope.web import server
from zscope.web.services import ConfigService


def test_web_config_service_returns_effective_depth_and_usage(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "zscope.yaml"
    path.write_text(
        json.dumps(
            {
                "config_version": 3,
                "llms": {
                    "default": {
                        "base_urls": ["http://example.invalid"],
                        "models": ["test"],
                        "api_key": "test",
                    }
                },
                "project": {
                    "targets": [{"id": "main", "compile_commands": "build/compile_commands.json"}],
                    "language": "c_cpp",
                },
            }
        ),
        encoding="utf-8",
    )
    effective = SimpleNamespace(
        scan=SimpleNamespace(depth="deep", depth_source="cli", rollout={}),
        scan_token_usage_ledger=ScanTokenUsageLedger(depth="deep"),
    )
    captured = {}

    def fake_load(config_path: str, **kwargs):
        captured.update(config_path=config_path, **kwargs)
        return effective

    monkeypatch.setattr("zscope.web.services.ConfigLoader.load", fake_load)
    payload = ConfigService(path, scan_depth="deep").structured_payload()

    assert captured == {"config_path": str(path.resolve()), "scan_depth": "deep"}
    assert payload["effective_scan"] == {
        "depth": "deep",
        "depth_source": "cli",
        "rollout": {},
    }
    assert payload["llm_usage"]["depth"] == "deep"
    assert "max_tokens" not in payload["llm_usage"]


def test_interface_scan_request_passes_only_depth_and_returns_usage(
    tmp_path: Path, monkeypatch
) -> None:
    # This unit test isolates argv/usage projection; the shared admission gate
    # is covered with real configuration in test_semantics_workflow.
    monkeypatch.setattr("zscope.config.semantics_workflow.require_workflow", lambda _: None)
    config_path = tmp_path / "zscope.yaml"
    config_path.write_text("config_version: 3\n", encoding="utf-8")
    effective = SimpleNamespace(
        project=SimpleNamespace(project_root=tmp_path),
        scan=SimpleNamespace(depth="balanced", depth_source="cli", rollout={}),
        scan_token_usage_ledger=ScanTokenUsageLedger(depth="balanced"),
    )
    monkeypatch.setattr(
        "zscope.orchestration.scan_request.ConfigLoader.load",
        lambda *args, **kwargs: effective,
    )
    captured = {}

    class Process:
        return_code = None

        def poll(self):
            return self.return_code

    process = Process()

    def process_factory(argv, **kwargs):
        captured["argv"] = list(argv)
        return process

    service = ScanRequestService(
        config_path, process_factory=process_factory, python_executable="python-test"
    )
    started = service.start(scan_depth="balanced")

    assert started["effective_scan"]["depth"] == "balanced"
    assert started["effective_scan"]["depth_source"] == "interface_request"
    assert captured["argv"][-2:] == ["--scan-depth", "balanced"]
    assert "--max-llm-tokens" not in captured["argv"]

    report = {
        "finding_status": "needs_review",
        "completeness": "complete",
        "metadata": {"llm_usage": {"consumed_tokens": 11_500_000}},
    }
    (tmp_path / "report.json").write_text(json.dumps(report), encoding="utf-8")
    process.return_code = 0
    completed = service.status(started["scan_id"])

    assert completed["scan_response"]["llm_usage"]["consumed_tokens"] == 11_500_000


def test_interface_scan_child_inherits_parent_cwd(tmp_path: Path, monkeypatch) -> None:
    """子进程继承父进程 CWD，保证相对 project.root 的解析与父进程完全一致。"""

    monkeypatch.setattr("zscope.config.semantics_workflow.require_workflow", lambda _: None)
    config_path = tmp_path / "zscope.yaml"
    config_path.write_text("config_version: 3\n", encoding="utf-8")
    effective = SimpleNamespace(
        project=SimpleNamespace(project_root=tmp_path),
        scan=SimpleNamespace(depth="fast", depth_source="cli", rollout={}),
        scan_token_usage_ledger=ScanTokenUsageLedger(depth="fast"),
    )
    monkeypatch.setattr(
        "zscope.orchestration.scan_request.ConfigLoader.load",
        lambda *args, **kwargs: effective,
    )
    captured = {}

    class Process:
        return_code = None

        def poll(self):
            return self.return_code

    def process_factory(argv, **kwargs):
        captured["cwd"] = kwargs.get("cwd")
        return Process()

    service = ScanRequestService(
        config_path, process_factory=process_factory, python_executable="python-test"
    )
    started = service.start()

    assert started["status"] == "running"
    assert captured["cwd"] == str(Path.cwd())


def test_web_scan_accepts_depth_only(monkeypatch) -> None:
    calls = []
    expected = {"scan_id": "scan-1", "status": "running"}
    monkeypatch.setattr(
        server,
        "_scan_request_service",
        SimpleNamespace(start=lambda **kwargs: calls.append(kwargs) or expected),
    )
    body = json.dumps({"scan_depth": "deep"}).encode()
    handler = object.__new__(server.ZScopeHandler)
    handler.path = "/api/scan"
    handler.headers = {"Content-Length": str(len(body))}
    handler.rfile = BytesIO(body)
    sent = []
    handler._send_json = lambda payload, status=200: sent.append((status, payload))

    handler.do_POST()

    assert calls == [{"scan_depth": "deep"}]
    assert sent == [(202, {"success": True, **expected})]


def test_web_scan_rejects_removed_token_override(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(
        server,
        "_scan_request_service",
        SimpleNamespace(start=lambda **kwargs: calls.append(kwargs) or {}),
    )
    body = json.dumps({"scan_depth": "fast", "max_llm_tokens": 2_000_000}).encode()
    handler = object.__new__(server.ZScopeHandler)
    handler.path = "/api/scan"
    handler.headers = {"Content-Length": str(len(body))}
    handler.rfile = BytesIO(body)
    sent = []
    handler._send_json = lambda payload, status=200: sent.append((status, payload))

    handler.do_POST()

    assert calls == []
    assert sent[0][0] == 400
    assert "unsupported scan request fields" in sent[0][1]["error"]
