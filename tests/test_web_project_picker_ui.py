"""Actual picker/settings/schedule UI over synthetic projects; no scan starts."""

import hashlib
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading

import pytest
import yaml


@pytest.mark.skipif(sys.platform != "linux", reason="Browser acceptance runs in Linux")
def test_real_http_project_picker_setup_schedule_and_switching(tmp_path, monkeypatch):
    if not os.environ.get("ZSCOPE_UI_PLAYWRIGHT_MODULE"):
        pytest.skip("Set Linux Playwright and Chromium environment variables")
    from zscope.cli.init import render_project_config
    from zscope.orchestration.jobs.schedules import ScanScheduleService
    from zscope.orchestration.jobs.service import ScanJobService
    from zscope.web import projects, server

    for key in ("Z_SCOPE_LLM_BASE_URL", "Z_SCOPE_LLM_MODEL", "Z_SCOPE_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    first = tmp_path / "synthetic-java-project"
    second = tmp_path / "synthetic-second-project"
    first.mkdir()
    second.mkdir()
    (first / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    (second / "unit.c").write_text("void f(void) {}\n", encoding="utf-8")
    (second / "build").mkdir()
    (second / "build/compile_commands.json").write_text("[]", encoding="utf-8")
    document = yaml.safe_load(render_project_config(second, language="c_cpp", preset="fast"))
    document["llms"]["default"].update(
        base_urls=["http://synthetic-model.invalid/v1"],
        models=["synthetic-model"],
        api_key="synthetic-only",
    )
    (second / "zscope.yaml").write_text(yaml.safe_dump(document), encoding="utf-8")
    library = projects.ProjectLibrary(tmp_path / "registry" / "projects.json")
    original_create = library.create

    def create_initial_project(payload):
        result = original_create(payload)
        # Match a server opened with -c A after creating the synthetic A fixture.
        library.initial_project_id = result["project"]["project_id"]
        return result

    monkeypatch.setattr(library, "create", create_initial_project)
    monkeypatch.setattr(server, "_project_library", library)
    original_init = ScanScheduleService.__init__
    schedule_services = []

    def schedule_init(self, *args, **kwargs):
        kwargs["spawn_daemon"] = False
        original_init(self, *args, **kwargs)
        schedule_services.append(self)

    def forbid_scan(*args, **kwargs):
        raise AssertionError("UI acceptance must never start or resume a scanner")

    monkeypatch.setattr(ScanScheduleService, "__init__", schedule_init)
    monkeypatch.setattr(ScanJobService, "start", forbid_scan)
    monkeypatch.setattr(ScanJobService, "resume", forbid_scan)
    root = Path(__file__).resolve().parents[1]
    output = root / os.environ.get("ZSCOPE_PICKER_EVIDENCE", "docs/webui-redesign/assets/followup")
    output.mkdir(parents=True, exist_ok=True)
    sources = (
        sorted((root / "zscope/web/static").glob("*.js"))
        + sorted((root / "zscope/web/static").glob("*.css"))
        + [
            root / name
            for name in (
                "zscope/web/static/index.html",
                "zscope/web/projects.py",
                "zscope/web/server.py",
                "zscope/web/services.py",
                "zscope/config/editor.py",
                "zscope/config/support.py",
                "zscope/config/v3.py",
                "zscope/orchestration/jobs/schedules.py",
                "tests/test_web_project_picker_ui.py",
                "tests/fixtures/web_project_picker_ui.cjs",
            )
        ]
    )
    before = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sources
    }
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.ZScopeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [shutil.which("node") or "node", "tests/fixtures/web_project_picker_ui.cjs"],
            cwd=root,
            env=dict(
                os.environ,
                ZSCOPE_UI_BASE_URL=f"http://127.0.0.1:{httpd.server_port}",
                ZSCOPE_PICKER_FIRST=str(first),
                ZSCOPE_PICKER_SECOND=str(second),
                ZSCOPE_PICKER_EVIDENCE=str(output),
            ),
            capture_output=True,
            text=True,
            timeout=180,
        )
        (output / "browser.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        assert result.returncode == 0, result.stdout + result.stderr
        assert before == {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sources
        }
        assert schedule_services and all(not item.spawn_daemon for item in schedule_services)
        assert all(item.engine.list().payload["jobs"] == [] for item in schedule_services)
        registry = library.registry.read_text(encoding="utf-8")
        assert "synthetic-only" not in registry
        receipt = json.loads((output / "browser-receipt.json").read_text(encoding="utf-8"))
        media = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in output.glob("*-*.png")
        }
        (output / "manifest.json").write_text(
            json.dumps(
                {
                    "scope": "Actual shipped HTML/CSS/JS and real HTTP/SQLite; synthetic local projects; no scanner or model execution",
                    "source_sha256": before,
                    "media_sha256": media,
                    "browser": receipt,
                    "schedule_daemon_spawned": False,
                    "scanner_started": False,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
