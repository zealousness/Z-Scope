"""Real shipped UI and HTTP with labelled synthetic discovery evidence."""

from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading

import pytest

from test_semantics_workflow import project, candidate, synthetic_receipt


@pytest.mark.skipif(
    not os.environ.get("ZSCOPE_UI_PLAYWRIGHT_MODULE"), reason="Requires Linux Playwright"
)
def test_semantics_ui_review_drafts_navigation_and_layout(project, monkeypatch):
    from zscope.web import server
    from zscope.web.projects import ProjectLibrary

    library = ProjectLibrary(project.root.parent / "browser-projects.json")
    selected = library.open(str(project.config_path))["project"]["project_id"]
    fresh = project.root.parent / "fresh"
    fresh.mkdir()
    fresh_id = library.create(
        {
            "directory": str(fresh),
            "language": "c_cpp",
            "base_url": "http://127.0.0.1:1",
            "model": "synthetic",
            "api_key": "synthetic",
        }
    )["project"]["project_id"]
    rows = []
    for index in range(95):
        row = candidate(project.root, f"project:allocate_{index:03d}", valid=index != 2)
        row["selector"]["name"] = f"buffer_allocate_{index:03d}"
        row["selector"]["usr"] += str(index)
        row["variants"][0]["usr"] = row["selector"]["usr"]
        rows.append(row)
    synthetic_receipt(project, monkeypatch, rows)
    monkeypatch.setattr(server, "_project_library", library)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.ZScopeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    root = Path(__file__).resolve().parents[1]
    output = root / "docs/design/webui/assets/primitives"
    output.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            ["node", "tests/fixtures/semantics_ui.cjs"],
            cwd=root,
            env={
                **os.environ,
                "ZSCOPE_SEM_BASE": f"http://127.0.0.1:{httpd.server_port}",
                "ZSCOPE_SEM_PROJECT": selected,
                "ZSCOPE_SEM_FRESH": fresh_id,
                "ZSCOPE_SEM_OUTPUT": str(output),
            },
            capture_output=True,
            text=True,
            timeout=180,
        )
        (output / "browser.log").write_text(result.stdout + result.stderr)
        assert result.returncode == 0, result.stdout + result.stderr
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
        library.close()
