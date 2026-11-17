"""Instance UI contracts and native ScanSession -> owner -> HTTP browser evidence."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(sys.platform != "linux", reason="UI checks require Linux")
def test_instance_coverage_state_contract():
    result = subprocess.run(
        [shutil.which("node") or "node", "tests/fixtures/instance_coverage_ui.cjs"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="Native owner checks require Linux")
def test_instance_coverage_native_owner_http(tmp_path, monkeypatch):
    if not os.environ.get("ZSCOPE_UI_PLAYWRIGHT_MODULE") or not os.environ.get(
        "Z_SCOPE_TEST_CLANG_INDEXER"
    ):
        pytest.skip("Native tool and Linux Playwright required")
    from test_scan_session_instances import _write_project
    from test_config_v3_preparation import _document, _write
    from zscope.orchestration.jobs.service import ScanJobService
    from zscope.web import server, services
    from zscope.web.scan_jobs_service import ScanJobsHttpService
    from zscope.reporting.json_io import read_report

    project = tmp_path / "native variants with spaces"
    project.mkdir()
    _write_project(project)
    document = _document()
    document["project"].pop("root", None)
    document["scan"]["preset"] = "deep"
    document["project"]["targets"] = [
        {"id": "variants", "compile_commands": "compile_commands.json"}
    ]
    config = _write(project, document)
    output = ROOT / os.environ.get("ZSCOPE_INSTANCE_EVIDENCE", "artifacts/instance-ui-r18/native")
    output.mkdir(parents=True, exist_ok=True)
    engine = ScanJobService(
        config,
        terminate_grace=1,
        scan_command_builder=lambda path, depth, executable: [
            executable,
            str(Path(__file__).resolve()),
            "--native-scanner",
            str(project),
        ],
    )
    feedback = services.ReportFeedbackService(report_filename=str(project / "report.json"))
    monkeypatch.setattr(server, "_config_service", services.ConfigService(config))
    monkeypatch.setattr(server, "_report_feedback_service", feedback)
    monkeypatch.setattr(
        server, "_scan_jobs_http_service", ScanJobsHttpService(config, feedback, engine=engine)
    )
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.ZScopeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    env = dict(
        os.environ,
        ZSCOPE_UI_BASE_URL=f"http://127.0.0.1:{httpd.server_port}",
        ZSCOPE_INSTANCE_EVIDENCE=str(output),
    )
    try:
        result = subprocess.run(
            [
                shutil.which("node") or "node",
                "tests/fixtures/instance_coverage_ui.cjs",
                "--browser",
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=240,
        )
        (output / "browser.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        assert result.returncode == 0, result.stdout + result.stderr
        report = read_report(project / "report.json")
        for name in ("report.json", "unit.c", "compile_commands.json"):
            shutil.copyfile(project / name, output / name)
        analysis = report["metadata"]["entry_instances"]["instance_analysis"]
        assert sorted(item["candidate_count"] for item in analysis["instances"]) == [0, 1]
        assert analysis["instance_scope_complete"] is True
        assert analysis["scan_coverage_complete"] is True
        assert analysis["consumer_scope_complete"] is True
        assert report["metadata"]["build_coverage"]["scan_complete"] is False
        # Use the same actual scheduler receipt as the owner. The current
        # queue is a per-attempt nonce file; neither globbing a legacy filename
        # nor trusting a report-supplied queue path proves this run's work.
        envelope = json.loads((output / "http-result.json").read_text(encoding="utf-8"))
        binding = envelope["binding"]
        job = engine.detail(binding["job_id"]).payload["job"]
        assert job["run_id"] == binding["run_id"]
        assert job["input_revision"] == binding["input_revision"]
        assert job["report"]["report_id"] == binding["report_id"]
        store = engine._locate_store()
        receipt = store.latest_event(
            job["job_id"], run_id=job["run_id"], kind="session_scheduler_started"
        )
        assert receipt is not None
        assert receipt["data"]["input_revision"] == job["input_revision"]
        queue = Path(receipt["data"]["work_queue"])
        run_dir = (store.db_path.parent / job["job_id"] / job["run_id"]).resolve()
        assert queue.is_absolute() and queue.resolve().parent == run_dir
        assert Path(binding["report_path"]).resolve().parent == run_dir
        assert queue.name.startswith("work-queue.db.") and queue.is_file()
        with sqlite3.connect(queue.resolve().as_uri() + "?mode=ro", uri=True) as connection:
            counts = dict(
                connection.execute(
                    "SELECT kind, COUNT(*) FROM items WHERE status='completed' GROUP BY kind"
                )
            )
        assert counts["instance_analysis"] == 2
        (output / "native-evidence.json").write_text(
            json.dumps(
                {
                    "native_sha256": hashlib.sha256(
                        Path(os.environ["Z_SCOPE_TEST_CLANG_INDEXER"]).read_bytes()
                    ).hexdigest(),
                    "entry_instances": report["metadata"]["entry_instances"],
                    "job": report["metadata"]["job"],
                    "queue_completed": counts,
                    "scope": "Real native dual-macro fixture, ScanSession, detached owner, SQLite and HTTP; model boundary unexercised; not a full project scan.",
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    finally:
        for job in engine.list().payload.get("jobs", []):
            if job["capabilities"]["cancel"]:
                engine.cancel(job["job_id"], base_revision=job["revision"], request_id="ui-cleanup")
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


if __name__ == "__main__" and "--native-scanner" in sys.argv:
    from test_scan_session_instances import _config
    from zscope.orchestration.scan_session import ScanSessionRunner

    # Existing native fixture configuration limits this to the real deterministic
    # double-free rule. No generated/synthetic report is substituted.
    result = ScanSessionRunner(_config(Path(sys.argv[-1])), task_id="ui-native").run()
    sys.exit(result.exit_code)
