"""Shipped UI state checks and real U02 HTTP/SQLite browser acceptance.

Report evidence is explicitly synthetic. Contract cases and real owner cases are separate.
"""

from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer

import pytest


@pytest.mark.skipif(sys.platform != "linux", reason="Browser checks run in Linux")
def test_workbench_v3_config_editor_real_http(tmp_path, monkeypatch):
    """Real config reads/writes; fault injection is labelled separately in evidence."""
    if not os.environ.get("ZSCOPE_UI_PLAYWRIGHT_MODULE"):
        pytest.skip("Set ZSCOPE_UI_PLAYWRIGHT_MODULE and ZSCOPE_UI_CHROMIUM for visual QA")
    from test_config_v3_preparation import _document, _materialize_project, _write
    from zscope.web import server, services
    from zscope.web.scan_jobs_service import ScanJobsHttpService

    root = Path(__file__).resolve().parents[1]
    project = _materialize_project(tmp_path / "config editor with spaces")
    document = _document()
    document["llms"]["default"]["api_key"] = "${ZSCOPE_UI_DUMMY_KEY}"
    document["llms"]["default"]["models"] = ["${ZSCOPE_UI_DUMMY_MODEL}"]
    document["llms"]["wiki_compiler"] = {
        "base_urls": ["http://dummy-wiki.invalid/v1"],
        "models": ["dummy-wiki"],
        "api_key": "dummy-wiki-secret",
        "timeout": None,
        "retry_until_available": True,
    }
    monkeypatch.setenv("ZSCOPE_UI_DUMMY_KEY", "dummy-secret-never-rendered")
    monkeypatch.setenv("ZSCOPE_UI_DUMMY_MODEL", "dummy-model")
    config = _write(project, document)
    monkeypatch.setattr(server, "_config_service", services.ConfigService(config))
    feedback = services.ReportFeedbackService(report_filename=str(project / "absent.json"))
    monkeypatch.setattr(server, "_report_feedback_service", feedback)
    monkeypatch.setattr(server, "_scan_jobs_http_service", ScanJobsHttpService(config, feedback))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.ZScopeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    output = root / os.environ.get("ZSCOPE_UI_CONFIG_EVIDENCE", "artifacts/ui-v3-config-r6")
    output.mkdir(parents=True, exist_ok=True)
    sources = [
        root / name
        for name in (
            "zscope/web/static/index.html",
            "zscope/web/static/dashboard_config.js",
            "zscope/web/static/dashboard_workbench.js",
            "zscope/web/static/dashboard_projects.js",
            "zscope/web/static/dashboard_schedules.js",
            "zscope/web/static/dashboard_workbench.css",
            "zscope/web/static/dashboard_navigation.js",
            "zscope/web/static/dashboard_redesign.css",
            "zscope/web/services.py",
            "zscope/web/server.py",
            "zscope/config/v3.py",
            "zscope/config/editor.py",
            "tests/test_agent_workbench_ui.py",
            "tests/fixtures/agent_workbench_ui.cjs",
        )
    ]
    before = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sources
    }
    env = os.environ.copy()
    env.update(
        ZSCOPE_UI_BASE_URL=f"http://127.0.0.1:{httpd.server_port}",
        ZSCOPE_UI_CONFIG_EVIDENCE=str(output),
    )
    try:
        result = subprocess.run(
            [
                shutil.which("node") or "node",
                "tests/fixtures/agent_workbench_ui.cjs",
                "--browser-config",
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=180,
            env=env,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert before == {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sources
        }
        (output / "source-sha256.json").write_text(
            json.dumps(before, indent=2) + "\n", encoding="utf-8"
        )
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.mark.skipif(sys.platform != "linux", reason="UI quality checks run in Linux")
def test_workbench_contract_state_and_recovery():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the shipped JavaScript behavior checks")
    result = subprocess.run(
        [node, "tests/fixtures/agent_workbench_ui.cjs"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="Browser checks run in Linux")
def test_workbench_browser_real_http_and_contract_fixture(tmp_path, monkeypatch):
    """Real U02 backend over synthetic evidence, then labelled S08 job fixtures."""
    if not os.environ.get("ZSCOPE_UI_PLAYWRIGHT_MODULE"):
        pytest.skip("Set ZSCOPE_UI_PLAYWRIGHT_MODULE and ZSCOPE_UI_CHROMIUM for visual QA")
    from test_config_options import _config, _write
    from test_acceptance_projection import (
        _assessment_for,
        _base_issue,
        _confirmed_issue,
        _protocol_issue,
        _realistic_report,
        _reject_proof,
    )
    from zscope.config.config import ConfigLoader
    from zscope.config.user_config_store import UserConfigStore
    from zscope.reporting.schema import REPORT_SCHEMA_VERSION
    from zscope.semantics.business_assumptions import assumption_key
    from zscope.web import server, services
    from zscope.web.acceptance_service import AcceptanceReviewService

    project = tmp_path / "UI sample with spaces"
    project.mkdir()
    (project / "unit.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    config_path = _write(project, _config(project))
    config = ConfigLoader.load(str(config_path))
    report_path = project / "report.json"
    conditional = _protocol_issue(
        id="synthetic-conditional", description="合成证据：业务前提尚待确认"
    )
    conditional["protocol_assessment"] = _assessment_for(conditional)
    # Complete synthetic identity for the real answer store; no native proof is granted.
    assumption = conditional["protocol_assessment"]["assumptions"][0]
    assumption["scope"].update(entry_usr="synthetic-entry", object_ref="pool-slot-0-gen-3")
    assumption["basis"] = {
        "dependency_hash": "synthetic-source-dependency",
        "observation_kind": "repeat_return",
    }
    conditional["protocol_assessment"]["feedback_revisions"] = {assumption_key(assumption): 0}
    issues = [
        _confirmed_issue(id="synthetic-confirmed"),
        conditional,
        _base_issue(
            id="synthetic-pending-a",
            description="合成证据：构建 A 待验证",
            evidence_pack={"build_context_id": "build-a"},
        ),
        _base_issue(
            id="synthetic-pending-b",
            description="合成证据：构建 B 待验证",
            evidence_pack={"build_context_id": "build-b"},
        ),
        _base_issue(
            id="synthetic-duplicate-a",
            location="src/handler.c:43",
            description="合成证据：构建 A 重复目标",
            evidence_pack={"build_context_id": "build-a"},
        ),
        _base_issue(
            id="synthetic-ruled-out",
            location="src/handler.c:44",
            description="合成证据：守卫已排除路径",
            validation_status="rejected",
            candidate_disposition="rejected_with_proof",
            rejection_source="deterministic_validator_proof",
            deterministic_rejection=True,
            evidence_pack={"build_context_id": "build-a", "proofs": [_reject_proof()]},
        ),
    ]
    report = _realistic_report()
    report.update(
        schema_version=REPORT_SCHEMA_VERSION,
        issues=issues,
        run_manifest={"project_id": "synthetic-ui", "run_id": "synthetic-u02"},
    )
    report.pop("report_views", None)
    report_path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
    original_report = report_path.read_bytes()
    monkeypatch.setattr(server, "_config_service", services.ConfigService(config_path))
    answer_store = UserConfigStore(project / "business-feedback")
    feedback = services.ReportFeedbackService(
        answer_store, report_filename=str(report_path), project_config=config.project
    )
    monkeypatch.setattr(server, "_report_feedback_service", feedback)
    monkeypatch.setattr(
        server, "_acceptance_review_service", AcceptanceReviewService(feedback, config_path)
    )
    monkeypatch.setattr(
        server, "_source_snippet_service", services.SourceSnippetService(config.project)
    )
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.ZScopeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    env = os.environ.copy()
    env["ZSCOPE_UI_BASE_URL"] = f"http://127.0.0.1:{httpd.server_port}"
    env["ZSCOPE_UI_PROJECT_ROOT"] = str(project)
    env["ZSCOPE_UI_REPORT_PATH"] = str(report_path)
    source_paths = [
        "zscope/web/static/index.html",
        "zscope/web/static/dashboard_workbench.js",
        "zscope/web/static/dashboard_projects.js",
        "zscope/web/static/dashboard_schedules.js",
        "zscope/web/static/dashboard_config.js",
        "zscope/web/static/dashboard_workbench.css",
        "zscope/web/static/dashboard_navigation.js",
        "zscope/web/static/dashboard_redesign.css",
        "zscope/web/static/dashboard_reports.js",
        "zscope/web/static/report_view.js",
        "zscope/web/server.py",
        "zscope/web/services.py",
        "zscope/config/editor.py",
        "zscope/web/review_reports.py",
        "zscope/web/acceptance_service.py",
        "zscope/config/acceptance_feedback.py",
        "zscope/config/protocol_feedback.py",
        "zscope/config/user_config_store.py",
        "zscope/reporting/acceptance.py",
        "zscope/reporting/schema.py",
        "zscope/reporting/views.py",
        "zscope/reporting/issue_markdown.py",
        "tests/test_agent_workbench_ui.py",
        "tests/fixtures/agent_workbench_ui.cjs",
    ]

    def source_hashes():
        return {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in source_paths}

    before_sources = source_hashes()
    try:
        result = subprocess.run(
            [shutil.which("node") or "node", "tests/fixtures/agent_workbench_ui.cjs", "--browser"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=180,
            env=env,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert report_path.read_bytes() == original_report, "Disposition must not rewrite evidence"
        business_output = Path(env.get("ZSCOPE_UI_EVIDENCE", "artifacts/ui-workbench-20261014"))
        business = json.loads((business_output / "business-answers.json").read_text())
        reopened_answers = UserConfigStore(answer_store.workbook.path).get_protocol_answers(
            [business["subject_key"]]
        )
        assert reopened_answers[business["subject_key"]]["answer"] == "unknown"
        assert reopened_answers[business["subject_key"]]["revision"] == 4
        assert (project / ".zscope_acceptance" / "dispositions.sqlite3").is_file()
        output = Path(env.get("ZSCOPE_UI_EVIDENCE", "artifacts/ui-workbench-20261014"))
        assert source_hashes() == before_sources, "UI/backend changed during browser acceptance"
        (output / "source-sha256.json").write_text(
            json.dumps(before_sources, indent=2) + "\n", encoding="utf-8"
        )
        evidence = json.loads((output / "u02-persistence.json").read_text(encoding="utf-8"))
        reopened = AcceptanceReviewService(
            services.ReportFeedbackService(report_filename=str(report_path)), config_path
        )
        status, current = reopened.get(evidence["query"])
        assert status == 200
        assert current["revision"] == evidence["revision"]
        assert current["disposition"]["reason"] == evidence["reason"]
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.mark.skipif(sys.platform != "linux", reason="Real owner browser checks require Linux")
@pytest.mark.parametrize("scenario", ["lifecycle", "projection"])
def test_workbench_browser_v3_and_real_owner(tmp_path, monkeypatch, scenario):
    """Real HTTP/SQLite/detached owner; only the scanner output is synthetic."""
    if not os.environ.get("ZSCOPE_UI_PLAYWRIGHT_MODULE"):
        pytest.skip("Set ZSCOPE_UI_PLAYWRIGHT_MODULE and ZSCOPE_UI_CHROMIUM for visual QA")
    from test_config_v3_preparation import _document, _materialize_project, _write
    from zscope.orchestration.jobs.service import ScanJobService

    root = Path(__file__).resolve().parents[1]
    project = _materialize_project(tmp_path / "real owner UI with spaces")
    document = _document()
    document["project"]["targets"].append({"id": "second", "compile_commands": "missing.json"})
    if scenario == "projection":
        document["project"]["targets"] = document["project"]["targets"][:1]
    config = _write(project, document)
    scanner = tmp_path / "controlled-scanner.py"
    scanner.write_text(
        "import os, sys, time\nfrom pathlib import Path\n"
        "from zscope.reporting.json_io import write_report_atomic\n"
        "from zscope.reporting.schema import REPORT_SCHEMA_VERSION\n"
        "root = Path(sys.argv[1])\n"
        "with (root/'scanner-starts.txt').open('a') as log: log.write(str(os.getpid())+'\\n')\n"
        "deadline=time.monotonic()+90\n"
        "while (root/'scanner-mode.txt').read_text() not in ('complete', 'partial'):\n"
        "    if time.monotonic() > deadline: sys.exit(2)\n"
        "    time.sleep(0.1)\n"
        "write_report_atomic(root/'report.json', {'schema_version':REPORT_SCHEMA_VERSION, 'completeness':'partial', "
        "'issues':[{'id':'synthetic-owner-result','function':'main','location':'unit.c:1',"
        "'description':'合成扫描器结果 · 不代表真实分析','validation_status':'needs_review',"
        "'evidence_pack':{'build_context_id':'synthetic-build'}}],"
        "'metadata':{'synthetic_only':True,'entry_instances':{'scan_coverage_complete':False},"
        "'business_questions':[{'id':'q1','question':'合成问题：谁负责释放此对象？',"
        "'affected_scope':'main','current_assumption':'保留未知','impact':'释放责任未确认'}]}})\n"
        "sys.exit(2 if (root/'scanner-mode.txt').read_text() == 'partial' else 0)\n",
        encoding="utf-8",
    )
    (project / "scanner-mode.txt").write_text("wait", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(root))
    env = os.environ.copy()
    env.update(
        ZSCOPE_UI_JOB_SCENARIO=scenario,
        ZSCOPE_UI_JOB_PROJECT=str(project),
        ZSCOPE_UI_JOB_CONFIG=str(config),
        ZSCOPE_UI_JOB_SCANNER=str(scanner),
        ZSCOPE_UI_PYTHON=sys.executable,
        ZSCOPE_UI_SERVER_HELPER=str(Path(__file__).resolve()),
        ZSCOPE_UI_JOB_EVIDENCE=env.get("ZSCOPE_UI_JOB_EVIDENCE", "artifacts/ui-jobs-real-20261014"),
    )
    if scenario == "projection":
        env["ZSCOPE_UI_JOB_EVIDENCE"] += "-projection"
    sources = list((root / "zscope/orchestration/jobs").glob("*.py")) + [
        root / name
        for name in (
            "zscope/web/server.py",
            "zscope/web/services.py",
            "zscope/web/scan_jobs_service.py",
            "zscope/reporting/job_result_projection.py",
            "zscope/config/v3.py",
            "zscope/config/editor.py",
            "zscope/config/v3_preparation.py",
            "zscope/web/static/index.html",
            "zscope/web/static/dashboard_workbench.js",
            "zscope/web/static/dashboard_projects.js",
            "zscope/web/static/dashboard_schedules.js",
            "zscope/web/static/dashboard_config.js",
            "zscope/web/static/dashboard_workbench.css",
            "zscope/web/static/dashboard_navigation.js",
            "zscope/web/static/dashboard_redesign.css",
            "tests/test_agent_workbench_ui.py",
            "tests/fixtures/agent_workbench_ui.cjs",
        )
    ]
    before = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sources
    }
    try:
        result = subprocess.run(
            [
                shutil.which("node") or "node",
                "tests/fixtures/agent_workbench_ui.cjs",
                "--browser-jobs",
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=240,
            env=env,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        after = {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sources
        }
        assert (
            before == after
        ), "Direct UI/job/config sources changed during real owner verification"
        (root / env["ZSCOPE_UI_JOB_EVIDENCE"] / "source-sha256.json").write_text(
            json.dumps(before, indent=2) + "\n", encoding="utf-8"
        )
    finally:
        # Only this disposable project's actual jobs are touched, through the product service.
        document["project"]["targets"] = document["project"]["targets"][:1]
        _write(project, document)
        engine = ScanJobService(config, terminate_grace=1)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            response = engine.list()
            active = [
                job
                for job in response.payload.get("jobs", [])
                if job["status"] in {"queued", "running", "stopping"}
            ]
            if not active:
                break
            for job in active:
                if job["capabilities"]["cancel"]:
                    engine.cancel(
                        job["job_id"],
                        base_revision=job["revision"],
                        request_id=f"cleanup-{job['revision']}",
                    )
            time.sleep(0.2)


def _serve_real_jobs_fixture():
    """Separate Web process; restarting it never owns or kills detached jobs."""
    from zscope.orchestration.jobs.service import ScanJobService
    from zscope.web import server, services
    from zscope.web.scan_jobs_service import ScanJobsHttpService
    from zscope.orchestration.jobs.schedules import ScanScheduleService

    config, scanner, port, portfile = sys.argv[2:6]
    project = Path(config).parent
    engine = ScanJobService(
        config,
        terminate_grace=1,
        scan_command_builder=lambda path, depth, executable: [executable, scanner, str(project)],
    )
    feedback = services.ReportFeedbackService(report_filename=str(project / "report.json"))
    server._config_service = services.ConfigService(Path(config))
    server._report_feedback_service = feedback
    server._scan_jobs_http_service = ScanJobsHttpService(Path(config), feedback, engine=engine)
    # Exercise the real schedule state machine with the same controlled scanner
    # command builder. Independent production coordinator ownership is covered
    # by schedule service tests; restarting this helper recreates its tick loop.
    schedules = ScanScheduleService(config, engine=engine, spawn_daemon=False)
    server._scan_jobs_http_service._schedule_engine = schedules

    def tick_schedules():
        while True:
            schedules.tick()
            time.sleep(0.2)

    threading.Thread(target=tick_schedules, daemon=True).start()
    httpd = ThreadingHTTPServer(("127.0.0.1", int(port)), server.ZScopeHandler)
    Path(portfile).write_text(str(httpd.server_port), encoding="utf-8")
    httpd.serve_forever()


if __name__ == "__main__" and "--serve-jobs-fixture" in sys.argv:
    _serve_real_jobs_fixture()
