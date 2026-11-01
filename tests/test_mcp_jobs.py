"""Real persistent-job tests for the MCP job tools (U01-MCP-JOBS).

Every test here drives the real MCP tool surface (provider → jobs adapter)
over a real :class:`~zscope.orchestration.jobs.service.ScanJobService`: real
SQLite store located from the saved config, real detached owner processes,
and a controlled scanner child per attempt.  The controlled scanner is the
only sanctioned substitution — the service, store, owner, and identity
reconciliation are never faked, and no test mocks a service success.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import pytest

from test_scan_jobs import make_project
from semantics_fixtures import reviewed_control_plane_project
from zscope.config.config import ConfigLoader
from zscope.mcp.jobs_adapter import McpJobsAdapter
from zscope.mcp.provider import ZScopeMcpProvider
from zscope.mcp.server import handle_jsonrpc_request
from zscope.orchestration.jobs import identity
from zscope.orchestration.jobs.models import PHASE_SCANNING, TERMINAL_STATUSES
from zscope.orchestration.jobs.service import ScanJobService
from zscope.tools.policy import ToolPolicy

pytestmark = pytest.mark.skipif(
    not identity.proc_available(),
    reason="persistent job tests require Linux /proc process identity",
)

SCANNER_SCRIPT = """\
import json
import sys
import time
from pathlib import Path

mode = sys.argv[1]
root = Path(sys.argv[2])
report = root / "zscope_batch_report.json"

FINDING = {
    "id": "iss-1",
    "rule": "demo_rule",
    "function": "main",
    "location": "src/main.c:3",
    "category": "memory",
    "subcategory": "resource",
    "defect_class": "leak",
    "severity": "high",
    "description": "demo finding for the projection contract",
    "dedup_key": "demo/iss-1",
    "validation_status": "needs_review",
}
REPORT = {
    "completeness": "complete",
    "issues": [FINDING],
    "metadata": {"build_coverage": {"selected_tus": 1, "total_tus": 1}},
}

if mode == "report":
    time.sleep(0.5)
    report.write_text(json.dumps(REPORT))
elif mode == "shared":
    from zscope.reporting.json_io import write_report_atomic

    time.sleep(0.5)
    write_report_atomic(report, REPORT)
elif mode == "sleep":
    time.sleep(300)
elif mode == "fail":
    sys.exit(3)
sys.exit(0)
"""

JOBS_TOOL_NAMES = (
    "zscope.scan.run",
    "zscope.scan.status",
    "zscope.jobs.list",
    "zscope.jobs.events",
    "zscope.jobs.result",
    "zscope.jobs.cancel",
    "zscope.jobs.resume",
)


class _ControlledCodeIndex:
    """Controlled cached state for provider construction only.

    Used where the saved config composes a backend this test environment
    cannot initialize (unified needs the full SVF toolchain); the jobs path
    under test never touches the code index.
    """

    backend_name = "unified"
    language = "c_cpp"
    _index_epoch = 1

    def list_functions(self, pattern=None, limit=100000, offset=0):
        return []

    def resolve_existing_file(self, file_path):
        return None

    def close(self):
        pass


class _ControlledSnapshotStore:
    snapshot_dir = Path(".")

    def list_snapshots(self):
        return []


def wait_for(
    predicate: Callable[[], Any],
    *,
    timeout: float = 60.0,
    interval: float = 0.2,
    description: str,
) -> Any:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {description}; last={last!r}")


def make_provider(
    project: Path,
    *,
    scanner: Path,
    mode: str = "report",
    profile: str = "default",
    code_index: Any = None,
    snapshot_store: Any = None,
):
    """Build a provider whose job tools run over a real service.

    Returns ``(provider, modes)`` where ``modes`` is the mutable per-attempt
    scanner mode box the controlled scanner builder reads.
    """

    config = ConfigLoader.load(str(project / "zscope.yaml"), read_only=profile != "default")
    adapter: Optional[McpJobsAdapter] = None
    modes = [mode]
    if profile == "default":

        def builder(config_path, scan_depth, python_executable):
            return [python_executable, str(scanner), modes[0], str(project)]

        adapter = McpJobsAdapter(
            project / "zscope.yaml",
            service=ScanJobService(
                project / "zscope.yaml",
                scan_command_builder=builder,
                spawn_owner=True,
                terminate_grace=2.0,
            ),
        )
    provider = ZScopeMcpProvider(
        config,
        code_index=code_index,
        snapshot_store=snapshot_store,
        config_path=project / "zscope.yaml",
        jobs_adapter=adapter,
        profile=profile,
        tool_policy=ToolPolicy.allow_all(),
    )
    return provider, modes


def job_of(provider: ZScopeMcpProvider, job_id: str) -> Optional[Dict[str, Any]]:
    response = provider.call_tool("zscope.scan.status", {"job_id": job_id})
    if not response["success"]:
        return None
    return response["data"]["job"]


def wait_terminal(
    provider: ZScopeMcpProvider, job_id: str, *, timeout: float = 60.0
) -> Dict[str, Any]:
    return wait_for(
        lambda: (lambda job: job if job and job["status"] in TERMINAL_STATUSES else None)(
            job_of(provider, job_id)
        ),
        timeout=timeout,
        description=f"terminal state of {job_id}",
    )


@pytest.fixture
def job_env(tmp_path: Path):
    project = make_project(tmp_path)
    scanner = tmp_path / "scanner.py"
    scanner.write_text(SCANNER_SCRIPT, encoding="utf-8")
    return {"project": project, "scanner": scanner, "tmp_path": tmp_path}


# --- start/status: the real durable binding ---------------------------------------


def test_scan_run_returns_real_persistent_job_binding(job_env) -> None:
    project = job_env["project"]
    provider, _modes = make_provider(project, scanner=job_env["scanner"])

    run = provider.call_tool("zscope.scan.run", {"request_id": "req-mcp-1"})

    assert run["success"] is True, run
    assert run["data"]["schema"] == "zscope.scan-jobs.v1"
    job = run["data"]["job"]
    assert job["job_id"].startswith("job_")
    assert job["run_id"].startswith("run_")
    assert job["revision"] >= 1
    assert re.fullmatch(r"[0-9a-f]{64}", str(job["input_revision"]))
    assert job["status"] in {"queued", "running"}
    # The durable store really exists where the saved config locates it.
    assert (project / ".zscope_jobs" / "jobs.db").is_file()

    final = wait_terminal(provider, job["job_id"])
    assert final["status"] == "completed"
    status = provider.call_tool("zscope.scan.status", {"job_id": job["job_id"]})
    assert status["success"] is True
    assert status["data"]["job"]["status"] == "completed"
    assert status["data"]["job"]["report"]["available"] is True
    assert status["data"]["job"]["run_id"] == job["run_id"]


def test_status_rejects_unknown_jobs_and_legacy_arguments(job_env) -> None:
    provider, _modes = make_provider(job_env["project"], scanner=job_env["scanner"])

    missing = provider.call_tool("zscope.scan.status", {})
    legacy = provider.call_tool("zscope.scan.status", {"scan_id": "scan-1"})
    unknown = provider.call_tool("zscope.scan.status", {"job_id": "job_nope"})

    assert missing["success"] is False and missing["code"] == "invalid_request"
    assert legacy["success"] is False and legacy["code"] == "invalid_request"
    assert unknown["success"] is False
    assert unknown["code"] == "job_not_found"
    assert unknown["status_code"] == 404


# --- one shared store across providers, adapters, and service restarts ------------


def test_two_providers_and_a_rebuilt_service_share_one_store(job_env) -> None:
    project = job_env["project"]
    provider_a, _ = make_provider(project, scanner=job_env["scanner"])
    run = provider_a.call_tool("zscope.scan.run", {"request_id": "req-share"})
    assert run["success"] is True, run
    job_id = run["data"]["job"]["job_id"]

    provider_b, _ = make_provider(project, scanner=job_env["scanner"])
    listing = provider_b.call_tool("zscope.jobs.list", {})

    assert listing["success"] is True, listing
    ids = [job["job_id"] for job in listing["data"]["jobs"]]
    assert ids == [job_id]

    # A rebuilt bare service (no MCP layer at all) sees the same durable state.
    fresh = ScanJobService(project / "zscope.yaml", spawn_owner=False)
    detail = fresh.detail(job_id)
    assert detail.status_code == 200
    assert detail.payload["job"]["job_id"] == job_id
    wait_terminal(provider_a, job_id)


# --- request_id replay and conflict semantics identical to the Web ----------------


def test_duplicate_request_id_replays_one_owner_without_a_second_job(job_env) -> None:
    provider, _modes = make_provider(job_env["project"], scanner=job_env["scanner"])

    first = provider.call_tool("zscope.scan.run", {"request_id": "req-dup", "scan_depth": "fast"})
    second = provider.call_tool("zscope.scan.run", {"request_id": "req-dup", "scan_depth": "fast"})

    assert first["success"] is True and second["success"] is True
    job_id = first["data"]["job"]["job_id"]
    assert second["data"]["job"]["job_id"] == job_id
    listing = provider.call_tool("zscope.jobs.list", {})
    assert [job["job_id"] for job in listing["data"]["jobs"]] == [job_id]

    events = provider.call_tool("zscope.jobs.events", {"job_id": job_id})
    kinds = [event["kind"] for event in events["data"]["events"]]
    assert kinds.count("owner_spawned") == 1
    assert "request_replayed" in kinds
    wait_terminal(provider, job_id)


def test_conflicting_request_id_reuse_is_rejected(job_env) -> None:
    provider, _modes = make_provider(job_env["project"], scanner=job_env["scanner"])

    first = provider.call_tool(
        "zscope.scan.run", {"request_id": "req-conflict", "scan_depth": "fast"}
    )
    conflict = provider.call_tool(
        "zscope.scan.run", {"request_id": "req-conflict", "scan_depth": "deep"}
    )

    assert first["success"] is True
    assert conflict["success"] is False
    assert conflict["code"] == "request_id_conflict"
    assert conflict["status_code"] == 409
    wait_terminal(provider, first["data"]["job"]["job_id"])


# --- cancel / resume with base_revision guards ------------------------------------


def test_cancel_replay_and_revision_conflict(job_env) -> None:
    provider, _modes = make_provider(job_env["project"], scanner=job_env["scanner"], mode="sleep")
    run = provider.call_tool("zscope.scan.run", {"request_id": "req-cancel-start"})
    assert run["success"] is True, run
    job_id = run["data"]["job"]["job_id"]
    # Owner startup publishes scanner identity after the initial running state.
    # Capture the revision after that transition, before the sleeping scanner
    # can finish; heartbeats preserve this public revision.
    running = wait_for(
        lambda: (
            lambda job: (
                job
                if job and job["status"] == "running" and job["phase"] == PHASE_SCANNING
                else None
            )
        )(job_of(provider, job_id)),
        description="running sleep scanner",
    )

    stale = provider.call_tool(
        "zscope.jobs.cancel",
        {"job_id": job_id, "base_revision": 1, "request_id": "req-cancel-stale"},
    )
    assert stale["success"] is False
    assert stale["code"] == "revision_conflict"
    assert stale["status_code"] == 409

    cancel = provider.call_tool(
        "zscope.jobs.cancel",
        {
            "job_id": job_id,
            "base_revision": running["revision"],
            "request_id": "req-cancel-2",
        },
    )
    assert cancel["success"] is True, cancel
    replay = provider.call_tool(
        "zscope.jobs.cancel",
        {
            "job_id": job_id,
            "base_revision": running["revision"],
            "request_id": "req-cancel-2",
        },
    )
    assert replay["success"] is True

    final = wait_terminal(provider, job_id)
    assert final["status"] == "cancelled"


def test_resume_arms_a_new_run_after_a_real_failure(job_env) -> None:
    # A completed job is not resumable: drive a real failed attempt first,
    # then resume it with a working scanner for the second attempt.
    provider, modes = make_provider(job_env["project"], scanner=job_env["scanner"], mode="fail")
    run = provider.call_tool("zscope.scan.run", {"request_id": "req-resume-1"})
    assert run["success"] is True, run
    job_id = run["data"]["job"]["job_id"]
    first_run = run["data"]["job"]["run_id"]
    failed = wait_terminal(provider, job_id)
    assert failed["status"] == "failed"

    modes[0] = "report"

    resume = provider.call_tool(
        "zscope.jobs.resume",
        {
            "job_id": job_id,
            "base_revision": failed["revision"],
            "request_id": "req-resume-2",
        },
    )

    assert resume["success"] is True, resume
    armed = resume["data"]["job"]
    assert armed["run_id"] != first_run
    assert armed["status"] in {"queued", "running"}
    final = wait_terminal(provider, job_id)
    assert final["status"] == "completed"
    events = provider.call_tool("zscope.jobs.events", {"job_id": job_id})
    kinds = [event["kind"] for event in events["data"]["events"]]
    assert "attempt_started" in kinds


def test_input_change_revokes_the_previous_attempt_binding(job_env) -> None:
    project = job_env["project"]
    provider, modes = make_provider(project, scanner=job_env["scanner"], mode="fail")
    run = provider.call_tool("zscope.scan.run", {"request_id": "req-input-1"})
    assert run["success"] is True, run
    job_id = run["data"]["job"]["job_id"]
    first_input = run["data"]["job"]["input_revision"]
    failed = wait_terminal(provider, job_id)
    assert failed["status"] == "failed"

    modes[0] = "report"
    (project / "src" / "main.c").write_text(
        "int main(void) { return 1; } // changed\n", encoding="utf-8"
    )
    reviewed_control_plane_project(project / "zscope.yaml")
    resume = provider.call_tool(
        "zscope.jobs.resume",
        {
            "job_id": job_id,
            "base_revision": failed["revision"],
            "request_id": "req-input-2",
        },
    )

    assert resume["success"] is True, resume
    assert resume["data"]["job"]["input_revision"] != first_input
    final = wait_terminal(provider, job_id)
    assert final["status"] == "completed"
    events = provider.call_tool("zscope.jobs.events", {"job_id": job_id})
    kinds = [event["kind"] for event in events["data"]["events"]]
    assert "input_revoked" in kinds


# --- result binding and the honest findings boundary ------------------------------


def test_result_reports_the_verified_report_binding(job_env) -> None:
    project = job_env["project"]
    provider, _modes = make_provider(project, scanner=job_env["scanner"])
    run = provider.call_tool("zscope.scan.run", {"request_id": "req-result"})
    assert run["success"] is True, run
    job_id = run["data"]["job"]["job_id"]
    completed = wait_terminal(provider, job_id)

    result = provider.call_tool("zscope.jobs.result", {"job_id": job_id})

    assert result["success"] is True, result
    data = result["data"]
    assert data["report_available"] is True
    report_path = Path(completed["report"]["path"])
    # The outer report_id stays the byte hash of the bound snapshot.
    assert data["report_id"] == hashlib.sha256(report_path.read_bytes()).hexdigest()
    assert "coverage" in data and "questions" in data
    # The real findings projection: one actual finding with its identity,
    # acceptance and review scope, bound to this attempt.
    findings = data["findings"]
    assert isinstance(findings, dict)
    assert findings["view"] == "with_needs_review"
    projected = findings["findings"]
    assert projected and projected[0]["id"] == "iss-1"
    assert re.fullmatch(r"[0-9a-f]{64}", str(projected[0]["issue_id"]))
    assert re.fullmatch(r"[0-9a-f]{64}", str(projected[0]["report_id"]))
    # Conservative acceptance: a needs_review finding without a re-derivable
    # decision proof projects as pending, never promoted.
    assert projected[0]["acceptance"]["state"] == "pending"
    assert findings["coverage"]["completeness"] == "complete"
    binding = data["binding"]
    assert binding["job_id"] == job_id
    assert binding["run_id"] == completed["run_id"]
    assert binding["report_id"] == data["report_id"]
    assert binding["input_revision"] == run["data"]["job"]["input_revision"]
    # The scanner's report is still the current project report, so the
    # review scope is shared with it.
    assert data["review_scope"]["shared_with_current"] is True
    assert Path(data["review_scope"]["filename"]) == project / "zscope_batch_report.json"


def test_result_projects_shared_json_report_over_jsonrpc(job_env) -> None:
    project = job_env["project"]
    provider, _modes = make_provider(project, scanner=job_env["scanner"], mode="shared")
    run = provider.call_tool("zscope.scan.run", {"request_id": "req-shared"})
    assert run["success"] is True, run
    job_id = run["data"]["job"]["run_id"] and run["data"]["job"]["job_id"]
    completed = wait_terminal(provider, job_id)

    response = handle_jsonrpc_request(
        provider,
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "zscope.jobs.result",
                "arguments": {"job_id": job_id},
            },
        },
    )
    structured = response["result"]["structuredContent"]
    assert structured["success"] is True, structured
    data = structured["data"]
    assert data["report_available"] is True
    findings = data["findings"]
    assert findings["findings"] and findings["findings"][0]["id"] == "iss-1"
    assert findings["findings"][0]["acceptance"]["state"] == "pending"
    # The shared-json storage envelope decodes to the logical report: the
    # projection is served from the logical graph, not the envelope bytes.
    bound = Path(completed["report"]["path"])
    assert json.loads(bound.read_text(encoding="utf-8"))["storage_schema"] == (
        "zscope.shared-json.v1"
    )
    assert data["review_scope"]["shared_with_current"] is True


def test_result_scope_stays_independent_when_current_report_differs(job_env) -> None:
    from zscope.web.review_reports import report_identity

    project = job_env["project"]
    provider, _modes = make_provider(project, scanner=job_env["scanner"])
    run = provider.call_tool("zscope.scan.run", {"request_id": "req-scope"})
    assert run["success"] is True, run
    job_id = run["data"]["job"]["job_id"]
    completed = wait_terminal(provider, job_id)

    # The project's current report is replaced with different content after
    # the attempt bound its snapshot: the bound result keeps its own review
    # scope and is never swapped for the current report.
    (project / "zscope_batch_report.json").write_text(
        json.dumps({"completeness": "incomplete", "issues": []}), encoding="utf-8"
    )

    result = provider.call_tool("zscope.jobs.result", {"job_id": job_id})
    assert result["success"] is True, result
    data = result["data"]
    assert data["report_available"] is True
    assert data["review_scope"]["shared_with_current"] is False
    snapshot = Path(completed["report"]["path"])
    assert Path(data["review_scope"]["filename"]) == snapshot
    findings = data["findings"]
    assert findings["findings"] and findings["findings"][0]["id"] == "iss-1"
    from zscope.reporting.json_io import read_report

    bound_logical = read_report(snapshot)
    assert findings["report_id"] == report_identity(bound_logical, str(snapshot))


def test_result_rebuilt_provider_serves_identical_findings(job_env) -> None:
    project = job_env["project"]
    provider_a, _ = make_provider(project, scanner=job_env["scanner"])
    run = provider_a.call_tool("zscope.scan.run", {"request_id": "req-rebuild"})
    assert run["success"] is True, run
    job_id = run["data"]["job"]["job_id"]
    wait_terminal(provider_a, job_id)

    first = provider_a.call_tool("zscope.jobs.result", {"job_id": job_id})
    provider_b, _ = make_provider(project, scanner=job_env["scanner"])
    second = provider_b.call_tool("zscope.jobs.result", {"job_id": job_id})

    assert first["success"] is True and second["success"] is True
    assert first["data"]["findings"] == second["data"]["findings"]
    assert first["data"]["binding"] == second["data"]["binding"]


def test_result_is_honest_when_no_report_was_produced(job_env) -> None:
    provider, _modes = make_provider(job_env["project"], scanner=job_env["scanner"], mode="fail")
    run = provider.call_tool("zscope.scan.run", {"request_id": "req-no-report"})
    assert run["success"] is True, run
    job_id = run["data"]["job"]["job_id"]
    failed = wait_terminal(provider, job_id)
    assert failed["status"] == "failed"

    result = provider.call_tool("zscope.jobs.result", {"job_id": job_id})
    assert result["success"] is True, result
    data = result["data"]
    assert data["report_available"] is False
    assert data["findings"] is None
    assert data["reason"] == "report_not_produced"
    assert data["binding"]["job_id"] == job_id


def test_events_cursor_pages_from_after_seq(job_env) -> None:
    provider, _modes = make_provider(job_env["project"], scanner=job_env["scanner"])
    run = provider.call_tool("zscope.scan.run", {"request_id": "req-events"})
    assert run["success"] is True, run
    job_id = run["data"]["job"]["job_id"]
    wait_terminal(provider, job_id)

    page = provider.call_tool("zscope.jobs.events", {"job_id": job_id})
    assert page["success"] is True, page
    events = page["data"]["events"]
    assert events
    seqs = [event["seq"] for event in events]
    assert seqs == sorted(seqs)
    assert page["data"]["next_seq"] == seqs[-1]

    tail = provider.call_tool(
        "zscope.jobs.events", {"job_id": job_id, "after_seq": page["data"]["next_seq"]}
    )
    assert tail["data"]["events"] == []
    assert tail["data"]["next_seq"] == page["data"]["next_seq"]

    negative = provider.call_tool("zscope.jobs.events", {"job_id": job_id, "after_seq": -1})
    assert negative["success"] is False
    assert negative["code"] == "invalid_request"


# --- profile boundary: read_only / candidate_blind never start or control ----------


@pytest.mark.parametrize("profile", ["read_only", "candidate_blind"])
def test_read_only_profiles_cannot_start_or_control_jobs(job_env, profile) -> None:
    project = job_env["project"]
    provider, _modes = make_provider(project, scanner=job_env["scanner"], profile=profile)

    names = {tool["name"] for tool in provider.list_tools()}
    for name in JOBS_TOOL_NAMES:
        assert name not in names
    for name in ("zscope.scan.run", "zscope.jobs.cancel", "zscope.jobs.resume"):
        result = provider.call_tool(name, {"request_id": "x", "job_id": "j", "base_revision": 1})
        assert result["status"] == "forbidden"
    # No store was ever located or created by these profiles.
    assert not (project / ".zscope_jobs").exists()


# --- v3 configs: single target composes, a multi-target edit stays unexecutable ----


def _v3_document(targets: list) -> dict:
    return {
        "config_version": 3,
        "llms": {
            "default": {
                "base_urls": ["http://dummy-endpoint.invalid/v1"],
                "models": ["dummy-model"],
                "api_key": "dummy-key",
            }
        },
        "project": {
            "language": "c_cpp",
            "platform": "linux_user",
            "targets": targets,
        },
        "scan": {"preset": "fast"},
    }


def test_v3_single_target_runs_and_multi_target_edit_is_refused(tmp_path: Path) -> None:
    project = tmp_path / "v3project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (project / "build").mkdir()
    (project / "build" / "compile_commands.json").write_text("[]\n", encoding="utf-8")
    (project / "zscope.yaml").write_text(
        json.dumps(
            _v3_document([{"id": "main", "compile_commands": "build/compile_commands.json"}])
        ),
        encoding="utf-8",
    )
    scanner = tmp_path / "scanner.py"
    reviewed_control_plane_project(project / "zscope.yaml")
    scanner.write_text(SCANNER_SCRIPT, encoding="utf-8")

    # The v3 document composes the unified backend; this environment has no
    # SVF toolchain, so the provider's code index is the one controlled cached
    # state injected here.  The jobs path under test never touches it.
    provider, _modes = make_provider(
        project,
        scanner=scanner,
        code_index=_ControlledCodeIndex(),
        snapshot_store=_ControlledSnapshotStore(),
    )
    single = provider.call_tool("zscope.scan.run", {"request_id": "req-v3-single"})
    assert single["success"] is True, single
    assert wait_terminal(provider, single["data"]["job"]["job_id"])["status"] == "completed"

    # The saved config becomes multi-target while the session is live: the
    # shared parser refuses composition and the job surface relays exactly
    # that refusal — no approximate schema, no first-target shortcut.
    (project / "zscope.yaml").write_text(
        json.dumps(
            _v3_document(
                [
                    {"id": "main", "compile_commands": "build/compile_commands.json"},
                    {"id": "bench", "compile_commands": "build/compile_commands.json"},
                ]
            )
        ),
        encoding="utf-8",
    )
    refused = provider.call_tool("zscope.scan.run", {"request_id": "req-v3-multi"})

    assert refused["success"] is False
    assert refused["code"] == "config_unavailable"
    assert refused["status_code"] == 503
    assert "exactly one" in refused["error"]
    assert "project.targets" in refused["error"]


# --- strict arguments and schema, without relaxing anything ------------------------


def test_jobs_tools_reject_unknown_and_mistyped_arguments(job_env) -> None:
    project = job_env["project"]
    provider, _modes = make_provider(project, scanner=job_env["scanner"])

    cases = [
        ("zscope.scan.run", {}, "missing required argument"),
        ("zscope.scan.run", {"request_id": "r", "scan_depth": "nightly"}, "scan_depth"),
        ("zscope.scan.run", {"request_id": "r", "depth": "fast"}, "unknown argument"),
        ("zscope.scan.run", {"request_id": ""}, "request_id"),
        ("zscope.jobs.cancel", {"job_id": "j", "base_revision": "3", "request_id": "r"}, "integer"),
        (
            "zscope.jobs.cancel",
            {"job_id": "j", "base_revision": True, "request_id": "r"},
            "integer",
        ),
        ("zscope.jobs.events", {"job_id": "j", "after_seq": -1}, "after_seq"),
        ("zscope.jobs.list", {"job_id": "j"}, "unknown argument"),
        ("zscope.jobs.result", {}, "missing required argument"),
        # An explicit null is not an omitted optional field under the
        # published schema; every one of these must reject at the boundary.
        ("zscope.scan.status", {"job_id": None}, "job_id"),
        ("zscope.jobs.events", {"job_id": "j", "after_seq": None}, "after_seq"),
        ("zscope.scan.run", {"request_id": "null-stop", "stop_at": None}, "stop_at"),
        ("zscope.scan.run", {"request_id": "null-depth", "scan_depth": None}, "scan_depth"),
        ("zscope.scan.run", {"request_id": None}, "request_id"),
        (
            "zscope.jobs.cancel",
            {"job_id": "j", "base_revision": None, "request_id": "r"},
            "integer",
        ),
        ("zscope.jobs.events", {"job_id": "j", "after_seq": True}, "after_seq"),
        ("zscope.scan.run", {"request_id": "r", "scan_depth": 3}, "scan_depth"),
        ("zscope.scan.status", {"job_id": ""}, "job_id"),
    ]
    for name, arguments, needle in cases:
        result = provider.call_tool(name, arguments)
        assert result["success"] is False, (name, arguments, result)
        assert result["code"] == "invalid_request"
        assert result["status_code"] == 400
        assert needle in result["error"], (name, arguments, result["error"])

    # Boundary validation failed before any engine call: no store was created.
    assert not (project / ".zscope_jobs").exists()


def test_omitted_optional_fields_remain_legal(job_env) -> None:
    # Only *present* fields are strictly checked: a minimal start request
    # with just request_id still reaches the real service and creates a job.
    provider, _modes = make_provider(job_env["project"], scanner=job_env["scanner"])

    run = provider.call_tool("zscope.scan.run", {"request_id": "req-minimal"})
    events = provider.call_tool("zscope.jobs.events", {"job_id": run["data"]["job"]["job_id"]})

    assert run["success"] is True, run
    assert events["success"] is True, events
    assert events["data"]["next_seq"] >= 1
    wait_terminal(provider, run["data"]["job"]["job_id"])


def test_jobs_tool_schemas_are_strict(job_env) -> None:
    provider, _modes = make_provider(job_env["project"], scanner=job_env["scanner"])

    schemas = {tool["name"]: tool for tool in provider.list_tools()}
    for name in JOBS_TOOL_NAMES:
        assert name in schemas
        assert schemas[name]["inputSchema"]["additionalProperties"] is False
    assert schemas["zscope.scan.run"]["inputSchema"]["required"] == ["request_id"]
    assert schemas["zscope.jobs.cancel"]["inputSchema"]["required"] == [
        "job_id",
        "base_revision",
        "request_id",
    ]
    assert schemas["zscope.jobs.resume"]["inputSchema"]["required"] == [
        "job_id",
        "base_revision",
        "request_id",
    ]
    assert schemas["zscope.jobs.cancel"]["annotations"]["readOnlyHint"] is False
    assert schemas["zscope.jobs.events"]["annotations"]["readOnlyHint"] is True


def test_jsonrpc_dispatch_reaches_the_real_service(job_env) -> None:
    provider, _modes = make_provider(job_env["project"], scanner=job_env["scanner"])

    response = handle_jsonrpc_request(
        provider,
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "zscope.scan.run",
                "arguments": {"request_id": "req-jsonrpc"},
            },
        },
    )

    structured = response["result"]["structuredContent"]
    assert structured["success"] is True, structured
    assert response["result"]["isError"] is False
    job_id = structured["data"]["job"]["job_id"]
    assert wait_terminal(provider, job_id)["status"] == "completed"


def test_jobs_unavailable_without_a_saved_config_is_honest(job_env) -> None:
    config = ConfigLoader.load(str(job_env["project"] / "zscope.yaml"))
    provider = ZScopeMcpProvider(config, tool_policy=ToolPolicy.allow_all())

    result = provider.call_tool("zscope.scan.run", {"request_id": "req-noconf"})

    assert result["success"] is False
    assert result["code"] == "unavailable"
    assert "saved config" in result["error"]
