"""Real-service tests for the job result findings projection (MCP-FINDINGS-R12).

Every test drives :func:`zscope.reporting.job_result_projection.project_job_result`
over a real :class:`~zscope.orchestration.jobs.service.ScanJobService`: real
SQLite store located from the saved config, real detached owner processes,
and a controlled scanner child per attempt.  The controlled scanner is the
only sanctioned substitution — the service, store, owner, projection helpers
and identity reconciliation are never faked, and no test mocks a service
success.  The Web ``ScanJobsHttpService._result`` is exercised read-only as
the parity reference for the same values.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from test_scan_jobs import make_project, store_for
from zscope.orchestration.jobs import identity
from zscope.orchestration.jobs.models import TERMINAL_STATUSES
from zscope.orchestration.jobs.service import ScanJobService
from zscope.reporting.job_result_projection import project_job_result
from zscope.reporting.json_io import read_report
from zscope.web.review_reports import report_identity
from zscope.web.scan_jobs_service import ScanJobsHttpService
from zscope.web.services import ReportFeedbackService

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
BARE = {"issues": [FINDING]}

if mode == "report":
    time.sleep(0.5)
    report.write_text(json.dumps(REPORT))
elif mode == "report_exit2":
    time.sleep(0.5)
    report.write_text(json.dumps(REPORT))
    sys.exit(2)
elif mode == "bare":
    time.sleep(0.5)
    report.write_text(json.dumps(BARE))
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


def wait_for(predicate, *, timeout: float = 60.0, interval: float = 0.2, description: str):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {description}; last={last!r}")


def make_service(project: Path, scanner: Path, mode_box: list, **kwargs: Any) -> ScanJobService:
    def builder(config_path, scan_depth, python_executable):
        return [python_executable, str(scanner), mode_box[0], str(project)]

    kwargs.setdefault("scan_command_builder", builder)
    kwargs.setdefault("spawn_owner", True)
    kwargs.setdefault("terminate_grace", 2.0)
    return ScanJobService(project / "zscope.yaml", **kwargs)


def run_to_terminal(service: ScanJobService, *, request_id: str, timeout: float = 60.0):
    response = service.start(request_id=request_id)
    assert response.status_code == 202, response.payload
    job = response.payload["job"]
    job_id = job["job_id"]

    def probe():
        current = service.detail(job_id).payload["job"]
        return current if current["status"] in TERMINAL_STATUSES else None

    terminal = wait_for(probe, timeout=timeout, description=f"terminal state of {job_id}")
    return job, terminal


class _SwitchingService(ScanJobService):
    """A real service that moves to a fresh attempt inside ``load_bound_report``.

    Only the *timing* is controlled: resume, the detached owner and the
    scanner all run for real, so the projection must observe a genuinely
    changed attempt binding, never a faked one.
    """

    def __init__(self, *args: Any, moves: int = 1, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._moves_left = int(moves)
        self.switched_runs: list[str] = []

    def load_bound_report(self, job_id: str) -> Any:
        if self._moves_left > 0:
            self._moves_left -= 1
            current = self.detail(job_id).payload["job"]
            resumed = self.resume(
                job_id,
                base_revision=current["revision"],
                request_id=f"req-switch-{len(self.switched_runs)}",
            )
            assert resumed.status_code == 202, resumed.payload
            deadline = time.monotonic() + 90.0
            while time.monotonic() < deadline:
                job = self.detail(job_id).payload["job"]
                if job["status"] in TERMINAL_STATUSES:
                    self.switched_runs.append(job["run_id"])
                    break
                time.sleep(0.2)
        return super().load_bound_report(job_id)


@pytest.fixture
def projection_env(tmp_path: Path):
    project = make_project(tmp_path)
    scanner = tmp_path / "scanner.py"
    scanner.write_text(SCANNER_SCRIPT, encoding="utf-8")
    return {"project": project, "scanner": scanner, "tmp_path": tmp_path}


def _project(service: Any, project: Path, job_id: str) -> Dict[str, Any]:
    status_code, payload = project_job_result(service, job_id, config_path=project / "zscope.yaml")
    assert status_code == 200, payload
    return payload


# ---------------------------------------------------------------------------
# the real projection over plain and shared-json reports


def test_plain_report_projects_real_findings_bound_to_the_attempt(projection_env):
    project = projection_env["project"]
    service = make_service(project, projection_env["scanner"], ["report"])
    job, terminal = run_to_terminal(service, request_id="req-plain")

    payload = _project(service, project, job["job_id"])

    assert payload["report_available"] is True
    snapshot = Path(terminal["report"]["path"])
    assert payload["report_id"] == hashlib.sha256(snapshot.read_bytes()).hexdigest()
    findings = payload["findings"]
    assert findings["view"] == "with_needs_review"
    assert [item["id"] for item in findings["findings"]] == ["iss-1"]
    assert all(item["issue_id"] and item["report_id"] for item in findings["findings"])
    assert findings["findings"][0]["acceptance"]["state"] == "pending"
    assert findings["coverage"]["completeness"] == "complete"
    binding = payload["binding"]
    assert binding["job_id"] == job["job_id"]
    assert binding["run_id"] == terminal["run_id"]
    assert binding["report_id"] == payload["report_id"]
    assert binding["input_revision"] == job["input_revision"]
    # The scanner's report is still the current report: shared review scope.
    assert payload["review_scope"]["shared_with_current"] is True
    assert Path(payload["review_scope"]["filename"]) == project / "zscope_batch_report.json"
    logical = read_report(snapshot)
    assert findings["report_id"] == report_identity(
        logical, str(project / "zscope_batch_report.json")
    )


def test_shared_json_report_projects_the_logical_graph(projection_env):
    project = projection_env["project"]
    service = make_service(project, projection_env["scanner"], ["shared"])
    job, terminal = run_to_terminal(service, request_id="req-shared")

    payload = _project(service, project, job["job_id"])

    snapshot = Path(terminal["report"]["path"])
    envelope = json.loads(snapshot.read_text(encoding="utf-8"))
    assert envelope["storage_schema"] == "zscope.shared-json.v1"
    assert payload["report_id"] == hashlib.sha256(snapshot.read_bytes()).hexdigest()
    findings = payload["findings"]
    assert [item["id"] for item in findings["findings"]] == ["iss-1"]
    assert findings["findings"][0]["acceptance"]["state"] == "pending"
    logical = read_report(snapshot)
    assert findings["report_id"] == report_identity(
        logical, str(project / "zscope_batch_report.json")
    )


def test_projection_matches_the_web_result_behavior(projection_env):
    """The MCP-side projection serves exactly the Web's pure projection."""

    project = projection_env["project"]
    service = make_service(project, projection_env["scanner"], ["report"])
    job, terminal = run_to_terminal(service, request_id="req-parity")

    payload = _project(service, project, job["job_id"])
    feedback = ReportFeedbackService(report_filename=str(project / "zscope_batch_report.json"))
    http = ScanJobsHttpService(project / "zscope.yaml", feedback, engine=service)
    web_status, web_payload = http._result(service, job["job_id"])

    assert web_status == 200
    assert web_payload["report_available"] is True
    assert web_payload["findings"] == payload["findings"]
    assert web_payload["report_id"] == payload["report_id"]


# ---------------------------------------------------------------------------
# review scope: shared with the current report only when fully equal


def test_scope_stays_independent_when_the_current_report_differs(projection_env):
    project = projection_env["project"]
    service = make_service(project, projection_env["scanner"], ["report"])
    job, terminal = run_to_terminal(service, request_id="req-independent")

    (project / "zscope_batch_report.json").write_text(
        json.dumps({"completeness": "incomplete", "issues": []}), encoding="utf-8"
    )
    payload = _project(service, project, job["job_id"])

    assert payload["report_available"] is True
    assert payload["review_scope"]["shared_with_current"] is False
    snapshot = Path(terminal["report"]["path"])
    assert Path(payload["review_scope"]["filename"]) == snapshot
    findings = payload["findings"]
    assert [item["id"] for item in findings["findings"]] == ["iss-1"]
    logical = read_report(snapshot)
    assert findings["report_id"] == report_identity(logical, str(snapshot))


def test_missing_or_corrupt_current_report_never_revokes_the_bound_result(projection_env):
    project = projection_env["project"]
    service = make_service(project, projection_env["scanner"], ["report"])
    job, terminal = run_to_terminal(service, request_id="req-current-gone")

    (project / "zscope_batch_report.json").unlink()
    payload = _project(service, project, job["job_id"])
    assert payload["report_available"] is True
    assert payload["review_scope"]["shared_with_current"] is False
    assert [item["id"] for item in payload["findings"]["findings"]] == ["iss-1"]

    # A corrupt current report degrades the same way: independent scope, the
    # bound historical result keeps serving its own findings.
    (project / "zscope_batch_report.json").write_bytes(b"{not json at all")
    payload = _project(service, project, job["job_id"])
    assert payload["report_available"] is True
    assert payload["review_scope"]["shared_with_current"] is False
    assert [item["id"] for item in payload["findings"]["findings"]] == ["iss-1"]


# ---------------------------------------------------------------------------
# honest refusal when the bound artifact is gone, tampered or corrupt


def test_bound_snapshot_loss_and_tampering_revoke_availability(projection_env):
    project = projection_env["project"]
    service = make_service(project, projection_env["scanner"], ["report"])
    job, terminal = run_to_terminal(service, request_id="req-damage")

    snapshot = Path(terminal["report"]["path"])
    snapshot.write_bytes(snapshot.read_bytes() + b"\n")
    payload = _project(service, project, job["job_id"])
    assert payload["report_available"] is False
    assert payload["findings"] is None
    assert payload["reason"] == "report_artifact_mismatch"

    snapshot.unlink()
    payload = _project(service, project, job["job_id"])
    assert payload["report_available"] is False
    assert payload["findings"] is None
    assert payload["reason"] == "report_artifact_missing"


def test_corrupt_object_graph_is_rejected_not_served(projection_env):
    project = projection_env["project"]
    service = make_service(project, projection_env["scanner"], ["shared"])
    job, terminal = run_to_terminal(service, request_id="req-corrupt-graph")

    snapshot = Path(terminal["report"]["path"])
    envelope = json.loads(snapshot.read_text(encoding="utf-8"))
    uid = next(iter(envelope["objects"]))
    envelope["objects"][uid] = ["value", "tampered-object-digest"]
    snapshot.write_text(json.dumps(envelope), encoding="utf-8")
    # Re-bind the recorded hash to the tampered bytes so the corruption, not
    # the byte change, is what the reader must catch.
    store = store_for(project)
    row = store.get_job(job["job_id"])
    report_json = dict(row["report_json"] or {})
    report_json["report_id"] = hashlib.sha256(snapshot.read_bytes()).hexdigest()
    store.update_job(
        job["job_id"], expected_revision=int(row["revision"]), updates={"report_json": report_json}
    )

    payload = _project(service, project, job["job_id"])
    assert payload["report_available"] is False
    assert payload["findings"] is None
    assert payload["reason"] == "report_artifact_corrupt"


# ---------------------------------------------------------------------------
# attempt identity: a moved attempt is never served as another's result


def test_attempt_switch_between_reads_is_served_as_the_new_attempt(projection_env):
    """A resume lands between the reads — even with identical report bytes.

    The projection re-verifies the run binding and retries, so the published
    findings belong to the new attempt, never to the stale one.
    """

    project = projection_env["project"]
    service = _SwitchingService(
        project / "zscope.yaml",
        moves=1,
        scan_command_builder=lambda config_path, scan_depth, python_executable: [
            python_executable,
            str(projection_env["scanner"]),
            "report_exit2",
            str(project),
        ],
        spawn_owner=True,
        terminate_grace=2.0,
    )
    job, terminal = run_to_terminal(service, request_id="req-switch")
    first_run = terminal["run_id"]

    payload = _project(service, project, job["job_id"])

    assert service.switched_runs, "the controlled switch must really have run"
    assert payload["report_available"] is True
    assert payload["binding"]["run_id"] == service.switched_runs[-1]
    assert payload["binding"]["run_id"] != first_run
    assert [item["id"] for item in payload["findings"]["findings"]] == ["iss-1"]


def test_persistently_moving_attempt_is_refused_honestly(projection_env):
    project = projection_env["project"]
    service = _SwitchingService(
        project / "zscope.yaml",
        moves=99,
        scan_command_builder=lambda config_path, scan_depth, python_executable: [
            python_executable,
            str(projection_env["scanner"]),
            "report_exit2",
            str(project),
        ],
        spawn_owner=True,
        terminate_grace=2.0,
    )
    job, _terminal = run_to_terminal(service, request_id="req-moving")

    payload = _project(service, project, job["job_id"])

    assert payload["report_available"] is False
    assert payload["findings"] is None
    assert payload["reason"] == "attempt_changed"


# ---------------------------------------------------------------------------
# unknown stays unknown


def test_active_job_and_unmeasured_coverage_stay_unknown(projection_env):
    project = projection_env["project"]
    service = make_service(project, projection_env["scanner"], ["sleep"])
    response = service.start(request_id="req-active")
    job = response.payload["job"]
    # Both waits drive a real subprocess owner. Under the full acceptance suite
    # (many concurrent native scans) the 60 s default can expire even though the
    # owner is healthy, so the budget matches the 180 s used by the crash-resume
    # boundary tests; the assertions themselves are unchanged.
    wait_for(
        lambda: (service.detail(job["job_id"]).payload["job"]["status"] == "running" or None),
        description="running sleep scanner",
        timeout=180.0,
    )

    payload = _project(service, project, job["job_id"])
    assert payload["report_available"] is False
    assert payload["findings"] is None
    assert payload["reason"] == "job_status:running"
    assert payload["binding"]["job_id"] == job["job_id"]
    service.cancel(
        job["job_id"],
        base_revision=service.detail(job["job_id"]).payload["job"]["revision"],
        request_id="req-active-cancel",
    )
    try:
        wait_for(
            lambda: (
                service.detail(job["job_id"]).payload["job"]
                if service.detail(job["job_id"]).payload["job"]["status"] in TERMINAL_STATUSES
                else None
            ),
            description="cancelled sleep scanner",
            timeout=180.0,
        )
    except AssertionError as exc:
        # A timeout here means the owner never reached a terminal status; report
        # the stored job so a starvation diagnosis does not need a rerun.
        raise AssertionError(f"{exc}; job={service.detail(job['job_id']).payload['job']}") from exc


def test_report_without_metadata_keeps_coverage_unknown(projection_env):
    project = projection_env["project"]
    service = make_service(project, projection_env["scanner"], ["bare"])
    job, terminal = run_to_terminal(service, request_id="req-bare")

    payload = _project(service, project, job["job_id"])

    assert payload["report_available"] is True
    findings = payload["findings"]
    assert [item["id"] for item in findings["findings"]] == ["iss-1"]
    # Unmeasured signals stay null; nothing is invented.
    assert findings["coverage"]["completeness"] is None
    assert payload["coverage"]["completeness"] is None


def test_projection_locates_the_root_from_the_saved_config_of_the_service(
    projection_env, monkeypatch: pytest.MonkeyPatch
):
    """No Bridge cwd: the current-report comparison follows the saved config."""

    project = projection_env["project"]
    service = make_service(project, projection_env["scanner"], ["report"])
    job, terminal = run_to_terminal(service, request_id="req-no-cwd")

    elsewhere = projection_env["tmp_path"] / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    # config_path omitted: the projection falls back to the service's own
    # saved config path and still finds the project-root current report.
    status_code, payload = project_job_result(service, job["job_id"])
    assert status_code == 200
    assert payload["review_scope"]["shared_with_current"] is True
    assert Path(payload["review_scope"]["filename"]) == project / "zscope_batch_report.json"


# ---------------------------------------------------------------------------
# envelope-boundary races: one round's envelope, binding and findings only


class _EnvelopeSwitchingService(ScanJobService):
    """A real service that resumes while ``result()`` is serving its envelope.

    Only the interleaving is controlled: ``result()`` returns the real old
    envelope after a real resume + detached owner + scanner already moved the
    job to a new attempt — the exact boundary the fence must catch.
    """

    def __init__(self, *args: Any, mode: str = "report_exit2", **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._mode = mode
        self.switch_once = True
        self.switched_to: Optional[Dict[str, Any]] = None

    def result(self, job_id: str) -> Any:
        response = super().result(job_id)
        if self.switch_once:
            self.switch_once = False
            prior = self.detail(job_id).payload["job"]
            resumed = self.resume(
                job_id,
                base_revision=prior["revision"],
                request_id="req-envelope-switch",
            )
            assert resumed.status_code == 202, resumed.payload
            deadline = time.monotonic() + 90.0
            while time.monotonic() < deadline:
                current = self.detail(job_id).payload["job"]
                if current["status"] in TERMINAL_STATUSES:
                    self.switched_to = current
                    break
                time.sleep(0.2)
            assert self.switched_to is not None
            assert self.switched_to["run_id"] != prior["run_id"]
        return response


def test_envelope_read_race_never_mixes_old_artifacts_with_new_binding(projection_env):
    """A resume lands inside ``result()`` with identical report bytes.

    The fence retries against the fresh envelope, so the published
    coverage/questions/artifacts, the binding and the findings all belong
    to the new round — never the old attempt's artifacts labelled with the
    new run binding.
    """

    project = projection_env["project"]
    service = _EnvelopeSwitchingService(
        project / "zscope.yaml",
        mode="report_exit2",
        scan_command_builder=lambda config_path, scan_depth, python_executable: [
            python_executable,
            str(projection_env["scanner"]),
            "report_exit2",
            str(project),
        ],
        spawn_owner=True,
        terminate_grace=2.0,
    )
    job, first = run_to_terminal(service, request_id="req-envelope-race")
    assert first["status"] == "partial"

    payload = _project(service, project, job["job_id"])

    assert service.switched_to is not None
    assert payload["binding"]["run_id"] == service.switched_to["run_id"]
    # The envelope itself is the new round's, not the stale one: a fresh
    # result call must serve byte-identical coverage/questions/artifacts.
    fresh = service.result(job["job_id"]).payload
    assert payload["artifacts"] == fresh["artifacts"]
    assert payload["coverage"] == fresh["coverage"]
    assert payload["questions"] == fresh["questions"]
    assert payload["findings"]["findings"][0]["id"] == "iss-1"
    # Every artifact path belongs to the new attempt's run directory.
    new_run = service.switched_to["run_id"]
    for artifact in payload["artifacts"]:
        assert new_run in str(artifact["path"]), artifact["path"]


def test_no_report_envelope_race_does_not_mix_later_binding(projection_env):
    """The no-report branch is fenced the same way.

    A resume inside ``result()`` on a report-less attempt must not publish
    the old envelope together with the later run's binding either; the
    round is retried and both come from the same (new) attempt.
    """

    project = projection_env["project"]
    service = _EnvelopeSwitchingService(
        project / "zscope.yaml",
        mode="fail",
        scan_command_builder=lambda config_path, scan_depth, python_executable: [
            python_executable,
            str(projection_env["scanner"]),
            "fail",
            str(project),
        ],
        spawn_owner=True,
        terminate_grace=2.0,
    )
    job, first = run_to_terminal(service, request_id="req-no-report-race")
    assert first["status"] == "failed"

    status_code, payload = project_job_result(
        service, job["job_id"], config_path=project / "zscope.yaml"
    )
    assert status_code == 200
    assert service.switched_to is not None
    assert payload["report_available"] is False
    assert payload["findings"] is None
    assert payload["reason"] == "report_not_produced"
    assert payload["binding"]["run_id"] == service.switched_to["run_id"]
    fresh = service.result(job["job_id"]).payload
    assert payload["reason"] == fresh["reason"]
