"""Job-bound CLI stop-window authority tests (U01-JOB-CLI-WINDOW-R20).

Real-owner tests run the detached owner and the real CLI scanner with only
the analysis ``run`` body controlled (the same harness shape as the
coordinator probes); negative tests drive the real CLI directly with
controlled environments.  The authority rule under test: with a *valid*
owner binding the job store's persisted window is the only budget source —
including a legitimate ``None`` after a resume cleared it — while a
standalone CLI keeps the config's one-shot parse.  A partially present or
unverifiable binding is refused, and an already-passed persisted window
refuses the scan instead of rolling.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional

import pytest

from test_config_stop_at_consumers import _make_project, _minute_ahead_utc, _store_for
from zscope.common.cancellation import CancellationToken
from zscope.orchestration.execution_profile import (
    InvalidJobBindingError,
    arm_persisted_deadline,
    session_stop_window_authority,
)
from zscope.orchestration.jobs.scheduler_hook import (
    JOB_ENV_JOB_ID,
    JOB_ENV_OWNER_TOKEN,
    JOB_ENV_RUN_DIR,
    JOB_ENV_RUN_ID,
    JOB_ENV_STORE,
)
from zscope.orchestration.jobs.service import ScanJobService
from zscope.orchestration.jobs.store import JobStore

# Only the analysis run body is controlled; the service, the detached owner,
# the CLI and the real ScanSessionRunner/token are all real.
HELPER = """\
import json, os, sys, time
from pathlib import Path
from zscope.orchestration.scan_session import ScanSessionRunner
from zscope.orchestration.execution_profile import session_cancellation_token


def controlled_analysis(self):
    token = session_cancellation_token(self)
    out = Path(sys.argv[2])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "remaining": token.remaining_seconds(),
        "wall_epoch": time.time(),
        "reason": token.reason,
        "job_id": os.environ.get("ZSCOPE_JOB_ID"),
        "run_id": os.environ.get("ZSCOPE_JOB_RUN_ID"),
        "shared_token": token is self.session_executor.cancellation_token,
    }), encoding="utf-8")
    # A controlled runtime failure keeps the attempt legitimately resumable.
    raise SystemExit(91)


ScanSessionRunner.run = controlled_analysis
from zscope.cli.cli import main
main(args=["-c", sys.argv[1], "--discover-entries"], standalone_mode=False)
"""

WORKSPACE = Path(__file__).resolve().parents[1]


def _helper_at(tmp_path: Path) -> Path:
    helper = tmp_path / "cli-window-helper.py"
    helper.write_text(HELPER, encoding="utf-8")
    return helper


def _service(project: Path, helper: Path) -> ScanJobService:
    def command(config_path: Path, scan_depth: Optional[str], python_executable: str):
        return [python_executable, "-u", str(helper), str(config_path), str(tmp_observation)]

    tmp_observation = helper.parent / "cli-budget.json"
    return ScanJobService(project / "zscope.yaml", scan_command_builder=command, terminate_grace=1)


def _wait_terminal(
    service: ScanJobService, job_id: str, *, timeout: float = 45.0
) -> Dict[str, Any]:
    end = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < end:
        response = service.detail(job_id)
        assert response.status_code == 200, response.payload
        last = response.payload["job"]
        if last["status"] in {"completed", "partial", "cancelled", "failed", "lost"}:
            return last
        time.sleep(0.1)
    raise AssertionError(f"real owner did not reach a terminal state; last={last!r}")


def _observation(helper: Path) -> Dict[str, Any]:
    path = helper.parent / "cli-budget.json"
    assert path.is_file(), "real CLI refused before controlled analysis"
    return json.loads(path.read_text(encoding="utf-8"))


def _run_cli(
    helper: Path, config: Path, *, env_extra: Dict[str, str], drop_job_env: bool = True
) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(WORKSPACE) + os.pathsep + env.get("PYTHONPATH", "")
    if drop_job_env:
        for key in (
            JOB_ENV_STORE,
            JOB_ENV_JOB_ID,
            JOB_ENV_RUN_ID,
            JOB_ENV_OWNER_TOKEN,
            JOB_ENV_RUN_DIR,
        ):
            env.pop(key, None)
    env.update(env_extra)
    observation = helper.parent / "cli-budget.json"
    return subprocess.run(
        [sys.executable, "-u", str(helper), str(config), str(observation)],
        cwd=str(config.parent),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        timeout=120,
    )


# --- real owner: the persisted SQL window is the only budget ---------------------


def test_real_owner_cli_uses_explicit_window_instead_of_config_window(
    tmp_path: Path,
) -> None:
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": "00:00"})
    helper = _helper_at(tmp_path)
    service = _service(project, helper)
    explicit = datetime.now(timezone.utc) + timedelta(seconds=60)
    response = service.start(request_id="req-explicit-cli-window", stop_at=explicit.isoformat())
    assert response.status_code == 202, response.payload
    job = _wait_terminal(service, response.payload["job"]["job_id"])
    assert datetime.fromisoformat(job["resolved_stop_time"]) == explicit
    data = _observation(helper)
    assert data["shared_token"] and data["job_id"] == job["job_id"]
    # The config window is 00:00 (next midnight); the budget must follow the
    # persisted explicit epoch instead.
    assert data["remaining"] is not None and 0 < data["remaining"] < 3600
    assert abs(data["remaining"] - (explicit.timestamp() - data["wall_epoch"])) < 0.5


def test_real_owner_cli_uses_config_window_persisted_at_start(tmp_path: Path) -> None:
    stop_at, _, _ = _minute_ahead_utc(offset_seconds=300)
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": stop_at})
    helper = _helper_at(tmp_path)
    service = _service(project, helper)
    response = service.start(request_id="req-config-cli-window")
    assert response.status_code == 202, response.payload
    job = _wait_terminal(service, response.payload["job"]["job_id"])
    row = _store_for(project).get_job(job["job_id"])
    assert row is not None and row["stop_at_epoch"] is not None
    data = _observation(helper)
    assert data["remaining"] is not None and 0 < data["remaining"]
    assert abs(data["remaining"] - (row["stop_at_epoch"] - data["wall_epoch"])) < 0.5


def test_real_resumed_cli_does_not_reapply_cleared_config_window(
    tmp_path: Path,
) -> None:
    stop_at, _, _ = _minute_ahead_utc(offset_seconds=300)
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": stop_at})
    helper = _helper_at(tmp_path)
    service = _service(project, helper)
    response = service.start(request_id="req-before-resume-cli-window")
    assert response.status_code == 202, response.payload
    first = _wait_terminal(service, response.payload["job"]["job_id"])
    assert _observation(helper)["remaining"] is not None
    response = service.resume(
        first["job_id"], base_revision=first["revision"], request_id="req-resume-cli-window"
    )
    assert response.status_code == 202, response.payload
    resumed = _wait_terminal(service, first["job_id"])
    row = _store_for(project).get_job(first["job_id"])
    assert resumed["run_id"] != first["run_id"] and row["stop_at_epoch"] is None
    data = _observation(helper)
    assert data["run_id"] == resumed["run_id"]
    # The resume cleared the SQL window: no budget at all, and the config
    # window is never re-applied under a valid owner binding.
    assert data["remaining"] is None


# --- standalone CLI keeps the config one-shot parse ------------------------------


def test_standalone_cli_keeps_the_config_window(tmp_path: Path) -> None:
    stop_at, _, expected = _minute_ahead_utc(offset_seconds=180)
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": stop_at})
    helper = _helper_at(tmp_path)
    result = _run_cli(helper, project / "zscope.yaml", env_extra={})
    assert result.returncode == 91, result.stdout[-2000:]
    # The standalone flavor of the arming line names the config window.
    armed = next(line for line in result.stdout.splitlines() if "Stop window armed" in line)
    assert f"{stop_at} UTC" in armed and "job " not in armed
    data = _observation(helper)
    assert data["job_id"] is None
    assert data["remaining"] is not None and 0 < data["remaining"] <= 180
    assert abs(data["remaining"] - (expected.timestamp() - data["wall_epoch"])) < 0.5


# --- partial or unverifiable bindings are refused, never guessed -----------------


def test_partial_job_env_is_refused_not_treated_as_standalone(tmp_path: Path) -> None:
    stop_at, _, _ = _minute_ahead_utc(offset_seconds=180)
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": stop_at})
    helper = _helper_at(tmp_path)
    result = _run_cli(
        helper,
        project / "zscope.yaml",
        env_extra={
            JOB_ENV_STORE: str(project / ".zscope_jobs" / "jobs.db"),
            JOB_ENV_JOB_ID: "job_x",
        },
    )
    assert result.returncode == 2, result.stdout[-2000:]
    assert "incomplete job binding environment" in result.stdout
    # The refusal happens before any scan work: no observation, and the
    # config window was never armed as a fallback.
    assert not (helper.parent / "cli-budget.json").is_file()
    assert "Stop window armed:" not in result.stdout


def _job_row_without_owner(project: Path, *, stop_at: Optional[str] = None) -> Dict[str, Any]:
    service = ScanJobService(project / "zscope.yaml", spawn_owner=False)
    response = service.start(request_id=f"req-{stop_at or 'none'}", stop_at=stop_at)
    assert response.status_code == 202, response.payload
    job = response.payload["job"]
    row = _store_for(project).get_job(job["job_id"])
    assert row is not None
    return row


def _full_job_env(row: Dict[str, Any], *, owner_token: Optional[str] = None) -> Dict[str, str]:
    store_path = Path(row["run_dir"]).parents[1] / "jobs.db"
    return {
        JOB_ENV_STORE: str(store_path),
        JOB_ENV_JOB_ID: row["job_id"],
        JOB_ENV_RUN_ID: row["run_id"],
        JOB_ENV_OWNER_TOKEN: owner_token if owner_token is not None else row["owner_token"],
        JOB_ENV_RUN_DIR: row["run_dir"],
    }


def test_wrong_owner_token_binding_is_refused(tmp_path: Path) -> None:
    stop_at, _, _ = _minute_ahead_utc(offset_seconds=300)
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": stop_at})
    helper = _helper_at(tmp_path)
    row = _job_row_without_owner(project)
    result = _run_cli(
        helper,
        project / "zscope.yaml",
        env_extra=_full_job_env(row, owner_token="foreign-owner-token"),
    )
    assert result.returncode == 2, result.stdout[-2000:]
    assert "owner_token_mismatch" in result.stdout
    assert not (helper.parent / "cli-budget.json").is_file()


def test_changed_inputs_binding_is_refused(tmp_path: Path) -> None:
    stop_at, _, _ = _minute_ahead_utc(offset_seconds=300)
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": stop_at})
    helper = _helper_at(tmp_path)
    row = _job_row_without_owner(project)
    # The row is bound to the inputs at start; a source change after that
    # must revoke the binding instead of authorizing a stale window.
    (project / "src" / "lib.c").write_text(
        '#include "lib.h"\nint process_data(const char *input, int len) { return len; }\n',
        encoding="utf-8",
    )
    result = _run_cli(helper, project / "zscope.yaml", env_extra=_full_job_env(row))
    assert result.returncode == 2, result.stdout[-2000:]
    assert "input_revision_changed" in result.stdout
    assert not (helper.parent / "cli-budget.json").is_file()


def test_expired_persisted_window_refuses_without_rolling(tmp_path: Path) -> None:
    # A valid binding whose persisted epoch already passed: the scan is
    # refused (job-failure exit code), never rolled to a later occurrence
    # and never silently swapped for the config window.
    past = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": "23:59"})
    helper = _helper_at(tmp_path)
    row = _job_row_without_owner(project, stop_at=past)
    assert row["stop_at_epoch"] is not None and row["stop_at_epoch"] < time.time()
    result = _run_cli(helper, project / "zscope.yaml", env_extra=_full_job_env(row))
    assert result.returncode == 2, result.stdout[-2000:]
    assert "persisted stop window" in result.stdout and "already passed" in result.stdout
    assert not (helper.parent / "cli-budget.json").is_file()
    assert "Stop window armed:" not in result.stdout


def _bound_authority(tmp_path: Path):
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": "00:00"})
    explicit = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    row = _job_row_without_owner(project, stop_at=explicit)
    env = _full_job_env(row)
    authority = session_stop_window_authority(project / "zscope.yaml", environ=env)
    assert authority is not None and authority.stop_at_epoch == row["stop_at_epoch"]
    return project, _store_for(project), row, env


@pytest.mark.parametrize(
    ("updates", "rejection"),
    [
        ({"owner_token": "replacement-owner"}, "owner_token_mismatch"),
        ({"run_id": "replacement-run"}, "run_superseded"),
        ({"input_revision": "replacement-inputs"}, "input_revision_changed"),
        ({"status": "failed"}, "job_terminal"),
        ({"run_dir": "/foreign-run-directory"}, "persisted_run_dir_mismatch"),
    ],
)
def test_concurrent_sql_change_does_not_mix_identity_and_window(
    tmp_path: Path, monkeypatch, updates: Dict[str, Any], rejection: str
) -> None:
    project, store, row, env = _bound_authority(tmp_path)
    original_get_job = JobStore.get_job
    read_count = 0

    def change_after_select(self, job_id):
        nonlocal read_count
        result = original_get_job(self, job_id)
        if self.db_path == store.db_path and job_id == row["job_id"]:
            read_count += 1
            if read_count == 1:
                assert result is not None and result["revision"] == row["revision"]
                # Commit a real optimistic SQL update after the SELECT has
                # read the row.  Return that actual row, without editing it.
                store.update_job(
                    job_id,
                    expected_revision=result["revision"],
                    updates={**updates, "stop_at_epoch": None, "resolved_stop_time": None},
                )
        return result

    monkeypatch.setattr(JobStore, "get_job", change_after_select)
    authority = session_stop_window_authority(project / "zscope.yaml", environ=env)
    assert authority is not None and authority.stop_at_epoch == row["stop_at_epoch"]
    assert authority.resolved_stop_time == row["resolved_stop_time"]
    assert read_count == 1
    committed = original_get_job(store, row["job_id"])
    assert committed is not None and committed["stop_at_epoch"] is None
    assert committed["revision"] == row["revision"] + 1
    assert all(committed[key] == value for key, value in updates.items())
    # A later read observes the new row and must reject its invalid binding.
    # The earlier consistent snapshot does not grant a permanent lease.
    with pytest.raises(InvalidJobBindingError, match=rejection):
        session_stop_window_authority(project / "zscope.yaml", environ=env)


@pytest.mark.parametrize("raw_epoch", ["nan", "inf", "-inf", "1e999", "broken", float("inf")])
def test_invalid_sql_deadline_is_rejected(tmp_path: Path, raw_epoch: Any) -> None:
    project, store, row, env = _bound_authority(tmp_path)
    store.update_job(
        row["job_id"], expected_revision=row["revision"], updates={"stop_at_epoch": raw_epoch}
    )
    # SQLite permits TEXT in this REAL column; a corrupt non-null value is
    # not the legitimate SQL NULL used by a window-less resumed attempt.
    with pytest.raises(InvalidJobBindingError, match="persisted_stop_window"):
        session_stop_window_authority(project / "zscope.yaml", environ=env)


def test_cli_rejects_nan_sql_window_before_analysis(tmp_path: Path) -> None:
    helper = _helper_at(tmp_path)
    project, store, row, env = _bound_authority(tmp_path)
    store.update_job(
        row["job_id"], expected_revision=row["revision"], updates={"stop_at_epoch": "nan"}
    )
    result = _run_cli(helper, project / "zscope.yaml", env_extra=env)
    assert result.returncode == 2, result.stdout[-2000:]
    assert "nonfinite_persisted_stop_window" in result.stdout
    assert "Stop window armed:" not in result.stdout
    assert not (helper.parent / "cli-budget.json").is_file()


@pytest.mark.parametrize("epoch", [float("nan"), float("inf"), float("-inf")])
def test_direct_arming_rejects_nonfinite_epoch_without_touching_token(epoch: float) -> None:
    token = CancellationToken()
    runner = SimpleNamespace(session_executor=SimpleNamespace(cancellation_token=token))
    with pytest.raises(InvalidJobBindingError, match="nonfinite_persisted_stop_window"):
        arm_persisted_deadline(runner, stop_at_epoch=epoch)
    assert token.remaining_seconds() is None
    assert not token.is_cancelled()


@pytest.mark.parametrize("relocate_persisted_directory", [False, True])
def test_copied_store_cannot_replace_configured_project_authority(
    tmp_path: Path, relocate_persisted_directory: bool
) -> None:
    project, store, row, env = _bound_authority(tmp_path)
    clone_root = tmp_path / "clone-outside-project"
    clone_root.mkdir()
    clone_path = clone_root / "jobs.db"
    with sqlite3.connect(store.db_path.as_uri() + "?mode=ro", uri=True) as source:
        with sqlite3.connect(clone_path) as target:
            source.backup(target)
    clone = JobStore(clone_path)
    clone_row = clone.get_job(row["job_id"])
    assert clone_row is not None and clone_row["run_dir"] == row["run_dir"]
    clone_run_dir = str(clone_root / row["job_id"] / row["run_id"])
    if relocate_persisted_directory:
        clone.update_job(
            row["job_id"], expected_revision=row["revision"], updates={"run_dir": clone_run_dir}
        )
    # The clone lies outside the project's source manifest: the original
    # authority still passes its real input fingerprint check after copying.
    valid = session_stop_window_authority(project / "zscope.yaml", environ=env)
    assert valid is not None and valid.stop_at_epoch == row["stop_at_epoch"]
    env[JOB_ENV_STORE] = str(clone_path)
    env[JOB_ENV_RUN_DIR] = clone_run_dir
    with pytest.raises(InvalidJobBindingError, match="store_project_mismatch"):
        session_stop_window_authority(project / "zscope.yaml", environ=env)


def test_persisted_run_directory_must_match_owner_and_project(tmp_path: Path) -> None:
    project, store, row, env = _bound_authority(tmp_path)
    store.update_job(
        row["job_id"],
        expected_revision=row["revision"],
        updates={"run_dir": str(tmp_path / "foreign-persisted-run")},
    )
    with pytest.raises(InvalidJobBindingError, match="persisted_run_dir_mismatch"):
        session_stop_window_authority(project / "zscope.yaml", environ=env)


def test_missing_project_store_is_not_created_by_authority_lookup(tmp_path: Path) -> None:
    project, store, _, env = _bound_authority(tmp_path)
    store.db_path.rename(store.db_path.with_name("saved-jobs.db"))
    with pytest.raises(InvalidJobBindingError, match="store_unreadable"):
        session_stop_window_authority(project / "zscope.yaml", environ=env)
    assert not store.db_path.exists()


def test_same_project_paths_resolve_to_same_sql_authority(tmp_path: Path) -> None:
    project, _, row, env = _bound_authority(tmp_path)
    alias = tmp_path / "project-alias"
    alias.symlink_to(project, target_is_directory=True)
    env[JOB_ENV_STORE] = str(alias / ".zscope_jobs" / "jobs.db")
    env[JOB_ENV_RUN_DIR] = str(alias / ".zscope_jobs" / row["job_id"] / row["run_id"])
    authority = session_stop_window_authority(project / "zscope.yaml", environ=env)
    assert authority is not None and authority.stop_at_epoch == row["stop_at_epoch"]


def test_default_config_path_uses_current_project_authority(tmp_path: Path, monkeypatch) -> None:
    project, _, row, env = _bound_authority(tmp_path)
    monkeypatch.chdir(project)
    authority = session_stop_window_authority(environ=env)
    assert authority is not None and authority.stop_at_epoch == row["stop_at_epoch"]
