"""Actual service/SQL authority boundaries, with a controlled concurrent row update."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_job_cli_effective_window_boundary import _make_project, _store_for
from zscope.orchestration.execution_profile import InvalidJobBindingError, session_stop_window_authority
from zscope.orchestration.jobs.service import ScanJobService
from zscope.orchestration.jobs.store import JobStore


def bound_job(tmp_path):
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": "00:00"})
    response = ScanJobService(project / "zscope.yaml", spawn_owner=False).start(request_id="authority-snapshot", stop_at=(datetime.now(timezone.utc)+timedelta(seconds=60)).isoformat())
    assert response.status_code == 202, response.payload
    store = _store_for(project)
    row = store.get_job(response.payload["job"]["job_id"])
    assert row is not None
    env = {"ZSCOPE_JOB_STORE": str(store.db_path), "ZSCOPE_JOB_ID": row["job_id"], "ZSCOPE_JOB_RUN_ID": row["run_id"], "ZSCOPE_JOB_OWNER_TOKEN": row["owner_token"], "ZSCOPE_JOB_RUN_DIR": row["run_dir"]}
    # A real positive service/SQL/fingerprint precondition, before injecting any update.
    authority = session_stop_window_authority(project / "zscope.yaml", environ=env)
    assert authority is not None and authority.stop_at_epoch == row["stop_at_epoch"]
    return project, store, row, env


def test_validated_identity_and_window_cannot_come_from_different_rows(tmp_path, monkeypatch):
    project, store, row, env = bound_job(tmp_path)
    original = JobStore.get_job
    changed = False

    def update_after_read(self, job_id):
        nonlocal changed
        result = original(self, job_id)
        if not changed and self.db_path == store.db_path and job_id == row["job_id"]:
            assert result is not None and result["owner_token"] == row["owner_token"]
            changed = True
            # Actual optimistic SQL update, after the valid row was read but
            # before the authority consumer can issue another read.
            store.update_job(job_id, expected_revision=result["revision"], updates={"owner_token": "superseding-owner", "stop_at_epoch": None, "resolved_stop_time": None})
        return result

    monkeypatch.setattr(JobStore, "get_job", update_after_read)
    try:
        authority = session_stop_window_authority(project / "zscope.yaml", environ=env)
    except InvalidJobBindingError:
        assert changed
        return  # A fresh recheck correctly refused the superseded row.
    assert changed, "the controlled actual SQL interleaving was not exercised"
    assert authority is not None and authority.stop_at_epoch == row["stop_at_epoch"], "validated old identity consumed a foreign owner's cleared window"


def test_nonfinite_persisted_window_is_not_authority(tmp_path):
    project, store, row, env = bound_job(tmp_path)
    store.update_job(row["job_id"], expected_revision=row["revision"], updates={"stop_at_epoch": "nan"})
    with pytest.raises(InvalidJobBindingError):
        session_stop_window_authority(project / "zscope.yaml", environ=env)
