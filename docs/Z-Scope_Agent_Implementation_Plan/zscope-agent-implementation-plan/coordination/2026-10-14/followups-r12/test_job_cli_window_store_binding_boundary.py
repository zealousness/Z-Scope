"""A copied SQL row cannot move its run directory authority to another store."""
from pathlib import Path
import sqlite3
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_job_cli_window_snapshot_boundary import bound_job
from zscope.orchestration.execution_profile import InvalidJobBindingError, session_stop_window_authority


def test_copied_store_cannot_authorize_a_different_run_directory(tmp_path):
    project, store, row, env = bound_job(tmp_path)
    copied_root = tmp_path / "copied-store"
    copied_root.mkdir()
    copied_store = copied_root / "jobs.db"
    with sqlite3.connect("file:" + str(store.db_path) + "?mode=ro", uri=True) as source:
        with sqlite3.connect(copied_store) as target:
            source.backup(target)
    # The actual copied row retains its original authoritative run_dir.
    with sqlite3.connect(copied_store) as db:
        assert db.execute("SELECT run_dir FROM jobs WHERE job_id=?", (row["job_id"],)).fetchone()[0] == row["run_dir"]
    # Cloning must not invalidate the original target's input fingerprint;
    # otherwise refusal would not establish a store/run-directory boundary.
    original_authority = session_stop_window_authority(project / "zscope.yaml", environ=env)
    assert original_authority is not None and original_authority.stop_at_epoch == row["stop_at_epoch"]
    env["ZSCOPE_JOB_STORE"] = str(copied_store)
    env["ZSCOPE_JOB_RUN_DIR"] = str(copied_root / row["job_id"] / row["run_id"])
    with pytest.raises(InvalidJobBindingError):
        session_stop_window_authority(project / "zscope.yaml", environ=env)
