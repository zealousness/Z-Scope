"""Native dual-variant scans and real attempt/queue/receipt recovery.

The project and scanner execute for real; no external model is used. These
fixtures measure this bounded route, not real-project recall or full S08.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest
from test_scan_checkpoint_resume import (
    _bind_env,
    _count_executions,
    _read_report,
    _resume,
    _session_config,
    _native_project,
)
from test_scan_jobs import start_job, store_for
from zscope.orchestration.jobs.service import ScanJobService
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer
from zscope.orchestration.scan_session import ScanSessionRunner


@pytest.fixture
def native_run(monkeypatch, tmp_path):
    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "real native tool required"
    project = _native_project(tmp_path)
    header = project / "src" / "flags.h"
    header.write_text("#define RECOVERY_FIXTURE_VALUE 1\n", encoding="utf-8")
    source = project / "src" / "unit.c"
    source.write_text('#include "flags.h"\n' + source.read_text(encoding="utf-8"), encoding="utf-8")
    service = ScanJobService(project / "zscope.yaml", spawn_owner=False)
    created = start_job(service, request_id="native-partial-recovery")
    store = store_for(project)
    job = store.get_job(created["job_id"])
    assert job is not None
    calls = _count_executions(monkeypatch)
    validation = []
    original = ParallelAnalyzer.validate_instance_batch

    def spy(self, batch):
        validation.append(
            {
                "restored": set(batch.restored_instances),
                "executed": set(batch.executed_instances),
                "settled": set(batch.settled_instances),
                "cache": self._validation_result_cache,
            }
        )
        return original(self, batch)

    monkeypatch.setattr(ParallelAnalyzer, "validate_instance_batch", spy)
    _bind_env(monkeypatch, project, store, job)
    ScanSessionRunner(_session_config(project), task_id="recovery/first").run()
    assert sum(map(len, calls)) == 2
    assert len(validation) == 1
    first = _read_report(project / "report.json")
    assert first["metadata"]["job"]["checkpointed"] is True
    with sqlite3.connect(str(store.db_path)) as connection:
        rows = connection.execute(
            "SELECT e.seq,e.data_json FROM events e JOIN bound_event_receipts r ON r.event_seq=e.seq "
            "WHERE e.job_id=? AND e.kind='instance_result_persisted' ORDER BY e.seq",
            (job["job_id"],),
        ).fetchall()
    assert len(rows) == 2
    receipts = [(seq, json.loads(data)) for seq, data in rows]
    return project, service, store, job, calls, validation, receipts


def resume_run(native_run, monkeypatch):
    project, service, store, old, calls, validation, receipts = native_run
    resumed = _resume(service, store, old)
    calls.clear()
    _bind_env(monkeypatch, project, store, resumed)
    ScanSessionRunner(_session_config(project), task_id="recovery/resumed").run()
    report = _read_report(project / "report.json")
    return resumed, report["metadata"]["job"], validation[-1]


def assert_partition(job, *, restored, executed):
    summary = job["instance_recovery"]
    r, e, p = map(
        set,
        (
            summary["restored_identities"],
            summary["executed_identities"],
            summary["analyzed_identities"],
        ),
    )
    assert not r & e
    assert r | e == p
    assert len(r) == restored and len(e) == executed and len(p) == restored + executed
    assert job["restored_instances"] == job["cached_instances"] == restored
    assert job["executed_instances"] == executed
    assert job["analyzed_instances"] == restored + executed
    assert summary["current_validation_state"] == "DONE"
    assert job["checkpointed"] is True


def test_all_restored_still_runs_current_validation_once(native_run, monkeypatch):
    _project, _service, _store, old, calls, validation, _receipts = native_run
    _resumed, job, observed = resume_run(native_run, monkeypatch)
    assert calls == []
    assert len(validation) == 2, "all-restored must traverse this attempt's real validation queue"
    assert observed["cache"] is not validation[0]["cache"]
    assert len(observed["restored"]) == 2 and observed["executed"] == set()
    assert observed["settled"] == observed["restored"]
    assert job["restored_from_run_id"] == old["run_id"]
    assert_partition(job, restored=2, executed=0)


def test_tampered_one_instance_only_reexecutes_that_instance(native_run, monkeypatch):
    *_prefix, calls, validation, receipts = native_run
    _seq, damaged = receipts[0]
    path = Path(damaged["artifact_path"])
    path.write_bytes(path.read_bytes() + b"\n")
    _resumed, job, observed = resume_run(native_run, monkeypatch)
    assert calls == [[damaged["instance"]["identity"]]]
    assert len(validation) == 2
    assert observed["executed"] == {damaged["instance"]["identity"]}
    assert_partition(job, restored=1, executed=1)


def test_artifact_without_receipt_is_reexecuted_and_old_whole_checkpoint_unused(
    native_run, monkeypatch
):
    project, _service, store, _old, calls, validation, receipts = native_run
    seq, missing = receipts[0]
    assert Path(missing["artifact_path"]).is_file()
    with sqlite3.connect(str(store.db_path)) as connection:
        connection.execute("DELETE FROM bound_event_receipts WHERE event_seq=?", (seq,))

    def forbidden(*args, **kwargs):
        raise AssertionError("old whole-checkpoint route bypassed current validation")

    monkeypatch.setattr(ScanSessionRunner, "_load_bound_completion", forbidden)
    _resumed, job, _observed = resume_run(native_run, monkeypatch)
    assert calls == [[missing["instance"]["identity"]]]
    assert len(validation) == 2
    assert_partition(job, restored=1, executed=1)


def test_changed_header_revokes_all_instance_recovery(native_run, monkeypatch):
    project, _service, _store, _old, calls, validation, _receipts = native_run
    header = project / "src" / "flags.h"
    assert header.is_file()
    before = header.read_bytes()
    stamp = header.stat()
    header.write_bytes(before + b"\n/* current native dependency changed */\n")
    os.utime(header, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    _resumed, job, _observed = resume_run(native_run, monkeypatch)
    assert sum(map(len, calls)) == 2
    assert len(validation) == 2
    assert_partition(job, restored=0, executed=2)
