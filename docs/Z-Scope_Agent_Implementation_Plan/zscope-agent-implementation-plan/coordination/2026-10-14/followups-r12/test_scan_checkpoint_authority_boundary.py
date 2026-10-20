"""Actual native/SQLite resume gates; no real model or project effect claim."""
from pathlib import Path
import sys
import threading
import sqlite3

import pytest

from zscope.orchestration.jobs import scan_work
from zscope.orchestration.jobs.models import JobError
from zscope.orchestration.jobs.store import JobStore
from zscope.orchestration.scan_session import ScanSessionRunner
from zscope.orchestration import scan_session as session_module
from zscope.semantics import contracts, contract_compiler, instance_semantics

sys.path.insert(0, str(Path(scan_work.__file__).resolve().parents[3] / "tests"))
import test_scan_checkpoint_resume as helpers  # noqa: E402


def test_changed_contract_compiler_cannot_reuse_a_previous_completion(monkeypatch, tmp_path):
    project, service, store, row = helpers._start(monkeypatch, tmp_path)
    calls = helpers._count_executions(monkeypatch)
    helpers._bind_env(monkeypatch, tmp_path, store, row)
    ScanSessionRunner(helpers._session_config(project), task_id="boundary/first").run()
    assert sum(map(len, calls)) == 2
    old = str(contracts.CONTRACT_COMPILER_VERSION)
    monkeypatch.setattr(contracts, "CONTRACT_COMPILER_VERSION", old + ".boundary-new")
    monkeypatch.setattr(contract_compiler, "CONTRACT_COMPILER_VERSION", old + ".boundary-new")
    # The frozen semantics fingerprint reads the constant from the module that
    # consumes it (by value at import), so patching the two declarers alone
    # leaves the recorded compiler version unchanged and the receipt stays
    # "current" for the wrong reason.
    monkeypatch.setattr(instance_semantics, "CONTRACT_COMPILER_VERSION", old + ".boundary-new")
    resumed = helpers._resume(service, store, row)
    assert resumed["input_revision"] == row["input_revision"]
    calls.clear()
    helpers._bind_env(monkeypatch, tmp_path, store, resumed)
    ScanSessionRunner(helpers._session_config(project), task_id="boundary/changed-contract").run()
    assert sum(map(len, calls)) == 2, "a changed contract compiler invalidates the completed instance work"


def test_owner_handoff_during_checkpoint_read_prevents_stale_report_publication(monkeypatch, tmp_path):
    project, service, store, row = helpers._start(monkeypatch, tmp_path)
    helpers._bind_env(monkeypatch, tmp_path, store, row)
    ScanSessionRunner(helpers._session_config(project), task_id="boundary/first").run()
    resumed = helpers._resume(service, store, row)
    helpers._bind_env(monkeypatch, tmp_path, store, resumed)
    # The trusted authority is the per-instance receipt set, decided by the
    # store while the run is bound. Re-hang the race there: a handoff observed
    # while the run reads its receipts must stop the stale report.
    original = JobStore.trusted_instance_results
    handoff = []

    def read_then_handoff(self, **kwargs):
        receipts = original(self, **kwargs)
        if not handoff:
            handoff.append(helpers._resume(service, store, resumed))
        return receipts

    monkeypatch.setattr(JobStore, "trusted_instance_results", read_then_handoff)
    report = project / "report.json"
    before = report.read_bytes()
    with pytest.raises(JobError):
        ScanSessionRunner(helpers._session_config(project), task_id="boundary/stale-reader").run()
    assert len(handoff) == 1
    assert store.get_job(row["job_id"])["run_id"] == handoff[0]["run_id"]
    assert report.read_bytes() == before, "the old reader cannot publish a report after actual SQL handoff"


def test_serialized_confirmation_cannot_become_a_current_scan_confirmation(monkeypatch, tmp_path):
    """Controlled report output, actual native scan/store; no fabricated proof claim."""
    project, service, store, row = helpers._start(monkeypatch, tmp_path)
    analyzer = helpers.parallel_module.ParallelAnalyzer
    original = analyzer.generate_combined_report
    inject = {"enabled": True}
    marker = "serialized-proof-is-not-current-authority"

    def controlled_report(self, *args, **kwargs):
        report = original(self, *args, **kwargs)
        if inject["enabled"]:
            report.setdefault("issues", []).append({"issue_id": marker, "validation_status": "validated", "candidate_disposition": "confirmed", "finding_kind": "verified_vulnerability", "deterministic_prevalidation_decision": "confirmed", "decision_proof": {"serialized_only_marker": marker}})
        return report

    monkeypatch.setattr(analyzer, "generate_combined_report", controlled_report)
    calls = helpers._count_executions(monkeypatch)
    helpers._bind_env(monkeypatch, tmp_path, store, row)
    ScanSessionRunner(helpers._session_config(project), task_id="boundary/first").run()
    assert sum(map(len, calls)) == 2
    first = helpers._read_report(project / "report.json")
    assert any(issue.get("issue_id") == marker for issue in first["issues"])
    inject["enabled"] = False
    resumed = helpers._resume(service, store, row)
    helpers._bind_env(monkeypatch, tmp_path, store, resumed)
    ScanSessionRunner(helpers._session_config(project), task_id="boundary/current").run()
    current = helpers._read_report(project / "report.json")
    assert all(issue.get("issue_id") != marker for issue in current.get("issues", [])), "a bound historical JSON must not grant a current proof-confirmed finding"


def test_final_report_publication_is_fenced_against_actual_owner_handoff(monkeypatch, tmp_path):
    """A check-only transaction must not leave publication outside its fence."""
    project, service, store, row = helpers._start(monkeypatch, tmp_path)
    helpers._bind_env(monkeypatch, tmp_path, store, row)
    ScanSessionRunner(helpers._session_config(project), task_id="boundary/first").run()
    resumed = helpers._resume(service, store, row)
    helpers._bind_env(monkeypatch, tmp_path, store, resumed)
    original = ScanSessionRunner._finalize_instance_run
    finished = threading.Event()
    entered = threading.Event()
    handoff = []
    errors = []
    threads = []
    wins_before_finalization = []

    def transfer():
        entered.set()
        try:
            handoff.append(helpers._resume(service, store, resumed))
        except BaseException as exc:
            errors.append(exc)
        finally:
            finished.set()

    def pause_before_finalize(self, state, **kwargs):
        # The resumed run reports per-instance reuse instead of a whole
        # restored report; both restored instances must be visible here.
        recovery = state.get("instance_recovery") or {}
        assert recovery.get("restored_instances") == 2, recovery
        thread = threading.Thread(target=transfer, name="checkpoint-publication-handoff")
        threads.append(thread)
        thread.start()
        assert entered.wait(5)
        # A real SQL publication fence blocks the other writer until the
        # report is published. Otherwise the actual service handoff wins here.
        wins_before_finalization.append(finished.wait(1))
        return original(self, state, **kwargs)

    monkeypatch.setattr(ScanSessionRunner, "_finalize_instance_run", pause_before_finalize)
    report = project / "report.json"
    before = report.read_bytes()
    try:
        ScanSessionRunner(helpers._session_config(project), task_id="boundary/publication").run()
    except JobError:
        pass  # A fence acquired after the handoff must refuse publication.
    finally:
        for thread in threads:
            thread.join(10)
            assert not thread.is_alive(), "the SQL handoff must not self-deadlock"
    assert not errors and len(handoff) == 1 and len(wins_before_finalization) == 1
    assert store.get_job(row["job_id"])["run_id"] == handoff[0]["run_id"]
    if wins_before_finalization[0]:
        assert report.read_bytes() == before, "an empty bound_attempt check does not fence the later report write"


def test_report_write_blocks_a_competing_job_store_writer(monkeypatch, tmp_path):
    """At the real file publication point another SQL writer cannot re-arm."""
    project, service, store, row = helpers._start(monkeypatch, tmp_path)
    helpers._bind_env(monkeypatch, tmp_path, store, row)
    ScanSessionRunner(helpers._session_config(project), task_id="boundary/first").run()
    resumed = helpers._resume(service, store, row)
    helpers._bind_env(monkeypatch, tmp_path, store, resumed)
    original = session_module.write_report_atomic
    checked = []

    def check_actual_write(path, report, *args, **kwargs):
        connection = sqlite3.connect(store.db_path, timeout=0, isolation_level=None)
        locked = False
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                assert "locked" in str(exc).lower() or "busy" in str(exc).lower()
                locked = True
            else:
                connection.rollback()
        finally:
            connection.close()
        checked.append(locked)
        assert locked, "the SQL binding fence must cover the actual report publication"
        return original(path, report, *args, **kwargs)

    monkeypatch.setattr(session_module, "write_report_atomic", check_actual_write)
    ScanSessionRunner(helpers._session_config(project), task_id="boundary/write-fence").run()
    assert checked and all(checked)
