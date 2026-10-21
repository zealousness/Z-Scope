"""Cross-run ScanSession checkpoint recovery through the bound completion API.

The scanner, native index, instance plan, SQLite job service/store and the
Analyzer/Validator chain all execute for real; only the model boundary is left
unexercised.  A later run of the *same* job/input/exact plan may restore an
earlier run's durable completion, and nothing else may.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from test_scan_session_instances import _config, _instance_analysis, _read_report, _write_project
from test_scan_jobs import CONFIG_TEMPLATE, start_job, store_for
from zscope.orchestration import parallel_analyzer as parallel_module
from zscope.orchestration.jobs.service import ScanJobService
from zscope.orchestration.jobs.store import JobStore
from zscope.orchestration.scan_session import ScanSessionRunner
from zscope.rules.extensions import preflight_rules

RULE = "clang_cfg_same_object_released_twice"
JOB_ENV_STORE = "ZSCOPE_JOB_STORE"
JOB_ENV_ID = "ZSCOPE_JOB_ID"
JOB_ENV_RUN_ID = "ZSCOPE_JOB_RUN_ID"
JOB_ENV_OWNER = "ZSCOPE_JOB_OWNER_TOKEN"
JOB_ENV_RUN_DIR = "ZSCOPE_JOB_RUN_DIR"


def _native_project(tmp_path: Path) -> Path:
    """A real dual-variant project with sources under ``src`` (reports stay out)."""

    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    _write_project(tmp_path)  # unit.c with RELEASE(p) + two compile commands
    (tmp_path / "unit.c").rename(src / "unit.c")
    database = tmp_path / "compile_commands.json"
    rows = json.loads(database.read_text(encoding="utf-8"))
    for row in rows:
        old = row["file"]
        row["file"] = str(src / "unit.c")
        row["arguments"] = [row["file"] if arg == old else arg for arg in row["arguments"]]
    database.write_text(json.dumps(rows), encoding="utf-8")
    public = yaml.safe_load(CONFIG_TEMPLATE.replace("{root}", str(tmp_path)))
    public["project"].update(
        source_root="src",
        entry_function="f",
        entry_file_path="unit.c",
        compile_commands_path="compile_commands.json",
    )
    public["rules"] = {"enabled_ids": [RULE]}
    (tmp_path / "zscope.yaml").write_text(
        yaml.safe_dump(public, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    return tmp_path


def _session_config(tmp_path: Path):
    config = _config(tmp_path)
    config.project.project_root = tmp_path
    config.project.source_root = tmp_path / "src"
    config.project.include_paths = [str(tmp_path / "src")]
    config.project.entry_file_path = "unit.c"
    preflight_rules(config)
    return config


def _bind_env(monkeypatch, tmp_path: Path, store: JobStore, row: Dict[str, Any]) -> None:
    _record_controlled_attempt(store, row)
    monkeypatch.setenv(JOB_ENV_STORE, str(store.db_path))
    monkeypatch.setenv(JOB_ENV_ID, str(row["job_id"]))
    monkeypatch.setenv(JOB_ENV_RUN_ID, str(row["run_id"]))
    monkeypatch.setenv(JOB_ENV_OWNER, str(row["owner_token"]))
    monkeypatch.setenv(JOB_ENV_RUN_DIR, str(row["run_dir"]))


def _record_controlled_attempt(store: JobStore, row: Dict[str, Any]) -> None:
    """spawn_owner=False fixtures explicitly execute the owner's attempt write."""
    from zscope.orchestration.jobs.models import utc_now_iso

    attempt = store.attempt_for(row["job_id"], row["run_id"])
    if attempt is None:
        store.record_attempt(
            {
                "job_id": row["job_id"],
                "run_id": row["run_id"],
                "attempt_no": store.next_attempt_no(row["job_id"]),
                "status": "running",
                "input_revision": row["input_revision"],
                "started_at": utc_now_iso(),
            }
        )
    actual = store.attempt_for(row["job_id"], row["run_id"])
    assert actual is not None and actual["input_revision"] == row["input_revision"]
    assert actual["attempt_no"] > 0


def _start(monkeypatch, tmp_path: Path):
    project = _native_project(tmp_path)
    service = ScanJobService(project / "zscope.yaml", spawn_owner=False)
    created = start_job(service, request_id=f"checkpoint-start-{tmp_path.name}")
    store = store_for(project)
    row = store.get_job(created["job_id"])
    assert row is not None
    return project, service, store, row


def _count_executions(monkeypatch) -> List[List[str]]:
    """Record every real per-instance analysis this process actually performs."""

    calls: List[List[str]] = []
    original = parallel_module.ParallelAnalyzer.run_instance_batch

    def _spy(self: Any, batch: Any, identities: Any) -> Any:
        calls.append([str(value) for value in identities])
        return original(self, batch, identities)

    monkeypatch.setattr(parallel_module.ParallelAnalyzer, "run_instance_batch", _spy)
    return calls


def _resume(service: ScanJobService, store: JobStore, row: Dict[str, Any]) -> Dict[str, Any]:
    current = store.get_job(row["job_id"])
    assert current is not None
    store.update_job(
        row["job_id"], expected_revision=int(current["revision"]), updates={"status": "partial"}
    )
    marked = store.get_job(row["job_id"])
    assert marked is not None
    response = service.resume(
        row["job_id"],
        base_revision=int(marked["revision"]),
        request_id=f"checkpoint-resume-{row['run_id']}",
    )
    assert response.status_code == 202, response.payload
    resumed = store.get_job(row["job_id"])
    assert resumed is not None
    assert resumed["run_id"] != row["run_id"]
    return resumed


def test_same_input_new_run_reuses_the_persisted_completion(monkeypatch, tmp_path) -> None:
    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "real native tool required"
    project, service, store, row = _start(monkeypatch, tmp_path)
    calls = _count_executions(monkeypatch)

    _bind_env(monkeypatch, tmp_path, store, row)
    ScanSessionRunner(_session_config(project), task_id="job/first").run()
    assert sum(len(group) for group in calls) == 2, "the first run must analyze both instances"
    first_report = _read_report(project / "report.json")
    first_analysis = _instance_analysis(first_report)
    assert first_report["metadata"]["job"]["checkpointed"] is True
    assert sorted(item["candidate_count"] for item in first_analysis["instances"]) == [0, 1]

    resumed = _resume(service, store, row)
    assert resumed["input_revision"] == row["input_revision"]
    calls.clear()
    _bind_env(monkeypatch, tmp_path, store, resumed)
    ScanSessionRunner(_session_config(project), task_id="job/second").run()

    assert calls == [], "a same-input new run must not re-analyze a persisted completion"
    report = _read_report(project / "report.json")
    analysis = _instance_analysis(report)
    assert sorted(item["candidate_count"] for item in analysis["instances"]) == [0, 1]
    assert any(
        candidate["defect_class"] == "double_free"
        for item in analysis["instances"]
        for candidate in item["candidates"]
    )
    job = report["metadata"]["job"]
    assert job["restored_from_run_id"] == row["run_id"]
    assert job["cached_instances"] == 2
    assert job["executed_instances"] == 0


def test_real_header_edit_revokes_the_completion(monkeypatch, tmp_path) -> None:
    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "real native tool required"
    project, service, store, row = _start(monkeypatch, tmp_path)
    calls = _count_executions(monkeypatch)

    _bind_env(monkeypatch, tmp_path, store, row)
    ScanSessionRunner(_session_config(project), task_id="job/first").run()
    assert sum(len(group) for group in calls) == 2

    # A real source edit changes the manifest the next attempt binds to.
    (project / "src" / "unit.c").write_text(
        "#include <stdlib.h>\nvoid f(void) { char *p = malloc(4); if (!p) { return; } free(p); }\n",
        encoding="utf-8",
    )
    resumed = _resume(service, store, row)
    assert resumed["input_revision"] != row["input_revision"]
    calls.clear()
    _bind_env(monkeypatch, tmp_path, store, resumed)
    ScanSessionRunner(_session_config(project), task_id="job/second").run()

    assert sum(len(group) for group in calls) == 2, "a changed input must re-analyze"
    report = _read_report(project / "report.json")
    job = report["metadata"]["job"]
    assert job["restored_from_run_id"] is None
    assert job["cached_instances"] == 0


def test_handwritten_checkpoint_without_a_receipt_is_not_reused(monkeypatch, tmp_path) -> None:
    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "real native tool required"
    project, service, store, row = _start(monkeypatch, tmp_path)
    calls = _count_executions(monkeypatch)

    from zscope.orchestration.jobs.scan_work import CHECKPOINT_FILENAME, CHECKPOINT_SCHEMA

    # A hand-written JSON that self-declares this job/run/input and "complete".
    forged = {
        "schema": CHECKPOINT_SCHEMA,
        "job_id": row["job_id"],
        "run_id": row["run_id"],
        "input_revision": row["input_revision"],
        "plan_fingerprint": "forged",
        "instance_analysis": {"status": "analyzed", "instances": []},
        "report": {"completeness": "complete", "summary": {"total_issues": 0}, "metadata": {}},
    }
    target = Path(row["run_dir"]) / CHECKPOINT_FILENAME
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(forged), encoding="utf-8")

    _bind_env(monkeypatch, tmp_path, store, row)
    ScanSessionRunner(_session_config(project), task_id="job/first").run()

    assert sum(len(group) for group in calls) == 2, "an unbound JSON must not authorize a skip"
    report = _read_report(project / "report.json")
    assert report["metadata"]["job"]["restored_from_run_id"] is None


def test_tampered_checkpoint_bytes_are_not_reused(monkeypatch, tmp_path) -> None:
    from dataclasses import asdict
    import sqlite3

    from zscope.orchestration.jobs.instance_results import RecoveryAccepted, verify_instance_result

    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "real native tool required"
    project, service, store, row = _start(monkeypatch, tmp_path)
    calls = _count_executions(monkeypatch)
    trusted_reads, restores, validations, legacy_calls = [], [], [], []
    original_trusted = JobStore.trusted_instance_results
    original_restore = parallel_module.ParallelAnalyzer.restore_instance_result
    original_validate = parallel_module.ParallelAnalyzer.validate_instance_batch
    original_legacy = ScanSessionRunner._load_bound_completion

    def observe_trusted(self, *, current, expected, instances):
        receipts = original_trusted(self, current=current, expected=expected, instances=instances)
        trusted_reads.append((current, expected, instances, receipts))
        return receipts

    def observe_restore(self, batch, *, admitted):
        result = original_restore(self, batch, admitted=admitted)
        context = self._instance_semantics_context
        scope = context.scopes[admitted.payload.instance.identity]
        snapshot = context.require(scope)
        restores.append((self.run_id, admitted, scope, snapshot.digest, context.manifest_digest()))
        return result

    def observe_validate(self, batch):
        event = {
            "analyzer_run_id": self.run_id,
            "planned": {item.identity for item in batch.instances},
            "settled": set(batch.settled_instances),
            "executed": set(batch.executed_instances),
            "restored": set(batch.restored_instances),
            "before": batch.validation_state,
        }
        validations.append(event)
        result = original_validate(self, batch)
        event["after"] = batch.validation_state
        event["drained"] = self._global_validation_state.get("validation_queue_drained")
        return result

    def observe_legacy(self, *args, **kwargs):
        legacy_calls.append("_load_bound_completion")
        return original_legacy(self, *args, **kwargs)

    # Observe the real methods and preserve their returns and all admission guards.
    monkeypatch.setattr(JobStore, "trusted_instance_results", observe_trusted)
    monkeypatch.setattr(
        parallel_module.ParallelAnalyzer, "restore_instance_result", observe_restore
    )
    monkeypatch.setattr(
        parallel_module.ParallelAnalyzer, "validate_instance_batch", observe_validate
    )
    monkeypatch.setattr(ScanSessionRunner, "_load_bound_completion", observe_legacy)

    _bind_env(monkeypatch, tmp_path, store, row)
    ScanSessionRunner(_session_config(project), task_id="job/first").run()
    (producer_validation,) = validations
    planned = producer_validation["planned"]
    assert len(planned) == 2
    assert len([identity for group in calls for identity in group]) == 2
    assert {identity for group in calls for identity in group} == planned
    assert producer_validation["executed"] == producer_validation["settled"] == planned
    assert producer_validation["restored"] == set()
    assert restores == []
    assert producer_validation["before"] == "NOT_STARTED"
    assert producer_validation["after"] == "DONE" and producer_validation["drained"] is True

    producer_checkpoint = Path(row["run_dir"]) / "instance-checkpoint.json"
    assert producer_checkpoint.is_file()
    original_bytes = producer_checkpoint.read_bytes()
    tampered = json.loads(original_bytes)
    assert tampered["scan_coverage_complete"] is False
    tampered["scan_coverage_complete"] = True
    producer_checkpoint.write_text(json.dumps(tampered), encoding="utf-8")
    tampered_bytes = producer_checkpoint.read_bytes()
    assert tampered_bytes != original_bytes
    assert hashlib.sha256(tampered_bytes).digest() != hashlib.sha256(original_bytes).digest()

    resumed = _resume(service, store, row)
    assert resumed["input_revision"] == row["input_revision"]
    calls.clear()
    _bind_env(monkeypatch, tmp_path, store, resumed)
    ScanSessionRunner(_session_config(project), task_id="job/second").run()

    assert calls == [], "only independently admitted per-instance results may avoid execution"
    assert len(validations) == 2, "each attempt must run its own current validation exactly once"
    resumed_validation = validations[1]
    assert resumed_validation["analyzer_run_id"] != producer_validation["analyzer_run_id"]
    assert resumed_validation["planned"] == resumed_validation["settled"] == planned
    assert resumed_validation["restored"] == planned and resumed_validation["executed"] == set()
    assert resumed_validation["before"] == "NOT_STARTED"
    assert resumed_validation["after"] == "DONE" and resumed_validation["drained"] is True
    assert legacy_calls == [], "the tampered whole checkpoint must not become restore authority"
    assert producer_checkpoint.read_bytes() == tampered_bytes

    assert len(restores) == 2
    assert {admitted.payload.instance.identity for _, admitted, _, _, _ in restores} == planned
    assert len({admitted.receipt.event_seq for _, admitted, _, _, _ in restores}) == 2
    producer_attempt = store.attempt_for(row["job_id"], row["run_id"])
    resumed_attempt = store.attempt_for(row["job_id"], resumed["run_id"])
    assert producer_attempt is not None and resumed_attempt is not None
    assert 0 < producer_attempt["attempt_no"] < resumed_attempt["attempt_no"]
    with sqlite3.connect(store.db_path.as_uri() + "?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        for analyzer_run_id, admitted, scope, scope_digest, manifest_digest in restores:
            receipt = admitted.receipt
            assert analyzer_run_id == resumed_validation["analyzer_run_id"]
            assert receipt.instance == admitted.payload.instance
            assert (receipt.instance.identity, receipt.instance.build_context_id) == (
                scope.identity,
                scope.build_context_id,
            )
            assert (receipt.instance.usr, receipt.instance.source) == (scope.usr, scope.source)
            assert receipt.instance_semantics_digest == scope_digest
            assert admitted.payload.instance_semantics_digest == scope_digest
            assert receipt.identity.semantics_digest == manifest_digest
            matching_reads = [
                (current, expected, targets)
                for current, expected, targets, receipts in trusted_reads
                if current.run_id == resumed["run_id"] and receipt in receipts
            ]
            assert matching_reads, "a real bound SQL lookup must precede each actual restore"
            current, expected, targets = matching_reads[0]
            assert current.job_id == row["job_id"]
            assert current.input_revision == resumed["input_revision"]
            assert current.run_dir.resolve() == Path(resumed["run_dir"]).resolve()
            (target,) = targets
            assert target.key == receipt.instance and target.semantics_digest == scope_digest
            assert expected == receipt.identity == admitted.payload.identity
            verified = verify_instance_result(receipt, expected=expected, instance=target)
            assert isinstance(verified, RecoveryAccepted) and verified.payload == admitted.payload
            raw = receipt.artifact_path.read_bytes()
            assert len(raw) == receipt.byte_count > 0
            assert hashlib.sha256(raw).hexdigest() == receipt.content_sha256
            assert receipt.producer_run_id == row["run_id"] != resumed["run_id"]
            assert receipt.producer_attempt_no == producer_attempt["attempt_no"]
            assert receipt.producer_run_dir == Path(row["run_dir"]).resolve()
            assert receipt.artifact_path.parent == receipt.producer_run_dir / "instance-results"
            bound = connection.execute(
                "SELECT e.kind,e.job_id,e.run_id,e.data_json,r.job_id AS receipt_job_id,"
                "r.run_id AS receipt_run_id,r.run_dir,r.input_revision,r.plan_fingerprint,"
                "a.attempt_no,a.input_revision AS attempt_input_revision "
                "FROM events e JOIN bound_event_receipts r ON r.event_seq=e.seq "
                "JOIN attempts a ON a.job_id=r.job_id AND a.run_id=r.run_id WHERE e.seq=?",
                (receipt.event_seq,),
            ).fetchall()
            assert len(bound) == 1
            sql_row = bound[0]
            assert sql_row["kind"] == "instance_result_persisted"
            assert sql_row["job_id"] == sql_row["receipt_job_id"] == current.job_id
            assert sql_row["run_id"] == sql_row["receipt_run_id"] == receipt.producer_run_id
            assert Path(sql_row["run_dir"]).resolve() == receipt.producer_run_dir
            assert sql_row["attempt_no"] == receipt.producer_attempt_no
            assert (
                sql_row["input_revision"]
                == sql_row["attempt_input_revision"]
                == expected.input_revision
            )
            assert sql_row["plan_fingerprint"] == expected.plan_fingerprint
            data = json.loads(sql_row["data_json"])
            assert data["identity"] == json.loads(json.dumps(asdict(expected)))
            assert data["instance"] == asdict(target.key)
            assert data["producer_run_id"] == receipt.producer_run_id
            assert data["producer_attempt_no"] == receipt.producer_attempt_no
            assert data["instance_semantics_digest"] == scope_digest
            assert data["artifact_path"] == str(receipt.artifact_path)
            assert data["content_sha256"] == receipt.content_sha256
            assert data["byte_count"] == receipt.byte_count

    report = _read_report(project / "report.json")
    job = report["metadata"]["job"]
    recovery = job["instance_recovery"]
    assert job["run_id"] == resumed["run_id"]
    assert job["restored_from_run_id"] == row["run_id"]
    assert job["cached_instances"] == job["analyzed_instances"] == 2
    assert job["executed_instances"] == 0
    assert recovery["planned_instances"] == 2
    assert set(recovery["restored_identities"]) == set(recovery["analyzed_identities"]) == planned
    assert recovery["executed_identities"] == []
    assert recovery["current_validation_state"] == "DONE"
    assert job["checkpointed"] is True and job["remaining_count"] == 0
    assert job["counts"]["pending"] == job["counts"]["active"] == job["counts"]["deferred"] == 0
    assert job["counts"]["failed"] == 0
    assert _instance_analysis(report)["scan_coverage_complete"] is False


def test_settled_queue_item_alone_never_authorizes_reuse(monkeypatch, tmp_path) -> None:
    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "real native tool required"
    project, service, store, row = _start(monkeypatch, tmp_path)
    calls = _count_executions(monkeypatch)

    # A leftover queue for this run that already claims both instances done:
    # settled queue history must never stand in for a bound completion.
    from zscope.orchestration.jobs.work_queue import WorkQueue
    from zscope.orchestration.entry_instances import plan_entry_instances
    from zscope.config.function_entry import FunctionEntry
    from zscope.retrieval.code_index import CodeIndex

    run_dir = Path(row["run_dir"])
    run_dir.mkdir(parents=True, exist_ok=True)
    queue = WorkQueue(
        run_dir / "work-queue.db", job_id=row["job_id"], input_revision=row["input_revision"]
    )
    index = CodeIndex(
        project,
        project / "compile_commands.json",
        source_root=project / "src",
        indexing_config=_session_config(project).indexing,
        include_paths=[project / "src"],
    )
    try:
        plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    finally:
        index.close()
    queue.enqueue(
        [
            {
                "kind": "instance_analysis",
                "scope_key": instance.identity,
                "build": instance.build_context_id,
            }
            for instance in plan.instances
        ],
        batch_no=1,
    )
    for claimed in queue.claim_batch(2)["claimed"]:
        queue.complete(int(claimed["item_id"]), claim_token=str(claimed["claim_token"]))
    assert queue.snapshot()["counts"]["completed"] == 2

    _bind_env(monkeypatch, tmp_path, store, row)
    ScanSessionRunner(_session_config(project), task_id="job/first").run()

    assert sum(len(group) for group in calls) == 2, "queue history must not authorize a skip"
    report = _read_report(project / "report.json")
    assert report["metadata"]["job"]["restored_from_run_id"] is None


# ---------------------------------------------------------------------------
# business-answer dependency verification (synthetic plan, real SQLite state)


def _synthetic_plan_config(tmp_path: Path, state_dir: Path):
    from types import SimpleNamespace

    return SimpleNamespace(
        analysis=SimpleNamespace(user_config_db=str(state_dir)),
        project=SimpleNamespace(
            user_config_file=None,
            project_root=tmp_path,
            source_root=tmp_path,
            language="c_cpp",
        ),
        rules=SimpleNamespace(enabled_ids=[], disabled_ids=[]),
    )


def _synthetic_plan():
    from types import SimpleNamespace

    return SimpleNamespace(
        instances=[
            SimpleNamespace(
                identity="synthetic-instance",
                build_context_id="synthetic-build",
                usr="synthetic-usr",
                source="unit.c",
                function_names=("f",),
            )
        ]
    )


def _record_answer(db_path: Path, subject: str = "owner-of-pool") -> None:
    """Insert one real answer row through the store's actual schema."""

    import sqlite3 as _sqlite3

    with _sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "INSERT INTO protocol_assumption_answers "
            "(subject_key, revision, subject_json, answer, source_note, origin) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (subject, 1, "{}", "yes", "unit test", "user"),
        )


def _synthetic_semantics(plan):
    """Explicit manifest for pure fingerprint tests; confers no factory authority."""
    from zscope.retrieval.instance_index import instance_scope_from_entry_instance
    from zscope.semantics.instance_semantics import (
        FrozenJSON,
        InstanceSemanticsSnapshot,
        SemanticsDependencies,
    )

    digest = hashlib.sha256(b"synthetic-fingerprint-fixture-only").hexdigest()
    dependencies = SemanticsDependencies("synthetic", "synthetic", digest, digest, digest)
    return {
        item.identity: InstanceSemanticsSnapshot(
            schema="zscope.instance-semantics.v1",
            authority_policy="builtin_current_manual_advisory_no_inferred.v1",
            scope=instance_scope_from_entry_instance(item),
            dependencies=dependencies,
            workbook_sha256=digest,
            effect_payload=FrozenJSON(b"{}"),
            advisory_payload=FrozenJSON(b"{}"),
            excluded_rows=(),
            digest=digest,
        )
        for item in plan.instances
    }


def test_corrupt_answer_database_is_a_miss_not_verified_empty(tmp_path) -> None:
    from zscope.config.user_config_store import UserConfigStore
    from zscope.orchestration.jobs.scan_work import compute_plan_fingerprint

    state_dir = tmp_path / "state"
    store = UserConfigStore(state_dir)
    config = _synthetic_plan_config(tmp_path, state_dir)
    plan = _synthetic_plan()
    assert (
        compute_plan_fingerprint(plan, config, semantics_by_instance=_synthetic_semantics(plan))
        is not None
    )

    store.db_path.write_bytes(b"this is not a SQLite database\n")
    assert (
        compute_plan_fingerprint(plan, config, semantics_by_instance=_synthetic_semantics(plan))
        is None
    )
    # The read-only lookup never repairs or rewrites the broken store.
    assert store.db_path.read_bytes() == b"this is not a SQLite database\n"


def test_unreadable_answer_schema_is_a_miss_not_verified_empty(tmp_path) -> None:
    import sqlite3

    from zscope.config.user_config_store import UserConfigStore
    from zscope.orchestration.jobs.scan_work import compute_plan_fingerprint

    state_dir = tmp_path / "state"
    store = UserConfigStore(state_dir)
    config = _synthetic_plan_config(tmp_path, state_dir)
    plan = _synthetic_plan()
    assert (
        compute_plan_fingerprint(plan, config, semantics_by_instance=_synthetic_semantics(plan))
        is not None
    )

    with sqlite3.connect(str(store.db_path)) as connection:
        connection.execute("ALTER TABLE protocol_assumption_answers DROP COLUMN origin")
    assert (
        compute_plan_fingerprint(plan, config, semantics_by_instance=_synthetic_semantics(plan))
        is None
    )


def test_missing_store_and_verified_empty_table_are_valid_empty_answers(tmp_path) -> None:
    from zscope.config.user_config_store import UserConfigStore
    from zscope.orchestration.jobs.scan_work import compute_plan_fingerprint

    # A first run with no recorded store yet is legitimately empty.
    empty_state = tmp_path / "empty-state"
    config = _synthetic_plan_config(tmp_path, empty_state)
    plan = _synthetic_plan()
    without_store = compute_plan_fingerprint(
        plan, config, semantics_by_instance=_synthetic_semantics(plan)
    )

    # A real store whose answer table is verified empty digests the same.
    store = UserConfigStore(tmp_path / "state")
    config_present = _synthetic_plan_config(tmp_path, tmp_path / "state")
    with_store = compute_plan_fingerprint(
        plan, config_present, semantics_by_instance=_synthetic_semantics(plan)
    )

    assert without_store is not None and with_store is not None
    assert without_store == with_store
    assert store.db_path.is_file(), "the read-only lookup must not create the store"


def test_readonly_digest_preserves_special_path_characters(tmp_path) -> None:
    from zscope.config.user_config_store import UserConfigStore
    from zscope.orchestration.jobs.scan_work import compute_plan_fingerprint

    for name in ("state#fragment", "state?query", "state name"):
        state_dir = tmp_path / name
        store = UserConfigStore(state_dir)
        config = _synthetic_plan_config(tmp_path, state_dir)
        plan = _synthetic_plan()
        empty = compute_plan_fingerprint(
            plan, config, semantics_by_instance=_synthetic_semantics(plan)
        )
        assert empty is not None

        # Reading the real store changes the fingerprint: the digest read
        # the exact file, not a URI-truncated neighbour.
        _record_answer(store.db_path)
        with_answer = compute_plan_fingerprint(
            plan, config, semantics_by_instance=_synthetic_semantics(plan)
        )
        assert with_answer is not None and with_answer != empty

        # No truncated "state" database was created beside the store.
        assert not (tmp_path / "state").exists(), name
        assert not (tmp_path / "state?query.db").exists(), name


def test_analyzer_baseline_writes_do_not_change_the_answer_digest(tmp_path) -> None:
    import sqlite3

    from zscope.config.user_config_store import UserConfigStore
    from zscope.orchestration.jobs.scan_work import compute_plan_fingerprint

    state_dir = tmp_path / "state"
    store = UserConfigStore(state_dir)
    config = _synthetic_plan_config(tmp_path, state_dir)
    plan = _synthetic_plan()
    before = compute_plan_fingerprint(
        plan, config, semantics_by_instance=_synthetic_semantics(plan)
    )
    assert before is not None

    # The analyzer writes baselines on every scan; they are not user answers
    # and must not invalidate the checkpoint dependency.
    with sqlite3.connect(str(store.db_path)) as connection:
        connection.execute(
            "INSERT INTO finding_baselines (dedup_key, stable_fingerprint, status, issue_json) "
            "VALUES ('dk-1', 'fp-1', 'accepted', '{}')"
        )
    after = compute_plan_fingerprint(plan, config, semantics_by_instance=_synthetic_semantics(plan))
    assert after == before
