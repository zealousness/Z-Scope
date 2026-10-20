"""Real Store/Queue fences; codec payloads here are controlled empty collections."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from test_job_bound_completion import binding
from zscope.orchestration.candidate_envelope import (
    CANDIDATE_SCHEMA_VERSION,
    DECISION_CONTEXT_VERSION,
)
from zscope.orchestration.jobs import store as store_module
from zscope.orchestration.jobs.instance_results import (
    AnalysisCompletion,
    CurrentAttempt,
    ExpectedInstance,
    FrozenJSON,
    InstanceKey,
    InstanceResultPayload,
    PreparedInstanceResult,
    RecoveryAccepted,
    RecoveryIdentity,
    prepare_instance_result,
    verify_instance_result,
)
from zscope.orchestration.jobs.models import JobError
from zscope.orchestration.jobs.store import SettlementClaim
from zscope.orchestration.jobs.work_queue import WorkQueue


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


@pytest.fixture
def settled_context(binding):
    service, store, job = binding
    # This controlled Store/Queue test records the owner's real SQL attempt
    # without importing the independently tested full native ScanSession.
    from zscope.orchestration.jobs.models import utc_now_iso

    store.record_attempt(
        {
            "job_id": job["job_id"],
            "run_id": job["run_id"],
            "attempt_no": store.next_attempt_no(job["job_id"]),
            "status": "running",
            "input_revision": job["input_revision"],
            "started_at": utc_now_iso(),
        }
    )
    assert (
        store.attempt_for(job["job_id"], job["run_id"])["input_revision"] == job["input_revision"]
    )
    directory = Path(job["run_dir"])
    directory.mkdir(parents=True, exist_ok=True)
    current = CurrentAttempt(
        job["job_id"], job["run_id"], job["owner_token"], job["input_revision"], directory
    )
    digest = hashlib.sha256(b"controlled-store-queue-input").hexdigest()
    recovery = RecoveryIdentity(
        job_id=job["job_id"],
        input_revision=job["input_revision"],
        plan_fingerprint=digest,
        versions=(
            ("candidate_decision_context", DECISION_CONTEXT_VERSION),
            ("candidate_schema", CANDIDATE_SCHEMA_VERSION),
        ),
        registry_digest=digest,
        semantics_policy="builtin_current_manual_advisory_no_inferred.v1",
        semantics_digest=digest,
        dependency_digest=digest,
    )
    instance = InstanceKey("controlled-instance", "controlled-build", "c:@F@f", "unit.c")
    payload = InstanceResultPayload(
        schema="zscope.instance-result.v1",
        producer_run_id=job["run_id"],
        identity=recovery,
        instance=instance,
        instance_semantics_digest=digest,
        completion=AnalysisCompletion(
            "zscope.instance-analysis-completion.v1", "complete", True, True, 0, 0, 0, ()
        ),
        outcome_json=FrozenJSON(canonical({"diagnostic_gaps": []})),
        records=(),
    )
    prepared = prepare_instance_result(payload, producer_run_dir=directory)
    assert isinstance(prepared, PreparedInstanceResult), prepared
    queue = WorkQueue(
        directory / "controlled-work-queue.db",
        job_id=job["job_id"],
        input_revision=job["input_revision"],
        max_batches=1,
    )
    queue.enqueue(
        [
            {
                "kind": "instance_analysis",
                "scope_key": instance.identity,
                "build": instance.build_context_id,
                "payload": {},
            }
        ],
        batch_no=1,
    )
    raw = queue.claim_batch(1, now=1000.0)["claimed"][0]
    claim = SettlementClaim(
        raw["item_id"], raw["claim_token"], raw["kind"], raw["scope_key"], raw["build"]
    )
    return service, store, job, current, recovery, instance, prepared, queue, claim


def settle(context, **overrides):
    _service, store, _job, current, recovery, instance, prepared, queue, claim = context
    kwargs = dict(
        current=current,
        queue=queue,
        claim=claim,
        expected=recovery,
        instance=instance,
        semantics_digest=prepared.payload.instance_semantics_digest,
        mode="executed",
        prepared=prepared,
        restored_receipt=None,
        discoveries=(),
        input_current_guard=lambda: None,
        now=1001.0,
    )
    kwargs.update(overrides)
    return store.settle_instance_result(**kwargs)


def trusted(context, **overrides):
    _service, store, _job, current, recovery, instance, prepared, _queue, _claim = context
    kwargs = dict(
        current=current,
        expected=recovery,
        instances=(ExpectedInstance(instance, prepared.payload.instance_semantics_digest),),
    )
    kwargs.update(overrides)
    return store.trusted_instance_results(**kwargs)


def queue_status(queue, claim):
    with sqlite3.connect(str(queue.db_path)) as connection:
        return connection.execute(
            "SELECT status FROM items WHERE item_id=?", (claim.item_id,)
        ).fetchone()[0]


def test_artifact_without_bound_receipt_does_not_authorize_reuse(settled_context):
    assert settled_context[6].artifact_path.is_file()
    assert trusted(settled_context) == ()


def test_actual_settlement_commits_queue_and_joined_receipt(settled_context):
    ack = settle(settled_context)
    assert ack.committed is True and ack.mode == "executed"
    assert ack.receipt is not None
    assert queue_status(settled_context[7], settled_context[8]) == "completed"
    rows = trusted(settled_context)
    assert rows == (ack.receipt,)
    accepted = verify_instance_result(
        rows[0],
        expected=settled_context[4],
        instance=ExpectedInstance(
            settled_context[5], settled_context[6].payload.instance_semantics_digest
        ),
    )
    assert isinstance(accepted, RecoveryAccepted)
    assert accepted.payload == settled_context[6].payload
    assert settled_context[3].owner_token not in repr(settled_context[3])
    assert settled_context[8].claim_token not in repr(settled_context[8])
    assert (
        settled_context[3].owner_token.encode() not in settled_context[6].artifact_path.read_bytes()
    )


def test_unbound_event_of_same_kind_is_ignored(settled_context):
    _service, store, job, *_ = settled_context
    store.append_event(
        job["job_id"],
        run_id=job["run_id"],
        kind="instance_result_persisted",
        message="unbound diagnostic only",
        data={"instance": {"identity": "controlled-instance"}},
    )
    assert trusted(settled_context) == ()


def test_generic_bound_event_cannot_mint_instance_result_receipt(settled_context):
    _service, store, job, *_ = settled_context
    with pytest.raises(JobError, match="instance results require current queue settlement"):
        store.append_bound_event(
            job["job_id"],
            run_id=job["run_id"],
            owner_token=job["owner_token"],
            kind="instance_result_persisted",
            message="forged binding",
            data={},
        )
    assert trusted(settled_context) == ()


@pytest.mark.parametrize("field", ["owner_token", "run_id", "input_revision"])
def test_stale_attempt_rejects_without_queue_or_receipt_write(settled_context, field):
    wrong = replace(settled_context[3], **{field: "foreign-binding"})
    with pytest.raises(JobError):
        settle(settled_context, current=wrong)
    assert queue_status(settled_context[7], settled_context[8]) == "active"
    assert trusted(settled_context) == ()


def test_expired_reclaimed_token_rejects_old_result(settled_context):
    queue, old = settled_context[7:]
    newer = queue.claim_batch(1, now=1601.0)["claimed"][0]
    assert newer["claim_token"] != old.claim_token
    with pytest.raises(JobError):
        settle(settled_context, now=1602.0)
    assert queue_status(queue, old) == "active"
    assert trusted(settled_context) == ()


def test_capacity_deferral_does_not_publish_result_receipt(settled_context):
    child = {
        "kind": "instance_validation",
        "scope_key": "scan-validation",
        "build": None,
        "payload": {},
    }
    ack = settle(settled_context, discoveries=(child,))
    assert ack.committed is False
    assert ack.receipt is None
    assert json.loads(ack.queue_result_json)["discovery_blocked"] == "batch_limit"
    assert queue_status(settled_context[7], settled_context[8]) == "deferred"
    assert trusted(settled_context) == ()


def test_receipt_sql_failure_after_queue_commit_leaves_no_reuse(settled_context, monkeypatch):
    original = store_module._append_event_on

    def fail_on_receipt(connection, *args, **kwargs):
        if kwargs.get("kind") == "instance_result_persisted":
            raise sqlite3.OperationalError("controlled receipt write failure")
        return original(connection, *args, **kwargs)

    monkeypatch.setattr(store_module, "_append_event_on", fail_on_receipt)
    with pytest.raises(sqlite3.OperationalError, match="controlled receipt"):
        settle(settled_context)
    assert queue_status(settled_context[7], settled_context[8]) == "completed"
    assert trusted(settled_context) == ()


def test_current_input_guard_runs_before_queue_and_again_before_receipt(settled_context):
    calls = []

    def guard():
        calls.append(queue_status(settled_context[7], settled_context[8]))
        if len(calls) == 3:
            raise ValueError("controlled current-input revocation")

    with pytest.raises(ValueError, match="current-input revocation"):
        settle(settled_context, input_current_guard=guard)
    assert calls == ["active", "active", "completed"]
    assert trusted(settled_context) == ()


def test_tampered_artifact_is_rejected_before_queue_settlement(settled_context):
    prepared = settled_context[6]
    prepared.artifact_path.write_bytes(prepared.artifact_path.read_bytes() + b"\n")
    with pytest.raises(JobError, match="artifact verification failed"):
        settle(settled_context)
    assert queue_status(settled_context[7], settled_context[8]) == "active"
    assert trusted(settled_context) == ()


def test_reader_newest_malformed_bound_row_does_not_fallback_to_old(settled_context):
    ack = settle(settled_context)
    assert ack.receipt is not None and len(trusted(settled_context)) == 1
    _service, store, job, current, recovery, instance, *_ = settled_context
    with sqlite3.connect(str(store.db_path)) as connection:
        cursor = connection.execute(
            "INSERT INTO events(job_id,run_id,at,kind,message,data_json) VALUES (?,?,?,?,?,?)",
            (
                job["job_id"],
                job["run_id"],
                "controlled-at",
                "instance_result_persisted",
                "malformed newest row",
                json.dumps({"instance": {"identity": instance.identity}}),
            ),
        )
        connection.execute(
            "INSERT INTO bound_event_receipts(event_seq,job_id,run_id,run_dir,input_revision,plan_fingerprint) VALUES (?,?,?,?,?,?)",
            (
                cursor.lastrowid,
                job["job_id"],
                job["run_id"],
                str(current.run_dir),
                current.input_revision,
                recovery.plan_fingerprint,
            ),
        )
    assert trusted(settled_context) == ()


@pytest.mark.parametrize(
    "damage", ["missing_attempt", "run_mismatch", "missing_event", "wrong_kind"]
)
def test_newest_damaged_join_is_not_hidden_before_seen(settled_context, damage):
    ack = settle(settled_context)
    assert ack.receipt is not None and len(trusted(settled_context)) == 1
    _service, store, job, current, recovery, *_ = settled_context
    with sqlite3.connect(str(store.db_path)) as connection:
        data = json.loads(
            connection.execute(
                "SELECT data_json FROM events WHERE seq=?", (ack.receipt.event_seq,)
            ).fetchone()[0]
        )
        if damage == "missing_event":
            seq = connection.execute("SELECT MAX(seq)+100 FROM events").fetchone()[0]
            receipt_run = current.run_id
        else:
            event_run = (
                "orphan-producer"
                if damage in {"missing_attempt", "run_mismatch"}
                else current.run_id
            )
            receipt_run = event_run if damage == "missing_attempt" else current.run_id
            data["producer_run_id"] = event_run
            kind = (
                "instance_checkpoint_persisted"
                if damage == "wrong_kind"
                else "instance_result_persisted"
            )
            cursor = connection.execute(
                "INSERT INTO events(job_id,run_id,at,kind,message,data_json) VALUES (?,?,?,?,?,?)",
                (
                    current.job_id,
                    event_run,
                    "controlled-newer",
                    kind,
                    "damaged association",
                    json.dumps(data),
                ),
            )
            seq = cursor.lastrowid
        connection.execute(
            "INSERT INTO bound_event_receipts(event_seq,job_id,run_id,run_dir,input_revision,plan_fingerprint) VALUES (?,?,?,?,?,?)",
            (
                seq,
                current.job_id,
                receipt_run,
                str(current.run_dir),
                current.input_revision,
                recovery.plan_fingerprint,
            ),
        )
    assert trusted(settled_context) == ()


def test_later_ordinary_bound_checkpoint_does_not_shadow_instance_result(settled_context):
    ack = settle(settled_context)
    assert ack.receipt is not None
    _service, store, job, current, recovery, *_ = settled_context
    path = current.run_dir / "instance-checkpoint.json"
    path.write_bytes(b"{}\n")
    store.append_bound_event(
        current.job_id,
        run_id=current.run_id,
        owner_token=current.owner_token,
        expected_input_revision=current.input_revision,
        kind="instance_checkpoint_persisted",
        message="controlled independent checkpoint",
        data={
            "plan_fingerprint": recovery.plan_fingerprint,
            "checkpoint_path": str(path),
            "checkpoint_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "input_revision": current.input_revision,
        },
    )
    assert trusted(settled_context) == (ack.receipt,)


def resumed_context(context):
    """Create an actual second service attempt and its separate claimed queue."""
    receipt = settle(context).receipt
    assert receipt is not None
    service, store, job, _current, recovery, instance, prepared, _queue, _claim = context
    current_job = store.get_job(job["job_id"])
    terminal = store.update_job(
        job["job_id"], expected_revision=current_job["revision"], updates={"status": "partial"}
    )
    response = service.resume(
        job["job_id"], base_revision=terminal["revision"], request_id="controlled-instance-resume"
    )
    assert response.status_code == 202, response.payload
    next_job = store.get_job(job["job_id"])
    assert next_job["run_id"] != job["run_id"]
    assert next_job["input_revision"] == job["input_revision"]
    from zscope.orchestration.jobs.models import utc_now_iso

    store.record_attempt(
        {
            "job_id": next_job["job_id"],
            "run_id": next_job["run_id"],
            "attempt_no": store.next_attempt_no(next_job["job_id"]),
            "status": "running",
            "input_revision": next_job["input_revision"],
            "started_at": utc_now_iso(),
        }
    )
    directory = Path(next_job["run_dir"])
    directory.mkdir(parents=True, exist_ok=True)
    current = CurrentAttempt(
        next_job["job_id"],
        next_job["run_id"],
        next_job["owner_token"],
        next_job["input_revision"],
        directory,
    )
    queue = WorkQueue(
        directory / "controlled-work-queue.db",
        job_id=current.job_id,
        input_revision=current.input_revision,
    )
    queue.enqueue(
        [
            {
                "kind": "instance_analysis",
                "scope_key": instance.identity,
                "build": instance.build_context_id,
                "payload": {},
            }
        ],
        batch_no=1,
    )
    raw = queue.claim_batch(1, now=2000.0)["claimed"][0]
    claim = SettlementClaim(
        raw["item_id"], raw["claim_token"], raw["kind"], raw["scope_key"], raw["build"]
    )
    updated = service, store, next_job, current, recovery, instance, prepared, queue, claim
    assert trusted(updated) == (receipt,)
    return updated, receipt


def test_real_resumed_attempt_settles_prior_receipt_without_republishing(settled_context):
    context, receipt = resumed_context(settled_context)
    store = context[1]
    with sqlite3.connect(str(store.db_path)) as connection:
        before = connection.execute("SELECT COUNT(*) FROM bound_event_receipts").fetchone()[0]
    ack = settle(context, mode="restored", prepared=None, restored_receipt=receipt, now=2001.0)
    assert ack.committed is True and ack.mode == "restored" and ack.receipt == receipt
    assert ack.receipt.producer_run_id == settled_context[3].run_id
    assert ack.receipt.producer_run_id != context[3].run_id
    assert queue_status(context[7], context[8]) == "completed"
    with sqlite3.connect(str(store.db_path)) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM bound_event_receipts").fetchone()[0] == before
        )


@pytest.mark.parametrize("damage", ["receipt_deleted", "artifact_tampered", "event_kind_changed"])
def test_resumed_settlement_rechecks_prior_receipt_after_discovery(settled_context, damage):
    context, receipt = resumed_context(settled_context)
    if damage == "artifact_tampered":
        receipt.artifact_path.write_bytes(receipt.artifact_path.read_bytes() + b"\n")
    else:
        with sqlite3.connect(str(context[1].db_path)) as connection:
            if damage == "receipt_deleted":
                connection.execute(
                    "DELETE FROM bound_event_receipts WHERE event_seq=?", (receipt.event_seq,)
                )
            else:
                connection.execute(
                    "UPDATE events SET kind='foreign-kind' WHERE seq=?", (receipt.event_seq,)
                )
    with pytest.raises(
        JobError, match="restore receipt no longer current|artifact verification failed"
    ):
        settle(context, mode="restored", prepared=None, restored_receipt=receipt, now=2001.0)
    assert queue_status(context[7], context[8]) == "active"


@pytest.mark.parametrize("blocked", [False, True])
def test_scheduler_publishes_observer_only_after_real_committed_settlement(
    settled_context, blocked
):
    from zscope.orchestration.jobs.session_scheduler import SessionWorkScheduler, WorkComplete
    from zscope.orchestration.jobs.store import InstanceCompletionRequest

    _service, store, job, current, recovery, instance, prepared, queue, claim = settled_context
    acknowledgements = []

    def observed(ack):
        assert queue_status(queue, claim) == "completed"
        assert trusted(settled_context) == (ack.receipt,)
        # A separate Store write in the observer proves the settlement's SQL
        # transaction has ended before live P/R/E observers can publish.
        store.append_event(
            job["job_id"],
            run_id=job["run_id"],
            kind="controlled_observer",
            message="after commit",
            data={},
        )
        acknowledgements.append(ack)

    def handler(work):
        assert not hasattr(work, "claim_token")
        request = InstanceCompletionRequest(
            current,
            recovery,
            instance,
            prepared.payload.instance_semantics_digest,
            "executed",
            prepared,
            None,
            lambda: None,
            observed,
        )
        children = (
            (
                {
                    "kind": "instance_validation",
                    "scope_key": "scan-validation",
                    "build": None,
                    "payload": {},
                },
            )
            if blocked
            else ()
        )
        return WorkComplete(discoveries=children, instance_completion=request)

    scheduler = SessionWorkScheduler(
        store_path=store.db_path,
        job_id=current.job_id,
        run_id=current.run_id,
        owner_token=current.owner_token,
        run_dir=current.run_dir,
        work_queue_path=queue.db_path,
        max_batches=1,
        now_fn=lambda: 1601.0,
    )
    scheduler.register_handler("instance_analysis", handler)
    summary = scheduler.run()
    if blocked:
        assert acknowledgements == [] and trusted(settled_context) == ()
        assert summary["completed_this_run"] == 0
        assert queue_status(queue, claim) == "deferred"
    else:
        assert len(acknowledgements) == 1 and acknowledgements[0].committed
        assert summary["completed_this_run"] == 1
        assert summary["remaining_count"] == 0


def test_legal_long_usr_cannot_publish_a_truncated_sql_receipt(settled_context):
    context = settled_context
    instance = replace(context[5], usr="c:@F@" + "template_parameter_" * 300)
    assert len(instance.usr) > 4000
    payload = replace(context[6].payload, instance=instance)
    prepared = prepare_instance_result(payload, producer_run_dir=context[3].run_dir)
    assert isinstance(prepared, PreparedInstanceResult), prepared
    assert prepared.artifact_path.is_file()
    with pytest.raises(JobError, match="receipt.*bounds"):
        settle(context, instance=instance, prepared=prepared)
    assert queue_status(context[7], context[8]) == "active"
    assert (
        trusted(context, instances=(ExpectedInstance(instance, payload.instance_semantics_digest),))
        == ()
    )
