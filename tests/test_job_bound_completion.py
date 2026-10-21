"""Real SQLite/service resume receipts; these tests do not execute a scanner."""

from pathlib import Path
import threading

import pytest
from test_scan_jobs import make_project, start_job, store_for
from zscope.orchestration.jobs.models import JobError
from zscope.orchestration.jobs.service import ScanJobService
from zscope.orchestration.jobs import store as store_module


@pytest.fixture
def binding(tmp_path):
    project = make_project(tmp_path)
    service = ScanJobService(project / "zscope.yaml", spawn_owner=False)
    created = start_job(service, request_id="bound-completion-start")
    store = store_for(project)
    job = store.get_job(created["job_id"])
    return service, store, job


def payload(job):
    return {
        "checkpoint_sha256": "a" * 64,
        "checkpoint_path": str(Path(job["run_dir"]) / "instance-checkpoint.json"),
        "input_revision": job["input_revision"],
        "plan_fingerprint": "exact-plan-a",
    }


def publish(store, job, **kwargs):
    return store.append_bound_event(
        job["job_id"],
        run_id=job["run_id"],
        owner_token=job["owner_token"],
        expected_input_revision=job["input_revision"],
        kind="instance_checkpoint_persisted",
        message="controlled completion receipt",
        data=kwargs.get("data", payload(job)),
    )


def read(store, job, plan="exact-plan-a"):
    return store.trusted_completion(
        job["job_id"],
        run_id=job["run_id"],
        owner_token=job["owner_token"],
        input_revision=job["input_revision"],
        plan_fingerprint=plan,
    )


def update(store, job, **fields):
    current = store.get_job(job["job_id"])
    return store.update_job(job["job_id"], expected_revision=current["revision"], updates=fields)


def counts(store):
    with store._read() as connection:
        return tuple(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("events", "bound_event_receipts")
        )


def test_current_bound_receipt_and_exact_plan(binding):
    service, store, job = binding
    receipt = publish(store, job)
    saved = read(store, job)
    assert saved["seq"] == receipt["seq"] and saved["run_id"] == job["run_id"]
    assert saved["input_revision"] == job["input_revision"] and saved["data"] == payload(job)
    assert read(store, job, "different-plan") is None


@pytest.mark.parametrize(
    "drift,code",
    [
        ("owner", "owner_token_mismatch"),
        ("run", "run_superseded"),
        ("input", "input_revision_changed"),
        ("terminal", "job_terminal"),
        ("missing", "job_missing"),
    ],
)
def test_stale_publisher_writes_no_event_or_receipt(binding, drift, code):
    service, store, job = binding
    if drift == "owner":
        update(store, job, owner_token="new-owner")
    if drift == "run":
        update(store, job, run_id="new-run")
    if drift == "input":
        update(store, job, input_revision="new-input")
    if drift == "terminal":
        update(store, job, status="partial")
    if drift == "missing":
        job = dict(job, job_id="missing-job")
    before = counts(store)
    with pytest.raises(JobError) as error:
        publish(store, job)
    assert error.value.code == code
    assert counts(store) == before


def test_plain_log_and_handwritten_json_cannot_supply_a_bound_completion(binding):
    service, store, job = binding
    data = payload(job)
    Path(data["checkpoint_path"]).write_text('{"complete":true}')
    store.append_event(
        job["job_id"],
        run_id=job["run_id"],
        kind="instance_checkpoint_persisted",
        message="unbound log",
        data=data,
    )
    assert read(store, job) is None


def test_real_resume_can_read_prior_bound_run_only_for_same_input(binding):
    service, store, job = binding
    publish(store, job)
    terminal = update(store, job, status="partial")
    response = service.resume(
        job["job_id"], base_revision=terminal["revision"], request_id="bound-completion-resume"
    )
    assert response.status_code == 202, response.payload
    current = store.get_job(job["job_id"])
    assert current["run_id"] != job["run_id"] and current["input_revision"] == job["input_revision"]
    assert read(store, current)["run_id"] == job["run_id"]
    with pytest.raises(JobError) as error:
        read(store, job)
    assert error.value.code == "run_superseded"
    changed = update(store, current, input_revision="actual-new-input")
    assert read(store, changed) is None


@pytest.mark.parametrize("invalid", ["path", "symlink", "hash", "plan", "input"])
def test_invalid_checkpoint_coordinates_never_publish(binding, tmp_path, invalid):
    service, store, job = binding
    data = payload(job)
    if invalid == "path":
        data["checkpoint_path"] = str(tmp_path / "foreign.json")
    if invalid == "symlink":
        path = Path(job["run_dir"]) / "escape.json"
        path.symlink_to(tmp_path / "foreign.json")
        data["checkpoint_path"] = str(path)
    if invalid == "hash":
        data["checkpoint_sha256"] = "unknown"
    if invalid == "plan":
        data["plan_fingerprint"] = ""
    if invalid == "input":
        data["input_revision"] = "foreign-input"
    before = counts(store)
    with pytest.raises(JobError) as error:
        publish(store, job, data=data)
    assert error.value.code == "invalid_checkpoint_binding" and counts(store) == before


def test_corrupt_receipt_data_is_unknown_and_not_a_legacy_fallback(binding):
    service, store, job = binding
    saved = publish(store, job)
    with store._write() as connection:
        connection.execute(
            "UPDATE events SET data_json=? WHERE seq=?", ("broken-json", saved["seq"])
        )
    assert read(store, job) is None


def test_matching_input_and_plan_from_a_different_job_are_not_reused(binding):
    service, store, job = binding
    publish(store, job)
    update(store, job, status="partial")
    created = start_job(service, request_id="different-job-same-input")
    other = store.get_job(created["job_id"])
    assert other["job_id"] != job["job_id"]
    assert other["input_revision"] == job["input_revision"]
    assert read(store, other) is None


@pytest.mark.parametrize("unknown", ["input", "plan"])
def test_unknown_identity_is_not_a_wildcard(binding, unknown):
    service, store, job = binding
    publish(store, job)
    before = counts(store)
    with pytest.raises(JobError) as error:
        if unknown == "input":
            read(store, dict(job, input_revision=""))
        else:
            read(store, job, "")
    assert error.value.code == "invalid_checkpoint_binding" and counts(store) == before


def test_bound_phase_event_is_not_a_completion(binding):
    service, store, job = binding
    store.append_bound_event(
        job["job_id"],
        run_id=job["run_id"],
        owner_token=job["owner_token"],
        kind="analysis_started",
        message="not completion",
        data=payload(job),
        expected_input_revision=job["input_revision"],
    )
    assert read(store, job) is None


def test_schema_upgrade_does_not_promote_existing_log_entries(binding):
    service, store, job = binding
    store.append_event(
        job["job_id"],
        run_id=job["run_id"],
        kind="instance_checkpoint_persisted",
        message="legacy",
        data=payload(job),
    )
    with store._write() as connection:
        connection.execute("DROP TABLE bound_event_receipts")
    store.initialize()
    assert read(store, job) is None
    assert publish(store, job)["seq"]


def test_publication_and_run_handoff_are_serialized(binding, monkeypatch):
    service, store, job = binding
    entered, released, flipped, attempted = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    original = store_module.JobStore._checked_bound_job
    errors = []

    def paused(*args, **kwargs):
        current = original(*args, **kwargs)
        if threading.current_thread().name == "bound-publisher":
            entered.set()
            assert released.wait(10)
        return current

    monkeypatch.setattr(store_module.JobStore, "_checked_bound_job", paused)

    def publisher():
        try:
            publish(store, job)
        except BaseException as error:
            errors.append(error)

    def handoff():
        try:
            attempted.set()
            update(store, job, run_id="next-run", owner_token="next-owner")
            flipped.set()
        except BaseException as error:
            errors.append(error)

    first = threading.Thread(target=publisher, name="bound-publisher")
    first.start()
    assert entered.wait(10)
    second = threading.Thread(target=handoff)
    second.start()
    assert attempted.wait(10)
    assert not flipped.wait(0.1), "run handoff escaped the publication transaction"
    released.set()
    first.join(10)
    second.join(10)
    assert not first.is_alive() and not second.is_alive() and not errors
    assert flipped.is_set() and read(store, store.get_job(job["job_id"]))["run_id"] == job["run_id"]
