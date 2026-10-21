"""Module-level positive/negative tests for the S08 instance-result codec.

These are the S08 worker-unit cases of the frozen R23 acceptance matrix:
artifact encoding/publication/immutability, trusted-receipt byte/schema/
identity/completeness verification, strict record projection validation,
membership-manifest integrity and serialized-authority contamination.  The
store/queue/ledger/scheduler integration rows (S08-P01..P05 reader joins, R/E
accounting, crash fencing, real consumers) stay with the coordinator and are
NOT claimed here.
"""

import ast
import dataclasses
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from zscope.orchestration.jobs.instance_results import (
    ARTIFACT_DIR_NAME,
    COMPLETION_SCHEMA,
    INSTANCE_RESULT_EVENT_KIND,
    INSTANCE_RESULT_SCHEMA,
    PENDING_RECORD_SCHEMA,
    RECOVERY_POLICY_VERSION,
    AnalysisCompletion,
    CurrentAttempt,
    ExpectedInstance,
    FrozenJSON,
    InstanceKey,
    InstanceResultPayload,
    PendingCandidate,
    PreparedInstanceResult,
    RecoveryAccepted,
    RecoveryIdentity,
    TrustedInstanceResultReceipt,
    prepare_instance_result,
    verify_instance_result,
)
import zscope.orchestration.jobs.instance_results as instance_results_module


def canon(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def make_instance(identity="inst-a", build="build-1", usr="c:@F@main", source="src/main.c"):
    return InstanceKey(identity=identity, build_context_id=build, usr=usr, source=source)


def make_identity(**overrides):
    fields = dict(
        job_id="job-1",
        input_revision="rev-7",
        plan_fingerprint="plan-fp-9",
        versions=(
            ("entry_instances", "zscope.entry-instances.v1"),
            ("candidate_schema", "zscope.candidate.v3.5"),
        ),
        registry_digest="reg-digest-1",
        semantics_policy="builtin_current_manual_advisory_no_inferred.v1",
        semantics_digest="sem-manifest-1",
        dependency_digest="dep-digest-1",
    )
    fields.update(overrides)
    return RecoveryIdentity(**fields)


def make_completion(
    *,
    state="complete",
    collection_closed=True,
    input_current=True,
    expected_record_count=1,
    expected_obligation_count=1,
    expected_occurrence_count=2,
    active_stage_errors=(),
):
    return AnalysisCompletion(
        schema=COMPLETION_SCHEMA,
        state=state,
        collection_closed=collection_closed,
        input_current=input_current,
        expected_record_count=expected_record_count,
        expected_obligation_count=expected_obligation_count,
        expected_occurrence_count=expected_occurrence_count,
        active_stage_errors=tuple(active_stage_errors),
    )


def make_record_json(
    *,
    candidate_uid="CAND_alpha",
    obligation_uid="OBL_alpha",
    validation_cluster_uid="VAL_alpha",
    build="build-1",
    status="queued",
    record_role="validation_obligation",
    occurrence_uids=("OCC_1", "OCC_2"),
    entries=("entry_a",),
    ticket_evidence_extra=None,
):
    evidence = {"candidate_payload": {"candidate_disposition": "needs_review"}}
    if ticket_evidence_extra:
        evidence.update(ticket_evidence_extra)
    projection = {
        "build_context_id": build,
        "call_paths": [["entry_a", "helper_b", "sink_c"]],
        "candidate_id": "C-1",
        "candidate_schema_version": "zscope.candidate.v3.5",
        "candidate_uid": candidate_uid,
        "canonical_sink": "sink_c",
        "canonical_source": "source_a",
        "context_signature": "ctxsig-alpha",
        "decision_context_version": "zscope.decision-context.v3.3",
        "decision_evidence_hash": "deh-alpha",
        "dedup_key": "dd-alpha",
        "defect_class": "resource_lifecycle",
        "entries": list(entries),
        "entry_paths": [["entry_a", "helper_b", "sink_c"]],
        "evidence_hash": "eh-alpha",
        "evidence_hashes": ["eh-alpha"],
        "history_key": "HIST-alpha",
        "occurrence_uids": list(occurrence_uids),
        "occurrences": [
            {
                "call_paths": [["entry_a", "helper_b"]],
                "context_signature": "ctxsig-alpha",
                "entry_identity": "entry_a",
                "occurrence_uid": uid,
            }
            for uid in occurrence_uids
        ],
        "obligation_uid": obligation_uid,
        "provenance_hashes": ["ph-1"],
        "record_role": record_role,
        "root_cause_key": "rc-alpha",
        "sources": ["clang_ast_cfg"],
        "status": status,
        "ticket": {
            "id": "C-1",
            "skill": "resource_lifecycle",
            "task": "Validate candidate",
            "trigger": "malloc",
            "line": 12,
            "context_slice": "void f(void){ char *p = malloc(4); }",
            "priority_score": 50,
            "priority_reasons": ["clang_ast_cfg"],
            "origin": "source_a",
            "sink": "sink_c",
            "resource_kind": "heap",
            "source": "clang_ast_cfg",
            "sources": ["clang_ast_cfg"],
            "call_paths": [["entry_a", "helper_b", "sink_c"]],
            "dedup_key": "dd-alpha",
            "evidence": evidence,
        },
        "validation_cluster_uid": validation_cluster_uid,
        "validation_contexts": ["ctxsig-alpha"],
    }
    return canon(projection)


def make_record(
    instance,
    *,
    owners=None,
    candidate_uid="CAND_alpha",
    obligation_uid="OBL_alpha",
    cluster="VAL_alpha",
    status="queued",
    role="validation_obligation",
    record_json_bytes=None,
    build=None,
    occurrence_uids=None,
):
    build = build or instance.build_context_id
    json_kwargs = dict(
        candidate_uid=candidate_uid,
        obligation_uid=obligation_uid,
        validation_cluster_uid=cluster,
        build=build,
        status=status,
        record_role=role,
    )
    if occurrence_uids is not None:
        json_kwargs["occurrence_uids"] = tuple(occurrence_uids)
    return PendingCandidate(
        schema=PENDING_RECORD_SCHEMA,
        candidate_uid=candidate_uid,
        obligation_uid=obligation_uid,
        validation_cluster_uid=cluster,
        build_context_id=build,
        owner_instances=tuple(owners) if owners is not None else (instance,),
        status=status,
        record_role=role,
        record_json=FrozenJSON(
            record_json_bytes if record_json_bytes is not None else make_record_json(**json_kwargs)
        ),
    )


def make_payload(
    instance,
    *,
    records,
    identity=None,
    producer_run_id="run-42",
    semantics_digest="sem-digest-a",
    completion=None,
    outcome=None,
):
    if completion is None:
        occurrence_total = 0
        for record in records:
            projection = json.loads(record.record_json)
            occurrence_total += len(projection["occurrence_uids"])
        completion = make_completion(
            expected_record_count=len(records),
            expected_obligation_count=len({record.obligation_uid for record in records}),
            expected_occurrence_count=occurrence_total,
        )
    return InstanceResultPayload(
        schema=INSTANCE_RESULT_SCHEMA,
        producer_run_id=producer_run_id,
        identity=identity or make_identity(),
        instance=instance,
        instance_semantics_digest=semantics_digest,
        completion=completion,
        outcome_json=FrozenJSON(
            outcome
            if outcome is not None
            else canon({"diagnostic_gaps": ["gap:helper_b_unresolved"], "verdict": "analyzed"})
        ),
        records=tuple(records),
    )


def make_receipt(
    prepared,
    *,
    kind=INSTANCE_RESULT_EVENT_KIND,
    event_seq=11,
    attempt_no=2,
    producer_run_id="run-42",
    run_dir=None,
    identity=None,
    instance=None,
    semantics_digest="sem-digest-a",
    artifact_path=None,
    content_sha256=None,
    byte_count=None,
):
    return TrustedInstanceResultReceipt(
        event_seq=event_seq,
        kind=kind,
        producer_run_id=producer_run_id,
        producer_run_dir=run_dir if run_dir is not None else prepared.artifact_path.parents[1],
        producer_attempt_no=attempt_no,
        identity=identity or prepared.payload.identity,
        instance=instance or prepared.payload.instance,
        instance_semantics_digest=semantics_digest,
        artifact_path=artifact_path or prepared.artifact_path,
        content_sha256=content_sha256 or prepared.content_sha256,
        byte_count=byte_count if byte_count is not None else prepared.byte_count,
    )


class Scenario:
    """One published valid artifact plus the objects to verify it."""

    def __init__(self, tmp_path):
        self.run_dir = tmp_path / "runs" / "job-1" / "run-42"
        self.instance = make_instance()
        self.other_owner = make_instance(
            identity="inst-b", build="build-1", usr="c:@F@other", source="src/other.c"
        )
        self.records = (
            make_record(
                self.instance,
                owners=(self.instance, self.other_owner),
                occurrence_uids=("OCC_1", "OCC_2"),
            ),
        )
        self.payload = make_payload(self.instance, records=self.records)
        prepared = prepare_instance_result(self.payload, producer_run_dir=self.run_dir)
        assert isinstance(prepared, PreparedInstanceResult)
        self.prepared = prepared
        self.expected_identity = self.payload.identity
        self.expected_instance = ExpectedInstance(
            key=self.instance, semantics_digest="sem-digest-a"
        )


@pytest.fixture
def scenario(tmp_path):
    return Scenario(tmp_path)


def verify(scenario, **receipt_overrides):
    receipt = make_receipt(scenario.prepared, **receipt_overrides)
    return verify_instance_result(
        receipt,
        expected=scenario.expected_identity,
        instance=scenario.expected_instance,
    )


def publish_raw(scenario, raw):
    """Write crafted bytes under a filename consistent with their own digest."""

    content_sha = hashlib.sha256(raw).hexdigest()
    name = (
        f"{hashlib.sha256(scenario.instance.identity.encode('utf-8')).hexdigest()}"
        f".{content_sha}.json"
    )
    path = scenario.run_dir / ARTIFACT_DIR_NAME / name
    path.write_bytes(raw)
    return make_receipt(
        scenario.prepared,
        artifact_path=path,
        content_sha256=content_sha,
        byte_count=len(raw),
    )


def load_document(prepared):
    return json.loads(prepared.artifact_path.read_bytes().decode("utf-8"))


def publish_document(run_dir, document, *, instance_identity, artifacts_dir=None):
    """Write a crafted canonical document under a filename-consistent name."""

    raw = canon(document)
    content_sha = hashlib.sha256(raw).hexdigest()
    name = f"{hashlib.sha256(instance_identity.encode('utf-8')).hexdigest()}" f".{content_sha}.json"
    directory = artifacts_dir or (run_dir / ARTIFACT_DIR_NAME)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(raw)
    return path, content_sha, len(raw)


def craft_receipt(scenario, document, *, run_dir=None, artifacts_dir=None):
    """Publish a mutated document and build a receipt that matches its bytes."""

    path, content_sha, byte_count = publish_document(
        run_dir or scenario.run_dir,
        document,
        instance_identity=scenario.instance.identity,
        artifacts_dir=artifacts_dir,
    )
    return make_receipt(
        scenario.prepared,
        run_dir=run_dir or scenario.run_dir,
        artifact_path=path,
        content_sha256=content_sha,
        byte_count=byte_count,
    )


# ---------------------------------------------------------------------------
# prepare: encoding, atomic immutable publication (matrix S08-P01/P04 encode)
# ---------------------------------------------------------------------------


def test_prepare_publishes_canonical_artifact_with_hashed_basename(scenario):
    prepared = scenario.prepared
    identity_hash = hashlib.sha256(scenario.instance.identity.encode("utf-8")).hexdigest()
    expected_path = (
        scenario.run_dir / ARTIFACT_DIR_NAME / f"{identity_hash}.{prepared.content_sha256}.json"
    )
    assert prepared.artifact_path == expected_path
    raw = expected_path.read_bytes()
    assert len(raw) == prepared.byte_count
    assert hashlib.sha256(raw).hexdigest() == prepared.content_sha256
    document = json.loads(raw.decode("utf-8"))
    assert document["schema"] == INSTANCE_RESULT_SCHEMA
    assert document["recovery_policy"] == RECOVERY_POLICY_VERSION
    assert document["producer_run_id"] == "run-42"
    assert canon(document) == raw  # canonical bytes: no whitespace variants
    assert prepared.payload == scenario.payload
    # No stray temp files remain next to the artifact.
    assert [
        entry.name
        for entry in (scenario.run_dir / ARTIFACT_DIR_NAME).iterdir()
        if entry.name.startswith(".")
    ] == []


def test_prepare_is_idempotent_for_identical_content(scenario):
    again = prepare_instance_result(scenario.payload, producer_run_dir=scenario.run_dir)
    assert isinstance(again, PreparedInstanceResult)
    assert again.artifact_path == scenario.prepared.artifact_path
    assert again.content_sha256 == scenario.prepared.content_sha256
    assert again.byte_count == scenario.prepared.byte_count


def test_prepare_refuses_to_overwrite_different_existing_bytes(scenario, tmp_path):
    target = scenario.prepared.artifact_path
    tampered = b'{"schema":"not-the-same-content"}'
    target.write_bytes(tampered)
    result = prepare_instance_result(scenario.payload, producer_run_dir=scenario.run_dir)
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "refusing to overwrite" in result.reason
    assert target.read_bytes() == tampered  # immutable: no overwrite happened


def test_prepare_rejects_ineligible_completions_before_writing(tmp_path):
    instance = make_instance()
    base = dict(
        expected_record_count=1,
        expected_obligation_count=1,
        expected_occurrence_count=2,
    )
    variants = {
        "error": make_completion(state="error", **base),
        "cancelled": make_completion(state="cancelled", **base),
        "deferred": make_completion(state="deferred", **base),
        "incomplete": make_completion(state="incomplete", **base),
        "unknown": make_completion(state="unknown", **base),
        "open-collection": make_completion(collection_closed=False, **base),
        "stale-input": make_completion(input_current=False, **base),
        "stage-error": make_completion(active_stage_errors=("engine failed",), **base),
    }
    for name, completion in variants.items():
        payload = make_payload(
            instance,
            records=(make_record(instance),),
            completion=completion,
        )
        run_dir = tmp_path / "runs" / name
        result = prepare_instance_result(payload, producer_run_dir=run_dir)
        assert isinstance(result, instance_results_module.RecoveryMiss), name
        assert "re-analy" in result.reason, name
        assert not (run_dir / ARTIFACT_DIR_NAME).exists(), name


def test_prepare_rejects_relative_or_escaping_run_dirs(tmp_path):
    instance = make_instance()
    payload = make_payload(instance, records=(make_record(instance),))
    assert isinstance(
        prepare_instance_result(payload, producer_run_dir=Path("runs/relative")),
        instance_results_module.RecoveryMiss,
    )
    assert isinstance(
        prepare_instance_result(payload, producer_run_dir=tmp_path / ".." / "escape"),
        instance_results_module.RecoveryMiss,
    )


def test_prepare_rejects_noncanonical_embedded_json(tmp_path):
    instance = make_instance()
    spaced = json.dumps(json.loads(make_record_json())).encode("utf-8")
    payload = make_payload(
        instance,
        records=(make_record(instance, record_json_bytes=spaced),),
    )
    result = prepare_instance_result(payload, producer_run_dir=tmp_path / "runs" / "a")
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "record_json" in result.reason

    payload = make_payload(
        instance,
        records=(make_record(instance),),
        outcome=json.dumps({"diagnostic_gaps": []}, indent=1).encode("utf-8"),
    )
    result = prepare_instance_result(payload, producer_run_dir=tmp_path / "runs" / "b")
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "outcome_json" in result.reason


def test_prepare_rejects_contaminated_payload(tmp_path):
    instance = make_instance()
    contaminated = make_record_json(ticket_evidence_extra={"candidate_disposition": "confirmed"})
    payload = make_payload(
        instance, records=(make_record(instance, record_json_bytes=contaminated),)
    )
    run_dir = tmp_path / "runs" / "contaminated"
    result = prepare_instance_result(payload, producer_run_dir=run_dir)
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "adjudication authority" in result.reason
    assert not (run_dir / ARTIFACT_DIR_NAME).exists()


def test_prepare_rejects_malformed_identity_versions(tmp_path):
    instance = make_instance()
    for versions in ((), (("dup", "1"), ("dup", "2"))):
        payload = make_payload(
            instance,
            records=(make_record(instance),),
            identity=make_identity(versions=versions),
        )
        result = prepare_instance_result(payload, producer_run_dir=tmp_path / "runs" / "x")
        assert isinstance(result, instance_results_module.RecoveryMiss)
        assert "versions" in result.reason


def test_prepare_rejects_manifest_count_disagreement(tmp_path):
    instance = make_instance()
    records = (make_record(instance),)
    payload = make_payload(
        instance,
        records=records,
        completion=make_completion(
            expected_record_count=2,
            expected_obligation_count=1,
            expected_occurrence_count=2,
        ),
    )
    result = prepare_instance_result(payload, producer_run_dir=tmp_path / "runs" / "x")
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "record count" in result.reason


# ---------------------------------------------------------------------------
# verify: trusted receipt round trip (matrix S08-P01/P03/P04 codec admission)
# ---------------------------------------------------------------------------


def test_verify_round_trips_full_payload_losslessly(scenario):
    result = verify(scenario)
    assert isinstance(result, RecoveryAccepted)
    assert result.receipt == make_receipt(scenario.prepared)
    assert result.payload == scenario.payload
    # Byte-exact record projection and outcome preservation.
    assert result.payload.records[0].record_json == scenario.records[0].record_json
    assert result.payload.outcome_json == scenario.payload.outcome_json
    assert result.payload.records[0].owner_instances == (
        scenario.instance,
        scenario.other_owner,
    )
    projection = json.loads(result.payload.records[0].record_json)
    assert projection["occurrence_uids"] == ["OCC_1", "OCC_2"]
    assert result.payload.completion.active_stage_errors == ()
    # Repeated verification is stable (idempotent admission evidence).
    again = verify(scenario)
    assert isinstance(again, RecoveryAccepted)
    assert again.payload == result.payload


def test_verify_accepts_instance_with_no_candidates(scenario, tmp_path):
    instance = make_instance(identity="inst-empty")
    payload = make_payload(
        instance,
        records=(),
        completion=make_completion(
            expected_record_count=0,
            expected_obligation_count=0,
            expected_occurrence_count=0,
        ),
        outcome=canon({"diagnostic_gaps": []}),
    )
    prepared = prepare_instance_result(payload, producer_run_dir=tmp_path / "runs" / "empty")
    assert isinstance(prepared, PreparedInstanceResult)
    result = verify_instance_result(
        make_receipt(prepared),
        expected=payload.identity,
        instance=ExpectedInstance(key=instance, semantics_digest="sem-digest-a"),
    )
    assert isinstance(result, RecoveryAccepted)
    assert result.payload.records == ()
    document = load_document(prepared)
    assert document["manifest"]["record_count"] == 0
    assert document["manifest"]["occurrence_count"] == 0


def test_same_name_instances_in_different_builds_stay_separate(tmp_path):
    build_a = make_instance(identity="inst-x", build="build-a")
    build_b = make_instance(identity="inst-x", build="build-b")
    run_dir = tmp_path / "runs" / "two-builds"
    prepared = []
    for instance in (build_a, build_b):
        payload = make_payload(instance, records=(make_record(instance),))
        result = prepare_instance_result(payload, producer_run_dir=run_dir)
        assert isinstance(result, PreparedInstanceResult)
        prepared.append((instance, result))
    # Same identity hash prefix, different content digests: two artifacts.
    names = [result.artifact_path.name for _, result in prepared]
    assert len(set(names)) == 2
    assert names[0].split(".")[0] == names[1].split(".")[0]
    for instance, result in prepared:
        accepted = verify_instance_result(
            make_receipt(result),
            expected=result.payload.identity,
            instance=ExpectedInstance(key=instance, semantics_digest="sem-digest-a"),
        )
        assert isinstance(accepted, RecoveryAccepted)
        assert accepted.payload.instance.build_context_id == instance.build_context_id


# ---------------------------------------------------------------------------
# verify: identity, instance and receipt-structure negatives (S08-N03/N04)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mutate",
    [
        "job_id",
        "input_revision",
        "plan_fingerprint",
        "versions",
        "registry_digest",
        "semantics_policy",
        "semantics_digest",
        "dependency_digest",
    ],
)
def test_verify_rejects_recovery_identity_mismatch(scenario, mutate):
    kwargs = {
        "job_id": "job-other",
        "input_revision": "rev-other",
        "plan_fingerprint": "plan-other",
        "versions": (("entry_instances", "zscope.entry-instances.v2"),),
        "registry_digest": "reg-other",
        "semantics_policy": "other-policy.v1",
        "semantics_digest": "sem-other",
        "dependency_digest": "dep-other",
    }
    expected = make_identity(**{mutate: kwargs[mutate]})
    receipt = make_receipt(scenario.prepared)
    result = verify_instance_result(receipt, expected=expected, instance=scenario.expected_instance)
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "identity" in result.reason


@pytest.mark.parametrize(
    "field,value",
    [
        ("identity", "inst-other"),
        ("build_context_id", "build-other"),
        ("usr", "c:@F@other"),
        ("source", "src/other.c"),
    ],
)
def test_verify_rejects_instance_mismatch(scenario, field, value):
    key = dataclasses.replace(make_instance(), **{field: value})
    result = verify(scenario, instance=key, semantics_digest="sem-digest-a")
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "instance" in result.reason


def test_verify_rejects_semantics_digest_mismatch(scenario):
    result = verify(scenario, semantics_digest="sem-digest-b")
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "semantics digest" in result.reason


def test_verify_rejects_empty_instance_identity(scenario):
    empty = make_instance(identity="")
    result = verify(
        scenario,
        instance=empty,
        semantics_digest="sem-digest-a",
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "identity" in result.reason


@pytest.mark.parametrize(
    "mutate",
    [
        {"kind": "instance_checkpoint_persisted"},
        {"event_seq": 0},
        {"attempt_no": 0},
        {"producer_run_id": ""},
        {"content_sha256": "XYZ"},
        {"content_sha256": "A" * 64},
        {"byte_count": 1},
    ],
)
def test_verify_rejects_malformed_receipt_structure(scenario, mutate):
    result = verify(scenario, **mutate)
    assert isinstance(result, instance_results_module.RecoveryMiss)


def test_verify_rejects_relative_receipt_paths(scenario, tmp_path):
    result = verify(scenario, run_dir=Path("relative/run"))
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "absolute" in result.reason

    receipt = make_receipt(
        scenario.prepared,
        artifact_path=scenario.prepared.artifact_path.relative_to(
            scenario.prepared.artifact_path.parents[1]
        ),
    )
    result = verify_instance_result(
        receipt,
        expected=scenario.expected_identity,
        instance=scenario.expected_instance,
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "absolute" in result.reason


def test_verify_missing_artifact_is_a_miss(scenario, tmp_path):
    scenario.prepared.artifact_path.unlink()
    result = verify(scenario)
    assert isinstance(result, instance_results_module.RecoveryMiss)


# ---------------------------------------------------------------------------
# verify: path fencing negatives (matrix S08-N02)
# ---------------------------------------------------------------------------


def test_verify_rejects_path_escapes_and_foreign_directories(scenario, tmp_path):
    name = scenario.prepared.artifact_path.name
    sha = scenario.prepared.content_sha256
    identity_hash = hashlib.sha256(scenario.instance.identity.encode("utf-8")).hexdigest()
    escapes = {
        "absolute-elsewhere": tmp_path / "elsewhere" / name,
        "parent-hop": scenario.run_dir / ARTIFACT_DIR_NAME / ".." / name,
        "subdirectory": scenario.run_dir / ARTIFACT_DIR_NAME / "sub" / name,
        "wrong-identity-hash": scenario.run_dir / ARTIFACT_DIR_NAME / f"{'0' * 64}.{sha}.json",
        "wrong-content-hash": scenario.run_dir
        / ARTIFACT_DIR_NAME
        / f"{identity_hash}.{'0' * 64}.json",
    }
    for label, path in escapes.items():
        result = verify(scenario, artifact_path=path)
        assert isinstance(result, instance_results_module.RecoveryMiss), label
    # A receipt naming a different producer run dir never reaches the file.
    result = verify(scenario, run_dir=tmp_path / "other-run")
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "instance-results" in result.reason


def test_verify_rejects_symlinked_artifact_file(scenario, tmp_path):
    raw = scenario.prepared.artifact_path.read_bytes()
    outside = tmp_path / "outside.json"
    outside.write_bytes(raw)
    scenario.prepared.artifact_path.unlink()
    scenario.prepared.artifact_path.symlink_to(outside)
    result = verify(scenario)
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "symlink" in result.reason


def test_verify_rejects_symlinked_instance_results_directory(scenario, tmp_path):
    raw = scenario.prepared.artifact_path.read_bytes()
    real_dir = tmp_path / "real-results"
    real_dir.mkdir()
    (real_dir / scenario.prepared.artifact_path.name).write_bytes(raw)
    results = scenario.run_dir / ARTIFACT_DIR_NAME
    shutil.rmtree(results)
    results.symlink_to(real_dir)
    result = verify(scenario)
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "symlink" in result.reason


# ---------------------------------------------------------------------------
# verify: byte-level negatives (matrix S08-N07 corruption side)
# ---------------------------------------------------------------------------


def test_verify_rejects_corrupted_or_truncated_bytes(scenario):
    original = scenario.prepared.artifact_path.read_bytes()
    scenario.prepared.artifact_path.write_bytes(original[:-1])
    truncated = verify(scenario)
    assert isinstance(truncated, instance_results_module.RecoveryMiss)

    scenario.prepared.artifact_path.write_bytes(original + b" ")
    appended = verify(scenario)
    assert isinstance(appended, instance_results_module.RecoveryMiss)


def test_verify_rejects_duplicate_keys_and_nonfinite_values(scenario):
    document = load_document(scenario.prepared)
    raw = canon(document)
    duplicated = b'{"schema":"x","schema":"x",' + raw.lstrip(b"{")
    result = verify_instance_result(
        publish_raw(scenario, duplicated),
        expected=scenario.expected_identity,
        instance=scenario.expected_instance,
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "duplicate" in result.reason

    nan_raw = raw.replace(b'"expected_record_count":1', b'"expected_record_count":NaN')
    result = verify_instance_result(
        publish_raw(scenario, nan_raw),
        expected=scenario.expected_identity,
        instance=scenario.expected_instance,
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "non-finite" in result.reason

    overflow_raw = raw.replace(b'"priority_score":50', b'"priority_score":1e999')
    result = verify_instance_result(
        publish_raw(scenario, overflow_raw),
        expected=scenario.expected_identity,
        instance=scenario.expected_instance,
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "non-finite" in result.reason


def test_verify_rejects_noncanonical_but_parseable_bytes(scenario):
    document = load_document(scenario.prepared)
    spaced = json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8")
    result = verify_instance_result(
        publish_raw(scenario, spaced),
        expected=scenario.expected_identity,
        instance=scenario.expected_instance,
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "canonical" in result.reason


# ---------------------------------------------------------------------------
# verify: completion and manifest negatives (matrix S08-N06, R23-CONTRACT-N2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["error", "cancelled", "deferred", "incomplete", "unknown"])
def test_verify_rejects_non_success_completion_in_bound_file(scenario, state):
    document = load_document(scenario.prepared)
    document["completion"]["state"] = state
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "re-analy" in result.reason


def test_verify_rejects_open_collection_or_stale_input_in_file(scenario):
    for mutation in ("collection_closed", "input_current"):
        document = load_document(scenario.prepared)
        document["completion"][mutation] = False
        receipt = craft_receipt(scenario, document)
        result = verify_instance_result(
            receipt,
            expected=scenario.expected_identity,
            instance=scenario.expected_instance,
        )
        assert isinstance(result, instance_results_module.RecoveryMiss)
        assert "re-analy" in result.reason


def test_verify_rejects_wrong_manifest_counts(scenario):
    document = load_document(scenario.prepared)
    document["manifest"]["record_count"] = 5
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "manifest" in result.reason

    document = load_document(scenario.prepared)
    document["completion"]["expected_occurrence_count"] = 9
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "occurrence count" in result.reason


def test_verify_rejects_same_count_occurrence_replacement(scenario):
    # Replace one occurrence UID with a new one: every count stays identical,
    # so only the membership digest can catch the swapped membership.
    document = load_document(scenario.prepared)
    record = document["records"][0]
    assert record["record_json"]["occurrence_uids"] == ["OCC_1", "OCC_2"]
    record["record_json"]["occurrence_uids"][0] = "OCC_9"
    record["record_json"]["occurrences"][0]["occurrence_uid"] = "OCC_9"
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "manifest" in result.reason


def test_verify_rejects_recomputed_membership_with_stale_receipt_digest(scenario):
    # An attacker who also recomputes the membership digest still changes the
    # file bytes; the trusted receipt's content digest no longer matches even
    # when the byte count is made consistent.
    document = load_document(scenario.prepared)
    record = document["records"][0]
    record["record_json"]["occurrence_uids"][0] = "OCC_9"
    record["record_json"]["occurrences"][0]["occurrence_uid"] = "OCC_9"
    membership = {
        "records": [
            [
                record["record_json"]["build_context_id"],
                record["candidate_uid"],
                record["obligation_uid"],
                record["validation_cluster_uid"],
                record["record_json"]["evidence_hash"],
                record["record_json"]["context_signature"],
                sorted(record["record_json"]["occurrence_uids"]),
            ]
        ],
        "obligation_uids": [record["obligation_uid"]],
        "occurrence_uids": sorted(record["record_json"]["occurrence_uids"]),
    }
    document["manifest"]["membership_digest"] = hashlib.sha256(canon(membership)).hexdigest()
    raw = canon(document)
    scenario.prepared.artifact_path.write_bytes(raw)
    receipt = make_receipt(
        scenario.prepared,  # keeps the ORIGINAL trusted content digest
        byte_count=len(raw),
    )
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "digest" in result.reason


# ---------------------------------------------------------------------------
# verify: record projection negatives (matrix S08-N07/N08, P04 isolation)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mutation",
    [
        "drop-field",
        "extra-proof-field",
        "terminal-status",
        "terminal-role",
        "uid-mismatch",
        "occurrence-shape",
        "occurrence-count",
        "ticket-shape",
    ],
)
def test_verify_rejects_record_projection_defects(scenario, mutation):
    document = load_document(scenario.prepared)
    record = document["records"][0]
    projection = record["record_json"]
    if mutation == "drop-field":
        del projection["evidence_hashes"]
    elif mutation == "extra-proof-field":
        projection["decision_proof"] = {"rule": "saved"}
    elif mutation == "terminal-status":
        projection["status"] = "confirmed"
    elif mutation == "terminal-role":
        projection["record_role"] = "terminal_decision"
    elif mutation == "uid-mismatch":
        record["candidate_uid"] = "CAND_something_else"
    elif mutation == "occurrence-shape":
        del projection["occurrences"][0]["call_paths"]
    elif mutation == "occurrence-count":
        projection["occurrence_uids"].append("OCC_3")
    elif mutation == "ticket-shape":
        del projection["ticket"]["evidence"]
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss), mutation


def test_owner_and_build_violations_are_rejected(scenario, tmp_path):
    foreign_instance = make_instance(
        identity="inst-c", build="build-2", usr="c:@F@foreign", source="src/c.c"
    )
    same_build_other = make_instance(
        identity="inst-d", build="build-1", usr="c:@F@d", source="src/d.c"
    )
    variants = {
        # A record not owned by the instance the result file describes.
        "not-owned": {"owners": (same_build_other,)},
        # A record whose owner comes from another build context.
        "cross-build-owner": {"owners": (scenario.instance, foreign_instance)},
        # A record whose own build differs from the instance's build.
        "record-build": {"build": "build-9"},
    }
    for name, kwargs in variants.items():
        payload = make_payload(
            scenario.instance,
            records=(make_record(scenario.instance, cluster=f"VAL_{name}", **kwargs),),
        )
        result = prepare_instance_result(payload, producer_run_dir=tmp_path / "runs" / name)
        assert isinstance(result, instance_results_module.RecoveryMiss), name
        assert not (tmp_path / "runs" / name / ARTIFACT_DIR_NAME).exists(), name

    # Decode side: a crafted document whose record lost its owning instance.
    document = load_document(scenario.prepared)
    document["records"][0]["owner_instances"] = [
        {
            "identity": "inst-d",
            "build_context_id": "build-1",
            "usr": "c:@F@d",
            "source": "src/d.c",
        }
    ]
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)


def test_verify_rejects_duplicate_cluster_records(scenario, tmp_path):
    duplicate = (
        make_record(scenario.instance),
        make_record(
            scenario.instance,
            cluster="VAL_alpha",
            candidate_uid="CAND_beta",
            obligation_uid="OBL_alpha",
        ),
    )
    payload = make_payload(
        scenario.instance,
        records=duplicate,
        completion=make_completion(
            expected_record_count=2,
            expected_obligation_count=1,
            expected_occurrence_count=4,
        ),
    )
    result = prepare_instance_result(payload, producer_run_dir=tmp_path / "runs" / "dup")
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "duplicate" in result.reason


@pytest.mark.parametrize(
    "contamination",
    [
        "confirmed-disposition",
        "saved-decision-proof",
        "validation-cache",
        "rejected-status",
        "confirmed-verdict",
    ],
)
def test_verify_rejects_serialized_adjudication_authority(scenario, contamination):
    document = load_document(scenario.prepared)
    evidence = document["records"][0]["record_json"]["ticket"]["evidence"]
    if contamination == "confirmed-disposition":
        evidence["candidate_payload"]["candidate_disposition"] = "confirmed"
    elif contamination == "saved-decision-proof":
        evidence["candidate_payload"]["decision_proof"] = {"rule": "saved-proof"}
    elif contamination == "validation-cache":
        evidence["candidate_payload"]["validation_cache"] = {"cached": True}
    elif contamination == "rejected-status":
        evidence["candidate_payload"]["status"] = "rejected"
    elif contamination == "confirmed-verdict":
        document["outcome"]["verdict"] = "confirmed"
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss), contamination
    assert "authority" in result.reason or "proof" in result.reason or "cache" in result.reason


def test_verify_accepts_neutral_needs_review_disposition(scenario):
    # A default envelope disposition is a producer assertion, not authority.
    document = load_document(scenario.prepared)
    evidence = document["records"][0]["record_json"]["ticket"]["evidence"]
    evidence["candidate_payload"]["candidate_disposition"] = "needs_review"
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, RecoveryAccepted)


def test_verify_rejects_outcome_shape_defects(scenario):
    document = load_document(scenario.prepared)
    document["outcome"] = ["not", "an", "object"]
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "outcome" in result.reason

    document = load_document(scenario.prepared)
    del document["outcome"]["diagnostic_gaps"]
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "diagnostic_gaps" in result.reason

    document = load_document(scenario.prepared)
    document["outcome"]["diagnostic_gaps"] = [7]
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "diagnostic_gaps" in result.reason


def test_verify_rejects_malformed_document_versions(scenario):
    document = load_document(scenario.prepared)
    document["identity"]["versions"] = []
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "versions" in result.reason

    document = load_document(scenario.prepared)
    document["identity"]["versions"] = [["dup", "1"], ["dup", "2"]]
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "duplicate" in result.reason


def test_verify_rejects_document_schema_drift(scenario):
    document = load_document(scenario.prepared)
    document["schema"] = "zscope.instance-result.v2"
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)

    document = load_document(scenario.prepared)
    document["unknown_extra_key"] = True
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "key set" in result.reason


# ---------------------------------------------------------------------------
# module boundaries (no product imports, hidden tokens, immutability)
# ---------------------------------------------------------------------------


def test_module_has_no_product_imports():
    source = Path(instance_results_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert imported == {
        "__future__",
        "hashlib",
        "json",
        "math",
        "os",
        "uuid",
        "dataclasses",
        "pathlib",
        "typing",
    }


def test_current_attempt_repr_hides_owner_token(tmp_path):
    attempt = CurrentAttempt(
        job_id="job-1",
        run_id="run-42",
        owner_token="secret-owner-token",
        input_revision="rev-7",
        run_dir=tmp_path,
    )
    rendered = repr(attempt)
    assert "secret-owner-token" not in rendered
    assert "job-1" in rendered and "run-42" in rendered


def test_artifact_file_contains_no_owner_or_claim_token(scenario):
    raw = scenario.prepared.artifact_path.read_bytes()
    assert b"owner_token" not in raw
    assert b"claim_token" not in raw
    assert b"secret" not in raw


def test_typed_results_are_immutable(scenario):
    with pytest.raises(Exception):
        scenario.payload.producer_run_id = "mutated"  # type: ignore[misc]
    with pytest.raises(Exception):
        scenario.prepared.content_sha256 = "0" * 64  # type: ignore[misc]
    with pytest.raises(Exception):
        scenario.prepared.artifact_path = Path("/tmp")  # type: ignore[misc]


# ---------------------------------------------------------------------------
# R24 repair: same-UID multi-path occurrences (S08-R24-P1-01)
# ---------------------------------------------------------------------------


def test_same_uid_two_distinct_paths_roundtrips(tmp_path):
    # The live ledger dedupes occurrence_uids but keeps one full row per
    # distinct (uid, entry, paths, context) attribution; one UID may carry
    # several path rows and must round-trip byte-for-byte without reshaping.
    instance = make_instance()
    projection = json.loads(make_record_json(occurrence_uids=("OCC_1",)))
    projection["occurrences"].append(
        {
            "call_paths": [["entry_a", "other_helper", "sink_c"]],
            "context_signature": "ctxsig-alpha",
            "entry_identity": "entry_a",
            "occurrence_uid": "OCC_1",
        }
    )
    record = make_record(instance, record_json_bytes=canon(projection))
    payload = make_payload(
        instance,
        records=(record,),
        completion=make_completion(expected_occurrence_count=1),
    )
    prepared = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(prepared, PreparedInstanceResult), prepared
    result = verify_instance_result(
        make_receipt(prepared),
        expected=payload.identity,
        instance=ExpectedInstance(instance, payload.instance_semantics_digest),
    )
    assert isinstance(result, RecoveryAccepted), result
    assert result.payload.records[0].record_json == record.record_json
    roundtripped = json.loads(result.payload.records[0].record_json)
    assert roundtripped["occurrence_uids"] == ["OCC_1"]
    assert len(roundtripped["occurrences"]) == 2
    assert roundtripped["occurrences"][0]["call_paths"] == [["entry_a", "helper_b"]]
    assert roundtripped["occurrences"][1]["call_paths"] == [["entry_a", "other_helper", "sink_c"]]


def test_reordered_occurrence_rows_keep_original_uid_order(tmp_path):
    instance = make_instance()
    projection = json.loads(make_record_json(occurrence_uids=("OCC_1", "OCC_2")))
    projection["occurrences"].reverse()  # rows deliberately not in UID-list order
    record = make_record(instance, record_json_bytes=canon(projection))
    payload = make_payload(instance, records=(record,))
    prepared = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(prepared, PreparedInstanceResult), prepared
    result = verify_instance_result(
        make_receipt(prepared),
        expected=payload.identity,
        instance=ExpectedInstance(instance, payload.instance_semantics_digest),
    )
    assert isinstance(result, RecoveryAccepted), result
    roundtripped = json.loads(result.payload.records[0].record_json)
    assert roundtripped["occurrence_uids"] == ["OCC_1", "OCC_2"]
    assert [row["occurrence_uid"] for row in roundtripped["occurrences"]] == [
        "OCC_2",
        "OCC_1",
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate-row",
        "duplicate-uid-list",
        "extra-uid-in-list",
        "unknown-row-uid",
        "same-uid-entry-conflict",
        "row-context-mismatch",
    ],
)
def test_occurrence_membership_defects_are_rejected(tmp_path, mutation):
    instance = make_instance()
    projection = json.loads(make_record_json(occurrence_uids=("OCC_1",)))
    if mutation == "duplicate-row":
        projection["occurrences"].append(dict(projection["occurrences"][0]))
    elif mutation == "duplicate-uid-list":
        projection["occurrence_uids"].append("OCC_1")
    elif mutation == "extra-uid-in-list":
        projection["occurrence_uids"].append("OCC_2")
    elif mutation == "unknown-row-uid":
        projection["occurrences"].append(
            {
                "call_paths": [["entry_a", "other_helper"]],
                "context_signature": "ctxsig-alpha",
                "entry_identity": "entry_a",
                "occurrence_uid": "OCC_9",
            }
        )
    elif mutation == "same-uid-entry-conflict":
        projection["occurrences"].append(
            {
                "call_paths": [["entry_a", "other_helper"]],
                "context_signature": "ctxsig-alpha",
                "entry_identity": "entry_b",
                "occurrence_uid": "OCC_1",
            }
        )
    elif mutation == "row-context-mismatch":
        projection["occurrences"][0]["context_signature"] = "ctxsig-other"
    record = make_record(instance, record_json_bytes=canon(projection))
    payload = make_payload(instance, records=(record,))
    result = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(result, instance_results_module.RecoveryMiss), mutation
    assert result.reason, mutation
    assert not (tmp_path / "run" / ARTIFACT_DIR_NAME).exists(), mutation


def test_decoded_occurrence_defect_is_rejected(scenario):
    document = load_document(scenario.prepared)
    record_json = document["records"][0]["record_json"]
    record_json["occurrences"].append(dict(record_json["occurrences"][0]))
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)


# ---------------------------------------------------------------------------
# R24 repair: immutable-bytes input ownership (S08-R24-P2-02)
# ---------------------------------------------------------------------------


def test_mutable_outcome_and_record_inputs_are_rejected(tmp_path):
    instance = make_instance()
    record = make_record(instance)
    canonical_outcome = canon({"diagnostic_gaps": []})
    for outcome in (
        bytearray(canonical_outcome),
        memoryview(canonical_outcome),
        '{"diagnostic_gaps":[]}',
    ):
        payload = make_payload(instance, records=(record,), outcome=outcome)
        result = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
        assert isinstance(result, instance_results_module.RecoveryMiss), outcome
        assert result.reason, outcome
        assert not (tmp_path / "run" / ARTIFACT_DIR_NAME).exists(), outcome

    payload = dataclasses.replace(make_payload(instance, records=(record,)), outcome_json=None)
    result = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert result.reason
    assert not (tmp_path / "run" / ARTIFACT_DIR_NAME).exists()

    mutable_record = dataclasses.replace(record, record_json=bytearray(make_record_json()))
    payload = make_payload(instance, records=(mutable_record,))
    result = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert result.reason
    assert not (tmp_path / "run" / ARTIFACT_DIR_NAME).exists()


def test_prepared_payload_is_an_immutable_bytes_snapshot(tmp_path):
    instance = make_instance()
    record = make_record(instance)
    outcome = canon({"diagnostic_gaps": [], "verdict": "analyzed"})
    payload = make_payload(instance, records=(record,), outcome=outcome)
    prepared = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(prepared, PreparedInstanceResult)
    raw = prepared.artifact_path.read_bytes()
    assert isinstance(prepared.payload.outcome_json, bytes)
    # A caller mutating a derived buffer cannot change the prepared snapshot,
    # the published artifact or a later decode.
    bytearray(prepared.payload.outcome_json).clear()
    assert prepared.payload.outcome_json == outcome
    assert prepared.artifact_path.read_bytes() == raw
    result = verify_instance_result(
        make_receipt(prepared),
        expected=payload.identity,
        instance=ExpectedInstance(instance, payload.instance_semantics_digest),
    )
    assert isinstance(result, RecoveryAccepted)
    assert result.payload.outcome_json == outcome


# ---------------------------------------------------------------------------
# R24 repair: malformed input stays inside the typed miss boundary (S08-R24-P2-03)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind",
    [
        "completion_state_list",
        "completion_state_dict",
        "record_status_list",
        "record_role_list",
        "outcome_string",
        "outcome_none",
        "outcome_memoryview",
    ],
)
def test_malformed_typed_fields_are_typed_misses(tmp_path, kind):
    instance = make_instance()
    record = make_record(instance)
    payload = make_payload(instance, records=(record,))
    if kind == "completion_state_list":
        payload = dataclasses.replace(
            payload, completion=dataclasses.replace(payload.completion, state=[])
        )
    elif kind == "completion_state_dict":
        payload = dataclasses.replace(
            payload, completion=dataclasses.replace(payload.completion, state={})
        )
    elif kind == "record_status_list":
        payload = dataclasses.replace(payload, records=(dataclasses.replace(record, status=[]),))
    elif kind == "record_role_list":
        payload = dataclasses.replace(
            payload, records=(dataclasses.replace(record, record_role=[]),)
        )
    elif kind == "outcome_string":
        payload = dataclasses.replace(payload, outcome_json='{"diagnostic_gaps":[]}')
    elif kind == "outcome_none":
        payload = dataclasses.replace(payload, outcome_json=None)
    elif kind == "outcome_memoryview":
        payload = dataclasses.replace(
            payload, outcome_json=memoryview(canon({"diagnostic_gaps": []}))
        )
    result = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(result, instance_results_module.RecoveryMiss), kind
    assert result.reason, kind
    assert not (tmp_path / "run" / ARTIFACT_DIR_NAME).exists(), kind


def test_prepare_rejects_invalid_run_dir_and_payload_objects(tmp_path):
    instance = make_instance()
    record = make_record(instance)
    payload = make_payload(instance, records=(record,))
    for bad_dir in (None, 123, b"/tmp/x"):
        result = prepare_instance_result(payload, producer_run_dir=bad_dir)
        assert isinstance(result, instance_results_module.RecoveryMiss), bad_dir
        assert result.reason, bad_dir
    result = prepare_instance_result(None, producer_run_dir=tmp_path / "run")
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert result.reason


def test_deeply_nested_disk_json_is_a_typed_miss(tmp_path):
    scenario = Scenario(tmp_path)
    raw = b'{"x":' * 1600 + b"0" + b"}" * 1600
    result = verify_instance_result(
        publish_raw(scenario, raw),
        expected=scenario.expected_identity,
        instance=scenario.expected_instance,
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert result.reason


def test_oversized_artifact_is_a_typed_miss(tmp_path):
    scenario = Scenario(tmp_path)
    limit = instance_results_module._MAX_JSON_BYTES
    raw = b'{"x":"' + b"a" * (limit + 1) + b'"}'
    result = verify_instance_result(
        publish_raw(scenario, raw),
        expected=scenario.expected_identity,
        instance=scenario.expected_instance,
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert result.reason


# ---------------------------------------------------------------------------
# R24 repair: embedded schema/decision-context version binding (S08-R24-P2-04)
# ---------------------------------------------------------------------------


def test_foreign_inner_candidate_schema_is_rejected(tmp_path):
    instance = make_instance()
    wire = json.loads(make_record_json())
    wire["candidate_schema_version"] = "zscope.candidate.v999"
    record = make_record(instance, record_json_bytes=canon(wire))
    payload = make_payload(instance, records=(record,))
    assert dict(payload.identity.versions)["candidate_schema"] == "zscope.candidate.v3.5"
    result = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "candidate schema" in result.reason
    assert not (tmp_path / "run" / ARTIFACT_DIR_NAME).exists()


def test_decoded_inner_schema_drift_is_rejected(scenario):
    document = load_document(scenario.prepared)
    document["records"][0]["record_json"]["candidate_schema_version"] = "zscope.candidate.unknown"
    receipt = craft_receipt(scenario, document)
    result = verify_instance_result(
        receipt, expected=scenario.expected_identity, instance=scenario.expected_instance
    )
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "candidate schema" in result.reason


def test_identity_without_candidate_schema_key_is_rejected(tmp_path):
    instance = make_instance()
    record = make_record(instance)
    payload = make_payload(
        instance,
        records=(record,),
        identity=make_identity(versions=(("entry_instances", "zscope.entry-instances.v1"),)),
    )
    result = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "candidate_schema" in result.reason


def test_identity_schema_disagreement_is_rejected(tmp_path):
    instance = make_instance()
    record = make_record(instance)
    payload = make_payload(
        instance,
        records=(record,),
        identity=make_identity(
            versions=(
                ("entry_instances", "zscope.entry-instances.v1"),
                ("candidate_schema", "zscope.candidate.v3.4"),
            )
        ),
    )
    result = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "does not match" in result.reason


@pytest.mark.parametrize(
    "version",
    [
        "zscope.decision-context.v3.1",
        "zscope.decision-context.v3.2",
        "zscope.decision-context.v3.3",
    ],
)
def test_supported_decision_context_versions_roundtrip(tmp_path, version):
    instance = make_instance()
    wire = json.loads(make_record_json())
    wire["decision_context_version"] = version
    record = make_record(instance, record_json_bytes=canon(wire))
    payload = make_payload(instance, records=(record,))
    prepared = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(prepared, PreparedInstanceResult)
    result = verify_instance_result(
        make_receipt(prepared),
        expected=payload.identity,
        instance=ExpectedInstance(instance, payload.instance_semantics_digest),
    )
    assert isinstance(result, RecoveryAccepted), result


def test_unsupported_decision_context_is_rejected(tmp_path):
    instance = make_instance()
    wire = json.loads(make_record_json())
    wire["decision_context_version"] = "zscope.decision-context.v9"
    record = make_record(instance, record_json_bytes=canon(wire))
    payload = make_payload(instance, records=(record,))
    result = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "decision context" in result.reason


def test_declared_decision_context_disagreement_is_rejected(tmp_path):
    instance = make_instance()
    record = make_record(instance)
    payload = make_payload(
        instance,
        records=(record,),
        identity=make_identity(
            versions=(
                ("entry_instances", "zscope.entry-instances.v1"),
                ("candidate_schema", "zscope.candidate.v3.5"),
                ("candidate_decision_context", "zscope.decision-context.v3.2"),
            )
        ),
    )
    result = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(result, instance_results_module.RecoveryMiss)
    assert "decision context" in result.reason


def test_declared_matching_decision_context_is_accepted(tmp_path):
    instance = make_instance()
    record = make_record(instance)
    payload = make_payload(
        instance,
        records=(record,),
        identity=make_identity(
            versions=(
                ("entry_instances", "zscope.entry-instances.v1"),
                ("candidate_schema", "zscope.candidate.v3.5"),
                ("candidate_decision_context", "zscope.decision-context.v3.3"),
            )
        ),
    )
    prepared = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(prepared, PreparedInstanceResult)


# ---------------------------------------------------------------------------
# R25 repair: shared-cluster multi-context projections (S08-R25-P1-01)
# ---------------------------------------------------------------------------


def test_live_shared_cluster_distinct_declared_contexts_roundtrip(tmp_path):
    # A real CandidateLedger merges equivalent tickets added from entry_a and
    # entry_b into ONE validation cluster: two occurrence UIDs, two declared
    # validation_contexts, and each row keeps the context of its own add.
    # The complete 28-field projection must round-trip byte-for-byte with no
    # context, path, UID or owner rewritten to a primary-context shortcut.
    from test_candidate_ledger import _ticket
    from zscope.orchestration.candidates import CandidateLedger

    ledger = CandidateLedger(project_id="demo", revision="rev")
    first_ticket = _ticket()
    first_ticket.evidence["build_context_id"] = "build-1"
    second_ticket = _ticket()
    second_ticket.evidence["build_context_id"] = "build-1"
    first, first_new = ledger.add(
        first_ticket,
        source="local",
        call_path=["entry_a", "sink"],
        record_role="validation_obligation",
        entry_identity="entry_a",
    )
    second, second_new = ledger.add(
        second_ticket,
        source="local",
        call_path=["entry_b", "sink"],
        record_role="validation_obligation",
        entry_identity="entry_b",
    )
    assert first is second and first_new and not second_new
    assert len(first.occurrences) == 2
    assert len(first.context_signatures) == 2
    raw = first.to_dict()
    projection = {key: raw[key] for key in instance_results_module._RECORD_JSON_KEYS}
    instance = make_instance()
    owner_b = make_instance(identity="inst-b", usr="c:@F@other")
    record = PendingCandidate(
        schema=PENDING_RECORD_SCHEMA,
        candidate_uid=first.candidate_uid,
        obligation_uid=first.obligation_uid,
        validation_cluster_uid=first.validation_cluster_uid,
        build_context_id="build-1",
        owner_instances=(instance, owner_b),
        status=first.status,
        record_role=first.record_role,
        record_json=FrozenJSON(canon(projection)),
    )
    payload = make_payload(
        instance,
        records=(record,),
        completion=make_completion(expected_occurrence_count=2),
    )
    prepared = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(prepared, PreparedInstanceResult), prepared
    recovered = verify_instance_result(
        make_receipt(prepared),
        expected=payload.identity,
        instance=ExpectedInstance(instance, payload.instance_semantics_digest),
    )
    assert isinstance(recovered, RecoveryAccepted), recovered
    assert recovered.payload.records[0].record_json == record.record_json
    roundtripped = json.loads(recovered.payload.records[0].record_json)
    assert len(roundtripped["validation_contexts"]) == 2
    assert {row["context_signature"] for row in roundtripped["occurrences"]} == set(
        roundtripped["validation_contexts"]
    )


def test_two_declared_contexts_two_entries_roundtrip(tmp_path):
    # Synthetic mirror of the shared-cluster shape: two UIDs, two declared
    # contexts, one row per context; primary stays primary and both contexts
    # survive the round trip unchanged.
    instance = make_instance()
    projection = json.loads(make_record_json(occurrence_uids=("OCC_1", "OCC_2")))
    projection["validation_contexts"] = ["ctxsig-alpha", "ctxsig-beta"]
    projection["occurrences"][1]["context_signature"] = "ctxsig-beta"
    record = make_record(instance, record_json_bytes=canon(projection))
    payload = make_payload(instance, records=(record,))
    prepared = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(prepared, PreparedInstanceResult), prepared
    recovered = verify_instance_result(
        make_receipt(prepared),
        expected=payload.identity,
        instance=ExpectedInstance(instance, payload.instance_semantics_digest),
    )
    assert isinstance(recovered, RecoveryAccepted), recovered
    assert recovered.payload.records[0].record_json == record.record_json
    roundtripped = json.loads(recovered.payload.records[0].record_json)
    assert roundtripped["validation_contexts"] == ["ctxsig-alpha", "ctxsig-beta"]
    assert roundtripped["context_signature"] == "ctxsig-alpha"
    assert [row["context_signature"] for row in roundtripped["occurrences"]] == [
        "ctxsig-alpha",
        "ctxsig-beta",
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        "undeclared-row-context",
        "primary-not-declared",
        "declared-context-without-row",
        "duplicate-declared-contexts",
    ],
)
def test_declared_context_defects_are_rejected(tmp_path, mutation):
    instance = make_instance()
    projection = json.loads(make_record_json(occurrence_uids=("OCC_1", "OCC_2")))
    if mutation == "undeclared-row-context":
        projection["validation_contexts"] = ["ctxsig-alpha", "ctxsig-beta"]
        projection["occurrences"][1]["context_signature"] = "ctxsig-gamma"
    elif mutation == "primary-not-declared":
        projection["context_signature"] = "ctxsig-alpha"
        projection["validation_contexts"] = ["ctxsig-beta", "ctxsig-gamma"]
        projection["occurrences"][0]["context_signature"] = "ctxsig-beta"
        projection["occurrences"][1]["context_signature"] = "ctxsig-gamma"
    elif mutation == "declared-context-without-row":
        projection["validation_contexts"] = ["ctxsig-alpha", "ctxsig-beta"]
        # both rows keep ctxsig-alpha; ctxsig-beta is declared but never carried
    elif mutation == "duplicate-declared-contexts":
        projection["validation_contexts"] = ["ctxsig-alpha", "ctxsig-alpha"]
    record = make_record(instance, record_json_bytes=canon(projection))
    payload = make_payload(instance, records=(record,))
    result = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(result, instance_results_module.RecoveryMiss), mutation
    assert result.reason, mutation
    assert not (tmp_path / "run" / ARTIFACT_DIR_NAME).exists(), mutation


# ---------------------------------------------------------------------------
# R25 repair: whole-envelope resource bounds in prepare (S08-R25-P2-02)
# ---------------------------------------------------------------------------


def _nested_lists(count):
    value = 0
    for _ in range(count):
        value = [value]
    return value


def test_outcome_depth_envelope_boundary_roundtrip_and_miss(tmp_path):
    # Outcome walk depth is lists+2 and the assembled document adds one more
    # wrapper level (lists+3): 253 nested lists stay inside the final
    # envelope boundary and round-trip; 254 are individually legal for the
    # outcome yet push the whole envelope past the same limit its verifier
    # enforces, so prepare must typed-miss and write nothing.
    instance = make_instance()
    record = make_record(instance)

    inside = canon({"diagnostic_gaps": [], "nested": _nested_lists(253)})
    payload = make_payload(instance, records=(record,), outcome=inside)
    prepared = prepare_instance_result(payload, producer_run_dir=tmp_path / "inside")
    assert isinstance(prepared, PreparedInstanceResult), prepared
    recovered = verify_instance_result(
        make_receipt(prepared),
        expected=payload.identity,
        instance=ExpectedInstance(instance, payload.instance_semantics_digest),
    )
    assert isinstance(recovered, RecoveryAccepted), recovered
    assert recovered.payload.outcome_json == inside

    outside = canon({"diagnostic_gaps": [], "nested": _nested_lists(254)})
    payload = make_payload(instance, records=(record,), outcome=outside)
    run_dir = tmp_path / "outside"
    result = prepare_instance_result(payload, producer_run_dir=run_dir)
    assert isinstance(result, instance_results_module.RecoveryMiss), result
    assert result.reason
    assert not list(run_dir.rglob("*.json"))


def test_ticket_evidence_depth_envelope_boundary(tmp_path):
    # Deep ticket evidence inside record_json: the record-level walk allows
    # deeper nesting than the assembled document, so the envelope check must
    # be the one that rejects (or accepts) the final publication.
    instance = make_instance()

    projection = json.loads(make_record_json())
    projection["ticket"]["evidence"]["deep"] = _nested_lists(249)
    record = make_record(instance, record_json_bytes=canon(projection))
    payload = make_payload(instance, records=(record,))
    prepared = prepare_instance_result(payload, producer_run_dir=tmp_path / "inside")
    assert isinstance(prepared, PreparedInstanceResult), prepared
    recovered = verify_instance_result(
        make_receipt(prepared),
        expected=payload.identity,
        instance=ExpectedInstance(instance, payload.instance_semantics_digest),
    )
    assert isinstance(recovered, RecoveryAccepted), recovered
    assert recovered.payload.records[0].record_json == record.record_json

    projection = json.loads(make_record_json())
    projection["ticket"]["evidence"]["deep"] = _nested_lists(250)
    record = make_record(instance, record_json_bytes=canon(projection))
    payload = make_payload(instance, records=(record,))
    run_dir = tmp_path / "outside"
    result = prepare_instance_result(payload, producer_run_dir=run_dir)
    assert isinstance(result, instance_results_module.RecoveryMiss), result
    assert result.reason
    assert not list(run_dir.rglob("*.json"))


def test_total_byte_overflow_from_legal_records_is_miss(tmp_path):
    # Two records, each individually far below the per-record byte cap,
    # exceed the whole-envelope byte cap together: prepare must typed-miss
    # before creating any directory or file.
    limit = instance_results_module._MAX_JSON_BYTES
    instance = make_instance()
    records = []
    for index in range(2):
        projection = json.loads(
            make_record_json(
                candidate_uid=f"CAND_big{index}",
                obligation_uid=f"OBL_big{index}",
                validation_cluster_uid=f"VAL_big{index}",
            )
        )
        projection["ticket"]["context_slice"] = "x" * (limit // 2 + 1024)
        records.append(
            make_record(
                instance,
                candidate_uid=f"CAND_big{index}",
                obligation_uid=f"OBL_big{index}",
                cluster=f"VAL_big{index}",
                record_json_bytes=canon(projection),
            )
        )
    payload = make_payload(
        instance,
        records=tuple(records),
        completion=make_completion(
            expected_record_count=2,
            expected_obligation_count=2,
            expected_occurrence_count=4,
        ),
    )
    run_dir = tmp_path / "run"
    result = prepare_instance_result(payload, producer_run_dir=run_dir)
    assert isinstance(result, instance_results_module.RecoveryMiss), result
    assert result.reason
    assert not list(run_dir.rglob("*.json"))


def test_total_node_overflow_from_legal_records_is_miss(tmp_path):
    # Two records whose node counts are individually legal together exceed
    # the whole-envelope node cap; the envelope check must reject before any
    # publication.
    node_limit = instance_results_module._MAX_JSON_NODES
    instance = make_instance()
    per_record = node_limit // 2 + 1000
    records = []
    for index in range(2):
        projection = json.loads(
            make_record_json(
                candidate_uid=f"CAND_nodes{index}",
                obligation_uid=f"OBL_nodes{index}",
                validation_cluster_uid=f"VAL_nodes{index}",
            )
        )
        projection["ticket"]["evidence"]["wide"] = [0] * per_record
        records.append(
            make_record(
                instance,
                candidate_uid=f"CAND_nodes{index}",
                obligation_uid=f"OBL_nodes{index}",
                cluster=f"VAL_nodes{index}",
                record_json_bytes=canon(projection),
            )
        )
    payload = make_payload(
        instance,
        records=tuple(records),
        completion=make_completion(
            expected_record_count=2,
            expected_obligation_count=2,
            expected_occurrence_count=4,
        ),
    )
    run_dir = tmp_path / "run"
    result = prepare_instance_result(payload, producer_run_dir=run_dir)
    assert isinstance(result, instance_results_module.RecoveryMiss), result
    assert result.reason
    assert not list(run_dir.rglob("*.json"))


def test_largest_boundary_payload_roundtrips(tmp_path):
    # A single record padded to just under the total byte cap stays within
    # every verifier limit and round-trips byte-exactly.
    limit = instance_results_module._MAX_JSON_BYTES
    instance = make_instance()
    projection = json.loads(make_record_json())
    projection["ticket"]["context_slice"] = "y" * (limit - 4096)
    record = make_record(instance, record_json_bytes=canon(projection))
    payload = make_payload(instance, records=(record,))
    prepared = prepare_instance_result(payload, producer_run_dir=tmp_path / "run")
    assert isinstance(prepared, PreparedInstanceResult), prepared
    recovered = verify_instance_result(
        make_receipt(prepared),
        expected=payload.identity,
        instance=ExpectedInstance(instance, payload.instance_semantics_digest),
    )
    assert isinstance(recovered, RecoveryAccepted), recovered
    assert recovered.payload.records[0].record_json == record.record_json


def test_envelope_rejection_leaves_existing_artifacts_immutable(tmp_path):
    # An over-envelope prepare is a typed miss and never disturbs an already
    # published immutable artifact in the same run directory.
    instance = make_instance()
    record = make_record(instance)
    payload = make_payload(instance, records=(record,))
    run_dir = tmp_path / "run"
    prepared = prepare_instance_result(payload, producer_run_dir=run_dir)
    assert isinstance(prepared, PreparedInstanceResult), prepared
    original = prepared.artifact_path.read_bytes()

    overflowing = make_payload(
        instance,
        records=(record,),
        outcome=canon({"diagnostic_gaps": [], "nested": _nested_lists(254)}),
    )
    result = prepare_instance_result(overflowing, producer_run_dir=run_dir)
    assert isinstance(result, instance_results_module.RecoveryMiss), result
    assert result.reason
    assert prepared.artifact_path.read_bytes() == original
    recovered = verify_instance_result(
        make_receipt(prepared),
        expected=payload.identity,
        instance=ExpectedInstance(instance, payload.instance_semantics_digest),
    )
    assert isinstance(recovered, RecoveryAccepted), recovered
