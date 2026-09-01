import argparse
import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts import p6_pilot_protocol as p6_cli

from zscope.benchmarking.p6_protocol import (
    CHECKPOINT_SCHEMA_VERSION,
    P6ProtocolError,
    P6_CHECKPOINT_STAGE_ORDER,
    P6_EXECUTION_STAGE_ORDER,
    P6_WORKFLOW_PATH,
    QUALIFICATION_OCI_RECEIPT_SCHEMA_VERSION,
    REPAIR_RECEIPT_SCHEMA_VERSION,
    STAGE_RESULT_SCHEMA_VERSION,
    artifact_root_sha256,
    build_stage_artifact,
    build_repair_receipt,
    canonical_sha256,
    diagnose_pilot,
    load_stage_results,
    public_failure_annotation,
    record_stage_result,
    require_pilot_request,
    validate_checkpoint,
    validate_repair_receipt,
    validate_repair_receipt_bundle,
    validate_qualification_oci_receipt,
    validate_stage_result,
    validate_stage_sequence,
)


def _qualification_oci_receipt() -> tuple[dict, dict[str, str]]:
    identity = {
        "provider": "5" * 64,
        "network": "6" * 64,
        "runtime": "7" * 64,
        "image": "registry.example/zscope@sha256:" + "8" * 64,
        "image_id": "sha256:" + "9" * 64,
        "proxy_container_id": "4" * 64,
        "network_name": "p6-model-only",
        "endpoint_origin": "https://models.example:443",
        "workflow_run_id": "12345",
        "workflow_run_attempt": "2",
        "attempt_id": "p6-12345-2",
        "repository": "example/zscope",
    }
    image_id = identity["image_id"]
    mounts = [
        {
            "source": "/sealed/p6-input",
            "destination": "/zscope-input",
            "purpose": "scan_input",
            "read_only": True,
        },
        {
            "source": "/sealed/p6-output",
            "destination": "/zscope-output",
            "purpose": "artifact_output",
            "read_only": False,
        },
        {
            "source": "/sealed/p6-cache",
            "destination": "/zscope-cache",
            "purpose": "cache",
            "read_only": False,
        },
        {
            "source": "/sealed/p6-runtime",
            "destination": "/zscope-runtime/zscope",
            "purpose": "runtime_source",
            "read_only": True,
        },
    ]
    phase = {
        "phase": "scan",
        "container_name": "zscope-benchmark-scan-deadbeef0000",
        "container_id": "a" * 64,
        "command_return_code": 0,
        "container_exit_code": 0,
        "accepted_returncodes": [0, 1, 2],
        "working_dir": "/zscope-input",
        "image": identity["image"],
        "image_id": image_id,
        "image_verified": True,
        "read_only_rootfs": True,
        "cap_drop": ["ALL"],
        "cap_drop_verified": True,
        "security_opt": ["no-new-privileges"],
        "security_verified": True,
        "scanner_labels_verified": True,
        "p6_cleanup_scope_verified": True,
        "p6_workflow_run_id": identity["workflow_run_id"],
        "p6_workflow_run_attempt": int(identity["workflow_run_attempt"]),
        "p6_attempt_id": identity["attempt_id"],
        "p6_repository": identity["repository"],
        "p6_concurrency_group": "p6-pilot-validation",
        "p6_phase": "scan",
        "scanner_provider_environment_verified": True,
        "scanner_provider_environment_keys": ["Z_SCOPE_API_KEY"],
        "stdout_persisted": False,
        "stderr_persisted": False,
        "mounts": mounts,
        "unexpected_mount_count": 0,
        "network_name": identity["network_name"],
        "runtime_network_mode": identity["network_name"],
        "network_attachment_verified": True,
        "network_peer_count": 2,
        "network_peers_verified": True,
        "network_internal": True,
        "network_contract_verified": True,
        "proxy_verified": True,
        "proxy_credential_metadata_safe": True,
        "provider_identity_sha256": identity["provider"],
        "container_inspect_sha256": "a" * 64,
        "proxy_inspect_sha256": "b" * 64,
        "network_inspect_sha256": "c" * 64,
        "network_membership_sha256": "d" * 64,
        "inspect_verified": True,
        "cancellation_cleanup_guard_verified": True,
    }
    execution = {
        "schema_version": "zscope.benchmark-isolation.v1",
        "mode": "oci",
        "runtime": "podman",
        "runtime_path": "/usr/bin/podman",
        "image": identity["image"],
        "available": True,
        "runtime_info_sha256": "e" * 64,
        "image_inspect_sha256": "f" * 64,
        "image_id": image_id,
        "network_inspect_sha256": "1" * 64,
        "network_membership_sha256": "2" * 64,
        "proxy_inspect_sha256": "3" * 64,
        "rootless_verified": True,
        "image_digest_verified": True,
        "network_internal": True,
        "network_policy_sha256": identity["network"],
        "network_name": identity["network_name"],
        "endpoint_origin": identity["endpoint_origin"],
        "provider_identity_sha256": identity["provider"],
        "proxy_credential_metadata_safe": True,
        "proxy_container_id": identity["proxy_container_id"],
        "proxy_running": True,
        "execution_verified": True,
        "actual_inspection_collected": True,
        "release_capable": True,
        "truth_mounted": False,
        "repository_mounted": False,
        "runtime_source_mounted": True,
        "runtime_source_sha256": identity["runtime"],
        "scanner_cwd": "/zscope-input",
        "scanner_cwd_isolated": True,
        "mounts": mounts,
        "mounts_verified": True,
        "security_verified": True,
        "network_mode": "model-endpoint-only",
        "network_restriction_verified": True,
        "phase_executions": [phase],
        "required_phases": ["scan"],
        "errors": [],
    }
    receipt = {
        "schema_version": QUALIFICATION_OCI_RECEIPT_SCHEMA_VERSION,
        "executions": [execution],
        "execution_sha256s": [canonical_sha256(execution)],
    }
    return receipt, identity


def _validate_qualification_receipt(receipt: dict, identity: dict[str, str]) -> tuple[str, ...]:
    return validate_qualification_oci_receipt(
        receipt,
        expected_provider_identity_sha256=identity["provider"],
        expected_network_policy_sha256=identity["network"],
        expected_network_name=identity["network_name"],
        expected_endpoint_origin=identity["endpoint_origin"],
        expected_image=identity["image"],
        expected_image_id=identity["image_id"],
        expected_proxy_container_id=identity["proxy_container_id"],
        expected_runtime_source_sha256=identity["runtime"],
        expected_workflow_run_id=identity["workflow_run_id"],
        expected_workflow_run_attempt=int(identity["workflow_run_attempt"]),
        expected_attempt_id=identity["attempt_id"],
        expected_repository=identity["repository"],
    )


def test_qualification_oci_receipt_binds_inspected_secret_and_isolation_boundary() -> None:
    receipt, identity = _qualification_oci_receipt()

    hashes = _validate_qualification_receipt(receipt, identity)

    assert hashes == tuple(receipt["execution_sha256s"])
    encoded = json.dumps(receipt, sort_keys=True)
    assert "Z_SCOPE_API_KEY" in encoded
    assert "top-secret" not in encoded


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda execution, phase: phase.__setitem__("scanner_provider_environment_keys", []),
            "invalid",
        ),
        (
            lambda execution, phase: phase.__setitem__("stdout_persisted", True),
            "invalid",
        ),
        (
            lambda execution, phase: phase.__setitem__(
                "cancellation_cleanup_guard_verified", False
            ),
            "invalid",
        ),
        (
            lambda execution, phase: execution.__setitem__("network_policy_sha256", "0" * 64),
            "lineage",
        ),
        (
            lambda execution, phase: execution.__setitem__("proxy_container_id", "0" * 64),
            "lineage",
        ),
        (
            lambda execution, phase: execution.__setitem__("image_id", "sha256:" + "0" * 64),
            "lineage",
        ),
        (
            lambda execution, phase: phase.__setitem__("scanner_environment", "secret"),
            "fields",
        ),
    ],
)
def test_qualification_oci_receipt_rejects_unproved_or_leaky_claims(
    mutation: object, message: str
) -> None:
    receipt, identity = _qualification_oci_receipt()
    execution = receipt["executions"][0]
    phase = execution["phase_executions"][0]
    mutation(execution, phase)  # type: ignore[operator]
    receipt["execution_sha256s"] = [canonical_sha256(execution)]

    with pytest.raises(P6ProtocolError, match=message):
        _validate_qualification_receipt(receipt, identity)


def test_offline_stage_persists_only_compact_oci_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conservation = {
        "physical_call_count": 1,
        "provider_reported_call_count": 1,
        "estimated_call_count": 0,
        "provider_usage_coverage": 1.0,
        "requested_model": "deepseek-v4-flash",
        "requested_model_coverage": 1.0,
        "response_model": "deepseek-v4-flash-ga-260731",
        "response_model_coverage": 1.0,
        "queue_empty": True,
        "dimensions": {
            name: {"numerator": 1, "denominator": 1, "conserved": True}
            for name in ("token", "tool", "trace", "finding", "terminal")
        },
    }
    context = {
        "provider_identity_sha256": "1" * 64,
        "network_policy_sha256": "2" * 64,
        "network_name": "p6-model-only",
        "endpoint_origin": "https://models.example:443",
        "image": "registry.example/zscope@sha256:" + "3" * 64,
        "runtime_source_sha256": "4" * 64,
        "toolchain_evidence_sha256": "5" * 64,
        "workflow_run_id": "33260000001",
        "workflow_run_attempt": "2",
        "attempt_id": "p6-33260000001-2",
        "repository": "example/zscope",
        "control_plane_commit": "6" * 40,
        "candidate_commit": "7" * 40,
        "harness_sha256": "8" * 64,
    }
    receipt = {
        "schema_version": "zscope.p6-hidden-holdout-receipt.v1",
        "workflow_run_id": context["workflow_run_id"],
        "workflow_run_attempt": 2,
        "attempt_id": context["attempt_id"],
        "control_plane_commit": context["control_plane_commit"],
        "candidate_sha": context["candidate_commit"],
        "provider_model": "deepseek-v4-flash",
        "harness_sha256": context["harness_sha256"],
        "input_sha256": "9" * 64,
        "passed": True,
        "answer_material_present": False,
        "formal_evidence": False,
        "release_eligible": False,
        "component_counts": {
            name: {"numerator": 1, "denominator": 1}
            for name in ("security_spec", "hypothesis_hunter", "proof")
        },
        "usage_conservation": conservation,
        "oci_execution_receipt": {"ephemeral_marker": "must-not-persist"},
    }
    receipt_path = tmp_path / "hidden-receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    output = tmp_path / "offline-hidden.json"
    args = argparse.Namespace(
        stage="hidden_holdout",
        suite_file=[receipt_path],
        receipt=receipt_path,
        receipt_sha256=hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        workflow_run_id=context["workflow_run_id"],
        workflow_run_attempt=2,
        attempt_id=context["attempt_id"],
        control_plane_commit=context["control_plane_commit"],
        candidate_commit=context["candidate_commit"],
        harness_sha256=context["harness_sha256"],
        qualification_input_sha256="9" * 64,
        toolchain_evidence=tmp_path / "toolchain.json",
        toolchain_evidence_sha256=context["toolchain_evidence_sha256"],
        canary_env=[],
        output=output,
    )
    monkeypatch.setattr(p6_cli, "_qualification_oci_context", lambda *_args, **_kw: context)
    monkeypatch.setattr(
        p6_cli,
        "_validate_qualification_oci_binding",
        lambda raw, *, context: ("a" * 64,),
    )
    monkeypatch.chdir(tmp_path)

    assert p6_cli._seal_offline_stage(args) == 0

    sealed_text = output.read_text(encoding="utf-8")
    sealed = json.loads(sealed_text)
    assert "ephemeral_marker" not in sealed_text
    assert sealed["oci_execution_sha256s"] == ["a" * 64]
    assert sealed["provider_identity_sha256"] == context["provider_identity_sha256"]


def _stage(stage: str, status: str = "completed", **updates: object) -> dict:
    value = {
        "schema_version": STAGE_RESULT_SCHEMA_VERSION,
        "workflow_run_id": "33260000001",
        "workflow_run_attempt": 1,
        "attempt_id": "p6-attempt-1",
        "control_plane_commit": "c" * 40,
        "stage": stage,
        "status": status,
        "failure_class": None,
        "failure_count": 0,
        "binding_sha256": "a" * 64,
    }
    value.update(updates)
    return value


@pytest.mark.parametrize(
    ("failure_class", "stage"),
    [
        (failure_class, stage)
        for failure_class in (
            "terminal_state_inconsistent",
            "post_proof_call",
            "silent_rejection_without_proof",
        )
        for stage in ("cold_fast", "cold_balanced", "cold_deep")
    ]
    + [
        ("quality_no_progress_gate_failed", stage)
        for stage in (
            "cold_fast",
            "cold_balanced",
            "balanced_quality_gate",
            "cold_deep",
        )
    ]
    + [
        (failure_class, stage)
        for failure_class in (
            "queue_not_drained",
            "accounting_conservation_failure",
            "component_metrics_incomplete",
        )
        for stage in ("cold_fast", "cold_balanced", "cold_deep", "conservation")
    ]
    + [
        (failure_class, stage)
        for failure_class in (
            "provider_identity_mismatch",
            "provider_usage_unverifiable",
            "provider_transport_exhausted",
        )
        for stage in ("provider_probe", "cold_fast", "cold_balanced", "cold_deep")
    ],
)
def test_typed_failure_classes_accept_every_real_producer_boundary(
    failure_class: str, stage: str
) -> None:
    validate_stage_result(
        _stage(
            stage,
            "failed",
            failure_class=failure_class,
            failure_count=1,
        )
    )


@pytest.mark.parametrize(
    ("failure_class", "stage"),
    [
        ("terminal_state_inconsistent", "provider_probe"),
        ("provider_transport_exhausted", "certificate_reverify"),
        ("queue_not_drained", "product_architecture_review"),
    ],
)
def test_typed_failure_classes_reject_unrelated_boundaries(failure_class: str, stage: str) -> None:
    with pytest.raises(P6ProtocolError, match="first execution boundary"):
        validate_stage_result(
            _stage(
                stage,
                "failed",
                failure_class=failure_class,
                failure_count=1,
            )
        )


def _checkpoint(*, complete: bool = True) -> tuple[dict, dict[str, dict]]:
    completed = list(P6_CHECKPOINT_STAGE_ORDER if complete else P6_CHECKPOINT_STAGE_ORDER[:8])
    caches = {
        "fast": {
            "identity_sha256": "9" * 64,
            "empty_at_start": True,
            "reused": False,
        },
        "balanced": {
            "identity_sha256": "a" * 64,
            "empty_at_start": True,
            "reused": False,
        },
        "deep": {
            "identity_sha256": "b" * 64,
            "empty_at_start": True,
            "reused": False,
        },
    }
    payloads = {
        stage: dict(
            build_stage_artifact(
                workflow_run_id="33260000001",
                workflow_run_attempt=1,
                attempt_id="p6-attempt-1",
                control_plane_commit="c" * 40,
                stage=stage,
                candidate_sha256="1" * 64,
                policy_sha256="2" * 64,
                plan_sha256="3" * 64,
                input_sha256="4" * 64,
                runtime_sha256="5" * 64,
                provider_sha256="6" * 64,
                oci_sha256="7" * 64,
                cold_cache_identities=caches,
                payload_sha256=f"{index + 20:064x}",
            )
        )
        for index, stage in enumerate(completed)
    }
    rows = []
    for stage in completed:
        encoded = json.dumps(payloads[stage], ensure_ascii=False, indent=2).encode() + b"\n"
        rows.append(
            {
                "stage": stage,
                "producer_attempt_id": "p6-attempt-1",
                "path": f"{stage}.json",
                "artifact_sha256": hashlib.sha256(encoded).hexdigest(),
                "artifact_schema_version": "zscope.p6-stage-artifact.v1",
                "binding_sha256": payloads[stage]["binding_sha256"],
            }
        )
    checkpoint = {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "workflow_path": P6_WORKFLOW_PATH,
        "workflow_run_id": "33260000001",
        "workflow_run_attempt": 1,
        "attempt_id": "p6-attempt-1",
        "control_plane_commit": "c" * 40,
        "status": "complete" if complete else "partial",
        "completed_stages": completed,
        "stage_artifacts": rows,
        "candidate_sha256": "1" * 64,
        "policy_sha256": "2" * 64,
        "plan_sha256": "3" * 64,
        "input_sha256": "4" * 64,
        "runtime_sha256": "5" * 64,
        "provider_sha256": "6" * 64,
        "oci_sha256": "7" * 64,
        "artifact_root_sha256": artifact_root_sha256(rows),
        "cold_cache_identities": caches,
        "formal_evidence": False,
        "release_eligible": False,
        "requires_full_revalidation": True,
        "zero_call_finalizable": complete,
    }
    return checkpoint, payloads


def _write_artifacts(root: Path, payloads: dict[str, dict]) -> None:
    root.mkdir()
    for stage, payload in payloads.items():
        (root / f"{stage}.json").write_bytes(
            json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
        )


def test_stage_sequence_records_first_failure_and_only_downstream_skips(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    record_stage_result(run_dir, _stage("entry"))
    record_stage_result(
        run_dir,
        _stage(
            "provider_probe",
            "failed",
            failure_class="provider_identity_mismatch",
            failure_count=1,
        ),
    )

    diagnostic = diagnose_pilot(run_dir, run_dir / "diagnostic.json")

    records = load_stage_results(run_dir)
    assert len(records) == len(P6_EXECUTION_STAGE_ORDER)
    assert all(record["status"] == "skipped" for record in records[2:])
    assert diagnostic["stage"] == "provider"
    assert diagnostic["failure_class"] == "provider_identity_mismatch"
    assert public_failure_annotation(diagnostic) == (
        "stage=provider; class=provider_identity_mismatch:1; count=1"
    )


def test_stage_sequence_rejects_success_after_failure() -> None:
    records = [
        _stage("entry", "failed", failure_class="input_binding_failure", failure_count=1),
        _stage("provider_probe"),
    ]

    with pytest.raises(P6ProtocolError, match="after the first failure"):
        validate_stage_sequence(records, require_complete=False)


def test_stage_result_directory_rejects_a_gap(tmp_path: Path) -> None:
    path = tmp_path / "stage-results"
    path.mkdir()
    (path / "provider_probe.json").write_text(
        json.dumps(_stage("provider_probe")), encoding="utf-8"
    )

    with pytest.raises(P6ProtocolError, match="gap"):
        load_stage_results(tmp_path)


def test_complete_checkpoint_is_zero_call_but_remains_non_formal(tmp_path: Path) -> None:
    checkpoint, payloads = _checkpoint()
    root = tmp_path / "stage-artifacts"
    _write_artifacts(root, payloads)

    validate_checkpoint(checkpoint, artifact_root=root)

    assert checkpoint["zero_call_finalizable"] is True
    assert checkpoint["formal_evidence"] is False
    assert checkpoint["release_eligible"] is False


def test_checkpoint_rejects_cross_attempt_artifact_merge() -> None:
    checkpoint, _ = _checkpoint()
    checkpoint["stage_artifacts"][4]["producer_attempt_id"] = "p6-attempt-2"

    with pytest.raises(P6ProtocolError, match="multiple attempts"):
        validate_checkpoint(checkpoint)


def test_checkpoint_rejects_warm_or_shared_cache_identity() -> None:
    checkpoint, _ = _checkpoint()
    checkpoint["cold_cache_identities"]["deep"]["identity_sha256"] = "9" * 64

    with pytest.raises(P6ProtocolError, match="distinct cold caches"):
        validate_checkpoint(checkpoint)


def test_partial_checkpoint_cannot_be_zero_call_finalized() -> None:
    checkpoint, _ = _checkpoint(complete=False)
    checkpoint["zero_call_finalizable"] = True

    with pytest.raises(P6ProtocolError, match="complete P6 checkpoint"):
        validate_checkpoint(checkpoint)


def test_repair_receipt_invalidates_exact_downstream_suffix() -> None:
    receipt = build_repair_receipt(
        failed_attempt_id="p6-attempt-1",
        failure_diagnostic_sha256="1" * 64,
        checkpoint_sha256="2" * 64,
        frozen_failure_artifact_sha256="3" * 64,
        answer_free_reproduction_sha256="4" * 64,
        repair_pr_number=123,
        repair_merge_sha="5" * 40,
        invalidated_from_stage="provider_probe",
        new_attempt_id="p6-attempt-2",
        selected_producer_artifact_sha256="6" * 64,
    )

    validate_repair_receipt(receipt)

    assert receipt["schema_version"] == REPAIR_RECEIPT_SCHEMA_VERSION
    assert receipt["invalidated_stages"] == list(P6_EXECUTION_STAGE_ORDER[1:])


def test_repair_receipt_rejects_selected_producer_from_old_attempt() -> None:
    receipt = dict(
        build_repair_receipt(
            failed_attempt_id="p6-attempt-1",
            failure_diagnostic_sha256="1" * 64,
            checkpoint_sha256="2" * 64,
            frozen_failure_artifact_sha256="3" * 64,
            answer_free_reproduction_sha256="4" * 64,
            repair_pr_number=123,
            repair_merge_sha="5" * 40,
            invalidated_from_stage="cold_fast",
            new_attempt_id="p6-attempt-2",
            selected_producer_artifact_sha256="6" * 64,
        )
    )
    receipt["selected_producer_attempt_id"] = "p6-attempt-1"

    with pytest.raises(P6ProtocolError, match="another attempt"):
        validate_repair_receipt(receipt)


def test_repair_receipt_binds_new_control_plane_to_protected_merge() -> None:
    receipt = dict(
        build_repair_receipt(
            failed_attempt_id="p6-attempt-1",
            failure_diagnostic_sha256="1" * 64,
            checkpoint_sha256="2" * 64,
            frozen_failure_artifact_sha256="3" * 64,
            answer_free_reproduction_sha256="4" * 64,
            repair_pr_number=123,
            repair_merge_sha="5" * 40,
            invalidated_from_stage="provider_probe",
            new_attempt_id="p6-attempt-2",
            selected_producer_artifact_sha256="6" * 64,
        )
    )
    receipt["control_plane_commit"] = "7" * 40

    with pytest.raises(P6ProtocolError, match="protected merge"):
        validate_repair_receipt(receipt)


def test_repair_receipt_bundle_requires_a_typed_new_attempt_producer(
    tmp_path: Path,
) -> None:
    checkpoint, _payloads = _checkpoint(complete=False)
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_path.write_text(
        json.dumps(checkpoint, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    checkpoint_sha = hashlib.sha256(checkpoint_path.read_bytes()).hexdigest()
    diagnostic = {
        "schema_version": "zscope.p6-failure-diagnostic.v1",
        "workflow_run_id": "33260000001",
        "workflow_run_attempt": 1,
        "attempt_id": "p6-attempt-1",
        "control_plane_commit": "c" * 40,
        "stage": "provider",
        "failure_class": "provider_identity_mismatch",
        "failure_count": 1,
        "total_count": 1,
        "checkpoint_sha256": checkpoint_sha,
        "binding_sha256": "a" * 64,
        "formal_evidence": False,
        "release_eligible": False,
    }
    diagnostic_path = tmp_path / "diagnostic.json"
    diagnostic_path.write_text(
        json.dumps(diagnostic, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    selected = dict(
        build_stage_artifact(
            workflow_run_id="33260000002",
            workflow_run_attempt=1,
            attempt_id="p6-attempt-2",
            control_plane_commit="d" * 40,
            stage="provider_probe",
            candidate_sha256="8" * 64,
            policy_sha256="2" * 64,
            plan_sha256="3" * 64,
            input_sha256="4" * 64,
            runtime_sha256="5" * 64,
            provider_sha256="6" * 64,
            oci_sha256="7" * 64,
            cold_cache_identities=checkpoint["cold_cache_identities"],
            payload_sha256="9" * 64,
        )
    )
    selected_path = tmp_path / "selected.json"
    selected_path.write_text(
        json.dumps(selected, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    receipt = build_repair_receipt(
        failed_attempt_id="p6-attempt-1",
        failure_diagnostic_sha256=hashlib.sha256(diagnostic_path.read_bytes()).hexdigest(),
        checkpoint_sha256=checkpoint_sha,
        frozen_failure_artifact_sha256="3" * 64,
        answer_free_reproduction_sha256="4" * 64,
        repair_pr_number=123,
        repair_merge_sha="d" * 40,
        invalidated_from_stage="provider_probe",
        new_attempt_id="p6-attempt-2",
        selected_producer_artifact_sha256=hashlib.sha256(selected_path.read_bytes()).hexdigest(),
    )

    validate_repair_receipt_bundle(
        receipt,
        failure_diagnostic_path=diagnostic_path,
        checkpoint_path=checkpoint_path,
        selected_producer_path=selected_path,
    )

    selected = dict(
        build_stage_artifact(
            workflow_run_id="33260000002",
            workflow_run_attempt=1,
            attempt_id="p6-attempt-3",
            control_plane_commit="d" * 40,
            stage="provider_probe",
            candidate_sha256="8" * 64,
            policy_sha256="2" * 64,
            plan_sha256="3" * 64,
            input_sha256="4" * 64,
            runtime_sha256="5" * 64,
            provider_sha256="6" * 64,
            oci_sha256="7" * 64,
            cold_cache_identities=checkpoint["cold_cache_identities"],
            payload_sha256="9" * 64,
        )
    )
    selected_path.write_text(
        json.dumps(selected, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    receipt = dict(receipt)
    receipt["selected_producer_artifact_sha256"] = hashlib.sha256(
        selected_path.read_bytes()
    ).hexdigest()
    with pytest.raises(P6ProtocolError, match="producer attempt"):
        validate_repair_receipt_bundle(
            receipt,
            failure_diagnostic_path=diagnostic_path,
            checkpoint_path=checkpoint_path,
            selected_producer_path=selected_path,
        )


def test_pilot_request_is_single_cpp_cold_run() -> None:
    require_pilot_request(language="c_cpp", mode="pilot", runs=1)

    with pytest.raises(P6ProtocolError, match="exactly one"):
        require_pilot_request(language="c_cpp", mode="pilot", runs=2)
    with pytest.raises(P6ProtocolError, match="forbids"):
        require_pilot_request(language="c_cpp", mode="pilot", runs=1, resume=True)
    with pytest.raises(P6ProtocolError, match=r"C/C\+\+"):
        require_pilot_request(language="java", mode="pilot", runs=1)


def test_protocol_json_schemas_are_strict_and_packaged() -> None:
    root = Path(__file__).resolve().parents[1] / "zscope" / "benchmarking"
    for name in (
        "p6_failure_diagnostic.schema.json",
        "p6_checkpoint.schema.json",
        "p6_repair_receipt.schema.json",
        "p6_stage_artifact.schema.json",
        "p6_toolchain_oci_evidence.schema.json",
    ):
        value = json.loads((root / name).read_text(encoding="utf-8"))
        assert value["additionalProperties"] is False


def test_certificate_reverify_receipt_is_strictly_self_and_manifest_bound(
    tmp_path: Path,
) -> None:
    body = {
        "schema_version": "zscope.v3-trace-reverification.v1",
        "workflow_run_id": "33260000001",
        "workflow_run_attempt": 1,
        "control_plane_commit": "c" * 40,
        "candidate_git_sha": "c" * 40,
        "trace_manifest_sha256": "1" * 64,
        "trace_manifest_file_sha256": "2" * 64,
        "trace_manifest_complete": True,
        "cluster_count": 2,
        "terminal_trace_count": 2,
        "v3_entered_cluster_count": 1,
        "v3_entered_with_empty_required_facts": 0,
        "verifier_cluster_count": 1,
        "claim_count": 2,
        "classification_counts": {"verified": 2},
        "fact_kind_counts": {"range": 2},
        "passed": True,
        "llm_calls": 0,
        "truth_inputs": 0,
        "answer_material_present": False,
        "formal_evidence": False,
        "release_eligible": False,
    }
    payload = {**body, "evidence_sha256": canonical_sha256(body)}
    path = tmp_path / "v3-reverify.json"
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()

    p6_cli._validate_reverify_receipt(
        path,
        digest,
        expected_control_plane_commit="c" * 40,
        expected_candidate_commit="c" * 40,
        expected_workflow_run_id="33260000001",
        expected_workflow_run_attempt=1,
        expected_trace_manifest_sha256="1" * 64,
        expected_trace_manifest_file_sha256="2" * 64,
    )

    payload["llm_calls"] = 1
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    with pytest.raises(P6ProtocolError, match="lineage"):
        p6_cli._validate_reverify_receipt(
            path,
            hashlib.sha256(path.read_bytes()).hexdigest(),
            expected_control_plane_commit="c" * 40,
            expected_candidate_commit="c" * 40,
            expected_workflow_run_id="33260000001",
            expected_workflow_run_attempt=1,
            expected_trace_manifest_sha256="1" * 64,
            expected_trace_manifest_file_sha256="2" * 64,
        )
