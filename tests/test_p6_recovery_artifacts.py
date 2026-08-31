import argparse
import copy
import hashlib
import json
import os
import stat
import zipfile
from pathlib import Path

import pytest

from scripts import download_p6_run_artifact as p6_download
from scripts import p6_pilot_protocol as p6_cli
from zscope.benchmarking import p6_protocol
from zscope.benchmarking.p6_protocol import (
    CHECKPOINT_SCHEMA_VERSION,
    P6ProtocolError,
    P6_CHECKPOINT_STAGE_ORDER,
    P6_EXECUTION_STAGE_ORDER,
    P6_WORKFLOW_PATH,
    answer_free_projection,
    artifact_root_sha256,
    build_qualification_from_projections,
    build_stage_artifact,
    seal_toolchain_evidence,
    emit_workflow_failure,
    public_failure_annotation,
    record_stage_result,
    canonical_sha256,
    validate_answer_free_artifact,
    validate_checkpoint,
    validate_pilot_aggregate,
    validate_provider_probe,
    validate_safe_zip,
    validate_toolchain_evidence,
)


def _caches() -> dict[str, dict[str, object]]:
    return {
        "fast": {"identity_sha256": "8" * 64, "empty_at_start": True, "reused": False},
        "balanced": {
            "identity_sha256": "9" * 64,
            "empty_at_start": True,
            "reused": False,
        },
        "deep": {"identity_sha256": "a" * 64, "empty_at_start": True, "reused": False},
    }


def _usage_conservation(calls: int = 3) -> dict[str, object]:
    return {
        "physical_call_count": calls,
        "provider_reported_call_count": calls,
        "estimated_call_count": 0,
        "provider_usage_coverage": 1.0,
        "requested_model": "GLM-5.2",
        "requested_model_coverage": 1.0,
        "response_model": "GLM-5.2",
        "response_model_coverage": 1.0,
        "queue_empty": True,
        "dimensions": {
            name: {"numerator": calls, "denominator": calls, "conserved": True}
            for name in ("token", "tool", "trace", "finding", "terminal")
        },
    }


def _depth_cache_sha256(depth: str) -> str:
    return hashlib.sha256(f"33260000001:2:{depth}".encode("utf-8")).hexdigest()


def _provider_probe() -> dict[str, object]:
    usage = _usage_conservation(1)
    for name in ("tool", "trace", "finding", "terminal"):
        usage["dimensions"][name] = {
            "numerator": 0,
            "denominator": 0,
            "conserved": True,
        }
    return {
        "schema_version": "zscope.p6-provider-probe.v1",
        "stage": "provider",
        "passed": True,
        "call_count": 1,
        "provider_usage_coverage": 1.0,
        "estimated_provider_call_count": 0,
        "provider_identity_sha256": "7" * 64,
        "config_sha256": "6" * 64,
        "model": "GLM-5.2",
        "usage_conservation": usage,
    }


def _toolchain_evidence() -> dict[str, object]:
    commit = "1" * 40
    draft = {
        "schema_version": "zscope.p6-toolchain-oci-evidence.v1",
        "workflow_path": P6_WORKFLOW_PATH,
        "workflow_run_id": "33260000001",
        "workflow_run_attempt": 2,
        "attempt_id": "p6-33260000001-2",
        "control_plane_commit": "c" * 40,
        "candidate_sha256": hashlib.sha256(commit.encode()).hexdigest(),
        "candidate_git_sha": commit,
        "candidate_git_tree": "2" * 40,
        "image_ref": "registry.invalid/zscope@sha256:" + "3" * 64,
        "image_digest": "sha256:" + "3" * 64,
        "image_id": "sha256:" + "4" * 64,
        "runtime_source_sha256": "5" * 64,
        "oci_execution_sha256": "6" * 64,
        "rootless_verified": True,
        "image_digest_verified": True,
        "mounts_verified": True,
        "network_restriction_verified": True,
        "runtime_source_mounted": True,
        "formal_evidence": False,
        "release_eligible": False,
    }
    return dict(seal_toolchain_evidence(draft))


def _pilot_aggregate(
    *,
    git_sha: str = "1" * 40,
    git_tree: str = "2" * 40,
    scan_depth: str = "fast",
) -> dict:
    toolchain = _toolchain_evidence()
    seed = {"fast": "a", "balanced": "b", "deep": "d"}[scan_depth]
    mounts = [
        {
            "source": "/sealed/input",
            "destination": "/zscope-input",
            "purpose": "scan_input",
            "read_only": True,
            "type": "bind",
        },
        {
            "source": "/sealed/output",
            "destination": "/zscope-output",
            "purpose": "artifact_output",
            "read_only": False,
            "type": "bind",
        },
        {
            "source": "/sealed/cache",
            "destination": "/zscope-cache",
            "purpose": "cache",
            "read_only": False,
            "type": "bind",
        },
        {
            "source": "/sealed/runtime",
            "destination": "/zscope-runtime/zscope",
            "purpose": "runtime_source",
            "read_only": True,
            "type": "bind",
        },
    ]
    phase = {
        "phase": "scan",
        "container_name": f"zscope-benchmark-scan-{seed * 12}",
        "container_id": seed * 64,
        "command_return_code": 0,
        "container_exit_code": 0,
        "accepted_returncodes": [0, 1, 2],
        "working_dir": "/zscope-input",
        "image": toolchain["image_ref"],
        "image_id": toolchain["image_id"],
        "image_verified": True,
        "read_only_rootfs": True,
        "cap_drop": ["ALL"],
        "cap_drop_verified": True,
        "security_opt": ["no-new-privileges"],
        "security_verified": True,
        "scanner_labels_verified": True,
        "p6_cleanup_scope_verified": True,
        "p6_workflow_run_id": toolchain["workflow_run_id"],
        "p6_workflow_run_attempt": toolchain["workflow_run_attempt"],
        "p6_attempt_id": toolchain["attempt_id"],
        "p6_repository": "example/zscope",
        "p6_concurrency_group": "p6-pilot-validation",
        "p6_phase": "scan",
        "scanner_provider_environment_verified": True,
        "scanner_provider_environment_keys": ["Z_SCOPE_API_KEY"],
        "stdout_persisted": False,
        "stderr_persisted": False,
        "mounts": mounts,
        "unexpected_mount_count": 0,
        "network_name": "p6-model-only",
        "runtime_network_mode": "p6-model-only",
        "network_attachment_verified": True,
        "network_peer_count": 2,
        "network_peers_verified": True,
        "network_internal": True,
        "network_contract_verified": True,
        "proxy_verified": True,
        "proxy_credential_metadata_safe": True,
        "provider_identity_sha256": "7" * 64,
        "container_inspect_sha256": seed * 64,
        "proxy_inspect_sha256": "e" * 64,
        "network_inspect_sha256": "f" * 64,
        "network_membership_sha256": "0" * 64,
        "inspect_verified": True,
        "cancellation_cleanup_guard_verified": True,
    }
    isolation = {
        "schema_version": "zscope.benchmark-isolation.v1",
        "mode": "oci",
        "runtime": "podman",
        "runtime_path": "/usr/bin/podman",
        "image": toolchain["image_ref"],
        "available": True,
        "runtime_info_sha256": "1" * 64,
        "image_inspect_sha256": "2" * 64,
        "image_id": toolchain["image_id"],
        "network_inspect_sha256": "3" * 64,
        "network_membership_sha256": "4" * 64,
        "proxy_inspect_sha256": "5" * 64,
        "rootless_verified": True,
        "image_digest_verified": True,
        "network_internal": True,
        "network_policy_sha256": "6" * 64,
        "network_name": "p6-model-only",
        "endpoint_origin": "https://models.example:443",
        "provider_identity_sha256": "7" * 64,
        "proxy_credential_metadata_safe": True,
        "proxy_container_id": "8" * 64,
        "proxy_running": True,
        "execution_verified": True,
        "actual_inspection_collected": True,
        "release_capable": True,
        "mounts_verified": True,
        "security_verified": True,
        "network_restriction_verified": True,
        "repository_mounted": False,
        "truth_mounted": False,
        "runtime_source_mounted": True,
        "runtime_source_sha256": toolchain["runtime_source_sha256"],
        "scanner_cwd": "/zscope-input",
        "scanner_cwd_isolated": True,
        "mounts": mounts,
        "network_mode": "model-endpoint-only",
        "phase_executions": [phase],
        "required_phases": ["scan"],
        "errors": [],
    }
    metrics = {
        "usage_accounting": {
            "complete": True,
            "conservation_passed": True,
            "provider_usage_coverage": 1.0,
            "totals": {
                "call_count": 3,
                "estimated_or_conservative_calls": 0,
                "failed_or_unknown_calls": 0,
                "budget_violation_count": 0,
            },
        },
        "token_conservation_passed": True,
        "provider_usage_coverage": 1.0,
        "provider_response_model_coverage": 1.0,
        "provider_response_model_missing_count": 0,
        "provider_response_model_mismatch_count": 0,
        "requested_model_mismatch_count": 0,
        "telemetry_complete_rate": 1.0,
        "protocol_anomaly_count": 0,
        "candidate_funnel": {"v3_investigation": {"eligible": 2, "entered": 2}},
        "p6_conservation": _usage_conservation(),
    }
    return {
        "language": "cpp",
        "mode": "pilot",
        "scan_depth": scan_depth,
        "formal_benchmark": False,
        "release_eligible": False,
        "cold_runs": 1,
        "all_completed": True,
        "passed": True,
        "git_sha": git_sha,
        "git_tree": git_tree,
        "runs": [
            {
                "completed": True,
                "formal_benchmark": False,
                "release_eligible": False,
                "queue_empty": True,
                "gate_failures": [],
                "metrics": metrics,
                "isolation": isolation,
                "cold_cache": {
                    "identity_sha256": _depth_cache_sha256(scan_depth),
                    "empty_at_start": True,
                    "reused": False,
                },
                "provenance": {
                    "provider_runtime": {
                        "model": "GLM-5.2",
                        "base_url": "https://st8tp3ajl0df3n8b8l8qu.apigateway-cn-beijing.volceapi.com/v1",
                        "required_environment_keys": ["Z_SCOPE_API_KEY"],
                        "identity_sha256": "7" * 64,
                    }
                },
            }
        ],
    }


def _materialize_checkpoint(root: Path, *, complete: bool = True) -> tuple[dict, Path]:
    stages = list(P6_CHECKPOINT_STAGE_ORDER if complete else P6_CHECKPOINT_STAGE_ORDER[:4])
    artifacts_root = root / "stage-artifacts"
    artifacts_root.mkdir(parents=True)
    rows = []
    for index, stage in enumerate(stages):
        payload = build_stage_artifact(
            workflow_run_id="33260000001",
            workflow_run_attempt=2,
            attempt_id="p6-33260000001-2",
            control_plane_commit="c" * 40,
            stage=stage,
            candidate_sha256="1" * 64,
            policy_sha256="2" * 64,
            plan_sha256="3" * 64,
            input_sha256="4" * 64,
            runtime_sha256="5" * 64,
            provider_sha256="6" * 64,
            oci_sha256="7" * 64,
            cold_cache_identities=_caches(),
            payload_sha256=f"{index + 20:064x}",
        )
        path = artifacts_root / f"{stage}.json"
        path.write_bytes(json.dumps(payload, indent=2).encode() + b"\n")
        rows.append(
            {
                "stage": stage,
                "producer_attempt_id": "p6-33260000001-2",
                "path": path.name,
                "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "artifact_schema_version": "zscope.p6-stage-artifact.v1",
                "binding_sha256": payload["binding_sha256"],
            }
        )
    checkpoint = {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "workflow_path": P6_WORKFLOW_PATH,
        "workflow_run_id": "33260000001",
        "workflow_run_attempt": 2,
        "attempt_id": "p6-33260000001-2",
        "control_plane_commit": "c" * 40,
        "status": "complete" if complete else "partial",
        "completed_stages": stages,
        "stage_artifacts": rows,
        "candidate_sha256": "1" * 64,
        "policy_sha256": "2" * 64,
        "plan_sha256": "3" * 64,
        "input_sha256": "4" * 64,
        "runtime_sha256": "5" * 64,
        "provider_sha256": "6" * 64,
        "oci_sha256": "7" * 64,
        "artifact_root_sha256": artifact_root_sha256(rows),
        "cold_cache_identities": _caches(),
        "formal_evidence": False,
        "release_eligible": False,
        "requires_full_revalidation": True,
        "zero_call_finalizable": complete,
    }
    return checkpoint, artifacts_root


def test_checkpoint_recomputes_each_restored_file(tmp_path: Path) -> None:
    checkpoint, root = _materialize_checkpoint(tmp_path)
    target = root / "cold_fast.json"
    target.write_bytes(target.read_bytes() + b" ")

    with pytest.raises(P6ProtocolError, match="restored artifact hash"):
        validate_checkpoint(checkpoint, artifact_root=root)


def test_checkpoint_rejects_forged_root_and_unbound_file(tmp_path: Path) -> None:
    checkpoint, root = _materialize_checkpoint(tmp_path)
    forged = copy.deepcopy(checkpoint)
    forged["artifact_root_sha256"] = "f" * 64
    with pytest.raises(P6ProtocolError, match="artifact root hash"):
        validate_checkpoint(forged, artifact_root=root)

    (root / "extra.json").write_text("{}", encoding="utf-8")
    with pytest.raises(P6ProtocolError, match="unbound files"):
        validate_checkpoint(checkpoint, artifact_root=root)


def test_checkpoint_rejects_forged_control_plane_lineage(tmp_path: Path) -> None:
    checkpoint, root = _materialize_checkpoint(tmp_path)
    checkpoint["control_plane_commit"] = "d" * 40

    with pytest.raises(P6ProtocolError, match="stage artifact lineage"):
        validate_checkpoint(checkpoint, artifact_root=root)


def test_complete_checkpoint_requires_restoration_and_partial_is_diagnostic_only(
    tmp_path: Path,
) -> None:
    complete, _ = _materialize_checkpoint(tmp_path / "complete")
    with pytest.raises(P6ProtocolError, match="requires restored"):
        validate_checkpoint(complete)

    partial, partial_root = _materialize_checkpoint(tmp_path / "partial", complete=False)
    validate_checkpoint(partial, artifact_root=partial_root)
    partial["zero_call_finalizable"] = True
    with pytest.raises(P6ProtocolError, match="only a complete"):
        validate_checkpoint(partial, artifact_root=partial_root)


def _finalize_fixture(tmp_path: Path) -> tuple[argparse.Namespace, bytes, Path]:
    checkpoint, artifact_root = _materialize_checkpoint(tmp_path)
    payload = tmp_path / "final-evidence.json"
    payload_bytes = b'{"schema_version":"zscope.p6-final-evidence.v1","passed":true}\n'
    payload.write_bytes(payload_bytes)
    final_path = artifact_root / "final_evidence_seal.json"
    final_artifact = build_stage_artifact(
        workflow_run_id="33260000001",
        workflow_run_attempt=2,
        attempt_id="p6-33260000001-2",
        control_plane_commit="c" * 40,
        stage="final_evidence_seal",
        candidate_sha256="1" * 64,
        policy_sha256="2" * 64,
        plan_sha256="3" * 64,
        input_sha256="4" * 64,
        runtime_sha256="5" * 64,
        provider_sha256="6" * 64,
        oci_sha256="7" * 64,
        cold_cache_identities=_caches(),
        payload_sha256=hashlib.sha256(payload_bytes).hexdigest(),
    )
    final_path.write_bytes(json.dumps(final_artifact, indent=2).encode() + b"\n")
    final_row = checkpoint["stage_artifacts"][-1]
    final_row["artifact_sha256"] = hashlib.sha256(final_path.read_bytes()).hexdigest()
    final_row["binding_sha256"] = final_artifact["binding_sha256"]
    checkpoint["artifact_root_sha256"] = artifact_root_sha256(checkpoint["stage_artifacts"])
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
    run_dir = tmp_path / "run"
    for row in checkpoint["stage_artifacts"]:
        record_stage_result(
            run_dir,
            {
                "schema_version": "zscope.p6-stage-result.v1",
                "workflow_run_id": "33260000001",
                "workflow_run_attempt": 2,
                "attempt_id": "p6-33260000001-2",
                "control_plane_commit": "c" * 40,
                "stage": row["stage"],
                "status": "completed",
                "failure_class": None,
                "failure_count": 0,
                "binding_sha256": row["binding_sha256"],
            },
        )
    args = argparse.Namespace(
        checkpoint=checkpoint_path,
        artifact_root=artifact_root,
        run_dir=run_dir,
        payload=payload,
        output=tmp_path / "finalized.json",
        workflow_run_id="33260000001",
        workflow_run_attempt=2,
        attempt_id="p6-33260000001-2",
        control_plane_commit="c" * 40,
        candidate_sha256="1" * 64,
        policy_sha256="2" * 64,
        plan_sha256="3" * 64,
        input_sha256="4" * 64,
        runtime_sha256="5" * 64,
        provider_sha256="6" * 64,
        oci_sha256="7" * 64,
        fast_cache_sha256="8" * 64,
        balanced_cache_sha256="9" * 64,
        deep_cache_sha256="a" * 64,
        canary_env=[],
    )
    return args, payload_bytes, payload


def test_finalize_uses_single_payload_read_when_path_is_exchanged(
    monkeypatch, tmp_path: Path
) -> None:
    args, original_bytes, payload = _finalize_fixture(tmp_path)
    secure_read = p6_cli.read_regular_file_once

    def exchange_after_read(path: Path, **kwargs):
        data = secure_read(path, **kwargs)
        if path.absolute() == payload.absolute():
            replacement = payload.with_suffix(".replacement")
            replacement.write_text('{"changed":true}\n', encoding="utf-8")
            os.replace(replacement, payload)
        return data

    monkeypatch.setattr(p6_cli, "read_regular_file_once", exchange_after_read)
    assert p6_cli._finalize_checkpoint(args) == 0
    assert args.output.read_bytes() == original_bytes
    assert payload.read_bytes() != original_bytes


def test_finalize_uses_validated_final_seal_bytes_when_path_is_exchanged(
    monkeypatch, tmp_path: Path
) -> None:
    args, original_bytes, _ = _finalize_fixture(tmp_path)
    final_seal = args.artifact_root / "final_evidence_seal.json"
    secure_read = p6_protocol.read_regular_file_once

    def exchange_after_read(path: Path, **kwargs):
        data = secure_read(path, **kwargs)
        if path.absolute() == final_seal.absolute():
            replacement = final_seal.with_suffix(".replacement")
            replacement.write_text('{"changed":true}\n', encoding="utf-8")
            os.replace(replacement, final_seal)
        return data

    monkeypatch.setattr(p6_protocol, "read_regular_file_once", exchange_after_read)
    assert p6_cli._finalize_checkpoint(args) == 0
    assert args.output.read_bytes() == original_bytes
    assert final_seal.read_text(encoding="utf-8") == '{"changed":true}\n'


def test_finalize_rejects_symbolic_link_payload(tmp_path: Path) -> None:
    args, _, payload = _finalize_fixture(tmp_path)
    target = payload.with_suffix(".target")
    target.write_bytes(payload.read_bytes())
    payload.unlink()
    try:
        payload.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable")
    with pytest.raises(P6ProtocolError, match="regular file"):
        p6_cli._finalize_checkpoint(args)


def test_finalize_rejects_stage_result_control_plane_mix(tmp_path: Path) -> None:
    args, _, _ = _finalize_fixture(tmp_path)
    record_path = args.run_dir / "stage-results" / "cold_fast.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["control_plane_commit"] = "d" * 40
    record_path.write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(
        P6ProtocolError,
        match="stage sequence mixes workflow attempts|stage-result lineage",
    ):
        p6_cli._finalize_checkpoint(args)


def test_checkpoint_rejects_attempt_and_provider_lineage_mix(tmp_path: Path) -> None:
    checkpoint, root = _materialize_checkpoint(tmp_path)
    path = root / "cold_balanced.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["provider_sha256"] = "b" * 64
    # Even re-binding and re-hashing the forged row cannot cross the checkpoint lineage.
    payload["binding_sha256"] = build_stage_artifact(
        workflow_run_id=payload["workflow_run_id"],
        workflow_run_attempt=payload["workflow_run_attempt"],
        attempt_id=payload["attempt_id"],
        control_plane_commit=payload["control_plane_commit"],
        stage=payload["stage"],
        candidate_sha256=payload["candidate_sha256"],
        policy_sha256=payload["policy_sha256"],
        plan_sha256=payload["plan_sha256"],
        input_sha256=payload["input_sha256"],
        runtime_sha256=payload["runtime_sha256"],
        provider_sha256=payload["provider_sha256"],
        oci_sha256=payload["oci_sha256"],
        cold_cache_identities=_caches(),
        payload_sha256=payload["payload_sha256"],
    )["binding_sha256"]
    path.write_bytes(json.dumps(payload, indent=2).encode() + b"\n")
    row = checkpoint["stage_artifacts"][9]
    row["artifact_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    row["binding_sha256"] = payload["binding_sha256"]
    checkpoint["artifact_root_sha256"] = artifact_root_sha256(checkpoint["stage_artifacts"])

    with pytest.raises(P6ProtocolError, match="lineage"):
        validate_checkpoint(checkpoint, artifact_root=root)


def test_safe_zip_rejects_traversal_and_symbolic_link(tmp_path: Path) -> None:
    traversal = tmp_path / "traversal.zip"
    with zipfile.ZipFile(traversal, "w") as bundle:
        bundle.writestr("../escape.json", "{}")
    with pytest.raises(P6ProtocolError, match="path traversal"):
        validate_safe_zip(traversal)

    link_zip = tmp_path / "link.zip"
    link = zipfile.ZipInfo("linked.json")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(link_zip, "w") as bundle:
        bundle.writestr(link, "target.json")
    with pytest.raises(P6ProtocolError, match="link or special"):
        validate_safe_zip(link_zip)


def test_toolchain_evidence_binds_runtime_source_and_candidate() -> None:
    evidence = _toolchain_evidence()
    validate_toolchain_evidence(
        evidence,
        expected_run_id="33260000001",
        expected_run_attempt=2,
        expected_attempt_id="p6-33260000001-2",
        expected_control_plane_commit="c" * 40,
        expected_git_sha="1" * 40,
        expected_git_tree="2" * 40,
    )

    forged = dict(evidence)
    forged["runtime_source_sha256"] = "f" * 64
    with pytest.raises(P6ProtocolError, match="evidence hash"):
        validate_toolchain_evidence(forged)

    with pytest.raises(P6ProtocolError, match="control-plane commit"):
        validate_toolchain_evidence(
            evidence,
            expected_control_plane_commit="d" * 40,
        )


def test_depth_projection_requires_exact_git_oci_and_runtime_source() -> None:
    evidence = _toolchain_evidence()
    projection = validate_pilot_aggregate(
        _pilot_aggregate(),
        scan_depth="fast",
        expected_control_plane_commit="c" * 40,
        expected_git_sha="1" * 40,
        expected_git_tree="2" * 40,
        toolchain_evidence=evidence,
        toolchain_evidence_file_sha256="8" * 64,
    )
    assert projection["runtime_source_sha256"] == "5" * 64
    assert projection["oci_image_id"] == "sha256:" + "4" * 64
    assert projection["toolchain_oci_execution_sha256"] == evidence["oci_execution_sha256"]
    assert projection["oci_execution_sha256"] == canonical_sha256(
        _pilot_aggregate()["runs"][0]["isolation"]
    )
    assert projection["oci_execution_sha256"] != projection["toolchain_oci_execution_sha256"]
    assert projection["cache_identity_sha256"] == _depth_cache_sha256("fast")
    assert projection["cache_empty_at_start"] is True
    assert projection["cache_reused"] is False

    with pytest.raises(P6ProtocolError, match="input_binding_failure"):
        validate_pilot_aggregate(
            _pilot_aggregate(git_sha=""),
            scan_depth="fast",
            expected_control_plane_commit="c" * 40,
            expected_git_sha="1" * 40,
            expected_git_tree="2" * 40,
            toolchain_evidence=evidence,
            toolchain_evidence_file_sha256="8" * 64,
        )

    leaky = _pilot_aggregate()
    leaky["runs"][0]["isolation"]["phase_executions"][0]["stdout_persisted"] = True
    with pytest.raises(P6ProtocolError, match="oci_isolation_violation"):
        validate_pilot_aggregate(
            leaky,
            scan_depth="fast",
            expected_control_plane_commit="c" * 40,
            expected_git_sha="1" * 40,
            expected_git_tree="2" * 40,
            toolchain_evidence=evidence,
            toolchain_evidence_file_sha256="8" * 64,
        )

    warm = _pilot_aggregate()
    warm["runs"][0]["cold_cache"]["empty_at_start"] = False
    with pytest.raises(P6ProtocolError, match="cold_cache_not_isolated"):
        validate_pilot_aggregate(
            warm,
            scan_depth="fast",
            expected_control_plane_commit="c" * 40,
            expected_git_sha="1" * 40,
            expected_git_tree="2" * 40,
            toolchain_evidence=evidence,
            toolchain_evidence_file_sha256="8" * 64,
        )

    mismatched = _pilot_aggregate()
    mismatched["runs"][0]["isolation"]["runtime_source_sha256"] = "9" * 64
    with pytest.raises(P6ProtocolError, match="oci_isolation_violation"):
        validate_pilot_aggregate(
            mismatched,
            scan_depth="fast",
            expected_control_plane_commit="c" * 40,
            expected_git_sha="1" * 40,
            expected_git_tree="2" * 40,
            toolchain_evidence=evidence,
            toolchain_evidence_file_sha256="8" * 64,
        )


def test_depth_projection_rejects_forged_global_conservation() -> None:
    evidence = _toolchain_evidence()
    aggregate = _pilot_aggregate()
    aggregate["runs"][0]["metrics"]["p6_conservation"]["dimensions"]["terminal"]["denominator"] = 4
    with pytest.raises(P6ProtocolError, match="accounting_conservation_failure"):
        validate_pilot_aggregate(
            aggregate,
            scan_depth="fast",
            expected_control_plane_commit="c" * 40,
            expected_git_sha="1" * 40,
            expected_git_tree="2" * 40,
            toolchain_evidence=evidence,
            toolchain_evidence_file_sha256="8" * 64,
        )


def test_qualification_binds_physical_provider_probe_and_global_usage() -> None:
    toolchain = _toolchain_evidence()
    probe = _provider_probe()
    validate_provider_probe(probe)
    projections = {}
    for depth in ("fast", "balanced", "deep"):
        aggregate = _pilot_aggregate(scan_depth=depth)
        projections[depth] = validate_pilot_aggregate(
            aggregate,
            scan_depth=depth,
            expected_control_plane_commit="c" * 40,
            expected_git_sha="1" * 40,
            expected_git_tree="2" * 40,
            toolchain_evidence=toolchain,
            toolchain_evidence_file_sha256="8" * 64,
        )
    qualification = build_qualification_from_projections(
        projections=projections,
        projection_file_sha256s={
            "fast": "b" * 64,
            "balanced": "c" * 64,
            "deep": "d" * 64,
        },
        cache_identity_sha256s={
            depth: _depth_cache_sha256(depth) for depth in ("fast", "balanced", "deep")
        },
        candidate_sha256=toolchain["candidate_sha256"],
        policy_sha256="e" * 64,
        offline_evidence_sha256="f" * 64,
        offline_usage_conservation=_usage_conservation(3),
        provider_probe=probe,
        provider_probe_file_sha256="0" * 64,
        toolchain_evidence=toolchain,
        toolchain_evidence_file_sha256="8" * 64,
        control_plane_commit="c" * 40,
        attempt_id="p6-33260000001-2",
    )
    assert qualification["provider_probe"]["artifact_sha256"] == "0" * 64
    assert qualification["usage_conservation"]["physical_call_count"] == 13

    mismatched = copy.deepcopy(probe)
    mismatched["provider_identity_sha256"] = "1" * 64
    with pytest.raises(P6ProtocolError, match="mix producer identities"):
        build_qualification_from_projections(
            projections=projections,
            projection_file_sha256s={
                "fast": "b" * 64,
                "balanced": "c" * 64,
                "deep": "d" * 64,
            },
            cache_identity_sha256s={
                depth: _depth_cache_sha256(depth) for depth in ("fast", "balanced", "deep")
            },
            candidate_sha256=toolchain["candidate_sha256"],
            policy_sha256="e" * 64,
            offline_evidence_sha256="f" * 64,
            offline_usage_conservation=_usage_conservation(3),
            provider_probe=mismatched,
            provider_probe_file_sha256="0" * 64,
            toolchain_evidence=toolchain,
            toolchain_evidence_file_sha256="8" * 64,
            control_plane_commit="c" * 40,
            attempt_id="p6-33260000001-2",
        )

    mixed = copy.deepcopy(projections)
    mixed["deep"] = copy.deepcopy(projections["balanced"])
    mixed["deep"]["scan_depth"] = "deep"
    mixed["deep"]["cache_identity_sha256"] = _depth_cache_sha256("deep")
    mixed["deep"]["artifact_sha256"] = "f" * 64
    with pytest.raises(P6ProtocolError, match="mix producer identities"):
        build_qualification_from_projections(
            projections=mixed,
            projection_file_sha256s={
                "fast": "b" * 64,
                "balanced": "c" * 64,
                "deep": "d" * 64,
            },
            cache_identity_sha256s={
                depth: _depth_cache_sha256(depth) for depth in ("fast", "balanced", "deep")
            },
            candidate_sha256=toolchain["candidate_sha256"],
            policy_sha256="e" * 64,
            offline_evidence_sha256="f" * 64,
            offline_usage_conservation=_usage_conservation(3),
            provider_probe=probe,
            provider_probe_file_sha256="0" * 64,
            toolchain_evidence=toolchain,
            toolchain_evidence_file_sha256="8" * 64,
            control_plane_commit="c" * 40,
            attempt_id="p6-33260000001-2",
        )

    wrong_cache = {depth: _depth_cache_sha256(depth) for depth in ("fast", "balanced", "deep")}
    wrong_cache["deep"] = "1" * 64
    with pytest.raises(P6ProtocolError, match="producer lineage"):
        build_qualification_from_projections(
            projections=projections,
            projection_file_sha256s={
                "fast": "b" * 64,
                "balanced": "c" * 64,
                "deep": "d" * 64,
            },
            cache_identity_sha256s=wrong_cache,
            candidate_sha256=toolchain["candidate_sha256"],
            policy_sha256="e" * 64,
            offline_evidence_sha256="f" * 64,
            offline_usage_conservation=_usage_conservation(3),
            provider_probe=probe,
            provider_probe_file_sha256="0" * 64,
            toolchain_evidence=toolchain,
            toolchain_evidence_file_sha256="8" * 64,
            control_plane_commit="c" * 40,
            attempt_id="p6-33260000001-2",
        )


def test_answer_gate_rejects_contaminated_key_and_canary(tmp_path: Path) -> None:
    with pytest.raises(P6ProtocolError, match="forbidden answer material"):
        answer_free_projection({"model_output": "redacted"})
    clean = tmp_path / "clean.json"
    clean.write_text(json.dumps({"value": "private-marker"}), encoding="utf-8")
    with pytest.raises(P6ProtocolError, match="protected canary"):
        validate_answer_free_artifact(clean, canaries=("private-marker",))


def test_workflow_failure_is_typed_and_materializes_all_skips(tmp_path: Path) -> None:
    diagnostic = emit_workflow_failure(
        run_dir=tmp_path / "failure-run",
        output=tmp_path / "diagnostic.json",
        workflow_run_id="33260000001",
        workflow_run_attempt=3,
        attempt_id="p6-attempt-3",
        control_plane_commit="c" * 40,
        execution_stage="provider_probe",
        status="failed",
        failure_class="provider_identity_mismatch",
        failure_count=1,
        binding_sha256="1" * 64,
    )

    assert public_failure_annotation(diagnostic) == (
        "stage=provider; class=provider_identity_mismatch:1; count=1"
    )
    rows = sorted((tmp_path / "failure-run" / "stage-results").glob("*.json"))
    assert len(rows) == len(P6_EXECUTION_STAGE_ORDER)


def test_canary_receipt_binds_physical_provider_usage(tmp_path: Path) -> None:
    conservation = {
        "physical_call_count": 3,
        "provider_reported_call_count": 3,
        "estimated_call_count": 0,
        "provider_usage_coverage": 1.0,
        "requested_model": "GLM-5.2",
        "requested_model_coverage": 1.0,
        "response_model": "GLM-5.2",
        "response_model_coverage": 1.0,
        "queue_empty": True,
        "dimensions": {
            "token": {"numerator": 30, "denominator": 30, "conserved": True},
            "tool": {"numerator": 3, "denominator": 3, "conserved": True},
            "trace": {"numerator": 3, "denominator": 3, "conserved": True},
            "finding": {"numerator": 3, "denominator": 3, "conserved": True},
            "terminal": {"numerator": 3, "denominator": 3, "conserved": True},
        },
    }
    context = {
        "toolchain_evidence_sha256": "1" * 64,
        "provider_identity_sha256": "2" * 64,
        "network_policy_sha256": "3" * 64,
        "runtime_source_sha256": "4" * 64,
        "image": "registry.example/zscope@sha256:" + "5" * 64,
    }
    artifact = {
        "schema_version": "zscope.p6-offline-stage.v1",
        "stage": "canary",
        "suite_files": [{"path": "v3-model-canary.json", "sha256": "6" * 64}],
        "suite_root_sha256": canonical_sha256(
            [{"path": "v3-model-canary.json", "sha256": "6" * 64}]
        ),
        "source_receipt_sha256": "7" * 64,
        "passed": True,
        "failure_count": 0,
        "model_call_count": 3,
        "usage_conservation": conservation,
        "oci_execution_sha256s": ["8" * 64],
        "toolchain_evidence_sha256": context["toolchain_evidence_sha256"],
        "provider_identity_sha256": context["provider_identity_sha256"],
        "network_policy_sha256": context["network_policy_sha256"],
        "runtime_source_sha256": context["runtime_source_sha256"],
        "oci_image": context["image"],
        "answer_material_present": False,
        "formal_evidence": False,
        "release_eligible": False,
    }
    path = tmp_path / "canary.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()

    assert p6_cli._validate_bound_answer_free_artifact(
        path,
        digest,
        canaries=(),
        expected_stage="canary",
        qualification_oci_context=context,
    ) == (digest, conservation)

    artifact["usage_conservation"]["estimated_call_count"] = 1
    path.write_text(json.dumps(artifact), encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(P6ProtocolError, match="usage conservation"):
        p6_cli._validate_bound_answer_free_artifact(
            path,
            digest,
            canaries=(),
            expected_stage="canary",
            qualification_oci_context=context,
        )


def _download_args(tmp_path: Path) -> argparse.Namespace:
    return argparse.Namespace(
        repository="zealousness/Z-Scope",
        run_id="33260000001",
        run_attempt=2,
        control_plane_commit="c" * 40,
        candidate_commit="1" * 40,
        producer_job="conservation and qualification seal",
        artifact_id=9716404772,
        artifact_name="p6-qualification-" + "1" * 40 + "-2",
        artifact_digest="sha256:" + "a" * 64,
        required_member=["qualification.json"],
        output_dir=tmp_path / "restored",
    )


def test_restore_primitive_enforces_protected_arguments(monkeypatch, tmp_path: Path) -> None:
    args = _download_args(tmp_path)
    monkeypatch.delenv("Z_SCOPE_P6_ENVIRONMENT", raising=False)
    monkeypatch.setattr(
        p6_download,
        "_fetch_and_validate_source_run",
        lambda **_: pytest.fail("network metadata must not be read before validation"),
    )

    with pytest.raises(P6ProtocolError, match="sealed-benchmark environment"):
        p6_download.restore_exact_p6_artifact(args, token="token")


def test_exact_restore_fails_closed_on_listed_digest(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z_SCOPE_P6_ENVIRONMENT", "sealed-benchmark")
    args = _download_args(tmp_path)
    monkeypatch.setattr(p6_download, "_fetch_and_validate_source_run", lambda **_: None)
    monkeypatch.setattr(
        p6_download, "_fetch_metadata", lambda *_args, **_kwargs: {"run_attempt": 2}
    )
    monkeypatch.setattr(
        p6_download,
        "_list_run_artifacts",
        lambda **_: [
            {
                "id": args.artifact_id,
                "name": args.artifact_name,
                "expired": False,
                "digest": "sha256:" + "b" * 64,
            }
        ],
    )

    with pytest.raises(P6ProtocolError, match="listed artifact metadata"):
        p6_download.restore_exact_p6_artifact(args, token="token")


def test_exact_restore_hardcodes_p6_source_identity(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z_SCOPE_P6_ENVIRONMENT", "sealed-benchmark")
    args = _download_args(tmp_path)
    observed: dict[str, object] = {}

    def capture(**kwargs):
        observed.update(kwargs)

    monkeypatch.setattr(p6_download, "_fetch_and_validate_source_run", capture)
    monkeypatch.setattr(
        p6_download, "_fetch_metadata", lambda *_args, **_kwargs: {"run_attempt": 2}
    )
    monkeypatch.setattr(
        p6_download,
        "_list_run_artifacts",
        lambda **_: [
            {
                "id": args.artifact_id,
                "name": args.artifact_name,
                "expired": False,
                "digest": args.artifact_digest,
            }
        ],
    )
    monkeypatch.setattr(
        p6_download,
        "_list_run_jobs",
        lambda **_: [
            {
                "name": args.producer_job,
                "run_id": int(args.run_id),
                "run_attempt": 1,
                "head_sha": args.control_plane_commit,
                "status": "completed",
                "conclusion": "success",
            }
        ],
    )

    with pytest.raises(P6ProtocolError, match="attempt is unbound"):
        p6_download.restore_exact_p6_artifact(args, token="token")
    assert observed["workflow_path"] == P6_WORKFLOW_PATH
    assert observed["event"] == "workflow_dispatch"
    assert observed["head_branch"] == "main"


def test_exact_restore_allows_only_explicit_cross_run_complete_checkpoint(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z_SCOPE_P6_ENVIRONMENT", "sealed-benchmark")
    args = _download_args(tmp_path)
    args.current_run_id = "33260000002"
    args.current_run_attempt = 1
    args.current_control_plane_commit = "d" * 40
    args.allow_prior_complete_checkpoint = True
    args.artifact_name = "p6-complete-checkpoint-" + "1" * 40 + "-2"
    args.required_member = ["checkpoint.json"]
    p6_download._validate_arguments(args)

    invalid = copy.copy(args)
    invalid.artifact_name = "p6-qualification-" + "1" * 40 + "-2"
    with pytest.raises(P6ProtocolError, match="restricted to explicit complete"):
        p6_download._validate_arguments(invalid)


def test_exact_restore_rejects_candidate_name_or_control_plane_shape(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z_SCOPE_P6_ENVIRONMENT", "sealed-benchmark")
    args = _download_args(tmp_path)
    args.artifact_name = "p6-qualification-" + "2" * 40 + "-2"
    with pytest.raises(P6ProtocolError, match="candidate commit"):
        p6_download._validate_arguments(args)

    args = _download_args(tmp_path)
    args.control_plane_commit = "not-a-commit"
    with pytest.raises(P6ProtocolError, match="control-plane or candidate"):
        p6_download._validate_arguments(args)


def test_cross_run_checkpoint_validates_recovery_workflow_identity(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z_SCOPE_P6_ENVIRONMENT", "sealed-benchmark")
    args = _download_args(tmp_path)
    args.current_run_id = "33260000002"
    args.current_run_attempt = 1
    args.current_control_plane_commit = "d" * 40
    args.allow_prior_complete_checkpoint = True
    args.artifact_name = "p6-complete-checkpoint-" + "1" * 40 + "-2"
    args.required_member = ["checkpoint.json"]
    identities = []

    def capture(**kwargs):
        identities.append(kwargs)

    def metadata(url: str, **_kwargs):
        if url.endswith("/actions/runs/33260000001"):
            return {"run_attempt": 2}
        if url.endswith("/actions/runs/33260000002"):
            return {"run_attempt": 1}
        raise AssertionError(url)

    monkeypatch.setattr(p6_download, "_fetch_and_validate_source_run", capture)
    monkeypatch.setattr(p6_download, "_fetch_metadata", metadata)
    monkeypatch.setattr(
        p6_download,
        "_list_run_artifacts",
        lambda **_: [
            {
                "id": args.artifact_id,
                "name": args.artifact_name,
                "expired": False,
                "digest": "sha256:" + "b" * 64,
            }
        ],
    )

    with pytest.raises(P6ProtocolError, match="listed artifact metadata"):
        p6_download.restore_exact_p6_artifact(args, token="token")
    assert [row["workflow_path"] for row in identities] == [
        P6_WORKFLOW_PATH,
        p6_download.P6_RECOVERY_WORKFLOW_PATH,
    ]
    assert [row["head_sha"] for row in identities] == [
        args.control_plane_commit,
        args.current_control_plane_commit,
    ]
