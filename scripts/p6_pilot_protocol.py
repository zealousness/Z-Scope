#!/usr/bin/env python3
"""Protected operator commands for the non-release P6 cold pilot."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Optional, Sequence, cast

from zscope.benchmarking.isolation import OciNetworkPolicy
from zscope.benchmarking.p6_protocol import (
    CHECKPOINT_SCHEMA_VERSION,
    FAILURE_CLASS_TO_STAGE,
    P6ProtocolError,
    P6_CHECKPOINT_STAGE_ORDER,
    P6_WORKFLOW_PATH,
    STAGE_RESULT_SCHEMA_VERSION,
    STAGE_ARTIFACT_SCHEMA_VERSION,
    answer_free_projection,
    artifact_root_sha256,
    build_stage_artifact,
    cold_cache_identities_sha256,
    combine_usage_conservation,
    canonical_sha256,
    build_qualification_from_projections,
    diagnose_pilot,
    emit_workflow_failure,
    load_json_strict,
    load_json_bytes_strict,
    load_stage_results,
    public_failure_annotation,
    read_answer_free_artifact,
    record_stage_result,
    read_regular_file_once,
    seal_toolchain_evidence,
    sha256_file,
    validate_pilot_aggregate,
    validate_checkpoint,
    validate_answer_free_artifact,
    validate_repair_receipt,
    validate_repair_receipt_bundle,
    validate_qualification_oci_receipt,
    validate_safe_zip,
    validate_toolchain_evidence,
    validate_usage_conservation,
    write_json_exclusive,
    zero_usage_conservation,
)
from zscope.benchmarking.provider_runtime import require_p6_provider_contract
from zscope.benchmarking.p6_review import (
    REVIEW_ROLES,
    aggregate_review_set,
    build_review_packet,
    run_reviewer,
    validate_review_packet,
)


def _sha256(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise argparse.ArgumentTypeError("expected one lowercase SHA-256")
    return value


def _git_object(value: str) -> str:
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise argparse.ArgumentTypeError("expected one lowercase 40-hex Git object")
    return value


def _artifact_row(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("artifact must use RELATIVE_PATH=LOCAL_PATH")
    relative, path = value.split("=", 1)
    if not relative or not path:
        raise argparse.ArgumentTypeError("artifact must use RELATIVE_PATH=LOCAL_PATH")
    return relative, Path(path)


def _canaries_from_args(args: argparse.Namespace) -> tuple[str, ...]:
    values = []
    for name in getattr(args, "canary_env", ()) or ():
        value = __import__("os").environ.get(name)
        if value:
            values.append(value)
    return tuple(values)


def _int_count(value: Any, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise P6ProtocolError(f"P6 {name} is invalid")
    return int(value)


def _derive_canary_usage_conservation(value: Mapping[str, Any]) -> Mapping[str, Any]:
    provider = value.get("provider_usage")
    ledger = value.get("usage_ledger")
    clusters = value.get("clusters")
    identities = value.get("model_identity_counts")
    if (
        not isinstance(provider, Mapping)
        or not isinstance(ledger, Mapping)
        or not isinstance(clusters, list)
        or not all(isinstance(cluster, Mapping) for cluster in clusters)
        or not isinstance(identities, Mapping)
        or set(identities)
        != {
            "successful_call_count",
            "requested_glm_5_2_count",
            "response_glm_5_2_count",
        }
    ):
        raise P6ProtocolError("P6 EvidenceAction canary usage inputs are incomplete")
    attribution = ledger.get("usage_attribution")
    totals = attribution.get("totals") if isinstance(attribution, Mapping) else None
    if not isinstance(totals, Mapping):
        raise P6ProtocolError("P6 EvidenceAction canary usage ledger is incomplete")
    physical = _int_count(totals.get("request_count"), name="canary request count")
    successful = _int_count(totals.get("successful_calls"), name="canary success count")
    reported = _int_count(totals.get("provider_reported_calls"), name="canary provider count")
    estimated = _int_count(
        totals.get("estimated_or_conservative_calls"), name="canary estimated count"
    )
    provider_successful = _int_count(
        provider.get("successful_calls"), name="canary client success count"
    )
    provider_reported = _int_count(
        provider.get("provider_reported_calls"), name="canary client provider count"
    )
    provider_estimated = _int_count(
        provider.get("estimated_calls"), name="canary client estimated count"
    )
    selected = _int_count(value.get("selected_cluster_count"), name="selected cluster count")
    if selected < 1 or len(clusters) != selected:
        raise P6ProtocolError("P6 EvidenceAction canary cluster conservation is invalid")
    requested_count = _int_count(
        identities.get("requested_glm_5_2_count"), name="requested model count"
    )
    response_count = _int_count(
        identities.get("response_glm_5_2_count"), name="response model count"
    )
    identity_successful = _int_count(
        identities.get("successful_call_count"), name="identity success count"
    )
    provider_tokens = _int_count(provider.get("total_tokens"), name="provider token count")
    ledger_tokens = _int_count(totals.get("total_tokens"), name="ledger token count")
    cluster_tokens = sum(
        _int_count(cluster.get("total_tokens"), name="cluster token count") for cluster in clusters
    )
    cluster_tools = sum(
        _int_count(cluster.get("tool_call_count"), name="cluster tool count")
        for cluster in clusters
    )
    ledger_tools = _int_count(totals.get("tool_call_count"), name="ledger tool count")
    cluster_uids = [cluster.get("validation_cluster_uid") for cluster in clusters]
    candidate_uids = [cluster.get("candidate_uid") for cluster in clusters]
    if any(not isinstance(uid, str) or not uid for uid in (*cluster_uids, *candidate_uids)):
        raise P6ProtocolError("P6 EvidenceAction canary identity row is invalid")
    trace_count = len(set(cluster_uids))
    finding_count = len(set(candidate_uids))
    terminal_count = sum(
        cluster.get("model_success") is True
        and isinstance(cluster.get("stop_reason"), str)
        and bool(str(cluster["stop_reason"]))
        for cluster in clusters
    )
    queue_empty = (
        _int_count(ledger.get("active_reservation_count"), name="active reservation count") == 0
    )
    event_count = _int_count(ledger.get("event_count"), name="usage event count")
    persisted = _int_count(ledger.get("persisted_event_count"), name="persisted usage event count")
    invalid_calls = sum(
        _int_count(totals.get(name), name=f"canary {name}")
        for name in ("denied_requests", "failed_or_unknown_calls", "budget_violation_count")
    )
    if (
        physical < 1
        or successful != physical
        or reported != physical
        or provider_successful != physical
        or provider_reported != physical
        or identity_successful != physical
        or estimated != 0
        or provider_estimated != 0
        or invalid_calls != 0
        or provider.get("provider_usage_coverage") != 1.0
        or event_count != physical
        or persisted != physical
        or ledger.get("telemetry_complete") is not True
        or value.get("current_v3_tokens") != cluster_tokens
    ):
        raise P6ProtocolError("P6 EvidenceAction canary call conservation is invalid")
    dimensions = {
        "token": {
            "numerator": provider_tokens,
            "denominator": ledger_tokens,
            "conserved": provider_tokens == ledger_tokens == cluster_tokens,
        },
        "tool": {
            "numerator": cluster_tools,
            "denominator": ledger_tools,
            "conserved": cluster_tools == ledger_tools,
        },
        "trace": {
            "numerator": trace_count,
            "denominator": selected,
            "conserved": trace_count == selected,
        },
        "finding": {
            "numerator": finding_count,
            "denominator": selected,
            "conserved": finding_count == selected,
        },
        "terminal": {
            "numerator": terminal_count,
            "denominator": selected,
            "conserved": terminal_count == selected,
        },
    }
    projection = {
        "physical_call_count": physical,
        "provider_reported_call_count": reported,
        "estimated_call_count": estimated,
        "provider_usage_coverage": 1.0,
        "requested_model": "GLM-5.2",
        "requested_model_coverage": requested_count / physical,
        "response_model": "GLM-5.2",
        "response_model_coverage": response_count / physical,
        "queue_empty": queue_empty,
        "dimensions": dimensions,
    }
    return cast(
        Mapping[str, Any],
        validate_usage_conservation(projection, require_model_calls=True),
    )


def _qualification_oci_context(
    args: argparse.Namespace, *, candidate_commit: str
) -> Mapping[str, str]:
    toolchain_path = args.toolchain_evidence.absolute()
    toolchain, _, actual_digest = read_answer_free_artifact(
        toolchain_path, canaries=_canaries_from_args(args)
    )
    if actual_digest != args.toolchain_evidence_sha256 or not isinstance(toolchain, Mapping):
        raise P6ProtocolError("P6 qualification toolchain evidence binding is invalid")
    candidate_sha256 = hashlib.sha256(candidate_commit.encode("utf-8")).hexdigest()
    validate_toolchain_evidence(
        toolchain,
        expected_run_id=args.workflow_run_id,
        expected_run_attempt=args.workflow_run_attempt,
        expected_attempt_id=args.attempt_id,
        expected_control_plane_commit=args.control_plane_commit,
        expected_candidate_sha256=candidate_sha256,
        expected_git_sha=candidate_commit,
    )
    contract = require_p6_provider_contract(Path("test/range/zscope.benchmark.yaml"))
    policy = OciNetworkPolicy.from_provider_contract(os.environ, contract)
    repository = str(os.environ.get("GITHUB_REPOSITORY") or "").strip()
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        raise P6ProtocolError("P6 qualification repository identity is invalid")
    return {
        "provider_identity_sha256": contract.identity_sha256,
        "network_policy_sha256": policy.policy_sha256,
        "network_name": policy.network_name,
        "endpoint_origin": policy.endpoint_origin,
        "image": str(toolchain["image_ref"]),
        "runtime_source_sha256": str(toolchain["runtime_source_sha256"]),
        "toolchain_evidence_sha256": actual_digest,
        "workflow_run_id": args.workflow_run_id,
        "workflow_run_attempt": str(args.workflow_run_attempt),
        "attempt_id": args.attempt_id,
        "control_plane_commit": args.control_plane_commit,
        "candidate_commit": candidate_commit,
        "harness_sha256": args.harness_sha256,
        "repository": repository,
    }


def _validate_qualification_oci_binding(
    receipt: Mapping[str, Any], *, context: Mapping[str, str]
) -> tuple[str, ...]:
    raw = receipt.get("oci_execution_receipt")
    if not isinstance(raw, Mapping):
        raise P6ProtocolError("P6 qualification OCI execution receipt is missing")
    return validate_qualification_oci_receipt(
        raw,
        expected_provider_identity_sha256=context["provider_identity_sha256"],
        expected_network_policy_sha256=context["network_policy_sha256"],
        expected_network_name=context["network_name"],
        expected_endpoint_origin=context["endpoint_origin"],
        expected_image=context["image"],
        expected_runtime_source_sha256=context["runtime_source_sha256"],
        expected_workflow_run_id=context["workflow_run_id"],
        expected_workflow_run_attempt=int(context["workflow_run_attempt"]),
        expected_attempt_id=context["attempt_id"],
        expected_repository=context["repository"],
    )


def _validate_bound_answer_free_artifact(
    path: Path,
    expected_sha256: str,
    *,
    canaries: Sequence[str],
    expected_stage: Optional[str] = None,
    qualification_oci_context: Optional[Mapping[str, str]] = None,
) -> tuple[str, Mapping[str, Any]]:
    resolved = path.absolute()
    value, _, actual = read_answer_free_artifact(resolved, canaries=canaries)
    if actual != expected_sha256:
        raise P6ProtocolError("P6 offline artifact digest binding is invalid")
    usage_conservation: Mapping[str, Any] = zero_usage_conservation()
    if expected_stage is not None:
        fields = {
            "schema_version",
            "stage",
            "suite_files",
            "suite_root_sha256",
            "source_receipt_sha256",
            "passed",
            "failure_count",
            "model_call_count",
            "usage_conservation",
            "oci_execution_sha256s",
            "toolchain_evidence_sha256",
            "provider_identity_sha256",
            "network_policy_sha256",
            "runtime_source_sha256",
            "oci_image",
            "answer_material_present",
            "formal_evidence",
            "release_eligible",
        }
        if (
            not isinstance(value, Mapping)
            or set(value) != fields
            or value.get("schema_version") != "zscope.p6-offline-stage.v1"
            or value.get("stage") != expected_stage
            or value.get("passed") is not True
            or value.get("failure_count") != 0
            or value.get("answer_material_present") is not False
            or value.get("formal_evidence") is not False
            or value.get("release_eligible") is not False
        ):
            raise P6ProtocolError("P6 offline stage artifact schema is invalid")
        requires_calls = expected_stage in {"hidden_holdout", "safe_pair", "canary"}
        usage_conservation = validate_usage_conservation(
            value.get("usage_conservation"), require_model_calls=requires_calls
        )
        if value.get("model_call_count") != usage_conservation["physical_call_count"]:
            raise P6ProtocolError("P6 offline stage model-call accounting is invalid")
        receipt_sha = value.get("source_receipt_sha256")
        if requires_calls or expected_stage == "reverify":
            if (
                not isinstance(receipt_sha, str)
                or len(receipt_sha) != 64
                or any(character not in "0123456789abcdef" for character in receipt_sha)
            ):
                raise P6ProtocolError("P6 offline model receipt binding is invalid")
            if not requires_calls:
                if (
                    value.get("oci_execution_sha256s") != []
                    or value.get("toolchain_evidence_sha256") is not None
                    or value.get("provider_identity_sha256") is not None
                    or value.get("network_policy_sha256") is not None
                    or value.get("runtime_source_sha256") is not None
                    or value.get("oci_image") is not None
                ):
                    raise P6ProtocolError(
                        "P6 certificate reverify stage cannot bind OCI model execution"
                    )
            elif qualification_oci_context is None:
                raise P6ProtocolError("P6 offline model OCI context is missing")
            elif (
                not isinstance(value.get("oci_execution_sha256s"), list)
                or not value["oci_execution_sha256s"]
                or any(
                    not isinstance(item, str)
                    or len(item) != 64
                    or any(character not in "0123456789abcdef" for character in item)
                    for item in value["oci_execution_sha256s"]
                )
                or len(set(value["oci_execution_sha256s"])) != len(value["oci_execution_sha256s"])
                or value.get("toolchain_evidence_sha256")
                != qualification_oci_context["toolchain_evidence_sha256"]
                or value.get("provider_identity_sha256")
                != qualification_oci_context["provider_identity_sha256"]
                or value.get("network_policy_sha256")
                != qualification_oci_context["network_policy_sha256"]
                or value.get("runtime_source_sha256")
                != qualification_oci_context["runtime_source_sha256"]
                or value.get("oci_image") != qualification_oci_context["image"]
            ):
                raise P6ProtocolError("P6 offline model OCI binding is invalid")
        elif receipt_sha is not None:
            raise P6ProtocolError("P6 zero-call stage cannot bind a receipt")
        elif (
            value.get("oci_execution_sha256s") != []
            or value.get("toolchain_evidence_sha256") is not None
            or value.get("provider_identity_sha256") is not None
            or value.get("network_policy_sha256") is not None
            or value.get("runtime_source_sha256") is not None
            or value.get("oci_image") is not None
        ):
            raise P6ProtocolError("P6 zero-call stage cannot bind OCI model execution")
        rows = value.get("suite_files")
        if not isinstance(rows, list) or not rows:
            raise P6ProtocolError("P6 offline stage suite binding is invalid")
        normalized = []
        for row in rows:
            if not isinstance(row, Mapping) or set(row) != {"path", "sha256"}:
                raise P6ProtocolError("P6 offline stage suite row is invalid")
            relative = row.get("path")
            if (
                not isinstance(relative, str)
                or PurePosixPath(relative).is_absolute()
                or any(part in {"", ".", ".."} for part in PurePosixPath(relative).parts)
            ):
                raise P6ProtocolError("P6 offline stage suite path is invalid")
            row_sha = row.get("sha256")
            if (
                not isinstance(row_sha, str)
                or len(row_sha) != 64
                or any(character not in "0123456789abcdef" for character in row_sha)
            ):
                raise P6ProtocolError("P6 offline stage suite SHA-256 is invalid")
            normalized.append({"path": relative, "sha256": row.get("sha256")})
        if rows != sorted(normalized, key=lambda row: str(row["path"])):
            raise P6ProtocolError("P6 offline stage suite rows are not canonical")
        if value.get("suite_root_sha256") != canonical_sha256(rows):
            raise P6ProtocolError("P6 offline stage suite root is invalid")
    return actual, usage_conservation


def _record_stage(args: argparse.Namespace) -> int:
    failure_class: Optional[str] = args.failure_class
    failure_count = args.failure_count
    if args.status != "failed":
        failure_class = None
        failure_count = 0
    record = {
        "schema_version": STAGE_RESULT_SCHEMA_VERSION,
        "workflow_run_id": args.workflow_run_id,
        "workflow_run_attempt": args.workflow_run_attempt,
        "attempt_id": args.attempt_id,
        "control_plane_commit": args.control_plane_commit,
        "stage": args.stage,
        "status": args.status,
        "failure_class": failure_class,
        "failure_count": failure_count,
        "binding_sha256": args.binding_sha256,
    }
    path = record_stage_result(args.run_dir.absolute(), record)
    print(path)
    return 0


def _cache_identities(args: argparse.Namespace) -> Mapping[str, Mapping[str, object]]:
    return {
        depth: {
            "identity_sha256": getattr(args, f"{depth}_cache_sha256"),
            "empty_at_start": True,
            "reused": False,
        }
        for depth in ("fast", "balanced", "deep")
    }


def _seal_stage_artifact(args: argparse.Namespace) -> int:
    payload = build_stage_artifact(
        workflow_run_id=args.workflow_run_id,
        workflow_run_attempt=args.workflow_run_attempt,
        attempt_id=args.attempt_id,
        control_plane_commit=args.control_plane_commit,
        stage=args.stage,
        candidate_sha256=args.candidate_sha256,
        policy_sha256=args.policy_sha256,
        plan_sha256=args.plan_sha256,
        input_sha256=args.input_sha256,
        runtime_sha256=args.runtime_sha256,
        provider_sha256=args.provider_sha256,
        oci_sha256=args.oci_sha256,
        cold_cache_identities=_cache_identities(args),
        payload_sha256=args.payload_sha256,
    )
    write_json_exclusive(args.output.absolute(), payload)
    print(payload["binding_sha256"])
    return 0


def _diagnose(args: argparse.Namespace) -> int:
    payload = diagnose_pilot(args.run_dir.absolute(), args.output.absolute())
    print(public_failure_annotation(payload))
    return 0


def _checkpoint(args: argparse.Namespace) -> int:
    run_dir = args.run_dir.absolute()
    records = load_stage_results(run_dir)
    completed = [
        str(record["stage"])
        for record in records
        if record["status"] == "completed" and record["stage"] in P6_CHECKPOINT_STAGE_ORDER
    ]
    expected = list(P6_CHECKPOINT_STAGE_ORDER[: len(completed)])
    if completed != expected:
        raise P6ProtocolError("P6 checkpoint completed stages are not one producer prefix")
    artifacts = []
    for record, stage in zip(
        [record for record in records if record["stage"] in P6_CHECKPOINT_STAGE_ORDER],
        completed,
    ):
        path = run_dir / "stage-artifacts" / f"{stage}.json"
        payload = load_json_strict(path)
        if not isinstance(payload, Mapping):
            raise P6ProtocolError("P6 stage artifact must be an object")
        if payload.get("binding_sha256") != record.get("binding_sha256"):
            raise P6ProtocolError("P6 stage result and artifact binding differ")
        artifacts.append(
            {
                "stage": stage,
                "producer_attempt_id": args.attempt_id,
                "path": f"{stage}.json",
                "artifact_sha256": sha256_file(path),
                "artifact_schema_version": STAGE_ARTIFACT_SCHEMA_VERSION,
                "binding_sha256": str(payload.get("binding_sha256") or ""),
            }
        )
    complete = completed == list(P6_CHECKPOINT_STAGE_ORDER)
    payload = {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "workflow_path": P6_WORKFLOW_PATH,
        "workflow_run_id": args.workflow_run_id,
        "workflow_run_attempt": args.workflow_run_attempt,
        "attempt_id": args.attempt_id,
        "control_plane_commit": args.control_plane_commit,
        "status": "complete" if complete else "partial",
        "completed_stages": completed,
        "stage_artifacts": artifacts,
        "candidate_sha256": args.candidate_sha256,
        "policy_sha256": args.policy_sha256,
        "plan_sha256": args.plan_sha256,
        "input_sha256": args.input_sha256,
        "runtime_sha256": args.runtime_sha256,
        "provider_sha256": args.provider_sha256,
        "oci_sha256": args.oci_sha256,
        "artifact_root_sha256": artifact_root_sha256(artifacts),
        "cold_cache_identities": _cache_identities(args),
        "formal_evidence": False,
        "release_eligible": False,
        "requires_full_revalidation": True,
        "zero_call_finalizable": complete,
    }
    validate_checkpoint(
        payload,
        artifact_root=run_dir / "stage-artifacts",
        run_dir=run_dir,
    )
    write_json_exclusive(args.output.absolute(), payload)
    print("p6_checkpoint_complete" if complete else "p6_checkpoint_partial")
    return 0


def _validate_checkpoint(args: argparse.Namespace) -> int:
    value = load_json_strict(args.checkpoint.absolute())
    if not isinstance(value, Mapping):
        raise P6ProtocolError("P6 checkpoint must be an object")
    validate_checkpoint(
        value,
        artifact_root=args.artifact_root.absolute(),
        run_dir=args.run_dir.absolute() if args.run_dir is not None else None,
    )
    print("p6_checkpoint_valid")
    return 0


def _expected_lineage(args: argparse.Namespace) -> Mapping[str, object]:
    return {
        "workflow_path": P6_WORKFLOW_PATH,
        "workflow_run_id": args.workflow_run_id,
        "workflow_run_attempt": args.workflow_run_attempt,
        "attempt_id": args.attempt_id,
        "control_plane_commit": args.control_plane_commit,
        "candidate_sha256": args.candidate_sha256,
        "policy_sha256": args.policy_sha256,
        "plan_sha256": args.plan_sha256,
        "input_sha256": args.input_sha256,
        "runtime_sha256": args.runtime_sha256,
        "provider_sha256": args.provider_sha256,
        "oci_sha256": args.oci_sha256,
        "cold_cache_identities": _cache_identities(args),
    }


def _finalize_checkpoint(args: argparse.Namespace) -> int:
    checkpoint_path = args.checkpoint.absolute()
    value = load_json_strict(checkpoint_path)
    if not isinstance(value, Mapping):
        raise P6ProtocolError("P6 checkpoint must be an object")
    artifact_root = args.artifact_root.absolute()
    restored_artifacts = validate_checkpoint(
        value,
        artifact_root=artifact_root,
        run_dir=args.run_dir.absolute(),
        expected_lineage=_expected_lineage(args),
    )
    if value.get("status") != "complete" or value.get("zero_call_finalizable") is not True:
        raise P6ProtocolError("P6 checkpoint is not complete and zero-call finalizable")
    final_evidence_row = next(
        (row for row in value["stage_artifacts"] if row.get("stage") == "final_evidence_seal"),
        None,
    )
    if final_evidence_row is None:
        raise P6ProtocolError("P6 complete checkpoint lacks the final payload binding")
    stage_bytes = restored_artifacts.get("final_evidence_seal")
    if stage_bytes is None:
        raise P6ProtocolError("P6 restored checkpoint lacks final evidence bytes")
    stage_value = load_json_bytes_strict(
        stage_bytes, name="restored final_evidence_seal stage artifact"
    )
    if not isinstance(stage_value, Mapping):
        raise P6ProtocolError("P6 final stage artifact must be an object")
    source = args.payload.absolute()
    source_bytes = read_regular_file_once(source)
    source_value = load_json_bytes_strict(source_bytes, name="P6 final evidence payload")
    answer_free_projection(source_value, canaries=_canaries_from_args(args))
    if hashlib.sha256(source_bytes).hexdigest() != stage_value.get("payload_sha256"):
        raise P6ProtocolError("P6 final payload differs from the complete checkpoint")
    target = args.output.absolute()
    if target.exists() or target.is_symlink():
        raise P6ProtocolError("refusing to overwrite immutable P6 checkpoint finalization")
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(target, flags, 0o600)
        try:
            view = memoryview(source_bytes)
            while view:
                written = os.write(descriptor, view)
                if written < 1:
                    raise P6ProtocolError("P6 checkpoint finalization write failed")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except FileExistsError as exc:
        raise P6ProtocolError("refusing to overwrite immutable P6 checkpoint finalization") from exc
    print("p6_checkpoint_zero_call_finalized")
    return 0


def _validate_receipt(args: argparse.Namespace) -> int:
    value = load_json_strict(args.receipt.absolute())
    if not isinstance(value, Mapping):
        raise P6ProtocolError("P6 repair receipt must be an object")
    bundle = (args.failure_diagnostic, args.checkpoint, args.selected_producer)
    if any(item is not None for item in bundle) and not all(item is not None for item in bundle):
        raise P6ProtocolError("P6 repair receipt referenced objects are all-or-none")
    if args.failure_diagnostic is None:
        validate_repair_receipt(value)
    else:
        validate_repair_receipt_bundle(
            value,
            failure_diagnostic_path=args.failure_diagnostic.absolute(),
            checkpoint_path=args.checkpoint.absolute(),
            selected_producer_path=args.selected_producer.absolute(),
            checkpoint_artifact_root=(
                args.checkpoint_artifact_root.absolute()
                if args.checkpoint_artifact_root is not None
                else None
            ),
        )
    print("p6_repair_receipt_valid")
    return 0


def _validate_answer_free(args: argparse.Namespace) -> int:
    digest = validate_answer_free_artifact(
        args.input.absolute(), canaries=_canaries_from_args(args)
    )
    if args.output is not None:
        value = load_json_strict(args.input.absolute())
        projected = answer_free_projection(value, canaries=_canaries_from_args(args))
        if not isinstance(projected, Mapping):
            raise P6ProtocolError("P6 answer-free artifact root must be an object")
        write_json_exclusive(args.output.absolute(), projected)
    print(digest)
    return 0


def _validate_zip(args: argparse.Namespace) -> int:
    print(
        validate_safe_zip(
            args.archive.absolute(),
            expected_sha256=args.sha256,
        )
    )
    return 0


def _emit_workflow_failure(args: argparse.Namespace) -> int:
    payload = emit_workflow_failure(
        run_dir=args.run_dir.absolute(),
        output=args.output.absolute(),
        workflow_run_id=args.workflow_run_id,
        workflow_run_attempt=args.workflow_run_attempt,
        attempt_id=args.attempt_id,
        control_plane_commit=args.control_plane_commit,
        execution_stage=args.stage,
        status=args.status,
        failure_class=args.failure_class,
        failure_count=args.failure_count,
        binding_sha256=args.binding_sha256,
        checkpoint_path=args.checkpoint.absolute() if args.checkpoint is not None else None,
        checkpoint_artifact_root=(
            args.checkpoint_artifact_root.absolute()
            if args.checkpoint_artifact_root is not None
            else None
        ),
    )
    print(public_failure_annotation(payload))
    return 0


def _qualification(args: argparse.Namespace) -> int:
    projections: dict[str, Mapping[str, Any]] = {}
    artifact_hashes: dict[str, str] = {}
    cache_hashes: dict[str, str] = {}
    for depth in ("fast", "balanced", "deep"):
        path = Path(getattr(args, depth)).absolute()
        value = load_json_strict(path)
        if not isinstance(value, Mapping):
            raise P6ProtocolError("P6 pilot aggregate must be an object")
        projections[depth] = value
        artifact_hashes[depth] = sha256_file(path)
        cache_hashes[depth] = getattr(args, f"{depth}_cache_sha256")
    offline_path = args.offline_evidence.absolute()
    offline, _, offline_digest = read_answer_free_artifact(
        offline_path, canaries=_canaries_from_args(args)
    )
    if offline_digest != args.offline_evidence_sha256:
        raise P6ProtocolError("P6 offline evidence digest binding is invalid")
    offline_fields = {
        "schema_version",
        "candidate_sha256",
        "policy_sha256",
        "stages",
        "all_passed",
        "model_call_count",
        "model_call_counts",
        "usage_conservation",
        "answer_material_present",
        "sealed_inputs",
        "formal_evidence",
        "release_eligible",
    }
    if (
        not isinstance(offline, Mapping)
        or set(offline) != offline_fields
        or offline.get("schema_version") != "zscope.p6-offline-evidence.v1"
        or offline.get("candidate_sha256") != args.candidate_sha256
        or offline.get("policy_sha256") != args.policy_sha256
        or offline.get("stages")
        != [
            "policy_replay",
            "certificate_reverify",
            "anonymous_qualification",
            "safe_pair_validation",
            "evidence_action_canary",
        ]
        or offline.get("all_passed") is not True
        or offline.get("answer_material_present") is not False
        or offline.get("formal_evidence") is not False
        or offline.get("release_eligible") is not False
    ):
        raise P6ProtocolError("P6 offline evidence lineage is invalid")
    offline_conservation = validate_usage_conservation(
        offline.get("usage_conservation"), require_model_calls=True
    )
    call_counts = offline.get("model_call_counts")
    sealed_inputs = offline.get("sealed_inputs")
    expected_offline_stages = {
        "policy_replay",
        "reverify",
        "hidden_holdout",
        "safe_pair",
        "canary",
    }
    if (
        not isinstance(call_counts, Mapping)
        or set(call_counts) != expected_offline_stages
        or any(
            isinstance(count, bool) or not isinstance(count, int) or count < 0
            for count in call_counts.values()
        )
        or not isinstance(sealed_inputs, Mapping)
        or set(sealed_inputs) != expected_offline_stages
        or any(
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for digest in sealed_inputs.values()
        )
        or call_counts.get("policy_replay") != 0
        or call_counts.get("reverify") != 0
        or int(call_counts.get("hidden_holdout", 0)) < 1
        or int(call_counts.get("safe_pair", 0)) < 1
        or int(call_counts.get("canary", 0)) < 1
        or sum(int(count) for count in call_counts.values())
        != offline_conservation["physical_call_count"]
        or offline.get("model_call_count") != offline_conservation["physical_call_count"]
    ):
        raise P6ProtocolError("P6 offline evidence call accounting is invalid")
    provider_probe_path = args.provider_probe.absolute()
    provider_probe, _, provider_probe_digest = read_answer_free_artifact(
        provider_probe_path, canaries=_canaries_from_args(args)
    )
    if provider_probe_digest != args.provider_probe_sha256:
        raise P6ProtocolError("P6 provider probe digest binding is invalid")
    if not isinstance(provider_probe, Mapping):
        raise P6ProtocolError("P6 provider probe must be an object")
    toolchain_path = args.toolchain_evidence.absolute()
    toolchain, _, toolchain_digest = read_answer_free_artifact(
        toolchain_path, canaries=_canaries_from_args(args)
    )
    if toolchain_digest != args.toolchain_evidence_sha256:
        raise P6ProtocolError("P6 toolchain evidence digest binding is invalid")
    if not isinstance(toolchain, Mapping):
        raise P6ProtocolError("P6 toolchain evidence must be an object")
    validate_toolchain_evidence(
        toolchain,
        expected_attempt_id=args.attempt_id,
        expected_control_plane_commit=args.control_plane_commit,
        expected_candidate_sha256=args.candidate_sha256,
    )
    payload = build_qualification_from_projections(
        projections=projections,
        projection_file_sha256s=artifact_hashes,
        cache_identity_sha256s=cache_hashes,
        candidate_sha256=args.candidate_sha256,
        policy_sha256=args.policy_sha256,
        offline_evidence_sha256=args.offline_evidence_sha256,
        offline_usage_conservation=offline_conservation,
        provider_probe=provider_probe,
        provider_probe_file_sha256=args.provider_probe_sha256,
        toolchain_evidence=toolchain,
        toolchain_evidence_file_sha256=args.toolchain_evidence_sha256,
        control_plane_commit=args.control_plane_commit,
        attempt_id=args.attempt_id,
    )
    write_json_exclusive(args.output.absolute(), payload)
    print(payload["qualification_sha256"])
    return 0


def _project_depth(args: argparse.Namespace) -> int:
    value = load_json_strict(args.aggregate.absolute())
    if not isinstance(value, Mapping):
        raise P6ProtocolError("P6 pilot aggregate must be an object")
    toolchain_path = args.toolchain_evidence.absolute()
    toolchain, _, toolchain_digest = read_answer_free_artifact(
        toolchain_path, canaries=_canaries_from_args(args)
    )
    if toolchain_digest != args.toolchain_evidence_sha256:
        raise P6ProtocolError("P6 toolchain evidence digest binding is invalid")
    if not isinstance(toolchain, Mapping):
        raise P6ProtocolError("P6 toolchain evidence must be an object")
    projection = validate_pilot_aggregate(
        value,
        scan_depth=args.scan_depth,
        expected_control_plane_commit=args.control_plane_commit,
        expected_git_sha=args.expected_git_sha,
        expected_git_tree=args.expected_git_tree,
        toolchain_evidence=toolchain,
        toolchain_evidence_file_sha256=args.toolchain_evidence_sha256,
    )
    write_json_exclusive(args.output.absolute(), projection)
    print(projection["artifact_sha256"])
    return 0


def _seal_toolchain_evidence(args: argparse.Namespace) -> int:
    draft = load_json_strict(args.draft.absolute())
    if not isinstance(draft, Mapping):
        raise P6ProtocolError("P6 toolchain evidence draft must be an object")
    payload = seal_toolchain_evidence(draft)
    validate_toolchain_evidence(
        payload,
        expected_control_plane_commit=args.control_plane_commit,
        expected_git_sha=args.candidate_commit,
        expected_git_tree=args.candidate_tree,
    )
    answer_free_projection(payload, canaries=_canaries_from_args(args))
    write_json_exclusive(args.output.absolute(), payload)
    print(sha256_file(args.output.absolute()))
    return 0


def _validate_policy_replay_artifact(
    path: Path,
    expected_sha256: str,
    *,
    canaries: Sequence[str],
    expected_control_plane_commit: str,
    expected_candidate_commit: str,
    expected_workflow_run_id: str,
    expected_workflow_run_attempt: int,
    expected_trace_manifest_file_sha256: str,
) -> tuple[str, Mapping[str, Any]]:
    value, _, actual = read_answer_free_artifact(path.absolute(), canaries=canaries)
    if actual != expected_sha256 or not isinstance(value, Mapping):
        raise P6ProtocolError("P6 policy replay artifact digest binding is invalid")
    expected_fields = {
        "schema_version",
        "workflow_run_id",
        "workflow_run_attempt",
        "control_plane_commit",
        "candidate_git_sha",
        "trace_manifest_sha256",
        "trace_manifest_file_sha256",
        "trace_count",
        "result_root_sha256",
        "terminal_match_counts",
        "policy_issue_counts",
        "llm_calls",
        "truth_inputs",
        "answer_material_present",
        "formal_evidence",
        "release_eligible",
        "evidence_sha256",
    }
    body = dict(value)
    evidence_sha = body.pop("evidence_sha256", None)
    if (
        set(value) != expected_fields
        or value.get("schema_version") != "zscope.p6-policy-replay-evidence.v1"
        or value.get("workflow_run_id") != expected_workflow_run_id
        or value.get("workflow_run_attempt") != expected_workflow_run_attempt
        or value.get("control_plane_commit") != expected_control_plane_commit
        or value.get("candidate_git_sha") != expected_candidate_commit
        or value.get("trace_manifest_file_sha256") != expected_trace_manifest_file_sha256
        or evidence_sha != canonical_sha256(body)
        or value.get("llm_calls") != 0
        or value.get("truth_inputs") != 0
        or value.get("answer_material_present") is not False
        or value.get("formal_evidence") is not False
        or value.get("release_eligible") is not False
    ):
        raise P6ProtocolError("P6 policy replay artifact lineage is invalid")
    for name in ("trace_manifest_sha256", "trace_manifest_file_sha256", "result_root_sha256"):
        raw = value.get(name)
        if (
            not isinstance(raw, str)
            or len(raw) != 64
            or any(character not in "0123456789abcdef" for character in raw)
        ):
            raise P6ProtocolError("P6 policy replay hash binding is invalid")
    trace_count = value.get("trace_count")
    terminal_counts = value.get("terminal_match_counts")
    policy_counts = value.get("policy_issue_counts")
    if (
        isinstance(trace_count, bool)
        or not isinstance(trace_count, int)
        or trace_count < 1
        or not isinstance(terminal_counts, Mapping)
        or not isinstance(policy_counts, Mapping)
        or any(
            not isinstance(key, str)
            or not key
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            for counts in (terminal_counts, policy_counts)
            for key, count in counts.items()
        )
        or sum(terminal_counts.values()) != trace_count
        or sum(policy_counts.values()) != trace_count
    ):
        raise P6ProtocolError("P6 policy replay accounting is invalid")
    return actual, zero_usage_conservation()


def _validate_reverify_receipt(
    path: Path,
    expected_sha256: str,
    *,
    expected_control_plane_commit: str,
    expected_candidate_commit: str,
    expected_workflow_run_id: str,
    expected_workflow_run_attempt: int,
    expected_trace_manifest_sha256: str,
    expected_trace_manifest_file_sha256: str,
) -> None:
    raw = read_regular_file_once(path.absolute())
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise P6ProtocolError("P6 certificate reverify receipt digest binding is invalid")
    value = load_json_bytes_strict(raw, name=str(path))
    fields = {
        "schema_version",
        "workflow_run_id",
        "workflow_run_attempt",
        "control_plane_commit",
        "candidate_git_sha",
        "trace_manifest_sha256",
        "trace_manifest_file_sha256",
        "trace_manifest_complete",
        "cluster_count",
        "terminal_trace_count",
        "v3_entered_cluster_count",
        "v3_entered_with_empty_required_facts",
        "verifier_cluster_count",
        "claim_count",
        "classification_counts",
        "fact_kind_counts",
        "passed",
        "llm_calls",
        "truth_inputs",
        "answer_material_present",
        "formal_evidence",
        "release_eligible",
        "evidence_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise P6ProtocolError("P6 certificate reverify receipt schema is invalid")
    body = dict(value)
    evidence_sha256 = body.pop("evidence_sha256", None)
    if (
        value.get("schema_version") != "zscope.v3-trace-reverification.v1"
        or value.get("workflow_run_id") != expected_workflow_run_id
        or value.get("workflow_run_attempt") != expected_workflow_run_attempt
        or value.get("control_plane_commit") != expected_control_plane_commit
        or value.get("candidate_git_sha") != expected_candidate_commit
        or value.get("trace_manifest_sha256") != expected_trace_manifest_sha256
        or value.get("trace_manifest_file_sha256") != expected_trace_manifest_file_sha256
        or value.get("trace_manifest_complete") is not True
        or value.get("passed") is not True
        or value.get("llm_calls") != 0
        or value.get("truth_inputs") != 0
        or value.get("answer_material_present") is not False
        or value.get("formal_evidence") is not False
        or value.get("release_eligible") is not False
        or evidence_sha256 != canonical_sha256(body)
    ):
        raise P6ProtocolError("P6 certificate reverify receipt lineage is invalid")
    counts = {
        name: _int_count(value.get(name), name=f"certificate {name}")
        for name in (
            "cluster_count",
            "terminal_trace_count",
            "v3_entered_cluster_count",
            "v3_entered_with_empty_required_facts",
            "verifier_cluster_count",
            "claim_count",
        )
    }
    if (
        counts["cluster_count"] < 1
        or counts["terminal_trace_count"] > counts["cluster_count"]
        or counts["v3_entered_cluster_count"] > counts["cluster_count"]
        or counts["v3_entered_with_empty_required_facts"] > counts["v3_entered_cluster_count"]
        or counts["verifier_cluster_count"] > counts["cluster_count"]
    ):
        raise P6ProtocolError("P6 certificate reverify aggregate counts are invalid")
    for field in ("classification_counts", "fact_kind_counts"):
        aggregate = value.get(field)
        if not isinstance(aggregate, Mapping) or any(
            not isinstance(key, str)
            or not key
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            for key, count in aggregate.items()
        ):
            raise P6ProtocolError("P6 certificate reverify aggregate map is invalid")
    if sum(value["classification_counts"].values()) != counts["claim_count"]:
        raise P6ProtocolError("P6 certificate reverify claim conservation is invalid")


def _offline_evidence(args: argparse.Namespace) -> int:
    canaries = _canaries_from_args(args)
    if hashlib.sha256(args.candidate_commit.encode("utf-8")).hexdigest() != args.candidate_sha256:
        raise P6ProtocolError("P6 offline candidate commit binding is invalid")
    qualification_context = _qualification_oci_context(args, candidate_commit=args.candidate_commit)
    validated = {
        "policy_replay": _validate_policy_replay_artifact(
            args.policy_replay_artifact,
            args.policy_replay_sha256,
            canaries=canaries,
            expected_control_plane_commit=args.control_plane_commit,
            expected_candidate_commit=args.candidate_commit,
            expected_workflow_run_id=args.workflow_run_id,
            expected_workflow_run_attempt=args.workflow_run_attempt,
            expected_trace_manifest_file_sha256=args.trace_manifest_file_sha256,
        ),
        "reverify": _validate_bound_answer_free_artifact(
            args.reverify_artifact,
            args.reverify_sha256,
            canaries=canaries,
            expected_stage="reverify",
        ),
        "hidden_holdout": _validate_bound_answer_free_artifact(
            args.hidden_holdout_artifact,
            args.hidden_holdout_sha256,
            canaries=canaries,
            expected_stage="hidden_holdout",
            qualification_oci_context=qualification_context,
        ),
        "safe_pair": _validate_bound_answer_free_artifact(
            args.safe_pair_artifact,
            args.safe_pair_sha256,
            canaries=canaries,
            expected_stage="safe_pair",
            qualification_oci_context=qualification_context,
        ),
        "canary": _validate_bound_answer_free_artifact(
            args.canary_artifact,
            args.canary_sha256,
            canaries=canaries,
            expected_stage="canary",
            qualification_oci_context=qualification_context,
        ),
    }
    inputs = {name: row[0] for name, row in validated.items()}
    conservation_rows = {name: row[1] for name, row in validated.items()}
    call_counts = {name: int(row["physical_call_count"]) for name, row in conservation_rows.items()}
    global_conservation = combine_usage_conservation(list(conservation_rows.values()))
    payload = {
        "schema_version": "zscope.p6-offline-evidence.v1",
        "candidate_sha256": args.candidate_sha256,
        "policy_sha256": args.policy_sha256,
        "stages": [
            "policy_replay",
            "certificate_reverify",
            "anonymous_qualification",
            "safe_pair_validation",
            "evidence_action_canary",
        ],
        "all_passed": True,
        "model_call_count": int(global_conservation["physical_call_count"]),
        "model_call_counts": call_counts,
        "usage_conservation": global_conservation,
        "answer_material_present": False,
        "sealed_inputs": inputs,
        "formal_evidence": False,
        "release_eligible": False,
    }
    answer_free_projection(payload, canaries=canaries)
    write_json_exclusive(args.output.absolute(), payload)
    print(canonical_sha256(payload))
    return 0


def _seal_offline_stage(args: argparse.Namespace) -> int:
    workspace = Path.cwd().resolve()
    rows = []
    for supplied in args.suite_file:
        path = supplied.absolute()
        try:
            relative = path.relative_to(workspace).as_posix()
        except ValueError as exc:
            raise P6ProtocolError("P6 offline suite input escapes the workspace") from exc
        rows.append({"path": relative, "sha256": sha256_file(path)})
    rows.sort(key=lambda row: row["path"])
    if len({row["path"] for row in rows}) != len(rows):
        raise P6ProtocolError("P6 offline suite inputs are not unique")
    source_receipt_sha256: Optional[str] = None
    usage_conservation = zero_usage_conservation()
    oci_execution_sha256s: list[str] = []
    qualification_context: Optional[Mapping[str, str]] = None
    model_receipt_lineage = (
        args.workflow_run_id,
        args.workflow_run_attempt,
        args.attempt_id,
        args.control_plane_commit,
        args.candidate_commit,
        args.harness_sha256,
        args.qualification_input_sha256,
        args.toolchain_evidence,
        args.toolchain_evidence_sha256,
    )
    if args.stage in {"hidden_holdout", "safe_pair", "canary"}:
        if (
            args.receipt is None
            or args.receipt_sha256 is None
            or any(value is None for value in model_receipt_lineage)
        ):
            raise P6ProtocolError(
                "P6 model qualification stage requires one complete physical receipt lineage"
            )
        if (
            not isinstance(args.workflow_run_id, str)
            or not args.workflow_run_id.isdigit()
            or args.workflow_run_id.startswith("0")
            or isinstance(args.workflow_run_attempt, bool)
            or not isinstance(args.workflow_run_attempt, int)
            or args.workflow_run_attempt < 1
        ):
            raise P6ProtocolError("P6 qualification receipt run identity is invalid")
        receipt_path = args.receipt.absolute()
        receipt_payload = read_regular_file_once(receipt_path)
        source_receipt_sha256 = hashlib.sha256(receipt_payload).hexdigest()
        if source_receipt_sha256 != args.receipt_sha256:
            raise P6ProtocolError("P6 qualification receipt digest binding is invalid")
        receipt = load_json_bytes_strict(receipt_payload, name=str(receipt_path))
        qualification_context = _qualification_oci_context(
            args, candidate_commit=args.candidate_commit
        )
        common = {
            "workflow_run_id": args.workflow_run_id,
            "workflow_run_attempt": args.workflow_run_attempt,
            "attempt_id": args.attempt_id,
            "control_plane_commit": args.control_plane_commit,
            "candidate_sha": args.candidate_commit,
            "provider_model": "GLM-5.2",
            "harness_sha256": args.harness_sha256,
            "input_sha256": args.qualification_input_sha256,
            "passed": True,
            "answer_material_present": False,
            "formal_evidence": False,
            "release_eligible": False,
        }
        if not isinstance(receipt, Mapping) or any(
            receipt.get(name) != expected for name, expected in common.items()
        ):
            raise P6ProtocolError("P6 qualification receipt lineage is invalid")
        answer_free_receipt = dict(receipt)
        answer_free_receipt.pop("oci_execution_receipt", None)
        answer_free_projection(answer_free_receipt, canaries=_canaries_from_args(args))
        oci_execution_sha256s = list(
            _validate_qualification_oci_binding(receipt, context=qualification_context)
        )
        if args.stage == "hidden_holdout":
            expected_fields = {
                "schema_version",
                *common,
                "component_counts",
                "usage_conservation",
                "oci_execution_receipt",
            }
            if (
                set(receipt) != expected_fields
                or receipt.get("schema_version") != "zscope.p6-hidden-holdout-receipt.v1"
            ):
                raise P6ProtocolError("P6 hidden holdout receipt schema is invalid")
            components = receipt.get("component_counts")
            if not isinstance(components, Mapping) or set(components) != {
                "security_spec",
                "hypothesis_hunter",
                "proof",
            }:
                raise P6ProtocolError("P6 hidden holdout component counts are invalid")
            for component in components.values():
                if not isinstance(component, Mapping) or set(component) != {
                    "numerator",
                    "denominator",
                }:
                    raise P6ProtocolError("P6 hidden holdout component row is invalid")
                numerator = component.get("numerator")
                denominator = component.get("denominator")
                if (
                    isinstance(numerator, bool)
                    or not isinstance(numerator, int)
                    or numerator < 0
                    or isinstance(denominator, bool)
                    or not isinstance(denominator, int)
                    or denominator < 1
                    or numerator > denominator
                ):
                    raise P6ProtocolError("P6 hidden holdout component accounting is invalid")
        elif args.stage == "safe_pair":
            expected_fields = {
                "schema_version",
                *common,
                "safe_count",
                "fixed_count",
                "near_miss_count",
                "false_confirmation_count",
                "usage_conservation",
                "oci_execution_receipt",
            }
            if (
                set(receipt) != expected_fields
                or receipt.get("schema_version") != "zscope.p6-safe-pair-receipt.v1"
                or receipt.get("false_confirmation_count") != 0
            ):
                raise P6ProtocolError("P6 safe-pair receipt schema is invalid")
            for name in ("safe_count", "fixed_count", "near_miss_count"):
                count = receipt.get(name)
                if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                    raise P6ProtocolError("P6 safe-pair coverage counts are invalid")
        else:
            expected_fields = {
                "schema_version",
                *common,
                "formal_eligible",
                "preflight_artifact_sha256",
                "trace_manifest_sha256",
                "trace_manifest_complete",
                "validation_llm_profile",
                "selected_cluster_count",
                "clusters_closing_at_least_one_clause",
                "protocol_error_count",
                "historical_comparable_v3_tokens",
                "comparable_cluster_count",
                "current_comparable_v3_tokens",
                "current_v3_tokens",
                "comparable_token_reduction",
                "provider_usage",
                "usage_ledger",
                "usage_conservation",
                "model_identity_counts",
                "model_canary_passed",
                "truth_inputs",
                "clusters",
                "artifact_sha256",
                "oci_execution_receipt",
            }
            body = dict(receipt)
            artifact_sha256 = body.pop("artifact_sha256", None)
            if (
                set(receipt) != expected_fields
                or receipt.get("schema_version") != "zscope.v3-action-model-canary.v1"
                or receipt.get("model_canary_passed") is not True
                or receipt.get("formal_eligible") is not False
                or receipt.get("truth_inputs") != 0
                or artifact_sha256 != canonical_sha256(body)
            ):
                raise P6ProtocolError("P6 EvidenceAction canary receipt schema is invalid")
            usage_conservation = _derive_canary_usage_conservation(receipt)
        if args.stage != "canary":
            usage_conservation = validate_usage_conservation(
                receipt.get("usage_conservation"), require_model_calls=True
            )
    elif args.stage == "reverify":
        if (
            args.receipt is None
            or args.receipt_sha256 is None
            or args.workflow_run_id is None
            or args.workflow_run_attempt is None
            or args.control_plane_commit is None
            or args.candidate_commit is None
            or args.trace_manifest_sha256 is None
            or args.trace_manifest_file_sha256 is None
            or any(
                value is not None
                for value in (
                    args.attempt_id,
                    args.harness_sha256,
                    args.qualification_input_sha256,
                    args.toolchain_evidence,
                    args.toolchain_evidence_sha256,
                )
            )
        ):
            raise P6ProtocolError("P6 certificate reverify receipt lineage is incomplete")
        source_receipt_sha256 = args.receipt_sha256
        _validate_reverify_receipt(
            args.receipt,
            args.receipt_sha256,
            expected_control_plane_commit=args.control_plane_commit,
            expected_candidate_commit=args.candidate_commit,
            expected_workflow_run_id=args.workflow_run_id,
            expected_workflow_run_attempt=args.workflow_run_attempt,
            expected_trace_manifest_sha256=args.trace_manifest_sha256,
            expected_trace_manifest_file_sha256=args.trace_manifest_file_sha256,
        )
    elif any(
        value is not None for value in (args.receipt, args.receipt_sha256, *model_receipt_lineage)
    ):
        raise P6ProtocolError("P6 zero-call stage cannot bind a model receipt")
    payload = {
        "schema_version": "zscope.p6-offline-stage.v1",
        "stage": args.stage,
        "suite_files": rows,
        "suite_root_sha256": canonical_sha256(rows),
        "source_receipt_sha256": source_receipt_sha256,
        "passed": True,
        "failure_count": 0,
        "model_call_count": 0,
        "usage_conservation": usage_conservation,
        "oci_execution_sha256s": oci_execution_sha256s,
        "toolchain_evidence_sha256": (
            qualification_context["toolchain_evidence_sha256"]
            if qualification_context is not None
            else None
        ),
        "provider_identity_sha256": (
            qualification_context["provider_identity_sha256"]
            if qualification_context is not None
            else None
        ),
        "network_policy_sha256": (
            qualification_context["network_policy_sha256"]
            if qualification_context is not None
            else None
        ),
        "runtime_source_sha256": (
            qualification_context["runtime_source_sha256"]
            if qualification_context is not None
            else None
        ),
        "oci_image": (
            qualification_context["image"] if qualification_context is not None else None
        ),
        "answer_material_present": False,
        "formal_evidence": False,
        "release_eligible": False,
    }
    payload["model_call_count"] = int(usage_conservation["physical_call_count"])
    answer_free_projection(payload, canaries=_canaries_from_args(args))
    write_json_exclusive(args.output.absolute(), payload)
    print(sha256_file(args.output.absolute()))
    return 0


def _build_review_packet(args: argparse.Namespace) -> int:
    packet_root = args.output.absolute().parent
    canaries = _canaries_from_args(args)
    rows = []
    for relative, local_path in args.artifact:
        source = local_path.absolute()
        destination = packet_root.joinpath(*Path(relative).parts)
        if source != destination.resolve():
            raise P6ProtocolError(
                "role artifact must already exist at RELATIVE_PATH under the packet output root"
            )
        value, payload, digest = read_answer_free_artifact(source, canaries=canaries)
        try:
            content = payload.decode("utf-8")
        except UnicodeError as exc:
            raise P6ProtocolError("review packet evidence must be strict UTF-8") from exc
        if not isinstance(value, Mapping):
            raise P6ProtocolError("review packet evidence must be an object")
        rows.append(
            {
                "path": relative.replace("\\", "/"),
                "sha256": digest,
                "content": content,
            }
        )
    packet = build_review_packet(
        role=args.role,
        candidate_sha256=args.candidate_sha256,
        policy_sha256=args.policy_sha256,
        qualification_sha256=args.qualification_sha256,
        evidence_root_sha256=args.evidence_root_sha256,
        artifact_files=rows,
    )
    validate_review_packet(packet, packet_root=packet_root)
    write_json_exclusive(args.output.absolute(), packet)
    print(packet["packet_sha256"])
    return 0


def _run_review(args: argparse.Namespace) -> int:
    decision = run_reviewer(
        role=args.role,
        packet_path=args.packet.absolute(),
        output_dir=args.output_dir.absolute(),
        timeout_seconds=args.timeout_seconds,
    )
    if decision["decision"] != "approved" or decision["blocker_count"] != 0:
        print("stage=independent_review; class=review_blocker:1; count=1")
        return 2
    print(f"p6_review_approved role={args.role}")
    return 0


def _aggregate_reviews(args: argparse.Namespace) -> int:
    packets = {role: Path(getattr(args, f"{role}_packet")).absolute() for role in REVIEW_ROLES}
    outputs = {role: Path(getattr(args, f"{role}_output")).absolute() for role in REVIEW_ROLES}
    payload = aggregate_review_set(packet_paths=packets, output_dirs=outputs)
    write_json_exclusive(args.output.absolute(), payload)
    print("p6_independent_reviews_approved")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    def add_lineage_arguments(command: argparse.ArgumentParser) -> None:
        command.add_argument("--workflow-run-id", required=True)
        command.add_argument("--workflow-run-attempt", required=True, type=int)
        command.add_argument("--attempt-id", required=True)
        command.add_argument("--control-plane-commit", required=True, type=_git_object)
        for name in (
            "candidate",
            "policy",
            "plan",
            "input",
            "runtime",
            "provider",
            "oci",
            "fast-cache",
            "balanced-cache",
            "deep-cache",
        ):
            command.add_argument(f"--{name}-sha256", required=True, type=_sha256)

    record = commands.add_parser("record-stage")
    record.add_argument("--run-dir", required=True, type=Path)
    record.add_argument("--workflow-run-id", required=True)
    record.add_argument("--workflow-run-attempt", required=True, type=int)
    record.add_argument("--attempt-id", required=True)
    record.add_argument("--control-plane-commit", required=True, type=_git_object)
    record.add_argument("--stage", required=True)
    record.add_argument("--status", choices=("completed", "failed", "skipped"), required=True)
    record.add_argument("--failure-class")
    record.add_argument("--failure-count", type=int, default=0)
    record.add_argument("--binding-sha256", required=True, type=_sha256)
    record.set_defaults(handler=_record_stage)

    stage_artifact = commands.add_parser("seal-stage-artifact")
    add_lineage_arguments(stage_artifact)
    stage_artifact.add_argument("--stage", required=True)
    stage_artifact.add_argument("--payload-sha256", required=True, type=_sha256)
    stage_artifact.add_argument("--output", required=True, type=Path)
    stage_artifact.set_defaults(handler=_seal_stage_artifact)

    diagnose = commands.add_parser("diagnose-pilot")
    diagnose.add_argument("--run-dir", required=True, type=Path)
    diagnose.add_argument("--output", required=True, type=Path)
    diagnose.set_defaults(handler=_diagnose)

    checkpoint = commands.add_parser("checkpoint")
    checkpoint.add_argument("--run-dir", required=True, type=Path)
    checkpoint.add_argument("--output", required=True, type=Path)
    checkpoint.add_argument("--workflow-run-id", required=True)
    checkpoint.add_argument("--workflow-run-attempt", required=True, type=int)
    checkpoint.add_argument("--attempt-id", required=True)
    checkpoint.add_argument("--control-plane-commit", required=True, type=_git_object)
    for name in (
        "candidate",
        "policy",
        "plan",
        "input",
        "runtime",
        "provider",
        "oci",
        "fast-cache",
        "balanced-cache",
        "deep-cache",
    ):
        checkpoint.add_argument(f"--{name}-sha256", required=True, type=_sha256)
    checkpoint.set_defaults(handler=_checkpoint)

    validate_checkpoint_command = commands.add_parser("validate-checkpoint")
    validate_checkpoint_command.add_argument("--checkpoint", required=True, type=Path)
    validate_checkpoint_command.add_argument("--artifact-root", required=True, type=Path)
    validate_checkpoint_command.add_argument("--run-dir", type=Path)
    validate_checkpoint_command.set_defaults(handler=_validate_checkpoint)

    finalize = commands.add_parser("finalize-checkpoint")
    finalize.add_argument("--checkpoint", required=True, type=Path)
    finalize.add_argument("--artifact-root", required=True, type=Path)
    finalize.add_argument("--run-dir", required=True, type=Path)
    finalize.add_argument("--payload", required=True, type=Path)
    finalize.add_argument("--output", required=True, type=Path)
    finalize.add_argument("--canary-env", action="append", default=[])
    add_lineage_arguments(finalize)
    finalize.set_defaults(handler=_finalize_checkpoint)

    validate_receipt = commands.add_parser("validate-repair-receipt")
    validate_receipt.add_argument("--receipt", required=True, type=Path)
    validate_receipt.add_argument("--failure-diagnostic", type=Path)
    validate_receipt.add_argument("--checkpoint", type=Path)
    validate_receipt.add_argument("--checkpoint-artifact-root", type=Path)
    validate_receipt.add_argument("--selected-producer", type=Path)
    validate_receipt.set_defaults(handler=_validate_receipt)

    answer_free = commands.add_parser("validate-answer-free")
    answer_free.add_argument("--input", required=True, type=Path)
    answer_free.add_argument("--output", type=Path)
    answer_free.add_argument("--canary-env", action="append", default=[])
    answer_free.set_defaults(handler=_validate_answer_free)

    safe_zip = commands.add_parser("validate-safe-zip")
    safe_zip.add_argument("--archive", required=True, type=Path)
    safe_zip.add_argument("--sha256", required=True, type=_sha256)
    safe_zip.set_defaults(handler=_validate_zip)

    workflow_failure = commands.add_parser("emit-workflow-failure")
    workflow_failure.add_argument("--run-dir", required=True, type=Path)
    workflow_failure.add_argument("--output", required=True, type=Path)
    workflow_failure.add_argument("--workflow-run-id", required=True)
    workflow_failure.add_argument("--workflow-run-attempt", required=True, type=int)
    workflow_failure.add_argument("--attempt-id", required=True)
    workflow_failure.add_argument("--control-plane-commit", required=True, type=_git_object)
    workflow_failure.add_argument("--stage", required=True)
    workflow_failure.add_argument("--status", choices=("failed",), required=True)
    workflow_failure.add_argument("--failure-class", required=True)
    workflow_failure.add_argument("--failure-count", type=int, required=True)
    workflow_failure.add_argument("--binding-sha256", required=True, type=_sha256)
    workflow_failure.add_argument("--checkpoint", type=Path)
    workflow_failure.add_argument("--checkpoint-artifact-root", type=Path)
    workflow_failure.set_defaults(handler=_emit_workflow_failure)

    qualification = commands.add_parser("seal-qualification")
    for depth in ("fast", "balanced", "deep"):
        qualification.add_argument(f"--{depth}", required=True, type=Path)
        qualification.add_argument(f"--{depth}-cache-sha256", required=True, type=_sha256)
    qualification.add_argument("--candidate-sha256", required=True, type=_sha256)
    qualification.add_argument("--control-plane-commit", required=True, type=_git_object)
    qualification.add_argument("--policy-sha256", required=True, type=_sha256)
    qualification.add_argument("--offline-evidence", required=True, type=Path)
    qualification.add_argument("--offline-evidence-sha256", required=True, type=_sha256)
    qualification.add_argument("--provider-probe", required=True, type=Path)
    qualification.add_argument("--provider-probe-sha256", required=True, type=_sha256)
    qualification.add_argument("--toolchain-evidence", required=True, type=Path)
    qualification.add_argument("--toolchain-evidence-sha256", required=True, type=_sha256)
    qualification.add_argument("--canary-env", action="append", default=[])
    qualification.add_argument("--attempt-id", required=True)
    qualification.add_argument("--output", required=True, type=Path)
    qualification.set_defaults(handler=_qualification)

    project = commands.add_parser("project-depth")
    project.add_argument("--aggregate", required=True, type=Path)
    project.add_argument("--scan-depth", choices=("fast", "balanced", "deep"), required=True)
    project.add_argument("--control-plane-commit", required=True, type=_git_object)
    project.add_argument("--expected-git-sha", required=True, type=_git_object)
    project.add_argument("--expected-git-tree", required=True, type=_git_object)
    project.add_argument("--toolchain-evidence", required=True, type=Path)
    project.add_argument("--toolchain-evidence-sha256", required=True, type=_sha256)
    project.add_argument("--canary-env", action="append", default=[])
    project.add_argument("--output", required=True, type=Path)
    project.set_defaults(handler=_project_depth)

    toolchain = commands.add_parser("seal-toolchain-evidence")
    toolchain.add_argument("--draft", required=True, type=Path)
    toolchain.add_argument("--control-plane-commit", required=True, type=_git_object)
    toolchain.add_argument("--candidate-commit", required=True, type=_git_object)
    toolchain.add_argument("--candidate-tree", required=True, type=_git_object)
    toolchain.add_argument("--canary-env", action="append", default=[])
    toolchain.add_argument("--output", required=True, type=Path)
    toolchain.set_defaults(handler=_seal_toolchain_evidence)

    offline = commands.add_parser("seal-offline-evidence")
    offline.add_argument("--candidate-sha256", required=True, type=_sha256)
    offline.add_argument("--policy-sha256", required=True, type=_sha256)
    offline.add_argument("--candidate-commit", required=True, type=_git_object)
    offline.add_argument("--workflow-run-id", required=True)
    offline.add_argument("--workflow-run-attempt", required=True, type=int)
    offline.add_argument("--attempt-id", required=True)
    offline.add_argument("--control-plane-commit", required=True, type=_git_object)
    offline.add_argument("--harness-sha256", required=True, type=_sha256)
    offline.add_argument("--toolchain-evidence", required=True, type=Path)
    offline.add_argument("--toolchain-evidence-sha256", required=True, type=_sha256)
    offline.add_argument("--trace-manifest-file-sha256", required=True, type=_sha256)
    for name in ("policy-replay", "reverify", "hidden-holdout", "safe-pair", "canary"):
        offline.add_argument(f"--{name}-artifact", required=True, type=Path)
        offline.add_argument(f"--{name}-sha256", required=True, type=_sha256)
    offline.add_argument("--canary-env", action="append", default=[])
    offline.add_argument("--output", required=True, type=Path)
    offline.set_defaults(handler=_offline_evidence)

    offline_stage = commands.add_parser("seal-offline-stage")
    offline_stage.add_argument(
        "--stage",
        choices=("reverify", "hidden_holdout", "safe_pair", "canary"),
        required=True,
    )
    offline_stage.add_argument("--suite-file", action="append", required=True, type=Path)
    offline_stage.add_argument("--receipt", type=Path)
    offline_stage.add_argument("--receipt-sha256", type=_sha256)
    offline_stage.add_argument("--workflow-run-id")
    offline_stage.add_argument("--workflow-run-attempt", type=int)
    offline_stage.add_argument("--attempt-id")
    offline_stage.add_argument("--control-plane-commit", type=_git_object)
    offline_stage.add_argument("--candidate-commit", type=_git_object)
    offline_stage.add_argument("--harness-sha256", type=_sha256)
    offline_stage.add_argument("--qualification-input-sha256", type=_sha256)
    offline_stage.add_argument("--toolchain-evidence", type=Path)
    offline_stage.add_argument("--toolchain-evidence-sha256", type=_sha256)
    offline_stage.add_argument("--trace-manifest-sha256", type=_sha256)
    offline_stage.add_argument("--trace-manifest-file-sha256", type=_sha256)
    offline_stage.add_argument("--canary-env", action="append", default=[])
    offline_stage.add_argument("--output", required=True, type=Path)
    offline_stage.set_defaults(handler=_seal_offline_stage)

    packet = commands.add_parser("build-review-packet")
    packet.add_argument("--role", choices=REVIEW_ROLES, required=True)
    packet.add_argument("--candidate-sha256", required=True, type=_sha256)
    packet.add_argument("--policy-sha256", required=True, type=_sha256)
    packet.add_argument("--qualification-sha256", required=True, type=_sha256)
    packet.add_argument("--evidence-root-sha256", required=True, type=_sha256)
    packet.add_argument("--artifact", action="append", required=True, type=_artifact_row)
    packet.add_argument("--canary-env", action="append", default=[])
    packet.add_argument("--output", required=True, type=Path)
    packet.set_defaults(handler=_build_review_packet)

    review = commands.add_parser("review")
    review.add_argument("--role", choices=REVIEW_ROLES, required=True)
    review.add_argument("--packet", required=True, type=Path)
    review.add_argument("--output-dir", required=True, type=Path)
    review.add_argument("--timeout-seconds", type=int, default=43200)
    review.set_defaults(handler=_run_review)

    aggregate = commands.add_parser("aggregate-reviews")
    for role in REVIEW_ROLES:
        aggregate.add_argument(f"--{role.replace('_', '-')}-packet", required=True)
        aggregate.add_argument(f"--{role.replace('_', '-')}-output", required=True)
    aggregate.add_argument("--output", required=True, type=Path)
    aggregate.set_defaults(handler=_aggregate_reviews)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except P6ProtocolError as exc:
        failure_class = str(exc)
        stage = FAILURE_CLASS_TO_STAGE.get(failure_class)
        if stage is None:
            failure_class = "internal_failure"
            stage = FAILURE_CLASS_TO_STAGE[failure_class]
        print(
            f"stage={stage}; class={failure_class}:1; count=1",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
