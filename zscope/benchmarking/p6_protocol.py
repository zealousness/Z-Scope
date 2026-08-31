"""Fail-closed protocol objects for the non-release P6 cold pilot.

This module deliberately contains no scanner, scorer, Truth, or provider response
handling.  It gives the protected workflow a small answer-free control plane for
recording the first failed boundary, preserving immutable attempts, and proving
that cold-stage artifacts were not assembled from multiple attempts.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
import re
import stat
import zipfile
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, NoReturn, Optional, Sequence, Tuple

from zscope.benchmarking.provider_runtime import P6_PROVIDER_MODEL, P6_PROVIDER_RESPONSE_MODEL


FAILURE_DIAGNOSTIC_SCHEMA_VERSION = "zscope.p6-failure-diagnostic.v1"
CHECKPOINT_SCHEMA_VERSION = "zscope.p6-checkpoint.v1"
REPAIR_RECEIPT_SCHEMA_VERSION = "zscope.p6-repair-receipt.v1"
STAGE_RESULT_SCHEMA_VERSION = "zscope.p6-stage-result.v1"
QUALIFICATION_SCHEMA_VERSION = "zscope.p6-qualification.v1"
DEPTH_PROJECTION_SCHEMA_VERSION = "zscope.p6-depth-projection.v1"
P6_WORKFLOW_PATH = ".github/workflows/p6-pilot-validation.yml"
STAGE_ARTIFACT_SCHEMA_VERSION = "zscope.p6-stage-artifact.v1"
ARTIFACT_ROOT_SCHEMA_VERSION = "zscope.p6-artifact-root.v1"
TOOLCHAIN_EVIDENCE_SCHEMA_VERSION = "zscope.p6-toolchain-oci-evidence.v1"
QUALIFICATION_OCI_RECEIPT_SCHEMA_VERSION = "zscope.p6-qualification-oci-receipt.v1"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ATTEMPT_RE = re.compile(r"^p6-[a-z0-9][a-z0-9._-]{2,127}$")
RUN_ID_RE = re.compile(r"^[1-9][0-9]*$")
IMAGE_ID_RE = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
MAX_PROTOCOL_ARTIFACT_BYTES = 64 * 1024 * 1024

P6_FAILURE_STAGE_ORDER: Tuple[str, ...] = (
    "entry_input",
    "provider",
    "toolchain_oci_cache",
    "candidates",
    "security_spec",
    "planner_hunter",
    "evidence_action",
    "proof_provider_checker",
    "terminal_authority",
    "report_finding",
    "usage_trace",
    "artifact_seal",
    "independent_review",
)

P6_EXECUTION_STAGE_ORDER: Tuple[str, ...] = (
    "entry",
    "provider_probe",
    "toolchain_oci_preflight",
    "policy_replay",
    "certificate_reverify",
    "anonymous_qualification",
    "safe_pair_validation",
    "evidence_action_canary",
    "cold_fast",
    "cold_balanced",
    "cold_deep",
    "conservation",
    "qualification_seal",
    "product_architecture_review",
    "proof_security_review",
    "independent_benchmark_review",
    "final_evidence_seal",
    "evidence_pr",
)

P6_CHECKPOINT_STAGE_ORDER: Tuple[str, ...] = P6_EXECUTION_STAGE_ORDER[
    : P6_EXECUTION_STAGE_ORDER.index("final_evidence_seal") + 1
]

EXECUTION_STAGE_TO_FAILURE_STAGE: Dict[str, str] = {
    "entry": "entry_input",
    "provider_probe": "provider",
    "toolchain_oci_preflight": "toolchain_oci_cache",
    "policy_replay": "proof_provider_checker",
    "certificate_reverify": "proof_provider_checker",
    "anonymous_qualification": "candidates",
    "safe_pair_validation": "terminal_authority",
    "evidence_action_canary": "evidence_action",
    "cold_fast": "candidates",
    "cold_balanced": "planner_hunter",
    "cold_deep": "proof_provider_checker",
    "conservation": "usage_trace",
    "qualification_seal": "artifact_seal",
    "product_architecture_review": "independent_review",
    "proof_security_review": "independent_review",
    "independent_benchmark_review": "independent_review",
    "final_evidence_seal": "artifact_seal",
    "evidence_pr": "artifact_seal",
}

FAILURE_CLASS_TO_STAGE: Dict[str, str] = {
    "entry_e0_unattested": "entry_input",
    "input_binding_failure": "entry_input",
    "provider_credentials_unavailable": "provider",
    "provider_identity_mismatch": "provider",
    "provider_identity_override_attempt": "provider",
    "provider_transport_exhausted": "provider",
    "provider_protocol_incompatible": "provider",
    "provider_usage_unverifiable": "provider",
    "toolchain_preflight_failed": "toolchain_oci_cache",
    "oci_capability_failed": "toolchain_oci_cache",
    "oci_isolation_violation": "toolchain_oci_cache",
    "cold_cache_not_isolated": "toolchain_oci_cache",
    "replay_input_binding_invalid": "entry_input",
    "certificate_reverify_failure": "proof_provider_checker",
    "replay_nondeterministic": "proof_provider_checker",
    "anonymous_qualification_failed": "candidates",
    "eligible_stage_not_entered": "planner_hunter",
    "evidence_action_not_consumed": "evidence_action",
    "terminal_state_inconsistent": "terminal_authority",
    "post_proof_call": "terminal_authority",
    "silent_rejection_without_proof": "terminal_authority",
    "safe_pair_false_confirmation": "terminal_authority",
    "coverage_gap_zero_unit": "planner_hunter",
    "quality_no_progress_gate_failed": "report_finding",
    "queue_not_drained": "usage_trace",
    "accounting_conservation_failure": "usage_trace",
    "component_metrics_incomplete": "usage_trace",
    "artifact_upload_transport_failed": "artifact_seal",
    "artifact_integrity_failure": "artifact_seal",
    "review_transport_failed": "independent_review",
    "review_binding_invalid": "independent_review",
    "review_blocker": "independent_review",
    "internal_failure": "artifact_seal",
}

TRANSPORT_RETRYABLE_FAILURES = frozenset(
    {
        "provider_transport_exhausted",
        "artifact_upload_transport_failed",
        "review_transport_failed",
    }
)

FAILURE_CLASS_TO_EXECUTION_STAGE: Dict[str, str] = {
    "entry_e0_unattested": "entry",
    "input_binding_failure": "entry",
    "provider_credentials_unavailable": "provider_probe",
    "provider_identity_mismatch": "provider_probe",
    "provider_identity_override_attempt": "provider_probe",
    "provider_transport_exhausted": "provider_probe",
    "provider_protocol_incompatible": "provider_probe",
    "provider_usage_unverifiable": "provider_probe",
    "toolchain_preflight_failed": "toolchain_oci_preflight",
    "oci_capability_failed": "toolchain_oci_preflight",
    "oci_isolation_violation": "toolchain_oci_preflight",
    "cold_cache_not_isolated": "toolchain_oci_preflight",
    "replay_input_binding_invalid": "policy_replay",
    "certificate_reverify_failure": "certificate_reverify",
    "replay_nondeterministic": "policy_replay",
    "anonymous_qualification_failed": "anonymous_qualification",
    "eligible_stage_not_entered": "anonymous_qualification",
    "evidence_action_not_consumed": "evidence_action_canary",
    "terminal_state_inconsistent": "cold_fast",
    "post_proof_call": "cold_fast",
    "silent_rejection_without_proof": "cold_fast",
    "safe_pair_false_confirmation": "safe_pair_validation",
    "coverage_gap_zero_unit": "anonymous_qualification",
    "quality_no_progress_gate_failed": "cold_fast",
    "queue_not_drained": "conservation",
    "accounting_conservation_failure": "conservation",
    "component_metrics_incomplete": "conservation",
    "artifact_upload_transport_failed": "qualification_seal",
    "artifact_integrity_failure": "qualification_seal",
    "review_transport_failed": "product_architecture_review",
    "review_binding_invalid": "product_architecture_review",
    "review_blocker": "product_architecture_review",
}

FAILURE_CLASS_TO_EXECUTION_STAGES: Dict[str, Tuple[str, ...]] = {
    failure_class: (stage,) for failure_class, stage in FAILURE_CLASS_TO_EXECUTION_STAGE.items()
}
FAILURE_CLASS_TO_EXECUTION_STAGES.update(
    {
        "provider_credentials_unavailable": (
            "provider_probe",
            "cold_fast",
            "cold_balanced",
            "cold_deep",
        ),
        "provider_identity_mismatch": (
            "provider_probe",
            "cold_fast",
            "cold_balanced",
            "cold_deep",
        ),
        "provider_identity_override_attempt": (
            "provider_probe",
            "cold_fast",
            "cold_balanced",
            "cold_deep",
        ),
        "provider_transport_exhausted": (
            "provider_probe",
            "cold_fast",
            "cold_balanced",
            "cold_deep",
        ),
        "provider_protocol_incompatible": (
            "provider_probe",
            "cold_fast",
            "cold_balanced",
            "cold_deep",
        ),
        "provider_usage_unverifiable": (
            "provider_probe",
            "cold_fast",
            "cold_balanced",
            "cold_deep",
        ),
        "oci_isolation_violation": (
            "toolchain_oci_preflight",
            "cold_fast",
            "cold_balanced",
            "cold_deep",
        ),
        "cold_cache_not_isolated": (
            "toolchain_oci_preflight",
            "cold_fast",
            "cold_balanced",
            "cold_deep",
        ),
        "terminal_state_inconsistent": ("cold_fast", "cold_balanced", "cold_deep"),
        "post_proof_call": ("cold_fast", "cold_balanced", "cold_deep"),
        "silent_rejection_without_proof": (
            "cold_fast",
            "cold_balanced",
            "cold_deep",
        ),
        "quality_no_progress_gate_failed": (
            "cold_fast",
            "cold_balanced",
            "cold_deep",
        ),
        "queue_not_drained": (
            "cold_fast",
            "cold_balanced",
            "cold_deep",
            "conservation",
        ),
        "accounting_conservation_failure": (
            "cold_fast",
            "cold_balanced",
            "cold_deep",
            "conservation",
        ),
        "component_metrics_incomplete": (
            "cold_fast",
            "cold_balanced",
            "cold_deep",
            "conservation",
        ),
        "artifact_upload_transport_failed": (
            "qualification_seal",
            "final_evidence_seal",
            "evidence_pr",
        ),
        "artifact_integrity_failure": (
            "qualification_seal",
            "final_evidence_seal",
            "evidence_pr",
        ),
        "review_transport_failed": (
            "product_architecture_review",
            "proof_security_review",
            "independent_benchmark_review",
        ),
        "review_binding_invalid": (
            "product_architecture_review",
            "proof_security_review",
            "independent_benchmark_review",
        ),
        "review_blocker": (
            "product_architecture_review",
            "proof_security_review",
            "independent_benchmark_review",
        ),
    }
)

_STAGE_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "workflow_run_id",
        "workflow_run_attempt",
        "attempt_id",
        "control_plane_commit",
        "stage",
        "status",
        "failure_class",
        "failure_count",
        "binding_sha256",
    }
)

_CHECKPOINT_FIELDS = frozenset(
    {
        "schema_version",
        "workflow_path",
        "workflow_run_id",
        "workflow_run_attempt",
        "attempt_id",
        "control_plane_commit",
        "status",
        "completed_stages",
        "stage_artifacts",
        "candidate_sha256",
        "policy_sha256",
        "plan_sha256",
        "input_sha256",
        "runtime_sha256",
        "provider_sha256",
        "oci_sha256",
        "artifact_root_sha256",
        "cold_cache_identities",
        "formal_evidence",
        "release_eligible",
        "requires_full_revalidation",
        "zero_call_finalizable",
    }
)

_DIAGNOSTIC_FIELDS = frozenset(
    {
        "schema_version",
        "workflow_run_id",
        "workflow_run_attempt",
        "attempt_id",
        "control_plane_commit",
        "stage",
        "failure_class",
        "failure_count",
        "total_count",
        "checkpoint_sha256",
        "binding_sha256",
        "formal_evidence",
        "release_eligible",
    }
)

_REPAIR_FIELDS = frozenset(
    {
        "schema_version",
        "failed_attempt_id",
        "control_plane_commit",
        "failure_diagnostic_sha256",
        "checkpoint_sha256",
        "frozen_failure_artifact_sha256",
        "answer_free_reproduction_sha256",
        "repair_pr_number",
        "repair_merge_sha",
        "invalidated_from_stage",
        "invalidated_stages",
        "new_attempt_id",
        "selected_producer_attempt_id",
        "selected_producer_schema_version",
        "selected_producer_artifact_sha256",
        "formal_evidence",
        "release_eligible",
    }
)

_STAGE_ARTIFACT_FIELDS = frozenset(
    {
        "schema_version",
        "workflow_path",
        "workflow_run_id",
        "workflow_run_attempt",
        "attempt_id",
        "control_plane_commit",
        "stage",
        "candidate_sha256",
        "policy_sha256",
        "plan_sha256",
        "input_sha256",
        "runtime_sha256",
        "provider_sha256",
        "oci_sha256",
        "cold_cache_identities_sha256",
        "binding_sha256",
        "payload_sha256",
        "formal_evidence",
        "release_eligible",
    }
)

_LINEAGE_SHA_FIELDS: Tuple[str, ...] = (
    "candidate_sha256",
    "policy_sha256",
    "plan_sha256",
    "input_sha256",
    "runtime_sha256",
    "provider_sha256",
    "oci_sha256",
)

# These are deliberately exact normalized keys.  Hash-only bindings such as
# ``source_sha256`` and accounting fields such as ``token_count`` remain
# admissible, while answer-bearing values fail closed instead of being silently
# deleted from an upload or reviewer packet.
_FORBIDDEN_ANSWER_KEYS = frozenset(
    {
        "api_key",
        "access_token",
        "bearer_token",
        "credential",
        "credentials",
        "secret",
        "source",
        "source_code",
        "source_text",
        "generated_source",
        "product_source",
        "log",
        "logs",
        "stdout",
        "stderr",
        "prompt",
        "prompt_text",
        "system_prompt",
        "user_prompt",
        "response",
        "raw_response",
        "model_response",
        "model_output",
        "output_text",
        "truth",
        "ground_truth",
        "expected",
        "hidden_expected",
        "scorer",
        "score_key",
    }
)

_FORBIDDEN_PATH_TOKENS = frozenset(
    {
        "ground_truth",
        "ground-truth",
        "truth",
        "expected",
        "scorer",
        "source",
        "prompt",
        "response",
        "model-output",
        "model_output",
        "stdout",
        "stderr",
        "secret",
    }
)

P6_CONSERVATION_DIMENSIONS: Tuple[str, ...] = (
    "token",
    "tool",
    "trace",
    "finding",
    "terminal",
)

_CONSERVATION_FIELDS = frozenset(
    {
        "physical_call_count",
        "provider_reported_call_count",
        "estimated_call_count",
        "provider_usage_coverage",
        "requested_model",
        "requested_model_coverage",
        "response_model",
        "response_model_coverage",
        "queue_empty",
        "dimensions",
    }
)
_PROVIDER_PROBE_FIELDS = frozenset(
    {
        "schema_version",
        "stage",
        "passed",
        "call_count",
        "provider_usage_coverage",
        "estimated_provider_call_count",
        "provider_identity_sha256",
        "config_sha256",
        "model",
        "usage_conservation",
    }
)
_TOOLCHAIN_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "workflow_path",
        "workflow_run_id",
        "workflow_run_attempt",
        "attempt_id",
        "control_plane_commit",
        "candidate_sha256",
        "candidate_git_sha",
        "candidate_git_tree",
        "image_ref",
        "image_digest",
        "image_id",
        "runtime_source_sha256",
        "oci_execution_sha256",
        "rootless_verified",
        "image_digest_verified",
        "mounts_verified",
        "network_restriction_verified",
        "runtime_source_mounted",
        "formal_evidence",
        "release_eligible",
        "evidence_sha256",
    }
)
_QUALIFICATION_OCI_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "mode",
        "runtime",
        "runtime_path",
        "image",
        "available",
        "runtime_info_sha256",
        "image_inspect_sha256",
        "image_id",
        "network_inspect_sha256",
        "network_membership_sha256",
        "proxy_inspect_sha256",
        "rootless_verified",
        "image_digest_verified",
        "network_internal",
        "network_policy_sha256",
        "network_name",
        "endpoint_origin",
        "provider_identity_sha256",
        "proxy_credential_metadata_safe",
        "proxy_container_id",
        "proxy_running",
        "execution_verified",
        "actual_inspection_collected",
        "release_capable",
        "truth_mounted",
        "repository_mounted",
        "runtime_source_mounted",
        "runtime_source_sha256",
        "scanner_cwd",
        "scanner_cwd_isolated",
        "mounts",
        "mounts_verified",
        "security_verified",
        "network_mode",
        "network_restriction_verified",
        "phase_executions",
        "required_phases",
        "errors",
    }
)
_QUALIFICATION_OCI_PHASE_FIELDS = frozenset(
    {
        "phase",
        "container_name",
        "container_id",
        "command_return_code",
        "container_exit_code",
        "accepted_returncodes",
        "working_dir",
        "image",
        "image_id",
        "image_verified",
        "read_only_rootfs",
        "cap_drop",
        "cap_drop_verified",
        "security_opt",
        "security_verified",
        "scanner_labels_verified",
        "p6_cleanup_scope_verified",
        "p6_workflow_run_id",
        "p6_workflow_run_attempt",
        "p6_attempt_id",
        "p6_repository",
        "p6_concurrency_group",
        "p6_phase",
        "scanner_provider_environment_verified",
        "scanner_provider_environment_keys",
        "stdout_persisted",
        "stderr_persisted",
        "mounts",
        "unexpected_mount_count",
        "network_name",
        "runtime_network_mode",
        "network_attachment_verified",
        "network_peer_count",
        "network_peers_verified",
        "network_internal",
        "network_contract_verified",
        "proxy_verified",
        "proxy_credential_metadata_safe",
        "provider_identity_sha256",
        "container_inspect_sha256",
        "proxy_inspect_sha256",
        "network_inspect_sha256",
        "network_membership_sha256",
        "inspect_verified",
        "cancellation_cleanup_guard_verified",
    }
)


class P6ProtocolError(RuntimeError):
    """Raised when a P6 protocol object fails closed."""


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def read_regular_file_once(path: Path, *, max_bytes: int = MAX_PROTOCOL_ARTIFACT_BYTES) -> bytes:
    """Read one immutable regular file through a no-follow descriptor.

    Both pathname replacement and in-place mutation fail closed.  Callers use
    the returned bytes for every subsequent hash, parse, validation, and copy;
    no security decision may reopen the path.
    """

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise P6ProtocolError("protocol artifact size bound is invalid")
    try:
        before = path.lstat()
    except OSError as exc:
        raise P6ProtocolError(f"protocol artifact is unavailable: {path}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise P6ProtocolError(f"protocol artifact must be a regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise P6ProtocolError(f"protocol artifact cannot be opened safely: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            raise P6ProtocolError("protocol artifact changed before secure open")
        chunks: List[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > max_bytes:
                raise P6ProtocolError("protocol artifact exceeds the bounded size")
        after = os.fstat(descriptor)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
            or size != after.st_size
        ):
            raise P6ProtocolError("protocol artifact changed during secure read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(read_regular_file_once(path)).hexdigest()


def _require_regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise P6ProtocolError(f"protocol artifact must be a regular file: {path}")


def load_json_strict(path: Path) -> Any:
    return load_json_bytes_strict(read_regular_file_once(path), name=str(path))


def load_json_bytes_strict(payload: bytes, *, name: str = "protocol artifact") -> Any:

    def no_duplicates(rows: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise P6ProtocolError(f"duplicate JSON key in protocol artifact: {key}")
            result[key] = value
        return result

    def no_constants(value: str) -> NoReturn:
        raise ValueError(f"non-finite JSON number: {value}")

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=no_constants,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise P6ProtocolError(f"protocol artifact is not strict UTF-8 JSON: {name}") from exc


def write_json_exclusive(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise P6ProtocolError(f"refusing to overwrite immutable P6 artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    try:
        with path.open("xb") as handle:
            handle.write(encoded)
    except FileExistsError as exc:
        raise P6ProtocolError(f"refusing to overwrite immutable P6 artifact: {path}") from exc


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")


def answer_free_projection(value: Any, *, canaries: Sequence[str] = ()) -> Any:
    """Return a deterministic JSON projection after an answer-material gate.

    The function never redacts.  Redaction could turn a contaminated object
    into apparently clean evidence, so any forbidden key or caller-supplied
    canary aborts the operation.  The round trip also rejects Python-only
    values (bytes, tuples with non-JSON members, NaN, custom mappings).
    """

    normalized_canaries: Tuple[str, ...] = tuple(
        item for item in canaries if isinstance(item, str) and item
    )

    def visit(item: Any) -> Any:
        if item is None or isinstance(item, (bool, int, str)):
            if isinstance(item, str) and any(canary in item for canary in normalized_canaries):
                raise P6ProtocolError("P6 answer-free projection contains a protected canary")
            return item
        if isinstance(item, float):
            if not (item == item and item not in {float("inf"), float("-inf")}):
                raise P6ProtocolError("P6 answer-free projection contains a non-finite number")
            return item
        if isinstance(item, list):
            return [visit(nested) for nested in item]
        if isinstance(item, Mapping):
            projected: Dict[str, Any] = {}
            for raw_key, nested in item.items():
                if not isinstance(raw_key, str):
                    raise P6ProtocolError("P6 answer-free projection keys must be strings")
                if _normalized_key(raw_key) in _FORBIDDEN_ANSWER_KEYS:
                    raise P6ProtocolError(
                        "P6 answer-free projection contains forbidden answer material"
                    )
                if raw_key in projected:
                    raise P6ProtocolError("P6 answer-free projection contains duplicate keys")
                projected[raw_key] = visit(nested)
            return {key: projected[key] for key in sorted(projected)}
        raise P6ProtocolError("P6 answer-free projection contains a non-JSON value")

    result = visit(value)
    try:
        json.dumps(result, allow_nan=False, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise P6ProtocolError("P6 answer-free projection is not strict JSON") from exc
    return result


def validate_answer_free_artifact(path: Path, *, canaries: Sequence[str] = ()) -> str:
    """Validate a JSON artifact before upload or inclusion in a review packet."""

    _, _, digest = read_answer_free_artifact(path, canaries=canaries)
    return digest


def read_answer_free_artifact(
    path: Path, *, canaries: Sequence[str] = ()
) -> Tuple[Any, bytes, str]:
    """Read, parse, gate, and hash one answer-free artifact exactly once."""

    lowered_parts = {_normalized_key(part) for part in path.parts}
    forbidden = {_normalized_key(item) for item in _FORBIDDEN_PATH_TOKENS}
    if any(
        token == part or part.startswith(f"{token}_") or part.endswith(f"_{token}")
        for part in lowered_parts
        for token in forbidden
    ):
        raise P6ProtocolError("P6 answer-free artifact path is forbidden")
    payload = read_regular_file_once(path)
    value = load_json_bytes_strict(payload, name=str(path))
    answer_free_projection(value, canaries=canaries)
    return value, payload, hashlib.sha256(payload).hexdigest()


def read_safe_zip(
    path: Path,
    *,
    expected_sha256: Optional[str] = None,
    max_entries: int = 256,
    max_total_size: int = 64 * 1024 * 1024,
    max_entry_size: int = 16 * 1024 * 1024,
) -> Tuple[bytes, str]:
    """Read and validate a ZIP through one no-follow descriptor."""

    payload = read_regular_file_once(path, max_bytes=max_total_size)
    digest = validate_safe_zip_bytes(
        payload,
        expected_sha256=expected_sha256,
        max_entries=max_entries,
        max_total_size=max_total_size,
        max_entry_size=max_entry_size,
    )
    return payload, digest


def validate_safe_zip(
    path: Path,
    *,
    expected_sha256: Optional[str] = None,
    max_entries: int = 256,
    max_total_size: int = 64 * 1024 * 1024,
    max_entry_size: int = 16 * 1024 * 1024,
) -> str:
    """Validate immutable ZIP metadata and payload through one secure read."""

    _, digest = read_safe_zip(
        path,
        expected_sha256=expected_sha256,
        max_entries=max_entries,
        max_total_size=max_total_size,
        max_entry_size=max_entry_size,
    )
    return digest


def validate_safe_zip_bytes(
    payload: bytes,
    *,
    expected_sha256: Optional[str] = None,
    max_entries: int = 256,
    max_total_size: int = 64 * 1024 * 1024,
    max_entry_size: int = 16 * 1024 * 1024,
) -> str:
    """Validate one already-captured ZIP byte string without reopening a path."""

    digest = hashlib.sha256(payload).hexdigest()
    if expected_sha256 is not None and digest != _expect_sha256(
        expected_sha256, name="ZIP SHA-256"
    ):
        raise P6ProtocolError("P6 ZIP digest binding is invalid")
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload), "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise P6ProtocolError("P6 artifact is not a valid ZIP") from exc
    with archive:
        members = archive.infolist()
        if not members or len(members) > max_entries:
            raise P6ProtocolError("P6 ZIP entry count is invalid")
        seen: set[str] = set()
        total = 0
        for member in members:
            name = member.filename
            if "\\" in name or "\x00" in name:
                raise P6ProtocolError("P6 ZIP contains a non-canonical path")
            pure = PurePosixPath(name)
            if (
                pure.is_absolute()
                or not pure.parts
                or any(part in {"", ".", ".."} for part in pure.parts)
                or ":" in pure.parts[0]
            ):
                raise P6ProtocolError("P6 ZIP contains path traversal")
            canonical = pure.as_posix().rstrip("/")
            folded = canonical.casefold()
            if not canonical or folded in seen:
                raise P6ProtocolError("P6 ZIP contains duplicate paths")
            seen.add(folded)
            if member.flag_bits & 0x1:
                raise P6ProtocolError("P6 ZIP contains an encrypted member")
            mode = (member.external_attr >> 16) & 0xFFFF
            kind = stat.S_IFMT(mode)
            if kind == stat.S_IFLNK or (kind not in {0, stat.S_IFREG, stat.S_IFDIR}):
                raise P6ProtocolError("P6 ZIP contains a link or special file")
            if member.file_size < 0 or member.file_size > max_entry_size:
                raise P6ProtocolError("P6 ZIP member size is invalid")
            total += member.file_size
            if total > max_total_size:
                raise P6ProtocolError("P6 ZIP uncompressed size is invalid")
            if member.compress_size == 0 and member.file_size > 0:
                raise P6ProtocolError("P6 ZIP compression metadata is invalid")
            if member.compress_size > 0 and member.file_size > member.compress_size * 1000:
                raise P6ProtocolError("P6 ZIP compression ratio is unsafe")
        try:
            corrupt = archive.testzip()
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise P6ProtocolError("P6 ZIP integrity validation failed") from exc
        if corrupt is not None:
            raise P6ProtocolError("P6 ZIP CRC validation failed")
    return digest


def _expect_exact_fields(value: Mapping[str, Any], expected: frozenset[str], *, name: str) -> None:
    fields = set(value)
    missing = sorted(expected - fields)
    extra = sorted(fields - expected)
    if missing or extra:
        raise P6ProtocolError(f"{name} fields are invalid; missing={missing}; extra={extra}")


def _expect_sha256(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise P6ProtocolError(f"{name} must be a lowercase SHA-256")
    return value


def _expect_attempt(value: Any, *, name: str = "attempt_id") -> str:
    if not isinstance(value, str) or not ATTEMPT_RE.fullmatch(value):
        raise P6ProtocolError(f"{name} is invalid")
    return value


def _expect_commit(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        raise P6ProtocolError(f"{name} must be one lowercase 40-hex Git commit")
    return value


def _expect_run_identity(value: Mapping[str, Any]) -> Tuple[str, int, str]:
    run_id = value.get("workflow_run_id")
    run_attempt = value.get("workflow_run_attempt")
    attempt_id = value.get("attempt_id")
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise P6ProtocolError("workflow_run_id is invalid")
    if isinstance(run_attempt, bool) or not isinstance(run_attempt, int) or run_attempt < 1:
        raise P6ProtocolError("workflow_run_attempt is invalid")
    return run_id, run_attempt, _expect_attempt(attempt_id)


def _expect_non_release(value: Mapping[str, Any]) -> None:
    if value.get("formal_evidence") is not False or value.get("release_eligible") is not False:
        raise P6ProtocolError("P6 protocol objects are permanently non-formal and non-release")


def zero_usage_conservation() -> Mapping[str, Any]:
    return {
        "physical_call_count": 0,
        "provider_reported_call_count": 0,
        "estimated_call_count": 0,
        "provider_usage_coverage": 1.0,
        "requested_model": P6_PROVIDER_MODEL,
        "requested_model_coverage": 1.0,
        "response_model": P6_PROVIDER_RESPONSE_MODEL,
        "response_model_coverage": 1.0,
        "queue_empty": True,
        "dimensions": {
            name: {"numerator": 0, "denominator": 0, "conserved": True}
            for name in P6_CONSERVATION_DIMENSIONS
        },
    }


def validate_usage_conservation(
    value: Any,
    *,
    require_model_calls: Optional[bool] = None,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _CONSERVATION_FIELDS:
        raise P6ProtocolError("P6 usage conservation fields are invalid")
    physical = value.get("physical_call_count")
    reported = value.get("provider_reported_call_count")
    estimated = value.get("estimated_call_count")
    if any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0
        for item in (physical, reported, estimated)
    ):
        raise P6ProtocolError("P6 usage conservation call counts are invalid")
    assert isinstance(physical, int) and not isinstance(physical, bool)
    assert isinstance(reported, int) and not isinstance(reported, bool)
    assert isinstance(estimated, int) and not isinstance(estimated, bool)
    if physical != reported or estimated != 0:
        raise P6ProtocolError("P6 usage conservation call accounting is invalid")
    if require_model_calls is True and int(physical) < 1:
        raise P6ProtocolError("P6 model stage has no physical model calls")
    if require_model_calls is False and int(physical) != 0:
        raise P6ProtocolError("P6 zero-call stage contains physical model calls")
    if (
        value.get("provider_usage_coverage") != 1.0
        or value.get("requested_model") != P6_PROVIDER_MODEL
        or value.get("requested_model_coverage") != 1.0
        or value.get("response_model") != P6_PROVIDER_RESPONSE_MODEL
        or value.get("response_model_coverage") != 1.0
        or value.get("queue_empty") is not True
    ):
        raise P6ProtocolError("P6 usage conservation identity or queue is invalid")
    dimensions = value.get("dimensions")
    if not isinstance(dimensions, Mapping) or set(dimensions) != set(P6_CONSERVATION_DIMENSIONS):
        raise P6ProtocolError("P6 usage conservation dimensions are incomplete")
    for name in P6_CONSERVATION_DIMENSIONS:
        row = dimensions[name]
        if not isinstance(row, Mapping) or set(row) != {
            "numerator",
            "denominator",
            "conserved",
        }:
            raise P6ProtocolError("P6 usage conservation dimension fields are invalid")
        numerator = row.get("numerator")
        denominator = row.get("denominator")
        if (
            isinstance(numerator, bool)
            or not isinstance(numerator, int)
            or numerator < 0
            or isinstance(denominator, bool)
            or not isinstance(denominator, int)
            or denominator < 0
            or numerator != denominator
            or row.get("conserved") is not True
        ):
            raise P6ProtocolError(f"P6 {name} conservation is invalid")
    return copy.deepcopy(dict(value))


def combine_usage_conservation(rows: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    if not rows:
        raise P6ProtocolError("P6 global usage conservation is empty")
    validated = [validate_usage_conservation(row) for row in rows]
    combined = dict(zero_usage_conservation())
    combined["physical_call_count"] = sum(int(row["physical_call_count"]) for row in validated)
    combined["provider_reported_call_count"] = sum(
        int(row["provider_reported_call_count"]) for row in validated
    )
    dimensions: Dict[str, Any] = {}
    for name in P6_CONSERVATION_DIMENSIONS:
        numerator = sum(int(row["dimensions"][name]["numerator"]) for row in validated)
        denominator = sum(int(row["dimensions"][name]["denominator"]) for row in validated)
        dimensions[name] = {
            "numerator": numerator,
            "denominator": denominator,
            "conserved": numerator == denominator,
        }
    combined["dimensions"] = dimensions
    return validate_usage_conservation(combined)


def validate_provider_probe(value: Mapping[str, Any]) -> None:
    """Validate the source-free physical deepseek-v4-flash provider probe."""

    _expect_exact_fields(value, _PROVIDER_PROBE_FIELDS, name="P6 provider probe")
    if (
        value.get("schema_version") != "zscope.p6-provider-probe.v1"
        or value.get("stage") != "provider"
        or value.get("passed") is not True
        or value.get("call_count") != 1
        or isinstance(value.get("call_count"), bool)
        or value.get("provider_usage_coverage") != 1.0
        or value.get("estimated_provider_call_count") != 0
        or value.get("model") != P6_PROVIDER_MODEL
    ):
        raise P6ProtocolError("P6 provider probe invariants are invalid")
    _expect_sha256(value.get("provider_identity_sha256"), name="provider probe identity")
    _expect_sha256(value.get("config_sha256"), name="provider probe config")
    conservation = validate_usage_conservation(
        value.get("usage_conservation"), require_model_calls=True
    )
    if conservation["physical_call_count"] != 1:
        raise P6ProtocolError("P6 provider probe call conservation is invalid")
    answer_free_projection(value)


def provider_probe_projection(value: Mapping[str, Any], *, file_sha256: str) -> Mapping[str, Any]:
    validate_provider_probe(value)
    _expect_sha256(file_sha256, name="provider probe artifact SHA-256")
    return {
        "artifact_sha256": file_sha256,
        "provider_identity_sha256": value["provider_identity_sha256"],
        "config_sha256": value["config_sha256"],
        "model": P6_PROVIDER_MODEL,
        "call_count": 1,
        "provider_usage_coverage": 1.0,
        "estimated_provider_call_count": 0,
        "usage_conservation": copy.deepcopy(value["usage_conservation"]),
    }


def validate_toolchain_evidence(
    value: Mapping[str, Any],
    *,
    expected_run_id: Optional[str] = None,
    expected_run_attempt: Optional[int] = None,
    expected_attempt_id: Optional[str] = None,
    expected_control_plane_commit: Optional[str] = None,
    expected_candidate_sha256: Optional[str] = None,
    expected_git_sha: Optional[str] = None,
    expected_git_tree: Optional[str] = None,
) -> None:
    _expect_exact_fields(value, _TOOLCHAIN_EVIDENCE_FIELDS, name="P6 toolchain evidence")
    if value.get("schema_version") != TOOLCHAIN_EVIDENCE_SCHEMA_VERSION:
        raise P6ProtocolError("P6 toolchain evidence schema version is invalid")
    if value.get("workflow_path") != P6_WORKFLOW_PATH:
        raise P6ProtocolError("P6 toolchain evidence workflow is invalid")
    run_id, run_attempt, attempt_id = _expect_run_identity(value)
    if expected_run_id is not None and run_id != expected_run_id:
        raise P6ProtocolError("P6 toolchain evidence run ID is invalid")
    if expected_run_attempt is not None and run_attempt != expected_run_attempt:
        raise P6ProtocolError("P6 toolchain evidence run attempt is invalid")
    if expected_attempt_id is not None and attempt_id != expected_attempt_id:
        raise P6ProtocolError("P6 toolchain evidence attempt ID is invalid")
    control_plane_commit = _expect_commit(
        value.get("control_plane_commit"), name="toolchain control-plane commit"
    )
    if (
        expected_control_plane_commit is not None
        and control_plane_commit != expected_control_plane_commit
    ):
        raise P6ProtocolError("P6 toolchain control-plane commit is invalid")
    candidate_sha256 = _expect_sha256(
        value.get("candidate_sha256"), name="toolchain candidate SHA-256"
    )
    git_sha = value.get("candidate_git_sha")
    git_tree = value.get("candidate_git_tree")
    if (
        not isinstance(git_sha, str)
        or COMMIT_RE.fullmatch(git_sha) is None
        or not isinstance(git_tree, str)
        or COMMIT_RE.fullmatch(git_tree) is None
    ):
        raise P6ProtocolError("P6 toolchain evidence Git identity is invalid")
    if candidate_sha256 != hashlib.sha256(git_sha.encode("utf-8")).hexdigest():
        raise P6ProtocolError("P6 toolchain candidate commit binding is invalid")
    if expected_candidate_sha256 is not None and candidate_sha256 != expected_candidate_sha256:
        raise P6ProtocolError("P6 toolchain candidate SHA-256 is invalid")
    if expected_git_sha is not None and git_sha != expected_git_sha:
        raise P6ProtocolError("P6 toolchain candidate Git SHA is invalid")
    if expected_git_tree is not None and git_tree != expected_git_tree:
        raise P6ProtocolError("P6 toolchain candidate Git tree is invalid")
    image_ref = value.get("image_ref")
    image_digest = value.get("image_digest")
    image_id = value.get("image_id")
    if (
        not isinstance(image_ref, str)
        or image_ref.count("@sha256:") != 1
        or not isinstance(image_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest) is None
        or image_ref.rsplit("@", 1)[1] != image_digest
        or not isinstance(image_id, str)
        or IMAGE_ID_RE.fullmatch(image_id) is None
    ):
        raise P6ProtocolError("P6 toolchain OCI image identity is invalid")
    _expect_sha256(value.get("runtime_source_sha256"), name="runtime source root")
    _expect_sha256(value.get("oci_execution_sha256"), name="OCI execution SHA-256")
    for name in (
        "rootless_verified",
        "image_digest_verified",
        "mounts_verified",
        "network_restriction_verified",
        "runtime_source_mounted",
    ):
        if value.get(name) is not True:
            raise P6ProtocolError(f"P6 toolchain {name} is not verified")
    _expect_non_release(value)
    claimed = _expect_sha256(value.get("evidence_sha256"), name="toolchain evidence hash")
    unhashed = dict(value)
    unhashed.pop("evidence_sha256")
    if claimed != canonical_sha256(unhashed):
        raise P6ProtocolError("P6 toolchain evidence hash is invalid")
    answer_free_projection(value)


def seal_toolchain_evidence(draft: Mapping[str, Any]) -> Mapping[str, Any]:
    expected = frozenset(_TOOLCHAIN_EVIDENCE_FIELDS - {"evidence_sha256"})
    _expect_exact_fields(draft, expected, name="P6 toolchain evidence draft")
    payload = copy.deepcopy(dict(draft))
    payload["evidence_sha256"] = canonical_sha256(payload)
    validate_toolchain_evidence(payload)
    return payload


def toolchain_evidence_projection(
    value: Mapping[str, Any], *, file_sha256: str
) -> Mapping[str, Any]:
    validate_toolchain_evidence(value)
    _expect_sha256(file_sha256, name="toolchain evidence file hash")
    return {
        "artifact_sha256": file_sha256,
        "evidence_sha256": value["evidence_sha256"],
        "control_plane_commit": value["control_plane_commit"],
        "candidate_git_sha": value["candidate_git_sha"],
        "candidate_git_tree": value["candidate_git_tree"],
        "image_ref": value["image_ref"],
        "image_digest": value["image_digest"],
        "image_id": value["image_id"],
        "runtime_source_sha256": value["runtime_source_sha256"],
        "oci_execution_sha256": value["oci_execution_sha256"],
    }


def validate_qualification_oci_receipt(
    value: Mapping[str, Any],
    *,
    expected_provider_identity_sha256: str,
    expected_network_policy_sha256: str,
    expected_network_name: str,
    expected_endpoint_origin: str,
    expected_image: str,
    expected_runtime_source_sha256: str,
    expected_workflow_run_id: str,
    expected_workflow_run_attempt: int,
    expected_attempt_id: str,
    expected_repository: str,
) -> Tuple[str, ...]:
    """Validate runner-inspected OCI facts emitted by a qualification harness.

    The harness is separately digest-pinned by the workflow.  This receipt is
    deliberately not a set of summary booleans: it carries the exact sanitized
    ``RootlessOciExecutor.execution_evidence`` objects, which the control plane
    revalidates and binds to the frozen provider, network, image, and candidate
    runtime-source identities.  Extra fields fail closed so captured output or
    environment values cannot hitchhike into an uploaded receipt.
    """

    from zscope.benchmarking.isolation import validate_oci_execution_evidence

    _expect_exact_fields(
        value,
        frozenset({"schema_version", "executions", "execution_sha256s"}),
        name="P6 qualification OCI receipt",
    )
    if value.get("schema_version") != QUALIFICATION_OCI_RECEIPT_SCHEMA_VERSION:
        raise P6ProtocolError("P6 qualification OCI receipt schema version is invalid")
    provider_identity = _expect_sha256(
        expected_provider_identity_sha256, name="qualification provider identity"
    )
    network_policy = _expect_sha256(
        expected_network_policy_sha256, name="qualification network policy"
    )
    runtime_source = _expect_sha256(
        expected_runtime_source_sha256, name="qualification runtime source"
    )
    if not isinstance(expected_network_name, str) or not expected_network_name:
        raise P6ProtocolError("P6 qualification network name is invalid")
    if not isinstance(expected_endpoint_origin, str) or not expected_endpoint_origin:
        raise P6ProtocolError("P6 qualification endpoint origin is invalid")
    if (
        not isinstance(expected_image, str)
        or expected_image.count("@sha256:") != 1
        or re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", expected_image) is None
    ):
        raise P6ProtocolError("P6 qualification image identity is invalid")

    executions = value.get("executions")
    if not isinstance(executions, list) or not 1 <= len(executions) <= 64:
        raise P6ProtocolError("P6 qualification OCI execution set is invalid")
    execution_hashes: List[str] = []
    for execution in executions:
        if not isinstance(execution, Mapping):
            raise P6ProtocolError("P6 qualification OCI execution is invalid")
        _expect_exact_fields(
            execution,
            _QUALIFICATION_OCI_EVIDENCE_FIELDS,
            name="P6 qualification OCI execution",
        )
        if validate_oci_execution_evidence(execution):
            raise P6ProtocolError("P6 qualification OCI execution evidence is invalid")
        if (
            execution.get("provider_identity_sha256") != provider_identity
            or execution.get("network_policy_sha256") != network_policy
            or execution.get("network_name") != expected_network_name
            or execution.get("endpoint_origin") != expected_endpoint_origin
            or execution.get("image") != expected_image
            or execution.get("runtime_source_mounted") is not True
            or execution.get("runtime_source_sha256") != runtime_source
            or execution.get("errors") != []
        ):
            raise P6ProtocolError("P6 qualification OCI execution lineage is invalid")
        required_phases = execution.get("required_phases")
        if not isinstance(required_phases, list) or "scan" not in required_phases:
            raise P6ProtocolError("P6 qualification OCI scan phase is not required")
        phases = execution.get("phase_executions")
        if not isinstance(phases, list):
            raise P6ProtocolError("P6 qualification OCI phase evidence is invalid")
        scan_count = 0
        for phase in phases:
            if not isinstance(phase, Mapping):
                raise P6ProtocolError("P6 qualification OCI phase evidence is invalid")
            _expect_exact_fields(
                phase,
                _QUALIFICATION_OCI_PHASE_FIELDS,
                name="P6 qualification OCI phase",
            )
            is_scan = phase.get("phase") == "scan"
            scan_count += int(is_scan)
            if phase.get("scanner_provider_environment_keys") != (
                ["Z_SCOPE_API_KEY"] if is_scan else []
            ):
                raise P6ProtocolError("P6 qualification OCI credential boundary is invalid")
            if (
                phase.get("provider_identity_sha256") != provider_identity
                or phase.get("image") != expected_image
                or phase.get("image_id") != execution.get("image_id")
                or phase.get("network_name") != expected_network_name
                or phase.get("p6_cleanup_scope_verified") is not True
                or phase.get("p6_workflow_run_id") != expected_workflow_run_id
                or phase.get("p6_workflow_run_attempt") != expected_workflow_run_attempt
                or phase.get("p6_attempt_id") != expected_attempt_id
                or phase.get("p6_repository") != expected_repository
                or phase.get("p6_concurrency_group") != "p6-pilot-validation"
                or phase.get("p6_phase") != phase.get("phase")
                or phase.get("stdout_persisted") is not False
                or phase.get("stderr_persisted") is not False
                or phase.get("cancellation_cleanup_guard_verified") is not True
            ):
                raise P6ProtocolError("P6 qualification OCI phase lineage is invalid")
        if scan_count != 1:
            raise P6ProtocolError("P6 qualification OCI receipt must bind one inspected scan")
        execution_hashes.append(canonical_sha256(execution))
    if len(set(execution_hashes)) != len(execution_hashes):
        raise P6ProtocolError("P6 qualification OCI execution receipts are not unique")
    if value.get("execution_sha256s") != execution_hashes:
        raise P6ProtocolError("P6 qualification OCI execution hash binding is invalid")
    return tuple(execution_hashes)


def validate_stage_result(value: Mapping[str, Any]) -> None:
    _expect_exact_fields(value, _STAGE_RESULT_FIELDS, name="P6 stage result")
    if value.get("schema_version") != STAGE_RESULT_SCHEMA_VERSION:
        raise P6ProtocolError("P6 stage result schema version is invalid")
    _expect_run_identity(value)
    _expect_commit(value.get("control_plane_commit"), name="stage-result control-plane commit")
    stage = value.get("stage")
    if stage not in P6_EXECUTION_STAGE_ORDER:
        raise P6ProtocolError("P6 execution stage is invalid")
    status = value.get("status")
    if status not in {"completed", "failed", "skipped"}:
        raise P6ProtocolError("P6 stage status is invalid")
    failure_class = value.get("failure_class")
    failure_count = value.get("failure_count")
    if status == "failed":
        if failure_class not in FAILURE_CLASS_TO_STAGE:
            raise P6ProtocolError("P6 stage failure class is invalid")
        if (
            isinstance(failure_count, bool)
            or not isinstance(failure_count, int)
            or failure_count < 1
        ):
            raise P6ProtocolError("P6 failed stage must have a positive failure_count")
        if (
            failure_class != "internal_failure"
            and stage not in FAILURE_CLASS_TO_EXECUTION_STAGES.get(str(failure_class), ())
        ):
            raise P6ProtocolError("P6 failure class is not bound to its first execution boundary")
    elif failure_class is not None or failure_count != 0:
        raise P6ProtocolError("completed/skipped P6 stages cannot carry failure details")
    _expect_sha256(value.get("binding_sha256"), name="binding_sha256")


def validate_stage_sequence(
    records: Sequence[Mapping[str, Any]], *, require_complete: bool
) -> None:
    if not records and require_complete:
        raise P6ProtocolError("P6 stage sequence is empty")
    identities: set[Tuple[str, int, str, str]] = set()
    failed_at: Optional[int] = None
    seen: set[str] = set()
    for index, record in enumerate(records):
        validate_stage_result(record)
        identities.add((*_expect_run_identity(record), str(record.get("control_plane_commit"))))
        stage = str(record["stage"])
        if stage in seen:
            raise P6ProtocolError("P6 stage sequence contains a duplicate stage")
        seen.add(stage)
        expected_stage = P6_EXECUTION_STAGE_ORDER[index]
        if stage != expected_stage:
            raise P6ProtocolError("P6 stage sequence is not a contiguous ordered prefix")
        status = record["status"]
        if status == "failed":
            if failed_at is not None:
                raise P6ProtocolError("P6 stage sequence contains more than one failed stage")
            failed_at = index
        elif failed_at is None and status == "skipped":
            raise P6ProtocolError("P6 stage was skipped without an upstream failure")
        elif failed_at is not None and status != "skipped":
            raise P6ProtocolError("all P6 stages after the first failure must be skipped")
    if len(identities) > 1:
        raise P6ProtocolError("P6 stage sequence mixes workflow attempts")
    if require_complete and len(records) != len(P6_EXECUTION_STAGE_ORDER):
        raise P6ProtocolError("P6 stage sequence does not explicitly record every stage")


def record_stage_result(run_dir: Path, value: Mapping[str, Any]) -> Path:
    validate_stage_result(value)
    stage = str(value["stage"])
    target = run_dir / "stage-results" / f"{stage}.json"
    existing = load_stage_results(run_dir)
    expected_index = len(existing)
    if (
        expected_index >= len(P6_EXECUTION_STAGE_ORDER)
        or stage != P6_EXECUTION_STAGE_ORDER[expected_index]
    ):
        raise P6ProtocolError("P6 stage results must be appended in the fixed execution order")
    validate_stage_sequence([*existing, value], require_complete=False)
    write_json_exclusive(target, value)
    return target


def load_stage_results(run_dir: Path) -> List[Mapping[str, Any]]:
    result_dir = run_dir / "stage-results"
    if result_dir.is_symlink():
        raise P6ProtocolError("P6 stage result directory cannot be a symlink")
    if not result_dir.exists():
        return []
    if not result_dir.is_dir():
        raise P6ProtocolError("P6 stage result path is not a directory")
    records: List[Mapping[str, Any]] = []
    for stage in P6_EXECUTION_STAGE_ORDER:
        path = result_dir / f"{stage}.json"
        if not path.exists():
            break
        value = load_json_strict(path)
        if not isinstance(value, Mapping):
            raise P6ProtocolError("P6 stage result must be an object")
        records.append(value)
    unexpected = sorted(
        path.name
        for path in result_dir.iterdir()
        if path.is_file()
        and path.name not in {f"{stage}.json" for stage in P6_EXECUTION_STAGE_ORDER}
    )
    if unexpected:
        raise P6ProtocolError("P6 stage result directory contains unbound files")
    present_expected = {
        stage for stage in P6_EXECUTION_STAGE_ORDER if (result_dir / f"{stage}.json").exists()
    }
    if present_expected != set(P6_EXECUTION_STAGE_ORDER[: len(records)]):
        raise P6ProtocolError("P6 stage result directory contains a gap")
    validate_stage_sequence(records, require_complete=False)
    return records


def append_downstream_skips(run_dir: Path) -> List[Mapping[str, Any]]:
    records = load_stage_results(run_dir)
    failures = [record for record in records if record["status"] == "failed"]
    if len(failures) != 1:
        raise P6ProtocolError("downstream skip materialization requires exactly one failed stage")
    identity = failures[0]
    while len(records) < len(P6_EXECUTION_STAGE_ORDER):
        stage = P6_EXECUTION_STAGE_ORDER[len(records)]
        record = {
            "schema_version": STAGE_RESULT_SCHEMA_VERSION,
            "workflow_run_id": identity["workflow_run_id"],
            "workflow_run_attempt": identity["workflow_run_attempt"],
            "attempt_id": identity["attempt_id"],
            "control_plane_commit": identity["control_plane_commit"],
            "stage": stage,
            "status": "skipped",
            "failure_class": None,
            "failure_count": 0,
            "binding_sha256": identity["binding_sha256"],
        }
        record_stage_result(run_dir, record)
        records.append(record)
    validate_stage_sequence(records, require_complete=True)
    return records


def validate_failure_diagnostic(value: Mapping[str, Any]) -> None:
    _expect_exact_fields(value, _DIAGNOSTIC_FIELDS, name="P6 failure diagnostic")
    if value.get("schema_version") != FAILURE_DIAGNOSTIC_SCHEMA_VERSION:
        raise P6ProtocolError("P6 failure diagnostic schema version is invalid")
    _expect_run_identity(value)
    _expect_commit(value.get("control_plane_commit"), name="diagnostic control-plane commit")
    failure_class = value.get("failure_class")
    if failure_class not in FAILURE_CLASS_TO_STAGE:
        raise P6ProtocolError("P6 failure diagnostic class is invalid")
    if (
        failure_class != "internal_failure"
        and value.get("stage") != FAILURE_CLASS_TO_STAGE[failure_class]
    ):
        raise P6ProtocolError("P6 failure diagnostic does not identify the first failure boundary")
    if failure_class == "internal_failure" and value.get("stage") not in P6_FAILURE_STAGE_ORDER:
        raise P6ProtocolError("P6 internal failure stage is invalid")
    failure_count = value.get("failure_count")
    total_count = value.get("total_count")
    if (
        isinstance(failure_count, bool)
        or not isinstance(failure_count, int)
        or failure_count < 1
        or isinstance(total_count, bool)
        or not isinstance(total_count, int)
        or total_count < failure_count
    ):
        raise P6ProtocolError("P6 failure diagnostic counts are invalid")
    checkpoint = value.get("checkpoint_sha256")
    if checkpoint is not None:
        _expect_sha256(checkpoint, name="checkpoint_sha256")
    _expect_sha256(value.get("binding_sha256"), name="binding_sha256")
    _expect_non_release(value)


def public_failure_annotation(value: Mapping[str, Any]) -> str:
    validate_failure_diagnostic(value)
    return (
        f"stage={value['stage']}; class={value['failure_class']}:{value['failure_count']}; "
        f"count={value['total_count']}"
    )


def diagnose_pilot(run_dir: Path, output: Path) -> Mapping[str, Any]:
    records = append_downstream_skips(run_dir)
    failed = [record for record in records if record["status"] == "failed"]
    if len(failed) != 1:
        raise P6ProtocolError("P6 diagnosis requires exactly one failed stage")
    failure = failed[0]
    checkpoint_path = run_dir / "checkpoint.json"
    checkpoint_sha256: Optional[str] = None
    if checkpoint_path.exists():
        checkpoint = load_json_strict(checkpoint_path)
        if not isinstance(checkpoint, Mapping):
            raise P6ProtocolError("P6 checkpoint must be an object")
        validate_checkpoint(checkpoint, artifact_root=run_dir / "stage-artifacts")
        if _expect_run_identity(checkpoint) != _expect_run_identity(failure):
            raise P6ProtocolError("P6 diagnosis checkpoint mixes workflow attempts")
        if checkpoint.get("control_plane_commit") != failure.get("control_plane_commit"):
            raise P6ProtocolError("P6 diagnosis checkpoint mixes control-plane commits")
        checkpoint_sha256 = sha256_file(checkpoint_path)
    payload: Dict[str, Any] = {
        "schema_version": FAILURE_DIAGNOSTIC_SCHEMA_VERSION,
        "workflow_run_id": failure["workflow_run_id"],
        "workflow_run_attempt": failure["workflow_run_attempt"],
        "attempt_id": failure["attempt_id"],
        "control_plane_commit": failure["control_plane_commit"],
        "stage": (
            EXECUTION_STAGE_TO_FAILURE_STAGE[str(failure["stage"])]
            if failure["failure_class"] == "internal_failure"
            else FAILURE_CLASS_TO_STAGE[str(failure["failure_class"])]
        ),
        "failure_class": failure["failure_class"],
        "failure_count": failure["failure_count"],
        "total_count": failure["failure_count"],
        "checkpoint_sha256": checkpoint_sha256,
        "binding_sha256": failure["binding_sha256"],
        "formal_evidence": False,
        "release_eligible": False,
    }
    validate_failure_diagnostic(payload)
    write_json_exclusive(output, payload)
    return payload


def emit_workflow_failure(
    *,
    run_dir: Path,
    output: Path,
    workflow_run_id: str,
    workflow_run_attempt: int,
    attempt_id: str,
    control_plane_commit: str,
    execution_stage: str,
    status: str,
    failure_class: str,
    failure_count: int,
    binding_sha256: str,
    checkpoint_path: Optional[Path] = None,
    checkpoint_artifact_root: Optional[Path] = None,
) -> Mapping[str, Any]:
    """Materialize a cross-job failure without consuming job output or logs."""

    if status != "failed":
        raise P6ProtocolError("P6 workflow failure status must be failed")
    if execution_stage not in P6_EXECUTION_STAGE_ORDER:
        raise P6ProtocolError("P6 workflow failure execution stage is invalid")
    if run_dir.exists() and any(run_dir.iterdir()):
        raise P6ProtocolError("P6 workflow failure directory must be new and empty")
    _expect_sha256(binding_sha256, name="binding_sha256")
    failure_index = P6_EXECUTION_STAGE_ORDER.index(execution_stage)
    identity = {
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
        "attempt_id": attempt_id,
        "control_plane_commit": control_plane_commit,
    }
    _expect_run_identity(identity)
    _expect_commit(control_plane_commit, name="workflow failure control-plane commit")
    for stage in P6_EXECUTION_STAGE_ORDER[:failure_index]:
        record_stage_result(
            run_dir,
            {
                "schema_version": STAGE_RESULT_SCHEMA_VERSION,
                **identity,
                "stage": stage,
                "status": "completed",
                "failure_class": None,
                "failure_count": 0,
                "binding_sha256": binding_sha256,
            },
        )
    record_stage_result(
        run_dir,
        {
            "schema_version": STAGE_RESULT_SCHEMA_VERSION,
            **identity,
            "stage": execution_stage,
            "status": "failed",
            "failure_class": failure_class,
            "failure_count": failure_count,
            "binding_sha256": binding_sha256,
        },
    )
    records = append_downstream_skips(run_dir)
    checkpoint_sha: Optional[str] = None
    if checkpoint_path is not None:
        checkpoint = load_json_strict(checkpoint_path)
        if not isinstance(checkpoint, Mapping):
            raise P6ProtocolError("P6 workflow failure checkpoint must be an object")
        validate_checkpoint(checkpoint, artifact_root=checkpoint_artifact_root)
        if _expect_run_identity(checkpoint) != _expect_run_identity(identity):
            raise P6ProtocolError("P6 workflow failure checkpoint attempt is invalid")
        if checkpoint.get("control_plane_commit") != control_plane_commit:
            raise P6ProtocolError("P6 workflow failure checkpoint control plane is invalid")
        checkpoint_sha = sha256_file(checkpoint_path)
    diagnostic: Dict[str, Any] = {
        "schema_version": FAILURE_DIAGNOSTIC_SCHEMA_VERSION,
        **identity,
        "stage": (
            EXECUTION_STAGE_TO_FAILURE_STAGE[execution_stage]
            if failure_class == "internal_failure"
            else FAILURE_CLASS_TO_STAGE.get(failure_class)
        ),
        "failure_class": failure_class,
        "failure_count": failure_count,
        "total_count": failure_count,
        "checkpoint_sha256": checkpoint_sha,
        "binding_sha256": binding_sha256,
        "formal_evidence": False,
        "release_eligible": False,
    }
    validate_stage_sequence(records, require_complete=True)
    validate_failure_diagnostic(diagnostic)
    answer_free_projection(diagnostic)
    write_json_exclusive(output, diagnostic)
    return diagnostic


def _validate_cold_cache_identities(value: Any) -> None:
    if not isinstance(value, Mapping) or set(value) != {"fast", "balanced", "deep"}:
        raise P6ProtocolError("P6 checkpoint cold cache identities are invalid")
    identities: List[str] = []
    for depth in ("fast", "balanced", "deep"):
        row = value[depth]
        if not isinstance(row, Mapping) or set(row) != {
            "identity_sha256",
            "empty_at_start",
            "reused",
        }:
            raise P6ProtocolError("P6 checkpoint cold cache record is invalid")
        identities.append(_expect_sha256(row.get("identity_sha256"), name="cache identity"))
        if row.get("empty_at_start") is not True or row.get("reused") is not False:
            raise P6ProtocolError("P6 cold cache must be empty and must not be reused")
    if len(set(identities)) != 3:
        raise P6ProtocolError("fast, balanced, and deep must use distinct cold caches")


def cold_cache_identities_sha256(value: Any) -> str:
    _validate_cold_cache_identities(value)
    return canonical_sha256(value)


def _stage_artifact_binding(value: Mapping[str, Any]) -> str:
    projection = {key: value[key] for key in sorted(_STAGE_ARTIFACT_FIELDS - {"binding_sha256"})}
    return canonical_sha256(projection)


def validate_stage_artifact(
    value: Mapping[str, Any],
    *,
    expected_checkpoint: Optional[Mapping[str, Any]] = None,
) -> None:
    _expect_exact_fields(value, _STAGE_ARTIFACT_FIELDS, name="P6 stage artifact")
    if value.get("schema_version") != STAGE_ARTIFACT_SCHEMA_VERSION:
        raise P6ProtocolError("P6 stage artifact schema version is invalid")
    if value.get("workflow_path") != P6_WORKFLOW_PATH:
        raise P6ProtocolError("P6 stage artifact workflow path is invalid")
    _expect_run_identity(value)
    _expect_commit(value.get("control_plane_commit"), name="stage control-plane commit")
    stage = value.get("stage")
    if stage not in P6_CHECKPOINT_STAGE_ORDER:
        raise P6ProtocolError("P6 stage artifact type is invalid")
    for name in (*_LINEAGE_SHA_FIELDS, "cold_cache_identities_sha256", "payload_sha256"):
        _expect_sha256(value.get(name), name=name)
    _expect_non_release(value)
    binding = _expect_sha256(value.get("binding_sha256"), name="binding_sha256")
    if binding != _stage_artifact_binding(value):
        raise P6ProtocolError("P6 stage artifact binding hash is invalid")
    if expected_checkpoint is not None:
        for name in (
            "workflow_path",
            "workflow_run_id",
            "workflow_run_attempt",
            "attempt_id",
            "control_plane_commit",
            *_LINEAGE_SHA_FIELDS,
        ):
            if value.get(name) != expected_checkpoint.get(name):
                raise P6ProtocolError("P6 restored stage artifact lineage is invalid")
        expected_cache_root = cold_cache_identities_sha256(
            expected_checkpoint.get("cold_cache_identities")
        )
        if value.get("cold_cache_identities_sha256") != expected_cache_root:
            raise P6ProtocolError("P6 restored stage artifact cache lineage is invalid")


def build_stage_artifact(
    *,
    workflow_run_id: str,
    workflow_run_attempt: int,
    attempt_id: str,
    control_plane_commit: str,
    stage: str,
    candidate_sha256: str,
    policy_sha256: str,
    plan_sha256: str,
    input_sha256: str,
    runtime_sha256: str,
    provider_sha256: str,
    oci_sha256: str,
    cold_cache_identities: Mapping[str, Any],
    payload_sha256: str,
) -> Mapping[str, Any]:
    payload: Dict[str, Any] = {
        "schema_version": STAGE_ARTIFACT_SCHEMA_VERSION,
        "workflow_path": P6_WORKFLOW_PATH,
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
        "attempt_id": attempt_id,
        "control_plane_commit": control_plane_commit,
        "stage": stage,
        "candidate_sha256": candidate_sha256,
        "policy_sha256": policy_sha256,
        "plan_sha256": plan_sha256,
        "input_sha256": input_sha256,
        "runtime_sha256": runtime_sha256,
        "provider_sha256": provider_sha256,
        "oci_sha256": oci_sha256,
        "cold_cache_identities_sha256": cold_cache_identities_sha256(cold_cache_identities),
        "binding_sha256": "",
        "payload_sha256": payload_sha256,
        "formal_evidence": False,
        "release_eligible": False,
    }
    payload["binding_sha256"] = _stage_artifact_binding(payload)
    validate_stage_artifact(payload)
    return payload


def artifact_root_sha256(artifacts: Sequence[Mapping[str, Any]]) -> str:
    return canonical_sha256(
        {
            "schema_version": ARTIFACT_ROOT_SCHEMA_VERSION,
            "files": list(artifacts),
        }
    )


def validate_checkpoint(
    value: Mapping[str, Any],
    *,
    artifact_root: Optional[Path] = None,
    run_dir: Optional[Path] = None,
    expected_lineage: Optional[Mapping[str, Any]] = None,
) -> Mapping[str, bytes]:
    _expect_exact_fields(value, _CHECKPOINT_FIELDS, name="P6 checkpoint")
    if value.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
        raise P6ProtocolError("P6 checkpoint schema version is invalid")
    if value.get("workflow_path") != P6_WORKFLOW_PATH:
        raise P6ProtocolError("P6 checkpoint workflow path is invalid")
    _, _, attempt_id = _expect_run_identity(value)
    _expect_commit(value.get("control_plane_commit"), name="checkpoint control-plane commit")
    _expect_non_release(value)
    if value.get("requires_full_revalidation") is not True:
        raise P6ProtocolError("P6 checkpoint must require full revalidation")
    status = value.get("status")
    if status not in {"partial", "complete"}:
        raise P6ProtocolError("P6 checkpoint status is invalid")
    completed = value.get("completed_stages")
    if not isinstance(completed, list) or not all(isinstance(stage, str) for stage in completed):
        raise P6ProtocolError("P6 checkpoint completed stages are invalid")
    expected_prefix = list(P6_CHECKPOINT_STAGE_ORDER[: len(completed)])
    if completed != expected_prefix:
        raise P6ProtocolError("P6 checkpoint stages must be one contiguous ordered prefix")
    artifacts = value.get("stage_artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(completed):
        raise P6ProtocolError("P6 checkpoint stage artifacts do not cover completed stages")
    artifact_stages: List[str] = []
    for artifact in artifacts:
        if not isinstance(artifact, Mapping) or set(artifact) != {
            "stage",
            "producer_attempt_id",
            "path",
            "artifact_sha256",
            "artifact_schema_version",
            "binding_sha256",
        }:
            raise P6ProtocolError("P6 checkpoint stage artifact is invalid")
        artifact_stages.append(str(artifact.get("stage")))
        if artifact.get("producer_attempt_id") != attempt_id:
            raise P6ProtocolError("P6 checkpoint cannot merge producers from multiple attempts")
        _expect_sha256(artifact.get("artifact_sha256"), name="stage artifact SHA-256")
        _expect_sha256(artifact.get("binding_sha256"), name="stage artifact binding SHA-256")
        if artifact.get("artifact_schema_version") != STAGE_ARTIFACT_SCHEMA_VERSION:
            raise P6ProtocolError("P6 checkpoint stage artifact schema is invalid")
        path_value = artifact.get("path")
        if not isinstance(path_value, str) or path_value != f"{artifact.get('stage')}.json":
            raise P6ProtocolError("P6 checkpoint stage artifact path is invalid")
    if artifact_stages != completed:
        raise P6ProtocolError("P6 checkpoint stage artifact order is invalid")
    for name in (
        "candidate_sha256",
        "policy_sha256",
        "plan_sha256",
        "input_sha256",
        "runtime_sha256",
        "provider_sha256",
        "oci_sha256",
        "artifact_root_sha256",
    ):
        _expect_sha256(value.get(name), name=name)
    _validate_cold_cache_identities(value.get("cold_cache_identities"))
    if value.get("artifact_root_sha256") != artifact_root_sha256(artifacts):
        raise P6ProtocolError("P6 checkpoint artifact root hash is invalid")
    if expected_lineage is not None:
        expected_fields = {
            "workflow_path",
            "workflow_run_id",
            "workflow_run_attempt",
            "attempt_id",
            "control_plane_commit",
            *_LINEAGE_SHA_FIELDS,
            "cold_cache_identities",
        }
        if set(expected_lineage) != expected_fields:
            raise P6ProtocolError("P6 expected checkpoint lineage fields are invalid")
        for name in expected_fields - {"cold_cache_identities"}:
            if value.get(name) != expected_lineage.get(name):
                raise P6ProtocolError("P6 checkpoint does not match the selected lineage")
        if value.get("cold_cache_identities") != expected_lineage.get("cold_cache_identities"):
            raise P6ProtocolError("P6 checkpoint cache lineage is invalid")
    complete = completed == list(P6_CHECKPOINT_STAGE_ORDER)
    zero_call = value.get("zero_call_finalizable")
    if not isinstance(zero_call, bool):
        raise P6ProtocolError("P6 checkpoint zero-call state is invalid")
    if status == "complete" and not complete:
        raise P6ProtocolError("complete P6 checkpoint does not cover every producer stage")
    if status == "partial" and complete:
        raise P6ProtocolError("fully covered P6 checkpoint cannot be marked partial")
    if zero_call is not (status == "complete"):
        raise P6ProtocolError("only a complete P6 checkpoint may be zero-call finalized")
    if complete and artifact_root is None:
        raise P6ProtocolError("complete P6 checkpoint requires restored stage artifacts")
    restored_bytes: Dict[str, bytes] = {}
    if artifact_root is not None:
        root = artifact_root.resolve()
        if artifact_root.is_symlink() or not artifact_root.is_dir():
            raise P6ProtocolError("P6 checkpoint artifact root is invalid")
        expected_names = {str(row["path"]) for row in artifacts}
        actual_names: set[str] = set()
        for child in artifact_root.iterdir():
            if child.is_symlink() or not child.is_file():
                raise P6ProtocolError("P6 checkpoint artifact root contains a link or directory")
            actual_names.add(child.name)
        if actual_names != expected_names:
            raise P6ProtocolError("P6 checkpoint artifact root contains unbound files")
        for row in artifacts:
            path = root / str(row["path"])
            try:
                path.resolve().relative_to(root)
            except ValueError as exc:
                raise P6ProtocolError("P6 checkpoint artifact escapes its root") from exc
            payload_bytes = read_regular_file_once(path)
            if hashlib.sha256(payload_bytes).hexdigest() != row["artifact_sha256"]:
                raise P6ProtocolError("P6 checkpoint restored artifact hash is invalid")
            payload = load_json_bytes_strict(payload_bytes, name=str(path))
            if not isinstance(payload, Mapping):
                raise P6ProtocolError("P6 restored stage artifact schema is invalid")
            validate_stage_artifact(payload, expected_checkpoint=value)
            if (
                payload.get("stage") != row["stage"]
                or payload.get("binding_sha256") != row["binding_sha256"]
            ):
                raise P6ProtocolError("P6 restored stage artifact lineage is invalid")
            answer_free_projection(payload)
            restored_bytes[str(row["stage"])] = payload_bytes
    if run_dir is not None:
        records = load_stage_results(run_dir)
        completed_records = [
            record for record in records if record.get("stage") in P6_CHECKPOINT_STAGE_ORDER
        ]
        if len(completed_records) != len(completed):
            raise P6ProtocolError("P6 checkpoint stage-result coverage is invalid")
        for record, row in zip(completed_records, artifacts):
            if (
                record.get("status") != "completed"
                or record.get("stage") != row.get("stage")
                or record.get("binding_sha256") != row.get("binding_sha256")
                or _expect_run_identity(record) != _expect_run_identity(value)
                or record.get("control_plane_commit") != value.get("control_plane_commit")
            ):
                raise P6ProtocolError("P6 checkpoint stage-result lineage is invalid")
    return restored_bytes


def validate_repair_receipt(value: Mapping[str, Any]) -> None:
    _expect_exact_fields(value, _REPAIR_FIELDS, name="P6 repair receipt")
    if value.get("schema_version") != REPAIR_RECEIPT_SCHEMA_VERSION:
        raise P6ProtocolError("P6 repair receipt schema version is invalid")
    failed_attempt = _expect_attempt(value.get("failed_attempt_id"), name="failed_attempt_id")
    new_attempt = _expect_attempt(value.get("new_attempt_id"), name="new_attempt_id")
    producer_attempt = _expect_attempt(
        value.get("selected_producer_attempt_id"), name="selected_producer_attempt_id"
    )
    if failed_attempt == new_attempt:
        raise P6ProtocolError("P6 repair must create a new immutable attempt")
    if producer_attempt != new_attempt:
        raise P6ProtocolError("P6 repair receipt cannot select a producer from another attempt")
    if value.get("selected_producer_schema_version") != STAGE_ARTIFACT_SCHEMA_VERSION:
        raise P6ProtocolError("P6 repair receipt selected producer type is invalid")
    for name in (
        "failure_diagnostic_sha256",
        "checkpoint_sha256",
        "frozen_failure_artifact_sha256",
        "answer_free_reproduction_sha256",
        "selected_producer_artifact_sha256",
    ):
        _expect_sha256(value.get(name), name=name)
    pr_number = value.get("repair_pr_number")
    if isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number < 1:
        raise P6ProtocolError("P6 repair PR number is invalid")
    merge_sha = value.get("repair_merge_sha")
    if not isinstance(merge_sha, str) or not COMMIT_RE.fullmatch(merge_sha):
        raise P6ProtocolError("P6 repair merge SHA is invalid")
    control_plane_commit = _expect_commit(
        value.get("control_plane_commit"), name="repair control-plane commit"
    )
    if control_plane_commit != merge_sha:
        raise P6ProtocolError("P6 repair control-plane commit must equal its protected merge")
    start = value.get("invalidated_from_stage")
    if start not in P6_EXECUTION_STAGE_ORDER:
        raise P6ProtocolError("P6 repair invalidation stage is invalid")
    expected_suffix = list(P6_EXECUTION_STAGE_ORDER[P6_EXECUTION_STAGE_ORDER.index(str(start)) :])
    if value.get("invalidated_stages") != expected_suffix:
        raise P6ProtocolError("P6 repair receipt must invalidate the complete downstream suffix")
    _expect_non_release(value)
    answer_free_projection(value)


def build_repair_receipt(
    *,
    failed_attempt_id: str,
    failure_diagnostic_sha256: str,
    checkpoint_sha256: str,
    frozen_failure_artifact_sha256: str,
    answer_free_reproduction_sha256: str,
    repair_pr_number: int,
    repair_merge_sha: str,
    invalidated_from_stage: str,
    new_attempt_id: str,
    selected_producer_artifact_sha256: str,
) -> Mapping[str, Any]:
    if invalidated_from_stage not in P6_EXECUTION_STAGE_ORDER:
        raise P6ProtocolError("P6 repair invalidation stage is invalid")
    payload: Dict[str, Any] = {
        "schema_version": REPAIR_RECEIPT_SCHEMA_VERSION,
        "failed_attempt_id": failed_attempt_id,
        "control_plane_commit": repair_merge_sha,
        "failure_diagnostic_sha256": failure_diagnostic_sha256,
        "checkpoint_sha256": checkpoint_sha256,
        "frozen_failure_artifact_sha256": frozen_failure_artifact_sha256,
        "answer_free_reproduction_sha256": answer_free_reproduction_sha256,
        "repair_pr_number": repair_pr_number,
        "repair_merge_sha": repair_merge_sha,
        "invalidated_from_stage": invalidated_from_stage,
        "invalidated_stages": list(
            P6_EXECUTION_STAGE_ORDER[P6_EXECUTION_STAGE_ORDER.index(invalidated_from_stage) :]
        ),
        "new_attempt_id": new_attempt_id,
        "selected_producer_attempt_id": new_attempt_id,
        "selected_producer_schema_version": STAGE_ARTIFACT_SCHEMA_VERSION,
        "selected_producer_artifact_sha256": selected_producer_artifact_sha256,
        "formal_evidence": False,
        "release_eligible": False,
    }
    validate_repair_receipt(payload)
    return payload


def validate_repair_receipt_bundle(
    value: Mapping[str, Any],
    *,
    failure_diagnostic_path: Path,
    checkpoint_path: Path,
    selected_producer_path: Path,
    checkpoint_artifact_root: Optional[Path] = None,
) -> None:
    """Validate a receipt against immutable referenced objects, not caller claims."""

    validate_repair_receipt(value)
    if sha256_file(failure_diagnostic_path) != value["failure_diagnostic_sha256"]:
        raise P6ProtocolError("P6 repair receipt failure diagnostic hash is invalid")
    if sha256_file(checkpoint_path) != value["checkpoint_sha256"]:
        raise P6ProtocolError("P6 repair receipt checkpoint hash is invalid")
    if sha256_file(selected_producer_path) != value["selected_producer_artifact_sha256"]:
        raise P6ProtocolError("P6 repair receipt selected producer hash is invalid")
    diagnostic = load_json_strict(failure_diagnostic_path)
    checkpoint = load_json_strict(checkpoint_path)
    selected_producer = load_json_strict(selected_producer_path)
    if (
        not isinstance(diagnostic, Mapping)
        or not isinstance(checkpoint, Mapping)
        or not isinstance(selected_producer, Mapping)
    ):
        raise P6ProtocolError("P6 repair receipt references invalid protocol objects")
    validate_failure_diagnostic(diagnostic)
    validate_checkpoint(checkpoint, artifact_root=checkpoint_artifact_root)
    validate_stage_artifact(selected_producer)
    if diagnostic.get("control_plane_commit") != checkpoint.get("control_plane_commit"):
        raise P6ProtocolError("P6 repair receipt source control-plane binding is invalid")
    if diagnostic.get("attempt_id") != value.get("failed_attempt_id"):
        raise P6ProtocolError("P6 repair receipt failed attempt binding is invalid")
    if checkpoint.get("attempt_id") != value.get("failed_attempt_id"):
        raise P6ProtocolError("P6 repair receipt checkpoint attempt binding is invalid")
    if diagnostic.get("checkpoint_sha256") not in {
        None,
        value.get("checkpoint_sha256"),
    }:
        raise P6ProtocolError("P6 repair receipt diagnostic checkpoint binding is invalid")
    if selected_producer.get("schema_version") != value.get("selected_producer_schema_version"):
        raise P6ProtocolError("P6 repair receipt selected producer type is invalid")
    if selected_producer.get("attempt_id") != value.get("new_attempt_id"):
        raise P6ProtocolError("P6 repair receipt selected producer attempt is invalid")
    if selected_producer.get("control_plane_commit") != value.get("repair_merge_sha"):
        raise P6ProtocolError("P6 repair receipt selected producer control plane is invalid")
    answer_free_projection(diagnostic)
    answer_free_projection(checkpoint)
    answer_free_projection(selected_producer)


def _pilot_failure(failure_class: str) -> NoReturn:
    if failure_class not in FAILURE_CLASS_TO_STAGE:
        raise P6ProtocolError("P6 pilot validator selected an unknown failure class")
    raise P6ProtocolError(failure_class)


def validate_pilot_aggregate(
    value: Mapping[str, Any],
    *,
    scan_depth: str,
    expected_control_plane_commit: str,
    expected_git_sha: str,
    expected_git_tree: str,
    toolchain_evidence: Mapping[str, Any],
    toolchain_evidence_file_sha256: str,
) -> Mapping[str, Any]:
    """Validate one complete cold pilot without retaining answer-bearing fields.

    The returned row is deliberately a hash/metric projection.  It is suitable
    for independent review packets; the raw scored Range artifact remains in a
    separately access-controlled workflow artifact.
    """

    if scan_depth not in {"fast", "balanced", "deep"}:
        raise P6ProtocolError("P6 pilot scan depth is invalid")
    if (
        COMMIT_RE.fullmatch(expected_control_plane_commit) is None
        or COMMIT_RE.fullmatch(expected_git_sha) is None
        or COMMIT_RE.fullmatch(expected_git_tree) is None
    ):
        _pilot_failure("input_binding_failure")
    try:
        validate_toolchain_evidence(
            toolchain_evidence,
            expected_control_plane_commit=expected_control_plane_commit,
            expected_git_sha=expected_git_sha,
            expected_git_tree=expected_git_tree,
        )
        _expect_sha256(toolchain_evidence_file_sha256, name="toolchain evidence file hash")
    except P6ProtocolError:
        _pilot_failure("input_binding_failure")
    expected = {
        "language": "cpp",
        "mode": "pilot",
        "scan_depth": scan_depth,
        "formal_benchmark": False,
        "release_eligible": False,
        "cold_runs": 1,
        "all_completed": True,
        "passed": True,
    }
    if any(value.get(key) != item for key, item in expected.items()):
        _pilot_failure("artifact_integrity_failure")
    runs = value.get("runs")
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], Mapping):
        _pilot_failure("artifact_integrity_failure")
    run = runs[0]
    if (
        run.get("completed") is not True
        or run.get("formal_benchmark") is not False
        or run.get("release_eligible") is not False
    ):
        _pilot_failure("artifact_integrity_failure")
    if run.get("queue_empty") is not True:
        _pilot_failure("queue_not_drained")
    if run.get("gate_failures") not in ([], None):
        _pilot_failure("quality_no_progress_gate_failed")
    metrics = run.get("metrics")
    if not isinstance(metrics, Mapping):
        _pilot_failure("component_metrics_incomplete")
    usage = metrics.get("usage_accounting")
    if not isinstance(usage, Mapping):
        _pilot_failure("provider_usage_unverifiable")
    totals = usage.get("totals")
    if not isinstance(totals, Mapping):
        _pilot_failure("provider_usage_unverifiable")
    if (
        usage.get("complete") is not True
        or usage.get("conservation_passed") is not True
        or float(usage.get("provider_usage_coverage") or 0.0) != 1.0
        or int(totals.get("estimated_or_conservative_calls") or 0) != 0
        or int(totals.get("failed_or_unknown_calls") or 0) != 0
        or int(totals.get("budget_violation_count") or 0) != 0
    ):
        _pilot_failure("accounting_conservation_failure")
    if int(totals.get("call_count") or 0) < 1:
        _pilot_failure("provider_usage_unverifiable")
    if metrics.get("token_conservation_passed") is not True:
        _pilot_failure("accounting_conservation_failure")
    if float(metrics.get("provider_usage_coverage") or 0.0) != 1.0:
        _pilot_failure("provider_usage_unverifiable")
    if (
        float(metrics.get("provider_response_model_coverage") or 0.0) != 1.0
        or int(metrics.get("provider_response_model_missing_count") or 0) != 0
        or int(metrics.get("provider_response_model_mismatch_count") or 0) != 0
        or int(metrics.get("requested_model_mismatch_count") or 0) != 0
    ):
        _pilot_failure("provider_identity_mismatch")
    if float(metrics.get("telemetry_complete_rate") or 0.0) != 1.0:
        _pilot_failure("component_metrics_incomplete")
    if int(metrics.get("protocol_anomaly_count") or 0) != 0:
        _pilot_failure("terminal_state_inconsistent")
    funnel = metrics.get("candidate_funnel")
    v3 = funnel.get("v3_investigation") if isinstance(funnel, Mapping) else None
    if not isinstance(v3, Mapping):
        _pilot_failure("component_metrics_incomplete")
    eligible = int(v3.get("eligible") or 0)
    entered = int(v3.get("entered") or 0)
    if eligible > entered:
        _pilot_failure("eligible_stage_not_entered")
    provenance = run.get("provenance")
    provider = provenance.get("provider_runtime") if isinstance(provenance, Mapping) else None
    if not isinstance(provider, Mapping):
        _pilot_failure("provider_identity_mismatch")
    if (
        provider.get("model") != P6_PROVIDER_MODEL
        or provider.get("base_url")
        != "https://st8tp3ajl0df3n8b8l8qu.apigateway-cn-beijing.volceapi.com/v1"
        or provider.get("required_environment_keys") != ["Z_SCOPE_API_KEY"]
    ):
        _pilot_failure("provider_identity_mismatch")
    provider_identity = _expect_sha256(
        provider.get("identity_sha256"), name="provider identity SHA-256"
    )
    try:
        conservation = validate_usage_conservation(
            metrics.get("p6_conservation"), require_model_calls=True
        )
    except P6ProtocolError:
        _pilot_failure("accounting_conservation_failure")
    if conservation["physical_call_count"] != int(totals["call_count"]):
        _pilot_failure("accounting_conservation_failure")
    git_sha = value.get("git_sha")
    git_tree = value.get("git_tree")
    if (
        not isinstance(git_sha, str)
        or COMMIT_RE.fullmatch(git_sha) is None
        or not isinstance(git_tree, str)
        or COMMIT_RE.fullmatch(git_tree) is None
    ):
        _pilot_failure("input_binding_failure")
    if expected_git_sha is not None and git_sha != expected_git_sha:
        _pilot_failure("input_binding_failure")
    if expected_git_tree is not None and git_tree != expected_git_tree:
        _pilot_failure("input_binding_failure")
    isolation = run.get("isolation")
    if not isinstance(isolation, Mapping):
        _pilot_failure("oci_isolation_violation")
    from zscope.benchmarking.isolation import validate_oci_execution_evidence

    if validate_oci_execution_evidence(isolation):
        _pilot_failure("oci_isolation_violation")
    if (
        isolation.get("mode") != "oci"
        or isolation.get("rootless_verified") is not True
        or isolation.get("image_digest_verified") is not True
        or isolation.get("execution_verified") is not True
        or isolation.get("mounts_verified") is not True
        or isolation.get("network_restriction_verified") is not True
        or isolation.get("repository_mounted") is not False
        or isolation.get("truth_mounted") is not False
        or isolation.get("runtime_source_mounted") is not True
        or isolation.get("runtime_source_sha256") != toolchain_evidence["runtime_source_sha256"]
        or isolation.get("image") != toolchain_evidence["image_ref"]
        or isolation.get("image_id") != toolchain_evidence["image_id"]
        or isolation.get("provider_identity_sha256") != provider_identity
    ):
        _pilot_failure("oci_isolation_violation")
    phases = isolation.get("phase_executions")
    if not isinstance(phases, list) or not phases:
        _pilot_failure("oci_isolation_violation")
    for phase in phases:
        if (
            not isinstance(phase, Mapping)
            or phase.get("image") != toolchain_evidence["image_ref"]
            or phase.get("image_id") != toolchain_evidence["image_id"]
            or phase.get("image_verified") is not True
            or phase.get("inspect_verified") is not True
            or phase.get("network_contract_verified") is not True
            or phase.get("p6_cleanup_scope_verified") is not True
            or phase.get("p6_workflow_run_id") != toolchain_evidence["workflow_run_id"]
            or phase.get("p6_workflow_run_attempt") != toolchain_evidence["workflow_run_attempt"]
            or phase.get("p6_attempt_id") != toolchain_evidence["attempt_id"]
            or phase.get("p6_concurrency_group") != "p6-pilot-validation"
            or phase.get("p6_phase") != phase.get("phase")
            or phase.get("scanner_provider_environment_keys")
            != (["Z_SCOPE_API_KEY"] if phase.get("phase") == "scan" else [])
        ):
            _pilot_failure("oci_isolation_violation")
    if sum(phase.get("phase") == "scan" for phase in phases) != 1:
        _pilot_failure("oci_isolation_violation")
    cold_cache = run.get("cold_cache")
    expected_cache_identity = hashlib.sha256(
        (
            f"{toolchain_evidence['workflow_run_id']}:"
            f"{toolchain_evidence['workflow_run_attempt']}:{scan_depth}"
        ).encode("utf-8")
    ).hexdigest()
    if (
        not isinstance(cold_cache, Mapping)
        or set(cold_cache) != {"identity_sha256", "empty_at_start", "reused"}
        or cold_cache.get("identity_sha256") != expected_cache_identity
        or cold_cache.get("empty_at_start") is not True
        or cold_cache.get("reused") is not False
    ):
        _pilot_failure("cold_cache_not_isolated")
    isolation_sha256 = canonical_sha256(isolation)
    return {
        "schema_version": DEPTH_PROJECTION_SCHEMA_VERSION,
        "scan_depth": scan_depth,
        "control_plane_commit": toolchain_evidence["control_plane_commit"],
        "producer_attempt_id": toolchain_evidence["attempt_id"],
        "artifact_sha256": canonical_sha256(value),
        "git_sha": git_sha,
        "git_tree": git_tree,
        "provider_identity_sha256": provider_identity,
        "call_count": int(totals["call_count"]),
        "provider_usage_coverage": 1.0,
        "provider_response_model_coverage": 1.0,
        "estimated_provider_call_count": 0,
        "queue_empty": True,
        "token_conservation_passed": True,
        "telemetry_complete_rate": 1.0,
        "eligible_count": eligible,
        "entered_count": entered,
        "usage_conservation": conservation,
        "toolchain_evidence_sha256": toolchain_evidence_file_sha256,
        "oci_image_ref": toolchain_evidence["image_ref"],
        "oci_image_digest": toolchain_evidence["image_digest"],
        "oci_image_id": toolchain_evidence["image_id"],
        "runtime_source_sha256": toolchain_evidence["runtime_source_sha256"],
        "toolchain_oci_execution_sha256": toolchain_evidence["oci_execution_sha256"],
        "oci_execution_sha256": isolation_sha256,
        "cache_identity_sha256": expected_cache_identity,
        "cache_empty_at_start": True,
        "cache_reused": False,
        "formal_benchmark": False,
        "release_eligible": False,
    }


def validate_depth_projection(value: Mapping[str, Any], *, scan_depth: str) -> None:
    expected_fields = {
        "schema_version",
        "scan_depth",
        "control_plane_commit",
        "producer_attempt_id",
        "artifact_sha256",
        "git_sha",
        "git_tree",
        "provider_identity_sha256",
        "call_count",
        "provider_usage_coverage",
        "provider_response_model_coverage",
        "estimated_provider_call_count",
        "queue_empty",
        "token_conservation_passed",
        "telemetry_complete_rate",
        "eligible_count",
        "entered_count",
        "usage_conservation",
        "toolchain_evidence_sha256",
        "oci_image_ref",
        "oci_image_digest",
        "oci_image_id",
        "runtime_source_sha256",
        "toolchain_oci_execution_sha256",
        "oci_execution_sha256",
        "cache_identity_sha256",
        "cache_empty_at_start",
        "cache_reused",
        "formal_benchmark",
        "release_eligible",
    }
    if (
        set(value) != expected_fields
        or value.get("schema_version") != DEPTH_PROJECTION_SCHEMA_VERSION
    ):
        raise P6ProtocolError("P6 depth projection schema is invalid")
    if value.get("scan_depth") != scan_depth:
        raise P6ProtocolError("P6 depth projection depth is invalid")
    _expect_commit(value.get("control_plane_commit"), name="depth control-plane commit")
    _expect_attempt(value.get("producer_attempt_id"))
    for name in (
        "artifact_sha256",
        "provider_identity_sha256",
        "toolchain_evidence_sha256",
        "runtime_source_sha256",
        "toolchain_oci_execution_sha256",
        "oci_execution_sha256",
        "cache_identity_sha256",
    ):
        _expect_sha256(value.get(name), name=name)
    image_ref = value.get("oci_image_ref")
    image_digest = value.get("oci_image_digest")
    image_id = value.get("oci_image_id")
    if (
        not isinstance(image_ref, str)
        or image_ref.count("@sha256:") != 1
        or not isinstance(image_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest) is None
        or image_ref.rsplit("@", 1)[1] != image_digest
        or not isinstance(image_id, str)
        or IMAGE_ID_RE.fullmatch(image_id) is None
    ):
        raise P6ProtocolError("P6 depth projection OCI image identity is invalid")
    if (
        not isinstance(value.get("git_sha"), str)
        or COMMIT_RE.fullmatch(str(value["git_sha"])) is None
        or not isinstance(value.get("git_tree"), str)
        or COMMIT_RE.fullmatch(str(value["git_tree"])) is None
    ):
        raise P6ProtocolError("P6 depth projection git identity is invalid")
    if (
        isinstance(value.get("call_count"), bool)
        or not isinstance(value.get("call_count"), int)
        or int(value["call_count"]) < 1
        or value.get("provider_usage_coverage") != 1.0
        or value.get("provider_response_model_coverage") != 1.0
        or value.get("estimated_provider_call_count") != 0
        or value.get("queue_empty") is not True
        or value.get("token_conservation_passed") is not True
        or value.get("telemetry_complete_rate") != 1.0
        or value.get("cache_empty_at_start") is not True
        or value.get("cache_reused") is not False
        or value.get("formal_benchmark") is not False
        or value.get("release_eligible") is not False
    ):
        raise P6ProtocolError("P6 depth projection invariants are invalid")
    eligible = value.get("eligible_count")
    entered = value.get("entered_count")
    if (
        isinstance(eligible, bool)
        or not isinstance(eligible, int)
        or eligible < 0
        or isinstance(entered, bool)
        or not isinstance(entered, int)
        or entered < eligible
    ):
        raise P6ProtocolError("P6 depth projection eligible-stage accounting is invalid")
    validate_usage_conservation(value.get("usage_conservation"), require_model_calls=True)


def build_qualification_from_projections(
    *,
    projections: Mapping[str, Mapping[str, Any]],
    projection_file_sha256s: Mapping[str, str],
    cache_identity_sha256s: Mapping[str, str],
    candidate_sha256: str,
    policy_sha256: str,
    offline_evidence_sha256: str,
    offline_usage_conservation: Mapping[str, Any],
    provider_probe: Mapping[str, Any],
    provider_probe_file_sha256: str,
    toolchain_evidence: Mapping[str, Any],
    toolchain_evidence_file_sha256: str,
    control_plane_commit: str,
    attempt_id: str,
) -> Mapping[str, Any]:
    expected_depths = {"fast", "balanced", "deep"}
    if set(projections) != expected_depths or set(projection_file_sha256s) != expected_depths:
        raise P6ProtocolError("P6 qualification projection set is incomplete")
    if set(cache_identity_sha256s) != expected_depths:
        raise P6ProtocolError("P6 qualification cache identity set is incomplete")
    _expect_attempt(attempt_id)
    _expect_commit(control_plane_commit, name="qualification control-plane commit")
    for name, item in (
        ("candidate_sha256", candidate_sha256),
        ("policy_sha256", policy_sha256),
        ("offline_evidence_sha256", offline_evidence_sha256),
    ):
        _expect_sha256(item, name=name)
    validate_toolchain_evidence(
        toolchain_evidence,
        expected_attempt_id=attempt_id,
        expected_control_plane_commit=control_plane_commit,
        expected_candidate_sha256=candidate_sha256,
    )
    toolchain_projection = toolchain_evidence_projection(
        toolchain_evidence, file_sha256=toolchain_evidence_file_sha256
    )
    probe_projection = provider_probe_projection(
        provider_probe, file_sha256=provider_probe_file_sha256
    )
    caches = list(cache_identity_sha256s.values())
    if len(set(caches)) != 3:
        raise P6ProtocolError("P6 cold depth producers must use distinct caches")
    rows: List[Mapping[str, Any]] = []
    conservation_rows: List[Mapping[str, Any]] = [
        validate_usage_conservation(
            probe_projection["usage_conservation"], require_model_calls=True
        ),
        validate_usage_conservation(offline_usage_conservation),
    ]
    providers: set[str] = set()
    git_identities: set[Tuple[str, str]] = set()
    toolchain_identities: set[Tuple[str, ...]] = set()
    cold_oci_execution_sha256s: set[str] = set()
    producer_artifact_sha256s: set[str] = set()
    projection_artifact_sha256s: set[str] = set()
    for depth in ("fast", "balanced", "deep"):
        projection = projections[depth]
        validate_depth_projection(projection, scan_depth=depth)
        file_sha = _expect_sha256(
            projection_file_sha256s[depth], name=f"{depth} projection file SHA-256"
        )
        cache_sha = _expect_sha256(
            cache_identity_sha256s[depth], name=f"{depth} cache identity SHA-256"
        )
        if (
            projection.get("producer_attempt_id") != attempt_id
            or projection.get("cache_identity_sha256") != cache_sha
            or projection.get("cache_empty_at_start") is not True
            or projection.get("cache_reused") is not False
        ):
            raise P6ProtocolError("P6 cold depth producer lineage is invalid")
        providers.add(str(projection["provider_identity_sha256"]))
        git_identities.add((str(projection["git_sha"]), str(projection["git_tree"])))
        cold_oci_execution_sha256s.add(str(projection["oci_execution_sha256"]))
        producer_artifact_sha256s.add(str(projection["artifact_sha256"]))
        projection_artifact_sha256s.add(file_sha)
        toolchain_identities.add(
            tuple(
                str(projection[name])
                for name in (
                    "toolchain_evidence_sha256",
                    "control_plane_commit",
                    "oci_image_ref",
                    "oci_image_digest",
                    "oci_image_id",
                    "runtime_source_sha256",
                    "toolchain_oci_execution_sha256",
                )
            )
        )
        rows.append(
            {
                **dict(projection),
                "projection_file_sha256": file_sha,
            }
        )
        conservation_rows.append(
            validate_usage_conservation(
                projection.get("usage_conservation"), require_model_calls=True
            )
        )
    expected_toolchain_identity = (
        str(toolchain_projection["artifact_sha256"]),
        str(toolchain_projection["control_plane_commit"]),
        str(toolchain_projection["image_ref"]),
        str(toolchain_projection["image_digest"]),
        str(toolchain_projection["image_id"]),
        str(toolchain_projection["runtime_source_sha256"]),
        str(toolchain_projection["oci_execution_sha256"]),
    )
    if (
        providers != {str(probe_projection["provider_identity_sha256"])}
        or git_identities
        != {
            (
                str(toolchain_projection["candidate_git_sha"]),
                str(toolchain_projection["candidate_git_tree"]),
            )
        }
        or toolchain_identities != {expected_toolchain_identity}
        or len(cold_oci_execution_sha256s) != 3
        or len(producer_artifact_sha256s) != 3
        or len(projection_artifact_sha256s) != 3
    ):
        raise P6ProtocolError("P6 cold depth projections mix producer identities")
    payload: Dict[str, Any] = {
        "schema_version": QUALIFICATION_SCHEMA_VERSION,
        "attempt_id": attempt_id,
        "control_plane_commit": control_plane_commit,
        "candidate_sha256": candidate_sha256,
        "policy_sha256": policy_sha256,
        "offline_evidence_sha256": offline_evidence_sha256,
        "provider_identity_sha256": probe_projection["provider_identity_sha256"],
        "provider_probe": probe_projection,
        "toolchain_evidence": toolchain_projection,
        "selected_producer_attempt_id": attempt_id,
        "depths": rows,
        "depth_count": 3,
        "usage_conservation": combine_usage_conservation(conservation_rows),
        "all_depths_passed": True,
        "formal_benchmark": False,
        "formal_evidence": False,
        "release_eligible": False,
    }
    payload["qualification_sha256"] = canonical_sha256(payload)
    return payload


def build_qualification_seal(
    *,
    aggregates: Mapping[str, Mapping[str, Any]],
    artifact_sha256s: Mapping[str, str],
    cache_identity_sha256s: Mapping[str, str],
    candidate_sha256: str,
    policy_sha256: str,
    offline_evidence_sha256: str,
    offline_usage_conservation: Mapping[str, Any],
    provider_probe: Mapping[str, Any],
    provider_probe_file_sha256: str,
    toolchain_evidence: Mapping[str, Any],
    toolchain_evidence_file_sha256: str,
    control_plane_commit: str,
    attempt_id: str,
) -> Mapping[str, Any]:
    """Build one non-release qualification from three producers of one attempt."""

    expected_depths = {"fast", "balanced", "deep"}
    if (
        set(aggregates) != expected_depths
        or set(artifact_sha256s) != expected_depths
        or set(cache_identity_sha256s) != expected_depths
    ):
        raise P6ProtocolError("P6 qualification requires fast, balanced, and deep")
    _expect_attempt(attempt_id)
    _expect_commit(control_plane_commit, name="qualification control-plane commit")
    _expect_sha256(candidate_sha256, name="candidate_sha256")
    _expect_sha256(policy_sha256, name="policy_sha256")
    _expect_sha256(offline_evidence_sha256, name="offline_evidence_sha256")
    validate_toolchain_evidence(
        toolchain_evidence,
        expected_attempt_id=attempt_id,
        expected_control_plane_commit=control_plane_commit,
        expected_candidate_sha256=candidate_sha256,
    )
    toolchain_projection = toolchain_evidence_projection(
        toolchain_evidence, file_sha256=toolchain_evidence_file_sha256
    )
    probe_projection = provider_probe_projection(
        provider_probe, file_sha256=provider_probe_file_sha256
    )
    caches = [
        _expect_sha256(cache_identity_sha256s[depth], name=f"{depth} cache identity")
        for depth in ("fast", "balanced", "deep")
    ]
    if len(set(caches)) != 3:
        raise P6ProtocolError("P6 cold depth producers must use three distinct caches")
    rows: List[Mapping[str, Any]] = []
    conservation_rows: List[Mapping[str, Any]] = [
        validate_usage_conservation(
            probe_projection["usage_conservation"], require_model_calls=True
        ),
        validate_usage_conservation(offline_usage_conservation),
    ]
    provider_identities: set[str] = set()
    git_identities: set[Tuple[str, str]] = set()
    cold_oci_execution_sha256s: set[str] = set()
    producer_artifact_sha256s: set[str] = set()
    for depth in ("fast", "balanced", "deep"):
        row = dict(
            validate_pilot_aggregate(
                aggregates[depth],
                scan_depth=depth,
                expected_control_plane_commit=control_plane_commit,
                expected_git_sha=str(toolchain_evidence["candidate_git_sha"]),
                expected_git_tree=str(toolchain_evidence["candidate_git_tree"]),
                toolchain_evidence=toolchain_evidence,
                toolchain_evidence_file_sha256=toolchain_evidence_file_sha256,
            )
        )
        supplied = _expect_sha256(
            artifact_sha256s[depth], name=f"{depth} aggregate artifact SHA-256"
        )
        if supplied != row["artifact_sha256"]:
            raise P6ProtocolError("P6 aggregate artifact hash binding is invalid")
        if (
            row.get("cache_identity_sha256") != cache_identity_sha256s[depth]
            or row.get("cache_empty_at_start") is not True
            or row.get("cache_reused") is not False
            or row.get("producer_attempt_id") != attempt_id
        ):
            raise P6ProtocolError("P6 cold depth producer lineage is invalid")
        provider_identities.add(str(row["provider_identity_sha256"]))
        git_identities.add((str(row["git_sha"]), str(row["git_tree"])))
        cold_oci_execution_sha256s.add(str(row["oci_execution_sha256"]))
        producer_artifact_sha256s.add(str(row["artifact_sha256"]))
        rows.append(row)
        conservation_rows.append(
            validate_usage_conservation(row.get("usage_conservation"), require_model_calls=True)
        )
    if (
        provider_identities != {str(probe_projection["provider_identity_sha256"])}
        or len(git_identities) != 1
        or len(cold_oci_execution_sha256s) != 3
        or len(producer_artifact_sha256s) != 3
    ):
        raise P6ProtocolError("P6 cold depth producers do not share one frozen identity")
    payload: Dict[str, Any] = {
        "schema_version": QUALIFICATION_SCHEMA_VERSION,
        "attempt_id": attempt_id,
        "control_plane_commit": control_plane_commit,
        "candidate_sha256": candidate_sha256,
        "policy_sha256": policy_sha256,
        "offline_evidence_sha256": offline_evidence_sha256,
        "provider_identity_sha256": probe_projection["provider_identity_sha256"],
        "provider_probe": probe_projection,
        "toolchain_evidence": toolchain_projection,
        "selected_producer_attempt_id": attempt_id,
        "depths": rows,
        "depth_count": 3,
        "usage_conservation": combine_usage_conservation(conservation_rows),
        "all_depths_passed": True,
        "formal_benchmark": False,
        "formal_evidence": False,
        "release_eligible": False,
    }
    payload["qualification_sha256"] = canonical_sha256(payload)
    return payload


def require_pilot_request(
    *,
    language: str,
    mode: str,
    runs: Optional[int],
    resume: bool = False,
    maintain: bool = False,
    warm_cache: bool = False,
) -> None:
    """Validate the public pilot request before provider or OCI work starts."""

    if mode != "pilot":
        return
    if language != "c_cpp":
        raise P6ProtocolError("P6 pilot mode is limited to the C/C++ Range benchmark")
    if runs not in {None, 1}:
        raise P6ProtocolError("P6 pilot mode runs exactly one cold scan")
    if resume or maintain or warm_cache:
        raise P6ProtocolError("P6 pilot forbids resume, maintain, and warm cache")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m zscope.benchmarking.p6_protocol")
    commands = parser.add_subparsers(dest="command", required=True)
    diagnose = commands.add_parser("diagnose-pilot")
    diagnose.add_argument("--run-dir", required=True, type=Path)
    diagnose.add_argument("--output", required=True, type=Path)
    validate_checkpoint_command = commands.add_parser("validate-checkpoint")
    validate_checkpoint_command.add_argument("--checkpoint", required=True, type=Path)
    validate_checkpoint_command.add_argument("--artifact-root", required=True, type=Path)
    validate_receipt_command = commands.add_parser("validate-repair-receipt")
    validate_receipt_command.add_argument("--receipt", required=True, type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "diagnose-pilot":
            payload = diagnose_pilot(args.run_dir.resolve(), args.output.resolve())
            print(public_failure_annotation(payload))
        elif args.command == "validate-checkpoint":
            payload = load_json_strict(args.checkpoint.resolve())
            if not isinstance(payload, Mapping):
                raise P6ProtocolError("P6 checkpoint must be an object")
            validate_checkpoint(payload, artifact_root=args.artifact_root.resolve())
            print("p6_checkpoint_valid")
        else:
            payload = load_json_strict(args.receipt.resolve())
            if not isinstance(payload, Mapping):
                raise P6ProtocolError("P6 repair receipt must be an object")
            validate_repair_receipt(payload)
            print("p6_repair_receipt_valid")
    except P6ProtocolError as exc:
        _parser().error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CHECKPOINT_SCHEMA_VERSION",
    "FAILURE_CLASS_TO_STAGE",
    "EXECUTION_STAGE_TO_FAILURE_STAGE",
    "FAILURE_DIAGNOSTIC_SCHEMA_VERSION",
    "P6ProtocolError",
    "P6_CHECKPOINT_STAGE_ORDER",
    "P6_EXECUTION_STAGE_ORDER",
    "P6_FAILURE_STAGE_ORDER",
    "P6_WORKFLOW_PATH",
    "QUALIFICATION_OCI_RECEIPT_SCHEMA_VERSION",
    "REPAIR_RECEIPT_SCHEMA_VERSION",
    "STAGE_RESULT_SCHEMA_VERSION",
    "STAGE_ARTIFACT_SCHEMA_VERSION",
    "TRANSPORT_RETRYABLE_FAILURES",
    "TOOLCHAIN_EVIDENCE_SCHEMA_VERSION",
    "append_downstream_skips",
    "answer_free_projection",
    "artifact_root_sha256",
    "build_repair_receipt",
    "build_stage_artifact",
    "canonical_sha256",
    "cold_cache_identities_sha256",
    "combine_usage_conservation",
    "diagnose_pilot",
    "emit_workflow_failure",
    "load_json_strict",
    "load_stage_results",
    "public_failure_annotation",
    "record_stage_result",
    "require_pilot_request",
    "seal_toolchain_evidence",
    "sha256_file",
    "validate_checkpoint",
    "validate_answer_free_artifact",
    "validate_failure_diagnostic",
    "validate_repair_receipt",
    "validate_repair_receipt_bundle",
    "validate_qualification_oci_receipt",
    "validate_safe_zip",
    "validate_stage_artifact",
    "validate_stage_result",
    "validate_stage_sequence",
    "validate_toolchain_evidence",
    "validate_usage_conservation",
    "write_json_exclusive",
    "zero_usage_conservation",
]
