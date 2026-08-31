"""Role-separated, subprocess-authenticated independent review for P6.

The scanner model is intentionally absent from this harness.  Every accepted
decision is tied to one exact packet, frozen CLI identity, strict command, and
captured raw envelope.  The integration operator can validate or aggregate the
objects but cannot create an accepted reviewer decision without the protected
reviewer subprocess.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from copy import deepcopy
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from zscope.benchmarking.p6_protocol import (
    P6ProtocolError,
    canonical_sha256,
    load_json_strict,
    sha256_file,
    validate_usage_conservation,
    write_json_exclusive,
)


P6_REVIEW_PACKET_SCHEMA_VERSION = "zscope.p6-review-packet.v1"
P6_REVIEW_DECISION_SCHEMA_VERSION = "zscope.p6-review-decision.v1"
P6_REVIEW_RAW_SCHEMA_VERSION = "zscope.p6-review-raw-envelope.v1"
P6_REVIEW_SET_SCHEMA_VERSION = "zscope.p6-independent-review-set.v1"

REVIEW_ROLES: Tuple[str, ...] = (
    "product_architecture",
    "proof_security",
    "independent_benchmark",
)

FROZEN_REVIEWER_IDENTITIES: Dict[str, Dict[str, Any]] = {
    "product_architecture": {
        "harness": "claude-code",
        "harness_version": "2.1.233",
        "provider": "claude-code",
        "model": "glm-5.3",
        "reasoning_effort": "high",
        "permission_mode": "read-only",
        "shell_enabled": False,
        "route_config_contract": "sealed-e0-route-snapshot-sha256",
    },
    "proof_security": {
        "harness": "dsh",
        "harness_version": "0.1.0-rc.6",
        "provider": "deepseek",
        "model": "deepseek-v4-pro-0813",
        "reasoning_effort": "max",
        "permission_mode": "read-only",
        "shell_enabled": False,
        "route_config_contract": "sealed-e0-route-snapshot-sha256",
    },
    "independent_benchmark": {
        "harness": "codex-cli",
        "harness_version": "0.144.4",
        "provider": "openai",
        "model": "gpt-5.6-sol",
        "reasoning_effort": "xhigh",
        "permission_mode": "read-only-ephemeral",
        "shell_enabled": False,
        "route_config_contract": "explicit-strict-cli-flags-and-sealed-login",
    },
}

ROLE_CHECKS: Dict[str, Tuple[str, ...]] = {
    "product_architecture": (
        "cli_contract",
        "workflow_dag",
        "isolation",
        "recovery",
        "rollback",
    ),
    "proof_security": (
        "replay",
        "certificate",
        "closure",
        "evidence_action",
        "authority",
        "soundness",
    ),
    "independent_benchmark": (
        "e0_lineage",
        "answer_isolation",
        "oci",
        "metrics",
        "usage_conservation",
        "non_release",
    ),
}

BLOCKER_CODES = frozenset(
    {
        "reviewer_binding_invalid",
        "architecture_contract_violation",
        "proof_soundness_violation",
        "benchmark_protocol_violation",
        "evidence_incomplete",
    }
)

_FORBIDDEN_PACKET_PATH_TOKENS = (
    "ground_truth",
    "ground-truth",
    "/truth/",
    "scorer",
    "fixture",
    "expected",
    "review-decision",
    "review_decision",
)

_HIDDEN_REASONING_KEYS = frozenset(
    {
        "analysis",
        "chain_of_thought",
        "chainofthought",
        "hidden_reasoning",
        "reasoning_content",
        "thinking",
        "thinking_content",
    }
)

_FORBIDDEN_EVIDENCE_KEYS = frozenset(
    {
        "api_key",
        "secret",
        "credential",
        "ground_truth",
        "truth",
        "expected",
        "fixture",
        "source",
        "prompt",
        "response",
        "model_output",
        "stdout",
        "stderr",
        "reasoning_content",
        "thinking_content",
    }
)

_PACKET_FIELDS = frozenset(
    {
        "schema_version",
        "packet_uid",
        "packet_sha256",
        "role",
        "candidate_sha256",
        "policy_sha256",
        "qualification_sha256",
        "evidence_root_sha256",
        "artifact_files",
    }
)

_DECISION_FIELDS = frozenset(
    {
        "schema_version",
        "packet_uid",
        "packet_sha256",
        "qualification_sha256",
        "evidence_root_sha256",
        "role",
        "harness",
        "harness_version",
        "provider",
        "model",
        "reasoning_effort",
        "decision",
        "blocker_count",
        "blockers",
        "checks",
    }
)

_RAW_FIELDS = frozenset(
    {
        "schema_version",
        "packet_uid",
        "packet_sha256",
        "role",
        "reviewer_identity_sha256",
        "runtime_identity_contract",
        "executable_path",
        "executable_sha256",
        "executable_snapshot_sha256",
        "harness_version_observed",
        "command_identity",
        "exit_code",
        "stdout",
        "stdout_sha256",
        "reviewer_stdout_sha256",
        "stderr_sha256",
        "transport_retry",
        "bounded_correction",
        "initial_prompt_sha256",
        "accepted_prompt_sha256",
        "material_root_sha256",
        "decision_sha256",
    }
)

_REVIEWER_EXECUTABLE_NAMES = {
    "product_architecture": "claude",
    "proof_security": "dsh",
    "independent_benchmark": "codex",
}

_SEALED_RUNNER_TEMPORAL_IDENTITY = "sealed-runner-temporal-command-identity.v1"
_SEALED_RUNNER_TEMPORAL_LAUNCHER_IDENTITY = "sealed-runner-temporal-launcher-identity.v1"
_MAX_REVIEWER_EXECUTABLE_BYTES = 512 * 1024 * 1024

_REVIEWER_CREDENTIAL_ENV = {
    "product_architecture": "ANTHROPIC_API_KEY",
    "proof_security": "DEEPSEEK_API_KEY",
    "independent_benchmark": "OPENAI_API_KEY",
}

_REVIEWER_AUTH_ENV_ALLOWLIST = {
    "product_architecture": (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
    ),
    "proof_security": ("DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL"),
    "independent_benchmark": ("CODEX_API_KEY", "OPENAI_API_KEY"),
}

_REVIEWER_ROUTE_CONFIG_ENV = {
    "product_architecture": (
        "Z_SCOPE_P6_REVIEW_PRODUCT_CONFIG_ROOT",
        "Z_SCOPE_P6_REVIEW_PRODUCT_CONFIG_TREE_SHA256",
    ),
    "proof_security": (
        "Z_SCOPE_P6_REVIEW_PROOF_CONFIG_ROOT",
        "Z_SCOPE_P6_REVIEW_PROOF_CONFIG_TREE_SHA256",
    ),
}

_CODEX_EXPLICIT_ROUTE_SHA256 = canonical_sha256(
    {
        "provider": "openai",
        "model": "gpt-5.6-sol",
        "reasoning_effort": "xhigh",
        "ignore_user_config": True,
        "strict_config": True,
    }
)


class _CorrectionKind(str, Enum):
    CONTRACT_REGENERATION = "contract_regeneration"
    GROUNDING_CORRECTION = "grounding_correction"


_MATERIAL_DECISION_FIELDS = frozenset({"decision", "blocker_count", "blockers", "checks"})
_CORRECTION_FEEDBACK_SCHEMA_VERSION = "zscope.p6-review-correction-feedback.v1"


_CORRECTION_FEEDBACK = {
    _CorrectionKind.CONTRACT_REGENERATION: (
        "the previous output did not satisfy the frozen decision contract"
    ),
    _CorrectionKind.GROUNDING_CORRECTION: (
        "the previous schema-valid decision did not satisfy role-packet grounding"
    ),
}

_MAX_REVIEWER_STDOUT_BYTES = 1024 * 1024
_CLAUDE_RESULT_FIELDS = frozenset(
    {
        "type",
        "subtype",
        "is_error",
        "duration_ms",
        "duration_api_ms",
        "num_turns",
        "result",
        "session_id",
        "total_cost_usd",
        "usage",
        "modelUsage",
        "permission_denials",
        "uuid",
        "structured_output",
    }
)

P6_REVIEW_MATERIAL_SCHEMA_VERSION = "zscope.p6-review-material-manifest.v1"

ROLE_REVIEW_MATERIAL_PATHS: Dict[str, Tuple[str, ...]] = {
    "product_architecture": (
        ".github/workflows/p6-pilot-finalize-recovery.yml",
        ".github/workflows/p6-pilot-validation.yml",
        "scripts/download_p6_run_artifact.py",
        "scripts/p6_pilot_protocol.py",
        "test/range/zscope.benchmark.yaml",
        "tests/test_benchmark_isolation_executor.py",
        "tests/test_benchmark_provider_runtime.py",
        "tests/test_benchmark_runner.py",
        "tests/test_p6_pilot_protocol.py",
        "tests/test_p6_recovery_artifacts.py",
        "tests/test_p6_review_protocol.py",
        "zscope/benchmarking/isolation.py",
        "zscope/benchmarking/p6_protocol.py",
        "zscope/benchmarking/p6_review.py",
        "zscope/benchmarking/provider_runtime.py",
        "zscope/benchmarking/runner.py",
        "zscope/cli/benchmark.py",
        "zscope/framework/llm_client.py",
        "zscope/framework/llm_usage.py",
    ),
    "proof_security": (
        ".github/workflows/p6-pilot-validation.yml",
        "scripts/prepare_v3_action_canary.py",
        "scripts/run_v3_action_canary.py",
        "tests/test_fact_action_canary.py",
        "tests/test_p6_pilot_protocol.py",
        "tests/test_p6_recovery_artifacts.py",
        "tests/test_p6_review_protocol.py",
        "tests/test_validator_evidence_slice.py",
        "zscope/benchmarking/p6_protocol.py",
        "zscope/benchmarking/p6_review.py",
        "zscope/core/validation/authority.py",
        "zscope/core/validation/proofs.py",
        "zscope/core/validation/proof_kernel/checker.py",
        "zscope/core/validation/proof_kernel/engine.py",
        "zscope/orchestration/runtime_authority.py",
    ),
    "independent_benchmark": (
        ".github/workflows/p6-pilot-finalize-recovery.yml",
        ".github/workflows/p6-pilot-validation.yml",
        "scripts/download_p6_run_artifact.py",
        "scripts/p6_pilot_protocol.py",
        "test/range/zscope.benchmark.yaml",
        "tests/test_benchmark_isolation_executor.py",
        "tests/test_benchmark_provider_runtime.py",
        "tests/test_benchmark_runner.py",
        "tests/test_p6_pilot_protocol.py",
        "tests/test_p6_recovery_artifacts.py",
        "tests/test_p6_review_protocol.py",
        "zscope/benchmarking/isolation.py",
        "zscope/benchmarking/p6_protocol.py",
        "zscope/benchmarking/p6_review.py",
        "zscope/benchmarking/provider_runtime.py",
        "zscope/benchmarking/runner.py",
        "zscope/framework/llm_client.py",
        "zscope/framework/llm_usage.py",
    ),
}


def _expect_fields(value: Mapping[str, Any], expected: frozenset[str], name: str) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing or extra:
        raise P6ProtocolError(f"{name} fields are invalid; missing={missing}; extra={extra}")


def _expect_sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise P6ProtocolError(f"{name} must be a lowercase SHA-256")
    return value


def _configured_role_credential(role: str) -> Optional[str]:
    credential_name = _REVIEWER_CREDENTIAL_ENV.get(role)
    if credential_name is None:
        return None
    credential = os.environ.get(credential_name)
    if credential is None or not credential.strip():
        return None
    return credential


def _configured_role_credentials(role: str) -> Tuple[str, ...]:
    return tuple(
        value
        for name in _REVIEWER_AUTH_ENV_ALLOWLIST.get(role, ())
        if (value := os.environ.get(name, "")).strip()
        and any(marker in name for marker in ("KEY", "TOKEN"))
    )


def _assert_role_credential_absent(value: Any, *, credential: str) -> None:
    """Reject a literal role credential anywhere in a persisted JSON object."""

    if not isinstance(credential, str) or not credential.strip():
        raise P6ProtocolError("review_binding_invalid")

    def visit(item: Any) -> None:
        if isinstance(item, Mapping):
            for raw_key, nested in item.items():
                if credential in str(raw_key):
                    raise P6ProtocolError("review_binding_invalid")
                visit(nested)
        elif isinstance(item, list):
            for nested in item:
                visit(nested)
        elif isinstance(item, str) and credential in item:
            raise P6ProtocolError("review_binding_invalid")

    visit(value)


def reviewer_identity_manifest_path() -> Path:
    return Path(__file__).with_name("p6_reviewer_identities.v1.json")


def load_reviewer_identity_manifest(path: Optional[Path] = None) -> Mapping[str, Any]:
    resolved = path or reviewer_identity_manifest_path()
    value = load_json_strict(resolved)
    if not isinstance(value, Mapping) or set(value) != {"schema_version", "scanner", "reviewers"}:
        raise P6ProtocolError("P6 reviewer identity manifest fields are invalid")
    if value.get("schema_version") != "zscope.p6-reviewer-identities.v1":
        raise P6ProtocolError("P6 reviewer identity manifest version is invalid")
    if value.get("scanner") != {"model": "GLM-5.2", "review_eligible": False}:
        raise P6ProtocolError("P6 scanner identity cannot be used as an independent reviewer")
    if value.get("reviewers") != FROZEN_REVIEWER_IDENTITIES:
        raise P6ProtocolError("P6 reviewer identities differ from the frozen contract")
    return value


def reviewer_identity_sha256(role: str) -> str:
    load_reviewer_identity_manifest()
    if role not in FROZEN_REVIEWER_IDENTITIES:
        raise P6ProtocolError("P6 reviewer role is invalid")
    return str(canonical_sha256({"role": role, **FROZEN_REVIEWER_IDENTITIES[role]}))


def project_role_evidence(qualification: Mapping[str, Any], *, role: str) -> Mapping[str, Any]:
    """Return the minimum answer-free qualification view for one reviewer role."""

    if role not in REVIEW_ROLES:
        raise P6ProtocolError("P6 reviewer role is invalid")
    expected_fields = {
        "schema_version",
        "attempt_id",
        "control_plane_commit",
        "candidate_sha256",
        "policy_sha256",
        "offline_evidence_sha256",
        "provider_identity_sha256",
        "provider_probe",
        "toolchain_evidence",
        "usage_conservation",
        "selected_producer_attempt_id",
        "depths",
        "depth_count",
        "all_depths_passed",
        "formal_benchmark",
        "formal_evidence",
        "release_eligible",
        "qualification_sha256",
    }
    if set(qualification) != expected_fields or qualification.get("schema_version") != (
        "zscope.p6-qualification.v1"
    ):
        raise P6ProtocolError("P6 qualification schema is invalid for independent review")
    claimed_sha = _expect_sha256(qualification.get("qualification_sha256"), "qualification")
    unhashed = {key: value for key, value in qualification.items() if key != "qualification_sha256"}
    if canonical_sha256(unhashed) != claimed_sha:
        raise P6ProtocolError("P6 qualification hash is invalid for independent review")
    control_plane_commit = qualification.get("control_plane_commit")
    if (
        not isinstance(control_plane_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", control_plane_commit) is None
    ):
        raise P6ProtocolError("P6 qualification control-plane commit is invalid")
    if (
        qualification.get("depth_count") != 3
        or qualification.get("all_depths_passed") is not True
        or qualification.get("formal_benchmark") is not False
        or qualification.get("formal_evidence") is not False
        or qualification.get("release_eligible") is not False
    ):
        raise P6ProtocolError("P6 qualification is not a complete non-release pilot")
    rows = qualification.get("depths")
    if (
        not isinstance(rows, list)
        or len(rows) != 3
        or not all(isinstance(row, Mapping) for row in rows)
    ):
        raise P6ProtocolError("P6 qualification depth evidence is invalid")
    by_depth = {str(row.get("scan_depth")): row for row in rows}
    if set(by_depth) != {"fast", "balanced", "deep"}:
        raise P6ProtocolError("P6 qualification depth evidence is incomplete")
    validate_usage_conservation(qualification.get("usage_conservation"), require_model_calls=True)
    provider_probe = qualification.get("provider_probe")
    if not isinstance(provider_probe, Mapping) or set(provider_probe) != {
        "artifact_sha256",
        "provider_identity_sha256",
        "config_sha256",
        "model",
        "call_count",
        "provider_usage_coverage",
        "estimated_provider_call_count",
        "usage_conservation",
    }:
        raise P6ProtocolError("P6 qualification provider probe is invalid")
    for name in ("artifact_sha256", "provider_identity_sha256", "config_sha256"):
        _expect_sha256(provider_probe.get(name), f"provider probe {name}")
    if (
        provider_probe.get("model") != "GLM-5.2"
        or provider_probe.get("call_count") != 1
        or provider_probe.get("provider_usage_coverage") != 1.0
        or provider_probe.get("estimated_provider_call_count") != 0
        or provider_probe.get("provider_identity_sha256")
        != qualification.get("provider_identity_sha256")
    ):
        raise P6ProtocolError("P6 qualification provider probe invariants are invalid")
    validate_usage_conservation(provider_probe.get("usage_conservation"), require_model_calls=True)
    toolchain = qualification.get("toolchain_evidence")
    if not isinstance(toolchain, Mapping) or set(toolchain) != {
        "artifact_sha256",
        "evidence_sha256",
        "control_plane_commit",
        "candidate_git_sha",
        "candidate_git_tree",
        "image_ref",
        "image_digest",
        "image_id",
        "runtime_source_sha256",
        "oci_execution_sha256",
    }:
        raise P6ProtocolError("P6 qualification toolchain evidence is invalid")
    for name in (
        "artifact_sha256",
        "evidence_sha256",
        "runtime_source_sha256",
        "oci_execution_sha256",
    ):
        _expect_sha256(toolchain.get(name), f"toolchain {name}")
    if toolchain.get("control_plane_commit") != control_plane_commit:
        raise P6ProtocolError("P6 qualification toolchain control-plane lineage is invalid")
    for depth in ("fast", "balanced", "deep"):
        validate_usage_conservation(
            by_depth[depth].get("usage_conservation"), require_model_calls=True
        )
        if (
            by_depth[depth].get("provider_identity_sha256")
            != provider_probe["provider_identity_sha256"]
            or by_depth[depth].get("toolchain_evidence_sha256") != toolchain["artifact_sha256"]
            or by_depth[depth].get("runtime_source_sha256") != toolchain["runtime_source_sha256"]
        ):
            raise P6ProtocolError("P6 qualification depth lineage is invalid")

    common: Dict[str, Any] = {
        "schema_version": "zscope.p6-role-evidence.v1",
        "role": role,
        "qualification_sha256": claimed_sha,
        "control_plane_commit": control_plane_commit,
        "candidate_sha256": _expect_sha256(
            qualification.get("candidate_sha256"), "candidate SHA-256"
        ),
        "policy_sha256": _expect_sha256(qualification.get("policy_sha256"), "policy SHA-256"),
        "provider_identity_sha256": _expect_sha256(
            qualification.get("provider_identity_sha256"), "provider identity SHA-256"
        ),
        "formal_benchmark": False,
        "formal_evidence": False,
        "release_eligible": False,
    }
    if role == "product_architecture":
        common["evidence"] = {
            "attempt_id": qualification["attempt_id"],
            "selected_producer_attempt_id": qualification["selected_producer_attempt_id"],
            "provider_probe": dict(provider_probe),
            "toolchain_evidence": dict(toolchain),
            "depths": [
                {
                    "scan_depth": depth,
                    "projection_file_sha256": by_depth[depth]["projection_file_sha256"],
                    "cache_identity_sha256": by_depth[depth]["cache_identity_sha256"],
                    "producer_attempt_id": by_depth[depth]["producer_attempt_id"],
                }
                for depth in ("fast", "balanced", "deep")
            ],
        }
    elif role == "proof_security":
        common["evidence"] = {
            "offline_evidence_sha256": _expect_sha256(
                qualification.get("offline_evidence_sha256"), "offline evidence SHA-256"
            ),
            "provider_probe": dict(provider_probe),
            "toolchain_evidence": dict(toolchain),
            "depths": [
                {
                    "scan_depth": depth,
                    "artifact_sha256": by_depth[depth]["artifact_sha256"],
                    "queue_empty": by_depth[depth]["queue_empty"],
                    "token_conservation_passed": by_depth[depth]["token_conservation_passed"],
                    "eligible_count": by_depth[depth]["eligible_count"],
                    "entered_count": by_depth[depth]["entered_count"],
                }
                for depth in ("fast", "balanced", "deep")
            ],
        }
    else:
        common["evidence"] = {
            "usage_conservation": qualification["usage_conservation"],
            "provider_probe": dict(provider_probe),
            "toolchain_evidence": dict(toolchain),
            "depths": [
                {
                    "scan_depth": depth,
                    "artifact_sha256": by_depth[depth]["artifact_sha256"],
                    "call_count": by_depth[depth]["call_count"],
                    "provider_usage_coverage": by_depth[depth]["provider_usage_coverage"],
                    "provider_response_model_coverage": by_depth[depth][
                        "provider_response_model_coverage"
                    ],
                    "estimated_provider_call_count": by_depth[depth][
                        "estimated_provider_call_count"
                    ],
                    "telemetry_complete_rate": by_depth[depth]["telemetry_complete_rate"],
                    "queue_empty": by_depth[depth]["queue_empty"],
                    "token_conservation_passed": by_depth[depth]["token_conservation_passed"],
                    "usage_conservation": by_depth[depth]["usage_conservation"],
                }
                for depth in ("fast", "balanced", "deep")
            ],
        }
    common["role_evidence_sha256"] = canonical_sha256(common)
    return common


def build_review_material_manifest(*, candidate_root: Path, role: str) -> Mapping[str, Any]:
    """Hash the frozen allowlist without copying candidate source into artifacts."""

    if role not in ROLE_REVIEW_MATERIAL_PATHS:
        raise P6ProtocolError("P6 reviewer role is invalid")
    root = candidate_root.resolve()
    rows: List[Mapping[str, str]] = []
    total_bytes = 0
    for relative in ROLE_REVIEW_MATERIAL_PATHS[role]:
        if (
            relative.startswith("test/range/") and relative != "test/range/zscope.benchmark.yaml"
        ) or any(token in f"/{relative.lower()}/" for token in _FORBIDDEN_PACKET_PATH_TOKENS):
            raise P6ProtocolError("P6 review material allowlist contains answer material")
        path = root.joinpath(*PurePosixPath(relative).parts)
        try:
            path.resolve().relative_to(root)
        except (OSError, ValueError) as exc:
            raise P6ProtocolError("P6 review material escapes the candidate root") from exc
        if path.is_symlink() or not path.is_file():
            raise P6ProtocolError("P6 review material is missing or not a regular file")
        file_payload = path.read_bytes()
        try:
            file_payload.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise P6ProtocolError("P6 review material must be strict UTF-8") from exc
        total_bytes += len(file_payload)
        if total_bytes > 2 * 1024 * 1024:
            raise P6ProtocolError("P6 review material exceeds the bounded prompt size")
        rows.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(file_payload).hexdigest(),
            }
        )
    if tuple(row["path"] for row in rows) != ROLE_REVIEW_MATERIAL_PATHS[role]:
        raise P6ProtocolError("P6 review material order differs from the frozen allowlist")
    payload: Dict[str, Any] = {
        "schema_version": P6_REVIEW_MATERIAL_SCHEMA_VERSION,
        "role": role,
        "files": rows,
        "file_count": len(rows),
    }
    payload["material_root_sha256"] = canonical_sha256(payload)
    return payload


def _material_from_packet(
    packet: Mapping[str, Any], *, material_root: Optional[Path]
) -> Tuple[str, str]:
    manifests = [
        row
        for row in packet["artifact_files"]
        if PurePosixPath(str(row.get("path"))).name == "review-material-manifest.json"
    ]
    if len(manifests) != 1:
        raise P6ProtocolError("P6 review packet requires one material manifest")
    manifest = _load_embedded_json_answer_free(str(manifests[0]["content"]))
    if not isinstance(manifest, Mapping):
        raise P6ProtocolError("P6 review material manifest must be an object")
    if set(manifest) != {
        "schema_version",
        "role",
        "files",
        "file_count",
        "material_root_sha256",
    }:
        raise P6ProtocolError("P6 review material manifest fields are invalid")
    role = str(packet["role"])
    if (
        manifest.get("schema_version") != P6_REVIEW_MATERIAL_SCHEMA_VERSION
        or manifest.get("role") != role
    ):
        raise P6ProtocolError("P6 review material manifest role is invalid")
    claimed_root = _expect_sha256(manifest.get("material_root_sha256"), "material root")
    projection = {key: value for key, value in manifest.items() if key != "material_root_sha256"}
    if canonical_sha256(projection) != claimed_root:
        raise P6ProtocolError("P6 review material root hash is invalid")
    rows = manifest.get("files")
    if not isinstance(rows, list) or manifest.get("file_count") != len(rows):
        raise P6ProtocolError("P6 review material file count is invalid")
    expected_paths = ROLE_REVIEW_MATERIAL_PATHS[role]
    if tuple(str(row.get("path")) for row in rows if isinstance(row, Mapping)) != expected_paths:
        raise P6ProtocolError("P6 review material differs from the frozen role allowlist")
    if material_root is None:
        return claimed_root, ""
    candidate_root = material_root.resolve()
    excerpts: List[str] = []
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {"path", "sha256"}:
            raise P6ProtocolError("P6 review material row is invalid")
        relative = str(row["path"])
        expected_sha = _expect_sha256(row["sha256"], "review material file")
        path = candidate_root.joinpath(*PurePosixPath(relative).parts)
        try:
            path.resolve().relative_to(candidate_root)
        except (OSError, ValueError) as exc:
            raise P6ProtocolError("P6 review material escapes the candidate root") from exc
        if path.is_symlink() or not path.is_file():
            raise P6ProtocolError("P6 review material is unavailable")
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != expected_sha:
            raise P6ProtocolError("P6 review material differs from its manifest")
        try:
            content = payload.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise P6ProtocolError("P6 review material must be strict UTF-8") from exc
        excerpts.append(f"--- {relative} sha256:{expected_sha} ---\n{content}")
    return claimed_root, "\n\n".join(excerpts)


def _canonical_packet_projection(packet: Mapping[str, Any]) -> Mapping[str, Any]:
    return _packet_content_projection(packet)


def _load_embedded_json_answer_free(content: str) -> Any:
    def reject_duplicates(rows: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise P6ProtocolError("P6 review evidence contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        value = json.loads(content, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as exc:
        raise P6ProtocolError("P6 review evidence must be strict UTF-8 JSON") from exc

    def visit(item: Any) -> None:
        if isinstance(item, Mapping):
            for raw_key, nested in item.items():
                key = re.sub(r"[^a-z0-9]+", "_", str(raw_key).lower()).strip("_")
                if key in _FORBIDDEN_EVIDENCE_KEYS:
                    raise P6ProtocolError("P6 review evidence contains forbidden answer material")
                visit(nested)
        elif isinstance(item, list):
            for nested in item:
                visit(nested)

    visit(value)
    return value


def validate_review_packet(packet: Mapping[str, Any], *, packet_root: Path) -> None:
    _expect_fields(packet, _PACKET_FIELDS, "P6 review packet")
    if packet.get("schema_version") != P6_REVIEW_PACKET_SCHEMA_VERSION:
        raise P6ProtocolError("P6 review packet schema version is invalid")
    role = packet.get("role")
    if role not in REVIEW_ROLES:
        raise P6ProtocolError("P6 review packet role is invalid")
    credential = _configured_role_credential(str(role))
    if credential is not None:
        _assert_role_credential_absent(packet, credential=credential)
    packet_sha = _expect_sha256(packet.get("packet_sha256"), "packet_sha256")
    if packet_sha != canonical_sha256(_canonical_packet_projection(packet)):
        raise P6ProtocolError("P6 review packet content hash is invalid")
    expected_uid = f"p6-review:{role}:{packet_sha}"
    if packet.get("packet_uid") != expected_uid:
        raise P6ProtocolError("P6 review packet UID is invalid")
    for name in (
        "candidate_sha256",
        "policy_sha256",
        "qualification_sha256",
        "evidence_root_sha256",
    ):
        _expect_sha256(packet.get(name), name)
    files = packet.get("artifact_files")
    if not isinstance(files, list) or not files:
        raise P6ProtocolError("P6 review packet must contain role-specific artifact files")
    seen: set[str] = set()
    normalized_rows: List[Mapping[str, Any]] = []
    for row in files:
        if not isinstance(row, Mapping) or set(row) != {"path", "sha256", "content"}:
            raise P6ProtocolError("P6 review packet artifact row is invalid")
        relative = row.get("path")
        if not isinstance(relative, str) or not relative:
            raise P6ProtocolError("P6 review packet artifact path is invalid")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
            raise P6ProtocolError("P6 review packet artifact path is not canonical")
        lowered = f"/{relative.lower()}/"
        if any(token in lowered for token in _FORBIDDEN_PACKET_PATH_TOKENS):
            raise P6ProtocolError("P6 review packet contains answer or cross-review material")
        if relative in seen:
            raise P6ProtocolError("P6 review packet contains a duplicate artifact path")
        seen.add(relative)
        expected_sha = _expect_sha256(row.get("sha256"), "packet artifact SHA-256")
        artifact = packet_root.joinpath(*pure.parts)
        try:
            artifact.resolve().relative_to(packet_root.resolve())
        except ValueError as exc:
            raise P6ProtocolError("P6 review packet artifact escapes the packet root") from exc
        if sha256_file(artifact) != expected_sha:
            raise P6ProtocolError("P6 review packet artifact hash is invalid")
        try:
            content = artifact.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise P6ProtocolError("P6 review packet artifacts must be strict UTF-8") from exc
        if row.get("content") != content:
            raise P6ProtocolError("P6 review packet embedded evidence differs from its artifact")
        if len(content.encode("utf-8")) > 1024 * 1024:
            raise P6ProtocolError("P6 review packet embedded evidence is too large")
        _load_embedded_json_answer_free(content)
        normalized_rows.append({"path": relative, "sha256": expected_sha, "content": content})
    if files != sorted(normalized_rows, key=lambda row: str(row["path"])):
        raise P6ProtocolError("P6 review packet artifacts must be sorted by path")
    _material_from_packet(packet, material_root=None)


def build_review_packet(
    *,
    role: str,
    candidate_sha256: str,
    policy_sha256: str,
    qualification_sha256: str,
    evidence_root_sha256: str,
    artifact_files: Sequence[Mapping[str, str]],
) -> Mapping[str, Any]:
    if role not in REVIEW_ROLES:
        raise P6ProtocolError("P6 reviewer role is invalid")
    payload: Dict[str, Any] = {
        "schema_version": P6_REVIEW_PACKET_SCHEMA_VERSION,
        "packet_uid": "",
        "packet_sha256": "",
        "role": role,
        "candidate_sha256": candidate_sha256,
        "policy_sha256": policy_sha256,
        "qualification_sha256": qualification_sha256,
        "evidence_root_sha256": evidence_root_sha256,
        "artifact_files": sorted(
            [dict(row) for row in artifact_files], key=lambda row: str(row.get("path", ""))
        ),
    }
    packet = finalize_review_packet(payload)
    credential = _configured_role_credential(role)
    if credential is not None:
        _assert_role_credential_absent(packet, credential=credential)
    return packet


def _packet_content_projection(packet: Mapping[str, Any]) -> Mapping[str, Any]:
    return {key: packet[key] for key in sorted(_PACKET_FIELDS - {"packet_sha256", "packet_uid"})}


def finalize_review_packet(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    result = dict(payload)
    packet_sha = canonical_sha256(_packet_content_projection(result))
    result["packet_sha256"] = packet_sha
    result["packet_uid"] = f"p6-review:{result['role']}:{packet_sha}"
    return result


def _decision_schema(packet: Mapping[str, Any], *, role: str) -> Mapping[str, Any]:
    identity = FROZEN_REVIEWER_IDENTITIES[role]
    check_names = ROLE_CHECKS[role]
    return {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(_DECISION_FIELDS),
        "properties": {
            "schema_version": {
                "type": "string",
                "const": P6_REVIEW_DECISION_SCHEMA_VERSION,
            },
            "packet_uid": {"type": "string", "const": packet["packet_uid"]},
            "packet_sha256": {"type": "string", "const": packet["packet_sha256"]},
            "qualification_sha256": {
                "type": "string",
                "const": packet["qualification_sha256"],
            },
            "evidence_root_sha256": {
                "type": "string",
                "const": packet["evidence_root_sha256"],
            },
            "role": {"type": "string", "const": role},
            "harness": {"type": "string", "const": identity["harness"]},
            "harness_version": {
                "type": "string",
                "const": identity["harness_version"],
            },
            "provider": {"type": "string", "const": identity["provider"]},
            "model": {"type": "string", "const": identity["model"]},
            "reasoning_effort": {
                "type": "string",
                "const": identity["reasoning_effort"],
            },
            "decision": {
                "type": "string",
                "enum": ["approved", "changes_required"],
            },
            "blocker_count": {"type": "integer", "minimum": 0},
            "blockers": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["code", "artifact_sha256"],
                    "properties": {
                        "code": {"type": "string", "enum": sorted(BLOCKER_CODES)},
                        "artifact_sha256": {
                            "type": "string",
                            "pattern": "^[0-9a-f]{64}$",
                        },
                    },
                },
            },
            "checks": {
                "type": "array",
                "minItems": len(check_names),
                "maxItems": len(check_names),
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["name", "result", "artifact_sha256"],
                    "properties": {
                        "name": {"type": "string", "enum": list(check_names)},
                        "result": {"type": "string", "enum": ["pass", "fail"]},
                        "artifact_sha256": {
                            "type": "string",
                            "pattern": "^[0-9a-f]{64}$",
                        },
                    },
                },
            },
        },
    }


def _validate_review_decision_contract(
    decision: Mapping[str, Any], *, packet: Mapping[str, Any], role: str
) -> None:
    _expect_fields(decision, _DECISION_FIELDS, "P6 review decision")
    if role not in REVIEW_ROLES or packet.get("role") != role:
        raise P6ProtocolError("P6 review decision role is invalid")
    identity = FROZEN_REVIEWER_IDENTITIES[role]
    expected = {
        "schema_version": P6_REVIEW_DECISION_SCHEMA_VERSION,
        "packet_uid": packet["packet_uid"],
        "packet_sha256": packet["packet_sha256"],
        "qualification_sha256": packet["qualification_sha256"],
        "evidence_root_sha256": packet["evidence_root_sha256"],
        "role": role,
        "harness": identity["harness"],
        "harness_version": identity["harness_version"],
        "provider": identity["provider"],
        "model": identity["model"],
        "reasoning_effort": identity["reasoning_effort"],
    }
    if any(decision.get(key) != value for key, value in expected.items()):
        raise P6ProtocolError("P6 review decision binding or reviewer identity is invalid")
    blockers = decision.get("blockers")
    blocker_count = decision.get("blocker_count")
    if (
        not isinstance(blockers, list)
        or isinstance(blocker_count, bool)
        or not isinstance(blocker_count, int)
    ):
        raise P6ProtocolError("P6 review blockers are invalid")
    if blocker_count != len(blockers):
        raise P6ProtocolError("P6 review blocker count does not conserve")
    for blocker in blockers:
        if not isinstance(blocker, Mapping) or set(blocker) != {"code", "artifact_sha256"}:
            raise P6ProtocolError("P6 review blocker is invalid")
        if blocker.get("code") not in BLOCKER_CODES:
            raise P6ProtocolError("P6 review blocker code is invalid")
        _expect_sha256(blocker.get("artifact_sha256"), "review blocker artifact")
    checks = decision.get("checks")
    if not isinstance(checks, list) or len(checks) != len(ROLE_CHECKS[role]):
        raise P6ProtocolError("P6 review checks are invalid")
    names: List[str] = []
    results: List[str] = []
    for row in checks:
        if not isinstance(row, Mapping) or set(row) != {"name", "result", "artifact_sha256"}:
            raise P6ProtocolError("P6 review check is invalid")
        names.append(str(row.get("name")))
        results.append(str(row.get("result")))
        _expect_sha256(row.get("artifact_sha256"), "review check artifact")
    if tuple(names) != ROLE_CHECKS[role] or any(
        result not in {"pass", "fail"} for result in results
    ):
        raise P6ProtocolError("P6 review checks do not match the frozen role contract")
    disposition = decision.get("decision")
    if disposition == "approved":
        if blocker_count != 0 or any(result != "pass" for result in results):
            raise P6ProtocolError("approved P6 review must have zero blockers and all checks pass")
    elif disposition == "changes_required":
        if blocker_count < 1 or all(result == "pass" for result in results):
            raise P6ProtocolError(
                "changes-required P6 review must contain a blocker and failed check"
            )
    else:
        raise P6ProtocolError("P6 review disposition is invalid")


def _validate_review_decision_grounding(
    decision: Mapping[str, Any], *, packet: Mapping[str, Any]
) -> None:
    allowed_artifacts = {str(row["sha256"]) for row in packet["artifact_files"]}
    material_artifacts = {
        str(row["sha256"])
        for row in packet["artifact_files"]
        if PurePosixPath(str(row.get("path"))).name == "review-material-manifest.json"
    }
    if len(material_artifacts) != 1:
        raise P6ProtocolError("P6 review decision lacks one material manifest")
    referenced_artifacts: set[str] = set()
    for blocker in decision["blockers"]:
        artifact_sha = str(blocker["artifact_sha256"])
        if artifact_sha not in allowed_artifacts:
            raise P6ProtocolError("P6 review grounding is outside the role packet")
        referenced_artifacts.add(artifact_sha)
    for check in decision["checks"]:
        artifact_sha = str(check["artifact_sha256"])
        if artifact_sha not in allowed_artifacts:
            raise P6ProtocolError("P6 review grounding is outside the role packet")
        referenced_artifacts.add(artifact_sha)
    if referenced_artifacts.isdisjoint(material_artifacts):
        raise P6ProtocolError("P6 review decision is not grounded to its material manifest")


def validate_review_decision(
    decision: Mapping[str, Any], *, packet: Mapping[str, Any], role: str
) -> None:
    credential = _configured_role_credential(role)
    if credential is not None:
        _assert_role_credential_absent(decision, credential=credential)
    _validate_review_decision_contract(decision, packet=packet, role=role)
    _validate_review_decision_grounding(decision, packet=packet)


def _decision_substantive_projection(decision: Mapping[str, Any]) -> Mapping[str, Any]:
    blockers = decision.get("blockers")
    checks = decision.get("checks")
    return {
        "decision": decision.get("decision"),
        "blocker_count": decision.get("blocker_count"),
        "blocker_codes": (
            [row.get("code") for row in blockers if isinstance(row, Mapping)]
            if isinstance(blockers, list)
            else None
        ),
        "checks": (
            [
                {"name": row.get("name"), "result": row.get("result")}
                for row in checks
                if isinstance(row, Mapping)
            ]
            if isinstance(checks, list)
            else None
        ),
    }


def _contract_locked_projection(
    decision: Mapping[str, Any], mutable_material_fields: Sequence[str]
) -> Mapping[str, Any]:
    mutable = set(mutable_material_fields)
    return {
        field: {"present": field in decision, "value": decision.get(field)}
        for field in sorted(_MATERIAL_DECISION_FIELDS)
        if field not in mutable
    }


def _contract_mutable_material_fields(
    decision: Mapping[str, Any], *, role: str
) -> Optional[Tuple[str, ...]]:
    """Return a bounded top-level material repair surface or fail closed as ambiguous."""

    mutable: set[str] = {field for field in _MATERIAL_DECISION_FIELDS if field not in decision}
    disposition = decision.get("decision")
    disposition_valid = disposition in {"approved", "changes_required"}
    if not disposition_valid:
        mutable.add("decision")

    blocker_count = decision.get("blocker_count")
    blocker_count_valid = (
        isinstance(blocker_count, int)
        and not isinstance(blocker_count, bool)
        and blocker_count >= 0
    )
    if not blocker_count_valid:
        mutable.add("blocker_count")

    blockers = decision.get("blockers")
    blockers_valid = isinstance(blockers, list)
    if blockers_valid:
        assert isinstance(blockers, list)
        for blocker in blockers:
            if (
                not isinstance(blocker, Mapping)
                or set(blocker) != {"code", "artifact_sha256"}
                or blocker.get("code") not in BLOCKER_CODES
                or re.fullmatch(r"[0-9a-f]{64}", str(blocker.get("artifact_sha256") or "")) is None
            ):
                blockers_valid = False
                break
    if not blockers_valid:
        mutable.add("blockers")

    checks = decision.get("checks")
    checks_valid = isinstance(checks, list) and len(checks) == len(ROLE_CHECKS[role])
    if checks_valid:
        assert isinstance(checks, list)
        names: List[str] = []
        for row in checks:
            if (
                not isinstance(row, Mapping)
                or set(row) != {"name", "result", "artifact_sha256"}
                or row.get("result") not in {"pass", "fail"}
                or re.fullmatch(r"[0-9a-f]{64}", str(row.get("artifact_sha256") or "")) is None
            ):
                checks_valid = False
                break
            names.append(str(row.get("name")))
        if checks_valid and tuple(names) != ROLE_CHECKS[role]:
            checks_valid = False
    if not checks_valid:
        mutable.add("checks")

    if disposition_valid and blocker_count_valid and blockers_valid and checks_valid:
        assert (
            isinstance(blocker_count, int)
            and not isinstance(blocker_count, bool)
            and isinstance(blockers, list)
            and isinstance(checks, list)
        )
        interfield_valid = blocker_count == len(blockers)
        if disposition == "approved":
            interfield_valid = (
                interfield_valid
                and blocker_count == 0
                and all(row["result"] == "pass" for row in checks)
            )
        else:
            interfield_valid = (
                interfield_valid
                and blocker_count >= 1
                and any(row["result"] == "fail" for row in checks)
            )
        if not interfield_valid:
            # The harness cannot choose which otherwise-valid judgment is authoritative.
            return None

    # With no immutable material field left, a retry would be an unbounded new review.
    if mutable == _MATERIAL_DECISION_FIELDS:
        return None
    return tuple(sorted(mutable))


def _correction_feedback(
    kind: _CorrectionKind,
    *,
    parsed_object: bool,
    mutable_material_fields: Optional[Sequence[str]],
) -> Mapping[str, Any]:
    return {
        "schema_version": _CORRECTION_FEEDBACK_SCHEMA_VERSION,
        "kind": kind.value,
        "validation_class": (
            "decision_contract_invalid"
            if kind is _CorrectionKind.CONTRACT_REGENERATION
            else "decision_grounding_invalid"
        ),
        "parsed_object": parsed_object,
        "mutable_material_fields": (
            list(mutable_material_fields) if mutable_material_fields is not None else None
        ),
        "mutable_grounding_paths": (
            ["$.blockers[*].artifact_sha256", "$.checks[*].artifact_sha256"]
            if kind is _CorrectionKind.GROUNDING_CORRECTION
            else []
        ),
    }


def _assert_no_hidden_reasoning(value: Any, *, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for raw_key, nested in value.items():
            key = re.sub(r"[^a-z0-9]+", "_", str(raw_key).lower()).strip("_")
            if key in _HIDDEN_REASONING_KEYS:
                raise P6ProtocolError(f"P6 reviewer output contains hidden reasoning at {path}")
            _assert_no_hidden_reasoning(nested, path=f"{path}.{raw_key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _assert_no_hidden_reasoning(nested, path=f"{path}[{index}]")


def _normalize_json_artifact(stdout: str) -> Any:
    if len(stdout.encode("utf-8")) > _MAX_REVIEWER_STDOUT_BYTES:
        raise P6ProtocolError("P6 reviewer output exceeds the bounded envelope size")

    def reject_duplicates(rows: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise P6ProtocolError("P6 reviewer output contains duplicate JSON keys")
            result[key] = value
        return result

    def parse(value: str) -> Any:
        try:
            return json.loads(value, object_pairs_hook=reject_duplicates)
        except json.JSONDecodeError as exc:
            raise P6ProtocolError("P6 reviewer output is not one JSON artifact") from exc

    stripped = stdout.strip()
    try:
        return parse(stripped)
    except P6ProtocolError:
        match = re.fullmatch(
            r"```(?:json)?[ \t]*\r?\n(?P<body>.*?)(?:\r?\n)?```",
            stripped,
            flags=re.DOTALL,
        )
        if match is None or "```" in match.group("body"):
            raise P6ProtocolError("P6 reviewer output is not one JSON artifact")
        return parse(match.group("body").strip())


def decision_from_stdout(stdout: str, *, role: str) -> Mapping[str, Any]:
    value = _normalize_json_artifact(stdout)
    _assert_no_hidden_reasoning(value)
    if role == "product_architecture" and isinstance(value, Mapping):
        if set(value) == _CLAUDE_RESULT_FIELDS:
            if (
                value.get("type") != "result"
                or value.get("subtype") != "success"
                or value.get("is_error") is not False
                or not isinstance(value.get("structured_output"), Mapping)
            ):
                raise P6ProtocolError("P6 Claude result envelope is invalid")
            value = value["structured_output"]
        elif set(value) != _DECISION_FIELDS:
            raise P6ProtocolError("P6 Claude result envelope fields are invalid")
    if not isinstance(value, Mapping):
        raise P6ProtocolError("P6 reviewer did not return a JSON decision object")
    return dict(value)


def _parsed_decision_for_correction(stdout: str, *, role: str) -> Optional[Mapping[str, Any]]:
    """Recover only a plain parsed decision, never a provider transport envelope."""

    try:
        value = _normalize_json_artifact(stdout)
        _assert_no_hidden_reasoning(value)
    except P6ProtocolError:
        return None
    if role == "product_architecture" and isinstance(value, Mapping):
        if set(value) == _CLAUDE_RESULT_FIELDS:
            structured = value.get("structured_output")
            value = structured if isinstance(structured, Mapping) else None
        elif "structured_output" in value:
            return None
    return dict(value) if isinstance(value, Mapping) else None


def _classify_decision_output(
    stdout: str, *, packet: Mapping[str, Any], role: str
) -> Tuple[Optional[Mapping[str, Any]], Optional[_CorrectionKind]]:
    """Classify only by the fixed validation stage, never by exception text."""

    try:
        decision = decision_from_stdout(stdout, role=role)
    except P6ProtocolError:
        return (
            _parsed_decision_for_correction(stdout, role=role),
            _CorrectionKind.CONTRACT_REGENERATION,
        )
    try:
        _validate_review_decision_contract(decision, packet=packet, role=role)
    except P6ProtocolError:
        return decision, _CorrectionKind.CONTRACT_REGENERATION
    try:
        _validate_review_decision_grounding(decision, packet=packet)
    except P6ProtocolError:
        return decision, _CorrectionKind.GROUNDING_CORRECTION
    return decision, None


def _claude_arguments(schema: Mapping[str, Any]) -> List[str]:
    return [
        "--print",
        "--model",
        "glm-5.3",
        "--effort",
        "high",
        "--output-format",
        "json",
        "--json-schema",
        json.dumps(schema, separators=(",", ":")),
        "--permission-mode",
        "plan",
        "--tools",
        "",
        "--no-session-persistence",
        "--disable-slash-commands",
    ]


def _codex_arguments() -> List[str]:
    return [
        "exec",
        "--model",
        "gpt-5.6-sol",
        "--config",
        'model_reasoning_effort="xhigh"',
        "--strict-config",
        "--disable",
        "shell_tool",
        "--sandbox",
        "read-only",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--skip-git-repo-check",
        "--output-schema",
        "decision-schema.json",
        "--color",
        "never",
        "-",
    ]


def _deepseek_patch_text() -> str:
    return (
        "- id: agent-default-model\n"
        "  config:\n"
        "    provider: deepseek\n"
        "    model: deepseek-v4-pro-0813\n"
        "    reasoningEffort: max\n"
        "- id: system-prompt\n"
        "  config:\n"
        "    persona: >-\n"
        "      You are an isolated P6 proof-security reviewer. Read only the role packet\n"
        "      and return exactly one JSON object matching decision-schema.json. Never\n"
        "      use external knowledge, shell access, or another reviewer output.\n"
        "- id: tool-web\n"
        "  disabled: true\n"
        "- id: tool-fs-search\n"
        "  disabled: true\n"
        "- id: tool-pwsh\n"
        "  disabled: true\n"
        "- id: tool-jobs\n"
        "  disabled: true\n"
        "- id: tool-subagent\n"
        "  disabled: true\n"
        "- id: tool-subagent-fork\n"
        "  disabled: true\n"
        "- id: tool-workflow\n"
        "  disabled: true\n"
        "- id: tool-ralph\n"
        "  disabled: true\n"
        "- id: tool-str-replace-editor\n"
        "  disabled: true\n"
        "- id: tool-todo\n"
        "  disabled: true\n"
        "- id: tool-goal\n"
        "  disabled: true\n"
    )


def _deepseek_instruction() -> str:
    return (
        "Read review-instructions.txt, packet.json, and decision-schema.json from the "
        "isolated current directory. Follow those instructions and return exactly one "
        "JSON object. Do not use external knowledge or another reviewer output."
    )


def _route_config_tree_sha256(root: Path) -> str:
    source = root.absolute()
    if not source.is_absolute() or source.is_symlink() or not source.is_dir():
        raise P6ProtocolError("review_binding_invalid")
    digest = hashlib.sha256()
    files = sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix())
    regular = 0
    for path in files:
        if path.is_symlink():
            raise P6ProtocolError("review_binding_invalid")
        if path.is_dir():
            continue
        if not path.is_file():
            raise P6ProtocolError("review_binding_invalid")
        relative = path.relative_to(source).as_posix().encode("utf-8")
        payload = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
        regular += 1
    if regular == 0:
        raise P6ProtocolError("review_binding_invalid")
    return digest.hexdigest()


def _discover_reviewer_config(role: str) -> Optional[Path]:
    home = Path(os.environ.get("HOME") or os.environ.get("USERPROFILE") or "")
    xdg = Path(os.environ.get("XDG_CONFIG_HOME") or (home / ".config"))
    candidates = {
        "product_architecture": (
            os.environ.get("CLAUDE_CONFIG_DIR", ""),
            str(home / ".claude") if str(home) else "",
        ),
        "proof_security": (
            os.environ.get("DSH_HOME", ""),
            str(xdg / "dsh") if str(xdg) else "",
            str(home / ".dsh") if str(home) else "",
        ),
        "independent_benchmark": (
            os.environ.get("CODEX_HOME", ""),
            str(home / ".codex") if str(home) else "",
        ),
    }[role]
    for raw in candidates:
        if not raw:
            continue
        source = Path(raw)
        if source.is_absolute() and not source.is_symlink() and source.is_dir():
            if role == "independent_benchmark":
                return source
            try:
                _route_config_tree_sha256(source)
            except P6ProtocolError:
                continue
            return source
    return None


def _install_reviewer_route_config(role: str, *, destination: Path) -> str:
    configured = _REVIEWER_ROUTE_CONFIG_ENV.get(role)
    raw_root = os.environ.get(configured[0], "") if configured else ""
    expected_sha = os.environ.get(configured[1], "") if configured else ""
    if bool(raw_root) != bool(expected_sha):
        raise P6ProtocolError("review_binding_invalid")
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    if role == "independent_benchmark":
        # Codex is forced to ignore user configuration.  Preserve an existing
        # sealed-runner login in place rather than recursively copying the
        # potentially large CODEX_HOME; --ephemeral prevents session writes.
        return _CODEX_EXPLICIT_ROUTE_SHA256
    source = Path(raw_root) if raw_root else _discover_reviewer_config(role)
    tree_sha = ""
    if source is not None:
        tree_sha = _route_config_tree_sha256(source)
        if expected_sha and tree_sha != expected_sha:
            raise P6ProtocolError("review_binding_invalid")
        for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
            if path.is_symlink():
                raise P6ProtocolError("review_binding_invalid")
            target = destination / path.relative_to(source)
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(path, target, follow_symlinks=False)
            target.chmod(0o600)
        if _route_config_tree_sha256(destination) != tree_sha:
            raise P6ProtocolError("review_binding_invalid")
    elif expected_sha:
        raise P6ProtocolError("review_binding_invalid")
    if expected_sha:
        return expected_sha
    route_environment = {
        name: os.environ[name]
        for name in ("ANTHROPIC_BASE_URL", "DEEPSEEK_BASE_URL")
        if name in _REVIEWER_AUTH_ENV_ALLOWLIST[role] and os.environ.get(name)
    }
    return canonical_sha256(
        {
            "role": role,
            "config_tree_sha256": tree_sha or ("0" * 64),
            "route_environment": route_environment,
        }
    )


def _reviewer_environment(role: str, *, temp_root: Path) -> Dict[str, str]:
    if role not in REVIEW_ROLES:
        raise P6ProtocolError("P6 reviewer role is invalid")
    root = temp_root.resolve()
    home = root / "home"
    config = root / "config"
    cache = root / "cache"
    data = root / "data"
    temporary = root / "tmp"
    for path in (home, config, cache, data, temporary):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.chmod(0o700)
    common = frozenset(
        {"PATH", "SYSTEMROOT", "WINDIR", "PATHEXT", "COMSPEC", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    )
    result = {
        key.upper(): value
        for key, value in os.environ.items()
        if key.upper() in common and key.upper() != "PATH"
    }
    result["PATH"] = _cleaned_runner_path(os.environ.get("PATH", ""))
    for name in _REVIEWER_AUTH_ENV_ALLOWLIST[role]:
        value = os.environ.get(name, "")
        if value.strip():
            result[name] = value
    result.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(config),
            "XDG_CACHE_HOME": str(cache),
            "XDG_DATA_HOME": str(data),
            "TEMP": str(temporary),
            "TMP": str(temporary),
            "TMPDIR": str(temporary),
        }
    )
    if role == "product_architecture":
        claude = config / "claude"
        route_sha = _install_reviewer_route_config(role, destination=claude)
        result["CLAUDE_CONFIG_DIR"] = str(claude)
        result["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    elif role == "proof_security":
        dsh = config / "dsh"
        route_sha = _install_reviewer_route_config(role, destination=dsh)
        result["DSH_HOME"] = str(dsh)
        result["DSH_PERMISSION_MODE"] = "read-only"
    else:
        codex = config / "codex"
        route_sha = _install_reviewer_route_config(role, destination=codex)
        sealed_codex_home = _discover_reviewer_config(role)
        result["CODEX_HOME"] = str(sealed_codex_home or codex)
    result["Z_SCOPE_P6_REVIEW_ROUTE_CONFIG_SHA256"] = route_sha
    return result


def _prompt(packet: Mapping[str, Any], *, role: str, material: str) -> str:
    identity = FROZEN_REVIEWER_IDENTITIES[role]
    return (
        "Review only the isolated P6 packet and its hash-bound role artifacts. Do not use "
        "external knowledge, another reviewer output, scanner Truth, expected results, or a "
        "scorer. Return one JSON object matching decision-schema.json. Every check must appear "
        f"once in this exact order: {json.dumps(ROLE_CHECKS[role])}. Bind role={role}, "
        f"harness={identity['harness']}, harness_version={identity['harness_version']}, "
        f"provider={identity['provider']}, model={identity['model']}, and "
        f"reasoning_effort={identity['reasoning_effort']}. Packet: "
        + json.dumps(packet, ensure_ascii=False, sort_keys=True)
        + "\nHash-bound ephemeral candidate review material (never persisted in review artifacts):\n"
        + material
    )


def _correction_prompt(
    prompt: str,
    kind: Any,
    *,
    feedback: Optional[Mapping[str, Any]] = None,
    prior_decision: Optional[Mapping[str, Any]] = None,
) -> str:
    try:
        correction_kind = kind if isinstance(kind, _CorrectionKind) else _CorrectionKind(kind)
    except (TypeError, ValueError):
        raise P6ProtocolError("P6 reviewer correction kind is invalid")
    correction = (
        prompt
        + "\nFixed answer-free feedback: "
        + _CORRECTION_FEEDBACK[correction_kind]
        + ". Re-emit exactly one schema-valid decision grounded only in the "
        "embedded artifact SHA-256 values. Do not discuss the failed output."
    )
    if feedback is not None:
        correction += "\nANSWER_FREE_VALIDATION_FEEDBACK:\n" + json.dumps(
            feedback,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    if prior_decision is not None:
        correction += (
            "\nPRIOR_PARSED_DECISION_FOR_BOUNDED_REPAIR:\n"
            + json.dumps(
                prior_decision,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\nPreserve every material field outside the exact mutable allowlist "
            "in the answer-free feedback."
        )
    return correction


def _next_correction_kind(
    history: Sequence[_CorrectionKind], failure: _CorrectionKind
) -> Optional[_CorrectionKind]:
    """Return the sole legal next correction for the bounded state machine."""

    frozen_history = tuple(history)
    if failure is _CorrectionKind.CONTRACT_REGENERATION:
        return failure if not frozen_history else None
    if failure is _CorrectionKind.GROUNDING_CORRECTION and frozen_history in {
        (),
        (_CorrectionKind.CONTRACT_REGENERATION,),
    }:
        return failure
    return None


def _command_for_role(
    role: str,
    *,
    executable: Path,
    executable_sha256: str,
    temp_root: Path,
    schema: Mapping[str, Any],
    prompt: str,
) -> Tuple[List[str], List[str]]:
    if role == "product_architecture":
        arguments = _claude_arguments(schema)
        return [str(executable), *arguments], [
            str(executable),
            f"<binary-sha256:{executable_sha256}>",
            *arguments,
        ]
    if role == "proof_security":
        patch = temp_root / "deepseek-max.patch.yml"
        patch.write_text(_deepseek_patch_text(), encoding="utf-8")
        patch.chmod(0o600)
        patch_hash = sha256_file(patch)
        command = [
            str(executable),
            "--profile",
            "headless",
            "--patch",
            str(patch),
            _deepseek_instruction(),
        ]
        identity = [
            str(executable),
            f"<binary-sha256:{executable_sha256}>",
            "--profile",
            "headless",
            "--patch",
            f"<ephemeral-patch-sha256:{patch_hash}>",
            "<isolated-instruction-sha256:"
            + hashlib.sha256(_deepseek_instruction().encode("utf-8")).hexdigest()
            + ">",
        ]
        return command, identity
    if role == "independent_benchmark":
        arguments = _codex_arguments()
        return [str(executable), *arguments], [
            str(executable),
            f"<binary-sha256:{executable_sha256}>",
            *arguments,
        ]
    raise P6ProtocolError("P6 reviewer role is invalid")


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        normalized_path = os.path.normcase(str(path.resolve(strict=False)))
        normalized_root = os.path.normcase(str(root.resolve(strict=False)))
        return os.path.commonpath((normalized_path, normalized_root)) == normalized_root
    except (OSError, ValueError):
        return False


def _untrusted_reviewer_roots() -> Tuple[Path, ...]:
    raw_roots = [
        str(Path.cwd()),
        os.environ.get("GITHUB_WORKSPACE", ""),
        os.environ.get("P6_CANDIDATE_ROOT", ""),
        os.environ.get("RUNNER_TEMP", ""),
        os.environ.get("TMPDIR", ""),
        os.environ.get("TMP", ""),
        os.environ.get("TEMP", ""),
        tempfile.gettempdir(),
    ]
    roots: List[Path] = []
    seen: set[str] = set()
    for raw_root in raw_roots:
        if not raw_root:
            continue
        root = Path(raw_root)
        if not root.is_absolute():
            continue
        try:
            resolved = root.resolve(strict=False)
        except OSError:
            continue
        key = os.path.normcase(str(resolved))
        if key not in seen:
            roots.append(resolved)
            seen.add(key)
    return tuple(roots)


def _cleaned_runner_path(raw_path: str) -> str:
    """Keep only absolute sealed-runner PATH directories outside job-controlled roots."""

    if not isinstance(raw_path, str):
        raise P6ProtocolError("review_binding_invalid")
    untrusted_roots = _untrusted_reviewer_roots()
    cleaned: List[str] = []
    seen: set[str] = set()
    for raw_entry in raw_path.split(os.pathsep):
        if not raw_entry:
            continue
        entry = Path(raw_entry)
        if not entry.is_absolute():
            continue
        try:
            resolved = entry.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        if not stat.S_ISDIR(metadata.st_mode) or any(
            _path_is_within(resolved, root) for root in untrusted_roots
        ):
            continue
        key = os.path.normcase(str(resolved))
        if key not in seen:
            cleaned.append(str(resolved))
            seen.add(key)
    if not cleaned:
        raise P6ProtocolError("review_binding_invalid")
    return os.pathsep.join(cleaned)


def _safe_executable_sha256(source: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        if source.is_symlink():
            raise P6ProtocolError("review_binding_invalid")
        descriptor = os.open(source, flags)
    except (OSError, P6ProtocolError):
        raise P6ProtocolError("review_binding_invalid") from None
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_size > _MAX_REVIEWER_EXECUTABLE_BYTES
            or (os.name != "nt" and before.st_mode & 0o111 == 0)
        ):
            raise P6ProtocolError("review_binding_invalid")
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise P6ProtocolError("review_binding_invalid")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise P6ProtocolError("review_binding_invalid")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise P6ProtocolError("review_binding_invalid")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _resolve_reviewer_executable(
    role: str, *, search_path: Optional[str] = None
) -> Tuple[Path, str]:
    """Resolve one E0 CLI only from the sanitized sealed-runner PATH."""

    command_name = _REVIEWER_EXECUTABLE_NAMES.get(role)
    if command_name is None:
        raise P6ProtocolError("review_binding_invalid")
    cleaned_path = _cleaned_runner_path(
        search_path if search_path is not None else os.environ.get("PATH", "")
    )
    discovered = shutil.which(command_name, path=cleaned_path)
    if not discovered:
        raise P6ProtocolError("review_binding_invalid")
    locator = Path(discovered)
    try:
        if not locator.is_absolute():
            raise P6ProtocolError("review_binding_invalid")
        source = locator.resolve(strict=True)
        metadata = source.stat()
    except (OSError, P6ProtocolError):
        raise P6ProtocolError("review_binding_invalid") from None
    if not stat.S_ISREG(metadata.st_mode) or any(
        _path_is_within(source, root) for root in _untrusted_reviewer_roots()
    ):
        raise P6ProtocolError("review_binding_invalid")
    return source, _safe_executable_sha256(source)


def _reviewer_executable_is_launcher(source: Path) -> bool:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError:
        raise P6ProtocolError("review_binding_invalid") from None
    try:
        prefix = os.read(descriptor, 8)
    finally:
        os.close(descriptor)
    return prefix.startswith(b"#!") or source.suffix.lower() in {
        ".bat",
        ".cmd",
        ".cjs",
        ".js",
        ".mjs",
        ".ps1",
        ".py",
    }


def _snapshot_reviewer_executable(
    source: Path,
    *,
    expected_sha256: str,
    destination_root: Path,
) -> Path:
    """Copy one no-follow, digest-bound executable into the private run directory."""

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        if source.is_symlink():
            raise P6ProtocolError("review_binding_invalid")
        descriptor = os.open(source, flags)
    except (OSError, P6ProtocolError):
        raise P6ProtocolError("review_binding_invalid") from None
    destination: Optional[Path] = None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_size > _MAX_REVIEWER_EXECUTABLE_BYTES
            or (os.name != "nt" and before.st_mode & 0o111 == 0)
        ):
            raise P6ProtocolError("review_binding_invalid")
        if _reviewer_executable_is_launcher(source):
            # A copied launcher could execute mutable, unsnapshotted adjacent files.
            # Callers must instead use the explicitly labelled temporal launcher
            # mode, which revalidates the sealed-runner source around every call.
            raise P6ProtocolError("review_runtime_snapshot_unsupported")
        destination_root.mkdir(mode=0o700, parents=True, exist_ok=False)
        suffix = source.suffix if os.name == "nt" else ""
        destination = destination_root / f"reviewer-executable{suffix}"
        target_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        target_descriptor = os.open(destination, target_flags, 0o500)
        digest = hashlib.sha256()
        remaining = before.st_size
        try:
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise P6ProtocolError("review_binding_invalid")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(target_descriptor, view)
                    if written < 1:
                        raise P6ProtocolError("review_binding_invalid")
                    view = view[written:]
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise P6ProtocolError("review_binding_invalid")
            os.fsync(target_descriptor)
        finally:
            os.close(target_descriptor)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise P6ProtocolError("review_binding_invalid")
        observed_sha256 = digest.hexdigest()
        if observed_sha256 != expected_sha256:
            raise P6ProtocolError("review_binding_invalid")
    finally:
        os.close(descriptor)
    try:
        if destination is None:
            raise P6ProtocolError("review_binding_invalid")
        destination.chmod(0o500)
        if _safe_executable_sha256(destination) != expected_sha256:
            raise P6ProtocolError("review_binding_invalid")
    except (OSError, P6ProtocolError):
        raise P6ProtocolError("review_binding_invalid") from None
    return destination.resolve()


def _prepare_reviewer_executable(
    source: Path,
    *,
    expected_sha256: str,
    destination_root: Path,
) -> Tuple[Path, str, Optional[str]]:
    if _reviewer_executable_is_launcher(source):
        if _safe_executable_sha256(source) != expected_sha256:
            raise P6ProtocolError("review_binding_invalid")
        return source, _SEALED_RUNNER_TEMPORAL_LAUNCHER_IDENTITY, None
    snapshot = _snapshot_reviewer_executable(
        source,
        expected_sha256=expected_sha256,
        destination_root=destination_root,
    )
    snapshot_sha256 = _safe_executable_sha256(snapshot)
    if snapshot_sha256 != expected_sha256:
        raise P6ProtocolError("review_binding_invalid")
    return snapshot, _SEALED_RUNNER_TEMPORAL_IDENTITY, snapshot_sha256


def _run_bound_reviewer_process(
    command: Sequence[str],
    *,
    executable: Path,
    expected_sha256: str,
    transport_failure_class: str = "review_transport_failed",
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    if not command or command[0] != str(executable):
        raise P6ProtocolError("review_binding_invalid")
    if _safe_executable_sha256(executable) != expected_sha256:
        raise P6ProtocolError("review_binding_invalid")
    try:
        try:
            return subprocess.run(list(command), **kwargs)
        except (OSError, subprocess.SubprocessError, UnicodeError):
            # TimeoutExpired may retain captured provider output.  Never let the
            # exception body cross the protected reviewer boundary.
            raise P6ProtocolError(transport_failure_class) from None
    finally:
        if _safe_executable_sha256(executable) != expected_sha256:
            raise P6ProtocolError("review_binding_invalid")


def _probe_reviewer_version(
    role: str,
    *,
    executable: Path,
    executable_sha256: str,
    environment: Mapping[str, str],
) -> str:
    identity = FROZEN_REVIEWER_IDENTITIES[role]
    try:
        completed = _run_bound_reviewer_process(
            [str(executable), "--version"],
            executable=executable,
            expected_sha256=executable_sha256,
            transport_failure_class="review_runtime_snapshot_unsupported",
            env=dict(environment),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise P6ProtocolError("review_runtime_snapshot_unsupported") from None
    if completed.returncode != 0:
        raise P6ProtocolError("review_runtime_snapshot_unsupported")
    observed = completed.stdout.strip()
    expected = str(identity["harness_version"])
    valid = (
        observed
        == {
            "product_architecture": f"{expected} (Claude Code)",
            "proof_security": expected,
            "independent_benchmark": f"codex-cli {expected}",
        }[role]
    )
    if not valid:
        raise P6ProtocolError("review_binding_invalid")
    return expected


def run_reviewer(
    *,
    role: str,
    packet_path: Path,
    output_dir: Path,
    material_root: Optional[Path] = None,
    timeout_seconds: int = 43200,
) -> Mapping[str, Any]:
    if output_dir.exists() or output_dir.is_symlink():
        raise P6ProtocolError("P6 reviewer output directory already exists")
    packet = load_json_strict(packet_path)
    if not isinstance(packet, Mapping):
        raise P6ProtocolError("P6 review packet must be an object")
    validate_review_packet(packet, packet_root=packet_path.parent)
    if packet.get("role") != role:
        raise P6ProtocolError("P6 reviewer packet role mismatch")
    material_sha, material = _material_from_packet(packet, material_root=material_root)
    if material_root is None or not material:
        raise P6ProtocolError("review_binding_invalid")
    schema = _decision_schema(packet, role=role)
    prompt = _prompt(packet, role=role, material=material)
    prompt_sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    with tempfile.TemporaryDirectory(prefix=f"zscope-p6-{role}-") as raw_temp:
        temp_root = Path(raw_temp)
        env = _reviewer_environment(role, temp_root=temp_root / "reviewer-environment")
        credentials = _configured_role_credentials(role)
        route_config_sha = env["Z_SCOPE_P6_REVIEW_ROUTE_CONFIG_SHA256"]
        for credential in credentials:
            _assert_role_credential_absent(packet, credential=credential)
        executable_source, executable_sha = _resolve_reviewer_executable(
            role, search_path=env["PATH"]
        )
        executable, runtime_identity_contract, executable_snapshot_sha = (
            _prepare_reviewer_executable(
                executable_source,
                expected_sha256=executable_sha,
                destination_root=temp_root / "reviewer-executable",
            )
        )
        observed_version = _probe_reviewer_version(
            role,
            executable=executable,
            executable_sha256=executable_sha,
            environment=env,
        )
        (temp_root / "packet.json").write_bytes(packet_path.read_bytes())
        (temp_root / "decision-schema.json").write_text(
            json.dumps(schema, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (temp_root / "review-instructions.txt").write_text(prompt, encoding="utf-8")
        for private_file in (
            temp_root / "packet.json",
            temp_root / "decision-schema.json",
            temp_root / "review-instructions.txt",
        ):
            private_file.chmod(0o600)
        command, command_identity = _command_for_role(
            role,
            executable=executable,
            executable_sha256=executable_sha,
            temp_root=temp_root,
            schema=schema,
            prompt=prompt,
        )
        command_identity[0] = str(executable_source)
        command_identity.insert(2, f"<route-config-sha256:{route_config_sha}>")
        input_text = prompt if role in {"product_architecture", "independent_benchmark"} else None
        completed = _run_bound_reviewer_process(
            command,
            executable=executable,
            expected_sha256=executable_sha,
            input=input_text,
            cwd=temp_root,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            check=False,
            timeout=timeout_seconds,
        )
        transport_retry: Optional[Mapping[str, Any]] = None
        if completed.returncode != 0:
            transport_retry = {
                "initial_exit_code": completed.returncode,
                "initial_stdout_sha256": hashlib.sha256(
                    completed.stdout.encode("utf-8")
                ).hexdigest(),
                "initial_stderr_sha256": hashlib.sha256(
                    completed.stderr.encode("utf-8")
                ).hexdigest(),
            }
            completed = _run_bound_reviewer_process(
                command,
                executable=executable,
                expected_sha256=executable_sha,
                input=input_text,
                cwd=temp_root,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                check=False,
                timeout=timeout_seconds,
            )
        bounded_correction: List[Dict[str, Any]] = []
        correction_history: List[_CorrectionKind] = []
        pending_correction: Optional[Dict[str, Any]] = None
        accepted_prompt = prompt
        while completed.returncode == 0:
            candidate, failure = _classify_decision_output(
                completed.stdout, packet=packet, role=role
            )
            if pending_correction is not None:
                if candidate is None:
                    break
                pending_correction["result_decision_sha256"] = canonical_sha256(candidate)
                pending_locked_projection_sha = pending_correction["locked_projection_sha256"]
                pending_kind = _CorrectionKind(str(pending_correction["kind"]))
                if pending_locked_projection_sha is not None:
                    if pending_kind is _CorrectionKind.CONTRACT_REGENERATION:
                        mutable = pending_correction["mutable_material_fields"]
                        if not isinstance(mutable, list):
                            raise P6ProtocolError("review_binding_invalid")
                        observed_projection_sha = canonical_sha256(
                            _contract_locked_projection(candidate, mutable)
                        )
                    else:
                        observed_projection_sha = canonical_sha256(
                            _decision_substantive_projection(candidate)
                        )
                    if observed_projection_sha != pending_locked_projection_sha:
                        raise P6ProtocolError("P6 reviewer correction changed substantive fields")
                pending_correction = None
            if failure is None:
                break
            correction_kind = _next_correction_kind(correction_history, failure)
            if correction_kind is None:
                break
            mutable_material_fields: Optional[Tuple[str, ...]] = None
            locked_projection: Optional[Mapping[str, Any]] = None
            locked_projection_sha: Optional[str] = None
            if correction_kind is _CorrectionKind.CONTRACT_REGENERATION:
                if candidate is not None:
                    mutable_material_fields = _contract_mutable_material_fields(
                        candidate, role=role
                    )
                    if mutable_material_fields is None:
                        raise P6ProtocolError(
                            "P6 reviewer contract correction material surface is unbounded"
                        )
                    locked_projection = _contract_locked_projection(
                        candidate, mutable_material_fields
                    )
                    locked_projection_sha = canonical_sha256(locked_projection)
            else:
                if candidate is None:
                    raise P6ProtocolError("P6 reviewer correction state is invalid")
                locked_projection = _decision_substantive_projection(candidate)
                locked_projection_sha = canonical_sha256(locked_projection)
            feedback = _correction_feedback(
                correction_kind,
                parsed_object=candidate is not None,
                mutable_material_fields=mutable_material_fields,
            )
            correction_prompt = _correction_prompt(
                prompt,
                correction_kind,
                feedback=feedback,
                prior_decision=candidate,
            )
            (temp_root / "review-instructions.txt").write_text(correction_prompt, encoding="utf-8")
            (temp_root / "review-instructions.txt").chmod(0o600)
            correction_command, correction_identity = _command_for_role(
                role,
                executable=executable,
                executable_sha256=executable_sha,
                temp_root=temp_root,
                schema=schema,
                prompt=correction_prompt,
            )
            correction_identity[0] = str(executable_source)
            correction_identity.insert(2, f"<route-config-sha256:{route_config_sha}>")
            if correction_identity != command_identity:
                raise P6ProtocolError("review_binding_invalid")
            correction_prompt_sha = hashlib.sha256(correction_prompt.encode("utf-8")).hexdigest()
            correction_record: Dict[str, Any] = {
                "kind": correction_kind.value,
                "initial_exit_code": completed.returncode,
                "initial_stdout_sha256": hashlib.sha256(
                    completed.stdout.encode("utf-8")
                ).hexdigest(),
                "initial_stderr_sha256": hashlib.sha256(
                    completed.stderr.encode("utf-8")
                ).hexdigest(),
                "validation_feedback_sha256": canonical_sha256(feedback),
                "prior_decision_sha256": (
                    canonical_sha256(candidate) if candidate is not None else None
                ),
                "result_decision_sha256": None,
                "correction_prompt_sha256": correction_prompt_sha,
                "correction_input_sha256": correction_prompt_sha,
                "command_identity": correction_identity,
                "mutable_material_fields": (
                    list(mutable_material_fields) if mutable_material_fields is not None else None
                ),
                "locked_projection": locked_projection,
                "locked_projection_sha256": locked_projection_sha,
            }
            bounded_correction.append(correction_record)
            pending_correction = correction_record
            correction_history.append(correction_kind)
            accepted_prompt = correction_prompt
            correction_input = (
                correction_prompt
                if role in {"product_architecture", "independent_benchmark"}
                else None
            )
            completed = _run_bound_reviewer_process(
                correction_command,
                executable=executable,
                expected_sha256=executable_sha,
                input=correction_input,
                cwd=temp_root,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                check=False,
                timeout=timeout_seconds,
            )
        reviewer_stdout_sha = hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest()
        stderr_sha = hashlib.sha256(completed.stderr.encode("utf-8")).hexdigest()
        if completed.returncode != 0:
            raise P6ProtocolError(
                "P6 reviewer transport failed after one bounded retry; "
                f"class=review_transport_failed; count={2 if transport_retry else 1}"
            )
        decision = decision_from_stdout(completed.stdout, role=role)
        validate_review_decision(decision, packet=packet, role=role)
        for credential in credentials:
            _assert_role_credential_absent(decision, credential=credential)
        decision_sha = canonical_sha256(decision)
        decision_stdout = json.dumps(
            decision,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        stdout_sha = hashlib.sha256(decision_stdout.encode("utf-8")).hexdigest()
        raw: Dict[str, Any] = {
            "schema_version": P6_REVIEW_RAW_SCHEMA_VERSION,
            "packet_uid": packet["packet_uid"],
            "packet_sha256": packet["packet_sha256"],
            "role": role,
            "reviewer_identity_sha256": reviewer_identity_sha256(role),
            "runtime_identity_contract": runtime_identity_contract,
            "executable_path": str(executable_source),
            "executable_sha256": executable_sha,
            "executable_snapshot_sha256": executable_snapshot_sha,
            "harness_version_observed": observed_version,
            "command_identity": command_identity,
            "exit_code": completed.returncode,
            "stdout": decision_stdout,
            "stdout_sha256": stdout_sha,
            "reviewer_stdout_sha256": reviewer_stdout_sha,
            "stderr_sha256": stderr_sha,
            "transport_retry": transport_retry,
            "bounded_correction": bounded_correction or None,
            "initial_prompt_sha256": prompt_sha,
            "accepted_prompt_sha256": hashlib.sha256(accepted_prompt.encode("utf-8")).hexdigest(),
            "material_root_sha256": material_sha,
            "decision_sha256": decision_sha,
        }
        for credential in credentials:
            _assert_role_credential_absent(raw, credential=credential)
    output_dir.mkdir(parents=True)
    write_json_exclusive(output_dir / "decision.json", decision)
    write_json_exclusive(output_dir / "raw-envelope.json", raw)
    validate_review_artifact(
        output_dir=output_dir,
        packet_path=packet_path,
        role=role,
        material_root=material_root,
    )
    return decision


def _expected_command_identity(
    role: str, raw: Mapping[str, Any], *, packet: Mapping[str, Any]
) -> bool:
    values = raw.get("command_identity")
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        return False
    executable_path = raw.get("executable_path")
    executable_sha = raw.get("executable_sha256")
    snapshot_sha = raw.get("executable_snapshot_sha256")
    runtime_contract = raw.get("runtime_identity_contract")
    runtime_binding_valid = (
        runtime_contract == _SEALED_RUNNER_TEMPORAL_IDENTITY and snapshot_sha == executable_sha
    ) or (runtime_contract == _SEALED_RUNNER_TEMPORAL_LAUNCHER_IDENTITY and snapshot_sha is None)
    if (
        not isinstance(executable_path, str)
        or not Path(executable_path).is_absolute()
        or any(_path_is_within(Path(executable_path), root) for root in _untrusted_reviewer_roots())
        or re.fullmatch(r"[0-9a-f]{64}", str(executable_sha)) is None
        or not runtime_binding_valid
        or values[:2] != [executable_path, f"<binary-sha256:{executable_sha}>"]
        or len(values) < 3
        or re.fullmatch(r"<route-config-sha256:[0-9a-f]{64}>", values[2]) is None
    ):
        return False
    route_sha = values[2][len("<route-config-sha256:") : -1]
    if role == "independent_benchmark" and route_sha != _CODEX_EXPLICIT_ROUTE_SHA256:
        return False
    configured = _REVIEWER_ROUTE_CONFIG_ENV.get(role)
    if configured is not None:
        expected_route_sha = os.environ.get(configured[1], "")
        if expected_route_sha and route_sha != expected_route_sha:
            return False
    if role == "product_architecture":
        return values[3:] == _claude_arguments(_decision_schema(packet, role=role))
    if role == "proof_security":
        expected_hash = hashlib.sha256(_deepseek_patch_text().encode("utf-8")).hexdigest()
        return values == [
            executable_path,
            f"<binary-sha256:{executable_sha}>",
            f"<route-config-sha256:{route_sha}>",
            "--profile",
            "headless",
            "--patch",
            f"<ephemeral-patch-sha256:{expected_hash}>",
            "<isolated-instruction-sha256:"
            + hashlib.sha256(_deepseek_instruction().encode("utf-8")).hexdigest()
            + ">",
        ]
    return values[3:] == _codex_arguments()


def validate_review_artifact(
    *,
    output_dir: Path,
    packet_path: Path,
    role: str,
    material_root: Optional[Path] = None,
) -> None:
    packet = load_json_strict(packet_path)
    decision = load_json_strict(output_dir / "decision.json")
    raw = load_json_strict(output_dir / "raw-envelope.json")
    if (
        not isinstance(packet, Mapping)
        or not isinstance(decision, Mapping)
        or not isinstance(raw, Mapping)
    ):
        raise P6ProtocolError("P6 review artifact objects are invalid")
    credential = _configured_role_credential(role)
    if credential is not None:
        for persisted in (packet, decision, raw):
            _assert_role_credential_absent(persisted, credential=credential)
    validate_review_packet(packet, packet_root=packet_path.parent)
    validate_review_decision(decision, packet=packet, role=role)
    _expect_fields(raw, _RAW_FIELDS, "P6 raw review envelope")
    if raw.get("schema_version") != P6_REVIEW_RAW_SCHEMA_VERSION:
        raise P6ProtocolError("P6 raw review envelope schema is invalid")
    expected_bindings = {
        "packet_uid": packet["packet_uid"],
        "packet_sha256": packet["packet_sha256"],
        "role": role,
        "reviewer_identity_sha256": reviewer_identity_sha256(role),
        "harness_version_observed": FROZEN_REVIEWER_IDENTITIES[role]["harness_version"],
        "exit_code": 0,
        "decision_sha256": canonical_sha256(decision),
    }
    if any(raw.get(key) != value for key, value in expected_bindings.items()):
        raise P6ProtocolError("P6 raw review envelope binding is invalid")
    executable_path = raw.get("executable_path")
    if not isinstance(executable_path, str) or not Path(executable_path).is_absolute():
        raise P6ProtocolError("P6 reviewer executable path binding is invalid")
    executable_sha = _expect_sha256(raw.get("executable_sha256"), "P6 reviewer executable")
    runtime_contract = raw.get("runtime_identity_contract")
    snapshot_value = raw.get("executable_snapshot_sha256")
    if runtime_contract == _SEALED_RUNNER_TEMPORAL_IDENTITY:
        snapshot_binding_valid = (
            _expect_sha256(snapshot_value, "P6 reviewer executable snapshot") == executable_sha
        )
    elif runtime_contract == _SEALED_RUNNER_TEMPORAL_LAUNCHER_IDENTITY:
        snapshot_binding_valid = snapshot_value is None
    else:
        snapshot_binding_valid = False
    if not snapshot_binding_valid:
        raise P6ProtocolError("P6 reviewer executable snapshot binding is invalid")
    stdout = raw.get("stdout")
    if not isinstance(stdout, str):
        raise P6ProtocolError("P6 raw review stdout is invalid")
    if hashlib.sha256(stdout.encode("utf-8")).hexdigest() != raw.get("stdout_sha256"):
        raise P6ProtocolError("P6 raw review stdout hash is invalid")
    _expect_sha256(raw.get("reviewer_stdout_sha256"), "P6 reviewer transport stdout hash")
    parsed = decision_from_stdout(stdout, role=role)
    if parsed != decision:
        raise P6ProtocolError("P6 raw review output and decision differ")
    _expect_sha256(raw.get("stderr_sha256"), "P6 reviewer stderr hash")
    configured_material_root = os.environ.get("P6_CANDIDATE_ROOT")
    candidate_root = (
        material_root
        or (Path(configured_material_root) if configured_material_root else Path.cwd())
    ).resolve()
    material_root_sha, material = _material_from_packet(packet, material_root=candidate_root)
    if raw.get("material_root_sha256") != material_root_sha:
        raise P6ProtocolError("P6 reviewer material root binding is invalid")
    initial_prompt = _prompt(packet, role=role, material=material)
    initial_prompt_sha = hashlib.sha256(initial_prompt.encode("utf-8")).hexdigest()
    if raw.get("initial_prompt_sha256") != initial_prompt_sha:
        raise P6ProtocolError("P6 reviewer initial prompt binding is invalid")
    retry = raw.get("transport_retry")
    if retry is not None:
        if not isinstance(retry, Mapping) or set(retry) != {
            "initial_exit_code",
            "initial_stdout_sha256",
            "initial_stderr_sha256",
        }:
            raise P6ProtocolError("P6 reviewer transport retry record is invalid")
        if (
            isinstance(retry.get("initial_exit_code"), bool)
            or not isinstance(retry.get("initial_exit_code"), int)
            or retry.get("initial_exit_code") == 0
        ):
            raise P6ProtocolError("P6 reviewer retry did not follow a transport failure")
        _expect_sha256(retry.get("initial_stdout_sha256"), "initial reviewer stdout hash")
        _expect_sha256(retry.get("initial_stderr_sha256"), "initial reviewer stderr hash")
    correction = raw.get("bounded_correction")
    if correction is not None:
        if not isinstance(correction, list) or not (1 <= len(correction) <= 2):
            raise P6ProtocolError("P6 reviewer bounded correction record is invalid")
        kind_values = tuple(
            row.get("kind") if isinstance(row, Mapping) else None for row in correction
        )
        valid_sequences = {
            (_CorrectionKind.CONTRACT_REGENERATION.value,),
            (_CorrectionKind.GROUNDING_CORRECTION.value,),
            (
                _CorrectionKind.CONTRACT_REGENERATION.value,
                _CorrectionKind.GROUNDING_CORRECTION.value,
            ),
        }
        if kind_values not in valid_sequences:
            raise P6ProtocolError("P6 reviewer bounded correction order is invalid")
        previous_result_sha: Optional[str] = None
        for index, row in enumerate(correction):
            if not isinstance(row, Mapping) or set(row) != {
                "kind",
                "initial_exit_code",
                "initial_stdout_sha256",
                "initial_stderr_sha256",
                "validation_feedback_sha256",
                "prior_decision_sha256",
                "result_decision_sha256",
                "correction_prompt_sha256",
                "correction_input_sha256",
                "command_identity",
                "mutable_material_fields",
                "locked_projection",
                "locked_projection_sha256",
            }:
                raise P6ProtocolError("P6 reviewer bounded correction record is invalid")
            kind = _CorrectionKind(str(row.get("kind")))
            if row.get("initial_exit_code") != 0:
                raise P6ProtocolError("P6 reviewer correction did not follow a contract output")
            _expect_sha256(row.get("initial_stdout_sha256"), "initial decision stdout hash")
            _expect_sha256(row.get("initial_stderr_sha256"), "initial decision stderr hash")
            feedback_sha = _expect_sha256(
                row.get("validation_feedback_sha256"), "correction validation feedback"
            )
            prompt_sha = _expect_sha256(
                row.get("correction_prompt_sha256"), "reviewer correction prompt"
            )
            if row.get("correction_input_sha256") != prompt_sha:
                raise P6ProtocolError("P6 reviewer correction prompt binding is invalid")
            if row.get("command_identity") != raw.get("command_identity"):
                raise P6ProtocolError("P6 reviewer correction command identity is invalid")
            prior_sha = row.get("prior_decision_sha256")
            if prior_sha is not None:
                _expect_sha256(prior_sha, "prior reviewer decision")
            if index > 0 and prior_sha != previous_result_sha:
                raise P6ProtocolError("P6 reviewer correction decision chain is invalid")
            result_sha = _expect_sha256(
                row.get("result_decision_sha256"), "corrected reviewer decision"
            )
            previous_result_sha = result_sha
            mutable = row.get("mutable_material_fields")
            locked_projection = row.get("locked_projection")
            locked = row.get("locked_projection_sha256")
            if kind is _CorrectionKind.CONTRACT_REGENERATION:
                if prior_sha is None:
                    if mutable is not None or locked_projection is not None or locked is not None:
                        raise P6ProtocolError("P6 reviewer contract correction lock is invalid")
                else:
                    if (
                        not isinstance(mutable, list)
                        or not all(isinstance(field, str) for field in mutable)
                        or mutable != sorted(set(mutable))
                        or not set(mutable).issubset(_MATERIAL_DECISION_FIELDS)
                        or set(mutable) == _MATERIAL_DECISION_FIELDS
                    ):
                        raise P6ProtocolError(
                            "P6 reviewer contract correction allowlist is invalid"
                        )
                    locked_sha = _expect_sha256(locked, "locked reviewer contract projection hash")
                    if not isinstance(locked_projection, Mapping):
                        raise P6ProtocolError(
                            "P6 reviewer contract correction projection is invalid"
                        )
                    expected_projection = _contract_locked_projection(decision, mutable)
                    if (
                        locked_sha != canonical_sha256(locked_projection)
                        or locked_projection != expected_projection
                    ):
                        raise P6ProtocolError(
                            "P6 reviewer contract correction changed substantive fields"
                        )
            else:
                if prior_sha is None or mutable is not None:
                    raise P6ProtocolError("P6 reviewer grounding correction lock is invalid")
                locked_sha = _expect_sha256(locked, "locked reviewer projection hash")
                if not isinstance(locked_projection, Mapping):
                    raise P6ProtocolError("P6 reviewer grounding projection is invalid")
                expected_projection = _decision_substantive_projection(decision)
                if (
                    locked_sha != canonical_sha256(locked_projection)
                    or locked_projection != expected_projection
                ):
                    raise P6ProtocolError(
                        "P6 reviewer grounding correction changed substantive fields"
                    )
            expected_feedback = _correction_feedback(
                kind,
                parsed_object=prior_sha is not None,
                mutable_material_fields=mutable if isinstance(mutable, list) else None,
            )
            if feedback_sha != canonical_sha256(expected_feedback):
                raise P6ProtocolError("P6 reviewer correction feedback binding is invalid")
        if previous_result_sha != canonical_sha256(decision):
            raise P6ProtocolError("P6 reviewer correction decision chain is invalid")
    accepted_prompt_sha = (
        correction[-1]["correction_prompt_sha256"]
        if isinstance(correction, list) and correction
        else initial_prompt_sha
    )
    if raw.get("accepted_prompt_sha256") != accepted_prompt_sha:
        raise P6ProtocolError("P6 reviewer accepted prompt binding is invalid")
    if not _expected_command_identity(role, raw, packet=packet):
        raise P6ProtocolError("P6 reviewer command identity is invalid")


def aggregate_review_set(
    *, packet_paths: Mapping[str, Path], output_dirs: Mapping[str, Path]
) -> Mapping[str, Any]:
    if set(packet_paths) != set(REVIEW_ROLES) or set(output_dirs) != set(REVIEW_ROLES):
        raise P6ProtocolError("P6 review set requires all three frozen roles")
    records: List[Mapping[str, Any]] = []
    common: set[Tuple[str, str]] = set()
    for role in REVIEW_ROLES:
        validate_review_artifact(
            output_dir=output_dirs[role], packet_path=packet_paths[role], role=role
        )
        packet = load_json_strict(packet_paths[role])
        decision = load_json_strict(output_dirs[role] / "decision.json")
        assert isinstance(packet, Mapping) and isinstance(decision, Mapping)
        if decision.get("decision") != "approved" or decision.get("blocker_count") != 0:
            raise P6ProtocolError("P6 completion requires three approved zero-blocker reviews")
        common.add(
            (
                str(packet["qualification_sha256"]),
                str(packet["evidence_root_sha256"]),
            )
        )
        records.append(
            {
                "role": role,
                "packet_sha256": packet["packet_sha256"],
                "decision_sha256": canonical_sha256(decision),
                "raw_envelope_sha256": sha256_file(output_dirs[role] / "raw-envelope.json"),
                "reviewer_identity_sha256": reviewer_identity_sha256(role),
                "decision": "approved",
                "blocker_count": 0,
            }
        )
    if len(common) != 1:
        raise P6ProtocolError("P6 reviews do not bind one qualification and evidence root")
    qualification_sha, evidence_root_sha = next(iter(common))
    return {
        "schema_version": P6_REVIEW_SET_SCHEMA_VERSION,
        "qualification_sha256": qualification_sha,
        "evidence_root_sha256": evidence_root_sha,
        "reviews": records,
        "approved_count": 3,
        "blocker_count": 0,
        "formal_evidence": False,
        "release_eligible": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m zscope.benchmarking.p6_review")
    commands = parser.add_subparsers(dest="command", required=True)
    project = commands.add_parser("project-role-evidence")
    project.add_argument("--qualification", required=True, type=Path)
    project.add_argument("--role", choices=REVIEW_ROLES, required=True)
    project.add_argument("--output", required=True, type=Path)
    material = commands.add_parser("build-review-material")
    material.add_argument("--candidate-root", required=True, type=Path)
    material.add_argument("--role", choices=REVIEW_ROLES, required=True)
    material.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "project-role-evidence":
            qualification = load_json_strict(args.qualification.resolve())
            if not isinstance(qualification, Mapping):
                raise P6ProtocolError("P6 qualification must be an object")
            projection = project_role_evidence(qualification, role=args.role)
            output_hash = str(projection["role_evidence_sha256"])
        else:
            projection = build_review_material_manifest(
                candidate_root=args.candidate_root.resolve(), role=args.role
            )
            output_hash = str(projection["material_root_sha256"])
        write_json_exclusive(args.output.resolve(), projection)
    except P6ProtocolError:
        print("stage=independent_review; class=review_binding_invalid:1; count=1")
        return 2
    print(output_hash)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BLOCKER_CODES",
    "FROZEN_REVIEWER_IDENTITIES",
    "P6_REVIEW_DECISION_SCHEMA_VERSION",
    "P6_REVIEW_PACKET_SCHEMA_VERSION",
    "P6_REVIEW_RAW_SCHEMA_VERSION",
    "P6_REVIEW_SET_SCHEMA_VERSION",
    "REVIEW_ROLES",
    "ROLE_CHECKS",
    "ROLE_REVIEW_MATERIAL_PATHS",
    "aggregate_review_set",
    "build_review_material_manifest",
    "build_review_packet",
    "decision_from_stdout",
    "finalize_review_packet",
    "load_reviewer_identity_manifest",
    "project_role_evidence",
    "reviewer_identity_sha256",
    "run_reviewer",
    "validate_review_artifact",
    "validate_review_decision",
    "validate_review_packet",
]
