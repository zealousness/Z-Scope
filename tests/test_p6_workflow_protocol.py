from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest
import yaml

from scripts.validate_p6_artifact_tree import (
    P6ArtifactTreeError,
    discover_regular_files,
    revalidate_regular_file,
)
from scripts.project_p6_entry_lineage import project_gate_lineage
from scripts import run_p6_cold_producer
from zscope.benchmarking.runner import BenchmarkError
from zscope.benchmarking.p6_producer_sandbox import (
    materialize_p6_host_producer_sandbox,
    p6_host_producer_child_environment,
)
from zscope.benchmarking.p6_protocol import (
    P6ProtocolError,
    canonical_sha256,
    load_json_strict,
    sha256_file,
)


WORKFLOW = Path(".github/workflows/p6-pilot-validation.yml")
RECOVERY_WORKFLOW = Path(".github/workflows/p6-pilot-finalize-recovery.yml")
SANITIZER_ACTION = Path(".github/actions/validate-p6-artifact/action.yml")
ENTRY_GATE = Path("docs/design/zscope-2.0-security-architecture/acceptance/p6-entry-gate.json")


class _DuplicateRejectingLoader(yaml.BaseLoader):
    pass


def _construct_unique_mapping(
    loader: yaml.Loader, node: yaml.MappingNode, deep: bool = False
) -> dict:
    result: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise AssertionError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_DuplicateRejectingLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _workflow() -> tuple[str, dict]:
    text = WORKFLOW.read_text(encoding="utf-8")
    value = yaml.load(text, Loader=_DuplicateRejectingLoader)
    assert isinstance(value, dict)
    return text, value


def test_dispatcher_binds_control_candidate_and_exact_local_wsl_evidence() -> None:
    text, workflow = _workflow()

    assert set(workflow["on"]["workflow_dispatch"]["inputs"]) == {
        "control_plane_commit",
        "candidate_sha",
        "local_evidence_commit",
        "local_evidence_receipt_sha256",
    }
    assert all(
        value["required"] == "true"
        for value in workflow["on"]["workflow_dispatch"]["inputs"].values()
    )
    assert "P6_CONTROL_PLANE_COMMIT: ${{ inputs.control_plane_commit }}" in text
    assert "P6_CANDIDATE_COMMIT: ${{ inputs.candidate_sha }}" in text
    assert "P6_LOCAL_EVIDENCE_COMMIT: ${{ inputs.local_evidence_commit }}" in text
    assert (
        "P6_LOCAL_EVIDENCE_RECEIPT_SHA256: " "${{ inputs.local_evidence_receipt_sha256 }}" in text
    )
    assert "P6_LOCAL_EVIDENCE_ROOT: " ".github/evidence/p6/local-balanced-evidence" in text
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            assert "${{ inputs." not in step.get("run", "")
    for name in (
        "Z_SCOPE_P6_FROZEN_TRACE_ROOT",
        "Z_SCOPE_P6_FROZEN_TRACE_MANIFEST_SHA256",
        "Z_SCOPE_P6_CANARY_SOURCE_ROOT",
        "Z_SCOPE_P6_CANARY_SOURCE_TREE_SHA256",
        "Z_SCOPE_P6_QUALIFICATION_HARNESS",
        "Z_SCOPE_P6_QUALIFICATION_HARNESS_SHA256",
        "Z_SCOPE_P6_HIDDEN_HOLDOUT_BUNDLE",
        "Z_SCOPE_P6_HIDDEN_HOLDOUT_BUNDLE_SHA256",
        "Z_SCOPE_P6_SAFE_PAIR_BUNDLE",
        "Z_SCOPE_P6_SAFE_PAIR_BUNDLE_SHA256",
    ):
        assert name in text
        assert f"inputs.{name.lower()}" not in text


def test_entry_fails_closed_before_provider_work_without_complete_local_wsl_bundle() -> None:
    _, workflow = _workflow()
    entry_steps = workflow["jobs"]["entry"]["steps"]
    evidence = next(
        step
        for step in entry_steps
        if step.get("name")
        == "Require immutable passed local WSL balanced evidence before provider work"
    )
    evidence_index = entry_steps.index(evidence)
    successor_projection = next(
        step
        for step in entry_steps
        if step.get("name") == "Validate resource-backed current-successor review projection"
    )
    projection_index = entry_steps.index(successor_projection)
    secret_index = next(
        index
        for index, step in enumerate(entry_steps)
        if step.get("name")
        == "Verify runner-owned secret and frozen-input authority before any model call"
    )
    cleanup_index = next(
        index
        for index, step in enumerate(entry_steps)
        if step.get("name") == "Remove exact-label stale P6 scanners before any secret is loaded"
    )
    assert projection_index < evidence_index < cleanup_index < secret_index
    assert "scripts/project_successor_review_evidence.py check" in successor_projection["run"]
    assert "--repository-root . --head HEAD" in successor_projection["run"]

    script = evidence["run"]
    for exact_binding in (
        "scripts/p6_balanced_orchestrator.py verify-local-evidence",
        '--hosted-control-plane-commit "$P6_CONTROL_PLANE_COMMIT"',
        '--evidence-commit "$P6_LOCAL_EVIDENCE_COMMIT"',
        '--receipt-sha256 "$P6_LOCAL_EVIDENCE_RECEIPT_SHA256"',
        'test "$P6_CANDIDATE_COMMIT" = "$P6_CONTROL_PLANE_COMMIT"',
    ):
        assert exact_binding in script
    assert "local-balanced-quality-gate.json" not in script
    assert "input_binding_failure" in script
    assert "|| true" not in script
    assert "continue-on-error" not in evidence

    seal = next(
        step for step in entry_steps if step.get("name") == "Seal answer-free entry evidence"
    )["run"]
    assert "import hashlib" in seal
    assert "hashlib.sha256(candidate.encode" in seal

    identities = entry_steps[0]["run"]
    assert '[[ "$P6_LOCAL_EVIDENCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]' in identities
    assert '[[ "$P6_LOCAL_EVIDENCE_RECEIPT_SHA256" =~ ^[0-9a-f]{64}$ ]]' in identities
    for job_name in (
        "provider_probe",
        "anonymous_qualification",
        "safe_pair_validation",
        "evidence_action_canary",
        "cold_fast",
        "cold_balanced",
        "cold_deep",
        "product_architecture_review",
        "proof_security_review",
        "independent_benchmark_review",
    ):
        pending = [job_name]
        seen: set[str] = set()
        while pending:
            current = pending.pop()
            if current == "entry":
                break
            if current in seen:
                continue
            seen.add(current)
            needs = workflow["jobs"][current].get("needs", [])
            pending.extend(needs if isinstance(needs, list) else [needs])
        else:
            raise AssertionError(f"{job_name} can run without the local evidence entry gate")


def test_workflow_is_one_sequential_non_release_pilot() -> None:
    _, workflow = _workflow()
    jobs = workflow["jobs"]

    assert workflow["concurrency"] == {
        "group": "p6-pilot-validation",
        "cancel-in-progress": "false",
    }
    assert workflow["env"]["P6_MAX_CONCURRENT_CALLS"] == "8"
    assert workflow["env"]["Z_SCOPE_BENCHMARK_OCI_RUNTIME"] == "podman"
    expected_needs = {
        "toolchain_oci": {"entry"},
        "provider_probe": {"entry", "toolchain_oci"},
        "policy_replay": {"provider_probe"},
        "certificate_reverify": {"policy_replay"},
        "anonymous_qualification": {"certificate_reverify", "toolchain_oci"},
        "safe_pair_validation": {"anonymous_qualification", "toolchain_oci"},
        "evidence_action_canary": {"safe_pair_validation", "toolchain_oci"},
        "offline_qualification": {
            "toolchain_oci",
            "policy_replay",
            "certificate_reverify",
            "anonymous_qualification",
            "safe_pair_validation",
            "evidence_action_canary",
        },
        "cold_fast": {"offline_qualification", "toolchain_oci"},
        "cold_balanced": {"cold_fast", "toolchain_oci"},
        "balanced_quality_gate": {"cold_balanced"},
        "cold_deep": {"balanced_quality_gate", "toolchain_oci"},
        "product_architecture_review": {
            "qualification_seal",
            "balanced_quality_gate",
            "entry",
            "toolchain_oci",
        },
        "proof_security_review": {
            "product_architecture_review",
            "qualification_seal",
            "balanced_quality_gate",
            "entry",
            "toolchain_oci",
        },
        "independent_benchmark_review": {
            "proof_security_review",
            "qualification_seal",
            "balanced_quality_gate",
            "entry",
            "toolchain_oci",
        },
        "finalize": {"final_evidence_seal"},
    }
    for job, dependency in expected_needs.items():
        actual = jobs[job]["needs"]
        assert set(actual if isinstance(actual, list) else [actual]) == dependency
    for job in ("cold_fast", "cold_balanced", "cold_deep"):
        assert jobs[job]["timeout-minutes"] == "720"
    assert jobs["policy_replay"]["timeout-minutes"] == "30"
    assert jobs["certificate_reverify"]["timeout-minutes"] == "30"
    assert jobs["offline_qualification"]["timeout-minutes"] == "30"
    assert jobs["balanced_quality_gate"]["timeout-minutes"] == "30"
    for job in (
        "anonymous_qualification",
        "safe_pair_validation",
        "evidence_action_canary",
    ):
        assert jobs[job]["timeout-minutes"] == "180"
    for job in (
        "product_architecture_review",
        "proof_security_review",
        "independent_benchmark_review",
    ):
        assert jobs[job]["timeout-minutes"] == "720"
    assert all(job["environment"] == "sealed-benchmark" for job in jobs.values())


def test_every_job_binds_hash_locked_python_to_current_checkout() -> None:
    _, workflow = _workflow()

    for name, job in workflow["jobs"].items():
        checkout = [step for step in job["steps"] if step.get("uses") == "actions/checkout@v7"]
        expected_paths = {"control"} if name == "cleanup_p6_oci" else {"control", "candidate"}
        assert {step["with"]["path"] for step in checkout} == expected_paths, name
        assert all(step["with"]["persist-credentials"] == "false" for step in checkout)
        setup_steps = [
            step
            for step in job["steps"]
            if step.get("uses") == "./control/.github/actions/setup-p6-python"
        ]
        assert len(setup_steps) == 1, name
        assert setup_steps[0]["with"]["checkout-path"] == "control"
        assert "install-project" not in setup_steps[0]["with"]
    assert workflow["defaults"]["run"]["working-directory"] == "control"
    assert workflow["env"]["PYTHONPATH"] == "${{ github.workspace }}/control"
    assert "candidate" not in workflow["env"]["PYTHONPATH"]
    setup = Path(".github/actions/setup-p6-python/action.yml").read_text(encoding="utf-8")
    assert "--require-hashes" in setup
    assert "requirements/constraints/py313.txt" in setup
    assert "--no-deps" not in setup and "--no-build-isolation" not in setup
    assert "P6_SETUP_CHECKOUT_ROOT" in setup
    assert 'PYTHONPATH="$checkout_root"' in setup
    assert "zscope.__file__" in setup
    assert "-e ." not in setup
    assert "steps.setup-python.outputs.python-path" in setup
    assert "RUNNER_TOOL_CACHE" in setup
    assert "LD_LIBRARY_PATH" in setup
    assert "libpython3.13.so.1.0" in setup


def test_workflow_runs_real_frozen_qualification_and_candidate_bound_cold_scans() -> None:
    text, _ = _workflow()

    for command in (
        "scripts/reverify_v3_trace.py",
        "scripts/run_p6_policy_replay.py",
        "scripts/prepare_v3_action_canary.py",
        '"evidence-action-canary"',
        '"hidden-holdout"',
        '"safe-pair-dual-scan"',
        "RootlessOciExecutor",
        "executor.preflight()",
        "executor.execute_phase(",
        "cc -std=c11 -Werror -Wall -Wextra -c",
    ):
        assert command in text
    assert text.count("scripts/run_p6_cold_producer.py --scan-depth") == 3
    for depth in ("fast", "balanced", "deep"):
        # One producer invocation plus the deterministic projection binding.
        assert text.count(f"--scan-depth {depth}") == 2
        assert text.count(f"p6-cold-{depth}-failure.json") == 2
    assert text.count('"--workers",') == 3
    assert text.count('"--provider-model", "deepseek-v4-flash"') == 3
    assert text.count('--expected-git-sha "$P6_CANDIDATE_COMMIT"') == 3
    assert text.count("--expected-git-tree") == 3
    assert "prepare_p6_runtime_source(" in text
    assert 'git_revision=os.environ["P6_CANDIDATE_COMMIT"]' in text
    assert "runtime_source=runtime_source" in text
    assert '"runtime_source_mounted": execution["runtime_source_mounted"] is True' in text
    assert "provider_credentials=False" in text
    assert '"schema_version": "zscope.oci-phase-log.v1"' in text
    assert '"stdout_persisted": False' in text
    assert '"stderr_persisted": False' in text
    assert "expected_probe" not in text
    assert text.count("--toolchain-evidence restored/toolchain/toolchain-evidence.json") == 9
    assert "provider_response_model_coverage" not in text or "seal-qualification" in text


def test_balanced_quality_scoring_is_post_freeze_truth_isolated_and_hard_gated() -> None:
    _, workflow = _workflow()
    balanced = workflow["jobs"]["cold_balanced"]
    quality = workflow["jobs"]["balanced_quality_gate"]

    balanced_script = "\n".join(step.get("run", "") for step in balanced["steps"])
    quality_script = "\n".join(step.get("run", "") for step in quality["steps"])
    assert "scripts/p6_balanced_orchestrator.py freeze" in balanced_script
    assert "--aggregate p6-balanced/aggregate.json" in balanced_script
    assert "--producer-metrics p6-balanced/run-01/producer-metrics.json" in balanced_script
    assert "--output p6-balanced-frozen" in balanced_script
    assert "python3 - <<'PY'" not in balanced_script
    assert "score_range_v5.py" not in balanced_script
    assert "Z_SCOPE_BENCHMARK_TRUTH" not in balanced_script
    assert "score.json" not in balanced_script
    assert "scripts/run_p6_cold_producer.py --scan-depth balanced" in balanced_script
    assert "Checkout candidate as untrusted read-only input" == balanced["steps"][1]["name"]

    assert quality["needs"] == ["cold_balanced"]
    assert quality["steps"][0]["name"] == "Checkout immutable control plane"
    assert quality["steps"][1]["name"] == "Checkout candidate as untrusted read-only input"
    assert "--producer-job 'one isolated cold balanced pilot'" in quality_script
    assert '--artifact-id "$BALANCED_ID"' in quality_script
    assert '--artifact-digest "sha256:$BALANCED_DIGEST"' in quality_script
    assert "scripts/p6_balanced_orchestrator.py score" in quality_script
    assert "--output quality-candidate" in quality_script
    assert "scripts/p6_balanced_orchestrator.py revalidate" in quality_script
    assert "--restored-bundle quality-candidate" in quality_script
    assert "--receipt quality-revalidation-receipt.json" in quality_script
    assert "--frozen-root restored/balanced/p6-balanced-frozen" in quality_script
    assert "--legacy-truth test/range/benchmark/ground_truth.json" in quality_script
    assert "--v16-truth test/range/benchmark/v16/ground_truth.json" in quality_script
    assert "zscope.cli.benchmark _score" not in quality_script
    assert "scripts/score_range_v5.py score" not in quality_script
    assert "python3 - <<'PY'" not in quality_script
    assert "scripts/p6_balanced_quality_gate.py" not in quality_script
    assert "--producer-projection restored/balanced/p6-balanced-projection.json" in (quality_script)
    assert "quality_no_progress_gate_failed" in quality_script
    assert "run_p6_cold_producer.py" not in quality_script

    upload = next(step for step in quality["steps"] if step.get("id") == "upload")
    assert upload["with"]["path"].splitlines() == [
        "control/quality",
        "control/quality-revalidation-receipt.json",
    ]
    assert workflow["jobs"]["cold_deep"]["needs"] == [
        "balanced_quality_gate",
        "toolchain_oci",
    ]

    benchmark_steps = workflow["jobs"]["independent_benchmark_review"]["steps"]
    benchmark_review = "\n".join(step.get("run", "") for step in benchmark_steps)
    benchmark_packet = next(
        step["run"]
        for step in benchmark_steps
        if step.get("name") == "Build the independent-benchmark packet without reviewer credentials"
    )
    assert "build-common-evidence" in benchmark_review
    assert "evidence/common-review-evidence.json" in benchmark_packet
    assert "evidence/p6-balanced-quality-gate.json" in benchmark_review
    assert "evidence/p6-balanced-bindings.json" in benchmark_packet
    assert "evidence/p6-balanced-frozen-manifest.json" in benchmark_packet
    assert "evidence/p6-balanced-producer-projection.json" in benchmark_packet
    assert "evidence/p6-balanced-quality-revalidation-receipt.json" in benchmark_packet
    assert "frozen-report" not in benchmark_packet
    assert "legacy-score" not in benchmark_packet
    assert "v16-score" not in benchmark_packet
    assert "matched" not in benchmark_packet
    assert "scripts/p6_balanced_orchestrator.py revalidate" in benchmark_review
    final_seal = "\n".join(
        step.get("run", "") for step in workflow["jobs"]["final_evidence_seal"]["steps"]
    )
    assert "checkpoint-run/payload/quality/p6-balanced-quality-gate.json" in final_seal
    assert "checkpoint-run/payload/quality/frozen-report.json" in final_seal
    assert "checkpoint-run/payload/quality-revalidation-receipt.json" in final_seal
    assert "--restored-bundle restored/quality-artifact/quality" in final_seal
    assert "cmp -s restored/quality-artifact/quality-revalidation-receipt.json" in final_seal


def test_toolchain_binds_exact_image_provenance_and_proxy_before_loading_key() -> None:
    _, workflow = _workflow()
    toolchain = workflow["jobs"]["toolchain_oci"]
    script = "\n".join(step.get("run", "") for step in toolchain["steps"])
    assert "Z_SCOPE_P6_OCI_IMAGE_PROVENANCE_FILE" in script
    assert 'load_image_provenance(Path("image-provenance.json"))' in script
    assert 'Path("containers/p6/Containerfile").read_bytes()' in script
    assert 'Path("containers/p6/runtime-lock.json").read_bytes()' in script
    assert 'Path("requirements/release/py313.txt").read_bytes()' in script
    assert "IMAGE_LABEL_BASE_DIGEST" in script
    assert "IMAGE_LABEL_CONTAINERFILE" in script
    assert "IMAGE_LABEL_LOCK" in script
    assert "IMAGE_LABEL_REVISION" in script
    assert "provision_transparent_proxy(" in script
    assert "Z_SCOPE_BENCHMARK_OCI_EGRESS_NETWORK" in script
    assert "load_explicit_api_key_file(" not in script
    assert '"Z_SCOPE_API_KEY": "p6-preflight-credential-not-forwarded"' in script
    assert "provider_credentials=False" in script
    assert "image_provenance_sha256" in script
    assert "proxy_provision_sha256" in script
    assert "import stat" in script
    assert "stat.S_ISREG" in script
    assert "canonical_sha256, load_json_strict" in script
    assert 'load_json_strict(root / "discarded-preflight.log")' in script

    upload = next(
        step
        for step in toolchain["steps"]
        if step.get("uses") == "./control/.github/actions/upload-artifact-retry"
    )
    assert "control/image-provenance.json" in upload["with"]["path"]
    assert "control/proxy-provision.json" in upload["with"]["path"]
    assert "control/toolchain-evidence.json" in upload["with"]["path"]


def test_every_model_executor_closes_proxy_attestation_before_credentials() -> None:
    text, workflow = _workflow()
    action = SANITIZER_ACTION.read_text(encoding="utf-8")
    model_steps = {
        "provider_probe": "Execute one constant source-free request",
        "anonymous_qualification": "Execute frozen hidden-holdout harness against the current candidate",
        "safe_pair_validation": "Execute frozen safe-pair dual-scan harness against the current candidate",
        "evidence_action_canary": "Prepare answer-free EvidenceAction input and invoke the sealed candidate harness",
        "cold_fast": "Execute fast from a new empty cache root",
        "cold_balanced": "Execute balanced from a new empty cache root",
        "cold_deep": "Execute deep from a new empty cache root",
        "product_architecture_review": "Invoke exact Claude Code 2.1.233 glm-5.3 high identity",
        "proof_security_review": "Invoke exact DSH 0.1.0-rc.6 DeepSeek v4 Pro max identity",
        "independent_benchmark_review": "Invoke exact Codex CLI 0.144.4 GPT-5.6-Sol xhigh identity",
    }
    for job_name, invocation_name in model_steps.items():
        steps = workflow["jobs"][job_name]["steps"]
        invocation_index = next(
            index for index, step in enumerate(steps) if step.get("name") == invocation_name
        )
        attestation_index, attestation_step = next(
            (index, step)
            for index, step in enumerate(steps)
            if step.get("uses") == "./control/.github/actions/validate-p6-artifact"
            and step.get("with", {}).get("expected-proxy-attestation")
        )
        assert attestation_index < invocation_index
        if job_name.endswith("_review"):
            packet_index = next(
                index
                for index, step in enumerate(steps)
                if "packet without reviewer credentials" in step.get("name", "")
            )
            assert attestation_index < packet_index < invocation_index
        assert attestation_step["with"]["require-key"] == "false"
        assert attestation_step["with"]["byte-scan-only"] == "true"
        assert attestation_step["with"]["paths"].splitlines() == [
            "restored/toolchain/image-provenance.json",
            "restored/toolchain/proxy-provision.json",
            "restored/toolchain/toolchain-evidence.json",
        ]
        restore_script = "\n".join(step.get("run", "") for step in steps[:attestation_index])
        for member in (
            "--required-member image-provenance.json",
            "--required-member proxy-provision.json",
            "--required-member toolchain-evidence.json",
        ):
            assert member in restore_script

    for contract_name in (
        "Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_FILE",
        "Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_SHA256",
    ):
        assert contract_name in action
        assert contract_name in text
    protocol_source = Path("zscope/benchmarking/p6_protocol.py").read_text(encoding="utf-8")
    assert (
        'EXPECTED_PROXY_ATTESTATION_SCHEMA_VERSION = "zscope.p6-expected-proxy-attestation.v2"'
        in protocol_source
    )
    assert "build_expected_proxy_attestation(" in action
    assert "zscope.p6-expected-proxy-attestation.v1" not in action
    assert "zscope.p6-expected-proxy-attestation.v1" not in text
    assert text.count("load_expected_proxy_attestation(") == 9
    assert '"candidate_git_tree": candidate_tree' in action
    assert "validate_expected_proxy_attestation(payload)" in action
    assert "_validate_proxy_inspection" not in action
    assert '"schema_version": "zscope.p6-expected-proxy-attestation' not in action
    assert "read_regular_file_once(output.absolute())" in action
    assert action.index("write_expected_proxy_attestation(control)") < action.index(
        "scanner_environment = load_explicit_api_key_file(key_file)"
    )
    for key_load in re.finditer(r'key_file = os\.environ\["Z_SCOPE_P6_API_KEY_FILE"\]', text):
        strict_load = text.rfind("load_expected_proxy_attestation(", 0, key_load.start())
        assert strict_load > 0
        assert key_load.start() - strict_load < 2_000
    provider_call = text.index("value = run_p6_provider_probe(")
    assert text.rfind("load_expected_proxy_attestation(", 0, provider_call) > 0
    for reviewer_call in re.finditer(r"run_reviewer\(", text):
        strict_load = text.rfind("load_expected_proxy_attestation(", 0, reviewer_call.start())
        assert strict_load > 0
        assert reviewer_call.start() - strict_load < 2_000

    review_source = Path("zscope/benchmarking/p6_review.py").read_text(encoding="utf-8")
    reviewer_environment = review_source.split("def _reviewer_environment(", 1)[1].split(
        "\ndef ", 1
    )[0]
    assert "Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_FILE" not in reviewer_environment
    assert "Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_SHA256" not in reviewer_environment


def test_qualification_and_final_seal_cross_bind_execution_proxy_lineage() -> None:
    _, workflow = _workflow()
    qualification = "\n".join(
        step.get("run", "") for step in workflow["jobs"]["qualification_seal"]["steps"]
    )
    final_seal = "\n".join(
        step.get("run", "") for step in workflow["jobs"]["final_evidence_seal"]["steps"]
    )
    for script in (qualification, final_seal):
        assert 'attestation["proxy_provision_sha256"]' in script
        assert 'attestation["image_provenance_sha256"]' in script
        assert 'attestation["provider_identity_sha256"]' in script
    assert 'receipt["proxy_container_id"] != attestation["proxy_container_id"]' in final_seal
    assert 'receipt["network_policy_sha256"]' in final_seal
    assert 'depth["oci_image_ref"] != attestation["image_ref"]' in final_seal
    assert 'depth["oci_image_id"] != attestation["image_id"]' in final_seal


def test_toolchain_and_final_manifest_are_cross_validated_at_every_trust_boundary() -> None:
    text, workflow = _workflow()
    recovery = RECOVERY_WORKFLOW.read_text(encoding="utf-8")

    assert text.count("validate-toolchain-provenance-files") == 3
    assert recovery.count("validate-toolchain-provenance-files") == 1
    assert text.count("validate-final-evidence-manifest") == 2
    assert recovery.count("validate-final-evidence-manifest") == 1

    expected_toolchain_flags = (
        "--toolchain-evidence",
        "--image-provenance",
        "--proxy-provision",
        "--workflow-run-id",
        "--workflow-run-attempt",
        "--attempt-id",
        "--control-plane-commit",
        "--candidate-commit",
        "--candidate-tree",
        "--candidate-sha256",
        "--provider-identity-sha256",
        "--image-ref",
        "--image-id",
        "--proxy-container",
        "--proxy-container-id",
        "--network-name",
        "--egress-network-name",
        "--network-policy-sha256",
        "--endpoint-origin",
    )
    for job_name in ("toolchain_oci", "final_evidence_seal", "finalize"):
        scripts = [
            step.get("run", "")
            for step in workflow["jobs"][job_name]["steps"]
            if "validate-toolchain-provenance-files" in step.get("run", "")
        ]
        assert len(scripts) == 1, job_name
        for flag in expected_toolchain_flags:
            assert flag in scripts[0], (job_name, flag)
    for flag in expected_toolchain_flags:
        assert flag in recovery

    for script in (text, recovery):
        for flag in (
            "--manifest",
            "--payload-root",
            "--workflow-run-id",
            "--workflow-run-attempt",
            "--attempt-id",
            "--control-plane-commit",
            "--candidate-commit",
            "--candidate-sha256",
        ):
            assert flag in script
    assert recovery.index("validate-final-evidence-manifest") < recovery.index(
        "validate-toolchain-provenance-files"
    )
    assert 'image_id="$($Z_SCOPE_BENCHMARK_OCI_RUNTIME image inspect' in text
    assert 'proxy_id="$($Z_SCOPE_BENCHMARK_OCI_RUNTIME container inspect' in text
    assert (
        'provenance = load_json_strict(Path("restored/checkpoint/payload/image-provenance.json"))'
        in recovery
    )
    assert (
        'proxy = load_json_strict(Path("restored/checkpoint/payload/proxy-provision.json"))'
        in recovery
    )


def test_artifacts_are_sanitized_and_restored_by_exact_id_and_digest() -> None:
    text, workflow = _workflow()

    assert "actions/download-artifact" not in text
    assert "scripts/download_p6_run_artifact.py" in text
    assert "--artifact-id" in text and "--artifact-digest" in text
    downloader_steps = [
        step
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if re.search(
            r"^\s*python3 scripts/download_p6_run_artifact\.py",
            step.get("run", ""),
            re.MULTILINE,
        )
    ]
    assert downloader_steps
    for step in downloader_steps:
        assert step["env"]["GITHUB_TOKEN"] == "${{ github.token }}"
        run = step.get("run", "")
        logical_lines = run.replace("\\\n", " ").splitlines()
        download_commands = [
            line for line in logical_lines if "python3 scripts/download_p6_run_artifact.py" in line
        ]
        assert len(download_commands) == run.count("scripts/download_p6_run_artifact.py")
        for command in download_commands:
            assert "--run-attempt" in command
            assert "--control-plane-commit" in command
            assert "--candidate-commit" in command
    forbidden_uploads = {
        "p6-fast",
        "p6-balanced",
        "p6-deep",
        "scan-input",
        "model_events",
        "GROUND_TRUTH",
        "ground_truth.json",
    }
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if step.get("uses") != "./control/.github/actions/upload-artifact-retry":
                continue
            path = str(step["with"]["path"])
            for forbidden in forbidden_uploads:
                assert path.strip() != forbidden
            if path.strip() != "control/quality-failure-aggregate.json":
                assert "aggregate.json" not in path
            assert ".log" not in path

    scanner_jobs = {
        "entry",
        "provider_probe",
        "toolchain_oci",
        "policy_replay",
        "certificate_reverify",
        "anonymous_qualification",
        "safe_pair_validation",
        "evidence_action_canary",
        "offline_qualification",
        "cold_fast",
        "cold_balanced",
        "balanced_quality_gate",
        "cold_deep",
        "qualification_seal",
        "product_architecture_review",
        "proof_security_review",
        "independent_benchmark_review",
        "final_evidence_seal",
        "finalize",
        "failure_evidence",
    }
    for job_name in scanner_jobs:
        steps = workflow["jobs"][job_name]["steps"]
        upload_index = next(
            index
            for index, step in enumerate(steps)
            if step.get("uses") == "./control/.github/actions/upload-artifact-retry"
        )
        assert any(
            step.get("uses") == "./control/.github/actions/validate-p6-artifact"
            for step in steps[:upload_index]
        ), job_name

    sanitizer = Path(".github/actions/validate-p6-artifact/action.yml").read_text(encoding="utf-8")
    assert "load_explicit_api_key_file" in sanitizer
    assert "byte-scan-only" in sanitizer
    assert "P6_SANITIZED_ARTIFACT_BYTE_SCAN_ONLY" in sanitizer
    assert "if byte_scan_only:" in sanitizer
    assert "--canary-env" not in sanitizer
    assert "child.update" not in sanitizer
    assert "Z_SCOPE_API_KEY" not in str(
        re.search(r"child = \{.*?\n        \}", sanitizer, re.DOTALL).group(0)
    )
    assert 'sysconfig.get_config_var("LIBDIR")' in sanitizer
    assert '"LD_LIBRARY_PATH": str(libdir)' in sanitizer
    assert 'os.environ.get("LD_LIBRARY_PATH"' not in sanitizer
    assert "scan_regular_artifact_tree_for_canaries" in sanitizer
    assert "derive_p6_artifact_canaries" in sanitizer
    assert 'strict_bool("P6_SANITIZED_ARTIFACT_REQUIRE_KEY")' in sanitizer
    assert 'strict_bool("P6_SANITIZED_ARTIFACT_BYTE_SCAN_ONLY")' in sanitizer
    assert "stdout=subprocess.DEVNULL" in sanitizer
    assert "stderr=subprocess.DEVNULL" in sanitizer


def test_byte_only_scans_cover_frozen_quality_and_each_reviewer_upload() -> None:
    _, workflow = _workflow()

    balanced_steps = workflow["jobs"]["cold_balanced"]["steps"]
    balanced_scan = next(
        step
        for step in balanced_steps
        if step.get("uses") == "./control/.github/actions/validate-p6-artifact"
        and step.get("with", {}).get("byte-scan-only") == "true"
        and "p6-balanced-frozen" in step.get("with", {}).get("paths", "")
    )
    assert balanced_scan["with"]["paths"].splitlines() == [
        "p6-balanced-projection.json",
        "p6-balanced-frozen",
    ]

    quality_steps = workflow["jobs"]["balanced_quality_gate"]["steps"]
    quality_scan = next(
        step
        for step in quality_steps
        if step.get("uses") == "./control/.github/actions/validate-p6-artifact"
        and step.get("with", {}).get("byte-scan-only") == "true"
        and "quality" in step.get("with", {}).get("paths", "").splitlines()
    )
    assert quality_scan["with"]["paths"].splitlines() == [
        "quality",
        "quality-revalidation-receipt.json",
    ]

    for job_name in (
        "product_architecture_review",
        "proof_security_review",
        "independent_benchmark_review",
    ):
        steps = workflow["jobs"][job_name]["steps"]
        upload_index = next(
            index
            for index, step in enumerate(steps)
            if step.get("uses") == "./control/.github/actions/upload-artifact-retry"
        )
        scan = next(
            step
            for step in steps[:upload_index]
            if step.get("uses") == "./control/.github/actions/validate-p6-artifact"
            and step.get("with", {}).get("byte-scan-only") == "true"
            and "review" in step.get("with", {}).get("paths", "").splitlines()
        )
        assert "review" in scan["with"]["paths"].splitlines()


def test_quality_receipt_is_outside_bundle_and_strictly_revalidated_on_recovery() -> None:
    _, workflow = _workflow()
    quality_upload = next(
        step
        for step in workflow["jobs"]["balanced_quality_gate"]["steps"]
        if step.get("id") == "upload"
    )["with"]["path"]
    assert quality_upload.splitlines() == [
        "control/quality",
        "control/quality-revalidation-receipt.json",
    ]

    independent_upload = next(
        step
        for step in workflow["jobs"]["independent_benchmark_review"]["steps"]
        if step.get("uses") == "./control/.github/actions/upload-artifact-retry"
    )["with"]["path"]
    assert "packet/quality-artifact/quality/p6-balanced-quality-gate.json" in independent_upload
    assert "packet/quality-artifact/quality-revalidation-receipt.json" in independent_upload
    assert "packet/quality-artifact/quality/frozen-report.json" not in independent_upload
    assert "packet/quality-artifact/quality/legacy-score.json" not in independent_upload
    assert "packet/quality-artifact/quality/v16-score.json" not in independent_upload
    assert "control/packet/quality-artifact\n" not in independent_upload

    final_script = "\n".join(
        step.get("run", "") for step in workflow["jobs"]["final_evidence_seal"]["steps"]
    )
    for member in (
        "quality/bindings.json",
        "quality/frozen-manifest.json",
        "quality/frozen-report.json",
        "quality/legacy-score.json",
        "quality/p6-balanced-quality-gate.json",
        "quality/producer-projection.json",
        "quality/usage-evidence.json",
        "quality/v16-score.json",
        "quality-revalidation-receipt.json",
    ):
        assert f"--required-member {member}" in final_script
    assert "scripts/p6_balanced_orchestrator.py revalidate" in final_script
    assert "payload/quality/usage-evidence.json" in final_script
    assert "payload/quality-revalidation-receipt.json" in final_script

    failure = workflow["jobs"]["failure_evidence"]
    restore_step = next(
        step
        for step in failure["steps"]
        if "longest continuous successful producer prefix" in step.get("name", "")
    )
    assert restore_step["env"]["QUALITY_RESULT"] == ("${{ needs.balanced_quality_gate.result }}")
    assert restore_step["env"]["QUALITY_ID"] == (
        "${{ needs.balanced_quality_gate.outputs.artifact_id }}"
    )
    restore = restore_step["run"]
    assert "scripts/p6_balanced_orchestrator.py revalidate" in restore
    assert "--restored-bundle failure-evidence/restored/quality-artifact/quality" in restore
    assert (
        "cmp -s failure-evidence/restored/quality-artifact/quality-revalidation-receipt.json"
        in restore
    )
    assert "balanced_quality_gate >> failure-evidence/prefix-stages.txt" in restore

    recovery = RECOVERY_WORKFLOW.read_text(encoding="utf-8")
    assert "--required-member payload/quality/usage-evidence.json" in recovery
    assert "--required-member payload/quality-revalidation-receipt.json" in recovery
    assert "validate_quality_revalidation_receipt" in recovery


def test_quality_hard_gate_failure_exports_only_one_closed_aggregate() -> None:
    _, workflow = _workflow()
    quality = workflow["jobs"]["balanced_quality_gate"]
    score = next(step for step in quality["steps"] if step.get("id") == "score")
    assert '--failure-aggregate "$aggregate"' in score["run"]
    assert "aggregate=quality-failure-aggregate.json" in score["run"]
    assert "failure_aggregate_present=true" in score["run"]

    scan = next(step for step in quality["steps"] if step.get("id") == "aggregate_scan")
    assert scan["if"] == (
        "${{ failure() && steps.score.outputs.failure_aggregate_present == 'true' }}"
    )
    assert scan["with"] == {
        "paths": "quality-failure-aggregate.json",
        "stage": "artifact_seal",
        "require-key": "false",
        "byte-scan-only": "true",
    }
    upload = next(step for step in quality["steps"] if step.get("id") == "upload_failure_aggregate")
    assert "steps.aggregate_scan.outcome == 'success'" in upload["if"]
    assert upload["with"]["path"] == "control/quality-failure-aggregate.json"
    assert quality["outputs"]["failure_aggregate_artifact_id"] == (
        "${{ steps.upload_failure_aggregate.outputs.artifact-id }}"
    )
    assert quality["outputs"]["failure_aggregate_artifact_digest"] == (
        "${{ steps.upload_failure_aggregate.outputs.artifact-digest }}"
    )

    success_upload = next(step for step in quality["steps"] if step.get("id") == "upload")
    assert "quality-failure-aggregate" not in success_upload["with"]["path"]
    for job_name in (
        "product_architecture_review",
        "proof_security_review",
        "independent_benchmark_review",
    ):
        reviewer = "\n".join(step.get("run", "") for step in workflow["jobs"][job_name]["steps"])
        assert "quality-failure-aggregate" not in reviewer

    failure = workflow["jobs"]["failure_evidence"]
    restore = next(
        step
        for step in failure["steps"]
        if "longest continuous successful producer prefix" in step.get("name", "")
    )
    assert restore["env"]["QUALITY_FAILURE_AGGREGATE_ID"] == (
        "${{ needs.balanced_quality_gate.outputs.failure_aggregate_artifact_id }}"
    )
    assert restore["env"]["QUALITY_FAILURE_AGGREGATE_DIGEST"] == (
        "${{ needs.balanced_quality_gate.outputs.failure_aggregate_artifact_digest }}"
    )
    assert '--required-member "$member"' in restore["run"]
    assert "quality-failure-aggregate.json" in restore["run"]
    restored_scan = next(
        step
        for step in failure["steps"]
        if step.get("name") == "Byte-scan the optionally restored quality failure aggregate"
    )
    assert restored_scan["with"]["paths"] == (
        "failure-evidence/quality-failure-aggregate/quality-failure-aggregate.json"
    )
    failure_upload = next(
        step
        for step in failure["steps"]
        if step.get("uses") == "./control/.github/actions/upload-artifact-retry"
    )
    assert failure_upload["with"]["path"] == "control/failure-evidence"


def test_failure_path_is_answer_free_and_non_finalizable() -> None:
    text, workflow = _workflow()
    failure = workflow["jobs"]["failure_evidence"]

    assert "always()" in failure["if"]
    script = "\n".join(step.get("run", "") for step in failure["steps"])
    assert "emit-workflow-failure" in script
    boundary = next(step for step in failure["steps"] if step.get("id") == "boundary")
    for job, prefix in (
        ("entry", "ENTRY"),
        ("provider_probe", "PROVIDER"),
        ("toolchain_oci", "TOOLCHAIN"),
        ("policy_replay", "POLICY"),
        ("certificate_reverify", "REVERIFY"),
        ("safe_pair_validation", "SAFE_PAIR"),
        ("final_evidence_seal", "FINAL_SEAL"),
        ("finalize", "FINALIZE"),
    ):
        assert boundary["env"][f"{prefix}_FAILURE_CLASS"] == (
            f"${{{{ needs.{job}.outputs.failure_class }}}}"
        )
        assert boundary["env"][f"{prefix}_FAILURE_COUNT"] == (
            f"${{{{ needs.{job}.outputs.failure_count }}}}"
        )
    assert "validate_stage_result" in boundary["run"]
    assert "failure_class=internal_failure" in boundary["run"]
    diagnostic = next(
        step for step in failure["steps"] if "Emit typed diagnostic" in step.get("name", "")
    )
    assert diagnostic["env"]["FAILURE_COUNT"] == ("${{ steps.boundary.outputs.failure_count }}")
    assert '--failure-count "$FAILURE_COUNT"' in diagnostic["run"]
    assert "checkpoint" in script
    assert "runtime_source_sha256" in script
    assert "provider_identity_sha256" in script
    assert "oci_execution_sha256" in script
    assert "sha256sum zscope/benchmarking/runner.py" not in script
    assert "sha256sum zscope/benchmarking/provider_runtime.py" not in script
    assert "sha256sum zscope/benchmarking/isolation.py" not in script
    assert "stdout" not in script and "stderr" not in script
    assert "formal_benchmark=false" in text
    assert "release_eligible=false" in text


def test_p6_scanner_cleanup_is_exact_label_scoped_and_survives_failure() -> None:
    text, workflow = _workflow()

    entry_script = "\n".join(step.get("run", "") for step in workflow["jobs"]["entry"]["steps"])
    assert "scripts/p6_oci_cleanup.py" in entry_script
    assert '--mode stale --repository "$GITHUB_REPOSITORY"' in entry_script
    assert entry_script.index("scripts/p6_oci_cleanup.py") < entry_script.index(
        "load_explicit_api_key_file"
    )

    oci_jobs = {
        "toolchain_oci",
        "anonymous_qualification",
        "safe_pair_validation",
        "evidence_action_canary",
        "cold_fast",
        "cold_balanced",
        "cold_deep",
    }
    for job_name in oci_jobs:
        cleanup = next(
            step
            for step in workflow["jobs"][job_name]["steps"]
            if "scripts/p6_oci_cleanup.py" in step.get("run", "")
        )
        assert cleanup["if"] == "${{ always() }}"
        script = cleanup["run"]
        assert "--mode current" in script
        assert '--repository "$GITHUB_REPOSITORY"' in script
        assert '--workflow-run-id "$GITHUB_RUN_ID"' in script
        assert '--workflow-run-attempt "$GITHUB_RUN_ATTEMPT"' in script
        assert '--attempt-id "$P6_ATTEMPT_ID"' in script
        assert "prune" not in script and "--filter" not in script and "*" not in script

    terminal = workflow["jobs"]["cleanup_p6_oci"]
    assert terminal["if"] == "${{ always() }}"
    assert oci_jobs <= set(terminal["needs"])
    terminal_script = "\n".join(step.get("run", "") for step in terminal["steps"])
    assert "--mode current" in terminal_script
    assert "prune" not in terminal_script and "--filter" not in terminal_script

    helper = Path("scripts/p6_oci_cleanup.py").read_text(encoding="utf-8")
    isolation = Path("zscope/benchmarking/isolation.py").read_text(encoding="utf-8")
    for label in (
        '"io.zscope.role": "scanner"',
        "io.zscope.p6-workflow-run-id",
        "io.zscope.p6-workflow-run-attempt",
        "io.zscope.p6-attempt-id",
        "io.zscope.p6-phase",
    ):
        assert label in helper or label in isolation
    assert "prune" not in helper


def test_provider_failure_output_is_typed_and_bound_to_the_probe_job() -> None:
    _, workflow = _workflow()
    assert workflow["jobs"]["entry"]["outputs"]["failure_class"] == (
        "${{ steps.classify.outputs.failure-class }}"
    )
    assert workflow["jobs"]["entry"]["outputs"]["failure_count"] == (
        "${{ steps.classify.outputs.failure-count }}"
    )
    authority = next(
        step for step in workflow["jobs"]["entry"]["steps"] if step.get("id") == "authority"
    )
    assert "validate_authority >/dev/null 2>&1" in authority["run"]
    assert "stage=entry_input; class=input_binding_failure:1; count=1" in authority["run"]
    assert "${!required_name:-}" in authority["run"]
    assert "|| return 2" in authority["run"]
    assert ":?sealed runner must configure" not in authority["run"]
    assert "P6_ENTRY_FAILURE_MARKER" in authority["env"]
    assert "os.O_EXCL" in authority["run"] and "os.O_NOFOLLOW" in authority["run"]
    assert '"failure_class": "input_binding_failure"' in authority["run"]
    entry_classifier = next(
        step for step in workflow["jobs"]["entry"]["steps"] if step.get("id") == "classify"
    )
    assert entry_classifier["if"] == "${{ always() }}"
    assert entry_classifier["with"]["status"] == "${{ job.status }}"
    assert entry_classifier["with"]["execution-stage"] == "entry"
    assert entry_classifier["with"]["default-class"] == "internal_failure"
    assert entry_classifier["with"]["marker"] == authority["env"]["P6_ENTRY_FAILURE_MARKER"]
    assert "str(exc)" not in authority["run"]
    assert workflow["jobs"]["provider_probe"]["outputs"]["failure_class"] == (
        "${{ steps.probe.outputs.failure_class }}"
    )
    probe = next(
        step for step in workflow["jobs"]["provider_probe"]["steps"] if step.get("id") == "probe"
    )
    assert "ProviderProbeError" in probe["run"]
    assert "exc.failure_class" in probe["run"]
    assert "str(exc)" not in probe["run"]
    failure_script = "\n".join(
        step.get("run", "") for step in workflow["jobs"]["failure_evidence"]["steps"]
    )
    assert "PROVIDER_FAILURE_CLASS" in failure_script
    assert "$PROVIDER_RESULT:provider_probe:$PROVIDER_FAILURE_CLASS" in failure_script


def test_three_tool_free_reviewers_have_exact_identity_and_ephemeral_material() -> None:
    text, workflow = _workflow()

    assert "Claude Code 2.1.233 glm-5.3 high" in text
    assert "DSH 0.1.0-rc.6 DeepSeek v4 Pro max" in text
    assert "Codex CLI 0.144.4 GPT-5.6-Sol xhigh" in text
    assert text.count("build-review-material") == 3
    assert text.count("review-material-manifest.json") >= 9
    assert text.count('material_root=Path(os.environ["P6_CANDIDATE_ROOT"])') >= 8
    for job_name in (
        "product_architecture_review",
        "proof_security_review",
        "independent_benchmark_review",
    ):
        upload = next(
            step
            for step in workflow["jobs"][job_name]["steps"]
            if step.get("uses") == "./control/.github/actions/upload-artifact-retry"
        )
        uploaded = str(upload["with"]["path"])
        assert "zscope/" not in uploaded
        assert "tests/" not in uploaded
        assert "test/range/" not in uploaded


def test_three_reviewers_share_one_strict_common_evidence_contract() -> None:
    text, workflow = _workflow()
    assert text.count("build-common-evidence") == 3
    expected_common_flags = {
        "--qualification packet/evidence/qualification.json",
        "--e0-lineage packet/evidence/e0-lineage.json",
        "--quality-bundle-root packet/quality-artifact/quality",
        "--quality-revalidation-receipt packet/quality-artifact/quality-revalidation-receipt.json",
        "--successor-qualification packet/evidence/successor-qualification.json",
        "--output packet/evidence/common-review-evidence.json",
    }
    for job_name in (
        "product_architecture_review",
        "proof_security_review",
        "independent_benchmark_review",
    ):
        job = workflow["jobs"][job_name]
        build = next(
            step for step in job["steps"] if "build-common-evidence" in step.get("run", "")
        )
        for flag in expected_common_flags:
            assert flag in build["run"]
        assert (
            "--artifact evidence/common-review-evidence.json="
            "packet/evidence/common-review-evidence.json"
        ) in build["run"]
        assert (
            "--artifact evidence/p6-balanced-quality-revalidation-receipt.json="
            "packet/evidence/p6-balanced-quality-revalidation-receipt.json"
        ) in build["run"]
        restore = next(
            step
            for step in job["steps"]
            if step.get("name") == "Restore the exact qualification artifact"
        )
        assert restore["env"]["QUALITY_ID"] == (
            "${{ needs.balanced_quality_gate.outputs.artifact_id }}"
        )
        assert "--required-member quality-revalidation-receipt.json" in restore["run"]
        upload = next(
            step
            for step in job["steps"]
            if step.get("uses") == "./control/.github/actions/upload-artifact-retry"
        )
        assert "control/packet/evidence/common-review-evidence.json" in upload["with"]["path"]
        assert "control/packet/evidence/successor-qualification.json" in upload["with"]["path"]
        assert (
            "control/packet/evidence/p6-balanced-quality-revalidation-receipt.json"
            in upload["with"]["path"]
        )
    final_script = "\n".join(
        step.get("run", "") for step in workflow["jobs"]["final_evidence_seal"]["steps"]
    )
    assert final_script.count("/packet/evidence checkpoint-run/payload/reviews/") == 3


def test_reviewer_usage_is_conserved_bound_and_excluded_from_scan_token_gate() -> None:
    _, workflow = _workflow()
    seal_script = "\n".join(
        step.get("run", "") for step in workflow["jobs"]["final_evidence_seal"]["steps"]
    )
    assert 'rows[role]["review_artifact_sha256"]' in seal_script
    assert 'review_set["reviewer_usage_conservation"]' in seal_script
    for invariant in (
        'conservation["provider_usage_coverage"] != 1.0',
        'conservation["missing_usage_call_count"] != 0',
        'conservation["mismatched_model_call_count"] != 0',
        'conservation["estimated_call_count"] != 0',
        'conservation["call_conservation_passed"] is not True',
        'conservation["token_conservation_passed"] is not True',
        'conservation["included_in_balanced_scan_token_gate"] is not False',
    ):
        assert invariant in seal_script
    assert "sha256sum restored/product-review/decision.json" not in seal_script
    assert "sha256sum restored/proof-review/decision.json" not in seal_script
    assert "sha256sum restored/benchmark-review/decision.json" not in seal_script


def test_review_failures_use_fixed_typed_markers() -> None:
    _, workflow = _workflow()
    for job_name in (
        "product_architecture_review",
        "proof_security_review",
        "independent_benchmark_review",
    ):
        job = workflow["jobs"][job_name]
        invoke = next(step for step in job["steps"] if "run_reviewer" in step.get("run", ""))
        assert "run_reviewer_with_failure_marker" in invoke["run"]
        assert 'failure_marker=Path(os.environ["P6_REVIEW_FAILURE_MARKER"])' in invoke["run"]
        assert "str(exc)" not in invoke["run"]
        classify = next(step for step in job["steps"] if step.get("id") == "classify")
        assert classify["with"]["marker"] == invoke["env"]["P6_REVIEW_FAILURE_MARKER"]


def test_final_and_recovery_revalidation_receipts_bind_the_exact_source_identity() -> None:
    _, workflow = _workflow()
    for job_name in ("final_evidence_seal", "finalize"):
        script = "\n".join(step.get("run", "") for step in workflow["jobs"][job_name]["steps"])
        assert "identity=BalancedRunIdentity(" in script
        assert 'workflow_run_id=os.environ["GITHUB_RUN_ID"]' in script
        assert 'attempt_id=os.environ["P6_ATTEMPT_ID"]' in script
        assert "candidate_git_tree=candidate_tree" in script
    recovery = RECOVERY_WORKFLOW.read_text(encoding="utf-8")
    assert "identity=BalancedRunIdentity(" in recovery
    assert 'workflow_run_id=os.environ["P6_SOURCE_RUN_ID"]' in recovery
    assert 'workflow_run_attempt=int(os.environ["P6_SOURCE_RUN_ATTEMPT"])' in recovery
    assert 'control_plane_commit=os.environ["P6_SOURCE_CONTROL_PLANE_COMMIT"]' in recovery


def test_complete_checkpoint_precedes_a_model_free_byte_exact_finalize() -> None:
    text, workflow = _workflow()
    seal = workflow["jobs"]["final_evidence_seal"]
    finalize = workflow["jobs"]["finalize"]

    assert seal["name"] == "seal complete reviewed P6 checkpoint"
    assert "product_architecture_review" in seal["needs"]
    assert "proof_security_review" in seal["needs"]
    assert "independent_benchmark_review" in seal["needs"]
    seal_script = "\n".join(step.get("run", "") for step in seal["steps"])
    assert "final_evidence_seal" in seal_script
    assert "seal-stage-artifact" in seal_script
    assert "validate-checkpoint" in seal_script
    assert "entry_payload" in seal_script
    assert "provider_payload" in seal_script
    assert "toolchain_payload" in seal_script
    assert "policy_payload" in seal_script
    assert "reverify_payload" in seal_script
    assert "hidden_payload" in seal_script
    assert "safe_payload" in seal_script
    assert "canary_payload" in seal_script
    assert "fast_payload" in seal_script and "deep_payload" in seal_script

    finalize_script = "\n".join(step.get("run", "") for step in finalize["steps"])
    assert "finalize-checkpoint" in finalize_script
    for forbidden in (
        "probe-p6",
        "--mode pilot",
        "run_reviewer",
        "hidden-holdout",
        "safe-pair-dual-scan",
    ):
        assert forbidden not in finalize_script
    assert text.index("name: seal complete reviewed P6 checkpoint") < text.index(
        "name: zero-call finalize reviewed P6 evidence"
    )


def test_runner_owned_harnesses_and_child_secret_boundaries_are_explicit() -> None:
    text, _ = _workflow()

    assert "dict(os.environ)" not in text
    assert text.count('key_file = os.environ["Z_SCOPE_P6_API_KEY_FILE"]') == 3
    assert text.count("load_explicit_api_key_file(Path(key_file))") == 3
    assert '"Z_SCOPE_API_KEY"' in text
    for forbidden in (
        '"ANTHROPIC_API_KEY"',
        '"DEEPSEEK_API_KEY"',
        '"OPENAI_API_KEY"',
        '"Z_SCOPE_P6_API_KEY_FILE",',
        '"Z_SCOPE_LLM_BASE_URL"',
        '"Z_SCOPE_LLM_MODEL"',
    ):
        assert forbidden not in "\n".join(
            line
            for line in text.splitlines()
            if "allowed =" in line or line.strip().startswith('"')
        )
    assert "Z_SCOPE_BENCHMARK_OCI_NETWORK" in text
    assert "Z_SCOPE_BENCHMARK_OCI_MODEL_PROXY_CONTAINER" in text
    assert text.count('"GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"') == 3
    assert text.count('"P6_CANDIDATE_COMMIT", "P6_ATTEMPT_ID"') == 3


def test_zero_call_recovery_requires_exact_prior_complete_checkpoint() -> None:
    text = RECOVERY_WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.load(text, Loader=_DuplicateRejectingLoader)
    assert isinstance(workflow, dict)
    assert set(workflow["on"]["workflow_dispatch"]["inputs"]) == {
        "source_run_id",
        "source_run_attempt",
        "source_control_plane_commit",
        "recovery_control_plane_commit",
        "candidate_sha",
        "checkpoint_artifact_id",
        "checkpoint_artifact_digest",
    }
    assert workflow["concurrency"] == {
        "group": (
            "p6-finalize-${{ inputs.source_run_id }}-${{ inputs.source_run_attempt }}-"
            "${{ inputs.checkpoint_artifact_id }}-${{ inputs.checkpoint_artifact_digest }}"
        ),
        "cancel-in-progress": "false",
    }
    script = "\n".join(step.get("run", "") for step in workflow["jobs"]["finalize"]["steps"])
    assert "--allow-prior-complete-checkpoint" in script
    assert '--current-run-id "$GITHUB_RUN_ID"' in script
    assert "--current-run-attempt" in script
    assert "--artifact-id" in script and "--artifact-digest" in script
    assert "--required-member checkpoint.json" in script
    assert "--required-member payload/image-provenance.json" in script
    assert "--required-member payload/proxy-provision.json" in script
    assert "--required-member payload/quality/frozen-report.json" in script
    assert "--required-member payload/quality/legacy-score.json" in script
    assert "--required-member payload/quality/v16-score.json" in script
    assert "validate_quality_gate_bundle" in script
    assert "finalize-checkpoint" in script
    assert "probe-p6" not in script and "run_reviewer" not in script
    restore = next(
        step
        for step in workflow["jobs"]["finalize"]["steps"]
        if "scripts/download_p6_run_artifact.py" in step.get("run", "")
    )
    assert restore["env"]["GITHUB_TOKEN"] == "${{ github.token }}"
    assert '--control-plane-commit "$P6_SOURCE_CONTROL_PLANE_COMMIT"' in script
    assert '--current-control-plane-commit "$P6_RECOVERY_CONTROL_PLANE_COMMIT"' in script
    assert 'git merge-base --is-ancestor "$P6_SOURCE_CONTROL_PLANE_COMMIT"' in script
    assert '--candidate-commit "$P6_CANDIDATE_COMMIT"' in script
    assert "source_head_sha" not in text and "--head-sha" not in text
    assert "Checkout immutable control plane only" in text
    assert "path: candidate" not in text
    steps = workflow["jobs"]["finalize"]["steps"]
    consume = next(
        step
        for step in steps
        if step.get("name") == "Fail closed if this exact checkpoint was already consumed"
    )
    restore_index = next(
        index
        for index, step in enumerate(steps)
        if step.get("name") == "Restore exact complete checkpoint from the protected source attempt"
    )
    assert steps.index(consume) < restore_index
    assert "/actions/artifacts?{query}" in consume["run"]
    assert 'os.environ["P6_CONSUMPTION_ARTIFACT_NAME"]' in consume["run"]
    assert 'os.environ["P6_CONSUMPTION_RECEIPT_NAME"]' in consume["run"]
    assert "if artifacts:" in consume["run"]
    formal_upload = next(step for step in steps if step.get("id") == "non_release_artifact")
    assert formal_upload["with"]["name"] == "${{ env.P6_CONSUMPTION_ARTIFACT_NAME }}"
    receipt = next(
        step
        for step in steps
        if step.get("name") == "Seal the immutable single-consumption receipt"
    )
    for binding in (
        "source_run_id",
        "source_run_attempt",
        "checkpoint_artifact_id",
        "checkpoint_artifact_digest",
        "formal_artifact_id",
        "formal_artifact_digest",
        "recovery_workflow_run_id",
        "content_sha256",
    ):
        assert f'"{binding}"' in receipt["run"]
    receipt_upload = next(step for step in steps if step.get("id") == "consumption_receipt")
    assert receipt_upload["with"]["name"] == "${{ env.P6_CONSUMPTION_RECEIPT_NAME }}"


def test_formal_artifact_names_are_run_and_attempt_immutable() -> None:
    text, _ = _workflow()

    assert (
        "p6-non-release-evidence-${{ env.P6_CONTROL_PLANE_COMMIT }}-"
        "${{ env.P6_CANDIDATE_COMMIT }}-${{ github.run_id }}-${{ github.run_attempt }}"
    ) in text
    assert "path: control/non-release-evidence" in text
    assert "formal-evidence" not in text
    assert "payload/final-evidence-manifest.json" in text
    assert "payload/qualification.json" in text
    assert "payload/reviews/product-architecture/decision.json" in text


def test_review_credentials_exist_only_in_the_exact_invocation_steps() -> None:
    _, workflow = _workflow()
    for job_name in (
        "product_architecture_review",
        "proof_security_review",
        "independent_benchmark_review",
    ):
        steps = workflow["jobs"][job_name]["steps"]
        invoke = next(step for step in steps if "run_reviewer" in step.get("run", ""))
        assert "build-review-material" not in invoke["run"]
        assert set(invoke.get("env", {})) == {"P6_REVIEW_FAILURE_MARKER"}
        assert "${{ runner.temp }}" in invoke["env"]["P6_REVIEW_FAILURE_MARKER"]
        build = next(step for step in steps if "build-review-material" in step.get("run", ""))
        validate = next(step for step in steps if "validate_review_artifact" in step.get("run", ""))
        assert not build.get("env")
        assert not validate.get("env")
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "secrets.P6_REVIEW_" not in text
    assert "vars.P6_REVIEW_" not in text


def test_reviewer_routes_reuse_sealed_e0_runtime_without_new_dispatch_configuration() -> None:
    text, workflow = _workflow()
    assert "secrets.P6_REVIEW_" not in text
    assert "vars.P6_REVIEW_" not in text
    for job_name in (
        "product_architecture_review",
        "proof_security_review",
        "independent_benchmark_review",
    ):
        assert workflow["jobs"][job_name]["environment"] == "sealed-benchmark"


def test_control_plane_never_executes_or_imports_candidate_on_host() -> None:
    text, workflow = _workflow()
    assert workflow["env"]["P6_CONTROL_ROOT"] == "${{ github.workspace }}/control"
    assert workflow["env"]["P6_CANDIDATE_ROOT"] == "${{ github.workspace }}/candidate"
    assert "pip install" not in "\n".join(
        step.get("run", "") for job in workflow["jobs"].values() for step in job["steps"]
    )
    assert 'git_revision=os.environ["P6_CANDIDATE_COMMIT"]' in text
    assert 'material_root=Path(os.environ["P6_CANDIDATE_ROOT"])' in text
    assert '--candidate-root "$P6_CANDIDATE_ROOT"' in text
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            run = step.get("run", "")
            assert "PYTHONPATH=$P6_CANDIDATE_ROOT" not in run
            assert "python3 $P6_CANDIDATE_ROOT" not in run


def test_cold_host_process_uses_a_physical_answer_free_cwd_and_pythonpath(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    for relative in (
        "scripts/run_p6_cold_producer.py",
        "zscope/__init__.py",
        "zscope/benchmarking/__init__.py",
        "zscope/benchmarking/p6_producer_metrics.py",
        "zscope/benchmarking/p6_producer_package_init.py",
        "zscope/benchmarking/p6_producer_sandbox.py",
        "zscope/benchmarking/runner.py",
        "test/range/zscope.benchmark.yaml",
        "test/range/src/example.c",
    ):
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        source = Path(relative)
        target.write_bytes(source.read_bytes() if source.is_file() else b"placeholder\n")
    forbidden = {
        "test/range/benchmark/ground_truth.json": b"{}\n",
        "zscope/benchmarking/protocol.py": b"SCORER = True\n",
        "zscope/cli/benchmark.py": b"SCORER_ENTRY = True\n",
        "zscope/core/ground_truth.json": b"{}\n",
        "zscope/core/review_packets/proof.json": b"{}\n",
        "zscope/orchestration/hypothesis_hunter/qualification/qualification-artifact.v2.json": b"{}\n",
        ".github/evidence/p6/review/decision.json": b"{}\n",
        "zscope/benchmarking/postscore_trace.py": b"POSTSCORE = True\n",
    }
    for relative, payload in forbidden.items():
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    for command in (
        ("git", "init", "--quiet"),
            ("git", "-c", "core.autocrlf=false", "add", "."),
        (
            "git",
            "-c",
            "user.name=P6 Test",
            "-c",
            "user.email=p6@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "candidate",
        ),
    ):
        subprocess.run(command, cwd=repository, check=True)
    candidate = subprocess.check_output(
        ("git", "rev-parse", "HEAD"), cwd=repository, text=True
    ).strip()
    sandbox = tmp_path / "producer-source"
    receipt = tmp_path / "producer-receipt.json"
    materialize_p6_host_producer_sandbox(
        repository_root=repository,
        candidate_commit=candidate,
        destination=sandbox,
        receipt_path=receipt,
    )

    for relative in forbidden:
        assert not (sandbox / relative).exists()
    environment = p6_host_producer_child_environment(
        {
            **os.environ,
            "GITHUB_WORKSPACE": str(tmp_path / "control"),
            "P6_CONTROL_ROOT": str(tmp_path / "control"),
            "P6_CANDIDATE_ROOT": str(tmp_path / "candidate"),
            "Z_SCOPE_BENCHMARK_TRUTH": str(tmp_path / "truth.json"),
            "GIT_DIR": str(repository / ".git"),
            "GIT_WORK_TREE": str(repository),
            "GIT_INDEX_FILE": str(repository / ".git/index"),
            "GIT_OBJECT_DIRECTORY": str(repository / ".git/objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(repository / ".git/objects"),
            "GIT_COMMON_DIR": str(repository / ".git"),
            "PWD": str(repository),
            "OLDPWD": str(tmp_path),
            "INIT_CWD": str(repository),
            "RUNNER_WORKSPACE": str(tmp_path),
            "CUSTOM_WORKSPACE_LOCATOR": str(repository / "test/range"),
            "Z_SCOPE_P6_CANDIDATE_COMMIT": candidate,
        },
        sandbox_root=sandbox,
        receipt_path=receipt,
        forbidden_roots=(repository,),
    )
    probe = (
        "import json,os,sys; from pathlib import Path; "
        "from zscope.benchmarking.p6_producer_sandbox import "
        "validate_p6_host_producer_sandbox; root=Path(os.environ["
        "'Z_SCOPE_P6_HOST_PRODUCER_ROOT']); receipt=Path(os.environ["
        "'Z_SCOPE_P6_HOST_PRODUCER_RECEIPT']); value="
        "validate_p6_host_producer_sandbox(sandbox_root=root,receipt_path=receipt,"
        "expected_candidate_commit=os.environ['Z_SCOPE_P6_CANDIDATE_COMMIT']); "
        "print(json.dumps({'cwd':str(Path.cwd()),'pythonpath':os.environ['PYTHONPATH'],"
        "'scorer':(root/'zscope/benchmarking/protocol.py').exists(),"
        "'truth':(root/'test/range/benchmark/ground_truth.json').exists(),"
        "'schema':value['schema_version']}))"
    )
    completed = subprocess.run(
        (sys.executable, "-c", probe),
        cwd=sandbox,
        env=environment,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    observed = json.loads(completed.stdout)
    assert observed == {
        "cwd": str(sandbox.resolve()),
        "pythonpath": str(sandbox.resolve()),
        "scorer": False,
        "truth": False,
        "schema": "zscope.p6-host-producer-sandbox.v1",
    }
    assert "GITHUB_WORKSPACE" not in environment
    assert "P6_CONTROL_ROOT" not in environment
    assert "P6_CANDIDATE_ROOT" not in environment
    assert "Z_SCOPE_BENCHMARK_TRUTH" not in environment
    assert not any(key.upper().startswith("GIT_") for key in environment)
    for key in (
        "PWD",
        "OLDPWD",
        "INIT_CWD",
        "RUNNER_WORKSPACE",
        "CUSTOM_WORKSPACE_LOCATOR",
    ):
        assert key not in environment
    git_probe = subprocess.run(
        ("git", "rev-parse", "--show-toplevel"),
        cwd=sandbox,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert git_probe.returncode != 0
    assert git_probe.stdout == ""


def test_cold_wrapper_enters_host_sandbox_before_importing_benchmark_runner() -> None:
    wrapper = Path("scripts/run_p6_cold_producer.py").read_text(encoding="utf-8")
    runner = Path("zscope/benchmarking/runner.py").read_text(encoding="utf-8")

    assert "materialize_p6_host_producer_sandbox(" in wrapper
    assert "cwd=str(sandbox)" in wrapper
    assert "p6_host_producer_child_environment(" in wrapper
    assert "forbidden_roots=(source_root,)" in wrapper
    assert 'launch_environment["Z_SCOPE_P6_API_KEY_FILE"]' in wrapper
    assert "str(private_output)" in wrapper
    assert "from zscope.benchmarking.runner import BenchmarkError, run_benchmark" not in wrapper
    assert (
        "from zscope.benchmarking.protocol import (" not in runner.split("def score_artifact", 1)[0]
    )


@pytest.mark.parametrize("child_returncode", [0, 2, "raise"])
def test_cold_launcher_does_not_pass_control_checkout_locators_to_actual_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    child_returncode: int | str,
) -> None:
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    control = tmp_path / "control"
    script = control / "scripts/run_p6_cold_producer.py"
    script.parent.mkdir(parents=True)
    script.write_text("# launcher\n", encoding="utf-8")
    key_file = control / "test/range/zscope.local.env"
    key_file.parent.mkdir(parents=True)
    key_file.write_text("Z_SCOPE_API_KEY=private\n", encoding="utf-8")
    attestation = control / "expected-proxy-attestation.json"
    attestation.write_text("{}\n", encoding="utf-8")
    if os.name == "posix":
        key_file.chmod(0o600)
        attestation.chmod(0o600)
    requested_output = control / "p6-balanced"
    marker = runner_temp / "p6-cold-balanced-failure.json"
    candidate = "a" * 40
    captured: dict[str, object] = {}

    def fake_materialize(**kwargs: object) -> dict[str, object]:
        destination = Path(str(kwargs["destination"]))
        receipt = Path(str(kwargs["receipt_path"]))
        (destination / "scripts").mkdir(parents=True)
        (destination / "scripts/run_p6_cold_producer.py").write_text("# child\n", encoding="utf-8")
        receipt.write_text("{}\n", encoding="utf-8")
        return {}

    def fake_child(
        command: list[str],
        *,
        cwd: str,
        env: dict[str, str],
        stdin: object,
        check: bool,
    ) -> subprocess.CompletedProcess[str]:
        del stdin, check
        captured.update(command=list(command), cwd=cwd, environment=dict(env))
        if child_returncode == "raise":
            raise OSError("synthetic child launch failure")
        if child_returncode == 0:
            private_output = Path(command[command.index("--output") + 1])
            private_output.mkdir()
            (private_output / "aggregate.json").write_text("{}\n", encoding="utf-8")
        else:
            marker.write_text(
                '{"failure_class":"internal_failure","failure_count":1}\n',
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(command, int(child_returncode))

    monkeypatch.setattr(run_p6_cold_producer, "__file__", str(script))
    monkeypatch.setattr(
        run_p6_cold_producer,
        "materialize_p6_host_producer_sandbox",
        fake_materialize,
    )
    monkeypatch.setattr(run_p6_cold_producer.subprocess, "run", fake_child)
    monkeypatch.setenv("RUNNER_TEMP", str(runner_temp))
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("Z_SCOPE_P6_CANDIDATE_COMMIT", candidate)
    monkeypatch.setenv("Z_SCOPE_P6_API_KEY_FILE", str(key_file))
    monkeypatch.setenv("Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_FILE", str(attestation))
    monkeypatch.setenv(
        "Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_SHA256",
        sha256_file(attestation),
    )
    monkeypatch.setenv("GITHUB_WORKSPACE", str(control))
    monkeypatch.setenv("P6_CONTROL_ROOT", str(control))
    monkeypatch.setenv("GIT_DIR", str(control / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(control))
    monkeypatch.setenv("CUSTOM_WORKSPACE_LOCATOR", str(control / "test/range"))

    invocation = run_p6_cold_producer.argparse.Namespace(
        scan_depth="balanced",
        output=requested_output,
        failure_marker=marker,
    )
    if child_returncode == "raise":
        with pytest.raises(OSError, match="synthetic child launch failure"):
            run_p6_cold_producer._run_from_answer_free_host_sandbox(invocation)
        result = None
    else:
        result = run_p6_cold_producer._run_from_answer_free_host_sandbox(invocation)

    if child_returncode != "raise":
        assert result == child_returncode
        assert (requested_output / "aggregate.json").is_file() is (child_returncode == 0)
    command = captured["command"]
    environment = captured["environment"]
    assert isinstance(command, list)
    assert isinstance(environment, dict)
    serialized_child_inputs = json.dumps(
        {"command": command, "environment": environment}, sort_keys=True
    )
    assert str(control) not in serialized_child_inputs
    assert str(requested_output) not in command
    assert not any(str(key).upper().startswith("GIT_") for key in environment)
    assert captured["cwd"] == environment["Z_SCOPE_P6_HOST_PRODUCER_ROOT"]
    assert environment["PYTHONPATH"] == captured["cwd"]
    assert Path(environment["Z_SCOPE_P6_API_KEY_FILE"]).parent == runner_temp
    assert (
        Path(environment["Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_FILE"]).parent == runner_temp
    )
    assert not Path(environment["Z_SCOPE_P6_API_KEY_FILE"]).exists()
    assert not Path(environment["Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_FILE"]).exists()
    assert not any(path.name.endswith("-key.env") for path in runner_temp.iterdir())
    assert not any(path.name.endswith("-proxy.json") for path in runner_temp.iterdir())
    assert all(
        b"Z_SCOPE_API_KEY=private" not in path.read_bytes()
        for path in runner_temp.rglob("*")
        if path.is_file() and not path.is_symlink()
    )


def test_answer_free_host_tree_imports_runner_without_loading_scorer(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    shutil.copytree(
        Path("zscope"),
        repository / "zscope",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    (repository / "scripts").mkdir()
    shutil.copy2(
        Path("scripts/run_p6_cold_producer.py"),
        repository / "scripts/run_p6_cold_producer.py",
    )
    for relative in ("CMakeLists.txt", "README.md", "zscope.benchmark.yaml"):
        source = Path("test/range") / relative
        if source.is_file():
            target = repository / "test/range" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    for directory in ("src", "include", "internal"):
        source = Path("test/range") / directory
        if source.is_dir():
            shutil.copytree(source, repository / "test/range" / directory)
    qualification_output = (
        repository / "zscope/orchestration/p6-proof-promotion-qualification.v1.json"
    )
    status_output = repository / "zscope/orchestration/successor-runtime-review-status.v1.json"
    qualification_environment = dict(os.environ)
    qualification_environment["PYTHONPATH"] = str(repository)
    subprocess.run(
        (
            sys.executable,
            str(Path("scripts/qualify_p6_proof_promotion.py").resolve()),
            "--output",
            str(qualification_output),
            "--status-output",
            str(status_output),
        ),
        cwd=Path.cwd(),
        env=qualification_environment,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    for command in (
        ("git", "init", "--quiet"),
        ("git", "-c", "core.autocrlf=false", "add", "."),
        (
            "git",
            "-c",
            "user.name=P6 Test",
            "-c",
            "user.email=p6@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "candidate",
        ),
    ):
        subprocess.run(command, cwd=repository, check=True)
    candidate = subprocess.check_output(
        ("git", "rev-parse", "HEAD"), cwd=repository, text=True
    ).strip()
    sandbox = tmp_path / "producer-source"
    receipt = tmp_path / "producer-receipt.json"
    materialize_p6_host_producer_sandbox(
        repository_root=repository,
        candidate_commit=candidate,
        destination=sandbox,
        receipt_path=receipt,
    )
    environment = p6_host_producer_child_environment(
        {**os.environ, "Z_SCOPE_P6_CANDIDATE_COMMIT": candidate},
        sandbox_root=sandbox,
        receipt_path=receipt,
    )
    probe = (
        "import json,sys; from pathlib import Path; "
        "from zscope.benchmarking.runner import run_benchmark; root=Path.cwd(); "
            "from zscope.orchestration.proof_promotion_qualification import load_runtime_successor_qualification; successor=load_runtime_successor_qualification(); "
        "print(json.dumps({'callable':callable(run_benchmark),"
        "'successor_loaded':successor['status']=='local_candidate_qualified',"
        "'scorer_loaded':'zscope.benchmarking.protocol' in sys.modules,"
        "'scorer_present':(root/'zscope/benchmarking/protocol.py').exists(),"
        "'scorer_entry_present':(root/'zscope/cli/benchmark.py').exists(),"
        "'truth_present':(root/'test/range/benchmark').exists(),"
        "'qualification_present':(root/'zscope/orchestration/hypothesis_hunter/qualification/qualification-artifact.v2.json').exists(),"
        "'review_present':(root/'.github/evidence').exists(),"
        "'postscore_present':(root/'zscope/benchmarking/postscore_trace.py').exists()}))"
    )
    completed = subprocess.run(
        (sys.executable, "-B", "-c", probe),
        cwd=sandbox,
        env=environment,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    assert json.loads(completed.stdout) == {
        "callable": True,
        "successor_loaded": True,
        "scorer_loaded": False,
        "scorer_present": False,
        "scorer_entry_present": False,
        "truth_present": False,
        "qualification_present": False,
        "review_present": False,
        "postscore_present": False,
    }


def test_candidate_is_exact_normal_merge_of_tested_tree_plus_evidence() -> None:
    text, _ = _workflow()
    verifier = Path("zscope/benchmarking/p6_balanced_orchestrator.py").read_text(encoding="utf-8")

    assert 'test "$P6_CANDIDATE_COMMIT" = "$P6_CONTROL_PLANE_COMMIT"' in text
    assert (
        "test \"$(git rev-parse 'HEAD^{tree}')\" = "
        '"$(git -C "$P6_CANDIDATE_ROOT" rev-parse \'HEAD^{tree}\')"'
    ) in text
    assert "len(hosted_parents) != 3" in verifier
    assert "evidence_commit not in hosted_parents[1:]" in verifier
    assert "len(evidence_parents) != 2" in verifier
    assert "changed_paths(tested_commit, evidence_commit)" in verifier
    assert "changed_paths(tested_commit, hosted_control_plane_commit)" in verifier
    assert 'f"{evidence_commit}^{{tree}}"' in verifier
    assert 'f"{hosted_control_plane_commit}^{{tree}}"' in verifier
    assert (
        'control_object="$(git rev-parse "${P6_CONTROL_PLANE_COMMIT}:${protected_path}")"' in text
    )
    assert 'candidate_object="$(git rev-parse "${P6_CANDIDATE_COMMIT}:${protected_path}")"' in text
    assert 'test "$control_object" = "$candidate_object"' in text


def test_failure_boundary_tracks_each_offline_stage_independently() -> None:
    text, workflow = _workflow()
    failure = workflow["jobs"]["failure_evidence"]
    assert set(failure["needs"]) >= {
        "policy_replay",
        "certificate_reverify",
        "anonymous_qualification",
        "safe_pair_validation",
        "evidence_action_canary",
    }
    script = "\n".join(step.get("run", "") for step in failure["steps"])
    for stage in (
        "policy_replay",
        "certificate_reverify",
        "anonymous_qualification",
        "safe_pair_validation",
        "evidence_action_canary",
    ):
        assert f":{stage}" in script
    assert "$OFFLINE_RESULT:cold_fast:$OFFLINE_FAILURE_CLASS:internal_failure" in script


def test_every_p6_producer_exports_one_always_typed_failure_result() -> None:
    _, workflow = _workflow()
    producers = {
        "entry": "entry",
        "toolchain_oci": "toolchain_oci_preflight",
        "policy_replay": "policy_replay",
        "certificate_reverify": "certificate_reverify",
        "anonymous_qualification": "anonymous_qualification",
        "safe_pair_validation": "safe_pair_validation",
        "evidence_action_canary": "evidence_action_canary",
        "offline_qualification": "cold_fast",
        "cold_fast": "cold_fast",
        "cold_balanced": "cold_balanced",
        "balanced_quality_gate": "balanced_quality_gate",
        "cold_deep": "cold_deep",
        "qualification_seal": "qualification_seal",
        "product_architecture_review": "product_architecture_review",
        "proof_security_review": "proof_security_review",
        "independent_benchmark_review": "independent_benchmark_review",
        "final_evidence_seal": "final_evidence_seal",
        "finalize": "evidence_pr",
    }
    for job_name, stage in producers.items():
        job = workflow["jobs"][job_name]
        assert job["outputs"]["failure_class"] == ("${{ steps.classify.outputs.failure-class }}")
        assert job["outputs"]["failure_count"] == ("${{ steps.classify.outputs.failure-count }}")
        classify = next(step for step in job["steps"] if step.get("id") == "classify")
        assert classify["if"] == "${{ always() }}"
        assert classify["with"]["status"] == "${{ job.status }}"
        assert classify["with"]["execution-stage"] == stage

    classifier = Path(".github/actions/classify-p6-job-failure/action.yml").read_text(
        encoding="utf-8"
    )
    assert "marker_was_present = False" in classifier
    assert "if marker_was_present:" in classifier


def test_failure_checkpoint_restores_and_seals_only_the_longest_exact_prefix() -> None:
    _, workflow = _workflow()
    failure = workflow["jobs"]["failure_evidence"]
    restore = next(
        step
        for step in failure["steps"]
        if "longest continuous successful producer prefix" in step.get("name", "")
    )["run"]
    seal = next(
        step
        for step in failure["steps"]
        if "exact non-finalizable checkpoint" in step.get("name", "")
    )["run"]
    assert "prefix_open=true" in restore
    assert 'if [[ "$prefix_open" != true ]]; then return 0; fi' in restore
    assert 'if [[ "$result" != success ]]; then prefix_open=false; return 0; fi' in restore
    for stage in (
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
    ):
        assert stage in restore or stage in seal
    assert "P6_CHECKPOINT_STAGE_ORDER[: len(stages)]" in seal
    assert 'payload_sha="$(sha256sum "$payload"' in seal
    assert '--payload-sha256 "$payload_sha"' in seal
    assert "zero_call_finalizable=true" not in seal


def test_final_checkpoint_uses_review_schema_validation_before_generic_answer_free_gate() -> None:
    _, workflow = _workflow()
    final = workflow["jobs"]["final_evidence_seal"]
    script = "\n".join(step.get("run", "") for step in final["steps"])
    action = Path(".github/actions/validate-p6-artifact/action.yml").read_text(encoding="utf-8")
    assert "validate_review_artifact" in script
    for role in (
        "product_architecture",
        "proof_security",
        "independent_benchmark",
    ):
        assert role in script
    assert "find checkpoint-run/payload -type f -name '*.json'" in script
    assert "*/reviews/*" in script
    assert 'if "/payload/reviews/" in f"/{relative}"' in action
    assert "derive_p6_artifact_canaries" in action


def test_checkpoint_lineage_comes_from_restored_evidence_not_source_files() -> None:
    text, workflow = _workflow()
    seal_script = "\n".join(
        step.get("run", "") for step in workflow["jobs"]["final_evidence_seal"]["steps"]
    )
    finalize_script = "\n".join(
        step.get("run", "") for step in workflow["jobs"]["finalize"]["steps"]
    )
    recovery = RECOVERY_WORKFLOW.read_text(encoding="utf-8")
    for script in (seal_script, finalize_script, recovery):
        assert '["evidence_sha256"]' in script
        assert '["runtime_source_sha256"]' in script
        assert '["provider_identity_sha256"]' in script
        assert '["oci_execution_sha256"]' in script
        assert "sha256sum zscope/benchmarking/runner.py" not in script
        assert "sha256sum zscope/benchmarking/provider_runtime.py" not in script
        assert "sha256sum zscope/benchmarking/isolation.py" not in script


def test_upload_tree_rejects_a_same_directory_symlink_alias(tmp_path: Path) -> None:
    control = tmp_path / "control"
    control.mkdir()
    target = control / "payload.json"
    target.write_text("{}\n", encoding="utf-8")
    alias = control / "alias.json"
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable")

    with pytest.raises(P6ArtifactTreeError, match="symbolic link"):
        discover_regular_files(control, [str(alias)])


def test_upload_tree_rejects_a_symlinked_directory_member(tmp_path: Path) -> None:
    control = tmp_path / "control"
    payload = control / "payload"
    payload.mkdir(parents=True)
    target = control / "target"
    target.mkdir()
    (target / "result.json").write_text("{}\n", encoding="utf-8")
    alias = payload / "alias"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable")

    with pytest.raises(P6ArtifactTreeError, match="symbolic link"):
        discover_regular_files(control, [str(payload)])


def test_upload_tree_revalidates_the_exact_resolved_regular_member(
    tmp_path: Path,
) -> None:
    control = tmp_path / "control"
    control.mkdir()
    member = control / "payload.json"
    member.write_text("{}\n", encoding="utf-8")

    discovered = discover_regular_files(control, [str(member)])

    assert discovered == (member.resolve(strict=True),)
    assert revalidate_regular_file(control, discovered[0]) == member.resolve(strict=True)


def test_upload_gate_scans_every_live_reviewer_credential_namespace() -> None:
    action = Path(".github/actions/validate-p6-artifact/action.yml").read_text(encoding="utf-8")
    for name in (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "DEEPSEEK_API_KEY",
        "CODEX_API_KEY",
        "OPENAI_API_KEY",
    ):
        assert f'"{name}"' in action
    assert "encoded_canaries" in action


def test_upload_and_freeze_scan_all_run_bound_answer_material_canaries() -> None:
    action = Path(".github/actions/validate-p6-artifact/action.yml").read_text(encoding="utf-8")
    protocol = Path("zscope/benchmarking/p6_protocol.py").read_text(encoding="utf-8")
    freeze_cli = Path("scripts/p6_balanced_orchestrator.py").read_text(encoding="utf-8")

    for category in (
        "source",
        "truth",
        "expected",
        "scorer",
        "prompt",
        "response",
        "model-output",
    ):
        assert f'"{category}"' in protocol
    assert "derive_p6_artifact_canaries(" in action
    assert "scan_regular_artifact_tree_for_canaries(path" in action
    assert 'os.environ.get("P6_SOURCE_RUN_ID")' in action
    assert 'os.environ.get("P6_SOURCE_RUN_ATTEMPT")' in action
    assert "derive_p6_artifact_canaries(" in freeze_cli


@pytest.mark.parametrize(
    ("depth", "failure_class"),
    [
        ("fast", "provider_transport_exhausted"),
        ("balanced", "terminal_state_inconsistent"),
        ("deep", "queue_not_drained"),
    ],
)
def test_cold_producer_persists_only_the_typed_benchmark_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    depth: str,
    failure_class: str,
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    marker = tmp_path / f"p6-cold-{depth}-failure.json"

    def fail(*_args: object, **_kwargs: object) -> None:
        raise BenchmarkError("private failure body", failure_class=failure_class)

    monkeypatch.setattr(run_p6_cold_producer, "run_benchmark", fail)

    assert (
        run_p6_cold_producer.run_cold_producer(
            scan_depth=depth,
            output=tmp_path / "output",
            failure_marker=marker,
            require_source_sandbox=False,
        )
        == 2
    )
    assert json.loads(marker.read_text(encoding="utf-8")) == {
        "failure_class": failure_class,
        "failure_count": 1,
    }
    assert "private" not in marker.read_text(encoding="utf-8")


def test_cold_producer_maps_unknown_exceptions_to_internal_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    marker = tmp_path / "p6-cold-fast-failure.json"
    monkeypatch.setattr(
        run_p6_cold_producer,
        "run_benchmark",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("secret body")),
    )

    assert (
        run_p6_cold_producer.run_cold_producer(
            scan_depth="fast",
            output=tmp_path / "output",
            failure_marker=marker,
            require_source_sandbox=False,
        )
        == 2
    )
    assert json.loads(marker.read_text(encoding="utf-8")) == {
        "failure_class": "internal_failure",
        "failure_count": 1,
    }
    assert "secret" not in marker.read_text(encoding="utf-8")


def test_cold_producer_forces_answer_free_scanning_before_external_freeze(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    observed: dict[str, object] = {}

    def succeed(*args: object, **kwargs: object) -> dict[str, object]:
        observed["args"] = args
        observed["kwargs"] = kwargs
        return {}

    monkeypatch.setattr(run_p6_cold_producer, "run_benchmark", succeed)
    marker = tmp_path / "p6-cold-balanced-failure.json"

    assert (
        run_p6_cold_producer.run_cold_producer(
            scan_depth="balanced",
            output=tmp_path / "output",
            failure_marker=marker,
            require_source_sandbox=False,
        )
        == 0
    )
    assert observed["args"] == ("c_cpp", "pilot")
    assert observed["kwargs"] == {
        "runs": 1,
        "output": tmp_path / "output",
        "scan_depth": "balanced",
        "answer_free_producer": True,
    }
    assert not marker.exists()


def test_entry_lineage_projection_binds_the_exact_successful_e0_gate() -> None:
    gate = load_json_strict(ENTRY_GATE)
    projection = project_gate_lineage(gate, gate_file_sha256=sha256_file(ENTRY_GATE))

    assert projection["review"]["run_id"] == gate["e0_review"]["run_id"]
    assert projection["review"]["artifacts"] == {
        name: {
            "id": artifact["id"],
            "digest": artifact["digest"],
            "expired": False,
        }
        for name, artifact in sorted(gate["e0_review"]["artifacts"].items())
    }
    assert projection["attestation"]["artifact_id"] == (gate["e0_attestation"]["artifact"]["id"])
    assert projection["entry_gate_file_sha256"] == sha256_file(ENTRY_GATE)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("e0_review", "conclusion"), "failure"),
        (("e0_review", "artifacts", "pair", "expired"), True),
        (("review_packets", "unchanged"), False),
        (("ancestry", "scorer_is_ancestor_of_truth"), False),
    ],
)
def test_entry_lineage_projection_rejects_unattested_or_drifted_gate(
    path: tuple[str, ...], value: object
) -> None:
    gate = copy.deepcopy(load_json_strict(ENTRY_GATE))
    cursor = gate
    for name in path[:-1]:
        cursor = cursor[name]
    cursor[path[-1]] = value
    gate["content_sha256"] = canonical_sha256(
        {name: body for name, body in gate.items() if name != "content_sha256"}
    )

    with pytest.raises(P6ProtocolError):
        project_gate_lineage(gate, gate_file_sha256=sha256_file(ENTRY_GATE))
