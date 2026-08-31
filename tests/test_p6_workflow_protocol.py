from __future__ import annotations

import copy
import json
from pathlib import Path
import re

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
from zscope.benchmarking.p6_protocol import (
    P6ProtocolError,
    canonical_sha256,
    load_json_strict,
    sha256_file,
)


WORKFLOW = Path(".github/workflows/p6-pilot-validation.yml")
RECOVERY_WORKFLOW = Path(".github/workflows/p6-pilot-finalize-recovery.yml")
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


def test_dispatcher_binds_immutable_control_plane_and_candidate_only() -> None:
    text, workflow = _workflow()

    assert set(workflow["on"]["workflow_dispatch"]["inputs"]) == {
        "control_plane_commit",
        "candidate_sha",
    }
    assert "P6_CONTROL_PLANE_COMMIT: ${{ inputs.control_plane_commit }}" in text
    assert "P6_CANDIDATE_COMMIT: ${{ inputs.candidate_sha }}" in text
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


def test_workflow_is_one_sequential_non_release_pilot() -> None:
    _, workflow = _workflow()
    jobs = workflow["jobs"]

    assert workflow["concurrency"] == {
        "group": "p6-pilot-validation",
        "cancel-in-progress": "false",
    }
    assert workflow["env"]["P6_MAX_CONCURRENT_CALLS"] == "8"
    expected_needs = {
        "provider_probe": {"entry"},
        "toolchain_oci": {"provider_probe"},
        "policy_replay": {"toolchain_oci"},
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
        "cold_deep": {"cold_balanced", "toolchain_oci"},
        "product_architecture_review": {"qualification_seal", "entry"},
        "proof_security_review": {
            "product_architecture_review",
            "qualification_seal",
            "entry",
        },
        "independent_benchmark_review": {
            "proof_security_review",
            "qualification_seal",
            "entry",
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
    for job in ("anonymous_qualification", "safe_pair_validation", "evidence_action_canary"):
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
    assert workflow["defaults"]["run"]["working-directory"] == "control"
    assert workflow["env"]["PYTHONPATH"] == "${{ github.workspace }}/control"
    assert "candidate" not in workflow["env"]["PYTHONPATH"]
    setup = Path(".github/actions/setup-p6-python/action.yml").read_text(encoding="utf-8")
    assert "--require-hashes" in setup
    assert "requirements/constraints/py313.txt" in setup
    assert "--no-deps" in setup and "--no-build-isolation" in setup


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
    assert text.count('"--provider-model", "GLM-5.2"') == 3
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
    assert text.count("--toolchain-evidence restored/toolchain/toolchain-evidence.json") == 8
    assert "provider_response_model_coverage" not in text or "seal-qualification" in text


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
        assert run.count("--run-attempt") == run.count("scripts/download_p6_run_artifact.py")
        assert run.count("--control-plane-commit") == run.count(
            "scripts/download_p6_run_artifact.py"
        )
        assert run.count("--candidate-commit") == run.count("scripts/download_p6_run_artifact.py")
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
        "cold_deep",
        "qualification_seal",
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
    assert "--canary-env" in sanitizer and "Z_SCOPE_API_KEY" in sanitizer
    assert "stdout=subprocess.DEVNULL" in sanitizer
    assert "stderr=subprocess.DEVNULL" in sanitizer


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
        "${{ steps.authority.outputs.failure_class }}"
    )
    authority = next(
        step for step in workflow["jobs"]["entry"]["steps"] if step.get("id") == "authority"
    )
    assert "validate_authority >/dev/null 2>&1" in authority["run"]
    assert "stage=entry_input; class=input_binding_failure:1; count=1" in authority["run"]
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
    assert workflow["concurrency"]["group"] == "p6-pilot-validation"
    script = "\n".join(step.get("run", "") for step in workflow["jobs"]["finalize"]["steps"])
    assert "--allow-prior-complete-checkpoint" in script
    assert '--current-run-id "$GITHUB_RUN_ID"' in script
    assert "--current-run-attempt" in script
    assert "--artifact-id" in script and "--artifact-digest" in script
    assert "--required-member checkpoint.json" in script
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
    assert (
        "source-${{ env.P6_SOURCE_CONTROL_PLANE_COMMIT }}-${{ env.P6_CANDIDATE_COMMIT }}-"
        "${{ env.P6_SOURCE_RUN_ID }}-${{ env.P6_SOURCE_RUN_ATTEMPT }}"
    ) in text
    assert (
        "recovery-${{ env.P6_RECOVERY_CONTROL_PLANE_COMMIT }}-"
        "${{ github.run_id }}-${{ github.run_attempt }}"
    ) in text


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
        assert not invoke.get("env")
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


def test_candidate_and_control_tree_are_identical_for_the_first_pilot_protocol() -> None:
    text, _ = _workflow()

    assert 'test "$P6_CANDIDATE_COMMIT" = "$P6_CONTROL_PLANE_COMMIT"' in text
    assert "git -C \"$P6_CANDIDATE_ROOT\" rev-parse 'HEAD^{tree}'" in text


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
        "toolchain_oci": "toolchain_oci_preflight",
        "policy_replay": "policy_replay",
        "certificate_reverify": "certificate_reverify",
        "anonymous_qualification": "anonymous_qualification",
        "safe_pair_validation": "safe_pair_validation",
        "evidence_action_canary": "evidence_action_canary",
        "offline_qualification": "cold_fast",
        "cold_fast": "cold_fast",
        "cold_balanced": "cold_balanced",
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
    assert "literal_canaries" in action


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


def test_upload_tree_revalidates_the_exact_resolved_regular_member(tmp_path: Path) -> None:
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
    assert "literal_canaries" in action


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
        )
        == 2
    )
    assert json.loads(marker.read_text(encoding="utf-8")) == {
        "failure_class": "internal_failure",
        "failure_count": 1,
    }
    assert "secret" not in marker.read_text(encoding="utf-8")


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
