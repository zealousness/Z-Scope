from __future__ import annotations

import copy
import re
import subprocess
import urllib.error
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from scripts import verify_e0_attestation_preflight as preflight


REPOSITORY = "zealousness/Z-Scope"
RUN_ID = "33247814685"
SOURCE_SHA = "b" * 40
TRUTH_SHA = "c" * 40
GOVERNANCE_SHA = "d" * 40
SCORER_SHA = "e" * 40
WORKFLOW_SHA = "f" * 40


def _attestation_workflow() -> str:
    return Path(".github/workflows/range-v16-benchmark-v5-attestation.yml").read_text(
        encoding="utf-8"
    )


def _workflow_steps(workflow: str) -> list[str]:
    starts = list(re.finditer(r"(?m)^      - (?:name: .+|uses: .+)$", workflow))
    return [
        workflow[match.start() : starts[index + 1].start() if index + 1 < len(starts) else None]
        for index, match in enumerate(starts)
    ]


def _step_containing(workflow: str, marker: str) -> str:
    matches = [step for step in _workflow_steps(workflow) if marker in step]
    assert len(matches) == 1, marker
    return matches[0]


def _review_run() -> dict[str, Any]:
    return {
        "id": int(RUN_ID),
        "head_sha": SOURCE_SHA,
        "head_branch": "main",
        "path": ".github/workflows/range-v16-review.yml",
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
    }


def _producer_job() -> dict[str, Any]:
    return {
        "id": 123,
        "name": preflight.PRODUCER_JOB,
        "run_id": int(RUN_ID),
        "head_sha": SOURCE_SHA,
        "status": "completed",
        "conclusion": "success",
    }


def _artifact_name(kind: str) -> str:
    suffix = {
        "review": "reviewed",
        "provenance": "review-provenance",
        "pair_author": "pair-author",
    }[kind]
    return f"range-v16-{suffix}-{SOURCE_SHA}"


def _listed_artifact(kind: str, artifact_id: int) -> dict[str, Any]:
    return {
        "id": artifact_id,
        "name": _artifact_name(kind),
        "expired": False,
        "digest": f"sha256:{artifact_id:064x}",
    }


def _exact_artifact(kind: str, artifact_id: int) -> dict[str, Any]:
    listed = _listed_artifact(kind, artifact_id)
    return {
        **listed,
        "size_in_bytes": 1024,
        "archive_download_url": (
            f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/" f"{artifact_id}/zip"
        ),
        "workflow_run": {"id": int(RUN_ID), "head_sha": SOURCE_SHA},
    }


def _assert_failure_class(
    expected: str,
    function: Any,
    *args: Any,
    **kwargs: Any,
) -> None:
    with pytest.raises(preflight.AttestationPreflightFailure) as caught:
        function(*args, **kwargs)
    assert caught.value.failure_class == expected
    assert str(caught.value) == expected


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("id", int(RUN_ID) + 1),
        ("head_sha", "0" * 40),
        ("head_branch", "feature"),
        ("path", ".github/workflows/other.yml"),
        ("event", "push"),
        ("repository", {"full_name": "other/repository"}),
        ("head_repository", {"full_name": "other/repository"}),
    ),
)
def test_review_run_requires_exact_protected_identity(field: str, value: object) -> None:
    metadata = _review_run()
    metadata[field] = value
    _assert_failure_class(
        "review_run_identity_mismatch",
        preflight._validate_review_run,
        metadata,
        repository=REPOSITORY,
        workflow_run_id=RUN_ID,
        review_source_sha=SOURCE_SHA,
    )


@pytest.mark.parametrize(
    ("status", "conclusion"),
    (("in_progress", None), ("completed", "failure"), ("completed", None)),
)
def test_review_run_must_be_terminal_success(status: str, conclusion: str | None) -> None:
    metadata = _review_run()
    metadata["status"] = status
    metadata["conclusion"] = conclusion
    _assert_failure_class(
        "review_run_not_successful",
        preflight._validate_review_run,
        metadata,
        repository=REPOSITORY,
        workflow_run_id=RUN_ID,
        review_source_sha=SOURCE_SHA,
    )


def test_review_run_accepts_only_the_frozen_successful_run() -> None:
    preflight._validate_review_run(
        _review_run(),
        repository=REPOSITORY,
        workflow_run_id=RUN_ID,
        review_source_sha=SOURCE_SHA,
    )


@pytest.mark.parametrize(
    ("mutation", "failure_class"),
    (
        ("missing", "producer_job_missing"),
        ("wrong_run", "producer_job_identity_mismatch"),
        ("wrong_head", "producer_job_identity_mismatch"),
        ("failed", "producer_job_not_successful"),
        ("running", "producer_job_not_successful"),
    ),
)
def test_producer_job_requires_source_bound_success(mutation: str, failure_class: str) -> None:
    job = _producer_job()
    jobs: list[dict[str, Any]] = [job]
    if mutation == "missing":
        jobs = []
    elif mutation == "wrong_run":
        job["run_id"] = int(RUN_ID) + 1
    elif mutation == "wrong_head":
        job["head_sha"] = "0" * 40
    elif mutation == "failed":
        job["conclusion"] = "failure"
    elif mutation == "running":
        job["status"] = "in_progress"
        job["conclusion"] = None
    _assert_failure_class(
        failure_class,
        preflight._validate_producer_job,
        jobs,
        workflow_run_id=RUN_ID,
        review_source_sha=SOURCE_SHA,
    )


def test_producer_job_accepts_the_exact_successful_job() -> None:
    preflight._validate_producer_job(
        [_producer_job()],
        workflow_run_id=RUN_ID,
        review_source_sha=SOURCE_SHA,
    )


def test_exact_artifact_binds_listing_and_immutable_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_id = 9713663607
    monkeypatch.setattr(
        preflight,
        "_fetch_bounded",
        lambda *_args, **_kwargs: _exact_artifact("review", artifact_id),
    )

    assert preflight._resolve_exact_artifact(
        [_listed_artifact("review", artifact_id)],
        repository=REPOSITORY,
        workflow_run_id=RUN_ID,
        review_source_sha=SOURCE_SHA,
        token="secret",
        name=_artifact_name("review"),
        failure_class="reviewed_artifact_missing_or_ambiguous",
    ) == (artifact_id, f"sha256:{artifact_id:064x}")


@pytest.mark.parametrize(
    "mutation",
    (
        "missing",
        "ambiguous",
        "expired",
        "listed_digest",
        "exact_id",
        "exact_name",
        "exact_expired",
        "exact_digest",
        "exact_run",
        "exact_head",
        "exact_archive_url",
    ),
)
def test_exact_artifact_fails_closed_on_every_identity_mismatch(
    mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_id = 9713663607
    listed = _listed_artifact("review", artifact_id)
    exact = _exact_artifact("review", artifact_id)
    artifacts = [listed]
    expected_class = "artifact_metadata_mismatch"
    if mutation == "missing":
        artifacts = []
        expected_class = "reviewed_artifact_missing_or_ambiguous"
    elif mutation == "ambiguous":
        artifacts.append(copy.deepcopy(listed))
        expected_class = "reviewed_artifact_missing_or_ambiguous"
    elif mutation == "expired":
        listed["expired"] = True
        expected_class = "reviewed_artifact_missing_or_ambiguous"
    elif mutation == "listed_digest":
        listed["digest"] = f"sha256:{'0' * 64}"
    elif mutation == "exact_id":
        exact["id"] = artifact_id + 1
    elif mutation == "exact_name":
        exact["name"] = "wrong"
    elif mutation == "exact_expired":
        exact["expired"] = True
    elif mutation == "exact_digest":
        exact["digest"] = f"sha256:{'0' * 64}"
    elif mutation == "exact_run":
        exact["workflow_run"]["id"] = int(RUN_ID) + 1
    elif mutation == "exact_head":
        exact["workflow_run"]["head_sha"] = "0" * 40
    elif mutation == "exact_archive_url":
        exact["archive_download_url"] = "https://example.invalid/artifact.zip"
    monkeypatch.setattr(preflight, "_fetch_bounded", lambda *_args, **_kwargs: exact)

    _assert_failure_class(
        expected_class,
        preflight._resolve_exact_artifact,
        artifacts,
        repository=REPOSITORY,
        workflow_run_id=RUN_ID,
        review_source_sha=SOURCE_SHA,
        token="secret",
        name=_artifact_name("review"),
        failure_class="reviewed_artifact_missing_or_ambiguous",
    )


def test_run_collection_uses_canonical_bounded_pagination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    urls: list[str] = []
    first_page = [{"id": identity} for identity in range(1, 101)]
    responses = iter(
        (
            {"total_count": 101, "artifacts": first_page},
            {"total_count": 101, "artifacts": [{"id": 101}]},
        )
    )

    def fetch(url: str, *, token: str) -> dict[str, Any]:
        assert token == "secret"
        urls.append(url)
        return next(responses)

    monkeypatch.setattr(preflight, "_fetch_bounded", fetch)
    artifacts = preflight._list_run_collection(
        repository=REPOSITORY,
        workflow_run_id=RUN_ID,
        token="secret",
        collection="artifacts",
        query="",
        invalid_class="review_artifact_listing_invalid",
    )

    assert len(artifacts) == 101
    assert urls == [
        f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{RUN_ID}/artifacts"
        "?per_page=100&page=1",
        f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{RUN_ID}/artifacts"
        "?per_page=100&page=2",
    ]


def test_run_collection_rejects_total_drift_and_duplicate_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = iter(
        (
            {"total_count": 101, "jobs": [{"id": identity} for identity in range(1, 101)]},
            {"total_count": 102, "jobs": [{"id": 101}, {"id": 102}]},
        )
    )
    monkeypatch.setattr(preflight, "_fetch_bounded", lambda *_args, **_kwargs: next(responses))
    _assert_failure_class(
        "review_job_listing_invalid",
        preflight._list_run_collection,
        repository=REPOSITORY,
        workflow_run_id=RUN_ID,
        token="secret",
        collection="jobs",
        query="?filter=all",
        invalid_class="review_job_listing_invalid",
    )

    monkeypatch.setattr(
        preflight,
        "_fetch_bounded",
        lambda *_args, **_kwargs: {
            "total_count": 2,
            "jobs": [{"id": 1}, {"id": 1}],
        },
    )
    _assert_failure_class(
        "review_job_listing_invalid",
        preflight._list_run_collection,
        repository=REPOSITORY,
        workflow_run_id=RUN_ID,
        token="secret",
        collection="jobs",
        query="?filter=all",
        invalid_class="review_job_listing_invalid",
    )


def test_review_lineage_resolves_exact_unique_artifacts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_ids = {
        "review": 9713663607,
        "provenance": 9713664518,
        "pair_author": 9713987274,
    }
    listed = [_listed_artifact(kind, artifact_id) for kind, artifact_id in artifact_ids.items()]
    seen: list[str] = []

    def fetch(url: str, *, token: str) -> dict[str, Any]:
        assert token == "secret"
        seen.append(url)
        if url.endswith(f"/actions/runs/{RUN_ID}"):
            return _review_run()
        if url.endswith(f"/actions/runs/{RUN_ID}/jobs?filter=all&per_page=100&page=1"):
            return {"total_count": 1, "jobs": [_producer_job()]}
        if url.endswith(f"/actions/runs/{RUN_ID}/artifacts?per_page=100&page=1"):
            return {"total_count": 3, "artifacts": listed}
        for kind, artifact_id in artifact_ids.items():
            if url.endswith(f"/actions/artifacts/{artifact_id}"):
                return _exact_artifact(kind, artifact_id)
        raise AssertionError(f"unexpected GitHub API URL: {url}")

    monkeypatch.setattr(preflight, "_fetch_bounded", fetch)
    outputs = preflight._resolve_review_lineage(
        repository=REPOSITORY,
        workflow_run_id=RUN_ID,
        review_source_sha=SOURCE_SHA,
        token="secret",
    )

    assert outputs == {
        "review_workflow_head_sha": SOURCE_SHA,
        "review_artifact_id": str(artifact_ids["review"]),
        "review_artifact_digest": f"sha256:{artifact_ids['review']:064x}",
        "review_provenance_artifact_id": str(artifact_ids["provenance"]),
        "review_provenance_artifact_digest": (f"sha256:{artifact_ids['provenance']:064x}"),
        "pair_author_artifact_id": str(artifact_ids["pair_author"]),
        "pair_author_artifact_digest": f"sha256:{artifact_ids['pair_author']:064x}",
    }
    assert len(seen) == 6


def test_bounded_fetch_retries_only_within_the_frozen_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    def fetch(_url: str, *, token: str) -> dict[str, str]:
        nonlocal attempts
        assert token == "secret"
        attempts += 1
        if attempts < len(preflight.RETRY_DELAYS_SECONDS):
            raise preflight.CheckpointArtifactTransportError("sensitive transport body")
        return {"status": "ok"}

    monkeypatch.setattr(preflight, "_fetch_metadata", fetch)
    monkeypatch.setattr(preflight, "RETRY_DELAYS_SECONDS", (0.0, 0.0, 0.0, 0.0))
    assert preflight._fetch_bounded("https://api.github.test/run", token="secret") == {
        "status": "ok"
    }
    assert attempts == 4


def test_bounded_fetch_uses_frozen_backoff_before_later_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    delays: list[float] = []

    def fetch(_url: str, *, token: str) -> dict[str, str]:
        nonlocal attempts
        assert token == "secret"
        attempts += 1
        if attempts < 3:
            raise preflight.CheckpointArtifactTransportError("transient")
        return {"status": "ok"}

    monkeypatch.setattr(preflight, "_fetch_metadata", fetch)
    monkeypatch.setattr(preflight.time, "sleep", delays.append)

    assert preflight._fetch_bounded("https://api.github.test/run", token="secret") == {
        "status": "ok"
    }
    assert attempts == 3
    assert delays == [1.0, 3.0]


@pytest.mark.parametrize("status", (408, 429, 500, 502, 503, 504))
def test_metadata_fetch_classifies_only_transient_http_as_retryable(
    status: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise urllib.error.HTTPError("https://api.github.test/run", status, "sensitive", None, None)

    monkeypatch.setattr(preflight.urllib.request.OpenerDirector, "open", fail)
    with pytest.raises(preflight.CheckpointArtifactTransportError):
        preflight._fetch_metadata("https://api.github.test/run", token="secret")


@pytest.mark.parametrize("status", (301, 400, 401, 403, 404, 422))
def test_metadata_fetch_rejects_nontransient_http_without_retry_classification(
    status: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise urllib.error.HTTPError("https://api.github.test/run", status, "sensitive", None, None)

    monkeypatch.setattr(preflight.urllib.request.OpenerDirector, "open", fail)
    with pytest.raises(preflight.CheckpointArtifactError):
        preflight._fetch_metadata("https://api.github.test/run", token="secret")


def test_bounded_fetch_does_not_retry_contract_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    def fetch(_url: str, *, token: str) -> dict[str, str]:
        nonlocal attempts
        attempts += 1
        raise preflight.CheckpointArtifactError("sensitive response body")

    monkeypatch.setattr(preflight, "_fetch_metadata", fetch)
    _assert_failure_class(
        "github_response_invalid",
        preflight._fetch_bounded,
        "https://api.github.test/run",
        token="secret",
    )
    assert attempts == 1


def test_bounded_fetch_exhaustion_reports_only_fixed_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    def fetch(_url: str, *, token: str) -> dict[str, str]:
        nonlocal attempts
        attempts += 1
        raise preflight.CheckpointArtifactTransportError("sensitive transport body")

    monkeypatch.setattr(preflight, "_fetch_metadata", fetch)
    monkeypatch.setattr(preflight, "RETRY_DELAYS_SECONDS", (0.0, 0.0, 0.0, 0.0))
    _assert_failure_class(
        "github_transport_failure",
        preflight._fetch_bounded,
        "https://api.github.test/run",
        token="secret",
    )
    assert attempts == 4


def test_git_lineage_checks_control_head_ancestry_and_packet_immutability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, ...]] = []

    def run_git(
        workspace: Path, *arguments: str, capture: bool = False
    ) -> subprocess.CompletedProcess[str]:
        assert workspace == tmp_path
        calls.append(arguments)
        if arguments[:2] == ("rev-parse", "--is-shallow-repository"):
            stdout = "false\n"
        elif arguments[:2] == ("rev-parse", "HEAD"):
            stdout = f"{WORKFLOW_SHA}\n"
        else:
            stdout = ""
        return subprocess.CompletedProcess(["git", *arguments], 0, stdout, "")

    monkeypatch.setattr(preflight, "_run_git", run_git)
    preflight._validate_git_lineage(
        workspace=tmp_path,
        workflow_head_sha=WORKFLOW_SHA,
        workflow_head_branch="main",
        truth_commit=TRUTH_SHA,
        governance_commit=GOVERNANCE_SHA,
        scorer_commit=SCORER_SHA,
        review_source_sha=SOURCE_SHA,
    )

    assert ("merge-base", "--is-ancestor", TRUTH_SHA, WORKFLOW_SHA) in calls
    assert ("merge-base", "--is-ancestor", GOVERNANCE_SHA, TRUTH_SHA) in calls
    assert ("merge-base", "--is-ancestor", SCORER_SHA, TRUTH_SHA) in calls
    assert (
        "diff",
        "--quiet",
        SOURCE_SHA,
        TRUTH_SHA,
        "--",
        *preflight.PACKET_PATHS,
    ) in calls


def test_git_lineage_failure_never_surfaces_git_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sensitive = "review prose must remain hidden"

    def run_git(
        _workspace: Path, *arguments: str, capture: bool = False
    ) -> subprocess.CompletedProcess[str]:
        if arguments[:2] == ("rev-parse", "--is-shallow-repository"):
            return subprocess.CompletedProcess(["git", *arguments], 0, "false\n", sensitive)
        if arguments[:2] == ("rev-parse", "HEAD"):
            return subprocess.CompletedProcess(
                ["git", *arguments], 0, f"{WORKFLOW_SHA}\n", sensitive
            )
        if arguments[:3] == ("diff", "--quiet", SOURCE_SHA):
            return subprocess.CompletedProcess(["git", *arguments], 1, sensitive, sensitive)
        return subprocess.CompletedProcess(["git", *arguments], 0, sensitive, sensitive)

    monkeypatch.setattr(preflight, "_run_git", run_git)
    with pytest.raises(preflight.AttestationPreflightFailure) as caught:
        preflight._validate_git_lineage(
            workspace=tmp_path,
            workflow_head_sha=WORKFLOW_SHA,
            workflow_head_branch="main",
            truth_commit=TRUTH_SHA,
            governance_commit=GOVERNANCE_SHA,
            scorer_commit=SCORER_SHA,
            review_source_sha=SOURCE_SHA,
        )
    assert caught.value.failure_class == "review_packets_changed"
    assert sensitive not in str(caught.value)


def test_main_writes_only_validated_lineage_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "github-output"
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setattr(preflight, "_validate_git_lineage", lambda **_kwargs: None)
    monkeypatch.setattr(
        preflight,
        "_resolve_review_lineage",
        lambda **_kwargs: {
            "review_workflow_head_sha": SOURCE_SHA,
            "review_artifact_id": "11",
            "review_artifact_digest": f"sha256:{'1' * 64}",
            "review_provenance_artifact_id": "12",
            "review_provenance_artifact_digest": f"sha256:{'2' * 64}",
            "pair_author_artifact_id": "13",
            "pair_author_artifact_digest": f"sha256:{'3' * 64}",
        },
    )

    assert (
        preflight.main(
            [
                "--repository",
                REPOSITORY,
                "--workflow-run-id",
                RUN_ID,
                "--review-source-sha",
                SOURCE_SHA,
                "--truth-commit",
                TRUTH_SHA,
                "--governance-commit",
                GOVERNANCE_SHA,
                "--scorer-commit",
                SCORER_SHA,
                "--workflow-head-sha",
                WORKFLOW_SHA,
                "--workflow-head-branch",
                "main",
                "--workspace",
                str(tmp_path),
                "--github-output",
                str(output),
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == "preflight_status=verified\n"
    assert output.read_text(encoding="utf-8").splitlines() == [
        f"review_workflow_head_sha={SOURCE_SHA}",
        "review_artifact_id=11",
        f"review_artifact_digest=sha256:{'1' * 64}",
        "review_provenance_artifact_id=12",
        f"review_provenance_artifact_digest=sha256:{'2' * 64}",
        "pair_author_artifact_id=13",
        f"pair_author_artifact_digest=sha256:{'3' * 64}",
    ]


@pytest.mark.parametrize(
    ("failure", "expected"),
    (
        (
            preflight.AttestationPreflightFailure("review_run_identity_mismatch"),
            "review_run_identity_mismatch",
        ),
        (RuntimeError("sensitive generated content"), "internal_failure"),
    ),
)
def test_main_failure_annotation_is_fixed_and_answer_free(
    failure: Exception,
    expected: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(_argv: object) -> int:
        raise failure

    monkeypatch.setattr(preflight, "_main", fail)
    assert preflight.main([]) == 1
    output = capsys.readouterr().out
    assert output == (
        "::error title=E0 attestation preflight::" f"preflight_failure={expected}; count=1\n"
    )
    assert "sensitive" not in output


def test_attestation_workflow_uses_hardened_preflight_and_frozen_truth_checkout() -> None:
    workflow = _attestation_workflow()

    assert "gh api" not in workflow
    assert "GH_TOKEN" not in workflow
    assert "id: review_lineage" in workflow
    assert "scripts/verify_e0_attestation_preflight.py" in workflow
    assert "GITHUB_TOKEN: ${{ github.token }}" in workflow
    assert "Z_SCOPE_E0_REVIEW_ENVIRONMENT: sealed-benchmark" in workflow
    control_checkout = workflow.index("ref: ${{ github.sha }}")
    preflight_call = workflow.index("scripts/verify_e0_attestation_preflight.py")
    truth_checkout = workflow.index("checkout --detach --quiet")
    assert control_checkout < preflight_call < truth_checkout
    assert 'if [ "$(git rev-parse HEAD 2>/dev/null)" != "$TRUTH_COMMIT" ]' in workflow
    assert "actions/download-artifact" not in workflow
    assert "scripts/download_e0_run_artifacts.py" in workflow
    assert '--expected-run-id "$REVIEW_RUN_ID"' in workflow
    assert '--expected-head-sha "$REVIEW_SOURCE_SHA"' in workflow
    assert '--expected-workflow-path ".github/workflows/range-v16-review.yml"' in workflow
    assert '--expected-event "workflow_dispatch"' in workflow
    assert '--expected-head-branch "main"' in workflow
    assert '--expected-producer-job "codex arbitration finalize and safe-pair author"' in workflow
    assert workflow.count("--exact-artifact ") == 3
    assert "${{ steps.review_lineage.outputs.review_artifact_id }}" in workflow
    assert "${{ steps.review_lineage.outputs.review_provenance_artifact_id }}" in workflow
    assert "${{ steps.review_lineage.outputs.pair_author_artifact_id }}" in workflow
    assert "${{ steps.review_lineage.outputs.review_workflow_head_sha }}" in workflow
    assert "${{ steps.review_lineage.outputs.review_artifact_digest }}" in workflow
    assert "${{ steps.review_lineage.outputs.pair_author_artifact_digest }}" in workflow
    assert "${{ steps.validate_e0.outputs.pair_author_artifact_digest }}" not in workflow


def test_attestation_workflow_binds_the_selected_python_and_removes_the_combined_step() -> None:
    workflow = _attestation_workflow()

    assert "python3" not in workflow
    assert 'python-version: "3.13"' in workflow
    assert "sys.version_info[:2] == (3, 13)" in workflow
    assert "Validate Truth v16, Benchmark v5, pairs, and answer isolation" not in workflow
    assert "id: validate_e0" not in workflow
    assert "pip install --no-deps -e ." not in workflow
    assert '"$E0_PYTHON" -m pip check' in workflow

    setup_python = workflow.index("uses: actions/setup-python@v7")
    selected_version = workflow.index('python-version: "3.13"')
    identity_gate = workflow.index("sys.version_info[:2] == (3, 13)")
    preflight = workflow.index("scripts/verify_e0_attestation_preflight.py")
    assert setup_python < selected_version < identity_gate < preflight

    identity_step = _step_containing(workflow, "sys.version_info[:2] == (3, 13)")
    assert "id: setup_python" in workflow
    assert "${{ steps.setup_python.outputs.python-path }}" in identity_step
    assert 'E0_PYTHON="$E0_VENV_ROOT/venv/bin/python"' in identity_step
    assert '"$E0_SETUP_PYTHON" -m venv "$E0_VENV_ROOT/venv"' in identity_step
    assert 'printf \'E0_PYTHON=%s\\n\' "$E0_PYTHON" >> "$GITHUB_ENV"' in identity_step
    assert "validation_failure=selected_python_identity_mismatch; count=1" in identity_step
    assert "validation_failure=venv_python_identity_mismatch; count=1" in identity_step
    assert ">/dev/null 2>&1" in identity_step
    assert re.search(r"(?m)^\s+(?:python|python3)(?:\s|$)", workflow) is None
    for marker in (
        "scripts/verify_e0_attestation_preflight.py",
        "scripts/download_e0_run_artifacts.py",
        "scripts/verify_e0_review_provenance.py",
        "scripts/generate_range_v16_truth.py normalize",
        "scripts/generate_range_v16_safe_pairs.py materialize",
        "scripts/generate_range_v16_truth.py build",
        "scripts/validate_range_v16_truth.py",
        "-m pytest -q tests/test_truth_contract_v2.py",
        "scripts/build_e0_attestation.py",
        "scripts/verify_e0_attestation.py",
    ):
        assert f'"$E0_PYTHON" {marker}' in workflow


def test_attestation_workflow_uses_ordered_independent_validation_failure_domains() -> None:
    workflow = _attestation_workflow()
    ordered_markers = (
        "checkout --detach --quiet",
        "scripts/download_e0_run_artifacts.py",
        '"$E0_PYTHON" -m pip install --only-binary=:all: --require-hashes',
        "scripts/verify_e0_review_provenance.py",
        "scripts/generate_range_v16_truth.py normalize",
        "cmp reconstructed-review/normalized-decisions.json",
        "scripts/generate_range_v16_safe_pairs.py materialize",
        "diff --recursive --brief --no-dereference reconstructed-pairs",
        "scripts/generate_range_v16_truth.py build",
        "cmp reconstructed-truth/ground_truth.json",
        "scripts/validate_range_v16_truth.py",
        '"$E0_PYTHON" -m pytest -q tests/test_truth_contract_v2.py',
        "scripts/build_e0_attestation.py",
        "scripts/verify_e0_attestation.py",
        "uses: actions/upload-artifact@v7",
    )

    positions = [workflow.index(marker) for marker in ordered_markers]
    assert positions == sorted(positions)

    independent_markers = ordered_markers[2:-1]
    independent_steps = [_step_containing(workflow, marker) for marker in independent_markers]
    assert len({step.partition("\n")[0] for step in independent_steps}) == len(independent_steps)

    restore_step = _step_containing(workflow, "scripts/download_e0_run_artifacts.py")
    upload_step = _step_containing(workflow, "uses: actions/upload-artifact@v7")
    restore_index = workflow.index(restore_step)
    upload_index = workflow.index(upload_step)
    for step in independent_steps:
        assert restore_index < workflow.index(step) < upload_index


def test_attestation_workflow_emits_only_fixed_answer_free_failure_annotations() -> None:
    workflow = _attestation_workflow()
    expected = Counter(
        [
            "::error title=E0 attestation validation::validation_failure=selected_python_identity_mismatch; count=1",
            "::error title=E0 attestation validation::validation_failure=venv_workspace_failure; count=1",
            "::error title=E0 attestation validation::validation_failure=venv_creation_failure; count=1",
            "::error title=E0 attestation validation::validation_failure=venv_python_identity_mismatch; count=1",
            "::error title=E0 attestation validation::validation_failure=venv_binding_failure; count=1",
            "::error title=E0 attestation validation::validation_failure=locked_dependency_install_failure; count=1",
            "::error title=E0 attestation validation::validation_failure=dependency_integrity_failure; count=1",
            "::error title=E0 attestation validation::validation_failure=review_provenance_failure; count=1",
            "::error title=E0 attestation validation::validation_failure=review_workspace_failure; count=1",
            "::error title=E0 attestation validation::validation_failure=review_normalization_failure; count=1",
            "::error title=E0 attestation validation::validation_failure=normalized_review_mismatch; count=1",
            "::error title=E0 attestation validation::validation_failure=pair_author_decision_mismatch; count=1",
            "::error title=E0 attestation validation::validation_failure=pair_materialization_failure; count=1",
            "::error title=E0 attestation validation::validation_failure=pair_tree_mismatch; count=1",
            "::error title=E0 attestation validation::validation_failure=truth_workspace_failure; count=1",
            "::error title=E0 attestation validation::validation_failure=truth_rebuild_failure; count=1",
            "::error title=E0 attestation validation::validation_failure=ground_truth_mismatch; count=1",
            "::error title=E0 attestation validation::validation_failure=safe_pair_manifest_mismatch; count=1",
            "::error title=E0 attestation validation::validation_failure=truth_manifest_mismatch; count=1",
            "::error title=E0 attestation validation::validation_failure=truth_validation_failure; count=1",
            "::error title=E0 attestation validation::validation_failure=truth_contract_test_failure; count=1",
            "::error title=E0 attestation validation::validation_failure=benchmark_v5_test_failure; count=1",
            "::error title=E0 attestation validation::validation_failure=benchmark_leakage_test_failure; count=1",
            "::error title=E0 attestation validation::validation_failure=change_scope_test_failure; count=1",
            "::error title=E0 attestation issuance::attestation_failure=release_workspace_failure; count=1",
            "::error title=E0 attestation issuance::attestation_failure=review_count_read_failure; count=1",
            "::error title=E0 attestation issuance::attestation_failure=review_count_invalid; count=1",
            "::error title=E0 attestation issuance::attestation_failure=attestation_build_failure; count=1",
            "::error title=E0 attestation issuance::attestation_failure=attestation_self_verification_failure; count=1",
        ]
    )
    protected_annotations = Counter(
        line.strip().removeprefix('echo "').removesuffix('"')
        for line in workflow.splitlines()
        if "::error title=E0 attestation validation::" in line
        or "::error title=E0 attestation issuance::" in line
    )

    assert protected_annotations == expected
    assert all("$" not in annotation for annotation in protected_annotations)

    protected_steps = [
        step
        for step in _workflow_steps(workflow)
        if "::error title=E0 attestation validation::" in step
        or "::error title=E0 attestation issuance::" in step
    ]
    guarded_commands = [
        command
        for step in protected_steps
        for command in re.findall(r"(?ms)^\s*if ! (.*?); then\s*$", step)
    ]
    assert guarded_commands
    for command in guarded_commands:
        if "OPUS_REVIEW_COUNT=" in command or "E0_VENV_ROOT=" in command:
            assert "2>/dev/null" in command
        elif "printf 'E0_PYTHON=%s" in command:
            assert '>> "$GITHUB_ENV"' in command
        else:
            assert ">/dev/null 2>&1" in command


def test_attestation_workflow_runs_each_focused_test_as_a_separate_silent_guard() -> None:
    workflow = _attestation_workflow()
    focused_step = _step_containing(
        workflow, '"$E0_PYTHON" -m pytest -q tests/test_truth_contract_v2.py'
    )
    commands = re.findall(
        r'if ! "\$E0_PYTHON" -m pytest -q (tests/[a-zA-Z0-9_]+\.py) \\\n'
        r"\s+>/dev/null 2>&1; then",
        focused_step,
    )

    assert commands == [
        "tests/test_truth_contract_v2.py",
        "tests/test_benchmark_v5.py",
        "tests/test_benchmark_leakage.py",
        "tests/test_zscope_2_change_scope.py",
    ]
    assert focused_step.count('"$E0_PYTHON" -m pytest -q ') == 4
    assert focused_step.count("_test_failure; count=1") == 4


def test_attestation_workflow_preserves_formal_builder_and_artifact_contract() -> None:
    workflow = _attestation_workflow()
    build_step = _step_containing(workflow, "scripts/build_e0_attestation.py")
    verify_step = _step_containing(workflow, "scripts/verify_e0_attestation.py")
    upload_step = _step_containing(workflow, "uses: actions/upload-artifact@v7")

    assert build_step != verify_step
    builder = re.search(
        r'(?ms)if ! "\$E0_PYTHON" scripts/build_e0_attestation\.py \\\n(.*?)'
        r"^\s*>/dev/null 2>&1; then$",
        build_step,
    )
    assert builder is not None
    assert re.findall(r"(?m)^\s+(--[a-z0-9-]+)\b", builder.group(1)) == [
        "--governance-commit",
        "--scorer-commit",
        "--truth-commit",
        "--truth",
        "--truth-manifest",
        "--source-truth-v15",
        "--review-packet-catalog",
        "--normalized-decisions",
        "--safe-pair-author-manifest",
        "--safe-pair-author-artifact-digest",
        "--review-bundle",
        "--review-provenance",
        "--safe-pair-manifest",
        "--defect-taxonomy",
        "--benchmark-policy",
        "--scorer-bundle-file",
        "--scorer-bundle-file",
        "--scorer-bundle-file",
        "--opus-review-count",
        "--output",
    ]
    assert "--output release-evidence/e0-attestation.json \\" in build_step
    assert "--attestation release-evidence/e0-attestation.json \\" in verify_step
    assert '--workflow-run-id "$GITHUB_RUN_ID" \\' in verify_step
    assert '--head-sha "$GITHUB_SHA" \\' in verify_step
    assert "name: e0-range-v16-benchmark-v5-${{ inputs.truth_commit }}" in upload_step
    assert "path: release-evidence/e0-attestation.json" in upload_step
    assert "if-no-files-found: error" in upload_step
    assert "retention-days: 90" in upload_step
    assert workflow.count("release-evidence/e0-attestation.json") == 3
