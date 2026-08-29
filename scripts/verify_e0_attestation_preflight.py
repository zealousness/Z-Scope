#!/usr/bin/env python3
"""Verify protected E0 attestation lineage without external CLI dependencies."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

if __package__:
    from scripts.download_e0_checkpoint_artifact import (
        CheckpointArtifactError,
        CheckpointArtifactTransportError,
        _NoRedirect,
        _validate_metadata,
    )
else:
    from download_e0_checkpoint_artifact import (  # type: ignore[import-not-found, no-redef]
        CheckpointArtifactError,
        CheckpointArtifactTransportError,
        _NoRedirect,
        _validate_metadata,
    )


API_ROOT = "https://api.github.com"
RETRY_DELAYS_SECONDS = (0.0, 1.0, 3.0, 7.0)
MAX_PAGES = 10
PER_PAGE = 100
MAX_METADATA_BYTES = 16 * 1024 * 1024
API_VERSION = "2022-11-28"
TRANSIENT_HTTP_STATUS = frozenset({408, 429, 500, 502, 503, 504})
REVIEW_WORKFLOW_PATH = ".github/workflows/range-v16-review.yml"
REVIEW_EVENT = "workflow_dispatch"
REVIEW_HEAD_BRANCH = "main"
ATTESTATION_HEAD_BRANCH = "main"
PRODUCER_JOB = "codex arbitration finalize and safe-pair author"
PACKET_PATHS = (
    "test/range/benchmark/v16/review-packet-catalog.json",
    "test/range/benchmark/v16/review-packets",
)
_SHA_RE = re.compile(r"[0-9a-f]{40}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_FAILURE_CLASS_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")


class AttestationPreflightFailure(RuntimeError):
    """A fixed, answer-free preflight failure classification."""

    def __init__(self, failure_class: str) -> None:
        if _FAILURE_CLASS_RE.fullmatch(failure_class) is None:
            raise ValueError("invalid attestation preflight failure class")
        super().__init__(failure_class)
        self.failure_class = failure_class


def _failure(failure_class: str) -> AttestationPreflightFailure:
    return AttestationPreflightFailure(failure_class)


def _run_git(
    workspace: Path, *arguments: str, capture: bool = False
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=workspace,
        text=True,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def _require_commit(workspace: Path, commit: str, *, failure_class: str) -> None:
    completed = _run_git(workspace, "cat-file", "-e", f"{commit}^{{commit}}")
    if completed.returncode != 0:
        raise _failure(failure_class)


def _require_ancestor(
    workspace: Path,
    ancestor: str,
    descendant: str,
    *,
    failure_class: str,
) -> None:
    completed = _run_git(workspace, "merge-base", "--is-ancestor", ancestor, descendant)
    if completed.returncode != 0:
        raise _failure(failure_class)


def _validate_git_lineage(
    *,
    workspace: Path,
    workflow_head_sha: str,
    workflow_head_branch: str,
    truth_commit: str,
    governance_commit: str,
    scorer_commit: str,
    review_source_sha: str,
) -> None:
    if workflow_head_branch != ATTESTATION_HEAD_BRANCH:
        raise _failure("attestation_branch_mismatch")
    shallow = _run_git(workspace, "rev-parse", "--is-shallow-repository", capture=True)
    if shallow.returncode != 0 or shallow.stdout.strip() != "false":
        raise _failure("control_plane_checkout_shallow")
    completed = _run_git(workspace, "rev-parse", "HEAD", capture=True)
    if completed.returncode != 0 or completed.stdout.strip() != workflow_head_sha:
        raise _failure("control_plane_checkout_mismatch")

    _require_commit(workspace, truth_commit, failure_class="truth_commit_unavailable")
    _require_commit(workspace, governance_commit, failure_class="governance_commit_unavailable")
    _require_commit(workspace, scorer_commit, failure_class="scorer_commit_unavailable")
    _require_commit(workspace, review_source_sha, failure_class="review_source_unavailable")
    _require_ancestor(
        workspace,
        truth_commit,
        workflow_head_sha,
        failure_class="truth_not_in_control_plane",
    )
    _require_ancestor(
        workspace,
        governance_commit,
        truth_commit,
        failure_class="governance_not_ancestor",
    )
    _require_ancestor(
        workspace,
        scorer_commit,
        truth_commit,
        failure_class="scorer_not_ancestor",
    )
    packet_diff = _run_git(
        workspace,
        "diff",
        "--quiet",
        review_source_sha,
        truth_commit,
        "--",
        *PACKET_PATHS,
    )
    if packet_diff.returncode == 1:
        raise _failure("review_packets_changed")
    if packet_diff.returncode != 0:
        raise _failure("review_packet_comparison_failed")


def _fetch_metadata(url: str, *, token: str) -> Mapping[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "zscope-e0-attestation-preflight",
            "X-GitHub-Api-Version": API_VERSION,
        },
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=60) as response:
            payload = response.read(MAX_METADATA_BYTES + 1)
    except urllib.error.HTTPError as exc:
        error_type = (
            CheckpointArtifactTransportError
            if exc.code in TRANSIENT_HTTP_STATUS
            else CheckpointArtifactError
        )
        raise error_type("GitHub metadata request failed") from None
    except (OSError, urllib.error.URLError):
        raise CheckpointArtifactTransportError("GitHub metadata request failed") from None
    if len(payload) > MAX_METADATA_BYTES:
        raise CheckpointArtifactError("GitHub metadata response is too large")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CheckpointArtifactError("GitHub metadata response is invalid") from None
    if not isinstance(value, Mapping):
        raise CheckpointArtifactError("GitHub metadata response is invalid")
    return value


def _fetch_bounded(url: str, *, token: str) -> Mapping[str, Any]:
    for index, delay in enumerate(RETRY_DELAYS_SECONDS):
        if delay:
            time.sleep(delay)
        try:
            return _fetch_metadata(url, token=token)
        except CheckpointArtifactTransportError:
            if index + 1 == len(RETRY_DELAYS_SECONDS):
                raise _failure("github_transport_failure") from None
        except CheckpointArtifactError:
            raise _failure("github_response_invalid") from None
    raise _failure("github_transport_failure")


def _list_run_collection(
    *,
    repository: str,
    workflow_run_id: str,
    token: str,
    collection: str,
    query: str,
    invalid_class: str,
) -> list[Mapping[str, Any]]:
    expected_total: int | None = None
    rows: list[Mapping[str, Any]] = []
    separator = "&" if query else "?"
    for page in range(1, MAX_PAGES + 1):
        url = (
            f"{API_ROOT}/repos/{repository}/actions/runs/{workflow_run_id}/{collection}"
            f"{query}{separator}per_page={PER_PAGE}&page={page}"
        )
        payload = _fetch_bounded(url, token=token)
        total_count = payload.get("total_count")
        page_rows = payload.get(collection)
        if (
            not isinstance(total_count, int)
            or isinstance(total_count, bool)
            or total_count < 0
            or not isinstance(page_rows, list)
            or any(not isinstance(row, Mapping) for row in page_rows)
        ):
            raise _failure(invalid_class)
        if expected_total is None:
            expected_total = total_count
        elif total_count != expected_total:
            raise _failure(invalid_class)
        rows.extend(page_rows)
        if len(rows) >= total_count:
            break
        if not page_rows:
            raise _failure(invalid_class)
    else:
        raise _failure(invalid_class)
    if expected_total is None or len(rows) != expected_total:
        raise _failure(invalid_class)
    identities = [row.get("id") for row in rows]
    if any(
        not isinstance(identity, int) or isinstance(identity, bool) or identity <= 0
        for identity in identities
    ) or len(set(identities)) != len(identities):
        raise _failure(invalid_class)
    return rows


def _validate_review_run(
    metadata: Mapping[str, Any],
    *,
    repository: str,
    workflow_run_id: str,
    review_source_sha: str,
) -> None:
    source_repository = metadata.get("repository")
    head_repository = metadata.get("head_repository")
    if (
        str(metadata.get("id") or "") != workflow_run_id
        or metadata.get("head_sha") != review_source_sha
        or metadata.get("head_branch") != REVIEW_HEAD_BRANCH
        or metadata.get("path") != REVIEW_WORKFLOW_PATH
        or metadata.get("event") != REVIEW_EVENT
        or not isinstance(source_repository, Mapping)
        or source_repository.get("full_name") != repository
        or not isinstance(head_repository, Mapping)
        or head_repository.get("full_name") != repository
    ):
        raise _failure("review_run_identity_mismatch")
    if metadata.get("status") != "completed" or metadata.get("conclusion") != "success":
        raise _failure("review_run_not_successful")


def _validate_producer_job(
    jobs: Sequence[Mapping[str, Any]],
    *,
    workflow_run_id: str,
    review_source_sha: str,
) -> None:
    matches = [job for job in jobs if job.get("name") == PRODUCER_JOB]
    if not matches:
        raise _failure("producer_job_missing")
    if any(
        str(job.get("run_id") or "") != workflow_run_id or job.get("head_sha") != review_source_sha
        for job in matches
    ):
        raise _failure("producer_job_identity_mismatch")
    if not any(
        job.get("status") == "completed" and job.get("conclusion") == "success" for job in matches
    ):
        raise _failure("producer_job_not_successful")


def _resolve_exact_artifact(
    artifacts: Sequence[Mapping[str, Any]],
    *,
    repository: str,
    workflow_run_id: str,
    review_source_sha: str,
    token: str,
    name: str,
    failure_class: str,
) -> tuple[int, str]:
    matches = [
        artifact
        for artifact in artifacts
        if artifact.get("name") == name and artifact.get("expired") is False
    ]
    if len(matches) != 1:
        raise _failure(failure_class)
    listed = matches[0]
    artifact_id = listed.get("id")
    listed_digest = listed.get("digest")
    if (
        not isinstance(artifact_id, int)
        or isinstance(artifact_id, bool)
        or artifact_id <= 0
        or not isinstance(listed_digest, str)
        or _DIGEST_RE.fullmatch(listed_digest) is None
    ):
        raise _failure("artifact_metadata_mismatch")
    metadata = _fetch_bounded(
        f"{API_ROOT}/repos/{repository}/actions/artifacts/{artifact_id}",
        token=token,
    )
    try:
        exact_digest = _validate_metadata(
            metadata,
            repository=repository,
            artifact_id=artifact_id,
            expected_run_id=workflow_run_id,
            expected_source_sha=review_source_sha,
            expected_name=name,
        )
    except CheckpointArtifactError:
        raise _failure("artifact_metadata_mismatch") from None
    if f"sha256:{exact_digest}" != listed_digest:
        raise _failure("artifact_metadata_mismatch")
    return artifact_id, listed_digest


def _resolve_review_lineage(
    *,
    repository: str,
    workflow_run_id: str,
    review_source_sha: str,
    token: str,
) -> dict[str, str]:
    run_metadata = _fetch_bounded(
        f"{API_ROOT}/repos/{repository}/actions/runs/{workflow_run_id}",
        token=token,
    )
    _validate_review_run(
        run_metadata,
        repository=repository,
        workflow_run_id=workflow_run_id,
        review_source_sha=review_source_sha,
    )
    jobs = _list_run_collection(
        repository=repository,
        workflow_run_id=workflow_run_id,
        token=token,
        collection="jobs",
        query="?filter=all",
        invalid_class="review_job_listing_invalid",
    )
    _validate_producer_job(
        jobs,
        workflow_run_id=workflow_run_id,
        review_source_sha=review_source_sha,
    )
    artifacts = _list_run_collection(
        repository=repository,
        workflow_run_id=workflow_run_id,
        token=token,
        collection="artifacts",
        query="",
        invalid_class="review_artifact_listing_invalid",
    )
    expected = {
        "review": (
            f"range-v16-reviewed-{review_source_sha}",
            "reviewed_artifact_missing_or_ambiguous",
        ),
        "provenance": (
            f"range-v16-review-provenance-{review_source_sha}",
            "provenance_artifact_missing_or_ambiguous",
        ),
        "pair_author": (
            f"range-v16-pair-author-{review_source_sha}",
            "pair_author_artifact_missing_or_ambiguous",
        ),
    }
    resolved: dict[str, tuple[int, str]] = {}
    for key, (name, failure_class) in expected.items():
        resolved[key] = _resolve_exact_artifact(
            artifacts,
            repository=repository,
            workflow_run_id=workflow_run_id,
            review_source_sha=review_source_sha,
            token=token,
            name=name,
            failure_class=failure_class,
        )
    artifact_ids = [artifact_id for artifact_id, _ in resolved.values()]
    if len(set(artifact_ids)) != len(artifact_ids):
        raise _failure("artifact_identity_collision")
    return {
        "review_workflow_head_sha": review_source_sha,
        "review_artifact_id": str(resolved["review"][0]),
        "review_artifact_digest": resolved["review"][1],
        "review_provenance_artifact_id": str(resolved["provenance"][0]),
        "review_provenance_artifact_digest": resolved["provenance"][1],
        "pair_author_artifact_id": str(resolved["pair_author"][0]),
        "pair_author_artifact_digest": resolved["pair_author"][1],
    }


def _write_github_output(path: Path, outputs: Mapping[str, str]) -> None:
    for key, value in outputs.items():
        if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key) is None or "\n" in value or "\r" in value:
            raise _failure("github_output_invalid")
    try:
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            for key, value in outputs.items():
                stream.write(f"{key}={value}\n")
    except OSError:
        raise _failure("github_output_failed") from None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--review-source-sha", required=True)
    parser.add_argument("--truth-commit", required=True)
    parser.add_argument("--governance-commit", required=True)
    parser.add_argument("--scorer-commit", required=True)
    parser.add_argument("--workflow-head-sha", required=True)
    parser.add_argument("--workflow-head-branch", required=True)
    parser.add_argument("--workspace", type=Path, default=Path("."))
    parser.add_argument("--github-output", type=Path, required=True)
    return parser


def _main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if os.environ.get("Z_SCOPE_E0_REVIEW_ENVIRONMENT") != "sealed-benchmark":
        raise _failure("environment_mismatch")
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise _failure("github_token_missing")
    if _REPOSITORY_RE.fullmatch(args.repository) is None:
        raise _failure("repository_identity_invalid")
    if not str(args.workflow_run_id).isdigit() or int(args.workflow_run_id) <= 0:
        raise _failure("review_run_identity_invalid")
    sha_values = (
        args.review_source_sha,
        args.truth_commit,
        args.governance_commit,
        args.scorer_commit,
        args.workflow_head_sha,
    )
    if any(_SHA_RE.fullmatch(value) is None for value in sha_values):
        raise _failure("commit_identity_invalid")
    workspace = args.workspace.resolve()
    if not workspace.is_dir():
        raise _failure("workspace_invalid")
    _validate_git_lineage(
        workspace=workspace,
        workflow_head_sha=args.workflow_head_sha,
        workflow_head_branch=args.workflow_head_branch,
        truth_commit=args.truth_commit,
        governance_commit=args.governance_commit,
        scorer_commit=args.scorer_commit,
        review_source_sha=args.review_source_sha,
    )
    outputs = _resolve_review_lineage(
        repository=args.repository,
        workflow_run_id=str(args.workflow_run_id),
        review_source_sha=args.review_source_sha,
        token=token,
    )
    _write_github_output(args.github_output, outputs)
    print("preflight_status=verified")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return _main(argv)
    except AttestationPreflightFailure as exc:
        print(
            "::error title=E0 attestation preflight::"
            f"preflight_failure={exc.failure_class}; count=1"
        )
        return 1
    except Exception:
        print(
            "::error title=E0 attestation preflight::" "preflight_failure=internal_failure; count=1"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
