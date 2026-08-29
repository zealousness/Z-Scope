#!/usr/bin/env python3
"""Restore exact immutable artifacts from one protected E0 workflow run."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import TypeVar

if __package__:
    from scripts.download_e0_checkpoint_artifact import (
        CheckpointArtifactError,
        CheckpointArtifactTransportError,
        _download_archive,
        _extract_archive,
        _fetch_metadata,
        _validate_metadata,
    )
else:
    from download_e0_checkpoint_artifact import (  # type: ignore[import-not-found, no-redef]
        CheckpointArtifactError,
        CheckpointArtifactTransportError,
        _download_archive,
        _extract_archive,
        _fetch_metadata,
        _validate_metadata,
    )


MAX_ARTIFACT_PAGES = 10
MAX_JOB_PAGES = 10
PER_PAGE = 100
RETRY_DELAYS_SECONDS = (0.0, 1.0, 3.0, 7.0)
E0_REVIEW_WORKFLOW_PATH = ".github/workflows/range-v16-review.yml"
E0_REVIEW_EVENT = "workflow_dispatch"
E0_REVIEW_HEAD_BRANCH = "main"
_T = TypeVar("_T")


class RunArtifactError(CheckpointArtifactError):
    """Raised when exact same-run artifact restoration cannot be proven safe."""


def _retry_transport(operation: Callable[[], _T], *, failure: str) -> _T:
    last_error: CheckpointArtifactTransportError | None = None
    for delay in RETRY_DELAYS_SECONDS:
        if delay:
            time.sleep(delay)
        try:
            return operation()
        except CheckpointArtifactTransportError as exc:
            last_error = exc
    raise RunArtifactError(failure) from last_error


def _list_run_artifacts(*, repository: str, run_id: str, token: str) -> list[Mapping[str, object]]:
    base_url = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/artifacts"
    expected_total: int | None = None
    artifacts: list[Mapping[str, object]] = []
    for page in range(1, MAX_ARTIFACT_PAGES + 1):
        url = f"{base_url}?per_page={PER_PAGE}&page={page}"

        def fetch_page() -> Mapping[str, object]:
            return _fetch_metadata(url, token=token)

        payload = _retry_transport(
            fetch_page,
            failure="GitHub run artifact listing failed after bounded retries",
        )
        total_count = payload.get("total_count")
        page_artifacts = payload.get("artifacts")
        if (
            not isinstance(total_count, int)
            or isinstance(total_count, bool)
            or total_count < 0
            or not isinstance(page_artifacts, list)
            or any(not isinstance(row, Mapping) for row in page_artifacts)
        ):
            raise RunArtifactError("GitHub run artifact listing is malformed")
        if expected_total is None:
            expected_total = total_count
        elif total_count != expected_total:
            raise RunArtifactError("GitHub run artifact listing changed during recovery")
        artifacts.extend(page_artifacts)
        if len(artifacts) >= total_count:
            break
        if not page_artifacts:
            raise RunArtifactError("GitHub run artifact listing is incomplete")
    else:
        raise RunArtifactError("GitHub run artifact listing exceeds the page limit")

    if expected_total is None or len(artifacts) != expected_total:
        raise RunArtifactError("GitHub run artifact listing count is inconsistent")
    artifact_ids: list[int] = []
    for artifact in artifacts:
        artifact_id = artifact.get("id")
        if not isinstance(artifact_id, int) or isinstance(artifact_id, bool) or artifact_id <= 0:
            raise RunArtifactError("GitHub run artifact identity is malformed")
        artifact_ids.append(artifact_id)
    if len(set(artifact_ids)) != len(artifact_ids):
        raise RunArtifactError("GitHub run artifact listing contains duplicate identities")
    return artifacts


def _validate_source_run(
    metadata: Mapping[str, object],
    *,
    repository: str,
    run_id: str,
    head_sha: str,
    workflow_path: str,
    event: str,
    head_branch: str,
) -> None:
    source_repository = metadata.get("repository")
    if (
        str(metadata.get("id") or "") != run_id
        or metadata.get("head_sha") != head_sha
        or metadata.get("path") != workflow_path
        or metadata.get("event") != event
        or metadata.get("head_branch") != head_branch
        or not isinstance(source_repository, Mapping)
        or source_repository.get("full_name") != repository
    ):
        raise RunArtifactError("GitHub source workflow run metadata is unbound")


def _fetch_and_validate_source_run(
    *,
    repository: str,
    run_id: str,
    head_sha: str,
    workflow_path: str,
    event: str,
    head_branch: str,
    token: str,
) -> None:
    url = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
    metadata = _retry_transport(
        lambda: _fetch_metadata(url, token=token),
        failure="GitHub source workflow run request failed after bounded retries",
    )
    _validate_source_run(
        metadata,
        repository=repository,
        run_id=run_id,
        head_sha=head_sha,
        workflow_path=workflow_path,
        event=event,
        head_branch=head_branch,
    )


def _list_run_jobs(*, repository: str, run_id: str, token: str) -> list[Mapping[str, object]]:
    base_url = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/jobs"
    expected_total: int | None = None
    jobs: list[Mapping[str, object]] = []
    for page in range(1, MAX_JOB_PAGES + 1):
        url = f"{base_url}?filter=all&per_page={PER_PAGE}&page={page}"
        payload = _retry_transport(
            lambda: _fetch_metadata(url, token=token),
            failure="GitHub source workflow job listing failed after bounded retries",
        )
        total_count = payload.get("total_count")
        page_jobs = payload.get("jobs")
        if (
            not isinstance(total_count, int)
            or isinstance(total_count, bool)
            or total_count < 0
            or not isinstance(page_jobs, list)
            or any(not isinstance(row, Mapping) for row in page_jobs)
        ):
            raise RunArtifactError("GitHub source workflow job listing is malformed")
        if expected_total is None:
            expected_total = total_count
        elif total_count != expected_total:
            raise RunArtifactError("GitHub source workflow job listing changed during recovery")
        jobs.extend(page_jobs)
        if len(jobs) >= total_count:
            break
        if not page_jobs:
            raise RunArtifactError("GitHub source workflow job listing is incomplete")
    else:
        raise RunArtifactError("GitHub source workflow job listing exceeds the page limit")

    if expected_total is None or len(jobs) != expected_total:
        raise RunArtifactError("GitHub source workflow job listing count is inconsistent")
    job_ids: list[int] = []
    for job in jobs:
        job_id = job.get("id")
        if not isinstance(job_id, int) or isinstance(job_id, bool) or job_id <= 0:
            raise RunArtifactError("GitHub source workflow job identity is malformed")
        job_ids.append(job_id)
    if len(set(job_ids)) != len(job_ids):
        raise RunArtifactError("GitHub source workflow job listing contains duplicate identities")
    return jobs


def _validate_producer_job(
    jobs: Sequence[Mapping[str, object]],
    *,
    expected_name: str,
    run_id: str,
    head_sha: str,
) -> None:
    matches = [job for job in jobs if job.get("name") == expected_name]
    if not matches:
        raise RunArtifactError("GitHub artifact producer job is absent")
    for job in matches:
        if str(job.get("run_id") or "") != run_id or job.get("head_sha") != head_sha:
            raise RunArtifactError("GitHub artifact producer job metadata is unbound")
    if not any(
        job.get("status") == "completed" and job.get("conclusion") == "success" for job in matches
    ):
        raise RunArtifactError("GitHub artifact producer job did not succeed")


def _parse_artifact_spec(value: str, *, workspace: Path) -> tuple[str, Path]:
    name, separator, output_value = value.partition("=")
    if (
        separator != "="
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", name)
        or not output_value
        or "\\" in output_value
    ):
        raise RunArtifactError("artifact restoration specification is invalid")
    relative = PurePosixPath(output_value)
    if relative.is_absolute() or ".." in relative.parts or any(not part for part in relative.parts):
        raise RunArtifactError("artifact restoration output path is invalid")
    output = (workspace / Path(*relative.parts)).resolve()
    try:
        output.relative_to(workspace)
    except ValueError as exc:
        raise RunArtifactError("artifact restoration output escapes the workspace") from exc
    if output == workspace:
        raise RunArtifactError("artifact restoration output cannot be the workspace")
    return name, output


def _parse_exact_artifact_spec(value: str, *, workspace: Path) -> tuple[str, Path, int, str]:
    parts = value.split("=")
    if len(parts) != 4:
        raise RunArtifactError("exact artifact restoration specification is invalid")
    name, output_value, artifact_id_value, digest = parts
    name, output = _parse_artifact_spec(f"{name}={output_value}", workspace=workspace)
    if (
        not artifact_id_value.isdigit()
        or int(artifact_id_value) <= 0
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
    ):
        raise RunArtifactError("exact artifact immutable binding is invalid")
    return name, output, int(artifact_id_value), digest.removeprefix("sha256:")


def _checkpoint_prefix_matches(artifact: Mapping[str, object], *, prefix: str) -> bool:
    name = artifact.get("name")
    return (
        isinstance(name, str)
        and re.fullmatch(rf"{re.escape(prefix)}-attempt-[1-9][0-9]*", name) is not None
    )


def _latest_nonexpired_optional(
    matches: Sequence[Mapping[str, object]],
) -> Mapping[str, object] | None:
    candidates: list[tuple[str, int, Mapping[str, object]]] = []
    for artifact in matches:
        artifact_id = artifact.get("id")
        expired = artifact.get("expired")
        created_at = artifact.get("created_at")
        if (
            not isinstance(artifact_id, int)
            or isinstance(artifact_id, bool)
            or artifact_id <= 0
            or not isinstance(expired, bool)
            or not isinstance(created_at, str)
            or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", created_at) is None
        ):
            raise RunArtifactError("optional run artifact selection metadata is malformed")
        if not expired:
            candidates.append((created_at, artifact_id, artifact))
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item[0], item[1]))[2]


def _download_and_extract(
    *,
    repository: str,
    artifact_id: int,
    run_id: str,
    head_sha: str,
    expected_name: str,
    token: str,
    output: Path,
    required_members: Sequence[str] = ("manifest.json",),
    external_digest: str | None = None,
) -> str:
    metadata_url = f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}"
    metadata = _retry_transport(
        lambda: _fetch_metadata(metadata_url, token=token),
        failure="GitHub artifact metadata request failed after bounded retries",
    )
    expected_digest = _validate_metadata(
        metadata,
        repository=repository,
        artifact_id=artifact_id,
        expected_run_id=run_id,
        expected_source_sha=head_sha,
        expected_name=expected_name,
    )
    if external_digest is not None and expected_digest != external_digest:
        raise RunArtifactError("GitHub run artifact external digest binding mismatch")
    handle, archive_name = tempfile.mkstemp(prefix="e0-run-artifact-", suffix=".zip")
    os.close(handle)
    archive = Path(archive_name)
    archive.unlink()

    def download() -> str:
        archive.unlink(missing_ok=True)
        return str(_download_archive(f"{metadata_url}/zip", token=token, output=archive))

    try:
        actual_digest = _retry_transport(
            download,
            failure="GitHub artifact archive download failed after bounded retries",
        )
        if actual_digest != expected_digest:
            raise RunArtifactError("GitHub run artifact digest mismatch")
        if external_digest is not None and actual_digest != external_digest:
            raise RunArtifactError("GitHub run artifact external digest mismatch")
        _extract_archive(
            archive,
            output=output,
            required_members=required_members,
        )
    finally:
        archive.unlink(missing_ok=True)
    return actual_digest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--expected-head-sha", required=True)
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="NAME=OUTPUT_DIR",
    )
    parser.add_argument(
        "--optional-artifact",
        action="append",
        default=[],
        metavar="NAME=OUTPUT_DIR",
    )
    parser.add_argument(
        "--optional-checkpoint-artifact",
        action="append",
        default=[],
        metavar="NAME=OUTPUT_DIR",
    )
    parser.add_argument(
        "--optional-checkpoint-prefix",
        action="append",
        default=[],
        metavar="PREFIX=OUTPUT_DIR",
    )
    parser.add_argument(
        "--exact-artifact",
        action="append",
        default=[],
        metavar="NAME=OUTPUT_DIR=ID=sha256:HEX",
    )
    parser.add_argument("--expected-workflow-path")
    parser.add_argument("--expected-event")
    parser.add_argument("--expected-head-branch")
    parser.add_argument("--expected-producer-job")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if os.environ.get("Z_SCOPE_E0_REVIEW_ENVIRONMENT") != "sealed-benchmark":
        raise RunArtifactError("artifact download requires sealed-benchmark environment")
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RunArtifactError("GITHUB_TOKEN is required")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        raise RunArtifactError("GitHub repository identity is invalid")
    if not str(args.expected_run_id).isdigit():
        raise RunArtifactError("GitHub workflow run identity is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", args.expected_head_sha):
        raise RunArtifactError("GitHub workflow head SHA is invalid")

    workspace = Path.cwd().resolve()
    exact_specs = [
        _parse_exact_artifact_spec(value, workspace=workspace) for value in args.exact_artifact
    ]
    required_specs = [_parse_artifact_spec(value, workspace=workspace) for value in args.artifact]
    optional_specs = [
        _parse_artifact_spec(value, workspace=workspace) for value in args.optional_artifact
    ]
    optional_checkpoint_specs = [
        _parse_artifact_spec(value, workspace=workspace)
        for value in args.optional_checkpoint_artifact
    ]
    optional_checkpoint_prefix_specs = [
        _parse_artifact_spec(value, workspace=workspace)
        for value in args.optional_checkpoint_prefix
    ]
    listed_mode = bool(
        required_specs
        or optional_specs
        or optional_checkpoint_specs
        or optional_checkpoint_prefix_specs
    )
    exact_mode = bool(exact_specs)
    if listed_mode == exact_mode:
        raise RunArtifactError(
            "choose exactly one of name-list or exact immutable artifact restoration"
        )
    external_expectations = (
        args.expected_workflow_path,
        args.expected_event,
        args.expected_head_branch,
        args.expected_producer_job,
    )
    if exact_mode:
        if (
            args.expected_workflow_path != E0_REVIEW_WORKFLOW_PATH
            or args.expected_event != E0_REVIEW_EVENT
            or args.expected_head_branch != E0_REVIEW_HEAD_BRANCH
            or not isinstance(args.expected_producer_job, str)
            or not args.expected_producer_job
            or len(args.expected_producer_job) > 256
            or any(ord(character) < 32 for character in args.expected_producer_job)
        ):
            raise RunArtifactError("exact artifact source workflow binding is invalid")
    elif any(value is not None for value in external_expectations):
        raise RunArtifactError("source workflow bindings require exact artifact restoration")

    specs = [
        *[(name, output) for name, output, _, _ in exact_specs],
        *required_specs,
        *optional_specs,
        *optional_checkpoint_specs,
        *optional_checkpoint_prefix_specs,
    ]
    names = [name for name, _ in specs]
    outputs = [output for _, output in specs]
    if len(set(names)) != len(names) or len(set(outputs)) != len(outputs):
        raise RunArtifactError("artifact restoration specifications are not unique")
    if any(output.exists() for output in outputs):
        raise RunArtifactError("artifact restoration output already exists")

    resolved: dict[str, tuple[int, str | None, str]] = {}
    if exact_mode:
        _fetch_and_validate_source_run(
            repository=args.repository,
            run_id=str(args.expected_run_id),
            head_sha=args.expected_head_sha,
            workflow_path=args.expected_workflow_path,
            event=args.expected_event,
            head_branch=args.expected_head_branch,
            token=token,
        )
        jobs = _list_run_jobs(
            repository=args.repository,
            run_id=str(args.expected_run_id),
            token=token,
        )
        _validate_producer_job(
            jobs,
            expected_name=args.expected_producer_job,
            run_id=str(args.expected_run_id),
            head_sha=args.expected_head_sha,
        )
        for name, _, artifact_id, digest in exact_specs:
            resolved[name] = (artifact_id, digest, name)
    else:
        listed = _list_run_artifacts(
            repository=args.repository,
            run_id=str(args.expected_run_id),
            token=token,
        )
        for expected_name, _ in required_specs:
            matches = [artifact for artifact in listed if artifact.get("name") == expected_name]
            if len(matches) != 1:
                raise RunArtifactError("expected immutable run artifact is not unique")
            artifact_id = matches[0].get("id")
            if not isinstance(artifact_id, int) or isinstance(artifact_id, bool):
                raise RunArtifactError("expected immutable run artifact identity is invalid")
            resolved[expected_name] = (artifact_id, None, expected_name)
        for expected_name, _ in [*optional_specs, *optional_checkpoint_specs]:
            matches = [artifact for artifact in listed if artifact.get("name") == expected_name]
            selected = _latest_nonexpired_optional(matches)
            if selected is not None:
                artifact_id = selected.get("id")
                if not isinstance(artifact_id, int) or isinstance(artifact_id, bool):
                    raise RunArtifactError("optional immutable run artifact identity is invalid")
                resolved[expected_name] = (artifact_id, None, expected_name)
        for prefix, _ in optional_checkpoint_prefix_specs:
            matches = [
                artifact
                for artifact in listed
                if _checkpoint_prefix_matches(artifact, prefix=prefix)
            ]
            selected = _latest_nonexpired_optional(matches)
            if selected is not None:
                artifact_id = selected.get("id")
                selected_name = selected.get("name")
                if (
                    not isinstance(artifact_id, int)
                    or isinstance(artifact_id, bool)
                    or not isinstance(selected_name, str)
                ):
                    raise RunArtifactError(
                        "optional checkpoint prefix artifact identity is invalid"
                    )
                resolved[prefix] = (artifact_id, None, selected_name)

    temporary = Path(tempfile.mkdtemp(prefix=".e0-run-artifacts-", dir=workspace))
    restored: list[tuple[str, int, str, Path]] = []
    try:
        checkpoint_names = {
            name
            for name, _ in [
                *optional_checkpoint_specs,
                *optional_checkpoint_prefix_specs,
            ]
        }
        selected_specs = [
            (
                name,
                output,
                (("checkpoint-manifest.json",) if name in checkpoint_names else ("manifest.json",)),
            )
            for name, output in specs
            if name in resolved
        ]
        for index, (name, output, required_members) in enumerate(selected_specs):
            temporary_output = temporary / str(index)
            artifact_id, external_digest, expected_name = resolved[name]
            digest = _download_and_extract(
                repository=args.repository,
                artifact_id=artifact_id,
                run_id=str(args.expected_run_id),
                head_sha=args.expected_head_sha,
                expected_name=expected_name,
                token=token,
                output=temporary_output,
                required_members=required_members,
                external_digest=external_digest,
            )
            restored.append((expected_name, artifact_id, digest, output))
        for _, _, _, output in restored:
            output.parent.mkdir(parents=True, exist_ok=True)
        for index, (_, _, _, output) in enumerate(restored):
            (temporary / str(index)).replace(output)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)

    for name, artifact_id, digest, _ in restored:
        print(
            "restored immutable run artifact "
            f"artifact_id={artifact_id} run_id={args.expected_run_id} "
            f"name={name} digest=sha256:{digest}"
        )
    for name, _ in [*optional_specs, *optional_checkpoint_specs]:
        if name not in resolved:
            print(f"optional immutable run artifact absent name={name}")
    for prefix, _ in optional_checkpoint_prefix_specs:
        if prefix not in resolved:
            print(f"optional immutable run artifact absent prefix={prefix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
