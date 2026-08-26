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
PER_PAGE = 100
RETRY_DELAYS_SECONDS = (0.0, 1.0, 3.0, 7.0)
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


def _download_and_extract(
    *,
    repository: str,
    artifact_id: int,
    run_id: str,
    head_sha: str,
    expected_name: str,
    token: str,
    output: Path,
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
        _extract_archive(
            archive,
            output=output,
            required_members=("manifest.json",),
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
        required=True,
        metavar="NAME=OUTPUT_DIR",
    )
    parser.add_argument(
        "--optional-artifact",
        action="append",
        default=[],
        metavar="NAME=OUTPUT_DIR",
    )
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
    required_specs = [_parse_artifact_spec(value, workspace=workspace) for value in args.artifact]
    optional_specs = [
        _parse_artifact_spec(value, workspace=workspace) for value in args.optional_artifact
    ]
    specs = [*required_specs, *optional_specs]
    names = [name for name, _ in specs]
    outputs = [output for _, output in specs]
    if len(set(names)) != len(names) or len(set(outputs)) != len(outputs):
        raise RunArtifactError("artifact restoration specifications are not unique")
    if any(output.exists() for output in outputs):
        raise RunArtifactError("artifact restoration output already exists")

    listed = _list_run_artifacts(
        repository=args.repository,
        run_id=str(args.expected_run_id),
        token=token,
    )
    resolved: dict[str, int] = {}
    for expected_name, _ in required_specs:
        matches = [artifact for artifact in listed if artifact.get("name") == expected_name]
        if len(matches) != 1:
            raise RunArtifactError("expected immutable run artifact is not unique")
        artifact_id = matches[0].get("id")
        if not isinstance(artifact_id, int) or isinstance(artifact_id, bool):
            raise RunArtifactError("expected immutable run artifact identity is invalid")
        resolved[expected_name] = artifact_id
    for expected_name, _ in optional_specs:
        matches = [artifact for artifact in listed if artifact.get("name") == expected_name]
        if len(matches) > 1:
            raise RunArtifactError("optional immutable run artifact is not unique")
        if matches:
            artifact_id = matches[0].get("id")
            if not isinstance(artifact_id, int) or isinstance(artifact_id, bool):
                raise RunArtifactError("optional immutable run artifact identity is invalid")
            resolved[expected_name] = artifact_id

    temporary = Path(tempfile.mkdtemp(prefix=".e0-run-artifacts-", dir=workspace))
    restored: list[tuple[str, int, str, Path]] = []
    try:
        selected_specs = [(name, output) for name, output in specs if name in resolved]
        for index, (name, output) in enumerate(selected_specs):
            temporary_output = temporary / str(index)
            artifact_id = resolved[name]
            digest = _download_and_extract(
                repository=args.repository,
                artifact_id=artifact_id,
                run_id=str(args.expected_run_id),
                head_sha=args.expected_head_sha,
                expected_name=name,
                token=token,
                output=temporary_output,
            )
            restored.append((name, artifact_id, digest, output))
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
    for name, _ in optional_specs:
        if name not in resolved:
            print(f"optional immutable run artifact absent name={name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
