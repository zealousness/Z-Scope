#!/usr/bin/env python3
"""Download one immutable E0 checkpoint artifact with fail-closed bindings."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse


API_VERSION = "2022-11-28"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXTRACTED_BYTES = 128 * 1024 * 1024


class CheckpointArtifactError(ValueError):
    """Raised when immutable checkpoint recovery cannot be proven safe."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Mapping[str, str],
        newurl: str,
    ) -> None:
        return None


def _headers(token: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "zscope-e0-checkpoint-recovery",
        "X-GitHub-Api-Version": API_VERSION,
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_metadata(url: str, *, token: str) -> Mapping[str, Any]:
    request = urllib.request.Request(url, headers=_headers(token))
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = response.read(MAX_ARCHIVE_BYTES + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise CheckpointArtifactError("GitHub artifact metadata request failed") from exc
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise CheckpointArtifactError("GitHub artifact metadata response is too large")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CheckpointArtifactError("GitHub artifact metadata is not strict JSON") from exc
    if not isinstance(value, Mapping):
        raise CheckpointArtifactError("GitHub artifact metadata must be an object")
    return value


def _validate_metadata(
    metadata: Mapping[str, Any],
    *,
    repository: str,
    artifact_id: int,
    expected_run_id: str,
    expected_source_sha: str,
    expected_name: str,
) -> str:
    workflow_run = metadata.get("workflow_run")
    expected_archive_url = (
        f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}/zip"
    )
    digest = metadata.get("digest")
    if (
        metadata.get("id") != artifact_id
        or metadata.get("name") != expected_name
        or metadata.get("expired") is not False
        or not isinstance(metadata.get("size_in_bytes"), int)
        or isinstance(metadata.get("size_in_bytes"), bool)
        or int(metadata["size_in_bytes"]) <= 0
        or metadata.get("archive_download_url") != expected_archive_url
        or not isinstance(workflow_run, Mapping)
        or str(workflow_run.get("id") or "") != expected_run_id
        or workflow_run.get("head_sha") != expected_source_sha
        or not isinstance(digest, str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    ):
        raise CheckpointArtifactError("GitHub checkpoint artifact metadata is unbound")
    return str(digest).removeprefix("sha256:")


def _download_archive(url: str, *, token: str, output: Path) -> str:
    request = urllib.request.Request(url, headers=_headers(token))
    opener = urllib.request.build_opener(_NoRedirect)
    location: str | None = None
    try:
        response = opener.open(request, timeout=60)
    except urllib.error.HTTPError as exc:
        if exc.code not in {301, 302, 303, 307, 308}:
            raise CheckpointArtifactError(
                f"GitHub artifact download failed with HTTP {exc.code}"
            ) from exc
        location = exc.headers.get("Location")
        response = None
    except (OSError, urllib.error.URLError) as exc:
        raise CheckpointArtifactError("GitHub artifact download request failed") from exc

    if location is not None:
        parsed = urlparse(location)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise CheckpointArtifactError("GitHub artifact redirect is unsafe")
        signed_request = urllib.request.Request(
            location,
            headers={"User-Agent": "zscope-e0-checkpoint-recovery"},
        )
        try:
            response = urllib.request.urlopen(signed_request, timeout=60)
        except urllib.error.HTTPError as exc:
            raise CheckpointArtifactError(
                f"GitHub signed artifact download failed with HTTP {exc.code}"
            ) from exc
        except (OSError, urllib.error.URLError) as exc:
            raise CheckpointArtifactError("GitHub signed artifact download failed") from exc

    if response is None:
        raise CheckpointArtifactError("GitHub artifact download produced no response")
    digest = hashlib.sha256()
    size = 0
    try:
        with response, output.open("xb") as handle:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_ARCHIVE_BYTES:
                    raise CheckpointArtifactError("GitHub checkpoint artifact is too large")
                digest.update(chunk)
                handle.write(chunk)
    except OSError as exc:
        raise CheckpointArtifactError("GitHub checkpoint artifact could not be stored") from exc
    if size == 0:
        raise CheckpointArtifactError("GitHub checkpoint artifact is empty")
    return digest.hexdigest()


def _safe_member_path(name: str) -> PurePosixPath:
    if not name or "\\" in name:
        raise CheckpointArtifactError("checkpoint archive member path is invalid")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or any(not part for part in path.parts):
        raise CheckpointArtifactError("checkpoint archive member escapes the output directory")
    return path


def _extract_archive(archive: Path, *, output: Path) -> None:
    if output.exists():
        raise CheckpointArtifactError("checkpoint output directory already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".e0-checkpoint-", dir=output.parent))
    try:
        try:
            with zipfile.ZipFile(archive) as bundle:
                infos = bundle.infolist()
                if not infos or len({info.filename for info in infos}) != len(infos):
                    raise CheckpointArtifactError("checkpoint archive members are invalid")
                total_size = 0
                has_manifest = False
                for info in infos:
                    path = _safe_member_path(info.filename)
                    mode = (info.external_attr >> 16) & 0o170000
                    if mode == stat.S_IFLNK:
                        raise CheckpointArtifactError("checkpoint archive contains a symlink")
                    if not info.is_dir():
                        total_size += info.file_size
                        if total_size > MAX_EXTRACTED_BYTES:
                            raise CheckpointArtifactError(
                                "checkpoint archive expands beyond the size limit"
                            )
                    if path == PurePosixPath("checkpoint-manifest.json"):
                        has_manifest = True
                if not has_manifest:
                    raise CheckpointArtifactError("checkpoint archive manifest is missing")

                for info in infos:
                    relative = _safe_member_path(info.filename)
                    target = temporary.joinpath(*relative.parts)
                    if info.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.open(info) as source, target.open("xb") as destination:
                        shutil.copyfileobj(source, destination)
        except (OSError, zipfile.BadZipFile) as exc:
            raise CheckpointArtifactError("checkpoint artifact is not a valid ZIP archive") from exc
        temporary.replace(output)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--artifact-id", required=True, type=int)
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--expected-name", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if os.environ.get("Z_SCOPE_E0_REVIEW_ENVIRONMENT") != "sealed-benchmark":
        raise CheckpointArtifactError("checkpoint download requires sealed-benchmark environment")
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise CheckpointArtifactError("GITHUB_TOKEN is required")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        raise CheckpointArtifactError("GitHub repository identity is invalid")
    if args.artifact_id <= 0 or not str(args.expected_run_id).isdigit():
        raise CheckpointArtifactError("GitHub artifact or run identity is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", args.expected_source_sha):
        raise CheckpointArtifactError("GitHub artifact source SHA is invalid")

    metadata_url = (
        f"https://api.github.com/repos/{args.repository}/actions/artifacts/{args.artifact_id}"
    )
    archive_url = f"{metadata_url}/zip"
    metadata = _fetch_metadata(metadata_url, token=token)
    expected_digest = _validate_metadata(
        metadata,
        repository=args.repository,
        artifact_id=args.artifact_id,
        expected_run_id=str(args.expected_run_id),
        expected_source_sha=args.expected_source_sha,
        expected_name=args.expected_name,
    )
    handle, archive_name = tempfile.mkstemp(prefix="e0-checkpoint-", suffix=".zip")
    os.close(handle)
    archive = Path(archive_name)
    archive.unlink()
    try:
        actual_digest = _download_archive(archive_url, token=token, output=archive)
        if actual_digest != expected_digest:
            raise CheckpointArtifactError("GitHub checkpoint artifact digest mismatch")
        _extract_archive(archive, output=args.output_dir.resolve())
    finally:
        archive.unlink(missing_ok=True)
    print(
        "restored immutable checkpoint "
        f"artifact_id={args.artifact_id} run_id={args.expected_run_id} "
        f"source_sha={args.expected_source_sha} digest=sha256:{actual_digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
