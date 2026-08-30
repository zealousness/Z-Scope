#!/usr/bin/env python3
"""Restore one exact immutable artifact from the protected P6 pilot run."""

from __future__ import annotations

import argparse
import io
import os
import re
import shutil
import stat
import tempfile
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath

if __package__:
    from scripts.download_e0_checkpoint_artifact import (
        _download_archive,
        _fetch_metadata,
        _validate_metadata,
    )
    from scripts.download_e0_run_artifacts import (
        _fetch_and_validate_source_run,
        _list_run_artifacts,
        _list_run_jobs,
        _retry_transport,
    )
else:
    from download_e0_checkpoint_artifact import (  # type: ignore[import-not-found,no-redef]
        _download_archive,
        _fetch_metadata,
        _validate_metadata,
    )
    from download_e0_run_artifacts import (  # type: ignore[import-not-found,no-redef]
        _fetch_and_validate_source_run,
        _list_run_artifacts,
        _list_run_jobs,
        _retry_transport,
    )

from zscope.benchmarking.p6_protocol import (
    P6ProtocolError,
    read_safe_zip,
    validate_safe_zip_bytes,
)


P6_WORKFLOW_PATH = ".github/workflows/p6-pilot-validation.yml"
P6_RECOVERY_WORKFLOW_PATH = ".github/workflows/p6-pilot-finalize-recovery.yml"
P6_EVENT = "workflow_dispatch"
P6_BRANCH = "main"
P6_PROTECTED_ENVIRONMENTS = frozenset(
    {
        "sealed-benchmark",
        "p6-review-product-architecture",
        "p6-review-proof-security",
        "p6-review-independent-benchmark",
    }
)


def _required_member(value: str) -> str:
    if "\\" in value:
        raise argparse.ArgumentTypeError("required member path is invalid")
    path = PurePosixPath(value)
    if not value or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise argparse.ArgumentTypeError("required member path is invalid")
    return path.as_posix()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True, type=int)
    parser.add_argument("--current-run-id")
    parser.add_argument("--current-run-attempt", type=int)
    parser.add_argument("--allow-prior-complete-checkpoint", action="store_true")
    parser.add_argument("--control-plane-commit", required=True)
    parser.add_argument("--current-control-plane-commit")
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--producer-job", required=True)
    parser.add_argument("--artifact-id", required=True, type=int)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--required-member", action="append", required=True, type=_required_member)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def _validate_arguments(args: argparse.Namespace) -> None:
    if os.environ.get("Z_SCOPE_P6_ENVIRONMENT") not in P6_PROTECTED_ENVIRONMENTS:
        raise P6ProtocolError("P6 artifact restore requires sealed-benchmark environment")
    current_run_id_arg = getattr(args, "current_run_id", None)
    current_attempt_arg = getattr(args, "current_run_attempt", None)
    if (current_run_id_arg is None) is not (current_attempt_arg is None):
        raise P6ProtocolError("P6 current recovery run identity is all-or-none")
    current_run_id = str(current_run_id_arg or args.run_id)
    current_attempt = current_attempt_arg or args.run_attempt
    current_control_plane_commit = getattr(args, "current_control_plane_commit", None)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        raise P6ProtocolError("P6 artifact repository identity is invalid")
    if (
        not str(args.run_id).isdigit()
        or not current_run_id.isdigit()
        or args.run_attempt < 1
        or current_attempt < 1
        or args.artifact_id <= 0
    ):
        raise P6ProtocolError("P6 artifact run or artifact identity is invalid")
    recovery_requested = current_run_id != str(args.run_id) or current_attempt > args.run_attempt
    if recovery_requested:
        if (
            current_run_id_arg is None
            or current_attempt_arg is None
            or getattr(args, "allow_prior_complete_checkpoint", False) is not True
            or not args.artifact_name.startswith("p6-complete-checkpoint-")
            or "checkpoint.json" not in args.required_member
            or re.fullmatch(r"[0-9a-f]{40}", str(current_control_plane_commit or "")) is None
        ):
            raise P6ProtocolError(
                "prior P6 attempts are restricted to explicit complete checkpoints"
            )
    elif getattr(args, "allow_prior_complete_checkpoint", False):
        raise P6ProtocolError("P6 prior-attempt recovery flag is unnecessary")
    elif current_control_plane_commit not in {None, args.control_plane_commit}:
        raise P6ProtocolError("P6 current control plane is only valid for recovery")
    if (
        re.fullmatch(r"[0-9a-f]{40}", args.control_plane_commit) is None
        or re.fullmatch(r"[0-9a-f]{40}", args.candidate_commit) is None
    ):
        raise P6ProtocolError("P6 artifact control-plane or candidate commit is invalid")
    if re.fullmatch(r"[A-Za-z0-9_.-]+", args.artifact_name) is None:
        raise P6ProtocolError("P6 artifact name is invalid")
    if not args.artifact_name.endswith(f"-{args.run_attempt}"):
        raise P6ProtocolError("P6 artifact name is not bound to the workflow attempt")
    if args.candidate_commit not in args.artifact_name:
        raise P6ProtocolError("P6 artifact name is not bound to the candidate commit")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", args.artifact_digest) is None:
        raise P6ProtocolError("P6 artifact external digest is invalid")
    if (
        not isinstance(args.producer_job, str)
        or not args.producer_job
        or len(args.producer_job) > 256
        or any(ord(character) < 32 for character in args.producer_job)
    ):
        raise P6ProtocolError("P6 artifact producer job identity is invalid")
    if len(set(args.required_member)) != len(args.required_member):
        raise P6ProtocolError("P6 artifact required members are not unique")
    output = args.output_dir.resolve()
    workspace = Path.cwd().resolve()
    try:
        output.relative_to(workspace)
    except ValueError as exc:
        raise P6ProtocolError("P6 artifact output escapes the workspace") from exc
    if output == workspace or output.exists() or args.output_dir.is_symlink():
        raise P6ProtocolError("P6 artifact output must be a new child directory")


def _extract_safe_zip_payload(
    payload: bytes, *, output: Path, required_members: Sequence[str]
) -> None:
    """Extract the exact bytes that passed digest and safe-ZIP validation."""

    validate_safe_zip_bytes(payload)
    required = {PurePosixPath(name) for name in required_members}
    if len(required) != len(required_members) or output.exists() or output.is_symlink():
        raise P6ProtocolError("P6 artifact extraction target or members are invalid")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".p6-artifact-", dir=output.parent))
    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as bundle:
            members: dict[PurePosixPath, zipfile.ZipInfo] = {}
            for info in bundle.infolist():
                relative = PurePosixPath(info.filename)
                canonical = PurePosixPath(relative.as_posix().rstrip("/"))
                if canonical in members:
                    raise P6ProtocolError("P6 artifact archive contains duplicate members")
                members[canonical] = info
            if not required.issubset(members):
                raise P6ProtocolError("P6 artifact archive is missing a required member")
            for relative, info in members.items():
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_IFMT(mode) == stat.S_IFLNK:
                    raise P6ProtocolError("P6 artifact archive contains a symbolic link")
                target = temporary.joinpath(*relative.parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(info, "r") as source, target.open("xb") as destination:
                    shutil.copyfileobj(source, destination, length=1024 * 1024)
        temporary.replace(output)
    except (OSError, zipfile.BadZipFile) as exc:
        raise P6ProtocolError("P6 artifact archive extraction failed") from exc
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def restore_exact_p6_artifact(args: argparse.Namespace, *, token: str) -> str:
    _validate_arguments(args)
    current_run_id = str(getattr(args, "current_run_id", None) or args.run_id)
    current_attempt = getattr(args, "current_run_attempt", None) or args.run_attempt
    current_control_plane_commit = (
        getattr(args, "current_control_plane_commit", None) or args.control_plane_commit
    )
    _fetch_and_validate_source_run(
        repository=args.repository,
        run_id=str(args.run_id),
        head_sha=args.control_plane_commit,
        workflow_path=P6_WORKFLOW_PATH,
        event=P6_EVENT,
        head_branch=P6_BRANCH,
        token=token,
    )
    run_metadata_url = f"https://api.github.com/repos/{args.repository}/actions/runs/{args.run_id}"
    run_metadata = _retry_transport(
        lambda: _fetch_metadata(run_metadata_url, token=token),
        failure="P6 workflow run metadata request failed after bounded retries",
    )
    source_metadata_attempt = (
        current_attempt if current_run_id == str(args.run_id) else args.run_attempt
    )
    if run_metadata.get("run_attempt") != source_metadata_attempt:
        raise P6ProtocolError("P6 workflow run attempt is invalid")
    if current_run_id != str(args.run_id):
        _fetch_and_validate_source_run(
            repository=args.repository,
            run_id=current_run_id,
            head_sha=current_control_plane_commit,
            workflow_path=P6_RECOVERY_WORKFLOW_PATH,
            event=P6_EVENT,
            head_branch=P6_BRANCH,
            token=token,
        )
        current_metadata_url = (
            f"https://api.github.com/repos/{args.repository}/actions/runs/{current_run_id}"
        )
        current_metadata = _retry_transport(
            lambda: _fetch_metadata(current_metadata_url, token=token),
            failure="P6 recovery workflow metadata request failed after bounded retries",
        )
        if current_metadata.get("run_attempt") != current_attempt:
            raise P6ProtocolError("P6 recovery workflow run attempt is invalid")
    listed = _list_run_artifacts(
        repository=args.repository,
        run_id=str(args.run_id),
        token=token,
    )
    matches = [row for row in listed if row.get("id") == args.artifact_id]
    if len(matches) != 1:
        raise P6ProtocolError("P6 exact artifact is absent or not unique in the source run")
    listed_row: Mapping[str, object] = matches[0]
    if (
        listed_row.get("name") != args.artifact_name
        or listed_row.get("expired") is not False
        or listed_row.get("digest") != args.artifact_digest
    ):
        raise P6ProtocolError("P6 listed artifact metadata is unbound")
    listed_workflow = listed_row.get("workflow_run")
    if isinstance(listed_workflow, Mapping) and listed_workflow.get("run_attempt") not in {
        None,
        args.run_attempt,
    }:
        raise P6ProtocolError("P6 listed artifact workflow attempt is unbound")
    jobs = _list_run_jobs(repository=args.repository, run_id=str(args.run_id), token=token)
    named_jobs = [job for job in jobs if job.get("name") == args.producer_job]
    if not named_jobs:
        raise P6ProtocolError("P6 artifact producer job is absent")
    matches = [
        job
        for job in named_jobs
        if str(job.get("run_id") or "") == str(args.run_id)
        and job.get("head_sha") == args.control_plane_commit
        and job.get("run_attempt") == args.run_attempt
    ]
    if len(matches) != 1:
        raise P6ProtocolError("P6 artifact producer job attempt is unbound")
    if not any(
        job.get("status") == "completed" and job.get("conclusion") == "success" for job in matches
    ):
        raise P6ProtocolError("P6 artifact producer job did not succeed")
    metadata_url = (
        f"https://api.github.com/repos/{args.repository}/actions/artifacts/{args.artifact_id}"
    )
    metadata = _retry_transport(
        lambda: _fetch_metadata(metadata_url, token=token),
        failure="P6 artifact metadata request failed after bounded retries",
    )
    metadata_workflow = metadata.get("workflow_run")
    if isinstance(metadata_workflow, Mapping) and metadata_workflow.get("run_attempt") not in {
        None,
        args.run_attempt,
    }:
        raise P6ProtocolError("P6 artifact metadata workflow attempt is unbound")
    expected_digest = _validate_metadata(
        metadata,
        repository=args.repository,
        artifact_id=args.artifact_id,
        expected_run_id=str(args.run_id),
        expected_source_sha=args.control_plane_commit,
        expected_name=args.artifact_name,
    )
    external = args.artifact_digest.removeprefix("sha256:")
    if expected_digest != external:
        raise P6ProtocolError("P6 artifact server and external digests differ")
    handle, archive_name = tempfile.mkstemp(prefix="p6-run-artifact-", suffix=".zip")
    os.close(handle)
    archive = Path(archive_name)
    archive.unlink()
    try:
        actual = _retry_transport(
            lambda: _download_archive(f"{metadata_url}/zip", token=token, output=archive),
            failure="P6 artifact archive download failed after bounded retries",
        )
        if not isinstance(actual, str) or re.fullmatch(r"[0-9a-f]{64}", actual) is None:
            raise P6ProtocolError("P6 artifact download digest is invalid")
        if actual != external:
            raise P6ProtocolError("P6 artifact downloaded digest is invalid")
        archive_payload, validated_digest = read_safe_zip(archive, expected_sha256=external)
        if validated_digest != actual:
            raise P6ProtocolError("P6 artifact validated digest is invalid")
        _extract_safe_zip_payload(
            archive_payload,
            output=args.output_dir.resolve(),
            required_members=tuple(args.required_member),
        )
    finally:
        archive.unlink(missing_ok=True)
    return actual


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    _validate_arguments(args)
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise P6ProtocolError("GITHUB_TOKEN is required")
    digest = restore_exact_p6_artifact(args, token=token)
    print(
        "restored immutable P6 artifact "
        f"artifact_id={args.artifact_id} run_id={args.run_id} "
        f"name={args.artifact_name} digest=sha256:{digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
