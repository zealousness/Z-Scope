#!/usr/bin/env python3
"""Project or check physical current-successor review evidence."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Mapping, Sequence

if __package__:
    from scripts.download_e0_checkpoint_artifact import _fetch_metadata
    from scripts.download_e0_run_artifacts import _retry_transport
    from scripts.download_p6_run_artifact import restore_exact_p6_artifact
else:
    from download_e0_checkpoint_artifact import _fetch_metadata  # type: ignore[import-not-found]
    from download_e0_run_artifacts import _retry_transport  # type: ignore[import-not-found]
    from download_p6_run_artifact import (  # type: ignore[import-not-found]
        restore_exact_p6_artifact,
    )

from zscope.benchmarking.p6_protocol import P6ProtocolError, load_json_strict
from zscope.benchmarking.p6_review import REVIEW_ROLES, ROLE_REVIEW_MATERIAL_PATHS
from zscope.orchestration.proof_promotion_qualification import (
    P6_PROOF_PROMOTION_QUALIFICATION_RESOURCE,
    load_successor_qualification,
    validate_successor_freshness,
)
from zscope.orchestration.successor_review_evidence import (
    SUCCESSOR_REVIEW_EVIDENCE_DIRECTORY,
    project_successor_runtime_review_status,
)
from zscope.orchestration import successor_review_evidence as evidence_contract
from zscope.orchestration.successor_review_integration import (
    SUCCESSOR_REVIEW_ALLOWED_EXACT_PATHS,
    SUCCESSOR_REVIEW_ALLOWED_PREFIXES,
    SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_RESOURCE,
    build_successor_review_integration_receipt,
    validate_successor_review_integration_receipt,
    validate_successor_review_integration_scope,
)
from zscope.orchestration.successor_runtime_review_status import (
    SUCCESSOR_RUNTIME_REVIEW_STATUS_RESOURCE,
    validate_successor_runtime_review_status,
)


ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATION_ROOT = ROOT / "zscope" / "orchestration"
_ONLINE_REQUIRED_MEMBERS = {
    "qualification": ("qualification.json",),
    "product_architecture": (
        "packet/packet.json",
        "review/decision.json",
        "review/raw-envelope.json",
    ),
    "proof_security": (
        "packet/packet.json",
        "review/decision.json",
        "review/raw-envelope.json",
    ),
    "independent_benchmark": (
        "packet/packet.json",
        "review/decision.json",
        "review/raw-envelope.json",
    ),
    "final_evidence": (
        "final-evidence-manifest.json",
        "complete-checkpoint/payload/final-evidence-manifest.json",
    ),
}


def _write_new_json(path: Path, value: object) -> None:
    path = path.resolve()
    if path.exists():
        raise ValueError("successor_review_projection_output_exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    ).stdout.strip()


def _git_bytes(root: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout


def _parse_name_status_z(payload: bytes) -> tuple[tuple[str, str], ...]:
    """Parse the only Git diff form accepted by the evidence-only gate."""

    if not payload:
        return ()
    fields = payload.split(b"\0")
    if fields[-1] != b"" or (len(fields) - 1) % 2:
        raise ValueError("successor_review_git_diff_malformed")
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()
    for index in range(0, len(fields) - 1, 2):
        try:
            status = fields[index].decode("ascii", errors="strict")
            path = fields[index + 1].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("successor_review_git_diff_malformed") from exc
        if status not in {"A", "M", "D"} or not path or path in seen:
            raise ValueError("successor_review_git_diff_malformed")
        seen.add(path)
        rows.append((status, path))
    return tuple(rows)


def _git_diff_entries(root: Path, old: str, new: str) -> tuple[tuple[str, str], ...]:
    return _parse_name_status_z(
        _git_bytes(
            root,
            "diff",
            "--no-renames",
            "--name-status",
            "-z",
            old,
            new,
            "--",
        )
    )


def _is_review_resource(path: str) -> bool:
    return path in SUCCESSOR_REVIEW_ALLOWED_EXACT_PATHS or path.startswith(
        SUCCESSOR_REVIEW_ALLOWED_PREFIXES
    )


def _review_resources_changed(root: Path, *, base: str, head: str) -> bool:
    return any(_is_review_resource(path) for _, path in _git_diff_entries(root, base, head))


def _validate_candidate_material(root: Path, *, bundle_root: Path, status: dict) -> None:
    candidate = str(status["candidate_git_sha"])
    if _git(root, "rev-parse", f"{candidate}^{{tree}}") != status["candidate_git_tree"]:
        raise ValueError("successor_review_candidate_tree_mismatch")
    for role in REVIEW_ROLES:
        material_root = bundle_root / "candidate-material" / role
        for relative in ROLE_REVIEW_MATERIAL_PATHS[role]:
            snapshot = material_root.joinpath(*relative.split("/"))
            if snapshot.is_symlink() or not snapshot.is_file():
                raise ValueError("successor_review_candidate_material_unavailable")
            if snapshot.read_bytes() != _git_bytes(root, "show", f"{candidate}:{relative}"):
                raise ValueError("successor_review_candidate_material_mismatch")


def _validate_git_scope(root: Path, *, status: dict, head: str) -> None:
    base = str(status["candidate_git_sha"])
    merge_base = _git(root, "merge-base", base, head)
    base_tree = _git(root, "rev-parse", f"{base}^{{tree}}")
    commits = tuple(
        filter(None, _git(root, "rev-list", "--reverse", f"{base}..{head}").splitlines())
    )
    parent_counts: list[int] = []
    touched: dict[str, str] = {}
    for commit in commits:
        ancestry = _git(root, "rev-list", "--parents", "-n", "1", commit).split()
        parent_counts.append(len(ancestry) - 1)
        if len(ancestry) == 2:
            for status_value, path in _git_diff_entries(root, ancestry[1], ancestry[0]):
                # Multiple commits touching one allowed path are legitimate,
                # but every intermediate status and path remains inspected.
                touched[path] = status_value
    final_entries = _git_diff_entries(root, base, head)
    valid, reason = validate_successor_review_integration_scope(
        reviewed_candidate_git_sha=base,
        reviewed_candidate_git_tree=str(status["candidate_git_tree"]),
        merge_base_git_sha=merge_base,
        base_git_tree=base_tree,
        ancestry_parent_counts=parent_counts,
        changed_entries=final_entries,
        touched_entries=tuple((status_value, path) for path, status_value in touched.items()),
    )
    if not valid:
        raise ValueError(reason)


def _validate_successful_source_run(manifest: Mapping[str, object], *, token: str) -> None:
    repository = str(manifest["repository"])
    run_id = str(manifest["workflow_run_id"])
    url = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
    metadata = _retry_transport(
        lambda: _fetch_metadata(url, token=token),
        failure="successor review workflow metadata request failed after bounded retries",
    )
    if (
        not isinstance(metadata, Mapping)
        or str(metadata.get("id") or "") != run_id
        or metadata.get("run_attempt") != manifest["workflow_run_attempt"]
        or metadata.get("status") != "completed"
        or metadata.get("conclusion") != "success"
    ):
        raise P6ProtocolError("successor review workflow run did not succeed")


def _validate_authoritative_artifacts_online(
    bundle_root: Path,
    *,
    token: str,
    workspace_root: Path,
) -> None:
    """Restore each immutable GitHub artifact and compare the physical trees."""

    manifest = load_json_strict(bundle_root / evidence_contract.SUCCESSOR_REVIEW_EVIDENCE_MANIFEST)
    if not isinstance(manifest, Mapping):
        raise P6ProtocolError("successor review evidence manifest is invalid")
    evidence_contract._validate_bundle_manifest(manifest)
    metadata = evidence_contract._validate_artifact_metadata(manifest)
    _validate_successful_source_run(manifest, token=token)
    workspace_root = workspace_root.resolve()
    if Path.cwd().resolve() != workspace_root:
        raise ValueError("successor_review_online_workspace_mismatch")
    with tempfile.TemporaryDirectory(
        prefix=".successor-review-online-", dir=workspace_root
    ) as temporary_value:
        temporary = Path(temporary_value)
        for key in evidence_contract._ARTIFACT_KEYS:
            row = metadata[key]
            output = temporary / key
            args = argparse.Namespace(
                repository=str(row["repository"]),
                run_id=str(row["workflow_run_id"]),
                run_attempt=int(row["workflow_run_attempt"]),
                current_run_id=None,
                current_run_attempt=None,
                allow_prior_complete_checkpoint=False,
                control_plane_commit=str(row["head_sha"]),
                current_control_plane_commit=None,
                candidate_commit=str(manifest["candidate_git_sha"]),
                producer_job=str(row["producer_job"]),
                artifact_id=int(row["artifact_id"]),
                artifact_name=str(row["artifact_name"]),
                artifact_digest="sha256:" + str(row["artifact_sha256"]),
                required_member=list(_ONLINE_REQUIRED_MEMBERS[key]),
                output_dir=output,
            )
            restore_exact_p6_artifact(args, token=token)
            source = bundle_root / evidence_contract._RESTORED_DIRECTORIES[key]
            source_root = evidence_contract._regular_tree_sha256(source)
            restored_root = evidence_contract._regular_tree_sha256(output)
            if source_root != restored_root:
                raise P6ProtocolError("successor review authoritative artifact tree differs")
            source_files = {
                path.relative_to(source).as_posix(): path
                for path in source.rglob("*")
                if path.is_file() and not path.is_symlink()
            }
            restored_files = {
                path.relative_to(output).as_posix(): path
                for path in output.rglob("*")
                if path.is_file() and not path.is_symlink()
            }
            if set(source_files) != set(restored_files) or any(
                source_files[name].read_bytes() != restored_files[name].read_bytes()
                for name in source_files
            ):
                raise P6ProtocolError("successor review authoritative artifact bytes differ")


def _project(args: argparse.Namespace) -> None:
    successor = load_successor_qualification()
    status = project_successor_runtime_review_status(
        args.bundle_root.resolve(), successor_qualification=successor
    )
    _validate_candidate_material(
        args.repository_root.resolve(),
        bundle_root=args.bundle_root.resolve(),
        status=dict(status),
    )
    receipt = build_successor_review_integration_receipt(status)
    _write_new_json(args.status_output, status)
    _write_new_json(args.receipt_output, receipt)


def _check(args: argparse.Namespace) -> None:
    resource_root = Path(getattr(args, "resource_root", None) or ORCHESTRATION_ROOT).resolve()
    status_path = resource_root / SUCCESSOR_RUNTIME_REVIEW_STATUS_RESOURCE
    receipt_path = resource_root / SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_RESOURCE
    bundle_root = resource_root / SUCCESSOR_REVIEW_EVIDENCE_DIRECTORY
    successor_path = resource_root / P6_PROOF_PROMOTION_QUALIFICATION_RESOURCE
    successor = load_json_strict(successor_path)
    if not isinstance(successor, dict) or not validate_successor_freshness(successor)[0]:
        raise ValueError("successor_review_qualification_invalid")
    status = load_json_strict(status_path)
    if not isinstance(status, dict):
        raise ValueError("successor_review_status_invalid")
    valid, _ = validate_successor_runtime_review_status(
        status,
        expected_implementation_root_sha256=str(successor["implementation_root_sha256"]),
        expected_successor_qualification_sha256=str(successor["content_sha256"]),
    )
    if not valid:
        raise ValueError("successor_review_status_invalid")
    if status.get("status") == "in_progress":
        if (
            bundle_root.exists()
            or bundle_root.is_symlink()
            or receipt_path.exists()
            or receipt_path.is_symlink()
        ):
            raise ValueError("successor_review_in_progress_contains_review_evidence")
        return
    projection = project_successor_runtime_review_status(
        bundle_root,
        successor_qualification=successor,
    )
    if dict(projection) != status:
        raise ValueError("successor_review_evidence_binding_mismatch")
    _validate_candidate_material(
        args.repository_root.resolve(), bundle_root=bundle_root, status=status
    )
    receipt = load_json_strict(receipt_path)
    if not isinstance(receipt, dict):
        raise ValueError("successor_review_integration_receipt_invalid")
    valid, reason = validate_successor_review_integration_receipt(receipt, expected_status=status)
    if not valid:
        raise ValueError(reason)
    change_base = getattr(args, "change_base", None)
    should_validate_scope = change_base is None or _review_resources_changed(
        args.repository_root.resolve(),
        base=str(change_base),
        head=str(args.head or "HEAD"),
    )
    if should_validate_scope:
        _validate_git_scope(
            args.repository_root.resolve(), status=status, head=str(args.head or "HEAD")
        )


def _online_check(args: argparse.Namespace) -> None:
    root = args.repository_root.resolve()
    resource_root = Path(getattr(args, "resource_root", None) or ORCHESTRATION_ROOT).resolve()
    status_path = resource_root / SUCCESSOR_RUNTIME_REVIEW_STATUS_RESOURCE
    status = load_json_strict(status_path)
    if not isinstance(status, dict) or not validate_successor_runtime_review_status(status)[0]:
        raise ValueError("successor_review_status_invalid")
    changed = _review_resources_changed(root, base=str(args.change_base), head=str(args.head))
    # The in-progress state is strictly offline and must not trigger even one
    # GitHub API request.  The normal checker still rejects physical evidence.
    if status.get("status") == "in_progress":
        _check(args)
        return
    if not changed:
        # Later product PRs retain offline physical validation but do not make
        # historical reviewed authority depend on artifact retention windows.
        _check(args)
        return
    _check(args)
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("successor_review_online_token_unavailable")
    _validate_authoritative_artifacts_online(
        resource_root / SUCCESSOR_REVIEW_EVIDENCE_DIRECTORY,
        token=token,
        workspace_root=root,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    project = commands.add_parser("project")
    project.add_argument("--bundle-root", required=True, type=Path)
    project.add_argument("--status-output", required=True, type=Path)
    project.add_argument("--receipt-output", required=True, type=Path)
    project.add_argument("--repository-root", required=True, type=Path)
    check = commands.add_parser("check")
    check.add_argument("--repository-root", required=True, type=Path)
    check.add_argument("--head")
    check.add_argument("--change-base")
    check.add_argument("--resource-root", type=Path)
    online = commands.add_parser("online-check")
    online.add_argument("--repository-root", required=True, type=Path)
    online.add_argument("--change-base", required=True)
    online.add_argument("--head", required=True)
    online.add_argument("--resource-root", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "project":
            _project(args)
        elif args.command == "online-check":
            _online_check(args)
        else:
            _check(args)
    except (OSError, TypeError, ValueError, subprocess.CalledProcessError, P6ProtocolError):
        print("stage=successor_review; class=review_binding_invalid:1; count=1")
        return 2
    print("successor_review_evidence_valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
