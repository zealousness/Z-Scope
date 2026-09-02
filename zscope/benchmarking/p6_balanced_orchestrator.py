"""Shared answer-isolated post-producer orchestration for P6 balanced scans.

The cold producer calls :func:`freeze_balanced_scan` before any Truth is made
available.  A separate trusted process then calls
:func:`score_frozen_balanced_scan`, which revalidates the byte-exact freeze,
executes both scorers with a credential-free environment, and seals the
non-release integer quality gate.  GitHub Actions and local WSL runs use this
same module through ``scripts/p6_balanced_orchestrator.py``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

from zscope.benchmarking.p6_protocol import (
    P6ProtocolError,
    canonical_sha256,
    load_json_bytes_strict,
    validate_depth_projection,
)
from zscope.benchmarking.provider_runtime import require_p6_provider_contract
from zscope.benchmarking.p6_sidecar_evidence import (
    P6SidecarEvidenceError,
    TRACE_SIDECAR_EVIDENCE_FILENAME,
    USAGE_EVENTS_EVIDENCE_FILENAME,
    build_trace_sidecar_evidence,
    materialize_trace_sidecar_evidence,
    validate_trace_sidecar_evidence,
)
from zscope.benchmarking.runner import (
    BenchmarkError,
    _read_usage_events_jsonl,
    _p6_answer_free_gate_failures,
    build_p6_answer_free_producer_metrics,
    prepare_p6_runtime_source,
)


FROZEN_SCAN_SCHEMA_VERSION = "zscope.p6-balanced-frozen-scan.v3"
USAGE_EVIDENCE_SCHEMA_VERSION = "zscope.p6-balanced-usage-evidence.v3"
TRUTH_PARTITION_PROJECTION_VERSION = "zscope.p6-truth-partition-projection.v1"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_GIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_RUN_ID_RE = re.compile(r"[1-9][0-9]*\Z")
_ATTEMPT_ID_RE = re.compile(r"p6-[a-z0-9][a-z0-9._-]{2,127}\Z")
_USAGE_FIELDS = frozenset(
    {
        "tokens",
        "queue_empty",
        "token_conservation_passed",
        "provider_response_model_missing_count",
        "provider_response_model_mismatch_count",
        "requested_model_mismatch_count",
        "provider_usage_coverage",
        "provider_response_model_coverage",
        "provider_response_model_successful_call_count",
        "provider_response_model_counts",
        "provider_response_model_counts_conserved",
        "estimated_provider_call_count",
        "failed_or_unknown_call_count",
        "budget_violation_count",
        "telemetry_complete_rate",
        "protocol_anomaly_count",
        "usage_accounting",
        "p6_conservation",
        "p6_admission_conservation",
        "p6_retry_conservation",
        "p6_terminal_authority",
    }
)
_SCORER_ENV_ALLOWLIST = frozenset(
    {
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "WINDIR",
    }
)
QUALITY_REVALIDATION_RECEIPT_VERSION = "zscope.p6-quality-revalidation-receipt.v1"
LOCAL_BALANCED_EVIDENCE_ROOT = ".github/evidence/p6/local-balanced-evidence"
LOCAL_BALANCED_EVIDENCE_RECEIPT = "quality-revalidation-receipt.json"
_QUALITY_BUNDLE_FILES = {
    "bindings": "bindings.json",
    "frozen_manifest": "frozen-manifest.json",
    "legacy_score": "legacy-score.json",
    "producer_projection": "producer-projection.json",
    "report": "frozen-report.json",
    "trace_sidecars": TRACE_SIDECAR_EVIDENCE_FILENAME,
    "usage_events": USAGE_EVENTS_EVIDENCE_FILENAME,
    "usage_evidence": "usage-evidence.json",
    "v16_score": "v16-score.json",
    "v16_truth_partitions": "v16-truth-partitions.json",
    "quality_gate": "p6-balanced-quality-gate.json",
}
_LOCAL_BALANCED_EVIDENCE_FILES = {
    **{
        f"quality/{filename}": f"{LOCAL_BALANCED_EVIDENCE_ROOT}/quality/{filename}"
        for filename in _QUALITY_BUNDLE_FILES.values()
    },
    LOCAL_BALANCED_EVIDENCE_RECEIPT: (
        f"{LOCAL_BALANCED_EVIDENCE_ROOT}/{LOCAL_BALANCED_EVIDENCE_RECEIPT}"
    ),
}
_CANONICAL_SOURCE_FILES = {
    "legacy_scorer_entry": "zscope/cli/benchmark.py",
    # The matching semantics live in protocol.py.  runner.py only adapts the
    # frozen report into the legacy score envelope and is intentionally named
    # as a wrapper so producer-side P6 telemetry work cannot be mistaken for a
    # Scorer change.
    "legacy_scorer_engine": "zscope/benchmarking/protocol.py",
    "legacy_scorer_wrapper": "zscope/benchmarking/runner.py",
    "v16_scorer": "scripts/score_range_v5.py",
    "quality_gate": "scripts/p6_balanced_quality_gate.py",
    "quality_gate_schema": "zscope/benchmarking/p6_balanced_quality_gate.schema.json",
    "sidecar_evidence": "zscope/benchmarking/p6_sidecar_evidence.py",
    "sidecar_evidence_schema": "zscope/benchmarking/p6_sidecar_evidence.schema.json",
    "truth_partition_projection_schema": (
        "zscope/benchmarking/p6_truth_partition_projection.schema.json"
    ),
    "provider_config": "test/range/zscope.benchmark.yaml",
    "orchestrator": "zscope/benchmarking/p6_balanced_orchestrator.py",
    "orchestrator_cli": "scripts/p6_balanced_orchestrator.py",
    "revalidation_receipt_schema": (
        "zscope/benchmarking/p6_quality_revalidation_receipt.schema.json"
    ),
}
_CANONICAL_TRUTH_FILES = {
    "legacy_truth": "test/range/benchmark/ground_truth.json",
    "v16_truth": "test/range/benchmark/v16/ground_truth.json",
}
_SCORING_CONTROL_SOURCE_NAMES = (
    "legacy_scorer_entry",
    "legacy_scorer_engine",
    "legacy_scorer_wrapper",
    "v16_scorer",
    "quality_gate",
)
_LEGACY_SCORER_LAUNCHER = """\
import importlib.util
import runpy
import sys

protocol_path, runner_path, entry_path = sys.argv[1:4]
protocol_spec = importlib.util.spec_from_file_location(
    "zscope.benchmarking.protocol", protocol_path
)
if protocol_spec is None or protocol_spec.loader is None:
    raise SystemExit(2)
protocol_module = importlib.util.module_from_spec(protocol_spec)
sys.modules[protocol_spec.name] = protocol_module
protocol_spec.loader.exec_module(protocol_module)
spec = importlib.util.spec_from_file_location("zscope.benchmarking.runner", runner_path)
if spec is None or spec.loader is None:
    raise SystemExit(2)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
sys.argv = [entry_path, *sys.argv[4:]]
runpy.run_path(entry_path, run_name="__main__")
"""

ProcessRunner = Callable[..., subprocess.CompletedProcess[Any]]
GitHeadResolver = Callable[[Path], str]

_MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024
_MAX_CONTROL_PLANE_TREE_BYTES = 1024 * 1024 * 1024
_USAGE_SIDECAR_NAME = USAGE_EVENTS_EVIDENCE_FILENAME
_TRACE_DIRECTORY_NAMES = frozenset(
    {"decision_traces", "coverage_traces", "evidence_objects", "model_events"}
)


@dataclass(frozen=True)
class _FileSnapshot:
    """One immutable, descriptor-bound input used for every later operation."""

    payload: bytes
    sha256: str
    device: int
    inode: int
    mode: int
    size: int


@dataclass(frozen=True)
class _ControlPlaneTreeSnapshot:
    """A private execution tree materialized from one immutable Git commit."""

    root: Path
    commit_sha: str
    tree_sha: str
    manifest_sha256: str


def _metadata_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_size),
        int(getattr(value, "st_mtime_ns", 0)),
        int(getattr(value, "st_ctime_ns", 0)),
    )


def _directory_object_identity(value: os.stat_result) -> tuple[int, int, int]:
    """Bind a directory object without treating a harmless rename as content drift."""

    return (int(value.st_dev), int(value.st_ino), int(value.st_mode))


def _read_descriptor_snapshot(
    descriptor: int,
    *,
    before: os.stat_result,
    name: str,
) -> _FileSnapshot:
    opened = os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode) or _metadata_identity(opened) != _metadata_identity(before):
        raise P6BalancedOrchestratorError(f"{name} changed before secure open")
    if opened.st_size > _MAX_SNAPSHOT_BYTES:
        raise P6BalancedOrchestratorError(f"{name} exceeds the snapshot size limit")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, _MAX_SNAPSHOT_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > _MAX_SNAPSHOT_BYTES:
            raise P6BalancedOrchestratorError(f"{name} exceeds the snapshot size limit")
    completed = os.fstat(descriptor)
    if _metadata_identity(completed) != _metadata_identity(opened) or total != opened.st_size:
        raise P6BalancedOrchestratorError(f"{name} changed during secure read")
    payload = b"".join(chunks)
    return _FileSnapshot(
        payload=payload,
        sha256=hashlib.sha256(payload).hexdigest(),
        device=int(opened.st_dev),
        inode=int(opened.st_ino),
        mode=int(opened.st_mode),
        size=int(opened.st_size),
    )


def _snapshot_regular_file(path: Path, *, name: str) -> _FileSnapshot:
    """Open, read, hash, and bind one pathname exactly once without following it."""

    target = Path(path)
    try:
        before = target.lstat()
    except OSError as exc:
        raise P6BalancedOrchestratorError(f"{name} is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise P6BalancedOrchestratorError(f"{name} must be a regular file")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise P6BalancedOrchestratorError(f"{name} cannot be opened safely") from exc
    try:
        snapshot = _read_descriptor_snapshot(descriptor, before=before, name=name)
    except OSError as exc:
        raise P6BalancedOrchestratorError(f"{name} cannot be read safely") from exc
    finally:
        os.close(descriptor)
    try:
        after = target.lstat()
    except OSError as exc:
        raise P6BalancedOrchestratorError(f"{name} changed after secure read") from exc
    if _metadata_identity(after) != _metadata_identity(before):
        raise P6BalancedOrchestratorError(f"{name} changed after secure read")
    return snapshot


def _snapshot_regular_file_at(
    directory_fd: int,
    member: str,
    *,
    name: str,
) -> _FileSnapshot:
    if not member or Path(member).name != member or member in {".", ".."}:
        raise P6BalancedOrchestratorError(f"{name} member name is invalid")
    try:
        before = os.stat(member, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise P6BalancedOrchestratorError(f"{name} is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise P6BalancedOrchestratorError(f"{name} must be a regular file")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(member, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise P6BalancedOrchestratorError(f"{name} cannot be opened safely") from exc
    try:
        snapshot = _read_descriptor_snapshot(descriptor, before=before, name=name)
    except OSError as exc:
        raise P6BalancedOrchestratorError(f"{name} cannot be read safely") from exc
    finally:
        os.close(descriptor)
    try:
        after = os.stat(member, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise P6BalancedOrchestratorError(f"{name} changed after secure read") from exc
    if _metadata_identity(after) != _metadata_identity(before):
        raise P6BalancedOrchestratorError(f"{name} changed after secure read")
    return snapshot


def _snapshot_directory_members(
    root: Path,
    members: Mapping[str, str],
    *,
    exact_members: bool,
    name: str,
) -> dict[str, _FileSnapshot]:
    """Snapshot directory members through one stable directory descriptor on POSIX."""

    target = Path(root)
    try:
        before = target.lstat()
    except OSError as exc:
        raise P6BalancedOrchestratorError(f"{name} is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise P6BalancedOrchestratorError(f"{name} must be a directory")
    if os.name == "nt":
        if exact_members and {entry.name for entry in target.iterdir()} != set(members.values()):
            raise P6BalancedOrchestratorError(f"{name} members are invalid")
        snapshots = {
            key: _snapshot_regular_file(target / member, name=f"{name} {key}")
            for key, member in members.items()
        }
        try:
            after = target.lstat()
        except OSError as exc:
            raise P6BalancedOrchestratorError(f"{name} changed during snapshot") from exc
        if _metadata_identity(after) != _metadata_identity(before):
            raise P6BalancedOrchestratorError(f"{name} changed during snapshot")
        return snapshots
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory_fd = os.open(target, flags)
    except OSError as exc:
        raise P6BalancedOrchestratorError(f"{name} cannot be opened safely") from exc
    try:
        opened = os.fstat(directory_fd)
        if not stat.S_ISDIR(opened.st_mode) or _directory_object_identity(
            opened
        ) != _directory_object_identity(before):
            raise P6BalancedOrchestratorError(f"{name} changed before secure open")
        if exact_members and set(os.listdir(directory_fd)) != set(members.values()):
            raise P6BalancedOrchestratorError(f"{name} members are invalid")
        snapshots = {
            key: _snapshot_regular_file_at(
                directory_fd,
                member,
                name=f"{name} {key}",
            )
            for key, member in members.items()
        }
        completed = os.fstat(directory_fd)
        if (
            _directory_object_identity(completed) != _directory_object_identity(opened)
            or exact_members
            and set(os.listdir(directory_fd)) != set(members.values())
        ):
            raise P6BalancedOrchestratorError(f"{name} changed during snapshot")
    finally:
        os.close(directory_fd)
    try:
        after = target.lstat()
    except OSError as exc:
        raise P6BalancedOrchestratorError(f"{name} changed during snapshot") from exc
    if _directory_object_identity(after) != _directory_object_identity(before):
        raise P6BalancedOrchestratorError(f"{name} changed during snapshot")
    return snapshots


def _object_from_snapshot(snapshot: _FileSnapshot, *, name: str) -> dict[str, Any]:
    try:
        value = load_json_bytes_strict(snapshot.payload, name=name)
    except Exception as exc:
        raise P6BalancedOrchestratorError(f"{name} is invalid") from exc
    if not isinstance(value, dict):
        raise P6BalancedOrchestratorError(f"{name} must contain one object")
    return value


def _write_snapshot(path: Path, snapshot: _FileSnapshot) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(snapshot.payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise P6BalancedOrchestratorError("snapshot copy could not be completed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _git_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if key.upper() in _SCORER_ENV_ALLOWLIST
    }
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return environment


def _run_git_bytes(
    repository_root: Path,
    arguments: Sequence[str],
    *,
    input_bytes: bytes | None = None,
) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repository_root), *arguments],
        cwd=str(repository_root),
        env=_git_environment(),
        check=False,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if int(result.returncode) != 0 or not isinstance(result.stdout, bytes):
        raise P6BalancedOrchestratorError("control-plane Git tree is unavailable")
    return result.stdout


def _validated_git_relative_path(raw: bytes) -> tuple[str, ...]:
    try:
        value = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise P6BalancedOrchestratorError("control-plane Git path is invalid") from exc
    pure = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
        or any(part.casefold() == ".git" for part in pure.parts)
    ):
        raise P6BalancedOrchestratorError("control-plane Git path is invalid")
    return pure.parts


def _parse_git_batch(
    payload: bytes,
    entries: Sequence[tuple[str, str, tuple[str, ...]]],
) -> list[bytes]:
    position = 0
    blobs: list[bytes] = []
    total = 0
    for expected_oid, _mode, _parts in entries:
        newline = payload.find(b"\n", position)
        if newline < 0:
            raise P6BalancedOrchestratorError("control-plane Git blob stream is invalid")
        header = payload[position:newline].split(b" ")
        if len(header) != 3:
            raise P6BalancedOrchestratorError("control-plane Git blob stream is invalid")
        try:
            object_id = header[0].decode("ascii", errors="strict")
            object_type = header[1].decode("ascii", errors="strict")
            size = int(header[2].decode("ascii", errors="strict"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise P6BalancedOrchestratorError("control-plane Git blob stream is invalid") from exc
        if object_id != expected_oid or object_type != "blob" or size < 0:
            raise P6BalancedOrchestratorError("control-plane Git blob identity is invalid")
        start = newline + 1
        end = start + size
        if end >= len(payload) or payload[end : end + 1] != b"\n":
            raise P6BalancedOrchestratorError("control-plane Git blob stream is truncated")
        blob = payload[start:end]
        total += len(blob)
        if total > _MAX_CONTROL_PLANE_TREE_BYTES:
            raise P6BalancedOrchestratorError("control-plane Git tree is too large")
        blobs.append(blob)
        position = end + 1
    if position != len(payload):
        raise P6BalancedOrchestratorError("control-plane Git blob stream has trailing data")
    return blobs


def _materialize_control_plane_tree(
    *, repository_root: Path, control_plane_commit: str, destination: Path
) -> _ControlPlaneTreeSnapshot:
    """Materialize only committed blobs, never live checkout pathnames."""

    if _GIT_RE.fullmatch(control_plane_commit) is None:
        raise P6BalancedOrchestratorError("control-plane Git identity is invalid")
    root = repository_root.resolve(strict=True)
    if destination.exists() or destination.is_symlink():
        raise P6BalancedOrchestratorError("control-plane snapshot destination already exists")
    resolved_commit = (
        _run_git_bytes(root, ("rev-parse", "--verify", f"{control_plane_commit}^{{commit}}"))
        .decode("ascii", errors="strict")
        .strip()
    )
    tree_sha = (
        _run_git_bytes(root, ("rev-parse", "--verify", f"{control_plane_commit}^{{tree}}"))
        .decode("ascii", errors="strict")
        .strip()
    )
    if resolved_commit != control_plane_commit or _GIT_RE.fullmatch(tree_sha) is None:
        raise P6BalancedOrchestratorError("control-plane Git identity is invalid")
    listing = _run_git_bytes(
        root,
        ("ls-tree", "-r", "-z", "--full-tree", control_plane_commit),
    )
    entries: list[tuple[str, str, tuple[str, ...]]] = []
    normalized_paths: set[str] = set()
    manifest = hashlib.sha256()
    for row in listing.split(b"\0"):
        if not row:
            continue
        prefix, separator, raw_path = row.partition(b"\t")
        fields = prefix.split(b" ")
        if not separator or len(fields) != 3:
            raise P6BalancedOrchestratorError("control-plane Git listing is invalid")
        try:
            mode = fields[0].decode("ascii", errors="strict")
            object_type = fields[1].decode("ascii", errors="strict")
            object_id = fields[2].decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise P6BalancedOrchestratorError("control-plane Git listing is invalid") from exc
        if (
            mode not in {"100644", "100755"}
            or object_type != "blob"
            or _GIT_RE.fullmatch(object_id) is None
        ):
            raise P6BalancedOrchestratorError(
                "control-plane Git tree contains an unsupported member"
            )
        parts = _validated_git_relative_path(raw_path)
        normalized = os.path.normcase(os.path.join(*parts))
        if normalized in normalized_paths:
            raise P6BalancedOrchestratorError("control-plane Git path is duplicated")
        normalized_paths.add(normalized)
        entries.append((object_id, mode, parts))
        manifest.update(mode.encode("ascii"))
        manifest.update(b"\0")
        manifest.update(b"/".join(part.encode("utf-8") for part in parts))
        manifest.update(b"\0")
        manifest.update(object_id.encode("ascii"))
        manifest.update(b"\n")
    if not entries:
        raise P6BalancedOrchestratorError("control-plane Git tree is empty")
    requests = b"".join(object_id.encode("ascii") + b"\n" for object_id, _, _ in entries)
    batch = _run_git_bytes(root, ("cat-file", "--batch"), input_bytes=requests)
    blobs = _parse_git_batch(batch, entries)
    if len(blobs) != len(entries):
        raise P6BalancedOrchestratorError("control-plane Git blob stream is incomplete")
    destination.mkdir(mode=0o700)
    try:
        directories: set[Path] = {destination}
        for (object_id, mode, parts), blob in zip(entries, blobs):
            if (
                hashlib.sha1(
                    b"blob " + str(len(blob)).encode("ascii") + b"\0" + blob,
                    usedforsecurity=False,
                ).hexdigest()
                != object_id
            ):
                raise P6BalancedOrchestratorError("control-plane Git blob digest is invalid")
            target = destination.joinpath(*parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            directories.update(target.parents)
            snapshot = _FileSnapshot(
                payload=blob,
                sha256=hashlib.sha256(blob).hexdigest(),
                device=0,
                inode=0,
                mode=0,
                size=len(blob),
            )
            _write_snapshot(target, snapshot)
            if os.name != "nt":
                target.chmod(0o500 if mode == "100755" else 0o400)
        if os.name != "nt":
            for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
                if directory == destination or destination in directory.parents:
                    directory.chmod(0o500)
    except BaseException:
        if os.name != "nt":
            for current, child_directories, files in os.walk(destination):
                Path(current).chmod(0o700)
                for name in files:
                    (Path(current) / name).chmod(0o600)
                for name in child_directories:
                    (Path(current) / name).chmod(0o700)
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return _ControlPlaneTreeSnapshot(
        root=destination,
        commit_sha=resolved_commit,
        tree_sha=tree_sha,
        manifest_sha256=manifest.hexdigest(),
    )


def _remove_control_plane_tree(snapshot: _ControlPlaneTreeSnapshot) -> None:
    if os.name != "nt" and snapshot.root.exists():
        for current, directories, files in os.walk(snapshot.root):
            Path(current).chmod(0o700)
            for name in files:
                (Path(current) / name).chmod(0o600)
            for name in directories:
                (Path(current) / name).chmod(0o700)
    shutil.rmtree(snapshot.root, ignore_errors=True)


class P6BalancedOrchestratorError(RuntimeError):
    """The frozen producer or trusted post-score boundary failed closed."""


@dataclass(frozen=True)
class BalancedRunIdentity:
    workflow_run_id: str
    workflow_run_attempt: int
    attempt_id: str
    control_plane_commit: str
    candidate_git_sha: str
    candidate_git_tree: str

    def validate(self) -> None:
        if _RUN_ID_RE.fullmatch(self.workflow_run_id) is None:
            raise P6BalancedOrchestratorError("workflow run identity is invalid")
        if isinstance(self.workflow_run_attempt, bool) or self.workflow_run_attempt < 1:
            raise P6BalancedOrchestratorError("workflow run attempt is invalid")
        if _ATTEMPT_ID_RE.fullmatch(self.attempt_id) is None:
            raise P6BalancedOrchestratorError("P6 attempt identity is invalid")
        if _GIT_RE.fullmatch(self.control_plane_commit) is None:
            raise P6BalancedOrchestratorError("control-plane commit is invalid")
        if _GIT_RE.fullmatch(self.candidate_git_sha) is None:
            raise P6BalancedOrchestratorError("candidate commit is invalid")
        if _GIT_RE.fullmatch(self.candidate_git_tree) is None:
            raise P6BalancedOrchestratorError("candidate tree is invalid")


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _fresh_output(output: Path) -> Path:
    if output.exists() or output.is_symlink():
        raise P6BalancedOrchestratorError("output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))


def _commit_output(temp: Path, output: Path) -> None:
    if output.exists() or output.is_symlink():
        raise P6BalancedOrchestratorError("output appeared during finalization")
    temp.replace(output)


def _projection(snapshot: _FileSnapshot, *, identity: BalancedRunIdentity) -> dict[str, Any]:
    value = _object_from_snapshot(snapshot, name="balanced producer projection")
    try:
        validate_depth_projection(value, scan_depth="balanced")
    except P6ProtocolError as exc:
        raise P6BalancedOrchestratorError("balanced producer projection is invalid") from exc
    expected = {
        "control_plane_commit": identity.control_plane_commit,
        "git_sha": identity.candidate_git_sha,
        "git_tree": identity.candidate_git_tree,
        "producer_attempt_id": identity.attempt_id,
        "formal_benchmark": False,
        "release_eligible": False,
    }
    if any(value.get(key) != expected_value for key, expected_value in expected.items()):
        raise P6BalancedOrchestratorError("balanced producer identity is invalid")
    return value


def _truth_partition_member_commitment(truth_id: str) -> str:
    return canonical_sha256({"truth_id": truth_id})


def _truth_partition_projection(
    truth_snapshot: _FileSnapshot,
) -> dict[str, Any]:
    """Project v16 product/design-risk membership in the P6 control plane.

    The frozen Benchmark v5 scorer remains byte-identical to ``origin/main``.
    This answer-separated projection is generated only after that scorer has
    completed and is persisted as a distinct, hash-bound P6 artifact.
    """

    truth = _object_from_snapshot(truth_snapshot, name="Truth v16 partition input")
    records = truth.get("vulnerabilities")
    if not isinstance(records, list) or any(not isinstance(row, Mapping) for row in records):
        raise P6BalancedOrchestratorError("Truth v16 partition input is invalid")
    partition_ids: dict[str, list[str]] = {"product": [], "design_risk": []}
    for row in records:
        contract = row.get("verification_contract")
        truth_id = str(row.get("id") or "").strip()
        kind = str(contract.get("kind") or "") if isinstance(contract, Mapping) else ""
        if not truth_id or kind not in {
            "concrete_trigger",
            "public_api_contract",
            "pattern_model",
            "retired",
        }:
            raise P6BalancedOrchestratorError("Truth v16 partition member is invalid")
        if kind in {"concrete_trigger", "public_api_contract"}:
            partition_ids["product"].append(truth_id)
        elif kind == "pattern_model":
            partition_ids["design_risk"].append(truth_id)
    if len(set(partition_ids["product"] + partition_ids["design_risk"])) != sum(
        len(values) for values in partition_ids.values()
    ):
        raise P6BalancedOrchestratorError("Truth v16 partitions are not unique")

    def partition(member_ids: Sequence[str]) -> dict[str, Any]:
        commitments = sorted(_truth_partition_member_commitment(value) for value in member_ids)
        return {
            "member_count": len(commitments),
            "member_commitments": commitments,
            "member_commitments_sha256": canonical_sha256(commitments),
        }

    product = partition(partition_ids["product"])
    design_risk = partition(partition_ids["design_risk"])
    product_set = set(product["member_commitments"])
    design_set = set(design_risk["member_commitments"])
    union = sorted(product_set | design_set)
    value: dict[str, Any] = {
        "schema_version": TRUTH_PARTITION_PROJECTION_VERSION,
        "truth_sha256": truth_snapshot.sha256,
        "product": product,
        "design_risk": design_risk,
        "partitions_disjoint": not bool(product_set & design_set),
        "union_member_count": len(union),
        "union_member_commitments_sha256": canonical_sha256(union),
        "answer_material_present": False,
    }
    value["content_sha256"] = canonical_sha256(value)
    if (
        product["member_count"] != 61
        or design_risk["member_count"] != 75
        or value["partitions_disjoint"] is not True
        or value["union_member_count"] != 136
    ):
        raise P6BalancedOrchestratorError("Truth v16 partition projection is invalid")
    return value


def _validate_complete_balanced_aggregate(
    *,
    aggregate: Mapping[str, Any],
    run: Mapping[str, Any],
    recomputed_metrics: Mapping[str, Any],
    projection: Mapping[str, Any],
    identity: BalancedRunIdentity,
) -> None:
    expected = {
        "language": "cpp",
        "mode": "pilot",
        "scan_depth": "balanced",
        "formal_benchmark": False,
        "release_eligible": False,
        "answer_free_producer": True,
        "cold_runs": 1,
        "all_completed": True,
        "passed": True,
        "git_sha": identity.candidate_git_sha,
        "git_tree": identity.candidate_git_tree,
    }
    if any(aggregate.get(name) != value for name, value in expected.items()):
        raise P6BalancedOrchestratorError("balanced aggregate is not a complete producer")
    if (
        run.get("completed") is not True
        or run.get("formal_benchmark") is not False
        or run.get("release_eligible") is not False
        or run.get("answer_free_producer") is not True
        or run.get("queue_empty") is not True
        or run.get("gate_failures") not in ([], None)
        or run.get("metrics") != recomputed_metrics
        or projection.get("artifact_sha256") != canonical_sha256(aggregate)
    ):
        raise P6BalancedOrchestratorError("balanced selected producer is incomplete")
    isolation = run.get("isolation")
    phases = isolation.get("phase_executions") if isinstance(isolation, Mapping) else None
    if not isinstance(phases, list) or not phases:
        raise P6BalancedOrchestratorError("balanced producer attempt lineage is incomplete")
    for phase in phases:
        if (
            not isinstance(phase, Mapping)
            or str(phase.get("p6_workflow_run_id") or "") != identity.workflow_run_id
            or phase.get("p6_workflow_run_attempt") != identity.workflow_run_attempt
            or str(phase.get("p6_attempt_id") or "") != identity.attempt_id
        ):
            raise P6BalancedOrchestratorError("balanced producer attempt lineage is invalid")
    if sum(str(phase.get("phase") or "") == "scan" for phase in phases) != 1:
        raise P6BalancedOrchestratorError("balanced producer scan phase is not unique")


def _validate_usage_sidecar_binding(
    *,
    report: Mapping[str, Any],
    run: Mapping[str, Any],
    trace_manifest: Mapping[str, Any],
    usage_snapshot: _FileSnapshot,
    usage_call_count: int,
) -> None:
    """Bind the exact usage sidecar to every selected-producer declaration."""

    expected_artifact = {
        "schema_version": "zscope.llm-usage-events-artifact.v1",
        "path": _USAGE_SIDECAR_NAME,
        "sha256": usage_snapshot.sha256,
        "call_count": usage_call_count,
        "answer_free": True,
    }
    metadata = report.get("metadata")
    manifest = report.get("run_manifest")
    if not isinstance(metadata, Mapping) or not isinstance(manifest, Mapping):
        raise P6BalancedOrchestratorError("balanced usage artifact owners are invalid")
    metadata_artifact = metadata.get("llm_usage_events_artifact")
    manifest_artifact = manifest.get("llm_usage_events_artifact")
    if (
        not isinstance(metadata_artifact, Mapping)
        or not isinstance(manifest_artifact, Mapping)
        or dict(metadata_artifact) != expected_artifact
        or dict(manifest_artifact) != expected_artifact
    ):
        raise P6BalancedOrchestratorError("balanced usage artifact binding is invalid")

    trace_usage = trace_manifest.get("llm_usage_events")
    if (
        not isinstance(trace_usage, Mapping)
        or trace_usage.get("available") is not True
        or trace_usage.get("path") != _USAGE_SIDECAR_NAME
        or trace_usage.get("file_sha256") != usage_snapshot.sha256
        or trace_usage.get("event_count") != usage_call_count
    ):
        raise P6BalancedOrchestratorError("balanced decision-trace usage binding is invalid")

    artifact_hashes = run.get("artifact_hashes")
    files = artifact_hashes.get("files") if isinstance(artifact_hashes, Mapping) else None
    if not isinstance(files, Mapping) or files.get(_USAGE_SIDECAR_NAME) != usage_snapshot.sha256:
        raise P6BalancedOrchestratorError("balanced aggregate usage binding is invalid")


def freeze_balanced_scan(
    *,
    aggregate_path: Path,
    report_path: Path,
    producer_metrics_path: Path,
    projection_path: Path,
    provider_config_path: Path,
    identity: BalancedRunIdentity,
    output: Path,
    literal_canaries: Sequence[bytes] = (),
) -> dict[str, Any]:
    """Freeze one selected cold-balanced report before either Truth is loaded."""

    identity.validate()
    aggregate_snapshot = _snapshot_regular_file(aggregate_path, name="balanced aggregate")
    report_snapshot = _snapshot_regular_file(report_path, name="balanced report")
    producer_metrics_snapshot = _snapshot_regular_file(
        producer_metrics_path, name="balanced answer-free producer metrics"
    )
    projection_snapshot = _snapshot_regular_file(
        projection_path, name="balanced producer projection"
    )
    normalized_canaries = tuple(
        value for value in literal_canaries if isinstance(value, bytes) and value
    )
    if len(normalized_canaries) != len(literal_canaries) or len(normalized_canaries) != len(
        set(normalized_canaries)
    ):
        raise P6BalancedOrchestratorError("balanced protected canary set is invalid")
    if any(
        canary in snapshot.payload
        for canary in normalized_canaries
        for snapshot in (
            aggregate_snapshot,
            report_snapshot,
            producer_metrics_snapshot,
            projection_snapshot,
        )
    ):
        raise P6BalancedOrchestratorError("balanced protected canary detected")
    aggregate = _object_from_snapshot(aggregate_snapshot, name="balanced aggregate")
    report = _object_from_snapshot(report_snapshot, name="balanced report")
    producer_metrics = _object_from_snapshot(
        producer_metrics_snapshot,
        name="balanced answer-free producer metrics",
    )
    projection = _projection(projection_snapshot, identity=identity)
    manifest = report.get("run_manifest")
    if (
        report.get("answer_material_present") is not False
        or not isinstance(manifest, Mapping)
        or manifest.get("validation_queue_drained") is not True
        or projection.get("artifact_sha256") != canonical_sha256(aggregate)
    ):
        raise P6BalancedOrchestratorError("balanced producer invariants are invalid")
    runs = aggregate.get("runs")
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], Mapping):
        raise P6BalancedOrchestratorError("balanced aggregate must select one run")
    provenance = runs[0].get("provenance")
    if not isinstance(provenance, Mapping):
        raise P6BalancedOrchestratorError("balanced runtime identity is invalid")
    runtime_spec_sha = provenance.get("runtime_spec_sha256")
    if not isinstance(runtime_spec_sha, str) or _SHA256_RE.fullmatch(runtime_spec_sha) is None:
        raise P6BalancedOrchestratorError("balanced runtime identity is invalid")
    contract = require_p6_provider_contract(provider_config_path)
    run = runs[0]
    artifact_hashes = run.get("artifact_hashes")
    files = artifact_hashes.get("files") if isinstance(artifact_hashes, Mapping) else None
    provider_runtime = provenance.get("provider_runtime")
    cold_cache = run.get("cold_cache")
    isolation = run.get("isolation")
    producer_source_sandbox = (
        isolation.get("producer_source_sandbox") if isinstance(isolation, Mapping) else None
    )
    host_process_sandbox = (
        producer_source_sandbox.get("host_process_sandbox")
        if isinstance(producer_source_sandbox, Mapping)
        else None
    )
    usage_accounting_value = producer_metrics.get("usage_accounting")
    usage_accounting: Mapping[str, Any] = (
        usage_accounting_value if isinstance(usage_accounting_value, Mapping) else {}
    )
    usage_totals = usage_accounting.get("totals")
    funnel = producer_metrics.get("candidate_funnel")
    v3 = funnel.get("v3_investigation") if isinstance(funnel, Mapping) else None
    if (
        not isinstance(files, Mapping)
        or files.get("report.json") != report_snapshot.sha256
        or files.get("producer-metrics.json") != producer_metrics_snapshot.sha256
        or provenance.get("candidate_commit") != identity.candidate_git_sha
        or not isinstance(provider_runtime, Mapping)
        or provider_runtime.get("identity_sha256") != projection.get("provider_identity_sha256")
        or provider_runtime.get("config_sha256") != contract.config_sha256
        or provider_runtime.get("identity_sha256") != contract.identity_sha256
        or not isinstance(cold_cache, Mapping)
        or cold_cache.get("identity_sha256") != projection.get("cache_identity_sha256")
        or cold_cache.get("empty_at_start") is not True
        or cold_cache.get("reused") is not False
        or not isinstance(isolation, Mapping)
        or isolation.get("image") != projection.get("oci_image_ref")
        or isolation.get("image_id") != projection.get("oci_image_id")
        or isolation.get("runtime_source_sha256") != projection.get("runtime_source_sha256")
        or isolation.get("provider_identity_sha256") != projection.get("provider_identity_sha256")
        or not isinstance(producer_source_sandbox, Mapping)
        or set(producer_source_sandbox)
        != {
            "schema_version",
            "runtime_source_sha256",
            "scan_input_manifest_sha256",
            "host_process_sandbox",
            "scorer_present",
            "truth_present",
            "expected_present",
            "review_decision_present",
            "postscore_evidence_present",
        }
        or producer_source_sandbox.get("schema_version") != "zscope.p6-producer-source-sandbox.v2"
        or producer_source_sandbox.get("runtime_source_sha256")
        != projection.get("runtime_source_sha256")
        or producer_source_sandbox.get("scan_input_manifest_sha256")
        != run.get("input_manifest_sha256")
        or any(
            producer_source_sandbox.get(name) is not False
            for name in (
                "scorer_present",
                "truth_present",
                "expected_present",
                "review_decision_present",
                "postscore_evidence_present",
            )
        )
        or not isinstance(host_process_sandbox, Mapping)
        or set(host_process_sandbox)
        != {
            "schema_version",
            "candidate_commit",
            "candidate_git_tree",
            "file_count",
            "source_manifest_sha256",
            "receipt_sha256",
            "scorer_present",
            "truth_present",
            "expected_answer_present",
            "review_decision_present",
            "postscore_evidence_present",
        }
        or host_process_sandbox.get("schema_version") != "zscope.p6-host-producer-sandbox.v1"
        or host_process_sandbox.get("candidate_commit") != identity.candidate_git_sha
        or host_process_sandbox.get("candidate_git_tree") != identity.candidate_git_tree
        or not isinstance(host_process_sandbox.get("file_count"), int)
        or int(host_process_sandbox.get("file_count") or 0) < 1
        or _SHA256_RE.fullmatch(str(host_process_sandbox.get("source_manifest_sha256") or ""))
        is None
        or _SHA256_RE.fullmatch(str(host_process_sandbox.get("receipt_sha256") or "")) is None
        or any(
            host_process_sandbox.get(name) is not False
            for name in (
                "scorer_present",
                "truth_present",
                "expected_answer_present",
                "review_decision_present",
                "postscore_evidence_present",
            )
        )
        or not isinstance(usage_totals, Mapping)
        or projection.get("call_count") != int(usage_accounting.get("call_count") or 0)
        or projection.get("provider_usage_coverage")
        != producer_metrics.get("provider_usage_coverage")
        or projection.get("provider_response_model_coverage")
        != producer_metrics.get("provider_response_model_coverage")
        or projection.get("estimated_provider_call_count")
        != int(producer_metrics.get("estimated_provider_call_count") or 0)
        or projection.get("queue_empty") != producer_metrics.get("queue_empty")
        or projection.get("token_conservation_passed")
        != producer_metrics.get("token_conservation_passed")
        or projection.get("telemetry_complete_rate")
        != producer_metrics.get("telemetry_complete_rate")
        or not isinstance(v3, Mapping)
        or projection.get("eligible_count") != int(v3.get("eligible") or 0)
        or projection.get("entered_count") != int(v3.get("entered") or 0)
        or projection.get("usage_conservation") != producer_metrics.get("p6_conservation")
    ):
        raise P6BalancedOrchestratorError("balanced report-to-producer binding is invalid")
    bindings = {
        "git_commit": identity.candidate_git_sha,
        "git_tree": identity.candidate_git_tree,
        "candidate_sha256": hashlib.sha256(identity.candidate_git_sha.encode("utf-8")).hexdigest(),
        "provider_identity_sha256": str(projection["provider_identity_sha256"]),
        "runtime_sha256": str(projection["runtime_source_sha256"]),
        "config_sha256": contract.config_sha256,
        "oci_image_digest": str(projection["oci_image_digest"]),
        "cold_cache_identity": str(projection["cache_identity_sha256"]),
        "selected_attempt_id": identity.attempt_id,
    }
    if str(projection.get("provider_identity_sha256")) != contract.identity_sha256:
        raise P6BalancedOrchestratorError("balanced provider identity is invalid")
    temp = _fresh_output(output)
    try:
        producer_workspace = temp / ".producer-input"
        producer_workspace.mkdir(mode=0o700)
        staged_report = producer_workspace / "report.json"
        _write_snapshot(staged_report, report_snapshot)
        usage_snapshot = _snapshot_regular_file(
            producer_metrics_path.parent / "llm_usage_events.jsonl",
            name="balanced usage sidecar",
        )
        trace_artifact = (
            manifest.get("decision_trace_artifact") if isinstance(manifest, Mapping) else None
        )
        trace_name = (
            str(trace_artifact.get("path") or "") if isinstance(trace_artifact, Mapping) else ""
        )
        if not trace_name or Path(trace_name).name != trace_name:
            raise P6BalancedOrchestratorError("balanced decision-trace sidecar identity is invalid")
        trace_snapshot = _snapshot_regular_file(
            producer_metrics_path.parent / trace_name,
            name="balanced decision-trace sidecar",
        )
        trace_sidecars = _trace_sidecar_snapshots(
            run_dir=producer_metrics_path.parent,
            manifest_snapshot=trace_snapshot,
        )
        if any(
            canary in snapshot.payload
            for canary in normalized_canaries
            for snapshot in (usage_snapshot, trace_snapshot, *trace_sidecars.values())
        ):
            raise P6BalancedOrchestratorError("balanced protected canary detected")
        _write_snapshot(producer_workspace / _USAGE_SIDECAR_NAME, usage_snapshot)
        _write_snapshot(producer_workspace / trace_name, trace_snapshot)
        for relative, snapshot in trace_sidecars.items():
            destination = producer_workspace / Path(*PurePosixPath(relative).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            _write_snapshot(destination, snapshot)
        try:
            usage_call_count = len(
                _read_usage_events_jsonl(producer_workspace / _USAGE_SIDECAR_NAME)
            )
        except (BenchmarkError, OSError, UnicodeError) as exc:
            raise P6BalancedOrchestratorError("balanced usage sidecar is invalid") from exc
        _validate_usage_sidecar_binding(
            report=report,
            run=run,
            trace_manifest=_object_from_snapshot(
                trace_snapshot, name="balanced decision-trace manifest"
            ),
            usage_snapshot=usage_snapshot,
            usage_call_count=usage_call_count,
        )
        try:
            trace_evidence = build_trace_sidecar_evidence(
                manifest_path=trace_name,
                manifest_payload=trace_snapshot.payload,
                sidecar_payloads={
                    relative: snapshot.payload for relative, snapshot in trace_sidecars.items()
                },
            )
        except P6SidecarEvidenceError as exc:
            raise P6BalancedOrchestratorError(
                "balanced decision-trace sidecar evidence is invalid"
            ) from exc
        try:
            recomputed_metrics = build_p6_answer_free_producer_metrics(
                report_path=staged_report,
                run_dir=producer_workspace,
                provider_contract=contract,
            )
        except (BenchmarkError, OSError, ValueError) as exc:
            raise P6BalancedOrchestratorError(
                "balanced answer-free producer metrics cannot be recomputed"
            ) from exc
        if producer_metrics != recomputed_metrics or any(
            name not in producer_metrics for name in _USAGE_FIELDS
        ):
            raise P6BalancedOrchestratorError("balanced usage evidence is incomplete")
        if _p6_answer_free_gate_failures(recomputed_metrics):
            raise P6BalancedOrchestratorError("balanced producer metrics failed closed")
        _validate_complete_balanced_aggregate(
            aggregate=aggregate,
            run=run,
            recomputed_metrics=recomputed_metrics,
            projection=projection,
            identity=identity,
        )
        usage_fields = {name: producer_metrics[name] for name in sorted(_USAGE_FIELDS)}
        shutil.rmtree(producer_workspace)
        frozen_report = temp / "report.json"
        _write_snapshot(frozen_report, report_snapshot)
        _write_json(temp / "bindings.json", bindings)
        _write_snapshot(temp / USAGE_EVENTS_EVIDENCE_FILENAME, usage_snapshot)
        _write_json(temp / TRACE_SIDECAR_EVIDENCE_FILENAME, trace_evidence)
        trace_evidence_snapshot = _snapshot_regular_file(
            temp / TRACE_SIDECAR_EVIDENCE_FILENAME,
            name="balanced trace sidecar evidence",
        )
        usage: dict[str, Any] = {
            "schema_version": USAGE_EVIDENCE_SCHEMA_VERSION,
            "workflow_run_id": identity.workflow_run_id,
            "workflow_run_attempt": identity.workflow_run_attempt,
            "attempt_id": identity.attempt_id,
            "llm_usage_events_sha256": usage_snapshot.sha256,
            "llm_usage_events_call_count": usage_call_count,
            "trace_sidecars_sha256": trace_evidence_snapshot.sha256,
            "trace_sidecar_member_count": trace_evidence["member_count"],
            "trace_count": trace_evidence["trace_count"],
            "coverage_trace_count": trace_evidence["coverage_trace_count"],
            "evidence_object_count": trace_evidence["evidence_object_count"],
            "model_event_count": trace_evidence["model_event_count"],
            "score_fields": usage_fields,
            "answer_material_present": False,
            "formal_benchmark": False,
            "release_eligible": False,
        }
        usage["content_sha256"] = canonical_sha256(usage)
        _write_json(temp / "usage-evidence.json", usage)
        frozen: dict[str, Any] = {
            "schema_version": FROZEN_SCAN_SCHEMA_VERSION,
            "workflow_run_id": identity.workflow_run_id,
            "workflow_run_attempt": identity.workflow_run_attempt,
            "control_plane_commit": identity.control_plane_commit,
            "candidate_git_sha": identity.candidate_git_sha,
            "candidate_git_tree": identity.candidate_git_tree,
            "attempt_id": identity.attempt_id,
            "llm_usage_events_sha256": usage_snapshot.sha256,
            "llm_usage_events_call_count": usage_call_count,
            "trace_sidecars_sha256": trace_evidence_snapshot.sha256,
            "trace_sidecar_member_count": trace_evidence["member_count"],
            "trace_count": trace_evidence["trace_count"],
            "coverage_trace_count": trace_evidence["coverage_trace_count"],
            "evidence_object_count": trace_evidence["evidence_object_count"],
            "model_event_count": trace_evidence["model_event_count"],
            "report_sha256": report_snapshot.sha256,
            "bindings_sha256": _snapshot_regular_file(
                temp / "bindings.json", name="balanced bindings"
            ).sha256,
            "usage_evidence_sha256": _snapshot_regular_file(
                temp / "usage-evidence.json", name="balanced usage evidence"
            ).sha256,
            "projection_sha256": projection_snapshot.sha256,
            "answer_material_present": False,
            "formal_benchmark": False,
            "release_eligible": False,
        }
        frozen["content_sha256"] = canonical_sha256(frozen)
        _write_json(temp / "manifest.json", frozen)
        _commit_output(temp, output)
        return frozen
    except BaseException:
        shutil.rmtree(temp, ignore_errors=True)
        raise


def _resolve_repository_head(repository_root: Path, *, process_runner: ProcessRunner) -> str:
    result = process_runner(
        ["git", "-C", str(repository_root.resolve()), "rev-parse", "HEAD"],
        cwd=str(repository_root.resolve()),
        env=_sanitized_environment(repository_root=repository_root),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if int(result.returncode) != 0:
        raise P6BalancedOrchestratorError("control-plane Git identity is unavailable")
    head = str(result.stdout or "").strip()
    if _GIT_RE.fullmatch(head) is None:
        raise P6BalancedOrchestratorError("control-plane Git identity is invalid")
    return head


def _quality_bundle_snapshots(root: Path) -> dict[str, _FileSnapshot]:
    return _snapshot_directory_members(
        root,
        _QUALITY_BUNDLE_FILES,
        exact_members=True,
        name="quality bundle",
    )


def _quality_bundle_hashes(
    snapshots: Mapping[str, _FileSnapshot],
) -> dict[str, str]:
    if set(snapshots) != set(_QUALITY_BUNDLE_FILES):
        raise P6BalancedOrchestratorError("quality bundle snapshot is incomplete")
    return {name: snapshots[name].sha256 for name in sorted(snapshots)}


def _stage_snapshot_set(
    destination: Path,
    snapshots: Mapping[str, _FileSnapshot],
    filenames: Mapping[str, str],
) -> None:
    destination.mkdir(mode=0o700)
    if set(snapshots) != set(filenames):
        raise P6BalancedOrchestratorError("snapshot set is incomplete")
    for name, filename in filenames.items():
        _write_snapshot(destination / filename, snapshots[name])


def _canonical_trace_relative_path(value: Any, *, field: str) -> str:
    raw = str(value or "")
    if not raw or "\\" in raw:
        raise P6BalancedOrchestratorError(f"{field} is invalid")
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or path.as_posix() != raw
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.parts[0] not in _TRACE_DIRECTORY_NAMES
    ):
        raise P6BalancedOrchestratorError(f"{field} is invalid")
    return raw


def _trace_sidecar_snapshots(
    *, run_dir: Path, manifest_snapshot: _FileSnapshot
) -> dict[str, _FileSnapshot]:
    """Snapshot the exact manifest-selected trace object graph without symlinks."""

    manifest = _object_from_snapshot(manifest_snapshot, name="decision-trace manifest")
    selected: set[str] = set()
    for collection_name in ("traces", "coverage_traces"):
        collection = manifest.get(collection_name)
        if not isinstance(collection, Mapping):
            raise P6BalancedOrchestratorError("decision-trace manifest is incomplete")
        for key, row in collection.items():
            if not isinstance(key, str) or not key or not isinstance(row, Mapping):
                raise P6BalancedOrchestratorError("decision-trace manifest row is invalid")
            selected.add(
                _canonical_trace_relative_path(
                    row.get("path"), field=f"decision trace {collection_name} path"
                )
            )
    for field, directory in (
        ("evidence_object_sha256", "evidence_objects"),
        ("model_event_sha256", "model_events"),
    ):
        digests = manifest.get(field)
        if (
            not isinstance(digests, list)
            or any(not isinstance(digest, str) for digest in digests)
            or len(digests) != len(set(digests))
        ):
            raise P6BalancedOrchestratorError("decision-trace object manifest is invalid")
        for digest in digests:
            if _SHA256_RE.fullmatch(digest) is None:
                raise P6BalancedOrchestratorError("decision-trace object digest is invalid")
            selected.add(f"{directory}/{digest}.json")
    if (
        int(manifest.get("trace_count") or 0) != len(manifest.get("traces") or {})
        or int(manifest.get("coverage_trace_count") or 0)
        != len(manifest.get("coverage_traces") or {})
        or int(manifest.get("evidence_object_count") or 0)
        != len(manifest.get("evidence_object_sha256") or [])
        or int(manifest.get("model_event_count") or 0)
        != len(manifest.get("model_event_sha256") or [])
    ):
        raise P6BalancedOrchestratorError("decision-trace manifest counts do not conserve")
    return {
        relative: _snapshot_regular_file(
            run_dir / Path(*PurePosixPath(relative).parts),
            name="decision-trace sidecar",
        )
        for relative in sorted(selected)
    }


def _literal_absolute_path(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _canonical_truth_paths(
    *, repository_root: Path, legacy_truth_path: Path, v16_truth_path: Path
) -> dict[str, Path]:
    root = repository_root.resolve()
    expected = {name: root / relative for name, relative in _CANONICAL_TRUTH_FILES.items()}
    supplied = {
        "legacy_truth": Path(legacy_truth_path),
        "v16_truth": Path(v16_truth_path),
    }
    if any(
        _literal_absolute_path(supplied[name]) != _literal_absolute_path(expected[name])
        for name in expected
    ):
        raise P6BalancedOrchestratorError("canonical Truth paths are invalid")
    return expected


def _canonical_truth_snapshots(
    *,
    repository_root: Path,
    execution_root: Path,
    legacy_truth_path: Path,
    v16_truth_path: Path,
) -> dict[str, _FileSnapshot]:
    # Caller paths are only a canonical-location assertion.  The bytes are
    # always read from the private exact-control-plane Git tree.
    _canonical_truth_paths(
        repository_root=repository_root,
        legacy_truth_path=legacy_truth_path,
        v16_truth_path=v16_truth_path,
    )
    return {
        name: _snapshot_regular_file(
            execution_root.resolve() / relative,
            name="committed canonical Truth input",
        )
        for name, relative in _CANONICAL_TRUTH_FILES.items()
    }


def _canonical_source_snapshots(
    *, execution_root: Path, truth_snapshots: Mapping[str, _FileSnapshot]
) -> dict[str, _FileSnapshot]:
    if set(truth_snapshots) != {"legacy_truth", "v16_truth"}:
        raise P6BalancedOrchestratorError("canonical Truth snapshot set is incomplete")
    root = execution_root.resolve()
    paths = {name: root / relative for name, relative in _CANONICAL_SOURCE_FILES.items()}
    snapshots = {
        name: _snapshot_regular_file(path, name="canonical scoring source")
        for name, path in sorted(paths.items())
    }
    snapshots.update(truth_snapshots)
    return snapshots


def _snapshot_hashes(snapshots: Mapping[str, _FileSnapshot]) -> dict[str, str]:
    return {name: snapshot.sha256 for name, snapshot in sorted(snapshots.items())}


def _scoring_control_snapshots(execution_root: Path) -> dict[str, _FileSnapshot]:
    root = execution_root.resolve()
    return {
        name: _snapshot_regular_file(
            root / _CANONICAL_SOURCE_FILES[name],
            name="canonical scoring implementation",
        )
        for name in _SCORING_CONTROL_SOURCE_NAMES
    }


def _identity_payload(identity: BalancedRunIdentity) -> dict[str, Any]:
    return {
        "workflow_run_id": identity.workflow_run_id,
        "workflow_run_attempt": identity.workflow_run_attempt,
        "attempt_id": identity.attempt_id,
        "control_plane_commit": identity.control_plane_commit,
        "candidate_git_sha": identity.candidate_git_sha,
        "candidate_git_tree": identity.candidate_git_tree,
    }


def validate_quality_revalidation_receipt(
    value: Mapping[str, Any], *, identity: BalancedRunIdentity | None = None
) -> None:
    if set(value) != {
        "schema_version",
        "source_control_plane_commit",
        "identity",
        "canonical_source_sha256s",
        "input_bundle_sha256s",
        "output_bundle_sha256s",
        "quality_gate_content_sha256",
        "byte_exact",
        "authority",
        "content_sha256",
    }:
        raise P6BalancedOrchestratorError("quality revalidation receipt fields are invalid")
    identity_row = value.get("identity")
    identity_fields = {
        "workflow_run_id",
        "workflow_run_attempt",
        "attempt_id",
        "control_plane_commit",
        "candidate_git_sha",
        "candidate_git_tree",
    }
    if not isinstance(identity_row, Mapping) or set(identity_row) != identity_fields:
        raise P6BalancedOrchestratorError("quality revalidation identity is invalid")
    try:
        if type(identity_row["workflow_run_attempt"]) is not int:
            raise ValueError
        receipt_identity = BalancedRunIdentity(
            workflow_run_id=str(identity_row["workflow_run_id"]),
            workflow_run_attempt=int(identity_row["workflow_run_attempt"]),
            attempt_id=str(identity_row["attempt_id"]),
            control_plane_commit=str(identity_row["control_plane_commit"]),
            candidate_git_sha=str(identity_row["candidate_git_sha"]),
            candidate_git_tree=str(identity_row["candidate_git_tree"]),
        )
        receipt_identity.validate()
    except (KeyError, TypeError, ValueError, P6BalancedOrchestratorError) as exc:
        raise P6BalancedOrchestratorError("quality revalidation identity is invalid") from exc
    if identity is not None and dict(identity_row) != _identity_payload(identity):
        raise P6BalancedOrchestratorError("quality revalidation identity does not match")
    source_hashes = value.get("canonical_source_sha256s")
    input_hashes = value.get("input_bundle_sha256s")
    output_hashes = value.get("output_bundle_sha256s")
    if (
        value.get("schema_version") != QUALITY_REVALIDATION_RECEIPT_VERSION
        or value.get("source_control_plane_commit") != identity_row.get("control_plane_commit")
        or value.get("byte_exact") is not True
        or value.get("authority") != "canonical_recalculation"
        or not isinstance(source_hashes, Mapping)
        or set(source_hashes) != {*_CANONICAL_SOURCE_FILES, "legacy_truth", "v16_truth"}
        or not isinstance(input_hashes, Mapping)
        or set(input_hashes) != set(_QUALITY_BUNDLE_FILES)
        or not isinstance(output_hashes, Mapping)
        or dict(output_hashes) != dict(input_hashes)
        or any(_SHA256_RE.fullmatch(str(item)) is None for item in source_hashes.values())
        or any(_SHA256_RE.fullmatch(str(item)) is None for item in input_hashes.values())
        or _SHA256_RE.fullmatch(str(value.get("quality_gate_content_sha256") or "")) is None
    ):
        raise P6BalancedOrchestratorError("quality revalidation receipt is invalid")
    unsigned = dict(value)
    supplied = unsigned.pop("content_sha256", None)
    if supplied != canonical_sha256(unsigned):
        raise P6BalancedOrchestratorError("quality revalidation receipt digest is invalid")


def _receipt_identity(value: Mapping[str, Any]) -> BalancedRunIdentity:
    validate_quality_revalidation_receipt(value)
    row = value["identity"]
    assert isinstance(row, Mapping)
    identity = BalancedRunIdentity(
        workflow_run_id=str(row["workflow_run_id"]),
        workflow_run_attempt=int(row["workflow_run_attempt"]),
        attempt_id=str(row["attempt_id"]),
        control_plane_commit=str(row["control_plane_commit"]),
        candidate_git_sha=str(row["candidate_git_sha"]),
        candidate_git_tree=str(row["candidate_git_tree"]),
    )
    identity.validate()
    return identity


def validate_complete_local_balanced_evidence(
    *,
    evidence_root: Path,
    expected_receipt_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], BalancedRunIdentity]:
    """Validate a complete local quality bundle plus its canonical receipt.

    A standalone quality gate is deliberately insufficient: the report,
    scores, bindings, usage/projection evidence, freeze manifest, and the
    authoritative byte-exact revalidation receipt must all be present.
    """

    from scripts.p6_balanced_quality_gate import validate_quality_gate_bundle

    if _SHA256_RE.fullmatch(expected_receipt_sha256) is None:
        raise P6BalancedOrchestratorError("local evidence receipt digest is invalid")
    root = Path(evidence_root)
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise P6BalancedOrchestratorError("local evidence bundle is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or {entry.name for entry in root.iterdir()} != {"quality", LOCAL_BALANCED_EVIDENCE_RECEIPT}
    ):
        raise P6BalancedOrchestratorError("local evidence bundle members are invalid")
    quality_root = root / "quality"
    quality_snapshots = _quality_bundle_snapshots(quality_root)
    receipt_snapshot = _snapshot_regular_file(
        root / LOCAL_BALANCED_EVIDENCE_RECEIPT,
        name="local quality revalidation receipt",
    )
    if receipt_snapshot.sha256 != expected_receipt_sha256:
        raise P6BalancedOrchestratorError("local evidence receipt digest does not match")
    receipt = _object_from_snapshot(
        receipt_snapshot,
        name="local quality revalidation receipt",
    )
    identity = _receipt_identity(receipt)
    bundle_hashes = _quality_bundle_hashes(quality_snapshots)
    if (
        receipt.get("input_bundle_sha256s") != bundle_hashes
        or receipt.get("output_bundle_sha256s") != bundle_hashes
    ):
        raise P6BalancedOrchestratorError("local evidence receipt does not bind the bundle")
    gate = validate_quality_gate_bundle(quality_root)
    if (
        gate.get("content_sha256") != receipt.get("quality_gate_content_sha256")
        or gate.get("hard_gate_passed") is not True
        or gate.get("formal_benchmark") is not False
        or gate.get("release_eligible") is not False
    ):
        raise P6BalancedOrchestratorError("local evidence quality gate is not eligible")
    after = root.lstat()
    if _metadata_identity(after) != _metadata_identity(metadata):
        raise P6BalancedOrchestratorError("local evidence bundle changed during validation")
    return receipt, gate, identity


def revalidate_balanced_quality_bundle(
    *,
    restored_bundle: Path,
    legacy_truth_path: Path,
    v16_truth_path: Path,
    identity: BalancedRunIdentity,
    output: Path,
    receipt_path: Path,
    repository_root: Path,
    process_runner: ProcessRunner = subprocess.run,
    python_executable: str = sys.executable,
    git_head_resolver: GitHeadResolver | None = None,
) -> dict[str, Any]:
    """Authoritatively rescore one restored exact bundle from its source commit."""

    identity.validate()
    from scripts.p6_balanced_quality_gate import validate_quality_gate_bundle

    output_resolved = output.resolve()
    receipt_resolved = receipt_path.resolve()
    restored_resolved = restored_bundle.resolve()
    if (
        output.exists()
        or output.is_symlink()
        or receipt_path.exists()
        or receipt_path.is_symlink()
        or receipt_resolved == output_resolved
        or receipt_resolved.is_relative_to(output_resolved)
        or output_resolved.is_relative_to(restored_resolved)
        or receipt_resolved.is_relative_to(restored_resolved)
    ):
        raise P6BalancedOrchestratorError("quality revalidation output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix=".p6-quality-revalidate.", dir=output.parent))
    output_committed = False
    control_plane_snapshot: _ControlPlaneTreeSnapshot | None = None
    try:
        restored_snapshots = _quality_bundle_snapshots(restored_bundle)
        restored_copy = workspace / "restored"
        _stage_snapshot_set(restored_copy, restored_snapshots, _QUALITY_BUNDLE_FILES)
        restored_gate = validate_quality_gate_bundle(restored_copy)
        input_hashes = _quality_bundle_hashes(restored_snapshots)
        head = (
            git_head_resolver(repository_root.resolve())
            if git_head_resolver is not None
            else _resolve_repository_head(repository_root, process_runner=process_runner)
        )
        if _GIT_RE.fullmatch(str(head)) is None or head != identity.control_plane_commit:
            raise P6BalancedOrchestratorError("control-plane HEAD does not match frozen manifest")
        control_plane_snapshot = _materialize_control_plane_tree(
            repository_root=repository_root,
            control_plane_commit=identity.control_plane_commit,
            destination=workspace / "control-plane",
        )
        if control_plane_snapshot.commit_sha != identity.control_plane_commit:
            raise P6BalancedOrchestratorError("control-plane snapshot identity does not match")
        frozen = workspace / "frozen"
        frozen.mkdir(mode=0o700)
        for source_name, target_name in {
            "report": "report.json",
            "bindings": "bindings.json",
            "trace_sidecars": TRACE_SIDECAR_EVIDENCE_FILENAME,
            "usage_events": USAGE_EVENTS_EVIDENCE_FILENAME,
            "usage_evidence": "usage-evidence.json",
            "frozen_manifest": "manifest.json",
        }.items():
            _write_snapshot(frozen / target_name, restored_snapshots[source_name])
        validated, frozen_snapshots, projection_snapshot = _snapshot_and_validate_frozen_scan(
            frozen_root=frozen,
            projection_path=restored_copy / "producer-projection.json",
            identity=identity,
        )
        truth_snapshots = _canonical_truth_snapshots(
            repository_root=repository_root,
            execution_root=control_plane_snapshot.root,
            legacy_truth_path=legacy_truth_path,
            v16_truth_path=v16_truth_path,
        )
        source_snapshots = _canonical_source_snapshots(
            execution_root=control_plane_snapshot.root,
            truth_snapshots=truth_snapshots,
        )
        canonical_sources = _snapshot_hashes(source_snapshots)
        control_source_snapshots = {
            name: source_snapshots[name] for name in _SCORING_CONTROL_SOURCE_NAMES
        }
        regenerated = workspace / "regenerated"
        regenerated_gate = _score_frozen_balanced_scan_with_snapshots(
            validated=validated,
            frozen_snapshots=frozen_snapshots,
            projection_snapshot=projection_snapshot,
            truth_snapshots=truth_snapshots,
            control_source_snapshots=control_source_snapshots,
            provider_config_snapshot=source_snapshots["provider_config"],
            identity=identity,
            output=regenerated,
            execution_root=control_plane_snapshot.root,
            failure_aggregate_path=None,
            process_runner=process_runner,
            python_executable=python_executable,
        )
        regenerated_snapshots = _quality_bundle_snapshots(regenerated)
        output_hashes = _quality_bundle_hashes(regenerated_snapshots)
        if (
            regenerated_gate != restored_gate
            or output_hashes != input_hashes
            or any(
                regenerated_snapshots[name].payload != restored_snapshots[name].payload
                for name in _QUALITY_BUNDLE_FILES
            )
        ):
            raise P6BalancedOrchestratorError("quality bundle did not reproduce byte-exactly")
        final_head = (
            git_head_resolver(repository_root.resolve())
            if git_head_resolver is not None
            else _resolve_repository_head(repository_root, process_runner=process_runner)
        )
        if final_head != head:
            raise P6BalancedOrchestratorError("control-plane HEAD changed during revalidation")
        receipt: dict[str, Any] = {
            "schema_version": QUALITY_REVALIDATION_RECEIPT_VERSION,
            "source_control_plane_commit": str(head),
            "identity": _identity_payload(identity),
            "canonical_source_sha256s": canonical_sources,
            "input_bundle_sha256s": input_hashes,
            "output_bundle_sha256s": output_hashes,
            "quality_gate_content_sha256": str(regenerated_gate["content_sha256"]),
            "byte_exact": True,
            "authority": "canonical_recalculation",
        }
        receipt["content_sha256"] = canonical_sha256(receipt)
        validate_quality_revalidation_receipt(receipt, identity=identity)
        receipt_temp = workspace / "receipt.json"
        _write_json(receipt_temp, receipt)
        if (
            output.exists()
            or output.is_symlink()
            or receipt_path.exists()
            or receipt_path.is_symlink()
        ):
            raise P6BalancedOrchestratorError("quality revalidation output appeared")
        final_bundle = workspace / "final-bundle"
        _stage_snapshot_set(final_bundle, regenerated_snapshots, _QUALITY_BUNDLE_FILES)
        if validate_quality_gate_bundle(final_bundle) != regenerated_gate:
            raise P6BalancedOrchestratorError("quality bundle final copy is invalid")
        final_bundle.replace(output)
        output_committed = True
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_temp.replace(receipt_path)
        return receipt
    except BaseException:
        if output_committed and output.exists() and output.is_dir():
            shutil.rmtree(output, ignore_errors=True)
        raise
    finally:
        if control_plane_snapshot is not None:
            _remove_control_plane_tree(control_plane_snapshot)
        shutil.rmtree(workspace, ignore_errors=True)


def revalidate_complete_local_balanced_evidence(
    *,
    evidence_root: Path,
    expected_receipt_sha256: str,
    repository_root: Path,
    process_runner: ProcessRunner = subprocess.run,
    python_executable: str = sys.executable,
) -> tuple[dict[str, Any], dict[str, Any], BalancedRunIdentity]:
    """Canonically rescore and byte-compare one complete local evidence bundle."""

    receipt, gate, identity = validate_complete_local_balanced_evidence(
        evidence_root=evidence_root,
        expected_receipt_sha256=expected_receipt_sha256,
    )
    root = Path(evidence_root).resolve(strict=True)
    workspace = Path(tempfile.mkdtemp(prefix=".p6-local-evidence-revalidate.", dir=root.parent))
    try:
        regenerated_receipt_path = workspace / "quality-revalidation-receipt.json"
        regenerated_receipt = revalidate_balanced_quality_bundle(
            restored_bundle=root / "quality",
            legacy_truth_path=repository_root / _CANONICAL_TRUTH_FILES["legacy_truth"],
            v16_truth_path=repository_root / _CANONICAL_TRUTH_FILES["v16_truth"],
            identity=identity,
            output=workspace / "quality",
            receipt_path=regenerated_receipt_path,
            repository_root=repository_root,
            process_runner=process_runner,
            python_executable=python_executable,
            # Hosted entry is checked out at the later evidence merge.  The
            # scorer is nevertheless materialized from this receipt's exact
            # immutable source commit and may not read the live checkout.
            git_head_resolver=lambda _root: identity.control_plane_commit,
        )
        original_receipt = _snapshot_regular_file(
            root / LOCAL_BALANCED_EVIDENCE_RECEIPT,
            name="local quality revalidation receipt",
        )
        regenerated_snapshot = _snapshot_regular_file(
            regenerated_receipt_path,
            name="regenerated local quality revalidation receipt",
        )
        if (
            regenerated_receipt != receipt
            or regenerated_snapshot.payload != original_receipt.payload
        ):
            raise P6BalancedOrchestratorError(
                "local evidence receipt did not reproduce byte-exactly"
            )
        return receipt, gate, identity
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def verify_committed_local_balanced_evidence(
    *,
    repository_root: Path,
    hosted_control_plane_commit: str,
    evidence_commit: str,
    expected_receipt_sha256: str,
    process_runner: ProcessRunner = subprocess.run,
    python_executable: str = sys.executable,
) -> dict[str, Any]:
    """Verify the immutable local evidence commit before hosted provider work.

    The evidence commit must add exactly the complete nine-file bundle to its
    tested parent.  The hosted control-plane commit must be a two-parent merge
    that retains those exact bytes and no other change relative to the tested
    source.  The committed bundle is then canonically rescored from the tested
    commit and compared byte-for-byte with its receipt.
    """

    root = Path(repository_root).resolve(strict=True)
    if (
        _GIT_RE.fullmatch(hosted_control_plane_commit) is None
        or _GIT_RE.fullmatch(evidence_commit) is None
        or _SHA256_RE.fullmatch(expected_receipt_sha256) is None
    ):
        raise P6BalancedOrchestratorError("local evidence commit identity is invalid")
    if _resolve_repository_head(root, process_runner=process_runner) != hosted_control_plane_commit:
        raise P6BalancedOrchestratorError("hosted control-plane HEAD is invalid")

    def git_text(*arguments: str) -> str:
        return _run_git_bytes(root, arguments).decode("utf-8", errors="strict").strip()

    for revision in (hosted_control_plane_commit, evidence_commit):
        if git_text("cat-file", "-t", revision) != "commit":
            raise P6BalancedOrchestratorError("local evidence commit is unavailable")
    evidence_parents = git_text("rev-list", "--parents", "-n", "1", evidence_commit).split()
    if len(evidence_parents) != 2 or evidence_parents[0] != evidence_commit:
        raise P6BalancedOrchestratorError("local evidence commit parent is invalid")
    tested_commit = evidence_parents[1]
    hosted_parents = git_text(
        "rev-list", "--parents", "-n", "1", hosted_control_plane_commit
    ).split()
    if (
        len(hosted_parents) != 3
        or hosted_parents[0] != hosted_control_plane_commit
        or evidence_commit not in hosted_parents[1:]
    ):
        raise P6BalancedOrchestratorError("hosted evidence merge lineage is invalid")
    expected_paths = set(_LOCAL_BALANCED_EVIDENCE_FILES.values())

    def changed_paths(left: str, right: str) -> set[str]:
        rows = git_text("diff", "--no-renames", "--name-status", left, right).splitlines()
        expected_rows = {f"A\t{path}" for path in expected_paths}
        if set(rows) != expected_rows or len(rows) != len(expected_rows):
            raise P6BalancedOrchestratorError("local evidence commit contents are invalid")
        return {row.split("\t", 1)[1] for row in rows}

    if changed_paths(tested_commit, evidence_commit) != expected_paths:
        raise P6BalancedOrchestratorError("local evidence commit contents are invalid")
    if changed_paths(tested_commit, hosted_control_plane_commit) != expected_paths:
        raise P6BalancedOrchestratorError("hosted evidence merge contents are invalid")
    if git_text("rev-parse", f"{evidence_commit}^{{tree}}") != git_text(
        "rev-parse", f"{hosted_control_plane_commit}^{{tree}}"
    ):
        raise P6BalancedOrchestratorError("hosted evidence tree is invalid")

    workspace = Path(tempfile.mkdtemp(prefix=".p6-committed-local-evidence."))
    control_plane_snapshot: _ControlPlaneTreeSnapshot | None = None
    try:
        staged = workspace / "evidence"
        (staged / "quality").mkdir(parents=True, mode=0o700)
        for local_relative, committed_path in sorted(_LOCAL_BALANCED_EVIDENCE_FILES.items()):
            row = git_text("ls-tree", evidence_commit, "--", committed_path).split()
            if len(row) != 4 or row[:2] != ["100644", "blob"] or row[3] != committed_path:
                raise P6BalancedOrchestratorError("local evidence Git member is invalid")
            payload = _run_git_bytes(root, ("show", f"{evidence_commit}:{committed_path}"))
            target = staged / local_relative
            target.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(target, flags, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
        receipt, gate, identity = revalidate_complete_local_balanced_evidence(
            evidence_root=staged,
            expected_receipt_sha256=expected_receipt_sha256,
            repository_root=root,
            process_runner=process_runner,
            python_executable=python_executable,
        )
        tested_tree = git_text("rev-parse", f"{tested_commit}^{{tree}}")
        if (
            identity.control_plane_commit != tested_commit
            or identity.candidate_git_sha != tested_commit
            or identity.candidate_git_tree != tested_tree
        ):
            raise P6BalancedOrchestratorError("local evidence tested identity is invalid")
        control_plane_snapshot = _materialize_control_plane_tree(
            repository_root=root,
            control_plane_commit=hosted_control_plane_commit,
            destination=workspace / "hosted-control-plane",
        )
        contract = require_p6_provider_contract(
            control_plane_snapshot.root / "test/range/zscope.benchmark.yaml"
        )
        runtime_source = workspace / "producer-runtime" / "zscope"
        runtime_sha256 = prepare_p6_runtime_source(
            runtime_source,
            source_root=control_plane_snapshot.root / "zscope",
        )
        bindings = gate.get("bindings")
        expected_bindings = {
            "git_commit": tested_commit,
            "git_tree": tested_tree,
            "candidate_sha256": hashlib.sha256(tested_commit.encode("ascii")).hexdigest(),
            "provider_identity_sha256": contract.identity_sha256,
            "runtime_sha256": runtime_sha256,
            "config_sha256": contract.config_sha256,
        }
        if not isinstance(bindings, Mapping) or any(
            bindings.get(name) != value for name, value in expected_bindings.items()
        ):
            raise P6BalancedOrchestratorError("local evidence candidate binding is invalid")
        if (
            _resolve_repository_head(root, process_runner=process_runner)
            != hosted_control_plane_commit
        ):
            raise P6BalancedOrchestratorError("hosted control-plane HEAD changed")
        return {
            "tested_commit": tested_commit,
            "evidence_commit": evidence_commit,
            "hosted_control_plane_commit": hosted_control_plane_commit,
            "receipt_sha256": expected_receipt_sha256,
            "receipt_content_sha256": str(receipt["content_sha256"]),
            "quality_gate_content_sha256": str(gate["content_sha256"]),
            "canonical_revalidation_passed": True,
            "complete_bundle_present": True,
        }
    finally:
        if control_plane_snapshot is not None:
            _remove_control_plane_tree(control_plane_snapshot)
        shutil.rmtree(workspace, ignore_errors=True)


_FROZEN_INPUT_FILES = {
    "manifest": "manifest.json",
    "report": "report.json",
    "bindings": "bindings.json",
    "trace_sidecars": TRACE_SIDECAR_EVIDENCE_FILENAME,
    "usage_events": USAGE_EVENTS_EVIDENCE_FILENAME,
    "usage_evidence": "usage-evidence.json",
}


def _usage_rows_from_snapshot(snapshot: _FileSnapshot) -> list[dict[str, Any]]:
    workspace = Path(tempfile.mkdtemp(prefix=".p6-usage-sidecar."))
    try:
        path = workspace / USAGE_EVENTS_EVIDENCE_FILENAME
        _write_snapshot(path, snapshot)
        return _read_usage_events_jsonl(path)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def _validate_frozen_snapshots(
    *,
    frozen_snapshots: Mapping[str, _FileSnapshot],
    projection_snapshot: _FileSnapshot,
    identity: BalancedRunIdentity,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    frozen = _object_from_snapshot(frozen_snapshots["manifest"], name="balanced freeze manifest")
    if set(frozen) != {
        "schema_version",
        "workflow_run_id",
        "workflow_run_attempt",
        "control_plane_commit",
        "candidate_git_sha",
        "candidate_git_tree",
        "attempt_id",
        "llm_usage_events_sha256",
        "llm_usage_events_call_count",
        "trace_sidecars_sha256",
        "trace_sidecar_member_count",
        "trace_count",
        "coverage_trace_count",
        "evidence_object_count",
        "model_event_count",
        "report_sha256",
        "bindings_sha256",
        "usage_evidence_sha256",
        "projection_sha256",
        "answer_material_present",
        "formal_benchmark",
        "release_eligible",
        "content_sha256",
    }:
        raise P6BalancedOrchestratorError("balanced freeze manifest fields are invalid")
    supplied = frozen.get("content_sha256")
    unsigned = dict(frozen)
    unsigned.pop("content_sha256", None)
    expected = {
        "schema_version": FROZEN_SCAN_SCHEMA_VERSION,
        "workflow_run_id": identity.workflow_run_id,
        "workflow_run_attempt": identity.workflow_run_attempt,
        "control_plane_commit": identity.control_plane_commit,
        "candidate_git_sha": identity.candidate_git_sha,
        "candidate_git_tree": identity.candidate_git_tree,
        "attempt_id": identity.attempt_id,
        "answer_material_present": False,
        "formal_benchmark": False,
        "release_eligible": False,
    }
    if (
        supplied != canonical_sha256(unsigned)
        or any(frozen.get(key) != value for key, value in expected.items())
        or _SHA256_RE.fullmatch(str(frozen.get("llm_usage_events_sha256") or "")) is None
        or type(frozen.get("llm_usage_events_call_count")) is not int
        or int(frozen.get("llm_usage_events_call_count") or 0) < 1
        or _SHA256_RE.fullmatch(str(frozen.get("trace_sidecars_sha256") or "")) is None
        or any(
            type(frozen.get(field)) is not int or int(frozen.get(field) or 0) < 0
            for field in (
                "trace_sidecar_member_count",
                "trace_count",
                "coverage_trace_count",
                "evidence_object_count",
                "model_event_count",
            )
        )
    ):
        raise P6BalancedOrchestratorError("balanced freeze manifest is invalid")
    for name, field in (
        ("report", "report_sha256"),
        ("bindings", "bindings_sha256"),
        ("usage_evidence", "usage_evidence_sha256"),
        ("trace_sidecars", "trace_sidecars_sha256"),
        ("usage_events", "llm_usage_events_sha256"),
    ):
        if frozen_snapshots[name].sha256 != frozen.get(field):
            raise P6BalancedOrchestratorError("balanced freeze artifact digest is invalid")
    if projection_snapshot.sha256 != frozen.get("projection_sha256"):
        raise P6BalancedOrchestratorError("balanced projection digest is invalid")
    projection = _projection(projection_snapshot, identity=identity)
    report = _object_from_snapshot(frozen_snapshots["report"], name="frozen balanced report")
    bindings = _object_from_snapshot(frozen_snapshots["bindings"], name="balanced bindings")
    usage = _object_from_snapshot(
        frozen_snapshots["usage_evidence"], name="balanced usage evidence"
    )
    usage_unsigned = dict(usage)
    usage_supplied = usage_unsigned.pop("content_sha256", None)
    if (
        set(usage)
        != {
            "schema_version",
            "workflow_run_id",
            "workflow_run_attempt",
            "attempt_id",
            "llm_usage_events_sha256",
            "llm_usage_events_call_count",
            "trace_sidecars_sha256",
            "trace_sidecar_member_count",
            "trace_count",
            "coverage_trace_count",
            "evidence_object_count",
            "model_event_count",
            "score_fields",
            "answer_material_present",
            "formal_benchmark",
            "release_eligible",
            "content_sha256",
        }
        or usage.get("schema_version") != USAGE_EVIDENCE_SCHEMA_VERSION
        or usage_supplied != canonical_sha256(usage_unsigned)
        or usage.get("workflow_run_id") != identity.workflow_run_id
        or usage.get("workflow_run_attempt") != identity.workflow_run_attempt
        or usage.get("attempt_id") != identity.attempt_id
        or usage.get("llm_usage_events_sha256") != frozen.get("llm_usage_events_sha256")
        or usage.get("llm_usage_events_call_count") != frozen.get("llm_usage_events_call_count")
        or usage.get("trace_sidecars_sha256") != frozen.get("trace_sidecars_sha256")
        or any(
            usage.get(field) != frozen.get(field)
            for field in (
                "trace_sidecar_member_count",
                "trace_count",
                "coverage_trace_count",
                "evidence_object_count",
                "model_event_count",
            )
        )
        or _SHA256_RE.fullmatch(str(usage.get("llm_usage_events_sha256") or "")) is None
        or type(usage.get("llm_usage_events_call_count")) is not int
        or int(usage.get("llm_usage_events_call_count") or 0) < 1
        or usage.get("answer_material_present") is not False
        or usage.get("formal_benchmark") is not False
        or usage.get("release_eligible") is not False
        or not isinstance(usage.get("score_fields"), Mapping)
        or set(usage["score_fields"]) != _USAGE_FIELDS
    ):
        raise P6BalancedOrchestratorError("balanced usage evidence is invalid")
    try:
        trace_payloads = validate_trace_sidecar_evidence(
            _object_from_snapshot(
                frozen_snapshots["trace_sidecars"],
                name="balanced trace sidecar evidence",
            )
        )
    except P6SidecarEvidenceError as exc:
        raise P6BalancedOrchestratorError("balanced trace sidecar evidence is invalid") from exc
    if (
        len(trace_payloads) != frozen.get("trace_sidecar_member_count")
        or any(
            frozen.get(field) != usage.get(field)
            for field in (
                "trace_count",
                "coverage_trace_count",
                "evidence_object_count",
                "model_event_count",
            )
        )
    ):
        raise P6BalancedOrchestratorError("balanced trace sidecar counts do not conserve")
    try:
        usage_rows = _usage_rows_from_snapshot(frozen_snapshots["usage_events"])
    except (BenchmarkError, OSError, UnicodeError) as exc:
        raise P6BalancedOrchestratorError("balanced usage sidecar is invalid") from exc
    if len(usage_rows) != frozen.get("llm_usage_events_call_count"):
        raise P6BalancedOrchestratorError("balanced usage sidecar count does not conserve")
    if (
        report.get("answer_material_present") is not False
        or not isinstance(report.get("run_manifest"), Mapping)
        or report["run_manifest"].get("validation_queue_drained") is not True
    ):
        raise P6BalancedOrchestratorError("frozen balanced report is invalid")
    return frozen, report, bindings, {**usage, "producer_projection": projection}


def _snapshot_and_validate_frozen_scan(
    *,
    frozen_root: Path,
    projection_path: Path,
    identity: BalancedRunIdentity,
) -> tuple[
    tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]],
    dict[str, _FileSnapshot],
    _FileSnapshot,
]:
    identity.validate()
    frozen_snapshots = _snapshot_directory_members(
        frozen_root,
        _FROZEN_INPUT_FILES,
        exact_members=True,
        name="balanced frozen input",
    )
    projection_snapshot = _snapshot_regular_file(
        projection_path, name="balanced producer projection"
    )
    validated = _validate_frozen_snapshots(
        frozen_snapshots=frozen_snapshots,
        projection_snapshot=projection_snapshot,
        identity=identity,
    )
    return validated, frozen_snapshots, projection_snapshot


def validate_frozen_balanced_scan(
    *,
    frozen_root: Path,
    projection_path: Path,
    identity: BalancedRunIdentity,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Revalidate the complete immutable pre-score boundary."""

    validated, _, _ = _snapshot_and_validate_frozen_scan(
        frozen_root=frozen_root,
        projection_path=projection_path,
        identity=identity,
    )
    return validated


def _sanitized_environment(
    *, repository_root: Path, legacy_truth: Path | None = None
) -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if key.upper() in _SCORER_ENV_ALLOWLIST
    }
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONSAFEPATH"] = "1"
    environment["PYTHONPATH"] = str(repository_root.resolve())
    if legacy_truth is not None:
        environment["Z_SCOPE_BENCHMARK_TRUTH"] = str(legacy_truth.resolve())
    return environment


def _run_scorer(
    runner: ProcessRunner,
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> None:
    result = runner(
        [str(value) for value in argv],
        cwd=str(cwd),
        env=dict(environment),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if int(result.returncode) != 0:
        raise P6BalancedOrchestratorError("balanced scorer failed")


def score_frozen_balanced_scan(
    *,
    frozen_root: Path,
    projection_path: Path,
    legacy_truth_path: Path,
    v16_truth_path: Path,
    identity: BalancedRunIdentity,
    output: Path,
    repository_root: Path,
    failure_aggregate_path: Path | None = None,
    process_runner: ProcessRunner = subprocess.run,
    python_executable: str = sys.executable,
) -> dict[str, Any]:
    """Score and seal an exact freeze without exposing secrets to either scorer."""

    validated, frozen_snapshots, projection_snapshot = _snapshot_and_validate_frozen_scan(
        frozen_root=frozen_root,
        projection_path=projection_path,
        identity=identity,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix=".p6-control-plane.", dir=output.parent))
    control_plane_snapshot: _ControlPlaneTreeSnapshot | None = None
    try:
        control_plane_snapshot = _materialize_control_plane_tree(
            repository_root=repository_root,
            control_plane_commit=identity.control_plane_commit,
            destination=workspace / "tree",
        )
        if control_plane_snapshot.commit_sha != identity.control_plane_commit:
            raise P6BalancedOrchestratorError("control-plane snapshot identity does not match")
        # Truth remains unavailable until the complete producer freeze and the
        # executable control-plane tree have both been independently sealed.
        truth_snapshots = _canonical_truth_snapshots(
            repository_root=repository_root,
            execution_root=control_plane_snapshot.root,
            legacy_truth_path=legacy_truth_path,
            v16_truth_path=v16_truth_path,
        )
        control_source_snapshots = _scoring_control_snapshots(control_plane_snapshot.root)
        provider_config_snapshot = _snapshot_regular_file(
            control_plane_snapshot.root / _CANONICAL_SOURCE_FILES["provider_config"],
            name="canonical provider config",
        )
        return _score_frozen_balanced_scan_with_snapshots(
            validated=validated,
            frozen_snapshots=frozen_snapshots,
            projection_snapshot=projection_snapshot,
            truth_snapshots=truth_snapshots,
            control_source_snapshots=control_source_snapshots,
            provider_config_snapshot=provider_config_snapshot,
            identity=identity,
            output=output,
            execution_root=control_plane_snapshot.root,
            failure_aggregate_path=failure_aggregate_path,
            process_runner=process_runner,
            python_executable=python_executable,
        )
    finally:
        if control_plane_snapshot is not None:
            _remove_control_plane_tree(control_plane_snapshot)
        shutil.rmtree(workspace, ignore_errors=True)


def _score_frozen_balanced_scan_with_snapshots(
    *,
    validated: tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]],
    frozen_snapshots: Mapping[str, _FileSnapshot],
    projection_snapshot: _FileSnapshot,
    truth_snapshots: Mapping[str, _FileSnapshot],
    control_source_snapshots: Mapping[str, _FileSnapshot],
    provider_config_snapshot: _FileSnapshot,
    identity: BalancedRunIdentity,
    output: Path,
    execution_root: Path,
    failure_aggregate_path: Path | None,
    process_runner: ProcessRunner,
    python_executable: str,
) -> dict[str, Any]:
    if set(truth_snapshots) != {"legacy_truth", "v16_truth"}:
        raise P6BalancedOrchestratorError("canonical Truth snapshot set is incomplete")
    if set(control_source_snapshots) != set(_SCORING_CONTROL_SOURCE_NAMES):
        raise P6BalancedOrchestratorError("scoring implementation snapshot set is incomplete")
    _, _, _, usage = validated
    recompute_root = Path(tempfile.mkdtemp(prefix=".p6-sidecar-recompute.", dir=output.parent))
    try:
        recompute_report = recompute_root / "report.json"
        _write_snapshot(recompute_report, frozen_snapshots["report"])
        _write_snapshot(
            recompute_root / USAGE_EVENTS_EVIDENCE_FILENAME,
            frozen_snapshots["usage_events"],
        )
        trace_value = _object_from_snapshot(
            frozen_snapshots["trace_sidecars"],
            name="balanced trace sidecar evidence",
        )
        try:
            materialize_trace_sidecar_evidence(trace_value, destination=recompute_root / "trace")
        except P6SidecarEvidenceError as exc:
            raise P6BalancedOrchestratorError(
                "balanced trace sidecar evidence cannot be materialized"
            ) from exc
        for source in sorted((recompute_root / "trace").rglob("*")):
            if source.is_file():
                destination = recompute_root / source.relative_to(recompute_root / "trace")
                destination.parent.mkdir(parents=True, exist_ok=True)
                source.replace(destination)
        shutil.rmtree(recompute_root / "trace")
        provider_config = recompute_root / "zscope.benchmark.yaml"
        _write_snapshot(provider_config, provider_config_snapshot)
        contract = require_p6_provider_contract(provider_config)
        recomputed = build_p6_answer_free_producer_metrics(
            report_path=recompute_report,
            run_dir=recompute_root,
            provider_contract=contract,
        )
        if (
            {name: recomputed.get(name) for name in sorted(_USAGE_FIELDS)}
            != dict(usage["score_fields"])
            or _p6_answer_free_gate_failures(recomputed)
        ):
            raise P6BalancedOrchestratorError(
                "balanced frozen sidecars do not reproduce producer metrics"
            )
    except (BenchmarkError, OSError, ValueError) as exc:
        if isinstance(exc, P6BalancedOrchestratorError):
            raise
        raise P6BalancedOrchestratorError(
            "balanced frozen sidecar recomputation failed"
        ) from exc
    finally:
        shutil.rmtree(recompute_root, ignore_errors=True)
    if failure_aggregate_path is not None and (
        failure_aggregate_path.exists() or failure_aggregate_path.is_symlink()
    ):
        raise P6BalancedOrchestratorError("quality failure aggregate output already exists")
    temp = _fresh_output(output)
    seal_parent: Path | None = None
    try:
        frozen_report = temp / "frozen-report.json"
        _write_snapshot(frozen_report, frozen_snapshots["report"])
        _write_snapshot(temp / "bindings.json", frozen_snapshots["bindings"])
        _write_snapshot(temp / "producer-projection.json", projection_snapshot)
        _write_snapshot(temp / "frozen-manifest.json", frozen_snapshots["manifest"])
        _write_snapshot(
            temp / TRACE_SIDECAR_EVIDENCE_FILENAME,
            frozen_snapshots["trace_sidecars"],
        )
        _write_snapshot(
            temp / USAGE_EVENTS_EVIDENCE_FILENAME,
            frozen_snapshots["usage_events"],
        )
        _write_snapshot(temp / "usage-evidence.json", frozen_snapshots["usage_evidence"])
        scorer_inputs = temp / ".scorer-input"
        scorer_inputs.mkdir(mode=0o700)
        scorer_report_copy = scorer_inputs / "frozen-report.json"
        legacy_truth_copy = scorer_inputs / "legacy-truth.json"
        v16_truth_copy = scorer_inputs / "v16-truth.json"
        _write_snapshot(scorer_report_copy, frozen_snapshots["report"])
        _write_snapshot(legacy_truth_copy, truth_snapshots["legacy_truth"])
        _write_snapshot(v16_truth_copy, truth_snapshots["v16_truth"])
        if os.name != "nt":
            for read_only_input in (
                scorer_report_copy,
                legacy_truth_copy,
                v16_truth_copy,
            ):
                read_only_input.chmod(0o400)
        control_inputs = temp / ".control-input"
        control_inputs.mkdir(mode=0o700)
        staged_control_paths: dict[str, Path] = {}
        for name in _SCORING_CONTROL_SOURCE_NAMES:
            staged = control_inputs / f"{name}.py"
            _write_snapshot(staged, control_source_snapshots[name])
            staged_control_paths[name] = staged
        legacy_launcher = control_inputs / "legacy-scorer-launcher.py"
        legacy_launcher.write_text(_LEGACY_SCORER_LAUNCHER, encoding="utf-8")
        scorer = staged_control_paths["v16_scorer"]
        gate_script = staged_control_paths["quality_gate"]
        legacy_raw = temp / "legacy-score-raw.json"
        legacy_score = temp / "legacy-score.json"
        v16_score = temp / "v16-score.json"
        quality_gate = temp / "p6-balanced-quality-gate.json"
        _run_scorer(
            process_runner,
            (
                python_executable,
                str(legacy_launcher),
                str(staged_control_paths["legacy_scorer_engine"]),
                str(staged_control_paths["legacy_scorer_wrapper"]),
                str(staged_control_paths["legacy_scorer_entry"]),
                "_score",
                "--report",
                str(scorer_report_copy),
                "--output",
                str(legacy_raw),
            ),
            cwd=execution_root,
            environment=_sanitized_environment(
                repository_root=execution_root,
                legacy_truth=legacy_truth_copy,
            ),
        )
        _run_scorer(
            process_runner,
            (
                python_executable,
                str(scorer),
                "score",
                "--report",
                str(scorer_report_copy),
                "--truth",
                str(v16_truth_copy),
                "--output",
                str(v16_score),
            ),
            cwd=execution_root,
            environment=_sanitized_environment(repository_root=execution_root),
        )
        legacy_raw_snapshot = _snapshot_regular_file(legacy_raw, name="legacy score")
        v16_score_snapshot = _snapshot_regular_file(v16_score, name="Truth v16 score")
        legacy = _object_from_snapshot(legacy_raw_snapshot, name="legacy score")
        v16 = _object_from_snapshot(v16_score_snapshot, name="Truth v16 score")
        report_sha = frozen_snapshots["report"].sha256
        legacy.update(dict(usage["score_fields"]))
        legacy["p6_frozen_report_sha256"] = report_sha
        v16["p6_frozen_report_sha256"] = report_sha
        _write_json(legacy_score, legacy)
        _write_json(v16_score, v16)
        v16_truth_partitions = temp / "v16-truth-partitions.json"
        _write_json(
            v16_truth_partitions,
            _truth_partition_projection(truth_snapshots["v16_truth"]),
        )
        legacy_raw.unlink()
        shutil.rmtree(scorer_inputs)
        gate_argv: list[str] = [
            python_executable,
            str(gate_script),
            "--report",
            str(frozen_report),
            "--legacy-score",
            str(legacy_score),
            "--v16-score",
            str(v16_score),
            "--v16-truth-partitions",
            str(v16_truth_partitions),
            "--producer-projection",
            str(temp / "producer-projection.json"),
            "--bindings",
            str(temp / "bindings.json"),
            "--frozen-manifest",
            str(temp / "frozen-manifest.json"),
            "--usage-evidence",
            str(temp / "usage-evidence.json"),
            "--usage-events",
            str(temp / USAGE_EVENTS_EVIDENCE_FILENAME),
            "--trace-sidecars",
            str(temp / TRACE_SIDECAR_EVIDENCE_FILENAME),
            "--output",
            str(quality_gate),
        ]
        if failure_aggregate_path is not None:
            gate_argv.extend(("--failure-aggregate", str(failure_aggregate_path)))
        _run_scorer(
            process_runner,
            gate_argv,
            cwd=execution_root,
            environment=_sanitized_environment(repository_root=execution_root),
        )
        if failure_aggregate_path is not None and (
            failure_aggregate_path.exists() or failure_aggregate_path.is_symlink()
        ):
            raise P6BalancedOrchestratorError("successful quality gate emitted a failure aggregate")
        # The gate CLI validates the same strict schema after writing.  Load it
        # again here so an incomplete or substituted subprocess output cannot
        # be selected as the shared orchestrator result.
        from scripts.p6_balanced_quality_gate import validate_quality_gate_bundle

        shutil.rmtree(control_inputs)
        final_snapshots = _quality_bundle_snapshots(temp)
        seal_parent = Path(tempfile.mkdtemp(prefix=f".{output.name}.sealed.", dir=output.parent))
        sealed = seal_parent / "bundle"
        _stage_snapshot_set(sealed, final_snapshots, _QUALITY_BUNDLE_FILES)
        gate = validate_quality_gate_bundle(sealed)
        _commit_output(sealed, output)
        shutil.rmtree(temp)
        return gate
    except BaseException:
        shutil.rmtree(temp, ignore_errors=True)
        raise
    finally:
        if seal_parent is not None:
            shutil.rmtree(seal_parent, ignore_errors=True)


__all__ = [
    "BalancedRunIdentity",
    "FROZEN_SCAN_SCHEMA_VERSION",
    "LOCAL_BALANCED_EVIDENCE_RECEIPT",
    "LOCAL_BALANCED_EVIDENCE_ROOT",
    "P6BalancedOrchestratorError",
    "QUALITY_REVALIDATION_RECEIPT_VERSION",
    "USAGE_EVIDENCE_SCHEMA_VERSION",
    "freeze_balanced_scan",
    "revalidate_complete_local_balanced_evidence",
    "revalidate_balanced_quality_bundle",
    "score_frozen_balanced_scan",
    "validate_frozen_balanced_scan",
    "validate_complete_local_balanced_evidence",
    "validate_quality_revalidation_receipt",
    "verify_committed_local_balanced_evidence",
]
