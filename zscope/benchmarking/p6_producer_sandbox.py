"""Physical source boundary for the host-side P6 cold producer.

The materializer runs before the cold producer process starts.  It selects a
minimal answer-free tree from one exact Git commit.  Truth, expected-answer
material, scorer/reviewer code, and post-score evidence are never written into
the child process' cwd/PYTHONPATH tree.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


HOST_PRODUCER_SANDBOX_SCHEMA_VERSION = "zscope.p6-host-producer-sandbox.v1"
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_TREE_BYTES = 128 * 1024 * 1024

_HOST_BENCHMARKING_FILES = frozenset(
    {
        "__init__.py",
        "benchmark_policy.v1.json",
        "benchmark_policy.v2.json",
        "isolation.py",
        "p6_expected_proxy_attestation.schema.json",
        "p6_producer_metrics.py",
        "p6_producer_package_init.py",
        "p6_producer_sandbox.py",
        "p6_protocol.py",
        "policy.py",
        "provider_runtime.py",
        "replay_bundle.py",
        "runner.py",
    }
)
_PUBLIC_RANGE_ROOT_FILES = frozenset({"CMakeLists.txt", "README.md", "zscope.benchmark.yaml"})
_PUBLIC_RANGE_PREFIXES = frozenset({"src", "include", "internal"})
_HISTORICAL_QUALIFICATION_PREFIXES = frozenset(
    {
        ("orchestration", "hypothesis_hunter", "qualification"),
    }
)
_REVIEW_PACKET_PARTS = frozenset(
    {
        "review-packet",
        "review-packets",
        "review_packet",
        "review_packets",
    }
)
_FORBIDDEN_ENVIRONMENT_KEYS = frozenset(
    {
        "BUILD_REPOSITORY_LOCALPATH",
        "BUILD_SOURCESDIRECTORY",
        "CI_PROJECT_DIR",
        "GITHUB_ACTION_PATH",
        "GITHUB_WORKSPACE",
        "INIT_CWD",
        "OLDPWD",
        "P6_CONTROL_ROOT",
        "P6_CANDIDATE_ROOT",
        "PWD",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "RUNNER_WORKSPACE",
        "SYSTEM_DEFAULTWORKINGDIRECTORY",
        "WORKSPACE",
        "Z_SCOPE_BENCHMARK_TRUTH",
        "Z_SCOPE_GROUND_TRUTH",
        "GROUND_TRUTH_PATH",
    }
)


def _environment_key_is_forbidden(key: str) -> bool:
    upper = key.upper()
    return bool(
        upper in _FORBIDDEN_ENVIRONMENT_KEYS
        or upper.startswith("GIT_")
        or "GROUND_TRUTH" in upper
        or "BENCHMARK_TRUTH" in upper
    )


def _path_locates_forbidden_root(value: str, roots: Sequence[Path]) -> bool:
    try:
        candidate = Path(value)
        if not candidate.is_absolute():
            return False
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return True
    return any(resolved == root or root in resolved.parents for root in roots)


class P6ProducerSandboxError(RuntimeError):
    """Fixed internal failure for an invalid answer-free producer source tree."""


def p6_product_runtime_member_allowed(path: PurePosixPath | Path) -> bool:
    """Return whether one path relative to ``zscope`` is live product material.

    This is a physical allow/exclude contract, not an assertion about file
    contents.  In particular, historical Hypothesis Hunter qualification
    artifacts are control-plane evidence: their digest may be bound by the
    current successor contract, but their answer-bearing corpus summaries are
    never mounted into the scanner process.
    """

    parts = tuple(path.parts)
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return False
    lowered = tuple(part.lower() for part in parts)
    basename = lowered[-1]
    if any(lowered[: len(prefix)] == prefix for prefix in _HISTORICAL_QUALIFICATION_PREFIXES):
        return False
    if any(
        part in _REVIEW_PACKET_PARTS
        or part in {"truth", "ground_truth", "ground-truth", "expected", "scorer"}
        or part in {"qualification_evidence", "qualification-evidence"}
        for part in lowered
    ):
        return False
    if (
        "ground_truth" in basename
        or "ground-truth" in basename
        or basename == "truth_contract.py"
        or "scorer" in basename
        or basename.startswith("expected-answer")
        or basename.startswith("expected_answer")
        or basename.startswith("qualification-artifact")
    ):
        return False
    return True


def _member_allowed(path: PurePosixPath) -> bool:
    parts = path.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return False
    if parts == ("scripts", "run_p6_cold_producer.py"):
        return True
    if parts[0] == "zscope":
        if len(parts) >= 2 and parts[1] == "benchmarking":
            return len(parts) == 3 and parts[2] in _HOST_BENCHMARKING_FILES
        if parts == ("zscope", "cli", "benchmark.py"):
            return False
        return len(parts) >= 2 and p6_product_runtime_member_allowed(PurePosixPath(*parts[1:]))
    if parts[:2] == ("test", "range"):
        relative = parts[2:]
        return bool(
            (len(relative) == 1 and relative[0] in _PUBLIC_RANGE_ROOT_FILES)
            or (relative and relative[0] in _PUBLIC_RANGE_PREFIXES)
        )
    return False


def _answer_authority_exposure(rows: Sequence[Mapping[str, Any]]) -> dict[str, bool]:
    """Derive receipt flags from the exact files that were materialized."""

    paths = tuple(str(row.get("path") or "").lower() for row in rows)
    return {
        "scorer_present": any(
            path == "zscope/cli/benchmark.py"
            or "scorer" in PurePosixPath(path).name
            for path in paths
        ),
        "truth_present": any(
            "ground_truth" in path
            or "ground-truth" in path
            or PurePosixPath(path).name == "truth_contract.py"
            or any(part == "truth" for part in PurePosixPath(path).parts)
            for path in paths
        ),
        "expected_answer_present": any(
            PurePosixPath(path).name.startswith("expected-answer")
            or PurePosixPath(path).name.startswith("expected_answer")
            for path in paths
        ),
        "review_decision_present": any(
            any(part in _REVIEW_PACKET_PARTS for part in PurePosixPath(path).parts)
            or path.startswith(".github/evidence/")
            for path in paths
        ),
        "postscore_evidence_present": any(
            path.startswith(".github/evidence/") or PurePosixPath(path).name == "postscore_trace.py"
            for path in paths
        ),
    }


def _write_materialized_member(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written < 1:
                raise OSError("short producer source write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _manifest(root: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise P6ProducerSandboxError("host producer sandbox contains a symbolic link")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise P6ProducerSandboxError("host producer sandbox contains a special file")
        relative = path.relative_to(root).as_posix()
        if not _member_allowed(PurePosixPath(relative)):
            raise P6ProducerSandboxError("host producer sandbox contains a forbidden member")
        payload = path.read_bytes()
        rows.append(
            {
                "path": relative,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    encoded = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "file_count": len(rows),
        "files": rows,
        "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _write_receipt(path: Path, payload: Mapping[str, Any]) -> None:
    encoded = (
        json.dumps(payload, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written < 1:
                raise OSError("short receipt write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def materialize_p6_host_producer_sandbox(
    *,
    repository_root: Path,
    candidate_commit: str,
    destination: Path,
    receipt_path: Path,
    process_runner: Any = subprocess.run,
) -> dict[str, Any]:
    """Materialize the exact product/driver subset for one cold child process."""

    root = Path(repository_root).resolve(strict=True)
    target = Path(destination)
    receipt = Path(receipt_path)
    if (
        _COMMIT_RE.fullmatch(candidate_commit) is None
        or target.exists()
        or target.is_symlink()
        or receipt.exists()
        or receipt.is_symlink()
    ):
        raise P6ProducerSandboxError("host producer sandbox identity is invalid")
    try:
        resolved = process_runner(
            ["git", "rev-parse", "--verify", f"{candidate_commit}^{{commit}}"],
            cwd=str(root),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        tree = process_runner(
            ["git", "rev-parse", f"{candidate_commit}^{{tree}}"],
            cwd=str(root),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        listed = process_runner(
            [
                "git",
                "ls-tree",
                "-r",
                "-z",
                "--full-tree",
                candidate_commit,
                "--",
                "scripts/run_p6_cold_producer.py",
                "zscope",
                "test/range/CMakeLists.txt",
                "test/range/README.md",
                "test/range/zscope.benchmark.yaml",
                "test/range/src",
                "test/range/include",
                "test/range/internal",
            ],
            cwd=str(root),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        resolved_commit = bytes(resolved.stdout).decode("ascii").strip()
        tree_sha256 = bytes(tree.stdout).decode("ascii").strip()
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        raise P6ProducerSandboxError("host producer Git source is invalid") from exc
    if (
        resolved.returncode != 0
        or tree.returncode != 0
        or listed.returncode != 0
        or resolved_commit != candidate_commit
        or _COMMIT_RE.fullmatch(tree_sha256) is None
    ):
        raise P6ProducerSandboxError("host producer Git source is invalid")

    target.mkdir(parents=True, mode=0o700)
    total = 0
    try:
        selected: list[tuple[PurePosixPath, str]] = []
        seen: set[PurePosixPath] = set()
        for encoded in bytes(listed.stdout).split(b"\0"):
            if not encoded:
                continue
            try:
                metadata, encoded_path = encoded.split(b"\t", 1)
                mode, object_type, object_id = metadata.decode("ascii").split(" ", 2)
                path = PurePosixPath(encoded_path.decode("utf-8"))
            except (UnicodeError, ValueError) as exc:
                raise P6ProducerSandboxError("host producer Git tree is invalid") from exc
            if path in seen:
                raise P6ProducerSandboxError("host producer Git tree is invalid")
            seen.add(path)
            if not _member_allowed(path):
                continue
            if (
                mode not in {"100644", "100755"}
                or object_type != "blob"
                or _COMMIT_RE.fullmatch(object_id) is None
            ):
                raise P6ProducerSandboxError("host producer Git member is invalid")
            selected.append((path, object_id))

        for path, object_id in selected:
            loaded = process_runner(
                ["git", "cat-file", "blob", object_id],
                cwd=str(root),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            payload = bytes(loaded.stdout)
            total += len(payload)
            if (
                loaded.returncode != 0
                or len(payload) > _MAX_MEMBER_BYTES
                or total > _MAX_TREE_BYTES
            ):
                raise P6ProducerSandboxError("host producer Git member is invalid")
            destination_parts = path.parts
            if path == PurePosixPath("zscope/benchmarking/__init__.py"):
                continue
            if path == PurePosixPath("zscope/benchmarking/p6_producer_package_init.py"):
                destination_parts = ("zscope", "benchmarking", "__init__.py")
            destination_path = target.joinpath(*destination_parts)
            destination_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _write_materialized_member(destination_path, payload)
    except (OSError, subprocess.SubprocessError) as exc:
        raise P6ProducerSandboxError("host producer materialization failed") from exc

    manifest = _manifest(target)
    required = {
        "scripts/run_p6_cold_producer.py",
        "test/range/zscope.benchmark.yaml",
        "zscope/__init__.py",
        "zscope/benchmarking/p6_producer_metrics.py",
        "zscope/benchmarking/p6_producer_sandbox.py",
        "zscope/benchmarking/runner.py",
    }
    present = {str(row["path"]) for row in manifest["files"]}
    if not required.issubset(present):
        raise P6ProducerSandboxError("host producer sandbox is incomplete")
    exposure = _answer_authority_exposure(manifest["files"])
    if any(exposure.values()):
        raise P6ProducerSandboxError("host producer sandbox contains answer authority")
    receipt_payload = {
        "schema_version": HOST_PRODUCER_SANDBOX_SCHEMA_VERSION,
        "candidate_commit": candidate_commit,
        "candidate_git_tree": tree_sha256,
        "file_count": manifest["file_count"],
        "source_manifest_sha256": manifest["manifest_sha256"],
        **exposure,
    }
    _write_receipt(receipt, receipt_payload)
    return receipt_payload


def validate_p6_host_producer_sandbox(
    *,
    sandbox_root: Path,
    receipt_path: Path,
    expected_candidate_commit: str,
) -> dict[str, Any]:
    """Revalidate the physical cwd/PYTHONPATH tree before any model call."""

    root = Path(sandbox_root).resolve(strict=True)
    receipt = Path(receipt_path)
    if (
        not root.is_dir()
        or receipt.is_symlink()
        or not receipt.is_file()
        or _COMMIT_RE.fullmatch(expected_candidate_commit) is None
    ):
        raise P6ProducerSandboxError("host producer sandbox is invalid")
    try:
        raw = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise P6ProducerSandboxError("host producer receipt is invalid") from exc
    fields = {
        "schema_version",
        "candidate_commit",
        "candidate_git_tree",
        "file_count",
        "source_manifest_sha256",
        "scorer_present",
        "truth_present",
        "expected_answer_present",
        "review_decision_present",
        "postscore_evidence_present",
    }
    if not isinstance(raw, dict) or set(raw) != fields:
        raise P6ProducerSandboxError("host producer receipt is invalid")
    manifest = _manifest(root)
    if (
        raw.get("schema_version") != HOST_PRODUCER_SANDBOX_SCHEMA_VERSION
        or raw.get("candidate_commit") != expected_candidate_commit
        or _COMMIT_RE.fullmatch(str(raw.get("candidate_git_tree") or "")) is None
        or raw.get("file_count") != manifest["file_count"]
        or raw.get("source_manifest_sha256") != manifest["manifest_sha256"]
        or any(raw.get(name) is not False for name in fields if name.endswith("_present"))
    ):
        raise P6ProducerSandboxError("host producer receipt does not match its source tree")
    if Path.cwd().resolve() != root:
        raise P6ProducerSandboxError("host producer cwd is outside its source sandbox")
    python_path = os.environ.get("PYTHONPATH", "")
    if python_path != str(root):
        raise P6ProducerSandboxError("host producer PYTHONPATH is outside its source sandbox")
    if any(_environment_key_is_forbidden(key) for key in os.environ):
        raise P6ProducerSandboxError("host producer inherited a forbidden source path")
    return dict(raw)


def p6_host_producer_child_environment(
    environment: Mapping[str, str],
    *,
    sandbox_root: Path,
    receipt_path: Path,
    forbidden_roots: Sequence[Path] = (),
) -> dict[str, str]:
    """Return the child environment with all checkout/answer locators removed."""

    child = {str(key): str(value) for key, value in environment.items()}
    roots = tuple(Path(root).resolve(strict=True) for root in forbidden_roots)
    for key in tuple(child):
        if _environment_key_is_forbidden(key):
            child.pop(key, None)
            continue
        value = child[key]
        if key.upper() == "PATH":
            child[key] = os.pathsep.join(
                part
                for part in value.split(os.pathsep)
                if part and not _path_locates_forbidden_root(part, roots)
            )
        elif _path_locates_forbidden_root(value, roots):
            child.pop(key, None)
    child["PYTHONPATH"] = str(Path(sandbox_root).resolve(strict=True))
    child["PYTHONDONTWRITEBYTECODE"] = "1"
    child["Z_SCOPE_P6_HOST_PRODUCER_ROOT"] = str(Path(sandbox_root).resolve(strict=True))
    child["Z_SCOPE_P6_HOST_PRODUCER_RECEIPT"] = str(Path(receipt_path).resolve(strict=True))
    return child


def receipt_sha256(path: Path) -> str:
    payload = Path(path).read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if _SHA256_RE.fullmatch(digest) is None:
        raise P6ProducerSandboxError("host producer receipt digest is invalid")
    return digest


__all__ = [
    "HOST_PRODUCER_SANDBOX_SCHEMA_VERSION",
    "P6ProducerSandboxError",
    "materialize_p6_host_producer_sandbox",
    "p6_product_runtime_member_allowed",
    "p6_host_producer_child_environment",
    "receipt_sha256",
    "validate_p6_host_producer_sandbox",
]
