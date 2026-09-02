#!/usr/bin/env python3
"""Run one P6 cold producer and persist only its fixed typed failure class."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

from zscope.benchmarking.p6_producer_sandbox import (
    P6ProducerSandboxError,
    materialize_p6_host_producer_sandbox,
    p6_host_producer_child_environment,
    validate_p6_host_producer_sandbox,
)


# Kept injectable for focused failure-boundary tests.  Production resolves the
# runner only after the child has entered its physical answer-free source tree.
run_benchmark: Optional[Callable[..., object]] = None


_DEPTH_TO_STAGE = {
    "fast": "cold_fast",
    "balanced": "cold_balanced",
    "deep": "cold_deep",
}

_PRIVATE_INPUT_MAX_BYTES = 1024 * 1024


def _marker_path(value: Path) -> Path:
    runner_temp_value = os.environ.get("RUNNER_TEMP", "")
    if not runner_temp_value:
        raise RuntimeError("P6 runner temporary boundary is unavailable")
    runner_temp = Path(runner_temp_value).resolve(strict=True)
    if runner_temp.is_symlink() or not runner_temp.is_dir():
        raise RuntimeError("P6 runner temporary boundary is invalid")
    lexical = Path(os.path.abspath(value))
    if lexical.parent != runner_temp or lexical.name not in {
        "p6-cold-fast-failure.json",
        "p6-cold-balanced-failure.json",
        "p6-cold-deep-failure.json",
    }:
        raise RuntimeError("P6 cold failure marker path is invalid")
    return lexical


def _write_marker(path: Path, failure_class: str) -> None:
    encoded = (
        json.dumps(
            {"failure_class": failure_class, "failure_count": 1},
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
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
                raise OSError("short P6 failure marker write")
            offset += written
        os.fsync(descriptor)
        mode = os.fstat(descriptor).st_mode
        if not stat.S_ISREG(mode) or (os.name == "posix" and mode & 0o077):
            raise OSError("unsafe P6 failure marker permissions")
    finally:
        os.close(descriptor)


def _copy_private_input(
    *,
    source: Path,
    destination: Path,
    expected_sha256: Optional[str] = None,
) -> Path:
    """Copy one validated private input without retaining its checkout locator."""

    if not source.is_absolute() or source.is_symlink() or not source.is_file():
        raise P6ProducerSandboxError("host producer private input is invalid")
    read_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        read_flags |= os.O_NOFOLLOW
    read_descriptor = os.open(source, read_flags)
    try:
        metadata = os.fstat(read_descriptor)
        if not stat.S_ISREG(metadata.st_mode) or (os.name == "posix" and metadata.st_mode & 0o077):
            raise P6ProducerSandboxError("host producer private input is invalid")
        chunks: list[bytes] = []
        size = 0
        while size <= _PRIVATE_INPUT_MAX_BYTES:
            chunk = os.read(
                read_descriptor,
                min(64 * 1024, _PRIVATE_INPUT_MAX_BYTES + 1 - size),
            )
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(read_descriptor)
    if len(payload) > _PRIVATE_INPUT_MAX_BYTES:
        raise P6ProducerSandboxError("host producer private input is invalid")
    digest = hashlib.sha256(payload).hexdigest()
    if expected_sha256 is not None and (
        re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None or digest != expected_sha256
    ):
        raise P6ProducerSandboxError("host producer private input digest is invalid")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written < 1:
                raise OSError("short private input write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return destination.resolve(strict=True)


def _secure_remove_private_input(path: Path, *, runner_temp: Path) -> None:
    """Best-effort overwrite, then unlink one launcher-owned private copy.

    The lexical parent check prevents cleanup from following a replaced path
    outside ``RUNNER_TEMP``.  A concurrent type swap is unlinked fail-closed;
    it is never followed to an attacker-selected target.
    """

    lexical = Path(os.path.abspath(path))
    if lexical.parent != runner_temp:
        raise P6ProducerSandboxError("host producer private cleanup boundary is invalid")
    try:
        metadata = lexical.lstat()
    except FileNotFoundError:
        return
    unsafe_type = (
        lexical.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > _PRIVATE_INPUT_MAX_BYTES
    )
    cleanup_error: Optional[BaseException] = None
    if not unsafe_type:
        flags = os.O_WRONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(lexical, flags)
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (
                hasattr(metadata, "st_ino")
                and (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            ):
                raise OSError("private input changed during cleanup")
            remaining = opened.st_size
            os.lseek(descriptor, 0, os.SEEK_SET)
            zeros = b"\0" * min(64 * 1024, max(remaining, 1))
            while remaining:
                written = os.write(descriptor, zeros[: min(len(zeros), remaining)])
                if written < 1:
                    raise OSError("short private input cleanup write")
                remaining -= written
            os.fsync(descriptor)
        except (OSError, ValueError) as exc:
            cleanup_error = exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    try:
        lexical.unlink(missing_ok=True)
    except OSError as exc:
        cleanup_error = cleanup_error or exc
    if lexical.exists() or lexical.is_symlink() or unsafe_type or cleanup_error is not None:
        raise P6ProducerSandboxError(
            "host producer private input cleanup failed"
        ) from cleanup_error


def _require_child_source_sandbox() -> None:
    root_value = os.environ.get("Z_SCOPE_P6_HOST_PRODUCER_ROOT", "").strip()
    receipt_value = os.environ.get("Z_SCOPE_P6_HOST_PRODUCER_RECEIPT", "").strip()
    candidate = os.environ.get("Z_SCOPE_P6_CANDIDATE_COMMIT", "").strip()
    if not root_value or not receipt_value:
        raise P6ProducerSandboxError("host producer source boundary is unavailable")
    root = Path(root_value).resolve(strict=True)
    script = (root / "scripts/run_p6_cold_producer.py").resolve(strict=True)
    if Path(__file__).resolve(strict=True) != script:
        raise P6ProducerSandboxError("host producer script is outside its source boundary")
    validate_p6_host_producer_sandbox(
        sandbox_root=root,
        receipt_path=Path(receipt_value),
        expected_candidate_commit=candidate,
    )


def run_cold_producer(
    *,
    scan_depth: str,
    output: Path,
    failure_marker: Path,
    require_source_sandbox: bool = True,
) -> int:
    stage = _DEPTH_TO_STAGE[scan_depth]
    marker = _marker_path(failure_marker)
    if marker.exists() or marker.is_symlink():
        raise RuntimeError("P6 cold failure marker already exists")
    try:
        if require_source_sandbox:
            _require_child_source_sandbox()
        benchmark = run_benchmark
        if benchmark is None:
            from zscope.benchmarking.runner import run_benchmark as benchmark
        assert benchmark is not None

        from zscope.benchmarking.p6_protocol import FAILURE_CLASS_TO_EXECUTION_STAGES
        from zscope.benchmarking.runner import BenchmarkError

        benchmark(
            "c_cpp",
            "pilot",
            runs=1,
            output=output,
            scan_depth=scan_depth,
            answer_free_producer=True,
        )
    except Exception as exc:
        from zscope.benchmarking.runner import BenchmarkError

        if not isinstance(exc, BenchmarkError):
            _write_marker(marker, "internal_failure")
            return 2
        from zscope.benchmarking.p6_protocol import FAILURE_CLASS_TO_EXECUTION_STAGES

        candidate = exc.failure_class
        failure_class = (
            candidate
            if isinstance(candidate, str)
            and stage in FAILURE_CLASS_TO_EXECUTION_STAGES.get(candidate, ())
            else "internal_failure"
        )
        _write_marker(marker, failure_class)
        return 2
    if marker.exists() or marker.is_symlink():
        raise RuntimeError("successful P6 cold producer left a failure marker")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-depth", choices=tuple(_DEPTH_TO_STAGE), required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--failure-marker", required=True, type=Path)
    return parser


def _run_from_answer_free_host_sandbox(args: argparse.Namespace) -> int:
    """Materialize and execute the actual producer from its private source tree."""

    runner_temp_value = os.environ.get("RUNNER_TEMP", "").strip()
    candidate = os.environ.get("Z_SCOPE_P6_CANDIDATE_COMMIT", "").strip()
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    if (
        not runner_temp_value
        or re.fullmatch(r"[0-9a-f]{40}", candidate) is None
        or re.fullmatch(r"(?:[1-9][0-9]*|local)", run_id) is None
        or re.fullmatch(r"[1-9][0-9]*", run_attempt) is None
    ):
        raise P6ProducerSandboxError("host producer launch identity is invalid")
    runner_temp = Path(runner_temp_value).resolve(strict=True)
    source_root = Path(__file__).resolve(strict=True).parents[1]
    sandbox = runner_temp / f"p6-host-producer-{run_id}-{run_attempt}-{args.scan_depth}"
    receipt = runner_temp / (
        f"p6-host-producer-{run_id}-{run_attempt}-{args.scan_depth}-receipt.json"
    )
    materialize_p6_host_producer_sandbox(
        repository_root=source_root,
        candidate_commit=candidate,
        destination=sandbox,
        receipt_path=receipt,
    )
    output = args.output.resolve()
    marker = args.failure_marker.resolve()
    if output.exists() or output.is_symlink():
        raise P6ProducerSandboxError("host producer output boundary is invalid")
    private_output = runner_temp / (
        f"p6-host-producer-{run_id}-{run_attempt}-{args.scan_depth}-output"
    )
    key_file_value = os.environ.get("Z_SCOPE_P6_API_KEY_FILE", "").strip()
    attestation_value = os.environ.get(
        "Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_FILE", ""
    ).strip()
    attestation_sha256 = os.environ.get(
        "Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_SHA256", ""
    ).strip()
    if not key_file_value or not attestation_value:
        raise P6ProducerSandboxError("host producer private input is unavailable")
    private_inputs: list[Path] = []
    try:
        private_key_destination = runner_temp / (
            f"p6-host-producer-{run_id}-{run_attempt}-{args.scan_depth}-key.env"
        )
        private_inputs.append(private_key_destination)
        private_key_file = _copy_private_input(
            source=Path(key_file_value),
            destination=private_key_destination,
        )
        private_attestation_destination = runner_temp / (
            f"p6-host-producer-{run_id}-{run_attempt}-{args.scan_depth}-proxy.json"
        )
        private_inputs.append(private_attestation_destination)
        private_attestation = _copy_private_input(
            source=Path(attestation_value),
            destination=private_attestation_destination,
            expected_sha256=attestation_sha256,
        )
        launch_environment = dict(os.environ)
        launch_environment["Z_SCOPE_P6_API_KEY_FILE"] = str(private_key_file)
        launch_environment["Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_FILE"] = str(
            private_attestation
        )
        child_environment = p6_host_producer_child_environment(
            launch_environment,
            sandbox_root=sandbox,
            receipt_path=receipt,
            forbidden_roots=(source_root,),
        )
        command = [
            sys.executable,
            "-B",
            str(sandbox / "scripts/run_p6_cold_producer.py"),
            "--scan-depth",
            args.scan_depth,
            "--output",
            str(private_output),
            "--failure-marker",
            str(marker),
        ]
        completed = subprocess.run(
            command,
            cwd=str(sandbox),
            env=child_environment,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        if completed.returncode not in {0, 2}:
            if not marker.exists() and not marker.is_symlink():
                _write_marker(_marker_path(marker), "internal_failure")
            return 2
        if completed.returncode == 2 and not marker.is_file():
            _write_marker(_marker_path(marker), "internal_failure")
        if completed.returncode == 0:
            if (
                not private_output.is_dir()
                or private_output.is_symlink()
                or output.exists()
                or output.is_symlink()
            ):
                _write_marker(_marker_path(marker), "internal_failure")
                return 2
            try:
                output.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(private_output), str(output))
            except (OSError, shutil.Error):
                if not marker.exists() and not marker.is_symlink():
                    _write_marker(_marker_path(marker), "internal_failure")
                return 2
        return completed.returncode
    finally:
        cleanup_error: Optional[BaseException] = None
        for private_input in reversed(private_inputs):
            try:
                _secure_remove_private_input(private_input, runner_temp=runner_temp)
            except (OSError, P6ProducerSandboxError) as exc:
                cleanup_error = cleanup_error or exc
        if cleanup_error is not None:
            raise P6ProducerSandboxError(
                "host producer private input cleanup failed"
            ) from cleanup_error


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if not os.environ.get("Z_SCOPE_P6_HOST_PRODUCER_RECEIPT", "").strip():
            return _run_from_answer_free_host_sandbox(args)
        return run_cold_producer(
            scan_depth=args.scan_depth,
            output=args.output,
            failure_marker=args.failure_marker,
        )
    except Exception:
        marker = _marker_path(args.failure_marker.resolve())
        if not marker.exists() and not marker.is_symlink():
            _write_marker(marker, "internal_failure")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
