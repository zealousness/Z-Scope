#!/usr/bin/env python3
"""Run one P6 cold producer and persist only its fixed typed failure class."""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from typing import Optional, Sequence

from zscope.benchmarking.p6_protocol import FAILURE_CLASS_TO_EXECUTION_STAGES
from zscope.benchmarking.runner import BenchmarkError, run_benchmark


_DEPTH_TO_STAGE = {
    "fast": "cold_fast",
    "balanced": "cold_balanced",
    "deep": "cold_deep",
}


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


def run_cold_producer(*, scan_depth: str, output: Path, failure_marker: Path) -> int:
    stage = _DEPTH_TO_STAGE[scan_depth]
    marker = _marker_path(failure_marker)
    if marker.exists() or marker.is_symlink():
        raise RuntimeError("P6 cold failure marker already exists")
    try:
        run_benchmark(
            "c_cpp",
            "pilot",
            runs=1,
            output=output,
            scan_depth=scan_depth,
            answer_free_producer=True,
        )
    except BenchmarkError as exc:
        candidate = exc.failure_class
        failure_class = (
            candidate
            if isinstance(candidate, str)
            and stage in FAILURE_CLASS_TO_EXECUTION_STAGES.get(candidate, ())
            else "internal_failure"
        )
        _write_marker(marker, failure_class)
        return 2
    except Exception:
        _write_marker(marker, "internal_failure")
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


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    return run_cold_producer(
        scan_depth=args.scan_depth,
        output=args.output,
        failure_marker=args.failure_marker,
    )


if __name__ == "__main__":
    raise SystemExit(main())
