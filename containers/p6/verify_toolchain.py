#!/usr/bin/env python3
"""Verify the exact executable contract required by a P6 C/C++ Range run."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Sequence


REQUIRED_TOOLS = (
    "python3",
    "cmake",
    "gcc",
    "clang",
    "clangd",
    "gclang",
    "get-bc",
    "llvm-link",
    "llvm-nm",
    "wpa",
    "saber",
    "cc",
)


def _first_line(argv: Sequence[str]) -> str:
    result = subprocess.run(
        list(argv),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError("tool version probe failed")
    return str(result.stdout or "").splitlines()[0].strip()[:256]


def verify() -> dict[str, object]:
    paths: dict[str, str] = {}
    for name in REQUIRED_TOOLS:
        resolved = shutil.which(name)
        if not resolved:
            raise RuntimeError("required tool is unavailable")
        paths[name] = str(Path(resolved).resolve())
    missing_libraries: dict[str, list[str]] = {}
    for name in ("wpa", "saber"):
        result = subprocess.run(
            ["ldd", paths[name]],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
        missing = sorted(
            line.strip().split()[0]
            for line in str(result.stdout or "").splitlines()
            if "not found" in line
        )
        if result.returncode != 0 or missing:
            raise RuntimeError("SVF shared-library contract is incomplete")
        missing_libraries[name] = missing
    versions = {
        "python3": _first_line([paths["python3"], "--version"]),
        "cmake": _first_line([paths["cmake"], "--version"]),
        "gcc": _first_line([paths["gcc"], "--version"]),
        "clang": _first_line([paths["clang"], "--version"]),
        "clangd": _first_line([paths["clangd"], "--version"]),
    }
    return {
        "schema_version": "zscope.p6-toolchain-probe.v1",
        "required_tools": list(REQUIRED_TOOLS),
        "paths": paths,
        "versions": versions,
        "missing_shared_libraries": missing_libraries,
        "passed": True,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = verify()
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
