#!/usr/bin/env python3
"""Generate the hash-locked Linux constraints for the supported Python minor."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ("3.13",)


def main() -> None:
    uv = shutil.which("uv")
    if not uv:
        raise SystemExit("uv is required to compile cross-version constraints")
    output_dir = ROOT / "requirements" / "constraints"
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="zscope-uv-") as cache_dir:
        for version in VERSIONS:
            suffix = version.replace(".", "")
            output = output_dir / f"py{suffix}.txt"
            subprocess.run(
                [
                    uv,
                    "pip",
                    "compile",
                    str(ROOT / "requirements" / "dev.in"),
                    "--python-version",
                    version,
                    "--python-platform",
                    "x86_64-manylinux_2_38",
                    "--generate-hashes",
                    "--no-emit-index-url",
                    "--no-header",
                    "--cache-dir",
                    cache_dir,
                    "--output-file",
                    str(output),
                ],
                cwd=str(ROOT),
                check=True,
                env={
                    **os.environ,
                    "UV_CACHE_DIR": cache_dir,
                    "UV_PYTHON_INSTALL_DIR": str(Path(cache_dir) / "python"),
                },
            )
        release_dir = ROOT / "requirements" / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                uv,
                "pip",
                "compile",
                str(ROOT / "requirements" / "java.in"),
                "--python-version",
                "3.13",
                "--python-platform",
                "x86_64-manylinux_2_38",
                "--generate-hashes",
                "--no-emit-index-url",
                "--no-header",
                "--cache-dir",
                cache_dir,
                "--output-file",
                str(release_dir / "py313.txt"),
            ],
            cwd=str(ROOT),
            check=True,
            env={
                **os.environ,
                "UV_CACHE_DIR": cache_dir,
                "UV_PYTHON_INSTALL_DIR": str(Path(cache_dir) / "python"),
            },
        )


if __name__ == "__main__":
    main()
