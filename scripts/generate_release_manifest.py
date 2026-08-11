#!/usr/bin/env python3
"""Generate a deterministic manifest for signed split release assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_NAMES = {"SHA256SUMS", "SHA256SUMS.sig", "public-key.pem", "release-manifest.json"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_value(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=str(ROOT), text=True).strip()


def _kind(name: str) -> str:
    if name.startswith("zscope-app-"):
        return "application"
    if name.startswith("zscope-deps-cpp-"):
        return "cpp-toolset"
    if name.startswith("zscope-deps-java-"):
        return "java-toolset"
    if name.startswith("third-party-licenses-"):
        return "licenses"
    if name.endswith(".spdx.json"):
        return "sbom"
    if name.startswith("release-py"):
        return "python-lock"
    if name == "install.sh":
        return "installer"
    return "support"


def build_manifest(directory: Path, version: str) -> Dict[str, Any]:
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    artifacts: List[Dict[str, Any]] = []
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.name in EXCLUDED_NAMES:
            continue
        artifacts.append(
            {
                "name": path.name,
                "kind": _kind(path.name),
                "size": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    return {
        "schema_version": "zscope.release-assets.v1",
        "package_version": version,
        "git_sha": _git_value("rev-parse", "HEAD"),
        "git_tree": _git_value("rev-parse", "HEAD^{tree}"),
        "source_date_epoch": epoch,
        "generated_at": datetime.fromtimestamp(epoch, timezone.utc).isoformat(),
        "platform": "linux-x86_64",
        "artifacts": artifacts,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_manifest(args.directory.resolve(), args.version)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
