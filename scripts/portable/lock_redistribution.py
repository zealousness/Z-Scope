"""Explicitly update full JDK sources to match the already locked binaries."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import unquote

from lock_sources import github_asset


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain-lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    lock = json.loads(args.toolchain_lock.read_text())
    binaries = [lock["sources"]["jdk-" + arch] for arch in ("x86_64", "aarch64")]
    tags = {unquote(entry["url"].split("/download/")[1].split("/")[0]) for entry in binaries}
    if len(tags) != 1:
        raise ValueError("JDK architecture versions differ")
    tag = tags.pop()
    filename = "OpenJDK21U-jdk-sources_" + tag.removeprefix("jdk-").replace("+", "_") + ".tar.gz"
    entry = github_asset("adoptium/temurin21-binaries", "tags/" + tag, filename)
    entry["sha256"] = entry.pop("upstream_sha256")
    if len(entry["sha256"]) != 64:
        raise ValueError("Upstream JDK source digest is unavailable")
    entry["profiles"] = ["java"]
    args.output.write_text(
        json.dumps(
            {"schema_version": "zscope.redistribution-sources.v1", "sources": {"jdk": entry}},
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
