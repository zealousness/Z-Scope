#!/usr/bin/env python3
"""Explicitly resolve test image tags to architecture-specific immutable digests."""
import argparse
import json
import subprocess
from pathlib import Path

IMAGES = {
    "2.34": "docker.io/library/rockylinux:9",
    "2.35": "docker.io/library/ubuntu:22.04",
    "2.36": "docker.io/library/debian:bookworm-slim",
    "2.39": "docker.io/library/ubuntu:24.04",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--toolchain-lock", type=Path, required=True)
    args = parser.parse_args()
    images = {"2.38": json.loads(args.toolchain_lock.read_text())["base_images"]}
    for version, image in IMAGES.items():
        result = json.loads(
            subprocess.check_output(["podman", "manifest", "inspect", image], text=True)
        )
        images[version] = {}
        for arch, oci in (("x86_64", "amd64"), ("aarch64", "arm64")):
            entry = next(
                item
                for item in result["manifests"]
                if item["platform"].get("os") == "linux"
                and item["platform"].get("architecture") == oci
            )
            images[version][arch] = image.rsplit(":", 1)[0] + "@" + entry["digest"]
    args.output.write_text(
        json.dumps(
            {"schema_version": "zscope.portable-runtime-images.v1", "images": images}, indent=2
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
