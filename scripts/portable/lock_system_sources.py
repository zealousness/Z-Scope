#!/usr/bin/env python3
"""Freeze corresponding Ubuntu source archives using the signed apt snapshot."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import lzma
import subprocess
import urllib.request
from pathlib import Path


def get(url):
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def records(stream):
    item, current = {}, ""
    for line in stream:
        if not line.strip():
            if item:
                yield item
            item, current = {}, ""
        elif line.startswith(" "):
            item[current] += "\n" + line.strip()
        else:
            current, value = line.split(":", 1)
            item[current] = value.strip()
    if item:
        yield item


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain-lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--image", default="localhost/zscope-portable-builder:x86_64")
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)
    output = subprocess.check_output(
        [
            "podman",
            "run",
            "--rm",
            "--network=none",
            args.image,
            "dpkg-query",
            "-W",
            "-f=${source:Package}\t${source:Version}\n",
        ],
        text=True,
    )
    needed = {tuple(line.split("\t")) for line in output.splitlines()}
    lock = json.loads(args.toolchain_lock.read_text())
    result = {}
    for suite, snapshot in lock["apt_snapshot"].items():
        release = get(snapshot["url"])
        if hashlib.sha256(release).hexdigest() != snapshot["sha256"]:
            raise ValueError("Signed apt snapshot digest changed")
        in_sha256 = False
        indices = {}
        for line in release.decode().splitlines():
            if line == "SHA256:":
                in_sha256 = True
                continue
            if in_sha256 and not line.startswith(" "):
                break
            if in_sha256:
                digest, size, path = line.split()
                if path in {"main/source/Sources.gz", "universe/source/Sources.gz"}:
                    indices[path] = digest
        if not indices:
            raise ValueError(f"Sources indices missing from {suite}")
        for relative, expected in indices.items():
            cache = args.cache / (suite + "-" + relative.replace("/", "-"))
            if not cache.exists():
                cache.write_bytes(
                    get("https://old-releases.ubuntu.com/ubuntu/dists/" + suite + "/" + relative)
                )
            if hashlib.sha256(cache.read_bytes()).hexdigest() != expected:
                raise ValueError("Source index checksum mismatch")
            with gzip.open(cache, "rt", encoding="utf-8") as stream:
                for record in records(stream):
                    identity = (record.get("Package"), record.get("Version"))
                    if identity not in needed:
                        continue
                    files = []
                    for entry in record["Checksums-Sha256"].splitlines():
                        if not entry.strip():
                            continue
                        digest, size, name = entry.split()
                        files.append(
                            {
                                "filename": name,
                                "sha256": digest,
                                "size": int(size),
                                "url": "https://old-releases.ubuntu.com/ubuntu/"
                                + record["Directory"]
                                + "/"
                                + name,
                            }
                        )
                    result[identity[0]] = {"version": identity[1], "suite": suite, "files": files}
                    needed.remove(identity)
            print(f"Indexed {suite}/{relative}; {len(needed)} source packages remain", flush=True)
    if needed:
        raise ValueError(f"Source packages absent from locked snapshot: {sorted(needed)}")
    args.output.write_text(
        json.dumps(
            {
                "schema_version": "zscope.portable-system-sources.v1",
                "apt_snapshot": lock["apt_snapshot"],
                "packages": result,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
