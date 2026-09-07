#!/usr/bin/env python3
"""Explicit maintainer operation: resolve sources and freeze verified downloads.

Normal fetch/build never calls this script or resolves moving release aliases.
HTTPS provides origin authentication when creating a new lock; upstream package
digests, when published, must also match. Review the resulting lock diff.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path


def request(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "zscope-portable-release"})
    with urllib.request.urlopen(req, timeout=180) as response:
        return response.read()


def api(url: str):
    return json.loads(request(url))


def github_asset(repo: str, tag: str, name: str) -> dict:
    release = api(f"https://api.github.com/repos/{repo}/releases/{tag}")
    asset = next(item for item in release["assets"] if item["name"] == name)
    return {
        "url": asset["browser_download_url"],
        "filename": name,
        "version": release["tag_name"],
        "size": asset["size"],
        "upstream_sha256": str(asset.get("digest") or "").removeprefix("sha256:"),
    }


def sources() -> dict:
    result = {
        "python": {
            "url": "https://www.python.org/ftp/python/3.13.15/Python-3.13.15.tar.xz",
            "filename": "Python-3.13.15.tar.xz",
            "version": "3.13.15",
            "profiles": ["cpp", "java"],
        },
        "clangd": github_asset(
            "llvm/llvm-project", "tags/llvmorg-22.1.7", "llvm-project-22.1.7.src.tar.xz"
        ),
        "llvm": github_asset(
            "llvm/llvm-project", "tags/llvmorg-18.1.0", "llvm-project-18.1.0.src.tar.xz"
        ),
        "svf": {
            "url": "https://codeload.github.com/SVF-tools/SVF/tar.gz/refs/tags/SVF-3.2",
            "filename": "SVF-3.2.tar.gz",
            "version": "3.2",
        },
        "gllvm": {
            "url": "https://codeload.github.com/SRI-CSL/gllvm/tar.gz/refs/tags/v1.3.0",
            "filename": "gllvm-1.3.0.tar.gz",
            "version": "1.3.0",
        },
    }
    for key in ("clangd", "llvm", "svf", "gllvm"):
        result[key]["profiles"] = ["cpp"]
    joern_tag = api("https://api.github.com/repos/joernio/joern/releases/latest")["tag_name"]
    for arch, upstream in (("x86_64", "x64"), ("aarch64", "aarch64")):
        joern_arch = "arm64" if arch == "aarch64" else arch
        result[f"joern-{arch}"] = github_asset(
            "joernio/joern", f"tags/{joern_tag}", f"joern-cli-linux-{joern_arch}.zip"
        )
        result[f"joern-{arch}"].update(arch=arch, profiles=["java"])
        packages = api(
            f"https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture={upstream}&image_type=jdk&os=linux&vendor=eclipse"
        )
        entry = packages[0]
        package = entry["binary"]["package"]
        result[f"jdk-{arch}"] = {
            "url": package["link"],
            "filename": package["name"],
            "version": entry["version"]["semver"],
            "upstream_sha256": package["checksum"],
            "size": package["size"],
            "arch": arch,
            "profiles": ["java"],
        }
    metadata = ET.fromstring(
        request(
            "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/maven-metadata.xml"
        )
    )
    versions = [
        v.text
        for v in metadata.findall("./versioning/versions/version")
        if re.fullmatch(r"3\.9\.\d+", v.text or "")
    ]
    version = max(versions, key=lambda value: tuple(map(int, value.split("."))))
    name = f"apache-maven-{version}-bin.tar.gz"
    result["maven"] = {
        "url": f"https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/{version}/{name}",
        "filename": name,
        "version": version,
        "profiles": ["java"],
    }
    for name, version in (("setuptools", "80.9.0"), ("wheel", "0.45.1"), ("packaging", "25.0")):
        metadata = api(f"https://pypi.org/pypi/{name}/{version}/json")
        wheel = next(
            item for item in metadata["urls"] if item["filename"].endswith("-py3-none-any.whl")
        )
        result["build-" + name] = {
            "url": wheel["url"],
            "filename": wheel["filename"],
            "version": version,
            "upstream_sha256": wheel["digests"]["sha256"],
            "build_only": True,
            "size": wheel["size"],
            "profiles": ["cpp", "java"],
        }
    return result


def download(name: str, item: dict, cache: Path) -> tuple:
    path = cache / item["filename"]
    if not path.is_file():
        temporary = path.with_suffix(path.suffix + ".partial")
        req = urllib.request.Request(item["url"], headers={"User-Agent": "zscope-portable-release"})
        with urllib.request.urlopen(req, timeout=180) as response, temporary.open("wb") as out:
            while chunk := response.read(1024 * 1024):
                out.write(chunk)
        temporary.replace(path)
    with path.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    expected = item.pop("upstream_sha256", "")
    if expected and expected != digest:
        raise ValueError(f"Upstream SHA256 mismatch: {name}")
    item.update(sha256=digest, size=path.stat().st_size)
    print(f"Locked {name} {item['version']} ({item['size']} bytes)", flush=True)
    return name, item


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--published-digests",
        action="store_true",
        help="Freeze authenticated upstream SHA256 values without downloading large assets",
    )
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)
    entries = sources()
    published = {}
    if args.published_digests:
        for name, item in list(entries.items()):
            if item.get("upstream_sha256"):
                item["sha256"] = item.pop("upstream_sha256")
                published[name] = entries.pop(name)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        locked = dict(pool.map(lambda pair: download(*pair, args.cache), entries.items()))
    locked.update(published)
    apt_snapshot = {}
    for suite in ("mantic", "mantic-updates", "mantic-security"):
        url = f"https://old-releases.ubuntu.com/ubuntu/dists/{suite}/InRelease"
        apt_snapshot[suite] = {"url": url, "sha256": hashlib.sha256(request(url)).hexdigest()}
    lock = {
        "schema_version": "zscope.portable-toolchain.v1",
        "build_glibc": "2.38",
        "base_images": {
            "x86_64": "docker.io/library/ubuntu@sha256:c57e8a329cd805f341ed7ee7fcc010761b29b9b8771b02a4f74fc794f1d7eac5",
            "aarch64": "docker.io/library/ubuntu@sha256:72c9c923b9807a752ba9c8ba41432e62bb88312de9d15b536caeaf3ea5965ad5",
        },
        "apt_snapshot": apt_snapshot,
        "sources": locked,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
