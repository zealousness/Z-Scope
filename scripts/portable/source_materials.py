"""Redistributable corresponding sources, separate from runtime archives."""

from __future__ import annotations

import concurrent.futures
import json
import shutil
from pathlib import Path

from .abi import sha256


def locked_sources(root, toolchain):
    entries = []
    for name in ("python", "llvm", "clangd", "svf", "gllvm"):
        entries.append(dict(toolchain["sources"][name], component=name))
    extra = json.loads((root / "requirements/portable/redistribution.lock.json").read_text())
    # The v1.2 portable deliverables contain no Java runtime.
    for name, item in extra["sources"].items():
        if name != "jdk":
            entries.append(dict(item, component=name))
    system = json.loads((root / "requirements/portable/system-sources.lock.json").read_text())
    for name, package in system["packages"].items():
        for item in package["files"]:
            entries.append(dict(item, component="system-" + name, version=package["version"]))
    return entries


def fetch_sources(root, work, toolchain, fetch_file):
    entries = locked_sources(root, toolchain)

    def fetch(item):
        original = work / "downloads" / item["filename"]
        target = work / "corresponding-sources" / item["component"]
        if original.is_file() and sha256(original) == item["sha256"]:
            target.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original, target / item["filename"])
        else:
            fetch_file(item, target)

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(fetch, entries))


def publish_sources(source, work, output, version, epoch, archive):
    """Bound source assets below the release service's per-file size limit."""
    lock = json.loads((source / "requirements/portable/toolchain.lock.json").read_text())
    entries = locked_sources(source, lock)
    snapshot = json.loads((source / "source-snapshot.json").read_text())
    stage = work / "source-materials" / snapshot["sha256"]
    product = stage / f"zscope-{version}-source"
    product.mkdir(parents=True, exist_ok=True)
    for item in snapshot["files"]:
        origin = source / item["path"]
        if sha256(origin) != item["sha256"]:
            raise ValueError("Source snapshot changed after capture: " + item["path"])
        target = product / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, target)
    shutil.copy2(source / "source-snapshot.json", product)
    archive(product, output / (product.name + ".tar.gz"), epoch)
    records = [
        {
            "name": product.name + ".tar.gz",
            "kind": "product-source",
            "snapshot_sha256": snapshot["sha256"],
        }
    ]
    # Files are already compressed upstream. Grouping by size avoids a huge
    # monolithic source asset, while preserving original signed source files.
    part, size, group = 0, 0, []
    for item in [*entries, None]:
        if item is not None and "size" not in item:
            item["size"] = (
                (work / "corresponding-sources" / item["component"] / item["filename"])
                .stat()
                .st_size
            )
        if group and (item is None or size + item["size"] > 1_500_000_000):
            directory = stage / f"zscope-{version}-third-party-sources-{part:02d}"
            directory.mkdir(parents=True, exist_ok=True)
            for row in group:
                origin = work / "corresponding-sources" / row["component"] / row["filename"]
                if not origin.is_file() or sha256(origin) != row["sha256"]:
                    raise ValueError("Missing corresponding source; run fetch: " + str(origin))
                target = directory / row["component"] / row["filename"]
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(origin, target)
            (directory / "sources.json").write_text(json.dumps(group, indent=2) + "\n")
            archive(directory, output / (directory.name + ".tar.gz"), epoch)
            records.append(
                {
                    "name": directory.name + ".tar.gz",
                    "kind": "third-party-source",
                    "components": sorted({r["component"] for r in group}),
                }
            )
            part, size, group = part + 1, 0, []
        if item is not None:
            group.append(item)
            size += item["size"]
    for row in records:
        row["sha256"] = sha256(output / row["name"])
    (output / "source-materials.json").write_text(
        json.dumps({"schema_version": "zscope.source-materials.v1", "artifacts": records}, indent=2)
        + "\n"
    )
