"""SPDX 2.3 inventory of the installed files and their locked source components."""

from __future__ import annotations

import hashlib
import json
import re
from email.parser import Parser
from datetime import datetime, timezone
from pathlib import Path

from .abi import sha256


def generate(root, output, *, version, epoch, source_snapshot):
    identity = hashlib.sha256((root.name + source_snapshot).encode()).hexdigest()
    files = []
    for index, path in enumerate(sorted(root.rglob("*"))):
        if not path.is_file() or path.is_symlink():
            continue
        files.append(
            {
                "SPDXID": f"SPDXRef-File-{index}",
                "fileName": "./" + path.relative_to(root).as_posix(),
                "checksums": [{"algorithm": "SHA256", "checksumValue": sha256(path)}],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
    package = {
        "SPDXID": "SPDXRef-ZScope",
        "name": "zscope",
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "MIT",
        "licenseDeclared": "MIT",
        "copyrightText": "NOASSERTION",
    }
    packages = [package]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package["SPDXID"],
        }
    ]
    metadata = json.loads((root / "bundle.json").read_text())
    lock = json.loads((root / "share/toolchain.lock.json").read_text())

    def add_package(
        name,
        version,
        location="NOASSERTION",
        checksum=None,
        kind="Runtime",
        license_id="NOASSERTION",
    ):
        reference = (
            "SPDXRef-"
            + kind
            + "-"
            + hashlib.sha256((name + version + location).encode()).hexdigest()[:24]
        )
        row = {
            "SPDXID": reference,
            "name": name,
            "versionInfo": version,
            "downloadLocation": location,
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": license_id,
            "copyrightText": "NOASSERTION",
        }
        if checksum:
            row["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
        packages.append(row)
        relationships.append(
            {
                "spdxElementId": reference,
                "relationshipType": "DEPENDENCY_OF",
                "relatedSpdxElement": "SPDXRef-ZScope",
            }
        )

    for path in sorted(root.glob("runtime/python/lib/python*/site-packages/*.dist-info/METADATA")):
        info = Parser().parsestr(path.read_text(encoding="utf-8"))
        if info["Name"].lower() != "zscope":
            add_package(
                info["Name"],
                info["Version"],
                "https://pypi.org/project/" + info["Name"] + "/" + info["Version"] + "/",
                kind="Python",
                license_id=info.get("License-Expression", "NOASSERTION"),
            )
    for path in sorted(root.glob("share/maven-repository/**/*.jar")):
        parts = path.relative_to(root / "share/maven-repository").parts
        if len(parts) >= 4:
            name = ".".join(parts[:-3]) + ":" + parts[-3]
            add_package(
                name,
                parts[-2],
                "https://repo.maven.apache.org/maven2/" + "/".join(parts),
                sha256(path),
                "Maven",
            )
    for path in sorted(root.glob("tools/joern/**/*.jar")):
        match = re.match(r"(.+?)-((?:\d+\.)+\d+.*)\.jar$", path.name)
        add_package(
            match[1] if match else path.stem,
            match[2] if match else "unknown",
            checksum=sha256(path),
            kind="Joern",
        )
    system = root / "share/system-runtime-packages.json"
    web_assets = root / "share/web-assets.lock.json"
    if web_assets.is_file():
        for name, row in json.loads(web_assets.read_text())["files"].items():
            add_package(
                name,
                row["version"],
                row.get("url", "NOASSERTION"),
                row["sha256"],
                "WebUI",
                row["license"],
            )
    if system.is_file():
        for row in json.loads(system.read_text()):
            add_package(
                row["name"],
                row["version"],
                "https://old-releases.ubuntu.com/ubuntu/",
                kind="System",
            )
    for name, entry in lock["sources"].items():
        if metadata["profile"] not in entry["profiles"] or (
            entry.get("arch") and entry["arch"] != metadata["arch"]
        ):
            continue
        reference = "SPDXRef-Source-" + name
        packages.append(
            {
                "SPDXID": reference,
                "name": name,
                "versionInfo": entry["version"],
                "downloadLocation": entry["url"],
                "filesAnalyzed": False,
                "checksums": [{"algorithm": "SHA256", "checksumValue": entry["sha256"]}],
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": reference,
                "relationshipType": (
                    "BUILD_DEPENDENCY_OF" if entry.get("build_only") else "DEPENDENCY_OF"
                ),
                "relatedSpdxElement": "SPDXRef-ZScope",
            }
        )
    for row in files:
        relationships.append(
            {
                "spdxElementId": "SPDXRef-ZScope",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": row["SPDXID"],
            }
        )
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": root.name,
        "documentNamespace": f"https://zscope.local/spdx/{identity}",
        "creationInfo": {
            "created": datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: zscope-portable-release"],
        },
        "packages": packages,
        "files": files,
        "relationships": relationships,
    }
    output.write_text(json.dumps(document, indent=2) + "\n")
