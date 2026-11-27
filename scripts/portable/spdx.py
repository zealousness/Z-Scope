"""SPDX 2.3 inventory of the installed files and their locked source components."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from email.parser import Parser
from pathlib import Path

from .abi import sha256

SPDX_NAMESPACE_PREFIX = "https://github.com/zealousness/Z-Scope/spdx"
ZSCOPE_DOWNLOAD_LOCATION = "https://github.com/zealousness/Z-Scope"
ZSCOPE_COPYRIGHT = "Copyright (c) 2026 Z-SCOPE Team"

# Canonical SPDX license expressions for locked toolchain and build components
# defined in requirements/portable/toolchain.lock.json.
LOCKED_SOURCE_LICENSES: dict[str, str] = {
    "build-packaging": "Apache-2.0 OR BSD-2-Clause",
    "build-setuptools": "MIT",
    "build-wheel": "MIT",
    "clangd": "Apache-2.0 WITH LLVM-exception",
    "gllvm": "BSD-3-Clause",
    "jdk-aarch64": "GPL-2.0-only WITH Classpath-exception-2.0",
    "jdk-x86_64": "GPL-2.0-only WITH Classpath-exception-2.0",
    "joern-aarch64": "Apache-2.0",
    "joern-x86_64": "Apache-2.0",
    "llvm": "Apache-2.0 WITH LLVM-exception",
    "maven": "Apache-2.0",
    "python": "PSF-2.0",
    "svf": "GPL-3.0-only",
}

JAVA_RUNNER_LICENSES: dict[str, str] = {
    "zscope-java-structure-javaparser": "MIT AND Apache-2.0",
    "zscope-java-structure-spoon": "MIT AND CeCILL-C",
    "zscope-java-signal-sootup": "MIT AND LGPL-2.1-only",
    "zscope-java-signal-wala": "MIT AND EPL-2.0",
}


def _normalize_python_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _load_python_license_policy(root: Path) -> dict[str, str]:
    for candidate in (
        root / "share/license-policy.json",
        Path(__file__).resolve().parents[2] / "requirements/license-policy.json",
    ):
        if candidate.is_file():
            payload = json.loads(candidate.read_text(encoding="utf-8"))
            packages = payload.get("packages") or {}
            if isinstance(packages, dict):
                return {
                    _normalize_python_name(str(k)): str(v)
                    for k, v in packages.items()
                    if isinstance(k, str) and isinstance(v, str)
                }
    return {}


def _resolve_python_license(info, policy: dict[str, str]) -> str:
    expression = (info.get("License-Expression") or "").strip()
    if expression and expression.upper() != "UNKNOWN":
        return expression
    normalized = _normalize_python_name(info["Name"])
    if normalized in policy:
        return policy[normalized]
    declared = (info.get("License") or "").strip()
    if declared and declared.upper() != "UNKNOWN" and len(declared) < 120:
        return declared
    return "NOASSERTION"


def generate(root, output, *, version, epoch, source_snapshot):
    root = Path(root)
    output = Path(output)
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
        "downloadLocation": ZSCOPE_DOWNLOAD_LOCATION,
        "filesAnalyzed": False,
        "licenseConcluded": "MIT",
        "licenseDeclared": "MIT",
        "copyrightText": ZSCOPE_COPYRIGHT,
    }
    packages = [package]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package["SPDXID"],
        }
    ]
    metadata = json.loads((root / "bundle.json").read_text(encoding="utf-8"))
    lock = json.loads((root / "share/toolchain.lock.json").read_text(encoding="utf-8"))
    python_policy = _load_python_license_policy(root)

    def add_package(
        name,
        version_info,
        location="NOASSERTION",
        checksum=None,
        kind="Runtime",
        license_id="NOASSERTION",
        concluded_id=None,
    ):
        reference = (
            "SPDXRef-"
            + kind
            + "-"
            + hashlib.sha256((name + version_info + location).encode()).hexdigest()[:24]
        )
        row = {
            "SPDXID": reference,
            "name": name,
            "versionInfo": version_info,
            "downloadLocation": location,
            "filesAnalyzed": False,
            "licenseConcluded": concluded_id if concluded_id is not None else license_id,
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
            resolved = _resolve_python_license(info, python_policy)
            add_package(
                info["Name"],
                info["Version"],
                "https://pypi.org/project/" + info["Name"] + "/" + info["Version"] + "/",
                kind="Python",
                license_id=resolved,
            )
    for path in sorted(root.glob("tools/java-jars/*.jar")):
        stem = path.stem
        license_expr = JAVA_RUNNER_LICENSES.get(stem, "NOASSERTION")
        add_package(
            stem,
            version,
            ZSCOPE_DOWNLOAD_LOCATION,
            sha256(path),
            kind="JavaRunner",
            license_id=license_expr,
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
        for name, row in json.loads(web_assets.read_text(encoding="utf-8"))["files"].items():
            add_package(
                name,
                row["version"],
                row.get("url", "NOASSERTION"),
                row["sha256"],
                "WebUI",
                row["license"],
            )
    if system.is_file():
        for row in json.loads(system.read_text(encoding="utf-8")):
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
        declared_license = LOCKED_SOURCE_LICENSES.get(name, "NOASSERTION")
        packages.append(
            {
                "SPDXID": reference,
                "name": name,
                "versionInfo": entry["version"],
                "downloadLocation": entry["url"],
                "filesAnalyzed": False,
                "checksums": [{"algorithm": "SHA256", "checksumValue": entry["sha256"]}],
                "licenseConcluded": declared_license,
                "licenseDeclared": declared_license,
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
        "documentNamespace": f"{SPDX_NAMESPACE_PREFIX}/{identity}",
        "creationInfo": {
            "created": datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: zscope-portable-release"],
        },
        "packages": packages,
        "files": files,
        "relationships": relationships,
    }
    output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
