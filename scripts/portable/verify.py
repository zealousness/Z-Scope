"""Fail-closed verification of portable release matrices (manifest v2)."""

from __future__ import annotations

import json
import re
import subprocess
import tarfile
from pathlib import Path

from .abi import sha256, version_tuple

MATRIX = {(arch, profile) for arch in ("x86_64", "aarch64") for profile in ("cpp", "java")}
COMMON_CHECKS = {
    "cli",
    "doctor",
    "ssl-sqlite",
    "webui",
    "webui-offline-assets",
    "mcp",
    "mcp-index",
    "reports",
    "relocation",
    "readonly",
    "ordinary-user",
}
PROFILE_CHECKS = {
    "cpp": {
        "compile",
        "build-tools",
        "bitcode",
        "llvm18-isolation",
        "toolchain-api",
        "clang-batch",
        "clang-batch-references",
        "clang-batch-cache",
        "wpa",
        "saber",
        "clangd-headers",
        "clangd-ast",
        "clangd-usr",
        "clangd-references",
        "clangd-calls",
        "clangd-incremental",
    },
    "java": {
        "javaparser",
        "spoon",
        "sootup",
        "wala",
        "maven-offline",
        "joern-parse",
        "joern-query",
        "joern-server",
    },
}


def flat_path(directory, name):
    if not isinstance(name, str) or Path(name).name != name or name in {"", ".", ".."}:
        raise ValueError(f"Invalid release filename: {name!r}")
    return directory / name


def check_smoke(evidence, arch, profile, archive_hash, floor):
    if evidence.get("archive_sha256") != archive_hash:
        raise ValueError("Smoke evidence belongs to another archive")
    if evidence.get("arch") != arch or evidence.get("profile") != profile:
        raise ValueError("Smoke evidence matrix identity mismatch")
    if arch == "aarch64" and evidence.get("execution") not in {"qemu", "native"}:
        raise ValueError("ARM execution mode is missing")
    runs = evidence.get("runs", [])
    by_glibc = {row.get("glibc"): row for row in runs}
    for required in {"2.34", "2.38", "2.39", floor}:
        if required not in by_glibc:
            raise ValueError(f"Missing compatibility test on glibc {required}")
    required_checks = COMMON_CHECKS | PROFILE_CHECKS[profile]
    for version, row in by_glibc.items():
        expected_success = version in {floor, "2.38", "2.39"}
        if not row.get("passed"):
            if expected_success or not row.get("failure_reason"):
                raise ValueError(f"Unacceptable smoke failure on glibc {version}")
            continue
        if (
            row.get("network") != "none"
            or row.get("uid", 0) == 0
            or row.get("bundle_mount") != "ro"
        ):
            raise ValueError("Smoke environment is not isolated, unprivileged, and read-only")
        checks = row.get("checks", {})
        if any(checks.get(name) is not True for name in required_checks):
            raise ValueError(
                f"Missing or failed smoke checks: {sorted(required_checks - {key for key, value in checks.items() if value is True})}"
            )


def inspect_bundle(path, arch, profile):
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        roots = {Path(item.name).parts[0] for item in members if Path(item.name).parts}
        if len(roots) != 1:
            raise ValueError("Portable archive must contain one top-level directory")
        root = roots.pop()
        for member in members:
            relative = Path(member.name)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or member.isdev()
                or member.isfifo()
            ):
                raise ValueError(f"Unsafe archive member: {member.name}")
            parts = relative.parts[1:]
            if parts and parts[0] == "tools":
                if any("codeql" in part.lower() for part in parts):
                    raise ValueError("CodeQL redistribution is forbidden")
                prohibited = (
                    {"jdk", "maven", "joern", "java-jars", "gradle"}
                    if profile == "cpp"
                    else {"gcc", "llvm18", "clangd22", "svf", "gllvm", "build", "gradle"}
                )
                if len(parts) > 1 and parts[1] in prohibited:
                    raise ValueError(f"Language isolation violated: {member.name}")
                if (
                    profile == "java"
                    and len(parts) > 3
                    and parts[1:3] == ("joern", "frontends")
                    and parts[3] != "javasrc2cpg"
                ):
                    raise ValueError(f"Non-Java Joern frontend found: {member.name}")
            if profile == "cpp" and any(
                part.startswith(("cpgqls_client", "websockets")) for part in parts
            ):
                raise ValueError("Java-only Python dependencies found in C/C++ bundle")
            if member.issym() or member.islnk():
                link = Path(member.linkname)
                if link.is_absolute():
                    raise ValueError(f"Absolute archive link: {member.name}")
                # Resolve .. lexically, without touching the local filesystem.
                stack = list(relative.parent.parts if member.issym() else ())
                for component in link.parts:
                    if component == "..":
                        if not stack:
                            raise ValueError("Archive link escapes its root")
                        stack.pop()
                    elif component != ".":
                        stack.append(component)
                if not stack or stack[0] != root:
                    raise ValueError("Archive link escapes its root")
        stream = archive.extractfile(root + "/bundle.json")
        if stream is None:
            raise ValueError("Bundle manifest is missing")
        metadata = json.load(stream)
        if (
            metadata.get("schema_version") != "zscope.portable.v1"
            or metadata.get("arch") != arch
            or metadata.get("profile") != profile
        ):
            raise ValueError("Bundle identity mismatch")
        names = {member.name for member in members}
        if profile == "cpp" and "zscope-clang-indexer" not in metadata.get("executables", {}):
            raise ValueError("C/C++ package is missing the batch Clang frontend")
        for section in ("tools", "executables", "java_jars"):
            for value in metadata.get(section, {}).values():
                if (
                    Path(value).is_absolute()
                    or ".." in Path(value).parts
                    or root + "/" + value not in names
                ):
                    raise ValueError(f"Missing/invalid bundle resource: {value}")
        return metadata


def verify_matrix(directory: Path, *, require_signature=True, inspect_archives=True):
    return _verify_assets(directory, MATRIX, require_signature, inspect_archives)


def verify_package(directory: Path, arch: str, profile: str):
    """Verify a local delivery with the same integrity/ABI/runtime checks.

    This deliberately cannot produce the formal four-package release summary.
    """
    if (arch, profile) not in MATRIX:
        raise ValueError("Unknown portable package")
    manifest = json.loads((directory / "release-manifest.json").read_text())
    if manifest.get("signature_status") != "unsigned-local":
        raise ValueError("verify-package is only for unsigned local deliveries")
    result = _verify_assets(directory, {(arch, profile)}, False, True)
    result.update(schema_version="zscope.portable-package-verification.v1", arch=arch,
                  profile=profile, formal_release=False)
    return result


def _verify_assets(directory, matrix, require_signature, inspect_archives):
    directory = directory.resolve()
    manifest_path = directory / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema_version") != "zscope.release-assets.v2":
        raise ValueError("Expected release manifest v2")
    if require_signature and (
        manifest.get("signature_status") != "signed" or manifest.get("dirty") is not False
    ):
        raise ValueError("Formal release requires a signed, clean source snapshot")
    version = manifest["package_version"]
    for field in ("source_snapshot_sha256", "toolchain_lock_sha256"):
        if not re.fullmatch("[0-9a-f]{64}", manifest.get(field, "")):
            raise ValueError(f"Missing provenance: {field}")
    artifacts = {}
    for row in manifest.get("artifacts", []):
        path = flat_path(directory, row["name"])
        if row["name"] in artifacts:
            raise ValueError("Duplicate manifest artifact")
        if (
            not path.is_file()
            or path.stat().st_size != row["size"]
            or sha256(path) != row["sha256"]
        ):
            raise ValueError(f"Artifact integrity failure: {path.name}")
        if path.stat().st_size >= 2_147_483_648:
            raise ValueError(f"Release asset exceeds 2 GiB: {path.name}")
        artifacts[path.name] = row
    sums = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match or match[2] in sums:
            raise ValueError("Malformed or duplicate checksum entry")
        if sha256(flat_path(directory, match[2])) != match[1]:
            raise ValueError(f"Checksum mismatch: {match[2]}")
        sums[match[2]] = match[1]
    if not set(artifacts).union({"release-manifest.json"}).issubset(sums):
        raise ValueError("Incomplete checksum coverage")
    if "source-materials.json" not in artifacts:
        raise ValueError("Corresponding source materials are missing")
    sources = json.loads((directory / "source-materials.json").read_text()).get("artifacts", [])
    if not {"product-source", "third-party-source"}.issubset({row.get("kind") for row in sources}):
        raise ValueError("Incomplete corresponding source materials")
    for row in sources:
        if row.get("name") not in artifacts or artifacts[row["name"]]["sha256"] != row.get(
            "sha256"
        ):
            raise ValueError("Corresponding source integrity failure")
    for arch, profile in sorted(matrix):
        stem = f"zscope-{version}-linux-{arch}-{profile}-portable"
        names = [
            stem + suffix
            for suffix in (".tar.gz", ".abi.json", ".abi.md", ".smoke.json", ".spdx.json")
        ]
        if not set(names).issubset(artifacts):
            raise ValueError(
                f"Incomplete release member {arch}/{profile}: {sorted(set(names) - artifacts.keys())}"
            )
        abi = json.loads((directory / (stem + ".abi.json")).read_text())
        if abi.get("passed") is not True or abi.get("arch") != arch or not abi.get("runtime"):
            raise ValueError("ABI audit is missing or failed")
        floor = abi.get("glibc_required", "")
        if not floor or version_tuple(floor) > (2, 38):
            raise ValueError("Invalid GLIBC symbol requirement")
        sbom = json.loads((directory / (stem + ".spdx.json")).read_text())
        if (
            sbom.get("spdxVersion") != "SPDX-2.3"
            or not sbom.get("packages")
            or not sbom.get("files")
        ):
            raise ValueError("Missing SPDX package/file inventory")
        archive = directory / (stem + ".tar.gz")
        if inspect_archives:
            metadata = inspect_bundle(archive, arch, profile)
            if metadata.get("source_snapshot_sha256") != manifest["source_snapshot_sha256"]:
                raise ValueError("Archive source snapshot mismatch")
            if metadata.get("toolchain_lock_sha256") != manifest["toolchain_lock_sha256"]:
                raise ValueError("Archive tool lock mismatch")
        check_smoke(
            json.loads((directory / (stem + ".smoke.json")).read_text()),
            arch,
            profile,
            artifacts[archive.name]["sha256"],
            floor,
        )
    if require_signature:
        subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(directory / "public-key.pem"),
                "-signature",
                str(directory / "SHA256SUMS.sig"),
                str(directory / "SHA256SUMS"),
            ],
            check=True,
            capture_output=True,
        )
    return {
        "schema_version": "zscope.release-assets-verification.v2",
        "passed": True,
        "package_version": version,
        "git_sha": manifest.get("git_sha"),
        "release_manifest_sha256": sha256(manifest_path),
        "artifact_count": len(artifacts),
    }
