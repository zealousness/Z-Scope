#!/usr/bin/env python3
"""Verify release asset names, hashes, signatures, SBOMs, and redistribution boundaries."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict

try:
    from scripts.verify_release_version import package_version
except ModuleNotFoundError:  # Direct execution sets sys.path[0] to scripts/.
    from verify_release_version import package_version


class ReleaseAssetError(RuntimeError):
    """Raised when a release asset contract is incomplete or invalid."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_matches(directory: Path, pattern: str, count: int = 1) -> None:
    matches = list(directory.glob(pattern))
    if len(matches) < count:
        raise ReleaseAssetError(f"missing release asset matching {pattern!r}")


def _asset_path(directory: Path, name: str) -> Path:
    if not name or Path(name).name != name:
        raise ReleaseAssetError(f"release asset name must be a flat filename: {name!r}")
    return directory / name


def verify_release_assets(
    directory: Path,
    *,
    verify_signature: bool = True,
    inspect_archives: bool = True,
) -> Dict[str, Any]:
    directory = directory.resolve()
    manifest_path = directory / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") == "zscope.release-assets.v2":
        try:
            from scripts.portable.verify import verify_matrix
        except ModuleNotFoundError:
            from portable.verify import verify_matrix
        if manifest.get("package_version") != package_version():
            raise ReleaseAssetError("portable manifest version does not match the package")
        try:
            return verify_matrix(directory, require_signature=verify_signature,
                                 inspect_archives=inspect_archives)
        except (ValueError, KeyError, subprocess.CalledProcessError) as exc:
            raise ReleaseAssetError(str(exc)) from exc
    version = str(manifest.get("package_version", ""))
    if version != package_version():
        raise ReleaseAssetError(
            f"manifest package version {version!r} does not equal {package_version()!r}"
        )
    required_patterns = (
        f"zscope-app-{version}-linux-x86_64.tar.zst",
        "zscope-deps-cpp-*-linux-x86_64.tar.zst",
        "zscope-deps-java-*-linux-x86_64.tar.zst",
        f"third-party-licenses-{version}.tar.zst",
        "install.sh",
        "release-py313.txt",
        f"zscope-{version}.spdx.json",
        "zscope-deps-cpp-*.spdx.json",
        "zscope-deps-java-*.spdx.json",
    )
    for pattern in (*required_patterns, "SHA256SUMS", "SHA256SUMS.sig", "public-key.pem"):
        _require_matches(directory, pattern)

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ReleaseAssetError("release manifest has no artifacts")
    artifact_names = {str(item.get("name", "")) for item in artifacts}
    for pattern in required_patterns:
        for required_path in directory.glob(pattern):
            if required_path.name not in artifact_names:
                raise ReleaseAssetError(
                    f"required asset is not covered by release manifest: {required_path.name}"
                )
    for item in artifacts:
        path = _asset_path(directory, str(item.get("name", "")))
        if not path.is_file():
            raise ReleaseAssetError(f"manifest artifact is missing: {path.name}")
        if path.stat().st_size != int(item.get("size", -1)):
            raise ReleaseAssetError(f"manifest size mismatch: {path.name}")
        if _sha256(path) != item.get("sha256"):
            raise ReleaseAssetError(f"manifest hash mismatch: {path.name}")
        if path.stat().st_size >= 2_147_483_648:
            raise ReleaseAssetError(f"asset exceeds 2 GiB: {path.name}")

    sums = {}
    for line in (directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})\s+\*?(.+)", line.strip())
        if not match:
            raise ReleaseAssetError("invalid SHA256SUMS line")
        if match.group(2) in sums:
            raise ReleaseAssetError(f"duplicate SHA256SUMS entry: {match.group(2)}")
        sums[match.group(2)] = match.group(1)
    expected_names = {str(item["name"]) for item in artifacts} | {"release-manifest.json"}
    missing_sums = sorted(expected_names - sums.keys())
    if missing_sums:
        raise ReleaseAssetError(f"SHA256SUMS is missing entries: {missing_sums}")
    for name, digest in sums.items():
        path = _asset_path(directory, name)
        if not path.is_file() or _sha256(path) != digest:
            raise ReleaseAssetError(f"SHA256SUMS verification failed: {name}")

    if verify_signature:
        openssl = shutil.which("openssl")
        if not openssl:
            raise ReleaseAssetError("openssl is required to verify the release signature")
        proc = subprocess.run(
            [
                openssl,
                "dgst",
                "-sha256",
                "-verify",
                str(directory / "public-key.pem"),
                "-signature",
                str(directory / "SHA256SUMS.sig"),
                str(directory / "SHA256SUMS"),
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise ReleaseAssetError("release signature verification failed")

    for sbom_path in directory.glob("*.spdx.json"):
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
        if sbom.get("spdxVersion") != "SPDX-2.3" or not sbom.get("packages"):
            raise ReleaseAssetError(f"invalid SPDX SBOM: {sbom_path.name}")

    if inspect_archives:
        tar = shutil.which("tar")
        if not tar:
            raise ReleaseAssetError("tar is required to inspect Java dependencies")
        for archive in directory.glob("zscope-deps-java-*-linux-x86_64.tar.zst"):
            proc = subprocess.run(
                [tar, "--zstd", "-tf", str(archive)],
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                raise ReleaseAssetError(f"unable to inspect archive: {archive.name}")
            if any("codeql" in line.lower() for line in proc.stdout.splitlines()):
                raise ReleaseAssetError("CodeQL redistribution is forbidden")

    return {
        "schema_version": "zscope.release-assets-verification.v1",
        "passed": True,
        "package_version": version,
        "git_sha": manifest.get("git_sha"),
        "release_manifest_sha256": _sha256(manifest_path),
        "artifact_count": len(artifacts),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--asset-dir", type=Path, required=True)
    parser.add_argument("--skip-signature", action="store_true")
    parser.add_argument("--skip-archive-inspection", action="store_true")
    args = parser.parse_args()
    result = verify_release_assets(
        args.asset_dir,
        verify_signature=not args.skip_signature,
        inspect_archives=not args.skip_archive_inspection,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
