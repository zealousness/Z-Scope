#!/usr/bin/env python3
"""Build and verify unsigned v1.2 Linux C/C++ portable packages.

Run inside Linux/WSL. Build/cache directories must be on a Linux filesystem.
Use lock_sources.py separately when intentionally updating dependency versions.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from portable.abi import sha256, version_tuple
from portable.download import fetch_file

ARCHES = {"x86_64": "amd64", "aarch64": "arm64"}
PROFILES = ("cpp",)


def run(command, **kwargs):
    print("+ " + " ".join(map(str, command)), flush=True)
    return subprocess.run(list(map(str, command)), check=True, **kwargs)


def read_lock(path):
    lock = json.loads(path.read_text(encoding="utf-8"))
    if (
        lock.get("schema_version") != "zscope.portable-toolchain.v1"
        or lock.get("build_glibc") != "2.38"
    ):
        raise ValueError("Unsupported toolchain lock")
    for name, entry in lock["sources"].items():
        if not re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", "")):
            raise ValueError(f"Missing immutable source digest: {name}")
        if Path(entry["filename"]).name != entry["filename"]:
            raise ValueError(f"Invalid source filename: {name}")
    return lock


def source_snapshot(work, *, overrides=None):
    """Copy exactly the product/build inputs, including current working edits."""
    overrides = overrides or {}
    output = subprocess.check_output(
        ["git", "ls-files", "-c", "-o", "--exclude-standard", "-z"], cwd=ROOT
    )
    allowed = {
        "zscope",
        "tools",
        "native",
        "requirements",
        "scripts",
        "tests",
        "test",
        "docs",
        ".github",
    }
    root_files = {
        "pyproject.toml",
        "README.md",
        "LICENSE",
        "MANIFEST.in",
        "setup.cfg",
        "setup.py",
        "zscope.c_cpp.yaml",
        "zscope.java.yaml",
        "AGENTS.md",
    }
    snapshots = work / "snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)
    captured = Path(tempfile.mkdtemp(prefix="capture-", dir=snapshots))
    initial_dirty = bool(
        subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)
    ) or any(
        not (ROOT / relative).is_file() or sha256(path) != sha256(ROOT / relative)
        for relative, path in overrides.items()
    )
    initial_head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    records = []
    for value in sorted((set(output.decode().split("\0")) | set(overrides)) - {""}):
        path = Path(value)
        if path.parts[0] not in allowed and value not in root_files:
            continue
        source = overrides.get(value, ROOT / path)
        if source.is_file():
            target = captured / path
            target.parent.mkdir(parents=True, exist_ok=True)
            for attempt in range(3):
                before = source.stat()
                shutil.copy2(source, target)
                after = source.stat()
                if (before.st_ino, before.st_size, before.st_mtime_ns) == (
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                ):
                    break
            else:
                raise RuntimeError("Source keeps changing during capture: " + value)
            records.append({"path": path.as_posix(), "sha256": sha256(target)})
    key = hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()
    destination = snapshots / key
    if not (destination / "source-snapshot.json").is_file():
        final_head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        metadata = {
            "sha256": key,
            "files": records,
            "git_sha": initial_head,
            "dirty": initial_dirty
            or initial_head != final_head
            or bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        }
        (captured / "source-snapshot.json").write_text(json.dumps(metadata, indent=2) + "\n")
        if destination.exists():
            # Only an incomplete generated capture can occupy this hash path.
            if destination.is_symlink() or destination.resolve().parent != snapshots.resolve():
                raise ValueError("Invalid snapshot destination")
            shutil.rmtree(destination)
        captured.rename(destination)
    else:
        shutil.rmtree(captured)
    return destination


def extract_sources(work, lock, arches, profiles):
    """Extract immutable source inputs on the build host before QEMU execution."""

    def extract(pair):
        arch, name, entry = pair
        directory = work / arch / "sources" / (name + "-" + entry["sha256"][:16])
        ready = directory / ".extracted"
        if ready.is_file():
            return
        archive = work / "downloads" / entry["filename"]
        if sha256(archive) != entry["sha256"]:
            raise ValueError("Source archive digest mismatch: " + name)
        directory.mkdir(parents=True, exist_ok=True)
        print(f"Extracting locked source {arch}/{name}", flush=True)
        with tarfile.open(archive) as package:
            package.extractall(directory, filter="data")
        ready.touch()

    selected = [
        (arch, name, entry)
        for arch in arches
        for name, entry in lock["sources"].items()
        if entry["filename"].endswith((".tar.gz", ".tar.xz"))
        and (not entry.get("arch") or entry["arch"] == arch)
        and set(entry["profiles"]) & set(profiles)
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(extract, selected))


def verify_source_snapshot(source):
    metadata = json.loads((source / "source-snapshot.json").read_text())
    records = metadata["files"]
    if (
        hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()
        != metadata["sha256"]
    ):
        raise ValueError("Source snapshot inventory digest mismatch")
    for row in records:
        relative = Path(row["path"])
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or sha256(source / relative) != row["sha256"]
        ):
            raise ValueError("Source snapshot changed: " + row["path"])
    return source


def deterministic_archive(source, output, epoch):
    with (
        output.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=6) as zipped,
    ):
        with tarfile.open(fileobj=zipped, mode="w|") as archive:
            for path in [source, *sorted(source.rglob("*"))]:
                info = archive.gettarinfo(
                    str(path), arcname=str(Path(source.name) / path.relative_to(source))
                )
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = epoch
                if info.isfile():
                    with path.open("rb") as stream:
                        archive.addfile(info, stream)
                else:
                    archive.addfile(info)


class Release:
    def __init__(self, args):
        self.args = args
        self.lock = read_lock(args.lock)
        self.work = args.work.resolve()
        if platform.system() != "Linux" or str(self.work).startswith("/mnt/"):
            raise RuntimeError("Run in Linux/WSL with --work on the Linux filesystem")
        self.arches = list(ARCHES) if args.arch == "all" else [args.arch]
        self.profiles = list(PROFILES) if args.profile == "all" else [args.profile]
        self.downloads = self.work / "downloads"
        self.work.mkdir(parents=True, exist_ok=True)
        args.output.mkdir(parents=True, exist_ok=True)
        self.version = re.search(
            r'__version__\s*=\s*[\'"]([^\'"]+)', (ROOT / "zscope/_version.py").read_text()
        )[1]

    def container(self, arch, command, *, online=False, source=None, helper=False):
        stage = self.work / arch
        stage.mkdir(exist_ok=True)
        source = source or ROOT
        extra = (
            [
                "-v",
                f"{self.work / 'compiler-helper'}:/helper:ro",
                "-e",
                "ZSCOPE_NATIVE_SHA256=/helper/bin/sha256sum",
            ]
            if helper
            else []
        )
        return run(
            [
                "podman",
                "run",
                "--rm",
                "--arch",
                ARCHES[arch],
                "--network",
                "host" if online else "none",
                "--userns",
                "keep-id",
                "-v",
                f"{source}:/inputs:rw",
                "-v",
                f"{stage}:/work:rw",
                "-v",
                f"{self.downloads}:/downloads:ro",
                "-e",
                f"SOURCE_DATE_EPOCH={self.args.epoch}",
                *extra,
                f"localhost/zscope-portable-builder:{arch}",
                *command,
            ]
        )

    def bootstrap(self):
        if os.geteuid() == 0:
            raise RuntimeError("Run rootless Podman as an ordinary WSL user")
        run(["podman", "info", "--format", "{{.Host.Security.Rootless}}"])
        for arch in self.arches:
            run(
                [
                    "podman",
                    "build",
                    "--network",
                    "host",
                    "--arch",
                    ARCHES[arch],
                    "--build-arg",
                    "BASE_IMAGE=" + self.lock["base_images"][arch],
                    "-t",
                    f"localhost/zscope-portable-builder:{arch}",
                    "-f",
                    ROOT / "scripts/portable/Containerfile",
                    ROOT / "scripts/portable",
                ]
            )
            # These exact signed indices define the apt snapshot used by dpkg.
            process = subprocess.run(
                [
                    "podman",
                    "run",
                    "--rm",
                    "--arch",
                    ARCHES[arch],
                    f"localhost/zscope-portable-builder:{arch}",
                    "cat",
                    "/opt/zscope-build-provenance/apt-metadata.sha256",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            observed = {line.split()[0] for line in process.stdout.splitlines()}
            expected = {entry["sha256"] for entry in self.lock["apt_snapshot"].values()}
            if observed != expected:
                raise RuntimeError(
                    "Ubuntu apt snapshot changed; review and update the lock explicitly"
                )
        runtime_images = json.loads(self.args.runtime_images.read_text())["images"]
        for images in runtime_images.values():
            for arch in self.arches:
                run(["podman", "pull", "--arch", ARCHES[arch], images[arch]])

    def fetch(self):
        from portable.web_assets import verify as verify_web_assets

        verify_web_assets(ROOT)
        selected = [
            entry
            for entry in self.lock["sources"].values()
            if set(entry["profiles"]) & set(self.profiles)
            and (not entry.get("arch") or entry["arch"] in self.arches)
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda entry: fetch_file(entry, self.downloads), selected))
        extract_sources(self.work, self.lock, self.arches, self.profiles)
        from portable.source_materials import fetch_sources

        fetch_sources(ROOT, self.work, self.lock, fetch_file)
        if "java" in self.profiles:
            maven = json.loads((ROOT / "requirements/portable/maven.lock.json").read_text())

            def fetch_maven(pair):
                relative, item = pair
                if Path(relative).is_absolute() or ".." in Path(relative).parts:
                    raise ValueError("Invalid Maven lock path")
                cached = self.work / "maven-cache" / relative
                if "inline_base64" in item:
                    value = base64.b64decode(item["inline_base64"], validate=True)
                    if hashlib.sha256(value).hexdigest() != item["sha256"]:
                        raise ValueError("Maven inline metadata hash mismatch")
                    cached.parent.mkdir(parents=True, exist_ok=True)
                    cached.write_bytes(value)
                else:
                    fetch_file(dict(item, filename=cached.name), cached.parent)
                for arch in self.arches:
                    target = self.work / arch / "prefix/maven-repository" / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(cached, target)

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(fetch_maven, maven["files"].items()))
        environment = self.work / "fetch-python"
        if not (environment / "bin/python").exists():
            run([sys.executable, "-m", "venv", environment])
        for arch in self.arches:
            wheels = self.work / arch / "wheels"
            wheels.mkdir(parents=True, exist_ok=True)
            for profile in self.profiles:
                run(
                    [
                        environment / "bin/python",
                        "-m",
                        "pip",
                        "download",
                        "--require-hashes",
                        "--only-binary=:all:",
                        "--python-version",
                        "313",
                        "--implementation",
                        "cp",
                        "--abi",
                        "cp313",
                        "--abi",
                        "abi3",
                        "--abi",
                        "none",
                        "--platform",
                        f"manylinux_2_17_{arch}",
                        "--platform",
                        f"manylinux_2_28_{arch}",
                        "--platform",
                        f"manylinux2014_{arch}",
                        "-r",
                        ROOT / "requirements/portable" / f"py313-{profile}.txt",
                        "-d",
                        wheels,
                    ]
                )

    def build(self):
        if self.args.formal and subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT):
            raise RuntimeError("Formal releases require a clean checkout")
        source = (
            verify_source_snapshot(self.args.source_snapshot.resolve())
            if self.args.source_snapshot
            else source_snapshot(
                self.work,
                overrides={"requirements/portable/toolchain.lock.json": self.args.lock.resolve()},
            )
        )
        if read_lock(source / "requirements/portable/toolchain.lock.json") != self.lock:
            raise RuntimeError("Toolchain lock changed during source capture")
        self.version = re.search(
            r'__version__\s*=\s*[\'"]([^\'"]+)', (source / "zscope/_version.py").read_text()
        )[1]
        if self.args.formal:
            metadata = json.loads((source / "source-snapshot.json").read_text())
            if (
                metadata["git_sha"]
                != subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
                ).strip()
            ):
                raise RuntimeError("Formal source snapshot must match the checkout commit")
            if metadata["dirty"] or subprocess.check_output(
                ["git", "status", "--porcelain"], cwd=ROOT
            ):
                raise RuntimeError("Formal releases require a clean checkout")
            run(
                [
                    sys.executable,
                    ROOT / "scripts/verify_release_version.py",
                    "--tag",
                    "v" + self.version,
                ]
            )
        for arch in self.arches:
            helper = self.args.arm_compiler_helper and arch == "aarch64" and "cpp" in self.profiles
            if helper:
                if platform.machine() != "x86_64":
                    raise ValueError(
                        "The optional ARM compiler helper requires an x86_64 build host"
                    )
                directory = self.work / "compiler-helper"
                directory.mkdir(exist_ok=True)
                run(
                    [
                        "podman",
                        "run",
                        "--rm",
                        "--network",
                        "none",
                        "--userns",
                        "keep-id",
                        "-v",
                        f"{source}:/inputs:ro",
                        "-v",
                        f"{self.work / 'x86_64'}:/work:ro",
                        "-v",
                        f"{directory}:/helper:rw",
                        "localhost/zscope-portable-builder:x86_64",
                        "python3",
                        "/inputs/scripts/portable/compiler_helper.py",
                        "--work",
                        "/work",
                        "--output",
                        "/helper",
                    ]
                )
            for profile in self.profiles:
                native = [
                    "python3",
                    "/inputs/scripts/portable/native.py",
                    "--lock",
                    "/inputs/requirements/portable/toolchain.lock.json",
                    "--downloads",
                    "/downloads",
                    "--source",
                    "/inputs",
                    "--work",
                    "/work",
                    "--arch",
                    arch,
                    "--profile",
                    profile,
                    "--jobs",
                    self.args.jobs,
                ]
                if helper:
                    native += ["--compiler-helper", "/helper"]
                self.container(arch, native, source=source, helper=helper)
                name = f"zscope-{self.version}-linux-{arch}-{profile}-portable"
                assemblies = self.work / arch / "bundles"
                assemblies.mkdir(exist_ok=True)
                attempt = Path(tempfile.mkdtemp(prefix="assembly-", dir=assemblies))
                stage = attempt / name
                self.container(
                    arch,
                    [
                        "python3",
                        "/inputs/scripts/portable/assemble.py",
                        "--lock",
                        "/inputs/requirements/portable/toolchain.lock.json",
                        "--downloads",
                        "/downloads",
                        "--source",
                        "/inputs",
                        "--prefix",
                        "/work/prefix",
                        "--wheels",
                        "/work/wheels",
                        "--output",
                        "/work/" + stage.relative_to(self.work / arch).as_posix(),
                        "--arch",
                        arch,
                        "--profile",
                        profile,
                    ],
                    source=source,
                    helper=helper,
                )
                shutil.copy2(source / "source-snapshot.json", stage / "share/source-snapshot.json")
                metadata = json.loads((stage / "bundle.json").read_text())
                metadata.update(
                    package_version=self.version,
                    source_snapshot_sha256=json.loads(
                        (source / "source-snapshot.json").read_text()
                    )["sha256"],
                )
                (stage / "bundle.json").write_text(json.dumps(metadata, indent=2) + "\n")
                # Evidence is bound to archive bytes and must be regenerated
                # after rebuilding, even when its version/name is unchanged.
                (self.args.output / (name + ".smoke.json")).unlink(missing_ok=True)
                deterministic_archive(stage, self.args.output / (name + ".tar.gz"), self.args.epoch)
                shutil.copy2(
                    stage / "share/compatibility.json", self.args.output / (name + ".abi.json")
                )
                shutil.copy2(
                    stage / "share/compatibility.md", self.args.output / (name + ".abi.md")
                )
                from portable.spdx import generate

                generate(
                    stage,
                    self.args.output / (name + ".spdx.json"),
                    version=self.version,
                    epoch=self.args.epoch,
                    source_snapshot=metadata["source_snapshot_sha256"],
                )
        from portable.source_materials import publish_sources

        publish_sources(
            source,
            self.work,
            self.args.output,
            self.version,
            self.args.epoch,
            deterministic_archive,
        )
        self.write_manifest(source)

    def artifact_records(self):
        records = []
        for path in sorted(self.args.output.iterdir()):
            if not path.is_file() or path.name in {
                "SHA256SUMS",
                "SHA256SUMS.sig",
                "public-key.pem",
                "release-manifest.json",
            }:
                continue
            record = {"name": path.name, "size": path.stat().st_size, "sha256": sha256(path)}
            match = re.fullmatch(
                r"zscope-.+-linux-(x86_64|aarch64)-(cpp|java)-portable\.tar\.gz", path.name
            )
            if match:
                stem = path.name.removesuffix(".tar.gz")
                abi = json.loads((path.parent / (stem + ".abi.json")).read_text())
                record.update(
                    arch=match[1],
                    profile=match[2],
                    glibc_required=abi["glibc_required"],
                    glibc_tested_min=None,
                )
                smoke = path.parent / (stem + ".smoke.json")
                if smoke.is_file():
                    evidence = json.loads(smoke.read_text())
                    if evidence.get("archive_sha256") != record["sha256"]:
                        raise ValueError("Stale smoke evidence: " + stem)
                    passed = [row["glibc"] for row in evidence["runs"] if row.get("passed")]
                    record["glibc_tested_min"] = min(passed, key=version_tuple) if passed else None
                    record["execution"] = evidence["execution"]
            records.append(record)
        return records

    def write_manifest(self, source):
        snapshot = json.loads((source / "source-snapshot.json").read_text())
        output = self.args.output
        artifacts = self.artifact_records()
        manifest = {
            "schema_version": "zscope.release-assets.v2",
            "package_version": self.version,
            "git_sha": snapshot["git_sha"],
            "source_snapshot_sha256": snapshot["sha256"],
            "dirty": snapshot["dirty"],
            "signature_status": "unsigned-local",
            "toolchain_lock_sha256": sha256(source / "requirements/portable/toolchain.lock.json"),
            "source_date_epoch": self.args.epoch,
            "input_locks": {
                path.name: sha256(path)
                for path in sorted((source / "requirements/portable").iterdir())
                if path.is_file()
            },
            "artifacts": artifacts,
        }
        (output / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        self.sums()

    def sums(self):
        excluded = {"SHA256SUMS", "SHA256SUMS.sig", "public-key.pem"}
        (self.args.output / "SHA256SUMS").write_text(
            "".join(
                f"{sha256(path)}  {path.name}\n"
                for path in sorted(self.args.output.iterdir())
                if path.is_file() and path.name not in excluded
            )
        )

    def verify(self):
        self.refresh_smoke()
        from portable.verify import verify_matrix

        result = verify_matrix(self.args.output, require_signature=self.args.formal)
        self.smoke_summary(result)
        print(json.dumps(result, indent=2))

    def verify_package(self):
        if self.args.formal or len(self.arches) != 1 or len(self.profiles) != 1:
            raise ValueError("verify-package requires one --arch/--profile and is not a formal release")
        self.refresh_smoke()
        from portable.verify import verify_package

        result = verify_package(self.args.output, self.arches[0], self.profiles[0])
        print(json.dumps(result, indent=2))

    def refresh_smoke(self):
        if self.args.run_smoke:
            path = self.args.output / "release-manifest.json"
            manifest = json.loads(path.read_text())
            if manifest.get("signature_status") == "signed":
                raise ValueError("Run smoke before signing; signed manifests are immutable")
            from portable.smoke_matrix import run_archive

            for arch in self.arches:
                for profile in self.profiles:
                    name = f"zscope-{self.version}-linux-{arch}-{profile}-portable.tar.gz"
                    run_archive(
                        self.args.output / name,
                        arch=arch,
                        profile=profile,
                        image_lock=self.args.runtime_images,
                        work=self.work,
                    )
            # Add the newly observed evidence to the integrity manifest while
            # retaining the exact source snapshot from the original build.
            manifest["artifacts"] = self.artifact_records()
            path.write_text(json.dumps(manifest, indent=2) + "\n")
            self.sums()

    def smoke_summary(self, verification):
        summary = {
            "schema_version": "zscope.portable-offline-smoke.v1",
            "passed": True,
            "synthetic_payload": False,
            "network_isolation_confirmed": True,
            "release_manifest_sha256": verification["release_manifest_sha256"],
            "matrix": [
                {"arch": arch, "profile": profile} for arch in ARCHES for profile in PROFILES
            ],
        }
        self.args.smoke_summary.parent.mkdir(parents=True, exist_ok=True)
        self.args.smoke_summary.write_text(json.dumps(summary, indent=2) + "\n")

    def sign(self):
        if not self.args.private_key:
            raise ValueError("sign requires --private-key")
        from portable.verify import verify_matrix

        verify_matrix(self.args.output, require_signature=False)
        path = self.args.output / "release-manifest.json"
        manifest = json.loads(path.read_text())
        if manifest.get("dirty"):
            raise ValueError("Cannot sign a release built from a dirty source snapshot")
        current_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        if (
            manifest.get("git_sha") != current_sha
            or manifest.get("package_version") != self.version
        ):
            raise ValueError("Signing checkout must match the built source commit and version")
        run(
            [
                sys.executable,
                ROOT / "scripts/verify_release_version.py",
                "--tag",
                "v" + self.version,
            ]
        )
        manifest["signature_status"] = "signed"
        path.write_text(json.dumps(manifest, indent=2) + "\n")
        self.sums()
        run(
            [
                "openssl",
                "pkey",
                "-in",
                self.args.private_key,
                "-pubout",
                "-out",
                self.args.output / "public-key.pem",
            ]
        )
        run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                self.args.private_key,
                "-out",
                self.args.output / "SHA256SUMS.sig",
                self.args.output / "SHA256SUMS",
            ]
        )
        self.smoke_summary(verify_matrix(self.args.output, require_signature=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["bootstrap", "fetch", "build", "verify-package"])
    parser.add_argument("--arch", choices=["all", *ARCHES], default="all")
    parser.add_argument("--profile", choices=["all", *PROFILES], default="all")
    parser.add_argument("--work", type=Path, default=Path.home() / ".cache/zscope-portable")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/portable")
    parser.add_argument(
        "--lock", type=Path, default=ROOT / "requirements/portable/toolchain.lock.json"
    )
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument(
        "--source-snapshot",
        type=Path,
        help="Reuse a verified frozen source snapshot when building the four variants in separate runs",
    )
    parser.add_argument(
        "--arm-compiler-helper",
        action="store_true",
        help="Use the locked x86 LLVM compiler inside ARM QEMU builds; build x86 C/C++ first",
    )
    parser.add_argument("--epoch", type=int, default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")))
    parser.set_defaults(formal=False, private_key=None)
    parser.add_argument(
        "--runtime-images",
        type=Path,
        default=ROOT / "requirements/portable/runtime-images.lock.json",
    )
    parser.add_argument(
        "--run-smoke",
        action="store_true",
        help="Execute the offline compatibility matrix before verifying",
    )
    parser.add_argument(
        "--smoke-summary", type=Path, default=ROOT / "release-evidence/portable-offline-smoke.json"
    )
    args = parser.parse_args()
    getattr(Release(args), args.command.replace("-", "_"))()


if __name__ == "__main__":
    main()
