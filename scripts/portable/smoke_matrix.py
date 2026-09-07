"""Run each archive unprivileged/offline against locked glibc test images."""

from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from .abi import sha256
from .verify import check_smoke


def run_archive(archive, *, arch, profile, image_lock, work):
    report = json.loads(
        archive.with_name(archive.name.removesuffix(".tar.gz") + ".abi.json").read_text()
    )
    required = {"2.34", "2.38", "2.39", report["glibc_required"]}
    images = json.loads(image_lock.read_text())["images"]
    missing = required - images.keys()
    if missing:
        raise ValueError(
            f"Lock runtime test images for the computed floors first: {sorted(missing)}"
        )
    identity = sha256(archive)
    directory = work / "smoke" / (archive.name.removesuffix(".tar.gz") + "-" + identity[:12])
    extracted = directory / "relocated archive"
    if not extracted.exists():
        extracted.mkdir(parents=True)
        with tarfile.open(archive) as package:
            package.extractall(extracted, filter="data")
    roots = list(extracted.iterdir())
    if len(roots) != 1:
        raise ValueError("Invalid portable archive root")
    def run_version(version):
        destination = Path(tempfile.mkdtemp(prefix="glibc-" + version + "-", dir=directory))
        (destination / "project spaces").mkdir(exist_ok=True)
        (destination / "home").mkdir(exist_ok=True)
        previous = destination / "result.json"
        previous.unlink(missing_ok=True)
        image = images[version][arch]
        options = [
            "podman",
            "run",
            "--rm",
            "--pull=never",
            "--arch",
            "amd64" if arch == "x86_64" else "arm64",
            "--network=none",
            "--http-proxy=false",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--userns=keep-id",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--tmpfs",
            "/tmp:rw,size=1g",
            "-v",
            f"{roots[0]}:/opt/zscope moved:ro",
            "-v",
            f"{destination}:/work:rw",
            "-v",
            f"{Path(__file__).with_name('smoke.py')}:/smoke.py:ro",
            "-w",
            "/work/project spaces",
            "-e",
            "HOME=/work/home",
            image,
        ]
        print(f"Smoke {arch}/{profile} on glibc {version} ({image})", flush=True)
        process = subprocess.run(
            [*options, "/opt/zscope moved/bin/python", "/smoke.py"], text=True, capture_output=True
        )
        (destination / "stdout.log").write_text(process.stdout)
        (destination / "stderr.log").write_text(process.stderr)
        if previous.is_file():
            row = json.loads(previous.read_text())
            if row.get("glibc") != version or row.get("arch") != arch:
                row.update(passed=False, failure_reason="Runtime image identity mismatch")
        else:
            row = {
                "glibc": version,
                "arch": arch,
                "passed": False,
                "failure_reason": process.stderr[-4000:] or f"Container exit {process.returncode}",
            }
        row.update(image=image, returncode=process.returncode)
        if process.returncode:
            row["passed"] = False
        return row
    # Each run owns a separate home, project, network namespace, and logs.
    # Bound concurrency so two Java/QEMU workloads fit ordinary release hosts.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        runs = list(pool.map(
            run_version, sorted(required, key=lambda value: tuple(map(int, value.split("."))))
        ))
    evidence = {
        "schema_version": "zscope.portable-smoke.v1",
        "arch": arch,
        "profile": profile,
        "archive_sha256": identity,
        "execution": "qemu" if arch != os.uname().machine else "native",
        "runtime_images_lock_sha256": sha256(image_lock),
        "runs": runs,
    }
    output = archive.with_name(archive.name.removesuffix(".tar.gz") + ".smoke.json")
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    check_smoke(evidence, arch, profile, identity, report["glibc_required"])
    return evidence
