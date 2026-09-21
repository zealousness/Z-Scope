#!/usr/bin/env python3
"""Build the product's batch frontend against the locked portable LLVM SDK.

Run only in the release builder, after native.py has produced LLVM 18. The
component has its own fingerprint so product changes do not rebuild CPython,
clangd, or SVF. No host LLVM headers or libraries are used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def build(source, work, arch, jobs):
    sdk = work / "build/llvm"
    stamp = work / "prefix/llvm.complete.json"
    if not stamp.is_file() or not (sdk / "lib/cmake/clang/ClangConfig.cmake").is_file():
        raise RuntimeError("Build the locked portable LLVM SDK with native.py first")
    inputs = {
        "recipe": digest(__file__),
        "sdk": digest(stamp),
        "arch": arch,
        "argument_policy": digest(source / "zscope/retrieval/compiler_argument_policy.json"),
        "source": {
            name: digest(source / "native/clang-indexer" / name)
            for name in ("CMakeLists.txt", "main.cpp", "ArgumentPolicy.h", "ArgumentCheck.h", "FunctionOwnership.h")
        },
    }
    identity = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
    prefix = work / "prefix/clang-indexer"
    complete = work / "prefix/clang-indexer.complete.json"
    binary = prefix / "bin/zscope-clang-indexer"
    if complete.is_file() and binary.is_file():
        previous = json.loads(complete.read_text())
        if (
            previous.get("identity") == identity
            and all(
                (prefix / name).is_file() and digest(prefix / name) == value
                for name, value in previous.get("files", {}).items()
            )
            and previous.get("files")
        ):
            print("Using verified batch indexer component " + identity, flush=True)
            return
    complete.unlink(missing_ok=True)
    subprocess.run(
        ["cmake", "--build", str(sdk), "--target", "clang-cpp", "-j", str(jobs)], check=True
    )
    build_dir = work / "build/clang-indexer"
    # Remove only this component's old objects if SDK/source/flags changed.
    if build_dir.is_dir():
        shutil.rmtree(build_dir)
    flags = "-ffile-prefix-map=/work=. -ffile-prefix-map=/inputs=. "
    flags += "-march=x86-64 -mtune=generic" if arch == "x86_64" else "-march=armv8-a"
    subprocess.run(
        [
            "cmake",
            "-S",
            str(source / "native/clang-indexer"),
            "-B",
            str(build_dir),
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DLLVM_DIR=" + str(sdk / "lib/cmake/llvm"),
            "-DClang_DIR=" + str(sdk / "lib/cmake/clang"),
            "-DCMAKE_C_FLAGS=" + flags,
            "-DCMAKE_CXX_FLAGS=" + flags,
            "-DCMAKE_INSTALL_PREFIX=" + str(prefix),
            "-DCMAKE_INSTALL_RPATH=$ORIGIN/../lib",
        ],
        check=True,
    )
    subprocess.run(["cmake", "--build", str(build_dir), "-j", str(jobs)], check=True)
    if prefix.is_dir():
        shutil.rmtree(prefix)
    subprocess.run(["cmake", "--install", str(build_dir)], check=True)
    (prefix / "lib").mkdir(exist_ok=True)
    dynamic = subprocess.check_output(["readelf", "-d", str(binary)], text=True)
    needed = re.findall(r"Shared library: \[(libclang-cpp[^]]+)\]", dynamic)
    if needed != ["libclang-cpp.so.18.1"]:
        raise RuntimeError("Unexpected Clang SDK dependency: " + str(needed))
    # A reused SDK may still contain old release-candidate SONAMEs.
    # Copy exactly the library imported by this executable.
    for name in needed:
        shutil.copy2(sdk / "lib" / name, prefix / "lib" / name)
    response = subprocess.check_output(
        [str(binary), "--version"],
        text=True,
        env=dict(os.environ, LD_LIBRARY_PATH=f"{prefix / 'lib'}:{work / 'prefix/llvm18/lib'}"),
    )
    capability = json.loads(response)
    if capability.get("protocol") != "zscope.clang-facts.v2" or not re.match(
        r"18\.1\.0(?:\s|$)", capability.get("clang_version", "")
    ):
        raise RuntimeError("Batch indexer is incompatible with the locked LLVM 18 SDK: " + response)
    files = {p.relative_to(prefix).as_posix(): digest(p) for p in prefix.rglob("*") if p.is_file()}
    complete.write_text(
        json.dumps(
            dict(identity=identity, inputs=inputs, capability=capability, files=files), indent=2
        )
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--arch", choices=("x86_64", "aarch64"), required=True)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    build(args.source.resolve(), args.work.resolve(), args.arch, max(1, args.jobs))
