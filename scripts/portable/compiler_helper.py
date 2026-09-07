"""Build-only native compiler acceleration inside an emulated ARM container.

The target sysroot and all configure probes remain in the ARM glibc 2.38 image.
The helper is built from the same locked LLVM sources and never enters a bundle.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from abi import sha256


def prepare(work, output):
    output = output.absolute()
    output.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or output.resolve() == Path("/"):
        raise ValueError("Invalid generated helper directory")
    unexpected = {path.name for path in output.iterdir()} - {"bin", "lib", "manifest.json"}
    if unexpected:
        raise ValueError("Helper directory contains unrelated files: " + str(sorted(unexpected)))
    # Remove old compiler libraries as well as drivers. Otherwise an obsolete
    # LLVM SONAME changes the fingerprint and can contaminate the new closure.
    for name in ("bin", "lib"):
        path = output / name
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise ValueError("Invalid generated helper component: " + str(path))
        if path.exists():
            shutil.rmtree(path)
    (output / "manifest.json").unlink(missing_ok=True)
    (output / "bin").mkdir(parents=True, exist_ok=True)
    (output / "lib").mkdir(exist_ok=True)
    clang = work / "prefix/llvm18/bin/clang"
    binaries = {"clang": clang, "sha256sum": Path("/usr/bin/sha256sum")}
    for component, suffix in (("llvm", "18"), ("clangd", "22")):
        for tool in ("llvm-tblgen", "clang-tblgen"):
            origin = work / "build" / component / "bin" / tool
            if origin.is_file():
                binaries[tool + suffix] = origin
    queue = []
    for name, origin in binaries.items():
        target = output / "lib" / name
        shutil.copy2(origin, target)
        queue.append(origin)
    visited = set()
    env = dict(os.environ, LD_LIBRARY_PATH=str(work / "prefix/llvm18/lib"))
    while queue:
        origin = queue.pop()
        if origin in visited:
            continue
        visited.add(origin)
        result = subprocess.run(["ldd", origin], env=env, text=True, capture_output=True)
        if "not found" in result.stdout:
            raise RuntimeError(result.stdout)
        for dependency in re.findall(r"(?:=>\s+|^\s*)(/\S+)", result.stdout, re.MULTILINE):
            source = Path(dependency)
            target = output / "lib" / source.name
            if not target.exists():
                shutil.copy2(source, target)
                queue.append(source)
    resource = work / "prefix/llvm18/lib/clang"
    shutil.copytree(resource, output / "lib/clang-resources", symlinks=True, dirs_exist_ok=True)
    resource_version = next(path.name for path in resource.iterdir() if path.is_dir())
    # clang re-executes /proc/self/exe for -cc1; invoking ld.so explicitly
    # would make it try to execute the loader as the compiler frontend.
    for name in binaries:
        subprocess.run(
            [
                "patchelf",
                "--set-interpreter",
                "/helper/lib/ld-linux-x86-64.so.2",
                "--set-rpath",
                "$ORIGIN",
                output / "lib" / name,
            ],
            check=True,
        )
    (output / "lib/clang++").unlink(missing_ok=True)
    (output / "lib/clang++").symlink_to("clang")
    for name in ["cc", "c++", *[name for name in binaries if name != "clang"]]:
        program = ("clang++" if name == "c++" else "clang") if name in {"cc", "c++"} else name
        extra = (
            f'--target=aarch64-linux-gnu --sysroot=/ --gcc-install-dir=/usr/lib/gcc/aarch64-linux-gnu/13 -resource-dir "$helper/lib/clang-resources/{resource_version}" $linker'
            if name in {"cc", "c++"}
            else ""
        )
        wrapper = output / "bin" / name
        wrapper.write_text(
            '#!/bin/sh\nset -eu\nhelper=$(dirname "$(dirname "$(readlink -f "$0")")")\n'
            + (
                'linker=--ld-path=/usr/bin/aarch64-linux-gnu-ld\n'
                'for argument do\n'
                '  case "$argument" in -c|-S|-E|--version|-dump*|-print*) linker= ;; esac\n'
                'done\n'
                if name in {"cc", "c++"}
                else ""
            )
            + f'exec "$helper/lib/{program}" {extra} "$@"\n'
        )
        wrapper.chmod(0o755)
    metadata = {
        "schema_version": "zscope.build-compiler-helper.v1",
        "host_arch": "x86_64",
        "target_arch": "aarch64",
        "llvm_version": "18.1.0",
        "files": {
            p.relative_to(output).as_posix(): sha256(p)
            for p in sorted(output.rglob("*"))
            if p.is_file() and p.name != "manifest.json"
        },
    }
    (output / "manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.work, args.output)
