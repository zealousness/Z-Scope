"""Bundle launcher payload. This file uses only the packaged Python stdlib."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

root = Path(os.environ["Z_SCOPE_BUNDLE_ROOT"])
name = sys.argv.pop(1)
args = sys.argv[1:]
manifest = json.loads((root / "bundle.json").read_text())
modules = {
    "zscope": "zscope.cli.cli",
    "zscope-init": "zscope.cli.init",
    "zscope-doctor": "zscope.cli.doctor",
    "zscope-config": "zscope.cli.config_cli",
    "zscope-rules": "zscope.cli.rules",
    "zscope-wiki": "zscope.cli.wiki",
    "zscope-benchmark": "zscope.cli.benchmark",
    "zscope-maven-cache": "zscope.cli.maven_cache",
}
entry_points = manifest.get(
    "entry_points", {key: value + ":main" for key, value in modules.items()}
)
if name in entry_points:
    sys.argv[0] = str(root / "bin" / name)
    module, attribute = entry_points[name].split(":", 1)
    callback = importlib.import_module(module)
    for part in attribute.split("."):
        callback = getattr(callback, part)
    raise SystemExit(callback())
if name in {"python", "python3", "python3.13"}:
    os.execv(str(root / "runtime/python/bin/python3.13"), [name, "-s", *args])
tool = manifest["executables"].get(name)
if not tool:
    raise SystemExit(f"Tool {name!r} is not part of the {manifest['profile']} package")
command = [str(root / tool), *args]
if name == "file":
    os.environ["MAGIC"] = str(root / "tools/build/share/misc/magic.mgc")
if name == "clangd" and not any(arg.startswith("--query-driver") for arg in args):
    drivers = (
        "gcc",
        "g++",
        "cc",
        "c++",
        "clang",
        "clang++",
        "clang-18",
        "clang++-18",
        "gclang",
        "gclang++",
    )
    command.insert(
        1, "--query-driver=" + ",".join(str(root / "bin" / driver) for driver in drivers)
    )
if name in {"clang", "clang++", "clang-18", "clang++-18", "gcc", "g++", "cc", "c++", "cpp"}:
    sysroot = root / "tools/gcc/sysroot"
    triple = manifest["target_triple"]
    gcc_lib = root / "tools/gcc/lib/gcc" / triple / "13"
    os.environ["GCC_EXEC_PREFIX"] = str(root / "tools/gcc/lib/gcc") + "/"
    gcc_exec = root / "tools/gcc/libexec/gcc" / triple / "13"
    os.environ["COMPILER_PATH"] = str(gcc_exec) + ":" + str(root / "tools/gcc/bin")
    os.environ["LIBRARY_PATH"] = ":".join(
        map(str, [gcc_lib, sysroot / "usr/lib" / triple, sysroot / "lib" / triple])
    )
    extra = [
        f"--sysroot={sysroot}",
        f"-B{gcc_lib}/",
        f"-B{gcc_exec}/",
        f"-B{root / 'tools/gcc/bin'}/",
    ]
    if name.startswith("clang"):
        extra += [f"--gcc-toolchain={root / 'tools/gcc'}"]
        os.environ.pop("GCC_EXEC_PREFIX", None)
    command[1:1] = extra
if name in {"wpa", "saber"} and not any(arg.startswith("-extapi") for arg in args):
    command.insert(1, f"-extapi={root / 'tools/svf/lib/extapi.bc'}")
if name in {"mvn", "mvnDebug"}:
    # Share the default repository with zscope-maven-cache install. A project can
    # select a different repository using Maven's normal -Dmaven.repo.local.
    explicit_cache = None
    for index, arg in enumerate(args):
        property_arg = args[index + 1] if arg == "-D" and index + 1 < len(args) else arg
        if property_arg.startswith("-Dmaven.repo.local="):
            explicit_cache = property_arg.split("=", 1)[1]
        elif arg == "-D" and property_arg.startswith("maven.repo.local="):
            explicit_cache = property_arg.split("=", 1)[1]
    if explicit_cache == "":
        raise SystemExit("maven.repo.local must name a repository directory")
    cache = Path(
        explicit_cache
        if explicit_cache is not None
        else os.environ.get("Z_SCOPE_MAVEN_REPO", str(Path.home() / ".cache/zscope/maven"))
    )
    cache.mkdir(parents=True, exist_ok=True)
    inventory = json.loads((root / "share/maven-repository.sha256.json").read_text())
    for relative, expected in inventory.items():
        target = cache / relative
        if target.is_file():
            continue
        source = root / "share/maven-repository" / relative
        actual = hashlib.sha256(source.read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"Corrupted Maven seed artifact: {relative}")
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".zscope-seed-", dir=target.parent)
        os.close(descriptor)
        try:
            shutil.copyfile(source, temporary)
            os.replace(temporary, target)
        finally:
            Path(temporary).unlink(missing_ok=True)
    if explicit_cache is None:
        command.insert(1, f"-Dmaven.repo.local={cache}")
executable = command[0]
if name == "make":
    # GNU Make reuses argv[0] in recursive $(MAKE) recipes without shell
    # quoting. A PATH-resolved name supports installations containing spaces.
    command[0] = "make"
os.execv(executable, command)
