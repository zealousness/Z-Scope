#!/usr/bin/env python3
"""Assemble one language/architecture bundle in the pinned build container."""
from __future__ import annotations

import argparse
import configparser
import json
import os
import re
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path

from abi import HOST_LIBRARIES, audit, elf_machine, inspect_elf, sha256, write_report
from native import copy_tree, run

SYSTEM_INPUTS = set()


def copy_file(source, destination):
    source, destination = Path(source), Path(destination)
    if str(source).startswith(("/usr/", "/lib/", "/lib64/", "/etc/ssl/")) and not str(
        source
    ).startswith("/usr/share/doc/"):
        SYSTEM_INPUTS.update((str(source), str(source.resolve())))
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def system_inventory(root):
    packages = set()
    paths = sorted(SYSTEM_INPUTS)
    for offset in range(0, len(paths), 200):
        result = subprocess.run(
            ["dpkg-query", "-S", *paths[offset : offset + 200]], text=True, capture_output=True
        )
        for line in result.stdout.splitlines():
            if ": /" in line:
                packages.update(line.split(": /", 1)[0].split(", "))
    rows = []
    if packages:
        result = subprocess.check_output(
            [
                "dpkg-query",
                "-W",
                "-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n",
                *sorted(packages),
            ],
            text=True,
        )
        for line in result.splitlines():
            name, version, source, source_version = line.split("\t")
            rows.append(
                dict(name=name, version=version, source=source, source_version=source_version)
            )
    (root / "share/system-runtime-packages.json").write_text(json.dumps(rows, indent=2) + "\n")


def runtime_elfs(root):
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink() or "sysroot" in path.relative_to(root).parts:
            continue
        with path.open("rb") as stream:
            if elf_machine(stream.read(20)):
                yield path


def bundle_libraries(root):
    """Copy the observed native dependency closure; glibc remains host-owned."""
    library_root = root / "lib"
    library_root.mkdir(exist_ok=True)
    queue = list(runtime_elfs(root))
    visited = set()
    while queue:
        binary = queue.pop()
        if binary in visited:
            continue
        visited.add(binary)
        # Component libraries must take precedence during collection, too.
        directories = [
            binary.parent,
            binary.parent.parent / "lib",
            root / "tools/svf/lib",
            root / "tools/llvm18/lib",
            root / "runtime/python/lib",
            library_root,
        ]
        if "jdk" in binary.parts:
            directories += [root / "tools/jdk/lib", root / "tools/jdk/lib/server"]
        env = dict(os.environ, LD_LIBRARY_PATH=":".join(map(str, directories)))
        process = subprocess.run(["ldd", str(binary)], text=True, capture_output=True, env=env)
        if "not found" in process.stdout:
            raise RuntimeError(f"Unresolved build dependency: {binary}\n{process.stdout}")
        for name, source in re.findall(r"^\s*(\S+)\s+=>\s+(/\S+)", process.stdout, re.MULTILINE):
            if HOST_LIBRARIES.fullmatch(name):
                continue
            origin = Path(source).resolve()
            if origin.is_relative_to(root):
                continue
            target = library_root / name
            if name.startswith(("libLLVM", "libclang-cpp")):
                components = [
                    component
                    for component, major in (("llvm18", "18"), ("clangd22", "22"))
                    if re.search(r"(?<!\d)" + major + r"(?:\.|$|-)", name)
                ]
                if len(components) != 1:
                    raise RuntimeError("Unrecognized LLVM library version: " + name)
                target = root / "tools" / components[0] / "lib" / name
            if target.exists() and sha256(target) != sha256(origin):
                raise RuntimeError(f"Conflicting native dependency: {name}")
            if not target.exists():
                copy_file(origin, target)
                queue.append(target)
    for binary in runtime_elfs(root):
        # GNU strip can corrupt section/segment layouts rewritten by patchelf
        # (notably Ubuntu's GCC drivers). Strip original ELFs before patching.
        run(["strip", "--strip-debug", binary])
        metadata = inspect_elf(binary)
        if not metadata["needed"] and not metadata["interpreter"]:
            continue  # Static Go executables have no dynamic section.
        paths = [
            binary.parent,
            binary.parent.parent / "lib",
            root / "runtime/python/lib",
            library_root,
        ]
        if "svf" in binary.parts:
            paths.insert(1, root / "tools/llvm18/lib")
        if "jdk" in binary.parts:
            paths += [root / "tools/jdk/lib", root / "tools/jdk/lib/server"]
        relative = list(
            dict.fromkeys("$ORIGIN/" + os.path.relpath(p, binary.parent) for p in paths)
        )
        run(["patchelf", "--set-rpath", ":".join(relative), binary])


def cpp_tools(root, prefix, manifest):
    for name in ("clangd22", "llvm18", "svf", "gllvm"):
        copy_tree(prefix / name, root / "tools" / name)
    # Install next to its matching Clang resource headers and LLVM libraries.
    # The SDK/build tools themselves remain outside the runtime archive.
    copy_tree(prefix / "clang-indexer", root / "tools/llvm18")
    indexer = json.loads((prefix / "clang-indexer.complete.json").read_text())
    manifest["clang_indexer"] = {
        "identity": indexer["identity"], "capability": indexer["capability"]
    }
    # LLVM's build configuration introspector is only needed while producing
    # SVF; its output refers to the build tree and is not a runtime tool.
    (root / "tools/llvm18/bin/llvm-config").unlink(missing_ok=True)
    commands = {"clangd": "clangd22", "wpa": "svf", "saber": "svf"}
    for name in (
        "zscope-clang-indexer",
        "clang",
        "clang++",
        "llvm-link",
        "llvm-nm",
        "llvm-ar",
        "llvm-objcopy",
        "llvm-dis",
        "llvm-as",
        "opt",
    ):
        commands[name] = "llvm18"
    for name in ("gclang", "gclang++", "get-bc", "gsanity-check"):
        commands[name] = "gllvm"
    for name, component in commands.items():
        manifest["executables"][name] = f"tools/{component}/bin/{name}"
    manifest["executables"]["clang-18"] = "tools/llvm18/bin/clang"
    manifest["executables"]["clang++-18"] = "tools/llvm18/bin/clang++"
    cpp_build_tools(root, manifest)


def cpp_build_tools(root, manifest):
    triple = subprocess.check_output(["gcc", "-dumpmachine"], text=True).strip()
    manifest["target_triple"] = triple
    gcc = root / "tools/gcc"
    copy_tree(Path("/usr/lib/gcc") / triple, gcc / "lib/gcc" / triple)
    executables = Path("/usr/libexec/gcc") / triple
    if executables.is_dir():
        copy_tree(executables, gcc / "libexec/gcc" / triple)
        for path in executables.rglob("*"):
            if path.is_file():
                SYSTEM_INPUTS.add(str(path))
    for origin in (Path("/usr/lib/gcc") / triple).rglob("*"):
        if origin.is_symlink():
            target = gcc / "lib/gcc" / triple / origin.relative_to(Path("/usr/lib/gcc") / triple)
            resolved = target.resolve()
            if not resolved.is_relative_to(gcc):
                raise ValueError("GCC development link escapes its component: " + str(origin))
            if not resolved.exists():
                copy_file(origin.resolve(), resolved)
    copy_tree("/usr/include/c++", gcc / "include/c++")
    copy_tree(Path("/usr/include") / triple / "c++", gcc / "include" / triple / "c++")
    for name in (
        "gcc",
        "g++",
        "cpp",
        "as",
        "ld",
        "ar",
        "nm",
        "objcopy",
        "objdump",
        "ranlib",
        "strip",
        "readelf",
    ):
        copy_file(shutil.which(name), gcc / "bin" / name)
        manifest["executables"][name] = f"tools/gcc/bin/{name}"
    manifest["executables"].update(cc="tools/gcc/bin/gcc", **{"c++": "tools/gcc/bin/g++"})
    # Development package inputs are separate from runtime search paths.
    for package in ("libc6-dev", "linux-libc-dev", "libgcc-13-dev", "libstdc++-13-dev"):
        files = subprocess.check_output(["dpkg-query", "-L", package], text=True).splitlines()
        for value in files:
            path = Path(value)
            if path.is_file() and value.startswith(("/usr/include/", "/usr/lib/")):
                copy_file(path, gcc / "sysroot" / path.relative_to("/"))
    for base in (Path("/lib") / triple, Path("/usr/lib") / triple):
        for pattern in (
            "libc.so*",
            "libm.so*",
            "libmvec.so*",
            "libpthread.so*",
            "libdl.so*",
            "librt.so*",
            "ld-linux*.so*",
            "libgcc_s.so*",
            "libstdc++.so*",
        ):
            for path in base.glob(pattern):
                copy_file(path, gcc / "sysroot" / path.relative_to("/"))
    loader = Path(
        "/lib64/ld-linux-x86-64.so.2"
        if manifest["arch"] == "x86_64"
        else "/lib/ld-linux-aarch64.so.1"
    )
    copy_file(loader, gcc / "sysroot" / loader.relative_to("/"))
    for name in ("cmake", "ctest", "cpack", "make", "ninja", "pkg-config", "file"):
        copy_file(shutil.which(name), root / "tools/build/bin" / name)
        manifest["executables"][name] = f"tools/build/bin/{name}"
    copy_file("/usr/share/misc/magic.mgc", root / "tools/build/share/misc/magic.mgc")
    for directory in Path("/usr/share").glob("cmake-*"):
        copy_tree(directory, root / "tools/build/share" / directory.name)


def java_tools(root, prefix, downloads, lock, manifest):
    for name in ("jdk", "maven", "java-jars"):
        copy_tree(prefix / name, root / "tools" / name)
    for name in ("java", "javac", "jar", "javap", "javadoc", "jlink", "jdeps", "keytool"):
        manifest["executables"][name] = f"tools/jdk/bin/{name}"
    manifest["executables"]["mvn"] = "tools/maven/bin/mvn"
    for jar in (root / "tools/java-jars").glob("*.jar"):
        key = jar.name.removeprefix("zscope-java-").removesuffix("-0.1.0.jar")
        manifest["java_jars"][key] = jar.relative_to(root).as_posix()
    copy_tree(prefix / "maven-repository", root / "share/maven-repository")
    copy_file(prefix / "maven-repository.sha256.json", root / "share/maven-repository.sha256.json")
    archive = downloads / lock["sources"]["joern-" + manifest["arch"]]["filename"]
    destination = root / "tools/joern"
    # Only the Java frontend and the shared query/runtime distribution belong in
    # this profile. The archive inventory and smoke tests guard this allowlist.
    excluded = re.compile(r"(?:^|/)(?:schema-extender(?:\.sh)?|jdk|jre)(?:/|$)")
    other_frontends = (
        "c2cpg",
        "ghidra2cpg",
        "jssrc2cpg",
        "jimple2cpg",
        "kotlin2cpg",
        "php2cpg",
        "pysrc2cpg",
        "rubysrc2cpg",
        "swiftsrc2cpg",
        "csharpsrc2cpg",
        "gosrc2cpg",
        "rust2cpg",
        "abap2cpg",
        "jruby",
    )
    frontend_pattern = re.compile(
        r"(?:^|[./_-])(?:" + "|".join(map(re.escape, other_frontends)) + r")(?=$|[./_-])"
    )
    with zipfile.ZipFile(archive) as package:
        for member in package.infolist():
            parts = Path(member.filename).parts
            if ".." in parts or Path(member.filename).is_absolute():
                raise ValueError("Unsafe Joern archive member")
            relative = Path(*parts[1:])
            if not relative.parts or excluded.search(relative.as_posix()):
                continue
            if (
                relative.parts[0] == "frontends"
                and len(relative.parts) > 1
                and relative.parts[1] != "javasrc2cpg"
            ):
                continue
            if relative.suffix in {".bat", ".ps1", ".sbt"} or frontend_pattern.search(
                relative.name.lower()
            ):
                continue
            target = destination / relative
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                if stat.S_ISLNK(member.external_attr >> 16):
                    target.symlink_to(package.read(member).decode("utf-8"))
                else:
                    with package.open(member) as source, target.open("wb") as output:
                        shutil.copyfileobj(source, output)
                mode = (member.external_attr >> 16) & 0o777
                if not target.is_symlink():
                    target.chmod(mode or 0o644)
                    with target.open("rb") as stream:
                        shell = stream.read(80).startswith(
                            (
                                b"#!/usr/bin/env sh",
                                b"#!/usr/bin/env bash",
                                b"#!/bin/bash",
                                b"#!/bin/sh",
                            )
                        )
                    if shell:
                        text = target.read_text().replace("\n$SCRIPT ", '\n"$SCRIPT" ')
                        target.write_text(text)
    for name in ("joern", "joern-parse", "joern-export", "joern-scan"):
        target = destination / name
        if not target.is_file():
            raise RuntimeError(f"Joern distribution layout changed: {name}")
        target.chmod(0o755)
        manifest["executables"][name] = f"tools/joern/{name}"
    java_frontend = destination / "frontends/javasrc2cpg"
    if not (java_frontend / "bin/javasrc2cpg").is_file() or not list(
        (java_frontend / "lib").glob("*javasrc2cpg*.jar")
    ):
        raise RuntimeError("The Java-only Joern distribution is missing its Java frontend")


def python_application(root, prefix, source, downloads, wheels, lock, profile):
    destination = root / "runtime/python"
    copy_tree(prefix / "python", destination)
    python = destination / "bin/python3.13"
    env = dict(
        os.environ,
        PYTHONHOME=str(destination),
        LD_LIBRARY_PATH=str(destination / "lib"),
        PYTHONDONTWRITEBYTECODE="1",
        PIP_DISABLE_PIP_VERSION_CHECK="1",
    )
    run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            *[
                downloads / value["filename"]
                for value in lock["sources"].values()
                if value.get("build_only") and value["filename"].endswith(".whl")
            ],
        ],
        env=env,
    )
    run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            wheels,
            "--require-hashes",
            "-r",
            source / "requirements/portable" / f"py313-{profile}.txt",
        ],
        env=env,
    )
    app_wheels = root.parent / (root.name + "-wheel")
    app_wheels.mkdir(exist_ok=True)
    run(
        [
            python,
            "-m",
            "pip",
            "wheel",
            "--no-index",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            app_wheels,
            source,
        ],
        env=env,
    )
    wheel = next(app_wheels.glob("zscope-*.whl"))
    run([python, "-m", "pip", "install", "--no-index", "--no-deps", wheel], env=env)
    run([python, "-m", "pip", "check"], env=env)
    # The installed runtime is complete. Build backends and installers are not
    # shipped as a second mechanism for fetching dependencies at user startup.
    run([python, "-m", "pip", "uninstall", "-y", "setuptools", "wheel", "packaging"], env=env)
    for path in destination.rglob("__pycache__"):
        shutil.rmtree(path)
    for path in (destination / "bin").iterdir():
        if path.name not in {"python3", "python3.13"}:
            path.unlink()
    for path in destination.glob("lib/python3.13/config-*"):
        shutil.rmtree(path)
    for pattern in ("lib/libpython*.a", "lib/python3.13/site-packages/pip*", "include"):
        for path in destination.glob(pattern):
            shutil.rmtree(path) if path.is_dir() else path.unlink()
    for path in destination.glob("lib/python3.13/_sysconfigdata*.py"):
        # Development-only directories are not useful in the shipped runtime.
        # sysconfig expands prefix/exec_prefix from the relocated interpreter.
        text = path.read_text().replace("/work/", "./").replace("/helper/bin/", "")
        path.write_text(text)
    for path in destination.glob("lib/python3.13/site-packages/*.dist-info/direct_url.json"):
        path.unlink()
    pkgconfig = destination / "lib/pkgconfig"
    if pkgconfig.is_dir():
        shutil.rmtree(pkgconfig)


def licenses(root, prefix, lock, profile):
    for name, entry in lock["sources"].items():
        if profile not in entry["profiles"] or entry.get("build_only"):
            continue
        directory = prefix.parent / "sources" / (name + "-" + entry["sha256"][:16])
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if not path.is_file() or not path.name.upper().startswith(
                ("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE")
            ):
                continue
            if path.stat().st_size < 2 * 1024 * 1024:
                copy_file(path, root / "licenses" / name / path.relative_to(directory))
    if profile == "java":
        for jar in [
            *(prefix / "maven-repository").rglob("*.jar"),
            *(root / "tools/joern").rglob("*.jar"),
        ]:
            with zipfile.ZipFile(jar) as archive:
                for member in archive.infolist():
                    if member.is_dir() or member.file_size > 1024 * 1024:
                        continue
                    name = Path(member.filename)
                    if name.is_absolute() or ".." in name.parts:
                        continue
                    if name.name.upper().startswith(
                        ("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE")
                    ):
                        target = root / "licenses/maven" / jar.name / name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(archive.read(member))
    index = {
        name: item
        for name, item in lock["sources"].items()
        if profile in item["profiles"] and not item.get("build_only")
    }
    (root / "share/source-materials.json").write_text(json.dumps(index, indent=2) + "\n")


def assemble(args):
    from web_assets import verify as verify_web_assets

    verify_web_assets(args.source)
    root = args.output.resolve()
    if root.exists():
        raise ValueError(f"Assembly destination already exists: {root}")
    root.mkdir(parents=True)
    lock = json.loads(args.lock.read_text())
    manifest = {
        "schema_version": "zscope.portable.v1",
        "profile": args.profile,
        "arch": args.arch,
        "build_glibc": "2.38",
        "tools": {},
        "executables": {},
        "java_jars": {},
        "toolchain_lock_sha256": sha256(args.lock),
    }
    copy_tree("/opt/zscope-build-provenance", root / "share/build-provenance")
    if (args.prefix / "build-execution.json").is_file():
        copy_file(
            args.prefix / "build-execution.json", root / "share/build-provenance/execution.json"
        )
    copy_file(shutil.which("git"), root / "tools/git/bin/git")
    manifest["executables"]["git"] = "tools/git/bin/git"
    git_binary = Path(shutil.which("git"))
    git_stat = git_binary.stat()
    git_copies = {(git_stat.st_dev, git_stat.st_ino): root / "tools/git/bin/git"}
    for path in Path("/usr/lib/git-core").iterdir():
        if path.is_file():
            with path.open("rb") as stream:
                header = stream.read(80)
            if elf_machine(header) or header.startswith((b"#!/bin/sh", b"#!/bin/bash")):
                target = root / "tools/git/libexec/git-core" / path.name
                info = path.stat()
                identity = (info.st_dev, info.st_ino)
                if identity in git_copies:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.symlink_to(os.path.relpath(git_copies[identity], target.parent))
                else:
                    copy_file(path, target)
                    git_copies[identity] = target
    copy_tree("/usr/share/git-core/templates", root / "tools/git/share/git-core/templates")
    # Watchman/Perl are optional integrations, not part of the portable Git
    # runtime. Do not ship a sample executable requiring either dependency.
    (root / "tools/git/share/git-core/templates/hooks/fsmonitor-watchman.sample").unlink(
        missing_ok=True
    )
    python_application(
        root, args.prefix, args.source, args.downloads, args.wheels, lock, args.profile
    )
    certificate = next(root.glob("runtime/python/lib/python*/site-packages/certifi/cacert.pem"))
    copy_file(certificate, root / "share/cacert.pem")
    if args.profile == "cpp":
        cpp_tools(root, args.prefix, manifest)
    else:
        java_tools(root, args.prefix, args.downloads, lock, manifest)
    for name in manifest["executables"]:
        manifest["tools"][name] = "bin/" + name
    bin_dir = root / "bin"
    bin_dir.mkdir()
    copy_file(Path(__file__).with_name("launcher.sh"), bin_dir / "zscope-launch")
    (bin_dir / "zscope-launch").chmod(0o755)
    copy_file(Path(__file__).with_name("dispatch.py"), root / "libexec/dispatch.py")
    entry_file = next(
        root.glob("runtime/python/lib/python*/site-packages/zscope-*.dist-info/entry_points.txt")
    )
    entry_config = configparser.ConfigParser(interpolation=None)
    entry_config.read(entry_file)
    language_cli = {"zscope-maven-cache": "java", "zscope-index-audit": "cpp"}
    manifest["entry_points"] = {
        name: value
        for name, value in entry_config["console_scripts"].items()
        if name not in language_cli or language_cli[name] == args.profile
    }
    cli_names = list(manifest["entry_points"])
    for name in [*cli_names, "python", "python3", "python3.13", *manifest["executables"]]:
        (bin_dir / name).symlink_to("zscope-launch")
    template = "zscope.c_cpp.yaml" if args.profile == "cpp" else "zscope.java.yaml"
    copy_file(args.source / template, root / "examples" / template)
    copy_file(args.source / "LICENSE", root / "LICENSE")
    notices = args.source / "THIRD_PARTY_NOTICES.md"
    if notices.is_file():
        copy_file(notices, root / "THIRD_PARTY_NOTICES.md")
    license_policy = args.source / "requirements/license-policy.json"
    if license_policy.is_file():
        copy_file(license_policy, root / "share/license-policy.json")
    copy_file(args.lock, root / "share/toolchain.lock.json")
    copy_file(
        args.source / "requirements/portable/web-assets.lock.json",
        root / "share/web-assets.lock.json",
    )
    # Preserve actual redistribution notices for every installed build package;
    # SPDX identifies the smaller runtime closure separately.
    for path in Path("/usr/share/doc").glob("*/copyright"):
        copy_file(path, root / "licenses/system" / path.parent.name / "copyright")
    licenses(root, args.prefix, lock, args.profile)
    (root / "bundle.json").write_text(json.dumps(manifest, indent=2) + "\n")
    bundle_libraries(root)
    system_inventory(root)
    report = audit(root, args.arch)
    write_report(report, root / "share/compatibility.json")
    if not report["passed"]:
        raise RuntimeError("Bundle ABI audit failed: " + "; ".join(report["errors"][:20]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("lock", "prefix", "source", "downloads", "wheels", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--arch", choices=["x86_64", "aarch64"], required=True)
    parser.add_argument("--profile", choices=["cpp", "java"], required=True)
    assemble(parser.parse_args())


if __name__ == "__main__":
    main()
