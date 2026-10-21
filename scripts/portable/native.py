#!/usr/bin/env python3
"""Build source components inside the locked glibc 2.38 container.

This module is deliberately independent of the application and of host Python.
Completion stamps include the inputs; a failed command never creates a stamp.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path


def run(command, *, cwd=None, env=None):
    print("+ " + " ".join(map(str, command)), flush=True)
    subprocess.run(list(map(str, command)), cwd=cwd, env=env, check=True)


def digest(path):
    hasher = os.environ.get("ZSCOPE_NATIVE_SHA256")
    if hasher and Path(path).stat().st_size > 4 * 1024 * 1024:
        return subprocess.check_output([hasher, str(path)], text=True).split()[0]
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def copy_tree(source, destination):
    source, destination = Path(source), Path(destination)
    if destination.exists():
        for path in source.rglob("*"):
            target = destination / path.relative_to(source)
            if path.is_symlink() and (target.is_symlink() or target.is_file()):
                target.unlink()
    shutil.copytree(source, destination, symlinks=True, dirs_exist_ok=True)


class Builder:
    def __init__(self, args):
        self.args = args
        self.recipe_digest = digest(__file__)
        self.lock = json.loads(args.lock.read_text())
        self.work = args.work.resolve()
        self.prefix = self.work / "prefix"
        self.prefix.mkdir(parents=True, exist_ok=True)
        self.cpu = (
            "-march=x86-64 -mtune=generic"
            if args.arch == "x86_64"
            else "-march=armv8-a -mtune=generic"
        )
        self.cpu += " -ffile-prefix-map=/work=. -fdebug-prefix-map=/work=."
        self.env = dict(
            os.environ,
            CFLAGS=self.cpu,
            CXXFLAGS=self.cpu,
            SOURCE_DATE_EPOCH=os.environ.get("SOURCE_DATE_EPOCH", "0"),
        )
        self.helper = args.compiler_helper
        if self.helper:
            if args.arch != "aarch64":
                raise ValueError("The compiler helper targets aarch64 only")
            metadata = json.loads((self.helper / "manifest.json").read_text())
            # The small hasher and wrapper are checked with Python first. Large
            # source archives can then be hashed natively inside the container.
            for relative in ("bin/sha256sum", "lib/sha256sum"):
                path = self.helper / relative
                if digest(path) != metadata["files"][relative]:
                    raise ValueError("Compiler helper hasher integrity failure")
            os.environ["ZSCOPE_NATIVE_SHA256"] = str(self.helper / "bin/sha256sum")
            self.env["ZSCOPE_NATIVE_SHA256"] = os.environ["ZSCOPE_NATIVE_SHA256"]
            for relative, expected in metadata["files"].items():
                if digest(self.helper / relative) != expected:
                    raise ValueError("Compiler helper integrity failure: " + relative)

    def reset_generated(self, path):
        path = Path(path)
        if path.is_symlink() or path.resolve() == self.work or not path.resolve().is_relative_to(self.work):
            raise ValueError("Invalid generated directory: " + str(path))
        if path.exists():
            if not path.is_dir():
                raise ValueError("Expected a generated directory: " + str(path))
            shutil.rmtree(path)

    def source(self, name):
        entry = self.lock["sources"][name]
        archive = self.args.downloads / entry["filename"]
        if digest(archive) != entry["sha256"]:
            raise ValueError(f"Source checksum mismatch: {name}")
        directory = self.work / "sources" / (name + "-" + entry["sha256"][:16])
        ready = directory / ".extracted"
        if not ready.exists():
            directory.mkdir(parents=True, exist_ok=True)
            with tarfile.open(archive) as package:
                package.extractall(directory, filter="data")
            ready.touch()
        roots = [path for path in directory.iterdir() if path.is_dir()]
        if len(roots) != 1:
            raise ValueError(f"Expected one archive root: {archive}")
        return roots[0]

    def cached(self, name, build):
        java_sources = {}
        if name == "java":
            for directory in (self.args.source / "tools").glob("java-*"):
                for path in directory.rglob("*"):
                    if path.is_file() and "target" not in path.relative_to(directory).parts:
                        java_sources[path.relative_to(self.args.source).as_posix()] = digest(path)
        key = hashlib.sha256(
            json.dumps(
                {
                    "lock": self.lock,
                    "arch": self.args.arch,
                    "java_sources": java_sources,
                    "recipe": self.recipe_digest,
                    "compiler_helper": (
                        digest(self.helper / "manifest.json")
                        if self.helper and name in {"python", "llvm", "clangd", "svf"}
                        else None
                    ),
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        stamp = self.prefix / (name + ".complete.json")
        if stamp.exists() and json.loads(stamp.read_text()).get("key") == key:
            print(f"Using verified build cache: {name}", flush=True)
            return
        stamp.unlink(missing_ok=True)
        build()
        stamp.write_text(json.dumps({"key": key, "component": name}) + "\n")

    def python(self):
        source = self.source("python")
        build = self.work / "build/python"
        build.mkdir(parents=True, exist_ok=True)
        prefix = self.prefix / "python"
        env = dict(self.env, LD_LIBRARY_PATH=str(prefix / "lib"))
        if self.helper:
            env.update(CC=str(self.helper / "bin/cc"), CXX=str(self.helper / "bin/c++"))
        settings = {"flags": self.cpu, "compiler": env.get("CC", "cc"), "source": str(source)}
        if self.helper:
            settings["compiler_sha256"] = digest(self.helper / "lib/clang")
            settings["compiler_launcher_sha256"] = digest(self.helper / "bin/cc")
        settings_path = build / ".zscope-compile-settings.json"
        previous = json.loads(settings_path.read_text()) if settings_path.is_file() else None
        # Make does not track compiler flag changes. Reconfiguring an old tree
        # alone can silently retain objects built without the prefix maps.
        if previous != settings and (build / "Makefile").exists():
            run(["make", "clean"], cwd=build, env=env)
        settings_path.write_text(json.dumps(settings, sort_keys=True) + "\n")
        run(
            [
                source / "configure",
                "--prefix=/usr/local",
                "--enable-shared",
                "--with-ensurepip=install",
                "--disable-test-modules",
            ],
            cwd=build,
            env=env,
        )
        makefile = build / "Makefile"
        generated = makefile.read_text()
        old_vpath = "-DVPATH='\"$(VPATH)\"'"
        if old_vpath not in generated:
            raise RuntimeError("CPython getpath build rule changed; review relocation flags")
        makefile.write_text(generated.replace(old_vpath, "-DVPATH='\".\"'"))
        stdlib_link = build / "Lib"
        if not stdlib_link.exists():
            stdlib_link.symlink_to(os.path.relpath(source / "Lib", build), target_is_directory=True)
        # Only getpath embeds VPATH as a C string; source lookup in Make still
        # uses the real source tree. PYTHONHOME selects the installed runtime.
        (build / "Modules/getpath.o").unlink(missing_ok=True)
        run(["make", f"-j{self.args.jobs}"], cwd=build, env=env)
        install = self.work / "python-install"
        self.reset_generated(install)
        run(["make", "install", f"DESTDIR={install}"], cwd=build, env=env)
        self.reset_generated(prefix)
        copy_tree(install / "usr/local", prefix)
        run(
            [
                prefix / "bin/python3.13",
                "-c",
                "import ssl,sqlite3,ctypes,bz2,lzma; print(ssl.OPENSSL_VERSION, sqlite3.sqlite_version)",
            ],
            env=env,
        )

    def llvm(self, clangd=False):
        name = "clangd" if clangd else "llvm"
        source = self.source(name)
        build = self.work / "build" / name
        self.prepare_cmake_compiler(build)
        prefix = self.prefix / ("clangd22" if clangd else "llvm18")
        projects = "clang;clang-tools-extra" if clangd else "clang"
        options = [
            "cmake",
            "-G",
            "Ninja",
            "-S",
            source / "llvm",
            "-B",
            build,
            f"-DCMAKE_INSTALL_PREFIX={prefix}",
            "-DCMAKE_BUILD_TYPE=Release",
            f"-DCMAKE_C_FLAGS={self.cpu}",
            f"-DCMAKE_CXX_FLAGS={self.cpu}",
            f"-DLLVM_ENABLE_PROJECTS={projects}",
            "-DLLVM_ENABLE_RTTI=ON",
            "-DCMAKE_POSITION_INDEPENDENT_CODE=" + ("ON" if self.args.arch == "aarch64" else "OFF"),
            "-DLLVM_VERSION_SUFFIX=",
            "-DLLVM_INCLUDE_TESTS=OFF",
            "-DLLVM_INCLUDE_BENCHMARKS=OFF",
            "-DLLVM_INCLUDE_EXAMPLES=OFF",
            "-DLLVM_ENABLE_ZSTD=OFF",
            "-DLLVM_ENABLE_TERMINFO=OFF",
            "-DLLVM_ENABLE_LIBXML2=OFF",
            "-DLLVM_ENABLE_ZLIB=OFF",
            "-DLLVM_PARALLEL_LINK_JOBS=1",
            "-DLLVM_TARGETS_TO_BUILD=X86;AArch64",
            "-DLLVM_ENABLE_ASSERTIONS=OFF",
            "-DCLANG_INCLUDE_TESTS=OFF",
            "-DCLANG_ENABLE_STATIC_ANALYZER=OFF",
            "-DCLANG_ENABLE_ARCMT=OFF",
        ]
        if clangd:
            options += ["-DLLVM_BUILD_LLVM_DYLIB=OFF", "-DCLANGD_BUILD_XPC=OFF"]
            targets = ["clangd", "clang-resource-headers"]
        else:
            options += ["-DLLVM_BUILD_LLVM_DYLIB=ON", "-DLLVM_LINK_LLVM_DYLIB=ON"]
            targets = [
                "clang",
                "llvm-link",
                "llvm-nm",
                "llvm-ar",
                "llvm-objcopy",
                "llvm-dis",
                "llvm-as",
                "opt",
                "llvm-config",
                "clang-resource-headers",
            ]
        if self.helper:
            options += [
                f"-DCMAKE_C_COMPILER={self.helper / 'bin/cc'}",
                f"-DCMAKE_CXX_COMPILER={self.helper / 'bin/c++'}",
            ]
            suffix = "22" if clangd else "18"
            for variable, tool in (
                ("LLVM_TABLEGEN", "llvm-tblgen"),
                ("CLANG_TABLEGEN", "clang-tblgen"),
            ):
                path = self.helper / "bin" / (tool + suffix)
                if path.is_file():
                    options.append(f"-D{variable}={path}")
        run(options, env=self.env)
        configuration = (build / "CMakeCache.txt").read_text()
        if not all(
            f"{language}_SUPPORTS_FPIC:INTERNAL=1" in configuration
            for language in ("C", "CXX")
        ):
            raise RuntimeError(
                "LLVM PIC compiler probes failed; inspect CMakeConfigureLog.yaml before building"
            )
        run(
            ["cmake", "--build", build, "--parallel", self.args.jobs, "--target", *targets],
            env=self.env,
        )
        if prefix.exists():
            if prefix.is_symlink() or prefix.resolve().parent != self.prefix.resolve():
                raise ValueError("Invalid generated component prefix")
            shutil.rmtree(prefix)
        (prefix / "bin").mkdir(parents=True, exist_ok=True)
        for target in targets:
            if (build / "bin" / target).is_file():
                shutil.copy2(build / "bin" / target, prefix / "bin" / target)
        if not clangd:
            for alias in ("clang++", "clang-18"):
                (prefix / "bin" / alias).unlink(missing_ok=True)
                (prefix / "bin" / alias).symlink_to("clang")
            for library in (build / "lib").glob("libLLVM*.so*"):
                if library.resolve() != (build / "lib/libLLVM.so").resolve():
                    continue
                (prefix / "lib").mkdir(exist_ok=True)
                shutil.copy2(library, prefix / "lib" / library.name, follow_symlinks=False)
        copy_tree(build / "lib/clang", prefix / "lib/clang")
        run(
            [prefix / "bin" / ("clangd" if clangd else "clang"), "--version"],
            env=dict(self.env, LD_LIBRARY_PATH=str(prefix / "lib")),
        )

    def svf(self):
        source = self.source("svf")
        build = self.work / "build/svf"
        self.prepare_cmake_compiler(build)
        llvm = self.work / "build/llvm"
        prefix = self.prefix / "svf"
        options = [
            "cmake",
            "-G",
            "Ninja",
            "-S",
            source,
            "-B",
            build,
            "-DCMAKE_BUILD_TYPE=Release",
            f"-DCMAKE_INSTALL_PREFIX={prefix}",
            f"-DCMAKE_C_FLAGS={self.cpu}",
            f"-DCMAKE_CXX_FLAGS={self.cpu}",
            f"-DLLVM_DIR={llvm / 'lib/cmake/llvm'}",
            f"-DLLVM_CLANG={llvm / 'bin/clang'}",
            "-DBUILD_SHARED_LIBS=ON",
            "-DSVF_WARN_AS_ERROR=OFF",
        ]
        if self.helper:
            options += [
                f"-DCMAKE_C_COMPILER={self.helper / 'bin/cc'}",
                f"-DCMAKE_CXX_COMPILER={self.helper / 'bin/c++'}",
            ]
        run(options, env=self.env)
        run(
            [
                "cmake",
                "--build",
                build,
                "--parallel",
                self.args.jobs,
                "--target",
                "wpa",
                "saber",
                "gen_extapi_ir",
            ],
            env=self.env,
        )
        if prefix.exists():
            if prefix.is_symlink() or prefix.resolve().parent != self.prefix.resolve():
                raise ValueError("Invalid generated component prefix")
            shutil.rmtree(prefix)
        (prefix / "bin").mkdir(parents=True, exist_ok=True)
        (prefix / "lib").mkdir(exist_ok=True)
        for name in ("wpa", "saber"):
            shutil.copy2(build / "bin" / name, prefix / "bin" / name)
        for library in (build / "lib").glob("*.so*"):
            shutil.copy2(library, prefix / "lib" / library.name, follow_symlinks=False)
        # Upstream's custom command uses an absolute input path and ignores
        # CFLAGS. Regenerate the same LLVM 18 IR from a relative source path.
        run(
            [
                llvm / "bin/clang",
                "-w",
                "-S",
                "-c",
                "-fPIC",
                "-std=gnu11",
                "-emit-llvm",
                *self.cpu.split(),
                "-o",
                prefix / "lib/extapi.bc",
                "extapi.c",
            ],
            cwd=source / "svf-llvm/lib",
            env=self.env,
        )

    def prepare_cmake_compiler(self, build):
        if not self.helper:
            return
        metadata = json.loads((self.helper / "manifest.json").read_text())
        identity = {
            name: value
            for name, value in metadata["files"].items()
            if name in {"bin/cc", "bin/c++", "lib/clang"} or ".so" in name
        }
        stamp = build / ".zscope-compiler.json"
        previous = json.loads(stamp.read_text()) if stamp.is_file() else None
        if build.exists() and previous != identity:
            if build.is_symlink() or build.resolve().parent != (self.work / "build").resolve():
                raise ValueError("Invalid generated CMake build directory")
            shutil.rmtree(build)
        build.mkdir(parents=True, exist_ok=True)
        stamp.write_text(json.dumps(identity, sort_keys=True) + "\n")

    def gllvm(self):
        source = self.source("gllvm")
        # v1.3.0 predates Go modules and imports only its own shared package
        # plus the standard library. This module declaration fetches nothing.
        if not (source / "go.mod").exists():
            (source / "go.mod").write_text("module github.com/SRI-CSL/gllvm\n\ngo 1.21\n")
        prefix = self.prefix / "gllvm/bin"
        prefix.mkdir(parents=True, exist_ok=True)
        env = dict(
            self.env,
            CGO_ENABLED="0",
            GOCACHE=str(self.work / "go-cache"),
            GOPATH=str(self.work / "go"),
        )
        for name in ("gclang", "gclang++", "get-bc", "gsanity-check"):
            run(
                [
                    "go",
                    "build",
                    "-mod=readonly",
                    "-trimpath",
                    "-ldflags=-s -w",
                    "-o",
                    prefix / name,
                    "./cmd/" + name,
                ],
                cwd=source,
                env=env,
            )

    def java(self):
        jdk = self.prefix / "jdk"
        maven = self.prefix / "maven"
        self.reset_generated(jdk)
        self.reset_generated(maven)
        copy_tree(self.source("jdk-" + self.args.arch), jdk)
        copy_tree(self.source("maven"), maven)
        repository = self.prefix / "maven-repository"
        if not self.args.refresh_maven_lock:
            frozen = json.loads(
                (self.args.source / "requirements/portable/maven.lock.json").read_text()
            )
            for relative, item in frozen["files"].items():
                if digest(repository / relative) != item["sha256"]:
                    raise ValueError(f"Maven cache hash mismatch: {relative}")
        maven_flags = [] if self.args.refresh_maven_lock else ["--offline"]
        env = dict(self.env, JAVA_HOME=str(jdk), PATH=f"{jdk}/bin:{maven}/bin:" + self.env["PATH"])
        jars = self.prefix / "java-jars"
        self.reset_generated(jars)
        jars.mkdir(exist_ok=True)
        for name in ("structure-javaparser", "structure-spoon", "signal-sootup", "signal-wala"):
            project = self.work / "build" / ("java-" + name)
            self.reset_generated(project)
            copy_tree(self.args.source / "tools" / ("java-" + name), project)
            run(
                [
                    maven / "bin/mvn",
                    *maven_flags,
                    "-B",
                    "-ntp",
                    f"-Dmaven.repo.local={repository}",
                    "-DskipTests",
                    "package",
                ],
                cwd=project,
                env=env,
            )
            shutil.copy2(project / "target" / ("zscope-java-" + name + "-0.1.0.jar"), jars)
        # Spoon's MavenLauncher and business-project import use these plugins.
        project = self.work / "build/java-structure-spoon"
        for goal in (
            "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:go-offline",
            "org.apache.maven.plugins:maven-help-plugin:3.5.1:effective-pom",
            "dependency:build-classpath",
        ):
            run(
                [
                    maven / "bin/mvn",
                    *maven_flags,
                    "-B",
                    "-ntp",
                    f"-Dmaven.repo.local={repository}",
                    goal,
                ],
                cwd=project,
                env=env,
            )
        inventory = {
            p.relative_to(repository).as_posix(): digest(p)
            for p in sorted(repository.rglob("*"))
            if p.is_file()
            and (p.suffix in {".jar", ".pom", ".xml"} or p.name == "_remote.repositories")
        }
        (self.prefix / "maven-repository.sha256.json").write_text(
            json.dumps(inventory, indent=2) + "\n"
        )

    def build(self):
        if (
            subprocess.check_output(["getconf", "GNU_LIBC_VERSION"], text=True).strip()
            != "glibc 2.38"
        ):
            raise RuntimeError("Native builds require the locked glibc 2.38 container")
        provenance = {"target_arch": self.args.arch, "build_glibc": "2.38", "compiler_helper": None}
        if self.helper:
            provenance["compiler_helper"] = json.loads((self.helper / "manifest.json").read_text())
        (self.prefix / "build-execution.json").write_text(json.dumps(provenance, indent=2) + "\n")
        components = self.args.component or (
            ["python", "llvm", "clangd", "svf", "gllvm"]
            if self.args.profile == "cpp"
            else ["python", "java"]
        )
        actions = {
            "python": self.python,
            "llvm": self.llvm,
            "clangd": lambda: self.llvm(clangd=True),
            "svf": self.svf,
            "gllvm": self.gllvm,
            "java": self.java,
        }
        for component in components:
            self.cached(component, actions[component])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--downloads", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--arch", choices=["x86_64", "aarch64"], required=True)
    parser.add_argument("--profile", choices=["cpp", "java"], required=True)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument(
        "--compiler-helper",
        type=Path,
        help="Optional locked native compiler helper inside the ARM container",
    )
    parser.add_argument(
        "--component", action="append", choices=["python", "llvm", "clangd", "svf", "gllvm", "java"]
    )
    parser.add_argument(
        "--refresh-maven-lock",
        action="store_true",
        help="Maintainer-only online dependency preparation before freezing maven.lock.json",
    )
    Builder(parser.parse_args()).build()


if __name__ == "__main__":
    main()
