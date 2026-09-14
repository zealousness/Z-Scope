#!/usr/bin/env python3
"""Install offline C/C++ dependencies for Z-SCOPE.

This script is intended for the intranet deployment target.  It consumes a
local tool directory, or a bundled archive that contains the required tool
archives, and installs clangd plus the unified/SVF dependency chain.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urlparse


CLANGD_ARCHIVE = "clangd-linux-20.1.0.zip"
LLVM_ARCHIVE = "llvm-18.1.0-ubuntu20-rtti-x86-64.tar.gz"
SVF_ARCHIVE = "SVF-3.2-ubuntu-24.04-x86_64.zip"
Z3_ARCHIVE = "z3-4.13.0-x64-glibc-2.35.zip"
GLLVM_ARCHIVE = "gllvm-1.3.1.zip"
GCC_RUNTIME_ARCHIVE = "gcc-13-runtime-linux-x86_64.tar.gz"

DEFAULT_BUILDTOOLS_DIR = Path("/opt/buildtools")
DEFAULT_SDK_DIR = Path("/root/sdk")
DEFAULT_PROFILE_PATH = Path("/etc/profile")
DEFAULT_CLANGD_DIR_NAME = "clangd_20.1.0"
DEFAULT_LLVM_DIR_NAME = "llvm-18"
DEFAULT_SVF_DIR_NAME = "svf"
DEFAULT_GOROOT_DIR_NAME = "golang_go-1.17.7"
DEFAULT_GOPATH_DIR_NAME = "go_workpace"
DEFAULT_GLLVM_DIR_NAME = "gllvm-1.3.1"
DEFAULT_GCC_RUNTIME_DIR_NAME = "gcc-13-runtime"
MIN_GLIBC_VERSION = (2, 38)
MIN_PYTHON_VERSION = (3, 9)
OS_RELEASE_PATHS = (Path("/etc/os-release"), Path("/usr/lib/os-release"))
PROBE_TIMEOUT_SECONDS = 30
MIN_GLIBCXX_VERSION = "3.4.32"
MIN_CXXABI_VERSION = "1.3.14"
ELF_MACHINE_X86_64 = 62

PROFILE_BLOCK_MARKER_START = "# >>> Z-SCOPE C/C++ toolchain >>>"
PROFILE_BLOCK_MARKER_END = "# <<< Z-SCOPE C/C++ toolchain <<<"
PIP_TRUSTED_HOST_ENV = "PIP_TRUSTED_HOST"


@dataclass
class StepResult:
    name: str
    status: str
    message: str = ""
    path: str = ""


class DeploymentError(RuntimeError):
    """Raised when a deployment step cannot complete."""


class Installer:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.tool_root = Path(args.tool_root).expanduser().resolve()
        self.buildtools_dir = Path(args.buildtools_dir).expanduser()
        self.sdk_dir = Path(args.sdk_dir).expanduser()
        self.profile_path = Path(args.profile_path).expanduser()
        self.clangd_dir = self.buildtools_dir / DEFAULT_CLANGD_DIR_NAME
        self.llvm_dir = self.sdk_dir / DEFAULT_LLVM_DIR_NAME
        self.svf_dir = self.sdk_dir / DEFAULT_SVF_DIR_NAME
        self.goroot = self.buildtools_dir / DEFAULT_GOROOT_DIR_NAME
        self.gopath = self.buildtools_dir / DEFAULT_GOPATH_DIR_NAME
        self.gllvm_dir = self.buildtools_dir / DEFAULT_GLLVM_DIR_NAME
        default_gcc_runtime_dir = DEFAULT_BUILDTOOLS_DIR / DEFAULT_GCC_RUNTIME_DIR_NAME
        if args.gcc_runtime_dir == str(default_gcc_runtime_dir) and self.buildtools_dir != DEFAULT_BUILDTOOLS_DIR:
            self.gcc_runtime_dir = self.buildtools_dir / DEFAULT_GCC_RUNTIME_DIR_NAME
        else:
            self.gcc_runtime_dir = Path(args.gcc_runtime_dir).expanduser()
        self.gcc_runtime_root = Path(args.gcc_runtime_root).expanduser() if args.gcc_runtime_root else None
        self.zscope_source = Path(args.zscope_source).expanduser().resolve()
        self.steps: list[StepResult] = []
        self._prepared_tool_root: Path | None = None
        self._temp_dir: tempfile.TemporaryDirectory[str] | None = None

    def close(self) -> None:
        if self._temp_dir is not None:
            self._temp_dir.cleanup()
            self._temp_dir = None

    def run(self) -> dict[str, Any]:
        self._ensure_supported_target()
        self._ensure_runtime_versions()
        self._prepare_tool_root()
        preflight = self._gcc_runtime_validation()
        if not preflight.get("ok"):
            raise DeploymentError("; ".join(preflight.get("errors") or ["GCC runtime preflight failed"]))
        self._ensure_root_or_dry_run()
        self._install_gcc_runtime()
        self._install_clangd()
        self._install_llvm()
        self._install_svf()
        self._install_z3()
        self._install_go()
        self._install_gllvm()
        self._install_zscope()
        self._write_profile_block()
        self._source_profile_once()
        payload = self.status_payload(success=True)
        if not self.args.dry_run:
            self._ensure_status_ok(payload)
        return payload

    def status_payload(self, *, success: bool | None = None) -> dict[str, Any]:
        gcc_runtime_validation = self._gcc_runtime_validation()
        probes = self._probe_statuses()
        symbol_versions = self._symbol_version_status()
        runtime_resolution = self._runtime_resolution_status()
        runtime_paths = self._runtime_paths()
        return {
            "success": success,
            "dry_run": bool(self.args.dry_run),
            "tool_root": str(self.tool_root),
            "preflight_ok": bool(gcc_runtime_validation.get("ok")),
            "gcc_runtime_validation": gcc_runtime_validation,
            "paths": {
                "buildtools_dir": str(self.buildtools_dir),
                "sdk_dir": str(self.sdk_dir),
                "clangd_dir": str(self.clangd_dir),
                "llvm_dir": str(self.llvm_dir),
                "svf_dir": str(self.svf_dir),
                "goroot": str(self.goroot),
                "gopath": str(self.gopath),
                "gllvm_dir": str(self.gllvm_dir),
                "gcc_runtime_dir": str(self.gcc_runtime_dir),
                "zscope_source": str(self.zscope_source),
                "zscope_executable": self._zscope_executable(),
                "profile_path": str(self.profile_path),
            },
            "archives": self._archive_statuses(),
            "installed": self._installed_statuses(),
            "environment": runtime_status(),
            "runtime_paths": runtime_paths,
            "probes": probes,
            "symbol_versions": symbol_versions,
            "runtime_resolution": runtime_resolution,
            "status_ok": self._status_ok(probes, symbol_versions, runtime_resolution, gcc_runtime_validation),
            "steps": [step.__dict__ for step in self.steps],
            "warnings": self._warnings(),
        }

    def _ensure_supported_target(self) -> None:
        if platform.system().lower() != "linux":
            raise DeploymentError("C/C++ dependency deployment currently supports Linux targets only")

    def _ensure_runtime_versions(self) -> None:
        env = runtime_status()
        errors = []
        if not env["glibc_ok"]:
            errors.append(_glibc_error_message(env))
        if not env["python_ok"]:
            errors.append(
                f"Python 3.9 or newer is required, current version is {env['python_version']}. "
                "Please upgrade Python manually before running dependency deployment."
            )
        if errors:
            raise DeploymentError("; ".join(errors))

    def _ensure_root_or_dry_run(self) -> None:
        geteuid = getattr(os, "geteuid", None)
        if self.args.dry_run or geteuid is None:
            return
        if geteuid() != 0:
            raise DeploymentError("Please run as root; installation writes to /opt, /root/sdk and /etc/profile")

    def _prepare_tool_root(self) -> Path:
        if self._prepared_tool_root is not None:
            return self._prepared_tool_root
        if self.tool_root.is_dir():
            self._prepared_tool_root = self.tool_root
            return self._prepared_tool_root
        if not self.tool_root.is_file():
            raise DeploymentError(f"Tool root not found: {self.tool_root}")
        self._temp_dir = tempfile.TemporaryDirectory(prefix="zscope_tools_")
        temp_root = Path(self._temp_dir.name)
        extract_archive(self.tool_root, temp_root)
        self._prepared_tool_root = temp_root
        return self._prepared_tool_root

    def _archive_statuses(self) -> dict[str, dict[str, Any]]:
        try:
            root = self._prepare_tool_root()
        except DeploymentError:
            root = self.tool_root
        archive_names = [CLANGD_ARCHIVE, LLVM_ARCHIVE, SVF_ARCHIVE, Z3_ARCHIVE, GLLVM_ARCHIVE]
        result = {}
        for name in archive_names:
            match = find_file(root, name)
            result[name] = {"present": match is not None, "path": str(match) if match else ""}
        go_archive = find_go_archive(root)
        result["go_binary_archive"] = {
            "present": go_archive is not None,
            "path": str(go_archive) if go_archive else "",
            "required": False,
        }
        gcc_runtime = self._selected_gcc_runtime_source(root)
        result["gcc_runtime"] = {
            "present": gcc_runtime is not None and gcc_runtime.exists(),
            "path": str(gcc_runtime) if gcc_runtime else "",
            "required": True,
        }
        return result

    def _installed_statuses(self) -> dict[str, bool]:
        return {
            "clangd": path_exists(self.clangd_dir / "bin" / "clangd"),
            "llvm": path_exists(self.llvm_dir / "bin" / "llvm-link"),
            "svf": path_exists(self.svf_dir / "bin" / "wpa")
            or path_exists(self.svf_dir / "bin" / "saber"),
            "z3_for_svf": path_exists(self.svf_dir / "lib" / "libz3.so"),
            "go": bool(self._go_executable()),
            "gllvm": path_exists(self.gopath / "bin" / "gclang")
            or bool(shutil.which("gclang")),
            "gcc_runtime": bool(validate_gcc_runtime_source(self.gcc_runtime_dir, runtime_status()).get("ok")),
            "zscope": bool(self._zscope_executable()),
            "profile_block": self._profile_has_block(),
        }

    def _warnings(self) -> list[str]:
        warnings: list[str] = []
        if str(self.buildtools_dir) != "/opt/buildtools":
            warnings.append("Custom buildtools_dir is used; /etc/profile block still follows configured paths.")
        if str(self.sdk_dir) != "/root/sdk":
            warnings.append("Custom sdk_dir is used; ensure runtime users source the generated profile block.")
        return warnings

    def _install_clangd(self) -> None:
        if self._skip_if_installed("install_clangd", self.clangd_dir, ("bin/clangd",)):
            return
        archive = self._require_archive(CLANGD_ARCHIVE)
        self._install_archive_root(
            step_name="install_clangd",
            archive=archive,
            target=self.clangd_dir,
            required_relative=("bin/clangd",),
        )

    def _install_llvm(self) -> None:
        if self._skip_if_installed("install_llvm", self.llvm_dir, ("bin/llvm-link", "bin/clang")):
            return
        archive = self._require_archive(LLVM_ARCHIVE)
        self._install_archive_root(
            step_name="install_llvm",
            archive=archive,
            target=self.llvm_dir,
            required_relative=("bin/llvm-link", "bin/clang"),
        )

    def _install_svf(self) -> None:
        if self._skip_if_installed("install_svf", self.svf_dir, ("bin/wpa", "bin/saber"), match_any=True):
            return
        archive = self._require_archive(SVF_ARCHIVE)
        self._install_archive_root(
            step_name="install_svf",
            archive=archive,
            target=self.svf_dir,
            required_relative=("bin/wpa", "bin/saber"),
            match_any=True,
        )

    def _install_z3(self) -> None:
        if path_exists(self.svf_dir / "lib" / "libz3.so") and not self.args.force:
            self._record("install_z3", "skipped", "Already installed", str(self.svf_dir / "lib" / "libz3.so"))
            return
        archive = self._require_archive(Z3_ARCHIVE)
        if self.args.dry_run:
            self._record("install_z3", "dry_run", f"Would copy libz3.so from {archive}", str(self.svf_dir / "lib"))
            return
        with tempfile.TemporaryDirectory(prefix="zscope_z3_") as tmp:
            temp_root = Path(tmp)
            extract_archive(archive, temp_root)
            libz3 = find_file(temp_root, "libz3.so")
            if not libz3:
                raise DeploymentError(f"libz3.so not found in {archive}")
            target_dir = self.svf_dir / "lib"
            target_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(libz3, target_dir / "libz3.so")
        self._record("install_z3", "ok", "Copied libz3.so into SVF lib directory", str(self.svf_dir / "lib" / "libz3.so"))

    def _install_gcc_runtime(self) -> None:
        existing_validation = validate_gcc_runtime_source(self.gcc_runtime_dir, runtime_status()) if self.gcc_runtime_dir.exists() else {"ok": False}
        if existing_validation.get("ok") and not self.args.force:
            self._record("install_gcc_runtime", "skipped", "Already installed and validated", str(self.gcc_runtime_dir))
            return
        source = self._selected_gcc_runtime_source(self._prepare_tool_root())
        if source is None:
            raise DeploymentError(
                "Required GCC runtime not found. Provide a directory or archive containing "
                "libstdc++.so.6 and libgcc_s.so.1 with --gcc-runtime-root, or place it under tool-root."
            )
        validation = validate_gcc_runtime_source(source, runtime_status())
        if not validation.get("ok"):
            raise DeploymentError("; ".join(validation.get("errors") or [f"Invalid GCC runtime: {source}"]))
        if self.args.dry_run:
            self._record("install_gcc_runtime", "dry_run", f"Would install GCC runtime from {source}", str(self.gcc_runtime_dir))
            return
        self.gcc_runtime_dir.parent.mkdir(parents=True, exist_ok=True)
        backup_dir: Path | None = None
        with tempfile.TemporaryDirectory(prefix=f".{self.gcc_runtime_dir.name}.staging.", dir=str(self.gcc_runtime_dir.parent)) as staging_parent_s:
            staging_parent = Path(staging_parent_s)
            staging_dir = staging_parent / self.gcc_runtime_dir.name
            copy_gcc_runtime_source(source, staging_dir)
            staging_validation = validate_gcc_runtime_source(staging_dir, runtime_status())
            if not staging_validation.get("ok"):
                raise DeploymentError("; ".join(staging_validation.get("errors") or [f"Invalid staged GCC runtime: {staging_dir}"]))
            try:
                if self.gcc_runtime_dir.exists():
                    backup_dir = self.gcc_runtime_dir.parent / f".{self.gcc_runtime_dir.name}.backup.{os.getpid()}"
                    if backup_dir.exists():
                        shutil.rmtree(backup_dir)
                    self.gcc_runtime_dir.rename(backup_dir)
                staging_dir.rename(self.gcc_runtime_dir)
            except Exception:
                if self.gcc_runtime_dir.exists():
                    shutil.rmtree(self.gcc_runtime_dir, ignore_errors=True)
                if backup_dir and backup_dir.exists():
                    backup_dir.rename(self.gcc_runtime_dir)
                raise
            else:
                if backup_dir and backup_dir.exists():
                    shutil.rmtree(backup_dir)
        self._record("install_gcc_runtime", "ok", f"Installed from {source}", str(self.gcc_runtime_dir))

    def _install_go(self) -> None:
        if self._go_executable():
            self._record("install_go", "skipped", "Go already available", str(self._go_executable()))
            return

        go_archive = Path(self.args.go_archive).expanduser() if self.args.go_archive else None
        if go_archive and not go_archive.exists():
            raise DeploymentError(f"Go archive not found: {go_archive}")
        if not go_archive:
            go_archive = find_go_archive(self._prepare_tool_root())

        if go_archive:
            self._install_archive_root(
                step_name="install_go",
                archive=go_archive,
                target=self.goroot,
                required_relative=("bin/go",),
            )
            return

        if self.args.skip_system_package_manager:
            raise DeploymentError("Go is not installed and no Go binary archive was found")
        command = go_system_install_command(runtime_status())
        if not command:
            raise DeploymentError(
                "Go is not installed, no Go binary archive was found, and no supported "
                "system package manager was detected. Provide --go-archive or install Go manually."
            )
        self._run(command, step_name="install_go", env=self._tool_env())

    def _install_gllvm(self) -> None:
        if (path_exists(self.gopath / "bin" / "gclang") or shutil.which("gclang")) and not self.args.force:
            self._record("install_gllvm", "skipped", "Already installed", str(self.gopath / "bin" / "gclang"))
            return
        archive = self._require_archive(GLLVM_ARCHIVE)
        if self.args.dry_run:
            self._record("install_gllvm", "dry_run", f"Would install gllvm from {archive}", str(self.gllvm_dir))
            return
        self.gllvm_dir.parent.mkdir(parents=True, exist_ok=True)
        if self.gllvm_dir.exists() and self.args.force:
            shutil.rmtree(self.gllvm_dir)
        if not self.gllvm_dir.exists():
            with tempfile.TemporaryDirectory(prefix="zscope_gllvm_") as tmp:
                temp_root = Path(tmp)
                extract_archive(archive, temp_root)
                source_root = choose_root(temp_root, ("README.md",), match_any=True)
                if not source_root:
                    entries = [path for path in temp_root.iterdir()]
                    source_root = entries[0] if len(entries) == 1 and entries[0].is_dir() else temp_root
                shutil.copytree(source_root, self.gllvm_dir)

        self.gopath.mkdir(parents=True, exist_ok=True)
        env = self._tool_env()
        if (self.gllvm_dir / "Makefile").exists():
            self._run(["make", "install"], cwd=self.gllvm_dir, step_name="install_gllvm", env=env)
            return
        if (self.gllvm_dir / "cmd").exists():
            self._run(["go", "install", "./cmd/..."], cwd=self.gllvm_dir, step_name="install_gllvm", env=env)
            return
        env["GO111MODULE"] = env.get("GO111MODULE", "off")
        self._run(["go", "install", "./..."], cwd=self.gllvm_dir, step_name="install_gllvm", env=env)

    def _install_zscope(self) -> None:
        existing = self._zscope_executable()
        if existing and not self.args.force:
            self._record("install_zscope", "skipped", "Already installed", existing)
            return
        if not (self.zscope_source / "pyproject.toml").exists():
            raise DeploymentError(f"Z-SCOPE source not found or invalid: {self.zscope_source}")
        self._run(
            [sys.executable, "-m", "pip", "install", "-e", str(self.zscope_source)],
            step_name="install_zscope",
            cwd=self.zscope_source,
            env=pip_env_with_index_trusted_host(),
        )

    def _write_profile_block(self) -> None:
        block = self._profile_block_for_paths()
        if self.args.dry_run:
            self._record("write_profile", "dry_run", "Would update profile environment block", str(self.profile_path))
            return
        self.profile_path.parent.mkdir(parents=True, exist_ok=True)
        existing = self.profile_path.read_text(encoding="utf-8") if self.profile_path.exists() else ""
        if PROFILE_BLOCK_MARKER_START in existing and PROFILE_BLOCK_MARKER_END in existing:
            before, rest = existing.split(PROFILE_BLOCK_MARKER_START, 1)
            _, after = rest.split(PROFILE_BLOCK_MARKER_END, 1)
            updated = before.rstrip() + "\n" + block + after.lstrip("\n")
        else:
            updated = existing.rstrip() + "\n\n" + block
        self.profile_path.write_text(updated, encoding="utf-8")
        self._record("write_profile", "ok", "Updated profile environment block", str(self.profile_path))

    def _profile_block_for_paths(self) -> str:
        go_lines = []
        go_path_entries = []
        if self._bundled_go_executable():
            go_lines.append(f"export GOROOT={self.goroot}")
            go_path_entries.append("$GOROOT/bin")
        go_lines.append(f"export GOPATH={self.gopath}")
        go_path_entries.append("$GOPATH/bin")
        go_block = "\n".join(go_lines)
        go_path = ":".join(go_path_entries)
        return f"""{PROFILE_BLOCK_MARKER_START}
export PATH={self.clangd_dir}/bin:$PATH
export LLVM_DIR={self.llvm_dir}
export PATH=$LLVM_DIR/bin:$PATH
export SVF_DIR={self.svf_dir}
export PATH=$SVF_DIR/bin:$PATH
export GCC_RUNTIME_DIR={self.gcc_runtime_dir}
export LD_LIBRARY_PATH=$SVF_DIR/lib:$GCC_RUNTIME_DIR/lib64:$GCC_RUNTIME_DIR/lib:$LLVM_DIR/lib:$LD_LIBRARY_PATH
export LLVM_COMPILER_PATH=$LLVM_DIR/bin
{go_block}
export PATH={go_path}:$PATH
{PROFILE_BLOCK_MARKER_END}
"""

    def _source_profile_once(self) -> None:
        if self.args.dry_run:
            self._record("source_profile", "dry_run", "Would source profile environment block", str(self.profile_path))
            return
        if not self.profile_path.exists():
            raise DeploymentError(f"Profile path does not exist: {self.profile_path}")
        self._run(
            ["bash", "-lc", f"source {shlex.quote(str(self.profile_path))} >/dev/null"],
            step_name="source_profile",
        )

    def _install_archive_root(
        self,
        *,
        step_name: str,
        archive: Path,
        target: Path,
        required_relative: Sequence[str],
        match_any: bool = False,
    ) -> None:
        if target.exists() and not self.args.force and has_required(target, required_relative, match_any=match_any):
            self._record(step_name, "skipped", "Already installed", str(target))
            return
        if self.args.dry_run:
            self._record(step_name, "dry_run", f"Would extract {archive} to {target}", str(target))
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            shutil.rmtree(target)
        with tempfile.TemporaryDirectory(prefix=f"zscope_{step_name}_") as tmp:
            temp_root = Path(tmp)
            extract_archive(archive, temp_root)
            source_root = choose_root(temp_root, required_relative, match_any=match_any)
            if not source_root:
                raise DeploymentError(f"Unable to locate expected files in {archive}: {required_relative}")
            shutil.copytree(source_root, target, symlinks=True)
        self._restore_tool_permissions()
        self._record(step_name, "ok", f"Installed from {archive.name}", str(target))

    def _skip_if_installed(
        self,
        step_name: str,
        target: Path,
        required_relative: Sequence[str],
        *,
        match_any: bool = False,
    ) -> bool:
        if target.exists() and not self.args.force and has_required(target, required_relative, match_any=match_any):
            self._record(step_name, "skipped", "Already installed", str(target))
            return True
        return False

    def _run(
        self,
        cmd: Sequence[str],
        *,
        step_name: str,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        printable = " ".join(cmd)
        if self.args.dry_run:
            self._record(step_name, "dry_run", f"Would run: {printable}", str(cwd or ""))
            return
        completed = subprocess.run(
            list(cmd),
            cwd=str(cwd) if cwd else None,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or "").strip()
            raise DeploymentError(f"{printable} failed with code {completed.returncode}: {message}")
        self._record(step_name, "ok", (completed.stdout or "").strip() or f"Ran: {printable}", str(cwd or ""))

    def _tool_env(self) -> dict[str, str]:
        env = os.environ.copy()
        go_path = self._go_bin_dir()
        if self._bundled_go_executable():
            env["GOROOT"] = str(self.goroot)
        else:
            env.pop("GOROOT", None)
        env.update(
            {
                "LLVM_DIR": str(self.llvm_dir),
                "SVF_DIR": str(self.svf_dir),
                "LLVM_COMPILER_PATH": str(self.llvm_dir / "bin"),
                "GOPATH": str(self.gopath),
                "LD_LIBRARY_PATH": prepend_path(
                    join_paths(
                        [
                            str(self.svf_dir / "lib"),
                            str(self.gcc_runtime_dir / "lib64"),
                            str(self.gcc_runtime_dir / "lib"),
                            str(self.llvm_dir / "lib"),
                        ]
                    ),
                    env.get("LD_LIBRARY_PATH", ""),
                ),
                "PATH": join_paths(
                    [
                        go_path,
                        str(self.gopath / "bin"),
                        str(self.llvm_dir / "bin"),
                        str(self.svf_dir / "bin"),
                        str(self.clangd_dir / "bin"),
                        env.get("PATH", ""),
                    ]
                ),
            }
        )
        return env

    def _runtime_paths(self) -> dict[str, str]:
        ld_library_path = prepend_path(
            join_paths(
                [
                    str(self.svf_dir / "lib"),
                    str(self.gcc_runtime_dir / "lib64"),
                    str(self.gcc_runtime_dir / "lib"),
                    str(self.llvm_dir / "lib"),
                ]
            ),
            os.environ.get("LD_LIBRARY_PATH", ""),
        )
        return {
            "gcc_runtime_dir": str(self.gcc_runtime_dir),
            "gcc_runtime_lib64": str(self.gcc_runtime_dir / "lib64"),
            "gcc_runtime_lib": str(self.gcc_runtime_dir / "lib"),
            "svf_lib": str(self.svf_dir / "lib"),
            "llvm_lib": str(self.llvm_dir / "lib"),
            "ld_library_path": ld_library_path,
        }

    def _restore_tool_permissions(self) -> None:
        for path in (
            self.clangd_dir / "bin" / "clangd",
            self.llvm_dir / "bin" / "llvm-link",
            self.llvm_dir / "bin" / "clang",
            self.svf_dir / "bin" / "wpa",
            self.svf_dir / "bin" / "saber",
            self.goroot / "bin" / "go",
            self.gopath / "bin" / "gclang",
        ):
            make_executable(path)

    def _probe_statuses(self) -> dict[str, dict[str, Any]]:
        env = self._tool_env()
        probes = {
            "clangd": [str(self.clangd_dir / "bin" / "clangd"), "--version"],
            "clang": [str(self.llvm_dir / "bin" / "clang"), "--version"],
            "llvm-link": [str(self.llvm_dir / "bin" / "llvm-link"), "--version"],
            "wpa": [str(self.svf_dir / "bin" / "wpa"), "-h"],
            "saber": [str(self.svf_dir / "bin" / "saber"), "-h"],
            "go": [self._go_executable() or str(self.goroot / "bin" / "go"), "version"],
            "gclang": [str(self.gopath / "bin" / "gclang"), "--version"],
            "zscope": [self._zscope_executable() or "zscope", "--help"],
        }
        return {name: run_probe(cmd, env=env) for name, cmd in probes.items()}

    def _symbol_version_status(self) -> dict[str, Any]:
        executable_paths = [
            self.clangd_dir / "bin" / "clangd",
            self.llvm_dir / "bin" / "clang",
            self.llvm_dir / "bin" / "llvm-link",
            self.svf_dir / "bin" / "wpa",
            self.svf_dir / "bin" / "saber",
        ]
        shared_library_paths = self._shared_library_paths()
        runtime_paths: list[Path] = []
        if self.gcc_runtime_dir.exists():
            runtime_paths.extend(self.gcc_runtime_dir.rglob("libstdc++.so*"))
            runtime_paths.extend(self.gcc_runtime_dir.rglob("libgcc_s.so*"))
        executable_versions = max_symbol_versions(executable_paths)
        shared_library_versions = max_symbol_versions(shared_library_paths)
        combined_required = combine_symbol_versions(executable_versions, shared_library_versions)
        runtime_versions = max_symbol_versions(runtime_paths)
        env = runtime_status()
        errors: list[str] = []
        if version_gt(combined_required.get("GLIBC", ""), env.get("glibc_version", "")):
            errors.append(
                f"toolchain requires GLIBC_{combined_required.get('GLIBC')}, current glibc is {env.get('glibc_version') or 'unknown'}"
            )
        for family in ("GLIBCXX", "CXXABI"):
            required = combined_required.get(family, "")
            provided = runtime_versions.get(family, "")
            if required and (not provided or version_gt(required, provided)):
                errors.append(f"tool requires {family}_{required}, GCC runtime provides {family}_{provided or 'none'}")
        return {
            "executables": executable_versions,
            "shared_libraries": shared_library_versions,
            "combined_required": combined_required,
            "gcc_runtime_provided": runtime_versions,
            "ok": not errors,
            "errors": errors,
        }

    def _shared_library_paths(self) -> list[Path]:
        paths: list[Path] = []
        for directory in (self.llvm_dir / "lib", self.svf_dir / "lib"):
            if directory.exists():
                paths.extend(sorted(path for path in directory.glob("*.so*") if path.is_file() or path.is_symlink()))
        libz3 = self.svf_dir / "lib" / "libz3.so"
        if libz3.exists() and libz3 not in paths:
            paths.append(libz3)
        return paths

    def _runtime_resolution_status(self) -> dict[str, dict[str, Any]]:
        env = self._tool_env()
        targets = {
            "clang": self.llvm_dir / "bin" / "clang",
            "wpa": self.svf_dir / "bin" / "wpa",
            "saber": self.svf_dir / "bin" / "saber",
        }
        return {
            name: self._runtime_resolution_for_tool(path, env)
            for name, path in targets.items()
        }

    def _runtime_resolution_for_tool(self, path: Path, env: dict[str, str]) -> dict[str, Any]:
        result: dict[str, Any] = {
            "command": [str(path)],
            "libstdc++.so.6": "",
            "libgcc_s.so.1": "",
            "ok": False,
            "errors": [],
        }
        if not path.exists():
            result["ok"] = True
            result["skipped"] = True
            result["errors"].append(f"not found: {path}")
            return result
        resolved = resolve_dynamic_libraries(path, env=env)
        result["libstdc++.so.6"] = resolved.get("libstdc++.so.6", "")
        result["libgcc_s.so.1"] = resolved.get("libgcc_s.so.1", "")
        errors = []
        for lib in ("libstdc++.so.6", "libgcc_s.so.1"):
            lib_path = result.get(lib, "")
            if not lib_path:
                errors.append(f"{lib} was not resolved")
                continue
            if not path_is_under(Path(lib_path), self.gcc_runtime_dir):
                errors.append(f"{lib} resolved outside isolated GCC runtime: {lib_path}")
        result["errors"] = errors
        result["ok"] = not errors
        return result

    def _status_ok(
        self,
        probes: dict[str, dict[str, Any]],
        symbol_versions: dict[str, Any],
        runtime_resolution: dict[str, dict[str, Any]],
        gcc_runtime_validation: dict[str, Any],
    ) -> bool:
        return (
            all(item.get("ok") for item in probes.values())
            and bool(symbol_versions.get("ok"))
            and bool(gcc_runtime_validation.get("ok"))
            and all(item.get("ok") for item in runtime_resolution.values())
        )

    def _ensure_status_ok(self, payload: dict[str, Any]) -> None:
        if payload.get("status_ok"):
            return
        failures = [name for name, item in payload.get("probes", {}).items() if not item.get("ok")]
        errors = list((payload.get("symbol_versions") or {}).get("errors") or [])
        errors.extend((payload.get("gcc_runtime_validation") or {}).get("errors") or [])
        for name, item in (payload.get("runtime_resolution") or {}).items():
            if not item.get("ok"):
                for error in item.get("errors", []):
                    errors.append(f"{name}: {error}")
        parts = [f"failed probes: {', '.join(failures)}"] if failures else []
        parts.extend(errors)
        detail = "; ".join(parts)
        raise DeploymentError(detail or "deployment status check failed")

    def _gcc_runtime_validation(self) -> dict[str, Any]:
        source = self._selected_gcc_runtime_source(self._prepared_tool_root or self.tool_root)
        if source is None and self.gcc_runtime_dir.exists():
            source = self.gcc_runtime_dir
        return validate_gcc_runtime_source(source, runtime_status())

    def _selected_gcc_runtime_source(self, root: Path | None = None) -> Path | None:
        if self.gcc_runtime_root:
            return self.gcc_runtime_root
        search_root = root or self._prepare_tool_root()
        if search_root.exists() and search_root.is_dir():
            exact = find_file(search_root, GCC_RUNTIME_ARCHIVE)
            if exact:
                return exact
            layout_root = find_gcc_runtime_layout_root(search_root)
            if layout_root:
                return layout_root
            for path in sorted(item for item in search_root.rglob("*") if item.is_dir()):
                layout_root = find_gcc_runtime_layout_root(path)
                if layout_root:
                    return layout_root
        return self._find_gcc_runtime_source(search_root)

    def _find_gcc_runtime_source(self, root: Path) -> Path | None:
        if not root.exists():
            return None
        if root.is_dir():
            layout_root = find_gcc_runtime_layout_root(root)
            if layout_root:
                return layout_root
        if root.is_file() and is_archive(root) and is_gcc_runtime_archive_candidate(root):
            try:
                with tempfile.TemporaryDirectory(prefix="zscope_gcc_probe_") as tmp:
                    temp_root = Path(tmp)
                    extract_archive(root, temp_root)
                    if find_gcc_runtime_layout_root(temp_root):
                        return root
            except (DeploymentError, OSError, zipfile.BadZipFile, tarfile.TarError):
                return None
        if root.is_dir():
            for path in sorted(item for item in root.rglob("*") if item.is_dir()):
                if find_gcc_runtime_layout_root(path):
                    return path
            for path in sorted(
                item
                for item in root.rglob("*")
                if item.is_file() and is_archive(item) and is_gcc_runtime_archive_candidate(item)
            ):
                found = self._find_gcc_runtime_source(path)
                if found:
                    return found
        return None

    def _go_executable(self) -> str:
        return self._bundled_go_executable() or shutil.which("go") or ""

    def _bundled_go_executable(self) -> str:
        bundled_go = self.goroot / "bin" / "go"
        if path_exists(bundled_go):
            return str(bundled_go)
        return ""

    def _go_bin_dir(self) -> str:
        bundled_go = self._bundled_go_executable()
        if bundled_go:
            return str(Path(bundled_go).parent)
        system_go = shutil.which("go")
        return str(Path(system_go).parent) if system_go else ""

    def _zscope_executable(self) -> str:
        return shutil.which("zscope") or ""

    def _profile_has_block(self) -> bool:
        try:
            content = self.profile_path.read_text(encoding="utf-8")
        except OSError:
            return False
        return PROFILE_BLOCK_MARKER_START in content and PROFILE_BLOCK_MARKER_END in content

    def _require_archive(self, name: str) -> Path:
        archive = find_file(self._prepare_tool_root(), name)
        if not archive:
            raise DeploymentError(f"Required archive not found under {self.tool_root}: {name}")
        return archive

    def _record(self, name: str, status: str, message: str = "", path: str = "") -> None:
        self.steps.append(StepResult(name=name, status=status, message=message, path=path))


def extract_archive(archive: Path, target_dir: Path) -> None:
    suffixes = "".join(archive.suffixes).lower()
    if suffixes.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            extract_zip_safely(zf, target_dir)
        return
    if suffixes.endswith(".tar.gz") or suffixes.endswith(".tgz"):
        with tarfile.open(archive, "r:gz") as tf:
            extract_tar_safely(tf, target_dir)
        return
    if suffixes.endswith(".tar"):
        with tarfile.open(archive, "r:") as tf:
            extract_tar_safely(tf, target_dir)
        return
    raise DeploymentError(f"Unsupported archive type: {archive}")


def extract_zip_safely(zf: zipfile.ZipFile, target_dir: Path) -> None:
    for info in zf.infolist():
        if not info.filename or info.filename.endswith("/"):
            safe_destination(target_dir, info.filename).mkdir(parents=True, exist_ok=True)
            continue
        dest = safe_destination(target_dir, info.filename)
        mode = (info.external_attr >> 16) & 0o777777
        dest.parent.mkdir(parents=True, exist_ok=True)
        if stat.S_ISLNK(mode):
            link_target = zf.read(info).decode("utf-8")
            validate_link_target(target_dir, dest, link_target)
            if dest.exists() or dest.is_symlink():
                dest.unlink()
            os.symlink(link_target, dest)
            continue
        with zf.open(info) as src, dest.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        if mode:
            dest.chmod(mode & 0o777)


def extract_tar_safely(tf: tarfile.TarFile, target_dir: Path) -> None:
    for member in tf.getmembers():
        safe_destination(target_dir, member.name)
        if member.issym() or member.islnk():
            validate_link_target(target_dir, target_dir / member.name, member.linkname)
    tf.extractall(target_dir)


def safe_destination(target_dir: Path, name: str) -> Path:
    candidate = target_dir / name
    resolved_target = target_dir.resolve()
    resolved_candidate = candidate.resolve(strict=False)
    if Path(name).is_absolute() or ".." in Path(name).parts or not is_relative_to(resolved_candidate, resolved_target):
        raise DeploymentError(f"Unsafe archive member path: {name}")
    return candidate


def validate_link_target(target_dir: Path, link_path: Path, link_target: str) -> None:
    if Path(link_target).is_absolute():
        raise DeploymentError(f"Unsafe absolute symlink target in archive: {link_target}")
    resolved = (link_path.parent / link_target).resolve(strict=False)
    if not is_relative_to(resolved, target_dir.resolve()):
        raise DeploymentError(f"Unsafe symlink target in archive: {link_target}")


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def is_archive(path: Path) -> bool:
    suffixes = "".join(path.suffixes).lower()
    return suffixes.endswith((".zip", ".tar.gz", ".tgz", ".tar"))


def is_gcc_runtime_archive_candidate(path: Path) -> bool:
    name = path.name.lower()
    return any(token in name for token in ("gcc", "runtime", "libstdc", "libgcc"))


def choose_root(
    root: Path,
    required_relative: Sequence[str],
    *,
    match_any: bool = False,
    recursive: bool = False,
) -> Path | None:
    candidates = [root] + [path for path in root.rglob("*") if path.is_dir()]
    for candidate in candidates:
        if has_required(candidate, required_relative, match_any=match_any, recursive=recursive):
            return candidate
    return None


def has_required(
    root: Path,
    required_relative: Sequence[str],
    *,
    match_any: bool = False,
    recursive: bool = False,
) -> bool:
    if recursive:
        checks = [find_file(root, item) is not None for item in required_relative]
    else:
        checks = [(root / item).exists() for item in required_relative]
    return any(checks) if match_any else all(checks)


def find_file(root: Path, name: str) -> Path | None:
    if root.is_file() and root.name == name:
        return root
    if not root.exists() or not root.is_dir():
        return None
    direct = root / name
    if direct.exists():
        return direct
    matches = sorted(path for path in root.rglob(name) if path.is_file())
    return matches[0] if matches else None


def find_go_archive(root: Path) -> Path | None:
    if not root.exists() or not root.is_dir():
        return None
    patterns = ("go*.linux-amd64.tar.gz", "golang_go*.tar.gz", "go*.tar.gz")
    for pattern in patterns:
        matches = sorted(path for path in root.rglob(pattern) if path.is_file())
        if matches:
            return matches[0]
    return None


def find_gcc_runtime_layout_root(root: Path) -> Path | None:
    roots = find_gcc_runtime_layout_roots(root)
    return roots[0] if roots else None


def find_gcc_runtime_layout_roots(root: Path) -> list[Path]:
    if not root.exists() or not root.is_dir():
        return []
    found: dict[str, Path] = {}
    candidates = [root] + [path for path in root.rglob("*") if path.is_dir()]
    for candidate in sorted(candidates, key=lambda path: len(path.parts), reverse=True):
        if (candidate / "libstdc++.so.6").exists() and (candidate / "libgcc_s.so.1").exists():
            layout = candidate.parent if candidate.name in {"lib", "lib64"} else candidate
            found[str(layout.resolve(strict=False))] = layout
        for lib_dir in ("lib64", "lib"):
            if (candidate / lib_dir / "libstdc++.so.6").exists() and (candidate / lib_dir / "libgcc_s.so.1").exists():
                found[str(candidate.resolve(strict=False))] = candidate
    return sorted(found.values())


def copy_gcc_runtime_source(source: Path, target: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    with tempfile.TemporaryDirectory(prefix="zscope_gcc_runtime_copy_") as tmp:
        temp_root = Path(tmp)
        source_root: Path | None
        if source.is_file():
            extract_archive(source, temp_root)
            roots = find_gcc_runtime_layout_roots(temp_root)
            source_root = roots[0] if len(roots) == 1 else None
        else:
            roots = find_gcc_runtime_layout_roots(source)
            source_root = roots[0] if len(roots) == 1 else None
        if not source_root:
            raise DeploymentError(f"Unable to locate a unique GCC runtime layout in {source}")
        shutil.copytree(source_root, target, symlinks=True)


def validate_gcc_runtime_source(source: Path | None, env: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "source": str(source) if source else "",
        "layout_root": "",
        "architecture": "",
        "libstdcxx": {},
        "libgcc_s": {},
        "missing_gcc_versions": [],
        "ok": False,
        "errors": [],
    }
    errors: list[str] = []
    if source is None:
        errors.append(
            "Required isolated GCC runtime not found before installing C/C++ tools. "
            "Place gcc-13-runtime-linux-x86_64.tar.gz under tool-root, or pass --gcc-runtime-root."
        )
        payload["errors"] = errors
        return payload
    if not source.exists():
        errors.append(f"GCC runtime source not found: {source}")
        payload["errors"] = errors
        return payload

    with tempfile.TemporaryDirectory(prefix="zscope_gcc_validate_") as tmp:
        temp_root = Path(tmp)
        root = source
        anchor = source
        try:
            if source.is_file():
                extract_archive(source, temp_root)
                root = temp_root
                anchor = temp_root
        except (DeploymentError, OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
            errors.append(f"GCC runtime archive cannot be safely extracted: {exc}")
            payload["errors"] = errors
            return payload

        roots = find_gcc_runtime_layout_roots(root)
        if len(roots) != 1:
            if not roots:
                errors.append("Unable to locate GCC runtime layout containing libstdc++.so.6 and libgcc_s.so.1")
            else:
                errors.append(f"Multiple GCC runtime layout roots found: {', '.join(str(path) for path in roots)}")
            payload["errors"] = errors
            return payload

        layout_root = roots[0]
        payload["layout_root"] = relative_or_absolute(layout_root, anchor)
        libstdcxx = locate_runtime_lib(layout_root, "libstdc++.so.6")
        libgcc = locate_runtime_lib(layout_root, "libgcc_s.so.1")
        if not libstdcxx:
            errors.append("libstdc++.so.6 not found in GCC runtime")
        if not libgcc:
            errors.append("libgcc_s.so.1 not found in GCC runtime")
        if errors:
            payload["errors"] = errors
            return payload

        assert libstdcxx is not None
        assert libgcc is not None
        resolved_libstdcxx = validate_runtime_symlink(layout_root, libstdcxx, errors)
        resolved_libgcc = validate_runtime_symlink(layout_root, libgcc, errors)
        if not is_x86_64_elf_shared_object(resolved_libstdcxx):
            errors.append(f"{relative_or_absolute(libstdcxx, layout_root)} is not an x86-64 ELF shared object")
        if not is_x86_64_elf_shared_object(resolved_libgcc):
            errors.append(f"{relative_or_absolute(libgcc, layout_root)} is not an x86-64 ELF shared object")

        libstdcxx_versions = max_symbol_versions([resolved_libstdcxx])
        libgcc_versions = max_symbol_versions([resolved_libgcc])
        libstdcxx_gcc_required = gcc_symbol_versions(resolved_libstdcxx)
        libgcc_gcc_provided = gcc_symbol_versions(resolved_libgcc)
        missing_gcc_versions = sorted(libstdcxx_gcc_required - libgcc_gcc_provided, key=version_tuple)

        max_glibcxx = libstdcxx_versions.get("GLIBCXX", "")
        max_cxxabi = libstdcxx_versions.get("CXXABI", "")
        libstdcxx_glibc = libstdcxx_versions.get("GLIBC", "")
        libgcc_glibc = libgcc_versions.get("GLIBC", "")
        current_glibc = env.get("glibc_version", "")
        if version_gt(MIN_GLIBCXX_VERSION, max_glibcxx):
            errors.append(f"libstdc++.so.6 must provide GLIBCXX_{MIN_GLIBCXX_VERSION}, found GLIBCXX_{max_glibcxx or 'none'}")
        if version_gt(MIN_CXXABI_VERSION, max_cxxabi):
            errors.append(f"libstdc++.so.6 must provide CXXABI_{MIN_CXXABI_VERSION}, found CXXABI_{max_cxxabi or 'none'}")
        if version_gt(libstdcxx_glibc, current_glibc):
            errors.append(f"libstdc++.so.6 requires GLIBC_{libstdcxx_glibc}, current glibc is {current_glibc or 'unknown'}")
        if version_gt(libgcc_glibc, current_glibc):
            errors.append(f"libgcc_s.so.1 requires GLIBC_{libgcc_glibc}, current glibc is {current_glibc or 'unknown'}")
        if missing_gcc_versions:
            errors.append(f"libgcc_s.so.1 does not provide required GCC versions: {', '.join(missing_gcc_versions)}")

        payload.update(
            {
                "architecture": "x86_64" if not errors else "",
                "libstdcxx": {
                    "path": relative_or_absolute(libstdcxx, layout_root),
                    "resolved_path": relative_or_absolute(resolved_libstdcxx, layout_root),
                    "max_glibcxx": max_glibcxx,
                    "max_cxxabi": max_cxxabi,
                    "max_required_glibc": libstdcxx_glibc,
                },
                "libgcc_s": {
                    "path": relative_or_absolute(libgcc, layout_root),
                    "resolved_path": relative_or_absolute(resolved_libgcc, layout_root),
                    "max_required_glibc": libgcc_glibc,
                },
                "missing_gcc_versions": missing_gcc_versions,
                "ok": not errors,
                "errors": errors,
            }
        )
        return payload


def locate_runtime_lib(layout_root: Path, name: str) -> Path | None:
    for candidate in (
        layout_root / "lib64" / name,
        layout_root / "lib" / name,
        layout_root / name,
    ):
        if candidate.exists() or candidate.is_symlink():
            return candidate
    return find_file(layout_root, name)


def validate_runtime_symlink(layout_root: Path, path: Path, errors: list[str]) -> Path:
    if not path.is_symlink():
        return path
    resolved = path.resolve(strict=False)
    if not resolved.exists():
        errors.append(f"Symlink target does not exist: {relative_or_absolute(path, layout_root)} -> {os.readlink(path)}")
        return resolved
    if not is_relative_to(resolved, layout_root.resolve(strict=False)):
        errors.append(f"Symlink target escapes GCC runtime layout: {relative_or_absolute(path, layout_root)} -> {os.readlink(path)}")
    return resolved


def relative_or_absolute(path: Path, parent: Path) -> str:
    try:
        return str(path.relative_to(parent))
    except ValueError:
        return str(path)


def is_x86_64_elf_shared_object(path: Path) -> bool:
    try:
        data = path.read_bytes()[:64]
    except OSError:
        return False
    if len(data) < 20 or data[:4] != b"\x7fELF" or data[4] != 2:
        return False
    endian = "little" if data[5] == 1 else "big"
    machine = int.from_bytes(data[18:20], endian)
    return machine == ELF_MACHINE_X86_64


def path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def make_executable(path: Path) -> None:
    try:
        if path.exists():
            path.chmod(path.stat().st_mode | 0o111)
    except OSError:
        return


def run_probe(cmd: Sequence[str], *, env: dict[str, str] | None = None) -> dict[str, Any]:
    executable = cmd[0] if cmd else ""
    result = {
        "command": list(cmd),
        "returncode": None,
        "ok": False,
        "stdout": "",
        "stderr": "",
    }
    if not executable or not shutil.which(executable) and not Path(executable).exists():
        result["stderr"] = f"not found: {executable}"
        return result
    try:
        completed = subprocess.run(
            list(cmd),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["stderr"] = str(exc)
        return result
    result.update(
        {
            "returncode": completed.returncode,
            "ok": completed.returncode == 0,
            "stdout": trim_probe_output(completed.stdout),
            "stderr": trim_probe_output(completed.stderr),
        }
    )
    return result


def trim_probe_output(value: str, limit: int = 2000) -> str:
    text = (value or "").strip()
    return text[:limit]


SYMBOL_VERSION_RE = re.compile(rb"\b(GLIBCXX|GLIBC|CXXABI)_([0-9]+(?:\.[0-9]+)*)")
GCC_SYMBOL_VERSION_RE = re.compile(rb"\bGCC_([0-9]+(?:\.[0-9]+)*)")
LDD_RESOLUTION_RE = re.compile(r"^\s*(\S+)\s+=>\s+(\S+)\s+\(")


def max_symbol_versions(paths: Iterable[Path]) -> dict[str, str]:
    versions = {"GLIBC": "", "GLIBCXX": "", "CXXABI": ""}
    for path in paths:
        try:
            if not path.exists() or path.is_dir():
                continue
            data = path.read_bytes()
        except OSError:
            continue
        for family_b, version_b in SYMBOL_VERSION_RE.findall(data):
            family = family_b.decode("ascii")
            version = version_b.decode("ascii")
            if version_gt(version, versions.get(family, "")):
                versions[family] = version
    return versions


def gcc_symbol_versions(path: Path) -> set[str]:
    try:
        if not path.exists() or path.is_dir():
            return set()
        data = path.read_bytes()
    except OSError:
        return set()
    return {version_b.decode("ascii") for version_b in GCC_SYMBOL_VERSION_RE.findall(data)}


def combine_symbol_versions(*items: dict[str, str]) -> dict[str, str]:
    combined = {"GLIBC": "", "GLIBCXX": "", "CXXABI": ""}
    for item in items:
        for family, version in item.items():
            if version_gt(version, combined.get(family, "")):
                combined[family] = version
    return combined


def resolve_dynamic_libraries(path: Path, *, env: dict[str, str] | None = None) -> dict[str, str]:
    try:
        completed = subprocess.run(
            ["ldd", str(path)],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    resolved: dict[str, str] = {}
    for line in (completed.stdout or "").splitlines():
        match = LDD_RESOLUTION_RE.match(line)
        if match:
            resolved[match.group(1)] = match.group(2)
    return resolved


def path_is_under(path: Path, parent: Path) -> bool:
    try:
        return is_relative_to(path.resolve(strict=False), parent.resolve(strict=False))
    except OSError:
        return False


def version_gt(left: str, right: str) -> bool:
    if not left:
        return False
    if not right:
        return True
    return version_tuple(left) > version_tuple(right)


def version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value))


def runtime_status() -> dict[str, Any]:
    libc_name, libc_version = platform.libc_ver()
    python_version = ".".join(str(part) for part in sys.version_info[:3])
    os_info = os_release_status()
    os_id = str(os_info.get("os_id") or "").lower()
    os_id_like = str(os_info.get("os_id_like") or "").lower()
    package_manager = detect_system_package_manager(os_info)
    return {
        **os_info,
        "glibc_name": libc_name,
        "glibc_version": libc_version,
        "glibc_required": "2.38",
        "glibc_ok": libc_name == "glibc" and parse_version(libc_version) >= MIN_GLIBC_VERSION,
        "python_version": python_version,
        "python_required": ">=3.9",
        "python_ok": tuple(sys.version_info[:2]) >= MIN_PYTHON_VERSION,
        "is_euleros": os_id in {"euleros", "openeuler"} or "euler" in os_id_like,
        "system_package_manager": package_manager,
    }


def _glibc_error_message(env: dict[str, Any]) -> str:
    current = env.get("glibc_version") or "unknown"
    if env.get("is_sles12_sp5"):
        return (
            f"SLES 12 SP5 requires glibc 2.38 or newer for the supplied Z-SCOPE toolchain, "
            f"current version is {current}. Please upgrade glibc from the internal SUSE source "
            "before running dependency deployment."
        )
    if env.get("is_euleros"):
        return (
            f"EulerOS requires glibc 2.38 or newer for the supplied Z-SCOPE toolchain, "
            f"current version is {current}. Please upgrade glibc from the internal EulerOS source "
            "before running dependency deployment."
        )
    return (
        f"glibc 2.38 or newer is required, current version is {current}. "
        "Please upgrade glibc manually before running dependency deployment."
    )


def os_release_status() -> dict[str, Any]:
    fields: dict[str, str] = {}
    for path in OS_RELEASE_PATHS:
        try:
            if path.exists():
                fields = parse_os_release(path.read_text(encoding="utf-8", errors="replace"))
                break
        except OSError:
            continue
    os_id = fields.get("ID", "")
    version_id = fields.get("VERSION_ID", "")
    return {
        "os_id": os_id,
        "os_id_like": fields.get("ID_LIKE", ""),
        "os_version_id": version_id,
        "os_pretty_name": fields.get("PRETTY_NAME", ""),
        "is_sles12_sp5": os_id.lower() in {"sles", "sle_hpc", "sles_sap"} and version_id.startswith("12.5"),
    }


def detect_system_package_manager(os_info: dict[str, Any] | None = None) -> str:
    os_info = os_info or {}
    os_id = str(os_info.get("os_id") or "").lower()
    os_id_like = str(os_info.get("os_id_like") or "").lower()
    preferred: list[str]
    if os_id in {"sles", "sle_hpc", "sles_sap", "opensuse", "opensuse-leap"} or "suse" in os_id_like:
        preferred = ["zypper", "dnf", "yum"]
    elif os_id in {"euleros", "openeuler"} or any(
        item in os_id_like for item in ("rhel", "fedora", "centos", "euler")
    ):
        preferred = ["dnf", "yum", "zypper"]
    else:
        preferred = ["zypper", "dnf", "yum"]
    for command in preferred:
        if shutil.which(command):
            return command
    return ""


def go_system_install_command(os_info: dict[str, Any] | None = None) -> list[str]:
    package_manager = detect_system_package_manager(os_info)
    if package_manager == "zypper":
        return ["zypper", "install", "-y", "go"]
    if package_manager in {"dnf", "yum"}:
        return [package_manager, "install", "-y", "golang"]
    return []


def parse_os_release(content: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        fields[key.strip()] = value
    return fields


def parse_version(value: str) -> tuple[int, int]:
    parts = []
    for item in value.split("."):
        if not item.isdigit():
            break
        parts.append(int(item))
    while len(parts) < 2:
        parts.append(0)
    return parts[0], parts[1]


def join_paths(parts: Iterable[str]) -> str:
    return os.pathsep.join(part for part in parts if part)


def prepend_path(prefix: str, existing: str) -> str:
    return join_paths([prefix, existing])


def pip_env_with_index_trusted_host(base_env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(base_env) if base_env is not None else os.environ.copy()
    host = pip_index_host(env.get("PIP_INDEX_URL", ""))
    if not host:
        return env
    trusted_hosts = split_trusted_hosts(env.get(PIP_TRUSTED_HOST_ENV, ""))
    if host not in trusted_hosts:
        trusted_hosts.append(host)
    env[PIP_TRUSTED_HOST_ENV] = " ".join(trusted_hosts)
    return env


def pip_index_host(index_url: str) -> str:
    parsed = urlparse(index_url.strip())
    return parsed.hostname or ""


def split_trusted_hosts(value: str) -> list[str]:
    return [part for part in re.split(r"[\s,]+", value.strip()) if part]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_tool_root() -> Path:
    return repo_root() / "tools" / "offline_dependencies"


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install Z-SCOPE C/C++ offline dependencies.")
    parser.add_argument(
        "--tool-root",
        default=str(default_tool_root()),
        help="Directory or bundle containing tool archives. Defaults to tools/offline_dependencies.",
    )
    parser.add_argument(
        "--zscope-source",
        default=str(repo_root()),
        help="Z-SCOPE source checkout to install with pip. Defaults to this repository.",
    )
    parser.add_argument("--buildtools-dir", default=str(DEFAULT_BUILDTOOLS_DIR))
    parser.add_argument("--sdk-dir", default=str(DEFAULT_SDK_DIR))
    parser.add_argument("--profile-path", default=str(DEFAULT_PROFILE_PATH))
    parser.add_argument("--go-archive", default="", help="Optional Go binary archive path.")
    parser.add_argument("--gcc-runtime-root", default="", help="Optional GCC runtime directory or archive containing libstdc++.so.6 and libgcc_s.so.1.")
    parser.add_argument("--gcc-runtime-dir", default=str(DEFAULT_BUILDTOOLS_DIR / DEFAULT_GCC_RUNTIME_DIR_NAME))
    parser.add_argument(
        "--skip-system-package-manager",
        dest="skip_system_package_manager",
        action="store_true",
        help="Do not use the system package manager to install Go.",
    )
    parser.add_argument(
        "--skip-zypper",
        dest="skip_system_package_manager",
        action="store_true",
        help="Deprecated alias for --skip-system-package-manager.",
    )
    parser.add_argument("--force", action="store_true", help="Replace existing installed tool directories.")
    parser.add_argument("--dry-run", action="store_true", help="Validate inputs and print planned steps only.")
    parser.add_argument("--status", action="store_true", help="Only report archive/install status.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    installer = Installer(args)
    try:
        payload = installer.status_payload() if args.status else installer.run()
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print_human(payload)
        if args.status and not payload.get("status_ok"):
            return 1
        return 0
    except DeploymentError as exc:
        payload = installer.status_payload(success=False)
        payload["error"] = str(exc)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Error: {exc}", file=sys.stderr)
            print_human(payload)
        return 1
    finally:
        installer.close()


def print_human(payload: dict[str, Any]) -> None:
    if payload.get("success") is not None:
        print(f"success: {payload['success']}")
    print(f"tool_root: {payload.get('tool_root', '')}")
    print("\nArchives:")
    for name, item in payload.get("archives", {}).items():
        status = "present" if item.get("present") else "missing"
        print(f"  {name}: {status} {item.get('path', '')}")
    print("\nInstalled:")
    for name, ok in payload.get("installed", {}).items():
        print(f"  {name}: {'yes' if ok else 'no'}")
    if payload.get("runtime_paths"):
        print("\nRuntime paths:")
        for name, value in payload["runtime_paths"].items():
            print(f"  {name}: {value}")
    if payload.get("symbol_versions"):
        print("\nSymbol versions:")
        versions = payload["symbol_versions"]
        print(f"  executables: {versions.get('executables', {})}")
        print(f"  shared_libraries: {versions.get('shared_libraries', {})}")
        print(f"  combined_required: {versions.get('combined_required', {})}")
        print(f"  gcc_runtime_provided: {versions.get('gcc_runtime_provided', {})}")
        for error in versions.get("errors", []):
            print(f"  error: {error}")
    if payload.get("runtime_resolution"):
        print("\nRuntime resolution:")
        for name, item in payload["runtime_resolution"].items():
            status = "ok" if item.get("ok") else "failed"
            print(f"  [{status}] {name}: libstdc++.so.6 => {item.get('libstdc++.so.6', '')}")
            for error in item.get("errors", []):
                print(f"    error: {error}")
    if payload.get("probes"):
        print("\nProbes:")
        for name, probe in payload["probes"].items():
            status = "ok" if probe.get("ok") else "failed"
            print(f"  [{status}] {name}: {' '.join(probe.get('command', []))}")
            if probe.get("stderr"):
                print(f"    stderr: {probe['stderr']}")
    if payload.get("steps"):
        print("\nSteps:")
        for step in payload["steps"]:
            print(f"  [{step['status']}] {step['name']}: {step.get('message', '')}")
    if payload.get("warnings"):
        print("\nWarnings:")
        for warning in payload["warnings"]:
            print(f"  - {warning}")


if __name__ == "__main__":
    raise SystemExit(main())
