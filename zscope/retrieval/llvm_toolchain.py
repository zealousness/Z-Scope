"""Resolve one coherent LLVM toolchain, never the highest compiler on PATH."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from .indexing_identity import executable_identity, file_digest, tool_major
from ..common.portable import bundled_executable


def svf_environment(bin_directory: str) -> Dict[str, str]:
    """Return a process-local environment for the selected SVF installation.

    Source installs commonly leave ``svf_bin_dir`` empty and select ``wpa``
    from PATH.  Resolve that executable before deriving library roots so a
    stale LD_LIBRARY_PATH cannot pair one SVF driver with another install's
    libSvf/LLVM libraries.  Portable builds keep LLVM in a sibling ``llvm18``
    prefix, while development builds conventionally use ``llvm-*``.
    """
    env = os.environ.copy()
    if os.name == "posix":
        paths = env.get("PATH", "").split(os.pathsep)
        env["PATH"] = os.pathsep.join(
            paths + [path for path in ("/usr/bin", "/usr/local/bin") if path not in paths]
        )
    selected = (
        str(Path(bin_directory) / "wpa")
        if bin_directory
        else shutil.which("wpa", path=env.get("PATH"))
    )
    if selected:
        bundled = bundled_executable(selected)
        executable = bundled or Path(selected).resolve()
        directory = executable.parent
        libraries = [directory.parent / "lib"]
        if bundled is None:
            for pattern in ("llvm18/lib", "llvm-*/lib", "llvm-*.obj/lib", "llvm*/lib"):
                libraries.extend(sorted(directory.parent.parent.glob(pattern)))
        paths = list(dict.fromkeys(str(path.resolve()) for path in libraries if path.is_dir()))
        if paths:
            env["LD_LIBRARY_PATH"] = os.pathsep.join(
                paths + ([env["LD_LIBRARY_PATH"]] if env.get("LD_LIBRARY_PATH") else [])
            )
    return env


def matching_clang(
    llvm_link: str, *, cxx: bool = False, environment: Optional[Dict[str, str]] = None
) -> Optional[str]:
    env = environment if environment is not None else os.environ
    major = tool_major(llvm_link)
    if major is None:
        return None
    name = "clang++" if cxx else "clang"
    explicit = env.get("LLVM_CXX_NAME" if cxx else "LLVM_CC_NAME")
    directory = env.get("LLVM_COMPILER_PATH")
    resolved_link = shutil.which(llvm_link)
    if explicit or directory:
        candidates = [str(Path(directory) / (explicit or name)) if directory else str(explicit)]
    else:
        candidates = [str(Path(resolved_link).resolve().parent / name)] if resolved_link else []
        candidates += [f"{name}-{major}", name]
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved and tool_major(resolved) == major:
            return str(Path(resolved).absolute())
    return None


def svf_identity(bin_directory: str) -> Dict[str, Any]:
    identities: Dict[str, Any] = {}
    environment = svf_environment(bin_directory)
    roots = set()
    for name in ("wpa", "saber"):
        command = str(Path(bin_directory) / name) if bin_directory else name
        identity = executable_identity(command, environment)
        identities[name] = identity
        if identity["sha256"] != "missing":
            roots.add(Path(identity["path"]).parent.parent)
    # ExtAPI and shared tool libraries can change independently of the driver.
    models: Dict[str, str] = {}
    explicit = os.environ.get("SVF_EXTAPI")
    if explicit:
        models[str(Path(explicit).resolve())] = file_digest(Path(explicit))
    for root in sorted(roots):
        for sub in (root / "lib", root / "share", root / "include"):
            if sub.is_dir():
                for path in sub.rglob("*"):
                    if path.is_file() and (
                        path.name.lower() == "extapi.bc"
                        or path.name.startswith(("libSvf", "libLLVM"))
                    ):
                        models[str(path.resolve())] = file_digest(path)
    identities["models_and_libraries"] = models
    identities["library_search_path"] = environment.get("LD_LIBRARY_PATH", "")
    identities["svf_extapi"] = explicit or ""
    return identities


def validate_svf_llvm(bin_directory: str, llvm_link: str) -> None:
    """Use reported LLVM build versions or linked-library metadata when present.

    Some SVF releases print their LLVM version only in ldd output. An unverified
    toolchain is rejected instead of compiling with an arbitrary newer Clang.
    """
    expected = tool_major(llvm_link)
    environment = svf_environment(bin_directory)
    if expected is None:
        raise RuntimeError("cannot determine llvm-link version")
    for name in ("wpa", "saber"):
        command = str(Path(bin_directory) / name) if bin_directory else name
        resolved = shutil.which(command, path=environment.get("PATH"))
        if not resolved:
            raise RuntimeError(f"SVF tool missing: {command}")
        executable = str(bundled_executable(resolved) or resolved)
        version = tool_major(resolved, environment)
        if os.name == "posix":
            result = subprocess.run(
                ["ldd", executable], capture_output=True, text=True, timeout=10, env=environment
            )
            if "not found" in result.stdout:
                raise RuntimeError(
                    f"{name} has unresolved shared libraries: {result.stdout.strip()}"
                )
            matches = re.findall(r"libLLVM(?:-|\.so\.)(\d+)", result.stdout)
            if any(int(value) != expected for value in matches):
                raise RuntimeError(
                    f"{name} loaded LLVM libraries {sorted(set(matches))}, expected {expected}"
                )
            if len(set(matches)) == 1:
                version = int(matches[0])
        if version is None:
            # Static builds must ship build metadata, alongside the tool.
            metadata = Path(executable).resolve().parent.parent / "llvm-version.txt"
            if metadata.is_file():
                match = re.match(r"\s*(\d+)", metadata.read_text())
                version = int(match.group(1)) if match else None
        if version != expected:
            raise RuntimeError(
                f"{name} LLVM version {version or 'unverified'} does not match llvm-link {expected}"
            )
