"""Backend-aware environment diagnostics for strict Z-SCOPE config v3."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

from ..config.config import ConfigLoader
from ..common.portable import bundle_manifest, bundle_root, java_jar


def _check(name: str, ok: bool, detail: str, *, required: bool = True) -> Dict[str, Any]:
    return {"name": name, "ok": bool(ok), "required": required, "detail": detail}


def _resolve_tool(command: str) -> Optional[str]:
    candidate = Path(str(command or "")).expanduser()
    if candidate.is_file():
        return str(candidate.resolve())
    return shutil.which(str(command or ""))


def _append_tool(
    checks: List[Dict[str, Any]], name: str, command: str, *, required: bool = True
) -> None:
    found = _resolve_tool(command)
    checks.append(
        _check(
            f"tool:{name}",
            found is not None,
            found or f"{command!r} not found",
            required=required,
        )
    )


def _java_build_tool(project_root: Path) -> str:
    for wrapper in ("mvnw", "mvnw.cmd"):
        if (project_root / wrapper).is_file():
            return str(project_root / wrapper)
    if (project_root / "pom.xml").is_file():
        return "mvn"
    for wrapper in ("gradlew", "gradlew.bat"):
        if (project_root / wrapper).is_file():
            return str(project_root / wrapper)
    if any((project_root / name).is_file() for name in ("build.gradle", "build.gradle.kts")):
        return "gradle"
    return "mvn"


def _configured_checks(config: Any, checks: List[Dict[str, Any]]) -> None:
    project = config.project
    indexing = config.indexing
    backend = indexing.backend
    if project.language == "c_cpp":
        if backend in {"clang", "unified"}:
            frontend = getattr(indexing, "clang_frontend", "auto")
            _append_tool(checks, "clangd", indexing.clangd_path, required=frontend != "batch")
            if frontend != "lsp":
                _append_tool(
                    checks,
                    "zscope-clang-indexer",
                    getattr(indexing, "clang_indexer_path", "zscope-clang-indexer"),
                    required=frontend == "batch",
                )
            compile_commands = project.compile_commands_path
            checks.append(
                _check(
                    "compile_commands",
                    bool(compile_commands and Path(compile_commands).is_file()),
                    str(compile_commands or "not configured"),
                )
            )
        if backend == "unified":
            from ..retrieval.llvm_toolchain import matching_clang

            direct_compiler = matching_clang(indexing.llvm_link_path)
            if direct_compiler:
                _append_tool(checks, "matching-clang", direct_compiler)
            for name, command in (
                ("gclang", indexing.gclang_path),
                ("get-bc", indexing.get_bc_path),
                ("llvm-link", indexing.llvm_link_path),
                ("llvm-nm", "llvm-nm"),
            ):
                _append_tool(
                    checks,
                    name,
                    command,
                    required=not direct_compiler or name not in {"gclang", "get-bc"},
                )
            if indexing.svf_bin_dir:
                svf_dir = Path(indexing.svf_bin_dir).expanduser()
                for name in ("wpa", "saber"):
                    candidates = [svf_dir / name, svf_dir / f"{name}.exe"]
                    found = next((path for path in candidates if path.is_file()), None)
                    checks.append(
                        _check(
                            f"tool:{name}",
                            found is not None,
                            str(found or candidates[0]),
                        )
                    )
            else:
                _append_tool(checks, "wpa", "wpa")
                _append_tool(checks, "saber", "saber")
            linux = platform.system().lower() == "linux"
            release = platform.release().lower()
            checks.append(
                _check(
                    "linux-userland",
                    linux,
                    f"{platform.system()} {platform.release()}"
                    + (" (WSL)" if "microsoft" in release else ""),
                )
            )
        return

    _append_tool(checks, "java", "java")
    if backend in {"java_source", "java_unified"}:
        build_tool = _java_build_tool(project.project_root)
        _append_tool(checks, Path(build_tool).name, build_tool)
    if backend == "joern" or "joern" in indexing.java_signal_backends:
        _append_tool(checks, "joern", indexing.joern_path)
    if backend == "java_unified":
        for provider in indexing.java_signal_backends:
            if provider == "joern":
                continue
            from ..retrieval.java_signal_providers import ExternalJavaSignalProvider

            command = indexing.java_signal_provider_commands.get(provider)
            if command is None:
                command = ExternalJavaSignalProvider(provider)._default_command()
            executable = command[0] if command else provider
            _append_tool(checks, f"java-provider:{provider}", executable)
    if bundle_root() is not None and backend in {"java_source", "java_unified"}:
        for frontend in ("structure-spoon", "structure-javaparser"):
            try:
                jar = java_jar(frontend)
                checks.append(_check(f"java-jar:{frontend}", True, str(jar)))
            except (OSError, ValueError) as exc:
                checks.append(_check(f"java-jar:{frontend}", False, str(exc)))


@click.command()
@click.option(
    "--config", "config_path", type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    "--profile",
    type=click.Choice(["auto", "cpp", "java", "all"]),
    default="auto",
    show_default=True,
)
@click.option("--json-output", is_flag=True, help="Emit machine-readable diagnostics.")
def main(config_path: Optional[Path], profile: str, json_output: bool) -> None:
    """Check config v3, selected backend, toolchain, paths, and runtime provenance."""

    checks: List[Dict[str, Any]] = []
    checks.append(
        _check(
            "python>=3.13",
            sys.version_info >= (3, 13),
            f"{platform.python_version()} ({sys.executable})",
        )
    )

    config = None
    effective_profile = profile
    portable = None
    try:
        portable = bundle_manifest()
        if portable:
            checks.append(_check("portable-bundle", True, str(bundle_root())))
            checks.append(
                _check(
                    "portable-architecture",
                    platform.machine() == portable["arch"],
                    str(portable["arch"]),
                )
            )
    except (OSError, ValueError, KeyError) as exc:
        checks.append(_check("portable-bundle", False, str(exc)))
    if config_path:
        try:
            config = ConfigLoader.load(str(config_path))
            effective_profile = "java" if config.project.language == "java" else "cpp"
            checks.append(
                _check(
                    "configuration",
                    True,
                    f"{config_path.resolve()} (v{config.user_config_version})",
                )
            )
            checks.append(
                _check(
                    "runtime-spec",
                    bool(config.runtime_provenance.sha256),
                    f"v{config.runtime_provenance.version} "
                    f"{config.runtime_provenance.sha256[:12]} "
                    f"{config.runtime_provenance.source_path}",
                )
            )
            rule_provenance = config.rule_catalog_provenance
            checks.append(
                _check(
                    "rule-catalog",
                    bool(getattr(rule_provenance, "catalog_sha256", ""))
                    and bool(getattr(rule_provenance, "effective_sha256", "")),
                    "catalog="
                    f"{getattr(rule_provenance, 'catalog_sha256', '')[:12]} "
                    "effective="
                    f"{getattr(rule_provenance, 'effective_sha256', '')[:12]}",
                )
            )
            for index, warning in enumerate(config.rule_validation_warnings, start=1):
                checks.append(
                    _check(
                        f"rule-catalog-warning:{index}",
                        False,
                        str(warning),
                        required=False,
                    )
                )
        except Exception as exc:
            checks.append(_check("configuration", False, str(exc)))
    elif profile == "auto":
        effective_profile = str(portable["profile"]) if portable else "cpp"

    if config is not None:
        _configured_checks(config, checks)
        directories = [
            config.project.project_root,
            Path(config.analysis.snapshot_dir),
            Path(config.indexing.knowledge_db_path).parent,
        ]
    else:
        directories = [Path.cwd()]
        if effective_profile in {"cpp", "all"}:
            for tool in ("clangd", "gclang", "get-bc", "llvm-link", "wpa", "saber"):
                _append_tool(checks, tool, tool)
        if effective_profile in {"java", "all"}:
            for tool in ("java", "mvn", "joern"):
                _append_tool(checks, tool, tool)

    for directory in dict.fromkeys(Path(path) for path in directories):
        parent = directory if directory.exists() else directory.parent
        checks.append(
            _check(
                f"writable:{directory}",
                parent.exists() and os.access(str(parent), os.W_OK),
                str(parent),
            )
        )

    payload = {
        "profile": effective_profile,
        "backend": getattr(getattr(config, "indexing", None), "backend", ""),
        "checks": checks,
    }
    if portable:
        versions: Dict[str, Dict[str, Any]] = {}
        portable_root = bundle_root()
        assert portable_root is not None
        selected_tools = {
            tool: str(portable_root / relative)
            for tool, relative in portable.get("tools", {}).items()
        }
        if config is not None:
            cfg = config.indexing
            if config.project.language == "c_cpp":
                selected_tools.update(
                    clangd=cfg.clangd_path,
                    gclang=cfg.gclang_path,
                    **{"get-bc": cfg.get_bc_path, "llvm-link": cfg.llvm_link_path},
                )
                if cfg.svf_bin_dir:
                    selected_tools.update(
                        {name: str(Path(cfg.svf_bin_dir) / name) for name in ("wpa", "saber")}
                    )
            else:
                selected_tools["joern"] = cfg.joern_path
        for tool, selected in selected_tools.items():
            installed = portable_root / portable.get("executables", {}).get(tool, "")
            selected_is_bundled = selected == str(portable_root / "bin" / tool)
            actual = installed if selected_is_bundled else Path(shutil.which(selected) or selected)
            present = actual.is_file() and os.access(actual, os.X_OK)
            checks.append(_check(f"tool:{tool}", present, str(actual)))
            architecture = "script"
            if present:
                with actual.open("rb") as stream:
                    header = stream.read(20)
                if header[:4] == b"\x7fELF" and len(header) == 20:
                    machine = int.from_bytes(header[18:20], "little" if header[5] == 1 else "big")
                    architecture = {62: "x86_64", 183: "aarch64"}.get(machine, f"ELF-{machine}")
                    checks.append(
                        _check(f"arch:{tool}", architecture == portable["arch"], architecture)
                    )
            versions[tool] = {
                "path": selected,
                "executable": str(actual),
                "architecture": architecture,
            }
            if tool not in {
                "clangd",
                "clang",
                "java",
                "javac",
                "mvn",
                "git",
                "cmake",
                "gcc",
                "g++",
                "make",
                "ninja",
                "pkg-config",
                "file",
                "llvm-link",
                "llvm-nm",
            }:
                if selected_is_bundled:
                    lock_path = portable_root / "share/toolchain.lock.json"
                    if lock_path.is_file():
                        sources = json.loads(lock_path.read_text(encoding="utf-8"))["sources"]
                        component = (
                            "svf"
                            if tool in {"wpa", "saber"}
                            else (
                                "gllvm"
                                if tool in {"gclang", "gclang++", "get-bc", "gsanity-check"}
                                else (
                                    "joern-" + portable["arch"]
                                    if tool.startswith("joern")
                                    else None
                                )
                            )
                        )
                        if component:
                            versions[tool].update(
                                version=sources[component]["version"], version_source="bundle-lock"
                            )
                continue
            try:
                process = subprocess.run(
                    [selected, "-version" if tool == "java" else "--version"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                versions[tool].update(
                    {
                        "returncode": process.returncode,
                        "output": (process.stdout or process.stderr).splitlines()[:3],
                    }
                )
                checks.append(
                    _check(
                        f"version:{tool}",
                        process.returncode == 0,
                        f"{selected}: " + (process.stdout or process.stderr).strip().split("\n")[0],
                    )
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                versions[tool] = {"path": selected, "error": str(exc)}
                checks.append(_check(f"version:{tool}", False, f"{selected}: {exc}"))
        compatibility = {}
        try:
            abi = json.loads(
                (portable_root / "share/compatibility.json").read_text(encoding="utf-8")
            )
            compatibility = {
                key: abi.get(key)
                for key in ("build_glibc", "glibc_required", "glibcxx_required", "cxxabi_required")
            }
            libc_name, libc_version = platform.libc_ver()
            compatibility["host_glibc"] = libc_version if libc_name == "glibc" else libc_name
            required = tuple(int(part) for part in str(abi["glibc_required"]).split("."))
            actual = tuple(int(part) for part in libc_version.split("."))
            checks.append(
                _check(
                    "portable-glibc",
                    libc_name == "glibc" and actual >= required,
                    f"host={libc_name} {libc_version}; required={abi['glibc_required']}",
                )
            )
        except (OSError, KeyError, ValueError) as exc:
            checks.append(_check("portable-glibc", False, str(exc)))
        payload["portable"] = {
            "root": str(bundle_root()),
            "profile": portable["profile"],
            "arch": portable["arch"],
            "versions": versions,
            "compatibility": compatibility,
        }
    if json_output:
        click.echo(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for item in checks:
            status = "PASS" if item["ok"] else ("WARN" if not item["required"] else "FAIL")
            click.echo(f"{status:4} {item['name']}: {item['detail']}")
    if any(not item["ok"] and item["required"] for item in checks):
        raise click.exceptions.Exit(1)


if __name__ == "__main__":
    main()
