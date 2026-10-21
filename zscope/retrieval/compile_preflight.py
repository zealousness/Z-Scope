"""Compiler-owned argument checks. No real TU, AST or build output is produced."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .compiler_compat import POLICY, adjust_arguments, unknown_options
from .indexing_identity import executable_identity


@dataclass
class CheckTool:
    name: str
    command: str
    kind: str = "clang"
    identity: dict[str, Any] = field(default_factory=dict)
    capability: dict[str, Any] = field(default_factory=dict)
    cxx: bool | None = None


def discover_tools(
    *,
    indexer: str = "",
    clangd: str = "",
    llvm_link: str = "",
    gclang: str = "",
    environment: dict[str, str] | None = None,
) -> list[CheckTool]:
    tools = []
    if indexer:
        from .clang_batch import find_indexer

        found = find_indexer(indexer)
        if found:
            command, capability = found
            tools.append(
                CheckTool(
                    "batch",
                    command,
                    (
                        "batch"
                        if capability.get("argument_check_protocol") == "zscope.clang-arguments.v1"
                        else "unverified"
                    ),
                    capability=capability,
                )
            )
    if llvm_link:
        from .llvm_toolchain import matching_clang

        for cxx in (False, True):
            compiler = matching_clang(llvm_link, cxx=cxx, environment=environment)
            if compiler:
                tools.append(CheckTool("bitcode-cxx" if cxx else "bitcode-c", compiler, cxx=cxx))
        # These identities participate even though their argument handling is
        # checked by their paired compiler, not by executing the wrapper.
        tools.append(CheckTool("llvm-link", llvm_link, "identity"))
        if gclang:
            tools.append(CheckTool("gllvm", gclang, "identity"))
    if clangd:
        tools.append(CheckTool("clangd", clangd, "unverified"))
    for tool in tools:
        tool.identity = executable_identity(tool.command, environment=environment)
    return tools


def compiler_offset(arguments: list[str]) -> int:
    i = 0
    while i < len(arguments) - 1 and Path(arguments[i]).name in {"ccache", "sccache", "distcc"}:
        i += 1
    return i


def driver_positions(arguments: list[str]) -> list[int]:
    """Positions in the outer driver; forwarded operands belong to other streams."""
    result = []
    i = 1
    operands = set(POLICY["operand_options"]) | set(POLICY["forwarded_options"])
    while i < len(arguments):
        value = arguments[i]
        if value == "--":
            break
        if value.startswith("-") and value != "-":
            result.append(i)
        i += 2 if value in operands or value.startswith(("-plugin-arg-", "-Xarch_")) else 1
    return result


def x86_64_arguments(arguments: list[str], host_arch: str) -> tuple[list[str], list[str]]:
    positions = driver_positions(arguments)
    targets = []
    for i in positions:
        value = arguments[i]
        if value in {"-target", "--target", "-arch"} and i + 1 < len(arguments):
            targets.append(arguments[i + 1])
        elif value.startswith(("--target=", "-target=")):
            targets.append(value.split("=", 1)[1])
    # cc1 triples are authoritative too, and must not silently override -m64.
    forwarded = []
    for i in positions:
        if arguments[i] == "-Xclang" and i + 1 < len(arguments):
            forwarded.append(arguments[i + 1])
        elif arguments[i].startswith("-Xclang="):
            forwarded.append(arguments[i][8:])
    for i, value in enumerate(forwarded[:-1]):
        if value == "-triple":
            targets.append(forwarded[i + 1])
    implicit = re.match(
        r"^((?:aarch64|arm|riscv\d+|powerpc\d*|mips\d*|i[3-6]86|x86_64)-.+)-(?:gcc|g\+\+|clang)(?:-\d+)?$",
        Path(arguments[0]).name,
    )
    if not targets and implicit:
        targets.append(implicit.group(1))
    m32 = [i for i in positions if arguments[i] == "-m32"]
    x64 = {"x86_64", "amd64"}
    target_arches = {target.split("-", 1)[0].lower() for target in targets}
    context_x64 = bool(target_arches & x64) or (not targets and host_arch.lower() in x64)
    if m32 and targets and not target_arches <= x64:
        raise ValueError(
            "compile database target conflict: -m32 with explicit target " + ", ".join(targets)
        )
    if context_x64 and (
        any(arguments[i] in {"-mx32", "-mabi=x32", "-mabi=ilp32"} for i in positions)
        or any("x32" in target or "gnuilp32" in target for target in targets)
        or (targets and not target_arches <= x64)
    ):
        raise ValueError("compile database target conflict: x86_64 with incompatible target/ABI")
    if not context_x64 or not m32:
        return arguments, []
    result = [value for i, value in enumerate(arguments) if i not in m32]
    # Insert before --, not after an input/operand terminator.
    at = result.index("--") if "--" in result else len(result)
    result.insert(at, "-m64")
    return result, ["-m32"] * len(m32)


def probe_arguments(arguments: list[str], source: str, directory: Path) -> tuple[list[str], bool]:
    """Remove only known output operands and the exact source input for dedup.

    The output is used only by non-executing driver/cc1 checks. Unrecognized
    operands remain verbatim; we never guess the arity of an unknown option.
    """
    offset = compiler_offset(arguments)
    values = arguments[offset:]
    cxx = source.endswith((".C", ".cc", ".cp", ".cpp", ".cxx", ".c++", ".CPP")) or "++" in values[0]
    positions = set(driver_positions(values))
    inferred_language = "c++" if cxx else "c"
    language = inferred_language
    operands: set[int] = set()
    removed: set[int] = set()
    source_path = os.path.normpath(os.path.join(str(directory), source))
    for i in positions:
        if values[i] in set(POLICY["operand_options"]) | set(POLICY["forwarded_options"]):
            operands.add(i + 1)
        if values[i] in {"-o", "-MF", "-MT", "-MQ", "-MJ"}:
            removed.update((i, i + 1))
        elif values[i].startswith(("-MF", "-MT", "-MQ", "-MJ")):
            removed.add(i)
        elif values[i] in {"-MD", "-MMD", "-MP", "-MG", "-M", "-MM", "-c", "-S", "-E"}:
            removed.add(i)
        elif values[i] == "-x" and i + 1 < len(values):
            language = inferred_language if values[i + 1] == "none" else values[i + 1]
            cxx = "++" in language
    for i, value in enumerate(values[1:], 1):
        if (
            i not in positions
            and i not in operands
            and os.path.normpath(os.path.join(str(directory), value)) == source_path
        ):
            removed.add(i)
    result = [v for i, v in enumerate(values) if i not in removed]
    at = result.index("--") if "--" in result else len(result)
    result[at:at] = ["-x", language, "-fsyntax-only", "/dev/null"]
    return result, cxx


_WARNING = re.compile(
    r"^(?:clang(?:\+\+)?(?:-\d+)?: )?warning: unknown warning option '([^'\r\n]+)'(?:; did you mean '[^']+'\?)?(?: \[-W[^\]]+\])?$"
)


def _run(
    command: list[str], directory: Path, deadline: float, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise subprocess.TimeoutExpired(command, 0)
    with tempfile.TemporaryDirectory(prefix="zscope-probe-argv-") as temp:
        if sum(len(arg) + 1 for arg in command) > 32768:
            response = Path(temp) / "arguments.rsp"
            response.write_text(shlex.join(command[1:]), encoding="utf-8")
            command = [command[0], "@" + str(response)]
        return subprocess.run(
            command,
            cwd=directory,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(0.001, deadline - time.monotonic()),
        )


def check_once(
    tool: CheckTool,
    arguments: list[str],
    directory: Path,
    deadline: float,
    environment: dict[str, str],
) -> dict[str, Any]:
    if tool.kind not in {"clang", "batch"}:
        return dict(status="unverified", reason="no_matching_argument_checker", unknown=[])
    # Loading extensions is neither necessary nor safe for an argument check.
    # Their parameters require real execution and retain the late retry path.
    if any(
        v in {"-load", "-plugin", "-add-plugin", "--config", "-mllvm"}
        or v.startswith(("--config=", "-fplugin", "-plugin-arg-"))
        for v in arguments[1:]
    ):
        return dict(status="unverified", reason="extension_arguments", unknown=[])
    env = dict(environment, LC_ALL="C", LANG="C")
    if tool.kind == "batch":
        with tempfile.TemporaryDirectory(prefix="zscope-argument-check-") as temp:
            job = Path(temp) / "job.json"
            job.write_text(json.dumps(dict(arguments=arguments)), encoding="utf-8")
            response = _run([tool.command, "--check-arguments", str(job)], directory, deadline, env)
        if response.returncode:
            return dict(
                status="unverified", reason="checker_failed", stderr=response.stderr, unknown=[]
            )
        data = json.loads(response.stdout)
        if data.get("protocol") != "zscope.clang-arguments.v1":
            raise ValueError("invalid argument checker protocol")
        unknown = [
            item["spelling"] for item in data["unknown_options"] if item.get("argument_indices")
        ]
        scopes = {
            item["spelling"]: item["scopes"]
            for item in data["unknown_options"]
            if item.get("argument_indices")
        }
        return dict(
            status=(
                "unknown"
                if unknown
                else (
                    "invalid"
                    if data["errors"]
                    else ("verified" if data["targets"] else "unverified")
                )
            ),
            unknown=unknown,
            unknown_scopes=scopes,
            evidence=data,
            targets=data["targets"],
        )
    command = [tool.command, "-###", "-fno-color-diagnostics", *arguments[1:]]
    driver = _run(command, directory, deadline, env)
    unknown = unknown_options(driver.stderr, arguments)
    scopes = {value: [""] for value in unknown}
    evidence: list[dict[str, Any]] = [
        dict(stage="driver", exit_code=driver.returncode, stderr=driver.stderr)
    ]
    if driver.returncode and unknown:
        adjusted, _ = adjust_arguments(arguments, unknown, unknown_scopes=scopes)
        driver = _run(
            [tool.command, "-###", "-fno-color-diagnostics", *adjusted[1:]],
            directory,
            deadline,
            env,
        )
        evidence.append(
            dict(stage="driver-after-unknown", exit_code=driver.returncode, stderr=driver.stderr)
        )
    if driver.returncode:
        return dict(
            status="unknown" if unknown else "invalid",
            unknown=unknown,
            unknown_scopes=scopes,
            evidence=evidence,
        )
    targets = []
    for line in driver.stderr.splitlines():
        if not line.lstrip().startswith('"'):
            continue
        cc1 = shlex.split(line)
        if len(cc1) < 2 or cc1[1] != "-cc1":
            continue
        # Execute only the configured compiler, never a program printed by it.
        if "-triple" in cc1:
            targets.append(cc1[cc1.index("-triple") + 1])
        frontend = _run(
            [tool.command, *cc1[1:], "-help", "-Wunknown-warning-option"], directory, deadline, env
        )
        evidence.append(
            dict(stage="frontend", exit_code=frontend.returncode, stderr=frontend.stderr)
        )
        frontend_unknown = unknown_options(frontend.stderr, arguments)
        for item in frontend.stderr.splitlines():
            match = _WARNING.fullmatch(item)
            if match:
                _, changes = adjust_arguments(arguments, [match.group(1)])
                frontend_unknown.extend(changes["removed_unknown_options"])
        for value in frontend_unknown:
            scopes.setdefault(value, []).extend(
                ["-Xclang", "-Xpreprocessor"] + ([""] if value.startswith("-W") else [])
            )
        unknown.extend(frontend_unknown)
        if frontend.returncode and not unknown:
            return dict(status="invalid", unknown=[], evidence=evidence, targets=targets)
    return dict(
        status="unknown" if unknown else ("verified" if targets else "unverified"),
        unknown=sorted(set(unknown)),
        unknown_scopes=scopes,
        evidence=evidence,
        targets=targets,
    )


def preflight(
    tool: CheckTool, arguments: list[str], directory: Path, environment: dict[str, str]
) -> dict[str, Any]:
    """Two checks share ten seconds. Only fully verified repairs are reusable."""
    deadline = time.monotonic() + 10
    attempts = []
    effective = arguments
    removed = []
    scopes: dict[str, list[str]] = {}
    try:
        for _ in range(2):
            result = check_once(tool, effective, directory, deadline, environment)
            attempts.append(dict(arguments=effective, **result))
            if result["status"] != "unknown":
                break
            for value, streams in result.get("unknown_scopes", {}).items():
                scopes.setdefault(value, []).extend(streams)
            changed, details = adjust_arguments(effective, result["unknown"], unknown_scopes=scopes)
            if changed == effective or len(attempts) == 2:
                break
            removed.extend(details["removed_unknown_options"])
            effective = changed
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        attempts.append(dict(status="unverified", reason=str(exc)))
    verified = attempts[-1]["status"] == "verified"
    return dict(
        status="verified" if verified else "unverified",
        attempts=attempts,
        removed_unknown_options=removed if verified else [],
        unknown_scopes=scopes if verified else {},
        targets=attempts[-1].get("targets", []),
        wall_seconds=10 - max(0, deadline - time.monotonic()),
    )
