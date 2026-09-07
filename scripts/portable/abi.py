"""Audit shipped ELF consumers, including native resources embedded in JARs.

The symbol floor is a necessary condition, not a runtime test result. Only
DT_VERNEED and undefined dynamic symbols count; exported GLIBC definitions do
not. Compiler sysroots are reported separately from host runtime consumers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import re
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List

MACHINES = {"x86_64": 62, "aarch64": 183}
LOADERS = {"x86_64": "/lib64/ld-linux-x86-64.so.2", "aarch64": "/lib/ld-linux-aarch64.so.1"}
HOST_LIBRARIES = re.compile(
    r"^(?:lib(?:c|m|mvec|pthread|dl|rt|resolv|util|anl|nss_dns|nss_files)\.so\.\d+|ld-linux[^/]*\.so\.\d+)$"
)
NUMERIC_VERSION = re.compile(r"^(GLIBC|GLIBCXX|CXXABI)_([0-9]+(?:\.[0-9]+)*)$")
ABI_MARKERS = {"GLIBC_ABI_DT_RELR": "2.36"}
BUILD_PREFIXES = (b"/work/build/", b"/work/sources/", b"/work/prefix/", b"/inputs/", b"/helper/")


def relocation_errors(path: Path) -> List[str]:
    errors = []
    if not path.stat().st_size:
        return errors
    with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        for prefix in BUILD_PREFIXES:
            # A Java package such as com/example/helper/Foo is not the
            # absolute build directory /helper. Require a path boundary,
            # including compiler options that can precede absolute paths.
            pattern = rb"(?<![A-Za-z0-9_./-])(?:-I|-L|-isystem|--sysroot=)?" + re.escape(prefix)
            position = data.find(prefix)
            while position >= 0:
                if re.search(pattern, data[max(0, position - 16) : position + len(prefix)]):
                    errors.append("Embedded build path: " + prefix.decode())
                    break
                position = data.find(prefix, position + len(prefix))
        # Compiler input templates can use #! as data (for example GHS .gpj).
        # Only files runnable directly need a host-independent interpreter.
        if data[:2] == b"#!" and path.stat().st_mode & 0o111:
            interpreter = data[:240].splitlines()[0][2:].strip().split()[0]
            if interpreter not in {b"/bin/sh", b"/bin/bash", b"/usr/bin/env"}:
                errors.append("Non-portable shebang: " + interpreter.decode(errors="replace"))
    return errors


def sha256(path: Path) -> str:
    hasher = os.environ.get("ZSCOPE_NATIVE_SHA256")
    if hasher and path.stat().st_size > 4 * 1024 * 1024:
        value = subprocess.check_output([hasher, str(path)], text=True).split()[0]
        if not re.fullmatch("[0-9a-f]{64}", value):
            raise ValueError("Invalid native SHA-256 response")
        return value
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def version_tuple(value: str) -> tuple:
    return tuple(int(part) for part in value.split("."))


def maximum(values) -> str:
    return max(values, key=version_tuple) if values else ""


def elf_machine(header: bytes) -> int:
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return 0
    return int(struct.unpack("<H" if header[5] == 1 else ">H", header[18:20])[0])


def parse_readelf(text: str) -> Dict[str, Any]:
    needed = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", text)
    runpaths = re.findall(r"\((?:RUNPATH|RPATH)\).*?\[([^\]]*)\]", text)
    interpreter = re.search(r"Requesting program interpreter:\s*([^\]]+)\]", text)
    requirements = set()
    symbols = []
    in_needs = False
    in_definitions = False
    definitions = set()
    for line in text.splitlines():
        if line.startswith("Version "):
            in_needs = line.startswith("Version needs section")
            in_definitions = line.startswith("Version definition section")
        if in_definitions:
            definitions.update(re.findall(r"Name:\s*((?:GLIBC|GLIBCXX|CXXABI)_[\w.]+)", line))
        if in_needs:
            for name in re.findall(r"Name:\s*((?:GLIBC|GLIBCXX|CXXABI)_[\w.]+)", line):
                requirements.add(name)
        if re.search(r"\bUND\b", line):
            match = re.search(r"(\S+)@((?:GLIBC|GLIBCXX|CXXABI)_[\w.]+)", line)
            if match:
                requirements.add(match[2])
                symbols.append({"symbol": match[1], "version": match[2]})
    floors = {"GLIBC": [], "GLIBCXX": [], "CXXABI": []}
    unknown = []
    for requirement in sorted(requirements):
        match = NUMERIC_VERSION.fullmatch(requirement)
        if match:
            floors[match[1]].append(match[2])
        elif requirement in ABI_MARKERS:
            floors["GLIBC"].append(ABI_MARKERS[requirement])
        else:
            unknown.append(requirement)
    return {
        "needed": needed,
        "runpath": [entry for value in runpaths for entry in value.split(":") if entry],
        "interpreter": interpreter[1] if interpreter else "",
        "requirements": sorted(requirements),
        "symbols": symbols,
        "definitions": sorted(definitions),
        "glibc_required": maximum(floors["GLIBC"]),
        "glibcxx_required": maximum(floors["GLIBCXX"]),
        "cxxabi_required": maximum(floors["CXXABI"]),
        "unknown_abi_markers": unknown,
    }


def inspect_elf(path: Path) -> Dict[str, Any]:
    process = subprocess.run(
        ["readelf", "-W", "-h", "-l", "-d", "-V", "--dyn-syms", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return parse_readelf(process.stdout)


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
        return True
    except ValueError:
        return False


def audit(root: Path, arch: str, *, ceiling: str = "2.38") -> Dict[str, Any]:
    root = root.resolve()
    runtime: List[Dict[str, Any]] = []
    compiler_inputs: List[Dict[str, Any]] = []
    excluded_natives: List[str] = []
    errors: List[str] = []
    seen = set()
    provider_versions = {}

    def consume(path: Path, label: str, header: bytes, *, embedded: bool = False) -> None:
        machine = elf_machine(header)
        if not machine:
            return
        if machine != MACHINES[arch]:
            if embedded:
                # Java native loaders choose a platform-specific resource. Such
                # resources are never counted as native Linux runtime consumers.
                excluded_natives.append(label)
            else:
                errors.append(f"Wrong ELF architecture ({machine}): {label}")
            return
        if header[4] != 2 or header[5] != 1:
            errors.append(f"Expected a little-endian 64-bit ELF: {label}")
            return
        row = inspect_elf(path)
        row.update(path=label, sha256=sha256(path), machine=machine, embedded=embedded)
        if label.startswith("tools/gcc/sysroot/"):
            compiler_inputs.append(row)
            return
        runtime.append(row)
        errors.extend(f"{issue}: {label}" for issue in relocation_errors(path))
        if row["unknown_abi_markers"]:
            errors.append(
                f"Unsupported/private ABI requirements: {label}: {row['unknown_abi_markers']}"
            )
        floor = row["glibc_required"]
        if floor and version_tuple(floor) > version_tuple(ceiling):
            errors.append(f"GLIBC_{floor} exceeds {ceiling}: {label}")
        if row["interpreter"] and row["interpreter"] != LOADERS[arch]:
            errors.append(f"Unexpected ELF interpreter: {label}: {row['interpreter']}")
        search = [root / "lib"]  # The launcher explicitly supplies this directory.
        for entry in row["runpath"]:
            expanded = entry.replace("${ORIGIN}", str(path.parent)).replace(
                "$ORIGIN", str(path.parent)
            )
            if "$" in expanded or (not entry.startswith(("$ORIGIN", "${ORIGIN}"))):
                errors.append(f"Non-relocatable RPATH: {label}: {entry}")
                continue
            directory = Path(expanded)
            if not embedded and not _within(directory, root):
                errors.append(f"Escaping RPATH: {label}: {entry}")
            search.append(directory)
        dependencies = {}
        for name in row["needed"]:
            if HOST_LIBRARIES.fullmatch(name):
                dependencies[name] = "host-glibc"
                continue
            found = next(
                (directory / name for directory in search if (directory / name).is_file()), None
            )
            if found is None or not _within(found, root):
                errors.append(f"Unresolved bundled dependency: {label}: {name}")
            else:
                dependencies[name] = found.resolve().relative_to(root).as_posix()
        row["resolved_dependencies"] = dependencies
        cxx_requirements = {
            value for value in row["requirements"] if value.startswith(("GLIBCXX_", "CXXABI_"))
        }
        if cxx_requirements:
            provider = dependencies.get("libstdc++.so.6")
            if provider and provider != "host-glibc":
                if provider not in provider_versions:
                    provider_versions[provider] = set(inspect_elf(root / provider)["definitions"])
                missing = cxx_requirements - provider_versions[provider]
                if missing:
                    errors.append(f"Bundled libstdc++ lacks versions: {label}: {sorted(missing)}")
            else:
                errors.append(f"C++ ABI provider is not bundled: {label}")

    for path in sorted(root.rglob("*")):
        label = path.relative_to(root).as_posix()
        if path.is_symlink() and (not path.exists() or not _within(path, root)):
            errors.append(f"Broken/escaping symlink: {label}")
            continue
        if not path.is_file() or path.resolve() in seen:
            continue
        seen.add(path.resolve())
        with path.open("rb") as stream:
            header = stream.read(20)
        if elf_machine(header):
            consume(path, label, header)
        elif path.suffix.lower() == ".jar":
            with (
                zipfile.ZipFile(path) as archive,
                tempfile.TemporaryDirectory(prefix="zscope-abi-") as temporary,
            ):
                for member in archive.infolist():
                    if not member.filename.lower().endswith((".so", ".so.1", ".so.2")):
                        continue
                    if re.search(
                        r"(?:^|[/_-])(?:freebsd|openbsd|netbsd|android|sunos|solaris|musl)(?:/|[-_])",
                        member.filename,
                        re.IGNORECASE,
                    ):
                        excluded_natives.append(f"{label}!/{member.filename}")
                        continue
                    with archive.open(member) as stream:
                        native_header = stream.read(20)
                        if not elf_machine(native_header):
                            continue
                        native = Path(temporary) / "native.so"
                        with native.open("wb") as output:
                            output.write(native_header)
                            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                                output.write(chunk)
                    consume(native, f"{label}!/{member.filename}", native_header, embedded=True)
        elif not label.startswith(("share/", "licenses/", "tools/gcc/sysroot/")):
            errors.extend(f"{issue}: {label}" for issue in relocation_errors(path))
    floor = maximum([row["glibc_required"] for row in runtime if row["glibc_required"]])
    if not runtime:
        errors.append("Bundle contains no runtime ELF consumers")
    return {
        "schema_version": "zscope.portable-abi.v1",
        "arch": arch,
        "build_glibc": "2.38",
        "glibc_ceiling": ceiling,
        "glibc_required": floor,
        "glibcxx_required": maximum(
            [row["glibcxx_required"] for row in runtime if row["glibcxx_required"]]
        ),
        "cxxabi_required": maximum(
            [row["cxxabi_required"] for row in runtime if row["cxxabi_required"]]
        ),
        "glibc_tested_min": None,
        "passed": not errors,
        "errors": errors,
        "highest_consumers": [row["path"] for row in runtime if row["glibc_required"] == floor],
        "runtime": runtime,
        "compiler_inputs": compiler_inputs,
        "foreign_jar_native_resources": excluded_natives,
    }


def write_report(report: dict, output: Path) -> None:
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Portable ABI report",
        "",
        f"Architecture: {report['arch']}",
        f"Build glibc: {report['build_glibc']}",
        f"Required glibc symbols: {report['glibc_required'] or 'none'}",
        f"Highest GLIBCXX requirement: {report['glibcxx_required'] or 'none'}",
        f"Highest CXXABI requirement: {report['cxxabi_required'] or 'none'}",
        "Runtime-tested minimum: recorded separately in smoke evidence",
        "",
        "| Runtime consumer | GLIBC | GLIBCXX | CXXABI |",
        "|---|---|---|---|",
    ]
    for row in report["runtime"]:
        lines.append(
            f"| `{row['path']}` | {row['glibc_required']} | {row['glibcxx_required']} | {row['cxxabi_required']} |"
        )
    lines.extend([
        "", "## Imports establishing the highest ABI requirements", "",
        "| ABI version | Consumer | Imported symbol |", "|---|---|---|",
    ])
    for family, field in (
        ("GLIBC", "glibc_required"), ("GLIBCXX", "glibcxx_required"), ("CXXABI", "cxxabi_required")
    ):
        highest = report[field]
        if highest:
            version = family + "_" + highest
            for row in report["runtime"]:
                for item in row["symbols"]:
                    if item["version"] == version:
                        lines.append(f"| {version} | `{row['path']}` | `{item['symbol']}` |")
    lines.extend([
        "", "## Compiler sysroot (excluded from runtime floor)", "",
        "| Compiler input | GLIBC | GLIBCXX | CXXABI |", "|---|---|---|---|",
    ])
    for row in report["compiler_inputs"]:
        lines.append(
            f"| `{row['path']}` | {row['glibc_required']} | {row['glibcxx_required']} | {row['cxxabi_required']} |"
        )
    lines.extend(["", "## Errors", "", *report["errors"], ""])
    output.with_suffix(".md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--arch", choices=list(MACHINES), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.root, args.arch)
    write_report(report, args.output)
    if not report["passed"]:
        raise SystemExit("ABI audit failed: " + "; ".join(report["errors"][:10]))


if __name__ == "__main__":
    main()
