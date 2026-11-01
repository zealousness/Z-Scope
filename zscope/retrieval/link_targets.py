"""Observed Linux object-only links, separate from per-TU BuildContext identity.

A compilation database is only a recipe. Recording explicitly recompiles the
selected C objects and links them; ordinary scanning only reads the receipt.
Archives, shared libraries, linker scripts, LTO and unrecorded objects remain
unsupported. Nothing here infers a target from directory or function names.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import sys
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping

from .indexing_identity import (
    atomic_json,
    command_identity,
    dependencies_current,
    dependency_snapshot,
    digest_json,
    executable_identity,
    file_digest,
    load_commands,
    parse_depfile,
    InputValidator,
)

SCHEMA = "zscope.observed-link.v1"
DIRECTORY = ".zscope-link-targets"


def absolute(value: str, directory: Path) -> Path:
    return (directory / value).resolve()


def output_of(args: list[str], directory: Path) -> Path:
    if args.count("-o") != 1 or args.index("-o") + 1 >= len(args):
        raise ValueError("one explicit -o output is required")
    return absolute(args[args.index("-o") + 1], directory)


def elf(path: Path) -> dict[str, int]:
    with path.open("rb") as handle:
        header = handle.read(20)
    if len(header) != 20 or header[:4] != b"\x7fELF" or header[5] not in (1, 2):
        raise ValueError("link recording requires ELF objects and executable")
    endian: Literal["little", "big"] = "little" if header[5] == 1 else "big"
    return {
        "class": header[4],
        "endian": header[5],
        "machine": int.from_bytes(header[18:20], endian),
        "type": int.from_bytes(header[16:18], endian),
    }


def symbols(path: Path, *, strict: bool = False) -> dict[str, str]:
    run = subprocess.run(
        ["nm", "--defined-only", "--format=posix", str(path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    result: dict[str, str] = {}
    for line in run.stdout.splitlines():
        values = line.split()
        if len(values) >= 2:
            name, kind = values[:2]
            if strict and kind in {"W", "w", "V", "v", "i", "I", "C"}:
                raise ValueError("weak, common and indirect symbols are not supported")
            result[name] = kind
    return result


def _run(args: list[str], directory: Path) -> None:
    subprocess.run(args, cwd=directory, check=True, timeout=300)


def record_link(
    root: Path, database: Path, args: list[str], *, directory: Path | None = None
) -> dict[str, Any]:
    """Explicit developer command: rebuild selected objects, then record a real link."""
    if sys.platform != "linux":
        raise ValueError("link recording requires Linux user space")
    root, database = root.resolve(), database.resolve()
    directory = (directory or Path.cwd()).resolve()
    if not args or not re.fullmatch(r"(?:[\w-]*-)?(?:clang|gcc|cc)(?:-\d+)?", Path(args[0]).name):
        raise ValueError("a direct Linux C compiler driver is required")
    output = output_of(args, directory)
    objects = []
    skip = -1
    for i, arg in enumerate(args[1:], 1):
        if i == skip:
            continue
        if arg == "-o":
            skip = i + 1
        elif arg.endswith(".o") and not arg.startswith("-"):
            objects.append(absolute(arg, directory))
        elif arg not in {"-g", "-O0", "-no-pie", "-pie"}:
            raise ValueError("only explicit object files and -o/-g/-O0/-pie/-no-pie are supported")
    if not objects or len(set(objects)) != len(objects) or output in objects:
        raise ValueError("missing, duplicate or overlapping link inputs")
    rows = load_commands(database)
    selected = []
    for obj in objects:
        matches = []
        for row in rows:
            command = command_identity(row, database.parent)
            try:
                if output_of(command["arguments"], Path(command["directory"])) == obj:
                    matches.append(command)
            except ValueError:
                continue
        if len(matches) != 1:
            raise ValueError("object must select exactly one compilation command: " + str(obj))
        command = matches[0]
        argv = command["arguments"]
        if (
            not command["source"].endswith(".c")
            or "-c" not in argv
            or command["response_files"]
            or any(x.startswith(("-flto", "-fplugin", "-Xclang")) for x in argv)
        ):
            raise ValueError("only direct non-LTO C compilation is supported")
        selected.append((obj, command))
    store = root / DIRECTORY
    store.mkdir(parents=True, exist_ok=True)
    receipt_path = store / (digest_json(str(output)) + ".json")
    # A failed new build must not leave a receipt for the previous target.
    receipt_path.unlink(missing_ok=True)
    members: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="capture-", dir=store) as temporary:
        for i, (obj, command) in enumerate(selected):
            cwd = Path(command["directory"])
            argv = command["arguments"]
            dep = Path(temporary) / f"{i}.d"
            preprocess = []
            skip_next = False
            for arg in argv:
                if skip_next:
                    skip_next = False
                elif arg in {"-o", "-MF", "-MT", "-MQ"}:
                    skip_next = True
                elif arg not in {"-c", "-MD", "-MMD", "-MP"}:
                    preprocess.append(arg)
            _run([*preprocess, "-M", "-MF", str(dep)], cwd)
            before = dependency_snapshot(parse_depfile(dep, cwd))
            compiler = executable_identity(argv[0])
            version = subprocess.run(
                [argv[0], "--version"],
                cwd=cwd,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout
            clang = re.search(r"clang version ([0-9]+\.[0-9]+\.[0-9]+)", version)
            compiler["clang_version"] = clang.group(1) if clang else ""
            _run([*argv, "-MD", "-MF", str(dep)], cwd)
            after = dependency_snapshot(parse_depfile(dep, cwd))
            if before != after or "missing" in after.values():
                raise ValueError("compilation inputs changed during recording")
            object_elf = elf(obj)
            if object_elf["type"] != 1:
                raise ValueError("expected an ELF relocatable object")
            members.append(
                {
                    "object": str(obj),
                    "object_sha256": file_digest(obj),
                    "command": command,
                    "command_id": digest_json(command),
                    "compiler": compiler,
                    "dependencies": after,
                    "elf": object_elf,
                    "symbols": symbols(obj, strict=True),
                }
            )
        linker = executable_identity(args[0])
        _run(args, directory)
        if any(
            not dependencies_current(m["dependencies"])
            or file_digest(Path(m["object"])) != m["object_sha256"]
            for m in members
        ):
            raise ValueError("link inputs changed during recording")
        target_elf = elf(output)
        if target_elf["type"] not in {2, 3} or any(
            any(m["elf"][k] != target_elf[k] for k in ("class", "endian", "machine"))
            for m in members
        ):
            raise ValueError("incompatible ELF link inputs")
        receipt = {
            "schema": SCHEMA,
            "output": str(output),
            "sha256": file_digest(output),
            "directory": str(directory),
            "arguments": args,
            "linker_driver": linker,
            "elf": target_elf,
            "symbols": symbols(output),
            "members": members,
        }
        receipt["target_id"] = digest_json(receipt)
        atomic_json(receipt_path, receipt)
    return receipt


def receipt_status(receipt: dict[str, Any]) -> str:
    try:
        if receipt.get("schema") != SCHEMA or receipt.get("target_id") != digest_json(
            {k: v for k, v in receipt.items() if k != "target_id"}
        ):
            return "invalid_link_receipt"
        if not receipt["members"] or file_digest(Path(receipt["output"])) != receipt["sha256"]:
            return "stale_link_output"
        for member in receipt["members"]:
            if file_digest(Path(member["object"])) != member[
                "object_sha256"
            ] or not dependencies_current(member["dependencies"]):
                return "stale_link_inputs"
            command = member["command"]
            current = command_identity(
                {
                    "file": command["source"],
                    "directory": command["directory"],
                    "arguments": command["arguments"],
                },
                Path(command["directory"]),
            )
            if digest_json(current) != member["command_id"]:
                return "stale_link_environment"
        return "current"
    except (KeyError, TypeError, ValueError, OSError):
        return "invalid_link_receipt"


def compilation_profile(command: dict[str, Any]) -> list[str]:
    """First slice requires the same frontend flags/directory, excluding TU/output."""
    args = command["arguments"]
    profile = [command["directory"]]
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg == "-o":
            skip = True
        elif arg != "-c" and str(absolute(arg, Path(command["directory"]))) != command["source"]:
            profile.append(arg)
    return profile


class LinkedTargets:
    """Read-only binding of observed object memberships to current native instances."""

    def __init__(self, index: Any):
        self.index = index
        self.targets: list[dict[str, Any]] = []
        self.diagnostics: list[dict[str, Any]] = []
        paths = sorted((Path(index.project_root) / DIRECTORY).glob("*.json"))
        self.contexts = (
            {c["build_context_id"]: c for c in index.get_build_contexts()} if paths else {}
        )
        validators: dict[str, InputValidator] = {}
        statuses: dict[str, str] = {}
        from .build_context import context_input_status

        for path in paths:
            try:
                receipt = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(receipt, dict):
                    raise ValueError("link receipt must be an object")
                reason = receipt_status(receipt)
                bound = {}
                for member in receipt.get("members", []) if reason == "current" else []:
                    matches = [
                        c for c in self.contexts.values() if c["command_id"] == member["command_id"]
                    ]
                    if len(matches) != 1:
                        reason = "link_member_instance_missing_or_ambiguous"
                        break
                    context = matches[0]
                    validator = self._input_validator(context, validators)
                    build = context["build_context_id"]
                    if build not in statuses:
                        statuses[build] = context_input_status(context, validator=validator)
                    reason = statuses[build]
                    if reason != "current":
                        break
                    clang = member.get("compiler", {}).get("clang_version")
                    if not clang or clang != context.get("tool", {}).get("capability", {}).get(
                        "clang_version"
                    ):
                        reason = "link_compiler_frontend_unverified"
                        break
                    observed = context.get("target", {})
                    pointer_bits = observed.get("target.pointer_bits")
                    triple = observed.get("target.triple", "")
                    machine = {"x86_64": 62, "aarch64": 183, "i386": 3, "i686": 3, "arm": 40}.get(
                        str(triple).split("-")[0]
                    )
                    if (
                        not machine
                        or machine != member["elf"]["machine"]
                        or pointer_bits != {1: 32, 2: 64}.get(member["elf"]["class"])
                    ):
                        reason = "link_native_abi_unverified"
                        break
                    if any(
                        member["dependencies"].get(
                            p, "missing" if Path(p).is_relative_to(Path(index.project_root)) else h
                        )
                        != h
                        for p, h in context["dependencies"].items()
                    ):
                        reason = "link_native_dependency_conflict"
                        break
                    bound[context["build_context_id"]] = member
                profiles = {digest_json(compilation_profile(m["command"])) for m in bound.values()}
                abi = {digest_json(self.contexts[k].get("target", {})) for k in bound}
                if reason == "current" and (len(profiles) != 1 or len(abi) != 1):
                    reason = "link_native_configuration_incompatible"
                if reason == "current":
                    self.targets.append({"receipt": receipt, "members": bound, "path": str(path)})
                self.diagnostics.append(
                    {"path": str(path), "target_id": receipt.get("target_id"), "status": reason}
                )
            except (OSError, ValueError, KeyError, TypeError):
                self.diagnostics.append({"path": str(path), "status": "invalid_link_receipt"})

    def resolve(self, caller_build: str, usr: str, selected: str = "") -> dict[str, Any]:
        choices = [
            t
            for t in self.targets
            if caller_build in t["members"]
            and (not selected or t["receipt"]["target_id"] == selected)
        ]
        if len(choices) != 1:
            return {"complete": False, "reason": "link_target_missing_or_ambiguous"}
        target = choices[0]
        if not re.fullmatch(r"c:@F@[A-Za-z_]\w*", usr):
            return {"complete": False, "reason": "non_external_c_function"}
        name = usr.removeprefix("c:@F@")
        definitions = []
        for build, member in target["members"].items():
            if member["symbols"].get(name) != "T":
                continue
            facts = self.index.get_function_program_facts(usr, build_context_id=build)
            bodies = facts.get("functions") or []
            if (
                len(bodies) == 1
                and facts.get("complete")
                and bodies[0].get("owner", {}).get("usr") == usr
            ):
                definitions.append(facts)
        if len(definitions) != 1 or target["receipt"]["symbols"].get(name) != "T":
            return {"complete": False, "reason": "linked_definition_missing_or_ambiguous"}
        result = dict(definitions[0])
        result["link_target"] = {
            "target_id": target["receipt"]["target_id"],
            "output": target["receipt"]["output"],
            "members": sorted(target["members"]),
        }
        return result

    def _input_validator(
        self,
        context: Mapping[str, Any],
        validators: dict[str, InputValidator],
    ) -> InputValidator:
        """Return one validator per live input namespace for this check.

        A scan job has already captured immutable namespace views.  Reusing
        those views avoids recursively walking every include directory for
        each link member while retaining the job/run/input fence.  Standalone
        callers still get a fresh content validator shared only within the
        current validation pass.
        """

        runtime = getattr(self.index, "_job_runtime_outputs", None)
        runtime_factory = getattr(runtime, "validator", None)
        build = str(context.get("build_context_id") or "")
        if getattr(runtime, "_active", False) and callable(runtime_factory) and build:
            key = f"runtime:{build}"
            if key not in validators:
                validators[key] = runtime_factory(context)
            return validators[key]

        excluded = context.get("search_excludes", [])
        key = f"filesystem:{digest_json(excluded)}"
        if key not in validators:
            validators[key] = InputValidator(Path(path) for path in excluded)
        return validators[key]

    def current_many(self, selected: Iterable[str]) -> bool:
        """Revalidate several target identities in one shared filesystem pass."""

        required = {str(value) for value in selected if str(value)}
        if not required:
            return True
        validators: dict[str, InputValidator] = {}
        statuses: dict[str, str] = {}
        matched: set[str] = set()
        from .build_context import context_input_status

        for target in self.targets:
            target_id = str(target["receipt"].get("target_id") or "")
            if target_id not in required:
                continue
            try:
                current = json.loads(Path(target["path"]).read_text(encoding="utf-8"))
                if current != target["receipt"] or receipt_status(current) != "current":
                    return False
                for build in target["members"]:
                    context = self.contexts[build]
                    if build not in statuses:
                        statuses[build] = context_input_status(
                            context,
                            validator=self._input_validator(context, validators),
                        )
                    if statuses[build] != "current":
                        return False
                matched.add(target_id)
            except (OSError, ValueError, KeyError, TypeError):
                return False
        return matched == required

    def current(self, selected: str) -> bool:
        return self.current_many((selected,))
