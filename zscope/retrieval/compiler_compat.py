"""One versioned argument policy with an external Clang/gllvm adapter.

LibTooling embeds the same JSON at build time and uses Clang's option table.
Here operand boundaries are conservative; an unknown option never consumes the
following token. A compiler error alone cannot authorize deleting source text.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any, Iterable

_RAW = Path(__file__).with_name("compiler_argument_policy.json").read_bytes()
POLICY = json.loads(_RAW)
POLICY_VERSION: int = POLICY["version"]
POLICY_DIGEST = hashlib.sha256(_RAW).hexdigest()
MAX_ATTEMPTS: int = POLICY["max_attempts"]
ADAPTER_DIGEST = hashlib.sha256(
    Path(__file__).read_bytes() + Path(__file__).with_name("compiler_diagnostics.py").read_bytes()
).hexdigest()


def gllvm_diagnostic_environment(
    environment: dict[str, str],
    directory: Path,
    compiler: str,
    cxx_compiler: str,
) -> dict[str, str]:
    """A per-attempt wrapper avoids gllvm's interleaved stderr, using no new tool."""
    directory.mkdir(parents=True, exist_ok=True)
    script = Path(__file__).with_name("compiler_diagnostics.py")
    environment = dict(environment, LLVM_COMPILER_PATH="")
    for name, executable in (("LLVM_CC_NAME", compiler), ("LLVM_CXX_NAME", cxx_compiler)):
        wrapper = directory / name.lower()
        command = shlex.join([sys.executable, str(script), str(directory), executable])
        wrapper.write_text("#!/bin/sh\nexec " + command + ' "$@"\n', encoding="utf-8")
        wrapper.chmod(0o700)
        environment[name] = str(wrapper)
    return environment


def compiler_diagnostics(directory: Path) -> list[dict[str, Any]]:
    result = []
    for path in sorted(directory.glob("clang-*.stderr.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        with Path(record["stderr_path"]).open("rb") as stream:
            record["stderr"] = stream.read(16 << 20).decode("utf-8", errors="replace")
        result.append(record)
    return result


def expand_arguments(arguments: list[str], directory: Path) -> list[str]:
    def expand(values: Iterable[str], parents: frozenset[Path]) -> list[str]:
        result = []
        for value in values:
            if not value.startswith("@"):
                result.append(value)
                continue
            path = Path(value[1:])
            path = (path if path.is_absolute() else directory / path).resolve()
            if path in parents or len(parents) >= 64:
                raise ValueError("recursive response file: " + str(path))
            result.extend(expand(shlex.split(path.read_text(encoding="utf-8")), parents | {path}))
        return result

    return expand(arguments, frozenset())


def _option_positions(values: list[str]) -> Iterable[int]:
    operands = set(POLICY["operand_options"])
    i = 0
    while i < len(values):
        value = values[i]
        if value == "--":
            return
        if value.startswith("-") and value != "-":
            yield i
        # Plugin arguments and target forwarding take one argument even though
        # their full spelling contains a user-provided name/triple.
        paired = value in operands or value.startswith(("-plugin-arg-", "-Xarch_"))
        i += 2 if paired else 1


def adjust_arguments(
    arguments: list[str],
    unknown: Iterable[str] = (),
) -> tuple[list[str], dict[str, Any]]:
    unknown = set(unknown)
    ignored: list[str] = []
    removed: list[str] = []
    replacements: dict[int, str] = {}
    deleted: set[int] = set()
    forwarded: dict[str, list[tuple[int, int, str]]] = {
        value: [] for value in POLICY["forwarded_options"]
    }
    wrappers: dict[int, tuple[str, list[str], list[int]]] = {}

    def adjust(value: str) -> str | None:
        if value in POLICY["remove_warning_options"]:
            ignored.append(value)
            return None
        if value.startswith(POLICY["warning_error_prefix"]):
            ignored.append(value)
            return str(POLICY["warning_prefix"]) + value[len(POLICY["warning_error_prefix"]) :]
        if value in unknown:
            removed.append(value)
            return None
        return value

    # First separate forwarded streams without losing their argv positions.
    direct: list[str] = []
    owners: list[int] = []
    i = 1
    while i < len(arguments):
        value = arguments[i]
        prefix, parts, indices, stream = "", [], [], ""
        if value in forwarded and i + 1 < len(arguments):
            stream, parts, indices = value, [arguments[i + 1]], [i, i + 1]
        elif value.startswith("-Xclang="):
            prefix, stream, parts, indices = "-Xclang=", "-Xclang", [value[8:]], [i]
        elif value.startswith("-Wp,"):
            prefix, stream, parts, indices = "-Wp,", "-Xpreprocessor", value[4:].split(","), [i]
        if stream:
            wrappers[i] = (prefix, parts, indices)
            forwarded[stream].extend((i, n, part) for n, part in enumerate(parts))
            i += len(indices)
            continue
        direct.append(value)
        owners.append(i)
        # Preserve operands here so a value such as '-Wp,...' is not mistaken
        # for a forwarding wrapper on the next iteration.
        if value in POLICY["operand_options"] or value.startswith(("-plugin-arg-", "-Xarch_")):
            if i + 1 < len(arguments):
                direct.append(arguments[i + 1])
                owners.append(i + 1)
                i += 1
        if value == "--":
            direct.extend(arguments[i + 1 :])
            owners.extend(range(i + 1, len(arguments)))
            break
        i += 1
    for position in _option_positions(direct):
        index = owners[position]
        changed = adjust(direct[position])
        if changed is None:
            deleted.add(index)
        elif changed != direct[position]:
            replacements[index] = changed
    changes: dict[tuple[int, int], str | None] = {}
    for forwarded_stream in forwarded.values():
        for position in _option_positions([value for _, _, value in forwarded_stream]):
            index, part, value = forwarded_stream[position]
            changes[index, part] = adjust(value)
    for index, (prefix, parts, indices) in wrappers.items():
        updated = [changes.get((index, n), value) for n, value in enumerate(parts)]
        kept = [value for value in updated if value is not None]
        if not kept:
            deleted.update(indices)
        elif prefix:
            replacements[index] = prefix + ",".join(kept)
        else:
            replacements[indices[1]] = kept[0]
    result = [replacements.get(n, value) for n, value in enumerate(arguments) if n not in deleted]
    return result, dict(ignored_warning_errors=ignored, removed_unknown_options=removed)


_UNKNOWN = re.compile(
    r"^(?:(?:[^\s:]*[/\\])?clang(?:\+\+|-cl)?(?:-\d+(?:\.\d+)*)?(?:\.exe)?: )?"
    r"(?:fatal )?error: unknown argument: '([^'\r\n]+)'(?:; did you mean '[^']+'\?)?\s*$"
)


def unknown_options(stderr: str, arguments: list[str]) -> list[str]:
    """Only driver/frontend diagnostic lines, never location-prefixed #error."""
    diagnosed = {
        match.group(1) for line in stderr.splitlines() if (match := _UNKNOWN.fullmatch(line))
    }
    _, changes = adjust_arguments(arguments, diagnosed)
    return sorted(set(changes["removed_unknown_options"]))


def new_report(identity: dict[str, Any]) -> dict[str, Any]:
    return dict(
        policy_version=POLICY_VERSION,
        policy_digest=POLICY_DIGEST,
        adapter_digest=ADAPTER_DIGEST,
        original_command=identity,
        ignored_warning_errors=[],
        removed_unknown_options=[],
        effective_arguments=[],
        attempts=[],
    )
