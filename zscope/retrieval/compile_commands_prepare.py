"""Atomic, recoverable preparation of the *original* compilation database.

The receipt is immutable for a scan generation. Execution retries never write
this database; a new preparation is allowed only before a new generation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shlex
import stat
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from .compiler_compat import ADAPTER_DIGEST, POLICY_DIGEST, POLICY_VERSION, adjust_arguments
from .compile_preflight import (
    CheckTool,
    compiler_offset,
    preflight,
    probe_arguments,
    x86_64_arguments,
)
from .indexing_identity import (
    command_arguments,
    digest_json,
    environment_identity,
    executable_identity,
    file_digest,
)
from .indexing_runtime import heartbeat

logger = logging.getLogger(__name__)
PREPARATION_VERSION = 1
PREPARATION_DIGEST = hashlib.sha256(
    Path(__file__).read_bytes() + Path(__file__).with_name("compile_preflight.py").read_bytes()
).hexdigest()
MANAGED_DIRECTORY = ".zscope-compile-commands"


def _bytes_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(
    path: Path,
    data: bytes,
    *,
    mode: int = 0o600,
    immutable: bool = False,
    before_replace: Callable[[], None] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".prepare-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        if immutable:
            try:
                os.link(temporary, path)  # An immutable name is never replaced.
            except FileExistsError:
                if path.read_bytes() != data:
                    raise RuntimeError("compile preparation artifact collision: " + str(path))
        else:
            if before_replace is not None:
                before_replace()
            os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _json_write(path: Path, value: Any, *, immutable: bool = False) -> None:
    _write(
        path,
        (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(),
        immutable=immutable,
    )


@contextmanager
def _lock(directory: Path) -> Iterator[None]:
    import fcntl  # Product C/C++ execution and its filesystem contracts are Linux.

    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "prepare.lock").open("a+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def _snapshot(path: Path) -> dict[str, str]:
    return dict(target=str(path.resolve(strict=True)), digest=file_digest(path))


def _current(dependencies: dict[str, dict[str, str]]) -> bool:
    try:
        return all(_snapshot(Path(path)) == expected for path, expected in dependencies.items())
    except OSError:
        return False


def _tool_current(tool: dict[str, Any]) -> bool:
    current = executable_identity(tool["command"])
    expected = dict(tool["identity"])
    # The loader nonce disables cross-run cache reuse; its random value is not
    # evidence that the binary changed during this run.
    current.pop("unverified_loader_run", None)
    expected.pop("unverified_loader_run", None)
    return current == expected


@dataclass(frozen=True)
class PreparationReceipt:
    path: str
    real_path: str
    original_digest: str
    effective_digest: str
    policy_digest: str
    tools_json: str
    dependencies_json: str
    environment_json: str
    report_path: str

    def validate(self, *, check_tools: bool = True) -> None:
        if (
            str(Path(self.path).resolve()) != self.real_path
            or file_digest(Path(self.path)) != self.effective_digest
            or self.policy_digest != POLICY_DIGEST
            or json.loads(self.environment_json) != environment_identity()
            or not _current(json.loads(self.dependencies_json))
        ):
            raise RuntimeError("Prepared compilation inputs changed; refresh the index generation")
        if check_tools:
            for tool in json.loads(self.tools_json):
                if not _tool_current(tool):
                    raise RuntimeError(
                        "Prepared compiler identity changed; refresh the index generation: "
                        + tool["name"]
                    )


def _receipt(path: Path, real: Path, record: dict[str, Any], report: Path) -> PreparationReceipt:
    return PreparationReceipt(
        str(path),
        str(real),
        record["original_digest"],
        record["effective_digest"],
        POLICY_DIGEST,
        json.dumps(record["tools"]),
        json.dumps(record["dependencies"]),
        json.dumps(record["environment"]),
        str(report),
    )


def _expand(
    arguments: list[str],
    directory: Path,
    dependencies: dict[str, dict[str, str]],
    contents: dict[str, tuple[dict[str, str], list[str]]],
) -> tuple[list[str], bool]:
    used = False

    def expand(values: list[str], parents: frozenset[str]) -> list[str]:
        nonlocal used
        result = []
        for value in values:
            if not value.startswith("@"):
                result.append(value)
                continue
            used = True
            path = Path(os.path.abspath(directory / value[1:]))
            cached = contents.get(str(path))
            if cached is None:
                snapshot = _snapshot(path)
                data = path.read_bytes()
                if _bytes_digest(data) != snapshot["digest"]:
                    raise RuntimeError("Response file changed while reading: " + str(path))
                tokens = shlex.split(data.decode("utf-8"))
                contents[str(path)] = (snapshot, tokens)
            else:
                snapshot, tokens = cached
            key = snapshot["target"]
            if key in parents or len(parents) >= 64:
                raise ValueError("recursive response file: " + str(path))
            previous = dependencies.setdefault(str(path), snapshot)
            if previous != snapshot:
                raise RuntimeError("Response file changed during preparation: " + str(path))
            result.extend(expand(tokens, parents | {key}))
        return result

    return expand(arguments, frozenset()), used


def prepare_compile_commands(
    path: Path, tools: list[CheckTool], *, workers: int = 4, host_arch: str | None = None
) -> PreparationReceipt:
    path = Path(os.path.abspath(path))
    real = path.resolve(strict=True)
    managed = real.parent / MANAGED_DIRECTORY
    started = time.monotonic()
    stats = dict(
        entries=0, contexts=0, cache_hits=0, architecture=0, warnings=0, unknown=0, unverified=0
    )
    logger.info("[compile-prepare] start database=%s", path)
    with heartbeat("compile-prepare", stats), _lock(managed):
        raw = real.read_bytes()
        current_digest = _bytes_digest(raw)
        # Records are installed before the database commit. A crash after replace
        # is therefore recoverable without guessing whether the args were edited.
        previous_path = managed / "effective" / (current_digest + ".json")
        previous = json.loads(previous_path.read_text()) if previous_path.exists() else None
        origin = current_digest if previous is None else previous["original_digest"]
        backup = managed / "original" / (origin + ".json")
        original = raw if previous is None else backup.read_bytes()
        if _bytes_digest(original) != origin:
            raise RuntimeError("Compile database backup checksum mismatch: " + str(backup))
        identities = [
            dict(
                name=t.name,
                command=t.command,
                kind=t.kind,
                identity=t.identity,
                capability=t.capability,
                cxx=t.cxx,
            )
            for t in tools
        ]
        environment = os.environ.copy()
        context_identity = dict(
            version=PREPARATION_VERSION,
            policy=POLICY_DIGEST,
            adapter=ADAPTER_DIGEST,
            preparation=PREPARATION_DIGEST,
            database_directory=str(path.parent),
            tools=identities,
            environment=environment_identity(),
            host_arch=host_arch or platform.machine(),
        )
        signature = digest_json(context_identity)
        if (
            previous
            and previous["signature"] == signature
            and previous.get("reusable")
            and _current(previous["dependencies"])
        ):
            result = _receipt(path, real, previous, Path(previous["report_path"]))
            stats.update(entries=previous["entries"], cache_hits=previous["entries"])
            logger.info(
                "[compile-prepare] complete reused=true stats=%s seconds=%.3f report=%s",
                stats,
                time.monotonic() - started,
                result.report_path,
            )
            return result
        rows = json.loads(original)
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise ValueError("compile_commands.json must be an array of objects")
        stats["entries"] = len(rows)
        dependencies: dict[str, dict[str, str]] = {}
        response_contents: dict[str, tuple[dict[str, str], list[str]]] = {}
        entries = []
        groups: dict[str, tuple[CheckTool, list[str], Path]] = {}
        for ordinal, row in enumerate(rows):
            arguments = command_arguments(row)
            if not arguments:
                raise ValueError(f"compile command {ordinal} has no arguments")
            directory = Path(row.get("directory") or path.parent)
            if not directory.is_absolute():
                directory = path.parent / directory
            expanded, response = _expand(arguments, directory, dependencies, response_contents)
            offset = compiler_offset(expanded)
            adjusted, changes = adjust_arguments(expanded[offset:])
            adjusted, architecture = x86_64_arguments(adjusted, str(context_identity["host_arch"]))
            effective = expanded[:offset] + adjusted
            probe, cxx = probe_arguments(effective, str(row.get("file", "")), directory)
            keys = []
            for tool in tools:
                if tool.kind == "identity" or (tool.cxx is not None and tool.cxx != cxx):
                    continue
                key = digest_json(
                    dict(
                        signature=signature,
                        tool=tool.name,
                        arguments=probe,
                        directory=str(directory),
                    )
                )
                keys.append(key)
                groups.setdefault(key, (tool, probe, directory))
            entries.append(
                dict(
                    ordinal=ordinal,
                    original_arguments=arguments,
                    expanded_arguments=expanded,
                    effective_arguments=effective,
                    architecture=architecture,
                    response=response,
                    preflight_keys=keys,
                    **changes,
                )
            )
            stats["architecture"] += len(architecture)
            stats["warnings"] += len(changes["ignored_warning_errors"])
        stats["contexts"] = len(groups)
        results = {}
        pending = {}
        with ThreadPoolExecutor(
            max_workers=max(1, min(workers, 4)), thread_name_prefix="CompilePreflight"
        ) as pool:
            for key, (tool, probe, directory) in groups.items():
                cached = managed / "checks" / (key + ".json")
                if cached.exists():
                    results[key] = json.loads(cached.read_text())
                    stats["cache_hits"] += 1
                else:
                    pending[pool.submit(preflight, tool, probe, directory, environment)] = key
            try:
                for future in as_completed(pending):
                    key = pending[future]
                    checked = future.result()
                    results[key] = checked
                    if checked["status"] == "verified":
                        _json_write(managed / "checks" / (key + ".json"), checked)
            except BaseException:
                for future in pending:
                    future.cancel()
                raise
        # Backup failure is fatal and occurs before changing the public database.
        _write(backup, original, mode=0o400, immutable=True)
        output = []
        generated: dict[str, dict[str, str]] = {}
        for row, entry in zip(rows, entries):
            removed = sorted(
                {
                    flag
                    for key in entry["preflight_keys"]
                    for flag in results[key]["removed_unknown_options"]
                }
            )
            expanded = entry["effective_arguments"]
            offset = compiler_offset(expanded)
            scopes: dict[str, list[str]] = {}
            for key in entry["preflight_keys"]:
                for value, streams in results[key].get("unknown_scopes", {}).items():
                    scopes.setdefault(value, []).extend(streams)
            adjusted, changes = adjust_arguments(
                expanded[offset:], removed, unknown_scopes=scopes or None
            )
            effective = expanded[:offset] + adjusted
            entry["removed_unknown_options"] = changes["removed_unknown_options"]
            entry["unverified"] = [
                key for key in entry["preflight_keys"] if results[key]["status"] != "verified"
            ]
            if not entry["preflight_keys"]:
                entry["unverified"].append("no_available_checker")
            stats["unknown"] += len(changes["removed_unknown_options"])
            stats["unverified"] += bool(entry["unverified"])
            if entry["architecture"]:
                for key in entry["preflight_keys"]:
                    for target in results[key].get("targets", []):
                        if target.split("-", 1)[0] != "x86_64" or "x32" in target:
                            raise ValueError(
                                "compile database target conflict after -m64: " + target
                            )
            entry["effective_arguments"] = effective
            changed = effective != entry["expanded_arguments"]
            copied = dict(row)
            if changed:
                if entry["response"]:
                    content = (shlex.join(effective[offset + 1 :]) + "\n").encode()
                    response_path = managed / "responses" / (_bytes_digest(content) + ".rsp")
                    _write(response_path, content, mode=0o400, immutable=True)
                    generated[str(response_path)] = _snapshot(response_path)
                    effective = effective[: offset + 1] + ["@" + str(response_path)]
                copied["arguments"] = effective
                copied.pop("command", None)
            output.append(copied)
        data = (
            raw
            if output == json.loads(raw)
            else (json.dumps(output, ensure_ascii=False, indent=2) + "\n").encode()
        )
        effective_digest = _bytes_digest(data)
        report_name = digest_json(
            dict(
                origin=origin,
                signature=signature,
                dependencies=dependencies,
                effective=effective_digest,
            )
        )
        report_path = managed / "reports" / (report_name + ".json")
        record = dict(
            original_digest=origin,
            effective_digest=effective_digest,
            signature=signature,
            policy_version=POLICY_VERSION,
            policy_digest=POLICY_DIGEST,
            tools=identities,
            dependencies={**dependencies, **generated},
            entries=len(rows),
            environment=environment_identity(),
            report_path=str(report_path),
            reusable=all(
                r["status"] == "verified" or groups[key][0].kind == "unverified"
                for key, r in results.items()
            ),
        )

        # Compiler replacement or response/symlink edits invalidate the entire
        # proposed rewrite, even if the edited entry happened not to need repairs.
        def validate_inputs() -> None:
            if (
                path.resolve() != real
                or file_digest(real) != current_digest
                or not _current(dependencies)
            ):
                raise RuntimeError(
                    "Compilation database or responses changed concurrently; rewrite aborted"
                )
            for tool in tools:
                if tool.identity and not _tool_current(
                    dict(command=tool.command, identity=tool.identity)
                ):
                    raise RuntimeError(
                        "Compiler changed during preparation; rewrite aborted: " + tool.name
                    )

        validate_inputs()
        _json_write(
            report_path,
            dict(
                record,
                contexts=results,
                adjustments=entries,
                stats=stats,
                wall_seconds=time.monotonic() - started,
            ),
        )
        _json_write(managed / "effective" / (effective_digest + ".json"), record)
        validate_inputs()
        if data != raw:
            permissions = stat.S_IMODE(real.stat().st_mode)
            if not permissions & 0o222:
                raise PermissionError("Compilation database is read-only: " + str(real))
            _write(real, data, mode=permissions, before_replace=validate_inputs)
        result = _receipt(path, real, record, report_path)
        logger.info(
            "[compile-prepare] complete rewritten=%s stats=%s seconds=%.3f report=%s",
            data != raw,
            stats,
            time.monotonic() - started,
            report_path,
        )
        return result
