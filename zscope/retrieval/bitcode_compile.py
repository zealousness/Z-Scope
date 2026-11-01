"""Per-TU compiler operation and dependency-complete artifact validation."""

from __future__ import annotations

import re
import time
import logging
from pathlib import Path
from typing import Any, Dict, List

from .indexing_identity import (
    command_identity,
    dependencies_current,
    dependency_snapshot,
    digest_json,
    file_digest,
    parse_depfile,
    include_search_roots,
    compiler_search_directories,
)
from .indexing_runtime import run_process
from .compiler_compat import (
    POLICY_VERSION,
    POLICY_DIGEST,
    MAX_ATTEMPTS,
    expand_arguments,
    adjust_arguments,
    unknown_options,
    new_report,
    ADAPTER_DIGEST,
    gllvm_diagnostic_environment,
    compiler_diagnostics,
)

logger = logging.getLogger(__name__)


def dependency_flags(arguments: List[str], depfile: Path) -> List[str]:
    result: List[str] = []
    skip = False
    for arg in arguments:
        if skip:
            skip = False
        elif arg in {"-MF", "-MT", "-MQ", "-MJ"}:
            skip = True
        elif arg in {"-M", "-MM", "-MD", "-MMD", "-MP", "-MG"} or arg.startswith(
            ("-MF", "-MT", "-MQ", "-MJ", "-Wp,-M")
        ):
            continue
        else:
            result.append(arg)
    return result + ["-MD", "-MF", str(depfile)]


def _file_version(path: Path) -> tuple[int, int, int, int, int]:
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def compile_tu(builder: Any, command: Dict[str, Any], ordinal: int) -> None:
    identity = command_identity(command, builder.compile_commands_path.parent)
    source, directory = Path(identity["source"]), Path(identity["directory"])
    context = digest_json(identity)
    adjustments = new_report(identity)
    attempted = {"source": str(source), "context": context, "status": "planned", "reason": ""}

    def status(value: str, reason: str = "", **extra: Any) -> None:
        with builder._state_lock:
            builder._manifest.setdefault("attempts", {})[context] = {
                **attempted,
                "status": value,
                "reason": reason,
                "argument_adjustments": dict(adjustments),
                **extra,
            }
            builder._manifest_dirty = True
        if value == "failed":
            builder._record_tu_failure(str(source), reason)

    status("planned")
    arguments = list(identity["arguments"])
    if not arguments:
        status("failed", "missing_compile_command")
        return
    cxx = source.suffix.lower() in {".cc", ".cpp", ".cxx"} or "++" in Path(arguments[0]).name
    compiler = builder._matching_compiler(cxx)
    if not compiler:
        status("failed", "matching_llvm_compiler_unavailable")
        return
    ordinary = bool(
        re.fullmatch(
            r"(?:clang\+\+|clang|gcc|g\+\+|cc|c\+\+)(?:-\d+(?:\.\d+)*)?(?:\.exe)?",
            Path(arguments[0]).name,
        )
    )
    # Preserve the wrapper path for complex compile commands. gllvm remains the
    # compatible path, using the verified compiler, and gets its original flags.
    direct = ordinary
    if not ordinary and Path(arguments[0]).name in {"ccache", "sccache", "distcc"}:
        arguments = arguments[1:]
    if not arguments:
        status("failed", "missing_wrapped_compiler")
        return
    arguments[0] = compiler if direct else builder.gclang
    try:
        arguments = expand_arguments(arguments, directory)
    except (OSError, ValueError) as exc:
        status("failed", "response_file_error: " + str(exc))
        return
    arguments = builder._sanitize_args(builder._inject_flags(arguments), str(source))
    arguments, changes = adjust_arguments(arguments)
    adjustments.update(changes)
    adjustments["effective_arguments"] = list(arguments)
    fingerprint = digest_json(
        {
            "schema": builder._MANIFEST_VERSION,
            "command": identity,
            "source_hash": file_digest(source),
            "arguments": arguments,
            "toolchain": builder._tool_identity(),
            "direct": direct,
            "argument_policy": [POLICY_VERSION, POLICY_DIGEST],
            "argument_adapter": ADAPTER_DIGEST,
            "source_validation": 1,
        }
    )
    # Stable context names survive compile-database reordering. The scope module
    # obtains actual paths from _bc_to_src, not a speculative filename.
    final = builder.output_dir / f"tu_{context[:24]}_{source.stem}.o.bc"
    if builder._reuse_bitcode_if_current(final, source, fingerprint, ordinal):
        entry = builder._bitcode_entry(final.resolve())
        adjustments.update(entry.get("argument_adjustments", {}))
        status("reused", bitcode=str(final))
        return
    builder._input_validator.directories(include_search_roots(arguments, directory))
    temporary = final.with_suffix(".partial.bc")
    obj = final.with_suffix(".partial.o")
    depfile = final.with_suffix(".d")
    for stale in (temporary, obj, Path(str(obj) + ".bc"), depfile):
        stale.unlink(missing_ok=True)
    output = temporary if direct else obj
    arguments = dependency_flags(builder._replace_output(arguments, str(output)), depfile)
    if direct:
        arguments += ["-emit-llvm"]
    if "-c" not in arguments:
        arguments.append("-c")
    arguments.append("-v")
    metrics: Dict[str, Any] = {}
    started = time.time_ns()
    try:
        source_version = _file_version(source)
        source_hash = file_digest(source)
        deadline = time.monotonic() + builder.timeout if builder.timeout is not None else None
        environment = dict(builder._env, LC_ALL="C", LANG="C")
        for attempt in range(1, MAX_ATTEMPTS + 1):
            remaining = max(0.0, deadline - time.monotonic()) if deadline is not None else None
            if (remaining is not None and remaining <= 0) or builder.cancel.is_set():
                status(
                    "failed",
                    "compile_cancelled" if builder.cancel.is_set() else "compile_timeout",
                    metrics=metrics,
                )
                return
            for stale in (temporary, obj, Path(str(obj) + ".bc"), depfile):
                stale.unlink(missing_ok=True)
            adjustments["effective_arguments"] = list(arguments)
            diagnostic_dir = final.with_suffix(f".compile.attempt{attempt}.children")
            attempt_env = environment
            if not direct:
                # Old failed logs are never evidence for a later invocation.
                diagnostic_dir.mkdir(parents=True, exist_ok=True)
                for stale_log in diagnostic_dir.glob("clang-*"):
                    if stale_log.is_file():
                        stale_log.unlink()
                attempt_env = gllvm_diagnostic_environment(
                    environment,
                    diagnostic_dir,
                    compiler,
                    builder._matching_compiler(True) or compiler,
                )
            remaining = max(0.0, deadline - time.monotonic()) if deadline is not None else None
            if (remaining is not None and remaining <= 0) or builder.cancel.is_set():
                status(
                    "failed",
                    "compile_cancelled" if builder.cancel.is_set() else "compile_timeout",
                    metrics=metrics,
                )
                return
            process = run_process(
                arguments,
                cwd=directory,
                env=attempt_env,
                output_prefix=final.with_suffix(f".compile.attempt{attempt}"),
                timeout=remaining,
                memory_limit_mb=builder.compile_memory_mb,
                label="bitcode-compile:" + str(source),
                cancel=builder.cancel,
            )
            metrics["compile"] = process.metrics
            metrics.setdefault("compile_attempts", []).append(process.metrics)
            children = compiler_diagnostics(diagnostic_dir) if not direct else []
            diagnosed = (
                sorted(
                    {
                        option
                        for diagnostic in children
                        for option in unknown_options(diagnostic["stderr"], arguments)
                    }
                )
                if not direct
                else unknown_options(process.stderr, arguments)
            )
            adjustments["attempts"].append(
                dict(
                    number=attempt,
                    tool_exit_code=process.returncode,
                    unknown_options=diagnosed,
                    metrics=process.metrics,
                    effective_arguments=list(arguments),
                    compiler_diagnostics=[
                        {key: value for key, value in child.items() if key != "stderr"}
                        for child in children
                    ],
                )
            )
            interrupted = any(
                process.metrics.get(name) for name in ("timed_out", "memory_exceeded", "cancelled")
            )
            child_failed = any(child["exit_code"] != 0 for child in children)
            if not process.returncode and not interrupted and not child_failed:
                break
            retry, changes = adjust_arguments(arguments, diagnosed)
            if (
                attempt < MAX_ATTEMPTS
                and not interrupted
                and diagnosed
                and changes["removed_unknown_options"]
                and retry != arguments
            ):
                adjustments["removed_unknown_options"].extend(changes["removed_unknown_options"])
                logger.debug(
                    "[compiler-arguments] source=%s retry=%d removed=%s",
                    source,
                    attempt,
                    changes["removed_unknown_options"],
                )
                arguments = retry
                continue
            status("failed", "compile_failed", metrics=metrics, stderr=process.stderr[-2000:])
            return
        if not direct:
            extraction = run_process(
                [builder.get_bc, str(obj)],
                cwd=builder.output_dir,
                env=builder._env,
                output_prefix=final.with_suffix(".extract"),
                timeout=60,
                memory_limit_mb=builder.compile_memory_mb,
                label="get-bc:" + str(source),
                cancel=builder.cancel,
            )
            metrics["extract"] = extraction.metrics
            if extraction.returncode or not Path(str(obj) + ".bc").is_file():
                status("failed", "get_bc_failed", metrics=metrics)
                return
            Path(str(obj) + ".bc").replace(temporary)
        if not temporary.is_file() or temporary.stat().st_size == 0:
            status("failed", "bitcode_missing", metrics=metrics)
            return
        dependencies: Dict[str, str] = {}
        complete = False
        try:
            paths = parse_depfile(depfile, directory)
            dependencies = dependency_snapshot(paths)
            complete = str(source) in dependencies and dependencies_current(dependencies)
            # Filesystem timestamps can be ahead of the process clock. For the
            # source we have a precompile identity: compare it directly, also
            # detecting same-content rewrites that restore the old mtime.
            # Headers discovered only after compilation retain the time guard.
            if (
                source_hash != file_digest(source)
                or source_version != _file_version(source)
                or any(p != source and p.stat().st_mtime_ns > started for p in paths)
            ):
                status("failed", "dependency_changed_during_compile", metrics=metrics)
                return
            # Negative include probes cannot be validated by existing files.
            complete = complete and not any(b"__has_include" in p.read_bytes() for p in paths)
        except (OSError, ValueError):
            pass
        # gllvm's object and bitcode compilers also interleave their -v include
        # lists. Validate each isolated list, just like unknown-option errors.
        compiler_root_lists = [
            compiler_search_directories(stderr, directory)
            for stderr in (
                [child["stderr"] for child in children] if not direct else [process.stderr]
            )
        ]
        complete = (
            complete
            and bool(compiler_root_lists)
            and all(roots is not None for roots in compiler_root_lists)
        )
        compiler_roots = [path for roots in compiler_root_lists for path in (roots or [])]
        search_roots = include_search_roots(arguments, directory, dependencies)
        search_roots.extend(compiler_roots)
        temporary.replace(final)
        with builder._state_lock:
            builder._bc_to_src[final.resolve()] = source
            builder._bc_compile_index[final.resolve()] = ordinal
        builder._record_bitcode_manifest(
            final.resolve(),
            source,
            fingerprint,
            dependencies=dependencies,
            dependencies_complete=complete,
            search_directories=builder._input_validator.directories(search_roots),
            command=identity,
            argument_adjustments=adjustments,
            metrics=metrics,
        )
        status(
            "compiled",
            "" if complete else "dependency_manifest_incomplete",
            bitcode=str(final),
            metrics=metrics,
        )
    except (OSError, ValueError) as exc:
        status("failed", str(exc), metrics=metrics)
