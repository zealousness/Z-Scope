"""Content identities shared by native indexing and LLVM builds.

Paths, commands and dependencies are facts; a missing dependency manifest must
never be interpreted as an unchanged translation unit.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import threading
from concurrent.futures import Future
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


ENVIRONMENT_KEYS = (
    "CPATH",
    "C_INCLUDE_PATH",
    "CPLUS_INCLUDE_PATH",
    "OBJC_INCLUDE_PATH",
    "SDKROOT",
    "INCLUDE",
    "MACOSX_DEPLOYMENT_TARGET",
    "GCC_EXEC_PREFIX",
    "COMPILER_PATH",
    "LIBRARY_PATH",
    "LLVM_COMPILER_PATH",
    "LLVM_CC_NAME",
    "LLVM_CXX_NAME",
    "LLVM_COMPILER",
    "GLLVM_OPTIONS",
    "SVF_EXTAPI",
)


def digest_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
    ).hexdigest()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with Path(path).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return "missing"
    return digest.hexdigest()


def environment_identity() -> Dict[str, str]:
    return {key: os.environ[key] for key in ENVIRONMENT_KEYS if key in os.environ}


def executable_identity(
    command: str, environment: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    from ..common.portable import bundled_executable

    resolved = shutil.which(command, path=environment.get("PATH") if environment else None)
    if not resolved and Path(command).is_file():
        resolved = str(Path(command).resolve())
    invocation = resolved
    payload = bundled_executable(resolved) if resolved else None
    if payload is not None:
        resolved = str(payload)
    identity: Dict[str, Any] = {
        "path": str(Path(resolved).resolve()) if resolved else command,
        "sha256": file_digest(Path(resolved)) if resolved else "missing",
    }
    if payload is not None and invocation:
        identity.update(invocation_path=invocation, launcher_sha256=file_digest(Path(invocation)))
    if resolved and os.name == "posix":
        # A replaced libclang/LLVM/SVF changes semantics even if the driver is
        # unchanged. Callers memoize this only for the current validation run.
        libraries: Dict[str, str] = {}
        try:
            result = subprocess.run(
                ["ldd", resolved], capture_output=True, text=True, timeout=10, env=environment
            )
            for line in result.stdout.splitlines():
                match = re.search(r"(?:=>\s*|^\s*)(/.+?)\s+\(0x[0-9a-fA-F]+\)", line)
                if match:
                    path = Path(match.group(1)).resolve()
                    libraries[str(path)] = file_digest(path)
                elif "not found" in line:
                    libraries[line.strip()] = "missing"
            identity["shared_libraries"] = libraries
        except (OSError, subprocess.SubprocessError):
            # Without loader provenance, avoid reuse across validation runs.
            identity["unverified_loader_run"] = os.urandom(16).hex()
    return identity


def tool_major(command: str, environment: Optional[Dict[str, str]] = None) -> Optional[int]:
    try:
        result = subprocess.run(
            [command, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(
        r"(?:clang|LLVM) version\s+(\d+)", result.stdout + result.stderr, re.IGNORECASE
    )
    return int(match.group(1)) if result.returncode == 0 and match else None


def command_arguments(row: Mapping[str, Any]) -> List[str]:
    if isinstance(row.get("arguments"), list) and row.get("arguments"):
        return [str(value) for value in row["arguments"]]
    command = str(row.get("command") or "")
    return shlex.split(command) if command else []


def source_path(row: Mapping[str, Any], base: Path) -> Path:
    directory = Path(str(row.get("directory") or base))
    if not directory.is_absolute():
        directory = base / directory
    source = Path(str(row.get("file") or ""))
    return (source if source.is_absolute() else directory / source).resolve()


def load_commands(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
        raise ValueError("compile_commands.json must contain an array of command objects")
    return data


def command_identity(row: Mapping[str, Any], base: Path) -> Dict[str, Any]:
    directory = Path(str(row.get("directory") or base))
    if not directory.is_absolute():
        directory = base / directory
    arguments = command_arguments(row)
    responses: Dict[str, str] = {}
    pending = list(arguments)
    while pending:
        arg = pending.pop()
        if not arg.startswith("@"):
            continue
        response = Path(arg[1:])
        response = (response if response.is_absolute() else directory / response).resolve()
        if str(response) in responses:
            continue
        responses[str(response)] = file_digest(response)
        if responses[str(response)] != "missing":
            pending.extend(shlex.split(response.read_text(encoding="utf-8")))
    return {
        "directory": str(directory.resolve()),
        "source": str(source_path(row, base)),
        "arguments": arguments,
        "response_files": responses,
        "environment": environment_identity(),
    }


def dependency_snapshot(paths: Iterable[Path]) -> Dict[str, str]:
    return {str(path): file_digest(path) for path in sorted({Path(p).resolve() for p in paths})}


def include_search_roots(
    arguments: Sequence[str], directory: Path, dependencies: Iterable[str] = ()
) -> List[Path]:
    roots = {Path(path).parent.resolve() for path in dependencies}
    roots.add(directory.resolve())
    for key in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH"):
        roots.update(
            Path(part).resolve() for part in os.environ.get(key, "").split(os.pathsep) if part
        )
    expanded = list(arguments)
    response_seen = set()
    for argument in expanded:
        if argument.startswith("@"):
            path = Path(argument[1:])
            path = (path if path.is_absolute() else directory / path).resolve()
            if path not in response_seen:
                response_seen.add(path)
                try:
                    expanded.extend(shlex.split(path.read_text(encoding="utf-8")))
                except (OSError, ValueError):
                    pass  # The compiler will reject an unreadable response file.
    pending = False
    for argument in expanded:
        value = ""
        if pending:
            value, pending = argument, False
        elif argument in {"-I", "-isystem", "-iquote", "-idirafter", "--sysroot", "-isysroot"}:
            pending = True
        else:
            for prefix in ("-isystem", "-iquote", "-idirafter", "--sysroot=", "-I"):
                if argument.startswith(prefix) and len(argument) > len(prefix):
                    value = argument[len(prefix) :]
                    break
        if value:
            path = Path(value)
            roots.add((path if path.is_absolute() else directory / path).resolve())
    ordered = sorted(roots, key=lambda path: len(path.parts))
    selected: List[Path] = []
    for path in ordered:
        if not any(path == parent or parent in path.parents for parent in selected):
            selected.append(path)
    return selected


def compiler_search_directories(stderr: str, directory: Path) -> Optional[List[Path]]:
    """Read Clang's actual -v search list without starting another compiler."""
    active = False
    roots: List[Path] = []
    for line in stderr.splitlines():
        if line.startswith("#include") and line.endswith("search starts here:"):
            active = True
        elif active and line == "End of search list.":
            return roots
        elif active:
            if not line.startswith(" ") or line.strip().endswith("(framework directory)"):
                return None
            path = Path(line.strip())
            roots.append((path if path.is_absolute() else directory / path).resolve())
    return None


def search_directories_snapshot(
    roots: Iterable[Path], *, exclude_paths: Iterable[Path] = ()
) -> Dict[str, str]:
    """Track include search membership, including newly created shadow headers.

    Only names/link targets are scanned here; dependency contents have their own
    hashes. Missing/unreadable roots disable persistent reuse conservatively.
    """
    result = {}
    ignored = {".git", ".zscope_bc", "clang_batch_cache", "__pycache__"}
    excluded = {p.resolve() for p in exclude_paths}
    excluded_parents = {parent for path in excluded for parent in path.parents}
    for root in sorted(set(Path(p).resolve() for p in roots)):
        if not root.is_dir():
            try:
                root.stat()
                result[str(root)] = "not_directory"
            except FileNotFoundError:
                result[str(root)] = "absent"
            except OSError:
                result[str(root)] = "missing"
            continue
        entries = []
        errors: List[OSError] = []
        for current, directories, files in os.walk(root, onerror=errors.append):
            directories[:] = sorted(
                name
                for name in directories
                if name not in ignored
                and not name.startswith(".zscope")
                and (Path(current) / name).resolve() not in excluded
            )
            for name in sorted(directories + files):
                path = Path(current) / name
                if path in excluded:
                    continue
                # Creating an ancestor of an owned cache is not a new include
                # candidate. Still traverse it and record all non-cache files.
                if name in directories and path in excluded_parents and not path.is_symlink():
                    continue
                entries.append(
                    (
                        path.relative_to(root).as_posix(),
                        os.readlink(path) if path.is_symlink() else "",
                    )
                )
        result[str(root)] = "missing" if errors else digest_json(entries)
    return result


def search_directories_current(snapshot: Any, *, exclude_paths: Iterable[Path] = ()) -> bool:
    return (
        isinstance(snapshot, dict)
        and bool(snapshot)
        and "missing" not in snapshot.values()
        and snapshot
        == search_directories_snapshot(
            (Path(value) for value in snapshot), exclude_paths=exclude_paths
        )
    )


class InputValidator:
    """Content hashes are shared only within a validation pass, never by mtime."""

    def __init__(self, exclude_paths: Iterable[Path] = ()):
        self.exclude_paths = tuple(exclude_paths)
        self._files: Dict[str, str] = {}
        self._directories: Dict[str, str] = {}
        self._paths: Dict[str, str] = {}
        self._pending: Dict[Tuple[str, str], Future[str]] = {}
        self.stats: Dict[str, int] = {}
        self._lock = threading.Lock()

    def _cached(
        self, namespace: str, values: Dict[str, str], key: str, compute: Callable[[], str]
    ) -> str:
        identity = (namespace, key)
        with self._lock:
            if key in values:
                metric = namespace + "_hits"
                self.stats[metric] = self.stats.get(metric, 0) + 1
                return values[key]
            future = self._pending.get(identity)
            owner = future is None
            if owner:
                future = Future()
                self._pending[identity] = future
                metric = namespace + "_computations"
                self.stats[metric] = self.stats.get(metric, 0) + 1
            else:
                self.stats["shared_waits"] = self.stats.get("shared_waits", 0) + 1
        assert future is not None
        if not owner:
            return future.result()
        try:
            value = compute()  # Never hold the registry lock across filesystem IO.
            with self._lock:
                values[key] = value
            future.set_result(value)
            return value
        except BaseException as exc:
            future.set_exception(exc)
            raise
        finally:
            with self._lock:
                self._pending.pop(identity, None)

    def dependencies(self, expected: Any) -> bool:
        if not isinstance(expected, dict) or not expected:
            return False
        for path, value in expected.items():
            if (
                value == "missing"
                or self._cached("file", self._files, path, lambda: file_digest(Path(path))) != value
            ):
                return False
        return True

    def directories(self, roots: Iterable[Path]) -> Dict[str, str]:
        result = {}
        for root in roots:
            key = self._cached("path", self._paths, str(root), lambda: str(root.resolve()))
            result[key] = self._cached(
                "directory",
                self._directories,
                key,
                lambda: search_directories_snapshot([Path(key)], exclude_paths=self.exclude_paths)[
                    key
                ],
            )
        return result

    def searches(self, expected: Any) -> bool:
        return (
            isinstance(expected, dict)
            and bool(expected)
            and "missing" not in expected.values()
            and self.directories(Path(path) for path in expected) == expected
        )


def dependencies_current(snapshot: Any) -> bool:
    return (
        isinstance(snapshot, dict)
        and bool(snapshot)
        and all(
            isinstance(path, str)
            and isinstance(digest, str)
            and digest != "missing"
            and file_digest(Path(path)) == digest
            for path, digest in snapshot.items()
        )
    )


def parse_depfile(path: Path, directory: Path) -> List[Path]:
    """Parse Make dependencies including escaped spaces, #, :, and continuations."""
    text = Path(path).read_text(encoding="utf-8").replace("\\\r\n", "").replace("\\\n", "")
    # GCC/Clang escape drive colons in Make output; a rule separator is followed
    # by whitespace. Multiple -MP rules are ignored after the first logical line.
    first = text.splitlines()[0] if text.splitlines() else ""
    separator = re.search(r"(?<!\\):(?:\s|$)", first)
    if not separator:
        raise ValueError("dependency file has no Make rule")
    words: List[str] = []
    word: List[str] = []
    escaped = False
    for char in first[separator.start() + 1 :]:
        if escaped:
            word.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char.isspace():
            if word:
                words.append("".join(word).replace("$$", "$"))
                word = []
        else:
            word.append(char)
    if word:
        words.append("".join(word).replace("$$", "$"))
    if not words:
        raise ValueError("dependency file has no inputs")
    return [
        (Path(word) if Path(word).is_absolute() else directory / word).resolve() for word in words
    ]


def atomic_json(path: Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        handle.write("\n")
    temporary.replace(path)
