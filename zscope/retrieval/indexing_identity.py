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
import stat
import subprocess
import threading
from concurrent.futures import Future
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, NoReturn, Optional, Sequence, Tuple


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


def include_probes_current(receipt: Any) -> bool:
    """Check native existence-only lookups without executing stored commands.

    Missing receipts retain the old producer's conservative completeness flag.
    Negative include-next/quote searches use a superset of search roots: an
    ambiguous existing candidate stays unproved. Header maps/frameworks remain
    incomplete at the native producer. Content reads are validated separately.
    """
    if receipt is None:
        return True
    if not isinstance(receipt, dict) or receipt.get("version") != "zscope.include-probes.v1":
        return False
    roots, queries = receipt.get("search_directories"), receipt.get("queries")
    if not isinstance(roots, list) or not isinstance(queries, list):
        return False
    try:
        if any(not isinstance(root, str) or not Path(root).is_absolute() for root in roots):
            return False
        for query in queries:
            if not isinstance(query, dict) or type(query.get("found")) is not bool:
                return False
            if type(query.get("angled")) is not bool or not query.get("name"):
                return False
            name = Path(query["name"])
            if query["found"]:
                target = Path(query.get("target_file", ""))
                if not target.is_absolute() or not target.is_file():
                    return False
            else:
                including = Path(query.get("including_file", ""))
                if not including.is_absolute():
                    return False
                candidates = [name] if name.is_absolute() else [Path(r) / name for r in roots]
                if not query["angled"] and not name.is_absolute():
                    candidates.append(including.parent / name)
                for candidate in candidates:
                    try:
                        if stat.S_ISREG(candidate.stat().st_mode):
                            return False
                    except (FileNotFoundError, NotADirectoryError):
                        pass
        return True
    except (OSError, TypeError, ValueError):
        return False


def search_directories_snapshot(
    roots: Iterable[Path], *, exclude_paths: Iterable[Path] = ()
) -> Dict[str, str]:
    """Track include search membership, including newly created shadow headers.

    Only names/link targets are scanned here; dependency contents have their own
    hashes. Missing/unreadable roots disable persistent reuse conservatively.
    """
    return {
        path: value[0]
        for path, value in _search_membership(roots, exclude_paths=exclude_paths).items()
    }


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


def _runtime_lookup_candidates(context: Mapping[str, Any]) -> frozenset[Path]:
    def refuse() -> NoReturn:
        raise ValueError("job_runtime_output_lookup_unverifiable")

    sdk_aliases: dict[Path, Path] = {}

    def plain(path: Path) -> bool:
        if not path.is_absolute() or ".." in path.parts:
            return False
        aliases = [parent for parent in (path, *path.parents) if parent.is_symlink()]
        if not aliases:
            return path.resolve() == path
        # Each supported SDK mapping has exact native and physical evidence.
        # No caller-selected or project alias is generalized from these roots.
        return any(
            path.is_relative_to(root)
            and aliases == [root]
            and path.resolve() == physical / path.relative_to(root)
            for root, physical in sdk_aliases.items()
        )

    def record_sdk_alias(root: Path, physical: Path) -> None:
        chain = {root, *root.parents, physical, *physical.parents}
        if (
            not root.is_relative_to(Path("/usr"))
            or not physical.is_relative_to(Path("/usr"))
            or root.resolve(strict=True) != physical
            or not physical.is_dir()
            or any(
                path.lstat().st_uid != 0 or (not path.is_symlink() and path.lstat().st_mode & 0o022)
                for path in chain
            )
            or any(path.is_symlink() for path in root.parents)
            or any(path.is_symlink() for path in (physical, *physical.parents))
        ):
            refuse()
        sdk_aliases[root] = physical

    capability = context.get("tool", {}).get("capability", {})
    receipt = context.get("include_lookups")
    probes = context.get("include_probes")
    if (
        capability.get("include_lookup_version") != 1
        or not isinstance(receipt, dict)
        or receipt.get("version") != "zscope.include-lookups.v1"
        or receipt.get("complete") is not True
        or receipt.get("unsupported_reasons") != []
        or not isinstance(probes, dict)
        or probes.get("version") != "zscope.include-probes.v1"
        or not isinstance(probes.get("queries"), list)
    ):
        refuse()
    resource = receipt.get("resource_directory")
    if not isinstance(resource, str) or not Path(resource).is_absolute():
        refuse()
    possible_resource_root = Path(resource) / "include"
    if possible_resource_root.is_symlink():
        record_sdk_alias(possible_resource_root, possible_resource_root.resolve(strict=True))
    ordinary, modes = receipt.get("queries"), receipt.get("probe_lookups")
    actual, configured = receipt.get("search_directories"), receipt.get("configured_directories")
    if not isinstance(ordinary, list):
        refuse()
    if not isinstance(modes, list):
        refuse()
    if not isinstance(actual, list):
        refuse()
    if not isinstance(configured, list):
        refuse()
    if len(modes) != len(probes["queries"]):
        refuse()
    # This explicit host SDK layout is bounded to the full native SDK version,
    # both actual/configured system-root receipts and the exact physical map.
    # Other releases/layouts keep their original refusal or ResourceDir policy.
    host_sdk = Path("/usr/include/clang/18.1.3/include")
    if (
        capability.get("clang_version") == "18.1.3"
        and any(
            isinstance(row, dict)
            and row.get("path") == str(host_sdk)
            and row.get("classification") == "system"
            and row.get("framework") is False
            and row.get("header_map") is False
            for row in actual
        )
        and any(
            isinstance(row, dict)
            and row.get("path") == str(host_sdk)
            and type(row.get("group")) is int
            and row["group"] == 3
            and row.get("framework") is False
            and row.get("quoted_only") is False
            and row.get("ignore_sysroot") is True
            for row in configured
        )
        and host_sdk.is_symlink()
    ):
        record_sdk_alias(host_sdk, Path("/usr/lib/llvm-18/lib/clang/18/include"))
    roots: set[Path] = set()
    for row in actual:
        if (
            not isinstance(row, dict)
            or row.get("classification") not in {"quoted", "angled", "system"}
            or row.get("framework") is not False
            or row.get("header_map") is not False
            or not isinstance(row.get("path"), str)
        ):
            refuse()
        root = Path(row["path"])
        if not plain(root) or not root.is_dir():
            refuse()
        roots.add(root)
    for row in configured:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("path"), str)
            or type(row.get("group")) is not int
            or not 0 <= row["group"] <= 9
            or row.get("framework") is not False
            or type(row.get("quoted_only")) is not bool
            or type(row.get("ignore_sysroot")) is not bool
        ):
            refuse()
        root = Path(row["path"])
        if not plain(root):
            refuse()
        roots.add(root)  # Includes configured roots omitted by actual HeaderSearch when absent.
    command, dependencies = context.get("command"), context.get("dependencies")
    if not isinstance(command, dict) or not isinstance(dependencies, dict):
        refuse()
    roots.update(
        include_search_roots(command["arguments"], Path(command["directory"]), dependencies)
    )
    if any(not plain(root) for root in roots):
        refuse()
    all_queries = [*ordinary, *modes]
    for row in all_queries:
        if not isinstance(row, dict) or not isinstance(row.get("including_file"), str):
            refuse()
        including = Path(row["including_file"])
        if not plain(including) or not including.is_file() or str(including) not in dependencies:
            refuse()
        roots.add(
            including.parent
        )  # Conservative superset includes every real quote-stack location.
    for mode, probe in zip(modes, probes["queries"]):
        if not isinstance(probe, dict) or mode.get("operator") != "__has_include":
            refuse()
        fields = ("name", "angled", "including_file", "found", "target_file")
        if {field: mode.get(field) for field in fields} != {
            field: probe.get(field) for field in fields
        }:
            refuse()
    candidates: set[Path] = set()
    for row in all_queries:
        name = row.get("name")
        if (
            not isinstance(name, str)
            or not name
            or "\0" in name
            or Path(name).is_absolute()
            or any(part in {".", ".."} for part in name.split("/"))
            or type(row.get("angled")) is not bool
            or type(row.get("found")) is not bool
            or not isinstance(row.get("target_file"), str)
        ):
            refuse()
        possible = {root / name for root in roots}
        candidates.update(possible)
        if row["found"]:
            target = Path(row["target_file"])
            if not plain(target) or not target.is_file() or target not in possible:
                refuse()
        elif row["target_file"]:
            refuse()
    for row in ordinary:
        if row.get("directive") != "include" or row.get("found") is not True:
            refuse()
        target = Path(row["target_file"])
        location = row.get("location")
        if (
            str(target) not in dependencies
            or not isinstance(location, dict)
            or location.get("file") != row["including_file"]
            or type(location.get("line")) is not int
            or location["line"] < 1
            or type(location.get("offset")) is not int
            or location["offset"] < 0
            or not isinstance(row.get("target_lexical"), str)
            or not isinstance(row.get("search_path"), str)
            or row.get("relative_path") != row["name"]
        ):
            refuse()
        lexical = Path(row["target_lexical"])
        if not lexical.is_absolute():
            lexical = Path(command["directory"]) / lexical
        if Path(os.path.normpath(lexical)) != target:
            refuse()
        if row["search_path"]:
            search = Path(row["search_path"])
        elif not row["angled"]:
            search = Path(row["including_file"]).parent
        else:
            refuse()
        if not plain(search) or Path(os.path.normpath(search / row["name"])) != target:
            refuse()
    # Native lexical roots and their proved physical SDK twins are both
    # candidates; this removes no names from the original namespace receipt.
    candidates.update(
        path.resolve()
        for path in tuple(candidates)
        if any(path.is_relative_to(root) for root in sdk_aliases)
    )
    return frozenset(candidates)


def _lookup_path_state(path: Path) -> tuple[Any, ...]:
    physical = str(path.resolve())
    try:
        observed = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return ("absent", physical)
    return (
        "present",
        physical,
        observed.st_dev,
        observed.st_ino,
        observed.st_uid,
        observed.st_mode,
        os.readlink(path) if path.is_symlink() else "",
    )


def _search_membership(
    roots: Iterable[Path], *, exclude_paths: Iterable[Path] = (), include_all_names: bool = False
) -> dict[str, tuple[str, tuple[tuple[str, str], ...]]]:
    """The one original namespace walker, shared by raw and derived checks."""
    result: dict[str, tuple[str, tuple[tuple[str, str], ...]]] = {}
    ignored = {".git", ".zscope_bc", "clang_batch_cache", "__pycache__"}
    excluded = {path.resolve() for path in exclude_paths}
    excluded_parents = {parent for path in excluded for parent in path.parents}
    for root in sorted(set(Path(path).resolve() for path in roots)):
        if not root.is_dir():
            try:
                root.stat()
                state = "not_directory"
            except FileNotFoundError:
                state = "absent"
            except OSError:
                state = "missing"
            result[str(root)] = (state, ())
            continue
        entries: list[tuple[str, str]] = []
        errors: list[OSError] = []
        for current, directories, files in os.walk(root, onerror=errors.append):
            directories[:] = sorted(
                name
                for name in directories
                if include_all_names
                or (
                    name not in ignored
                    and not name.startswith(".zscope")
                    and (Path(current) / name).resolve() not in excluded
                )
            )
            for name in sorted(directories + files):
                path = Path(current) / name
                if not include_all_names and path in excluded:
                    continue
                if (
                    not include_all_names
                    and name in directories
                    and path in excluded_parents
                    and not path.is_symlink()
                ):
                    continue
                entries.append(
                    (
                        path.relative_to(root).as_posix(),
                        os.readlink(path) if path.is_symlink() else "",
                    )
                )
        result[str(root)] = ("missing" if errors else digest_json(entries), tuple(entries))
    return result


def _physical_chain(path: Path) -> tuple[tuple[str, int, int, int, int, str], ...]:
    result = []
    for parent in (path, *path.parents):
        try:
            observed = parent.lstat()
        except FileNotFoundError:
            continue
        result.append(
            (
                str(parent),
                observed.st_dev,
                observed.st_ino,
                observed.st_uid,
                observed.st_mode,
                os.readlink(parent) if stat.S_ISLNK(observed.st_mode) else "",
            )
        )
    return tuple(result)


def _same_entry(left: Path, right: Path) -> bool:
    """Whether two paths name one entry, tolerating files removed mid-comparison.

    The job runtime declares its own SQLite files as outputs while SQLite creates
    and removes ``-wal``/``-shm`` beside them, so a ``samefile()`` call can lose
    either side between the existence check and the stat. An entry that vanished
    during the comparison is not the same file as anything; raising here used to
    abort the whole scan (``FileNotFoundError: .../jobs.db-wal``).
    """

    try:
        return left.samefile(right)
    except OSError:
        return False


class _RuntimeNamespaceView:
    """Immutable raw baseline plus individually proved added output names."""

    def __init__(
        self,
        raw: Mapping[str, str],
        excludes: Iterable[Path],
        protected: Iterable[Path],
        candidates: Iterable[Path],
        *,
        provenance: Iterable[Path] = (),
        footprint_roots: Iterable[Path] = (),
    ) -> None:
        self.raw = dict(raw)
        self.excludes = tuple(excludes)
        self.baseline = _search_membership(
            (Path(path) for path in raw), exclude_paths=self.excludes
        )
        if {path: value[0] for path, value in self.baseline.items()} != self.raw:
            raise ValueError("job_runtime_output_raw_namespace_changed_before_issuance")
        if not raw or any(value in {"missing", "not_directory"} for value in raw.values()):
            raise ValueError("job_runtime_output_raw_namespace_unverifiable")
        self.protected = tuple(protected)
        self.protected_chains = {path: _physical_chain(path) for path in self.protected}
        self.provenance_chains = {path: _physical_chain(path) for path in provenance}
        self.footprint_roots = tuple(footprint_roots)
        # An additional complete run-directory census never removes an entry
        # from the original raw receipt. It also catches unknown names when a
        # normal project cache exclude predates this live factory scope.
        self.footprint_baseline = _search_membership(self.footprint_roots, include_all_names=True)
        self.candidates = frozenset(candidates)
        self.candidate_states = {path: _lookup_path_state(path) for path in self.candidates}
        self.files: set[Path] = set()
        self.directories: set[Path] = set()
        self.uncreated_directories: set[Path] = set()
        self.output_chains: dict[Path, tuple[tuple[str, int, int, int, int, str], ...]] = {}

    def declare(self, path: Path, *, directory: bool = False) -> None:
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("job_runtime_output_path_not_exact")
        if any(parent.is_symlink() for parent in (path, *path.parents)):
            raise ValueError("job_runtime_output_symlink_path")
        if path.resolve() != path:
            raise ValueError("job_runtime_output_physical_path_not_exact")
        for protected in self.protected:
            if path == protected or path.resolve() == protected.resolve():
                raise ValueError("job_runtime_output_input_overlap")
            if _same_entry(path, protected):
                raise ValueError("job_runtime_output_input_overlap")
        if path in self.candidates:
            raise ValueError("job_runtime_output_lookup_conflict")
        if path.exists() and (path.is_dir() != directory):
            raise ValueError("job_runtime_output_path_kind_conflict")
        if path in self.files or path in self.directories:
            if (path in self.directories) != directory:
                raise ValueError("job_runtime_output_redeclared_kind")
            return
        if directory and not path.exists():
            self.uncreated_directories.add(path)
        (self.directories if directory else self.files).add(path)
        self.output_chains[path] = _physical_chain(path if directory else path.parent)

    def seal_created_directories(self) -> None:
        for path in tuple(self.uncreated_directories):
            if path.exists():
                if path.is_symlink() or not path.is_dir() or path.stat().st_uid != os.geteuid():
                    raise ValueError("job_runtime_output_directory_identity_unverifiable")
                current = {row[0]: row[1:] for row in _physical_chain(path)}
                if any(current.get(row[0]) != row[1:] for row in self.output_chains[path]):
                    raise ValueError("job_runtime_output_parent_changed_during_publish")
                self.output_chains[path] = _physical_chain(path)
                self.uncreated_directories.remove(path)

    def current(self, expected: Any) -> bool:
        if expected != self.raw:
            return False
        if any(_lookup_path_state(path) != value for path, value in self.candidate_states.items()):
            return False
        if any(_physical_chain(path) != chain for path, chain in self.protected_chains.items()):
            return False
        for path, chain in self.provenance_chains.items():
            current_chain = {row[0]: row[1:] for row in _physical_chain(path)}
            if any(current_chain.get(row[0]) != row[1:] for row in chain):
                return False
            if path.is_symlink() and not any(row[0] == str(path) and row[-1] for row in chain):
                return False
        if any(path.exists() for path in self.uncreated_directories):
            return False
        for output, chain in self.output_chains.items():
            if any(parent.is_symlink() for parent in (output, *output.parents)):
                return False
            current = dict(
                (row[0], row[1:])
                for row in _physical_chain(output if output in self.directories else output.parent)
            )
            if any(current.get(row[0]) != row[1:] for row in chain):
                return False
            if output.exists() and (output.is_dir() != (output in self.directories)):
                return False
            if output.exists():
                try:
                    owner = output.stat().st_uid
                except OSError:
                    # Removed between the existence check and the stat: the
                    # recorded proof no longer describes what is on disk.
                    return False
                if owner != os.geteuid():
                    return False
            if any(_same_entry(output, path) for path in self.protected):
                return False
        observations = (
            (
                self.baseline,
                _search_membership((Path(path) for path in self.raw), exclude_paths=self.excludes),
            ),
            (
                self.footprint_baseline,
                _search_membership(self.footprint_roots, include_all_names=True),
            ),
        )
        for baseline, observed in observations:
            if set(observed) != set(baseline):
                return False
            for root, (digest, entries) in observed.items():
                old_digest, old_entries = baseline[root]
                if digest in {"missing", "not_directory"}:
                    return False
                old = dict(old_entries)
                current_entries = dict(entries)
                if any(current_entries.get(name) != target for name, target in old.items()):
                    return False
                if old_digest != "absent" and digest == "absent":
                    return False
                if (
                    old_digest == "absent"
                    and digest != "absent"
                    and Path(root) not in self.directories
                ):
                    return False
                for name, target in entries:
                    if name in old:
                        continue
                    path = Path(root) / name
                    if target or not (
                        path in self.files
                        and path.is_file()
                        or path in self.directories
                        and path.is_dir()
                    ):
                        return False
        return True


class _RuntimeInputValidator(InputValidator):
    def __init__(self, view: _RuntimeNamespaceView, owner: Any) -> None:
        from .code_index import _JobRuntimeOutputs

        if not isinstance(owner, _JobRuntimeOutputs) or view not in owner._views.values():
            raise ValueError("job_runtime_output_factory_validator_required")
        owner._issued()
        super().__init__(view.excludes)
        self.view = view
        self.owner = owner

    def searches(self, expected: Any) -> bool:
        # Reuse a genuine same-thread SQL frame, or acquire the real first
        # SQL gate. The namespace lock is never held while querying SQLite.
        with self.owner.binding():
            if not self.owner.native_current():
                return False
            with self.owner._lock:
                return self.view.current(expected)
