"""Canonical, answer-isolated benchmark runner for the bundled fixtures."""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re
import shutil
import stat
import statistics
import itertools
import subprocess
import sys
import tempfile
import tarfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import yaml

from zscope.benchmarking.protocol import (
    MATCHER_VERSION,
    aggregate_usage_ledger,
    candidate_funnel,
    score_report_views,
)
from zscope.benchmarking.isolation import (
    BenchmarkIsolationError,
    RootlessOciExecutor,
    oci_capability,
    require_release_isolation,
    sealed_runtime_source_sha256,
)
from zscope.benchmarking.policy import DEFAULT_BENCHMARK_POLICY
from zscope.benchmarking.p6_protocol import (
    P6ProtocolError,
    scan_regular_artifact_tree_for_canaries,
    validate_usage_conservation,
)
from zscope.benchmarking.provider_runtime import (
    P6_API_KEY_ENVIRONMENT_KEY,
    P6_MAX_CONTRACT_REGENERATIONS,
    P6_MAX_TRANSPORT_RETRIES,
    P6_PROVIDER_FAILURE_FILENAME,
    PROVIDER_FAILURE_CLASSES,
    PROVIDER_BASE_URL_ENVIRONMENT_KEY,
    PROVIDER_MODEL_ENVIRONMENT_KEY,
    ProviderRuntimeContract,
    ProviderRuntimeError,
    load_p6_provider_failure_marker,
    load_explicit_api_key_file,
    reject_conflicting_provider_identity_environment,
    require_p6_provider_contract,
    required_environment_keys,
)
from zscope.benchmarking.replay_bundle import write_validator_replay_bundle
from zscope.config.config import ConfigLoader
from zscope.framework.llm_usage import (
    LEGACY_USAGE_EVENT_SCHEMA_VERSION,
    PREVIOUS_USAGE_EVENT_SCHEMA_VERSION,
    TOKEN_USAGE_STAGES,
    USAGE_ATTRIBUTION_SCHEMA_VERSION,
    USAGE_EVENT_SCHEMA_VERSION,
    canonical_usage_stage,
)
from zscope.core.validation.authority import TerminalAuthorityEvaluator
from zscope.orchestration.decision_trace import (
    DECISION_TRACE_MANIFEST_VERSION,
    load_decision_trace,
    verify_coverage_trace,
    verify_evidence_object,
    verify_model_event,
)
from zscope.reporting.finding_roots import _has_complete_deterministic_proof


FORMAL_SCHEMA_VERSION = DEFAULT_BENCHMARK_POLICY.formal_schema_version
P6_ANSWER_FREE_PRODUCER_METRICS_SCHEMA_VERSION = "zscope.p6-answer-free-producer-metrics.v1"
MIN_FORMAL_RUNS = DEFAULT_BENCHMARK_POLICY.minimum_formal_trials
TRUTH_ENVIRONMENT_KEYS = {
    "Z_SCOPE_BENCHMARK_TRUTH",
    "Z_SCOPE_GROUND_TRUTH",
    "GROUND_TRUTH_PATH",
}
P6_CANDIDATE_COMMIT_ENVIRONMENT_KEY = "Z_SCOPE_P6_CANDIDATE_COMMIT"
C_GATES = dict(DEFAULT_BENCHMARK_POLICY.range_gates)
C_SEALED_GATES = dict(DEFAULT_BENCHMARK_POLICY.sealed_delta_gates)
_OCI_EXECUTOR_FACTORY = RootlessOciExecutor
_P6_RUNTIME_BOOTSTRAP = (
    "import runpy,sys;"
    "sys.path.insert(0,'/zscope-runtime');"
    "module=sys.argv.pop(1);"
    "runpy.run_module(module,run_name='__main__')"
)


def _container_scan_argv(container_python: str, *, mode: str) -> list[str]:
    return [
        container_python,
        *(
            ("-c", _P6_RUNTIME_BOOTSTRAP, "zscope.cli.cli")
            if mode == "pilot"
            else ("-m", "zscope.cli.cli")
        ),
        "-c",
        "/zscope-input/zscope.execution.yaml",
        "--verbose",
        *(("--p6-pilot",) if mode == "pilot" else ()),
    ]


class BenchmarkError(RuntimeError):
    """Raised when a benchmark invariant is not satisfied."""

    def __init__(self, message: str, *, failure_class: Optional[str] = None) -> None:
        self.failure_class = failure_class
        super().__init__(message)


class _P6ProtectedCanaryError(BenchmarkError):
    """Fixed, answer-free signal for a contaminated cold-producer attempt."""

    def __init__(self) -> None:
        super().__init__(
            "artifact_integrity_failure",
            failure_class="artifact_integrity_failure",
        )


def _p6_failure(failure_class: str, *, message: Optional[str] = None) -> BenchmarkError:
    """Construct an explicitly typed P6 boundary failure."""

    return BenchmarkError(message or failure_class, failure_class=failure_class)


def _provider_runtime_failure_class(
    error: ProviderRuntimeError,
    *,
    default: str,
) -> str:
    """Read only the typed attribute; provider exception text is never parsed."""

    failure_class = error.failure_class
    if failure_class in PROVIDER_FAILURE_CLASSES | {"provider_identity_override_attempt"}:
        return str(failure_class)
    return default


def _p6_scan_provider_failure_class(
    marker_path: Path,
    *,
    return_code: int,
) -> Optional[str]:
    """Validate the fixed scanner side channel without reading process output."""

    if not marker_path.exists() and not marker_path.is_symlink():
        return None
    try:
        marker = load_p6_provider_failure_marker(marker_path)
    except ProviderRuntimeError as exc:
        raise _p6_failure("oci_isolation_violation") from exc
    if return_code != 2:
        raise _p6_failure("oci_isolation_violation")
    return str(marker["failure_class"])


def _p6_scan_failure_class(
    marker_path: Path,
    *,
    return_code: int,
) -> Optional[str]:
    """Classify every non-successful P6 scanner boundary fail closed.

    Exit 1 is the normal findings-present report contract.  Exit 2 is accepted
    by the process wrapper only so a complete typed provider marker can be
    inspected without reading scanner output.  A marker-free exit 2 must never
    be archived as a completed cold producer: it means the scanner stopped
    before the sealed report/accounting boundary could be established.
    """

    provider_failure = _p6_scan_provider_failure_class(
        marker_path,
        return_code=return_code,
    )
    if provider_failure is not None:
        return provider_failure
    if return_code == 2:
        return "accounting_conservation_failure"
    return None


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


@dataclass(frozen=True)
class BenchmarkSpec:
    language: str
    fixture_relative: str
    required_tools: Tuple[str, ...]

    @property
    def fixture_root(self) -> Path:
        return repository_root() / self.fixture_relative

    @property
    def config_path(self) -> Path:
        return self.fixture_root / "zscope.benchmark.yaml"

    @property
    def truth_path(self) -> Path:
        return self.fixture_root / "benchmark" / "ground_truth.json"

    def truth_path_for_mode(self, mode: str) -> Path:
        """Select the governed scoring contract for one execution mode.

        Historical trial/formal v4 runs remain bound to the repository-root
        v15 truth.  P6 is a new, non-release qualification protocol and must
        consume the independently attested v16 contract instead of inheriting
        v15's static denominator and Arm-A release comparison.
        """

        if self.language == "c_cpp" and mode == "pilot":
            return self.fixture_root / "benchmark" / "v16" / "ground_truth.json"
        return self.truth_path


SPECS = {
    "c_cpp": BenchmarkSpec(
        language="c_cpp",
        fixture_relative="test/range",
        required_tools=(
            "cmake",
            "gcc",
            "clang",
            "clangd",
            "gclang",
            "get-bc",
            "llvm-link",
            "llvm-nm",
            "wpa",
            "saber",
        ),
    ),
    "java": BenchmarkSpec(
        language="java",
        fixture_relative="test/java_range",
        required_tools=("java", "mvn", "joern"),
    ),
}


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def prepare_p6_runtime_source(
    destination: Path,
    *,
    source_root: Optional[Path] = None,
    git_revision: Optional[str] = None,
) -> str:
    """Copy the complete candidate ``zscope`` package into a sealed tree.

    The copied tree deliberately excludes only interpreter caches.  Prompts,
    rule catalogs, schemas, policies, and every other runtime asset remain
    included and are bound by one canonical all-file digest.
    """

    target = Path(destination).resolve()
    if target.exists():
        raise _p6_failure(
            "input_binding_failure",
            message="p6_runtime_source_invalid",
        )
    target.mkdir(parents=True, mode=0o700)
    if source_root is None:
        try:
            revision = str(
                git_revision
                or subprocess.check_output(
                    ["git", "rev-parse", "HEAD"],
                    cwd=str(repository_root()),
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip()
            )
            if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
                raise _p6_failure(
                    "input_binding_failure",
                    message="p6_runtime_source_invalid",
                )
            object_type = subprocess.check_output(
                ["git", "cat-file", "-t", revision],
                cwd=str(repository_root()),
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            resolved_commit = subprocess.check_output(
                ["git", "rev-parse", "--verify", f"{revision}^{{commit}}"],
                cwd=str(repository_root()),
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            if object_type != "commit" or resolved_commit != revision:
                raise _p6_failure(
                    "input_binding_failure",
                    message="p6_runtime_source_invalid",
                )
            archived = subprocess.run(
                ["git", "archive", "--format=tar", revision, "--", "zscope"],
                cwd=str(repository_root()),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if archived.returncode != 0 or len(archived.stdout) > 128 * 1024 * 1024:
                raise _p6_failure(
                    "input_binding_failure",
                    message="p6_runtime_source_invalid",
                )
            total_size = 0
            with tarfile.open(fileobj=io.BytesIO(archived.stdout), mode="r:") as archive:
                for member in archive.getmembers():
                    parts = Path(member.name).parts
                    if (
                        not parts
                        or parts[0] != "zscope"
                        or any(part in {"", ".", ".."} for part in parts)
                        or member.issym()
                        or member.islnk()
                    ):
                        raise _p6_failure(
                            "input_binding_failure",
                            message="p6_runtime_source_invalid",
                        )
                    relative = Path(*parts[1:])
                    if member.isdir():
                        if relative.parts:
                            (target / relative).mkdir(parents=True, exist_ok=True)
                        continue
                    if not member.isreg() or not relative.parts:
                        raise _p6_failure(
                            "input_binding_failure",
                            message="p6_runtime_source_invalid",
                        )
                    source_handle = archive.extractfile(member)
                    if source_handle is None:
                        raise _p6_failure(
                            "input_binding_failure",
                            message="p6_runtime_source_invalid",
                        )
                    payload = source_handle.read(64 * 1024 * 1024 + 1)
                    total_size += len(payload)
                    if len(payload) != member.size or total_size > 64 * 1024 * 1024:
                        raise _p6_failure(
                            "input_binding_failure",
                            message="p6_runtime_source_invalid",
                        )
                    copied = target / relative
                    copied.parent.mkdir(parents=True, exist_ok=True)
                    copied.write_bytes(payload)
        except (OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
            raise _p6_failure(
                "input_binding_failure",
                message="p6_runtime_source_invalid",
            ) from exc
    else:
        source = Path(source_root).resolve()
        if not source.is_dir() or not (source / "__init__.py").is_file():
            raise _p6_failure(
                "input_binding_failure",
                message="p6_runtime_source_invalid",
            )
        try:
            for path in sorted(
                source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()
            ):
                relative = path.relative_to(source)
                metadata = path.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    raise _p6_failure(
                        "input_binding_failure",
                        message="p6_runtime_source_invalid",
                    )
                if stat.S_ISDIR(metadata.st_mode):
                    if "__pycache__" not in relative.parts:
                        (target / relative).mkdir(parents=True, exist_ok=True)
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    raise _p6_failure(
                        "input_binding_failure",
                        message="p6_runtime_source_invalid",
                    )
                if "__pycache__" in relative.parts or path.suffix.lower() in {".pyc", ".pyo"}:
                    continue
                copied = target / relative
                copied.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, copied)
        except OSError as exc:
            raise _p6_failure(
                "input_binding_failure",
                message="p6_runtime_source_invalid",
            ) from exc
    try:
        return sealed_runtime_source_sha256(target)
    except (OSError, BenchmarkIsolationError) as exc:
        raise _p6_failure(
            "input_binding_failure",
            message="p6_runtime_source_invalid",
        ) from exc


def _p6_provider_contract_for_execution(
    execution_config: Path, *, source_config: Path
) -> ProviderRuntimeContract:
    """Validate an execution config while retaining the frozen provider identity."""

    require_p6_provider_contract(execution_config)
    return require_p6_provider_contract(source_config)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_dump(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _load_json_object(path: Path) -> Dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise BenchmarkError(f"expected a JSON object: {path}")
    return value


def _allowed_fixture_file(language: str, relative: Path) -> bool:
    parts = relative.parts
    if language == "c_cpp":
        return relative.as_posix() in {"CMakeLists.txt", "README.md"} or bool(
            parts and parts[0] in {"src", "include", "internal"}
        )
    return relative.as_posix() in {"pom.xml", "README.md"} or bool(parts and parts[0] == "src")


def _fixture_source_files(source: Path, language: str) -> List[Path]:
    """Enumerate only public fixture roots; never walk ignored runtime directories."""

    roots = ("src", "include", "internal") if language == "c_cpp" else ("src",)
    root_files = (
        ("CMakeLists.txt", "README.md") if language == "c_cpp" else ("pom.xml", "README.md")
    )
    candidates = [source / name for name in root_files if (source / name).is_file()]
    for name in roots:
        directory = source / name
        if directory.is_dir():
            candidates.extend(path for path in directory.rglob("*") if path.is_file())
    return sorted(candidates, key=lambda path: path.relative_to(source).as_posix())


def _sanitized_java_entries(source: Path) -> Dict[str, Any]:
    raw = _load_json_object(source / "benchmark" / "entries.json")
    functions = raw.get("functions")
    if not isinstance(functions, list):
        raise BenchmarkError("Java benchmark entries.functions must be a list")
    forbidden = {"covers_rule_ids", "cwe", "cwes", "truth_id", "truth_ids", "audit_prompt"}
    sanitized: List[Dict[str, Any]] = []
    for index, item in enumerate(functions):
        if not isinstance(item, dict):
            raise BenchmarkError(f"Java benchmark entries.functions[{index}] must be an object")
        leaked = forbidden.intersection(item)
        if leaked:
            raise BenchmarkError(
                "Java runtime entries contain answer metadata: " + ", ".join(sorted(leaked))
            )
        sanitized.append(dict(item))
    return {
        "description": "Z-SCOPE Java benchmark runtime entry manifest (answer-free).",
        "functions": sanitized,
    }


def scan_input_manifest(root: Path) -> Dict[str, Any]:
    files = []
    entries = sorted(root.rglob("*"), key=str)
    if any(path.is_symlink() for path in entries):
        raise BenchmarkError("scan input contains a symbolic link")
    for path in (item for item in entries if item.is_file()):
        relative = path.relative_to(root).as_posix()
        files.append(
            {
                "path": relative,
                "size": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        )
    digest = _sha256_bytes(json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return {
        "schema_version": "zscope.benchmark-input.v1",
        "files": files,
        "file_count": len(files),
        "manifest_sha256": digest,
    }


def copy_scan_input(source: Path, destination: Path, language: str) -> Dict[str, Any]:
    """Copy only the declared public fixture surface into an isolated scan root."""

    source = source.resolve()
    if destination.exists():
        raise BenchmarkError(f"scan input already exists: {destination}")
    destination.mkdir(parents=True)
    for path in _fixture_source_files(source, language):
        if path.is_symlink():
            raise BenchmarkError("fixture scan input contains a symbolic link")
        try:
            path.resolve().relative_to(source)
        except ValueError as exc:
            raise BenchmarkError("fixture scan input escapes its root") from exc
        relative = path.relative_to(source)
        if not _allowed_fixture_file(language, relative):
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    if language == "java":
        _json_dump(destination / "entries.json", _sanitized_java_entries(source))
    manifest = scan_input_manifest(destination)
    for row in manifest["files"]:
        relative = Path(str(row["path"]))
        allowed = _allowed_fixture_file(language, relative) or (
            language == "java" and relative.as_posix() == "entries.json"
        )
        if not allowed:
            raise BenchmarkError(f"unexpected scan-input file: {relative.as_posix()}")
    return manifest


def restore_scan_input(root: Path, manifest: Mapping[str, Any]) -> None:
    """Remove run-generated files so archived scan-input remains the sealed initial input."""

    expected = {
        str(row["path"]): str(row["sha256"])
        for row in manifest.get("files", [])
        if isinstance(row, dict) and isinstance(row.get("path"), str)
    }
    for relative, digest in expected.items():
        path = root / relative
        if not path.is_file() or _sha256_file(path) != digest:
            raise BenchmarkError(f"scan modified sealed input file: {relative}")
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_symlink():
            raise BenchmarkError(f"scan created a symbolic link in sealed input: {path}")
        if path.is_file() and path.relative_to(root).as_posix() not in expected:
            path.unlink()
        elif path.is_dir():
            try:
                path.rmdir()
            except OSError:
                pass


def preview_scan_input(source: Path, language: str) -> Dict[str, Any]:
    files = [
        path.relative_to(source).as_posix() for path in _fixture_source_files(source, language)
    ]
    if language == "java":
        _sanitized_java_entries(source)
        files.append("entries.json")
    return {"files": files, "file_count": len(files)}


def _validate_truth(path: Path) -> Dict[str, Any]:
    truth = _load_json_object(path)
    vulnerabilities = truth.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise BenchmarkError(f"truth vulnerabilities must be a list: {path}")
    ids = [str(item.get("id") or "") for item in vulnerabilities if isinstance(item, dict)]
    if any(not item for item in ids) or len(ids) != len(vulnerabilities):
        raise BenchmarkError(f"every truth record must have an id: {path}")
    if len(set(ids)) != len(ids):
        raise BenchmarkError(f"truth ids must be unique: {path}")
    declared = truth.get("total_vulnerabilities")
    if declared is not None and declared != len(vulnerabilities):
        raise BenchmarkError(
            f"truth total_vulnerabilities={declared!r} != {len(vulnerabilities)}: {path}"
        )
    return truth


def _benchmark_environment(base: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    environment = dict(base or os.environ)
    for key in tuple(environment):
        upper = key.upper()
        if key in TRUTH_ENVIRONMENT_KEYS or "GROUND_TRUTH" in upper or "BENCHMARK_TRUTH" in upper:
            environment.pop(key, None)
    return environment


def _is_wsl() -> bool:
    if platform.system() != "Linux":
        return False
    try:
        release = platform.release().lower()
        version = Path("/proc/version").read_text(encoding="utf-8").lower()
    except OSError:
        version = ""
    return "microsoft" in release or "microsoft" in version


def _is_windows_mount_in_wsl(path: Path) -> bool:
    parts = path.resolve().parts
    return len(parts) >= 3 and parts[1] == "mnt" and len(parts[2]) == 1


def _benchmark_work_parent(language: str) -> Path:
    configured = os.environ.get("Z_SCOPE_BENCHMARK_WORK_ROOT", "").strip()
    if configured:
        parent = Path(configured).expanduser()
        if not parent.is_absolute():
            raise BenchmarkError("Z_SCOPE_BENCHMARK_WORK_ROOT must be an absolute path")
    elif _is_wsl():
        parent = Path("/tmp")
    else:
        parent = Path(tempfile.gettempdir())
    parent.mkdir(parents=True, exist_ok=True)
    parent = parent.resolve()
    if language == "c_cpp" and _is_wsl() and _is_windows_mount_in_wsl(parent):
        raise BenchmarkError(
            "C/C++ benchmark work root must use the WSL native filesystem, not /mnt/<drive>"
        )
    return parent


def _workspace_storage_class(path: Path) -> str:
    if _is_wsl():
        return "wsl_windows_mount" if _is_windows_mount_in_wsl(path) else "wsl_native"
    if platform.system() == "Linux":
        return "native_linux"
    return platform.system().lower() or "unknown"


def _write_execution_config(
    spec: BenchmarkSpec, scan_root: Path, path: Path, *, scan_depth: str = "fast"
) -> Dict[str, Any]:
    raw = yaml.safe_load(spec.config_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise BenchmarkError(f"benchmark config must be an object: {spec.config_path}")
    project = raw.setdefault("project", {})
    if not isinstance(project, dict):
        raise BenchmarkError("benchmark config project must be an object")
    project["root"] = scan_root.resolve().as_posix()
    project["source_root"] = "."
    scan = raw.setdefault("scan", {})
    if not isinstance(scan, dict):
        raise BenchmarkError("benchmark config scan must be an object")
    scan["depth"] = scan_depth
    if spec.language == "java":
        project["entry_functions_list"] = "entries.json"
    else:
        project.pop("entry_functions_list", None)
        project["compile_commands_path"] = "build/compile_commands.json"
    path.write_text(
        yaml.safe_dump(raw, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return raw


def _write_container_execution_config(source: Path, destination: Path) -> None:
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("project"), dict):
        raise BenchmarkError("benchmark config project must be an object")
    raw["project"]["root"] = "/zscope-cache/project"
    destination.write_text(
        yaml.safe_dump(raw, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def _validation_environment_value(key: str, environment: Mapping[str, str]) -> str:
    if key == P6_API_KEY_ENVIRONMENT_KEY or key.endswith("API_KEY"):
        return "benchmark-validation-no-network"
    if key == PROVIDER_BASE_URL_ENVIRONMENT_KEY:
        return str(environment.get(key) or "https://benchmark.invalid/v1")
    if key == PROVIDER_MODEL_ENVIRONMENT_KEY:
        return str(environment.get(key) or "benchmark-smoke")
    return str(environment.get(key) or "benchmark-validation")


def _validate_config(
    path: Path,
    *,
    smoke: bool,
    environment: Optional[Mapping[str, str]] = None,
) -> Any:
    source_environment = environment if environment is not None else os.environ
    referenced = required_environment_keys(path)
    missing = [key for key in referenced if not str(source_environment.get(key) or "").strip()]
    if missing and not smoke:
        raise BenchmarkError(
            "missing required benchmark environment: " + ", ".join(missing),
            failure_class="provider_credentials_unavailable",
        )
    keys = {key: _validation_environment_value(key, source_environment) for key in referenced}
    old = {key: os.environ.get(key) for key in referenced}
    try:
        for key, value in keys.items():
            os.environ[key] = value
        return ConfigLoader.load(str(path))
    finally:
        for key, old_value in old.items():
            if old_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old_value


def _command_sha256(argv: Sequence[str]) -> str:
    return _sha256_bytes(json.dumps(list(argv), separators=(",", ":")).encode("utf-8"))


def _run_command(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    log_path: Path,
    accepted_returncodes: Iterable[int] = (0,),
) -> float:
    started = time.monotonic()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.run(
            list(argv),
            cwd=str(cwd),
            env=dict(environment),
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
        )
    elapsed = time.monotonic() - started
    if process.returncode not in set(accepted_returncodes):
        raise BenchmarkError(f"command failed ({process.returncode}): {argv[0]}")
    return elapsed


def _tool_health(spec: BenchmarkSpec) -> Dict[str, Any]:
    checks = [
        {"tool": tool, "path": shutil.which(tool), "ok": shutil.which(tool) is not None}
        for tool in spec.required_tools
    ]
    return {"checks": checks, "ok": all(item["ok"] for item in checks)}


def _require_llm_environment(
    required_keys: Sequence[str],
    environment: Optional[Mapping[str, str]] = None,
) -> None:
    source = environment if environment is not None else os.environ
    missing = [key for key in required_keys if not str(source.get(key) or "").strip()]
    if missing:
        raise BenchmarkError(
            "missing required benchmark environment: " + ", ".join(missing),
            failure_class="provider_credentials_unavailable",
        )


def _build_fixture(spec: BenchmarkSpec, scan_root: Path, run_dir: Path) -> float:
    if spec.language == "c_cpp":
        build = scan_root / "build"
        started = time.monotonic()
        _run_command(
            ["cmake", "-S", str(scan_root), "-B", str(build), "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
            cwd=repository_root(),
            environment=_benchmark_environment(),
            log_path=run_dir / "configure.log",
        )
        _run_command(
            ["cmake", "--build", str(build), "--parallel", "2"],
            cwd=repository_root(),
            environment=_benchmark_environment(),
            log_path=run_dir / "build.log",
        )
        return time.monotonic() - started
    return _run_command(
        ["mvn", "-q", "-f", str(scan_root / "pom.xml"), "-DskipTests", "package"],
        cwd=repository_root(),
        environment=_benchmark_environment(),
        log_path=run_dir / "build.log",
    )


def _run_structural_smoke(spec: BenchmarkSpec, scan_root: Path, run_dir: Path) -> Dict[str, Any]:
    if spec.language == "c_cpp":
        output = run_dir / "deterministic-regression.json"
        argv = [
            sys.executable,
            "-m",
            "scripts.evaluate_range_regression",
            "--project-root",
            str(scan_root),
            "--entries",
            str(spec.fixture_root / "benchmark/deterministic_entries.json"),
            "--truth",
            str(spec.truth_path),
            "--candidate-backend",
            "regex",
            "--output",
            str(output),
        ]
        elapsed = _run_command(
            argv,
            cwd=repository_root(),
            environment=_benchmark_environment(),
            log_path=run_dir / "deterministic-regression.log",
        )
        result = _load_json_object(output)
        return {
            "kind": "deterministic_candidate_regression",
            "seconds": round(elapsed, 4),
            "issues": result.get("report_issue_count"),
            "missing_entry_impls": result.get("missing_entry_impls", []),
        }
    from zscope.core.candidates.java_rules import JavaRuleCandidateGenerator

    expected_payload = _load_json_object(
        spec.fixture_root / "benchmark/maintenance/entry_rule_coverage.json"
    )
    mapped = {
        rule_id
        for row in expected_payload.get("entries", [])
        if isinstance(row, dict)
        for rule_id in row.get("rule_ids", [])
        if isinstance(rule_id, str)
    }
    generated = set()
    generator = JavaRuleCandidateGenerator()
    for path in (scan_root / "src").rglob("*.java"):
        relative = path.relative_to(scan_root).as_posix()
        numbered = "\n".join(
            f"{line_number} | {line}"
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            )
        )
        for issue in generator.generate_issues(f"<project-file>:{relative}", numbered, relative):
            generated.add(str(issue.get("rule_id") or issue.get("rule") or ""))
    expected = {rule.rule_id for rule in JavaRuleCandidateGenerator._RULES}
    missing_mapping = sorted(expected - mapped)
    if missing_mapping:
        raise BenchmarkError(
            "Java maintenance mapping missed local rules: " + ", ".join(missing_mapping)
        )
    missing = sorted(expected - generated)
    if missing:
        raise BenchmarkError("Java structural smoke missed rules: " + ", ".join(missing))
    result = {
        "kind": "java_structural_rule_regression",
        "expected_rule_ids": len(expected),
        "generated_rule_ids": len(generated),
        "missing_rule_ids": missing,
    }
    _json_dump(run_dir / "structural-regression.json", result)
    return result


def _range_gates_for_depth(
    scan_depth: str,
    *,
    required_confirmed_tp: Optional[float] = None,
) -> Dict[str, Tuple[str, float]]:
    gates = dict(C_GATES)
    if required_confirmed_tp is not None:
        gates["median_confirmed_tp"] = (">=", float(required_confirmed_tp))
        gates["median_confirmed_recall"] = (">=", 0.85)
    expectations = DEFAULT_BENCHMARK_POLICY.range_depth_token_expectations[scan_depth]
    gates["median_tokens"] = ("<=", float(expectations["median_tokens"]))
    gates["per_run_tokens"] = ("<=", float(expectations["per_run_tokens"]))
    return gates


def _pilot_range_gates(scan_depth: str) -> Dict[str, Tuple[str, float]]:
    """Return the non-release quality/accounting gates for one P6 pilot."""

    gates = _range_gates_for_depth(scan_depth)
    selected = {
        name: contract
        for name, contract in gates.items()
        if name
        in {
            "median_tokens",
            "per_run_tokens",
            "provider_usage_coverage",
            "explicit_attribution_coverage",
            "queue_drained_rate",
            "token_conservation_rate",
            "telemetry_complete_rate",
            "protocol_anomaly_count",
        }
    }
    selected["median_with_review_recall"] = (">=", 0.85)
    return selected


def _gate_c(
    score: Dict[str, Any],
    *,
    scan_depth: str = "balanced",
    require_release_rule_qualification: bool = True,
) -> List[str]:
    """Evaluate only invariants that must hold on every cold Range run.

    Median quality, cross-run stability, and the Arm-A comparison belong to
    ``_aggregate``.  Treating those as per-run gates was the source of the
    historical 85-TP/6M contract drift.
    """

    per_run_names = {
        "per_run_tokens": "tokens",
        "provider_usage_coverage": "provider_usage_coverage",
        "explicit_attribution_coverage": "explicit_attribution_coverage",
        "protocol_anomaly_count": "protocol_anomaly_count",
        "telemetry_complete_rate": "telemetry_complete_rate",
    }
    depth_gates = _range_gates_for_depth(scan_depth)
    gates = {
        metric_name: depth_gates[gate_name] for gate_name, metric_name in per_run_names.items()
    }
    failures = _gate_metrics(score, gates)
    if score.get("queue_empty") is not True:
        failures.append("validation queue was not drained")
    if score.get("token_conservation_passed") is not True:
        failures.append("token accounting does not conserve totals")
    requirements = DEFAULT_BENCHMARK_POLICY.requirements
    usage = _as_dict(score.get("usage_accounting"))
    if requirements.get("require_provider_usage_for_release") and usage.get("complete") is not True:
        failures.append("provider usage accounting is incomplete")
    if (
        requirements.get("require_call_level_usage_events_for_release")
        and usage.get("source") != "response_usage_spans"
    ):
        failures.append("call-level LLM usage event ledger is missing")
    if (
        require_release_rule_qualification
        and requirements.get("require_qualified_default_rules_for_release")
        and int(score.get("default_enabled_unqualified_rule_count") or 0) > 0
    ):
        failures.append("default-enabled deterministic rules are not externally qualified")
    if (
        require_release_rule_qualification
        and requirements.get("require_qualified_default_rules_for_release")
        and score.get("rule_qualification_telemetry_present") is not True
    ):
        failures.append("rule qualification telemetry is missing")
    attribution = _as_dict(_as_dict(score.get("report_views")).get("default")).get("attribution")
    if requirements.get("require_explicit_finding_attribution") and (
        not isinstance(attribution, dict)
        or float(attribution.get("explicit_coverage") or 0.0) < 0.99
    ):
        failures.append("explicit finding attribution coverage is below 99%")
    return failures


def _gate_c_sealed(score: Dict[str, Any]) -> List[str]:
    return _gate_metrics(score, C_SEALED_GATES)


def _gate_metrics(score: Dict[str, Any], gates: Mapping[str, Tuple[str, float]]) -> List[str]:
    failures = []
    for key, (operator, threshold) in gates.items():
        try:
            value = float(score[key])
        except (KeyError, TypeError, ValueError):
            failures.append(f"missing numeric metric: {key}")
            continue
        if operator == ">=" and value < threshold:
            failures.append(f"{key}={value} < {threshold}")
        if operator == "<=" and value > threshold:
            failures.append(f"{key}={value} > {threshold}")
    return failures


def _performance_outliers(summaries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    outliers: List[Dict[str, Any]] = []
    series: Dict[str, List[float]] = {}
    for summary in summaries:
        metrics = summary.get("metrics", {})
        for metric in ("scan_wall_seconds", "end_to_end_wall_seconds"):
            value = metrics.get(metric)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                series.setdefault(metric, []).append(float(value))
        if "scan_wall_seconds" not in metrics:
            wall = metrics.get("wall_seconds")
            if isinstance(wall, (int, float)) and not isinstance(wall, bool):
                series.setdefault("wall_seconds", []).append(float(wall))
        for phase, value in summary.get("phase_seconds", {}).items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                series.setdefault(f"phase_seconds.{phase}", []).append(float(value))
    thresholds = {
        name: max(statistics.median(values) * 2.0, statistics.median(values) + 300.0)
        for name, values in series.items()
        if len(values) >= 3
    }
    for summary in summaries:
        metrics = summary.get("metrics", {})
        observed = {
            metric: metrics.get(metric)
            for metric in ("scan_wall_seconds", "end_to_end_wall_seconds")
            if metric in metrics
        }
        if "scan_wall_seconds" not in metrics:
            observed["wall_seconds"] = metrics.get("wall_seconds")
        observed.update(
            {
                f"phase_seconds.{phase}": value
                for phase, value in summary.get("phase_seconds", {}).items()
            }
        )
        for name, raw in observed.items():
            if isinstance(raw, (int, float)) and name in thresholds and raw > thresholds[name]:
                outliers.append(
                    {
                        "run": summary.get("run"),
                        "metric": name,
                        "value": round(float(raw), 4),
                        "threshold": round(thresholds[name], 4),
                    }
                )
    return outliers


def score_artifact(report_path: Path, truth_path: Path, output_path: Path) -> Dict[str, Any]:
    report = _load_json_object(report_path)
    truth = _validate_truth(truth_path)
    views = score_report_views(report, truth)
    usage_spans = _read_archived_usage_events(report_path.parent)
    usage_accounting = aggregate_usage_ledger(
        report,
        usage_spans=usage_spans if usage_spans is not None else None,
    )
    ledger_tokens = int(_as_dict(usage_accounting.get("totals")).get("total_tokens") or 0)
    default = views["default"]
    review = views["with_needs_review"]
    manifest = _as_dict(report.get("run_manifest"))
    summary = _as_dict(report.get("summary"))
    usage = _as_dict(summary.get("llm_usage"))
    attribution = _as_dict(default.get("attribution"))
    rule_catalog = _as_dict(
        report.get("rule_catalog") or _as_dict(report.get("metadata")).get("rule_catalog")
    )
    qualification_rows = _as_dict(rule_catalog.get("qualification")).get("rules")
    qualification_by_key = (
        {
            (str(row.get("rule_id") or ""), int(row.get("revision") or 0)): str(
                row.get("state") or "pending"
            )
            for row in qualification_rows or []
            if isinstance(row, dict)
        }
        if isinstance(qualification_rows, list)
        else {}
    )
    default_enabled_unqualified = 0
    rule_rows = rule_catalog.get("rules")
    rule_rows = rule_rows if isinstance(rule_rows, list) else []
    for row in rule_catalog.get("rules") or []:
        if (
            not isinstance(row, dict)
            or row.get("effective_status") != "enabled"
            or row.get("effective_reason") != "enabled_by_default"
        ):
            continue
        key = (str(row.get("id") or ""), int(row.get("revision") or 0))
        if qualification_by_key.get(key) != "qualified":
            default_enabled_unqualified += 1
    precision = float(default.get("actionable_precision") or 0.0)
    if precision <= 1.0:
        precision *= 100.0
    confirmed_recall = float(default.get("recall") or 0.0)
    confirmed_precision = float(default.get("actionable_precision") or 0.0)
    with_review_recall = float(review.get("recall") or 0.0)
    with_review_precision = float(review.get("actionable_precision") or 0.0)
    quality_views = {
        "confirmed": {
            "true_positives": int(default.get("true_positives") or 0),
            "false_negatives": int(default.get("false_negatives") or 0),
            "recall": confirmed_recall,
            "precision": confirmed_precision,
            "root_cause_precision": float(default.get("root_cause_precision") or 0.0),
        },
        "with_review": {
            "true_positives": int(review.get("true_positives") or 0),
            "false_negatives": int(review.get("false_negatives") or 0),
            "recall": with_review_recall,
            "precision": with_review_precision,
            "root_cause_precision": float(review.get("root_cause_precision") or 0.0),
        },
    }
    queue = _as_dict(summary.get("global_validation_queue"))
    source_kloc = float(
        _as_dict(report.get("metadata")).get("source_kloc") or manifest.get("source_kloc") or 0.0
    )
    scan_wall_seconds = summary.get("batch_wall_seconds")
    payload: Dict[str, Any] = {
        **default,
        "confirmed_tp": int(default.get("true_positives") or 0),
        "precision": round(precision, 6),
        "confirmed_recall": confirmed_recall,
        "confirmed_precision": confirmed_precision,
        "with_review_tp": int(review.get("true_positives") or 0),
        "with_review_raw_fp": int(review.get("false_positives_raw") or 0),
        "with_review_recall": with_review_recall,
        "with_review_precision": with_review_precision,
        "needs_review": int(manifest.get("needs_review_count") or 0),
        "tokens": ledger_tokens
        or int(summary.get("total_cumulative_total_tokens") or usage.get("total_tokens") or 0),
        "token_accounting_mode": (
            str(usage_accounting.get("source") or "usage_ledger")
            if usage_accounting.get("present")
            else "legacy_aggregate"
        ),
        "queue_empty": manifest.get("validation_queue_drained") is True,
        "provider_usage_coverage": float(usage_accounting.get("provider_usage_coverage") or 0.0),
        "token_conservation_passed": usage_accounting.get("conservation_passed") is True,
        "telemetry_complete_rate": float(usage_accounting.get("telemetry_complete") is True),
        "explicit_attribution_coverage": float(attribution.get("explicit_coverage") or 0.0),
        "protocol_anomaly_count": int(summary.get("validator_protocol_exhausted_count") or 0)
        + len(usage_accounting.get("errors") or []),
        "default_enabled_unqualified_rule_count": default_enabled_unqualified,
        "rule_qualification_telemetry_present": bool(rule_rows and qualification_by_key),
        "actionable_false_discovery_rate": float(
            default.get("actionable_false_discovery_rate") or 0.0
        ),
        "true_positive_truth_ids": list(default.get("matched") or []),
        "quality_views": quality_views,
        "performance_telemetry": {
            "validation_queue_wall_seconds": float(queue.get("duration_seconds") or 0.0),
            "validator_session_count": int(queue.get("validator_session_count") or 0),
            "validator_api_call_count": int(queue.get("validator_api_call_count") or 0),
            "batch_wall_seconds": float(scan_wall_seconds or 0.0),
            "report_tail_seconds": float(summary.get("report_tail_seconds") or 0.0),
            "llm_successful_call_wall_seconds_mean": float(
                usage.get("successful_call_wall_seconds_mean") or 0.0
            ),
            "llm_successful_call_wall_seconds_p50": float(
                usage.get("successful_call_wall_seconds_p50") or 0.0
            ),
            "llm_successful_call_wall_seconds_p95": float(
                usage.get("successful_call_wall_seconds_p95") or 0.0
            ),
            "llm_successful_call_wall_seconds_max": float(
                usage.get("successful_call_wall_seconds_max") or 0.0
            ),
        },
        "report_views": views,
        "candidate_funnel": candidate_funnel(report),
        "usage_accounting": usage_accounting,
        "benchmark_policy": DEFAULT_BENCHMARK_POLICY.as_dict(),
    }
    payload["source_kloc"] = round(source_kloc, 6)
    payload["tokens_per_kloc"] = (
        round(float(payload["tokens"]) / source_kloc, 6) if source_kloc > 0 else None
    )
    baseline = _as_dict(
        report.get("validator_arm_a_baseline") or manifest.get("validator_arm_a_baseline")
    )
    baseline_tokens = baseline.get("median_tokens")
    baseline_tp = baseline.get("median_confirmed_tp")
    if all(
        isinstance(value, (int, float)) and not isinstance(value, bool)
        for value in (baseline_tokens, baseline_tp)
    ):
        added_tp = int(payload["confirmed_tp"]) - int(float(baseline_tp or 0))
        added_tokens = int(payload["tokens"]) - int(float(baseline_tokens or 0))
        payload["marginal_tokens_per_added_tp"] = (
            round(max(0, added_tokens) / added_tp, 6) if added_tp > 0 else None
        )
    else:
        payload["marginal_tokens_per_added_tp"] = None
    if isinstance(scan_wall_seconds, (int, float)) and not isinstance(scan_wall_seconds, bool):
        payload["scan_wall_seconds"] = round(float(scan_wall_seconds), 6)
        # zscope.formal-benchmark.v2 compatibility: wall_seconds remains the C gate alias.
        payload["wall_seconds"] = payload["scan_wall_seconds"]
    for field in C_SEALED_GATES:
        if field in report:
            payload[field] = report[field]
        elif field in manifest:
            payload[field] = manifest[field]
    arm_a_fdr = report.get("validator_arm_a_actionable_false_discovery_rate")
    if arm_a_fdr is None:
        arm_a_fdr = manifest.get("validator_arm_a_actionable_false_discovery_rate")
    if isinstance(arm_a_fdr, (int, float)) and not isinstance(arm_a_fdr, bool):
        payload["actionable_fdr_delta_vs_arm_a_pp"] = round(
            (payload["actionable_false_discovery_rate"] - float(arm_a_fdr)) * 100.0,
            6,
        )
    arm_a_baseline = report.get("validator_arm_a_baseline")
    if arm_a_baseline is None:
        arm_a_baseline = manifest.get("validator_arm_a_baseline")
    if isinstance(arm_a_baseline, dict):
        payload["validator_arm_a_baseline"] = dict(arm_a_baseline)
    _json_dump(output_path, payload)
    return payload


def _run_release_eligible(
    mode: str, score: Mapping[str, Any], gate_failures: Sequence[str]
) -> bool:
    return mode == "formal" and score.get("queue_empty") is True and not gate_failures


def _truth_matcher_gate_failures(mode: str, score: Mapping[str, Any]) -> List[str]:
    if mode != "formal":
        return []
    matcher_version = str(_as_dict(score.get("scoring_contract")).get("matcher_version") or "")
    if matcher_version == MATCHER_VERSION:
        return []
    return [f"formal scorer requires {MATCHER_VERSION}; observed {matcher_version or 'missing'}"]


def _locate_report(scan_root: Path) -> Path:
    root = scan_root.resolve()
    for name in ("zscope_batch_report.json", "report.json"):
        candidate = scan_root / name
        if candidate.is_file():
            if candidate.is_symlink():
                raise BenchmarkError("scan report must not be a symbolic link")
            resolved = candidate.resolve()
            try:
                resolved.relative_to(root)
            except ValueError as exc:
                raise BenchmarkError("scan report escapes the isolated cache project") from exc
            return resolved
    raise BenchmarkError(f"scan did not produce a JSON report under {scan_root}")


_USAGE_EVENTS_ARCHIVE_NAME = "llm_usage_events.jsonl"
_DECISION_TRACE_MANIFEST_ARCHIVE_NAME = "decision_trace_manifest.json"
_DECISION_TRACE_DIRECTORY_NAMES = frozenset(
    {"decision_traces", "coverage_traces", "evidence_objects", "model_events"}
)
_USAGE_EVENT_FORBIDDEN_KEYS = frozenset(
    {
        "assistant_response",
        "messages",
        "model_output",
        "prompt",
        "prompts",
        "raw_request",
        "raw_response",
        "reasoning",
        "response",
        "content",
        "reasoning_content",
        "reasoning_text",
        "request_body",
        "response_body",
        "system_prompt",
        "thinking",
        "chain_of_thought",
        "user_prompt",
    }
)
_USAGE_EVENT_FIELDS_V1 = frozenset(
    {
        "schema_version",
        "sequence",
        "call_id",
        "reservation_id",
        "agent",
        "stage",
        "candidate_uid",
        "audit_unit_uid",
        "validation_cluster_uid",
        "llm_ref",
        "call_kind",
        "outcome",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "reserved_total_tokens",
        "provider_reported",
        "conservative_charge",
        "budget_violation",
        "attribution",
        "budget_stage",
        "model",
        "reason",
        "finish_reason",
        "cached_prompt_tokens",
        "reasoning_tokens",
        "retry",
        "repair",
        "tool_call_count",
        "new_fact_count",
        "duration_ms",
    }
)
_USAGE_EVENT_FIELDS_V2 = _USAGE_EVENT_FIELDS_V1.union(
    {"requested_model", "provider_response_model"}
)
_USAGE_EVENT_FIELDS_V3 = _USAGE_EVENT_FIELDS_V2.union(
    {"call_chain_id", "attempt_index", "logical_operation_id"}
)
_USAGE_ATTRIBUTION_FIELDS = frozenset(
    {
        "schema_version",
        "stage",
        "agent",
        "skill",
        "entry_identity",
        "audit_unit_uid",
        "candidate_uid",
        "finding_uid",
        "validation_cluster_uid",
        "llm_ref",
        "call_kind",
    }
)
_USAGE_EVENT_STRING_FIELDS = frozenset(
    {
        "call_id",
        "reservation_id",
        "agent",
        "stage",
        "candidate_uid",
        "audit_unit_uid",
        "validation_cluster_uid",
        "llm_ref",
        "call_kind",
        "outcome",
        "budget_stage",
        "model",
        "requested_model",
        "provider_response_model",
        "reason",
        "finish_reason",
    }
)
_USAGE_EVENT_BOOLEAN_FIELDS = frozenset(
    {
        "provider_reported",
        "conservative_charge",
        "budget_violation",
        "retry",
        "repair",
    }
)
_USAGE_EVENT_NON_NEGATIVE_INTEGER_FIELDS = frozenset(
    {
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "reserved_total_tokens",
        "cached_prompt_tokens",
        "reasoning_tokens",
        "tool_call_count",
        "new_fact_count",
        "duration_ms",
    }
)
_USAGE_EVENT_DUPLICATED_ATTRIBUTION_FIELDS = frozenset(
    {
        "agent",
        "candidate_uid",
        "audit_unit_uid",
        "validation_cluster_uid",
        "llm_ref",
        "call_kind",
    }
)


def _normalized_usage_key(value: Any) -> str:
    text = str(value or "")
    text = re.sub(r"(?<!^)(?=[A-Z])", "_", text)
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _sensitive_usage_keys(value: Any) -> set[str]:
    """Find prompt/response body keys at any nesting depth.

    The formal archive accepts one exact schema, but this recursive privacy
    check deliberately runs first so a payload hidden inside an unexpected
    extension cannot be mistaken for a harmless forward-compatible field.
    """

    found: set[str] = set()
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = _normalized_usage_key(key)
            if normalized in _USAGE_EVENT_FORBIDDEN_KEYS:
                found.add(normalized)
            found.update(_sensitive_usage_keys(nested))
    elif isinstance(value, list):
        for nested in value:
            found.update(_sensitive_usage_keys(nested))
    return found


def _require_exact_usage_fields(
    value: Mapping[str, Any],
    *,
    expected: frozenset[str],
    context: str,
) -> None:
    actual = set(value)
    missing = expected - actual
    unknown = actual - expected
    if missing or unknown:
        details: List[str] = []
        if missing:
            details.append("missing=" + ",".join(sorted(missing)))
        if unknown:
            details.append("unknown=" + ",".join(sorted(unknown)))
        raise BenchmarkError(f"{context} fields do not match v1: {'; '.join(details)}")


def _validate_usage_event_v1(raw: Mapping[str, Any], *, line_number: int) -> int:
    context = f"LLM usage event line {line_number}"
    forbidden = _sensitive_usage_keys(raw)
    if forbidden:
        raise BenchmarkError(
            "LLM usage events must not retain prompts, responses, or reasoning: "
            + ", ".join(sorted(forbidden))
        )
    schema_version = raw.get("schema_version")
    expected_fields = {
        LEGACY_USAGE_EVENT_SCHEMA_VERSION: _USAGE_EVENT_FIELDS_V1,
        PREVIOUS_USAGE_EVENT_SCHEMA_VERSION: _USAGE_EVENT_FIELDS_V2,
        USAGE_EVENT_SCHEMA_VERSION: _USAGE_EVENT_FIELDS_V3,
    }.get(str(schema_version), _USAGE_EVENT_FIELDS_V3)
    _require_exact_usage_fields(raw, expected=expected_fields, context=context)
    if schema_version not in {
        LEGACY_USAGE_EVENT_SCHEMA_VERSION,
        PREVIOUS_USAGE_EVENT_SCHEMA_VERSION,
        USAGE_EVENT_SCHEMA_VERSION,
    }:
        raise BenchmarkError(f"{context} has unsupported schema_version {raw['schema_version']!r}")

    for field in _USAGE_EVENT_STRING_FIELDS:
        if field not in raw:
            continue
        if not isinstance(raw[field], str):
            raise BenchmarkError(f"{context} field {field} must be a string")
    for field in _USAGE_EVENT_BOOLEAN_FIELDS:
        if not isinstance(raw[field], bool):
            raise BenchmarkError(f"{context} field {field} must be a boolean")
    for field in _USAGE_EVENT_NON_NEGATIVE_INTEGER_FIELDS:
        value = raw[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise BenchmarkError(f"{context} field {field} must be a non-negative integer")

    sequence = raw["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        raise BenchmarkError(f"{context} field sequence must be a positive integer")
    if not raw["call_id"]:
        raise BenchmarkError(f"{context} has no call_id")
    if not raw["outcome"]:
        raise BenchmarkError(f"{context} has no outcome")
    if (
        schema_version in {PREVIOUS_USAGE_EVENT_SCHEMA_VERSION, USAGE_EVENT_SCHEMA_VERSION}
        and raw["model"] != raw["requested_model"]
    ):
        raise BenchmarkError(f"{context} model does not match requested_model")
    if schema_version == USAGE_EVENT_SCHEMA_VERSION:
        chain_id = raw["call_chain_id"]
        attempt_index = raw["attempt_index"]
        operation_id = raw["logical_operation_id"]
        if (
            not isinstance(chain_id, str)
            or re.fullmatch(r"llm-call-chain-[1-9][0-9]*", chain_id) is None
            or isinstance(attempt_index, bool)
            or not isinstance(attempt_index, int)
            or attempt_index < 1
            or not isinstance(operation_id, str)
            or (operation_id and re.fullmatch(r"[0-9a-f]{64}", operation_id) is None)
        ):
            raise BenchmarkError(f"{context} transport lineage is invalid")

    attribution = raw["attribution"]
    if not isinstance(attribution, dict):
        raise BenchmarkError(f"{context} field attribution must be an object")
    _require_exact_usage_fields(
        attribution,
        expected=_USAGE_ATTRIBUTION_FIELDS,
        context=f"{context} attribution",
    )
    if attribution["schema_version"] != USAGE_ATTRIBUTION_SCHEMA_VERSION:
        raise BenchmarkError(
            f"{context} attribution has unsupported schema_version "
            f"{attribution['schema_version']!r}"
        )
    for field in _USAGE_ATTRIBUTION_FIELDS - {"schema_version"}:
        if not isinstance(attribution[field], str):
            raise BenchmarkError(f"{context} attribution field {field} must be a string")
    for field in _USAGE_EVENT_DUPLICATED_ATTRIBUTION_FIELDS:
        if raw[field] != attribution[field]:
            raise BenchmarkError(f"{context} field {field} does not match attribution.{field}")

    if raw["stage"] != raw["budget_stage"]:
        raise BenchmarkError(f"{context} stage does not match budget_stage")
    if raw["budget_stage"] not in TOKEN_USAGE_STAGES:
        raise BenchmarkError(f"{context} has unknown budget_stage {raw['budget_stage']!r}")
    if canonical_usage_stage(attribution["stage"]) != raw["budget_stage"]:
        raise BenchmarkError(f"{context} stage does not match attribution.stage")

    expected_call_id = raw["reservation_id"] or f"denied:{sequence}"
    if raw["call_id"] != expected_call_id:
        raise BenchmarkError(f"{context} call_id does not match its reservation/denial identity")
    if raw["total_tokens"] != raw["prompt_tokens"] + raw["completion_tokens"]:
        raise BenchmarkError(f"{context} token totals do not conserve")
    if raw["cached_prompt_tokens"] > raw["prompt_tokens"]:
        raise BenchmarkError(f"{context} cached_prompt_tokens exceeds prompt_tokens")
    if raw["reasoning_tokens"] > raw["completion_tokens"]:
        raise BenchmarkError(f"{context} reasoning_tokens exceeds completion_tokens")
    return int(sequence)


def _read_usage_events_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        raise BenchmarkError(f"LLM usage event sidecar is missing: {path}")
    if path.stat().st_size > 256 * 1024 * 1024:
        raise BenchmarkError("LLM usage event sidecar exceeds the 256 MiB audit limit")
    rows: List[Dict[str, Any]] = []
    call_ids: set[str] = set()
    sequences: set[int] = set()
    previous_sequence = 0
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise BenchmarkError(
                f"invalid LLM usage event JSON at line {line_number}: {exc}"
            ) from exc
        if not isinstance(raw, dict):
            raise BenchmarkError(f"LLM usage event line {line_number} is not an object")
        sequence = _validate_usage_event_v1(raw, line_number=line_number)
        call_id = raw["call_id"]
        if call_id in call_ids:
            raise BenchmarkError(f"duplicate LLM usage call_id: {call_id}")
        if sequence in sequences:
            raise BenchmarkError(f"duplicate LLM usage sequence: {sequence}")
        if sequence != previous_sequence + 1:
            raise BenchmarkError(
                "LLM usage event sequence must start at 1 and be contiguous in file order: "
                f"expected {previous_sequence + 1}, got {sequence}"
            )
        call_ids.add(call_id)
        sequences.add(sequence)
        previous_sequence = sequence
        rows.append(raw)
    if not rows:
        raise BenchmarkError("LLM usage event sidecar is empty")
    return rows


def _read_archived_usage_events(run_dir: Path) -> Optional[List[Dict[str, Any]]]:
    path = run_dir / _USAGE_EVENTS_ARCHIVE_NAME
    return _read_usage_events_jsonl(path) if path.is_file() else None


def _provider_model_identity_metrics(
    rows: Sequence[Mapping[str, Any]],
    *,
    expected_model: str,
    expected_response_model: Optional[str] = None,
    expected_response_models: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Aggregate response identity without substituting the requested model."""

    frozen_response_model = expected_response_model or expected_model
    frozen_response_models = {
        str(value).strip()
        for value in (expected_response_models or (frozen_response_model,))
        if str(value).strip()
    }
    successful = [row for row in rows if row.get("outcome") == "success"]
    requested_mismatch = 0
    missing = 0
    mismatch = 0
    present = 0
    response_model_counts = {model: 0 for model in sorted(frozen_response_models)}
    for row in successful:
        requested = str(row.get("requested_model") or row.get("model") or "").strip()
        response_model = str(row.get("provider_response_model") or "").strip()
        if requested != expected_model:
            requested_mismatch += 1
        if not response_model:
            missing += 1
            continue
        present += 1
        if response_model not in frozen_response_models:
            mismatch += 1
        else:
            response_model_counts[response_model] += 1
    count = len(successful)
    return {
        "provider_response_model_coverage": round(present / count if count else 0.0, 6),
        "provider_response_model_missing_count": missing,
        "provider_response_model_mismatch_count": mismatch,
        "requested_model_mismatch_count": requested_mismatch,
        "provider_response_model_successful_call_count": count,
        "provider_response_model_counts": response_model_counts,
        "provider_response_model_counts_conserved": bool(
            sum(response_model_counts.values()) == count and missing == 0 and mismatch == 0
        ),
    }


def _p6_admission_conservation(
    report: Mapping[str, Any],
    *,
    physical_call_count: int,
) -> Dict[str, Any]:
    """Project P6 admission accounting without turning denials into calls.

    The admission ledger is embedded in the frozen report while physical
    provider attempts come from the independently archived usage sidecar.
    Keeping those domains separate is essential: a soft/hard budget refusal
    is a zero-call control-plane event and must never reduce provider usage
    coverage or fabricate estimated/missing usage.
    """

    owners = (
        _as_dict(report.get("llm_usage")),
        _as_dict(_as_dict(report.get("metadata")).get("llm_usage")),
        _as_dict(_as_dict(report.get("summary")).get("llm_usage")),
        _as_dict(_as_dict(report.get("run_manifest")).get("llm_usage")),
    )
    snapshots = tuple(
        candidate
        for owner in owners
        for candidate in (owner, _as_dict(owner.get("scan_token_usage")))
        if candidate
    )
    snapshot = next(
        (value for value in snapshots if isinstance(value.get("p6_balanced_admission"), Mapping)),
        {},
    )
    admission = _as_dict(snapshot.get("p6_balanced_admission"))

    def count(name: str) -> int:
        value = admission.get(name)
        return int(value) if isinstance(value, int) and not isinstance(value, bool) else -1

    requests = count("request_count")
    admitted = count("admitted_request_count")
    denied = count("denied_request_count")
    active = snapshot.get("active_reservation_count")
    rejected = snapshot.get("rejected_before_model_count")
    active = int(active) if isinstance(active, int) and not isinstance(active, bool) else -1
    rejected = int(rejected) if isinstance(rejected, int) and not isinstance(rejected, bool) else -1
    raw_reasons = admission.get("denied_reasons")
    reasons = raw_reasons if isinstance(raw_reasons, Mapping) else {}
    reason_counts = {
        str(name): int(value)
        for name, value in reasons.items()
        if isinstance(name, str)
        and isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    }
    reason_conserved = bool(
        isinstance(raw_reasons, Mapping)
        and len(reason_counts) == len(raw_reasons)
        and sum(reason_counts.values()) == denied
    )
    request_conserved = bool(
        admission.get("request_conservation_passed") is True
        and requests >= 0
        and admitted >= 0
        and denied >= 0
        and requests == admitted + denied
    )
    # At finalization no reservation may remain in flight.  Every admitted
    # request is therefore either a physical archived call or an explicitly
    # counted pre-model rejection; denied admissions are not in either set.
    zero_call_denials = bool(
        active == 0 and rejected >= 0 and admitted == int(physical_call_count) + rejected
    )
    return {
        "enabled": admission.get("enabled") is True,
        "request_count": max(0, requests),
        "admitted_request_count": max(0, admitted),
        "denied_request_count": max(0, denied),
        "denied_reasons": dict(sorted(reason_counts.items())),
        "request_conservation_passed": request_conserved,
        "zero_call_denial_conservation_passed": zero_call_denials,
    }


def _p6_retry_conservation(
    report: Mapping[str, Any],
    *,
    usage_rows: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Prove bounded transport retry and contract regeneration per call chain.

    Physical attempts are independently archived in the usage JSONL.  HTTP
    rejections proven to occur before model execution remain zero-token events,
    but their content-free chain/attempt lineage is retained in the scan ledger
    embedded in the frozen report.  Combining both sources prevents a sequence
    of rejected attempts from disappearing from the retry proof.
    """

    owners = (
        _as_dict(report.get("llm_usage")),
        _as_dict(_as_dict(report.get("metadata")).get("llm_usage")),
        _as_dict(_as_dict(report.get("summary")).get("llm_usage")),
        _as_dict(_as_dict(report.get("run_manifest")).get("llm_usage")),
    )
    snapshots = tuple(
        candidate
        for owner in owners
        for candidate in (owner, _as_dict(owner.get("scan_token_usage")))
        if candidate
    )
    snapshot = next(
        (value for value in snapshots if isinstance(value.get("p6_balanced_admission"), Mapping)),
        {},
    )
    raw_rejections = snapshot.get("rejected_before_model_attempts")
    rejections = raw_rejections if isinstance(raw_rejections, list) else []
    expected_rejection_count = snapshot.get("rejected_before_model_count")
    expected_rejection_count = (
        int(expected_rejection_count)
        if isinstance(expected_rejection_count, int)
        and not isinstance(expected_rejection_count, bool)
        else -1
    )

    attempts: Dict[str, Dict[int, str]] = {}
    contract_chains: Dict[str, set[str]] = {}
    valid = True

    def add_attempt(
        *,
        chain_id: Any,
        attempt_index: Any,
        source: str,
        call_kind: Any,
        operation_id: Any,
    ) -> None:
        nonlocal valid
        if (
            not isinstance(chain_id, str)
            or re.fullmatch(r"llm-call-chain-[1-9][0-9]*", chain_id) is None
            or isinstance(attempt_index, bool)
            or not isinstance(attempt_index, int)
            or attempt_index < 1
        ):
            valid = False
            return
        chain = attempts.setdefault(chain_id, {})
        if attempt_index in chain:
            valid = False
            return
        chain[attempt_index] = source
        if call_kind == "contract_regeneration":
            if (
                not isinstance(operation_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", operation_id) is None
            ):
                valid = False
                return
            contract_chains.setdefault(operation_id, set()).add(chain_id)

    for row in usage_rows:
        if row.get("schema_version") != USAGE_EVENT_SCHEMA_VERSION:
            valid = False
            continue
        add_attempt(
            chain_id=row.get("call_chain_id"),
            attempt_index=row.get("attempt_index"),
            source="physical",
            call_kind=row.get("call_kind"),
            operation_id=row.get("logical_operation_id"),
        )
        if row.get("retry") is not (row.get("attempt_index") != 1):
            valid = False

    rejection_reasons: Dict[str, int] = {}
    for row in rejections:
        if not isinstance(row, Mapping) or set(row) != {
            "call_chain_id",
            "attempt_index",
            "logical_operation_id",
            "call_kind",
            "reason",
        }:
            valid = False
            continue
        reason = row.get("reason")
        if not isinstance(reason, str) or not reason:
            valid = False
            continue
        rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1
        add_attempt(
            chain_id=row.get("call_chain_id"),
            attempt_index=row.get("attempt_index"),
            source="pre_model_rejection",
            call_kind=row.get("call_kind"),
            operation_id=row.get("logical_operation_id"),
        )

    declared_reasons = snapshot.get("rejected_before_model_reasons")
    if (
        expected_rejection_count != len(rejections)
        or not isinstance(declared_reasons, Mapping)
        or dict(sorted(rejection_reasons.items())) != dict(sorted(declared_reasons.items()))
    ):
        valid = False

    max_attempt = 0
    retry_count = 0
    for indices in attempts.values():
        highest = max(indices, default=0)
        max_attempt = max(max_attempt, highest)
        retry_count += max(0, highest - 1)
        if set(indices) != set(range(1, highest + 1)):
            valid = False
        if highest > P6_MAX_TRANSPORT_RETRIES + 1:
            valid = False

    max_regenerations = max((len(value) for value in contract_chains.values()), default=0)
    regeneration_conserved = max_regenerations <= P6_MAX_CONTRACT_REGENERATIONS
    return {
        "maximum_transport_retries": P6_MAX_TRANSPORT_RETRIES,
        "maximum_contract_regenerations": P6_MAX_CONTRACT_REGENERATIONS,
        "logical_call_chain_count": len(attempts),
        "physical_attempt_count": len(usage_rows),
        "pre_model_rejection_count": len(rejections),
        "transport_retry_count": retry_count,
        "maximum_observed_attempt_index": max_attempt,
        "contract_regeneration_operation_count": len(contract_chains),
        "maximum_observed_contract_regenerations": max_regenerations,
        "call_chain_conservation_passed": valid,
        "contract_regeneration_conservation_passed": regeneration_conserved,
        "passed": valid and regeneration_conserved,
    }


def _p6_usage_conservation(
    *,
    report: Mapping[str, Any],
    score: Mapping[str, Any],
    usage_rows: Sequence[Mapping[str, Any]],
    model_identity: Mapping[str, Any],
    decision_trace_artifact: Optional[Mapping[str, Any]],
    expected_model: str,
    expected_response_model: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the answer-free P6 physical conservation projection.

    Every numerator and denominator is obtained independently: persisted
    response events versus the ledger, archived traces versus report clusters,
    terminal records versus report clusters, and projected finding roots versus
    the manifest declaration.  No Truth or expected result participates.
    """

    usage = _as_dict(score.get("usage_accounting"))
    totals = _as_dict(usage.get("totals"))
    physical_calls = int(usage.get("call_count") or 0)
    provider_calls = int(usage.get("provider_reported_call_count") or 0)
    explicit_estimated = int(totals.get("estimated_or_conservative_calls") or 0)
    estimated_calls = max(explicit_estimated, physical_calls - provider_calls)
    successful_calls = int(model_identity.get("provider_response_model_successful_call_count") or 0)
    requested_mismatches = int(model_identity.get("requested_model_mismatch_count") or 0)

    report_clusters: set[str] = set()
    finding_roots: set[str] = set()
    for collection_name in ("issues", "issues_with_needs_review", "candidate_terminal_states"):
        collection = report.get(collection_name)
        if not isinstance(collection, list):
            continue
        for raw in collection:
            if not isinstance(raw, Mapping):
                continue
            cluster_uid = str(raw.get("validation_cluster_uid") or "")
            if cluster_uid:
                report_clusters.add(cluster_uid)
            if collection_name != "candidate_terminal_states":
                root_uid = str(raw.get("finding_root_uid") or "")
                if root_uid:
                    finding_roots.add(root_uid)

    terminal_clusters = {
        str(raw.get("validation_cluster_uid") or "")
        for raw in report.get("candidate_terminal_states") or []
        if isinstance(raw, Mapping)
        and str(raw.get("validation_cluster_uid") or "")
        and str(raw.get("terminal_event_uid") or "")
        and str(raw.get("terminal_authority") or "")
    }
    manifest = _as_dict(report.get("run_manifest"))
    trace_count = int(_as_dict(decision_trace_artifact).get("trace_count") or 0)
    manifest_root_count = int(manifest.get("finding_root_count") or 0)
    row_tokens = sum(int(row.get("total_tokens") or 0) for row in usage_rows)
    row_tools = sum(int(row.get("tool_call_count") or 0) for row in usage_rows)

    def dimension(numerator: int, denominator: int, *, complete: bool = True) -> Dict[str, Any]:
        return {
            "numerator": numerator,
            "denominator": denominator,
            "conserved": complete and numerator == denominator,
        }

    return {
        "physical_call_count": physical_calls,
        "provider_reported_call_count": provider_calls,
        "estimated_call_count": estimated_calls,
        "provider_usage_coverage": float(usage.get("provider_usage_coverage") or 0.0),
        "requested_model": expected_model,
        "requested_model_coverage": round(
            (
                (successful_calls - requested_mismatches) / successful_calls
                if successful_calls
                else 0.0
            ),
            6,
        ),
        "response_model": expected_response_model or expected_model,
        "response_model_coverage": float(
            model_identity.get("provider_response_model_coverage") or 0.0
        ),
        "queue_empty": score.get("queue_empty") is True,
        "dimensions": {
            "token": dimension(int(totals.get("total_tokens") or 0), row_tokens),
            "tool": dimension(int(totals.get("tool_call_count") or 0), row_tools),
            "trace": dimension(
                trace_count,
                len(report_clusters),
                complete=bool(
                    decision_trace_artifact and decision_trace_artifact.get("complete") is True
                ),
            ),
            "finding": dimension(manifest_root_count, len(finding_roots)),
            "terminal": dimension(len(terminal_clusters), len(report_clusters)),
        },
    }


def _archived_decision_trace_artifact(report: Mapping[str, Any], run_dir: Path) -> Dict[str, Any]:
    """Revalidate the archived answer-free trace manifest used by P6 accounting."""

    manifest_owner = _as_dict(report.get("run_manifest"))
    raw = manifest_owner.get("decision_trace_artifact")
    if not isinstance(raw, Mapping):
        raw = _as_dict(report.get("metadata")).get("decision_trace_artifact")
    if not isinstance(raw, Mapping) or set(raw) != {
        "schema_version",
        "path",
        "sha256",
        "manifest_sha256",
        "trace_count",
        "coverage_trace_count",
        "evidence_object_count",
        "model_event_count",
        "complete",
        "answer_free",
    }:
        raise BenchmarkError("answer-free decision-trace artifact is missing")
    if (
        raw.get("schema_version") != "zscope.decision-trace-artifact.v1"
        or raw.get("path") != _DECISION_TRACE_MANIFEST_ARCHIVE_NAME
        or raw.get("complete") is not True
        or raw.get("answer_free") is not True
    ):
        raise BenchmarkError("answer-free decision-trace artifact is invalid")
    path = run_dir / _DECISION_TRACE_MANIFEST_ARCHIVE_NAME
    if path.is_symlink() or not path.is_file() or _sha256_file(path) != raw.get("sha256"):
        raise BenchmarkError("answer-free decision-trace artifact digest is invalid")
    manifest = _load_json_object(path)
    supplied = str(manifest.get("manifest_sha256") or "")
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    if (
        manifest.get("schema_version") != DECISION_TRACE_MANIFEST_VERSION
        or supplied != _canonical_object_sha256(unsigned)
        or supplied != raw.get("manifest_sha256")
        or manifest.get("complete") is not True
        or int(manifest.get("trace_count") or 0) != int(raw.get("trace_count") or 0)
        or int(manifest.get("coverage_trace_count") or 0)
        != int(raw.get("coverage_trace_count") or 0)
        or int(manifest.get("evidence_object_count") or 0)
        != int(raw.get("evidence_object_count") or 0)
        or int(manifest.get("model_event_count") or 0) != int(raw.get("model_event_count") or 0)
    ):
        raise BenchmarkError("answer-free decision-trace manifest is invalid")
    return dict(raw)


_P6_V4_POLICY_FIELDS = (
    "terminal_authority_decision",
    "proof_kernel_input",
    "proof_kernel_live_selected_action_uids",
    "proof_kernel_artifact_refs",
    "proof_kernel_checker_results",
    "proof_kernel_checker_result_refs",
    "proof_kernel_frozen_state",
    "proof_kernel_closure_evaluation",
    "proof_kernel_promotion_certificate",
    "proof_kernel_root_manifest_sha256",
    "proof_kernel_terminal_authority_decision",
)


def _p6_terminal_authority_conservation(
    *,
    report: Mapping[str, Any],
    run_dir: Path,
    usage_rows: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Reverify v4 terminal authority and post-terminal call conservation.

    The projection is reconstructed from the archived report, hash-chained
    decision traces, content-addressed policy evidence and the physical usage
    ledger.  No producer-declared aggregate or score participates.
    """

    raw_terminal = report.get("candidate_terminal_states")
    if not isinstance(raw_terminal, list) or any(
        not isinstance(item, Mapping) for item in raw_terminal
    ):
        raise BenchmarkError("candidate terminal state archive is malformed")
    terminal_items = [dict(item) for item in raw_terminal]
    by_cluster: Dict[str, Dict[str, Any]] = {}
    for item in terminal_items:
        cluster_uid = str(item.get("validation_cluster_uid") or "")
        if not cluster_uid or cluster_uid in by_cluster:
            raise BenchmarkError("candidate terminal cluster identity is invalid")
        by_cluster[cluster_uid] = item

    manifest_owner = _as_dict(report.get("run_manifest"))
    artifact = _as_dict(manifest_owner.get("decision_trace_artifact"))
    manifest_name = str(artifact.get("path") or "")
    if Path(manifest_name).name != manifest_name or not manifest_name:
        raise BenchmarkError("decision-trace manifest archive identity is invalid")
    manifest = _load_json_object(run_dir / manifest_name)
    trace_rows = manifest.get("traces")
    if not isinstance(trace_rows, Mapping) or set(trace_rows) != set(by_cluster):
        raise BenchmarkError("terminal report and decision traces do not conserve")

    usage_call_ids = [str(row.get("call_id") or "") for row in usage_rows]
    if any(not value for value in usage_call_ids) or len(usage_call_ids) != len(
        set(usage_call_ids)
    ):
        raise BenchmarkError("physical usage call identities are invalid")
    traced_call_ids: list[str] = []
    traced_tool_call_ids: list[str] = []
    referenced_model_digests: set[str] = set()
    post_terminal_call_ids: list[str] = []
    post_terminal_tool_call_ids: list[str] = []
    confirmed = [
        item
        for item in terminal_items
        if str(item.get("candidate_disposition") or "").lower() == "confirmed"
        and str(item.get("record_role") or "") != "operational_obligation"
    ]
    confirmed_report_v4_count = sum(_has_complete_deterministic_proof(item) for item in confirmed)
    confirmed_trace_v4_count = 0

    for cluster_uid, item in sorted(by_cluster.items()):
        trace_row = trace_rows[cluster_uid]
        if not isinstance(trace_row, Mapping):
            raise BenchmarkError("decision-trace manifest row is malformed")
        relative = str(trace_row.get("path") or "")
        trace_path = _safe_trace_source_path(run_dir, relative, context="archived decision trace")
        trace = load_decision_trace(trace_path)
        if (
            str(trace.get("validation_cluster_uid") or "") != cluster_uid
            or str(trace.get("document_sha256") or "")
            != str(item.get("decision_trace_sha256") or "")
            or relative != str(item.get("decision_trace_ref") or "")
            or str(trace.get("terminal_event_uid") or "")
            != str(item.get("terminal_event_uid") or "")
        ):
            raise BenchmarkError("terminal report-to-trace binding is invalid")
        events = trace.get("events")
        if not isinstance(events, list) or any(not isinstance(event, Mapping) for event in events):
            raise BenchmarkError("archived decision trace events are malformed")
        disposition = str(item.get("candidate_disposition") or "").lower()
        original_disposition = str(item.get("finding_root_original_disposition") or "").lower()
        proven_alias = bool(
            disposition == "deduplicated_alias"
            and original_disposition in {"confirmed", "rejected_with_proof"}
        )
        proof_disposition = original_disposition if proven_alias else disposition
        proof_terminal = proof_disposition in {"confirmed", "rejected_with_proof"}
        transition_fields = {
            "terminal_transition_event_uid": str(item.get("terminal_transition_event_uid") or ""),
            "terminal_transition_event_hash": str(item.get("terminal_transition_event_hash") or ""),
            "terminal_transition_authority_sha256": str(
                item.get("terminal_transition_authority_sha256") or ""
            ),
            "terminal_transition_level": str(item.get("terminal_transition_level") or ""),
            "terminal_transition_disposition": str(
                item.get("terminal_transition_disposition") or ""
            ),
        }
        if proof_terminal:
            if (
                transition_fields["terminal_transition_event_uid"]
                != str(trace.get("terminal_transition_event_uid") or "")
                or transition_fields["terminal_transition_event_hash"]
                != str(trace.get("terminal_transition_event_hash") or "")
                or transition_fields["terminal_transition_authority_sha256"]
                != str(trace.get("terminal_transition_authority_sha256") or "")
                or transition_fields["terminal_transition_level"]
                != str(trace.get("terminal_transition_level") or "")
                or transition_fields["terminal_transition_disposition"]
                != str(trace.get("terminal_transition_disposition") or "")
                or transition_fields["terminal_transition_level"] not in {"V0", "V1", "V2", "V3"}
                or transition_fields["terminal_transition_disposition"] != proof_disposition
                or transition_fields["terminal_transition_authority_sha256"]
                != _canonical_object_sha256(_as_dict(item.get("terminal_authority_decision")))
            ):
                raise BenchmarkError("proof terminal transition binding is invalid")
        elif any(transition_fields.values()):
            raise BenchmarkError("non-proof terminal declares a proof transition")
        terminal_uid = str(trace.get("terminal_event_uid") or "")
        if proof_terminal and terminal_uid != transition_fields["terminal_transition_event_uid"]:
            raise BenchmarkError("proof terminal boundary moved during finalization")
        terminal_indexes = [
            index
            for index, event in enumerate(events)
            if str(event.get("event_uid") or "") == terminal_uid
        ]
        if len(terminal_indexes) != 1:
            raise BenchmarkError("decision trace has no unique terminal event")
        terminal_index = terminal_indexes[0]
        terminal_event = events[terminal_index]
        if (
            terminal_event.get("stage") != "policy"
            or terminal_event.get("actor") != "terminal_authority_evaluator"
            or str(terminal_event.get("disposition_after") or "").lower() != proof_disposition
        ):
            raise BenchmarkError("decision trace terminal authority event is invalid")
        if proof_terminal:
            details = terminal_event.get("details")
            details = details if isinstance(details, Mapping) else {}
            archived_authority = _as_dict(item.get("terminal_authority_decision"))
            if (
                str(terminal_event.get("event_hash") or "")
                != transition_fields["terminal_transition_event_hash"]
                or str(details.get("terminal_transition_level") or "")
                != transition_fields["terminal_transition_level"]
                or str(details.get("terminal_authority_sha256") or "")
                != transition_fields["terminal_transition_authority_sha256"]
                or set(details) != {"terminal_transition_level", "terminal_authority_sha256"}
                or str(terminal_event.get("reason_code") or "")
                != str(archived_authority.get("reason_code") or "")
                or list(terminal_event.get("call_ids") or [])
                or list(terminal_event.get("tool_call_ids") or [])
                or int(terminal_event.get("token_delta") or 0) != 0
            ):
                raise BenchmarkError("proof terminal transition event is invalid")

        for index, event in enumerate(events):
            calls = [str(value) for value in event.get("call_ids") or [] if str(value)]
            tools = [str(value) for value in event.get("tool_call_ids") or [] if str(value)]
            traced_call_ids.extend(calls)
            traced_tool_call_ids.extend(tools)
            for ref in event.get("output_refs") or []:
                value = str(ref or "")
                if value.startswith("model_events/") and value.endswith(".json"):
                    referenced_model_digests.add(Path(value).stem)
            if index > terminal_index:
                post_terminal_call_ids.extend(calls)
                post_terminal_tool_call_ids.extend(tools)
                if int(event.get("token_delta") or 0) != 0:
                    raise BenchmarkError("decision trace records tokens after terminal authority")

        if not proof_terminal:
            continue
        policy_refs = [
            str(value)
            for value in terminal_event.get("input_refs") or []
            if str(value).startswith("evidence_objects/")
        ]
        if len(policy_refs) != 1:
            raise BenchmarkError("proof terminal has no unique policy evidence")
        evidence_path = _safe_trace_source_path(
            run_dir, policy_refs[0], context="terminal policy evidence"
        )
        valid_evidence, _ = verify_evidence_object(evidence_path)
        evidence = _load_json_object(evidence_path)
        if (
            not valid_evidence
            or evidence_path.stem != str(evidence.get("sha256") or "")
            or evidence.get("kind") != "terminal_policy_input"
            or evidence.get("producer") != "terminal_authority_evaluator"
        ):
            raise BenchmarkError("proof terminal policy evidence is invalid")
        payload = evidence.get("payload")
        if not isinstance(payload, Mapping):
            raise BenchmarkError("proof terminal policy payload is invalid")
        if any(payload.get(field) != item.get(field) for field in _P6_V4_POLICY_FIELDS):
            raise BenchmarkError("proof terminal report and policy evidence disagree")
        policy_carrier = dict(payload)
        state_projection = payload.get("issue")
        if isinstance(state_projection, Mapping):
            policy_carrier.update(state_projection)
        projected_authority = (
            TerminalAuthorityEvaluator()
            .evaluate(
                policy_carrier,
                operation="audit",
            )
            .to_dict()
        )
        if projected_authority != _as_dict(item.get("terminal_authority_decision")):
            raise BenchmarkError("proof trace does not reverify TerminalAuthority v4")
        if disposition == "confirmed":
            if not _has_complete_deterministic_proof(policy_carrier):
                raise BenchmarkError("confirmed trace does not reverify promotion")
            confirmed_trace_v4_count += 1

    coverage_rows = manifest.get("coverage_traces")
    if not isinstance(coverage_rows, Mapping):
        raise BenchmarkError("decision-trace coverage manifest is malformed")
    for audit_uid, raw_row in sorted(coverage_rows.items()):
        if not isinstance(raw_row, Mapping):
            raise BenchmarkError("decision-trace coverage row is malformed")
        relative = str(raw_row.get("path") or "")
        path = _safe_trace_source_path(run_dir, relative, context="archived coverage trace")
        valid, _ = verify_coverage_trace(_load_json_object(path))
        coverage_value = _load_json_object(path)
        if (
            not valid
            or str(coverage_value.get("audit_unit_uid") or "") != str(audit_uid)
            or str(coverage_value.get("document_sha256") or "")
            != str(raw_row.get("document_sha256") or "")
        ):
            raise BenchmarkError("archived coverage trace is invalid")
        events = coverage_value.get("events")
        if not isinstance(events, list) or any(not isinstance(event, Mapping) for event in events):
            raise BenchmarkError("archived coverage events are malformed")
        for event in events:
            traced_call_ids.extend(
                str(call_id) for call_id in event.get("call_ids") or [] if str(call_id)
            )

    if len(traced_call_ids) != len(set(traced_call_ids)):
        raise BenchmarkError("decision trace duplicates physical call identities")
    call_trace_conserved = set(traced_call_ids) == set(usage_call_ids)
    tool_usage_count = sum(int(row.get("tool_call_count") or 0) for row in usage_rows)
    tool_trace_conserved = (
        len(traced_tool_call_ids) == len(set(traced_tool_call_ids))
        and len(traced_tool_call_ids) == tool_usage_count
    )
    model_digests = manifest.get("model_event_sha256")
    if not isinstance(model_digests, list) or any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in model_digests
    ):
        raise BenchmarkError("decision-trace model-event identities are invalid")
    model_trace_conserved = referenced_model_digests == set(model_digests)
    for digest in model_digests:
        path = _safe_trace_source_path(
            run_dir,
            f"model_events/{digest}.json",
            context="archived model event",
        )
        valid, _ = verify_model_event(path)
        model_value = _load_json_object(path)
        if (
            not valid
            or path.stem != str(model_value.get("sha256") or "")
            or str(model_value.get("validation_cluster_uid") or "") not in by_cluster
        ):
            raise BenchmarkError("archived model event is invalid")

    passed = bool(
        confirmed_report_v4_count == len(confirmed)
        and confirmed_trace_v4_count == len(confirmed)
        and not post_terminal_call_ids
        and not post_terminal_tool_call_ids
        and call_trace_conserved
        and tool_trace_conserved
        and model_trace_conserved
    )
    return {
        "terminal_trace_count": len(by_cluster),
        "confirmed_terminal_count": len(confirmed),
        "confirmed_v4_report_count": confirmed_report_v4_count,
        "confirmed_v4_trace_count": confirmed_trace_v4_count,
        "post_terminal_model_call_count": len(post_terminal_call_ids),
        "post_terminal_tool_call_count": len(post_terminal_tool_call_ids),
        "call_trace_conservation_passed": call_trace_conserved,
        "tool_trace_conservation_passed": tool_trace_conserved,
        "model_event_trace_conservation_passed": model_trace_conserved,
        "passed": passed,
    }


def build_p6_answer_free_producer_metrics(
    *,
    report_path: Path,
    run_dir: Path,
    provider_contract: ProviderRuntimeContract,
) -> Dict[str, Any]:
    """Deterministically recompute P6 producer metrics without loading Truth.

    Only the frozen report and its already archived usage/trace sidecars are
    inputs.  Callers cannot supply usage totals, model identity, queue state,
    or conservation results.
    """

    report = _load_json_object(report_path)
    if report.get("answer_material_present") is not False:
        raise BenchmarkError("answer-free producer report is not answer isolated")
    usage_rows = _read_archived_usage_events(run_dir)
    if not usage_rows:
        raise BenchmarkError("answer-free producer usage sidecar is missing")
    trace_artifact = _archived_decision_trace_artifact(report, run_dir)
    terminal_authority = _p6_terminal_authority_conservation(
        report=report,
        run_dir=run_dir,
        usage_rows=usage_rows,
    )
    usage_accounting = aggregate_usage_ledger(report, usage_spans=usage_rows)
    totals = _as_dict(usage_accounting.get("totals"))
    admission_conservation = _p6_admission_conservation(
        report,
        physical_call_count=int(usage_accounting.get("call_count") or 0),
    )
    retry_conservation = _p6_retry_conservation(report, usage_rows=usage_rows)
    manifest = _as_dict(report.get("run_manifest"))
    summary = _as_dict(report.get("summary"))
    model_identity = _provider_model_identity_metrics(
        usage_rows,
        expected_model=provider_contract.model,
        expected_response_model=provider_contract.response_model,
        expected_response_models=provider_contract.accepted_response_models,
    )
    metrics: Dict[str, Any] = {
        "schema_version": P6_ANSWER_FREE_PRODUCER_METRICS_SCHEMA_VERSION,
        "answer_material_present": False,
        "formal_benchmark": False,
        "release_eligible": False,
        "tokens": int(totals.get("total_tokens") or 0),
        "queue_empty": manifest.get("validation_queue_drained") is True,
        "provider_usage_coverage": float(usage_accounting.get("provider_usage_coverage") or 0.0),
        "estimated_provider_call_count": sum(
            row.get("provider_reported") is not True or row.get("conservative_charge") is True
            for row in usage_rows
        ),
        "failed_or_unknown_call_count": sum(row.get("outcome") != "success" for row in usage_rows),
        "budget_violation_count": sum(row.get("budget_violation") is True for row in usage_rows),
        "token_conservation_passed": usage_accounting.get("conservation_passed") is True,
        "telemetry_complete_rate": float(usage_accounting.get("telemetry_complete") is True),
        "protocol_anomaly_count": int(summary.get("validator_protocol_exhausted_count") or 0)
        + len(usage_accounting.get("errors") or []),
        "candidate_funnel": candidate_funnel(report),
        "usage_accounting": usage_accounting,
        "p6_admission_conservation": admission_conservation,
        "p6_retry_conservation": retry_conservation,
        "p6_terminal_authority": terminal_authority,
        **model_identity,
    }
    metrics["p6_conservation"] = _p6_usage_conservation(
        report=report,
        score=metrics,
        usage_rows=usage_rows,
        model_identity=model_identity,
        decision_trace_artifact=trace_artifact,
        expected_model=provider_contract.model,
        expected_response_model=provider_contract.response_model,
    )
    metrics["content_sha256"] = _canonical_object_sha256(metrics)
    return metrics


def _p6_answer_free_gate_failures(metrics: Mapping[str, Any]) -> List[str]:
    """Evaluate only answer-free producer invariants before post-freeze scoring."""

    failures: List[str] = []
    usage = _as_dict(metrics.get("usage_accounting"))
    totals = _as_dict(usage.get("totals"))
    if metrics.get("queue_empty") is not True:
        failures.append("queue_not_drained")
    if (
        usage.get("complete") is not True
        or usage.get("conservation_passed") is not True
        or float(usage.get("provider_usage_coverage") or 0.0) != 1.0
        or int(usage.get("call_count") or 0) < 1
        or int(metrics.get("estimated_provider_call_count") or 0) != 0
        or int(metrics.get("failed_or_unknown_call_count") or 0) != 0
        or int(metrics.get("budget_violation_count") or 0) != 0
        or metrics.get("token_conservation_passed") is not True
    ):
        failures.append("accounting_conservation_failure")
    if (
        float(metrics.get("provider_response_model_coverage") or 0.0) != 1.0
        or int(metrics.get("provider_response_model_missing_count") or 0) != 0
        or int(metrics.get("provider_response_model_mismatch_count") or 0) != 0
        or int(metrics.get("requested_model_mismatch_count") or 0) != 0
        or int(metrics.get("provider_response_model_successful_call_count") or 0) < 1
        or metrics.get("provider_response_model_counts_conserved") is not True
        or sum(
            int(value)
            for value in _as_dict(metrics.get("provider_response_model_counts")).values()
            if isinstance(value, int) and not isinstance(value, bool)
        )
        != int(metrics.get("provider_response_model_successful_call_count") or 0)
    ):
        failures.append("provider_identity_mismatch")
    if (
        float(metrics.get("telemetry_complete_rate") or 0.0) != 1.0
        or int(metrics.get("protocol_anomaly_count") or 0) != 0
    ):
        failures.append("component_metrics_incomplete")
    admission = _as_dict(metrics.get("p6_admission_conservation"))
    if (
        admission.get("enabled") is not True
        or admission.get("request_conservation_passed") is not True
        or admission.get("zero_call_denial_conservation_passed") is not True
    ):
        failures.append("accounting_conservation_failure")
    retry_conservation = _as_dict(metrics.get("p6_retry_conservation"))
    if retry_conservation.get("passed") is not True:
        failures.append("accounting_conservation_failure")
    terminal_authority = _as_dict(metrics.get("p6_terminal_authority"))
    if terminal_authority.get("passed") is not True:
        failures.append("terminal_state_inconsistent")
    try:
        validate_usage_conservation(
            _as_dict(metrics.get("p6_conservation")), require_model_calls=True
        )
    except P6ProtocolError:
        failures.append("accounting_conservation_failure")
    return list(dict.fromkeys(failures))


def _usage_events_source_path(report: Mapping[str, Any], scan_root: Path) -> Optional[Path]:
    owners = [
        _as_dict(report.get("llm_usage")),
        _as_dict(_as_dict(report.get("metadata")).get("llm_usage")),
        _as_dict(_as_dict(report.get("summary")).get("llm_usage")),
        _as_dict(_as_dict(report.get("run_manifest")).get("llm_usage")),
        _as_dict(report.get("llm_budget")),
        _as_dict(_as_dict(report.get("metadata")).get("llm_budget")),
        _as_dict(_as_dict(report.get("summary")).get("llm_budget")),
        _as_dict(_as_dict(report.get("run_manifest")).get("llm_budget")),
    ]
    candidates = [
        candidate
        for owner in owners
        for candidate in (owner, _as_dict(owner.get("scan_token_usage")))
    ]
    raw_path = next(
        (
            str(candidate.get("usage_events_path") or "").strip()
            for candidate in candidates
            if str(candidate.get("usage_events_path") or "").strip()
        ),
        "",
    )
    if not raw_path:
        return None
    container_prefix = "/zscope-cache/project/"
    if raw_path.replace("\\", "/").startswith(container_prefix):
        relative = raw_path.replace("\\", "/")[len(container_prefix) :]
        path = scan_root / relative
    else:
        path = Path(raw_path)
    if not path.is_absolute():
        path = scan_root / path
    resolved = path.resolve()
    root = scan_root.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise BenchmarkError("LLM usage event path escapes the answer-free scan workspace") from exc
    return resolved


def _archive_usage_events(
    report: Dict[str, Any],
    *,
    scan_root: Path,
    run_dir: Path,
) -> Optional[Dict[str, Any]]:
    source = _usage_events_source_path(report, scan_root)
    if source is None:
        return None
    rows = _read_usage_events_jsonl(source)
    destination = run_dir / _USAGE_EVENTS_ARCHIVE_NAME
    serialized = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        for row in rows
    )
    destination.write_bytes(serialized.encode("utf-8"))
    artifact = {
        "schema_version": "zscope.llm-usage-events-artifact.v1",
        "path": destination.name,
        "sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        "call_count": len(rows),
        "answer_free": True,
    }
    metadata = report.setdefault("metadata", {})
    if isinstance(metadata, dict):
        metadata["llm_usage_events_artifact"] = dict(artifact)
    manifest = report.setdefault("run_manifest", {})
    if isinstance(manifest, dict):
        manifest["llm_usage_events_artifact"] = dict(artifact)
    return artifact


def _canonical_object_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _safe_trace_source_path(root: Path, relative: str, *, context: str) -> Path:
    raw = str(relative or "").strip()
    if not raw or "\\" in raw:
        raise BenchmarkError(f"{context} has an invalid relative path")
    path = Path(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise BenchmarkError(f"{context} has a non-canonical relative path")
    if path.parts[0] not in _DECISION_TRACE_DIRECTORY_NAMES:
        raise BenchmarkError(f"{context} is outside the decision-trace artifact set")
    resolved_root = root.resolve()
    resolved = (root / path).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise BenchmarkError(f"{context} escapes the decision-trace root") from exc
    current = resolved
    while current != resolved_root:
        if current.is_symlink():
            raise BenchmarkError(f"{context} traverses a symbolic link")
        current = current.parent
    if not resolved.is_file():
        raise BenchmarkError(f"{context} is missing")
    return resolved


def _decision_trace_manifest_source(report: Mapping[str, Any], scan_root: Path) -> Optional[Path]:
    summaries = [
        _as_dict(_as_dict(report.get("run_manifest")).get("decision_trace")),
        _as_dict(_as_dict(report.get("metadata")).get("decision_trace")),
    ]
    raw_path = next(
        (str(value.get("manifest_path") or "").strip() for value in summaries if value),
        "",
    )
    if not raw_path:
        if any(summaries):
            raise BenchmarkError("decision-trace summary has no manifest_path")
        return None
    path = Path(raw_path)
    if not path.is_absolute():
        path = scan_root / path
    resolved_root = scan_root.resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise BenchmarkError("decision-trace manifest escapes the answer-free workspace") from exc
    current = resolved
    while current != resolved_root:
        if current.is_symlink():
            raise BenchmarkError("decision-trace manifest traverses a symbolic link")
        current = current.parent
    if not resolved.is_file():
        raise BenchmarkError("decision-trace manifest is missing")
    return resolved


def _archive_decision_trace_artifacts(
    report: Dict[str, Any],
    *,
    scan_root: Path,
    run_dir: Path,
    usage_artifact: Optional[Mapping[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Archive and rebind the complete answer-free trace sidecar."""

    source_manifest = _decision_trace_manifest_source(report, scan_root)
    if source_manifest is None:
        return None
    trace_root = source_manifest.parent
    try:
        manifest = _load_json_object(source_manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"cannot read decision-trace manifest: {exc}") from exc
    if manifest.get("schema_version") != DECISION_TRACE_MANIFEST_VERSION:
        raise BenchmarkError("decision-trace manifest has an unsupported schema")
    supplied_manifest_sha = str(manifest.get("manifest_sha256") or "")
    manifest_body = dict(manifest)
    manifest_body.pop("manifest_sha256", None)
    if supplied_manifest_sha != _canonical_object_sha256(manifest_body):
        raise BenchmarkError("decision-trace manifest hash mismatch")

    copied_paths: set[str] = set()

    def copy_verified(relative: str, *, kind: str) -> None:
        source = _safe_trace_source_path(trace_root, relative, context=f"{kind} artifact")
        if relative in copied_paths:
            raise BenchmarkError(f"duplicate decision-trace artifact path: {relative}")
        if kind == "trace":
            load_decision_trace(source)
        elif kind == "coverage":
            value = _load_json_object(source)
            valid, reason = verify_coverage_trace(value)
            if not valid:
                raise BenchmarkError(f"invalid coverage trace {relative}: {reason}")
        elif kind == "evidence":
            valid, reason = verify_evidence_object(source)
            if not valid:
                raise BenchmarkError(f"invalid evidence object {relative}: {reason}")
        elif kind == "model":
            valid, reason = verify_model_event(source)
            if not valid:
                raise BenchmarkError(f"invalid model event {relative}: {reason}")
        destination = run_dir / Path(relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copied_paths.add(relative)

    traces = _as_dict(manifest.get("traces"))
    coverage = _as_dict(manifest.get("coverage_traces"))
    if int(manifest.get("trace_count") or 0) != len(traces):
        raise BenchmarkError("decision-trace manifest trace_count does not conserve")
    if int(manifest.get("coverage_trace_count") or 0) != len(coverage):
        raise BenchmarkError("decision-trace manifest coverage_trace_count does not conserve")
    archived_traces: Dict[str, Dict[str, Any]] = {}
    for cluster_uid, record in sorted(traces.items()):
        relative = str(_as_dict(record).get("path") or "")
        copy_verified(relative, kind="trace")
        archived = load_decision_trace(run_dir / relative)
        if str(archived.get("validation_cluster_uid") or "") != str(cluster_uid):
            raise BenchmarkError("decision-trace cluster identity does not match the manifest")
        if str(archived.get("document_sha256") or "") != str(
            _as_dict(record).get("document_sha256") or ""
        ):
            raise BenchmarkError("decision-trace document hash does not match the manifest")
        if not str(archived.get("terminal_event_uid") or "") or not str(
            archived.get("terminal_disposition") or ""
        ):
            raise BenchmarkError("decision trace has no unique terminal event/disposition")
        archived_traces[str(cluster_uid)] = archived
    for unit_uid, record in sorted(coverage.items()):
        relative = str(_as_dict(record).get("path") or "")
        copy_verified(relative, kind="coverage")
        archived = _load_json_object(run_dir / relative)
        if str(archived.get("audit_unit_uid") or "") != str(unit_uid):
            raise BenchmarkError("coverage-trace unit identity does not match the manifest")
        if str(archived.get("document_sha256") or "") != str(
            _as_dict(record).get("document_sha256") or ""
        ):
            raise BenchmarkError("coverage-trace document hash does not match the manifest")

    evidence_hashes = manifest.get("evidence_object_sha256") or []
    model_hashes = manifest.get("model_event_sha256") or []
    if not isinstance(evidence_hashes, list) or not isinstance(model_hashes, list):
        raise BenchmarkError("decision-trace content-addressed hash lists are invalid")
    if int(manifest.get("evidence_object_count") or 0) != len(evidence_hashes):
        raise BenchmarkError("decision-trace evidence_object_count does not conserve")
    if int(manifest.get("model_event_count") or 0) != len(model_hashes):
        raise BenchmarkError("decision-trace model_event_count does not conserve")
    for digest in evidence_hashes:
        value = str(digest or "")
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise BenchmarkError("decision-trace evidence digest is invalid")
        copy_verified(f"evidence_objects/{value}.json", kind="evidence")
    for digest in model_hashes:
        value = str(digest or "")
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise BenchmarkError("decision-trace model-event digest is invalid")
        copy_verified(f"model_events/{value}.json", kind="model")

    report_clusters: set[str] = set()
    for collection_name in ("issues", "issues_with_needs_review", "candidate_terminal_states"):
        collection = report.get(collection_name)
        if not isinstance(collection, list):
            continue
        for index, raw_item in enumerate(collection):
            if not isinstance(raw_item, Mapping):
                continue
            cluster_uid = str(raw_item.get("validation_cluster_uid") or "")
            if not cluster_uid:
                # Operational engine records are coverage obligations, not validation clusters.
                continue
            report_clusters.add(cluster_uid)
            trace = archived_traces.get(cluster_uid)
            if trace is None:
                raise BenchmarkError(
                    f"{collection_name}[{index}] references an unarchived validation cluster"
                )
            record = _as_dict(traces.get(cluster_uid))
            if str(raw_item.get("decision_trace_ref") or "") != str(record.get("path") or ""):
                raise BenchmarkError(
                    f"{collection_name}[{index}] decision_trace_ref does not match the manifest"
                )
            if str(raw_item.get("decision_trace_sha256") or "") != str(
                trace.get("document_sha256") or ""
            ):
                raise BenchmarkError(
                    f"{collection_name}[{index}] decision_trace_sha256 does not match the trace"
                )
            if str(raw_item.get("terminal_event_uid") or "") != str(
                trace.get("terminal_event_uid") or ""
            ):
                raise BenchmarkError(
                    f"{collection_name}[{index}] terminal event does not match the trace"
                )
            disposition = str(raw_item.get("candidate_disposition") or "").lower()
            original_disposition = str(
                raw_item.get("finding_root_original_disposition") or ""
            ).lower()
            proof_terminal = disposition in {"confirmed", "rejected_with_proof"} or (
                disposition == "deduplicated_alias"
                and original_disposition in {"confirmed", "rejected_with_proof"}
            )
            transition_fields = (
                "terminal_transition_event_uid",
                "terminal_transition_event_hash",
                "terminal_transition_authority_sha256",
                "terminal_transition_level",
                "terminal_transition_disposition",
            )
            if proof_terminal:
                if any(
                    not str(raw_item.get(field) or "")
                    or str(raw_item.get(field) or "") != str(trace.get(field) or "")
                    for field in transition_fields
                ):
                    raise BenchmarkError(
                        f"{collection_name}[{index}] proof transition does not match the trace"
                    )
            elif any(str(raw_item.get(field) or "") for field in transition_fields):
                raise BenchmarkError(
                    f"{collection_name}[{index}] non-proof terminal declares a transition"
                )
            if not str(raw_item.get("terminal_authority") or ""):
                raise BenchmarkError(f"{collection_name}[{index}] has no terminal authority")
    if set(archived_traces) != report_clusters:
        missing = sorted(set(archived_traces) - report_clusters)
        raise BenchmarkError(
            "decision-trace manifest contains clusters absent from the terminal report: "
            + ", ".join(missing[:5])
        )

    usage = manifest.get("llm_usage_events")
    if isinstance(usage, dict) and usage.get("available"):
        if usage_artifact is None:
            raise BenchmarkError("decision trace references usage but no usage archive exists")
        if int(usage.get("event_count") or 0) != int(usage_artifact.get("call_count") or 0):
            raise BenchmarkError("decision-trace and usage archive call counts differ")
        usage["path"] = _USAGE_EVENTS_ARCHIVE_NAME
        usage["file_sha256"] = str(usage_artifact.get("sha256") or "")

    manifest_body = dict(manifest)
    manifest_body.pop("manifest_sha256", None)
    manifest["manifest_sha256"] = _canonical_object_sha256(manifest_body)
    destination_manifest = run_dir / _DECISION_TRACE_MANIFEST_ARCHIVE_NAME
    _json_dump(destination_manifest, manifest)
    artifact = {
        "schema_version": "zscope.decision-trace-artifact.v1",
        "path": destination_manifest.name,
        "sha256": _sha256_file(destination_manifest),
        "manifest_sha256": manifest["manifest_sha256"],
        "trace_count": len(traces),
        "coverage_trace_count": len(coverage),
        "evidence_object_count": len(evidence_hashes),
        "model_event_count": len(model_hashes),
        "complete": bool(manifest.get("complete")),
        "answer_free": True,
    }
    summary = {
        "schema_version": DECISION_TRACE_MANIFEST_VERSION,
        "manifest_path": destination_manifest.name,
        "manifest_sha256": manifest["manifest_sha256"],
        "trace_count": len(traces),
        "coverage_trace_count": len(coverage),
        "evidence_object_count": len(evidence_hashes),
        "model_event_count": len(model_hashes),
        "complete": bool(manifest.get("complete")),
        "errors": list(manifest.get("errors") or []),
    }
    for owner_name in ("metadata", "run_manifest"):
        owner = report.setdefault(owner_name, {})
        if isinstance(owner, dict):
            owner["decision_trace"] = dict(summary)
            owner["decision_trace_artifact"] = dict(artifact)
    return artifact


def _source_line_metrics(scan_root: Path, language: str) -> Dict[str, Any]:
    extensions = (
        {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
        if language == "c_cpp"
        else {".java"}
    )
    excluded_parts = {
        "build",
        ".git",
        ".zscope_cache",
        ".zscope_snapshots",
        ".zscope_knowledge",
        "benchmark_runs",
    }
    files = 0
    lines = 0
    for path in scan_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in extensions:
            continue
        try:
            relative = path.relative_to(scan_root)
        except ValueError:
            continue
        if any(part.lower() in excluded_parts for part in relative.parts[:-1]):
            continue
        files += 1
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            lines += sum(1 for _ in handle)
    return {
        "source_file_count": files,
        "source_line_count": lines,
        "source_kloc": round(lines / 1000.0, 6),
        "loc_definition": "physical lines in answer-free language source/header files",
    }


def _report_provenance(report: Dict[str, Any]) -> Dict[str, Any]:
    manifest = _as_dict(report.get("run_manifest"))
    return {
        "config_hash": report.get("config_hash") or manifest.get("config_hash"),
        "runtime_spec": report.get("runtime_spec") or manifest.get("runtime_spec"),
        "rule_catalog": report.get("rule_catalog") or manifest.get("rule_catalog"),
    }


def _p6_scan_cold_producer_material_for_secret(
    paths: Sequence[Path],
    *,
    credential_environment: Optional[Mapping[str, str]],
) -> None:
    """Scan selected producer inputs/outputs with the actual in-memory key bytes."""

    if credential_environment is None or set(credential_environment) != {
        P6_API_KEY_ENVIRONMENT_KEY
    }:
        raise _P6ProtectedCanaryError()
    secret = credential_environment.get(P6_API_KEY_ENVIRONMENT_KEY)
    if not isinstance(secret, str) or not secret:
        raise _P6ProtectedCanaryError()
    canaries = (secret.encode("utf-8"),)
    try:
        for path in paths:
            if not path.exists() and not path.is_symlink():
                continue
            scan_regular_artifact_tree_for_canaries(path, canaries=canaries)
    except (OSError, P6ProtocolError, ValueError) as exc:
        raise _P6ProtectedCanaryError() from exc


def _run_trial_in_workspace(
    spec: BenchmarkSpec,
    run_dir: Path,
    run_number: int,
    *,
    mode: str,
    workspace: Path,
    scan_depth: str = "fast",
    credential_environment: Optional[Mapping[str, str]] = None,
    candidate_revision: Optional[str] = None,
    answer_free_producer: bool = False,
) -> Dict[str, Any]:
    started = time.monotonic()
    truth_path = spec.truth_path_for_mode(mode)
    scan_root = workspace / "scan-input"
    cache = workspace / "cache"
    cache_existed_before_run = cache.exists()
    cache.mkdir(parents=True)
    cache_empty_at_start = not cache_existed_before_run and not any(cache.iterdir())
    if mode == "pilot" and not cache_empty_at_start:
        raise _p6_failure("cold_cache_not_isolated")
    runtime_source: Optional[Path] = None
    runtime_source_sha256 = ""
    if mode == "pilot":
        if candidate_revision is None or re.fullmatch(r"[0-9a-f]{40}", candidate_revision) is None:
            raise _p6_failure("input_binding_failure")
        runtime_source = workspace / "runtime-source" / "zscope"
        runtime_source_sha256 = prepare_p6_runtime_source(
            runtime_source,
            git_revision=candidate_revision,
        )
    input_manifest = copy_scan_input(spec.fixture_root, scan_root, spec.language)
    _json_dump(run_dir / "input-manifest.json", input_manifest)
    execution_root = scan_root
    oci_output: Optional[Path] = None
    if mode in {"formal", "pilot"}:
        execution_root = cache / "project"
        shutil.copytree(scan_root, execution_root)
        oci_output = workspace / "oci-output"
        oci_output.mkdir()
    config_path = run_dir / "zscope.execution.yaml"
    _write_execution_config(spec, execution_root, config_path, scan_depth=scan_depth)
    environment = _benchmark_environment()
    if credential_environment is not None:
        # The runner-level locator is consumed here and must never become part
        # of the scanner/OCI child environment.  Only the validated key mapping
        # crosses that process boundary.
        environment.pop("Z_SCOPE_P6_API_KEY_FILE", None)
        for key in credential_environment:
            environment.pop(key, None)
        environment.update({str(key): str(value) for key, value in credential_environment.items()})
    cold_cache_evidence: Optional[Dict[str, Any]] = None
    if mode == "pilot":
        workflow_run_id = str(environment.get("GITHUB_RUN_ID") or "").strip()
        workflow_run_attempt = str(environment.get("GITHUB_RUN_ATTEMPT") or "").strip()
        if re.fullmatch(r"[1-9][0-9]*", workflow_run_id) and re.fullmatch(
            r"[1-9][0-9]*", workflow_run_attempt
        ):
            cache_identity_material = f"{workflow_run_id}:{workflow_run_attempt}:{scan_depth}"
        else:
            cache_identity_material = f"local:{workspace.name}:{scan_depth}"
        cold_cache_evidence = {
            "identity_sha256": hashlib.sha256(cache_identity_material.encode("utf-8")).hexdigest(),
            "empty_at_start": cache_empty_at_start,
            "reused": False,
        }
    effective = _validate_config(config_path, smoke=False, environment=environment)
    try:
        if mode == "pilot":
            # The provider identity is the frozen, source-controlled contract.
            # Per-depth execution configs intentionally differ (for example,
            # ``scan.depth`` and isolated project paths), so hashing those files
            # as the provider identity would make fast/balanced/deep appear to
            # use three different providers.  Validate every generated config
            # against the exact P6 contract, but retain the source contract as
            # the stable provider provenance.
            provider_contract = _p6_provider_contract_for_execution(
                config_path, source_config=spec.config_path
            )
        else:
            provider_contract = ProviderRuntimeContract.from_effective_config(
                effective,
                config_path=config_path,
            )
        reject_conflicting_provider_identity_environment(provider_contract, environment)
    except ProviderRuntimeError as exc:
        if mode == "pilot":
            failure_class = _provider_runtime_failure_class(
                exc,
                default="provider_identity_mismatch",
            )
            raise BenchmarkError(failure_class, failure_class=failure_class) from exc
        raise BenchmarkError(str(exc)) from exc
    environment["Z_SCOPE_BENCHMARK_LANGUAGE"] = spec.language
    environment["Z_SCOPE_BENCHMARK_SOURCE"] = str(execution_root)
    environment["Z_SCOPE_BENCHMARK_CACHE"] = str(cache)
    python = sys.executable
    isolation_capability: Dict[str, Any]
    health: Dict[str, Any]
    if mode in {"formal", "pilot"}:
        assert oci_output is not None
        container_config = scan_root / "zscope.execution.yaml"
        _write_container_execution_config(config_path, container_config)
        try:
            if mode == "pilot":
                provider_contract = _p6_provider_contract_for_execution(
                    container_config, source_config=spec.config_path
                )
            else:
                provider_contract = ProviderRuntimeContract.from_effective_config(
                    effective,
                    config_path=container_config,
                )
            reject_conflicting_provider_identity_environment(provider_contract, environment)
        except ProviderRuntimeError as exc:
            if mode == "pilot":
                failure_class = _provider_runtime_failure_class(
                    exc,
                    default="provider_identity_mismatch",
                )
                raise BenchmarkError(failure_class, failure_class=failure_class) from exc
            raise BenchmarkError(str(exc)) from exc
        input_manifest = scan_input_manifest(scan_root)
        _json_dump(run_dir / "input-manifest.json", input_manifest)
        container_python = environment.get("Z_SCOPE_BENCHMARK_OCI_PYTHON", "python3").strip()
        health_argv = [
            container_python,
            *(
                ("-c", _P6_RUNTIME_BOOTSTRAP, "zscope.cli.doctor")
                if mode == "pilot"
                else ("-m", "zscope.cli.doctor")
            ),
            "--config",
            "/zscope-input/zscope.execution.yaml",
        ]
        build_index_argv = [
            container_python,
            *(
                ("-c", _P6_RUNTIME_BOOTSTRAP, "zscope.cli.cli")
                if mode == "pilot"
                else ("-m", "zscope.cli.cli")
            ),
            "-c",
            "/zscope-input/zscope.execution.yaml",
            "--build-index",
        ]
        scan_argv = _container_scan_argv(container_python, mode=mode)
        try:
            executor = _OCI_EXECUTOR_FACTORY(
                runtime=environment.get("Z_SCOPE_BENCHMARK_OCI_RUNTIME", ""),
                image=environment.get("Z_SCOPE_BENCHMARK_OCI_IMAGE", ""),
                scan_input=scan_root,
                artifact_output=oci_output,
                cache_output=cache,
                environment=environment,
                provider_contract=provider_contract,
                runtime_source=runtime_source,
            )
            executor.preflight()
            required_phases: list[str] = []
            build_started = time.monotonic()
            if spec.language == "c_cpp":
                configure_argv = [
                    "cmake",
                    "-S",
                    "/zscope-cache/project",
                    "-B",
                    "/zscope-cache/project/build",
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                ]
                executor.execute_phase(
                    "build-configure",
                    configure_argv,
                    log_path=run_dir / "configure.log",
                    provider_credentials=mode != "pilot",
                )
                required_phases.append("build-configure")
                build_argv = [
                    "cmake",
                    "--build",
                    "/zscope-cache/project/build",
                    "--parallel",
                    "2",
                ]
            else:
                build_argv = [
                    "mvn",
                    "-q",
                    "-f",
                    "/zscope-cache/project/pom.xml",
                    "-DskipTests",
                    "package",
                ]
            executor.execute_phase(
                "build",
                build_argv,
                log_path=run_dir / "build.log",
                provider_credentials=mode != "pilot",
            )
            required_phases.append("build")
            build_seconds = time.monotonic() - build_started
            health_result = executor.execute_phase(
                "health",
                health_argv,
                log_path=run_dir / "health.log",
                provider_credentials=mode != "pilot",
            )
            required_phases.append("health")
            index_result = executor.execute_phase(
                "index",
                build_index_argv,
                log_path=run_dir / "index.log",
                provider_credentials=mode != "pilot",
            )
            required_phases.append("index")
            provider_failure_marker = oci_output / P6_PROVIDER_FAILURE_FILENAME
            if mode == "pilot" and (
                provider_failure_marker.exists() or provider_failure_marker.is_symlink()
            ):
                raise _p6_failure("oci_isolation_violation")
            scan_result = executor.execute_phase(
                "scan",
                scan_argv,
                log_path=run_dir / "scan.log",
                # Exit 2 is the public contract for a saved, budget-limited
                # partial scan.  Archive and score that artifact so the
                # benchmark policy can fail the quality gate explicitly.
                accepted_returncodes=(0, 1, 2),
                provider_credentials=True,
            )
            required_phases.append("scan")
            if mode == "pilot":
                scan_failure_class = _p6_scan_failure_class(
                    provider_failure_marker,
                    return_code=scan_result.return_code,
                )
            else:
                scan_failure_class = None
            if scan_failure_class is not None:
                raise BenchmarkError(
                    scan_failure_class,
                    failure_class=scan_failure_class,
                )
            isolation_capability = executor.execution_evidence(required_phases=required_phases)
            if mode == "pilot" and (
                isolation_capability.get("runtime_source_mounted") is not True
                or isolation_capability.get("runtime_source_sha256") != runtime_source_sha256
            ):
                raise BenchmarkIsolationError("P6 runtime source binding is invalid")
            require_release_isolation(
                required=True,
                capability=isolation_capability,
                repository_checkout=repository_root(),
                truth_paths=(truth_path,),
            )
        except BenchmarkIsolationError as exc:
            if mode == "pilot":
                raise _p6_failure("oci_isolation_violation") from exc
            raise BenchmarkError(str(exc)) from exc
        health = {
            "checks": [
                {
                    "tool": "container-doctor",
                    "path": isolation_capability.get("image"),
                    "ok": True,
                }
            ],
            "ok": True,
            "execution_verified": True,
        }
        phase_seconds = {
            "build": build_seconds,
            "health": health_result.seconds,
            "index": index_result.seconds,
            "scan": scan_result.seconds,
        }
    else:
        isolation_capability = oci_capability(
            runtime=environment.get("Z_SCOPE_BENCHMARK_OCI_RUNTIME", ""),
            image=environment.get("Z_SCOPE_BENCHMARK_OCI_IMAGE", ""),
        )
        health = _tool_health(spec)
        if not health["ok"]:
            missing = [item["tool"] for item in health["checks"] if not item["ok"]]
            raise BenchmarkError("missing required benchmark tools: " + ", ".join(missing))
        health_argv = [python, "-m", "zscope.cli.doctor", "--config", str(config_path)]
        build_index_argv = [
            python,
            "-m",
            "zscope.cli.cli",
            "-c",
            str(config_path),
            "--build-index",
        ]
        scan_argv = [python, "-m", "zscope.cli.cli", "-c", str(config_path), "--verbose"]
        phase_seconds = {
            "build": _build_fixture(spec, execution_root, run_dir),
            "health": _run_command(
                health_argv,
                cwd=execution_root,
                environment=environment,
                log_path=run_dir / "health.log",
            ),
            "index": _run_command(
                build_index_argv,
                cwd=execution_root,
                environment=environment,
                log_path=run_dir / "index.log",
            ),
            "scan": _run_command(
                scan_argv,
                cwd=execution_root,
                environment=environment,
                log_path=run_dir / "scan.log",
                accepted_returncodes=(0, 1, 2),
            ),
        }
    _json_dump(run_dir / "tool-health.json", health)
    source_report = _locate_report(execution_root)
    if mode == "pilot" and answer_free_producer:
        prearchive_paths = [run_dir, source_report, scan_root]
        trace_root = execution_root / ".zscope_snapshots"
        if trace_root.exists() or trace_root.is_symlink():
            prearchive_paths.append(trace_root)
        generated_entries = execution_root / "entry_functions_list.json"
        if generated_entries.exists() or generated_entries.is_symlink():
            prearchive_paths.append(generated_entries)
        if oci_output is not None:
            prearchive_paths.append(oci_output)
        _p6_scan_cold_producer_material_for_secret(
            prearchive_paths,
            credential_environment=credential_environment,
        )
    report_path = run_dir / "report.json"
    shutil.copy2(source_report, report_path)
    archived_report = _load_json_object(report_path)
    source_metrics = _source_line_metrics(scan_root, spec.language)
    archived_metadata = archived_report.setdefault("metadata", {})
    if isinstance(archived_metadata, dict):
        archived_metadata.update(source_metrics)
    archived_manifest = archived_report.setdefault("run_manifest", {})
    if isinstance(archived_manifest, dict):
        archived_manifest.update(source_metrics)
    usage_artifact = _archive_usage_events(
        archived_report,
        scan_root=execution_root,
        run_dir=run_dir,
    )
    decision_trace_artifact = _archive_decision_trace_artifacts(
        archived_report,
        scan_root=execution_root,
        run_dir=run_dir,
        usage_artifact=usage_artifact,
    )
    _json_dump(report_path, archived_report)
    replay_bundle_path = run_dir / "validator-replay-bundle.json"
    replay_bundle = write_validator_replay_bundle(
        replay_bundle_path,
        _load_json_object(report_path),
    )
    generated_entries = execution_root / "entry_functions_list.json"
    if generated_entries.is_file():
        if generated_entries.is_symlink():
            raise BenchmarkError("generated entry manifest must not be a symbolic link")
        shutil.copy2(generated_entries, run_dir / "entry_functions_list.json")
    restore_scan_input(scan_root, input_manifest)
    archived_scan_root = run_dir / "scan-input"
    shutil.copytree(scan_root, archived_scan_root)
    if scan_input_manifest(archived_scan_root) != input_manifest:
        raise BenchmarkError("archived scan input does not match the sealed input manifest")
    report = _load_json_object(report_path)
    score_path: Optional[Path] = None
    if answer_free_producer:
        if mode != "pilot":
            raise BenchmarkError("answer-free producer mode is restricted to P6 pilot")
        metrics = build_p6_answer_free_producer_metrics(
            report_path=report_path,
            run_dir=run_dir,
            provider_contract=provider_contract,
        )
        producer_metrics_path = run_dir / "producer-metrics.json"
        _json_dump(producer_metrics_path, metrics)
        _p6_scan_cold_producer_material_for_secret(
            (run_dir,),
            credential_environment=credential_environment,
        )
        phase_seconds["producer_metrics"] = 0.0
        gate_failures = _p6_answer_free_gate_failures(metrics)
        sealed_failures: List[str] = []
    else:
        truth_environment = dict(environment)
        for key in set(provider_contract.required_environment_keys).union(
            {PROVIDER_BASE_URL_ENVIRONMENT_KEY, PROVIDER_MODEL_ENVIRONMENT_KEY}
        ):
            truth_environment.pop(key, None)
        truth_environment["Z_SCOPE_BENCHMARK_TRUTH"] = str(truth_path.resolve())
        score_path = run_dir / "score.json"
        score_argv = [
            python,
            "-m",
            "zscope.cli.benchmark",
            "_score",
            "--report",
            str(report_path),
            "--output",
            str(score_path),
        ]
        phase_seconds["score"] = _run_command(
            score_argv,
            cwd=repository_root(),
            environment=truth_environment,
            log_path=run_dir / "score.log",
        )
        score = _load_json_object(score_path)
        usage_rows = _read_archived_usage_events(run_dir) or []
        model_identity = _provider_model_identity_metrics(
            usage_rows,
            expected_model=provider_contract.model,
            expected_response_model=provider_contract.response_model,
            expected_response_models=provider_contract.accepted_response_models,
        )
        score.update(model_identity)
        score.setdefault("scan_wall_seconds", round(phase_seconds["scan"], 6))
        score["wall_seconds"] = score["scan_wall_seconds"]
        telemetry = _as_dict(score.get("performance_telemetry"))
        telemetry["validator_workers"] = effective.concurrency.validator_workers
        telemetry["llm_max_inflight"] = effective.concurrency.llm_max_inflight
        validation_profile = effective.scan.llm_profiles.validation
        validation_llm = effective.llms.get(validation_profile, effective.llm)
        telemetry["validation_llm_profile"] = validation_profile
        telemetry["validation_endpoint_max_inflight"] = (
            validation_llm.base_url_max_concurrent_requests
        )
        score["performance_telemetry"] = telemetry
        if mode == "pilot":
            score["p6_conservation"] = _p6_usage_conservation(
                report=report,
                score=score,
                usage_rows=usage_rows,
                model_identity=model_identity,
                decision_trace_artifact=decision_trace_artifact,
                expected_model=provider_contract.model,
                expected_response_model=provider_contract.response_model,
            )
        metrics = score
        gate_failures = (
            _gate_c(
                score,
                scan_depth=scan_depth,
                require_release_rule_qualification=mode != "pilot",
            )
            if spec.language == "c_cpp"
            else []
        )
        if mode == "pilot" and (
            model_identity["provider_response_model_coverage"] != 1.0
            or model_identity["provider_response_model_missing_count"] != 0
            or model_identity["provider_response_model_mismatch_count"] != 0
            or model_identity["requested_model_mismatch_count"] != 0
            or model_identity["provider_response_model_successful_call_count"] < 1
        ):
            gate_failures.append("provider_identity_mismatch")
        if mode == "pilot":
            try:
                validate_usage_conservation(
                    _as_dict(score.get("p6_conservation")), require_model_calls=True
                )
            except P6ProtocolError:
                gate_failures.append("accounting_conservation_failure")
        gate_failures.extend(_truth_matcher_gate_failures(mode, score))
        sealed_failures = _gate_c_sealed(score) if spec.language == "c_cpp" else []
    phase_seconds["total"] = time.monotonic() - started
    if not answer_free_producer:
        metrics["end_to_end_wall_seconds"] = round(phase_seconds["total"], 6)
        metrics["timing_contract"] = {
            "gate_metric": "scan_wall_seconds",
            "legacy_gate_alias": "wall_seconds",
            "end_to_end_metric": "end_to_end_wall_seconds",
            "scan_wall_source": (
                "report.summary.batch_wall_seconds"
                if _as_dict(report.get("summary")).get("batch_wall_seconds") is not None
                else "runner.phase_seconds.scan"
            ),
        }
        assert score_path is not None
        _json_dump(score_path, metrics)
    report_ablation = _as_dict(_as_dict(report.get("metadata")).get("benchmark_ablation"))
    if report_ablation:
        gate_failures.append("semantic/discovery ablation artifacts are not release eligible")
        sealed_failures.append("semantic/discovery ablation artifacts are not release eligible")
    artifact_names = [
        "report.json",
        "producer-metrics.json" if answer_free_producer else "score.json",
        "input-manifest.json",
        "tool-health.json",
        "validator-replay-bundle.json",
    ]
    usage_artifact_path = run_dir / _USAGE_EVENTS_ARCHIVE_NAME
    if usage_artifact_path.is_file():
        artifact_names.append(_USAGE_EVENTS_ARCHIVE_NAME)
    if decision_trace_artifact is not None:
        artifact_names.append(_DECISION_TRACE_MANIFEST_ARCHIVE_NAME)
    artifact_hashes = {
        name: _sha256_file(run_dir / name) for name in artifact_names if (run_dir / name).is_file()
    }
    summary_payload = {
        "run": run_number,
        "completed": True,
        "formal_benchmark": mode == "formal",
        "release_eligible": _run_release_eligible(mode, metrics, gate_failures),
        "answer_free_producer": answer_free_producer,
        "queue_empty": bool(metrics.get("queue_empty")),
        "gate_failures": gate_failures,
        "sealed_gate_failures": sealed_failures,
        "completeness": {
            "report_present": True,
            "score_present": not answer_free_producer,
            "producer_metrics_present": answer_free_producer,
            "summary_present": True,
            "backend_health_present": True,
            "queue_empty": bool(metrics.get("queue_empty")),
            "backend_valid": health["ok"],
            "source_truth_isolated": True,
            "input_manifest_present": True,
            "validator_replay_bundle_present": True,
            "decision_trace_artifact_present": decision_trace_artifact is not None,
        },
        "phase_seconds": {key: round(value, 4) for key, value in phase_seconds.items()},
        "metrics": metrics,
        "input_manifest_sha256": input_manifest["manifest_sha256"],
        "input_files": input_manifest["files"],
        "validator_replay_bundle": {
            "schema_version": replay_bundle["schema_version"],
            "group_count": replay_bundle["group_count"],
            "bundle_sha256": replay_bundle["bundle_sha256"],
            "path": replay_bundle_path.name,
            "answer_material_present": False,
        },
        "decision_trace_artifact": decision_trace_artifact,
        "artifact_hashes": {
            "schema_version": "zscope.formal-run-artifact-hashes.v1",
            "files": artifact_hashes,
        },
        "execution": {
            "health_argv": health_argv,
            "index_argv": build_index_argv,
            "scan_argv": scan_argv,
            **(
                {}
                if answer_free_producer
                else {"score_argv": [python, "-m", "zscope.cli.benchmark", "_score"]}
            ),
        },
        "workspace": {
            "temporary": True,
            "storage_class": _workspace_storage_class(workspace),
            "artifact_exported": True,
        },
        **({"cold_cache": cold_cache_evidence} if cold_cache_evidence is not None else {}),
        "benchmark_policy": DEFAULT_BENCHMARK_POLICY.as_dict(),
        "isolation": {
            **isolation_capability,
            "required_for_release": bool(
                DEFAULT_BENCHMARK_POLICY.requirements.get(
                    "require_oci_isolation_for_release", False
                )
            ),
            "scan_cwd": str(scan_root),
            "truth_available_to_scan": False,
        },
        "provenance": {
            **_report_provenance(report),
            **(
                {"candidate_commit": candidate_revision}
                if mode == "pilot" and candidate_revision is not None
                else {}
            ),
            "runtime_spec_sha256": effective.runtime_provenance.sha256,
            "rule_catalog_sha256": effective.rule_catalog_provenance.catalog_sha256,
            "effective_rules_sha256": effective.rule_catalog_provenance.effective_sha256,
            "provider_runtime": provider_contract.as_dict(),
        },
    }
    _json_dump(run_dir / "summary.json", summary_payload)
    return summary_payload


def _run_trial(
    spec: BenchmarkSpec,
    run_dir: Path,
    run_number: int,
    *,
    mode: str,
    scan_depth: str = "fast",
    credential_environment: Optional[Mapping[str, str]] = None,
    candidate_revision: Optional[str] = None,
    answer_free_producer: bool = False,
) -> Dict[str, Any]:
    parent = _benchmark_work_parent(spec.language)
    workspace = Path(
        tempfile.mkdtemp(prefix=f"zscope-benchmark-{spec.language}-{run_number:02d}-", dir=parent)
    )
    protected_canary_failure = False
    try:
        kwargs: Dict[str, Any] = {
            "mode": mode,
            "workspace": workspace,
            "scan_depth": scan_depth,
        }
        if credential_environment is not None:
            kwargs["credential_environment"] = credential_environment
        if candidate_revision is not None:
            kwargs["candidate_revision"] = candidate_revision
        if answer_free_producer:
            kwargs["answer_free_producer"] = True
        return _run_trial_in_workspace(spec, run_dir, run_number, **kwargs)
    except _P6ProtectedCanaryError:
        protected_canary_failure = True
        try:
            metadata = run_dir.lstat()
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                run_dir.unlink(missing_ok=True)
            else:
                shutil.rmtree(run_dir, ignore_errors=True)
        raise
    finally:
        if not protected_canary_failure and not (run_dir / "summary.json").is_file():
            if mode == "pilot":
                _archive_pilot_interrupted_diagnostics(workspace, run_dir)
            else:
                _archive_interrupted_diagnostics(workspace, run_dir)
        shutil.rmtree(workspace, ignore_errors=True)


def _archive_pilot_interrupted_diagnostics(
    workspace: Path,
    run_dir: Path,
) -> Optional[Dict[str, Any]]:
    """Archive only aggregate, answer-free accounting for an interrupted P6 pilot."""

    sources: List[Path] = []
    for project_root in (workspace / "scan-input", workspace / "cache" / "project"):
        trace_root = project_root / ".zscope_snapshots"
        if not trace_root.is_dir() or trace_root.is_symlink():
            continue
        sources.extend(
            path
            for path in sorted(trace_root.glob("llm_usage_events_*.jsonl"))
            if path.is_file() and not path.is_symlink()
        )
    if not sources:
        return None
    event_count = 0
    successful_count = 0
    failed_count = 0
    provider_reported_count = 0
    response_model_present_count = 0
    invalid_file_count = 0
    file_hashes: List[str] = []
    for source in sources:
        file_hashes.append(_sha256_file(source))
        try:
            rows = _read_usage_events_jsonl(source)
        except BenchmarkError:
            invalid_file_count += 1
            continue
        event_count += len(rows)
        successful_count += sum(row.get("outcome") == "success" for row in rows)
        failed_count += sum(row.get("outcome") != "success" for row in rows)
        provider_reported_count += sum(row.get("provider_reported") is True for row in rows)
        response_model_present_count += sum(
            bool(str(row.get("provider_response_model") or "").strip())
            for row in rows
            if row.get("outcome") == "success"
        )
    payload = {
        "schema_version": "zscope.p6-interrupted-diagnostics.v1",
        "formal_evidence": False,
        "release_eligible": False,
        "reason": "pilot_interrupted_or_failed",
        "event_file_count": len(sources),
        "event_file_sha256s": sorted(file_hashes),
        "invalid_event_file_count": invalid_file_count,
        "event_count": event_count,
        "successful_call_count": successful_count,
        "failed_or_unknown_call_count": failed_count,
        "provider_reported_call_count": provider_reported_count,
        "provider_response_model_present_count": response_model_present_count,
        "answer_material_present": False,
    }
    _json_dump(run_dir / "interrupted-diagnostics.json", payload)
    return payload


def _archive_interrupted_diagnostics(workspace: Path, run_dir: Path) -> Optional[Dict[str, Any]]:
    """Preserve answer-free trace telemetry before a failed trial workspace is removed.

    A normal completed run goes through the stricter report-bound archival path.
    This fallback is deliberately non-release and copies only trace/usage
    artifacts, never source files, configuration, truth, or model reasoning.
    """

    trace_root = workspace / "scan-input" / ".zscope_snapshots"
    if not trace_root.is_dir():
        return None
    target = run_dir / "interrupted-diagnostics"
    allowed_directories = (
        "decision_traces",
        "coverage_traces",
        "evidence_objects",
        "model_events",
    )
    candidates: List[Path] = []
    manifest = trace_root / _DECISION_TRACE_MANIFEST_ARCHIVE_NAME
    if manifest.is_file() and not manifest.is_symlink():
        candidates.append(manifest)
    candidates.extend(
        path
        for path in sorted(trace_root.glob("llm_usage_events_*.jsonl"))
        if path.is_file() and not path.is_symlink()
    )
    for directory_name in allowed_directories:
        directory = trace_root / directory_name
        if not directory.is_dir() or directory.is_symlink():
            continue
        candidates.extend(
            path
            for path in sorted(directory.rglob("*.json"))
            if path.is_file() and not path.is_symlink()
        )
    if not candidates:
        return None
    target.mkdir(parents=True, exist_ok=False)
    files: List[Dict[str, Any]] = []
    for source in candidates:
        relative = source.relative_to(trace_root)
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        files.append(
            {
                "path": relative.as_posix(),
                "sha256": _sha256_file(destination),
                "size": destination.stat().st_size,
            }
        )
    payload = {
        "schema_version": "zscope.interrupted-benchmark-diagnostics.v1",
        "release_eligible": False,
        "reason": "benchmark_trial_interrupted_or_failed",
        "answer_material_present": False,
        "file_count": len(files),
        "files": files,
    }
    _json_dump(run_dir / "interrupted-diagnostics.json", payload)
    return payload


def _git_identity(revision: Optional[str] = None) -> Tuple[str, str]:
    try:
        selected = str(revision or "HEAD")
        if revision is not None and re.fullmatch(r"[0-9a-f]{40}", selected) is None:
            return "unknown", "unknown"
        sha = subprocess.check_output(
            ["git", "rev-parse", "--verify", f"{selected}^{{commit}}"],
            cwd=str(repository_root()),
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        tree = subprocess.check_output(
            ["git", "rev-parse", f"{sha}^{{tree}}"],
            cwd=str(repository_root()),
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        if revision is not None and sha != selected:
            return "unknown", "unknown"
        return sha, tree
    except (OSError, subprocess.CalledProcessError):
        return "unknown", "unknown"


def _aggregate(
    spec: BenchmarkSpec,
    summaries: List[Dict[str, Any]],
    mode: str,
    *,
    scan_depth: str = "fast",
    git_revision: Optional[str] = None,
    answer_free_producer: bool = False,
) -> Dict[str, Any]:
    git_sha, git_tree = _git_identity(git_revision)
    numeric_keys = sorted(
        {
            key
            for summary in summaries
            for key, value in summary.get("metrics", {}).items()
            if isinstance(value, (int, float)) and not isinstance(value, bool)
        }
    )
    medians = {
        key: statistics.median(
            float(summary["metrics"][key])
            for summary in summaries
            if key in summary.get("metrics", {})
        )
        for key in numeric_keys
    }
    phase_names = sorted(
        {phase for summary in summaries for phase in summary.get("phase_seconds", {})}
    )
    phase_medians = {
        phase: statistics.median(
            float(summary["phase_seconds"][phase])
            for summary in summaries
            if phase in summary.get("phase_seconds", {})
        )
        for phase in phase_names
    }
    commands = summaries[0].get("execution", {}) if summaries else {}
    formal = mode == "formal"
    pilot = mode == "pilot"
    per_run_passed = bool(summaries) and all(
        summary.get("queue_empty") is True and not summary.get("gate_failures")
        for summary in summaries
    )
    aggregate_gate_metrics = _aggregate_range_gate_metrics(summaries)
    truth_contracts = [
        _as_dict(_as_dict(summary.get("metrics")).get("truth_contract"))
        for summary in summaries
        if "truth_contract" in _as_dict(summary.get("metrics"))
    ]
    required_tp_values = {
        float(str(contract.get("required_confirmed_tp")))
        for contract in truth_contracts
        if contract.get("formal_eligible") is True
        and isinstance(contract.get("required_confirmed_tp"), (int, float))
    }
    required_tp = next(iter(required_tp_values)) if len(required_tp_values) == 1 else None
    depth_gates = _range_gates_for_depth(
        scan_depth,
        required_confirmed_tp=required_tp,
    )
    if pilot:
        # P6 is a one-run, non-release qualification.  It must expose both
        # quality views, but gates the reviewable set without fabricating that
        # needs-review findings have independent confirmation.  P7/formal
        # retains dynamic confirmed-TP/recall and Arm-A requirements.
        depth_gates = _pilot_range_gates(scan_depth)
    aggregate_gate_failures = (
        [] if answer_free_producer else _gate_metrics(aggregate_gate_metrics, depth_gates)
    )
    if (
        formal
        and truth_contracts
        and (
            len(truth_contracts) != len(summaries)
            or any(contract.get("formal_eligible") is not True for contract in truth_contracts)
            or len(required_tp_values) != 1
        )
    ):
        aggregate_gate_failures.append(
            "formal Range requires one consistent independently attested truth contract"
        )
    arm_a_binding = _aggregate_arm_a_binding(summaries)
    if not pilot and arm_a_binding.get("passed") is not True:
        aggregate_gate_failures.append("frozen Validator Arm-A baseline is missing or inconsistent")
    passed = per_run_passed and not aggregate_gate_failures
    sealed_gate_metrics = _aggregate_named_metrics(summaries, C_SEALED_GATES)
    sealed_gate_failures = _gate_metrics(sealed_gate_metrics, C_SEALED_GATES)
    sealed_set_verified = spec.language != "c_cpp" or not sealed_gate_failures
    return {
        "schema_version": FORMAL_SCHEMA_VERSION,
        "language": "cpp" if spec.language == "c_cpp" else "java",
        "mode": mode,
        "formal_benchmark": formal,
        "scan_depth": scan_depth,
        # This artifact attests the Range formal gate only. Product/default
        # release additionally consumes an independent balanced attestation.
        "release_eligible": formal and passed,
        "answer_free_producer": answer_free_producer,
        "git_sha": git_sha,
        "git_tree": git_tree,
        "benchmark_policy": DEFAULT_BENCHMARK_POLICY.as_dict(),
        "command_sha256": {
            name.removesuffix("_argv"): _command_sha256(argv)
            for name, argv in commands.items()
            if isinstance(argv, list)
        },
        "cold_runs": len(summaries),
        "all_completed": True,
        "passed": passed,
        "range_gate_metrics": aggregate_gate_metrics,
        "range_gate_failures": aggregate_gate_failures,
        "arm_a_baseline": arm_a_binding,
        "sealed_gate_metrics": sealed_gate_metrics,
        "sealed_gate_failures": sealed_gate_failures,
        "sealed_set_verified": sealed_set_verified,
        "medians": medians,
        "phase_medians": phase_medians,
        "performance_outliers": _performance_outliers(summaries),
        "runs": summaries,
    }


def _aggregate_arm_a_binding(summaries: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    bindings = [
        _as_dict(_as_dict(summary.get("metrics")).get("validator_arm_a_baseline"))
        for summary in summaries
    ]
    expected = len(summaries)
    bundle_hashes = {str(row.get("replay_bundle_sha256") or "") for row in bindings}
    baseline_hashes = {str(row.get("baseline_sha256") or "") for row in bindings}
    target_bundle_hashes = {
        str(_as_dict(summary.get("validator_replay_bundle")).get("bundle_sha256") or "")
        for summary in summaries
    }
    valid = bool(
        expected
        and len(bindings) == expected
        and all(
            row.get("frozen") is True
            and row.get("arm") == "A"
            and len(str(row.get("replay_bundle_sha256") or "")) == 64
            and len(str(row.get("baseline_sha256") or "")) == 64
            for row in bindings
        )
        and len(bundle_hashes) == 1
        and len(baseline_hashes) == 1
        and len(target_bundle_hashes) == 1
        and next(iter(bundle_hashes)) == next(iter(target_bundle_hashes))
    )
    return {
        "passed": valid,
        "trial_count": expected,
        "replay_bundle_sha256": next(iter(bundle_hashes), "") if len(bundle_hashes) == 1 else "",
        "target_replay_bundle_sha256": (
            next(iter(target_bundle_hashes), "") if len(target_bundle_hashes) == 1 else ""
        ),
        "baseline_sha256": next(iter(baseline_hashes), "") if len(baseline_hashes) == 1 else "",
    }


def _aggregate_named_metrics(
    summaries: Sequence[Dict[str, Any]],
    gates: Mapping[str, Tuple[str, float]],
) -> Dict[str, float]:
    result: Dict[str, float] = {}
    for name in gates:
        values = [
            float(summary["metrics"][name])
            for summary in summaries
            if isinstance(summary.get("metrics"), dict)
            and isinstance(summary["metrics"].get(name), (int, float))
            and not isinstance(summary["metrics"].get(name), bool)
        ]
        if len(values) == len(summaries) and values:
            result[name] = float(statistics.median(values))
    return result


def _aggregate_range_gate_metrics(
    summaries: Sequence[Dict[str, Any]],
) -> Dict[str, float]:
    metric_rows: List[Dict[str, Any]] = [
        _as_dict(summary.get("metrics"))
        for summary in summaries
        if isinstance(summary.get("metrics"), dict)
    ]

    def values(name: str) -> List[float]:
        return [
            float(row[name])
            for row in metric_rows
            if isinstance(row.get(name), (int, float)) and not isinstance(row.get(name), bool)
        ]

    tp_values = values("confirmed_tp")
    token_values = values("tokens")
    recall_values = values("confirmed_recall")
    with_review_recall_values = values("with_review_recall")
    fdr_deltas = values("actionable_fdr_delta_vs_arm_a_pp")
    provider_coverage = values("provider_usage_coverage")
    attribution_coverage = values("explicit_attribution_coverage")
    anomaly_counts = values("protocol_anomaly_count")
    expected = len(summaries)
    tp_identity_lists = [row.get("true_positive_truth_ids") for row in metric_rows]
    tp_sets = [
        set(map(str, value)) for value in tp_identity_lists if isinstance(value, list) and value
    ]
    jaccards = [
        1.0 if not left | right else len(left & right) / len(left | right)
        for left, right in itertools.combinations(tp_sets, 2)
    ]
    result = {
        "median_confirmed_tp": (
            float(statistics.median(tp_values)) if len(tp_values) == expected else 0.0
        ),
        "median_confirmed_recall": (
            float(statistics.median(recall_values)) if len(recall_values) == expected else 0.0
        ),
        "median_with_review_recall": (
            float(statistics.median(with_review_recall_values))
            if len(with_review_recall_values) == expected
            else 0.0
        ),
        "median_tokens": (
            float(statistics.median(token_values)) if len(token_values) == expected else 0.0
        ),
        "per_run_tokens": max(token_values) if len(token_values) == expected else 0.0,
        "provider_usage_coverage": (
            min(provider_coverage) if len(provider_coverage) == expected else 0.0
        ),
        "explicit_attribution_coverage": (
            min(attribution_coverage) if len(attribution_coverage) == expected else 0.0
        ),
        "queue_drained_rate": (
            sum(summary.get("queue_empty") is True for summary in summaries) / len(summaries)
            if summaries
            else 0.0
        ),
        "token_conservation_rate": (
            sum(
                _as_dict(summary.get("metrics")).get("token_conservation_passed") is True
                for summary in summaries
            )
            / len(summaries)
            if summaries
            else 0.0
        ),
        "telemetry_complete_rate": (
            sum(
                float(_as_dict(summary.get("metrics")).get("telemetry_complete_rate") or 0.0)
                for summary in summaries
            )
            / len(summaries)
            if summaries
            else 0.0
        ),
    }
    if len(tp_sets) == expected:
        result["true_positive_jaccard"] = float(statistics.fmean(jaccards)) if jaccards else 1.0
    if len(fdr_deltas) == expected:
        result["actionable_fdr_delta_vs_arm_a_pp"] = float(statistics.median(fdr_deltas))
    if len(recall_values) == expected:
        result["recall_range_pp"] = (max(recall_values) - min(recall_values)) * 100.0
    if len(anomaly_counts) == expected:
        result["protocol_anomaly_count"] = sum(anomaly_counts)
    return result


def _default_output(language: str, mode: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return repository_root() / "benchmark-artifacts" / language / mode / stamp


def benchmark_plan(
    language: str,
    mode: str,
    runs: int,
    *,
    scan_depth: str = "fast",
    answer_free_producer: bool = False,
) -> Dict[str, Any]:
    spec = SPECS[language]
    isolation = oci_capability(
        runtime=os.environ.get("Z_SCOPE_BENCHMARK_OCI_RUNTIME", ""),
        image=os.environ.get("Z_SCOPE_BENCHMARK_OCI_IMAGE", ""),
    )
    return {
        "language": language,
        "mode": mode,
        "runs": runs,
        "scan_depth": scan_depth,
        "fixture": str(spec.fixture_root),
        "config": str(spec.config_path),
        "truth_stage": "post_freeze_score" if answer_free_producer else "score_only",
        "answer_free_producer": answer_free_producer,
        "required_tools": list(spec.required_tools if mode != "smoke" else spec.required_tools[:1]),
        "scan_input": preview_scan_input(spec.fixture_root, language),
        "isolation": {
            **isolation,
            "required": mode in {"formal", "pilot"},
            "fail_closed": True,
            "scanner_cwd": "/zscope-input",
            "allowed_mount_purposes": ["scan_input", "artifact_output", "cache"],
            "forbidden_material": ["repository_checkout", "truth", "scorer"],
        },
        "stages": (
            ["fixture", "config", "truth", "build", "deterministic-structure"]
            if mode == "smoke"
            else (
                [
                    "copy",
                    "config",
                    "build",
                    "health",
                    "index",
                    "scan",
                    "producer_metrics",
                    "freeze_external",
                ]
                if answer_free_producer
                else ["copy", "config", "build", "health", "index", "scan", "score", "gate"]
            )
        ),
    }


def run_benchmark(
    language: str,
    mode: str,
    *,
    runs: Optional[int] = None,
    output: Optional[Path] = None,
    dry_run: bool = False,
    scan_depth: str = "fast",
    answer_free_producer: Optional[bool] = None,
) -> Dict[str, Any]:
    if language not in SPECS:
        raise BenchmarkError(f"unsupported language: {language}")
    if mode not in {"smoke", "trial", "formal", "pilot"}:
        raise BenchmarkError(f"unsupported mode: {mode}")
    if mode == "pilot" and language != "c_cpp":
        raise BenchmarkError("pilot mode is restricted to the C/C++ Range benchmark")
    if answer_free_producer is None:
        answer_free_producer = mode == "pilot"
    if answer_free_producer and mode != "pilot":
        raise BenchmarkError("answer-free producer mode is restricted to P6 pilot")
    if scan_depth not in {"fast", "balanced", "deep"}:
        raise BenchmarkError("scan depth must be fast, balanced, or deep")
    run_count = 1 if mode != "formal" else (runs or MIN_FORMAL_RUNS)
    if mode == "trial" and runs not in {None, 1}:
        raise BenchmarkError("trial mode always runs exactly one cold scan")
    if mode == "pilot" and runs not in {None, 1}:
        raise BenchmarkError("pilot mode always runs exactly one cold scan")
    if mode == "formal" and run_count < MIN_FORMAL_RUNS:
        raise BenchmarkError("formal release benchmarks require at least five cold trials")
    if mode == "smoke" and runs not in {None, 1}:
        raise BenchmarkError("smoke mode runs once")
    spec = SPECS[language]
    if mode == "pilot":
        try:
            pilot_contract = require_p6_provider_contract(spec.config_path)
            reject_conflicting_provider_identity_environment(pilot_contract, os.environ)
        except ProviderRuntimeError as exc:
            failure_class = _provider_runtime_failure_class(
                exc,
                default="provider_identity_mismatch",
            )
            raise BenchmarkError(failure_class, failure_class=failure_class) from exc
    plan = benchmark_plan(
        language,
        mode,
        run_count,
        scan_depth=scan_depth,
        answer_free_producer=answer_free_producer,
    )
    if dry_run:
        return {"dry_run": True, "answer_free_producer": answer_free_producer, **plan}
    if mode in {"formal", "pilot"}:
        capability = oci_capability(
            runtime=os.environ.get("Z_SCOPE_BENCHMARK_OCI_RUNTIME", ""),
            image=os.environ.get("Z_SCOPE_BENCHMARK_OCI_IMAGE", ""),
        )
        if not capability.get("available"):
            if mode == "pilot":
                raise _p6_failure("oci_capability_failed")
            raise BenchmarkError("; ".join(capability.get("errors") or []))
    credential_environment: Optional[Dict[str, str]] = None
    candidate_revision: Optional[str] = None
    if mode == "pilot":
        candidate_revision = os.environ.get(P6_CANDIDATE_COMMIT_ENVIRONMENT_KEY, "").strip()
        if re.fullmatch(r"[0-9a-f]{40}", candidate_revision) is None:
            raise _p6_failure("input_binding_failure")
        credential_path_value = os.environ.get("Z_SCOPE_P6_API_KEY_FILE", "").strip()
        if not credential_path_value:
            raise BenchmarkError(
                "provider_credentials_unavailable",
                failure_class="provider_credentials_unavailable",
            )
        credential_path = Path(credential_path_value)
        if not credential_path.is_absolute():
            raise BenchmarkError(
                "provider_credentials_unavailable",
                failure_class="provider_credentials_unavailable",
            )
        try:
            credential_environment = load_explicit_api_key_file(credential_path)
        except ProviderRuntimeError as exc:
            raise BenchmarkError(
                "provider_credentials_unavailable",
                failure_class="provider_credentials_unavailable",
            ) from exc
    destination = (output or _default_output(language, mode)).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    if not answer_free_producer:
        _validate_truth(spec.truth_path_for_mode(mode))
    if mode == "smoke":
        scan_root = destination / "scan-input"
        manifest = copy_scan_input(spec.fixture_root, scan_root, language)
        config_path = destination / "zscope.execution.yaml"
        _write_execution_config(spec, scan_root, config_path, scan_depth=scan_depth)
        _validate_config(config_path, smoke=True)
        health = _tool_health(
            BenchmarkSpec(language, spec.fixture_relative, spec.required_tools[:1])
        )
        if not health["ok"]:
            raise BenchmarkError("missing smoke build tool: " + spec.required_tools[0])
        build_seconds = _build_fixture(spec, scan_root, destination)
        structural = _run_structural_smoke(spec, scan_root, destination)
        payload = {
            "schema_version": "zscope.benchmark-smoke.v1",
            "language": language,
            "mode": mode,
            "scan_depth": scan_depth,
            "passed": True,
            "release_eligible": False,
            "network_used": False,
            "llm_called": False,
            "input_manifest": manifest,
            "build_seconds": round(build_seconds, 4),
            "structural_regression": structural,
        }
        _json_dump(destination / "smoke.json", payload)
        return payload
    if platform.system() != "Linux" and (spec.language == "c_cpp" or mode == "formal"):
        raise BenchmarkError(
            "C/C++ trial and all formal benchmarks require Linux (Windows must use WSL2)"
        )
    required_keys = required_environment_keys(spec.config_path)
    required_source = dict(os.environ)
    if credential_environment is not None:
        required_source.pop(P6_API_KEY_ENVIRONMENT_KEY, None)
        required_source.update(credential_environment)
    try:
        try:
            _require_llm_environment(required_keys, required_source)
        finally:
            if credential_environment is not None:
                for key in credential_environment:
                    required_source.pop(key, None)
        summaries = []
        for index in range(1, run_count + 1):
            run_dir = destination / f"run-{index:02d}"
            run_dir.mkdir()
            summaries.append(
                _run_trial(
                    spec,
                    run_dir,
                    index,
                    mode=mode,
                    scan_depth=scan_depth,
                    credential_environment=credential_environment,
                    candidate_revision=candidate_revision,
                    answer_free_producer=answer_free_producer,
                )
            )
    finally:
        if credential_environment is not None:
            credential_environment.clear()
    aggregate = _aggregate(
        spec,
        summaries,
        mode,
        scan_depth=scan_depth,
        git_revision=candidate_revision if mode == "pilot" else None,
        answer_free_producer=answer_free_producer,
    )
    if mode in {"trial", "pilot"}:
        aggregate["release_eligible"] = False
    if mode == "pilot":
        aggregate["formal_benchmark"] = False
    _json_dump(destination / "aggregate.json", aggregate)
    if mode == "formal" and not aggregate["passed"]:
        raise BenchmarkError("formal benchmark gates failed")
    return aggregate


_STANDARD_CLEAN_NAMES = {
    "build",
    "target",
    ".zscope_knowledge",
    ".zscope_snapshots",
    ".zscope_svf",
    ".zscope_bc",
    ".zscope_joern",
}
_LARGE_CLEAN_NAMES = {"benchmark_runs", "codeql_runs", ".zscope_conversations"}
_GENERATED_FILES = {
    "entry_functions_list.json",
    "zscope_batch_report.json",
    "zscope_batch_report.md",
    "zscope_alert_verify_report.json",
    "report.json",
    "report.md",
    "evaluation.json",
    "current_eval.json",
    "metrics.json",
    "zscope_run.log",
}


def _tracked_paths() -> set[Path]:
    try:
        output = subprocess.check_output(
            ["git", "ls-files", "-z"],
            cwd=str(repository_root()),
            stderr=subprocess.DEVNULL,
        ).decode("utf-8")
    except (OSError, subprocess.CalledProcessError):
        return set()
    return {(repository_root() / item).resolve() for item in output.split("\0") if item}


def _directory_size(path: Path) -> Tuple[int, int]:
    if path.is_file():
        return path.stat().st_size, 1
    size = 0
    count = 0
    for item in path.rglob("*"):
        if item.is_file() and not item.is_symlink():
            try:
                size += item.stat().st_size
                count += 1
            except OSError:
                continue
    return size, count


def clean_benchmark_artifacts(
    scope: str,
    *,
    apply: bool = False,
    include_runs: bool = False,
) -> Dict[str, Any]:
    languages = list(SPECS) if scope == "all" else [scope]
    if any(language not in SPECS for language in languages):
        raise BenchmarkError(f"unsupported clean scope: {scope}")
    tracked = _tracked_paths()
    targets: List[Path] = []
    for language in languages:
        root = SPECS[language].fixture_root.resolve()
        allowed_names = set(_STANDARD_CLEAN_NAMES)
        if include_runs:
            allowed_names.update(_LARGE_CLEAN_NAMES)
        for child in root.iterdir():
            if child.name in allowed_names or child.name in _GENERATED_FILES:
                targets.append(child)
            elif child.name.startswith("entry_functions_diff") and child.suffix == ".json":
                targets.append(child)
    rows = []
    for target in sorted(set(targets), key=str):
        root = next(
            spec.fixture_root.resolve()
            for spec in SPECS.values()
            if target.is_relative_to(spec.fixture_root.resolve())
        )
        resolved = target.resolve()
        if target.is_symlink() or not resolved.is_relative_to(root):
            raise BenchmarkError(f"refusing suspicious clean target: {target}")
        if resolved in tracked or any(item.is_relative_to(resolved) for item in tracked):
            raise BenchmarkError(f"refusing to delete tracked content: {target}")
        if target.name in {"zscope.local.env", "zscope.local.yaml"} or target.suffix == ".sarif":
            raise BenchmarkError(f"refusing protected clean target: {target}")
        size, count = _directory_size(target)
        rows.append({"path": str(target), "bytes": size, "files": count})
        if apply:
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
    return {
        "scope": scope,
        "dry_run": not apply,
        "include_runs": include_runs,
        "targets": rows,
        "total_bytes": sum(row["bytes"] for row in rows),
        "total_files": sum(row["files"] for row in rows),
    }
