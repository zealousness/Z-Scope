"""Canonical, answer-isolated benchmark runner for the bundled fixtures."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import statistics
import itertools
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import yaml

from zscope.benchmarking.protocol import (
    aggregate_usage_ledger,
    candidate_funnel,
    score_report_views,
)
from zscope.benchmarking.isolation import (
    BenchmarkIsolationError,
    RootlessOciExecutor,
    oci_capability,
    require_release_isolation,
)
from zscope.benchmarking.policy import DEFAULT_BENCHMARK_POLICY
from zscope.benchmarking.replay_bundle import write_validator_replay_bundle
from zscope.config.config import ConfigLoader
from zscope.framework.llm_usage import (
    TOKEN_USAGE_STAGES,
    USAGE_ATTRIBUTION_SCHEMA_VERSION,
    USAGE_EVENT_SCHEMA_VERSION,
    canonical_usage_stage,
    escalation_rung_for_call_kind,
)

FORMAL_SCHEMA_VERSION = DEFAULT_BENCHMARK_POLICY.formal_schema_version
MIN_FORMAL_RUNS = DEFAULT_BENCHMARK_POLICY.minimum_formal_trials
TRUTH_ENVIRONMENT_KEYS = {
    "Z_SCOPE_BENCHMARK_TRUTH",
    "Z_SCOPE_GROUND_TRUTH",
    "GROUND_TRUTH_PATH",
}
C_GATES = dict(DEFAULT_BENCHMARK_POLICY.range_gates)
C_SEALED_GATES = dict(DEFAULT_BENCHMARK_POLICY.sealed_delta_gates)
_OCI_EXECUTOR_FACTORY = RootlessOciExecutor


class BenchmarkError(RuntimeError):
    """Raised when a benchmark invariant is not satisfied."""


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
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=str):
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


def _validate_config(path: Path, *, smoke: bool) -> Any:
    keys = {
        "Z_SCOPE_LLM_BASE_URL": os.environ.get(
            "Z_SCOPE_LLM_BASE_URL", "https://benchmark.invalid/v1"
        ),
        "Z_SCOPE_LLM_MODEL": os.environ.get("Z_SCOPE_LLM_MODEL", "benchmark-smoke"),
        "Z_SCOPE_API_KEY": os.environ.get("Z_SCOPE_API_KEY", "benchmark-smoke-no-network"),
    }
    old = {key: os.environ.get(key) for key in keys}
    try:
        for key, value in keys.items():
            if smoke or not os.environ.get(key):
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


def _require_llm_environment() -> None:
    missing = [
        key
        for key in ("Z_SCOPE_LLM_BASE_URL", "Z_SCOPE_LLM_MODEL", "Z_SCOPE_API_KEY")
        if not os.environ.get(key, "").strip()
    ]
    if missing:
        raise BenchmarkError("missing required benchmark environment: " + ", ".join(missing))


def _render_trial_metrics(run_dir: Path, *, language: str) -> float:
    """Render the human-readable metrics report into one run artifact directory."""

    script = repository_root() / "scripts" / "render_trial_metrics.py"
    output = run_dir / "metrics.md"
    environment = _benchmark_environment()
    for key in ("Z_SCOPE_API_KEY", "Z_SCOPE_LLM_BASE_URL", "Z_SCOPE_LLM_MODEL"):
        environment.pop(key, None)
    return _run_command(
        [
            sys.executable,
            str(script),
            str(run_dir),
            "--language",
            language,
            "--output",
            str(output),
        ],
        cwd=repository_root(),
        environment=environment,
        log_path=run_dir / "render_trial_metrics.log",
    )


def _fixture_c_compiler() -> Optional[str]:
    """Pin the fixture build to the fact compiler when Clang is available.

    Checked proofs bind facts to the recorded compile driver; building the
    fixture with the same Clang keeps that binding satisfiable.  Returns None
    when Clang is absent so the build falls back and checked proofs
    auto-disable downstream (CompleteFactStore.driver_bound).
    """
    return shutil.which("clang")


def _build_fixture(spec: BenchmarkSpec, scan_root: Path, run_dir: Path) -> float:
    if spec.language == "c_cpp":
        build = scan_root / "build"
        started = time.monotonic()
        configure_argv = [
            "cmake",
            "-S",
            str(scan_root),
            "-B",
            str(build),
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        ]
        fact_clang = _fixture_c_compiler()
        if fact_clang:
            configure_argv.append(f"-DCMAKE_C_COMPILER={fact_clang}")
        _run_command(
            configure_argv,
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


def _range_gates_for_depth(scan_depth: str) -> Dict[str, Tuple[str, float]]:
    gates = dict(C_GATES)
    expectations = DEFAULT_BENCHMARK_POLICY.range_depth_token_expectations[scan_depth]
    gates["median_tokens"] = ("<=", float(expectations["median_tokens"]))
    gates["per_run_tokens"] = ("<=", float(expectations["per_run_tokens"]))
    return gates


def _gate_c(score: Dict[str, Any], *, scan_depth: str = "balanced") -> List[str]:
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
        requirements.get("require_qualified_default_rules_for_release")
        and int(score.get("default_enabled_unqualified_rule_count") or 0) > 0
    ):
        failures.append("default-enabled deterministic rules are not externally qualified")
    if (
        requirements.get("require_qualified_default_rules_for_release")
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
_SCAN_EXTRAS_DIR_NAME = "scan-extras"
_SCAN_EXTRAS_MANIFEST_NAME = "scan-extras-manifest.json"
_SCAN_EXTRAS_SCHEMA_VERSION = "zscope.scan-extras-artifact.v1"
_SCAN_EXTRA_EXCLUDED_ROOTS = frozenset(
    {
        "build",
        "target",
        ".zscope_svf",
        ".zscope_svf_cache",
        ".zscope_bc",
        ".zscope_joern",
    }
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
_USAGE_EVENT_FIELDS = frozenset(
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
        "escalation_rung",
    }
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
        "reason",
        "finish_reason",
        "escalation_rung",
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
    _require_exact_usage_fields(raw, expected=_USAGE_EVENT_FIELDS, context=context)
    if raw["schema_version"] != USAGE_EVENT_SCHEMA_VERSION:
        raise BenchmarkError(f"{context} has unsupported schema_version {raw['schema_version']!r}")

    for field in _USAGE_EVENT_STRING_FIELDS:
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
        # Compatibility shim: archives written before escalation-rung
        # observability (balanced_confirmed_tp_plan.md Phase 5) lack the
        # field.  Backfill it from call_kind so historical artifacts stay
        # readable for replay and marginal attribution; fresh producers must
        # still emit the field explicitly.
        if "escalation_rung" not in raw:
            raw["escalation_rung"] = escalation_rung_for_call_kind(raw.get("call_kind"))
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


def _relative_posix_within(path: Path, root: Path) -> str:
    resolved = path.resolve()
    base = root.resolve()
    try:
        return resolved.relative_to(base).as_posix()
    except ValueError as exc:
        raise BenchmarkError(
            "scan extra path escapes the scan workspace: " + str(path)
        ) from exc


def _archive_scan_extras(
    *,
    execution_root: Path,
    run_dir: Path,
    input_manifest: Mapping[str, Any],
    extra_roots: Optional[Mapping[str, Optional[Path]]] = None,
) -> Dict[str, Any]:
    """Copy generated scan-side files, including conversation traces, into the run artifact.

    Sealed fixture files stay in ``scan-input``. Rebuildable toolchain trees are
    excluded so extras remain inspectable without copying SVF/bitcode/build
    caches. The extras sidecar is not part of the formal artifact-hash set.
    """

    sealed = {
        str(row["path"])
        for row in input_manifest.get("files", [])
        if isinstance(row, dict) and isinstance(row.get("path"), str)
    }
    destination = run_dir / _SCAN_EXTRAS_DIR_NAME
    if destination.exists():
        raise BenchmarkError(
            "scan extras archive already exists: " + str(destination)
        )
    sources: List[Tuple[str, Path, Path]] = [("execution_root", execution_root, Path())]
    for name, root in (extra_roots or {}).items():
        if root is None:
            continue
        sources.append((name, Path(root), Path(name)))
    files: List[Dict[str, Any]] = []
    for origin, root, prefix in sources:
        if not root.exists():
            continue
        resolved_root = root.resolve()
        for path in sorted(resolved_root.rglob("*"), key=lambda item: item.as_posix()):
            if path.is_symlink():
                raise BenchmarkError(
                    "scan extra must not be a symbolic link: " + str(path)
                )
            if not path.is_file():
                continue
            relative = Path(_relative_posix_within(path, resolved_root))
            if origin == "execution_root" and relative.as_posix() in sealed:
                continue
            if relative.parts and relative.parts[0] in _SCAN_EXTRA_EXCLUDED_ROOTS:
                continue
            archived_relative = relative if prefix == Path() else prefix / relative
            target = destination / archived_relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            files.append(
                {
                    "path": archived_relative.as_posix(),
                    "origin": origin,
                    "size": target.stat().st_size,
                    "sha256": _sha256_file(target),
                }
            )
    files.sort(key=lambda row: str(row["path"]))
    payload = {
        "schema_version": _SCAN_EXTRAS_SCHEMA_VERSION,
        "path": _SCAN_EXTRAS_DIR_NAME,
        "manifest": _SCAN_EXTRAS_MANIFEST_NAME,
        "file_count": len(files),
        "conversation_present": any(
            str(row["path"]) == ".zscope_conversations"
            or str(row["path"]).startswith(".zscope_conversations/")
            or "/.zscope_conversations/" in str(row["path"])
            for row in files
        ),
        "excluded_roots": sorted(_SCAN_EXTRA_EXCLUDED_ROOTS),
        "files": files,
    }
    _json_dump(run_dir / _SCAN_EXTRAS_MANIFEST_NAME, payload)
    return payload


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


def _run_trial_in_workspace(
    spec: BenchmarkSpec,
    run_dir: Path,
    run_number: int,
    *,
    mode: str,
    workspace: Path,
    scan_depth: str = "fast",
) -> Dict[str, Any]:
    started = time.monotonic()
    scan_root = workspace / "scan-input"
    cache = workspace / "cache"
    cache.mkdir(parents=True)
    input_manifest = copy_scan_input(spec.fixture_root, scan_root, spec.language)
    _json_dump(run_dir / "input-manifest.json", input_manifest)
    execution_root = scan_root
    oci_output: Optional[Path] = None
    if mode == "formal":
        execution_root = cache / "project"
        shutil.copytree(scan_root, execution_root)
        oci_output = workspace / "oci-output"
        oci_output.mkdir()
    config_path = run_dir / "zscope.execution.yaml"
    _write_execution_config(spec, execution_root, config_path, scan_depth=scan_depth)
    effective = _validate_config(config_path, smoke=False)
    review_experiment = any(bool(getattr(effective.analysis, name, False)) for name in (
        "validation_review_checkpoint", "validation_review_protocol", "validation_checked_proofs",
        "validation_positive_case", "validation_related_findings",
    ))
    if review_experiment and mode == "formal":
        raise BenchmarkError("review experiment capabilities are not qualified for formal runs")
    if review_experiment:
        # Absolute compiler dependencies must remain replayable after trial.
        # The retained workspace contains only scanner inputs and outputs;
        # independent scoring still runs outside it.
        retained = {"schema_version": "zscope.review-workspace.v1", "workspace": str(workspace),
                    "source": str(execution_root), "snapshot_dir": str(effective.analysis.snapshot_dir),
                    "reason": "retain original dependency paths for review checkpoint replay"}
        _json_dump(workspace / ".review-checkpoints-retained.json", retained)
        _json_dump(run_dir / "review-workspace.json", retained)
    environment = _benchmark_environment()
    environment["Z_SCOPE_BENCHMARK_LANGUAGE"] = spec.language
    environment["Z_SCOPE_BENCHMARK_SOURCE"] = str(execution_root)
    environment["Z_SCOPE_BENCHMARK_CACHE"] = str(cache)
    python = sys.executable
    isolation_capability: Dict[str, Any]
    health: Dict[str, Any]
    if mode == "formal":
        assert oci_output is not None
        container_config = scan_root / "zscope.execution.yaml"
        _write_container_execution_config(config_path, container_config)
        input_manifest = scan_input_manifest(scan_root)
        _json_dump(run_dir / "input-manifest.json", input_manifest)
        container_python = environment.get("Z_SCOPE_BENCHMARK_OCI_PYTHON", "python3").strip()
        health_argv = [
            container_python,
            "-m",
            "zscope.cli.doctor",
            "--config",
            "/zscope-input/zscope.execution.yaml",
        ]
        build_index_argv = [
            container_python,
            "-m",
            "zscope.cli.cli",
            "-c",
            "/zscope-input/zscope.execution.yaml",
            "--build-index",
        ]
        scan_argv = [
            container_python,
            "-m",
            "zscope.cli.cli",
            "-c",
            "/zscope-input/zscope.execution.yaml",
            "--verbose",
        ]
        try:
            executor = _OCI_EXECUTOR_FACTORY(
                runtime=environment.get("Z_SCOPE_BENCHMARK_OCI_RUNTIME", ""),
                image=environment.get("Z_SCOPE_BENCHMARK_OCI_IMAGE", ""),
                scan_input=scan_root,
                artifact_output=oci_output,
                cache_output=cache,
                environment=environment,
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
                fact_clang = shutil.which("clang")
                if fact_clang:
                    configure_argv.append(f"-DCMAKE_C_COMPILER={fact_clang}")
                executor.execute_phase(
                    "build-configure", configure_argv, log_path=run_dir / "configure.log"
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
            executor.execute_phase("build", build_argv, log_path=run_dir / "build.log")
            required_phases.append("build")
            build_seconds = time.monotonic() - build_started
            health_result = executor.execute_phase(
                "health", health_argv, log_path=run_dir / "health.log"
            )
            required_phases.append("health")
            index_result = executor.execute_phase(
                "index", build_index_argv, log_path=run_dir / "index.log"
            )
            required_phases.append("index")
            scan_result = executor.execute_phase(
                "scan",
                scan_argv,
                log_path=run_dir / "scan.log",
                # Exit 2 is the public contract for a saved, budget-limited
                # partial scan.  Archive and score that artifact so the
                # benchmark policy can fail the quality gate explicitly.
                accepted_returncodes=(0, 1, 2),
            )
            required_phases.append("scan")
            isolation_capability = executor.execution_evidence(required_phases=required_phases)
            require_release_isolation(
                required=True,
                capability=isolation_capability,
                repository_checkout=repository_root(),
                truth_paths=(spec.truth_path,),
            )
        except BenchmarkIsolationError as exc:
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
    _archive_usage_events(
        archived_report,
        scan_root=execution_root,
        run_dir=run_dir,
    )
    extras = _archive_scan_extras(
        execution_root=execution_root,
        run_dir=run_dir,
        input_manifest=input_manifest,
        extra_roots={"oci-output": oci_output} if oci_output is not None else None,
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
    archived_scan_root = run_dir / "scan-input"
    if review_experiment:
        copy_scan_input(scan_root, archived_scan_root, spec.language)
    else:
        restore_scan_input(scan_root, input_manifest)
        shutil.copytree(scan_root, archived_scan_root)
    if scan_input_manifest(archived_scan_root) != input_manifest:
        raise BenchmarkError("archived scan input does not match the sealed input manifest")
    truth_environment = dict(environment)
    for key in ("Z_SCOPE_API_KEY", "Z_SCOPE_LLM_BASE_URL", "Z_SCOPE_LLM_MODEL"):
        truth_environment.pop(key, None)
    truth_environment["Z_SCOPE_BENCHMARK_TRUTH"] = str(spec.truth_path.resolve())
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
    phase_seconds["total"] = time.monotonic() - started
    score = _load_json_object(score_path)
    score.setdefault("scan_wall_seconds", round(phase_seconds["scan"], 6))
    score["wall_seconds"] = score["scan_wall_seconds"]
    score["end_to_end_wall_seconds"] = round(phase_seconds["total"], 6)
    score["timing_contract"] = {
        "gate_metric": "scan_wall_seconds",
        "legacy_gate_alias": "wall_seconds",
        "end_to_end_metric": "end_to_end_wall_seconds",
        "scan_wall_source": (
            "report.summary.batch_wall_seconds"
            if _as_dict(_load_json_object(report_path).get("summary")).get("batch_wall_seconds")
            is not None
            else "runner.phase_seconds.scan"
        ),
    }
    telemetry = _as_dict(score.get("performance_telemetry"))
    telemetry["validator_workers"] = effective.concurrency.validator_workers
    telemetry["llm_max_inflight"] = effective.concurrency.llm_max_inflight
    validation_profile = effective.scan.llm_profiles.validation
    validation_llm = effective.llms.get(validation_profile, effective.llm)
    telemetry["validation_llm_profile"] = validation_profile
    telemetry["validation_endpoint_max_inflight"] = validation_llm.base_url_max_concurrent_requests
    score["performance_telemetry"] = telemetry
    _json_dump(score_path, score)
    gate_failures = _gate_c(score, scan_depth=scan_depth) if spec.language == "c_cpp" else []
    sealed_failures = _gate_c_sealed(score) if spec.language == "c_cpp" else []
    if review_experiment:
        gate_failures.append("review experiment requires independent audit and paired qualification")
        sealed_failures.append("review experiment is not release eligible")
    report = _load_json_object(report_path)
    report_ablation = _as_dict(_as_dict(report.get("metadata")).get("benchmark_ablation"))
    if report_ablation:
        gate_failures.append("semantic/discovery ablation artifacts are not release eligible")
        sealed_failures.append("semantic/discovery ablation artifacts are not release eligible")
    artifact_names = [
        "report.json",
        "score.json",
        "input-manifest.json",
        "tool-health.json",
        "validator-replay-bundle.json",
    ]
    usage_artifact_path = run_dir / _USAGE_EVENTS_ARCHIVE_NAME
    if usage_artifact_path.is_file():
        artifact_names.append(_USAGE_EVENTS_ARCHIVE_NAME)
    artifact_hashes = {
        name: _sha256_file(run_dir / name) for name in artifact_names if (run_dir / name).is_file()
    }
    summary_payload = {
        "run": run_number,
        "language": spec.language,
        "mode": mode,
        "scan_depth": scan_depth,
        "completed": True,
        "release_eligible": _run_release_eligible(mode, score, gate_failures),
        "queue_empty": bool(score.get("queue_empty")),
        "gate_failures": gate_failures,
        "sealed_gate_failures": sealed_failures,
        "completeness": {
            "report_present": True,
            "score_present": True,
            "summary_present": True,
            "backend_health_present": True,
            "queue_empty": bool(score.get("queue_empty")),
            "backend_valid": health["ok"],
            "source_truth_isolated": True,
            "input_manifest_present": True,
            "validator_replay_bundle_present": True,
        },
        "phase_seconds": {key: round(value, 4) for key, value in phase_seconds.items()},
        "metrics": score,
        "input_manifest_sha256": input_manifest["manifest_sha256"],
        "input_files": input_manifest["files"],
        "validator_replay_bundle": {
            "schema_version": replay_bundle["schema_version"],
            "group_count": replay_bundle["group_count"],
            "bundle_sha256": replay_bundle["bundle_sha256"],
            "path": replay_bundle_path.name,
            "answer_material_present": False,
        },
        "artifact_hashes": {
            "schema_version": "zscope.formal-run-artifact-hashes.v1",
            "files": artifact_hashes,
        },
        "scan_extras": {
            "schema_version": extras["schema_version"],
            "path": extras["path"],
            "manifest": extras["manifest"],
            "file_count": extras["file_count"],
            "conversation_present": extras["conversation_present"],
            "manifest_sha256": _sha256_file(run_dir / _SCAN_EXTRAS_MANIFEST_NAME),
        },
        "execution": {
            "health_argv": health_argv,
            "index_argv": build_index_argv,
            "scan_argv": scan_argv,
            "score_argv": [python, "-m", "zscope.cli.benchmark", "_score"],
        },
        "workspace": {
            "temporary": not review_experiment,
            "retained_for_review": review_experiment,
            "storage_class": _workspace_storage_class(workspace),
            "artifact_exported": True,
        },
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
            "runtime_spec_sha256": effective.runtime_provenance.sha256,
            "rule_catalog_sha256": effective.rule_catalog_provenance.catalog_sha256,
            "effective_rules_sha256": effective.rule_catalog_provenance.effective_sha256,
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
) -> Dict[str, Any]:
    parent = _benchmark_work_parent(spec.language)
    workspace = Path(
        tempfile.mkdtemp(prefix=f"zscope-benchmark-{spec.language}-{run_number:02d}-", dir=parent)
    )
    try:
        summary = _run_trial_in_workspace(
            spec,
            run_dir,
            run_number,
            mode=mode,
            workspace=workspace,
            scan_depth=scan_depth,
        )
        _render_trial_metrics(run_dir, language=spec.language)
        return summary
    finally:
        if not (workspace / ".review-checkpoints-retained.json").is_file():
            shutil.rmtree(workspace, ignore_errors=True)


def _git_identity() -> Tuple[str, str]:
    try:
        sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(repository_root()), text=True
        ).strip()
        tree = subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=str(repository_root()), text=True
        ).strip()
        return sha, tree
    except (OSError, subprocess.CalledProcessError):
        return "unknown", "unknown"


def _aggregate(
    spec: BenchmarkSpec,
    summaries: List[Dict[str, Any]],
    mode: str,
    *,
    scan_depth: str = "fast",
) -> Dict[str, Any]:
    git_sha, git_tree = _git_identity()
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
    per_run_passed = bool(summaries) and all(
        summary.get("queue_empty") is True and not summary.get("gate_failures")
        for summary in summaries
    )
    aggregate_gate_metrics = _aggregate_range_gate_metrics(summaries)
    depth_gates = _range_gates_for_depth(scan_depth)
    aggregate_gate_failures = _gate_metrics(aggregate_gate_metrics, depth_gates)
    arm_a_binding = _aggregate_arm_a_binding(summaries)
    if arm_a_binding.get("passed") is not True:
        aggregate_gate_failures.append("frozen Validator Arm-A baseline is missing or inconsistent")
    passed = per_run_passed and not aggregate_gate_failures
    sealed_gate_metrics = _aggregate_named_metrics(summaries, C_SEALED_GATES)
    sealed_gate_failures = _gate_metrics(sealed_gate_metrics, C_SEALED_GATES)
    sealed_set_verified = spec.language != "c_cpp" or not sealed_gate_failures
    return {
        "schema_version": FORMAL_SCHEMA_VERSION,
        "language": "cpp" if spec.language == "c_cpp" else "java",
        "mode": mode,
        "scan_depth": scan_depth,
        # This artifact attests the Range formal gate only. Product/default
        # release additionally consumes an independent balanced attestation.
        "release_eligible": formal and passed,
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
    language: str, mode: str, runs: int, *, scan_depth: str = "fast"
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
        "truth_stage": "score_only",
        "required_tools": list(spec.required_tools if mode != "smoke" else spec.required_tools[:1]),
        "scan_input": preview_scan_input(spec.fixture_root, language),
        "isolation": {
            **isolation,
            "required": mode == "formal",
            "fail_closed": True,
            "scanner_cwd": "/zscope-input",
            "allowed_mount_purposes": ["scan_input", "artifact_output", "cache"],
            "forbidden_material": ["repository_checkout", "truth", "scorer"],
        },
        "stages": (
            ["fixture", "config", "truth", "build", "deterministic-structure"]
            if mode == "smoke"
            else ["copy", "config", "build", "health", "index", "scan", "score", "gate"]
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
) -> Dict[str, Any]:
    if language not in SPECS:
        raise BenchmarkError(f"unsupported language: {language}")
    if mode not in {"smoke", "trial", "formal"}:
        raise BenchmarkError(f"unsupported mode: {mode}")
    if scan_depth not in {"fast", "balanced", "deep"}:
        raise BenchmarkError("scan depth must be fast, balanced, or deep")
    run_count = 1 if mode != "formal" else (runs or MIN_FORMAL_RUNS)
    if mode == "trial" and runs not in {None, 1}:
        raise BenchmarkError("trial mode always runs exactly one cold scan")
    if mode == "formal" and run_count < MIN_FORMAL_RUNS:
        raise BenchmarkError("formal release benchmarks require at least five cold trials")
    if mode == "smoke" and runs not in {None, 1}:
        raise BenchmarkError("smoke mode runs once")
    spec = SPECS[language]
    plan = benchmark_plan(language, mode, run_count, scan_depth=scan_depth)
    if dry_run:
        return {"dry_run": True, **plan}
    if mode == "formal":
        capability = oci_capability(
            runtime=os.environ.get("Z_SCOPE_BENCHMARK_OCI_RUNTIME", ""),
            image=os.environ.get("Z_SCOPE_BENCHMARK_OCI_IMAGE", ""),
        )
        if not capability.get("available"):
            raise BenchmarkError("; ".join(capability.get("errors") or []))
    destination = (output or _default_output(language, mode)).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    _validate_truth(spec.truth_path)
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
    _require_llm_environment()
    summaries = []
    for index in range(1, run_count + 1):
        run_dir = destination / f"run-{index:02d}"
        run_dir.mkdir()
        summaries.append(_run_trial(spec, run_dir, index, mode=mode, scan_depth=scan_depth))
    aggregate = _aggregate(spec, summaries, mode, scan_depth=scan_depth)
    if mode == "trial":
        aggregate["release_eligible"] = False
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
