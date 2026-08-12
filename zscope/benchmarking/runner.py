"""Canonical, answer-isolated benchmark runner for the bundled fixtures."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import yaml

from zscope.benchmarking.protocol import score_report_views
from zscope.config.config import ConfigLoader


FORMAL_SCHEMA_VERSION = "zscope.formal-benchmark.v2"
MIN_FORMAL_RUNS = 5
TRUTH_ENVIRONMENT_KEYS = {
    "Z_SCOPE_BENCHMARK_TRUTH",
    "Z_SCOPE_GROUND_TRUTH",
    "GROUND_TRUTH_PATH",
}
C_GATES = {
    "confirmed_tp": (">=", 85.0),
    "precision": (">=", 95.0),
    "with_review_tp": (">=", 134.0),
    "with_review_raw_fp": ("<=", 100.0),
    "needs_review": ("<=", 150.0),
    "tokens": ("<=", 6_000_000.0),
    "scan_wall_seconds": ("<=", 3600.0),
}
C_SEALED_GATES = {
    "sealed_confirmed_recall_delta_pp": (">=", -2.0),
    "sealed_precision_delta_pp": (">=", -2.0),
}


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


def _write_execution_config(spec: BenchmarkSpec, scan_root: Path, path: Path) -> Dict[str, Any]:
    raw = yaml.safe_load(spec.config_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise BenchmarkError(f"benchmark config must be an object: {spec.config_path}")
    project = raw.setdefault("project", {})
    if not isinstance(project, dict):
        raise BenchmarkError("benchmark config project must be an object")
    project["root"] = scan_root.resolve().as_posix()
    project["source_root"] = "."
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


def _gate_c(score: Dict[str, Any]) -> List[str]:
    return _gate_metrics(score, C_GATES)


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
    default = views["default"]
    review = views["with_needs_review"]
    manifest = _as_dict(report.get("run_manifest"))
    summary = _as_dict(report.get("summary"))
    usage = _as_dict(summary.get("llm_usage"))
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
        "tokens": int(
            summary.get("total_cumulative_total_tokens") or usage.get("total_tokens") or 0
        ),
        "queue_empty": manifest.get("validation_queue_drained") is True,
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
    }
    if isinstance(scan_wall_seconds, (int, float)) and not isinstance(scan_wall_seconds, bool):
        payload["scan_wall_seconds"] = round(float(scan_wall_seconds), 6)
        # zscope.formal-benchmark.v2 compatibility: wall_seconds remains the C gate alias.
        payload["wall_seconds"] = payload["scan_wall_seconds"]
    for field in C_SEALED_GATES:
        if field in report:
            payload[field] = report[field]
        elif field in manifest:
            payload[field] = manifest[field]
    _json_dump(output_path, payload)
    return payload


def _run_release_eligible(
    mode: str, score: Mapping[str, Any], gate_failures: Sequence[str]
) -> bool:
    return mode == "formal" and score.get("queue_empty") is True and not gate_failures


def _locate_report(scan_root: Path) -> Path:
    for name in ("zscope_batch_report.json", "report.json"):
        candidate = scan_root / name
        if candidate.is_file():
            return candidate
    raise BenchmarkError(f"scan did not produce a JSON report under {scan_root}")


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
) -> Dict[str, Any]:
    started = time.monotonic()
    scan_root = workspace / "scan-input"
    cache = workspace / "cache"
    cache.mkdir(parents=True)
    input_manifest = copy_scan_input(spec.fixture_root, scan_root, spec.language)
    _json_dump(run_dir / "input-manifest.json", input_manifest)
    config_path = run_dir / "zscope.execution.yaml"
    _write_execution_config(spec, scan_root, config_path)
    effective = _validate_config(config_path, smoke=False)
    environment = _benchmark_environment()
    environment["Z_SCOPE_BENCHMARK_LANGUAGE"] = spec.language
    environment["Z_SCOPE_BENCHMARK_SOURCE"] = str(scan_root)
    environment["Z_SCOPE_BENCHMARK_CACHE"] = str(cache)
    health = _tool_health(spec)
    _json_dump(run_dir / "tool-health.json", health)
    if not health["ok"]:
        missing = [item["tool"] for item in health["checks"] if not item["ok"]]
        raise BenchmarkError("missing required benchmark tools: " + ", ".join(missing))
    python = sys.executable
    health_argv = [python, "-m", "zscope.cli.doctor", "--config", str(config_path)]
    build_index_argv = [python, "-m", "zscope.cli.cli", "-c", str(config_path), "--build-index"]
    scan_argv = [python, "-m", "zscope.cli.cli", "-c", str(config_path), "--verbose"]
    phase_seconds = {
        "build": _build_fixture(spec, scan_root, run_dir),
        "health": _run_command(
            health_argv,
            cwd=repository_root(),
            environment=environment,
            log_path=run_dir / "health.log",
        ),
        "index": _run_command(
            build_index_argv,
            cwd=repository_root(),
            environment=environment,
            log_path=run_dir / "index.log",
        ),
        "scan": _run_command(
            scan_argv,
            cwd=repository_root(),
            environment=environment,
            log_path=run_dir / "scan.log",
            accepted_returncodes=(0, 1),
        ),
    }
    source_report = _locate_report(scan_root)
    report_path = run_dir / "report.json"
    shutil.copy2(source_report, report_path)
    generated_entries = scan_root / "entry_functions_list.json"
    if generated_entries.is_file():
        shutil.copy2(generated_entries, run_dir / "entry_functions_list.json")
    restore_scan_input(scan_root, input_manifest)
    archived_scan_root = run_dir / "scan-input"
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
    gate_failures = _gate_c(score) if spec.language == "c_cpp" else []
    sealed_failures = _gate_c_sealed(score) if spec.language == "c_cpp" else []
    report = _load_json_object(report_path)
    summary_payload = {
        "run": run_number,
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
        },
        "phase_seconds": {key: round(value, 4) for key, value in phase_seconds.items()},
        "metrics": score,
        "input_manifest_sha256": input_manifest["manifest_sha256"],
        "input_files": input_manifest["files"],
        "execution": {
            "health_argv": health_argv,
            "index_argv": build_index_argv,
            "scan_argv": scan_argv,
            "score_argv": [python, "-m", "zscope.cli.benchmark", "_score"],
        },
        "workspace": {
            "temporary": True,
            "storage_class": _workspace_storage_class(workspace),
            "artifact_exported": True,
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


def _run_trial(spec: BenchmarkSpec, run_dir: Path, run_number: int, *, mode: str) -> Dict[str, Any]:
    parent = _benchmark_work_parent(spec.language)
    workspace = Path(
        tempfile.mkdtemp(prefix=f"zscope-benchmark-{spec.language}-{run_number:02d}-", dir=parent)
    )
    try:
        return _run_trial_in_workspace(
            spec,
            run_dir,
            run_number,
            mode=mode,
            workspace=workspace,
        )
    finally:
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


def _aggregate(spec: BenchmarkSpec, summaries: List[Dict[str, Any]], mode: str) -> Dict[str, Any]:
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
    passed = bool(summaries) and all(
        summary.get("queue_empty") is True and not summary.get("gate_failures")
        for summary in summaries
    )
    return {
        "schema_version": FORMAL_SCHEMA_VERSION,
        "language": "cpp" if spec.language == "c_cpp" else "java",
        "mode": mode,
        "release_eligible": formal and passed,
        "git_sha": git_sha,
        "git_tree": git_tree,
        "command_sha256": {
            name.removesuffix("_argv"): _command_sha256(argv)
            for name, argv in commands.items()
            if isinstance(argv, list)
        },
        "cold_runs": len(summaries),
        "all_completed": True,
        "passed": passed,
        "sealed_set_verified": spec.language != "c_cpp"
        or all(not summary.get("sealed_gate_failures") for summary in summaries),
        "medians": medians,
        "phase_medians": phase_medians,
        "performance_outliers": _performance_outliers(summaries),
        "runs": summaries,
    }


def _default_output(language: str, mode: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return repository_root() / "benchmark-artifacts" / language / mode / stamp


def benchmark_plan(language: str, mode: str, runs: int) -> Dict[str, Any]:
    spec = SPECS[language]
    return {
        "language": language,
        "mode": mode,
        "runs": runs,
        "fixture": str(spec.fixture_root),
        "config": str(spec.config_path),
        "truth_stage": "score_only",
        "required_tools": list(spec.required_tools if mode != "smoke" else spec.required_tools[:1]),
        "scan_input": preview_scan_input(spec.fixture_root, language),
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
) -> Dict[str, Any]:
    if language not in SPECS:
        raise BenchmarkError(f"unsupported language: {language}")
    if mode not in {"smoke", "trial", "formal"}:
        raise BenchmarkError(f"unsupported mode: {mode}")
    run_count = 1 if mode != "formal" else (runs or MIN_FORMAL_RUNS)
    if mode == "trial" and runs not in {None, 1}:
        raise BenchmarkError("trial mode always runs exactly one cold scan")
    if mode == "formal" and run_count < MIN_FORMAL_RUNS:
        raise BenchmarkError("formal release benchmarks require at least five cold trials")
    if mode == "smoke" and runs not in {None, 1}:
        raise BenchmarkError("smoke mode runs once")
    spec = SPECS[language]
    plan = benchmark_plan(language, mode, run_count)
    if dry_run:
        return {"dry_run": True, **plan}
    destination = (output or _default_output(language, mode)).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    _validate_truth(spec.truth_path)
    if mode == "smoke":
        scan_root = destination / "scan-input"
        manifest = copy_scan_input(spec.fixture_root, scan_root, language)
        config_path = destination / "zscope.execution.yaml"
        _write_execution_config(spec, scan_root, config_path)
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
        summaries.append(_run_trial(spec, run_dir, index, mode=mode))
    aggregate = _aggregate(spec, summaries, mode)
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
