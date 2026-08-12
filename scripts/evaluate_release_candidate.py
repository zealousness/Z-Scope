#!/usr/bin/env python3
"""Evaluate benchmark, asset, and offline-smoke evidence for a release candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from scripts.verify_release_assets import ReleaseAssetError, verify_release_assets
    from scripts.verify_release_version import package_version
except ModuleNotFoundError:  # Direct execution sets sys.path[0] to scripts/.
    from verify_release_assets import ReleaseAssetError, verify_release_assets
    from verify_release_version import package_version

ROOT = Path(__file__).resolve().parents[1]
SCAN_INPUT_ALLOWED_ROOTS = {
    "cpp": {"src", "include", "internal"},
    "java": {"src"},
}
SCAN_INPUT_ALLOWED_FILES = {
    "cpp": {"CMakeLists.txt", "README.md"},
    "java": {"pom.xml", "README.md", "entries.json"},
}
CPP_FORMAL_LIMITS = {
    "confirmed_tp": (("confirmed_tp",), ">=", 85.0),
    "confirmed_precision_percent": (
        ("confirmed_precision_percent", "precision"),
        ">=",
        95.0,
    ),
    "with_review_tp": (("with_review_tp",), ">=", 134.0),
    "with_review_raw_fp": (("with_review_raw_fp",), "<=", 100.0),
    "needs_review": (("needs_review",), "<=", 150.0),
    "total_tokens": (("total_tokens", "tokens"), "<=", 6_000_000.0),
    "scan_wall_seconds": (("scan_wall_seconds", "wall_seconds"), "<=", 3600.0),
}
CPP_SEALED_LIMITS = {
    "sealed_confirmed_recall_delta_pp": (
        ("sealed_confirmed_recall_delta_pp",),
        ">=",
        -2.0,
    ),
    "sealed_precision_delta_pp": (("sealed_precision_delta_pp",), ">=", -2.0),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _metric_value(metrics: Dict[str, Any], aliases: tuple[str, ...]) -> Optional[float]:
    for alias in aliases:
        try:
            return float(metrics[alias])
        except (KeyError, TypeError, ValueError):
            continue
    return None


def _metric_gate_failures(
    metrics: Dict[str, Any],
    limits: Dict[str, tuple[tuple[str, ...], str, float]],
    *,
    prefix: str,
) -> List[str]:
    failures: List[str] = []
    for name, (aliases, operator, threshold) in limits.items():
        value = _metric_value(metrics, aliases)
        if value is None:
            failures.append(f"{prefix}_{name}_missing")
            continue
        failed = (operator == ">=" and value < threshold) or (
            operator == "<=" and value > threshold
        )
        if failed:
            failures.append(f"{prefix}_{name}_gate_failed")
    return failures


def _validate_scan_input_manifest(
    run_dir: Path,
    run: Dict[str, Any],
    *,
    language: str,
) -> bool:
    """Validate additive v2 input provenance without rejecting historical v2 artifacts."""

    manifest_path = run_dir / "input-manifest.json"
    if not manifest_path.is_file():
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    files = manifest.get("files")
    if not isinstance(files, list) or manifest.get("manifest_sha256") != run.get(
        "input_manifest_sha256"
    ):
        return False
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != manifest.get("manifest_sha256"):
        return False
    observed = []
    for row in files:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            return False
        relative = Path(row["path"])
        if relative.is_absolute() or ".." in relative.parts:
            return False
        allowed = relative.as_posix() in SCAN_INPUT_ALLOWED_FILES[language] or (
            bool(relative.parts) and relative.parts[0] in SCAN_INPUT_ALLOWED_ROOTS[language]
        )
        if not allowed or "ground_truth" in relative.as_posix().lower():
            return False
        actual = run_dir / "scan-input" / relative
        if not actual.is_file() or _sha256(actual) != row.get("sha256"):
            return False
        observed.append(relative.as_posix())
    actual_files = sorted(
        path.relative_to(run_dir / "scan-input").as_posix()
        for path in (run_dir / "scan-input").rglob("*")
        if path.is_file()
    )
    return sorted(observed) == actual_files


def _evaluate_formal_artifact(
    directory: Path,
    *,
    language: str,
    release_sha: str,
    hard_blockers: List[str],
    rc_blockers: List[str],
    advisories: List[str],
) -> Dict[str, Any]:
    directory = directory.resolve()
    aggregate_path = directory / "aggregate.json"
    result: Dict[str, Any] = {
        "language": language,
        "required_for_release": True,
        "source": "workflow_artifact",
        "artifact_directory": str(directory),
        "aggregate_sha256": None,
        "benchmark_git_sha": None,
        "cold_runs": 0,
    }
    if not aggregate_path.is_file():
        hard_blockers.append(f"{language}:formal_artifact_aggregate_missing")
        return result
    try:
        aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        hard_blockers.append(f"{language}:formal_artifact_aggregate_invalid")
        return result
    raw_runs = aggregate.get("runs", [])
    runs = raw_runs if isinstance(raw_runs, list) else []
    result.update(
        {
            "aggregate_sha256": _sha256(aggregate_path),
            "benchmark_git_sha": aggregate.get("git_sha"),
            "cold_runs": len(runs),
        }
    )
    if aggregate.get("schema_version") != "zscope.formal-benchmark.v2":
        hard_blockers.append(f"{language}:formal_artifact_schema_invalid")
    if aggregate.get("language") != language:
        hard_blockers.append(f"{language}:formal_artifact_language_mismatch")
    if aggregate.get("git_sha") != release_sha:
        hard_blockers.append(f"{language}:benchmark_sha_not_release_sha")
    if not isinstance(raw_runs, list) or len(runs) != 5:
        hard_blockers.append(f"{language}:formal_artifact_run_count_invalid")
    if aggregate.get("cold_runs") != len(runs) or aggregate.get("all_completed") is not True:
        hard_blockers.append(f"{language}:formal_artifact_incomplete")
    if aggregate.get("passed") is not True:
        hard_blockers.append(f"{language}:numeric_gate_failed")
    current_frontend = aggregate.get("mode") is not None
    if current_frontend and (
        aggregate.get("mode") != "formal" or aggregate.get("release_eligible") is not True
    ):
        hard_blockers.append(f"{language}:formal_artifact_not_release_eligible")

    seen_runs = set()
    for run in runs:
        run_number = run.get("run") if isinstance(run, dict) else None
        if not isinstance(run_number, int) or run_number < 1 or run_number in seen_runs:
            hard_blockers.append(f"{language}:formal_artifact_run_identity_invalid")
            continue
        seen_runs.add(run_number)
        run_dir = directory / f"run-{run_number:02d}"
        required_files = {
            "report_present": run_dir / "report.json",
            "score_present": run_dir / "score.json",
            "summary_present": run_dir / "summary.json",
            "backend_health_present": run_dir / "health.log",
        }
        completeness_value = run.get("completeness", {})
        completeness = completeness_value if isinstance(completeness_value, dict) else {}
        complete = run.get("completed") is True and all(
            path.is_file() and completeness.get(key) is True for key, path in required_files.items()
        )
        complete = complete and all(
            (run_dir / name).is_file() for name in ("scan.log", "score.log")
        )
        complete = complete and all(
            completeness.get(key) is True
            for key in ("queue_empty", "backend_valid", "source_truth_isolated")
        )
        scan_input = run_dir / "scan-input"
        leaked_truth = (
            any(
                path.name in {"GROUND_TRUTH.md", "ground_truth.json"}
                for path in scan_input.rglob("*")
            )
            if scan_input.is_dir()
            else True
        )
        if not complete or leaked_truth:
            hard_blockers.append(f"{language}:run_{run_number}_incomplete")
        if current_frontend:
            if completeness.get(
                "input_manifest_present"
            ) is not True or not _validate_scan_input_manifest(
                run_dir,
                run,
                language=language,
            ):
                hard_blockers.append(f"{language}:run_{run_number}_input_manifest_invalid")
            execution = run.get("execution") if isinstance(run.get("execution"), dict) else {}
            scan_phase_text = json.dumps(
                {
                    key: value
                    for key, value in execution.items()
                    if key in {"health_argv", "index_argv", "scan_argv"}
                },
                sort_keys=True,
            ).lower()
            if "ground_truth" in scan_phase_text or "benchmark/ground_truth" in scan_phase_text:
                hard_blockers.append(f"{language}:run_{run_number}_truth_isolation_invalid")
        try:
            archived_summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            archived_summary = None
        if archived_summary != run:
            hard_blockers.append(f"{language}:run_{run_number}_summary_mismatch")
        if run.get("queue_empty") is not True or run.get("gate_failures"):
            hard_blockers.append(f"{language}:run_{run_number}_numeric_gate_failed")
        metrics = run.get("metrics", {})
        if language == "cpp" and isinstance(metrics, dict):
            hard_blockers.extend(
                _metric_gate_failures(
                    metrics,
                    CPP_FORMAL_LIMITS,
                    prefix=f"{language}:run_{run_number}",
                )
            )

    if seen_runs != set(range(1, 6)):
        hard_blockers.append(f"{language}:formal_artifact_run_identity_invalid")

    if language == "cpp":
        sealed_failures = []
        for run in runs:
            run_number = run.get("run") if isinstance(run, dict) else "unknown"
            metrics = run.get("metrics", {}) if isinstance(run, dict) else {}
            sealed_failures.extend(
                _metric_gate_failures(
                    metrics if isinstance(metrics, dict) else {},
                    CPP_SEALED_LIMITS,
                    prefix=f"{language}:run_{run_number}",
                )
            )
        if aggregate.get("sealed_set_verified") is not True or sealed_failures:
            rc_blockers.append(f"{language}:sealed_set_not_verified")
    if aggregate.get("performance_outliers"):
        advisories.append(f"{language}:performance_outlier_present")
    return result


def evaluate_candidate(
    provenance_path: Path,
    *,
    release_sha: str,
    version: str,
    tag: str = "",
    asset_dir: Optional[Path] = None,
    smoke_evidence: Optional[Path] = None,
    formal_artifacts: Optional[Dict[str, Path]] = None,
) -> Dict[str, Any]:
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    hard_blockers: List[str] = []
    rc_blockers: List[str] = []
    advisories: List[str] = []
    if provenance.get("package_version") != version:
        hard_blockers.append("package_version_mismatch")
    if not tag:
        hard_blockers.append("release_tag_missing")
    elif tag != f"v{version}":
        hard_blockers.append("tag_package_version_mismatch")
    else:
        try:
            tag_sha = subprocess.check_output(
                ["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"],
                cwd=str(ROOT),
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            if tag_sha != release_sha:
                hard_blockers.append("release_tag_not_release_sha")
        except subprocess.CalledProcessError:
            hard_blockers.append("release_tag_not_found")

    formal_artifacts = formal_artifacts or {}
    benchmark_results = []
    for item in provenance.get("benchmarks", []):
        required = bool(item.get("required_for_release", False))
        language = str(item.get("language"))
        if required and language in formal_artifacts:
            benchmark_results.append(
                _evaluate_formal_artifact(
                    formal_artifacts[language],
                    language=language,
                    release_sha=release_sha,
                    hard_blockers=hard_blockers,
                    rc_blockers=rc_blockers,
                    advisories=advisories,
                )
            )
            continue
        archive_path = (ROOT / str(item["archive"])).resolve()
        archive = json.loads(archive_path.read_text(encoding="utf-8"))
        result = {
            "language": language,
            "required_for_release": required,
            "archive": str(item["archive"]),
            "archive_sha256": _sha256(archive_path),
            "benchmark_git_sha": archive.get("benchmark_git_sha"),
            "cold_runs": len(archive.get("runs", [])),
        }
        if archive.get("benchmark_git_sha") != item.get("git_sha"):
            hard_blockers.append(f"{language}:provenance_archive_sha_mismatch")
        if required and archive.get("benchmark_git_sha") != release_sha:
            hard_blockers.append(f"{language}:benchmark_sha_not_release_sha")
        runs = archive.get("runs", [])
        if len(runs) < 5:
            hard_blockers.append(f"{language}:fewer_than_five_runs")
        for run in runs:
            completeness = run.get("completeness", {})
            if not all(
                completeness.get(key) is True
                for key in (
                    "report_present",
                    "score_present",
                    "summary_present",
                    "backend_health_present",
                    "queue_empty",
                    "backend_valid",
                    "source_truth_isolated",
                )
            ):
                hard_blockers.append(f"{language}:run_{run.get('run')}_incomplete")
        gate = archive.get("gate", {})
        if required and gate.get("numeric_gates_passed") is not True:
            hard_blockers.append(f"{language}:numeric_gate_failed")
        if required and language == "cpp":
            limits = {
                "confirmed_tp": (">=", 85.0),
                "confirmed_precision_percent": (">=", 95.0),
                "with_review_tp": (">=", 134.0),
                "with_review_raw_fp": ("<=", 100.0),
                "needs_review": ("<=", 150.0),
                "total_tokens": ("<=", 6_000_000.0),
                "wall_seconds": ("<=", 3600.0),
            }
            for run in runs:
                metrics = run.get("metrics", {})
                for metric, (operator, threshold) in limits.items():
                    try:
                        value = float(metrics[metric])
                    except (KeyError, TypeError, ValueError):
                        hard_blockers.append(f"{language}:run_{run.get('run')}_{metric}_missing")
                        continue
                    failed = (operator == ">=" and value < threshold) or (
                        operator == "<=" and value > threshold
                    )
                    if failed:
                        hard_blockers.append(
                            f"{language}:run_{run.get('run')}_{metric}_gate_failed"
                        )
        if required and gate.get("sealed_set_verified") is not True:
            rc_blockers.append(f"{language}:sealed_set_not_verified")
        if archive.get("performance_analysis", {}).get("outlier_runs"):
            advisories.append(f"{language}:performance_outlier_present")
        benchmark_results.append(result)

    known_languages = {str(item.get("language")) for item in provenance.get("benchmarks", [])}
    for language in formal_artifacts.keys() - known_languages:
        hard_blockers.append(f"{language}:unexpected_formal_artifact")

    asset_result: Optional[Dict[str, Any]] = None
    if asset_dir is None:
        hard_blockers.append("release_assets_missing")
    else:
        try:
            asset_result = verify_release_assets(asset_dir)
            if asset_result.get("git_sha") != release_sha:
                hard_blockers.append("release_assets_git_sha_not_release_sha")
        except (OSError, ValueError, json.JSONDecodeError, ReleaseAssetError) as exc:
            hard_blockers.append(f"release_assets_invalid:{type(exc).__name__}")

    smoke_result: Optional[Dict[str, Any]] = None
    if smoke_evidence is None:
        hard_blockers.append("production_offline_smoke_missing")
    else:
        smoke_result = json.loads(smoke_evidence.read_text(encoding="utf-8"))
        if smoke_result.get("passed") is not True:
            hard_blockers.append("production_offline_smoke_failed")
        if smoke_result.get("synthetic_payload") is not False:
            hard_blockers.append("production_offline_smoke_is_synthetic")
        if smoke_result.get("network_isolation_confirmed") is not True:
            hard_blockers.append("production_offline_smoke_not_network_isolated")
        if asset_result and smoke_result.get("release_manifest_sha256") != asset_result.get(
            "release_manifest_sha256"
        ):
            hard_blockers.append("offline_smoke_asset_manifest_mismatch")

    hard_blockers = list(dict.fromkeys(hard_blockers))
    rc_blockers = list(dict.fromkeys(rc_blockers))
    if hard_blockers:
        status = "blocked"
    elif rc_blockers:
        status = "rc_only"
    else:
        status = "release_ready"
    return {
        "schema_version": "zscope.release-candidate-audit.v1",
        "status": status,
        "package_version": version,
        "tag": tag or None,
        "release_sha": release_sha,
        "benchmarks": benchmark_results,
        "assets": asset_result,
        "offline_smoke": smoke_result,
        "hard_blockers": hard_blockers,
        "rc_blockers": rc_blockers,
        "advisories": advisories,
        "publishable": status == "release_ready",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--provenance",
        type=Path,
        default=ROOT / "docs/releases/benchmark-provenance.json",
    )
    parser.add_argument("--release-sha", default="")
    parser.add_argument("--package-version", default=package_version())
    parser.add_argument("--tag", default="")
    parser.add_argument("--asset-dir", type=Path)
    parser.add_argument("--offline-smoke-evidence", type=Path)
    parser.add_argument(
        "--formal-artifact",
        action="append",
        default=[],
        metavar="LANGUAGE=DIR",
        help="Verified formal workflow artifact directory; may be repeated",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-incomplete", action="store_true")
    args = parser.parse_args()
    release_sha = (
        args.release_sha
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(ROOT), text=True).strip()
    )
    formal_artifacts: Dict[str, Path] = {}
    for value in args.formal_artifact:
        language, separator, path = value.partition("=")
        if separator != "=" or language not in {"cpp", "java"} or not path:
            raise SystemExit("--formal-artifact must be cpp=DIR or java=DIR")
        if language in formal_artifacts:
            raise SystemExit(f"duplicate --formal-artifact language: {language}")
        formal_artifacts[language] = Path(path)
    report = evaluate_candidate(
        args.provenance,
        release_sha=release_sha,
        version=args.package_version,
        tag=args.tag,
        asset_dir=args.asset_dir,
        smoke_evidence=args.offline_smoke_evidence,
        formal_artifacts=formal_artifacts,
    )
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if not report["publishable"] and not args.allow_incomplete:
        raise SystemExit("release candidate is not publishable")


if __name__ == "__main__":
    main()
