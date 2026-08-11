#!/usr/bin/env python3
"""Run five isolated formal benchmark trials on an approved Linux runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shlex
import shutil
import statistics
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
ANSWER_FILES = {"GROUND_TRUTH.md", "ground_truth.json"}
C_GATES = {
    "confirmed_tp": (">=", 85.0),
    "precision": (">=", 95.0),
    "with_review_tp": (">=", 134.0),
    "with_review_raw_fp": ("<=", 100.0),
    "needs_review": ("<=", 150.0),
    "tokens": ("<=", 6_000_000.0),
    "wall_seconds": ("<=", 3600.0),
}
C_SEALED_GATES = {
    "sealed_confirmed_recall_delta_pp": (">=", -2.0),
    "sealed_precision_delta_pp": (">=", -2.0),
}


def _copy_scan_input(source: Path, destination: Path) -> None:
    def ignore(_directory: str, names: List[str]) -> List[str]:
        return [
            name
            for name in names
            if name in ANSWER_FILES
            or name.startswith(".zscope")
            or name in {"reports", "__pycache__"}
        ]

    shutil.copytree(source, destination, ignore=ignore)
    leaked = [path for path in destination.rglob("*") if path.name in ANSWER_FILES]
    if leaked:
        raise RuntimeError(f"ground truth leaked into scan input: {leaked}")


def _run(command: str, *, env: Dict[str, str], log_path: Path) -> float:
    args = shlex.split(command)
    if not args:
        raise RuntimeError("empty benchmark command")
    started = time.monotonic()
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.run(args, cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT)
    elapsed = time.monotonic() - started
    if proc.returncode != 0:
        raise RuntimeError(f"command failed with exit code {proc.returncode}: {args[0]}")
    return elapsed


def _gate_c(score: Dict[str, Any]) -> List[str]:
    failures = []
    for key, (operator, threshold) in C_GATES.items():
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


def _gate_c_sealed(score: Dict[str, Any]) -> List[str]:
    failures = []
    for key, (operator, threshold) in C_SEALED_GATES.items():
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
    """Flag gross wall/phase outliers without turning Preview variance into a gate."""

    outliers: List[Dict[str, Any]] = []
    series: Dict[str, List[float]] = {}
    for summary in summaries:
        wall = summary.get("metrics", {}).get("wall_seconds")
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
        observed: Dict[str, float] = {}
        wall = summary.get("metrics", {}).get("wall_seconds")
        if isinstance(wall, (int, float)) and not isinstance(wall, bool):
            observed["wall_seconds"] = float(wall)
        observed.update(
            {
                f"phase_seconds.{phase}": float(value)
                for phase, value in summary.get("phase_seconds", {}).items()
                if isinstance(value, (int, float)) and not isinstance(value, bool)
            }
        )
        for name, value in observed.items():
            threshold = thresholds.get(name)
            if threshold is not None and value > threshold:
                outliers.append(
                    {
                        "run": summary.get("run"),
                        "metric": name,
                        "value": round(value, 4),
                        "threshold": round(threshold, 4),
                    }
                )
    return outliers


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--language", choices=("cpp", "java"), required=True)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux":
        raise SystemExit("formal benchmarks require a Linux userland (Windows must use WSL2)")
    if args.runs < 5:
        raise SystemExit("formal release benchmarks require at least five cold trials")

    prefix = f"Z_SCOPE_{args.language.upper()}"
    health_command = os.environ.get(f"{prefix}_HEALTH_COMMAND", "").strip()
    scan_command = os.environ.get(f"{prefix}_SCAN_COMMAND", "").strip()
    score_command = os.environ.get(f"{prefix}_SCORE_COMMAND", "").strip()
    if not health_command or not scan_command or not score_command:
        raise SystemExit(
            f"{prefix}_HEALTH_COMMAND, {prefix}_SCAN_COMMAND, and {prefix}_SCORE_COMMAND are required"
        )

    source = ROOT / ("test/range" if args.language == "cpp" else "test/java_range")
    truth = source / "benchmark" / "ground_truth.json"
    if not truth.is_file():
        raise SystemExit(f"ground truth is missing: {truth}")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    summaries = []
    for index in range(1, args.runs + 1):
        run_dir = output / f"run-{index:02d}"
        scan_input = run_dir / "scan-input"
        cache_dir = run_dir / "cache"
        report = run_dir / "report.json"
        score = run_dir / "score.json"
        run_dir.mkdir(parents=True, exist_ok=False)
        cache_dir.mkdir()
        _copy_scan_input(source, scan_input)
        env = {
            **os.environ,
            "Z_SCOPE_BENCHMARK_LANGUAGE": args.language,
            "Z_SCOPE_BENCHMARK_SOURCE": str(scan_input),
            "Z_SCOPE_BENCHMARK_CACHE": str(cache_dir),
            "Z_SCOPE_BENCHMARK_REPORT": str(report),
            "Z_SCOPE_BENCHMARK_SCORE": str(score),
        }
        started = time.monotonic()
        phase_seconds = {
            "health": _run(health_command, env=env, log_path=run_dir / "health.log"),
            "scan": _run(scan_command, env=env, log_path=run_dir / "scan.log"),
        }
        if not report.is_file():
            raise RuntimeError(f"scan did not produce {report}")
        score_env = {**env, "Z_SCOPE_BENCHMARK_TRUTH": str(truth.resolve())}
        phase_seconds["score"] = _run(score_command, env=score_env, log_path=run_dir / "score.log")
        phase_seconds["total"] = time.monotonic() - started
        if not score.is_file():
            raise RuntimeError(f"scorer did not produce {score}")
        payload = json.loads(score.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError(f"score payload must be an object: {score}")
        payload.setdefault("wall_seconds", time.monotonic() - started)
        failures = _gate_c(payload) if args.language == "cpp" else []
        sealed_failures = _gate_c_sealed(payload) if args.language == "cpp" else []
        summary = {
            "run": index,
            "completed": True,
            "queue_empty": bool(payload.get("queue_empty", False)),
            "gate_failures": failures,
            "sealed_gate_failures": sealed_failures,
            "completeness": {
                "report_present": report.is_file(),
                "score_present": score.is_file(),
                "summary_present": True,
                "backend_health_present": (run_dir / "health.log").is_file(),
                "queue_empty": bool(payload.get("queue_empty", False)),
                "backend_valid": True,
                "source_truth_isolated": True,
            },
            "phase_seconds": {phase: round(seconds, 4) for phase, seconds in phase_seconds.items()},
            "metrics": payload,
        }
        (run_dir / "summary.json").write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8"
        )
        summaries.append(summary)

    numeric_keys = sorted(
        {
            key
            for summary in summaries
            for key, value in summary["metrics"].items()
            if isinstance(value, (int, float)) and not isinstance(value, bool)
        }
    )
    medians = {
        key: statistics.median(
            float(summary["metrics"][key]) for summary in summaries if key in summary["metrics"]
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
    passed = all(summary["queue_empty"] and not summary["gate_failures"] for summary in summaries)
    sealed_set_verified = args.language != "cpp" or all(
        not summary["sealed_gate_failures"] for summary in summaries
    )
    aggregate = {
        "schema_version": "zscope.formal-benchmark.v2",
        "language": args.language,
        "git_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "git_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip(),
        "command_sha256": {
            "health": hashlib.sha256(health_command.encode("utf-8")).hexdigest(),
            "scan": hashlib.sha256(scan_command.encode("utf-8")).hexdigest(),
            "score": hashlib.sha256(score_command.encode("utf-8")).hexdigest(),
        },
        "cold_runs": len(summaries),
        "all_completed": len(summaries) == args.runs,
        "passed": passed,
        "sealed_set_verified": sealed_set_verified,
        "medians": medians,
        "phase_medians": phase_medians,
        "performance_outliers": _performance_outliers(summaries),
        "runs": summaries,
    }
    (output / "aggregate.json").write_text(json.dumps(aggregate, indent=2) + "\n", encoding="utf-8")
    if not passed:
        raise SystemExit("formal benchmark gates failed")


if __name__ == "__main__":
    main()
