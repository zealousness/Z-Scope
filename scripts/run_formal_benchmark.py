#!/usr/bin/env python3
"""Run five isolated formal benchmark trials on an approved Linux runner."""

from __future__ import annotations

import argparse
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
    "raw_fp": ("<=", 100.0),
    "needs_review": ("<=", 150.0),
    "tokens": ("<=", 6_000_000.0),
    "wall_seconds": ("<=", 3600.0),
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


def _run(command: str, *, env: Dict[str, str], log_path: Path) -> None:
    args = shlex.split(command)
    if not args:
        raise RuntimeError("empty benchmark command")
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.run(args, cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        raise RuntimeError(f"command failed with exit code {proc.returncode}: {args[0]}")


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
        _run(health_command, env=env, log_path=run_dir / "health.log")
        _run(scan_command, env=env, log_path=run_dir / "scan.log")
        if not report.is_file():
            raise RuntimeError(f"scan did not produce {report}")
        score_env = {**env, "Z_SCOPE_BENCHMARK_TRUTH": str(truth.resolve())}
        _run(score_command, env=score_env, log_path=run_dir / "score.log")
        if not score.is_file():
            raise RuntimeError(f"scorer did not produce {score}")
        payload = json.loads(score.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError(f"score payload must be an object: {score}")
        payload.setdefault("wall_seconds", time.monotonic() - started)
        failures = _gate_c(payload) if args.language == "cpp" else []
        summary = {
            "run": index,
            "completed": True,
            "queue_empty": bool(payload.get("queue_empty", False)),
            "gate_failures": failures,
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
    passed = all(summary["queue_empty"] and not summary["gate_failures"] for summary in summaries)
    aggregate = {
        "schema_version": "zscope.formal-benchmark.v1",
        "language": args.language,
        "git_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "cold_runs": len(summaries),
        "all_completed": len(summaries) == args.runs,
        "passed": passed,
        "medians": medians,
        "runs": summaries,
    }
    (output / "aggregate.json").write_text(json.dumps(aggregate, indent=2) + "\n", encoding="utf-8")
    if not passed:
        raise SystemExit("formal benchmark gates failed")


if __name__ == "__main__":
    main()
