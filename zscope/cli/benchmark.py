"""Single public command for bundled Z-SCOPE benchmark execution and cleanup."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from zscope.benchmarking.runner import (
    BenchmarkError,
    clean_benchmark_artifacts,
    repository_root,
    run_benchmark,
    score_artifact,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zscope-benchmark")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run a bundled benchmark")
    run.add_argument("--language", choices=("c_cpp", "java"), required=True)
    run.add_argument("--mode", choices=("smoke", "trial", "formal"), required=True)
    run.add_argument("--runs", type=int)
    run.add_argument("--output", type=Path)
    run.add_argument("--dry-run", action="store_true")
    clean = commands.add_parser("clean", help="preview or remove generated fixture artifacts")
    clean.add_argument("--scope", choices=("c_cpp", "java", "all"), required=True)
    clean.add_argument("--apply", action="store_true")
    clean.add_argument("--include-runs", action="store_true")
    return parser


def _score_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zscope-benchmark _score")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def _wsl_argv(argv: List[str]) -> List[str]:
    root = repository_root()
    converted = subprocess.check_output(["wsl", "wslpath", "-a", str(root)], text=True).strip()
    converted_arguments = list(argv)
    if "--output" in converted_arguments:
        index = converted_arguments.index("--output") + 1
        if index < len(converted_arguments):
            converted_arguments[index] = subprocess.check_output(
                ["wsl", "wslpath", "-a", converted_arguments[index]], text=True
            ).strip()
    forwarded = ["python3", "-m", "zscope.cli.benchmark", *converted_arguments]
    command = (
        "cd " + shlex.quote(converted) + " && " + " ".join(shlex.quote(item) for item in forwarded)
    )
    return ["wsl", "bash", "-lc", command]


def main(argv: Optional[List[str]] = None) -> None:
    arguments = list(argv if argv is not None else sys.argv[1:])
    if arguments[:1] == ["_score"]:
        args = _score_parser().parse_args(arguments[1:])
        try:
            truth = os.environ.get("Z_SCOPE_BENCHMARK_TRUTH", "").strip()
            if not truth:
                raise BenchmarkError("score phase requires Z_SCOPE_BENCHMARK_TRUTH")
            payload = score_artifact(args.report, Path(truth), args.output)
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        except BenchmarkError as exc:
            _score_parser().error(str(exc))
        return
    parser = _parser()
    args = parser.parse_args(arguments)
    try:
        if args.command == "clean":
            payload = clean_benchmark_artifacts(
                args.scope,
                apply=args.apply,
                include_runs=args.include_runs,
            )
        else:
            if (
                platform.system() == "Windows"
                and args.language == "c_cpp"
                and not args.dry_run
                and os.environ.get("Z_SCOPE_BENCHMARK_IN_WSL") != "1"
            ):
                environment = dict(os.environ)
                forwarded = [
                    "Z_SCOPE_LLM_BASE_URL",
                    "Z_SCOPE_LLM_MODEL",
                    "Z_SCOPE_API_KEY",
                    "Z_SCOPE_DEVELOPER_MODE",
                    "Z_SCOPE_RUNTIME_SPEC",
                    "Z_SCOPE_BENCHMARK_WORK_ROOT/p",
                ]
                existing = environment.get("WSLENV", "")
                environment["WSLENV"] = ":".join([item for item in [existing, *forwarded] if item])
                environment["Z_SCOPE_BENCHMARK_IN_WSL"] = "1"
                environment["WSLENV"] += ":Z_SCOPE_BENCHMARK_IN_WSL"
                completed = subprocess.run(_wsl_argv(arguments), env=environment, check=False)
                raise SystemExit(completed.returncode)
            payload = run_benchmark(
                args.language,
                args.mode,
                runs=args.runs,
                output=args.output,
                dry_run=args.dry_run,
            )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    except BenchmarkError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
