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
    P6_CANDIDATE_COMMIT_ENVIRONMENT_KEY,
    SPECS,
    clean_benchmark_artifacts,
    repository_root,
    run_benchmark,
    score_artifact,
)
from zscope.benchmarking.provider_runtime import (
    P6_API_KEY_ENVIRONMENT_KEY,
    ProviderRuntimeError,
    reject_conflicting_provider_identity_environment,
    require_p6_provider_contract,
    required_environment_keys,
)
from zscope.benchmarking.p6_protocol import FAILURE_CLASS_TO_STAGE, diagnose_pilot


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zscope-benchmark")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run a bundled benchmark")
    run.add_argument("--language", choices=("c_cpp", "java"), required=True)
    run.add_argument("--mode", choices=("smoke", "trial", "formal", "pilot"), required=True)
    run.add_argument("--runs", type=int)
    run.add_argument(
        "--scan-depth",
        choices=("fast", "balanced", "deep"),
        default="fast",
        help="Select the analysis depth; token use is measured after the run.",
    )
    run.add_argument("--output", type=Path)
    run.add_argument("--dry-run", action="store_true")
    clean = commands.add_parser("clean", help="preview or remove generated fixture artifacts")
    clean.add_argument("--scope", choices=("c_cpp", "java", "all"), required=True)
    clean.add_argument("--apply", action="store_true")
    clean.add_argument("--include-runs", action="store_true")
    diagnose = commands.add_parser(
        "diagnose-pilot", help="emit an answer-free P6 pilot failure diagnostic"
    )
    diagnose.add_argument("--run-dir", type=Path, required=True)
    diagnose.add_argument("--output", type=Path, required=True)
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
        elif args.command == "diagnose-pilot":
            payload = dict(diagnose_pilot(args.run_dir.resolve(), args.output.resolve()))
        else:
            if args.mode == "pilot" and not args.dry_run:
                try:
                    pilot_provider = require_p6_provider_contract(SPECS[args.language].config_path)
                    reject_conflicting_provider_identity_environment(pilot_provider, os.environ)
                except ProviderRuntimeError as exc:
                    failure_class = exc.failure_class or "provider_identity_mismatch"
                    raise BenchmarkError(
                        failure_class,
                        failure_class=failure_class,
                    ) from exc
            if (
                platform.system() == "Windows"
                and args.language == "c_cpp"
                and not args.dry_run
                and os.environ.get("Z_SCOPE_BENCHMARK_IN_WSL") != "1"
            ):
                environment = dict(os.environ)
                provider_keys = list(required_environment_keys(SPECS[args.language].config_path))
                if args.mode == "pilot":
                    provider_keys = [
                        key for key in provider_keys if key != P6_API_KEY_ENVIRONMENT_KEY
                    ]
                    provider_keys.append("Z_SCOPE_P6_API_KEY_FILE/p")
                    provider_keys.append(P6_CANDIDATE_COMMIT_ENVIRONMENT_KEY)
                    # The direct key and legacy provider selectors must not be
                    # present in the wsl.exe child environment.  WSL receives
                    # only the explicit one-key file locator; the Linux child
                    # validates and loads it without mutating its global env.
                    environment.pop(P6_API_KEY_ENVIRONMENT_KEY, None)
                    environment.pop("Z_SCOPE_LLM_BASE_URL", None)
                    environment.pop("Z_SCOPE_LLM_MODEL", None)
                provider_keys = [
                    item for item in provider_keys if item.removesuffix("/p") in environment
                ]
                forwarded = [
                    *provider_keys,
                    *(
                        ["Z_SCOPE_DEVELOPER_MODE"]
                        if "Z_SCOPE_DEVELOPER_MODE" in environment
                        else []
                    ),
                    *(["Z_SCOPE_RUNTIME_SPEC/p"] if "Z_SCOPE_RUNTIME_SPEC" in environment else []),
                    *(
                        ["Z_SCOPE_BENCHMARK_WORK_ROOT/p"]
                        if "Z_SCOPE_BENCHMARK_WORK_ROOT" in environment
                        else []
                    ),
                    "Z_SCOPE_BENCHMARK_IN_WSL",
                ]
                environment["Z_SCOPE_BENCHMARK_IN_WSL"] = "1"
                # Never inherit an arbitrary pre-existing WSLENV: it could
                # re-enable a secret or identity variable that pilot mode
                # intentionally removed from the forwarding contract.
                environment["WSLENV"] = ":".join(dict.fromkeys(forwarded))
                completed = subprocess.run(_wsl_argv(arguments), env=environment, check=False)
                raise SystemExit(completed.returncode)
            payload = run_benchmark(
                args.language,
                args.mode,
                runs=args.runs,
                output=args.output,
                dry_run=args.dry_run,
                scan_depth=args.scan_depth,
            )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    except BenchmarkError as exc:
        if getattr(args, "command", "") == "run" and getattr(args, "mode", "") == "pilot":
            allowed = set(FAILURE_CLASS_TO_STAGE)
            public_failure = exc.failure_class
            if public_failure not in allowed:
                public_failure = "internal_failure"
            stage = FAILURE_CLASS_TO_STAGE[public_failure]
            print(
                f"stage={stage}; class={public_failure}:1; count=1",
                file=sys.stderr,
            )
            raise SystemExit(2)
        parser.error(str(exc))


if __name__ == "__main__":
    main()
