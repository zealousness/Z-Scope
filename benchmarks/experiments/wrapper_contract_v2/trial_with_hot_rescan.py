"""Run the official cold trial, then a separately archived hot-cache rescan.

The extra scan runs after the cold report and semantic publication are archived,
before the official runner restores sealed inputs. Neither run is formal evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from zscope.benchmarking import runner


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 13) or sys.platform != "linux":
        raise RuntimeError("This experiment requires Linux Python 3.13")
    for name in runner.SPECS["c_cpp"].required_tools:
        if not shutil.which(name):
            raise RuntimeError("Missing tool: " + name)
    for name in ("wpa", "saber"):
        result = subprocess.run(
            ["ldd", shutil.which(name)], capture_output=True, text=True, check=True
        )
        if "not found" in result.stdout + result.stderr:
            raise RuntimeError("Missing shared library for " + name)
    for name in ("Z_SCOPE_LLM_BASE_URL", "Z_SCOPE_LLM_MODEL", "Z_SCOPE_API_KEY"):
        if not os.environ.get(name):
            raise RuntimeError("Missing " + name)
    output = args.output.resolve()
    matcher = runner.repository_root() / "zscope/benchmarking/protocol.py"
    matcher_hash = hashlib.sha256(matcher.read_bytes()).hexdigest()
    restore = runner.restore_scan_input
    copy_inputs = runner.copy_scan_input
    hot_done = False

    def rescan(source: Path) -> None:
        nonlocal hot_done
        if hot_done:
            return
        hot_done = True
        run_dir = output / "run-01"
        hot = run_dir / "hot-rescan"
        hot.mkdir(parents=True, exist_ok=True)
        environment = runner._benchmark_environment()
        environment.update(
            Z_SCOPE_BENCHMARK_LANGUAGE="c_cpp",
            Z_SCOPE_BENCHMARK_SOURCE=str(source),
            Z_SCOPE_BENCHMARK_CACHE=str(source.parent / "cache"),
        )
        seconds = runner._run_command(
            [
                sys.executable,
                "-m",
                "zscope.cli.cli",
                "-c",
                str(run_dir / "zscope.execution.yaml"),
                "--verbose",
            ],
            cwd=source,
            environment=environment,
            log_path=hot / "scan.log",
            accepted_returncodes=(0, 1, 2),
        )
        report = runner._load_json_object(runner._locate_report(source))
        runner._archive_usage_events(report, scan_root=source, run_dir=hot)
        runner._json_dump(hot / "report.json", report)
        semantic_dir = source / ".zscope_snapshots" / ".semantic-modeling"
        if (semantic_dir / "publication.json").is_file():
            shutil.copy2(semantic_dir / "publication.json", hot / "publication.json")
            publication = runner._load_json_object(semantic_dir / "publication.json")
            workbook = Path(publication["workbook"])
            shutil.copy2(workbook, hot / "user_config.xlsx")
        runner._json_dump(
            hot / "experiment.json",
            {
                "cache": "retained from cold trial",
                "scan_seconds": seconds,
                "matcher_sha256": matcher_hash,
                "release_eligible": False,
                "source": str(source),
            },
        )

    def rescan_then_restore(source: Path, manifest: dict) -> None:
        rescan(source)
        restore(source, manifest)

    def rescan_then_copy(source: Path, destination: Path, language: str) -> dict:
        # Review-capability trials retain their workspace rather than restore
        # it. The archive boundary is still before cleanup and independent score.
        if destination.resolve() == output / "run-01" / "scan-input":
            rescan(source)
        return copy_inputs(source, destination, language)

    runner.restore_scan_input = rescan_then_restore
    runner.copy_scan_input = rescan_then_copy
    try:
        result = runner.run_benchmark("c_cpp", "trial", output=output, scan_depth="balanced")
    finally:
        runner.restore_scan_input = restore
        runner.copy_scan_input = copy_inputs
    if hashlib.sha256(matcher.read_bytes()).hexdigest() != matcher_hash:
        raise RuntimeError("Matcher changed during experiment")
    hot = output / "run-01" / "hot-rescan"
    if hot_done:
        runner.score_artifact(
            hot / "report.json", runner.SPECS["c_cpp"].truth_path, hot / "score.json"
        )
    else:
        raise RuntimeError("Cold trial did not reach the retained-cache rescan boundary")
    runner._json_dump(
        output / "experiment.json",
        {
            "matcher_sha256": matcher_hash,
            "hot_rescan": hot_done,
            "release_eligible": False,
            "cold_trial": result,
        },
    )
    print(str(output))


if __name__ == "__main__":
    main()
