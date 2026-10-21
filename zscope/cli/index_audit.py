"""Inventory and measure existing indexing inputs without starting an LLM scan."""

from __future__ import annotations

import json
import logging
import platform
import time
from pathlib import Path
from typing import Any, Dict, Optional

import click

from ..config.config import ConfigLoader
from ..retrieval.indexing_identity import atomic_json, file_digest, digest_json
from ..retrieval.indexing_inventory import inventory
from ..retrieval.indexing_runtime import admitted_workers, resource_limits
from ..retrieval.llvm_toolchain import svf_identity
from ..retrieval.svf_runner import SvfRunner


@click.command()
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option("--bitcode-dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--replay-fixture",
    is_flag=True,
    help="Compare incremental and clean strict-batch facts for the built-in C mutations; no LLM/SVF.",
)
@click.option(
    "--work-directory",
    type=click.Path(path_type=Path),
    help="New directory for replay sources and independent caches; existing paths are refused.",
)
@click.option(
    "--clang-indexer",
    default="zscope-clang-indexer",
    show_default=True,
    help="Native indexer for --replay-fixture only; no install or fallback.",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default="indexing-audit.json",
    show_default=True,
)
@click.option(
    "--tasks",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Explicit JSON task array: group, tool (wpa/saber), bitcode, inputs.",
)
@click.option(
    "--measure-svf",
    is_flag=True,
    help="Run the verified existing task set, largest input first, one process at a time.",
)
@click.option(
    "--window-seconds",
    type=click.FloatRange(min=1),
    default=1800,
    show_default=True,
    help="Stop starting new tasks after this window; an active task retains its configured timeout.",
)
def main(
    config_path: Optional[Path],
    bitcode_dir: Optional[Path],
    output: Path,
    tasks: Optional[Path],
    measure_svf: bool,
    window_seconds: float,
    replay_fixture: bool,
    work_directory: Optional[Path],
    clang_indexer: str,
) -> None:
    """Audit compilation coverage; optionally time the existing bitcode task set."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if replay_fixture:
        if config_path or bitcode_dir or tasks or measure_svf:
            raise click.UsageError("--replay-fixture cannot consume a project config or SVF inputs")
        if work_directory is None:
            raise click.UsageError("--replay-fixture requires --work-directory")
        from ..retrieval.incremental_replay import run_fixture_replay

        try:
            replay = run_fixture_replay(work_directory, clang_indexer=clang_indexer)
        except (ValueError, OSError) as exc:
            raise click.ClickException(str(exc)) from exc
        atomic_json(output, replay)
        click.echo(f"Wrote {output.resolve()}: replay complete={replay['complete']}")
        if not replay["complete"]:
            raise click.ClickException("incremental replay failed; inspect preserved artifacts")
        return
    if work_directory is not None or clang_indexer != "zscope-clang-indexer":
        raise click.UsageError("--work-directory/--clang-indexer require --replay-fixture")
    if config_path is None or bitcode_dir is None:
        raise click.UsageError("normal indexing audit requires --config and --bitcode-dir")
    config = ConfigLoader.load(str(config_path.resolve()))
    cdb = config.project.compile_commands_path
    if config.project.language != "c_cpp" or not cdb:
        raise click.ClickException("A C/C++ config with compile_commands_path is required")
    report = inventory(Path(cdb), bitcode_dir.resolve())
    report.update(
        config=str(config_path.resolve()),
        working_directory=str(Path.cwd()),
        project_root=str(config.project.project_root),
        resources=resource_limits(),
    )
    if tasks:
        task_list = json.loads(tasks.read_text(encoding="utf-8"))
        if not isinstance(task_list, list):
            raise click.ClickException("--tasks must contain a JSON array")
        report["groups"] = task_list
    atomic_json(output, report)
    if measure_svf:
        if platform.system() != "Linux":
            raise click.ClickException(
                "Run SVF measurements inside Linux/WSL with its installed Z-SCOPE environment"
            )
        cfg = config.indexing
        runner = SvfRunner(cfg.svf_bin_dir, cfg.svf_heap_limit_mb, cfg.svf_timeout)
        runner.validate_llvm(cfg.llvm_link_path)
        if not admitted_workers(1, 1, cfg.svf_heap_limit_mb):
            raise click.ClickException("SVF reservation exceeds 75% of available memory")
        groups = report["groups"]
        if not groups or any(group.get("tool") not in {"wpa", "saber"} for group in groups):
            raise click.ClickException(
                "Task roles are unverified; provide --tasks or a current bitcode manifest"
            )
        for group in groups:
            path = Path(group["bitcode"])
            path = path if path.is_absolute() else bitcode_dir / path
            if not path.is_file():
                raise click.ClickException(f"Missing input: {path}")
            group.update(
                bitcode=str(path.resolve()),
                sha256=file_digest(path),
                size_bytes=path.stat().st_size,
            )
        identity = svf_identity(cfg.svf_bin_dir)
        results: Dict[str, Any] = {}
        report["measurements"] = []
        started = time.monotonic()
        # Measure each tool's largest group first, then its smaller groups.
        ordered = []
        remaining = []
        for tool in ("wpa", "saber"):
            tool_groups = sorted(
                (item for item in groups if item["tool"] == tool),
                key=lambda item: item["size_bytes"],
                reverse=True,
            )
            ordered.extend(tool_groups[:1])
            remaining.extend(tool_groups[1:])
        ordered.extend(sorted(remaining, key=lambda item: item["size_bytes"]))
        for group in ordered:
            measurement = dict(group, status="not_executed", reason="validation_window_elapsed")
            report["measurements"].append(measurement)
            key = digest_json(
                {
                    "tool": group["tool"],
                    "input": group["sha256"],
                    "identity": identity,
                    "options": (
                        ["-ander", "-dump-callgraph"]
                        if group["tool"] == "wpa"
                        else ["-leak", "-dfree"]
                    ),
                }
            )
            if key in results:
                measurement.update(
                    status="reused", reason="identical_complete_input", metrics=results[key]
                )
            elif time.monotonic() - started < window_seconds:
                path = Path(group["bitcode"])
                directory = output.resolve().parent / "indexing-measurements" / key
                result = (
                    runner.run_ander(path, directory)
                    if group["tool"] == "wpa"
                    else runner.run_saber(path, directory)
                )
                complete = result.success and (group["tool"] != "wpa" or bool(result.output_file))
                measurement.update(
                    status="success" if complete else "failed",
                    reason=result.stderr[-1000:] if not complete else "",
                    metrics=result.metrics,
                )
                if complete:
                    results[key] = result.metrics
            report["measurement_wall_seconds"] = time.monotonic() - started
            atomic_json(output, report)
        report["measurement_scope"] = (
            "existing bitcode task set; compilation coverage is reported separately"
        )
        atomic_json(output, report)
    click.echo(
        f"Wrote {output.resolve()}: {report['command_entries']} commands, "
        f"{report['compile_contexts']} contexts, coverage_verified={report['coverage_verified']}"
    )


if __name__ == "__main__":
    main()
