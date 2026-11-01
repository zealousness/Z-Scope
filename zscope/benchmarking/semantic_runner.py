"""Native admission checks and answer-isolated interface discovery trials."""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tempfile
import time
from typing import Any

from .runner import (
    BenchmarkError,
    SPECS,
    _benchmark_environment,
    _benchmark_work_parent,
    _build_fixture,
    _is_windows_mount_in_wsl,
    _is_wsl,
    _json_dump,
    _record_range_link_target,
    _require_llm_environment,
    _run_command,
    _sha256_file,
    _tool_health,
    _write_execution_config,
    copy_scan_input,
    _read_usage_events_jsonl,
)
from .semantics import seed_document, validate_reviewed
from ..config.project_semantics import _yaml_round_trip_dump


def model_evaluation_complete(
    advisory: dict[str, Any], proposals: dict[str, Any], usage: dict[str, Any]
) -> bool:
    """Either discovery channel can supply the work; neither may hide errors."""
    return bool(
        advisory.get("eligible", 0) + proposals.get("eligible", 0) > 0
        and usage.get("calls", 0) > 0
        and all(
            stage.get("eligible", 0) == stage.get("reviewed", 0) and not stage.get("errors", 0)
            for stage in (advisory, proposals)
        )
    )


def archive_semantic_state(project: Path, output: Path) -> dict[str, Any]:
    """Retain partial discoveries and failed HTTP attempts as well as successes."""
    path = project / "zscope.semantics.yaml"
    if path.is_file():
        shutil.copy2(path, output / "zscope.semantics.yaml")
    snapshot = project / ".zscope_snapshots" / "semantics"
    if snapshot.is_dir():
        shutil.copytree(snapshot, output / "evidence", dirs_exist_ok=True)
    artifacts: list[dict[str, Any]] = []
    events: dict[str, dict[str, Any]] = {}
    for path in sorted((project / ".zscope_snapshots").glob("llm_usage_events_*.jsonl")):
        if not path.stat().st_size:
            continue
        rows = _read_usage_events_jsonl(path)
        shutil.copy2(path, output / path.name)
        artifacts.append({"path": path.name, "sha256": _sha256_file(path), "calls": len(rows)})
        for row in rows:
            if row["call_id"] in events and events[row["call_id"]] != row:
                raise BenchmarkError("Conflicting discovery usage attempts")
            events[row["call_id"]] = row
    result = {
        "artifacts": artifacts,
        "calls": len(events),
        "total_tokens": sum(row["total_tokens"] for row in events.values()),
        "provider_reported_calls": sum(bool(row["provider_reported"]) for row in events.values()),
    }
    _json_dump(output / "usage.json", result)
    return result


def run_semantic_benchmark(
    *,
    output: Path,
    work_directory: Path | None = None,
    scan_depth: str = "fast",
    discovery: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    if scan_depth not in {"fast", "balanced", "deep"}:
        raise BenchmarkError("Unknown scan depth")
    if work_directory is not None:
        if not work_directory.is_absolute() or work_directory.exists():
            raise BenchmarkError("--work-directory must be an absolute, new directory")
        if _is_wsl() and _is_windows_mount_in_wsl(work_directory):
            raise BenchmarkError("C/C++ work-directory must use the WSL native filesystem")
    if dry_run:
        return {
            "dry_run": True,
            "scan_depth": scan_depth,
            "llm_called": False,
            "llm_requested": discovery,
            "stages": (
                ["copy", "build", "link-record", "discover", "score"]
                if discovery
                else ["copy", "build", "link-record", "semantics-prepare", "health"]
            ),
            "release_eligible": False,
        }
    if platform.system() != "Linux":
        raise BenchmarkError("Semantic benchmark requires Linux/WSL")
    if discovery:
        _require_llm_environment()
    spec = SPECS["c_cpp"]
    reference_path = spec.fixture_root / "zscope.semantics.yaml"
    reference_sha256 = _sha256_file(reference_path)
    # Preparation also checks the tool prerequisites of the subsequent scan.
    health = _tool_health(spec)
    if not health["ok"]:
        raise BenchmarkError(
            "Missing tools: " + ", ".join(row["tool"] for row in health["checks"] if not row["ok"])
        )
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    workspace = work_directory or Path(
        tempfile.mkdtemp(prefix="zscope-semantic-benchmark-", dir=_benchmark_work_parent("c_cpp"))
    )
    workspace.mkdir(parents=True, exist_ok=True)
    _json_dump(
        output / "workspace.json", {"path": str(workspace), "retained": work_directory is not None}
    )
    started = time.monotonic()
    try:
        project = workspace / "project"
        copy_scan_input(spec.fixture_root, project, "c_cpp")
        if discovery:
            # The reviewed YAML must be absent BEFORE discovery/index/LLM start.
            _yaml_round_trip_dump(project / "zscope.semantics.yaml", seed_document())
        shutil.copy2(project / "zscope.semantics.yaml", output / "input.semantics.yaml")
        from .runner import scan_input_manifest

        manifest = scan_input_manifest(project)
        _json_dump(output / "input-manifest.json", manifest)
        config_path = project / "zscope.execution.yaml"
        _write_execution_config(spec, project, config_path, scan_depth=scan_depth)
        shutil.copy2(config_path, output / "zscope.execution.yaml")
        environment = _benchmark_environment()
        if not discovery:
            for key, value in {
                "Z_SCOPE_LLM_BASE_URL": "https://benchmark.invalid/v1",
                "Z_SCOPE_LLM_MODEL": "native-preparation",
                "Z_SCOPE_API_KEY": "no-model-call",
            }.items():
                environment.setdefault(key, value)
        _build_fixture(spec, project, output)
        _record_range_link_target(project, output, environment=environment)
        if discovery:
            argv = [
                sys.executable,
                "-m",
                "zscope.cli.cli",
                "-c",
                str(config_path),
                "--discover-primitives",
            ]
        else:
            argv = [
                sys.executable,
                "-m",
                "zscope.benchmarking.semantics",
                "--config",
                str(config_path),
            ]
        try:
            seconds = _run_command(
                argv, cwd=project, environment=environment, log_path=output / "semantics.log"
            )
        finally:
            usage = archive_semantic_state(project, output)
        semantics_path = output / "zscope.semantics.yaml"
        shutil.copy2(project / "zscope.semantics.yaml", semantics_path)
        _json_dump(output / "tool-health.json", health)
        if discovery:
            # The subprocess is finished, raw output has been archived; only
            # now may the independent host scorer open its reviewed reference.
            import yaml
            from .semantic_scoring import score_discovery

            if _sha256_file(reference_path) != reference_sha256:
                raise BenchmarkError("Reviewed semantic reference changed during discovery")
            reference = validate_reviewed(
                yaml.safe_load(reference_path.read_text(encoding="utf-8")), project
            )
            score = score_discovery(
                yaml.safe_load(semantics_path.read_text(encoding="utf-8")), reference
            )
            audit = score["discovery_llm"]
            proposals = (
                yaml.safe_load(semantics_path.read_text(encoding="utf-8"))
                .get("discovery_receipt", {})
                .get("contract_proposals", {})
            )
            score["model_evaluation_complete"] = model_evaluation_complete(audit, proposals, usage)
            score["contract_proposal_audit"] = proposals
            score.update(
                {
                    "output_sha256": _sha256_file(semantics_path),
                    "reference_sha256": _sha256_file(reference_path),
                }
            )
            _json_dump(output / "score.json", score)
            shutil.copy2(reference_path, output / "reference.semantics.yaml")
        else:
            _run_command(
                [sys.executable, "-m", "zscope.cli.doctor", "--config", str(config_path)],
                cwd=project,
                environment=environment,
                log_path=output / "health.log",
            )
        result = {
            "schema_version": "zscope.semantic-benchmark.v1",
            "completed": True,
            "scan_depth": scan_depth,
            "operation": "discovery" if discovery else "prepare",
            "ready": not discovery,
            "llm_called": usage["calls"] > 0,
            "model_evaluation_complete": score["model_evaluation_complete"] if discovery else None,
            "usage": usage,
            "release_eligible": False,
            "semantics_seconds": seconds,
            "wall_seconds": time.monotonic() - started,
        }
        _json_dump(output / "summary.json", result)
        return result
    finally:
        if work_directory is None:
            shutil.rmtree(workspace)
