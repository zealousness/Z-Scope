"""Performance tooling for Z-Scope using test/range as a fixed workload.

The benchmark project is only the workload. This script profiles Z-Scope itself
and writes all artifacts under ``test/range/benchmark_runs/perf_*``.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
RUNS_ROOT = REPO_ROOT / "test" / "range" / "benchmark_runs"
AUTO_CONFIG = REPO_ROOT / "test" / "range" / "zscope.benchmark.yaml"
GROUND_TRUTH = REPO_ROOT / "test" / "range" / "benchmark" / "ground_truth.json"
HARNESS_DIR = REPO_ROOT / "scripts" / "perf_harness"
TIMESTAMP_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")


def _json_load(path: Path, default: Any = None) -> Any:
    try:
        from zscope.reporting.json_io import read_report
        return read_report(path)
    except (OSError, json.JSONDecodeError):
        return default


def _json_dump(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def _now_run_id(prefix: str) -> str:
    return f"{prefix}_{_dt.datetime.now().strftime('%Y%m%d_%H%M%S')}"


def _log_timestamp(line: str) -> Optional[_dt.datetime]:
    match = TIMESTAMP_RE.match(line)
    if not match:
        return None
    try:
        return _dt.datetime.strptime(match.group("ts"), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _parse_time_v(path: Path) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    if not path.exists():
        return data
    key_map = {
        "User time (seconds)": "user_seconds",
        "System time (seconds)": "system_seconds",
        "Percent of CPU this job got": "cpu_percent",
        "Elapsed (wall clock) time (h:mm:ss or m:ss)": "elapsed",
        "Maximum resident set size (kbytes)": "max_rss_kb",
        "Major (requiring I/O) page faults": "major_page_faults",
        "Minor (reclaiming a frame) page faults": "minor_page_faults",
        "File system inputs": "fs_inputs",
        "File system outputs": "fs_outputs",
        "Exit status": "exit_status",
    }
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        matched_key = None
        matched_val = ""
        for raw_key in key_map:
            prefix = f"{raw_key}:"
            if stripped.startswith(prefix):
                matched_key = raw_key
                matched_val = stripped[len(prefix) :].strip()
                break
        if matched_key is None:
            continue
        key = key_map.get(matched_key)
        if not key:
            continue
        val = matched_val
        if key in {"user_seconds", "system_seconds"}:
            try:
                data[key] = float(val)
            except ValueError:
                data[key] = val
        elif key in {
            "max_rss_kb",
            "major_page_faults",
            "minor_page_faults",
            "fs_inputs",
            "fs_outputs",
            "exit_status",
        }:
            try:
                data[key] = int(val)
            except ValueError:
                data[key] = val
        else:
            data[key] = val
    return data


def _slow_entries(report: Dict[str, Any], limit: int = 15) -> List[Dict[str, Any]]:
    rows = report.get("function_results") if isinstance(report, dict) else []
    if not isinstance(rows, list):
        return []
    compact = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        compact.append(
            {
                "function": row.get("function"),
                "entry_key": row.get("entry_key"),
                "duration_seconds": row.get("duration_seconds"),
                "issue_count": row.get("issue_count"),
                "context_tokens": row.get("context_tokens"),
                "tool_call_count": (
                    (row.get("validation_performance") or {}).get("tool_call_count")
                ),
                "iterations": ((row.get("validation_performance") or {}).get("iterations")),
                "error": row.get("error"),
            }
        )
    return sorted(compact, key=lambda item: float(item.get("duration_seconds") or 0), reverse=True)[
        :limit
    ]


def _extract_log_markers(path: Path) -> Dict[str, Any]:
    tool_calls: Counter[str] = Counter()
    markers = {
        "first_timestamp": None,
        "last_timestamp": None,
        "entry_discovery_started": None,
        "entry_discovery_done": None,
        "svf_started": None,
        "svf_done": None,
        "shared_semantics_started": None,
        "shared_semantics_done": None,
        "batch_complete": None,
        "entry_worker_end_count": 0,
        "llm_request_count_estimate": 0,
        "llm_request_error_count": 0,
        "llm_stream_timeout_count": 0,
        "tool_call_count_estimate": 0,
        "tool_calls_by_name": {},
        "snippet_replay_count": 0,
        "snapshot_lock_outcomes": {},
    }
    snapshot_locks: Counter[str] = Counter()
    if not path.exists():
        return markers
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        ts = _log_timestamp(line)
        if ts:
            markers["first_timestamp"] = markers["first_timestamp"] or ts.isoformat(sep=" ")
            markers["last_timestamp"] = ts.isoformat(sep=" ")
        if "Entry discovery activated" in line:
            markers["entry_discovery_started"] = ts.isoformat(sep=" ") if ts else None
        elif "Entry discovery:" in line:
            markers["entry_discovery_done"] = ts.isoformat(sep=" ") if ts else None
        elif "SVF incremental:" in line:
            markers["svf_started"] = markers["svf_started"] or (
                ts.isoformat(sep=" ") if ts else None
            )
        elif "SVF analysis completed" in line:
            markers["svf_done"] = ts.isoformat(sep=" ") if ts else None
        elif "[entry-worker] shared-semantics start" in line:
            markers["shared_semantics_started"] = ts.isoformat(sep=" ") if ts else None
        elif "[entry-worker] shared-semantics end" in line:
            markers["shared_semantics_done"] = ts.isoformat(sep=" ") if ts else None
        elif "[entry-worker] end entry=" in line:
            markers["entry_worker_end_count"] += 1
        elif "Token usage" in line or "[LLM API Trace]" in line:
            markers["llm_request_count_estimate"] += 1
        elif "request error" in line:
            markers["llm_request_error_count"] += 1
            if "stream exceeded" in line:
                markers["llm_stream_timeout_count"] += 1
        elif "Tool call:" in line:
            markers["tool_call_count_estimate"] += 1
            _, _, tool_name = line.partition("Tool call:")
            tool_name = tool_name.strip().split()[0] if tool_name.strip() else "unknown"
            tool_calls[tool_name] += 1
        elif "Replayed cached result for covered get_file_snippet range" in line:
            markers["snippet_replay_count"] += 1
        elif "[snapshot-lock] outcome" in line:
            if "status=done" in line:
                snapshot_locks["done"] += 1
            elif "status=acquired" in line:
                snapshot_locks["acquired"] += 1
            elif "status=timeout" in line:
                snapshot_locks["timeout"] += 1
            else:
                snapshot_locks["other"] += 1
        elif "Batch Analysis Complete" in line:
            markers["batch_complete"] = ts.isoformat(sep=" ") if ts else None
    markers["tool_calls_by_name"] = dict(tool_calls.most_common(50))
    markers["snapshot_lock_outcomes"] = dict(snapshot_locks)
    return markers


def _summarize_run_dir(run_dir: Path) -> Dict[str, Any]:
    run_summary = _json_load(run_dir / "run_summary.json", {})
    report = _json_load(run_dir / "zscope_batch_report.json", {})
    evaluation = _json_load(run_dir / "evaluation.json", {})
    review_eval = _json_load(run_dir / "evaluation.with_needs_review.json", {})
    entries = _json_load(run_dir / "entry_functions_list.json", {})
    summary = report.get("summary", {}) if isinstance(report, dict) else {}
    entries_discovered = (run_summary.get("entry_discovery") or {}).get("entries_discovered")
    if not entries_discovered and isinstance(entries, dict):
        entries_discovered = len(entries.get("functions", []))
    return {
        "run_id": run_dir.name,
        "run_dir": _rel(run_dir),
        "scan_wall_seconds": run_summary.get("scan_wall_seconds"),
        "scan_completed": run_summary.get("scan_completed"),
        "entries_discovered": entries_discovered,
        "report_summary": summary,
        "benchmark_metrics": {
            "default": {
                key: evaluation.get(key)
                for key in (
                    "report_issue_count",
                    "true_positives",
                    "false_positives",
                    "false_positives_raw",
                    "false_positives_effective",
                    "duplicate_of_matched_count",
                    "false_negatives",
                    "precision",
                    "false_discovery_rate",
                    "recall",
                    "f1",
                )
            },
            "with_needs_review": {
                key: review_eval.get(key)
                for key in (
                    "report_issue_count",
                    "true_positives",
                    "false_positives",
                    "false_positives_raw",
                    "false_positives_effective",
                    "duplicate_of_matched_count",
                    "false_negatives",
                    "precision",
                    "false_discovery_rate",
                    "recall",
                    "f1",
                )
            },
        },
        "log_markers": {
            "build_cpg": _extract_log_markers(run_dir / "build_cpg.log"),
            "scan": _extract_log_markers(run_dir / "zscope_run.log"),
        },
        "slow_entries": _slow_entries(report),
    }


def _percentile(values: Sequence[float], pct: float) -> Optional[float]:
    if not values:
        return None
    sorted_values = sorted(values)
    index = int(round((len(sorted_values) - 1) * pct))
    return round(sorted_values[index], 3)


def _aggregate_historical(runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    completed = [run for run in runs if run.get("scan_completed")]
    wall = [
        float(run["scan_wall_seconds"])
        for run in completed
        if run.get("scan_wall_seconds") is not None
    ]
    latest = completed[-1] if completed else (runs[-1] if runs else {})
    return {
        "run_count": len(runs),
        "completed_run_count": len(completed),
        "wall_seconds": {
            "min": min(wall) if wall else None,
            "p50": _percentile(wall, 0.5),
            "p95": _percentile(wall, 0.95),
            "max": max(wall) if wall else None,
            "latest": latest.get("scan_wall_seconds"),
        },
        "latest_completed": latest,
    }


def command_history(args: argparse.Namespace) -> int:
    output_dir = (
        Path(args.output_dir) if args.output_dir else RUNS_ROOT / _now_run_id("perf_history")
    )
    candidates = sorted(
        path
        for path in RUNS_ROOT.iterdir()
        if path.is_dir()
        and path.name.startswith(args.prefix)
        and (path / "run_summary.json").exists()
    )
    runs = [_summarize_run_dir(path) for path in candidates]
    result = {
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "source_runs_root": _rel(RUNS_ROOT),
        "run_prefix": args.prefix,
        "runs": runs,
        "aggregate": _aggregate_historical(runs),
    }
    _json_dump(output_dir / "historical_baseline.json", result)
    _write_report(output_dir, result)
    print(f"[perf] historical baseline: {output_dir / 'historical_baseline.json'}")
    print(f"[perf] report: {output_dir / 'performance_report.md'}")
    return 0


def _require_wsl() -> None:
    proc_version = Path("/proc/version")
    text = (
        proc_version.read_text(encoding="utf-8", errors="replace") if proc_version.exists() else ""
    )
    if "microsoft" not in text.lower() and "wsl" not in text.lower():
        raise SystemExit("profile must run inside WSL/Linux for the range unified workload")


def _run_bash(script: str, *, env: Dict[str, str]) -> int:
    proc = subprocess.run(["bash", "-lc", script], cwd=REPO_ROOT, env=env)
    return int(proc.returncode)


def _profile_command(
    command: str, log_path: Path, time_path: Path, speedscope_path: Path, use_py_spy: bool
) -> str:
    log = _shell_quote(log_path.as_posix())
    time_file = _shell_quote(time_path.as_posix())
    if use_py_spy:
        profile = _shell_quote(speedscope_path.as_posix())
        profiled = (
            "py-spy record --format speedscope --native --subprocesses "
            f"-o {profile} -- {command}"
        )
    else:
        profiled = command
    return f"/usr/bin/time -v -o {time_file} {profiled} > {log} 2>&1"


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def command_profile(args: argparse.Namespace) -> int:
    _require_wsl()
    run_id = args.run_id or _now_run_id("perf_profile")
    run_dir = RUNS_ROOT / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    timeline = run_dir / "timeline.jsonl"
    py_spy_available = shutil.which("py-spy") is not None
    use_py_spy = bool(py_spy_available and not args.no_py_spy)
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{HARNESS_DIR}:{REPO_ROOT}" + (
        f":{existing_pythonpath}" if existing_pythonpath else ""
    )
    env["Z_SCOPE_PERF_TIMELINE"] = str(timeline)
    env["Z_SCOPE_PERF_RUN_ID"] = run_id

    config_path = "test/range/zscope.benchmark.yaml"
    build_cmd = f"python3 -m zscope.cli.cli -c {config_path} --build-index"
    scan_cmd = f"python3 -m zscope.cli.cli -c {config_path} --discover-entries --verbose"
    script = f"""
set -euo pipefail
if [[ -f test/range/zscope.local.env ]]; then
  source test/range/zscope.local.env
fi
if [[ -z "${{Z_SCOPE_API_KEY:-}}" ]]; then
  echo "[perf] ERROR: Z_SCOPE_API_KEY is not set." >&2
  exit 2
fi
export PATH="$HOME/go/bin:/usr/lib/llvm-18/bin:$HOME/.local/svf/SVF-linux-x86_64/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/.local/svf/SVF-linux-x86_64/lib:$HOME/.local/svf/llvm-18.1.0.obj/lib:${{LD_LIBRARY_PATH:-}}"
export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-18
python3 scripts/range_perf_analysis.py preflight
rm -rf test/range/.zscope_snapshots test/range/.zscope_knowledge
rm -f test/range/zscope_batch_report.json test/range/zscope_batch_report.md test/range/entry_functions_list.json
{_profile_command("cmake -S test/range -B test/range/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON", run_dir / "cmake.log", run_dir / "cmake.time", run_dir / "cmake.speedscope.json", False)}
{_profile_command(build_cmd, run_dir / "build_cpg.log", run_dir / "build_cpg.time", run_dir / "build_cpg.speedscope.json", use_py_spy)}
set +e
{_profile_command(scan_cmd, run_dir / "zscope_run.log", run_dir / "scan.time", run_dir / "scan.speedscope.json", use_py_spy)}
scan_rc="$?"
set -e
printf '%s\\n' "$scan_rc" > {_shell_quote((run_dir / "scan.returncode").as_posix())}
if [[ -f test/range/entry_functions_list.json ]]; then cp test/range/entry_functions_list.json {_shell_quote((run_dir / "entry_functions_list.json").as_posix())}; fi
if [[ -f test/range/zscope_batch_report.json ]]; then cp test/range/zscope_batch_report.json {_shell_quote((run_dir / "zscope_batch_report.json").as_posix())}; fi
if [[ -f test/range/zscope_batch_report.md ]]; then cp test/range/zscope_batch_report.md {_shell_quote((run_dir / "zscope_batch_report.md").as_posix())}; fi
cp {config_path} {_shell_quote((run_dir / "zscope.benchmark.yaml").as_posix())}
if [[ -f {_shell_quote((run_dir / "zscope_batch_report.json").as_posix())} ]]; then
  python3 scripts/external_benchmark.py evaluate --report {_shell_quote((run_dir / "zscope_batch_report.json").as_posix())} --truth test/range/benchmark/ground_truth.json --output {_shell_quote((run_dir / "evaluation.json").as_posix())}
  python3 scripts/external_benchmark.py evaluate --report {_shell_quote((run_dir / "zscope_batch_report.json").as_posix())} --truth test/range/benchmark/ground_truth.json --output {_shell_quote((run_dir / "evaluation.with_needs_review.json").as_posix())} --view with_needs_review
fi
python3 scripts/range_perf_analysis.py summarize --run-dir {_shell_quote(run_dir.as_posix())}
if [[ "$scan_rc" -ne 0 && ! -f {_shell_quote((run_dir / "zscope_batch_report.json").as_posix())} ]]; then
  exit "$scan_rc"
fi
"""
    rc = _run_bash(script, env=env)
    print(f"[perf] profile artifacts: {run_dir}")
    if not use_py_spy:
        print(
            "[perf] py-spy was not used; install py-spy or omit --no-py-spy for speedscope profiles."
        )
    return rc


def _preflight_config() -> Dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise SystemExit("PyYAML is required for preflight") from exc
    cfg = yaml.safe_load(AUTO_CONFIG.read_text(encoding="utf-8"))
    indexing = cfg.get("indexing") or {}
    project = cfg.get("project") or {}
    discovery = project.get("entry_discovery") or {}
    checks = {
        "config_version": cfg.get("config_version"),
        "backend": indexing.get("backend"),
        "entry_discovery_enabled": bool(discovery.get("enabled")),
        "interface_files": discovery.get("interface_files") or [],
    }
    failures = []
    if checks["config_version"] != 2:
        failures.append(f"expected config_version=2, got {checks['config_version']!r}")
    if checks["backend"] != "unified":
        failures.append(f"expected indexing.backend=unified, got {checks['backend']!r}")
    if checks["entry_discovery_enabled"] is not True:
        failures.append("expected project.entry_discovery.enabled=true")
    if checks["interface_files"] != ["**/*.h"]:
        failures.append(
            "expected interface_files=['**/*.h'], " f"got {checks['interface_files']!r}"
        )
    if failures:
        raise SystemExit("; ".join(failures))
    return checks


def command_preflight(_args: argparse.Namespace) -> int:
    checks = _preflight_config()
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0


def _load_timeline(path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    if not path.exists():
        return events
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            events.append(item)
    return events


def _aggregate_timeline(events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    by_phase: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "duration_ms": 0.0, "errors": 0}
    )
    slow_events: List[Dict[str, Any]] = []
    llm = {
        "count": 0,
        "duration_ms": 0.0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
    }
    tools = Counter()
    tool_durations: Dict[str, float] = defaultdict(float)
    for event in events:
        if event.get("event") != "timing":
            continue
        phase = str(event.get("phase") or "unknown")
        duration = float(event.get("duration_ms") or 0.0)
        bucket = by_phase[phase]
        bucket["count"] += 1
        bucket["duration_ms"] += duration
        if event.get("error"):
            bucket["errors"] += 1
        if phase == "llm.chat_completion":
            details = event.get("details") if isinstance(event.get("details"), dict) else {}
            llm["count"] += 1
            llm["duration_ms"] += duration
            for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                try:
                    llm[key] += int(details.get(key) or 0)
                except (TypeError, ValueError):
                    pass
        if phase in {"tool.execute", "agent.tool_execute"}:
            details = event.get("details") if isinstance(event.get("details"), dict) else {}
            tool_name = str(details.get("tool_name") or "unknown")
            tools[tool_name] += 1
            tool_durations[tool_name] += duration
        slow_events.append(
            {
                "phase": phase,
                "target": event.get("target"),
                "entry": event.get("entry"),
                "duration_ms": duration,
                "details": event.get("details", {}),
            }
        )
    phases = []
    for phase, data in by_phase.items():
        count = max(1, int(data["count"]))
        phases.append(
            {
                "phase": phase,
                "count": data["count"],
                "total_seconds": round(float(data["duration_ms"]) / 1000.0, 3),
                "avg_ms": round(float(data["duration_ms"]) / count, 3),
                "errors": data["errors"],
            }
        )
    phases.sort(key=lambda item: item["total_seconds"], reverse=True)
    slow_events.sort(key=lambda item: item["duration_ms"], reverse=True)
    llm["duration_seconds"] = round(llm.pop("duration_ms") / 1000.0, 3)
    return {
        "phases": phases,
        "slow_events": slow_events[:30],
        "llm": llm,
        "tools": [
            {
                "tool_name": name,
                "count": count,
                "total_seconds": round(tool_durations[name] / 1000.0, 3),
                "avg_ms": round(tool_durations[name] / max(1, count), 3),
            }
            for name, count in tools.most_common(30)
        ],
    }


def command_summarize(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    if not run_dir.is_absolute():
        run_dir = REPO_ROOT / run_dir
    result = {
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "run": _summarize_run_dir(run_dir),
        "time_v": {
            "cmake": _parse_time_v(run_dir / "cmake.time"),
            "build_cpg": _parse_time_v(run_dir / "build_cpg.time"),
            "scan": _parse_time_v(run_dir / "scan.time"),
        },
        "profiles": {
            "build_cpg_speedscope": (
                _rel(run_dir / "build_cpg.speedscope.json")
                if (run_dir / "build_cpg.speedscope.json").exists()
                else ""
            ),
            "scan_speedscope": (
                _rel(run_dir / "scan.speedscope.json")
                if (run_dir / "scan.speedscope.json").exists()
                else ""
            ),
        },
        "timeline": _aggregate_timeline(_load_timeline(run_dir / "timeline.jsonl")),
    }
    _json_dump(run_dir / "perf_summary.json", result)
    _write_report(run_dir, result)
    print(f"[perf] summary: {run_dir / 'perf_summary.json'}")
    print(f"[perf] report: {run_dir / 'performance_report.md'}")
    return 0


def _write_report(output_dir: Path, data: Dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Z-Scope Performance Report",
        "",
        f"Generated: {data.get('generated_at', '')}",
        "",
    ]
    if "aggregate" in data:
        aggregate = data.get("aggregate") or {}
        wall = aggregate.get("wall_seconds") or {}
        lines.extend(
            [
                "## Historical Baseline",
                "",
                f"- Runs parsed: {aggregate.get('run_count', 0)}",
                f"- Completed runs: {aggregate.get('completed_run_count', 0)}",
                f"- Wall seconds: min={wall.get('min')}, p50={wall.get('p50')}, p95={wall.get('p95')}, max={wall.get('max')}, latest={wall.get('latest')}",
                "",
            ]
        )
        latest = aggregate.get("latest_completed") or {}
        if latest:
            lines.extend(_run_report_lines(latest))
    else:
        run = data.get("run") or {}
        lines.extend(_run_report_lines(run))
        lines.extend(
            [
                "## Stage Resource Usage",
                "",
                "| Stage | Elapsed | User s | System s | Max RSS KB |",
                "| --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for stage, stats in (data.get("time_v") or {}).items():
            lines.append(
                f"| {stage} | {stats.get('elapsed', '')} | {stats.get('user_seconds', '')} | {stats.get('system_seconds', '')} | {stats.get('max_rss_kb', '')} |"
            )
        lines.extend(["", "## Timeline Hotspots", ""])
        lines.extend(
            ["| Phase | Count | Total s | Avg ms | Errors |", "| --- | ---: | ---: | ---: | ---: |"]
        )
        for row in ((data.get("timeline") or {}).get("phases") or [])[:20]:
            lines.append(
                f"| {row.get('phase')} | {row.get('count')} | {row.get('total_seconds')} | {row.get('avg_ms')} | {row.get('errors')} |"
            )
        llm = (data.get("timeline") or {}).get("llm") or {}
        scan_markers = (run.get("log_markers") or {}).get("scan") or {}
        lines.extend(
            [
                "",
                "## LLM Split",
                "",
                f"- LLM requests: {llm.get('count', 0)}",
                f"- LLM wall seconds inside client: {llm.get('duration_seconds', 0)}",
                f"- Prompt/completion/total tokens: {llm.get('prompt_tokens', 0)} / {llm.get('completion_tokens', 0)} / {llm.get('total_tokens', 0)}",
                f"- Log-derived request errors / stream timeouts: {scan_markers.get('llm_request_error_count', 0)} / {scan_markers.get('llm_stream_timeout_count', 0)}",
                f"- Cached get_file_snippet replays: {scan_markers.get('snippet_replay_count', 0)}",
                f"- Snapshot lock outcomes: {scan_markers.get('snapshot_lock_outcomes', {})}",
                "",
                "## Tool Calls",
                "",
            ]
        )
        timeline_tools = (data.get("timeline") or {}).get("tools") or []
        if timeline_tools:
            lines.extend(["| Tool | Count | Total s | Avg ms |", "| --- | ---: | ---: | ---: |"])
            for row in timeline_tools[:20]:
                lines.append(
                    f"| {row.get('tool_name')} | {row.get('count')} | {row.get('total_seconds')} | {row.get('avg_ms')} |"
                )
            lines.append("")
        else:
            log_tools = scan_markers.get("tool_calls_by_name") or {}
            lines.append(
                "_No tool execution timing was captured in this run; below is a log-derived call count fallback._"
            )
            lines.extend(["", "| Tool | Log count |", "| --- | ---: |"])
            for name, count in list(log_tools.items())[:20]:
                lines.append(f"| {name} | {count} |")
            lines.append("")
        lines.extend(
            [
                "## Speedscope Profiles",
                "",
            ]
        )
        profiles = data.get("profiles") or {}
        for label, path in profiles.items():
            lines.append(f"- {label}: `{path or 'not captured'}`")
        lines.append("")
    output_dir.joinpath("performance_report.md").write_text("\n".join(lines), encoding="utf-8")


def _run_report_lines(run: Dict[str, Any]) -> List[str]:
    summary = run.get("report_summary") or {}
    metrics = run.get("benchmark_metrics") or {}
    default_metrics = metrics.get("default") or {}
    review_metrics = metrics.get("with_needs_review") or {}
    lines = [
        "## Run Summary",
        "",
        f"- Run: `{run.get('run_id', '')}`",
        f"- Scan completed: {run.get('scan_completed')}",
        f"- Scan wall seconds: {run.get('scan_wall_seconds')}",
        f"- Entries discovered/analyzed: {run.get('entries_discovered')} / {summary.get('functions_analyzed')}",
        f"- Batch wall seconds: {summary.get('batch_wall_seconds')}",
        f"- Issues / needs_review: {summary.get('total_issues')} / {summary.get('needs_review_issues')}",
        f"- Validation iterations / tool calls: {(summary.get('validation_performance') or {}).get('iterations')} / {(summary.get('validation_performance') or {}).get('tool_call_count')}",
        f"- Tokens total: {summary.get('total_cumulative_total_tokens')}",
        f"- Default precision/recall/F1: {default_metrics.get('precision')} / {default_metrics.get('recall')} / {default_metrics.get('f1')}",
        f"- Default FP split raw/duplicate/effective: {default_metrics.get('false_positives_raw')} / {default_metrics.get('duplicate_of_matched_count')} / {default_metrics.get('false_positives_effective')}",
        f"- With-review precision/recall/F1: {review_metrics.get('precision')} / {review_metrics.get('recall')} / {review_metrics.get('f1')}",
        f"- With-review FP split raw/duplicate/effective: {review_metrics.get('false_positives_raw')} / {review_metrics.get('duplicate_of_matched_count')} / {review_metrics.get('false_positives_effective')}",
        "",
        "## Slow Entries",
        "",
        "| Function | Duration s | Issues | Tokens | Tool calls |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for entry in run.get("slow_entries") or []:
        lines.append(
            f"| {entry.get('function')} | {entry.get('duration_seconds')} | {entry.get('issue_count')} | {entry.get('context_tokens')} | {entry.get('tool_call_count')} |"
        )
    lines.append("")
    return lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("history", help="Parse existing auto_unified_wsl run artifacts")
    p.add_argument("--prefix", default="auto_unified_wsl", help="Run directory prefix to parse")
    p.add_argument("--output-dir", default="", help="Output directory for historical_baseline.json")
    p.set_defaults(func=command_history)

    p = sub.add_parser("profile", help="Run the fixed range workload with profiling enabled")
    p.add_argument("--run-id", default="", help="Run id under test/range/benchmark_runs")
    p.add_argument("--no-py-spy", action="store_true", help="Skip py-spy even if available")
    p.set_defaults(func=command_profile)

    p = sub.add_parser("summarize", help="Summarize one profile run directory")
    p.add_argument("--run-dir", required=True)
    p.set_defaults(func=command_summarize)

    p = sub.add_parser("preflight", help="Validate fixed workload constraints")
    p.set_defaults(func=command_preflight)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
