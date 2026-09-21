"""Retained cold trial followed by an ordinary same-workspace cache scan.

No mutation of product settings, fixture, contracts, truth, or matcher. The
canonical runner owns cold isolation and scoring; warm uses its exact config.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time

from persistent_trial import memory_snapshot, source_hashes
from zscope.benchmarking import runner
from zscope.reporting.json_io import read_report, write_json_atomic


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    write_json_atomic(path, value)


def environment(root, endpoint):
    env = {k: v for k, v in os.environ.items() if not k.startswith("Z_SCOPE_")}
    for line in (root / "test/range/zscope.local.env").read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip().removeprefix("export ").strip() == "Z_SCOPE_API_KEY":
            env["Z_SCOPE_API_KEY"] = " ".join(shlex.split(value, comments=True))
    if not env.get("Z_SCOPE_API_KEY"):
        raise RuntimeError("Existing API key unavailable")
    env.update(
        Z_SCOPE_LLM_BASE_URL=endpoint,
        Z_SCOPE_LLM_MODEL="deepseek-v4-flash",
        LLVM_COMPILER="clang",
        LLVM_CC_NAME="clang-18",
        PYTHONUNBUFFERED="1",
        LD_LIBRARY_PATH="/home/zeal/.local/svf/SVF-linux-x86_64/lib:/home/zeal/.local/svf/llvm-18.1.0.obj/lib",
    )
    env["PATH"] = ":".join(
        [
            "/home/zeal/.cache/zscope-wrapper-v2/install/bin",
            str(Path(sys.executable).parent),
            "/home/zeal/go/bin",
            "/usr/lib/llvm-18/bin",
            "/home/zeal/.local/svf/SVF-linux-x86_64/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        ]
    )
    return env


def usage(paths, offsets=None):
    events = []
    for path in sorted(paths):
        with path.open("rb") as stream:
            stream.seek((offsets or {}).get(str(path), 0))
            for line in stream:
                if line.endswith(b"\n") and line.strip():
                    events.append(json.loads(line))
    return events


def usage_counts(events):
    calls, tokens, kinds = Counter(), Counter(), Counter()
    for event in events:
        attribution = event.get("attribution") or {}
        agent = attribution.get("agent") or event.get("agent") or "unknown"
        calls[agent] += 1
        amount = int(
            (event.get("usage") or {}).get("total_tokens") or event.get("total_tokens") or 0
        )
        tokens[agent] += amount
        kinds[agent + ":" + str(attribution.get("call_kind") or event.get("call_kind"))] += amount
    return {"calls": dict(calls), "tokens": dict(tokens), "tokens_by_call_kind": dict(kinds)}


def compact_metrics(score):
    return {
        name: {
            k: row.get(k)
            for k in (
                "true_positives",
                "false_positives_raw",
                "false_positives_effective",
                "recall",
                "actionable_precision",
                "root_cause_precision",
            )
        }
        for name, row in score["report_views"].items()
    }


def summarize(root, control, cold, warm):
    old_truth = (
        root / "benchmark-artifacts/persistent-rerun-20260911/scoring-inputs/ground_truth.json"
    )
    baseline_paths = {
        "audit": root / "benchmark-artifacts/semantic-next/hot-v15/score.json",
        "latest": root / "benchmark-artifacts/balanced-rerun-20260919/score-frozen136.json",
    }
    baselines = {k: load(v) for k, v in baseline_paths.items()}
    summary = {
        "scope": "unified balanced cold trial and ordinary cached scan; no formal qualification",
        "baselines_common136": {k: compact_metrics(v) for k, v in baselines.items()},
        "runs": {},
    }
    for label, directory in (("cold", cold), ("warm", warm)):
        report_path = directory / "report.json"
        score_path = directory / "score.json"
        if not score_path.exists():
            runner.score_artifact(
                report_path, control / "scoring-inputs/ground_truth139.json", score_path
            )
        common_path = directory / "score-frozen136.json"
        if not common_path.exists():
            runner.score_artifact(report_path, old_truth, common_path)
        current, common = load(score_path), load(common_path)
        report = read_report(report_path, immutable=True)
        terminals = report.get("candidate_terminal_states", [])
        sources = Counter(r.get("candidate_source") or "unknown" for r in terminals)
        delta = {
            base: {
                view: {
                    "gained": sorted(
                        set(common["report_views"][view]["matched"])
                        - set(before["report_views"][view]["matched"])
                    ),
                    "lost": sorted(
                        set(before["report_views"][view]["matched"])
                        - set(common["report_views"][view]["matched"])
                    ),
                }
                for view in ("default", "with_needs_review")
            }
            for base, before in baselines.items()
        }
        row = {
            "path": str(directory),
            "current139": compact_metrics(current),
            "common136": compact_metrics(common),
            "deltas_common136": delta,
            "terminal_sources": dict(sources),
            "semantic_snapshot_candidates": sources.get("semantic_snapshot", 0),
            "report_bytes": report_path.stat().st_size,
            "usage": usage_counts(usage([directory / "llm_usage_events.jsonl"])),
            "metadata": dict(report.get("metadata") or {}),
            "summary": (
                load(directory / "summary.json") if (directory / "summary.json").exists() else {}
            ),
        }
        summary["runs"][label] = row
    summary["fixed_replay"] = {
        k: v
        for k, v in load(control / "replay-06/results.json").items()
        if k not in {"rows", "implementation"}
    }
    save(control / "latest-results.json", summary)
    lines = [
        "# 对象所有权修复试验",
        "",
        "冷扫描与普通缓存重扫均为 trial，不代表正式 benchmark 资格。",
        "",
        "| 扫描 | truth | 视图 | TP | raw FP | effective FP |",
        "|---|---|---|---:|---:|---:|",
    ]
    for label, row in summary["runs"].items():
        for population in ("current139", "common136"):
            for view in ("default", "with_needs_review"):
                m = row[population][view]
                lines.append(
                    f"| {label} | {population} | {view} | {m['true_positives']} | {m['false_positives_raw']} | {m['false_positives_effective']} |"
                )
        lines.extend(
            [
                "",
                f"{label}: 独立 semantic_snapshot 候选 {row['semantic_snapshot_candidates']}；调用 {sum(row['usage']['calls'].values())}；tokens {sum(row['usage']['tokens'].values()):,}；report {row['report_bytes']:,} bytes。",
                "",
            ]
        )
    lines.extend(
        [
            "审计与最近扫描共同 136 truth 基线分别保留比较；逐条新增/丢失、阶段用量与完整 metadata 见 latest-results.json。",
            "",
            "63 条固定回放保留全部原记录和证据。程序反驳只否定具体原主张，未知项保留 review；新扫描中候选不再出现不能直接当作修复证明。",
            "",
        ]
    )
    (control / "latest-results.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--offline-pid", type=int, help="Wait for the already running independent rule replay before starting the cold trial")
    args = parser.parse_args()
    if sys.platform != "linux" or sys.version_info[:2] != (3, 13):
        raise RuntimeError("Requires WSL/Linux Python 3.13")
    root, control = Path.cwd().resolve(), args.control.resolve()
    control.mkdir(parents=True, exist_ok=True)
    lock = (control / ".sequence.lock").open("a+")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if (control / "sequence.json").exists():
        raise RuntimeError("Sequence already exists; inspect it instead of starting another scan")
    state = {
        "status": "running",
        "phase": "preflight",
        "pid": os.getpid(),
        "started": datetime.now(timezone.utc).isoformat(),
    }
    save(control / "sequence.json", state)
    try:
        frozen = load(control / "baseline.json")["frozen_files"]
        for name, expected in frozen.items():
            if sha(root / name) != expected:
                raise RuntimeError("Frozen input changed: " + name)
        code = source_hashes(root)
        if args.offline_pid:
            state.update(phase="offline_rule_replay", offline_pid=args.offline_pid)
            save(control / "sequence.json", state)
            while True:
                status = Path(f"/proc/{args.offline_pid}/status")
                if not status.exists() or "State:\tZ" in status.read_text():
                    break
                time.sleep(30)
            replay = load(control / "replay-05/generators.json")
            if not replay.get("arms") or any(a.get("graph_query_errors") for a in replay["arms"]):
                raise RuntimeError("Independent rule replay is incomplete; cold scan withheld")
            if source_hashes(root) != code:
                raise RuntimeError("Product changed while waiting for offline replay")
        env = environment(root, args.base_url)
        for name in runner.SPECS["c_cpp"].required_tools:
            if not shutil.which(name, path=env["PATH"]):
                raise RuntimeError("Missing tool: " + name)
        for name in ("wpa", "saber"):
            result = subprocess.run(
                ["ldd", shutil.which(name, path=env["PATH"])],
                env=env,
                text=True,
                capture_output=True,
                check=True,
            )
            if "not found" in result.stdout + result.stderr:
                raise RuntimeError("Missing library: " + name)
        scoring = control / "scoring-inputs"
        scoring.mkdir(exist_ok=True)
        shutil.copy2(
            root / "test/range/benchmark/ground_truth.json", scoring / "ground_truth139.json"
        )
        save(
            control / "preflight.json",
            {
                "source_hashes": code,
                "frozen_files": frozen,
                "tools": {
                    n: shutil.which(n, path=env["PATH"])
                    for n in runner.SPECS["c_cpp"].required_tools
                },
                "python": sys.version,
                "truth_sent_to_llm": False,
            },
        )
        state.update(phase="cold")
        save(control / "sequence.json", state)
        with (control / "supervisor.log").open("w") as stream:
            subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("persistent_trial.py")),
                    "--control",
                    str(control / "cold"),
                    "--base-url",
                    args.base_url,
                ],
                stdout=stream,
                stderr=subprocess.STDOUT,
                check=True,
            )
        execution = load(control / "cold/execution.json")
        if (
            execution.get("status") != "complete"
            or execution.get("returncode") != 0
            or execution.get("changed_source_files")
        ):
            raise RuntimeError("Cold scan failed or product changed; automatic warm scan withheld")
        cold = Path(execution["output"]) / "run-01"
        source = Path(execution["workspace"]) / "scan-input"
        if not (cold / "score.json").is_file():
            raise RuntimeError("Cold official score missing")
        warm = cold / "hot-rescan"
        warm.mkdir()
        if any(
            (source / name).exists() for name in ("GROUND_TRUTH.md", "benchmark/ground_truth.json")
        ):
            raise RuntimeError("Warm source is not answer-isolated")
        if source_hashes(root) != code:
            raise RuntimeError("Product changed before ordinary cached scan")
        snapshots = source / ".zscope_snapshots"
        publication_path = snapshots / ".semantic-modeling/publication.json"
        publication = load(publication_path)
        workbook = Path(publication["workbook"])
        workbook_before = {"sha256": sha(workbook), "mtime_ns": workbook.stat().st_mtime_ns}
        offsets = {str(p): p.stat().st_size for p in snapshots.glob("llm_usage_events_*.jsonl")}
        env.update(
            Z_SCOPE_BENCHMARK_LANGUAGE="c_cpp",
            Z_SCOPE_BENCHMARK_SOURCE=str(source),
            Z_SCOPE_BENCHMARK_CACHE=str(source.parent / "cache"),
        )
        state.update(
            phase="warm",
            cold=str(cold),
            warm=str(warm),
            workspace=str(source),
            cold_completed=datetime.now(timezone.utc).isoformat(),
        )
        save(control / "sequence.json", state)
        started = time.monotonic()
        peak = 0
        with (warm / "scan.log").open("w") as stream:
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "zscope.cli.cli",
                    "-c",
                    str(cold / "zscope.execution.yaml"),
                    "--verbose",
                ],
                cwd=source,
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            state["scan_pid"] = child.pid
            save(control / "sequence.json", state)
            while child.poll() is None:
                memory = memory_snapshot(child.pid)
                peak = max(peak, sum(p["rss_kib"] for p in memory["processes"]))
                save(
                    control / "warm-latest.json",
                    {
                        "time": datetime.now(timezone.utc).isoformat(),
                        "elapsed_seconds": time.monotonic() - started,
                        "memory": memory,
                    },
                )
                time.sleep(30)
            if child.returncode not in (0, 1, 2):
                raise RuntimeError("Ordinary cached scan exited: " + str(child.returncode))
        report = runner._locate_report(source)
        if report.stat().st_mtime < started + (time.time() - time.monotonic()) - 2:
            raise RuntimeError("Ordinary cached scan did not publish a fresh report")
        shutil.copy2(report, warm / "report.json")
        runner._archive_report_for_scoring(
            warm / "report.json", source, warm, runner._source_line_metrics(source, "c_cpp")
        )
        fresh_events = usage(snapshots.glob("llm_usage_events_*.jsonl"), offsets)
        with (warm / "llm_usage_events.jsonl").open("w", encoding="utf-8") as stream:
            for event in fresh_events:
                stream.write(json.dumps(event, ensure_ascii=False) + "\n")
        shutil.copy2(publication_path, warm / "publication.json")
        shutil.copy2(workbook, warm / "user_config.xlsx")
        save(
            warm / "experiment.json",
            {
                "cache": "ordinary rescan in unchanged cold workspace; no resume flag",
                "scan_seconds": time.monotonic() - started,
                "peak_rss_kib": peak,
                "workbook_before": workbook_before,
                "workbook_after": {
                    "sha256": sha(workbook),
                    "mtime_ns": workbook.stat().st_mtime_ns,
                },
                "usage": usage_counts(fresh_events),
                "release_eligible": False,
            },
        )
        for name, expected in frozen.items():
            if sha(root / name) != expected:
                raise RuntimeError("Frozen input changed: " + name)
        if source_hashes(root) != code:
            raise RuntimeError(
                "Product changed during scans; results are not a controlled comparison"
            )
        state.update(phase="offline_score")
        save(control / "sequence.json", state)
        summarize(root, control, cold, warm)
        state.update(
            status="complete", phase="complete", finished=datetime.now(timezone.utc).isoformat()
        )
    except Exception as exc:
        state.update(
            status="failed",
            failure=type(exc).__name__ + ": " + str(exc),
            finished=datetime.now(timezone.utc).isoformat(),
        )
        save(control / "sequence.json", state)
        raise
    save(control / "sequence.json", state)


if __name__ == "__main__":
    main()
