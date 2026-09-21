"""Resume an interrupted retained scan without rebuilding its sealed input.

This experiment is explicitly interrupted, never a qualified cold trial. The
scanner uses the original configuration and its normal semantic cache policy.
Post-scan scoring remains a separate, answer-aware process.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import time

from persistent_trial import observe, source_hashes
from zscope.reporting.json_io import write_json_atomic


def save(path: Path, data: dict) -> None:
    write_json_atomic(path, data)


def environment(root: Path, base_url: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("Z_SCOPE_")}
    for line in (root / "test/range/zscope.local.env").read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip().removeprefix("export ").strip() == "Z_SCOPE_API_KEY":
            env["Z_SCOPE_API_KEY"] = " ".join(shlex.split(value, comments=True))
    if not env.get("Z_SCOPE_API_KEY"):
        raise RuntimeError("Existing API key is unavailable")
    env.update(
        Z_SCOPE_LLM_BASE_URL=base_url,
        Z_SCOPE_LLM_MODEL="deepseek-v4-flash",
        LLVM_COMPILER="clang",
        LLVM_CC_NAME="clang-18",
        LD_LIBRARY_PATH="/home/zeal/.local/svf/SVF-linux-x86_64/lib:/home/zeal/.local/svf/llvm-18.1.0.obj/lib",
        PYTHONUNBUFFERED="1",
    )
    env["PATH"] = ":".join([
        "/home/zeal/.cache/zscope-wrapper-v2/install/bin", str(Path(sys.executable).parent),
        "/home/zeal/go/bin", "/usr/lib/llvm-18/bin", "/home/zeal/.local/svf/SVF-linux-x86_64/bin", env["PATH"],
    ])
    return env


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--base-url", required=True)
    args = parser.parse_args()
    if sys.platform != "linux" or sys.version_info[:2] != (3, 13):
        raise RuntimeError("Requires Linux Python 3.13")
    root = Path.cwd().resolve()
    control = args.control.resolve()
    original = json.loads((control / "execution.json").read_text())
    workspace = Path(original["workspace"])
    scan = workspace / "scan-input"
    run = Path(original["output"]) / "run-01"
    if not scan.is_dir() or original["temporary"]:
        raise RuntimeError("A retained original workspace is required")
    if source_hashes(root) != original["source_start_hashes"]:
        raise RuntimeError("Product source changed since the interrupted run")
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            argv = (proc / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if b"zscope.cli.cli" in argv and str(run / "zscope.execution.yaml").encode() in argv:
            raise RuntimeError("The original scanner is still running")
    manifest = json.loads((run / "input-manifest.json").read_text())
    for item in manifest["files"]:
        path = scan / item["path"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise RuntimeError("Sealed source changed: " + item["path"])
    for forbidden in ("GROUND_TRUTH.md", "benchmark", "ground_truth.json"):
        if (scan / forbidden).exists():
            raise RuntimeError("Answer material found inside scanner input")
    checks = []
    for directory in (scan / ".zscope_snapshots", scan / ".zscope_knowledge"):
        for path in directory.rglob("*"):
            if path.suffix == ".json":
                json.loads(path.read_text())
            elif path.suffix in {".db", ".sqlite", ".sqlite3"}:
                with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as database:
                    result = database.execute("PRAGMA quick_check").fetchall()
                if result != [("ok",)]:
                    raise RuntimeError("Invalid database: " + str(path))
                checks.append({"path": str(path), "quick_check": "ok"})
    env = environment(root, args.base_url)
    from zscope.benchmarking.runner import SPECS, _benchmark_environment
    for name in SPECS["c_cpp"].required_tools:
        if not shutil.which(name, path=env["PATH"]):
            raise RuntimeError("Missing tool: " + name)
    for name in ("wpa", "saber"):
        result = subprocess.run(["ldd", shutil.which(name, path=env["PATH"])], env=env, capture_output=True, text=True, check=True)
        if "not found" in result.stdout + result.stderr:
            raise RuntimeError("Missing shared library: " + name)
    env = _benchmark_environment(env)
    env.update(Z_SCOPE_BENCHMARK_LANGUAGE="c_cpp", Z_SCOPE_BENCHMARK_SOURCE=str(scan), Z_SCOPE_BENCHMARK_CACHE=str(workspace / "cache"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    segment = run / "interruptions" / stamp
    segment.mkdir(parents=True, exist_ok=False)
    for name in ("scan.log",):
        shutil.copy2(run / name, segment / name)
    for name in ("execution.json", "latest.json", "monitor.jsonl"):
        shutil.copy2(control / name, segment / name)
    with tarfile.open(segment / "semantic-state-before-resume.tar.gz", "w:gz") as archive:
        archive.add(scan / ".zscope_snapshots", arcname=".zscope_snapshots")
    rows = []
    incomplete_usage = []
    for path in (scan / ".zscope_snapshots").glob("llm_usage_events_*.jsonl"):
        shutil.copy2(path, segment / path.name)
        contents = path.read_bytes()
        end = contents.rfind(b"\n") + 1
        rows.extend(json.loads(line) for line in contents[:end].splitlines() if line.strip())
        if end < len(contents):
            incomplete_usage.append({"path": str(path), "uncommitted_tail_bytes": len(contents) - end})
    command = [sys.executable, "-m", "zscope.cli.cli", "-c", str(run / "zscope.execution.yaml"), "--verbose"]
    metadata = {
        "schema_version": "zscope.interrupted-trial-recovery.v1", "status": "running",
        "reason": "user-reported unexpected host power loss", "resumed_at": datetime.now(timezone.utc).isoformat(),
        "workspace": str(workspace), "original_started": original["started"],
        "resumed": True, "continuous_cold_scan": False, "release_eligible": False,
        "segment": str(segment), "scan_argv": command, "database_checks": checks,
        "source_unchanged": True, "truth_sent_to_llm": False,
        "pre_interruption_observed_calls": len(rows),
        "incomplete_usage_files": incomplete_usage,
        "pre_interruption_observed_tokens": sum(int(r.get("total_tokens") or 0) for r in rows),
        "usage_limit": "Calls interrupted before a persisted usage event may be absent; provider billing is not reconstructed.",
    }
    save(run / "recovery.json", metadata)
    save(control / "recovery.json", metadata)
    started = time.monotonic()
    with (run / "scan.log").open("w") as log:
        child = subprocess.Popen(command, cwd=scan, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        metadata["pid"] = child.pid
        save(run / "recovery.json", metadata)
        save(control / "recovery.json", metadata)
        print(json.dumps(metadata), flush=True)
        while True:
            try:
                observation = observe(run, workspace, child.pid)
                save(control / "latest.json", observation)
                with (control / "monitor.jsonl").open("a") as stream:
                    stream.write(json.dumps(observation, ensure_ascii=False) + "\n")
                print(json.dumps({k: observation[k] for k in ("time", "phase", "tokens_by_agent", "calls_by_agent", "publication_available", "reports_bytes")}), flush=True)
            except Exception as exc:
                print("Monitor error (scanner continues): " + repr(exc), flush=True)
            result = child.poll()
            if result is not None:
                break
            time.sleep(30)
    metadata.update(status="scan_finished" if result in (0, 1, 2) else "failed", returncode=result,
                    scan_resume_seconds=time.monotonic() - started, finished_at=datetime.now(timezone.utc).isoformat(),
                    source_unchanged=source_hashes(root) == original["source_start_hashes"])
    save(run / "recovery.json", metadata)
    save(control / "recovery.json", metadata)
    print(json.dumps(metadata), flush=True)
    raise SystemExit(0 if result in (0, 1, 2) else result)


if __name__ == "__main__":
    main()
