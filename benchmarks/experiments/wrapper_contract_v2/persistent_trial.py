"""Run the canonical trial in a named retained directory and preserve live telemetry.

This supervisor never changes scanner settings, candidates, contracts, or truth.
Secrets are read only into the child environment, never copied into artifacts.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time


def save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def source_hashes(root: Path) -> dict:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((root / "zscope").rglob("*"))
        if path.is_file() and path.suffix in {".py", ".yaml", ".json", ".md"}
    }


def memory_snapshot(parent_pid: int) -> dict:
    rows = {}
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            values = {}
            for line in (proc / "status").read_text().splitlines():
                key, _, value = line.partition(":")
                values[key] = value.strip()
            rows[int(proc.name)] = {
                "pid": int(proc.name), "ppid": int(values["PPid"]),
                "name": values["Name"], "rss_kib": int(values.get("VmRSS", "0").split()[0]),
                "peak_rss_kib": int(values.get("VmHWM", "0").split()[0]),
                "threads": int(values.get("Threads", "0")),
            }
        except (OSError, ValueError, KeyError):
            continue
    members = {parent_pid}
    for _ in range(20):
        children = {pid for pid, row in rows.items() if row["ppid"] in members}
        if children.issubset(members):
            break
        members.update(children)
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in {"MemAvailable", "MemTotal", "SwapFree", "SwapTotal"}:
            memory[key] = int(value.strip().split()[0])
    return {"processes": [rows[pid] for pid in sorted(members) if pid in rows], **memory}


def observe(run: Path, workspace: Path, pid: int) -> dict:
    scan = workspace / "scan-input"
    snapshots = scan / ".zscope_snapshots"
    usage_backup = run / "live-usage"
    usage_backup.mkdir(parents=True, exist_ok=True)
    tokens, calls, groups = Counter(), Counter(), set()
    for path in snapshots.glob("llm_usage_events_*.jsonl"):
        contents = path.read_bytes()
        # A concurrently written trailing line is not yet a committed usage event.
        complete = contents[:contents.rfind(b"\n") + 1]
        (usage_backup / path.name).write_bytes(complete)
        for line in complete.splitlines():
            row = json.loads(line)
            agent = row.get("agent", "unknown")
            tokens[agent] += int(row.get("total_tokens") or 0)
            calls[agent] += 1
            uid = row.get("validation_cluster_uid") or (row.get("attribution") or {}).get("validation_cluster_uid")
            if agent == "validator_agent" and uid:
                groups.add(uid)
    phase = next((name for name in ("score", "scan", "index", "health", "build") if (run / (name + ".log")).exists()), "prepare")
    logfile = run / (phase + ".log")
    content = logfile.read_text(encoding="utf-8", errors="replace") if logfile.exists() else ""
    warnings = [line[:1500] for line in content.splitlines() if re.search(r"ERROR|Traceback|KeyError|MemoryError|invalid terminal output|fallback|degrad", line, re.I)]
    publication_path = snapshots / ".semantic-modeling/publication.json"
    publication = json.loads(publication_path.read_text()) if publication_path.exists() else {}
    archive_path = run / "archive-state.json"
    archive = json.loads(archive_path.read_text()) if archive_path.exists() else {}
    reports = {str(p.relative_to(workspace)): p.stat().st_size for p in scan.glob("*report*.json")}
    reports.update({str(p.relative_to(workspace)): p.stat().st_size for p in scan.glob(".report-*.tmp")})
    return {
        "time": datetime.now(timezone.utc).isoformat(), "phase": phase, "archive": archive,
        "last_log": content.splitlines()[-1][:600] if content else "",
        "log_bytes": logfile.stat().st_size if logfile.exists() else 0,
        "tokens_by_agent": dict(tokens), "calls_by_agent": dict(calls),
        "validator_groups": len(groups), "modeling": publication.get("stats"),
        "publication_available": bool(publication), "contract_version": publication.get("contract_version"),
        "diagnostics_count": len(warnings), "recent_diagnostics": warnings[-12:],
        "reports_bytes": reports, "memory": memory_snapshot(pid),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--base-url", required=True)
    args = parser.parse_args()
    if sys.platform != "linux" or sys.version_info[:2] != (3, 13):
        raise RuntimeError("Requires Linux Python 3.13")
    root = Path.cwd().resolve()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = root / "benchmark-artifacts/c_cpp/trial" / stamp
    work_root = Path("/home/zeal/zscope-benchmark-runs") / stamp
    control = args.control.resolve()
    control.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    for key in list(env):
        if key.startswith("Z_SCOPE_"):
            env.pop(key)
    for line in (root / "test/range/zscope.local.env").read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip().removeprefix("export ").strip() == "Z_SCOPE_API_KEY":
            env["Z_SCOPE_API_KEY"] = " ".join(shlex.split(value, comments=True))
    if not env.get("Z_SCOPE_API_KEY"):
        raise RuntimeError("Existing API key was not found")
    env.update(
        Z_SCOPE_LLM_BASE_URL=args.base_url,
        Z_SCOPE_LLM_MODEL="deepseek-v4-flash", LLVM_COMPILER="clang", LLVM_CC_NAME="clang-18",
        LD_LIBRARY_PATH="/home/zeal/.local/svf/SVF-linux-x86_64/lib:/home/zeal/.local/svf/llvm-18.1.0.obj/lib",
        PYTHONUNBUFFERED="1",
    )
    env["PATH"] = ":".join([
        "/home/zeal/.cache/zscope-wrapper-v2/install/bin", str(Path(sys.executable).parent),
        "/home/zeal/go/bin", "/usr/lib/llvm-18/bin", "/home/zeal/.local/svf/SVF-linux-x86_64/bin", env["PATH"],
    ])
    from zscope.benchmarking.runner import SPECS
    for name in SPECS["c_cpp"].required_tools:
        if not shutil.which(name, path=env["PATH"]):
            raise RuntimeError("Missing tool: " + name)
    for name in ("wpa", "saber"):
        result = subprocess.run(["ldd", shutil.which(name, path=env["PATH"])], env=env, capture_output=True, text=True, check=True)
        if "not found" in result.stdout + result.stderr:
            raise RuntimeError("Missing shared libraries for " + name)
    initial = source_hashes(root)
    metadata = {
        "status": "running", "started": stamp, "output": str(output), "work_directory": str(work_root),
        "workspace": str(work_root / "run-01"), "temporary": False, "mode": "trial", "scan_depth": "balanced",
        "model": env["Z_SCOPE_LLM_MODEL"], "source_start_hashes": initial,
        "matcher_sha256": initial["zscope/benchmarking/protocol.py"],
        "truth_sent_to_llm": False, "manual_contract_override": False,
    }
    save(control / "execution.json", metadata)
    command = [sys.executable, "-m", "zscope.cli.benchmark", "run", "--language", "c_cpp", "--mode", "trial", "--scan-depth", "balanced", "--output", str(output), "--work-directory", str(work_root)]
    print(json.dumps({key: value for key, value in metadata.items() if key != "source_start_hashes"}), flush=True)
    with (control / "runner.log").open("w") as log:
        child = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        metadata["pid"] = child.pid
        save(control / "execution.json", metadata)
        while True:
            run = output / "run-01"
            if run.exists():
                try:
                    observation = observe(run, work_root / "run-01", child.pid)
                    save(control / "latest.json", observation)
                    with (control / "monitor.jsonl").open("a") as stream:
                        stream.write(json.dumps(observation, ensure_ascii=False) + "\n")
                    print(json.dumps({key: observation[key] for key in ("time", "phase", "archive", "calls_by_agent", "tokens_by_agent", "validator_groups", "diagnostics_count", "reports_bytes")}), flush=True)
                except Exception as exc:
                    print("Monitor error (scanner continues): " + repr(exc), flush=True)
            result = child.poll()
            if result is not None:
                break
            time.sleep(30)
    final = source_hashes(root)
    metadata.update(status="complete" if result == 0 else "failed", returncode=result,
                    finished=datetime.now(timezone.utc).isoformat(),
                    changed_source_files=sorted(key for key in initial.keys() | final.keys() if initial.get(key) != final.get(key)))
    save(control / "execution.json", metadata)
    print(json.dumps({key: value for key, value in metadata.items() if key != "source_start_hashes"}), flush=True)
    raise SystemExit(result)


if __name__ == "__main__":
    main()
