"""Archive and independently score a retained run interrupted by power loss."""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone
import gc
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from persistent_trial import source_hashes
from recover_persistent_scan import environment
from zscope.benchmarking import runner as r
from zscope.benchmarking.replay_bundle import write_validator_replay_bundle

def aggregate_usage(snapshot_root, run):
    sessions, tails, identities = [], [], set()
    total_calls = total_tokens = 0
    agents = Counter()
    usage_kinds = Counter()
    token_components = Counter()
    target = run / "recovery-usage"
    target.mkdir(exist_ok=True)
    for path in sorted(snapshot_root.glob("llm_usage_events_*.jsonl")):
        raw = path.read_bytes()
        end = raw.rfind(b"\n") + 1
        shutil.copy2(path, target / path.name)
        rows = [json.loads(line) for line in raw[:end].splitlines() if line.strip()]
        (target / (path.stem + ".committed.jsonl")).write_bytes(raw[:end])
        session_tokens = 0
        for row in rows:
            identity = (path.name, row["call_id"])
            if identity in identities:
                raise RuntimeError("Duplicate event identity inside a session")
            identities.add(identity)
            tokens = int(row.get("total_tokens") or 0)
            session_tokens += tokens
            agents[row.get("agent") or "unknown"] += tokens
            usage_kinds["provider_reported_tokens" if row.get("provider_reported") else "estimated_or_conservative_tokens"] += tokens
            usage_kinds["conservative_charge_calls"] += int(bool(row.get("conservative_charge")))
            for field in ("prompt_tokens", "completion_tokens", "cached_prompt_tokens", "reasoning_tokens"):
                token_components[field] += int(row.get(field) or 0)
        total_calls += len(rows)
        total_tokens += session_tokens
        sessions.append({"source": path.name, "calls": len(rows), "observed_tokens": session_tokens,
                         "committed_sha256": hashlib.sha256(raw[:end]).hexdigest()})
        if end < len(raw):
            tails.append({"source": path.name, "bytes": len(raw) - end})
    result = {"schema_version": "zscope.interrupted-usage-account.v1",
              "sessions": sessions, "observed_calls": total_calls,
              "observed_tokens": total_tokens, "tokens_by_agent": dict(agents),
              "usage_kinds": dict(usage_kinds), "token_components": dict(token_components),
              "components_note": "Cached prompt is a prompt subset; reasoning is a completion subset. Neither is added twice.",
              "incomplete_tails": tails, "provider_bill_complete": False,
              "note": "Complete persisted events across interrupted and resumed processes. In-flight uncommitted provider usage is unknown; ordinary score usage covers only the final process."}
    r._json_dump(run / "recovery-usage.json", result)
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--base-url", required=True)
    args = parser.parse_args()
    root, control = Path.cwd().resolve(), args.control.resolve()
    original = json.loads((control / "execution.json").read_text())
    run = Path(original["output"]) / "run-01"
    recovery = json.loads((run / "recovery.json").read_text())
    if recovery["status"] != "scan_finished":
        raise RuntimeError("Scanner must finish before independent scoring")
    if source_hashes(root) != original["source_start_hashes"]:
        raise RuntimeError("Product source changed during scan")
    workspace = Path(original["workspace"])
    scan = workspace / "scan-input"
    manifest = json.loads((run / "input-manifest.json").read_text())
    started = time.monotonic()
    env = environment(root, args.base_url)
    os.environ.update(env)
    env = r._benchmark_environment(env)
    env.update(Z_SCOPE_BENCHMARK_LANGUAGE="c_cpp", Z_SCOPE_BENCHMARK_SOURCE=str(scan),
               Z_SCOPE_BENCHMARK_CACHE=str(workspace / "cache"))
    health = r._tool_health(r.SPECS["c_cpp"])
    r._json_dump(run / "tool-health.json", health)
    if not health["ok"]:
        raise RuntimeError("Required backend tools unavailable")
    source_report = r._locate_report(scan)
    report_path = run / "report.json"
    r._json_dump(run / "archive-state.json", {"stage": "copy_report", "source": str(source_report)})
    shutil.copy2(source_report, report_path)
    r._json_dump(run / "archive-state.json", {"stage": "read_report", "bytes": report_path.stat().st_size})
    report = r._load_json_object(report_path)
    source_metrics = r._source_line_metrics(scan, "c_cpp")
    for key in ("metadata", "run_manifest"):
        report.setdefault(key, {}).update(source_metrics)
        report[key]["benchmark_recovery"] = {
            "resumed": True, "continuous_cold_scan": False, "release_eligible": False,
            "recovery_artifact": "recovery.json", "combined_cost_artifact": "recovery-usage.json",
            "ordinary_usage_scope": "final scanner process only"}
    r._archive_usage_events(report, scan_root=scan, run_dir=run)
    combined = aggregate_usage(scan / ".zscope_snapshots", run)
    r._json_dump(report_path, report)
    r._json_dump(run / "archive-state.json", {"stage": "replay_bundle"})
    replay = write_validator_replay_bundle(run / "validator-replay-bundle.json", report)
    replay = {k: replay[k] for k in ("schema_version", "group_count", "bundle_sha256")}
    provenance = r._report_provenance(report)
    del report
    gc.collect()
    entries = scan / "entry_functions_list.json"
    if entries.exists():
        shutil.copy2(entries, run / entries.name)
    publication = scan / ".zscope_snapshots/.semantic-modeling/publication.json"
    if publication.exists():
        folder = run / "semantic-publication"
        folder.mkdir(exist_ok=True)
        shutil.copy2(publication, folder / "publication.json")
        data = json.loads(publication.read_text())
        workbook = Path(data["workbook"]).resolve()
        if not workbook.is_relative_to(scan.resolve()):
            raise RuntimeError("Workbook escapes isolated source")
        shutil.copy2(workbook, folder / "user_config.xlsx")
        subprocess.run([sys.executable, str(root / "benchmarks/experiments/wrapper_contract_v2/archive_semantics.py"),
                        "--run", str(run), "--workspace", str(workspace)], check=True)
    archived_input = run / "scan-input"
    if not archived_input.exists():
        r.copy_scan_input(scan, archived_input, "c_cpp")
    if r.scan_input_manifest(archived_input) != manifest:
        raise RuntimeError("Exported source differs from original sealed input")
    truth_env = dict(env)
    for key in ("Z_SCOPE_API_KEY", "Z_SCOPE_LLM_BASE_URL", "Z_SCOPE_LLM_MODEL"):
        truth_env.pop(key, None)
    scoring_manifest = json.loads((control / "scoring-inputs/manifest.json").read_text())
    frozen_truth = Path(scoring_manifest["truth_path"])
    if r._sha256_file(frozen_truth) != scoring_manifest["truth_sha256"]:
        raise RuntimeError("Frozen scoring truth changed")
    if r._sha256_file(root / "zscope/benchmarking/protocol.py") != scoring_manifest["matcher_sha256"]:
        raise RuntimeError("Scoring matcher changed")
    scoring_archive = run / "scoring-inputs"
    scoring_archive.mkdir(exist_ok=True)
    shutil.copy2(frozen_truth, scoring_archive / "ground_truth.json")
    scoring_manifest = {**scoring_manifest, "truth_path": str(scoring_archive / "ground_truth.json")}
    truth_env["Z_SCOPE_BENCHMARK_TRUTH"] = scoring_manifest["truth_path"]
    r._json_dump(run / "scoring-inputs.json", scoring_manifest)
    command = [sys.executable, "-m", "zscope.cli.benchmark", "_score",
               "--report", str(report_path), "--output", str(run / "score.json")]
    r._json_dump(run / "archive-state.json", {"stage": "independent_score"})
    score_seconds = r._run_command(command, cwd=root, environment=truth_env, log_path=run / "score.log")
    score = r._load_json_object(run / "score.json")
    names = ("report.json", "score.json", "input-manifest.json", "tool-health.json",
             "validator-replay-bundle.json", "llm_usage_events.jsonl", "recovery.json", "recovery-usage.json", "scoring-inputs.json")
    summary = {
        "schema_version": "zscope.interrupted-trial-summary.v1", "run": 1, "completed": True,
        "mode": "interrupted_trial_recovery", "release_eligible": False,
        "continuous_cold_scan": False, "queue_empty": bool(score.get("queue_empty")),
        "gate_failures": ["Host power loss interrupted original cold run"] + r._gate_c(score, scan_depth="balanced"),
        "metrics": score, "combined_observed_usage": combined,
        "phase_seconds": {"resumed_scan": recovery["scan_resume_seconds"],
                          "score": score_seconds, "archive_and_score": time.monotonic() - started},
        "input_manifest_sha256": manifest["manifest_sha256"], "validator_replay_bundle": replay,
        "artifact_hashes": {name: r._sha256_file(run / name) for name in names if (run / name).exists()},
        "workspace": {"path": str(workspace), "temporary": False, "retained_by_request": True},
        "isolation": {"scan_cwd": str(scan), "truth_available_to_scan": False, "formal_oci_verified": False},
        "provenance": provenance, "scoring_inputs": scoring_manifest,
        "timing_note": "Resumed scan wall is not uninterrupted cold timing; original timestamps remain in interruptions/."}
    r._json_dump(run / "summary.json", summary)
    r._json_dump(run / "archive-state.json", {"stage": "complete"})
    original.update(status="complete_after_recovery", finished=datetime.now(timezone.utc).isoformat(),
                    recovery_artifact=str(run / "recovery.json"), continuous_cold_scan=False,
                    release_eligible=False, changed_source_files=[])
    r._json_dump(control / "execution.json", original)
    print(json.dumps({"summary": str(run / "summary.json"), "combined_observed_tokens": combined["observed_tokens"],
                      "release_eligible": False}), flush=True)

if __name__ == "__main__":
    main()
