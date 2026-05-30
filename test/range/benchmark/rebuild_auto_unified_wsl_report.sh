#!/usr/bin/env bash
set -euo pipefail

if [[ ! -r /proc/version ]] || ! grep -qiE 'microsoft|wsl' /proc/version; then
  echo "[range] ERROR: report rebuild must run inside WSL/Linux." >&2
  exit 2
fi

repo_root="${Z_SCOPE_REPO_ROOT:-/mnt/c/Users/10273/home/work/Z-Scope}"
cd "${repo_root}"

if [[ -f test/range/zscope.local.env ]]; then
  # Local secret-bearing config. This file is ignored by git.
  # shellcheck disable=SC1091
  source test/range/zscope.local.env
fi

if [[ -z "${Z_SCOPE_API_KEY:-}" ]]; then
  echo "[range] ERROR: Z_SCOPE_API_KEY is not set." >&2
  exit 2
fi

export PATH="$HOME/go/bin:/usr/lib/llvm-18/bin:$HOME/.local/svf/SVF-linux-x86_64/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/.local/svf/SVF-linux-x86_64/lib:$HOME/.local/svf/llvm-18.1.0.obj/lib:${LD_LIBRARY_PATH:-}"
export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-18

run_id="${1:?usage: rebuild_auto_unified_wsl_report.sh <run_id>}"
run_dir="test/range/benchmark_runs/${run_id}"
if [[ ! -d "${run_dir}" ]]; then
  echo "[range] ERROR: run directory not found: ${run_dir}" >&2
  exit 2
fi

echo "[range] rebuilding report from WSL snapshots for ${run_id}"
set +e
python3 -m zscope.cli.cli -c test/range/zscope.auto_unified.yaml --discover-entries --resume --verbose \
  > "${run_dir}/zscope_resume.log" 2>&1
resume_rc="$?"
set -e
printf '%s\n' "${resume_rc}" > "${run_dir}/zscope_resume.rc"

if [[ -f test/range/entry_functions_list.json ]]; then
  cp test/range/entry_functions_list.json "${run_dir}/entry_functions_list.json"
fi
if [[ -f test/range/zscope_batch_report.json ]]; then
  cp test/range/zscope_batch_report.json "${run_dir}/zscope_batch_report.json"
fi
if [[ -f test/range/zscope_batch_report.md ]]; then
  cp test/range/zscope_batch_report.md "${run_dir}/zscope_batch_report.md"
fi

if [[ ! -f "${run_dir}/zscope_batch_report.json" ]]; then
  echo "[range] ERROR: resume did not produce ${run_dir}/zscope_batch_report.json" >&2
  exit 2
fi

python3 scripts/external_benchmark.py evaluate \
  --report "${run_dir}/zscope_batch_report.json" \
  --truth test/range/benchmark/ground_truth.json \
  --output "${run_dir}/evaluation.json"
python3 scripts/external_benchmark.py evaluate \
  --report "${run_dir}/zscope_batch_report.json" \
  --truth test/range/benchmark/ground_truth.json \
  --output "${run_dir}/evaluation.with_needs_review.json" \
  --view with_needs_review

python3 - "${run_dir}" "${resume_rc}" <<'PY'
import json
import re
import sys
from pathlib import Path

run_dir = Path(sys.argv[1])
resume_rc = int(sys.argv[2])

def load_json(path):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}

existing = load_json(run_dir / "run_summary.json")
entries = load_json(run_dir / "entry_functions_list.json")
report = load_json(run_dir / "zscope_batch_report.json")
default_eval = load_json(run_dir / "evaluation.json")
review_eval = load_json(run_dir / "evaluation.with_needs_review.json")
build_log = (run_dir / "build_cpg.log").read_text(encoding="utf-8", errors="replace") if (run_dir / "build_cpg.log").exists() else ""
scan_log = (run_dir / "zscope_run.log").read_text(encoding="utf-8", errors="replace") if (run_dir / "zscope_run.log").exists() else ""
resume_log = (run_dir / "zscope_resume.log").read_text(encoding="utf-8", errors="replace") if (run_dir / "zscope_resume.log").exists() else ""
combined_log = build_log + "\n" + scan_log

metric_keys = [
    "report_issue_count",
    "ground_truth_count",
    "true_positives",
    "false_positives",
    "false_negatives",
    "precision",
    "recall",
    "f1",
]
summary = dict(existing)
summary.update(
    {
        "run_id": run_dir.name,
        "mode": "wsl_auto_discover_entries_unified_backend_with_svf_required",
        "entry_discovery": {
            "entries_discovered": len(entries.get("functions", [])),
        },
        "report_summary": report.get("summary", {}),
        "benchmark_metrics": {
            "default": {k: default_eval.get(k) for k in metric_keys},
            "with_needs_review": {k: review_eval.get(k) for k in metric_keys},
        },
        "report_rebuild": {
            "resume_return_code": resume_rc,
            "resume_traceback_count": len(re.findall(r"Traceback", resume_log)),
            "original_traceback_count": len(re.findall(r"Traceback", scan_log)),
        },
        "backend_evidence": {
            "wsl_detected": "WSL detected" in build_log,
            "unified_backend": True,
            "clangd_lsp_initialized": "clangd LSP initialized successfully" in combined_log,
            "gclang_invoked": "gclang cmd:" in combined_log,
            "wpa_ander_succeeded": "wpa-ander succeeded" in combined_log,
            "saber_succeeded": "saber succeeded" in combined_log,
            "svf_completed": "SVF analysis completed and wrote results to KnowledgeDB" in combined_log,
            "imported_svf_indirect_edges": bool(re.search(r"Imported \d+ indirect call edges from SVF", combined_log)),
            "imported_saber_bugs": bool(re.search(r"Imported \d+ saber bugs", combined_log)),
            "svf_unavailable_mentions": len(re.findall(r"SVF tools unavailable|SVF analysis failed", combined_log)),
        },
    }
)
(run_dir / "run_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False, indent=2))
PY

echo "[range] rebuilt report: ${run_dir}"
