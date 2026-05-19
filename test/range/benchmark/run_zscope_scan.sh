#!/usr/bin/env bash
set -euo pipefail

if [[ ! -r /proc/version ]] || ! grep -qiE 'microsoft|wsl' /proc/version; then
  echo "[range] ERROR: range benchmark must run inside WSL/Linux for SVF/Saber." >&2
  echo "[range]        Launch with: wsl bash -lc 'cd /mnt/c/Users/10273/home/work/Z-Scope && test/range/benchmark/run_zscope_scan.sh'" >&2
  exit 2
fi

cd /mnt/c/Users/10273/home/work/Z-Scope

if [[ -f test/range/zscope.local.env ]]; then
  # Local secret-bearing config. This file is ignored by git.
  # shellcheck disable=SC1091
  source test/range/zscope.local.env
fi

if [[ -z "${Z_SCOPE_API_KEY:-}" ]]; then
  echo "[range] ERROR: Z_SCOPE_API_KEY is not set." >&2
  echo "[range] Set it in the environment or in test/range/zscope.local.env." >&2
  exit 2
fi

export PATH="$HOME/go/bin:/usr/lib/llvm-18/bin:$HOME/.local/svf/SVF-linux-x86_64/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/.local/svf/SVF-linux-x86_64/lib:$HOME/.local/svf/llvm-18.1.0.obj/lib:${LD_LIBRARY_PATH:-}"
export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-18

run_id="${1:-unified_$(date +%Y%m%d_%H%M%S)}"
run_dir="test/range/benchmark_runs/${run_id}"
mkdir -p "${run_dir}"
printf '%s\n' "${run_dir}" > test/range/benchmark_runs/latest_unified_wsl.txt

echo "[range] run_dir=${run_dir}"
echo "[range] backend preflight"
if ! command -v clangd >/dev/null 2>&1; then
  echo "[range] ERROR: clangd is required for the normal benchmark backend." >&2
  exit 2
fi

missing_svf=()
for tool in gclang get-bc llvm-link wpa saber; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing_svf+=("$tool")
  fi
done
if ((${#missing_svf[@]})); then
  echo "[range] ERROR: missing required WSL SVF/gllvm tools: ${missing_svf[*]}" >&2
  exit 2
fi

echo "[range] configure CMake"
cmake -S test/range -B test/range/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  > "${run_dir}/cmake.log" 2>&1

echo "[range] entry coverage preflight"
python3 test/range/benchmark/check_entry_coverage.py \
  --config test/range/zscope.benchmark.yaml \
  --truth test/range/benchmark/ground_truth.json \
  > "${run_dir}/entry_coverage.json"

echo "[range] build unified CPG"
python3 -m zscope.cli.cli -c test/range/zscope.benchmark.yaml --build-cpg \
  > "${run_dir}/build_cpg.log" 2>&1

echo "[range] scan"
start_epoch="$(date +%s)"
set +e
python3 -m zscope.cli.cli -c test/range/zscope.benchmark.yaml --verbose \
  > "${run_dir}/zscope_run.log" 2>&1
scan_rc="$?"
set -e
end_epoch="$(date +%s)"
wall_seconds="$((end_epoch - start_epoch))"

if [[ -f test/range/zscope_batch_report.json ]]; then
  cp test/range/zscope_batch_report.json "${run_dir}/zscope_batch_report.json"
fi
if [[ -f test/range/zscope_batch_report.md ]]; then
  cp test/range/zscope_batch_report.md "${run_dir}/zscope_batch_report.md"
fi

if [[ -f "${run_dir}/zscope_batch_report.json" ]]; then
  python3 test/range/benchmark/evaluate_zscope_report.py \
    --report "${run_dir}/zscope_batch_report.json" \
    --truth test/range/benchmark/ground_truth.json \
    > "${run_dir}/evaluation.json"
fi

python3 - "${run_dir}" "${scan_rc}" "${wall_seconds}" <<'PY'
import json
import sys
from pathlib import Path

run_dir = Path(sys.argv[1])
scan_rc = int(sys.argv[2])
wall_seconds = int(sys.argv[3])
entry_count = 0
entries_path = Path("test/range/benchmark/entries.json")
if entries_path.exists():
    entry_count = len(json.loads(entries_path.read_text(encoding="utf-8")).get("functions", []))
metrics = {
    "scan_return_code": scan_rc,
    "scan_wall_seconds": wall_seconds,
    "entry_count": entry_count,
    "seconds_per_entry": round(wall_seconds / entry_count, 4) if entry_count else None,
}
eval_path = run_dir / "evaluation.json"
if eval_path.exists():
    metrics["evaluation"] = json.loads(eval_path.read_text(encoding="utf-8"))
    views = metrics["evaluation"].get("report_views", {})
    if views:
        metrics["benchmark_views"] = {
            name: {
                "issues": view.get("report_issue_count"),
                "true_positives": view.get("true_positives"),
                "false_positives": view.get("false_positives"),
                "false_negatives": view.get("false_negatives"),
                "detection_rate": view.get("recall"),
                "false_positive_rate": view.get("false_positive_rate"),
            }
            for name, view in views.items()
            if isinstance(view, dict) and name in {"default", "with_needs_review"}
        }
(run_dir / "metrics.json").write_text(
    json.dumps(metrics, ensure_ascii=False, indent=2),
    encoding="utf-8",
)
print(json.dumps(metrics, ensure_ascii=False, indent=2))
PY

if [[ -f "${run_dir}/evaluation.json" ]]; then
  exit 0
fi
exit "${scan_rc}"
