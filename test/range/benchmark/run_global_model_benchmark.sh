#!/usr/bin/env bash
set -euo pipefail

# Continues a completed global-model run with the full benchmark workflow.
# The existing entry/callee snapshots are reused, then vulnerability mining,
# validation, reporting, evaluation, and metrics generation are executed.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
cd "${repo_root}"

if [[ ! -r /proc/version ]] || ! grep -qiE 'microsoft|wsl' /proc/version; then
  echo "[global-model] ERROR: this benchmark must run inside WSL/Linux for SVF/Saber." >&2
  exit 2
fi

if [[ -f test/range/zscope.local.env ]]; then
  # Local secret-bearing config. This file is ignored by git.
  # shellcheck disable=SC1091
  source test/range/zscope.local.env
fi

if [[ -z "${Z_SCOPE_API_KEY:-}" ]]; then
  echo "[global-model] ERROR: Z_SCOPE_API_KEY is not set." >&2
  echo "[global-model] Set it in the environment or test/range/zscope.local.env." >&2
  exit 2
fi

export PATH="$HOME/go/bin:/usr/lib/llvm-18/bin:$HOME/.local/svf/SVF-SVF-3.2/build/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/.local/svf/SVF-SVF-3.2/build/lib:$HOME/.local/svf/llvm-18.1.0.obj/lib:${LD_LIBRARY_PATH:-}"
export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-18

latest_run_file="test/range/benchmark_runs/latest_global_model_wsl.txt"
if [[ -n "${1:-}" ]]; then
  if [[ -d "$1" ]]; then
    run_dir="${1%/}"
  else
    run_dir="test/range/benchmark_runs/${1%/}"
  fi
elif [[ -f "${latest_run_file}" ]]; then
  run_dir="$(<"${latest_run_file}")"
else
  echo "[global-model] ERROR: no previous global-model run was found." >&2
  echo "[global-model] Pass a run ID/path or create ${latest_run_file}." >&2
  exit 2
fi

if [[ ! -d "${run_dir}" ]]; then
  echo "[global-model] ERROR: run directory does not exist: ${run_dir}" >&2
  exit 2
fi
if [[ ! -d "${run_dir}/snapshots" ]]; then
  echo "[global-model] ERROR: snapshot directory does not exist: ${run_dir}/snapshots" >&2
  exit 2
fi

if [[ "${run_dir}" = /* ]]; then
  export Z_SCOPE_GLOBAL_MODEL_SNAPSHOT_DIR="${run_dir}/snapshots"
else
  export Z_SCOPE_GLOBAL_MODEL_SNAPSHOT_DIR="${repo_root}/${run_dir}/snapshots"
fi
config_path="test/range/zscope.global_model.benchmark.yaml"

echo "[global-model] repo_root=${repo_root}"
echo "[global-model] run_dir=${run_dir}"
echo "[global-model] snapshot_dir=${Z_SCOPE_GLOBAL_MODEL_SNAPSHOT_DIR}"

if ! command -v clangd >/dev/null 2>&1; then
  echo "[global-model] ERROR: clangd is required for the unified backend." >&2
  exit 2
fi

missing_svf=()
for tool in gclang get-bc llvm-link wpa saber; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing_svf+=("$tool")
  fi
done
if ((${#missing_svf[@]})); then
  echo "[global-model] ERROR: missing required WSL SVF/gllvm tools: ${missing_svf[*]}" >&2
  exit 2
fi

echo "[global-model] refresh CMake configuration"
cmake -S test/range -B test/range/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  > "${run_dir}/cmake.full_benchmark.log" 2>&1

echo "[global-model] entry coverage preflight"
python3 test/range/benchmark/check_entry_coverage.py \
  --config "${config_path}" \
  --truth test/range/benchmark/ground_truth.json \
  > "${run_dir}/entry_coverage.full_benchmark.json"

if [[ -f "${run_dir}/zscope_run.log" && ! -f "${run_dir}/global_model_only.log" ]]; then
  cp "${run_dir}/zscope_run.log" "${run_dir}/global_model_only.log"
fi
if [[ -f "${run_dir}/global_model_metrics.json" && ! -f "${run_dir}/global_model_only_metrics.json" ]]; then
  cp "${run_dir}/global_model_metrics.json" "${run_dir}/global_model_only_metrics.json"
fi

echo "[global-model] scan: reuse snapshots, then run the full benchmark workflow"
start_epoch="$(date +%s)"
set +e
python3 -m zscope.cli.cli -c "${config_path}" --verbose \
  > "${run_dir}/zscope_run.log" 2>&1
scan_rc="$?"
set -e
end_epoch="$(date +%s)"

if [[ -f test/range/zscope_batch_report.json ]]; then
  cp test/range/zscope_batch_report.json "${run_dir}/zscope_batch_report.json"
fi
if [[ -f test/range/zscope_batch_report.md ]]; then
  cp test/range/zscope_batch_report.md "${run_dir}/zscope_batch_report.md"
fi

if [[ -f "${run_dir}/zscope_batch_report.json" ]]; then
  python3 scripts/external_benchmark.py evaluate \
    --report "${run_dir}/zscope_batch_report.json" \
    --truth test/range/benchmark/ground_truth.json \
    --output "${run_dir}/evaluation.json"
  python3 scripts/external_benchmark.py evaluate \
    --report "${run_dir}/zscope_batch_report.json" \
    --truth test/range/benchmark/ground_truth.json \
    --output "${run_dir}/evaluation.with_needs_review.json" \
    --view with_needs_review
fi

python3 - "${run_dir}" "${scan_rc}" "$((end_epoch - start_epoch))" <<'PY'
import json
import re
import sys
from pathlib import Path

run_dir = Path(sys.argv[1])
log_text = (run_dir / "zscope_run.log").read_text(encoding="utf-8", errors="replace")
metrics = {
    "scan_return_code": int(sys.argv[2]),
    "scan_wall_seconds": int(sys.argv[3]),
    "global_model_start_count": len(re.findall(r"\[global-model\] start entries=", log_text)),
    "global_model_end_count": len(re.findall(r"\[global-model\] end entries=", log_text)),
    "global_llm_snapshot_count": len(re.findall(r"\[snapshot-llm\] completed context=global .*success=true", log_text)),
    "global_deterministic_or_cache_counts_logged_in_summary": True,
    "entry_snapshot_reuse_count": len(re.findall(r"\[global-model\] Reusing entry snapshot", log_text)),
    "global_model_fallback_count": len(re.findall(r"\[global-model\] failed before entry fan-out", log_text)),
    "per_entry_premodel_log_count": len(re.findall(r"\[premodel\]", log_text)),
    "per_entry_llm_snapshot_count": len(re.findall(r"\[snapshot-llm\] completed context=entry .*success=true", log_text)),
}
evaluation_path = run_dir / "evaluation.json"
if evaluation_path.exists():
    metrics["evaluation"] = json.loads(evaluation_path.read_text(encoding="utf-8"))
(run_dir / "global_model_metrics.json").write_text(
    json.dumps(metrics, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
print(json.dumps(metrics, ensure_ascii=False, indent=2))
PY

python3 test_scripts/generate_global_model_metrics.py "${run_dir}"

echo "[global-model] inspect ${run_dir}/evaluation.json, ${run_dir}/metrics.md, ${run_dir}/global_model_metrics.json, and ${run_dir}/zscope_run.log"
if [[ -f "${run_dir}/evaluation.json" ]]; then
  exit 0
fi
exit "${scan_rc}"
