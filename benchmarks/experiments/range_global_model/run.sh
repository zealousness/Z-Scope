#!/usr/bin/env bash
set -euo pipefail

# Runs the full benchmark entry list through the global semantic-modeling path.
# It intentionally omits benchmark evaluation and disables vulnerability mining,
# validation, and subagents through the developer-only RuntimeSpec override.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
cd "${repo_root}"

if [[ ! -r /proc/version ]] || ! grep -qiE 'microsoft|wsl' /proc/version; then
  echo "[global-model] ERROR: this benchmark must run inside WSL/Linux for SVF/Saber." >&2
  exit 2
fi

if [[ -z "${Z_SCOPE_API_KEY:-}" || -z "${Z_SCOPE_LLM_BASE_URL:-}" || -z "${Z_SCOPE_LLM_MODEL:-}" ]]; then
  echo "[global-model] ERROR: Z_SCOPE_API_KEY, Z_SCOPE_LLM_BASE_URL, and Z_SCOPE_LLM_MODEL are required." >&2
  exit 2
fi

export LLVM_COMPILER=clang
export LLVM_CC_NAME="${LLVM_CC_NAME:-clang}"

run_id="${1:-global_model_$(date +%Y%m%d_%H%M%S)}"
run_root="${Z_SCOPE_BENCHMARK_OUTPUT:-benchmark-artifacts/experiments/range_global_model}"
run_dir="${run_root}/${run_id}"
mkdir -p "${run_dir}"

export Z_SCOPE_GLOBAL_MODEL_SNAPSHOT_DIR="${repo_root}/${run_dir}/snapshots"
export Z_SCOPE_DEVELOPER_MODE=1
export Z_SCOPE_RUNTIME_SPEC="${repo_root}/benchmarks/experiments/range_global_model/runtime.override.yaml"
config_path="benchmarks/experiments/range_global_model/zscope.benchmark.yaml"

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

echo "[global-model] configure CMake"
cmake -S test/range -B test/range/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  > "${run_dir}/cmake.log" 2>&1

echo "[global-model] entry coverage preflight"
python3 test/range/benchmark/check_entry_coverage.py \
  --config "${config_path}" \
  --entries test/range/benchmark/deterministic_entries.json \
  --truth test/range/benchmark/ground_truth.json \
  > "${run_dir}/entry_coverage.json"

echo "[global-model] build unified CPG"
python3 -m zscope.cli.cli -c "${config_path}" --build-index \
  > "${run_dir}/build_cpg.log" 2>&1

echo "[global-model] scan: global modeling plus entry snapshot reuse"
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
(run_dir / "global_model_metrics.json").write_text(
    json.dumps(metrics, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
print(json.dumps(metrics, ensure_ascii=False, indent=2))
PY

python3 benchmarks/experiments/range_global_model/generate_metrics.py \
  "${run_dir}" \
  --model "${Z_SCOPE_LLM_MODEL}"

echo "[global-model] inspect ${run_dir}/metrics.md, ${run_dir}/global_model_metrics.json, and ${run_dir}/zscope_run.log"
exit "${scan_rc}"
