#!/usr/bin/env bash
set -euo pipefail

if [[ ! -r /proc/version ]] || ! grep -qiE 'microsoft|wsl' /proc/version; then
  echo "[range-alert] ERROR: background launcher must run inside WSL." >&2
  exit 2
fi

repo_root="${Z_SCOPE_REPO_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)}"
cd "${repo_root}"

sarif_path="${1:-test/range/codeql_runs/codeql_cpp_security_quality_20260606_100438/results_pruned_global_minfp_73tp.sarif}"
config_path="${2:-test/range/benchmark_runs/auto_unified_wsl_unlimited_20260604_111838/zscope.auto_unified.yaml}"
run_id="${3:-alert_verify_codeql_pruned_global_$(date +%Y%m%d_%H%M%S)}"
run_dir="test/range/benchmark_runs/${run_id}"
mkdir -p "${run_dir}"

setsid test/range/benchmark/run_alert_verify_wsl.sh \
  "${sarif_path}" \
  "${config_path}" \
  "${run_id}" \
  > "${run_dir}/driver_stdout.log" \
  2> "${run_dir}/driver_stderr.log" \
  < /dev/null &
pid="$!"

sleep 2
if ! kill -0 "${pid}" >/dev/null 2>&1; then
  echo "[range-alert] ERROR: background alert verification exited during startup." >&2
  cat "${run_dir}/driver_stdout.log" >&2 || true
  cat "${run_dir}/driver_stderr.log" >&2 || true
  exit 1
fi

echo "${pid}" > "${run_dir}/wsl.pid"
echo "pid=${pid}"
echo "run_id=${run_id}"
echo "run_dir=${run_dir}"
echo "stdout=${run_dir}/driver_stdout.log"
echo "stderr=${run_dir}/driver_stderr.log"
