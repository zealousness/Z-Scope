#!/usr/bin/env bash
set -euo pipefail

if [[ ! -r /proc/version ]] || ! grep -qiE 'microsoft|wsl' /proc/version; then
  echo "[range] ERROR: background launcher must run inside WSL." >&2
  exit 2
fi

repo_root="${Z_SCOPE_REPO_ROOT:-/mnt/c/Users/10273/home/work/Z-Scope}"
cd "${repo_root}"

run_id="${1:-auto_unified_wsl_$(date +%Y%m%d_%H%M%S)}"
run_dir="test/range/benchmark_runs/${run_id}"
mkdir -p "${run_dir}"

setsid test/range/benchmark/run_auto_unified_wsl.sh "${run_id}" \
  > "${run_dir}/driver_stdout.log" \
  2> "${run_dir}/driver_stderr.log" \
  < /dev/null &
pid="$!"

sleep 1
if ! kill -0 "${pid}" >/dev/null 2>&1; then
  echo "[range] ERROR: background run exited during startup." >&2
  cat "${run_dir}/driver_stdout.log" >&2 || true
  cat "${run_dir}/driver_stderr.log" >&2 || true
  exit 1
fi

echo "pid=${pid}"
echo "run_id=${run_id}"
echo "run_dir=${run_dir}"
echo "stdout=${run_dir}/driver_stdout.log"
echo "stderr=${run_dir}/driver_stderr.log"
