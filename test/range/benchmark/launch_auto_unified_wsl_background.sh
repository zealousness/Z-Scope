#!/usr/bin/env bash
set -euo pipefail

if [[ ! -r /proc/version ]] || ! grep -qiE 'microsoft|wsl' /proc/version; then
  echo "[range] ERROR: benchmark launcher must run inside WSL." >&2
  exit 2
fi

repo_root="${Z_SCOPE_REPO_ROOT:-/mnt/c/Users/10273/home/work/Z-Scope}"
cd "${repo_root}"

run_id="${1:-auto_unified_wsl_opt_$(date +%Y%m%d_%H%M%S)}"
run_dir="test/range/benchmark_runs/${run_id}"
mkdir -p "${run_dir}"

setsid bash test/range/benchmark/run_auto_unified_wsl.sh "${run_id}" \
  > "${run_dir}/launcher.nohup.log" 2>&1 < /dev/null &
pid="$!"
echo "${pid}" > "${run_dir}/wsl.pid"

sleep 2
if ! kill -0 "${pid}" >/dev/null 2>&1; then
  echo "[range] ERROR: benchmark process exited immediately; see ${run_dir}/launcher.nohup.log" >&2
  tail -40 "${run_dir}/launcher.nohup.log" >&2 || true
  exit 1
fi

printf '{"run_id":"%s","pid":%s,"run_dir":"%s"}\n' "${run_id}" "${pid}" "${run_dir}"
