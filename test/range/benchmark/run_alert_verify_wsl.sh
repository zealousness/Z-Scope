#!/usr/bin/env bash
set -euo pipefail

if [[ ! -r /proc/version ]] || ! grep -qiE 'microsoft|wsl' /proc/version; then
  echo "[range-alert] ERROR: alert verification benchmark must run inside WSL/Linux." >&2
  echo "[range-alert]        Launch with: wsl bash -lc 'cd /path/to/Z-Scope && test/range/benchmark/run_alert_verify_wsl.sh <sarif>'" >&2
  exit 2
fi

repo_root="${Z_SCOPE_REPO_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)}"
cd "${repo_root}"

if [[ -f test/range/zscope.local.env ]]; then
  # Local secret-bearing config. This file is ignored by git.
  # shellcheck disable=SC1091
  source test/range/zscope.local.env
fi

if [[ -z "${Z_SCOPE_API_KEY:-}" ]]; then
  echo "[range-alert] ERROR: Z_SCOPE_API_KEY is not set." >&2
  echo "[range-alert] Set it in the environment or in test/range/zscope.local.env." >&2
  exit 2
fi

export PATH="$HOME/go/bin:/usr/lib/llvm-18/bin:$HOME/.local/svf/SVF-linux-x86_64/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/.local/svf/SVF-linux-x86_64/lib:$HOME/.local/svf/llvm-18.1.0.obj/lib:${LD_LIBRARY_PATH:-}"
export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-18

sarif_path="${1:-test/range/codeql_runs/codeql_cpp_security_quality_20260606_100438/results_pruned_global_minfp_73tp.sarif}"
config_path="${2:-test/range/benchmark_runs/auto_unified_wsl_unlimited_20260604_111838/zscope.auto_unified.yaml}"
run_id="${3:-alert_verify_codeql_pruned_$(date +%Y%m%d_%H%M%S)}"
run_dir="test/range/benchmark_runs/${run_id}"
mkdir -p "${run_dir}"
printf '%s\n' "${run_dir}" > test/range/benchmark_runs/latest_alert_verify_wsl.txt

if [[ ! -f "${sarif_path}" ]]; then
  echo "[range-alert] ERROR: SARIF not found: ${sarif_path}" >&2
  exit 2
fi
if [[ ! -f "${config_path}" ]]; then
  echo "[range-alert] ERROR: config not found: ${config_path}" >&2
  exit 2
fi

echo "[range-alert] run_dir=${run_dir}"
echo "[range-alert] sarif=${sarif_path}"
echo "[range-alert] config=${config_path}"

python3 - "${config_path}" <<'PY'
import sys
from pathlib import Path

import yaml

path = Path(sys.argv[1])
cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
analysis = cfg.get("analysis") or {}
indexing = cfg.get("indexing") or {}
parallel_workers = int(analysis.get("parallel_workers") or 1)
validation_workers = int(analysis.get("validation_parallel_workers") or 0)
backend = (indexing.get("backend") or "").lower()
clangd_path = indexing.get("clangd_path")
if backend != "unified":
    raise SystemExit(f"[range-alert] ERROR: expected indexing.backend=unified, got {backend!r}")
if clangd_path != "clangd":
    raise SystemExit(f"[range-alert] ERROR: WSL config must use clangd_path=clangd, got {clangd_path!r}")
effective_workers = validation_workers if validation_workers > 0 else parallel_workers
if effective_workers <= 1:
    raise SystemExit(f"[range-alert] ERROR: expected alert verification workers > 1, got {effective_workers}")
print(f"[range-alert] config preflight passed: unified backend, effective alert workers={effective_workers}")
PY

rm -f test/range/zscope_alert_verify_report.json

start_epoch="$(date +%s)"
set +e
python3 -m zscope.cli.cli \
  -c "${config_path}" \
  --mode alert-verify \
  --sarif "${sarif_path}" \
  --verbose \
  > "${run_dir}/alert_verify.log" 2>&1
verify_rc="$?"
set -e
end_epoch="$(date +%s)"
wall_seconds="$((end_epoch - start_epoch))"

if [[ -f test/range/zscope_alert_verify_report.json ]]; then
  cp test/range/zscope_alert_verify_report.json "${run_dir}/zscope_alert_verify_report.json"
fi
cp "${config_path}" "${run_dir}/zscope.alert_verify.yaml"
cp "${sarif_path}" "${run_dir}/input.sarif"

python3 - "${run_dir}" "${verify_rc}" "${wall_seconds}" <<'PY'
import json
import re
import sys
from pathlib import Path

run_dir = Path(sys.argv[1])
verify_rc = int(sys.argv[2])
wall_seconds = int(sys.argv[3])

def load_json(path):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}

report = load_json(run_dir / "zscope_alert_verify_report.json")
results = report.get("results") if isinstance(report.get("results"), list) else []
log = (run_dir / "alert_verify.log").read_text(encoding="utf-8", errors="replace") if (run_dir / "alert_verify.log").exists() else ""
counts = {}
for item in results:
    verdict = str(item.get("verdict") or "missing")
    counts[verdict] = counts.get(verdict, 0) + 1
worker_match = re.search(r"Verifying alerts with (\d+) worker", log)
summary = {
    "run_id": run_dir.name,
    "verify_return_code": verify_rc,
    "verify_completed": bool(results) and "Verification complete:" in log,
    "verify_wall_seconds": wall_seconds,
    "mode": "wsl_alert_verify_codeql_sarif",
    "artifacts": {
        "input_sarif": str((run_dir / "input.sarif").resolve()),
        "config": str((run_dir / "zscope.alert_verify.yaml").resolve()),
        "alert_verify_log": str((run_dir / "alert_verify.log").resolve()),
        "alert_verify_report": str((run_dir / "zscope_alert_verify_report.json").resolve()),
    },
    "verdict_counts": counts,
    "alert_count": len(results),
    "effective_alert_workers": int(worker_match.group(1)) if worker_match else None,
    "api_key_error": "invalid_api_key" in log or "Incorrect API key" in log,
}
(run_dir / "run_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False, indent=2))
PY

if [[ "${verify_rc}" -ne 0 && ! -f "${run_dir}/zscope_alert_verify_report.json" ]]; then
  echo "[range-alert] ERROR: alert verification failed with rc=${verify_rc} before writing report; see ${run_dir}/alert_verify.log" >&2
  exit "${verify_rc}"
fi

echo "[range-alert] completed: ${run_dir}"
