#!/usr/bin/env bash
# Artifact-only concrete-build draft. Root must review/install; ready is absent.
set -euo pipefail
FINAL_NATIVE_SHA='2f71ea9417c9d3d06a2a57d113b1414e7400bc4cefb77b87b578039df6238fe9'
SUCCESSFUL_BUILD_RECEIPT_SHA='6e05586999c536da82ef1c7e4fa4613afc6d83637d861a4eab6e399396d2f84d'
if [[ ! "$FINAL_NATIVE_SHA" =~ ^[0-9a-f]{64}$ || ! "$SUCCESSFUL_BUILD_RECEIPT_SHA" =~ ^[0-9a-f]{64}$ ]]; then
  echo 'Pending actual successful native build and binary SHA; execution forbidden.' >&2
  exit 2
fi
if [[ $# != 1 || ! "$1" =~ ^[0-9a-f]{64}$ ]]; then
  echo 'Exactly one real bounded-ready SHA is required.' >&2
  exit 2
fi
if [[ -n "${PYTHONOPTIMIZE:-}" || -n "${PYTEST_ADDOPTS:-}" || -n "${PYTEST_PLUGINS:-}" || -n "${ZSCOPE_COORDINATOR_TEST_SLOT:-}" ]]; then
  echo 'Optimization, external pytest settings, or nested slots are forbidden.' >&2
  exit 2
fi
ROOT='/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope'
WORK="$ROOT/.coordination/20261014/workspaces/coordinator-bounded-native-acceptance-r36"
D="$ROOT/docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14"
PYTHON='/home/zeal/venv313/bin/python'
ENV_PROLOGUE="$ROOT/.coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34/native-build-env-r36-v9.sh"
if [[ "$(/usr/bin/sha256sum -- "$ENV_PROLOGUE")" != "969cddf552a7180eebf115f35a0351c55a7c902750800af686e359e64ce1b266  $ENV_PROLOGUE" ]]; then
  echo 'Fixed successful-v9 ENV boundary changed.' >&2
  exit 2
fi
source "$ENV_PROLOGUE"
if [[ "$PATH" != '/home/zeal/venv313/bin:/home/zeal/go/bin:/usr/lib/llvm-18/bin:/home/zeal/.local/svf/SVF-linux-x86_64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/lib/wsl/lib' || "$LD_LIBRARY_PATH" != '/home/zeal/.local/svf/SVF-linux-x86_64/lib:/home/zeal/.local/svf/llvm-18.1.0.obj/lib:' || "$ZSCOPE_R36_NATIVE_ENV_BOUNDARY" != r36-v9 ]]; then
  echo 'Actual canonical Linux PATH/LD boundary missing.' >&2
  exit 2
fi
if [[ "$(uname -s)" != Linux || "$(id -un)" != zeal || "${BASH_SOURCE[0]}" != "$D/verify_bounded_native_acceptance_r36.sh" ]]; then
  echo 'Root-reviewed installed Linux launcher under zeal is required.' >&2
  exit 2
fi
export PYTHONDONTWRITEBYTECODE=1
"$PYTHON" -c 'import hashlib,pathlib,sys; p=pathlib.Path(sys.argv[1]); s="7fd4e683bb9e7523a3247eb5efd21ff5a130ebc83375933f32290f4007f9c158"; sys.exit(0 if hashlib.sha256(p.read_bytes()).hexdigest()==s else "fixed slot helper changed")' "$D/test_slot.py"
exec "$PYTHON" "$D/test_slot.py" --workspace "$WORK" -- "$PYTHON" "$D/verify_bounded_native_acceptance_r36.py" "$1"
