#!/usr/bin/env bash
# DRAFT ONLY: Root must review and install both frozen files first.
set -euo pipefail
if [[ $# != 1 || ! "$1" =~ ^[0-9a-f]{64}$ ]]; then
  echo 'Exactly one real final-ready SHA is required.' >&2
  exit 2
fi
if [[ -n "${PYTHONOPTIMIZE:-}" || -n "${PYTEST_ADDOPTS:-}" || -n "${PYTEST_PLUGINS:-}" || -n "${ZSCOPE_COORDINATOR_TEST_SLOT:-}" ]]; then
  echo 'External optimization/pytest settings or a nested coordination slot are forbidden.' >&2
  exit 2
fi
ROOT='/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope'
WORK="$ROOT/.coordination/20261014/workspaces/coordinator-native-job-independent-r35"
D="$ROOT/docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14"
PYTHON='/home/zeal/venv313/bin/python'
if [[ "$(uname -s)" != Linux || "$(id -un)" != zeal || "${BASH_SOURCE[0]}" != "$D/verify_native_job_independent_r35.sh" ]]; then
  echo 'Root-reviewed installed Linux launcher under zeal is required.' >&2
  exit 2
fi
export PATH="/home/zeal/venv313/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1
"$PYTHON" -c 'import hashlib,pathlib,sys; p=pathlib.Path(sys.argv[1]); expected="7fd4e683bb9e7523a3247eb5efd21ff5a130ebc83375933f32290f4007f9c158"; actual=hashlib.sha256(p.read_bytes()).hexdigest(); sys.exit(0 if actual==expected else "fixed outer slot helper SHA changed")' "$D/test_slot.py"
exec "$PYTHON" "$D/test_slot.py" --workspace "$WORK" -- "$PYTHON" "$D/verify_native_job_independent_r35.py" "$1"
