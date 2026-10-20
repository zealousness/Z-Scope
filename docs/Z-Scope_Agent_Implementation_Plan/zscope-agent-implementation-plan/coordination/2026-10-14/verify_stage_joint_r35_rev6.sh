#!/usr/bin/env bash
# Artifact-only draft. Root must review and install the exact frozen pair.
set -euo pipefail
if [[ $# != 0 || "$(uname -s)" != Linux || "$(id -un)" != zeal ]]; then
  echo 'Fixed ordinary Linux zeal invocation without saved commands required.' >&2
  exit 2
fi
if [[ -n "${PYTHONOPTIMIZE:-}" || -n "${PYTEST_ADDOPTS:-}" || -n "${PYTEST_PLUGINS:-}" || -n "${ZSCOPE_COORDINATOR_TEST_SLOT:-}" ]]; then
  echo 'Optimization, external pytest settings, or an already-held outer slot are forbidden.' >&2
  exit 2
fi
ROOT='/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope'
D="$ROOT/docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14"
STAGE="$ROOT/.coordination/20261014/workspaces/coordinator-instance-integration-r24"
PYTHON='/home/zeal/venv313/bin/python'
if [[ "${BASH_SOURCE[0]}" != "$D/verify_stage_joint_r35_rev6.sh" ]]; then
  echo 'Only the exact Root-reviewed installed launcher path is accepted.' >&2
  exit 2
fi
export PATH="/home/zeal/venv313/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1
"$PYTHON" -c 'import hashlib,pathlib,sys; p=pathlib.Path(sys.argv[1]); expected="7fd4e683bb9e7523a3247eb5efd21ff5a130ebc83375933f32290f4007f9c158"; actual=hashlib.sha256(p.read_bytes()).hexdigest(); sys.exit(0 if actual==expected else "fixed outer slot helper changed")' "$D/test_slot.py"
exec "$PYTHON" "$D/test_slot.py" --workspace "$STAGE" -- "$PYTHON" "$D/verify_stage_joint_r35_rev6.py"
