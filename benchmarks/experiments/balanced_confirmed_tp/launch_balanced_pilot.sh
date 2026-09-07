#!/bin/bash
# M5 balanced-depth pilot launcher (reference and rung rows share this script;
# the rung row is selected by Z_SCOPE_PILOT_RUNG).
#   Z_SCOPE_PILOT_RUNG=ref  -> rungs off (balanced reference)
#   Z_SCOPE_PILOT_RUNG=r2   -> analysis.validation_v3_reattempt=true
set -euo pipefail
REPO=/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope
RUNG="${Z_SCOPE_PILOT_RUNG:-ref}"
set -a
source "$REPO/test/range/zscope.local.env"
set +a
export PATH="$HOME/go/bin:/usr/lib/llvm-18/bin:$HOME/.local/svf/SVF-linux-x86_64/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/.local/svf/SVF-linux-x86_64/lib:$HOME/.local/svf/llvm-18.1.0.obj/lib:${LD_LIBRARY_PATH:-}"
export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-18
# The stale system/venv editable installs map `zscope` to the old checkout
# (work/Z-Scope @ c2f97a6). PYTHONPATH must pin the pilot to THIS tree.
export PYTHONPATH="$REPO"
cd "$REPO"

# Rung switches ride the runtime-spec override (public config schema rejects
# runtime.analysis); developer mode is required for the override to load.
export Z_SCOPE_DEVELOPER_MODE=1
export Z_SCOPE_RUNTIME_SPEC="$REPO/benchmarks/experiments/balanced_confirmed_tp/runtime_spec_${RUNG}.yaml"
if [ ! -f "$Z_SCOPE_RUNTIME_SPEC" ]; then
  echo "missing runtime override: $Z_SCOPE_RUNTIME_SPEC" >&2
  exit 2
fi

echo "=== zscope-benchmark mode=trial depth=balanced rung=$RUNG spec=$Z_SCOPE_RUNTIME_SPEC base_url=$Z_SCOPE_LLM_BASE_URL model=$Z_SCOPE_LLM_MODEL key_len=${#Z_SCOPE_API_KEY} ==="
echo "=== git: $(git rev-parse --abbrev-ref HEAD) @ $(git rev-parse --short HEAD) ==="
exec python3 -m zscope.cli.benchmark run --language c_cpp --mode trial --scan-depth balanced
