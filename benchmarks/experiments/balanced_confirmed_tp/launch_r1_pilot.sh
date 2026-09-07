#!/bin/bash
# R1 pilot launcher — mirrors the frozen trial's operator procedure
# (see benchmark-artifacts/c_cpp/trial/20260904T094432Z/run-01/runner-stdout.log).
set -euo pipefail
REPO=/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope
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
echo "=== zscope-benchmark mode=trial base_url=$Z_SCOPE_LLM_BASE_URL model=$Z_SCOPE_LLM_MODEL key_len=${#Z_SCOPE_API_KEY} ==="
echo "=== git: $(git rev-parse --abbrev-ref HEAD) @ $(git rev-parse --short HEAD) ==="
exec python3 -m zscope.cli.benchmark run --language c_cpp --mode trial --scan-depth fast
