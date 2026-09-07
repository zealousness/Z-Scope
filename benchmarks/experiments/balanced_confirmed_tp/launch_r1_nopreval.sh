#!/bin/bash
# Diagnostic: same pilot launch but with deterministic prevalidation disabled,
# to test whether the prevalidation pass is consuming all groups silently.
set -euo pipefail
REPO=/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope
set -a
source "$REPO/test/range/zscope.local.env"
set +a
export PATH="$HOME/go/bin:/usr/lib/llvm-18/bin:$HOME/.local/svf/SVF-linux-x86_64/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/.local/svf/SVF-linux-x86_64/lib:$HOME/.local/svf/llvm-18.1.0.obj/lib:${LD_LIBRARY_PATH:-}"
export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-18
cd "$REPO"
export Z_SCOPE_DIAG_OVERRIDE="1"
exec python3 - <<'PYEOF'
import logging
logging.basicConfig(level=logging.DEBUG)

# Patch BEFORE importing anything that binds it.
from zscope.core.validation import runner as vr
vr.ValidationRunner._deterministic_prevalidation_enabled = lambda self: False

from zscope.cli.benchmark import main
import sys
sys.argv = [
    "zscope-benchmark", "run",
    "--language", "c_cpp",
    "--mode", "trial",
    "--scan-depth", "fast",
]
main(sys.argv[1:])
PYEOF
