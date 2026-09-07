#!/bin/bash
# Diagnostic v2: instrument the runner to trace where each prepared item goes.
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
exec python3 - <<'PYEOF'
import logging, sys, time

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("diag")

from zscope.core.validation import runner as vr
import zscope.core.validation.runner as vrmod

log.info("diag: runner module = %s", vrmod.__file__)
log.info("diag: ValidationRunner from = %s", vr.ValidationRunner.__module__)

# Wrap the branch decision points.
_orig_enabled = vr.ValidationRunner._deterministic_prevalidation_enabled
def _enabled(self):
    log.info("diag: _deterministic_prevalidation_enabled called -> False")
    return False
vr.ValidationRunner._deterministic_prevalidation_enabled = _enabled

_orig_prepare = vr.ValidationRunner._prepare_issue_for_validation
_preps = {"n": 0, "none": 0, "item": 0}
def _prepare(self, state, raw_issue, index):
    _preps["n"] += 1
    result = _orig_prepare(self, state, raw_issue, index)
    if result is None:
        _preps["none"] += 1
    else:
        _preps["item"] += 1
    if _preps["n"] in (1, 100, 308):
        issue = raw_issue
        log.info(
            "diag: prep#%d id=%s validation_required=%r finding_kind=%r val_req_in_pack=%r result=%s",
            _preps["n"], issue.get("id"),
            issue.get("validation_required"),
            issue.get("finding_kind"),
            (issue.get("evidence_pack") or {}).get("validation_required") if isinstance(issue.get("evidence_pack"), dict) else None,
            "item" if result is not None else "None",
        )
    return result
vr.ValidationRunner._prepare_issue_for_validation = _prepare

_orig_run = vr.ValidationRunner.run
def _run(self, state):
    pending = state.get("pending_new_issues") or []
    log.info("diag: run() pending=%d validator_enabled=%s workers_cfg=%s",
             len(pending), self._validator_enabled(),
             getattr(self.config.concurrency, "validator_workers", None))
    t0 = time.monotonic()
    _orig_run(self, state)
    log.info("diag: run() done in %.1fs state: issues=%d observations=%d notes=%d avoided=%s preval_dec=%s",
             time.monotonic() - t0,
             len(state.get("issues") or []), len(state.get("observations") or []),
             len(state.get("notes") or []),
             state.get("validator_avoided_count"), state.get("deterministic_prevalidation_decision_count"))
vr.ValidationRunner.run = _run

from zscope.cli.benchmark import main
sys.argv = ["zscope-benchmark", "run", "--language", "c_cpp", "--mode", "trial", "--scan-depth", "fast"]
main(sys.argv[1:])
PYEOF
