"""Prepare an isolated, uniquely owned Store seam candidate from the exact Stage floor."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
WORK = ROOT / ".coordination/20261014/workspaces/store-active-transactions-r35"
OUT = ROOT / "artifacts/store-active-transactions-r35-20261017"
PLAN = ROOT / ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34/ACTIVE-TRANSACTION-PLAN.md"
INTAKE = ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Use unoptimized Linux Python")
assert sha(PLAN) == "c852779752277dc46d88640a8b08a2a7d85f8eec6925fb7ee19bd05acb38c53f"
intake = read(INTAKE)
source, root_inputs = intake["complete_inputs_after"], intake["root_inputs"]
assert len(source) == 1082 and len(root_inputs) == 1065
assert all(sha(STAGE / p) == v for p, v in source.items())
assert all(sha(ROOT / p) == v for p, v in root_inputs.items())
assert source["zscope/orchestration/jobs/store.py"] == "e9ea6ef86fece2f002c75b144d0fab102377d0d3b67a7f3deb6c884e3693c1d8"
if WORK.exists() or OUT.exists():
    raise RuntimeError("Do not duplicate or replace the existing isolated task")
WORK.mkdir()
OUT.mkdir()
for name in source:
    target = WORK / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(STAGE / name, target)
assert all(sha(WORK / p) == v for p, v in source.items())
assert all(sha(STAGE / p) == v for p, v in source.items())
assert all(sha(ROOT / p) == v for p, v in root_inputs.items())
references = [
    PLAN, INTAKE, HERE / "test_slot.py", HERE / "root_runtime_preflight_r23.py",
    ROOT / "artifacts/job-runtime-footprint-source-review-r34-20261017/concurrency-first-gate-plan-review.json",
    ROOT / "artifacts/coordinator-current-verification-r29-20261017/store-bounded-acceptance.json",
    ROOT / "artifacts/coordinator-store-queue-r26-e0560b7b2e9d/review.json",
    ROOT / "artifacts/store-queue-source-review-r28-20261017/review.json",
]
receipt = dict(
    actual_preparer="/root", prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),
    logical_task="STORE-ACTIVE-TRANSACTION-SEAM-R35", bridge_task_id=None,
    requested_model="gpt-6.1-sol", requested_effort="xhigh", workspace=str(WORK),
    initial_inputs=source, root_inputs=root_inputs, root_and_stage_unchanged=True,
    owned_product_paths=["zscope/orchestration/jobs/store.py"],
    owned_new_test_paths=["tests/test_store_active_transactions_r35.py"],
    owned_artifact_prefix="artifacts/store_active_transactions_r35",
    other_products_readonly=True, job_worker_store_edits_forbidden=True,
    interface_contract=dict(
        bound_attempt_original_signature_retained=True,
        private_active_connection_accessor="_active_transaction_connection",
        accessor_returns="sqlite3.Connection only inside a verified live same-Store/same-thread write frame; otherwise typed JobError",
        borrowed_connection_never_begun_committed_rolled_back_or_closed=True,
        read_transactions_never_issue_authority=True,
        capability_revoked_before_transaction_finish=True,
        exact_attempt_binding_still_checked_in_actual_connection=True,
    ),
    original_failed_deliveries=0, stage_intake=False, root_intake=False,
    test_execution_confirmed=False, independent_acceptance=False,
    source_review_required_before_implementation=True,
    reference_sha256={str(p): sha(p) for p in references},
)
(OUT / "preparation.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(workspace=str(WORK), copied_inputs=len(source), ownership_sha256=sha(OUT / "preparation.json"), root_stage_unchanged=True)))
