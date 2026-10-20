"""Audit final evidence/encoding and retain bounded scopes in summary projections."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-consumer-acceptance-r29-20261017/handoff-audit.json"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


acceptance_path = OUT.parent / "review.json"
acceptance = read(acceptance_path)
assert acceptance["independent_acceptance"] and not acceptance["root_intake"] and not acceptance["coordinator_stage_intake"]
assert acceptance["s01"]["consecutive_failed_actual_deliveries"] == 3 and not acceptance["s01"]["fourth_dispatched"]
assert all(sha(ROOT / path) == digest for path, digest in acceptance["references_sha256"].items())
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
ledger = read(HERE / "tasks.json")
rows = {row["id"]: row for row in ledger["tasks"]}
assert len(rows) == len(ledger["tasks"])
assert rows["ASTRA-INSTANCE-CONSUMERS-R25"]["original_delivery_independent_acceptance"] is False
assert rows["ASTRA-INSTANCE-CONSUMERS-R25"]["prior_failed_actual_deliveries_before_acceptance"] == 1
assert rows["ASTRA-INSTANCE-CONSUMERS-R25"]["consecutive_failed_actual_deliveries"] == 0
assert rows["S01-INSTANCE-SEMANTICS-MIN-R23"]["consecutive_failed_actual_deliveries"] == 3
fields = ("accepted_repair_task", "original_delivery_independent_acceptance", "independent_acceptance_scope", "coordinator_stage_intake", "prior_failed_actual_deliveries_before_acceptance", "store_bounds_repair_verified", "store_bounded_acceptance")
for entry in ledger["next_module_tasks"]:
    source = rows[entry["id"]]
    entry.update({key: source[key] for key in fields if key in source})
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation["next_module_tasks"] = ledger["next_module_tasks"]
write(HERE / "continuation-r6.json", continuation)
paths = [HERE / name for name in ("tasks.json", "continuation-r6.json", "PROGRESS.md", "DAG.md", "CURRENT_STATE_R29.md")]
for path in paths:
    data = path.read_bytes()
    assert not data.startswith(b"\xef\xbb\xbf") and b"\r" not in data and data.endswith(b"\n")
    data.decode("utf-8", errors="strict")
proof = dict(audited_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), actual_task="/root", parent_acceptance_receipt=acceptance_path.relative_to(ROOT).as_posix(), parent_acceptance_sha256=sha(acceptance_path), accepted_evidence_references_current=True, root_pinned_inputs_current=1065, unique_ledger_task_ids=True, logical_original_rejected_vs_accepted_repair_projection_explicit=True, prior_failed_consumer_delivery_retained=1, consecutive_consumer_failures_after_bounded_acceptance=0, s01_failed_deliveries_unchanged=3, s01_fourth_dispatched=False, shared_documents_utf8_no_bom_lf_final_newline=True, files_sha256={path.relative_to(ROOT).as_posix(): sha(path) for path in paths}, tests_executed_by_audit=0, quality_executed_by_audit=0, source_writes=0, root_intake=False, stage_intake=False, root_joint_rerun=False, services_started_or_restarted=0, bridge_dispatches=0, archived_s06_operations=0)
assert not OUT.exists()
write(OUT, proof)
print(json.dumps(dict(receipt=OUT.relative_to(ROOT).as_posix(), audited_at=proof["audited_at"], documents_utf8_lf=True, root_pinned_inputs_current=1065)))
