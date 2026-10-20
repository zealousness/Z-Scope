"""Freeze the independent contract supplement for prepared isolated workers."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

def read(p):
    return json.loads(p.read_text(encoding="utf-8"))

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

review_paths = ["artifacts/design-contract-independent-review-r23-20261016/review.json", "artifacts/design-contract-independent-review-r23-20261016/DELIVERY.md"]
review = read(ROOT / review_paths[0])
assert review["source_review_passed"] and review["design_dispatch_ready"] and not review["blocking_findings"]
assert all(sha(ROOT / p) == h for p, h in review["reviewed_contract_hashes"].items())
assert review["source_hashes_before"] == review["source_hashes_after"] and all(sha(ROOT / p) == h for p, h in review["source_hashes_after"].items())
ledger = read(HERE / "tasks.json")
rows = {r["id"]: r for r in ledger["tasks"]}
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
for identity, name in (("S01-INSTANCE-SEMANTICS-MIN-R23", "s01-instance-semantics-min-r23"), ("S08-INSTANCE-RECOVERY-MIN-R23", "s08-instance-recovery-min-r23")):
    assert not rows[identity].get("bridge_task_id")
    branch = ROOT / ".coordination/20261014/workspaces" / name
    dependencies = []
    for p in review_paths:
        target = branch / p
        assert not target.exists()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / p).read_bytes())
        dependencies.append({"path": p, "previous_sha256": None, "sha256": sha(target), "read_only": True})
    write(HERE / "followups-r12" / (name + "-dependencies.json"), {"captured_at": at, "files": dependencies, "coordinator_authorized": True})
    payload_path = HERE / "followups-r12" / (name + "-request.json")
    payload = read(payload_path)
    payload["arguments"]["message"] += "\n冻结独立合同复核已通过，必读副本 artifacts/design-contract-independent-review-r23-20261016/{DELIVERY.md,review.json}；仅两个新增readonly依赖，连原1067基线共1069输入。实施细节：dependencies_current_status()不能单独替代精确program-facts/context-input的compile DB/命令/include-search/include-probes当前性核验；任何未知拒绝效果/复用。S08 codec必须完整成员摘要，exporter在Ledger锁内提供完整成员manifest，同计数替换occurrence负例也要拒绝；token字段repr=False/不入磁盘/日志。允许在各自新文件内添加实现所需helper与严格不可变JSON manifest字段，但新增公开字段或接口与冻结typed合同冲突时先报告协调者。模块交付仅候选，全部真实消费者接线/claim settle/ledger/R-E barrier由协调者后续完成。\n"
    write(payload_path, payload)
    (HERE / "followups-r12" / (name + "-message.txt")).write_text(payload["arguments"]["message"], encoding="utf-8", newline="\n")
    rows[identity].update(contract_review_passed=True, contract_review=review_paths[0], prepared_readonly_input_files=1069, checked_at=at)
rows["ASTRA-DESIGN-CONTRACT-R23"].update(status="readonly_implementation_contract_independent_source_review_accepted", independent_acceptance=True, independent_acceptance_scope="read-only typed implementation contract, tests0; no feature acceptance", functional_acceptance=False, independent_evidence=review_paths[0], checked_at=at)
rows["ASTRA-DESIGN-CONTRACT-REVIEW-R23"].update(status="completed_independent_contract_source_review_passed", artifact_available=True, source_review_passed=True, design_dispatch_ready=True, evidence=review_paths[0], finished_at=review["clock_observations"]["final_source_review_external_utc"], checked_at=at)
ledger["updated_at"] = at
write(HERE / "tasks.json", ledger)
print(json.dumps({"at": at, "contract_source_review_passed": True, "prepared_workers": 2, "readonly_inputs_each": 1069, "dispatched": False}), flush=True)
