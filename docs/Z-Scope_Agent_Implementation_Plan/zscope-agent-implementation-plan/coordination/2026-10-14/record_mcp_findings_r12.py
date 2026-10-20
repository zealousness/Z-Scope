"""Record the distinct running MCP consumer and the accepted Astra intake."""
from pathlib import Path
import datetime as dt
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
follow = HERE / "followups-r12"
baseline = json.loads((follow / "mcp-findings-r12-baseline.json").read_text(encoding="utf-8"))
task = baseline["task"]
dispatch = json.loads((HERE / "route-check/bridge-response-mcp-findings-r12.json").read_text(encoding="utf-8"))
public_path = max((HERE / "route-check").glob("bridge-response-r12-current-mcp-*.json"), key=lambda p:p.stat().st_mtime_ns)
public = json.loads(public_path.read_text(encoding="utf-8"))
assert dispatch["ok"] and public["status"] == "running" and public["task_id"] == dispatch["task_id"]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
row = {key:value for key,value in task.items() if key != "message"}
row.update(title="Bound persistent-job findings projection for MCP",packages=["U01","U02"],owner=task["agent"],requested_model=task["model"],write_paths=task["owns"],status="dispatched_execution_observed",bridge_task_id=dispatch["task_id"],bridge_session_id=dispatch["session_id"],accepted_model=dispatch["model"],observed_model=public.get("observed_model"),request_id=dispatch["request_id"],actual_execution_at=public["started_at"],dispatch_evidence="route-check/bridge-response-mcp-findings-r12.json",execution_evidence="route-check/" + public_path.name,baseline_receipt="followups-r12/mcp-findings-r12-baseline.json",checked_at=at,artifact_available=False,independent_acceptance=False,integrated=False,joint_verification=False,whole_package_complete=False)
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
assert row["id"] not in {r["id"] for r in ledger["tasks"]}
ledger["tasks"].append(row)
ledger["updated_at"] = at
left, done, layers = {r["id"] for r in ledger["tasks"]}, set(), []
while left:
    ready = [r["id"] for r in ledger["tasks"] if r["id"] in left and set(r["depends_on"]) <= done]
    assert ready
    layers.append(ready); left.difference_update(ready); done.update(ready)
ledger["topological_layers"] = layers
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
(follow / "mcp-findings-status.json").write_text(json.dumps(row,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
note = f"""## {at} · Astra R12 intaken; MCP projection executing

- Astra title repair independently88/0fail/error/skip and compileall/mypy353/Black passed02:32:23 with stable1002 inputs; independent screenshot verified completed/exited neutral heading and unknown remaining/questions1. Three files intaken02:33:46, lock only HTML/JS SHA changed. Receipt artifacts/intake-astra-queue-ux-r12-20261015/receipt.json; independent artifacts/coordinator-astra-r12-title-acceptance-20261015/review.json. Initial88 checks passed but visual hold retained separately, then repaired and reverified. Current same-root joint is running at artifacts/coordinator-r13-astra-intaken-20261015; preceding1132 was before Astra intake and is historical.
- Fresh original-owner inventory confirmed S08 ZCode session idle. Distinct MCP-FINDINGS-R12 task_a3a56d31b4 started02:33:00, pinned GLM5.3, actual public tool activity observed. New disjoint mcp-findings-r12 copy has1003 inputs from accepted1132 root snapshot; exact paths followups-r12/mcp-findings-r12-baseline.json. No repeat of completed MCP persistent-job task; this addresses still-None findings only. Dispatched/executing, no accepted delivery/intake/joint claim.
- Kimi task_1cee9c8e9d and contract ZCode task_315195c1a1 continue their original isolated tasks. Shared Web/service/docs/lock integration remains coordinator-owned. No new Bridge service, model transfer, old S06 action or conditional extension.

---

"""
for name in ("PROGRESS.md","DAG.md"):
    target = HERE / name
    target.write_text(note + target.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
print(json.dumps({"recorded":row["bridge_task_id"],"started_at":row["actual_execution_at"],"astra_intaken":True,"current_joint_pending":True}))
