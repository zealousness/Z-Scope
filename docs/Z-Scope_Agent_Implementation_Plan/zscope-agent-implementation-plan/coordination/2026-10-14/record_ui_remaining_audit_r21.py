"""Record a read-only UI preparation task with no product write ownership."""
from pathlib import Path
import datetime as dt
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
rows = {r["id"]: r for r in ledger["tasks"]}
identity = "ASTRA-UX-REMAINING-AUDIT-R21"
assert identity not in rows
assert rows["ASTRA-INSTANCE-UI-R18"]["independent_acceptance"] and rows["ASTRA-INSTANCE-UI-R18"]["integrated"]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
row = {"id": identity, "owner": "Astra", "agent_kind": "native_subagent", "agent_task_id": "/root/astra_instance_ui_r18", "depends_on": ["ASTRA-INSTANCE-UI-R18", "CURRENT-JOINT-R19"], "scope": "Read-only preparation: current UI capability/coverage/config claims, preserve accepted R18 and historical synthetic boundaries; no development or repeated scan", "write_paths": ["artifacts/astra-ux-remaining-audit-r21-20261015/**"], "owns": ["artifacts/astra-ux-remaining-audit-r21-20261015/**"], "status": "readonly_audit_dispatched_actual_execution_pending", "producer_status": "dispatched", "artifact_available": False, "independent_acceptance": False, "integrated": False, "joint_verification": False, "whole_package_complete": False, "product_write_permission": False, "development_requires": "CURRENT-JOINT-R20 pass and stable backend contract plus explicit exclusive ownership", "checked_at": at}
ledger["tasks"].append(row)
rows[identity] = row
pending, done, layers = set(rows), set(), []
while pending:
    ready = sorted(p for p in pending if set(rows[p].get("depends_on", [])) <= done)
    assert ready
    layers.append(ready)
    done.update(ready)
    pending.difference_update(ready)
ledger.update(updated_at=at, topological_layers=layers)
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
note = f"## {at} · R21 UI read-only preparation in parallel with strict verification\n\nAstra /root/astra_instance_ui_r18 reused for new logical ASTRA-UX-REMAINING-AUDIT-R21, dispatched read-only current UI/config/coverage contract audit; only artifacts/astra-ux-remaining-audit-r21-20261015/** writable. No product/old test/static lock/service/browser/native scan change, no repeated R18 development. Actual audit execution not yet observed. Development still requires current R20 full Root union pass and stable backend contracts. Existing R18 and97 synthetic boundaries retained. DAG {len(rows)} nodes/{len(layers)} layers valid. Current SQL producer frozen, coordinator final-byte full independent run active; Root not intaken.\n\n---\n\n"
for filename in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R20.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "logical_task": identity, "native_task": row["agent_task_id"], "nodes": len(rows), "layers": len(layers)}), flush=True)
