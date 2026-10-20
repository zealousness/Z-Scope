"""Record first observed real tools and current disjoint ownership status."""
from pathlib import Path
import datetime as dt
import json
from uuid import uuid4

HERE = Path(__file__).resolve().parent
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
rows = {r["id"]: r for r in ledger["tasks"]}
specs = [("DOC-IDENTITY-R18", "dsh-native/bridge-response-r18-doc-first-source-page.json", "2026-10-15T09:36:26"), ("VALIDATION-CONTEXT-R18", "route-check/bridge-response-r18-inner-source-tools.json", "2026-10-15T09:23:59"), ("U01-STOP-AT-R18", "route-check/bridge-response-r18-tools-stop-first.json", "2026-10-15T09:23:58")]
for identity, receipt, lower in specs:
    events = json.loads((HERE / receipt).read_text(encoding="utf-8"))["events"]
    tools = [e for e in events if e["type"] == "tool_call" and str(e.get("ts", "")) >= lower and not str(e.get("data", {}).get("title", "")).startswith("TodoWrite")]
    assert tools
    first = min(tools, key=lambda e: e["ts"])
    rows[identity].update(status="actual_execution_in_progress", actual_execution_at=first["ts"], actual_execution_evidence=receipt, actual_execution_note="Earliest actual tool visible in this saved page; not claimed to be the first tool of the entire session.", checked_at=at)
astra = rows["ASTRA-INSTANCE-UI-R18"]
astra.update(status="delivered_independent_acceptance_running", producer_finished_at="2026-10-15T09:37:23.3839689Z", artifact_available=True, delivery_evidence=".coordination/20261014/workspaces/astra-instance-ui-r18/artifacts/instance-ui-r18/DELIVERY.json", independent_acceptance=False, integrated=False, joint_verification=False, checked_at=at)
rows["CURRENT-JOINT-R17"].update(status="current_root_joint_running_failures_observed", preliminary_failures_observed=2, quality_checks="pending full collection", whole_package_complete=False, checked_at=at)
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
note = f"""## {at} · R18 real execution / R17 current joint pending

- DSH task_b579d5cd4e accepted deepseek/deepseek-v4.1-flash, started17:36:26; actual pwsh tool17:36:36 recorded in dsh-native/bridge-response-r18-doc-first-source-page.json. Bundled0.2.0-rc.2/ACP hash verified; native owner restored only after terminal tasks and absent prior owner/worker; normal80748 untouched. No config/credential/provider change.
- ZCode task_cb7011476d actual source tool17:27:15 saved (earlier current-turn source reads not yet paged); task_5b722e514f actual directory tool17:24:31. Both isolated, no observed outside ownership change at17:40.
- Astra /root/astra_instance_ui_r18 delivered17:37:23; actual native dual macro→ScanSession→owner→SQLite→HTTP→desktop/mobile self-check passed, independent acceptance now running. Four owned files; coordinator services.py readonly dependency77/0+fourquality0.
- R17 accepted batch29files intaken; current full joint ongoing with two failures already observed. Do not claim current pass or substitute historical R16 1207. Full collection continues before diagnosis/repair. Frozen current source, separate workspace coding remains parallel.
- ContractR5 independent1016, MainR3 independent423, checkpointZCodeR18 independent441 are different collections, not added. Whole-plan recovery remains bounded; full S01/S08/U01, real-project/model effect and conditional S10/Q remain open/separate.

---

"""
for filename in ("PROGRESS.md", "DAG.md"):
    p = HERE / filename
    p.write_text(note + p.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
for identity, route in (("VALIDATION-CONTEXT-R18", "route-check"), ("U01-STOP-AT-R18", "route-check"), ("DOC-IDENTITY-R18", "dsh-native")):
    label = "r18-progress-" + uuid4().hex[:10]
    target = HERE / route / "bridge-queue" / ("080-" + label + ".request.json")
    target.write_text(json.dumps({"id": label, "tool": "check_task", "arguments": {"task_id": rows[identity]["bridge_task_id"]}}) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"recorded_at": at, "real_tools_recorded": 3, "current_joint_passed": False}))
