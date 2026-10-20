"""Record actual R12 executions and prepare the coordinator-owned integration copy."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
follow = HERE / "followups-r12"
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
prepared = json.loads((follow / "prepared.json").read_text(encoding="utf-8"))
ledger_path = HERE / "tasks.json"
ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
existing = {row["id"]: row for row in ledger["tasks"]}
rows = []
for task in prepared["tasks"]:
    row = {key: value for key, value in task.items() if key != "message"}
    row.update(packages=["S01", "S08"] if task["agent"] == "kimi" else ["S01"] if task["agent"] == "zcode" else ["U01", "U02"],
        owner=task["agent"], requested_model=task["model"], write_paths=task["owns"], status="dispatched_execution_observed",
        checked_at=at, artifact_available=False, independent_acceptance=False, integrated=False, joint_verification=False, whole_package_complete=False,
        baseline_receipt=f"followups-r12/{task['workspace']}-baseline.json")
    if task["agent"] != "Astra":
        response_name = "bridge-response-" + task["workspace"] + ".json"
        dispatch = json.loads((HERE / "route-check" / response_name).read_text(encoding="utf-8"))
        assert dispatch["ok"] and dispatch["session_id"] == task["session_id"]
        public_files = sorted((HERE / "route-check").glob("bridge-response-r12-current-" + ("kimi" if task["agent"] == "kimi" else "zcode") + "-*.json"))
        public = json.loads(public_files[-1].read_text(encoding="utf-8"))
        assert public["status"] == "running" and public["task_id"] == dispatch["task_id"]
        row.update(bridge_task_id=dispatch["task_id"], bridge_session_id=dispatch["session_id"], accepted_model=dispatch["model"], observed_model=public.get("observed_model"), request_id=dispatch["request_id"], actual_execution_at=public["started_at"], dispatch_evidence="route-check/" + response_name, execution_evidence="route-check/" + public_files[-1].name)
    else:
        row.update(agent_kind="native_astra", native_agent_id="/root/astra_v3_editor_r6", actual_execution_at=at,
                   execution_evidence="followups-r12/astra-execution.json")
        (follow / "astra-execution.json").write_text(json.dumps({"at":at,"native_agent_id":row["native_agent_id"],"observed":"Native Astra message confirmed task/baseline/architecture/plans/source reads in new copy; identified owner pending_count=question count, investigating actual owner/UI.","independent_acceptance":False},ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    assert row["id"] not in existing
    rows.append(row)
ledger["tasks"].extend(rows)
left, done, layers = {row["id"] for row in ledger["tasks"]}, set(), []
while left:
    ready = [row["id"] for row in ledger["tasks"] if row["id"] in left and set(row["depends_on"]) <= done]
    assert ready
    layers.append(ready)
    left.difference_update(ready)
    done.update(ready)
ledger.update(topological_layers=layers, updated_at=at)
ledger_path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
status = {"at":at,"current_root_joint":"artifacts/coordinator-r11-all-intaken-20261015/review.json","root_unchanged_since_joint":True,"owner_pid":80748,"tasks":rows,
          "shared_blocker":"owner._finalize overwrites actual remaining with question count; coordinator owns fix. Full ScanSession and precise contracts not yet independently accepted.","reserved_s06":"human-confirmed archived; no API query/resume/dispatch"}
(follow / "status.json").write_text(json.dumps(status,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
note = f"""## {at} · R12 actual parallel execution

- Reused owner80748; preflight agents/sessions at02:05+08 found the two original sessions idle. No new service, duplicate worker or archived S06 operation.
- Kimi K3 `task_1cee9c8e9d` started02:09:21, new isolated scan-session-r12; ZCode GLM5.3 `task_315195c1a1` started02:09:21, contract-validation-r12. Public task status running and actual tool activity observed; final observed models pending. Native Astra `/root/astra_v3_editor_r6` confirmed actual source/UI audit in astra-queue-ux-r12. Three disjoint copies derive from the same R11 1002-file accepted snapshot; exact owned paths in followups-r12/*-baseline.json.
- These rows are dispatched/executing only: no R12 delivery, independent acceptance, intake or joint pass yet. Current root remains the R11 1123/six-command accepted bytes. Coordinator owns shared jobs owner/service, MCP projection, docs/locks and final integration.
- Actual blocker found: owner._finalize sets pending_count=len(questions), overwriting genuine scheduler remaining. Coordinator will repair only with current attempt/input bound queue evidence; business questions stay independent. Real project/model effects, formal/portable and conditional extensions remain separate.

---

"""
for name in ("PROGRESS.md", "DAG.md"):
    path = HERE / name
    path.write_text(note + path.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
source = json.loads((ROOT / "artifacts/coordinator-r11-all-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
workspace = ROOT / ".coordination/20261014/workspaces/coordinator-shared-r12"
workspace.mkdir(exist_ok=False)
for name, sha in source.items():
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == sha
    target = workspace / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / name, target)
ownership = {"captured_at":at,"workspace":str(workspace),"files":source,
    "owns":["zscope/orchestration/jobs/owner.py","zscope/mcp/jobs_adapter.py","zscope/web/scan_jobs_service.py","zscope/web/job_projection.py","tests/test_mcp_jobs.py","tests/test_scan_job_execution.py","tests/test_job_result_projection.py"]}
(follow / "coordinator-shared-baseline.json").write_text(json.dumps(ownership,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"executing":[r["id"] for r in rows],"coordinator_workspace":str(workspace)}))
