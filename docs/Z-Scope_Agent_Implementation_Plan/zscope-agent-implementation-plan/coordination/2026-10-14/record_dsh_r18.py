"""Record public DSH dispatch and nonsecret route audit; never infer execution."""
from pathlib import Path
import datetime as dt
import json

HERE = Path(__file__).resolve().parent
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
route = HERE / "dsh-native"
result = json.loads((route / "bridge-response-doc-identity-r18.json").read_text(encoding="utf-8"))
assert result["ok"] and not result["reused"] and result["model"] == "deepseek/deepseek-v4.1-flash"
baseline = json.loads((HERE / "followups-r12/doc-identity-r18-baseline.json").read_text(encoding="utf-8"))
audit = {"recorded_at": at, "installation_version": "0.2.0-rc.2", "version_source": "app.asar/dsh/node_modules/@deepseek-ai/dsh-desktop-host/package.json", "provider": "deepseek", "model": result["model"], "entry_sha256": "c6c38be7f9f66a7bfb96d5ac9490618f9713df5ffb552cb7e66b831affb20ab9", "acp_sha256": "23259e019f6a7293ebb429654d7cc223414d3651d5be542968a81fc6265fc38b", "environment_reference_names": [], "root_cause": "Registered dedicated native owner exited; normal ZCode client deliberately requires --dsh-native for DSH. dsh-model=unset and cmd.exe version are not ACP configuration/version failures.", "external_configuration_changed": False, "credentials_copied": False, "normal_owner_restarted": False, "prior_native_tasks_terminal": True, "dedicated_owner_restoration": "dsh-native/r18-owner-restoration.json", "public_agents": "dsh-native/bridge-response-r18-public-agents.json", "public_sessions": "dsh-native/bridge-response-r18-public-sessions.json", "dispatch": "dsh-native/bridge-response-doc-identity-r18.json", "actual_execution": "pending public tool evidence"}
(HERE / "followups-r12/dsh-route-r18-audit.json").write_text(json.dumps(audit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
assert not any(r["id"] == "DOC-IDENTITY-R18" for r in ledger["tasks"])
ledger["tasks"].append({**baseline["task"], "agent": "dsh", "owner": "deepseek_harness", "bridge_task_id": result["task_id"], "bridge_session_id": result["session_id"], "accepted_model": result["model"], "observed_model": None, "request_id": result["request_id"], "dispatch_evidence": "dsh-native/bridge-response-doc-identity-r18.json", "baseline_receipt": "followups-r12/doc-identity-r18-baseline.json", "status": "dispatched_execution_pending", "actual_execution_at": None, "artifact_available": False, "independent_acceptance": False, "integrated": False, "joint_verification": False, "whole_package_complete": False, "checked_at": at})
ledger["updated_at"] = at
ledger["current_worker_policy"]["simple_deterministic_work"] = "Verified bundled DSH 0.2.0-rc.2, deepseek/deepseek-v4.1-flash; DOC-IDENTITY-R18 accepted task_b579d5cd4e"
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
for request_route, identity, tool, arguments in ((route, "r18-doc-first", "check_task", {"task_id": result["task_id"]}), (HERE / "route-check", "r18-inner-toolcalls-count", "get_transcript", {"session_id": "sess_a0adb99b15", "kinds": "tool_call", "offset": 0, "limit": 20})):
    target = request_route / "bridge-queue" / ("080-" + identity + ".request.json")
    assert not target.exists()
    target.write_text(json.dumps({"id": identity, "tool": tool, "arguments": arguments}) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"task_id": result["task_id"], "dispatch_recorded": True, "execution_pending": True, "at": at}))
