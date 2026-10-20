"""Mark execution only from completed tools later than each R2 dispatch."""
from pathlib import Path
import datetime as dt
import json

HERE = Path(__file__).resolve().parent
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
receipts = {
    "S01-INST-EXEC": ("route-check/bridge-response-r6-public-1d98e649c1.json", "2026-10-14T13:35:46.673984+00:00"),
    "S08-SESSION-SCHEDULER": ("route-check/bridge-response-r6-public-b27f2b6b27.json", "2026-10-14T13:32:32.046785+00:00"),
}
for row in ledger["tasks"]:
    if row["id"] not in receipts:
        continue
    name, started = receipts[row["id"]]
    result = json.loads((HERE / name).read_text(encoding="utf-8"))
    events = [event for event in result["events"] if event.get("data", {}).get("status") == "completed"
              and dt.datetime.fromisoformat(event["ts"]) >= dt.datetime.fromisoformat(started)]
    assert events
    row.update(status="running_review2_actual_tool_observed", started_at=started,
               execution_evidence=name, actual_execution_at=events[0]["ts"],
               observed_model=None, independent_acceptance=False, integrated=False)
ledger["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
stage_path = HERE / "continuation-r6.json"
stage = json.loads(stage_path.read_text(encoding="utf-8"))
stage["next_task_rows"] = [row for row in ledger["tasks"] if row["id"] in {
    "S01-INST-EXEC", "S08-SESSION-SCHEDULER", "U01-ENTRYPOINTS", "ASTRA-V3-EDITOR"}]
stage["updated_at"] = ledger["updated_at"]
stage_path.write_text(json.dumps(stage, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"actual_execution_verified": list(receipts)}))
