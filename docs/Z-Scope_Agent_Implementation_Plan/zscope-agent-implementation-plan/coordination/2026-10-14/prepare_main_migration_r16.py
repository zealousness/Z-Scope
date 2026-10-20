"""Stage coordinator-owned resume test migration without modifying root or producer."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
from audit_followup_r12 import audit, ROOT, HERE

producer=ROOT/".coordination/20261014/workspaces/scan-session-r12"
ownership=audit("scan-session-r12");assert not ownership["nonowned_changes"]
baseline=json.loads((HERE/"followups-r12/scan-session-r12-baseline.json").read_text(encoding="utf-8"))
deps=json.loads((HERE/"followups-r12/scan-session-r12-dependencies.json").read_text(encoding="utf-8"))
names=sorted({row["path"] for row in baseline["files"]}|{row["path"] for row in deps["files"]}|{row["path"] for row in ownership["changes"]})
before={name:hashlib.sha256((producer/name).read_bytes()).hexdigest() for name in names}
branch=ROOT/".coordination/20261014/workspaces/coordinator-main-migration-r16"
branch.mkdir(exist_ok=False)
for name in names:
    target=branch/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(producer/name,target)
assert all(hashlib.sha256((producer/name).read_bytes()).hexdigest()==sha for name,sha in before.items())
name="tests/test_scan_session_resume_svf.py"
assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==before[name]
p=branch/name;s=p.read_text(encoding="utf-8")
old='def test_resume_merges_duplicate_function_reports_by_entry_path(\n    tmp_path: Path, current_policy: bool, experiment: str\n) -> None:\n    cfg = _config(tmp_path)\n'
new='@pytest.mark.parametrize("language", ["c_cpp", "java"])\ndef test_resume_merges_duplicate_function_reports_by_entry_path(\n    tmp_path: Path, current_policy: bool, experiment: str, language: str, monkeypatch: pytest.MonkeyPatch\n) -> None:\n    cfg = _config(tmp_path)\n    cfg.project.language = language\n'
assert s.count(old)==1;s=s.replace(old,new)
needle='    runner = ScanSessionRunner(cfg, resume=True)\n    state = {\n        "entries_loaded": True,\n        "batch_mode": True,\n        "entries": list(entries),'
replacement='    runner = ScanSessionRunner(cfg, resume=True)\n    if language == "c_cpp":\n        def forbidden_name_resume(*args, **kwargs):\n            pytest.fail("C/C++ resume borrowed a name-only saved report")\n        monkeypatch.setattr(runner, "_load_current_saved_report", forbidden_name_resume)\n    state = {\n        "entries_loaded": True,\n        "batch_mode": True,\n        "entries": list(entries),'
assert s.count(needle)==1;s=s.replace(needle,replacement)
needle='    if not current_policy or experiment != "off":\n        assert state["entries"] == entries\n        assert state["results"] == {}\n'
replacement='    if language == "c_cpp" or not current_policy or experiment != "off":\n        assert state["entries"] == entries\n        assert state["skipped_entries"] == []\n        assert state["results"] == {}\n'
assert s.count(needle)==1;s=s.replace(needle,replacement)
p.write_text(s,encoding="utf-8",newline="\n")
receipt={"at":dt.datetime.now(dt.timezone.utc).isoformat(),"workspace":str(branch),"files":before,"producer_task_id":"task_2ba352c7a1","producer_owned_hashes":{row["path"]:row["after"] for row in ownership["changes"]},"coordinator_owned_paths":[name],"root_before":before[name],"scope":"Original10 cases retained for Java cache-routing unit behavior; add10C/C++ cases forbidding name-only saved-report reads under all policies/experiments. Actual native cold/single/batch/resume/owner coverage remains separate and required. Not a Java scanner effect claim.","integrated":False,"whole_package_complete":False}
(HERE/"followups-r12/coordinator-main-migration-r16-baseline.json").write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"workspace":str(branch),"inputs":len(before),"coordinator_owned_test":name}))
