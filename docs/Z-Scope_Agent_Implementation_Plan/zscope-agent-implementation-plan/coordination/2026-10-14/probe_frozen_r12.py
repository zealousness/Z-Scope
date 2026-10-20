"""Freeze visible owned bytes; probes are diagnostic, never intake acceptance."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from audit_followup_r12 import audit, ROOT, HERE

assert sys.platform == "linux"
kind, label = sys.argv[1:3]
name = {"contract":"contract-validation-r12","main":"scan-session-r12","checkpoint":"scan-checkpoint-r17","mcp":"mcp-findings-r12","job_cli_r20":"job-cli-window-r20","job_cli_authority_r20":"job-cli-window-r20"}[kind]
if kind=="checkpoint":
    name=next(row["workspace"] for row in json.loads((HERE/"tasks.json").read_text(encoding="utf-8"))["tasks"] if row["id"]=="SCAN-CHECKPOINT-R17")
producer = ROOT / ".coordination/20261014/workspaces" / name
branch = ROOT / ".coordination/20261014/workspaces" / ("coordinator-"+label)
out = ROOT / "artifacts" / label
ownership = audit(name)
assert not ownership["nonowned_changes"], ownership["nonowned_changes"]
baseline = json.loads((HERE/"followups-r12"/(name+"-baseline.json")).read_text(encoding="utf-8"))
names = sorted({row["path"] for row in baseline["files"]} | {row["path"] for row in ownership["changes"]})
dependency_path=HERE/"followups-r12"/(name+"-dependencies.json")
if dependency_path.exists():
    names=sorted(set(names)|{row["path"] for row in json.loads(dependency_path.read_text(encoding="utf-8"))["files"]})
def hashes(root):
    return {name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in names}
before = hashes(producer)
reuse_label = sys.argv[3] if len(sys.argv) > 3 else None
if reuse_label:
    previous = json.loads((ROOT/"artifacts"/reuse_label/"review.json").read_text(encoding="utf-8"))
    branch = ROOT / ".coordination/20261014/workspaces" / ("coordinator-"+reuse_label)
    assert hashes(branch) == before == previous["before"]
else:
    branch.mkdir(exist_ok=False)
out.mkdir(exist_ok=False)
if not reuse_label:
    for name in names:
        target = branch/name
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(producer/name,target)
assert hashes(branch) == before == hashes(producer), "producer changed while freezing"
(out/"launcher.py").write_bytes(Path(__file__).read_bytes())
probe_names = {
    "contract":["test_validation_thread_context.py","test_contract_usr_boundary.py","test_contract_protocol_usr_boundary.py","test_contract_omitted_usr_boundary.py","test_contract_context_receipt_boundary.py"],
    "main":["test_scan_session_native_boundary.py","test_scan_session_crash_resume.py","test_scan_session_queue_fencing.py","test_scan_session_deadline.py"],
    "checkpoint":["test_scan_checkpoint_authority_boundary.py", "test_scan_checkpoint_dependency_boundary.py"],
    "mcp":["test_mcp_findings_boundaries.py"],
    "job_cli_r20":["test_job_cli_effective_window_boundary.py", "test_job_cli_window_identity_boundary.py"],
    "job_cli_authority_r20":["test_job_cli_effective_window_boundary.py", "test_job_cli_window_snapshot_boundary.py", "test_job_cli_window_store_binding_boundary.py"],
}[kind]
probes=[]
for probe_name in probe_names:
    target = out/probe_name
    shutil.copyfile(HERE/"followups-r12"/probe_name,target)
    probes.append(str(target))
env=os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"]="/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
command=[sys.executable,str(HERE/"test_slot.py"),"--workspace",str(branch),"--",sys.executable,"-m","pytest","-q",*probes,"--junitxml="+str(out/"results.xml")]
started=dt.datetime.now(dt.timezone.utc).isoformat()
with (out/"command-0.log").open("w",encoding="utf-8") as log:
    result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
suite=ET.parse(out/"results.xml").getroot().find("testsuite")
after=hashes(branch)
proof={"kind":kind,"started_at":started,"finished_at":dt.datetime.now(dt.timezone.utc).isoformat(),"command":command,"returncode":result.returncode,"junit":suite.attrib,"original_ownership":ownership,"before":before,"after":after,"stable_frozen_inputs":before==after,"producer_current_matches_frozen":hashes(producer)==before,"probes":{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.glob("test_*.py")},"diagnostic_only":True,"independent_acceptance":False,"integrated":False,"whole_package_complete":False}
(out/"review.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({k:proof[k] for k in ("finished_at","returncode","junit","stable_frozen_inputs","producer_current_matches_frozen")}),flush=True)
sys.exit(result.returncode)
