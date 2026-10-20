"""Independent full native hot-baseline intake gate, including retained regressions."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from audit_followup_r12 import HERE, ROOT, audit

assert sys.platform == "linux"
name = "native-hot-cache-r19"
workspace = ROOT / ".coordination/20261014/workspaces" / name
ownership = audit(name)
assert not ownership["nonowned_changes"]
baseline = json.loads((HERE / "followups-r12" / (name+"-baseline.json")).read_text(encoding="utf-8"))
names = {r["path"] for r in baseline["files"]} | {r["path"] for r in ownership["changes"]}
def hashes():
    return {p:hashlib.sha256((workspace/p).read_bytes()).hexdigest() for p in sorted(names)}
before = hashes()
out = ROOT / "artifacts/coordinator-native-hot-r19-final-acceptance-20261015"
out.mkdir(exist_ok=False)
delivered = {r["path"]:r["after"] for r in ownership["changes"]}
for p, sha in delivered.items():
    target=out/"source-before"/p
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes((workspace/p).read_bytes())
    assert hashlib.sha256(target.read_bytes()).hexdigest()==sha
original=HERE/"followups-r12/test_native_hot_process_boundary.py"
probe=out/original.name
shutil.copyfile(original,probe)
probe_sha=hashlib.sha256(probe.read_bytes()).hexdigest()
native=Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
native_sha=hashlib.sha256(native.read_bytes()).hexdigest()
assert native_sha=="d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
tests=["test_clang_batch","test_clang_batch_arguments","test_clang_batch_logging","test_clang_identity_validation","test_clang_cache_pressure","test_build_context","test_code_index_cache","test_incremental_replay","test_native_replay_hot_cache","test_protocol_incremental_equivalence","test_native_model_cache","test_candidate_build_identity"]
env=dict(os.environ,Z_SCOPE_TEST_CLANG_INDEXER=str(native),ZSCOPE_NATIVE_PROCESS_EVIDENCE=str(out/"native-processes"))
commands=[[sys.executable,"-m","pytest","-q",*["tests/"+p+".py" for p in tests],str(probe),"--junitxml="+str(out/"results.xml")],[sys.executable,"-m","compileall","-f","-q","zscope","scripts","test","tests"],[sys.executable,"-m","mypy","zscope"],[sys.executable,"-m","black","--check","tests/test_native_replay_hot_cache.py","tests/test_incremental_replay.py"]]
results=[]
for i,command in enumerate(commands):
    started=dt.datetime.now(dt.timezone.utc).isoformat()
    with (out/f"command-{i}.log").open("w",encoding="utf-8") as log:
        result=subprocess.run([sys.executable,str(HERE/"test_slot.py"),"--workspace",str(workspace),"--",*command],env=env,stdout=log,stderr=subprocess.STDOUT)
    results.append({"command":command,"returncode":result.returncode,"started_at":started,"finished_at":dt.datetime.now(dt.timezone.utc).isoformat()})
    print(json.dumps({"command_index":i,"returncode":result.returncode,"finished_at":results[-1]["finished_at"]}),flush=True)
    if result.returncode:break
suite=ET.parse(out/"results.xml").getroot().find("testsuite")
assert suite is not None
after=hashes()
final=audit(name)
stable=before==after and not final["nonowned_changes"] and hashlib.sha256(native.read_bytes()).hexdigest()==native_sha and hashlib.sha256(original.read_bytes()).hexdigest()==probe_sha==hashlib.sha256(probe.read_bytes()).hexdigest()
accepted=stable and len(results)==4 and all(r["returncode"]==0 for r in results) and all(suite.get(k)=="0" for k in ("errors","failures","skipped"))
proof={"task_id":"task_7118aeca55","finished_at":dt.datetime.now(dt.timezone.utc).isoformat(),"junit":dict(suite.attrib),"commands":results,"ownership":ownership,"after_ownership":final,"before_all_inputs":before,"after_all_inputs":after,"source_unchanged":stable,"delivered_hashes":delivered,"native_sha256":native_sha,"probe_sha256":probe_sha,"independent_acceptance_passed":accepted,"coordinator_readonly_migration":"followups-r12/native-hot-cache-r19-dependencies.json","integrated":False,"whole_package_complete":False,"scope":"Retains producer108-regression and all8-mutation replay/new6, adds native model/identity/protocol neighbors plus actual extraction process/premise-flip checks. Version and ldd provenance queries are recorded separately; no all-native-process-zero claim. Navigation projection/full S01/S07/real project/model/formal/portable remain unaccepted."}
(out/"review.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"accepted":accepted,"junit":proof["junit"],"finished_at":proof["finished_at"]}),flush=True)
sys.exit(0 if accepted else 1)
