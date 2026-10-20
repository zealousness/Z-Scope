"""Frozen coordinator source-root repair, native consumers and Linux quality."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

assert sys.platform=="linux"
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
branch=ROOT/".coordination/20261014/workspaces/coordinator-shared-r13"
out=ROOT/"artifacts"/sys.argv[1]
out.mkdir(exist_ok=False)
(out/"launcher.py").write_bytes(Path(__file__).read_bytes())
baseline=json.loads((HERE/"followups-r12/coordinator-shared-r13-baseline.json").read_text(encoding="utf-8"))
names=set(baseline["files"]) | {"tests/test_native_source_roots.py"}
def hashes():
    return {p:hashlib.sha256((branch/p).read_bytes()).hexdigest() for p in sorted(names)}
before=hashes()
changed={p:sha for p,sha in before.items() if baseline["files"].get(p)!=sha}
assert set(changed)<={"zscope/retrieval/code_index.py","tests/test_native_source_roots.py"}
for p in changed:
    target=out/"source-before"/p
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes((branch/p).read_bytes())
tests=["test_native_source_roots","test_instance_analysis","test_entry_instance_coverage","test_all_variant_scan","test_build_context","test_candidate_build_identity","test_native_model_cache","test_native_wrapper_inference","test_resource_inference_coverage","test_link_targets","test_linked_lifecycle_paths","test_contract_build_scope","test_protocol_incremental_equivalence"]
probes=[str(HERE/"followups-r6"/name) for name in ("test_instance_consumer_guard.py","test_instance_navigation_consumers.py","test_instance_validation_scope.py","test_instance_native_body.py")]+[str(HERE/"followups-r10/test_symbol_consumer_receipts.py")]
commands=[
    [sys.executable,"-m","pytest","-q",*["tests/"+t+".py" for t in tests],*probes,"--junitxml="+str(out/"results.xml")],
    [sys.executable,"-m","compileall","-f","-q","zscope","scripts","test","tests"],
    [sys.executable,"-m","mypy","zscope"],
    [sys.executable,"-m","black","--check",*sorted(changed)],
]
env=os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"]="/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
results=[]
for i,command in enumerate(commands):
    at=dt.datetime.now(dt.timezone.utc).isoformat()
    with (out/f"command-{i}.log").open("w",encoding="utf-8") as log:
        result=subprocess.run([sys.executable,str(HERE/"test_slot.py"),"--workspace",str(branch),"--",*command],env=env,stdout=log,stderr=subprocess.STDOUT)
    results.append({"command":command,"returncode":result.returncode,"started_at":at,"finished_at":dt.datetime.now(dt.timezone.utc).isoformat(),"log":str((out/f"command-{i}.log").relative_to(ROOT))})
    print(json.dumps(results[-1]),flush=True)
    if result.returncode:
        break
suite=ET.parse(out/"results.xml").getroot().find("testsuite")
after=hashes()
passed=len(results)==4 and all(r["returncode"]==0 for r in results) and before==after and all(suite.get(k)=="0" for k in ("failures","errors","skipped"))
proof={"at":dt.datetime.now(dt.timezone.utc).isoformat(),"junit":suite.attrib,"commands":results,"before_all_inputs":before,"after_all_inputs":after,"source_unchanged":before==after,"changed_files":changed,"passed":passed,"integrated":False,"whole_package_complete":False,"coordinator_authored":True,"scope":"Actual native source-root/project-root path resolution, exact compile identity, ALT-only double_free, existing scoped consumers. Controlled no external model; not full project/formal/portable acceptance."}
(out/"review.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"passed":passed,"junit":suite.attrib,"receipt":str(out/"review.json")}))
sys.exit(0 if passed else 1)
