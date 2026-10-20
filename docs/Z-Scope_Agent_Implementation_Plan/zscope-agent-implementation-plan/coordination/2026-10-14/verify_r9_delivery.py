"""Independently verify a stable R3 producer through Linux tests and quality."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from audit_followup_r6 import audit

assert sys.platform=="linux"
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
kind=sys.argv[1]
assert kind in {"s01","s08"}
workspace="s01-analysis-r6" if kind=="s01" else "s08-session-r6"
branch=ROOT/".coordination/20261014/workspaces"/workspace
out=ROOT/"artifacts"/(sys.argv[2] if len(sys.argv)>2 else f"coordinator-{kind}-r3-acceptance-20261014")
out.mkdir(exist_ok=False)
ownership=audit(workspace)
assert ownership["safe_to_review"] and ownership["delivery_exists"],ownership
files={row["path"]:row["after"] for row in ownership["changes"]}
def hashes():
    return {name:hashlib.sha256((branch/name).read_bytes()).hexdigest() for name in files}
assert hashes()==files
for name, expected in files.items():
    snapshot = out / "source-before" / name
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_bytes((branch / name).read_bytes())
    assert hashlib.sha256(snapshot.read_bytes()).hexdigest() == expected
if kind=="s01":
    tests=["test_all_variant_scan","test_build_context","test_candidate_build_identity","test_candidate_ledger",
           "test_incremental_semantic_modeling","test_instance_analysis","test_lifecycle_paths","test_native_model_cache",
           "test_parallel_entry_budget","test_parallel_shared_semantics","test_protocol_incremental_equivalence",
           "test_report_assembler","test_retained_slot_teardown","test_scan_session_resume_svf","test_validation_runner"]
    probes=["test_instance_consumer_guard.py","test_instance_navigation_consumers.py","test_instance_validation_scope.py","test_instance_native_body.py"]
    black=["zscope/retrieval/instance_index.py","zscope/orchestration/entry_instances.py","tests/test_instance_analysis.py"]
else:
    tests=["test_job_session_scheduler","test_scan_job_execution","test_scan_job_work_queue","test_scan_jobs","test_scan_jobs_http_api"]
    probes=["test_scheduler_guard_probes.py","test_scheduler_discovery_durability.py","test_scheduler_settlement_edges.py"]
    black=[name for name in files if name.endswith(".py")]
env=os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"]="/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
commands=[
    [sys.executable,"-m","pytest","-q",*[f"tests/{name}.py" for name in tests],
     *[str(HERE/"followups-r6"/name) for name in probes],f"--junitxml={out/'results.xml'}"],
    [sys.executable,"-m","compileall","-f","-q","zscope","scripts","test","tests"],
    [sys.executable,"-m","mypy","zscope"],
    [sys.executable,"-m","black","--check",*black],
]
started=dt.datetime.now(dt.timezone.utc).isoformat()
results=[]
for index,command in enumerate(commands):
    wrapped=[sys.executable,str(HERE/"test_slot.py"),"--workspace",str(branch),"--",*command]
    log_path=out/f"command-{index}.log"
    with log_path.open("w",encoding="utf-8") as log:
        result=subprocess.run(wrapped,env=env,stdout=log,stderr=subprocess.STDOUT)
    results.append({"command":command,"returncode":result.returncode,"log":str(log_path.relative_to(ROOT))})
    print(json.dumps(results[-1]),flush=True)
    if result.returncode:
        break
suite=ET.parse(out/"results.xml").getroot().find("testsuite")
assert suite is not None
after=hashes()
accepted=len(results)==4 and all(row["returncode"]==0 for row in results) and after==files and all(suite.get(key)=="0" for key in ("failures","errors","skipped"))
proof={"task_id":"task_6e14411a6c" if kind=="s01" else "task_a110e5866a","started_at":started,
       "finished_at":dt.datetime.now(dt.timezone.utc).isoformat(),"junit":suite.attrib,"commands":results,"ownership":ownership,
       "delivered_hashes":files,"after_hashes":after,"source_unchanged":after==files,"independent_acceptance_passed":accepted,
       "source_snapshot":str(out/"source-before"),
       "integrated":False,"whole_package_complete":False,
       "scope":"S01 actual native instance/candidate/shared validation plus synthetic rejection boundaries; S08 real SQLite/owner/controlled callbacks. No actual LLM/full ScanSession queue integration, formal or portable smoke."}
(out/"review.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"accepted":accepted,"junit":suite.attrib,"receipt":str(out/"review.json")}))
sys.exit(0 if accepted else 1)
