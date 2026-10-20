"""Observe failed producer JUnit; do not claim it tested today's exact bytes."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import xml.etree.ElementTree as ET
from audit_followup_r12 import audit, ROOT, HERE

workspace=ROOT/".coordination/20261014/workspaces/contract-validation-r12"
ownership=audit("contract-validation-r12")
assert not ownership["nonowned_changes"]
baseline=json.loads((HERE/"followups-r12/contract-validation-r12-baseline.json").read_text(encoding="utf-8"))
names={r["path"] for r in baseline["files"]}|{r["path"] for r in ownership["changes"]}
def hashes():
    return {p:hashlib.sha256((workspace/p).read_bytes()).hexdigest() for p in sorted(names)}
before=hashes()
source=workspace/"artifacts/contract-validation-r12/results-contract-validation-r12-repair.xml"
suite=ET.parse(source).getroot().find("testsuite")
assert suite.get("failures")=="5" and suite.get("tests")=="892"
out=ROOT/"artifacts/coordinator-contract-r12-producer-regression-observation-20261015"
out.mkdir(exist_ok=False)
shutil.copyfile(source,out/"producer-results.xml")
after=hashes()
assert before==after
proof={"at":dt.datetime.now(dt.timezone.utc).isoformat(),"returncode":1,"junit":suite.attrib,"producer_receipt":str(source.relative_to(ROOT)).replace("\\","/"),"producer_receipt_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),"before":before,"after":after,"stable_frozen_inputs":True,"source_binding":"Current bytes are frozen for investigation; producer JUnit may precede formatting. Exact-byte independent revalidation pending; not an independently executed test receipt.","independent_acceptance":False,"integrated":False,"whole_package_complete":False}
(out/"review.json").write_text(json.dumps(proof,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"junit":suite.attrib,"receipt":str(out/"review.json"),"independent_execution":False}))
