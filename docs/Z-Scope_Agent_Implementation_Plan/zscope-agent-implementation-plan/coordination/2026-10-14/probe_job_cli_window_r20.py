"""Probe additional real job-to-CLI window consumption on frozen current root."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

assert sys.platform=="linux"
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
expected=json.loads((ROOT/"artifacts/coordinator-r18-same-bytes-clock-observed-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
for row in json.loads((ROOT/"artifacts/intake-batch-r19-20261015/receipt.json").read_text(encoding="utf-8"))["files"]:expected[row["path"]]=row["after"]
def hashes():return {p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in expected}
before=hashes()
assert before==expected
out=ROOT/"artifacts"/(sys.argv[1] if len(sys.argv)>1 else "coordinator-current-job-cli-window-r20-probes-20261015")
out.mkdir(exist_ok=False)
original=HERE/"followups-r12/test_job_cli_effective_window_boundary.py"
probe=out/original.name
shutil.copyfile(original,probe)
sha=hashlib.sha256(probe.read_bytes()).hexdigest()
probes = [probe]
extra_sha = None
if "--identity" in sys.argv[2:]:
    extra_original = HERE / "followups-r12/test_job_cli_window_identity_boundary.py"
    extra = out / extra_original.name
    shutil.copyfile(extra_original, extra)
    extra_sha = hashlib.sha256(extra.read_bytes()).hexdigest()
    probes.append(extra)
command=[sys.executable,str(HERE/"test_slot.py"),"--workspace",str(ROOT),"--",sys.executable,"-m","pytest","-q",*[str(p) for p in probes],"--junitxml="+str(out/"results.xml")]
started=dt.datetime.now(dt.timezone.utc).isoformat()
with (out/"command-0.log").open("w",encoding="utf-8") as log:result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
suite=ET.parse(out/"results.xml").getroot().find("testsuite")
assert suite is not None
after=hashes()
stable=before==after and hashlib.sha256(original.read_bytes()).hexdigest()==sha==hashlib.sha256(probe.read_bytes()).hexdigest()
if extra_sha is not None:
    stable = stable and hashlib.sha256(extra_original.read_bytes()).hexdigest() == extra_sha == hashlib.sha256(extra.read_bytes()).hexdigest()
proof={"started_at":started,"finished_at":dt.datetime.now(dt.timezone.utc).isoformat(),"returncode":result.returncode,"junit":dict(suite.attrib),"before":before,"after":after,"source_unchanged":stable,"probe_sha256":sha,"passed":stable and result.returncode==0 and all(suite.get(k)=="0" for k in ("errors","failures","skipped")),"scope":"Additional real persistent service/owner/CLI/actual ScanSessionRunner shared-token consumers, controlling only analysis body. Explicit-request vs config and resumed-attempt window consumption, not real-project/model effect or redo of the accepted3 slices."}
(out/"review.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({k:proof[k] for k in ("finished_at","returncode","junit","source_unchanged","passed")}),flush=True)
sys.exit(0 if proof["passed"] else 1)
