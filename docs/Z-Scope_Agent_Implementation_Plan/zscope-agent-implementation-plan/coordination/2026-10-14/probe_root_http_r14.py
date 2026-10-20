"""Repeat the unchanged HTTP file after an observed TCP-connect timeout."""
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
out=ROOT/"artifacts/root-r14-http-file-probes-20261015"
out.mkdir(exist_ok=False)
(out/"launcher.py").write_bytes(Path(__file__).read_bytes())
source=json.loads((ROOT/"artifacts/coordinator-r14-source-roots-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
def hashes():
    return {p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in source}
before=hashes()
assert before==source
results=[]
for i in range(3):
    command=[sys.executable,str(HERE/"test_slot.py"),"--workspace",str(ROOT),"--",sys.executable,"-m","pytest","-q","tests/test_agent_integration_boundaries.py","--junitxml="+str(out/f"results-{i}.xml")]
    at=dt.datetime.now(dt.timezone.utc).isoformat()
    with (out/f"command-{i}.log").open("w",encoding="utf-8") as log:
        result=subprocess.run(command,env=os.environ.copy(),stdout=log,stderr=subprocess.STDOUT)
    suite=ET.parse(out/f"results-{i}.xml").getroot().find("testsuite")
    results.append({"started_at":at,"finished_at":dt.datetime.now(dt.timezone.utc).isoformat(),"command":command,"returncode":result.returncode,"junit":suite.attrib})
    print(json.dumps(results[-1]),flush=True)
    if result.returncode:
        break
after=hashes()
proof={"at":dt.datetime.now(dt.timezone.utc).isoformat(),"before":before,"after":after,"source_unchanged":before==after,"results":results,"previous_failure":"artifacts/coordinator-r14-source-roots-intaken-20261015/command-0.log","observed_failure":"TCP connect to local HTTP endpoint timed out at socket.connect, after six successful detail replies; not pytest capture or a test assertion on scan effects.","test_timeouts_unchanged":True,"pytest_capture":"fd default, ext4 TMPDIR via test_slot","current_joint_verification":False,"scope":"Diagnostic repeats of the unchanged real HTTP/SQLite/owner test file with controlled scanner/report. Does not replace current complete joint collection."}
(out/"review.json").write_text(json.dumps(proof,indent=2)+"\n",encoding="utf-8",newline="\n")
sys.exit(0 if len(results)==3 and before==after and all(r["returncode"]==0 for r in results) else 1)
