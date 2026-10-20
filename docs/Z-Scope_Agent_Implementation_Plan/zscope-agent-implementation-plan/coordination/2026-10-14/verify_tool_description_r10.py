"""Compare the exact legacy-description failure on root and delivered bytes."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET

assert sys.platform=="linux"
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
out=ROOT/"artifacts/coordinator-tool-description-baseline-r10-20261015"
out.mkdir(exist_ok=False)
names=("zscope/tools/search_code.py","tests/test_function_info_tool.py")
baseline=json.loads((HERE/"followups-r10/s01-symbol-r10-baseline.json").read_text(encoding="utf-8"))
original={row["path"]:row["sha256"] for row in baseline["files"]}
proof={"started_at":dt.datetime.now(dt.timezone.utc).isoformat(),"cases":[]}
for label,workspace in (("root",ROOT),("s01",ROOT/".coordination/20261014/workspaces/s01-symbol-r10")):
    hashes={name:hashlib.sha256((workspace/name).read_bytes()).hexdigest() for name in names}
    assert all(hashes[name]==original[name] for name in names)
    command=[sys.executable,str(HERE/"test_slot.py"),"--workspace",str(workspace),"--",sys.executable,"-m","pytest","-q","tests/test_function_info_tool.py",f"--junitxml={out/(label+'.xml')}"]
    with (out/(label+".log")).open("w",encoding="utf-8") as stream:
        result=subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT)
    suite=ET.parse(out/(label+".xml")).getroot().find("testsuite")
    failures=[case.get("name") for case in suite.findall("testcase") if case.find("failure") is not None]
    proof["cases"].append({"label":label,"hashes":hashes,"returncode":result.returncode,"junit":suite.attrib,"failures":failures})
    print(json.dumps(proof["cases"][-1]),flush=True)
proof.update(finished_at=dt.datetime.now(dt.timezone.utc).isoformat(),
             preexisting=proof["cases"][0]["failures"]==proof["cases"][1]["failures"]==["test_legacy_function_info_remains_internal_while_runtime_uses_search"],
             conclusion="Same tool/test hashes as dispatch baseline; baseline and delivered whole file compared. No product behavior repaired by this probe.")
(out/"review.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
assert proof["preexisting"]
