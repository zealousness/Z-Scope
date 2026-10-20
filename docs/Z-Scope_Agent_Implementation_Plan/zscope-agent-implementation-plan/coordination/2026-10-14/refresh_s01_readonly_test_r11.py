"""Refresh one coordinator-repaired read-only test only after producer stop."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
response=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert response["task_id"]=="task_0afb819799" and response["status"]=="completed"
branch=ROOT/".coordination/20261014/workspaces/s01-symbol-r10"
baseline=json.loads((HERE/"followups-r10/s01-symbol-r10-baseline.json").read_text(encoding="utf-8"))
original={row["path"]:row["sha256"] for row in baseline["files"]}
name="tests/test_function_info_tool.py"
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(branch/name)==original[name]
out=ROOT/"artifacts/coordinator-s01-readonly-dependency-refresh-r11-20261015"
out.mkdir(exist_ok=False)
(out/"before-test_function_info_tool.py").write_bytes((branch/name).read_bytes())
(branch/name).write_bytes((ROOT/name).read_bytes())
proof={"at":dt.datetime.now(dt.timezone.utc).isoformat(),"author":"coordinator",
       "reason":"Same preexisting tool-description failure proven on dispatch baseline; root synchronized test and stronger no-body check passed50, then complete current root776. Producer source unchanged; independent full suite will include this file.",
       "root_evidence":"artifacts/coordinator-r11-astra-intaken-20261015/review.json",
       "files":[{"path":name,"previous_sha256":original[name],"sha256":sha(branch/name)}]}
(HERE/"followups-r10/s01-symbol-r10-dependencies.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
(out/"receipt.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(proof))
