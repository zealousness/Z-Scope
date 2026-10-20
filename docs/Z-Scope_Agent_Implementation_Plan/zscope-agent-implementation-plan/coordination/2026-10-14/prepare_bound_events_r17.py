"""Stage shared persistent completion APIs from the current verified R16."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
source=json.loads((ROOT/"artifacts/coordinator-r16-astra-projection-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
branch=ROOT/".coordination/20261014/workspaces/coordinator-bound-events-r17"
branch.mkdir(exist_ok=False)
for name,sha in source.items():
    assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha
    p=branch/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,p)
receipt={"at":dt.datetime.now(dt.timezone.utc).isoformat(),"files":source,"workspace":str(branch),"owns":["zscope/orchestration/jobs/store.py","tests/test_job_bound_completion.py"],"dependency":"CURRENT-JOINT-R16","integrated":False,"whole_package_complete":False}
(HERE/"followups-r12/coordinator-bound-events-r17-baseline.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8",newline="\n")
print(branch)
