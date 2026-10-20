"""Coordinator-owned shared integration, from the accepted R13 source set."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
source=json.loads((ROOT/"artifacts/coordinator-r13-astra-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
branch=ROOT/".coordination/20261014/workspaces/coordinator-shared-r13"
branch.mkdir(exist_ok=False)
for name,sha in source.items():
    assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha,name
    target=branch/name
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(ROOT/name,target)
(HERE/"followups-r12/coordinator-shared-r13-baseline.json").write_text(json.dumps({"at":dt.datetime.now(dt.timezone.utc).isoformat(),"files":source,"workspace":str(branch),"owns":["zscope/retrieval/code_index.py","zscope/orchestration/jobs/owner.py","zscope/orchestration/jobs/store.py","tests/test_job_remaining.py","tests/test_native_source_roots.py"],"intaken":False},indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"prepared":str(branch),"inputs":len(source),"intaken":False}))
