"""Install only the independently prepared readonly test migration after producer quiescence."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
name="tests/test_scan_session_resume_svf.py"
producer=ROOT/".coordination/20261014/workspaces/scan-session-r12"
branch=ROOT/".coordination/20261014/workspaces/coordinator-main-migration-r16"
proof_path=ROOT/"artifacts/coordinator-main-migration-r16-20261015/review.json"
proof=json.loads(proof_path.read_text(encoding="utf-8"))
assert proof["coordinator_validation_passed"] and proof["source_unchanged"]
linux_here="/mnt/c/"+HERE.as_posix()[3:]
processes=json.loads(subprocess.check_output(["wsl","-d","Ubuntu","--","bash","-lc",f"/home/zeal/venv313/bin/python {linux_here}/inspect_workspace_processes.py scan-session-r12"],text=True))
assert not processes["processes"]
assert all(hashlib.sha256((producer/p).read_bytes()).hexdigest()==sha for p,sha in proof["producer_owned_hashes"].items())
baseline=json.loads((HERE/"followups-r12/scan-session-r12-baseline.json").read_text(encoding="utf-8"))
old=next(r["sha256"] for r in baseline["files"] if r["path"]==name)
assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==old
assert hashlib.sha256((producer/name).read_bytes()).hexdigest()==old
sha=proof["coordinator_owned_files"][name]
assert hashlib.sha256((branch/name).read_bytes()).hexdigest()==sha
p=HERE/"followups-r12/scan-session-r12-dependencies.json"
backup=p.with_name("scan-session-r12-dependencies-before-migration-r16.json")
assert not backup.exists();shutil.copyfile(p,backup)
d=json.loads(p.read_text(encoding="utf-8"));assert not any(r["path"]==name for r in d["files"])
shutil.copyfile(branch/name,producer/name)
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
d["files"].append({"path":name,"previous_sha256":old,"sha256":sha,"authority":proof_path.relative_to(ROOT).as_posix(),"authority_scope":"coordinator validated test migration staged with producerR3; not root-intaken", "readonly":True})
d["migration_refresh_at"]=at;d["prior_receipt"]=backup.relative_to(HERE).as_posix()
p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"at":at,"refreshed_readonly_test":name,"producer_owned_source_unchanged":True,"root_unchanged":True,"dependency_count":len(d["files"])}))
