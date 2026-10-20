"""Read-only live ownership audit; not independent acceptance."""
from pathlib import Path
import datetime as dt
import fnmatch
import hashlib
import json
import os

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None

def audit(workspace_name):
    baseline = json.loads((HERE/"followups-r10"/(workspace_name+"-baseline.json")).read_text(encoding="utf-8"))
    task = baseline["task"]
    workspace = ROOT / ".coordination/20261014/workspaces" / workspace_name
    files = {row["path"]:row["sha256"] for row in baseline["files"]}
    dependency_path = HERE / "followups-r10" / (workspace_name+"-dependencies.json")
    dependencies = []
    if dependency_path.exists():
        dependencies = json.loads(dependency_path.read_text(encoding="utf-8"))["files"]
        for row in dependencies:
            assert row["previous_sha256"] == files.get(row["path"])
            files[row["path"]] = row["sha256"]
    def owned(name):
        return name not in {row["path"] for row in dependencies} and not name.startswith("zscope/web/static/vendor/") and any(fnmatch.fnmatchcase(name,p) for p in task["owns"])
    changes=[]
    for name,before in files.items():
        after=digest(workspace/name)
        if after!=before:
            changes.append({"path":name,"before":before,"after":after,"owned":owned(name)})
    for directory,dirs,names in os.walk(workspace):
        dirs[:]=[name for name in dirs if name not in {"artifacts","__pycache__",".pytest_cache",".mypy_cache",".git"}]
        for filename in names:
            path=Path(directory)/filename
            name=path.relative_to(workspace).as_posix()
            if name not in files and name!="DELIVERY.md":
                changes.append({"path":name,"before":None,"after":digest(path),"owned":owned(name)})
    return {"captured_at":dt.datetime.now(dt.timezone.utc).isoformat(),"task":task["id"],
            "workspace":str(workspace),"changes":changes,"nonowned_changes":[row for row in changes if not row["owned"]],
            "delivery_exists":(workspace/"DELIVERY.md").is_file(),"independent_acceptance":False,
            "note":"Live worker snapshot; a delivery or change is not acceptance."}

if __name__=="__main__":
    import sys
    names=sys.argv[1:] or ["s01-symbol-r10","u01-mcp-r10","astra-ux-r10"]
    for name in names:
        value=audit(name)
        print(json.dumps({"workspace":name,"captured_at":value["captured_at"],"owned_changes":[row['path'] for row in value['changes'] if row['owned']],
                          "nonowned_changes":value['nonowned_changes'],"delivery_exists":value['delivery_exists']},ensure_ascii=False))
