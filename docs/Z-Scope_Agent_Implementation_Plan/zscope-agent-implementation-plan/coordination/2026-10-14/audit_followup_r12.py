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
    baseline = json.loads((HERE/"followups-r12"/(workspace_name+"-baseline.json")).read_text(encoding="utf-8"))
    task = baseline["task"]
    owns = list(task.get("owns", task.get("write_paths", [])))
    extension_paths = sorted((HERE / "followups-r12").glob(workspace_name+"-ownership-extension*.json"))
    for extension_path in extension_paths:
        extension = json.loads(extension_path.read_text(encoding="utf-8"))
        assert extension["coordinator_authorized"]
        owns.extend(extension["write_paths"])
    workspace = ROOT / ".coordination/20261014/workspaces" / workspace_name
    files = {row["path"]:row["sha256"] for row in baseline["files"]}
    dependency_path = HERE / "followups-r12" / (workspace_name+"-dependencies.json")
    if workspace_name == "astra-queue-ux-r12":
        dependency_path = HERE / "followups-r12/astra-readonly-dependencies.json"
    dependencies = []
    if dependency_path.exists():
        dependencies = json.loads(dependency_path.read_text(encoding="utf-8"))["files"]
        for row in dependencies:
            assert row.get("previous_sha256", row.get("before")) == files.get(row["path"])
            files[row["path"]] = row.get("sha256", row.get("after"))
    def owned(name):
        return name not in {row["path"] for row in dependencies} and not name.startswith("zscope/web/static/vendor/") and not name.startswith("zscope/web/static/LICENSE") and any(fnmatch.fnmatchcase(name,p) for p in owns)
    changes=[]
    for name,before in files.items():
        after=digest(workspace/name)
        if after!=before:
            changes.append({"path":name,"before":before,"after":after,"owned":owned(name)})
    for directory,dirs,names in os.walk(workspace):
        # DELIVERY is a producer receipt directory, equivalent to artifacts;
        # it never grants product-code ownership or enters a source intake.
        dirs[:]=[name for name in dirs if name not in {"artifacts","DELIVERY","__pycache__",".pytest_cache",".mypy_cache",".git"}]
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
    names=sys.argv[1:] or ["scan-session-r12","contract-validation-r12","astra-queue-ux-r12"]
    for name in names:
        value=audit(name)
        print(json.dumps({"workspace":name,"captured_at":value["captured_at"],"owned_changes":[row['path'] for row in value['changes'] if row['owned']],
                          "nonowned_changes":value['nonowned_changes'],"delivery_exists":value['delivery_exists']},ensure_ascii=False))
