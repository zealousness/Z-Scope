"""Prepare an exclusive isolated complex consumer task, without starting it."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
NAME = "astra-instance-consumers-r25"
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
BRANCH = ROOT / ".coordination/20261014/workspaces" / NAME

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

source = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert all(sha(ROOT / path) == digest for path, digest in source.items())
baseline = {}
for name in ("s01-instance-semantics-min-r23-baseline.json", "s01-instance-semantics-min-r23-dependencies.json"):
    baseline.update({row["path"]: row["sha256"] for row in read(HERE / "followups-r12" / name)["files"]})
assert len(baseline) == 1069
assert all(sha(ROOT / path) == digest for path, digest in baseline.items())
shared_paths = ("zscope/semantics/models.py", "tests/test_semantics_shadow_overlay.py")
for path in shared_paths:
    baseline[path] = sha(STAGE / path)
assert len(baseline) == 1070
owns = ["zscope/core/candidates/regex.py", "zscope/core/candidates/graph.py", "zscope/core/candidates/clang_ast_cfg.py", "zscope/rules/builtin_catalog.yaml", "tests/test_instance_builtin_consumers.py"]
BRANCH.mkdir(exist_ok=False)
for path, digest in baseline.items():
    target = BRANCH / path
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile((STAGE if path in shared_paths else ROOT) / path, target)
    assert sha(target) == digest
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
task = dict(id="ASTRA-INSTANCE-CONSUMERS-R25", actual_task="/root/astra_design_contract_r23", workspace=NAME, owner="Astra", owns=owns, write_paths=owns, artifact_write_paths=["DELIVERY.md", "artifacts/instance-consumers-r25/**"], inherits="COORD-INSTANCE-INTEGRATION-R24", depends_on=["CURRENT-JOINT-R23"], related_tasks=["S01-INSTANCE-SEMANTICS-MIN-R23"], status="isolated_workspace_prepared_execution_unconfirmed", dispatched=False, actual_execution_confirmed=False, artifact_available=False, independent_acceptance=False, integrated=False, joint_verification=False, whole_package_complete=False, root_product_write_permission=False, checked_at=at, scope="Complex candidate builtin authority consumer repair; current bounded semantic inputs only, no factory/native changes or whole-package claims")
receipt = dict(prepared_at=at, task=task, files=[dict(path=path, sha256=digest) for path, digest in baseline.items()], readonly_input_count=len(set(baseline) - set(owns)), total_inputs=len(baseline), root_bound_inputs_unchanged=len(source), shared_readonly_paths=list(shared_paths), models_static_review="artifacts/instance-shadow-consumer-precheck-r25-20261016/review.json", root_intake=False)
with (HERE / "followups-r12" / (NAME + "-baseline.json")).open("x", encoding="utf-8", newline="\n") as stream:
    stream.write(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
ledger = read(HERE / "tasks.json")
assert not any(row["id"] == task["id"] for row in ledger["tasks"])
ledger["tasks"].append(task)
ledger["updated_at"] = at
(HERE / "tasks.json").write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
assert all(sha(ROOT / path) == digest for path, digest in source.items())
print(json.dumps(dict(prepared_at=at, task_id=task["id"], actual_task=task["actual_task"], workspace=str(BRANCH), total_inputs=len(baseline), readonly_inputs=receipt["readonly_input_count"], execution_confirmed=False)))
