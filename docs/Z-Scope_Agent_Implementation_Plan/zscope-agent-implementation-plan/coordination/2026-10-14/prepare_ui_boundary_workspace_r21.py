"""Freeze R20 intake for isolated UI/projection preparation, never Root writes."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
name = "astra-stop-coverage-ux-r21"
base = json.loads((ROOT / "artifacts/coordinator-r19-all-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
intake = json.loads((ROOT / "artifacts/intake-job-cli-window-r20-20261015/receipt.json").read_text(encoding="utf-8"))
assert len(intake["files"]) == 9
source = {**base, **{r["path"]: r["after"] for r in intake["files"] + intake["launcher_updates"]}}
for label in ("coordinator-job-cli-window-r20-final-acceptance-20261015", "coordinator-first-cause-r20-final-acceptance-20261015"):
    review = json.loads((ROOT / "artifacts" / label / "review.json").read_text(encoding="utf-8"))
    assert review["independent_acceptance_passed"]
    for origin, row in review["independent_probe_sources"].items():
        path = Path(origin).relative_to(ROOT).as_posix()
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == row["sha256"]
        source[path] = row["sha256"]
for path in (HERE / "verify_joint_with_clock_r21.py",):
    source[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
assert all(hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == sha for path, sha in source.items())
branch = ROOT / ".coordination/20261014/workspaces" / name
assert not branch.exists()
branch.mkdir()
for path, sha in sorted(source.items()):
    target = branch / path
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / path, target)
    assert hashlib.sha256(target.read_bytes()).hexdigest() == sha
owns = ["zscope/web/static/index.html", "zscope/web/static/dashboard_workbench.js", "tests/test_agent_workbench_ui.py", "tests/fixtures/agent_workbench_ui.cjs", "tests/test_instance_coverage_ui.py", "tests/fixtures/instance_coverage_ui.cjs", "tests/test_ux_capability_boundaries_ui.py", "tests/fixtures/ux_capability_boundaries_ui.cjs"]
task = {"id": "ASTRA-STOP-COVERAGE-UX-R21", "workspace": name, "owner": "Astra", "owns": owns, "write_paths": owns, "depends_on": ["CURRENT-JOINT-R20", "ASTRA-UX-REMAINING-AUDIT-R21"], "scope": "Narrow current stop/config wording and coverage reason UI; no full scanner capability", "root_product_write_permission": False}
receipt = {"captured_at": dt.datetime.now(dt.timezone.utc).isoformat(), "task": task, "files": [{"path": path, "sha256": sha} for path, sha in sorted(source.items())], "root_intake": "artifacts/intake-job-cli-window-r20-20261015/receipt.json", "current_root_joint_passed": False, "dispatch_state": "not_dispatched_waiting_current_Root_full_joint", "scope": "Isolated coordinator projection preparation; future UI baseline must be reconciled with passing R20 proof before native dispatch"}
(HERE / "followups-r12" / (name + "-baseline.json")).write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"workspace": name, "bound_inputs": len(source), "ui_dispatched": False, "root_product_changed": False}), flush=True)
