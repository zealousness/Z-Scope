"""Reconcile the unused UI copy with the passing current Root bytes."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
name = "astra-stop-coverage-ux-r21"
branch = ROOT / ".coordination/20261014/workspaces" / name
path = HERE / "followups-r12" / (name + "-baseline.json")
old = json.loads(path.read_text(encoding="utf-8"))
assert old["dispatch_state"] == "not_dispatched_waiting_current_Root_full_joint"
original = {r["path"]: r["sha256"] for r in old["files"]}
assert all(hashlib.sha256((branch / p).read_bytes()).hexdigest() == h for p, h in original.items())
assert not (branch / "DELIVERY.md").exists(), "UI workspace already used; reconcile before copying"
gate = ROOT / "artifacts/coordinator-r22-unchanged-union-20261016/review.json"
review = json.loads(gate.read_text(encoding="utf-8"))
assert review["all_current_selected_validation_passed"] and review["is_current_root"] and review["commands_passed"] == 6
source = json.loads((gate.parent / "source-evidence.json").read_text(encoding="utf-8"))["after"]
assert set(original) <= set(source)
fixture_intake = json.loads((ROOT / "artifacts/intake-root-fixtures-r21-20261015/receipt.json").read_text(encoding="utf-8"))
authorized = {r["path"]: r["after"] for r in fixture_intake["files"]}
assert all(source[p] == authorized.get(p, h) for p, h in original.items())
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in source.items())
backup = path.with_name(name + "-baseline-r20-before-refresh.json")
assert not backup.exists()
backup.write_bytes(path.read_bytes())
changes = []
for p, h in sorted(source.items()):
    if original.get(p) == h:
        continue
    target = branch / p
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((ROOT / p).read_bytes())
    assert hashlib.sha256(target.read_bytes()).hexdigest() == h
    changes.append({"path": p, "before": original.get(p), "after": h, "readonly_dependency_refresh": True})
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
updated = {**old, "captured_at": at, "files": [{"path": p, "sha256": h} for p, h in sorted(source.items())], "current_root_joint_passed": True, "current_root_review": gate.relative_to(ROOT).as_posix(), "dispatch_state": "not_dispatched_waiting_coordinator_projection_dependency", "previous_baseline": backup.relative_to(HERE).as_posix(), "readonly_refresh": changes}
updated["task"]["depends_on"] = ["CURRENT-JOINT-R22", "ASTRA-UX-REMAINING-AUDIT-R21", "COORD-COVERAGE-PROJECTION-R21"]
path.write_text(json.dumps(updated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "inputs": len(source), "updated_readonly_inputs": len(changes), "ui_dispatched": False, "root_product_changed": False}), flush=True)
