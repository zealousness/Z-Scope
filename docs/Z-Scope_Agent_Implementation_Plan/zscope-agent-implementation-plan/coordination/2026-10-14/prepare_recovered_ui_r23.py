"""Reconcile frozen deliveries and prepare a separate coordinator acceptance copy."""
from pathlib import Path
import copy
import datetime as dt
import hashlib
from html.parser import HTMLParser
import importlib.util
import json
import sys
from audit_followup_r12 import audit

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
def read(p):
    return json.loads(p.read_text(encoding="utf-8"))
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p, v):
    p.write_text(json.dumps(v, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
out = ROOT / "artifacts/coordinator-recovery-r23-20261016"
out.mkdir(exist_ok=False)
root_source = read(ROOT / "artifacts/coordinator-r22-unchanged-union-20261016/source-evidence.json")["after"]
drift = [p for p, h in root_source.items() if not (ROOT / p).is_file() or sha(ROOT / p) != h]
write(out / "root-reconciliation.json", {"at": dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), "source_inputs": len(root_source), "drift": drift, "prior_selected_union_repeated": False, "wsl_process_inspection": False})
assert not drift, "Root changed since R22: review actual changes before integration"
name = "astra-stop-coverage-ux-r21"
producer = ROOT / ".coordination/20261014/workspaces" / name
report_path = producer / "artifacts/stop-coverage-ux-r21/review.json"
report = read(report_path)
assert report["logical_task"] == "ASTRA-STOP-COVERAGE-UX-R21"
assert report["tests"]["tests"] == 123 and all(report["tests"][k] == 0 for k in ("failures", "errors", "skipped"))
assert len(report["commands"]) == 8 and all(r["returncode"] == 0 for r in report["commands"])
ownership = audit(name)
assert ownership["nonowned_changes"] == []
assert {r["path"] for r in ownership["changes"]} == set(report["changed_paths"])
assert all(sha(producer / r["path"]) == r["after"] for r in report["owned_paths"])
dependency = read(HERE / "followups-r12" / (name + "-dependencies.json"))
assert all(sha(producer / r["path"]) == r["sha256"] for r in dependency["files"])
expected = dict(root_source)
expected.update({r["path"]: r["sha256"] for r in dependency["files"]})
expected.update({r["path"]: r["after"] for r in report["owned_paths"]})
assert len(expected) == 1059
assert all(sha(producer / p) == h for p, h in expected.items())
full = read(producer / "artifacts/stop-coverage-ux-r21/full-input-sha256.json")
assert all(expected[r["path"]] == r["after"] for r in full)
producer_hashes = {p: sha(producer / p) for p in ("DELIVERY.md", "artifacts/stop-coverage-ux-r21/review.json", "artifacts/stop-coverage-ux-r21/full-input-sha256.json")}
stage = ROOT / ".coordination/20261014/workspaces/coordinator-ui-acceptance-r23"
stage.mkdir(exist_ok=False)
for p, h in sorted(expected.items()):
    target = stage / p
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((producer / p).read_bytes())
    assert sha(target) == h
class Classes(HTMLParser):
    def __init__(self):
        super().__init__()
        self.classes = set()
    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key == "class" and value:
                self.classes.update(value.split())
old_html, new_html = Classes(), Classes()
old_html.feed((ROOT / "zscope/web/static/index.html").read_text(encoding="utf-8"))
new_html.feed((stage / "zscope/web/static/index.html").read_text(encoding="utf-8"))
assert new_html.classes == old_html.classes, "New Tailwind classes need explicit resource build workflow"
assert sha(stage / "zscope/web/static/dashboard_workbench.css") == root_source["zscope/web/static/dashboard_workbench.css"]
spec = importlib.util.spec_from_file_location("locked_web_assets", stage / "scripts/portable/web_assets.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
lock_path = stage / "requirements/portable/web-assets.lock.json"
old_lock = read(lock_path)
new_lock = copy.deepcopy(old_lock)
for filename in module.FIRST_PARTY:
    new_lock["first_party"][filename]["sha256"] = sha(stage / "zscope/web/static" / filename)
changed_assets = [p for p in old_lock["first_party"] if old_lock["first_party"][p] != new_lock["first_party"][p]]
assert set(changed_assets) == {"index.html", "dashboard_workbench.js"}
assert {k: v for k, v in old_lock.items() if k != "first_party"} == {k: v for k, v in new_lock.items() if k != "first_party"}
(out / "web-assets.lock.before.json").write_bytes(lock_path.read_bytes())
write(lock_path, new_lock)
expected["requirements/portable/web-assets.lock.json"] = sha(lock_path)
assert all(sha(ROOT / p) == h for p, h in root_source.items())
assert all(sha(producer / p) == h for p, h in producer_hashes.items())
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
proof = {"at": at, "root_inputs": len(root_source), "root_unchanged_from_R22": True, "bridge_owner_verified": {"windows_pid": 80748, "started_at": "2026-10-14T16:58:25+08:00", "observed_at": "2026-10-16T10:02:02+08:00", "service_started_or_restarted": False}, "producer_finished_at": report["finished_at"], "producer_hashes": producer_hashes, "producer_source_files": len(expected), "ownership": ownership, "coordinator_workspace": stage.relative_to(ROOT).as_posix(), "files": [{"path": p, "sha256": h} for p, h in sorted(expected.items())], "asset_lock": {"before": root_source["requirements/portable/web-assets.lock.json"], "after": expected["requirements/portable/web-assets.lock.json"], "changed_first_party": changed_assets, "vendor_inputs_css_classes_unchanged": True, "network_or_tailwind_update": False}, "independent_acceptance": False, "root_intaken": False, "joint_verification": False, "wsl_process_inspection": False}
write(out / "prepared.json", proof)
ledger = read(HERE / "tasks.json")
row = next(r for r in ledger["tasks"] if r["id"] == "ASTRA-STOP-COVERAGE-UX-R21")
row.update(status="frozen_delivery_reconciled_coordinator_independent_acceptance_pending", producer_status="completed", worker_finished_at=report["finished_at"], artifact_available=True, delivery_evidence=report_path.relative_to(ROOT).as_posix(), recovery_evidence=(out / "prepared.json").relative_to(ROOT).as_posix(), independent_acceptance=False, integrated=False, joint_verification=False, checked_at=at)
ledger["updated_at"] = at
write(HERE / "tasks.json", ledger)
print(json.dumps({"at": at, "Root_inputs_unchanged": len(root_source), "UI_completed": report["finished_at"], "stage_inputs": len(expected), "changed_asset_lock_entries": changed_assets, "independent_acceptance": False, "root_product_changed": False}), flush=True)
