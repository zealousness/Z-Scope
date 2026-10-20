"""Bind accepted local application bytes without modifying vendor assets."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/intake-astra-phase2-r6-20261014"
accepted = json.loads((ROOT / "artifacts/coordinator-astra-r6-phase2-retry1-20261014/review.json").read_text(encoding="utf-8"))
assert accepted["independent_acceptance_passed"] and accepted["source_unchanged"]
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
for name, expected in accepted["after_hashes"].items():
    assert digest(ROOT / name) == expected, name
script = ROOT / "scripts/portable/web_assets.py"
lock_path = ROOT / "requirements/portable/web-assets.lock.json"
before_script, before_lock = digest(script), digest(lock_path)
for path in (script, lock_path):
    backup = OUT / "before" / path.relative_to(ROOT)
    backup.parent.mkdir(parents=True, exist_ok=True)
    assert not backup.exists()
    shutil.copyfile(path, backup)
text = script.read_text(encoding="utf-8")
old = '    "dashboard_reports.js",\n    "dashboard_workbench.js",'
assert text.count(old) == 1 and '    "dashboard_config.js",' not in text
script.write_text(text.replace(old, '    "dashboard_reports.js",\n    "dashboard_config.js",\n    "dashboard_workbench.js",'), encoding="utf-8", newline="\n")
lock = json.loads(lock_path.read_text(encoding="utf-8"))
vendor_before = json.dumps({key: value for key, value in lock.items() if key != "first_party"}, sort_keys=True)
for name in ("index.html", "dashboard_config.js", "dashboard_workbench.js", "dashboard_workbench.css"):
    lock["first_party"][name] = {"sha256": digest(ROOT / "zscope/web/static" / name), "license": "MIT"}
assert json.dumps({key: value for key, value in lock.items() if key != "first_party"}, sort_keys=True) == vendor_before
lock_path.write_text(json.dumps(lock, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
receipt = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "accepted_receipt": str(ROOT / "artifacts/coordinator-astra-r6-phase2-retry1-20261014/review.json"), "script_before": before_script, "script_after": digest(script), "lock_before": before_lock, "lock_after": digest(lock_path), "vendor_unchanged": True, "network_used": False, "first_party": lock["first_party"]}
(OUT / "asset-binding.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"receipt": str(OUT / "asset-binding.json"), "first_party_count": len(lock["first_party"])}))
