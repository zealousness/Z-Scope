"""Bind Astra's stable existing assets without a network/vendor/CSS rebuild."""
from pathlib import Path
import hashlib
import json
import datetime as dt
import importlib.util

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
expected = {
    "index.html": "c739a7976281ef9ab1dc9f747f48f7415466f9fee7622dd12dca700f87215e91",
    "dashboard_workbench.js": "caa7ab961963cfc46781010dc1fa941c4341a2a9bd9ef807c959da29f82e1ff6",
    "dashboard_workbench.css": "c57bd0ca61d564b3cb05b7ddc27aca5043b93762a48ad0dc34d4a11d55b898c0",
}
for name, value in expected.items():
    assert hashlib.sha256((ROOT / "zscope/web/static" / name).read_bytes()).hexdigest() == value, name
module_spec = importlib.util.spec_from_file_location("asset_metadata", ROOT / "scripts/portable/web_assets.py")
assert module_spec and module_spec.loader
module = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(module)
lock_path = ROOT / "requirements/portable/web-assets.lock.json"
old = json.loads(lock_path.read_text(encoding="utf-8"))
new = dict(old)
new["first_party"] = {
    name: {"sha256": hashlib.sha256((ROOT / "zscope/web/static" / name).read_bytes()).hexdigest(), "license": "MIT"}
    for name in module.FIRST_PARTY
}
assert {k: v for k, v in old.items() if k != "first_party"} == {k: v for k, v in new.items() if k != "first_party"}
with lock_path.open("w", encoding="utf-8", newline="\n") as output:
    output.write(json.dumps(new, indent=2) + "\n")
proof = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "astra_final_bytes_verified": expected, "before": old["first_party"], "after": new["first_party"], "vendor_and_other_lock_inputs_unchanged": True, "network_or_tailwind_rebuild": False}
with (HERE / "static-lock-real-jobs.json").open("x", encoding="utf-8", newline="\n") as output:
    output.write(json.dumps(proof, indent=2) + "\n")
print(json.dumps({"assets": len(new["first_party"]), "vendor_unchanged": True}))
