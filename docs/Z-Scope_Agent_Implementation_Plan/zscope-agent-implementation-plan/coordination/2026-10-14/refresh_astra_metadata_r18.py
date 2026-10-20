"""Refresh exactly one validated readonly UI dependency, preserving ownership."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
review = json.loads((ROOT / "artifacts/coordinator-lightweight-r18-20261015/review.json").read_text(encoding="utf-8"))
assert review["coordinator_validation_passed"] and review["source_unchanged"]
assert review["junit"]["tests"] == "77" and all(review["junit"][k] == "0" for k in ("failures", "errors", "skipped"))
assert len(review["commands"]) == 4 and all(r["returncode"] == 0 for r in review["commands"])
name = "zscope/web/services.py"
baseline = json.loads((HERE / "followups-r12/astra-instance-ui-r18-baseline.json").read_text(encoding="utf-8"))
expected = next(r["sha256"] for r in baseline["files"] if r["path"] == name)
source = ROOT / ".coordination/20261014/workspaces/coordinator-lightweight-r18" / name
target = ROOT / ".coordination/20261014/workspaces/astra-instance-ui-r18" / name
assert hashlib.sha256(target.read_bytes()).hexdigest() == expected
assert hashlib.sha256(source.read_bytes()).hexdigest() == review["after"][name]
target.write_bytes(source.read_bytes())
receipt = {"recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(), "coordinator_authorized": True, "validation": "artifacts/coordinator-lightweight-r18-20261015/review.json", "files": [{"path": name, "previous_sha256": expected, "sha256": review["after"][name], "source": str(source), "readonly": True}], "root_changed": False}
out = HERE / "followups-r12/astra-instance-ui-r18-dependencies.json"
assert not out.exists()
out.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"receipt": str(out), "services_sha256": review["after"][name], "root_changed": False}))
