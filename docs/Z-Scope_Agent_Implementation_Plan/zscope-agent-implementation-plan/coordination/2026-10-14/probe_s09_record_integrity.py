"""Read-only code review probe using explicitly synthetic S09 fixtures."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORKSPACE = ROOT / ".coordination/20261014/workspaces/s09-prep"
sys.path.insert(0, str(WORKSPACE))
spec = importlib.util.spec_from_file_location("s09_review_fixtures", WORKSPACE / "tests/test_agent_plan_evaluation.py")
assert spec and spec.loader
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
out = HERE / "review-repro/s09-record-integrity"
if out.exists():
    raise SystemExit("probe output already exists; inspect rather than overwrite")
out.mkdir(parents=True)
identity_a = fixture._write_identity(out / "a")
identity_b = fixture._write_identity(out / "b", model_manifest_hash="ee" * 32)
report_a = fixture._write_report(out / "a")
report_b = fixture._write_report(out / "b", manifest_overrides={"model_manifest_hash": "ee" * 32})
run_a = fixture._record_run(out, label="cold", mode="cold", identity=identity_a, report=report_a)
run_b = fixture._record_run(out, label="warm", mode="warm", identity=identity_b, report=report_b)
before = fixture._comparison(out, [f"cold={run_a}", f"warm={run_b}"])
baseline = fixture._load(run_a)
changed = fixture._load(run_b)
old_record_id = changed["record_id"]
changed["identity"] = baseline["identity"]
changed["counts"]["confirmed_count"] = 999
run_b.write_text(json.dumps(changed), encoding="utf-8")
after = fixture._comparison(out, [f"cold={run_a}", f"warm={run_b}"])
result = {"synthetic_only": True, "before_status": before["comparison_status"],
          "after_status": after["comparison_status"], "record_id_unchanged": changed["record_id"] == old_record_id,
          "confirmed_comparison": after.get("counts_comparison", {}).get("confirmed_count"),
          "report_and_usage_inputs_unchanged": True}
(out / "review.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result))
