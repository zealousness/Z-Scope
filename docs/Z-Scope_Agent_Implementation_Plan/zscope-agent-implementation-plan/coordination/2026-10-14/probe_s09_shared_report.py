"""Prove S09's record reader handles the current actual storage format."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("s09_shared_review_fixture", ROOT / "tests/test_agent_plan_evaluation.py")
assert spec and spec.loader
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
from zscope.reporting.json_io import write_report_atomic
from scripts.agent_plan_evaluation import load_json

out = HERE / "review-repro/s09-shared-report"
if out.exists():
    raise SystemExit("review output exists; inspect rather than overwrite")
out.mkdir(parents=True)
report_path = fixture._write_report(out)
logical = fixture._load(report_path)
write_report_atomic(report_path, logical)
actual = load_json(report_path)
result = {"synthetic_only": True, "actual_product_writer_used": True,
          "logical_schema": logical.get("schema_version"), "loaded_schema": actual.get("schema_version"),
          "loaded_storage_schema": actual.get("storage_schema"),
          "logical_report_decoded": actual == logical}
(out / "review.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result))
