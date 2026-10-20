"""Exercise the actual large-file answer-isolation path with synthetic markers."""

from pathlib import Path
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(ROOT / ".coordination/20261014/workspaces/s09-prep"))
from scripts.agent_plan_evaluation import LARGE_REPORT_BYTES, load_logical_report, PlanEvaluationError
from zscope.reporting.json_io import write_report_atomic

directory = HERE / "review-repro/s09-large-envelope"
directory.mkdir(parents=True, exist_ok=True)
path = directory / "synthetic-report.json"
write_report_atomic(path, {"schema_version": 2, "issues": [], "metadata": {}})
envelope = json.loads(path.read_text(encoding="utf-8"))
envelope["padding"] = "x" * (LARGE_REPORT_BYTES + 128)
envelope["matched_pairs"] = []
path.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
try:
    report, info = load_logical_report(path)
    result = {"accepted": True, "format": info, "logical_keys": sorted(report)}
except PlanEvaluationError as error:
    result = {"accepted": False, "error": str(error), "code": error.code}
proof = {"synthetic_only": True, "size": path.stat().st_size,
         "actual_large_threshold": LARGE_REPORT_BYTES,
         "empty_forbidden_marker": "matched_pairs", "result": result}
(directory / "review.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
print(json.dumps(proof))
