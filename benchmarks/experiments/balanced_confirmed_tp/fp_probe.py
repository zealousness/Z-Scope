import json, collections
from pathlib import Path

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
d = json.loads((ROOT / "benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01/score.json").read_text())
rv = d.get("report_views")
print("report_views type:", type(rv).__name__)
if isinstance(rv, dict):
    print("report_views keys:", list(rv.keys())[:6])
    for k, v in list(rv.items())[:2]:
        s = v.get("summary") or v
        if isinstance(s, dict):
            keep = {kk: s.get(kk) for kk in ("true_positives", "false_positives", "false_positives_raw",
                                             "duplicate_of_matched_count", "recall", "precision") if kk in s}
            print(f"  view[{k}]: {json.dumps(keep)}")
qv = d.get("quality_views")
print("quality_views:", json.dumps(qv, ensure_ascii=False)[:300] if qv else None)
