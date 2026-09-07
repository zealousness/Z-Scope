import json, collections
from pathlib import Path

SIZE = {"resource_allocation_without_limits", "integer_overflow", "unchecked_allocation"}
d = json.loads(Path("benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01/score.v2.json").read_text(encoding="utf-8"))["default"]
rep = json.loads(Path("benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01/report.json").read_text(encoding="utf-8"))
issues = rep["issues"]
matched_idx = set(d.get("matched_issue_indices") or [])
print("== v2 确认层的尺寸族条目（TP 与 FP 分列）:")
tp_rows, fp_rows = [], []
for n, i in enumerate(issues):
    if i.get("category") not in SIZE:
        continue
    is_tp = n in matched_idx
    proofs = [str(p.get("proof_kind"))[:44] for p in (i.get("deterministic_proofs") or [])
              if isinstance(p, dict) and p.get("outcome") == "confirm"]
    row = (i.get("id", "")[:40], i.get("function"), i.get("location"),
           str((i.get("attribution") or {}).get("decision_level")), proofs)
    (tp_rows if is_tp else fp_rows).append(row)
print(f"  TP n={len(tp_rows)}:")
for r in tp_rows:
    print(f"    {r[0]:42} {r[3]} {r[1]}:{r[2]} proofs={r[4]}")
print(f"  FP n={len(fp_rows)}:")
for r in fp_rows:
    print(f"    {r[0]:42} {r[3]} {r[1]}:{r[2]} proofs={r[4]}")
# 尺寸族 truth 清单（truth set 里这些类别有几条）
gt = json.loads(Path("test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))
sc = collections.Counter(v["category"] for v in gt["vulnerabilities"] if v["category"] in SIZE)
print("\n  truth 集中尺寸族条数:", dict(sc), " matched:", len(tp_rows))
