import json, sys, collections
from pathlib import Path
B = Path("/mnt/c/Users/10273/home/work/Z-Scope")
A = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
sys.path.insert(0, str(B))
from zscope.benchmarking.protocol import issue_match_detail, score_report_views

gt = json.loads((A/"test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))
vmap = {v["id"]: v for v in gt["vulnerabilities"]}
rd = A/"benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01"
rep = json.loads((rd/"report.json").read_text(encoding="utf-8"))
issues = rep["issues"]
dA = json.loads((rd/"score.json").read_text())

scB = score_report_views(rep, gt)["default"]
b_matched = set(scB.get("matched") or [])
a_pairs = dA["matched_pairs"]
a_matched = {p["truth_id"] for p in a_pairs}
only_a = a_matched - b_matched
only_b = b_matched - a_matched
print(f"A-only: {len(only_a)}  B-only: {len(only_b)}  共同: {len(a_matched & b_matched)}")

def line_of(i):
    loc = str(i.get("location") or "")
    try: return int(str(loc.split(":")[1]))
    except Exception: return 0

def truth_range(v):
    try: return int(v.get("line")), int(v.get("end_line") or v.get("line"))
    except Exception: return None

far = near = no_line = 0
rows = []
for tid in sorted(only_a):
    pair = next(p for p in a_pairs if p["truth_id"] == tid)
    issue = issues[pair["issue_index"]]
    v = vmap[tid]
    tr = truth_range(v)
    il = line_of(issue)
    d = None
    if tr and il:
        d = min(abs(il - tr[0]), abs(il - tr[1])) if il < tr[0] or il > tr[1] else 0
        if d > 8: far += 1
        else: near += 1
    else:
        no_line += 1
    md = issue_match_detail(issue, v, 8)
    stage = "MATCHED?!" if md else ("cat" if md is None else "?")
    # B 拒绝的阶段
    from zscope.benchmarking import protocol as BP
    cat_ok = bool(BP._structured_category_match_reason(issue, v))
    rows.append((tid, issue, v, d, cat_ok))
print(f"A-only 里: 主行距 truth 区间 >8 行 = {far}  <=8 行 = {near}  无行 = {no_line}")
print(f"B 结构化类别匹配通过率: {sum(1 for r in rows if r[4])}/{len(rows)}")
print("\n抽样判定（前 10 个 A-only）:")
for tid, issue, v, d, cat_ok in rows[:10]:
    print(f"  {tid} [{v.get('category')}] truth@{v.get('function')}:{v.get('line')}-{v.get('end_line')}")
    print(f"    issue: {issue.get('id','')[:40]} [{issue.get('category')}] {issue.get('function')}:{line_of(issue)} "
          f"rule={str(issue.get('rule'))[:40]} d={d} cat_ok={cat_ok}")
    print(f"    sink={str(issue.get('sink'))[:60]!r}")
