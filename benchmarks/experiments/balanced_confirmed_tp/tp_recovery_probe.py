import json, sys
from pathlib import Path
B = Path("C:/Users/10273/home/work/Z-Scope")
sys.path.insert(0, str(B))
from zscope.benchmarking import protocol as BP
A = Path("C:/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
d = A / "benchmark-artifacts/c_cpp/trial/20260908T055018Z/run-01"
n = json.loads((d / "score.json").read_text(encoding="utf-8"))
g = json.loads((A / "benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01/score.v2.json").read_text(encoding="utf-8"))["default"]
gt = json.loads((A / "test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))
vmap = {v["id"]: v for v in gt["vulnerabilities"]}
rep = json.loads((d / "report.json").read_text(encoding="utf-8"))
issues = rep["issues"]
conf_ids = {i.get("id") for i in issues}
pool = [i for i in rep.get("issues_with_needs_review", []) if i.get("id") not in conf_ids]
gm = {p["truth_id"] for p in g.get("matched_pairs", [])}
nm = {p["truth_id"] for p in n.get("matched_pairs", [])}
lost = sorted(gm - nm)

paths = {"T1_pool_strict": [], "T2_confirmed_site_mismatch": [], "T3_no_candidate": []}
for tid in lost:
    v = vmap[tid]
    pool_hit = [i for i in pool if BP.issue_match_detail(i, v, 8) is not None]
    if pool_hit:
        paths["T1_pool_strict"].append((tid, pool_hit[0].get("id", "")[:34], pool_hit[0].get("category")))
        continue
    same_func = [i for i in issues if i.get("function") == v.get("function")]
    if same_func:
        paths["T2_confirmed_site_mismatch"].append((tid, same_func[0].get("category")))
        continue
    paths["T3_no_candidate"].append(tid)
for k, v in paths.items():
    print(f"{k}: {len(v)}")
    for x in v[:16]:
        print("   ", x)

pool_tp_all = []
for i in pool:
    ts = [v["id"] for v in gt["vulnerabilities"]
          if BP.issue_match_detail(i, v, 8) is not None and v["id"] not in nm]
    if ts:
        pool_tp_all.append((i.get("id", "")[:34], i.get("category"), ts[0]))
print(f"\n复核池内覆盖未确认 truth 的条目总数: {len(pool_tp_all)}")
for x in pool_tp_all[:18]:
    print("   ", x)
