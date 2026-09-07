import json, collections, sys
from pathlib import Path

sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
from zscope.benchmarking.protocol import issue_match_detail

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
RUN = "benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01"
d = json.loads((ROOT / RUN / "score.json").read_text())
rep = json.loads((ROOT / RUN / "report.json").read_text())
gt = json.loads((ROOT / "test/range/benchmark/ground_truth.json").read_text())
vulns = gt["vulnerabilities"]
issues = rep.get("issues", [])
conf_ids = {i.get("id") for i in issues}
pool = [i for i in rep.get("issues_with_needs_review", []) if i.get("id") not in conf_ids]
matched_pairs = d.get("matched_pairs", [])
matched_truths = {p["truth_id"] for p in matched_pairs}
truth2rep = {p["truth_id"]: issues[p["issue_index"]] for p in matched_pairs}
tinfo = {v["id"]: v for v in vulns}


def line_of(x):
    loc = str(x.get("location") or "")
    try:
        return int(str(loc.split(":")[1]))
    except Exception:
        return 0


def strict_truths(issue):
    return [str(v["id"]) for v in vulns if issue_match_detail(issue, v, 8) is not None]


# 1) 池内 strict-dup 与其代表的位点一致性
dists = []
same_cat = same_sink = same_src = 0
pairs = []
for i in pool:
    ts = [t for t in strict_truths(i) if t in matched_truths]
    if not ts:
        continue
    t = ts[0]
    r = truth2rep.get(t)
    if not r:
        continue
    dl = abs(line_of(i) - line_of(r))
    dists.append(dl)
    same_cat += int(i.get("category") == r.get("category"))
    same_sink += int(str(i.get("sink")) == str(r.get("sink")))
    same_src += int(str(i.get("source")) == str(r.get("source")))
    pairs.append((dl, i, r, t))
dists.sort()
n = len(dists)
print(f"pool strict-dups with matched rep: n={n}")
if n:
    print(f"  line distance: median={dists[n//2]} p90={dists[int(n*0.9)]} max={dists[-1]}  <=2行: {sum(1 for x in dists if x<=2)}/{n}")
print(f"  same category: {same_cat}/{n}  identical sink expr: {same_sink}/{n}  identical source expr: {same_src}/{n}")
print("\n  samples (farthest first):")
for dl, i, r, t in sorted(pairs, key=lambda p: -p[0])[:5]:
    print(f"   d={dl} truth={t}")
    print(f"     dup : {i.get('id','')[:36]} {i.get('category')} L{line_of(i)} src={str(i.get('source'))[:40]!r} snk={str(i.get('sink'))[:40]!r}")
    print(f"     rep : {r.get('id','')[:36]} {r.get('category')} L{line_of(r)} src={str(r.get('source'))[:40]!r} snk={str(r.get('sink'))[:40]!r}")
for dl, i, r, t in sorted(pairs, key=lambda p: p[0])[:3]:
    print(f"   d={dl} truth={t}  dup={i.get('id','')[:34]} rep={r.get('id','')[:34]}")

# 2) K4 折叠丢的 3 个 truth：合并视图是否兜住
matched_idx = set(d.get("matched_issue_indices") or [])
# 重建 K4 折叠（同 fold_tp_safety）
import copy
out = copy.deepcopy(rep)
conf, pool_only = out.get("issues", []), [i for i in rep.get("issues_with_needs_review", []) if i.get("id") not in conf_ids]
groups = {}
for i in conf + pool_only:
    groups.setdefault(str(i.get("dedup_key") or f"NOK:{i.get('id')}"), []).append(i)
keep = {max(g, key=lambda x: (float(x.get("final_score") or 0), str(x.get("id")))).get("id") for g in groups.values()}
conf_k = [i for i in conf if i.get("id") in keep]
pool_k = [i for i in pool_only if i.get("id") in keep]
before_t = set()
for p in matched_pairs:
    before_t.add(p["truth_id"])
# 折叠后 confirmed matched
after_pairs = []
for n2, i in enumerate(conf_k):
    for v in vulns:
        if issue_match_detail(i, v, 8) is not None and str(v["id"]) in matched_truths:
            after_pairs.append(str(v["id"]))
            break
lost_conf = before_t - set(after_pairs)
still_in_view = 0
for t in lost_conf:
    v = tinfo[t]
    found = any(issue_match_detail(i, v, 8) is not None for i in conf_k + pool_k)
    still_in_view += int(found)
print(f"\nK4 fold: confirmed truths {len(before_t)} -> {len(set(after_pairs))}  (lost {len(lost_conf)}: {sorted(lost_conf)})")
print(f"  lost truths still strictly covered in folded with_review view: {still_in_view}/{len(lost_conf)}")
