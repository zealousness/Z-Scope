import json, collections, sys, copy
from pathlib import Path

sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
from zscope.benchmarking.protocol import issue_match_detail, score_report_views

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
RUN = "benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01"
d = json.loads((ROOT / RUN / "score.json").read_text())
rep = json.loads((ROOT / RUN / "report.json").read_text())
gt = json.loads((ROOT / "test/range/benchmark/ground_truth.json").read_text())
vulns = gt["vulnerabilities"]
tinfo = {v["id"]: v for v in vulns}
issues = rep.get("issues", [])
conf_ids = {i.get("id") for i in issues}
pool = [i for i in rep.get("issues_with_needs_review", []) if i.get("id") not in conf_ids]
matched_pairs = d.get("matched_pairs", [])
matched_truths = {p["truth_id"] for p in matched_pairs}
truth2rep = {p["truth_id"]: issues[p["issue_index"]] for p in matched_pairs}


def line_of(x):
    loc = str(x.get("location") or "")
    try:
        return int(str(loc.split(":")[1]))
    except Exception:
        return 0


def strict_truths(issue):
    return [str(v["id"]) for v in vulns if issue_match_detail(issue, v, 8) is not None]


# 1) 远距样本的 truth 行号约束检查
for tid in ("ISSUE42-020", "RANGE-016", "ISSUE42-009", "ISSUE42-027"):
    v = tinfo.get(tid) or {}
    print(f"{tid}: keys={ [k for k in v if 'line' in k.lower()] }",
          {k: v.get(k) for k in ("line", "start_line", "end_line", "lines", "location", "file", "function") if k in v})

# 2) 确认层 16 个 duplicate 的位点一致性
dists = []
same_cat = 0
for n, i in enumerate(issues):
    if n in set(d.get("matched_issue_indices") or []):
        continue
    ts = [t for t in strict_truths(i) if t in matched_truths]
    if not ts:
        continue
    t = ts[0]
    r = truth2rep.get(t)
    if r:
        dists.append(abs(line_of(i) - line_of(r)))
        same_cat += int(i.get("category") == r.get("category"))
dists.sort()
n = len(dists)
print(f"\nconfirmed raw-FP dups: n={n} line-dist median={dists[n//2] if n else '-'} "
      f"<=2行:{sum(1 for x in dists if x <= 2)} <=8行:{sum(1 for x in dists if x <= 8)} same_cat={same_cat}/{n}")

# 3) K4 折叠的 truth 损失：官方 scorer 重做
def item_line(i):
    return line_of(i)

out = copy.deepcopy(rep)
conf, pool_only = out.get("issues", []), pool
groups = {}
for i in conf + pool_only:
    groups.setdefault(str(i.get("dedup_key") or f"NOK:{i.get('id')}"), []).append(i)
keep = {max(g, key=lambda x: (float(x.get("final_score") or 0), str(x.get("id")))).get("id") for g in groups.values()}
conf_k = [i for i in conf if i.get("id") in keep]
pool_k = [i for i in pool_only if i.get("id") in keep]
out["issues"] = conf_k
out["issues_with_needs_review"] = pool_k
out["report_views"] = {"default": {"issues": conf_k}, "with_needs_review": {"issues": conf_k + pool_k}}
sc = score_report_views(out, gt)
s0, s1 = score_report_views(rep, gt)["default"], sc["default"]
before = {p["truth_id"] for p in d.get("matched_pairs", [])}
after = set(sc["default"].get("matched") or [])
print(f"\nK4 (official scorer): confirmed tp {s0['true_positives']}->{s1['true_positives']}")
lost = sorted(before - after)
print(f"  truths lost from CONFIRMED view: {len(lost)}: {lost}")
still_wr = 0
sw = sc["with_needs_review"]
after_wr = set(sw.get("matched") or [])
print(f"  with_review tp {sw['true_positives']} (baseline 134)  truths lost from MERGED view: {len(before - after_wr)}: {sorted(before - after_wr)}")
for t in lost:
    v = tinfo.get(t) or {}
    print(f"    {t}: {v.get('category')} @ {v.get('function')} lines={ {k: v.get(k) for k in ('line','start_line','end_line') if k in v} }")
