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
matched_truths = {p["truth_id"] for p in d.get("matched_pairs", [])}
tinfo = {v["id"]: v for v in vulns}

def strict_match_truths(issue):
    out = []
    for v in vulns:
        if issue_match_detail(issue, v, 8) is not None:
            out.append(str(v.get("id")))
    return out

def classify(items, label):
    strict_dup = root_only = effective = []
    strict_dup, root_only, effective = [], [], []
    for i in items:
        sm = strict_match_truths(i)
        sm_matched = [t for t in sm if t in matched_truths]
        if sm_matched:
            strict_dup.append((i, sm_matched))
        else:
            root_only.append(i)
    print(f"== {label}: n={len(items)} strict-dup-of-matched={len(strict_dup)} other={len(root_only)}")
    return strict_dup, root_only

# 确认层 16 raw FP
fp_ids_raw = set()
for r in (d.get("false_positive_audit") or {}).get("effective_records", []):
    pass
confirmed_fp = [i for n, i in enumerate(issues) if n not in set(d.get("matched_issue_indices") or [])]
sd, ro = classify(confirmed_fp, "confirmed raw FP (16)")
for i, ts in sd[:5]:
    print("   strict-dup:", i.get("id", "")[:40], "->", ts[:2])
for i in ro[:6]:
    print("   OTHER:", i.get("id", "")[:40], i.get("category"), i.get("function"))

# 池内 86 个非 TP
matched_pool_tp = 18  # with_review_tp 134 - confirmed 116
sd2, ro2 = classify(pool, "pool non-TP (86)")
print(f"pool strict-dup examples:")
for i, ts in sd2[:8]:
    print("   ", i.get("id", "")[:40], i.get("category"), i.get("function"), "->", ts[:2])
print(f"pool OTHER (root-cause-only or true noise): {len(ro2)}")
for i in ro2[:12]:
    print("   ", i.get("id", "")[:40], "|", i.get("category"), "|", i.get("function"), "|", str(i.get("needs_review_sub_state")))

# 6 个有效 FP 的字段结构
rv = (d.get("report_views") or {}).get("with_needs_review") or {}
recs = rv.get("false_positive_issue_records") or []
if recs:
    print("\neffective FP record keys:", sorted(recs[0].keys()))
    for r in recs:
        print("   ", json.dumps({k: str(r.get(k))[:60] for k in list(r.keys())[:6]}, ensure_ascii=False))
