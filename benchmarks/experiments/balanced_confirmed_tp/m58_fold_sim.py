"""M5-8 closing simulation: fold only TRUE same-site same-framing duplicates.

Fold key = (category, file, function, |dline|<=2, identical sink string).
Keep the higher-final_score member.  Official scorer measures the delta.
"""
import json, sys, copy, collections
from pathlib import Path

sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
from zscope.benchmarking.protocol import score_report_views

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
GT = json.loads((ROOT / "test/range/benchmark/ground_truth.json").read_text())


def site(i):
    loc = str(i.get("location") or "")
    try:
        line = int(str(loc.split(":")[1]))
    except Exception:
        line = 0
    return (i.get("category"), str(loc.split(":")[0]), i.get("function"), str(i.get("sink")), line)


def fold(rep):
    out = copy.deepcopy(rep)
    conf = out.get("issues", [])
    conf_ids = {i.get("id") for i in conf}
    pool_only = [i for i in out.get("issues_with_needs_review", []) if i.get("id") not in conf_ids]
    items = conf + pool_only
    groups = collections.defaultdict(list)
    for i in items:
        groups[site(i)].append(i)
    keep = set()
    folded = 0
    for g in groups.values():
        best = max(g, key=lambda x: (float(x.get("final_score") or 0), str(x.get("id"))))
        keep.add(best.get("id"))
        folded += len(g) - 1
    conf_k = [i for i in conf if i.get("id") in keep]
    pool_k = [i for i in pool_only if i.get("id") in keep]
    out["issues"] = conf_k
    out["issues_with_needs_review"] = pool_k
    out["report_views"] = {
        "default": {"issues": conf_k},
        "with_needs_review": {"issues": conf_k + pool_k},
    }
    return out, folded


for run in ("20260905T130307Z", "20260906T132051Z"):
    rd = ROOT / "benchmark-artifacts/c_cpp/trial" / run / "run-01"
    rep = json.loads((rd / "report.json").read_text())
    base = score_report_views(rep, GT)
    folded, n = fold(rep)
    sc = score_report_views(folded, GT)
    print(f"===== {run}  folded items: {n}")
    for view in ("default", "with_needs_review"):
        a, b = base[view], sc[view]
        print(f"  [{view}] tp {a['true_positives']}->{b['true_positives']} ({b['true_positives']-a['true_positives']:+d}) "
              f"fp_raw {a['false_positives_raw']}->{b['false_positives_raw']} "
              f"recall {a['recall']:.4f}->{b['recall']:.4f} "
              f"precision(raw口径) {a['true_positives']/(a['true_positives']+a['false_positives_raw']):.4f}->"
              f"{b['true_positives']/(b['true_positives']+b['false_positives_raw']):.4f}")
