"""Empirical TP-safety test for candidate-level duplicate folding.

Folds report items with an answer-free key (no truth labels), keeps one
representative per group (max final_score), then re-scores the folded report
with the OFFICIAL scorer and measures TP damage.

Keys:
  K1 = (category, file, function)                coarse
  K2 = (category, file, function, line // 16)    line-aware bucket
"""
import json, copy, sys
from pathlib import Path

sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
from zscope.benchmarking.protocol import score_report_views

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
GT = json.loads((ROOT / "test/range/benchmark/ground_truth.json").read_text())


def item_line(i):
    loc = str(i.get("location") or "")
    try:
        return int(str(loc.split(":")[1]))
    except Exception:
        try:
            return int(i.get("line") or 0)
        except Exception:
            return 0


def fold_report(rep, key_fn):
    out = copy.deepcopy(rep)
    conf = out.get("issues", [])
    pool = out.get("issues_with_needs_review", [])
    conf_ids = {i.get("id") for i in conf}
    pool_only = [i for i in pool if i.get("id") not in conf_ids]
    groups = {}
    for i in conf + pool_only:
        groups.setdefault(key_fn(i), []).append(i)
    keep = set()
    for g in groups.values():
        best = max(g, key=lambda x: (float(x.get("final_score") or 0), str(x.get("id"))))
        keep.add(best.get("id"))
    conf_kept = [i for i in conf if i.get("id") in keep]
    pool_kept = [i for i in pool if i.get("id") in keep]
    out["issues"] = conf_kept
    out["issues_with_needs_review"] = pool_kept
    # scorer reads embedded report_views first - rebuild them to match the fold
    out["report_views"] = {
        "default": {"issues": conf_kept},
        "with_needs_review": {"issues": conf_kept + pool_kept},
    }
    return out, len(conf) + len(pool_only), len(keep)


def key1(i):
    f = str(i.get("location") or "").split(":")[0]
    return (i.get("category"), f, i.get("function"))


def key2(i):
    f = str(i.get("location") or "").split(":")[0]
    return (i.get("category"), f, i.get("function"), item_line(i) // 16)


for run in ("20260905T130307Z", "20260906T132051Z"):
    rd = ROOT / "benchmark-artifacts/c_cpp/trial" / run / "run-01"
    rep = json.loads((rd / "report.json").read_text())
    base = score_report_views(rep, GT)
    print(f"===== {run}")
    for view in ("default", "with_needs_review"):
        s = base[view]
        print(f"  baseline[{view}]: tp={s['true_positives']} fp_raw={s['false_positives_raw']} "
              f"recall={s['recall']} precision={s['precision']}")
    def key3(i):
        f = str(i.get("location") or "").split(":")[0]
        return (i.get("category"), f, i.get("function"), item_line(i))

    def key4(i):
        return str(i.get("dedup_key") or f"NOK:{i.get('id')}")

    for name, kf in (("K3 cat+file+func+line", key3), ("K4 dedup_key", key4),
                     ("K1 cat+file+func", key1), ("K2 +line/16", key2)):
        folded, before, after = fold_report(rep, kf)
        sc = score_report_views(folded, GT)
        print(f"  -- fold {name}: items {before}->{after}")
        for view in ("default", "with_needs_review"):
            s0, s1 = base[view], sc[view]
            d_tp = s1["true_positives"] - s0["true_positives"]
            print(f"     [{view}] tp {s0['true_positives']}->{s1['true_positives']} ({d_tp:+d})  "
                  f"fp_raw {s0['false_positives_raw']}->{s1['false_positives_raw']}  "
                  f"recall {s0['recall']:.4f}->{s1['recall']:.4f}  "
                  f"precision {s0['precision']:.4f}->{s1['precision']:.4f}")
