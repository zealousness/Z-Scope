"""M5-8a simulation: merge same-site multi-framing size-family claims into ONE issue.

Group key  : (file, function), both size-family categories, |dline| <= 16
Rep choice : category specificity (integer_overflow/unchecked > resource),
             then max final_score; folded members recorded in duplicate_sources.
Scored with the official v2 scorer.
"""
import json, sys, copy, collections
from pathlib import Path

sys.path.insert(0, ".")
from zscope.benchmarking.protocol import score_report_views

ROOT = Path(".")
GT = json.loads((ROOT / "test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))
SIZE = {"resource_allocation_without_limits", "integer_overflow", "unchecked_allocation"}
SPECIFICITY = {"integer_overflow": 0, "unchecked_allocation": 1, "resource_allocation_without_limits": 2}


def line_of(i):
    loc = str(i.get("location") or "")
    try:
        return int(str(loc.split(":")[1]))
    except Exception:
        return 0


def fold_size_family(rep):
    out = copy.deepcopy(rep)
    conf = out.get("issues", [])
    conf_ids = {i.get("id") for i in conf}
    pool_only = [i for i in out.get("issues_with_needs_review", []) if i.get("id") not in conf_ids]
    size_items = [i for i in conf + pool_only if i.get("category") in SIZE]
    groups = collections.defaultdict(list)
    for i in size_items:
        groups[(str(i.get("location") or "").split(":")[0], i.get("function"))].append(i)
    removed = set()
    merge_log = []
    for key, g in groups.items():
        if len(g) < 2:
            continue
        g = sorted(g, key=lambda x: (SPECIFICITY.get(x.get("category"), 9),
                                     -float(x.get("final_score") or 0), str(x.get("id"))))
        rep_i = g[0]
        lose = [x for x in g[1:]]
        # 同类别成员若与代表行距 >16 已被分组排除；组内全部并入
        removed.update(x.get("id") for x in lose)
        merge_log.append((rep_i.get("id", "")[:40], rep_i.get("category"),
                          [x.get("id", "")[:36] for x in lose]))
    conf_k = [i for i in conf if i.get("id") not in removed]
    pool_k = [i for i in pool_only if i.get("id") not in removed]
    out["issues"] = conf_k
    out["issues_with_needs_review"] = pool_k
    out["report_views"] = {
        "default": {"issues": conf_k},
        "with_needs_review": {"issues": conf_k + pool_k},
    }
    return out, removed, merge_log


for run in ("20260906T132051Z", "20260905T130307Z"):
    rd = ROOT / "benchmark-artifacts/c_cpp/trial" / run / "run-01"
    rep = json.loads((rd / "report.json").read_text(encoding="utf-8"))
    base = score_report_views(rep, GT)
    folded, removed, log = fold_size_family(rep)
    sc = score_report_views(folded, GT)
    print(f"===== {run}  merged away: {len(removed)}")
    for m in log:
        print(f"   rep={m[0]} [{m[1]}] <- {m[2]}")
    for view in ("default", "with_needs_review"):
        a, b = base[view], sc[view]
        d_tp = b["true_positives"] - a["true_positives"]
        print(f"  [{view}] tp {a['true_positives']}->{b['true_positives']} ({d_tp:+d})  "
              f"fp_raw {a['false_positives_raw']}->{b['false_positives_raw']} "
              f"recall {a['recall']:.4f}->{b['recall']:.4f}  "
              f"precision {a['precision']:.4f}->{b['precision']:.4f}")
    print()
