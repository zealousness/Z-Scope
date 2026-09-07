import json, sys, copy
from pathlib import Path

sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
from zscope.benchmarking.protocol import score_report_views
from zscope.common.issue_identity import deduplicate_issues

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
GT = json.loads((ROOT / "test/range/benchmark/ground_truth.json").read_text())

for run in ("20260905T130307Z", "20260906T132051Z"):
    rd = ROOT / "benchmark-artifacts/c_cpp/trial" / run / "run-01"
    rep = json.loads((rd / "report.json").read_text())
    base = score_report_views(rep, GT)
    b = base["default"]
    print(f"===== {run}  baseline: tp={b['true_positives']} fp_raw={b['false_positives_raw']} "
          f"recall={b['recall']:.4f}")
    items = list(rep.get("issues", [])) + [
        i for i in rep.get("issues_with_needs_review", [])
        if i.get("id") not in {x.get("id") for x in rep.get("issues", [])}
    ]
    for label in ("unconditional site-aware dedup",):
        redone = deduplicate_issues([copy.deepcopy(i) for i in items])
        groups = {}
        for i in redone:
            groups.setdefault(i.get("dedup_key"), []).append(i)
        keep = {
            max(g, key=lambda x: (float(x.get("final_score") or 0), str(x.get("id")))).get("id")
            for g in groups.values()
        }
        conf_ids = {x.get("id") for x in rep.get("issues", [])}
        conf_k = [i for i in redone if i.get("id") in keep and i.get("id") in conf_ids]
        pool_k = [i for i in redone if i.get("id") in keep and i.get("id") not in conf_ids]
        out = copy.deepcopy(rep)
        out["issues"] = conf_k
        out["issues_with_needs_review"] = pool_k
        out["report_views"] = {
            "default": {"issues": conf_k},
            "with_needs_review": {"issues": conf_k + pool_k},
        }
        sc = score_report_views(out, GT)
        s1, sw = sc["default"], sc["with_needs_review"]
        d_tp = s1["true_positives"] - b["true_positives"]
        d_wr = sw["true_positives"] - base["with_needs_review"]["true_positives"]
        print(f"  {label}: items {len(items)}->{len(redone)} | "
              f"confirmed tp {b['true_positives']}->{s1['true_positives']} ({d_tp:+d}) "
              f"recall {b['recall']:.4f}->{s1['recall']:.4f} | "
              f"merged tp {base['with_needs_review']['true_positives']}->"
              f"{sw['true_positives']} ({d_wr:+d})")
    print()
