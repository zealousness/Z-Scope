import json
from pathlib import Path

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
for run in ("20260906T132051Z", "20260905T130307Z"):
    d = json.loads((ROOT / f"benchmark-artifacts/c_cpp/trial/{run}/run-01/score.v2.json").read_text(encoding="utf-8"))
    print("==", run)
    for view in ("default", "with_needs_review"):
        s = d[view]
        audit = (s.get("false_positive_audit") or {}).get("counts") or {}
        tp, raw, eff = s["true_positives"], s["false_positives_raw"], s["false_positives"]
        raw_prec = tp / (tp + raw) if tp + raw else 0
        print("  [{view}] tp={tp} fp_raw={raw} fp_eff={eff} recall={r:.4f} precision_raw={pr:.4f} precision_eff={pe:.4f}".format(
            view=view, tp=tp, raw=raw, eff=eff, r=s["recall"], pr=raw_prec, pe=s["precision"]))
        print("      audit:", json.dumps(audit, ensure_ascii=False))
