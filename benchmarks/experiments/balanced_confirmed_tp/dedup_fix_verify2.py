import json, sys
from pathlib import Path

sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
from zscope.common.issue_identity import _same_defect_site

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")

for run, truths in (("20260905T130307Z", None), ("20260906T132051Z", ["ISSUE42-025", "REAL-003", "REAL-019"])):
    rd = ROOT / "benchmark-artifacts/c_cpp/trial" / run / "run-01"
    d = json.loads((rd / "score.json").read_text())
    rep = json.loads((rd / "report.json").read_text())
    issues = rep.get("issues", [])
    nr = rep.get("issues_with_needs_review", [])
    conf_ids = {i.get("id") for i in issues}
    pool = [i for i in nr if i.get("id") not in conf_ids]
    all_items = {i.get("id"): i for i in issues + nr}
    print(f"===== {run}")
    targets = truths if truths else [p["truth_id"] for p in d.get("matched_pairs", [])]
    for tid in targets:
        pair = next((p for p in d.get("matched_pairs", []) if p["truth_id"] == tid), None)
        if not pair:
            continue
        tp = issues[pair["issue_index"]]
        key = tp.get("dedup_key")
        if not key:
            continue
        sibs = [i for i in issues + nr if i.get("dedup_key") == key and i.get("id") != tp.get("id")]
        if not sibs:
            continue
        would_split = [s for s in sibs if not _same_defect_site(tp, s)]
        print(f"  {tid}: TP={tp.get('id','')[:36]} L{tp.get('line') or tp.get('location')}")
        print(f"    group size={1+len(sibs)}  site-aware would split off {len(would_split)} sibling(s)")
        for s in sibs[:3]:
            print(f"      sib: {s.get('id','')[:36]} L{s.get('line') or s.get('location')} "
                  f"cat={s.get('category')} same_site={_same_defect_site(tp, s)} "
                  f"score={s.get('final_score')} tp_score={tp.get('final_score')}")
