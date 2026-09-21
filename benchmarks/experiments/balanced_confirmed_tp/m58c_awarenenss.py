import json, sys
from pathlib import Path
B = Path("C:/Users/10273/home/work/Z-Scope")
sys.path.insert(0, str(B))
from zscope.benchmarking import protocol as BP
A = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
nd = A / "benchmark-artifacts/c_cpp/trial/20260908T055018Z/run-01"
gd = A / "benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01"
repn = json.loads((nd / "report.json").read_text(encoding="utf-8"))
repg = json.loads((gd / "report.json").read_text(encoding="utf-8"))
gv = json.loads((gd / "score.v2.json").read_text(encoding="utf-8"))["default"]
gt = json.loads((A / "test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))
vmap = {v["id"]: v for v in gt["vulnerabilities"]}
issues_n = repn["issues"] + [i for i in repn.get("issues_with_needs_review", [])
                             if i.get("id") not in {x.get("id") for x in repn["issues"]}]

targets = {
    "REAL-003": {"truth_cat": "double_free", "func": "_runtime_apply_component_stage"},
    "ISSUE42-023": {"truth_cat": "toctou", "func": "_runtime_map_linked_segment"},
    "REAL-023": {"truth_cat": "missing_unlock", "func": "_runtime_link_allocated_node"},
}
for tid, meta in targets.items():
    v = vmap[tid]
    print(f"================ {tid} [{v.get('category')}] {v.get('file')}:{v.get('function')}:{v.get('line')}-{v.get('end_line')}")
    print(f"   truth 描述: {str(v.get('description'))[:150]}")
    # 新 run 同函数条目
    for i in issues_n:
        if i.get("function") != meta["func"]:
            continue
        dl = str((i.get("attribution") or {}).get("decision_level"))
        print(f"\n  [new] {i.get('id','')[:40]} cat={i.get('category')} cwe={i.get('cwe')} dl={dl} "
              f"disp={i.get('candidate_disposition')}")
        print(f"    sink: {str(i.get('sink'))[:90]}")
        pe = i.get("positive_evidence") or []
        for e in pe[:3]:
            print(f"    +证据: {str(e)[:110]}")
        ne = i.get("negative_evidence") or []
        for e in ne[:2]:
            print(f"    -证据: {str(e)[:110]}")
        print(f"    理由: {str(i.get('validation_reasoning'))[:360]}")
    # guards run 该 truth 的配对条目（旧匹配用的框架）
    pair = next((p for p in gv.get("matched_pairs", []) if p["truth_id"] == tid), None)
    if pair:
        gi = (rep_g["issues"] + [i for i in rep_g.get("issues_with_needs_review", [])
                                if i.get("id") not in {x.get("id") for x in rep_g["issues"]}])[pair["issue_index"]] \
            if pair["issue_index"] < len(rep_g["issues"]) else None
        # guards matched_pairs 的 issue_index 指向 issues[]（default view）——direct
        gi = rep_g["issues"][pair["issue_index"]]
        print(f"\n  [guards 配对框架] {gi.get('id','')[:40]} cat={gi.get('category')} cwe={gi.get('cwe')} "
              f"rule={str(gi.get('rule'))[:48]}")
        print(f"    sink: {str(gi.get('sink'))[:90]}")
    print()
