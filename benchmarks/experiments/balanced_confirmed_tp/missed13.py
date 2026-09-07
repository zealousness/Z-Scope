import json, sys, collections
from pathlib import Path

sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
from zscope.benchmarking.protocol import (
    issue_match_detail,
    _structured_category_match_reason,
    _issue_structured_anchors,
    _truth_structured_anchors,
)

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")


def line_of(i):
    loc = str(i.get("location") or "")
    try:
        return int(str(loc.split(":")[1]))
    except Exception:
        return 0


def analyse(run):
    rd = ROOT / "benchmark-artifacts/c_cpp/trial" / run / "run-01"
    sc = json.loads((rd / "score.v2.json").read_text(encoding="utf-8"))
    rep = json.loads((rd / "report.json").read_text(encoding="utf-8"))
    gt = json.loads((ROOT / "test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))
    vmap = {v["id"]: v for v in gt["vulnerabilities"]}
    issues = rep.get("issues", [])
    conf_ids = {i.get("id") for i in issues}
    pool = [i for i in rep.get("issues_with_needs_review", []) if i.get("id") not in conf_ids]
    all_items = issues + pool
    missed = sc["with_needs_review"].get("missed") or []
    print(f"===== {run}: missed={len(missed)}")
    buckets = collections.Counter()
    rows = []
    for tid in missed:
        v = vmap[tid]
        same_func = [i for i in all_items if i.get("function") == v.get("function")]
        same_file = [i for i in all_items
                     if str(i.get("location") or "").split(":")[0] == str(v.get("file"))]
        # 严格可配但被一对一占用？
        strict_pair = [i for i in all_items if issue_match_detail(i, v, 8) is not None]
        if strict_pair:
            stage = "strict-match-but-one-to-one-taken"
            nearest, dist, sub = strict_pair[0], 0, strict_pair[0].get("needs_review_sub_state")
        elif not same_file:
            stage = "no-candidate-in-file"
            nearest, dist, sub = None, None, None
        elif not same_func:
            stage = "same-file-diff-function"
            nearest = min(same_file, key=lambda i: abs(line_of(i) - int(v.get("line") or 0))) if same_file else None
            dist = abs(line_of(nearest) - int(v.get("line") or 0)) if nearest else None
            sub = nearest.get("needs_review_sub_state") or (nearest.get("attribution") or {}).get("decision_level")
        else:
            # 同函数有候选：找失败阶段
            cat_ok = any(_structured_category_match_reason(i, v) for i in same_func)
            if not cat_ok:
                stage = "same-func-category-mismatch"
            else:
                # 类别可配：行区间不相交
                ia = _issue_structured_anchors(same_func[0])
                ta = _truth_structured_anchors(v)
                stage = "same-func-line-no-overlap"
            nearest = min(same_func, key=lambda i: abs(line_of(i) - int(v.get("line") or 0)))
            dist = abs(line_of(nearest) - int(v.get("line") or 0))
            sub = nearest.get("needs_review_sub_state") or (nearest.get("attribution") or {}).get("decision_level")
        buckets[stage] += 1
        rows.append((tid, v, stage, nearest, dist, sub))
    for k, n in buckets.most_common():
        print(f"  {k}: {n}")
    for tid, v, stage, nearest, dist, sub in rows:
        print(f"  {tid} [{v.get('category')}] {v.get('function')}:{v.get('line')}-{v.get('end_line')}")
        print(f"      {stage}" + (f" | nearest: {str(nearest.get('id'))[:36]} [{nearest.get('category')}] "
                                    f"L{line_of(nearest)} d={dist} state={sub}" if nearest is not None else ""))
    return set(missed)


m2 = analyse("20260905T130307Z")
m3 = analyse("20260906T132051Z")
print(f"\nR2 missed={len(m2)}  guards missed={len(m3)}")
print(f"  两轮共同(结构性): {sorted(m2 & m3)}")
print(f"  守卫 run 新增: {sorted(m3 - m2)}")
print(f"  守卫 run 修复: {sorted(m2 - m3)}")
