"""语义建模候选（candidate_source=="semantic_snapshot"）的 TP/FP 归因。
用法: python3 sem_snapshot_attribution.py
"""
import json, sys, collections
from pathlib import Path
sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
from zscope.benchmarking.protocol import score_report_views

D = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope/benchmark-artifacts/c_cpp/trial/20260910T015537Z/run-01")
GT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope/test/range/benchmark/ground_truth.json")

rep = json.loads((D / "report.json").read_text(encoding="utf-8"))
gt = json.loads(GT.read_text(encoding="utf-8"))
views = score_report_views(rep, gt)
conf = rep.get("issues", [])
pool = [i for i in rep.get("issues_with_needs_review", []) if i.get("id") not in {x.get("id") for x in conf}]
all_items = conf + pool
mp = views["default"].get("matched_pairs", [])
mpi = views["with_needs_review"].get("matched_pairs", [])

def snap_tp(pairs, view):
    return {p.get("truth_id") for p in pairs
            if 0 <= int(p.get("issue_index") or -1) < len(view)
            and (view[int(p.get("issue_index"))].get("candidate_source") or "") == "semantic_snapshot"}

snap_all = [i for i in all_items if (i.get("candidate_source") or "") == "semantic_snapshot"]
print(f"semantic_snapshot: 全部 {len(snap_all)}（确认 {sum(1 for i in snap_all if i in conf)}）")
print(f"  确认层 TP: {len(snap_tp(mp, conf))}")
print(f"  合并层 TP: {len(snap_tp(mpi, all_items))}")
print(f"  类别: {dict(collections.Counter(i.get('category') for i in snap_all).most_common(10))}")
print(f"  确认 via: {dict(collections.Counter(str(i.get('confirmed_via')) for i in snap_all if i in conf))}")

# AST 可疑点预算路径（对照口径）
ast_susp = [i for i in all_items if (i.get("candidate_priority_group") or "") == "semantic_suspicious_point"]
def pgroup_tp(pairs, view):
    return {p.get("truth_id") for p in pairs
            if 0 <= int(p.get("issue_index") or -1) < len(view)
            and (view[int(p.get("issue_index"))].get("candidate_priority_group") or "") == "semantic_suspicious_point"}
print(f"\n对照口径 candidate_priority_group==semantic_suspicious_point: 全部 {len(ast_susp)}")
print(f"  确认层 TP: {len(pgroup_tp(mp, conf))} -> {sorted(pgroup_tp(mp, conf))}")
print(f"  确认层 FP: {sum(1 for i in ast_susp if i in conf) - len(pgroup_tp(mp, conf))}")