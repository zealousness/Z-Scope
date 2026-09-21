"""语义建模强化版 benchmark（20260910T015537Z）——回退分解与疑点清单。
用法: python3 sem_regression_refine.py
"""
import json, sys, collections
from pathlib import Path
sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
from zscope.benchmarking.protocol import score_report_views

D = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope/benchmark-artifacts/c_cpp/trial/20260910T015537Z/run-01")
PREV = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope/benchmark-artifacts/c_cpp/trial/20260908T055018Z/run-01")
GT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope/test/range/benchmark/ground_truth.json")

rep = json.loads((D / "report.json").read_text(encoding="utf-8"))
gt = json.loads(GT.read_text(encoding="utf-8"))
vmap = {v["id"]: v for v in gt["vulnerabilities"]}
views = score_report_views(rep, gt)
conf = rep.get("issues", [])
pool = [i for i in rep.get("issues_with_needs_review", []) if i.get("id") not in {x.get("id") for x in conf}]
all_items = conf + pool

prev = json.loads((PREV / "score.v2.json").read_text(encoding="utf-8"))
prev_m = set(prev["with_needs_review"].get("matched") or [])
cur_m = set(views["with_needs_review"].get("matched") or [])
lost = sorted(prev_m - cur_m)
gained = sorted(cur_m - prev_m)
print(f"merged 丢失 {len(lost)}: {lost}")
print(f"merged 新增 {len(gained)}: {gained}")

print("\n丢失 truth 本轮候选状态（function | 同函数条目数 | 类别 | 是否有 semantic_snapshot）:")
rows = []
for tid in lost:
    v = vmap[tid]
    same = [i for i in all_items if i.get("function") == v.get("function")]
    snap = [i for i in same if (i.get("candidate_source") or "") == "semantic_snapshot"]
    cats = sorted({i.get("category") for i in same})
    rows.append((tid, v.get("category"), v.get("function"), len(same), len(snap), cats))
    print(f"  {tid:14} [{str(v.get('category')):26}] {v.get('file').split('/')[-1]}:{v.get('function')} "
          f"line={v.get('line')} 同函数={len(same)} snap={len(snap)} cats={cats[:5]}")

print("\nsemantic_snapshot 候选清单（id | category | function | verdict）:")
snap_all = [i for i in all_items if (i.get("candidate_source") or "") == "semantic_snapshot"]
for i in snap_all:
    disp = "confirmed" if i in conf else "pool"
    print(f"  {i.get('id','')[:44]:46} {str(i.get('category'))[:24]:26} "
          f"{str(i.get('function'))[:38]:40} {disp} dl={(i.get('attribution') or {}).get('decision_level')}")

print("\nscore.log 特性痕迹计数:")
sl = (D / "score.log").read_text(errors="ignore")
for pat in ("source_lifecycle", "infunction_release", "checked_proof", "replay_review", "uncertain", "suspicious"):
    print(f"  {pat}: {sl.lower().count(pat.lower())}")