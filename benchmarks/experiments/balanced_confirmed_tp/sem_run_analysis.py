"""语义建模强化版 benchmark 分析：tokens 归因 / TP-FP 归因 / 双视图评分。
用法: python3 sem_run_analysis.py <trial_run_dir>
"""
import json, sys, collections
from pathlib import Path
sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
from zscope.benchmarking.protocol import score_report_views

d = Path(sys.argv[1])
rep = json.loads((d / "report.json").read_text(encoding="utf-8"))
gt = json.loads(Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope/test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))
views = score_report_views(rep, gt)
vmap = {v["id"]: v for v in gt["vulnerabilities"]}

print("=" * 70)
print("③ 双视图评分 (v2)")
for vname in ("default", "with_needs_review"):
    sc = views[vname]
    print(f"  {vname}: tp={sc['true_positives']} fp_raw={sc['false_positives_raw']} "
          f"recall={sc['recall']:.4f} precision={sc['precision']:.4f}")

print("=" * 70)
print("① tokens 归因")
evfile = d / "llm_usage_events.jsonl"
agg = collections.Counter()
kind_by_agent = collections.defaultdict(collections.Counter)
if evfile.exists():
    for line in evfile.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        att = e.get("attribution") or {}
        agent = str(att.get("agent") or e.get("agent") or "unknown")
        kind = str(e.get("call_kind") or att.get("call_kind") or "unknown")
        toks = 0
        u = e.get("usage")
        if isinstance(u, dict):
            toks = int(u.get("total_tokens") or 0)
        toks = toks or int(e.get("tokens") or e.get("total_tokens") or 0)
        agg[agent] += toks
        kind_by_agent[agent][kind] += toks
    print("  按 Agent:")
    for a, t in agg.most_common():
        print(f"    {a}: {t:,} tokens | kinds: {dict(kind_by_agent[a])}")
else:
    print("  llm_usage_events.jsonl 不存在")
usage = (rep.get("metadata") or {}).get("llm_usage") or (rep.get("summary") or {}).get("llm_usage") or {}
stages = ((usage.get("scan_token_usage") or {}).get("stages") or {}) or (usage.get("stages") or {})
if stages:
    print("  stage 汇总:")
    for k, v in stages.items():
        print(f"    {k}: {json.dumps(v, ensure_ascii=False)[:90]}")

print("=" * 70)
print("② TP/FP 归因")
confirmed = rep.get("issues", [])
pool = [i for i in rep.get("issues_with_needs_review", [])
        if i.get("id") not in {x.get("id") for x in confirmed}]
all_items = confirmed + pool
# 1) 可疑点来源候选（candidate_priority_group == semantic_suspicious_point）
susp = [i for i in all_items if (i.get("candidate_priority_group") or "") == "semantic_suspicious_point"]
print(f"  语义建模可疑点候选: {len(susp)} 条（确认 {sum(1 for i in susp if i in confirmed)} / 复核 {len(susp)-sum(1 for i in susp if i in confirmed)}）")
# 配对：matched 视图下这些候选的 truth 配对
mp = views["default"].get("matched_pairs", [])
mpi = views["with_needs_review"].get("matched_pairs", [])
truth_ids_default = {p.get("truth_id") for p in mp}
susp_tp_default = set()
for p in mp:
    idx = int(p.get("issue_index") or -1)
    if 0 <= idx < len(confirmed) and (confirmed[idx].get("candidate_priority_group") or "") == "semantic_suspicious_point":
        susp_tp_default.add(p.get("truth_id"))
print(f"  其中确认层 TP（truth 配对）: {len(susp_tp_default)} -> {sorted(susp_tp_default)[:8]}")
susp_fp = [i for i in susp if i.get("id") not in truth_ids_default]
fp_ids = views["default"].get("false_positive_ids") or set()
susp_fp_confirmed = [i.get("id") for i in susp if i in confirmed and i.get("id") in fp_ids]
print(f"  其中确认层 FP: {len(susp_fp_confirmed)}")
print("  可疑点候选的类别分布:", dict(collections.Counter(i.get("category") for i in susp).most_common(8)))
print("  可疑点候选的规则分布:", dict(collections.Counter(str(i.get("rule"))[:40] for i in susp).most_common(6)))

# 2) 自定义资源接口/宏/锁的识别与配对
wrappers = ("_safe_malloc", "_safe_calloc", "_safe_realloc", "_str_dup", "_str_copy_wrapper",
            "SAFE_FREE", "LOCK(", "UNLOCK(", "_lock_wrapper", "_unlock_wrapper", "g_runtime_",
            "fd_alloc", "_file_open", "_file_close")
wr = collections.Counter()
wr_items = []
for i in all_items:
    txt = json.dumps(i, ensure_ascii=False)
    hit = [w for w in wrappers if w in txt]
    for w in hit:
        wr[w] += 1
    if hit:
        wr_items.append(i)
print(f"  涉及自定义接口/宏/锁的条目: {len(wr_items)}")
print("  wrapper 命中分布:", dict(wr.most_common(12)))
# wrapper 条目与 truth 的配对正确性（d<=8 同函数类别家族）
import re as _re
def catset(i):
    return str(i.get("category") or "").lower()
wr_tp = []
for p in mpi:
    idx = int(p.get("issue_index") or -1)
    if 0 <= idx < len(all_items) and all_items[idx] in wr_items:
        wr_tp.append((p.get("truth_id"), all_items[idx].get("category"), all_items[idx].get("function")))
print(f"  wrapper 条目中的 truth 配对: {len(wr_tp)} -> {sorted(set(t for t,_,_ in wr_tp))[:10]}")

# 3) 验证 Agent 各特性的 TP/FP
print("  验证特性标记统计（确认+复核）:")
feat = collections.Counter()
for key in ("validation_uncertain_replay_review", "validation_demote_source_lifecycle_confirm",
            "validation_obligation_infunction_release_guard", "validation_checked_proofs",
            "validation_positive_case", "validation_related_findings", "validation_review_checkpoint"):
    for i in all_items:
        if i.get(key) not in (None, False):
            feat[key] += 1
print("   ", dict(feat))
# 特性相关的 TP/FP（标记 item 是否配对 truth）
def matched_truth_ids(issue_id, pairs, view_items):
    return {p.get("truth_id") for p in pairs
            if 0 <= int(p.get("issue_index") or -1) < len(view_items)
            and view_items[int(p.get("issue_index"))].get("id") == issue_id}
for key in ("validation_uncertain_replay_review", "validation_demote_source_lifecycle_confirm",
            "validation_obligation_infunction_release_guard", "validation_checked_proofs"):
    feats = [i for i in all_items if i.get(key) not in (None, False)]
    tp = 0
    for i in feats:
        if i in confirmed:
            tp += 1 if matched_truth_ids(i.get("id"), mp, confirmed) else 0
        else:
            tp += 1 if matched_truth_ids(i.get("id"), mpi, all_items) else 0
    print(f"    {key}: items={len(feats)} truth配对={tp}")

# 4) 验证 Agent 归因（validator_llm 决策的 TP/FP）
att = (rep.get("metadata") or {}).get("candidate_funnel") or {}
att2 = (att.get("canonical_group_attribution") or {})
print("  funnel 归因 by_discovery_and_decision:", json.dumps(att2.get("by_discovery_and_decision"), ensure_ascii=False)[:400])
print("  funnel 归因 by_discovery:", json.dumps(att2.get("by_discovery"), ensure_ascii=False)[:200])
print("  funnel 归因 exclusive_by_discovery:", json.dumps(att2.get("exclusive_by_discovery"), ensure_ascii=False)[:200])
