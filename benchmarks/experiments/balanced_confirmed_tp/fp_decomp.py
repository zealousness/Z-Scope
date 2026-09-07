import json, collections
from pathlib import Path

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
d = json.loads((ROOT / "benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01/score.json").read_text())
rep = json.loads((ROOT / "benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01/report.json").read_text())
issues = rep.get("issues", [])
conf_ids = {i.get("id") for i in issues}
pool = [i for i in rep.get("issues_with_needs_review", []) if i.get("id") not in conf_ids]

# 1) 确认层 16 个 raw FP 的 duplicate 判定依据
audit = d.get("false_positive_audit") or {}
print("audit keys:", list(audit.keys())[:8] if isinstance(audit, dict) else type(audit))
dups = audit.get("duplicate_of_matched_records") or []
print("confirmed duplicate records:", len(dups))
reasons = collections.Counter()
for r in dups[:20]:
    if isinstance(r, dict):
        reasons[str(r.get("reason") or r.get("basis") or r.get("match_reason") or "?")[:60]] += 1
print("reason sample:", dict(reasons))
if dups and isinstance(dups[0], dict):
    print("one record:", json.dumps(dups[0], ensure_ascii=False)[:300])

# 2) with_needs_review 视图的 6 个有效 FP
rv = (d.get("report_views") or {}).get("with_needs_review") or {}
fp_eff = rv.get("false_positive_issue_records") or rv.get("false_positive_issue_identities") or []
print("\nwith_needs_review effective FP records:", len(fp_eff))
for r in (fp_eff if isinstance(fp_eff, list) else [])[:10]:
    if isinstance(r, dict):
        iid = str(r.get("issue_identity") or "")[:110]
        print("  FP:", iid)

# 3) 池内 96 duplicate 的折叠结构（按 rule+function 聚类看最大簇）
dups_idx = set()
matched_idx = set(d.get("matched_issue_indices") or [])
# 用 root_cause 维度近似折叠簇：pool + confirmed 按 (file,function,category) 分组
groups = collections.Counter()
for i in pool:
    groups[(i.get("rule_engine"), i.get("category"), i.get("function"))] += 1
multi = {k: v for k, v in groups.items() if v >= 3}
print("\npool clusters >=3 (engine,category,function):")
for k, v in sorted(multi.items(), key=lambda kv: -kv[1])[:14]:
    print(f"   {v}x  {k}")
print("pool total:", len(pool), "| clusters>=3 cover:", sum(multi.values()))
