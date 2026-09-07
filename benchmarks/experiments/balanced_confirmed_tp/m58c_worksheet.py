import json, sys, re, collections
from pathlib import Path

sys.path.insert(0, ".")
from zscope.benchmarking.protocol import issue_identity

WS = Path("/tmp/cp_ws/scan-input")
GT = json.loads(Path("test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))
vulns = GT["vulnerabilities"]

d = json.loads(Path("benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01/score.v2.json").read_text(encoding="utf-8"))["default"]
rep = json.loads(Path("benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01/report.json").read_text(encoding="utf-8"))
issues = rep["issues"]

# v2 确认层 TP 的 (file,function) 集合 —— 同站点多框架判定用
matched_idx = set(d.get("matched_issue_indices") or [])
tp_sites = set()
for n, i in enumerate(issues):
    if n in matched_idx:
        tp_sites.add((i.get("file") or "", i.get("function") or ""))

def line_of(i):
    loc = str(i.get("location") or "")
    try:
        return int(str(loc.split(":")[1]))
    except Exception:
        return int(i.get("line") or 0)

def code_context(i, width=4):
    rel = str(i.get("location") or "").split(":")[0]
    ln = line_of(i)
    f = WS / rel
    try:
        lines = f.read_text(errors="ignore").splitlines()
    except OSError:
        return "(workspace 文件不可读)"
    lo, hi = max(0, ln - 1 - width), min(len(lines), ln + width)
    out = [f"{n+1}: {lines[n]}" for n in range(lo, hi)]
    mark = ln
    return "\n".join(("  >> " if (n+1) == mark else "     ") + l for n, l in
                     [(n, out[n-lo]) for n in range(lo, hi)]) if out else "(空)"

# 建议 disposition 规则（可复核，非最终裁定）
def suggest(i, has_proof, proof_kinds, is_wrapper, tp_sibling):
    if is_wrapper:
        return ("design_exemption", "包装/基础设施站点（utils.c/_safe_*），真值集刻意不登记；对应 M5-8b 降级或豁免清单")
    if tp_sibling:
        return ("m5_8a_merge", "与已匹配 TP 同位点同机制家族的多框架重复 → 按 M5-8a 并入代表，不作为独立 FP 治理")
    if has_proof:
        return ("truth_gap(候选)", "确定性证明 + 模型 双方一致确认，最可能是真值遗漏 → 人工复核后走 truth 扩充")
    return ("model_error(待复核)", "无确定性佐证；需人工复核确认理由是否成立（若成立转 truth_gap 候选）")

rows = []
for r in d.get("false_positive_issue_records") or []:
    ident = str(r.get("identity") or "")
    issue = None
    for i in issues:
        try:
            if issue_identity(i) == ident:
                issue = i
                break
        except Exception:
            pass
    if issue is None:
        # 退化：按 category+function 匹配
        parts = ident.split("|")
        for i in issues:
            if i.get("category") == parts[1] and i.get("function") == parts[3]:
                issue = i
                break
    if issue is None:
        rows.append({"ident": ident, "suggest": ("未回连", "identity 无法回连 report 条目")})
        continue
    proofs = [p for p in (issue.get("deterministic_proofs") or []) if isinstance(p, dict) and p.get("outcome") == "confirm"]
    proof_kinds = [str(p.get("proof_kind")) for p in proofs]
    filef = str(issue.get("file") or issue.get("file_path") or "")
    func = str(issue.get("function") or "")
    is_wrapper = filef.endswith("utils.c") and func.startswith("_safe_")
    tp_sibling = (filef, func) in tp_sites
    sugg, why = suggest(issue, bool(proofs), proof_kinds, is_wrapper, tp_sibling)
    # truth 邻近检查：同函数的 truth
    near_truths = [v["id"] for v in vulns if v.get("function") == func]
    rows.append({
        "ident": ident, "issue": issue, "suggest": (sugg, why),
        "proofs": proof_kinds, "near_truths": near_truths,
    })

rows.sort(key=lambda r: (r["suggest"][0], r.get("issue", {}).get("category") or "", r.get("issue", {}).get("function") or ""))

# 汇总表
lines = []
lines.append("# M5-8c 复核工作表 — 21 个有效 FP（v2 口径，守卫 run 20260906T132051Z）")
lines.append("")
lines.append("disposition 三选一：`truth_gap`（真缺陷，走真值扩充）/ `design_exemption`（故意不计分，进豁免清单）/ `model_error`（留 FP，回 validation 修复）。")
lines.append("`m5_8a_merge` = 由 M5-8a 合并消化，不属于治理对象。")
lines.append("")
counts = collections.Counter(r["suggest"][0] for r in rows)
lines.append("## 汇总（按建议 disposition）")
lines.append("")
lines.append("| # | 建议 disposition | 条目 |")
lines.append("|---|---|---|")
for k, v in counts.most_common():
    lines.append(f"| | **{k}** | **{v}** |")
lines.append("")
lines.append("| # | id | 类别 | 位点 | DL | 确定性证明 | 建议 disposition |")
lines.append("|---|---|---|---|---|---|---|")
for n, r in enumerate(rows, 1):
    i = r.get("issue") or {}
    lines.append(f"| {n} | {str(i.get('id','?'))[:36]} | {i.get('category','?')} | "
                 f"{str(i.get('location','?')).split('/')[-1]} | {str((i.get('attribution') or {}).get('decision_level','?'))} | "
                 f"{', '.join(r.get('proofs') or ['-'])[:44]} | {r['suggest'][0]} |")
lines.append("")

# 明细
lines.append("## 逐条明细")
lines.append("")
for n, r in enumerate(rows, 1):
    i = r.get("issue") or {}
    if not i:
        lines.append(f"### {n}. {r['ident'][:60]}\n\n- 未回连\n")
        continue
    proofs = i.get("deterministic_proofs") or []
    proof_txt = "; ".join(
        f"{p.get('proof_kind')}({str(p.get('summary') or p.get('contradiction_or_obligation') or '')[:60]})"
        for p in proofs if isinstance(p, dict)) or "无"
    near = r.get("near_truths") or []
    lines.append(f"### {n}. {i.get('id')}  —  建议: {r['suggest'][0]}")
    lines.append("")
    lines.append(f"- **identity**: `{r['ident'][:120]}`")
    lines.append(f"- **类别/规则**: {i.get('category')} / {i.get('rule')}")
    lines.append(f"- **位点**: {i.get('location')}  (function: {i.get('function')})  decision_level: "
                 f"{(i.get('attribution') or {}).get('decision_level')}")
    lines.append(f"- **source**: {str(i.get('source'))[:90]}")
    lines.append(f"- **sink**: {str(i.get('sink'))[:90]}")
    lines.append(f"- **确定性证明**: {proof_txt}")
    lines.append(f"- **同函数 truth**: {', '.join(near) if near else '无'}")
    lines.append(f"- **同函数已匹配 TP**: {'是（多框架重复）' if (i.get('file') or '', i.get('function') or '') in tp_sites else '否'}")
    lines.append(f"- **建议理由**: {r['suggest'][1]}")
    lines.append("- **确认理由（模型）**:")
    reasoning = str(i.get("validation_reasoning") or "").strip().replace("\n", " ")
    lines.append(f"  > {reasoning[:420]}{'…' if len(reasoning) > 420 else ''}")
    lines.append("- **代码上下文**:")
    lines.append("```c")
    lines.append(code_context(i))
    lines.append("```")
    lines.append("")

out = Path("benchmarks/experiments/balanced_confirmed_tp/m5_8c_review_worksheet.md")
out.write_text("\n".join(lines), encoding="utf-8")
print(f"worksheet written: {out} ({len(rows)} items)")
print("disposition 分布:", dict(counts.most_common()))
