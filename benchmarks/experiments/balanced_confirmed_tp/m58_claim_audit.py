"""M5-8: V3 claim-audit offline calculation.

Measures deterministic (answer-free) audit signals over every V3-confirmed
issue and builds contingency tables TP/FP per candidate gate:
  S1  corroboration: any deterministic confirm proof record attached
  S2  memory_leak: in-function free of the sink object token (M3' predicate)
  S3  memory_leak: same-file free of the sink object token
  S4  size family: confirmation cites a concrete bound (MAX_/sizeof/min(...)
  S5  memory_leak: escape narrative in reasoning (registry/field store)
Gates are "demote to review when signal fires" policies.
"""
import json, re, sys, collections
from pathlib import Path

sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
from zscope.benchmarking.protocol import issue_match_detail
from zscope.core.validation.evidence_completion import EvidenceCompletionQueue

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
WS = Path("/tmp/cp_ws/scan-input")  # clang-bound workspace (fixture copy)
GU = EvidenceCompletionQueue._infunction_release_contradiction
ESCAPE = re.compile(r"registry|全局|存入|插入|insert|挂到|链入|登记|slot|hash|哈希|map\b|->next", re.I)
BOUND = re.compile(r"MAX_|sizeof|上限|bound|clip|clamp|\bmin\(|截断|capped|不超过|limit", re.I)


def fk(p):
    return str(p).replace("\\", "/").split("/")[-1]


def body_span(path, func, near):
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except OSError:
        return ""
    pat = re.compile(r"^[A-Za-z_][\w \t\*]*\b(\w+)\s*\([^;]*\)\s*\{?\s*$")
    start = None
    for idx in range(max(0, near - 500), min(len(lines), near + 5)):
        m = pat.match(lines[idx])
        if m and m.group(1) == func:
            start = idx
            break
    if start is None:
        return ""
    depth = 0
    begun = False
    for end in range(start, min(len(lines), start + 500)):
        depth += lines[end].count("{") - lines[end].count("}")
        if "{" in lines[end]:
            begun = True
        if begun and depth <= 0:
            return "\n".join(lines[start:end + 1])
    return "\n".join(lines[start:start + 500])


def load(run):
    rd = ROOT / "benchmark-artifacts/c_cpp/trial" / run / "run-01"
    d = json.loads((rd / "score.json").read_text())
    rep = json.loads((rd / "report.json").read_text())
    return d, rep


def evaluate(run, workspace):
    d, rep = load(run)
    issues = rep["issues"]
    matched_idx = {p["issue_index"] for p in d.get("matched_pairs", [])}
    matched = {p["truth_id"] for p in d.get("matched_pairs", [])}
    vulns = json.loads((ROOT / "test/range/benchmark/ground_truth.json").read_text())["vulnerabilities"]
    rows = []
    for n, i in enumerate(issues):
        if str((i.get("attribution") or {}).get("decision_level")) != "V3":
            continue
        is_tp = n in matched_idx
        cat = i.get("category")
        proofs = i.get("deterministic_proofs") or []
        s1 = any(isinstance(p, dict) and p.get("outcome") == "confirm" for p in proofs)
        text = str(i.get("validation_reasoning") or "")
        func = i.get("function")
        rel = str(i.get("location") or "").split(":")[0]
        line_no = int(str(i.get("line") or 0) or 0)
        body = body_span(workspace / rel, func, line_no) if rel else ""
        s2 = s3 = s5 = False
        if cat == "memory_leak":
            whole = ""
            fp = workspace / rel
            try:
                whole = fp.read_text(errors="ignore")
            except OSError:
                pass
            if body:
                s2 = GU(str(i.get("sink") or ""), body)
            snk = str(i.get("sink") or "")
            tok = re.findall(r"\b[A-Za-z_]\w*\b", snk)
            s3 = bool(whole) and any(
                re.search(r"\b(?:SAFE_FREE|free)\s*\(\s*[^)]*\b" + re.escape(t) + r"\b", whole)
                for t in tok
            )
            s5 = bool(ESCAPE.search(text))
        s4 = bool(BOUND.search(text)) if cat in {
            "resource_allocation_without_limits", "integer_overflow", "unchecked_allocation"
        } else None
        rows.append({"id": i["id"], "cat": cat, "func": func, "tp": is_tp,
                     "s1": s1, "s2": s2, "s3": s3, "s4": s4, "s5": s5})
    return rows


def contingency(rows, sig_filter, label):
    hit_tp = hit_fp = miss_tp = miss_fp = 0
    for r in rows:
        fire = sig_filter(r)
        if fire:
            if r["tp"]:
                hit_tp += 1
            else:
                hit_fp += 1
        else:
            if r["tp"]:
                miss_tp += 1
            else:
                miss_fp += 1
    print(f"  {label}: fire TP={hit_tp} FP={hit_fp} | pass TP={miss_tp} FP={miss_fp} "
          f"=> FP捕获 {hit_fp}/{hit_fp+miss_fp}, TP误伤 {hit_tp}")


for run, ws in (("20260905T130307Z", WS), ("20260906T132051Z", WS)):
    rows = evaluate(run, ws)
    tp = sum(1 for r in rows if r["tp"])
    fp = len(rows) - tp
    print(f"===== {run}: V3-confirmed n={len(rows)} (TP={tp} FP={fp})")
    contingency(rows, lambda r: r["s1"], "S1 无确定性佐证证明")
    contingency(rows, lambda r: r["cat"] == "memory_leak" and r["s2"], "S2 ml+函数体内自相矛盾释放")
    contingency(rows, lambda r: r["cat"] == "memory_leak" and r["s3"], "S3 ml+同文件存在 free")
    contingency(rows, lambda r: r["cat"] == "memory_leak" and r["s5"], "S5 ml+逃逸叙事")
    contingency(rows, lambda r: r["s4"] is False, "S4 尺寸族+确认未引用 bound")
    # 组合门：ml 走 S2，尺寸族走 S4
    contingency(rows, lambda r: (r["cat"] == "memory_leak" and r["s2"]) or (r["s4"] is False),
                "组合门 G1 (S2 ∪ S4)")
    # 组合门 G2: ml 的 S2+S3 双条件
    contingency(rows, lambda r: (r["cat"] == "memory_leak" and (r["s2"] or r["s3"])) or (r["s4"] is False),
                "组合门 G2 (S2∪S3 ∪ S4)")
    print()
