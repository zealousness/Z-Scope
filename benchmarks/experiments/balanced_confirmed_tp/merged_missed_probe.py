import json, sys, collections
from pathlib import Path
B = Path("C:/Users/10273/home/work/Z-Scope")
sys.path.insert(0, str(B))
from zscope.benchmarking import protocol as BP

A = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope") if Path("/mnt/c").exists() else Path("C:/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
d = A / "benchmark-artifacts/c_cpp/trial/20260908T055018Z/run-01"
v2 = json.loads((d / "score.v2.json").read_text(encoding="utf-8"))
wr = v2["with_needs_review"]
gt = json.loads((A / "test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))
vulns = gt["vulnerabilities"]
vmap = {v["id"]: v for v in vulns}
rep = json.loads((d / "report.json").read_text(encoding="utf-8"))
issues = rep["issues"]
conf_ids = {i.get("id") for i in issues}
pool = [i for i in rep.get("issues_with_needs_review", []) if i.get("id") not in conf_ids]
all_items = issues + pool

wr_matched = set(wr.get("matched") or [])
missed = [v["id"] for v in vulns if v["id"] not in wr_matched]
print(f"合并视图未挖掘 TP: {len(missed)} / 136 (matched {len(wr_matched)})\n")


def line_of(i):
    loc = str(i.get("location") or "")
    try:
        return int(str(loc.split(":")[1]))
    except Exception:
        return int(i.get("line") or 0)


def truth_range(v):
    try:
        return int(v.get("line")), int(v.get("end_line") or v.get("line"))
    except Exception:
        return None


cls = collections.Counter()
detail = []
for tid in missed:
    v = vmap[tid]
    tfunc = v.get("function")
    tfile = str(v.get("file") or "").split("/")[-1]
    tr = truth_range(v)
    # 同函数候选（任意框架，confirmed+pool）
    same_func = [i for i in all_items if i.get("function") == tfunc]
    # 同文件同函数的类别分布
    cats = sorted({i.get("category") for i in same_func})
    # 锚点行距：同函数候选里离 truth 区间最近的主行距
    best_d = None
    if tr and same_func:
        best_d = min(min(abs(line_of(i) - tr[0]), abs(line_of(i) - tr[1])) for i in same_func)
    # 宽松匹配测试（行容差放宽到 32）
    loose = [i for i in same_func if BP.issue_match_detail(i, v, 32) is not None]
    if not same_func:
        c = "NO_CANDIDATE_IN_FUNCTION"
        cls[c] += 1
    elif loose:
        c = "MATCHES_AT_LOOSE_32(容差敏感)"
        cls[c] += 1
    elif best_d is not None and best_d <= 32:
        c = "NEAR_SITE_ANCHOR_FAIL(±32内但结构化锚点失配)"
        cls[c] += 1
    else:
        c = f"SAME_FUNC_ONLY_FAR(最近行距={best_d})"
        cls[c] += 1
    detail.append((tid, v.get("category"), tfile, tfunc, v.get("line"), v.get("end_line"),
                   len(same_func), cats, best_d, c))

print("归因分布:")
for k, v in cls.most_common():
    print(f"  {k}: {v}")
print("\n逐条:")
for tid, cat, tfile, tfunc, tl, te, nc, cats, bd, c in detail:
    print(f"  {tid} [{cat}] {tfile}:{tfunc} truth行={tl}-{te}")
    print(f"    同函数候选={nc} 类别={cats} 最近行距={bd} => {c}")
