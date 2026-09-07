"""同类问题聚合方案实测：语义家族 × 站点身份 的双层聚合键。

Key  = (category_family,                       # L3 语义家族（跨类别桥梁）
        file, function,                        # L1 必要条件
        sink_operation_signature,              # L2 位点：操作 + 对象（归一化）
        line cluster: 单链聚类 gap<=8, 组内总跨度<=24)
跨函数流缺陷（race/lost_wakeup 等）: 用 call_path/端点 key 替代 function。
代表选择: 确定性证明 > 类别特异度 > final_score。
"""
import json, sys, copy, collections
from pathlib import Path

sys.path.insert(0, ".")
from zscope.benchmarking.protocol import score_report_views
from zscope.common.issue_identity import semantic_category_family, source_sink_location_issue_key

ROOT = Path(".")
GT = json.loads((ROOT / "test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))


def line_of(i):
    loc = str(i.get("location") or "")
    try:
        return int(str(loc.split(":")[1]))
    except Exception:
        return int(i.get("line") or 0)


def sink_sig(i):
    s = re.sub(r"\s+", " ", str(i.get("sink") or "")).strip().lower()
    return s[:64]


def flow_key(i):
    try:
        k = source_sink_location_issue_key(i)
        return k or ""
    except Exception:
        return ""


import re  # noqa: E402


def agg_key(i):
    fam = semantic_category_family(i.get("category"))
    filef = str(i.get("location") or "").split(":")[0]
    func = i.get("function")
    fk = flow_key(i)
    if fam in {"concurrency", "race", "synchronization"} or fk:
        # 跨函数流缺陷：端点流身份优先
        return (fam, fk or (filef, func))
    return (fam, filef, func, sink_sig(i), "L")


def cluster_lines(members, gap=8, span=24):
    """行单链聚类：gap 内合并，组内总跨度超限则拆分。"""
    items = sorted(members, key=lambda x: line_of(x))
    clusters = []
    cur = [items[0]]
    for it in items[1:]:
        if line_of(it) - line_of(cur[-1]) <= gap and line_of(it) - line_of(cur[0]) <= span:
            cur.append(it)
        else:
            clusters.append(cur)
            cur = [it]
    clusters.append(cur)
    return clusters


SPECIFIC = {"integer_overflow": 0, "unchecked_allocation": 1, "bounds": 1,
            "use_after_free": 0, "double_free": 0, "invalid_free": 1,
            "resource_allocation_without_limits": 2, "memory_leak": 1}


def rep_rank(i):
    return (0 if i.get("deterministic_proofs") else 1,
            SPECIFIC.get(i.get("category"), 5),
            -float(i.get("final_score") or 0))


def fold(rep):
    out = copy.deepcopy(rep)
    conf = out.get("issues", [])
    conf_ids = {i.get("id") for i in conf}
    pool_only = [i for i in out.get("issues_with_needs_review", []) if i.get("id") not in conf_ids]
    items = conf + pool_only
    groups = collections.defaultdict(list)
    for i in items:
        groups[agg_key(i)].append(i)
    keep, folded, examples = set(), 0, []
    for key, g in groups.items():
        if key[0] in {"concurrency", "race", "synchronization"} or len(key) == 2:
            # 流缺陷：同 flow key 整组合并
            clusters = [g]
        else:
            clusters = cluster_lines(g)
        for cl in clusters:
            best = max(cl, key=rep_rank)
            keep.add(best.get("id"))
            if len(cl) > 1:
                folded += len(cl) - 1
                if len(examples) < 12:
                    examples.append((best.get("id", "")[:36], best.get("category"),
                                     [(x.get("id", "")[:32], x.get("category")) for x in cl if x is not best]))
    conf_k = [i for i in conf if i.get("id") in keep]
    pool_k = [i for i in pool_only if i.get("id") in keep]
    out["issues"] = conf_k
    out["issues_with_needs_review"] = pool_k
    out["report_views"] = {"default": {"issues": conf_k},
                           "with_needs_review": {"issues": conf_k + pool_k}}
    return out, folded, examples


for run in ("20260906T132051Z", "20260905T130307Z"):
    rd = ROOT / "benchmark-artifacts/c_cpp/trial" / run / "run-01"
    rep = json.loads((rd / "report.json").read_text(encoding="utf-8"))
    base = score_report_views(rep, GT)
    folded, n, ex = fold(rep)
    sc = score_report_views(folded, GT)
    print(f"===== {run}  折叠条目: {n}")
    for e in ex:
        print(f"   rep={e[0]} [{e[1]}] <- {e[2]}")
    for view in ("default", "with_needs_review"):
        a, b = base[view], sc[view]
        d_tp = b["true_positives"] - a["true_positives"]
        print(f"  [{view}] tp {a['true_positives']}->{b['true_positives']} ({d_tp:+d})  "
              f"fp_raw {a['false_positives_raw']}->{b['false_positives_raw']}  "
              f"recall {a['recall']:.4f}->{b['recall']:.4f}  "
              f"precision {a['precision']:.4f}->{b['precision']:.4f}")
    print()
