import json, collections
from pathlib import Path

ROOT = Path(".")
for run, label in (("20260906T132051Z", "guards-run"), ("20260905T130307Z", "r2-baseline")):
    d = json.loads(Path(f"benchmark-artifacts/c_cpp/trial/{run}/run-01/score.v2.json").read_text(encoding="utf-8"))
    s = d["default"]
    rep = json.loads(Path(f"benchmark-artifacts/c_cpp/trial/{run}/run-01/report.json").read_text(encoding="utf-8"))
    issues = rep["issues"]
    audit = s.get("false_positive_audit") or {}
    # raw FP 记录 + 分类（unmatched_issue_classifications 带每条的分类）
    cls = s.get("unmatched_issue_classifications") or []
    cls_map = {}
    for c in cls:
        cls_map[str(c.get("identity") or c.get("stable_fingerprint") or "")] = str(c.get("classification") or c.get("category") or "?")
    raw_recs = s.get("false_positive_issue_records_raw") or []
    eff_ids = set()
    for r in s.get("false_positive_issue_records") or []:
        eff_ids.add(str(r.get("identity") or r.get("stable_fingerprint") or ""))
    id2issue = {}
    for i in issues:
        id2issue.setdefault(str(i.get("id")), i)
    print(f"===== {label}: raw={len(raw_recs)} effective={s['false_positives']}")
    rows = []
    for r in raw_recs:
        identity = str(r.get("identity") or "")
        cls_name = cls_map.get(identity, "?")
        # identity 形如 v1|category|file|function|...
        parts = identity.split("|")
        cat, filef, func = (parts[1] if len(parts) > 1 else "?"), (parts[2] if len(parts) > 2 else "?"), (parts[3] if len(parts) > 3 else "?")
        # 找回 report issue（按 identity 前缀匹配）
        issue = None
        for i in issues:
            from zscope.benchmarking.protocol import issue_identity  # type: ignore
            break
        rows.append({"cls": cls_name, "cat": cat, "func": func, "file": filef})
    for view in (None,):
        pass
    by = collections.Counter((r["cls"], r["cat"]) for r in rows)
    print("  (classification, category):")
    for k, v in by.most_common(12):
        print(f"    {k}: {v}")
    # decision_level / engine 需要回连 report —— 用 function+file 精确匹配
    idx = collections.defaultdict(list)
    for i in issues:
        idx[(i.get("category"), i.get("function"))].append(i)
    dl = collections.Counter()
    for r in rows:
        for i in idx.get((r["cat"], r["func"]), []):
            dl[str((i.get("attribution") or {}).get("decision_level"))] += 1
            break
    print("  decision_level(尽力回连):", dict(dl.most_common()))
    print()
