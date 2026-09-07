import json, sys, collections
from pathlib import Path

sys.path.insert(0, ".")
from zscope.benchmarking.protocol import issue_identity  # noqa
from zscope.benchmarking.protocol import score_report_views  # noqa

for run, label in (("20260906T132051Z", "guards-run"), ("20260905T130307Z", "r2-baseline")):
    d = json.loads(Path(f"benchmark-artifacts/c_cpp/trial/{run}/run-01/score.v2.json").read_text(encoding="utf-8"))
    s = d["default"]
    rep = json.loads(Path(f"benchmark-artifacts/c_cpp/trial/{run}/run-01/report.json").read_text(encoding="utf-8"))
    issues = rep["issues"]
    recs = s.get("false_positive_issue_records") or []
    print(f"===== {label} effective FP = {len(recs)}")
    # identity -> report issue 回连（用 issue_identity 重建比对）
    idmap = {}
    for i in issues:
        try:
            idmap[issue_identity(i)] = i
        except Exception:
            pass
    wrapper = caller = other = 0
    rows = []
    for r in recs:
        ident = str(r.get("identity") or "")
        parts = ident.split("|")
        cat = parts[1] if len(parts) > 1 else "?"
        filef = parts[2] if len(parts) > 2 else "?"
        func = parts[3] if len(parts) > 3 else "?"
        is_wrapper = filef.endswith("utils.c") and func.startswith("_safe_")
        wrapper += int(is_wrapper)
        caller += int(not is_wrapper and filef.endswith((".c", ".h")) and not filef.endswith("utils.c"))
        issue = idmap.get(ident)
        dl = str((issue.get("attribution") or {}).get("decision_level")) if issue else "?"
        rule = str((issue or {}).get("rule") or "?")[:44]
        rows.append((cat, filef, func, dl, rule, is_wrapper))
    print(f"  wrapper-anchored(utils.c/_safe_*): {wrapper}  caller/other: {caller}")
    bycat = collections.Counter((r[0], r[4] if r[5] else "caller") for r in rows)
    for k, v in sorted(bycat.items(), key=lambda kv: -kv[1]):
        print(f"    {k[0]:38} {'WRAPPER' if k[1]=='WRAPPER' else 'caller'}: {v}" if isinstance(k[1], bool) else f"    {k}: {v}")
    print("  明细:")
    for cat, filef, func, dl, rule, is_wrapper in rows:
        print(f"    {'W' if is_wrapper else 'C'} {dl:3} {cat[:34]:36} {filef}:{func[:30]} {rule[:40]}")
    print()
