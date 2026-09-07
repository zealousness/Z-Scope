import json, sys, collections
from pathlib import Path

sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
from zscope.retrieval.validation_facts import CompleteFactStore
from zscope.core.validation.review_checks import ReviewClaimChecker
from zscope.benchmarking.protocol import score_report_views, issue_match_detail

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
WS = Path("/tmp/cp_ws/scan-input")
GT = json.loads((ROOT / "test/range/benchmark/ground_truth.json").read_text())
facts_dir = Path("/tmp/checked_proofs_facts")
store = CompleteFactStore(WS, WS / "build" / "compile_commands.json", facts_dir)
checker = ReviewClaimChecker(store)
vulns = GT["vulnerabilities"]

def strict_truths(issue):
    return [str(v["id"]) for v in vulns if issue_match_detail(issue, v, 8) is not None]

for run in ("20260905T130307Z", "20260906T132051Z"):
    rd = ROOT / "benchmark-artifacts/c_cpp/trial" / run / "run-01"
    rep = json.loads((rd / "report.json").read_text())
    issues = rep.get("issues", [])
    conf_ids = {i.get("id") for i in issues}
    pool = [i for i in rep.get("issues_with_needs_review", []) if i.get("id") not in conf_ids]
    uniq = {i.get("id"): i for i in issues + pool}
    stats = collections.Counter()
    receipted_pool, receipted_conf = [], []
    risk_items = 0
    proposals = 0
    for cid, i in uniq.items():
        try:
            desc = checker.prepare(i)
            risks = i.get("review_conditional_risks") or []
            if risks:
                risk_items += 1
            proposals += len(i.get("review_related_proposals") or [])
            checker.check(i, "auto")
        except Exception as exc:
            stats[f"error:{type(exc).__name__}"] += 1
            continue
        rcpt = i.get("review_checked_proof")
        if rcpt:
            stats["receipt"] += 1
            stats[f"rule:{i.get('rule') or i.get('rule_id')}"] += 1
            if cid in conf_ids:
                receipted_conf.append(i)
            else:
                receipted_pool.append(i)
        else:
            stats[f"status:{(i.get('review_claim_checks') or [{}])[-1].get('status', 'none')}"] += 1
    print(f"===== {run}: uniq={len(uniq)} pool={len(pool)} confirmed={len(issues)}")
    for k, v in stats.most_common(14):
        print(f"   {k}: {v}")
    print(f"   conditional-risk items: {risk_items}  related proposals: {proposals}")
    # TP 安全：receipt 项的真值覆盖
    matched = {p["truth_id"] for p in json.loads((rd / "score.json").read_text()).get("matched_pairs", [])}
    for label, items in (("receipted-pool", receipted_pool), ("receipted-confirmed", receipted_conf)):
        for i in items:
            ts = strict_truths(i)
            unmatched = [t for t in ts if t not in matched]
            if unmatched:
                chk = (i.get("review_claim_checks") or [{}])[-1]
                print(f"      >> UNMATCHED-cover receipt: {i.get('id','')[:40]} cat={i.get('category')} "
                      f"truths={unmatched} rule={i.get('rule') or i.get('rule_id')} "
                      f"reason={str(chk.get('reason'))[:50]} loc={i.get('location')}")
        cov_unmatched = cov_matched = no_truth = 0
        for i in items:
            ts = strict_truths(i)
            if any(t in matched for t in ts):
                cov_matched += 1
            elif ts:
                cov_unmatched += 1
            else:
                no_truth += 1
        print(f"   {label}: n={len(items)} cov-matched(dup)={cov_matched} cov-UNMATCHED(TP-loss!)={cov_unmatched} no-truth={no_truth}")
    # 视图差分：receipted pool -> 终态拒绝（从池中移除）；receipted confirmed -> 冲突降 review
    if receipted_pool or receipted_conf:
        import copy
        out = copy.deepcopy(rep)
        drop_ids = {i.get("id") for i in receipted_pool}
        move_ids = {i.get("id") for i in receipted_conf}
        out["issues"] = [i for i in out.get("issues", []) if i.get("id") not in move_ids]
        moved = [i for i in rep.get("issues_with_needs_review", []) if i.get("id") in move_ids]
        out["issues_with_needs_review"] = [
            i for i in out.get("issues_with_needs_review", []) if i.get("id") not in drop_ids
        ] + moved
        out["report_views"] = {
            "default": {"issues": out["issues"]},
            "with_needs_review": {"issues": out["issues"] + out["issues_with_needs_review"]},
        }
        sc = score_report_views(out, GT)
        s0 = score_report_views(rep, GT)
        for view in ("default", "with_needs_review"):
            a, b = s0[view], sc[view]
            print(f"   [{view}] tp {a['true_positives']}->{b['true_positives']} ({b['true_positives']-a['true_positives']:+d}) "
                  f"fp_raw {a['false_positives_raw']}->{b['false_positives_raw']} "
                  f"recall {a['recall']:.4f}->{b['recall']:.4f}")
