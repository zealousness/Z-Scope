"""Full-funnel view: candidate layer -> V0 -> V1 -> V3 -> terminal routing.

Builds the ladder-contribution view for one benchmark run:
  candidates entering validation (unique clusters, by engine)
  -> V0 deterministic layer (confirm/reject, TP/FP)
  -> V1 initial validation (verdict mix)
  -> V3 targeted investigation (transitions, conversations, tokens)
  -> terminal routing (confirmed / needs_review / rejected-dropped)
  -> per-layer truth contribution and token cost.
"""
import json, collections
from pathlib import Path

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
GT = json.loads((ROOT / "test/range/benchmark/ground_truth.json").read_text())
TOTAL = len(GT["vulnerabilities"])


def fk(p):
    return str(p).replace("\\", "/").split("/")[-1]


def truth_indexes():
    tk = collections.defaultdict(list)
    tf = collections.defaultdict(list)
    for v in GT["vulnerabilities"]:
        tk[(v.get("category"), fk(v.get("file")), v.get("function"))].append(v["id"])
        tf[(fk(v.get("file")), v.get("function"))].append(v)
    return tk, tf


TK, TF = truth_indexes()


def coarse_cover(issue):
    key = (issue.get("category"), fk(str(issue.get("location") or "").split(":")[0]), issue.get("function"))
    tids = set(TK.get(key, []))
    if not tids:
        tids = {v["id"] for v in TF.get((fk(str(issue.get("location") or "").split(":")[0]), issue.get("function")), [])}
    return tids


def funnel(run_dir: str):
    d = ROOT / "benchmark-artifacts/c_cpp" / run_dir
    rep = json.loads((d / "report.json").read_text())
    score = json.loads((d / "score.json").read_text())
    matched = {p["truth_id"] for p in (score.get("matched_pairs") or [])}
    matched_idx = {p["issue_index"] for p in (score.get("matched_pairs") or [])}
    issues = rep.get("issues", [])
    nr_raw = rep.get("issues_with_needs_review", [])
    conf_ids = {i.get("id") for i in issues}
    pool = [i for i in nr_raw if i.get("id") not in conf_ids]

    # unique candidates (report projection dedups aliases)
    uniq = {}
    for i in issues:
        uniq[i.get("id")] = {"issue": i, "terminal": "confirmed"}
    for i in pool:
        uniq.setdefault(i.get("id"), {"issue": i, "terminal": "needs_review"})

    # events: conversations & tokens per layer
    ev = collections.defaultdict(lambda: {"calls": 0, "tokens": 0, "clusters": set()})
    for line in (d / "llm_usage_events.jsonl").read_text(errors="ignore").splitlines():
        try:
            r = json.loads(line)
        except Exception:
            continue
        k = r.get("call_kind") or "?"
        ev[k]["calls"] += 1
        ev[k]["tokens"] += int(r.get("total_tokens") or 0)
        c = r.get("validation_cluster_uid")
        if c:
            ev[k]["clusters"].add(c)

    # V0 / V1 / V3 contributions over unique candidates
    hist = collections.defaultdict(lambda: collections.Counter())
    initial_verdict = collections.Counter()
    v3_transition = collections.Counter()
    dl_stat = collections.defaultdict(lambda: [0, 0])  # TP, FP for confirmed
    engines = collections.Counter()
    for cid, u in uniq.items():
        issue = u["issue"]
        engines[issue.get("rule_engine") or "?"] += 1
        h = issue.get("validator_pass_history") or []
        kinds_seq = [str(x.get("pass")) for x in h]
        verd_seq = [str(x.get("verdict")) for x in h]
        if kinds_seq:
            initial_verdict[verd_seq[0]] += 1
            if "investigation_synthesis" in kinds_seq:
                idx = kinds_seq.index("investigation_synthesis")
                v3_transition[f"{verd_seq[0]} -> {verd_seq[idx]}"] += 1
            hist[tuple(kinds_seq)][verd_seq[-1]] += 1
        if u["terminal"] == "confirmed":
            n = None
            for n2, i2 in enumerate(issues):
                if i2.get("id") == cid:
                    n = n2
                    break
            ok = n in matched_idx
            dl = str((issue.get("attribution") or {}).get("decision_level") or "?")
            dl_stat[dl][0 if ok else 1] += 1

    pool_cover = [i for i in pool if coarse_cover(i)]
    pool_cover_distinct = set().union(*[coarse_cover(i) for i in pool_cover]) if pool_cover else set()
    out = {
        "run": run_dir,
        "candidates_in_validation": len(uniq),
        "engines": dict(engines.most_common()),
        "V0_deterministic": {"confirm_TP": dl_stat["V0"][0], "confirm_FP": dl_stat["V0"][1],
                             "precision": round(dl_stat["V0"][0] / max(1, dl_stat["V0"][0] + dl_stat["V0"][1]) * 100, 1)},
        "V1_initial": {"conversations": ev["initial"]["calls"], "tokens": ev["initial"]["tokens"],
                       "verdicts": dict(initial_verdict.most_common())},
        "V3_investigation": {"conversations": ev["targeted_investigation"]["calls"],
                             "tokens": ev["targeted_investigation"]["tokens"],
                             "candidates_with_v3": len(ev["targeted_investigation"]["clusters"]),
                             "transitions": dict(v3_transition.most_common())},
        "V3_confirmed": {"TP": dl_stat["V3"][0], "FP": dl_stat["V3"][1],
                         "precision": round(dl_stat["V3"][0] / max(1, dl_stat["V3"][0] + dl_stat["V3"][1]) * 100, 1)},
        "V1_confirmed": {"TP": dl_stat["V1"][0], "FP": dl_stat["V1"][1]},
        "terminal": {"confirmed": len(issues),
                     "needs_review_pure": len(pool),
                     "confirmed_matched_truths": len(matched),
                     "confirmed_FP": len(issues) - len(matched)},
        "review_pool": {"covers_unmatched_truth_items": len(pool_cover),
                        "covers_unmatched_truths_distinct": len(pool_cover_distinct - matched),
                        "no_truth": len(pool) - len(pool_cover)
                        - sum(1 for i in pool if not coarse_cover(i) is None and coarse_cover(i) and coarse_cover(i) <= matched)},
        "tokens_other_layers": {k: v["tokens"] for k, v in ev.items() if k not in ("initial", "targeted_investigation")},
    }
    return out


rows = [funnel("trial/20260905T130307Z/run-01"), funnel("trial/20260906T132051Z/run-01")]
out = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope/benchmarks/experiments/balanced_confirmed_tp/funnel_view.json")
out.write_text(json.dumps(rows, ensure_ascii=False, indent=1))
for r in rows:
    print(json.dumps(r, ensure_ascii=False, indent=1))
    print("=" * 60)
