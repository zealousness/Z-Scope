import json, sys, collections
from pathlib import Path

sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
from zscope.retrieval.validation_facts import CompleteFactStore
from zscope.core.validation.review_checks import ReviewClaimChecker

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
WS = Path("/tmp/zscope-benchmark-c_cpp-01-soxjqsl0/scan-input")
store = CompleteFactStore(WS, WS / "build" / "compile_commands.json", Path("/tmp/checked_proofs_facts"))
checker = ReviewClaimChecker(store)
print("compiler_environment:", store.compiler_environment())

rd = ROOT / "benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01"
rep = json.loads((rd / "report.json").read_text())
issues = rep.get("issues", [])
conf_ids = {i.get("id") for i in issues}
pool = [i for i in rep.get("issues_with_needs_review", []) if i.get("id") not in conf_ids]
uniq = {i.get("id"): i for i in issues + pool}

reasons = collections.Counter()
samples = {}
for cid, i in uniq.items():
    try:
        desc = checker.prepare(i)
    except Exception as exc:
        reasons[f"prepare-error:{type(exc).__name__}"] += 1
        continue
    complete = bool(desc.get("complete"))
    r = str(desc.get("reason") or ("complete" if complete else "?"))
    reasons[r[:60]] += 1
    samples.setdefault(r[:60], (cid, desc))
for k, v in reasons.most_common(10):
    print(f"  {k}: {v}")
k0 = next(iter(samples))
cid, desc = samples[k0]
print("\nsample descriptor:", json.dumps(desc, ensure_ascii=False)[:500])
checker.check(uniq[cid], "auto")
print("check result:", json.dumps((uniq[cid].get("review_claim_checks") or [{}])[-1], ensure_ascii=False)[:400])
