import json, re
from pathlib import Path

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
rep = json.loads((ROOT / "benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01/report.json").read_text())
for i in rep.get("issues", [])[:1]:
    print("confirmed sample:", i.get("id")[:40])
    print(json.dumps(i.get("validator_pass_history"), ensure_ascii=False)[:500])
for i in rep.get("issues_with_needs_review", [])[:2]:
    print("review sample:", i.get("id")[:40])
    print(json.dumps(i.get("validator_pass_history"), ensure_ascii=False)[:400])
log = (ROOT / "benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01/scan.log").read_text(errors="ignore")
for pat in (r"verdict[=:]\s*(verified|rejected|uncertain)",
            r"disposition[=:]\s*\w+",
            r"validator (?:finished|done)",
            r"rejected",
            r"worker result",
            r"candidate_uid"):
    hits = re.findall(pat, log, re.I)
    print(f"log pattern {pat!r}: {len(hits)} hits", list(dict.fromkeys(hits))[:4])
