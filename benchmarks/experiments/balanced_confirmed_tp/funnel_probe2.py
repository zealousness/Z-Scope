import json
from pathlib import Path

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
p = ROOT / "benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01/llm_usage_events.jsonl"
kinds = {}
sample = None
for line in p.read_text(errors="ignore").splitlines():
    try:
        rec = json.loads(line)
    except Exception:
        continue
    k = rec.get("call_kind") or rec.get("kind") or "?"
    kinds[k] = kinds.get(k, 0) + 1
    if sample is None:
        sample = rec
print("call_kind counts:", json.dumps(kinds, ensure_ascii=False))
print("sample keys:", sorted(sample.keys()))
print(json.dumps({k: sample.get(k) for k in list(sample.keys())[:16]}, ensure_ascii=False)[:600])
