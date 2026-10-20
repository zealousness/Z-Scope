"""Keep observed producer failures distinct from the independent 11 probes."""
from pathlib import Path
import json
HERE=Path(__file__).resolve().parent
path=HERE/"tasks.json"
ledger=json.loads(path.read_text(encoding="utf-8"))
row=next(r for r in ledger["tasks"] if r["id"]=="CONTRACT-VALIDATION-R12")
row["execution_history"][-1].update(observation_kind="producer_junit_not_independent_execution",exact_byte_regression_revalidation="pending")
row["independent_boundary_slice"]={"task_id":"task_6b0ca95206","passed":11,"failed":0,"errors":0,"skipped":0,"at":"2026-10-15T03:29:44.538211+08:00","evidence":"artifacts/coordinator-contract-r12-repaired-boundary-20261015/review.json","whole_package_acceptance":False}
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
for name in ("PROGRESS.md","DAG.md"):
    path=HERE/name
    text=path.read_text(encoding="utf-8")
    text=text.replace("892 diagnostic tests/5 failures","892 producer-observed tests/5 failures (not independent execution; final-byte revalidation pending)",1)
    text=text.replace("· Independent boundary failures; same-session repairs","· Producer regression observation; same-session investigation",1)
    path.write_text(text,encoding="utf-8",newline="\n")
print("receipt distinctions recorded")
