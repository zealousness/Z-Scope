"""Observe the original timing test and a serial counterexample without edits."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import sys
import threading
import time
import pytest

assert sys.platform == "linux" and os.environ.get("ZSCOPE_COORDINATOR_TEST_SLOT")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(ROOT / "tests"))
import test_subagents_parallel as original

out = ROOT / "artifacts/subagent-parallel-probe-r22-20261016"
out.mkdir(exist_ok=False)
paths = [ROOT/"tests/test_subagents_parallel.py", ROOT/"zscope/orchestration/subagents.py", ROOT/"zscope/common/cancellation.py"]
before = {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
records = []
for forced_workers in (None, 1):
    events, reports = [], []
    lock = threading.Lock()
    worker_run = original.FakeDeepWorker.run
    run_tickets = original.SubAgentOrchestrator.run_tickets
    def observe_worker(self, input_data):
        ticket_id = input_data["ticket"]["id"]
        with lock:
            events.append({"event":"enter","ticket":ticket_id,"thread_id":threading.get_ident(),"at":time.perf_counter()})
        try:
            return worker_run(self, input_data)
        finally:
            with lock:
                events.append({"event":"exit","ticket":ticket_id,"thread_id":threading.get_ident(),"at":time.perf_counter()})
    def observe_batch(self, *args, **kwargs):
        if forced_workers is not None:
            kwargs["max_workers"] = forced_workers
        result = run_tickets(self, *args, **kwargs)
        reports.extend(result)
        return result
    started = time.perf_counter()
    error = None
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(original.FakeDeepWorker, "run", observe_worker)
        patch.setattr(original.SubAgentOrchestrator, "run_tickets", observe_batch)
        try:
            original.test_run_tickets_parallel_keeps_stable_report_order(patch)
        except AssertionError as exc:
            error = str(exc) or "original assertion failed; inspect measured elapsed and preserved original source"
    elapsed = time.perf_counter() - started
    active = maximum = 0
    for event in sorted(events, key=lambda e:e["at"]):
        active += 1 if event["event"] == "enter" else -1
        maximum = max(maximum, active)
    records.append({"mode":"original_parallel" if forced_workers is None else "explicit_serial_negative_control", "original_test_passed":error is None,"original_assertion_error":error,"elapsed_with_probe":elapsed,"maximum_worker_overlap":maximum,"distinct_worker_threads":len({e["thread_id"] for e in events}),"report_order":[r["ticket"]["id"] for r in reports],"statuses":[r["status"] for r in reports],"worker_events":events})
after = {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
assert before == after
proof = {"finished_at":dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),"python":sys.executable,"source_root":str(ROOT),"before":before,"after":after,"original_0_18_assertion_unchanged":True,"records":records,"scope":"Diagnostic observations only; serial override exists only in probe memory; no product/test edit or current full-union acceptance"}
(out/"review.json").write_text(json.dumps(proof,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(proof),flush=True)
