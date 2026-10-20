"""Preserve stopped R4 bytes, then isolate implementation context payloads."""
from pathlib import Path
import datetime as dt
import hashlib
import json
from audit_followup_r6 import audit, ROOT

HERE = Path(__file__).resolve().parent
response = json.loads((HERE / "route-check/bridge-response-r9-kimi-cancel-native-callee.json").read_text(encoding="utf-8"))
assert response["task_id"] == "task_6e14411a6c" and response["status"] == "cancelled"
review = audit("s01-analysis-r6")
assert review["safe_to_review"]
branch = Path(review["workspace"])
out = ROOT / "artifacts/coordinator-s01-context-repair-r9-20261014"
out.mkdir(exist_ok=True)
assert not (out / "repair.json").exists()
for row in review["changes"]:
    destination = out / "before" / row["path"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes((branch / row["path"]).read_bytes())
path = branch / "zscope/retrieval/instance_index.py"
before = path.read_text(encoding="utf-8")
old = "            include_context=include_context,\n            file_path=source,\n"
new = "            include_context=False,\n            file_path=source,\n"
assert before.count(old) == 1
after = before.replace(old, new)
old_return = '''        impl = dict(impl)
        if impl.get("callees"):
            # The base callee projection is a shared navigation view and cannot
            # be bound to one build when a source holds conditional call sites.
            self._record_blocked(
                "get_function_impl", detail="navigation callee projection is not per-instance"
            )
            impl["callees"] = []
        self.__dict__["_entry_body_resolved"] = True
        return impl'''
new_return = '''        # The base navigation context contains its global call graph and
        # declaration comments.  Even a body at the exact native owner location
        # does not bind those separate projections to this compilation instance.
        # Copy before clearing so the shared index's cached payload stays intact.
        impl = dict(impl)
        impl["callees"] = []
        impl["comment_blocks"] = []
        if include_context:
            self._record_blocked(
                "get_function_impl.context",
                detail="callee and declaration context has no per-instance receipt",
            )
        self.__dict__["_entry_body_resolved"] = True
        return impl'''
assert after.count(old_return) == 1
after = after.replace(old_return, new_return)
# The interrupted worker appended the same owner guard twice.  Keep one check.
start = before.index('        range_problem = self._native_body_range_problem(impl.get("start_line"))')
end = before.index('        impl = dict(impl)', start)
guards = before[start:end]
half = len(guards) // 2
assert guards[:half] == guards[half:]
assert after.count(guards) == 1
after = after.replace(guards, guards[:half])
path.write_text(after, encoding="utf-8", newline="\n")
proof = {"task_id": response["task_id"], "worker_status": "cancelled",
         "worker_finished_at": response["finished_at"],
         "repair_at": dt.datetime.now(dt.timezone.utc).isoformat(),
         "author": "coordinator", "file": str(path.relative_to(ROOT)),
         "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
         "after_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
         "failure_evidence": "artifacts/coordinator-s01-native-payload-r4-20261014/results.xml",
         "scope": "Confirmed unscoped callees/comment context in implementation payload; native owner guard retained. No native rebuild or full consumer migration.",
         "independent_acceptance": "pending", "integrated": False,
         "whole_package_complete": False}
(out / "repair.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")
print(json.dumps(proof))
