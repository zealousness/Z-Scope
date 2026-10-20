"""Coordinator-only migration of two frozen readonly tests, with explicit evidence."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
workspace = ROOT / ".coordination/20261014/workspaces/config-stop-at-r18"
probe = json.loads((ROOT / "artifacts/coordinator-stop-reason-repaired-r19-probes-20261015/review.json").read_text(encoding="utf-8"))
assert probe["independent_acceptance_passed"] and probe["task_id"] == "task_4e43cb393d"
native = json.loads((ROOT / "artifacts/coordinator-current-native-process-classified-r19-20261015/review.json").read_text(encoding="utf-8"))
assert native["passed"] and native["source_unchanged"]
for p in ("zscope/retrieval/clang_batch.py", "zscope/retrieval/clang_backend.py", "zscope/retrieval/indexing_identity.py", "zscope/retrieval/incremental_replay.py"):
    assert hashlib.sha256((workspace / p).read_bytes()).hexdigest() == native["after"][p], p
out = ROOT / "artifacts/coordinator-stop-readonly-tests-r19-migration-20261015"
out.mkdir(exist_ok=False)
changes=[]
for p in ("tests/test_config_v3_preparation.py", "tests/test_incremental_replay.py"):
    path = workspace / p
    before = path.read_bytes()
    assert hashlib.sha256(before).hexdigest() == probe["after"][p]
    text = before.decode("utf-8")
    target = out / "source-before" / p
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(before)
    if p.endswith("test_config_v3_preparation.py"):
        assert text.count('"stop_window_scheduler_wired": False') == 1
        assert text.count('["scheduler_consumer_wired"] is False') == 1
        text = text.replace('"stop_window_scheduler_wired": False', '"stop_window_scheduler_wired": True').replace('["scheduler_consumer_wired"] is False', '["scheduler_consumer_wired"] is True')
    else:
        assert text.count('(2 if row["mutation"] == "negative_include" else 0)') == 1
        text = text.replace('(2 if row["mutation"] == "negative_include" else 0)', '0')
        anchor='    assert all(row["stages"]["clean"]["reused_tus"] == 0 for row in result["mutations"])'
        assert text.count(anchor) == 1
        text = text.replace(anchor, '    assert all(\n        row["stages"]["baseline_hot"]["reused_tus"]\n        == row["stages"]["baseline_cold"]["planned_tus"]\n        for row in result["mutations"]\n    )\n'+anchor)
    path.write_text(text, encoding="utf-8", newline="\n")
    changes.append({"path":p,"previous_sha256":hashlib.sha256(before).hexdigest(),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
dependency = HERE / "followups-r12/config-stop-at-r18-dependencies.json"
assert not dependency.exists()
proof = {"captured_at":dt.datetime.now(dt.timezone.utc).isoformat(),"coordinator_authored":True,"producer_write_permission_granted":False,"root_changed":False,"files":changes,"scope":"Two readonly tests only: actual stop wiring flags; exact unchanged native AST hot0 + full reuse invariant under current include-probe contract, preserving all8 mutations, clean-reuse0, complete and zero unexplained differences. Runtime native version/loader queries are permitted and separately disclosed, no AST extraction or argument checks in the hot phase.","evidence":["artifacts/coordinator-stop-reason-repaired-r19-probes-20261015/review.json","artifacts/coordinator-current-native-process-classified-r19-20261015/review.json"],"validated":False}
dependency.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
(out / "migration.json").write_bytes(dependency.read_bytes())
print(json.dumps({"root_changed":False,"coordinator_only_readonly_tests":changes,"validation_pending":True}),flush=True)
