"""Prepare immutable style retry and a separate successor for the confirmed job defect."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-shared-style-r34"
OUT = ROOT / "artifacts/coordinator-shared-style-r34-20261017"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
frozen = read(OUT / "input-freeze.json")
assert len(frozen["complete_inputs"]) == 1082
assert all(sha(WORK / p) == v for p, v in frozen["complete_inputs"].items())
old = (HERE / "verify_final_composite_r33.py").read_text(encoding="utf-8")
new = old.replace("coordinator-final-composite-r33", "coordinator-shared-style-r34")
new = new.replace('assert not os.environ.get("PYTEST_ADDOPTS") and not os.environ.get("PYTEST_PLUGINS")', 'assert not any(os.environ.get(k) for k in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONOPTIMIZE"))')
new = new.replace('read(BASE / "input-freeze-v2.json")', 'read(BASE / "input-freeze.json")')
start = new.index('assert frozen["previous_freeze_sha256"]')
end = new.index('before = snapshot()', start)
new = new[:start] + 'assert frozen["original_preparation_sha256"] == sha(BASE / "preparation.json")\nassert frozen["entire_AST_identical"] and frozen["all_other_1080_inputs_unchanged"]\n' + new[end:]
new = new.replace("1081", "1082")
new = new.replace('prior_paths = dict(', 'session = ROOT / "artifacts/coordinator-session-cost-r33-20261017/green2"\nprior_paths = dict(session=session / "results.xml", ')
new = new.replace('dict(context=50, cost=16, revision=33, classifier=49)', 'dict(session=2, context=50, cost=16, revision=33, classifier=49)')
new = new.replace("== 148", "== 150").replace("tests=148", "tests=150")
new = new.replace('BASE / "input-freeze-v2.json", ', '')
new = new.replace('context / "receipt.json", ', 'session / "review.json", context / "receipt.json", ')
new = new.replace('tests = ["tests/test_instance_currentness_revocation_r33.py"', 'tests = ["tests/test_session_preentry_cost_r33.py", "tests/test_instance_currentness_revocation_r33.py"')
assert (WORK / "tests/test_session_preentry_cost_r33.py").is_file()
new = new.replace('black = [*tests, ', 'black = [*tests, "zscope/orchestration/scan_session.py", "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r12/test_scan_checkpoint_dependency_boundary.py", ')
new = new.replace('Session_Wiki_handoff_not_in_this_combination=True', 'Session_Wiki_handoff_in_this_combination=True')
new = new.replace('all_four_prior_counters_exact', 'all_five_prior_counters_exact')
target = HERE / "verify_shared_style_r34.py"
assert not target.exists()
target.write_text(new, encoding="utf-8", newline="\n")
job = ROOT / ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34"
jobout = ROOT / "artifacts/job-runtime-footprint-repair-r34-20261017"
job.mkdir(exist_ok=False)
jobout.mkdir(exist_ok=False)
for p in frozen["complete_inputs"]:
    destination = job / p
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(WORK / p, destination)
assert all(sha(job / p) == v for p, v in frozen["complete_inputs"].items())
prep = read(OUT / "preparation.json")
refs = dict(prep["source_review_sha256"])
for p in (OUT / "input-freeze.json", Path(__file__), target):
    refs[str(p)] = sha(p)
probe = ROOT / ".coordination/20261014/workspaces/shared-job-probes-r34/artifacts/shared_job_probes_r34"
for p in (probe / "final-freeze.json", probe / "DELIVERY.md", probe / "currentness-cause.json", probe / "checkpoint-interpretation.json", probe / "v2/currentness/receipt.json", probe / "v2/checkpoint/receipt.json"):
    refs[str(p)] = sha(p)
assert all(sha(Path(p)) == v for p, v in refs.items())
owned = ["zscope/orchestration/scan_session.py", "zscope/retrieval/code_index.py", "zscope/retrieval/unified_backend.py", "zscope/retrieval/clang_backend.py", "zscope/retrieval/clang_batch.py", "zscope/retrieval/indexing_identity.py", "zscope/orchestration/instance_semantics_context.py", "tests/test_job_runtime_footprint_r34.py"]
receipt = dict(logical_task="JOB-RUNTIME-FOOTPRINT-REPAIR-R34", actual_task="/root/stage_cost_repair_r33", transport="native_followup", bridge_task_id=None, model="gpt-6.1-sol", reasoning_effort="xhigh", prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), workspace=str(job.relative_to(ROOT)), complete_inputs=frozen["complete_inputs"], root_inputs=prep["root_inputs"], reference_sha256=refs, product_and_test_ownership=owned, other_inputs_readonly=True, old_cost_failed_deliveries=1, old_s01_failed_deliveries=3, repair_failed_deliveries=0, no_bridge_restart=True, no_archived_s06_r02=True, stage_intake=False, root_intake=False)
(jobout / "preparation.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(retry_launcher=str(target), job_workspace=str(job), inputs=1082, ownership=owned)))
