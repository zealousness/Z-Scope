"""Integrate exactly two reviewed test fixtures after all isolated gates pass."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
branch = ROOT / ".coordination/20261014/workspaces/coordinator-root-fixtures-r21"
def read(path):
    return json.loads(path.read_text(encoding="utf-8"))
def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
initial_path = ROOT / "artifacts/coordinator-root-fixtures-r21-acceptance-20261015/review.json"
final_path = ROOT / "artifacts/coordinator-root-fixtures-r21-final-acceptance-20261015/review.json"
static_path = ROOT / "artifacts/root-joint-fixture-review-r21-20261015/final-staged-review.json"
initial, final, static = read(initial_path), read(final_path), read(static_path)
for review in (initial, final):
    assert review["passed"] and review["root_unchanged"] and review["protected_inputs_unchanged"]
    assert len(review["commands"]) == 3 and all(r["returncode"] == 0 for r in review["commands"])
    assert all(s[k] == "0" for s in review["junit"] for k in ("errors", "failures", "skipped"))
    assert review["slow8_scanner_and_stop_claim_test_unchanged"] and not review["product_changed"]
assert static["decision"] == "accept_final_staged_fixture_bytes"
assert static["original_contract_assertions_preserved"] and not static["test_executed"]
owns = set(final["delivered_hashes"])
assert owns == {"tests/test_mcp_jobs.py", "tests/test_job_remaining.py"}
assert static["delivered_hashes"] == final["delivered_hashes"]
assert final["after"]["tests/test_mcp_jobs.py"] == initial["after"]["tests/test_mcp_jobs.py"]
assert all(final["after"][p] == h for p, h in initial["after"].items() if p != "tests/test_job_remaining.py")
original = read(ROOT / "artifacts/coordinator-r20-job-cli-intaken-20261015/source-evidence.json")["after"]
assert all(sha(ROOT / p) == h for p, h in original.items()), "Root changed; do not overwrite"
assert all(sha(branch / p) == h for p, h in final["after"].items()), "producer input drift"
assert static["shared_scheduler_sha256"] == original["tests/test_job_session_scheduler.py"] == final["after"]["tests/test_job_session_scheduler.py"]
staged = {p: (branch / p).read_bytes() for p in owns}
for raw in staged.values():
    raw.decode("utf-8", errors="strict")
    assert not raw.startswith(b"\xef\xbb\xbf") and b"\r" not in raw and raw.endswith(b"\n")
assert read(ROOT / "artifacts/coordinator-root-tool-environment-r21-20261015/login-full-preflight.json")["passed"]
out = ROOT / "artifacts/intake-root-fixtures-r21-20261015"
out.mkdir(exist_ok=False)
files = []
for p in sorted(owns):
    backup = out / "before" / p
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_bytes((ROOT / p).read_bytes())
    (ROOT / p).write_bytes(staged[p])
    files.append({"path": p, "before": original[p], "after": sha(ROOT / p), "backup": backup.relative_to(ROOT).as_posix()})
expected = {**original, **final["delivered_hashes"]}
assert all(sha(ROOT / p) == h for p, h in expected.items())
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
launchers = {name: sha(HERE / name) for name in ("test_slot.py", "verify_current_root_r21.py", "verify_joint_retry_with_clock_r21.py", "root_runtime_preflight_r21.py", "publish_joint_r21.py")}
receipt = {"task_id": "COORD-ROOT-FIXTURES-R21", "intaken_at": at, "files": files, "isolated_acceptance_passed": True, "independent_static_review_passed": True, "initial_review": initial_path.relative_to(ROOT).as_posix(), "final_review": final_path.relative_to(ROOT).as_posix(), "static_review": static_path.relative_to(ROOT).as_posix(), "product_changed": False, "old_failed_root_preserved": "artifacts/coordinator-r20-job-cli-intaken-20261015/review.json", "original_window_and_timeouts_retained": True, "shared_slow8_scanner_unchanged": True, "source_inputs": len(expected), "launchers": launchers, "quality_commands_required": 6, "joint_verification_passed": False, "clock_problem_resolved": False}
write(out / "receipt.json", receipt)
ledger_path = HERE / "tasks.json"
ledger = read(ledger_path)
rows = {r["id"]: r for r in ledger["tasks"]}
new = [
    {"id": "ASTRA-ROOT-FIXTURE-REVIEW-R21", "depends_on": ["CURRENT-JOINT-R20"], "agent_kind": "native_subagent", "agent_task_id": "/root/astra_first_cause_r20", "owner": "Astra", "accepted_model": "gpt-6-astra", "reasoning_effort": "xhigh", "status": "readonly_review_completed_final_fixture_bytes_accepted", "producer_status": "completed", "artifact_available": True, "independent_static_review": True, "independent_acceptance": False, "integrated": False, "product_changed": False, "evidence": static_path.relative_to(ROOT).as_posix(), "worker_finished_at": static["review_finished_at"], "whole_package_complete": False},
    {"id": "COORD-ROOT-FIXTURES-R21", "depends_on": ["ASTRA-ROOT-FIXTURE-REVIEW-R21"], "owner": "coordinator", "status": "isolated_verified_reviewed_test_fixtures_intaken_joint_pending", "artifact_available": True, "independent_acceptance": True, "integrated": True, "integrated_at": at, "joint_verification": False, "product_changed": False, "write_paths": sorted(owns), "evidence": (out / "receipt.json").relative_to(ROOT).as_posix(), "whole_package_complete": False},
    {"id": "CURRENT-JOINT-R21", "depends_on": ["COORD-ROOT-FIXTURES-R21", "U01-JOB-CLI-WINDOW-R20", "U01-FIRST-CAUSE-R20"], "owner": "coordinator", "status": "ready_login_preflight_required_current_full_union_and_six_commands", "artifact_available": False, "independent_acceptance": False, "integrated": False, "joint_verification": False, "is_current_root": False, "whole_package_complete": False}
]
for row in new:
    assert row["id"] not in rows
    ledger["tasks"].append({**row, "checked_at": at})
rows = {r["id"]: r for r in ledger["tasks"]}
pending, done, layers = set(rows), set(), []
while pending:
    ready = sorted(p for p in pending if set(rows[p].get("depends_on", [])) <= done)
    assert ready, pending
    layers.append(ready)
    done.update(ready)
    pending.difference_update(ready)
ledger["topological_layers"] = layers
ledger["updated_at"] = at
ledger["current_accepted_stage"]["is_current_root"] = False
write(ledger_path, ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, active_phase="R21 reviewed fixture intake complete; next full current Root union in verified login environment", latest_fixture_intake=receipt, current_joint_status="pending_R21_full_union_and_six_commands", latest_joint_attempt_passed=False, prior_pass_is_current_root=False, whole_packages_complete=False)
write(HERE / "continuation-r6.json", continuation)
note = f"## {at} · R21 launcher diagnosis and two test-fixture intake\n\nExisting Bridge owner PID80748 remains alive; public active-only check23:50:43 returned zero active sessions, no dispatch/resume. Login preflight passed clang/clang++/clangd18, exact native d39cbe72… with no missing libraries and ext4 unlinked-fd truncate; direct WSL context rejected missing clang/clang++. Independent read-only reviewer /root/astra_first_cause_r20 accepted final fixture bytes; original23-file evidence stable, no tests run by reviewer. Coordinator initial isolated114/three commands0; final focused{final['junit'][0]['tests']}/three commands0, zero skip/error/fail, separate scopes not added. Exactly two reviewed test files intaken; product, shared scanner/slow8, original2.5s window/timeouts unchanged. Receipt artifacts/intake-root-fixtures-r21-20261015/receipt.json. Current full Root and six strict commands still pending; prior2539 failure remains immutable. Clock problem unresolved. No whole-package/real-project conclusion or new UI/backend dispatch.\n\n---\n\n"
for name in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R20.md"):
    path = HERE / name
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "files": files, "receipt": str(out / "receipt.json"), "joint_passed": False}), flush=True)
