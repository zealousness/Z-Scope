"""Integrate only the quiescent independently accepted consumer and readonly notes."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import time
from uuid import uuid4
from audit_followup_r12 import audit

sys.stdout.reconfigure(encoding="utf-8")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"
stamp = "r20-intake-sessions-" + uuid4().hex[:10]
request = {"id": stamp, "tool": "list_sessions", "arguments": {"active_only": False}}
(route / "bridge-queue" / ("080-" + stamp + ".request.json")).write_text(json.dumps(request) + "\n", encoding="utf-8", newline="\n")
response = route / ("bridge-response-" + stamp + ".json")
until = time.monotonic() + 40
while not response.exists() and time.monotonic() < until:
    time.sleep(.25)
assert response.exists()
sessions = json.loads(response.read_text(encoding="utf-8"))
assert sessions["ok"]
assert not any(r.get("proc_state") in {"busy", "running"} and str(ROOT).lower() in str(r.get("cwd", "")).lower() for r in sessions["sessions"])
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
rows = {r["id"]: r for r in ledger["tasks"]}
row = rows["U01-JOB-CLI-WINDOW-R20"]
assert row["producer_status"] == "completed" and row["worker_finished_at"]
producer_id = row["agent_task_id"] if row.get("agent_kind") == "native_subagent" else row["bridge_task_id"]
assert row["observed_model"] == row["requested_model"]
name = row["workspace"]
if row.get("agent_kind") != "native_subagent":
    assert next(r for r in sessions["sessions"] if r["session_id"] == row["bridge_session_id"])["proc_state"] in {"ready", "idle_unloaded"}
else:
    assert next(r for r in sessions["sessions"] if r["session_id"] == row["bridge_session_id"])["proc_state"] == "dead"
ownership = audit(name)
assert not ownership["nonowned_changes"]
review_path = ROOT / "artifacts/coordinator-job-cli-window-r20-final-acceptance-20261015/review.json"
review = json.loads(review_path.read_text(encoding="utf-8"))
assert review["independent_acceptance_passed"] and review["source_unchanged"] and review["independent_probes_unchanged"]
assert review["task_id"] == producer_id
assert len(review["commands"]) == 4 and all(r["returncode"] == 0 for r in review["commands"])
assert all(review["junit"][k] == "0" for k in ("failures", "errors", "skipped"))
assert review["native_before"] == review["native_after"] == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
assert "test_job_cli_window_snapshot_boundary.py" in {Path(p).name for p in review["independent_probe_sources"]}
base = json.loads((ROOT / "artifacts/coordinator-r19-all-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
branch = ROOT / ".coordination/20261014/workspaces" / name
slot_path = (HERE / "test_slot.py").relative_to(ROOT).as_posix()
slot_before = (branch / slot_path).read_bytes()
slot_after = (ROOT / slot_path).read_bytes()
assert hashlib.sha256(slot_before).hexdigest() == base[slot_path] == "7f67c4a69c51eaffc452c681f3443a461a8ca9c76474dc3f8622575aa20396d6"
assert hashlib.sha256(slot_after).hexdigest() == "7fd4e683bb9e7523a3247eb5efd21ff5a130ebc83375933f32290f4007f9c158"
expected_slot = slot_before.replace(b'    workspace = args.workspace.resolve(strict=True)\n', b'    if os.environ.get("ZSCOPE_COORDINATOR_TEST_SLOT"):\n        parser.error("nested test_slot invocation refused; wrap each command exactly once")\n    workspace = args.workspace.resolve(strict=True)\n').replace(b'        env = os.environ.copy()\n', b'        env = os.environ.copy()\n        env["ZSCOPE_COORDINATOR_TEST_SLOT"] = f"{os.getpid()}:{acquired}"\n')
assert slot_after == expected_slot, "only the reviewed exact guard addition is authorized"
startup_path = ROOT / "artifacts/coordinator-job-cli-window-r20-interrupted-nested-startup-20261015/interruption-receipt.json"
startup = json.loads(startup_path.read_text(encoding="utf-8"))
assert startup["nested_guard_probe_returncode"] == 2 and startup["slot_helper_sha256"] == hashlib.sha256(slot_after).hexdigest()
assert not startup["tests_or_timeouts_or_capture_weakened"]
launcher_updates = [{"path": slot_path, "before": base[slot_path], "after": hashlib.sha256(slot_after).hexdigest(), "already_applied_observed_at": startup["at"], "owner": "coordinator_verification_launcher", "validation": [startup_path.relative_to(ROOT).as_posix(), review_path.relative_to(ROOT).as_posix()], "scope": "Exact two-hunk nested-slot rejection/child marker addition; original two-slot locking, ext4 temp, fd capture and subprocess command unchanged"}]
expected_root = {**base, slot_path: launcher_updates[0]["after"]}
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in expected_root.items())
baseline = json.loads((HERE / "followups-r12" / (name + "-baseline.json")).read_text(encoding="utf-8"))
parents = {r["path"]: r["sha256"] for r in baseline["files"]}
sources = {}
for p, sha in review["delivered_hashes"].items():
    assert hashlib.sha256((branch / p).read_bytes()).hexdigest() == sha == review["after_all_inputs"][p]
    assert base.get(p) == parents.get(p)
    if p not in parents:
        assert not (ROOT / p).exists()
    sources[p] = (branch / p, sha, producer_id)
dependencies = json.loads((HERE / "followups-r12" / (name + "-dependencies.json")).read_text(encoding="utf-8"))
for r in dependencies["files"]:
    p = r["path"]
    assert base.get(p) == r["previous_sha256"]
    if p not in base:
        assert not (ROOT / p).exists()
    assert hashlib.sha256((branch / p).read_bytes()).hexdigest() == r["sha256"] == review["after_all_inputs"][p]
    sources[p] = (branch / p, r["sha256"], r["owner"])
assert {"zscope/cli/cli.py", "zscope/orchestration/execution_profile.py", "tests/test_job_cli_stop_window.py"} <= set(sources)
core_review_path = ROOT / "artifacts/coordinator-first-cause-r20-final-acceptance-20261015/review.json"
core_review = json.loads(core_review_path.read_text(encoding="utf-8"))
assert core_review["independent_acceptance_passed"] and core_review["source_unchanged"] and core_review["independent_probes_unchanged"]
assert len(core_review["commands"]) == 4 and all(r["returncode"] == 0 for r in core_review["commands"])
assert all(core_review["junit"][k] == "0" for k in ("failures", "errors", "skipped"))
assert core_review["native_before"] == core_review["native_after"] == review["native_after"]
for p, sha in core_review["delivered_hashes"].items():
    assert p in sources and sources[p][1] == sha
core_row = rows["U01-FIRST-CAUSE-R20"]
assert core_row["producer_status"] == "completed" and core_row["independent_acceptance"]
assert len(sources) == 9
# Validate every byte before the first Root write, including the accepted
# dependency, the new files and encoding. A failed check cannot leave a partial
# intake merely because a later source failed validation.
pending_bytes = {}
for p, (origin, sha, owner) in sorted(sources.items()):
    data = origin.read_bytes()
    assert hashlib.sha256(data).hexdigest() == sha
    data.decode("utf-8")
    assert not data.startswith(b"\xef\xbb\xbf") and b"\r\n" not in data and data.endswith(b"\n"), p
    pending_bytes[p] = data
out = ROOT / "artifacts/intake-job-cli-window-r20-20261015"
out.mkdir(exist_ok=False)
slot_backup = out / "launcher-before" / slot_path
slot_backup.parent.mkdir(parents=True, exist_ok=True)
slot_backup.write_bytes(slot_before)
files = []
for p, (origin, sha, owner) in sorted(sources.items()):
    target = ROOT / p
    before = hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None
    if before is not None:
        backup = out / "backup" / p
        backup.parent.mkdir(parents=True, exist_ok=True)
        backup.write_bytes(target.read_bytes())
    data = pending_bytes[p]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    files.append({"path": p, "before": before, "after": sha, "owner": owner, "source": str(origin)})
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == sha for p, (_, sha, _) in sources.items())
receipt = {"intaken_at": at, "files": files, "launcher_updates": launcher_updates, "task_id": producer_id, "task_ids": [producer_id, core_row["agent_task_id"]], "independent_review": review_path.relative_to(ROOT).as_posix(), "first_cause_independent_review": core_review_path.relative_to(ROOT).as_posix(), "session_preflight": response.relative_to(HERE).as_posix(), "joint_verification_passed": False, "whole_packages_complete": False, "scope": "Nine product/test/doc files plus a separately reviewed already-applied coordinator launcher guard with preserved old bytes; previous R19 selected2314 now historical, strict full union/six commands pending"}
(out / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
row.update(status="independent_accepted_intaken_current_union_joint_pending", artifact_available=True, independent_acceptance=True, acceptance_evidence=review_path.relative_to(ROOT).as_posix(), independent_result=review["junit"], independent_finished_at=review["finished_at"], integrated=True, integrated_at=at, intake_evidence=(out / "receipt.json").relative_to(ROOT).as_posix(), joint_verification=False, whole_package_complete=False, checked_at=at, consecutive_failed_actual_deliveries=0)
core_row.update(status="independent_accepted_intaken_current_union_joint_pending", artifact_available=True, independent_acceptance=True, acceptance_evidence=core_review_path.relative_to(ROOT).as_posix(), independent_result=core_review["junit"], independent_finished_at=core_review["finished_at"], integrated=True, integrated_at=at, intake_evidence=(out / "receipt.json").relative_to(ROOT).as_posix(), joint_verification=False, whole_package_complete=False, checked_at=at)
rows["CURRENT-JOINT-R20"].update(status="intaken_current_union_joint_pending", evidence="artifacts/coordinator-r20-job-cli-intaken-20261015", checked_at=at)
ledger["current_accepted_stage"].update(is_current_root=False, current_root_status="R20 accepted Job-to-CLI consumer intaken; previous R19 selected2314/six0 historical; fresh full union pending")
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "continuation-r6.json"
continuation = json.loads(path.read_text(encoding="utf-8"))
continuation.update(updated_at=at, current_joint="artifacts/coordinator-r20-job-cli-intaken-20261015", current_joint_status="intaken_current_union_joint_pending", current_root_status=ledger["current_accepted_stage"]["current_root_status"], prior_pass_is_current_root=False, latest_joint_attempt_passed=False, latest_joint_attempt="artifacts/coordinator-r20-job-cli-intaken-20261015", active_phase="R20 accepted consumer intaken; retain R19 full collection plus every additional boundary/producer test and six commands")
path.write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
note = f"## {at} · R20 accepted consumer and shared token intaken; current full joint pending\n\nTask {producer_id} independent {review['junit']['tests']}/0, four commands0, finish {review['finished_at']}; source/native/probes/ownership stable. Native {core_row['agent_task_id']} independent397/four0 retained. {len(files)} files intaken with backups/before-after SHA: artifacts/intake-job-cli-window-r20-20261015/receipt.json. Parent three accepted slices preserved. Prior R19 selected2314/six0 now historical; fresh R20 full union includes every previous collection plus real owner/window/identity, actual SQL snapshot/nonfinite/store boundaries and first-cause callers; six commands and source proof required. No whole packages, real-project/model, formal or portable conclusion.\n\n---\n\n"
for filename in ("DAG.md", "PROGRESS.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"intaken_at": at, "task_id": producer_id, "paths": len(files), "current_joint_passed": False}), flush=True)
