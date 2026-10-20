"""Create a new candidate revision with a causal, guarded original-red prerequisite."""
from pathlib import Path
import datetime as dt
import difflib
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BASE = ROOT / "artifacts/stage-joint-launcher-draft-r35-20261017"
OLD, NEW = BASE / "revision-2", BASE / "revision-3"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Use unoptimized Linux Python")
source = OLD / "verify_stage_joint_r35.py"
assert sha(source) == "c584f8a8cacfaabf9f45319f1e7b90345e913f5105f332997bcdceb957e0d98b"
old = source.read_text(encoding="utf-8")
needle = '    job_counter = cases(red_path)\n    require(bool(job_counter) and job_counter == cases(green_path), "actual full native-job red/green Counters differ")\n'
assert old.count(needle) == 1
replacement = '''    job_counter = cases(red_path)
    require(bool(job_counter) and job_counter == cases(green_path), "actual full native-job red/green Counters differ")
    red_counts = junit(red_path)
    require(red_counts["tests"] == sum(job_counter.values()) and red_counts["failures"] > 0 and red_counts["errors"] == red_counts["skipped"] == 0, "original red must contain actual failures without setup errors or skips")
    red_audit_path = bind_ref(job["valid_red_audit"], refs)
    red_audit = read(red_audit_path)
    require(red_audit["schema"] == "zscope.stage-native-job-valid-red.r35.v1" and red_audit["actual_task"] == "/root" and red_audit["causal_review_passed"] is True and red_audit["evidence_guards_passed"] is True, "coordinator causal original-red audit missing")
    require(red_audit["results_xml"] == str(red_path) and red_audit["results_xml_sha256"] == sha(red_path) and red_audit["test_sha256"] == before["tests/test_job_runtime_footprint_r34.py"] and red_audit["case_counter"] == case_rows(job_counter) and red_audit["junit"] == red_counts, "causal audit is not bound to the exact actual red XML/test/Counter")
    merge_refs(refs, red_audit["reference_sha256"])
    raw_red_path = bind_ref(red_audit["raw_red_receipt"], refs)
    raw_red = read(raw_red_path)
    require(raw_red["test_started"] is True and raw_red["evidence_guards_passed"] is True and bool(raw_red["guards"]) and all(value is True for value in raw_red["guards"].values()), "raw original-red execution did not preserve all evidence guards")
    require(raw_red["new_test_sha256"] == red_audit["test_sha256"] and raw_red["case_counter"] == case_rows(job_counter) and raw_red["junit"] == red_counts and raw_red["artifact_sha256"]["results.xml"] == sha(red_path), "raw red receipt/test/actual XML identities differ")
    require(bool(raw_red["commands"]) and any(command["returncode"] == 1 for command in raw_red["commands"]), "actual original-red pytest failure execution absent")
    failed_identities = {(node.get("classname", ""), node.get("name", "")) for node in ET.parse(red_path).getroot().iter("testcase") if node.find("failure") is not None}
    targets = red_audit["valid_target_failure_identities"]
    require(isinstance(targets, list) and bool(targets) and all(isinstance(row, list) and len(row) == 2 and all(isinstance(value, str) for value in row) for row in targets), "actual causal failure targets missing")
    target_identities = {tuple(row) for row in targets}
    original_job = ("tests.test_scan_session_jobs", "test_job_scan_runs_exact_instances_on_the_queue")
    require(len(target_identities) == len(targets) and original_job in target_identities and target_identities <= failed_identities and all(job_counter[identity] == 1 for identity in target_identities), "original real job failure and causal targets must actually fail once in the frozen red XML")
    causal_projection = bind_ref(red_audit["causal_projection"], refs)
    require(str(causal_projection) in red_audit["reference_sha256"] and read(causal_projection)["causal_review_passed"] is True, "fixed per-ID first-cause projection absent")
'''
new = old.replace(needle, replacement)
assert not NEW.exists()
NEW.mkdir()
(NEW / "verify_stage_joint_r35.py").write_text(new, encoding="utf-8", newline="\n")
pending = json.loads((OLD / "aggregate-intake.pending.json").read_text(encoding="utf-8"))
assert pending["status"] == "pending" and not pending["stage_intake"]
pending["pending_dependencies"].append("Coordinator guarded original-red first-cause audit bound to raw execution receipt, actual failed target IDs, test SHA and exact red XML/Counter")
pending["native_job_evidence"]["valid_red_audit"] = {"path": None, "sha256": None}
(NEW / "aggregate-intake.pending.json").write_text(json.dumps(pending, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
contract = (OLD / "INTAKE-CONTRACT.md").read_text(encoding="utf-8").rstrip()
contract += "\n\n## Revision 3: guarded original-red causality\n\nThe coordinator binds native_job_evidence.valid_red_audit to a zscope.stage-native-job-valid-red.r35.v1 record. It must identify /root, causal_review_passed/evidence_guards_passed, actual results_xml and SHA, fixed test_sha256, full raw case_counter and JUnit counts, raw_red_receipt, nonempty unique valid_target_failure_identities, fixed causal_projection and conflict-free reference_sha256. The original SessionJobs single-case identity must actually fail once; all target identities must be real failure nodes. The red XML must contain at least one failure with zero errors/skips. The raw runner receipt must prove test_started, every guard true, exact same test/Counter/XML SHA and a real pytest rc1. A separate causal projection links each target to the real first failed gate; feature absence and setup failures remain separately classified. Existing invalid red receipts are preserved. No pending field is a pass or an execution grant.\n"
(NEW / "INTAKE-CONTRACT.md").write_text(contract, encoding="utf-8", newline="\n")
(NEW / "candidate-delta.patch").write_text("".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True), fromfile="revision-2/verify_stage_joint_r35.py", tofile="revision-3/verify_stage_joint_r35.py")), encoding="utf-8", newline="\n")
receipt = dict(actual_task="/root", revised_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), old_candidate_sha256=sha(source), candidate_sha256=sha(NEW / "verify_stage_joint_r35.py"), change="Bind guarded actual failed original-red execution and per-ID first-cause audit", old_candidate_unchanged=sha(source)=="c584f8a8cacfaabf9f45319f1e7b90345e913f5105f332997bcdceb957e0d98b", execution_count=0, independent_source_review_passed=False, installed=False, joint_validation_passed=False, artifacts_sha256={p.name:sha(p) for p in NEW.iterdir() if p.is_file()})
(NEW / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(receipt))
