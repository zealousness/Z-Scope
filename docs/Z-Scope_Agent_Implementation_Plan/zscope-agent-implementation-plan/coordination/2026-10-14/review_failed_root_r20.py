"""Preserve the actual failed joint run, separating environment and other gates."""
from pathlib import Path
from collections import Counter
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-r20-job-cli-intaken-20261015"
source = json.loads((OUT / "source-evidence.json").read_text(encoding="utf-8"))
assert source["direct_source_unchanged"] and source["before"] == source["after"]
assert source["native_before"] == source["native_after"] and source["launcher_before"] == source["launcher_after"]
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in source["after"].items())
assert len(source["commands"]) == 1 and source["commands"][0]["returncode"] == 1
root = ET.parse(OUT / "results.xml").getroot()
suites = root.findall("testsuite")
counts = {k: sum(int(s.get(k, "0")) for s in suites) for k in ("tests", "failures", "errors", "skipped")}
assert counts == {"tests": 2539, "failures": 58, "errors": 16, "skipped": 159}
skip_reasons, failure_reasons, failed_modules = Counter(), Counter(), Counter()
noncompiler = []
for case in root.iter("testcase"):
    for tag in ("failure", "error", "skipped"):
        item = case.find(tag)
        if item is None:
            continue
        text = item.text or item.get("message", "")
        if tag == "skipped":
            skip_reasons[item.get("message", text)] += 1
        else:
            final_line = text.splitlines()[-1] if text.splitlines() else text
            failure_reasons[final_line] += 1
            failed_modules[case.get("classname", "")] += 1
            if case.get("classname") in {"tests.test_mcp_jobs", "tests.test_job_remaining"}:
                noncompiler.append({"classname": case.get("classname"), "name": case.get("name"), "failure_text": text})
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
proof = {"verified_at": at, "finished_at": source["captured_at"], "junit": counts, "passed": 2306, "source_inputs": len(source["after"]), "source_unchanged": True, "native_unchanged": True, "launcher_unchanged": True, "commands_executed": 1, "commands_required": 6, "quality_completed": False, "joint_verification_passed": False, "whole_packages_complete": False, "skip_reasons": dict(skip_reasons), "failure_last_lines": failure_reasons.most_common(), "failed_modules": dict(failed_modules), "other_failures_requiring_independent_diagnosis": noncompiler, "environment_probes": "artifacts/coordinator-root-tool-environment-r21-20261015", "environment_diagnosis": "Direct WSL Python PATH cannot resolve clang; unchanged installed toolchain resolves it in existing login shell. No missing tool installation or native binary mutation inferred. MCP/remaining failures remain separate.", "clock_problem_resolved": False, "scope": "Failed real current Root union. No native skips accepted, no historical or independent subset substitution; all original artifacts retained, remaining five quality commands not executed after pytest failure."}
assert not (OUT / "review.json").exists()
(OUT / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
rows = {r["id"]: r for r in ledger["tasks"]}
rows["CURRENT-JOINT-R20"].update(status="failed_current_union_wrong_compiler_PATH_and_two_other_gates", evidence=(OUT / "review.json").relative_to(ROOT).as_posix(), finished_at=proof["finished_at"], result=counts, joint_verification=False, quality_completed=False, checked_at=at)
ledger["current_accepted_stage"].update(is_current_root=False, current_root_status="R20 nine files intaken, first current union failed:58 failures16 errors159 skips; direct WSL compiler PATH invalid; MCP/remaining failures separately pending; quality not completed")
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "continuation-r6.json"
continuation = json.loads(path.read_text(encoding="utf-8"))
continuation.update(updated_at=at, current_joint_status="failed_current_union_wrong_compiler_PATH_and_two_other_gates", current_joint_result=counts, latest_joint_attempt=(OUT / "review.json").relative_to(ROOT).as_posix(), latest_joint_attempt_passed=False, current_root_status=ledger["current_accepted_stage"]["current_root_status"], active_phase="Use verified existing WSL login toolchain; diagnose MCP/remaining separately before full retry; no UI development dispatched")
path.write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "finished_at": proof["finished_at"], "junit": counts, "skip_reasons": dict(skip_reasons), "top_failure_last_lines": failure_reasons.most_common(5), "failed_modules": dict(failed_modules), "source_unchanged": True, "other_failures": [{**r, "failure_text": r["failure_text"][-5500:]} for r in noncompiler]}, ensure_ascii=False, indent=2), flush=True)
