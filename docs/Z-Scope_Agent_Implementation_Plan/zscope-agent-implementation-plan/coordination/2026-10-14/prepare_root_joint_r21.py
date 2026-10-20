"""Create a fresh Root retry launcher; preserve failed R20 launchers and logs."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
old = HERE / "verify_current_root_r20.py"
assert old.read_bytes() == (ROOT / "artifacts/coordinator-r20-job-cli-intaken-20261015/launcher.py").read_bytes()
def replace_once(text, before, after):
    assert text.count(before) == 1, before
    return text.replace(before, after)
main = old.read_text(encoding="utf-8")
main = replace_once(main, 'ROOT = HERE.parents[4]\nOUT = ', '''ROOT = HERE.parents[4]
from root_runtime_preflight_r21 import inspect_root_runtime
runtime_preflight = inspect_root_runtime()
fixture_intake_path = ROOT / "artifacts/intake-root-fixtures-r21-20261015/receipt.json"
fixture_intake = json.loads(fixture_intake_path.read_text(encoding="utf-8"))
assert fixture_intake["isolated_acceptance_passed"] and fixture_intake["independent_static_review_passed"]
assert len(fixture_intake["files"]) == 2 and not fixture_intake["product_changed"]
failed_inputs = json.loads((ROOT / "artifacts/coordinator-r20-job-cli-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
fixture_overrides = {r["path"]: r["after"] for r in fixture_intake["files"]}
assert set(fixture_overrides) == {"tests/test_mcp_jobs.py", "tests/test_job_remaining.py"}
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == fixture_overrides.get(p, sha) for p, sha in failed_inputs.items())
assert len(sys.argv) == 2 and sys.argv[1].startswith("coordinator-r21-")
OUT = ''')
main = replace_once(main, 'OUT.mkdir(exist_ok=False)\n', 'OUT.mkdir(exist_ok=False)\n(OUT / "runtime-preflight.json").write_text(json.dumps(runtime_preflight, indent=2) + "\\n", encoding="utf-8", newline="\\n")\n')
main = replace_once(main, 'r19_source_paths.update(R20_OVERRIDES)\n', 'r19_source_paths.update(R20_OVERRIDES)\nr19_source_paths.update(fixture_overrides)\nr19_black_paths.update(fixture_overrides)\n')
main = replace_once(main, 'for name in ("test_slot.py", "verify_joint_with_clock_r21.py")', 'for name in ("test_slot.py", "verify_joint_with_clock_r21.py", "verify_current_root_r21.py", "verify_joint_retry_with_clock_r21.py", "root_runtime_preflight_r21.py")')
main = replace_once(main, '"environment_evidence": "artifacts/coordinator-runtime-r18-20261015.json",', '"environment_evidence": str((OUT / "runtime-preflight.json").relative_to(ROOT)),\n    "runtime_preflight": runtime_preflight,\n    "fixture_intake": fixture_intake_path.relative_to(ROOT).as_posix(),\n    "original_failed_union": "artifacts/coordinator-r20-job-cli-intaken-20261015/review.json",')
clock = (HERE / "verify_joint_with_clock_r21.py").read_text(encoding="utf-8")
clock = replace_once(clock, 'label.startswith("coordinator-r20-")', 'label.startswith("coordinator-r21-")')
clock = replace_once(clock, 'launcher = HERE / "verify_current_root_r20.py"', 'launcher = HERE / "verify_current_root_r21.py"')
publisher = (HERE / "publish_joint_r20.py").read_text(encoding="utf-8")
publisher = replace_once(publisher, 'OUT = ROOT / "artifacts/coordinator-r20-job-cli-intaken-20261015"', 'OUT = ROOT / "artifacts/coordinator-r21-verified-environment-20261015"')
publisher = replace_once(publisher, 'assert count >= 2314', 'assert count >= 2539')
publisher = replace_once(publisher, 'assert old_cases <= new_cases, list((old_cases - new_cases).items())[:10]', '''assert old_cases <= new_cases, list((old_cases - new_cases).items())[:10]
failed_cases = Counter((c.get("classname"), c.get("name")) for c in ET.parse(ROOT / "artifacts/coordinator-r20-job-cli-intaken-20261015/results.xml").getroot().iter("testcase"))
assert failed_cases <= new_cases, list((failed_cases - new_cases).items())[:10]
runtime = read(OUT / "runtime-preflight.json")
assert runtime["passed"] and runtime["ext4_unlinked_fd_truncate"] and runtime["temporary_mount"][1] == "ext4"
assert all(runtime["tools"][n] for n in ("clang", "clang++", "gcc", "cmake", "clangd", "node"))
assert runtime["native_sha256"] == source["native_after"]
fixture_intake = read(ROOT / source["fixture_intake"])
assert fixture_intake["isolated_acceptance_passed"] and fixture_intake["independent_static_review_passed"] and not fixture_intake["product_changed"]
assert len(fixture_intake["files"]) == 2
for r in fixture_intake["files"]:
    assert source["after"][r["path"]] == r["after"]''')
publisher = replace_once(publisher, 'assert all(source["after"][p] == overrides.get(p, h) for p, h in prior_source["after"].items())', 'overrides.update({r["path"]: r["after"] for r in fixture_intake["files"]})\nassert all(source["after"][p] == overrides.get(p, h) for p, h in prior_source["after"].items())')
publisher = replace_once(publisher, 'proof.update(all_current_root_validation_passed=False,', 'proof.update(runtime_preflight=runtime, fixture_intake=source["fixture_intake"], preserved_failed_trial="artifacts/coordinator-r20-job-cli-intaken-20261015/review.json", all_current_root_validation_passed=False,')
publisher = publisher.replace('rows["CURRENT-JOINT-R20"].update(status="current_complete', 'rows["CURRENT-JOINT-R21"].update(status="current_complete')
publisher = publisher.replace('superseded_by="CURRENT-JOINT-R20"', 'superseded_by="CURRENT-JOINT-R21"')
publisher = replace_once(publisher, 'ledger["current_accepted_stage"] = ', 'rows["CURRENT-JOINT-R20"].update(is_current_root=False, superseded_by="CURRENT-JOINT-R21", failure_receipt="artifacts/coordinator-r20-job-cli-intaken-20261015/review.json")\nledger["current_accepted_stage"] = ')
publisher = publisher.replace('R20 selected full union', 'R21 selected full union').replace('R20 current union passed;', 'R21 current union passed;').replace('R20 current selected full union passed', 'R21 current selected full union passed')
files = {"verify_current_root_r21.py": main, "verify_joint_retry_with_clock_r21.py": clock, "publish_joint_r21.py": publisher}
hashes = {}
for name, content in files.items():
    target = HERE / name
    assert not target.exists()
    compile(content, str(target), "exec")
    target.write_text(content, encoding="utf-8", newline="\n")
    hashes[name] = hashlib.sha256(target.read_bytes()).hexdigest()
receipt = {"captured_at": dt.datetime.now(dt.timezone.utc).isoformat(), "files": hashes, "root_product_changed": False, "prior_r20_launchers_changed": False, "required_test_case_floor": 2539, "commands_required": 6, "default_fd_capture": True, "exactly_one_external_test_slot": True, "login_shell_required": True, "new_preflight_before_artifact_creation": True}
target = HERE / "followups-r12/root-launcher-r21-setup.json"
assert not target.exists()
target.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(receipt), flush=True)
