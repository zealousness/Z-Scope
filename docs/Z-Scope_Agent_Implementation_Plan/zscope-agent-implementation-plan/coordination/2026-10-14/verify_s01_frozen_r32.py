"""Verify frozen delivery and run the already-reviewed independent launcher."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from root_runtime_preflight_r23 import inspect_root_runtime

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORK = ROOT / ".coordination/20261014/workspaces/s01-origin-repair-r31"
OUT = ROOT / "artifacts/coordinator-s01-independent-r32-20261017"
assert sys.platform == "linux" and not sys.flags.optimize and Path.cwd().resolve() == WORK.resolve()
runtime = inspect_root_runtime(require_slot=True)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def cases(path):
    return Counter((node.get("classname", ""), node.get("name", "")) for node in ET.parse(path).getroot().iter("testcase"))


freeze_path = WORK / "artifacts/s01-repair-r31/freeze.json"
freeze = read(freeze_path)
assert freeze["actual_task"] == "/root/s01_origin_repair_r31" and freeze["writes_stopped_after_this_manifest"]
assert freeze["source_sha256"] == {"zscope/semantics/instance_semantics.py": "fcb1fc85b3f50fceff2362b17cf43c403d46afa9dc69454fb7d4e0f92d9bd351", "tests/test_instance_semantics.py": "d13bdd2044fad733bf579c4fb197c3f1e4d73ef2c07a0a0603088abbe3efd701"}
frozen_inputs = freeze["source_sha256"] | freeze["artifact_sha256"]
assert all(sha(WORK / path) == digest for path, digest in frozen_inputs.items())
launcher = HERE / "check_s01_replacement_r31.py"
assert sha(launcher) == "1e77538bcfa9521939255298a7511ac0f13fa4de8dc0433e760c00a802e81d84"
assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == "010f40210b54ba0f79a088312ce5d8be3a82ace0"
OUT.mkdir(exist_ok=False)
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
write(OUT / "preflight.json", dict(started_at=at, actual_task="/root", producer_task=freeze["actual_task"], frozen_at=freeze["frozen_at"], frozen_source_and_artifacts_verified=True, freeze_sha256=sha(freeze_path), old_failure_count=3, launcher_sha256=sha(launcher), runtime_preflight=runtime, independent_acceptance=False, root_intake=False))
(OUT / "launcher.py").write_bytes(Path(__file__).read_bytes())
command = [sys.executable, str(launcher), "independent", "r32-independent"]
result = subprocess.run(command, cwd=WORK)
independent_path = ROOT / "artifacts/coordinator-s01-repair-r31-r32-independent-20261017/review.json"
independent = read(independent_path)
producer_dir = WORK / "artifacts/s01-repair-r31/run3"
new_dir = independent_path.parent
counter_checks = {name: cases(producer_dir / name) == cases(new_dir / name) for name in ("results.xml", "authority-r24.xml")}
assert all(sha(WORK / path) == digest for path, digest in frozen_inputs.items())
verified = result.returncode == 0 and independent["checks_passed"] and all(counter_checks.values())
write(OUT / "review.json", dict(actual_task="/root", actual_producer_task=freeze["actual_task"], finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), command=command, returncode=result.returncode, independent_execution_receipt=independent_path.relative_to(ROOT).as_posix(), independent_junit=independent["junit"], exact_producer_case_counters_preserved=counter_checks, producer_source_artifacts_unchanged=True, frozen_source_sha256=freeze["source_sha256"], execution_checks_passed=verified, source_review_pending=True, independent_acceptance=False, integrated=False, root_joint_verification=False, full_package_complete=False))
print(json.dumps(dict(receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), execution_checks_passed=verified, junit=independent["junit"])))
raise SystemExit(0 if verified else 1)
