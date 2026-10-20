"""Coordinator snapshot of a delivered isolated repair, prior to independent run."""
from collections import Counter
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import xml.etree.ElementTree as ET

assert sys.platform == "linux" and not sys.flags.optimize
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BRANCH = ROOT / ".coordination/20261014/workspaces/consumer-exact-repair-r29"
ART = BRANCH / "artifacts/consumer-exact-repair-r29"
OUT = ROOT / "artifacts/consumer-repair-coordinator-inputs-r29-20261017"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def cases(path):
    return Counter((node.get("classname", ""), node.get("name", "")) for node in ET.parse(path).getroot().iter("testcase"))


manifest_path = HERE / "followups-r12/consumer-exact-repair-r29-ownership.json"
manifest = read(manifest_path)
producer_path = ART / "review.json"
producer = read(producer_path)
assert producer["actual_task"] == "/root/consumer_exact_repair_r29"
assert (BRANCH / "DELIVERY.md").is_file()
original = ROOT / ".coordination/20261014/workspaces/astra-instance-consumers-r25"
inputs = {path: sha(BRANCH / path) for path in manifest["source_baseline"]}
assert len(inputs) == 1071 and len(manifest["readonly_paths"]) == 1068
assert all(inputs[path] == digest for path, digest in manifest["readonly_paths"].items())
assert all(sha(original / path) == digest for path, digest in manifest["source_baseline"].items())
old_test = (original / "tests/test_instance_builtin_consumers.py").read_bytes()
assert (BRANCH / "tests/test_instance_builtin_consumers.py").read_bytes().startswith(old_test)
actual = {path.relative_to(BRANCH).as_posix(): sha(path) for directory in ("zscope", "scripts", "test", "tests", "docs/modules") for path in (BRANCH / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"}
assert not set(actual) - set(inputs)
producer_xml = ART / "regression-01.xml"
suites = ET.parse(producer_xml).getroot().findall("testsuite")
counts = {key: sum(int(suite.get(key, "0")) for suite in suites) for key in ("tests", "failures", "errors", "skipped")}
assert counts == dict(tests=893, failures=0, errors=0, skipped=0)
required = cases(ROOT / "artifacts/coordinator-astra-consumers-r28-20261017/results.xml") + cases(ROOT / "artifacts/coordinator-consumer-boundary-probes-r28-20261017/results.xml")
assert sum(required.values()) == 855 and not (required - cases(producer_xml))
assert sum((cases(producer_xml) - required).values()) == 38
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
launcher_review_path = ROOT / "artifacts/consumer-repair-source-review-r29-20261017/launcher-review.json"
assert sha(launcher_review_path) == "f7e953977c1ac88881cae4f61d075541e1d770ecc9f3109ff013328d4dd93c10"
launcher = HERE / "verify_consumer_repair_r29.py"
assert sha(launcher) == "bcff8a838a45ea01418d875a1d205c81d997f179a19c133409c5a7c560609da5"
history = ROOT / "artifacts/astra-consumer-failure-freeze-r28-20261017/history-preservation.json"
artifact_paths = [BRANCH / "DELIVERY.md", *[path for path in ART.rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"]]
artifacts = {path.relative_to(ROOT).as_posix(): sha(path) for path in artifact_paths}
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
OUT.mkdir(exist_ok=False)
for path in manifest["owned_paths"]:
    destination = OUT / "frozen-candidate" / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes((BRANCH / path).read_bytes())
proof = dict(recorded_at=at, actual_task="/root", actual_producer_task="/root/consumer_exact_repair_r29", producer_frozen=True, logical_task="CONSUMER-EXACT-REPAIR-R29", source_after=inputs, readonly_inputs_current=1068, old_test_file_complete_prefix_preserved=True, producer_final_xml=producer_xml.relative_to(ROOT).as_posix(), producer_junit=counts, original852_plus_immutable3_and_new38_case_counter_preserved=True, producer_artifacts_sha256=artifacts, failure_history_receipt=history.relative_to(ROOT).as_posix(), failure_history_sha256=sha(history), independent_launcher=launcher.relative_to(ROOT).as_posix(), independent_launcher_sha256=sha(launcher), launcher_source_review=launcher_review_path.relative_to(ROOT).as_posix(), launcher_source_review_sha256=sha(launcher_review_path), independent_acceptance=False, root_intake=False, stage_intake=False, root_joint_verification=False)
(OUT / "frozen-inputs.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
assert inputs == {path: sha(BRANCH / path) for path in inputs}
assert all(sha(ROOT / path) == digest for path, digest in artifacts.items())
print(json.dumps(dict(recorded_at=at, receipt=(OUT / "frozen-inputs.json").relative_to(ROOT).as_posix(), source_inputs=1071, producer_junit=counts)))
