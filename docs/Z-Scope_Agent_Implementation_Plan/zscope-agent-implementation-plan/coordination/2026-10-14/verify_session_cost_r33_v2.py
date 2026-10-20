"""Real native Session builder red/green with a controlled model-free Wiki stage."""
from collections import Counter
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from root_runtime_preflight_r23 import inspect_root_runtime

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-session-cost-r33"
BASE = ROOT / "artifacts/coordinator-session-cost-r33-20261017"
read = lambda path: json.loads(path.read_text(encoding="utf-8"))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")


def snapshot():
    return {path.relative_to(WORK).as_posix():sha(path) for path in WORK.rglob("*") if path.is_file() and path.relative_to(WORK).parts[0]!="artifacts" and not any(part in {"__pycache__",".pytest_cache",".mypy_cache"} for part in path.parts) and path.suffix!=".pyc"}


assert sys.platform=="linux" and not sys.flags.optimize and Path.cwd().resolve()==WORK
assert len(sys.argv)==2 and sys.argv[1] in {"red","green"}
assert not os.environ.get("PYTEST_ADDOPTS") and not os.environ.get("PYTEST_PLUGINS")
phase=sys.argv[1]
prep,frozen=read(BASE/"preparation.json"),read(BASE/"test-freeze.json")
assert sha(ROOT/prep["readonly_source_review"])==prep["readonly_source_review_sha256"]
assert frozen["original_preparation_sha256"]==sha(BASE/"preparation.json")
expected=frozen["complete_inputs"]
if phase=="green":
    change=read(BASE/"candidate.json")
    only_path="zscope/orchestration/scan_session.py"
    assert set(change["candidate_sha256"])=={only_path}
    assert change["before_sha256"]=={only_path:frozen["complete_inputs"][only_path]}
    assert sha(BASE/"candidate"/only_path)==change["candidate_sha256"][only_path]
    causal=read(BASE/"red-causal-audit.json")
    assert causal["strict_current_preentry_red_confirmed"]
    assert causal["red_receipt_sha256"]==sha(BASE/"red/review.json")
    assert causal["red_xml_sha256"]==sha(BASE/"red/results.xml")
    expected=expected|change["candidate_sha256"]
before=snapshot()
assert len(before)==1078 and before==expected
configs={path.relative_to(WORK).as_posix():sha(path) for name in ("conftest.py","pytest.ini",".pytest.ini","mypy.ini",".mypy.ini","tox.ini","setup.cfg","pyproject.toml") for path in WORK.rglob(name) if path.is_file()}
assert configs=={"pyproject.toml":before["pyproject.toml"]}
assert all(sha(ROOT/path)==digest for path,digest in prep["root_inputs"].items())
runtime=inspect_root_runtime(require_slot=True)
native=Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
native_before=sha(native)
identities=Counter({("tests.test_session_preentry_cost_r33",f"test_real_instance_builder_retains_current_preentry_cost_and_service[{value}]"):1 for value in ("True","False")})
references=[Path(__file__),HERE/"test_slot.py",HERE/"root_runtime_preflight_r23.py",BASE/"preparation.json",BASE/"test-freeze.json",BASE/"fixed-test.py",ROOT/prep["readonly_source_review"]]
if phase=="green":
    references += [BASE/"candidate.json",BASE/"red/review.json",BASE/"red/results.xml",BASE/"red-causal-audit.json"]
refs={str(path):sha(path) for path in references}
target=BASE/phase
target.mkdir(exist_ok=False)
write(target/"preflight.json",dict(actual_task="/root",started_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),phase=phase,inputs=before,configurations=configs,references_sha256=refs,expected_counter=[list(key)+[value] for key,value in identities.items()],runtime=runtime,provider_requests=False,real_Wiki_effect_acceptance=False))
command=[sys.executable,"-m","pytest","-q",f"--rootdir={WORK}",f"--confcutdir={WORK}",frozen["fixed_test_path"],f"--junitxml={target/'results.xml'}"]
env=os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"]=str(native)
with (target/"command-0.log").open("w",encoding="utf-8") as stream:
    result=subprocess.run(command,cwd=WORK,env=env,stdout=stream,stderr=subprocess.STDOUT)
tree=ET.parse(target/"results.xml").getroot()
actual=Counter((node.get("classname",""),node.get("name","")) for node in tree.iter("testcase"))
counts=dict(tests=len(list(tree.iter("testcase"))),failures=len(list(tree.iter("failure"))),errors=len(list(tree.iter("error"))),skipped=len(list(tree.iter("skipped"))))
gates=dict(complete1078_unchanged=snapshot()==before,root1065_unchanged=all(sha(ROOT/path)==digest for path,digest in prep["root_inputs"].items()),exact2_counter=actual==identities,fixed_test_unchanged=sha(WORK/frozen["fixed_test_path"])==frozen["fixed_test_sha256"],references_unchanged=all(sha(Path(path))==digest for path,digest in refs.items()),native_unchanged=sha(native)==native_before)
if phase=="green":
    red=read(BASE/"red/review.json")
    gates["valid_red_preserved"]=red["valid_red"]
    gates["red_green_counter_exact"]=red["case_counter"]==[list(key)+[value] for key,value in sorted(actual.items())]
valid=all(gates.values()) and counts["tests"]==2 and counts["errors"]==counts["skipped"]==0
failed=[node for node in tree.iter("testcase") if node.find("failure") is not None]
strict_red_cause=bool(len(failed)==1 and failed[0].get("name")=="test_real_instance_builder_retains_current_preentry_cost_and_service[True]" and "total_tokens" in "".join(failed[0].find("failure").itertext()) and "assert 0 == 24" in "".join(failed[0].find("failure").itertext()))
red_ok=phase=="red" and valid and result.returncode==1 and counts["failures"]==1 and strict_red_cause
green_ok=phase=="green" and valid and result.returncode==0 and counts["failures"]==0
write(target/"review.json",dict(actual_task="/root",finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),phase=phase,command=command,returncode=result.returncode,junit=counts,gates=gates,case_counter=[list(key)+[value] for key,value in sorted(actual.items())],valid_red=red_ok,bounded_session_handoff_green_passed=green_ok,provider_requests=False,real_Wiki_or_project_effect_acceptance=False,stage_intake=False,root_intake=False))
print(json.dumps(dict(phase=phase,junit=counts,gates=gates,valid_red=red_ok,green_passed=green_ok)))
raise SystemExit(0 if red_ok or green_ok else 1)
