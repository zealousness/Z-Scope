"""Guarded Wiki/usage/legacy-Session regression after the strict native handoff pair."""
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

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
WORK=ROOT/".coordination/20261014/workspaces/coordinator-session-cost-r33"
BASE=ROOT/"artifacts/coordinator-session-cost-r33-20261017"
OUT=BASE/"regression"
read=lambda p:json.loads(p.read_text(encoding="utf-8"))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()


def write(p,value):
    p.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")


def snapshot():
    return {p.relative_to(WORK).as_posix():sha(p) for p in WORK.rglob("*") if p.is_file() and p.relative_to(WORK).parts[0]!="artifacts" and not any(v in {"__pycache__",".pytest_cache",".mypy_cache"} for v in p.parts) and p.suffix!=".pyc"}


def configs():
    return {p.relative_to(WORK).as_posix():sha(p) for name in ("conftest.py","pytest.ini",".pytest.ini","mypy.ini",".mypy.ini","tox.ini","setup.cfg","pyproject.toml") for p in WORK.rglob(name) if p.is_file()}


def cases(p):
    return Counter((n.get("classname",""),n.get("name","")) for n in ET.parse(p).getroot().iter("testcase"))


assert sys.platform=="linux" and not sys.flags.optimize and Path.cwd().resolve()==WORK
assert not os.environ.get("PYTEST_ADDOPTS") and not os.environ.get("PYTEST_PLUGINS")
prep,frozen,candidate=read(BASE/"preparation.json"),read(BASE/"test-freeze-v2.json"),read(BASE/"candidate.json")
green=read(BASE/"green2/review.json")
assert green["bounded_session_handoff_green_passed"] and all(green["gates"].values())
assert sha(ROOT/prep["readonly_source_review"])==prep["readonly_source_review_sha256"]
source_review=ROOT/"artifacts/coordinator-session-cost-source-review-r33-20261017/launcher-v3-session-bc0c-source-review.json"
assert read(source_review)["bounded_session_handoff_source_review_passed"]
before=snapshot()
assert len(before)==1078 and before==frozen["complete_inputs"]|candidate["candidate_sha256"]
config_before=configs()
assert config_before=={"pyproject.toml":before["pyproject.toml"]}
assert all(sha(ROOT/p)==digest for p,digest in prep["root_inputs"].items())
runtime=inspect_root_runtime(require_slot=True)
native=Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
assert sha(native)=="d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
prior=cases(BASE/"green2/results.xml")
assert sum(prior.values())==2
refs={str(p):sha(p) for p in (Path(__file__),HERE/"test_slot.py",HERE/"root_runtime_preflight_r23.py",BASE/"preparation.json",BASE/"test-freeze-v2.json",BASE/"candidate.json",BASE/"candidate/zscope/orchestration/scan_session.py",BASE/"fixed-test-v2.py",BASE/"green2/review.json",BASE/"green2/results.xml",BASE/"red2-causal-audit.json",source_review)}
tests=[frozen["fixed_test_path"],"tests/test_wiki_workflow.py","tests/test_wiki_service.py","tests/test_validator_project_knowledge.py","tests/test_scan_session_resume_svf.py","tests/test_semantic_modeling_usage.py","tests/test_modeling_provider_usage.py","tests/test_llm_client_tokens.py","tests/test_scan_token_budget.py"]
assert len(tests)==len(set(tests))==9 and all((WORK/p).is_file() for p in tests)
commands=[
    [sys.executable,"-m","pytest","-q",f"--rootdir={WORK}",f"--confcutdir={WORK}",*tests,f"--junitxml={OUT/'results.xml'}"],
    [sys.executable,"-m","compileall","-f","-q","zscope","scripts","test","tests"],
    [sys.executable,"-m","mypy","zscope"],
    [sys.executable,"-m","mypy","--no-incremental","zscope"],
    [sys.executable,"-m","black","--check","zscope/orchestration/scan_session.py",frozen["fixed_test_path"]],
]
OUT.mkdir(exist_ok=False)
write(OUT/"preflight.json",dict(actual_task="/root",started_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),complete_inputs=before,configurations=config_before,references_sha256=refs,runtime=runtime,prior_counter=[list(k)+[v] for k,v in sorted(prior.items())],provider_requests=False,real_Wiki_effect_acceptance=False))
env=os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"]=str(native)
results=[]
for i,command in enumerate(commands):
    started=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    with (OUT/f"command-{i}.log").open("w",encoding="utf-8") as stream:
        result=subprocess.run(command,cwd=WORK,env=env,stdout=stream,stderr=subprocess.STDOUT)
    results.append(dict(argv=command,returncode=result.returncode,started_at=started,finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()))
    print(json.dumps(dict(command_index=i,returncode=result.returncode)),flush=True)
tree=ET.parse(OUT/"results.xml").getroot()
counts=dict(tests=len(list(tree.iter("testcase"))),failures=len(list(tree.iter("failure"))),errors=len(list(tree.iter("error"))),skipped=len(list(tree.iter("skipped"))))
gates=dict(complete1078_unchanged=snapshot()==before,configurations_unchanged=configs()==config_before,root1065_unchanged=all(sha(ROOT/p)==digest for p,digest in prep["root_inputs"].items()),references_unchanged=all(sha(Path(p))==digest for p,digest in refs.items()),native_unchanged=sha(native)=="d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399",original_pair_retained=not(prior-cases(OUT/"results.xml")))
passed=all(gates.values()) and all(r["returncode"]==0 for r in results) and counts["tests"]>2 and counts["failures"]==counts["errors"]==counts["skipped"]==0
write(OUT/"review.json",dict(actual_task="/root",finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),commands=results,junit=counts,gates=gates,bounded_session_regression_and_full_quality_passed=passed,stage_intake=False,root_intake=False,joint_validation_passed=False,real_Wiki_effect_acceptance=False))
print(json.dumps(dict(passed=passed,junit=counts,gates=gates)))
raise SystemExit(0 if passed else 1)
