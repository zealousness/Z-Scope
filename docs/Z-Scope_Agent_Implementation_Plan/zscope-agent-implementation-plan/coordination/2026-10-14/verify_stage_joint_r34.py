"""Complete-input guarded Stage union; old failed and passed collections remain gates."""
from collections import Counter
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from root_runtime_preflight_r23 import inspect_root_runtime

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
STAGE=ROOT/".coordination/20261014/workspaces/coordinator-instance-integration-r24"
INTAKE=ROOT/"artifacts/stage-shared-intake-r34-20261017/receipt.json"
OUT=ROOT/"artifacts/coordinator-stage-joint-r34-20261017"
read=lambda p:json.loads(p.read_text(encoding="utf-8"))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()


def write(p,value):
    p.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")


def snapshot():
    return {p.relative_to(STAGE).as_posix():sha(p) for p in STAGE.rglob("*") if p.is_file() and p.relative_to(STAGE).parts[0]!="artifacts" and not any(v in {"__pycache__",".pytest_cache",".mypy_cache"} for v in p.parts) and p.suffix!=".pyc" and p.name!="DELIVERY.md"}


def configs():
    return {p.relative_to(STAGE).as_posix():sha(p) for name in ("conftest.py","pytest.ini",".pytest.ini","mypy.ini",".mypy.ini","tox.ini","setup.cfg","pyproject.toml") for p in STAGE.rglob(name) if p.is_file()}


def cases(p):
    return Counter((n.get("classname",""),n.get("name","")) for n in ET.parse(p).getroot().iter("testcase"))


def host_inputs():
    tool=Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
    assert sha(tool)=="d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
    linked=subprocess.run(["ldd",str(tool)],capture_output=True,text=True,timeout=10)
    assert linked.returncode==0 and "not found" not in linked.stdout+linked.stderr
    libraries={Path(v) for v in re.findall(r"/[^\s()]+",linked.stdout)}
    assert libraries and all(p.is_file() for p in libraries)
    chrome=Path("/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome")
    playwright=Path("/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright/package.json")
    files={str(p):dict(sha256=sha(p),physical=str(p.resolve(strict=True))) for p in libraries|{tool,Path("/usr/include/stdlib.h"),Path("/usr/include/features.h"),chrome,playwright}}
    installation={}
    for header in (Path("/usr/include/stdlib.h"),Path("/usr/include/features.h")):
        for p in (header,*header.parents):
            stat=p.lstat()
            installation[str(p)]=dict(uid=stat.st_uid,mode=stat.st_mode,physical=str(p.resolve(strict=True)))
    return dict(files=files,standard_installation=installation)


if sys.platform!="linux" or sys.flags.optimize or Path.cwd().resolve()!=STAGE:
    raise RuntimeError("Linux, unoptimized Python and the fixed Stage workspace are required")
if any(os.environ.get(k) for k in ("PYTHONOPTIMIZE","PYTEST_ADDOPTS","PYTEST_PLUGINS")):
    raise RuntimeError("External test plugins/options and optimization are forbidden")
intake=read(INTAKE)
assert intake["stage_intake"] and intake["bounded_independent_acceptance_passed"] and intake["shared_source_review_passed"] and not intake["root_intake"]
before=snapshot()
assert before==intake["complete_inputs_after"]
config_before=configs()
assert config_before=={"pyproject.toml":before["pyproject.toml"]}
root_inputs=intake["root_inputs"]
assert len(root_inputs)==1065 and all(sha(ROOT/p)==digest for p,digest in root_inputs.items())
runtime,host_before=inspect_root_runtime(require_slot=True),host_inputs()
r32=read(ROOT/"artifacts/coordinator-stage-joint-r32-20261017/review.json")
old_tests=r32["commands"][2]["argv"][6:-1]
assert len(old_tests)==198
cost_tests=["tests/test_instance_partial_recovery_integration.py","tests/test_instance_result_recovery.py","tests/test_job_bound_instance_results.py","tests/test_instance_semantics_integration.py","tests/test_instance_analysis.py","tests/test_scan_checkpoint_resume.py","tests/test_scan_session_instances.py","tests/test_scan_session_jobs.py","tests/test_scan_token_budget.py","tests/test_report_views.py","tests/test_report_schema_v2.py","tests/test_parallel_entry_budget.py","tests/test_parallel_markdown_report.py","tests/test_global_modeler.py","tests/test_semantic_modeling_usage.py","tests/test_modeling_provider_usage.py","tests/test_llm_client_tokens.py"]
new_tests=["tests/test_instance_currentness_revocation_r33.py","tests/test_instance_recovery_cost_r33.py","tests/test_review_current_revisions_r33.py","tests/test_native_classifier_currentness_r33.py","tests/test_session_preentry_cost_r33.py"]
session_tests=["tests/test_wiki_workflow.py","tests/test_wiki_service.py","tests/test_validator_project_knowledge.py","tests/test_scan_session_resume_svf.py"]
additional_tests=intake["additional_regression_test_paths"]
assert isinstance(additional_tests,list) and all(isinstance(p,str) for p in additional_tests)
tests=list(dict.fromkeys(old_tests+cost_tests+new_tests+session_tests+additional_tests))
assert tests[:198]==old_tests and all((Path(p) if Path(p).is_absolute() else STAGE/p).is_file() for p in tests)
resolved_tests=[(Path(p) if Path(p).is_absolute() else STAGE/p).resolve(strict=True) for p in tests]
assert len(resolved_tests)==len(set(resolved_tests)), "test path aliases would collect a file twice"
authority=ROOT/"artifacts/s01-authority-probe-r24-20261016/test_s01_authority_probe.py"
prior_paths=dict(root_r23=ROOT/"artifacts/coordinator-r23-ui-projection-union-20261016/results.xml",stage_r30=ROOT/"artifacts/coordinator-stage-regression-r30-20261017/results.xml",s01_r32=ROOT/"artifacts/coordinator-s01-repair-r31-r32-independent-20261017/results.xml",failed_stage_r32=ROOT/"artifacts/coordinator-stage-joint-r32-20261017/results.xml",composite_r33=ROOT/"artifacts/coordinator-final-composite-r33-20261017/independent/results.xml",review_r33=ROOT/"artifacts/coordinator-review-revision-repair-r33-20261017/regression/results.xml",session_r33=ROOT/"artifacts/coordinator-session-cost-r33-20261017/regression/results.xml",currentness_original755=ROOT/".coordination/20261014/workspaces/stage-currentness-repair-r33/artifacts/stage-currentness-r33/focused-20261017T035157.866301Z/pytest.xml")
prior={name:cases(p) for name,p in prior_paths.items()}
prior_paths["failed_cost_r33"]=ROOT/".coordination/20261014/workspaces/stage-cost-repair-r33/artifacts/stage-cost-r33/regression-usage/pytest.xml"
prior["failed_cost_r33"]=cases(prior_paths["failed_cost_r33"])
assert {name:sum(c.values()) for name,c in prior.items()}==dict(root_r23=2551,stage_r30=1147,s01_r32=209,failed_stage_r32=3543,composite_r33=148,review_r33=271,currentness_original755=755,failed_cost_r33=308,session_r33=89)
expected_prior=Counter()
for c in prior.values():
    for identity,multiplicity in c.items():
        assert identity not in expected_prior or expected_prior[identity]==multiplicity, (identity,"inconsistent prior collection multiplicity")
        expected_prior[identity]=multiplicity
authority_prior=cases(ROOT/"artifacts/coordinator-s01-repair-r31-r32-independent-20261017/authority-r24.xml")
assert sum(authority_prior.values())==4
old_black=r32["commands"][6]["argv"]
assert old_black[:4]==[sys.executable,"-m","black","--check"]
black_paths=list(dict.fromkeys(old_black[4:]+new_tests+additional_tests+["zscope/orchestration/scan_session.py"]))
commands=[
    [sys.executable,"-m","mypy","zscope"],
    [sys.executable,"-m","mypy","--no-incremental","zscope"],
    [sys.executable,"-m","pytest","-q",f"--rootdir={STAGE}",f"--confcutdir={STAGE}",*tests,f"--junitxml={OUT/'results.xml'}"],
    [sys.executable,"-m","pytest","-q",f"--rootdir={STAGE}",f"--confcutdir={STAGE}",str(authority),f"--junitxml={OUT/'authority-r24.xml'}"],
    [sys.executable,"-m","compileall","-f","-q","zscope","scripts","test","tests"],
    [sys.executable,"-m","mypy","scripts/agent_plan_evaluation.py"],
    [sys.executable,"-m","black","--check",*black_paths],
    [sys.executable,"scripts/portable/web_assets.py"],
]
references=[Path(__file__),INTAKE,HERE/"test_slot.py",HERE/"root_runtime_preflight_r23.py",ROOT/"artifacts/coordinator-stage-joint-r32-20261017/review.json",authority,ROOT/"artifacts/coordinator-s01-repair-r31-r32-independent-20261017/authority-r24.xml",*prior_paths.values(),*[Path(p) for p in tests if Path(p).is_absolute()]]
refs=dict(intake["reference_sha256"])
for p in references:
    key,digest=str(p),sha(p)
    assert key not in refs or refs[key]==digest, (key,"frozen reference changed before execution")
    refs[key]=digest
assert all(sha(Path(p))==digest for p,digest in refs.items())
OUT.mkdir(exist_ok=False)
write(OUT/"preflight.json",dict(actual_task="/root",started_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),complete_inputs=before,configurations=config_before,references_sha256=refs,selected_test_files=len(tests),prior_case_counters={name:[list(k)+[v] for k,v in sorted(c.items())] for name,c in prior.items()},authority_counter=[list(k)+[v] for k,v in sorted(authority_prior.items())],runtime=runtime,host_inputs_before=host_before,old198_ordered_collection_retained=True,default_fd_capture=True,test_slot_wrappers=1,root_intake=False))
env=os.environ.copy()
env.update(Z_SCOPE_TEST_CLANG_INDEXER="/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer",ZSCOPE_UI_PLAYWRIGHT_MODULE="/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright",ZSCOPE_UI_CHROMIUM="/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome",ZSCOPE_UI_MULTI_TARGET_EDITING="1")
for key,directory in (("ZSCOPE_UI_EVIDENCE","browser"),("ZSCOPE_UI_CONFIG_EVIDENCE","config"),("ZSCOPE_UI_JOB_EVIDENCE","owner"),("ZSCOPE_INSTANCE_EVIDENCE","native-browser"),("ZSCOPE_UX_BOUNDARY_EVIDENCE","boundaries")):
    env[key]=str(OUT/directory)
results=[]
for i,command in enumerate(commands):
    started=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    with (OUT/f"command-{i}.log").open("w",encoding="utf-8") as stream:
        result=subprocess.run(command,cwd=STAGE,env=env,stdout=stream,stderr=subprocess.STDOUT)
    results.append(dict(argv=command,returncode=result.returncode,started_at=started,finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()))
    print(json.dumps(dict(command_index=i,returncode=result.returncode)),flush=True)
counts={}
for name in ("results","authority-r24"):
    tree=ET.parse(OUT/f"{name}.xml").getroot()
    counts[name]=dict(tests=len(list(tree.iter("testcase"))),failures=len(list(tree.iter("failure"))),errors=len(list(tree.iter("error"))),skipped=len(list(tree.iter("skipped"))))
actual=cases(OUT/"results.xml")
preserved={name:all(actual[identity]==multiplicity for identity,multiplicity in c.items()) for name,c in prior.items()}
gates=dict(all_actual_stage_inputs_unchanged=snapshot()==before,configurations_unchanged=configs()==config_before,root1065_unchanged=all(sha(ROOT/p)==digest for p,digest in root_inputs.items()),references_unchanged=all(sha(Path(p))==digest for p,digest in refs.items()),host_inputs_unchanged=host_inputs()==host_before,all_prior_counters_retained=all(preserved.values()),authority4_exact=cases(OUT/"authority-r24.xml")==authority_prior)
passed=all(gates.values()) and all(r["returncode"]==0 for r in results) and all(c["tests"]>0 and c["failures"]==c["errors"]==c["skipped"]==0 for c in counts.values())
write(OUT/"review.json",dict(actual_task="/root",finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),commands=results,junit=counts,gates=gates,prior_case_counters_preserved=preserved,selected_stage_joint_checks_passed=passed,full_stage_quality_passed=all(gates.values()) and all(results[i]["returncode"]==0 for i in (0,1,4,5,6,7)),root_intake=False,root_joint_verification=False,full_repository_suite_run=False,full_packages_complete=False,real_project_effect_acceptance=False))
print(json.dumps(dict(passed=passed,junit=counts,gates=gates)))
raise SystemExit(0 if passed else 1)
