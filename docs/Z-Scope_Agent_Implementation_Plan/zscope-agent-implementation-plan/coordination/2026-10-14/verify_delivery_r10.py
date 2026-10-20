"""Independent R10 verification, frozen source evidence and strict Linux checks."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from audit_followup_r10 import audit, ROOT, HERE

assert sys.platform == "linux"
kind, label = sys.argv[1:3]
workspace_name = {"astra":"astra-ux-r10", "mcp":"u01-mcp-r10", "s01":"s01-symbol-r10"}[kind]
branch = ROOT / ".coordination/20261014/workspaces" / workspace_name
out = ROOT / "artifacts" / label
out.mkdir(exist_ok=False)
(out/"launcher.py").write_bytes(Path(__file__).read_bytes())
ownership = audit(workspace_name)
assert not ownership["nonowned_changes"], ownership["nonowned_changes"]
baseline = json.loads((HERE/"followups-r10"/(workspace_name+"-baseline.json")).read_text(encoding="utf-8"))
names = set(row["path"] for row in baseline["files"]) | {row["path"] for row in ownership["changes"]}
def hashes():
    return {name:hashlib.sha256((branch/name).read_bytes()).hexdigest() for name in sorted(names)}
before = hashes()
files = {row["path"]:row["after"] for row in ownership["changes"]}
for name, sha in files.items():
    target=out/"source-before"/name
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes((branch/name).read_bytes())
    assert hashlib.sha256(target.read_bytes()).hexdigest()==sha
if kind=="astra":
    tests=["test_agent_workbench_ui","test_config_editor_http","test_project_preparation","test_config_v3_preparation","test_acceptance_projection","test_protocol_review_ui","test_tool_registry"]
    black=["tests/test_agent_workbench_ui.py"]
elif kind=="mcp":
    tests=["test_mcp_http_server","test_mcp_policy","test_mcp_read_only","test_mcp_security","test_mcp_jobs","test_scan_jobs","test_scan_job_execution","test_scan_jobs_http_api","test_job_session_scheduler","test_scan_job_work_queue","test_config_v3_entrypoints"]
    black=[name for name in files if name.endswith(".py")]
else:
    tests=["test_full_symbol_build_scope","test_instance_symbol_native","test_instance_analysis","test_all_variant_scan","test_build_context","test_candidate_build_identity","test_candidate_ledger","test_incremental_semantic_modeling","test_lifecycle_paths","test_native_model_cache","test_parallel_entry_budget","test_parallel_shared_semantics","test_protocol_incremental_equivalence","test_report_assembler","test_retained_slot_teardown","test_scan_session_resume_svf","test_validation_runner","test_function_lookup_index","test_code_index_cache","test_function_info_tool","test_tool_registry"]
    black=["zscope/retrieval/instance_index.py","tests/test_full_symbol_build_scope.py","tests/test_instance_symbol_native.py"]
    tests += ["test_compilation_symbols","test_contract_symbol_ambiguity","test_graph_candidates","test_candidate_pipeline","test_callers_tool","test_type_info_tool"]
probes=[]
if kind=="mcp":
    probes=[str(HERE/"followups-r10/test_mcp_strict_boundary.py")]
if kind=="s01":
    probes=[str(HERE/"followups-r6"/name) for name in ("test_instance_consumer_guard.py","test_instance_navigation_consumers.py","test_instance_validation_scope.py","test_instance_native_body.py")]
    probes += [str(HERE/"followups-r10/test_symbol_consumer_receipts.py")]
env=os.environ.copy()
env.update(Z_SCOPE_TEST_CLANG_INDEXER="/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer",
           ZSCOPE_UI_MULTI_TARGET_EDITING="1",
           ZSCOPE_UI_PLAYWRIGHT_MODULE="/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright",
           ZSCOPE_UI_CHROMIUM="/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome",
           ZSCOPE_UI_EVIDENCE=str(out/"browser"),ZSCOPE_UI_CONFIG_EVIDENCE=str(out/"config"),ZSCOPE_UI_JOB_EVIDENCE=str(out/"owner"))
commands=[
    [sys.executable,"-m","pytest","-q",*[f"tests/{name}.py" for name in tests],*probes,f"--junitxml={out/'results.xml'}"],
    [sys.executable,"-m","compileall","-f","-q","zscope","scripts","test","tests"],
    [sys.executable,"-m","mypy","zscope"],
    [sys.executable,"-m","black","--check",*black],
]
started=dt.datetime.now(dt.timezone.utc).isoformat()
results=[]
for index, command in enumerate(commands):
    wrapped=[sys.executable,str(HERE/"test_slot.py"),"--workspace",str(branch),"--",*command]
    log=out/f"command-{index}.log"
    at=dt.datetime.now(dt.timezone.utc).isoformat()
    with log.open("w",encoding="utf-8") as stream:
        result=subprocess.run(wrapped,env=env,stdout=stream,stderr=subprocess.STDOUT)
    results.append({"command":command,"returncode":result.returncode,"started_at":at,"finished_at":dt.datetime.now(dt.timezone.utc).isoformat(),"log":str(log.relative_to(ROOT))})
    print(json.dumps(results[-1]),flush=True)
    if result.returncode:
        break
suite=ET.parse(out/"results.xml").getroot().find("testsuite")
assert suite is not None
after=hashes()
final_ownership=audit(workspace_name)
accepted=len(results)==4 and all(row["returncode"]==0 for row in results) and before==after and not final_ownership["nonowned_changes"] and all(suite.get(k)=="0" for k in ("failures","errors","skipped"))
lock_delta=[]
if kind=="astra":
    lock=json.loads((branch/"requirements/portable/web-assets.lock.json").read_text(encoding="utf-8"))
    for name, entry in lock["files"].items():
        assert hashlib.sha256((branch/"zscope/web/static/vendor"/name).read_bytes()).hexdigest()==entry["sha256"]
    for name, entry in lock["first_party"].items():
        actual=hashlib.sha256((branch/"zscope/web/static"/name).read_bytes()).hexdigest()
        if actual != entry["sha256"]:
            lock_delta.append({"name":name,"locked":entry["sha256"],"actual":actual})
    assert [row["name"] for row in lock_delta]==["index.html"]
proof={"kind":kind,"task_id":{"s01":"task_0afb819799","mcp":"task_feb229984d","astra":"/root/astra_v3_editor_r6"}[kind],
       "started_at":started,"finished_at":dt.datetime.now(dt.timezone.utc).isoformat(),"junit":suite.attrib,"commands":results,
       "ownership":ownership,"after_ownership":final_ownership,"before_all_inputs":before,"after_all_inputs":after,
       "delivered_hashes":files,"after_hashes":{name:after[name] for name in files},"source_unchanged":before==after,
       "source_snapshot":str(out/"source-before"),"independent_acceptance_passed":accepted,
       "expected_static_lock_delta":lock_delta,"static_lock_full_verify":"pending root intake/update" if kind=="astra" else "not relevant",
       "integrated":False,"whole_package_complete":False,
       "scope":"Actual native fixture and controlled model for S01; real Linux/SQLite/owner/HTTP/browser over controlled scanners and synthetic report/assumption data. Full scanner/consumer/real-project/formal/portable acceptance remains separate."}
(out/"review.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"accepted":accepted,"junit":suite.attrib,"receipt":str(out/"review.json")}))
sys.exit(0 if accepted else 1)
