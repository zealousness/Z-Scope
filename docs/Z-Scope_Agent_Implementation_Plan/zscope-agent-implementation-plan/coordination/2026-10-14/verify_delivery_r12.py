"""Independent R10 verification, frozen source evidence and strict Linux checks."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from audit_followup_r12 import audit, ROOT, HERE

assert sys.platform == "linux"
kind, label = sys.argv[1:3]
boundary_preflight = "--boundary-preflight" in sys.argv[3:]
assert not boundary_preflight or kind in {"context_r18", "job_cli_r20", "first_cause_r20"}
workspace_name = {"astra":"astra-queue-ux-r12", "astra_r15":"astra-job-projection-r15", "astra_r18":"astra-instance-ui-r18", "context_r18":"validation-context-r18", "stop_r19":"config-stop-at-r18", "job_cli_r20":"job-cli-window-r20", "first_cause_r20":"astra-first-cause-r20", "contract":"contract-validation-r12", "main":"scan-session-r12", "checkpoint":"scan-checkpoint-r17", "mcp":"mcp-findings-r12"}[kind]
if kind=="checkpoint":
    workspace_name=next(row["workspace"] for row in json.loads((HERE/"tasks.json").read_text(encoding="utf-8"))["tasks"] if row["id"]=="SCAN-CHECKPOINT-R17")
branch = ROOT / ".coordination/20261014/workspaces" / workspace_name
out = ROOT / "artifacts" / label
out.mkdir(exist_ok=False)
(out/"launcher.py").write_bytes(Path(__file__).read_bytes())
ownership = audit(workspace_name)
assert not ownership["nonowned_changes"], ownership["nonowned_changes"]
baseline = json.loads((HERE/"followups-r12"/(workspace_name+"-baseline.json")).read_text(encoding="utf-8"))
names = set(row["path"] for row in baseline["files"]) | {row["path"] for row in ownership["changes"]}
dependency_path=HERE/"followups-r12"/(workspace_name+"-dependencies.json")
if dependency_path.exists():
    names|={row["path"] for row in json.loads(dependency_path.read_text(encoding="utf-8"))["files"]}
def hashes():
    return {name:hashlib.sha256((branch/name).read_bytes()).hexdigest() for name in sorted(names)}
before = hashes()
files = {row["path"]:row["after"] for row in ownership["changes"]}
if kind=="checkpoint":
    # A handover baseline inherits the tested Kimi publication changes. Capture
    # all six owned files, including unchanged inherited files, for final intake.
    files.update({name:before[name] for name in baseline["task"]["owns"]})
for name, sha in files.items():
    target=out/"source-before"/name
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes((branch/name).read_bytes())
    assert hashlib.sha256(target.read_bytes()).hexdigest()==sha
if kind in {"astra","astra_r15","astra_r18"}:
    tests=["test_agent_workbench_ui","test_config_editor_http","test_project_preparation","test_config_v3_preparation","test_acceptance_projection","test_protocol_review_ui","test_tool_registry"]
    black=["tests/test_agent_workbench_ui.py"]
    if kind=="astra_r18":
        tests += ["test_instance_coverage_ui", "test_job_result_http_binding", "test_job_result_projection"]
        black += ["tests/test_instance_coverage_ui.py"]
elif kind in {"contract","context_r18"}:
    tests=["test_contract_usr_scope","test_validation_build_scope","test_contract_build_scope","test_contract_symbol_ambiguity","test_validation_runner","test_native_wrapper_inference","test_resource_inference_coverage","test_native_model_cache","test_protocol_incremental_equivalence","test_candidate_build_identity","test_instance_analysis","test_candidate_pipeline","test_refcount_protocols","test_refcount_integration","test_handle_protocols","test_handle_integration","test_pool_protocol_modeling","test_lock_modes","test_raii_lifecycle","test_link_targets","test_linked_lifecycle_paths","test_conditional_ownership_contracts","test_semantic_contract_schema","test_semantic_contract_chain","test_wrapper_contract_compiler","test_contract_only_publication","test_source_contract_boundaries"]
    black=[name for name in files if name.endswith(".py")]
    # Retain the producer's original37-file regression collection, then add
    # independently identified protocol/publication neighbors; never shrink
    # acceptance to only the new boundary cases.
    tests=list(dict.fromkeys(tests+["test_async_cleanup","test_async_contracts","test_async_incremental","test_async_paths","test_async_wait","test_evidence_completion","test_full_symbol_build_scope","test_lifecycle_paths","test_lock_coverage","test_parallel_shared_semantics","test_protocol_assessment","test_protocol_feedback","test_retained_slot_teardown","test_scan_session_resume_svf","test_semantic_coordinator_effects","test_validation_pipeline"]))
    tests=list(dict.fromkeys(tests+["test_single_slot_pool", "test_retention_protocols"]))
    if kind=="context_r18":
        tests=list(dict.fromkeys(tests+["test_agent_integration_boundaries", "test_decision_explanation", "test_protocol_review_ui", "test_review_experiment_protocol", "test_spec_registry", "test_validation_context_workers"]))
elif kind == "first_cause_r20":
    tests=["test_cancellation", "test_cancellation_first_cause", "test_config_stop_at_consumers", "test_parallel_entry_budget", "test_scan_job_execution", "test_job_session_scheduler", "test_scan_session_jobs", "test_validation_runner", "test_validation_build_scope", "test_coordinator_versions", "test_coordinator_roots", "test_semantic_coordinator_effects", "test_incremental_semantic_modeling", "test_subagents_parallel", "test_bounded_investigation", "test_external_investigation", "test_semantic_next_round", "test_single_entry_active_discovery", "test_source_contract_boundaries", "test_llm_owner_cleanup"]
    black=[name for name in files if name.endswith(".py")]
elif kind in {"stop_r19", "job_cli_r20"}:
    tests=["test_config_stop_at_consumers", "test_cancellation", "test_config_v3", "test_config_v3_preparation", "test_config_v3_entrypoints", "test_cli_config_v2", "test_project_preparation", "test_config_migration", "test_scan_jobs", "test_scan_jobs_http_api", "test_mcp_jobs", "test_job_session_scheduler", "test_job_remaining", "test_job_queue_receipts", "test_job_result_http_binding", "test_job_result_projection", "test_scan_job_execution", "test_scan_job_work_queue", "test_cli_output", "test_mcp_read_only", "test_incremental_replay", "test_review_memory_cli", "test_rule_cli", "test_config_v2", "test_config_editor_http", "test_mcp_http_server", "test_mcp_policy", "test_mcp_security"]
    black=[name for name in files if name.endswith(".py")]+["tests/test_config_v3_preparation.py", "tests/test_incremental_replay.py"]
    if kind == "job_cli_r20":
        tests.append("test_job_cli_stop_window")
        tests += ["test_agent_docs", "test_portable_runtime", "test_portable_release"]
        if (branch / "tests/test_cancellation_first_cause.py").is_file():
            tests.append("test_cancellation_first_cause")
elif kind=="mcp":
    tests=["test_job_result_projection","test_mcp_jobs","test_mcp_read_only","test_mcp_http_server","test_mcp_policy","test_mcp_security","test_tool_registry","test_scan_jobs","test_scan_job_execution","test_scan_jobs_http_api","test_scan_job_work_queue","test_job_session_scheduler","test_job_remaining","test_report_json_io","test_shared_report_storage","test_report_views","test_acceptance_projection","test_frozen_report_reader"]
    black=[name for name in files if name.endswith(".py")]
else:
    tests=["test_scan_session_instances","test_scan_session_jobs","test_instance_analysis","test_all_variant_scan","test_entry_instance_coverage","test_build_context","test_candidate_build_identity","test_candidate_ledger","test_parallel_entry_budget","test_parallel_shared_semantics","test_report_assembler","test_scan_session_resume_svf","test_validation_runner","test_wiki_workflow","test_job_session_scheduler","test_scan_job_work_queue","test_scan_jobs","test_scan_job_execution","test_candidate_pipeline"]
    black=[name for name in files if name.endswith(".py")]
    if kind=="checkpoint":
        tests.append("test_scan_checkpoint_resume")
probes=[]
if kind == "first_cause_r20":
    probes=[str(HERE / "followups-r12" / name) for name in ("test_config_stop_deadline_boundary.py", "test_stop_reason_precedence_boundary.py", "test_stop_first_cause_observation_boundary.py")]
if kind in {"stop_r19", "job_cli_r20"}:
    probes=[str(HERE/"followups-r12"/name) for name in ("test_config_stop_deadline_boundary.py", "test_stop_reason_precedence_boundary.py", "test_native_hot_process_boundary.py")]
    if kind == "job_cli_r20":
        probes += [str(HERE / "followups-r12" / name) for name in ("test_job_cli_effective_window_boundary.py", "test_job_cli_window_identity_boundary.py", "test_job_cli_window_snapshot_boundary.py", "test_job_cli_window_store_binding_boundary.py")]
        if (branch / "tests/test_cancellation_first_cause.py").is_file():
            probes.append(str(HERE / "followups-r12/test_stop_first_cause_observation_boundary.py"))
if kind=="mcp":
    probes=[str(HERE/"followups-r12/test_mcp_findings_boundaries.py")]
if kind in {"contract","context_r18"}:
    probes=[str(HERE/"followups-r12"/name) for name in ("test_validation_thread_context.py","test_contract_usr_boundary.py","test_contract_protocol_usr_boundary.py","test_contract_omitted_usr_boundary.py","test_contract_context_receipt_boundary.py")]
    if kind == "context_r18":
        probes.append(str(HERE / "followups-r12/test_validation_callee_rebind_boundary.py"))
        probes.append(str(HERE / "followups-r12/test_validation_call_snapshot_boundary.py"))
        probes.append(str(HERE / "followups-r12/test_validation_call_values_snapshot_boundary.py"))
if kind in {"main", "checkpoint"}:
    probes=[str(HERE/"followups-r6"/name) for name in ("test_instance_consumer_guard.py","test_instance_navigation_consumers.py","test_instance_validation_scope.py","test_instance_native_body.py")]
    probes += [str(HERE/"followups-r10/test_symbol_consumer_receipts.py")]
    probes += [str(HERE/"followups-r12/test_scan_session_native_boundary.py"), str(HERE/"followups-r12/test_scan_session_crash_resume.py"),str(HERE/"followups-r12/test_scan_session_queue_fencing.py")]
    probes += [str(HERE/"followups-r12/test_scan_session_deadline.py")]
    if kind=="checkpoint":
        probes += [str(HERE/"followups-r12/test_scan_checkpoint_authority_boundary.py")]
        probes += [str(HERE/"followups-r12/test_scan_checkpoint_dependency_boundary.py")]
probe_sources={}
if boundary_preflight:
    # A failed fast boundary blocks the later full acceptance. This mode never
    # grants independent delivery acceptance or replaces the full collection.
    if kind == "job_cli_r20":
        probes = [p for p in probes if Path(p).name in {"test_job_cli_effective_window_boundary.py", "test_job_cli_window_identity_boundary.py", "test_job_cli_window_snapshot_boundary.py", "test_job_cli_window_store_binding_boundary.py", "test_stop_first_cause_observation_boundary.py"}]
    else:
        probes = probes[-3:]
if probes:
    frozen_probes=out/"frozen-probes";frozen_probes.mkdir()
    copied=[]
    for raw in probes:
        original=Path(raw);target=frozen_probes/original.name
        assert not target.exists(), "duplicate independent probe filename"
        shutil.copyfile(original,target)
        probe_sources[str(original)]={"sha256":hashlib.sha256(target.read_bytes()).hexdigest(),"frozen":str(target)}
        copied.append(str(target))
    probes=copied
assert all((branch/f"tests/{name}.py").is_file() for name in tests), "required test file missing; delivery incomplete"
env=os.environ.copy()
env.update(Z_SCOPE_TEST_CLANG_INDEXER="/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer",
           ZSCOPE_UI_MULTI_TARGET_EDITING="1",
           ZSCOPE_UI_PLAYWRIGHT_MODULE="/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright",
           ZSCOPE_UI_CHROMIUM="/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome",
           ZSCOPE_UI_EVIDENCE=str(out/"browser"),ZSCOPE_UI_CONFIG_EVIDENCE=str(out/"config"),ZSCOPE_UI_JOB_EVIDENCE=str(out/"owner"))
if kind=="astra_r18":env["ZSCOPE_INSTANCE_EVIDENCE"]=str(out/"native-browser")
native_path=Path(env["Z_SCOPE_TEST_CLANG_INDEXER"])
native_before=hashlib.sha256(native_path.read_bytes()).hexdigest()
assert native_before=="d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
commands=[
    [sys.executable,"-m","pytest","-q",*[f"tests/{name}.py" for name in tests],*probes,f"--junitxml={out/'results.xml'}"],
    [sys.executable,"-m","compileall","-f","-q","zscope","scripts","test","tests"],
    [sys.executable,"-m","mypy","zscope"],
    [sys.executable,"-m","black","--check",*black],
]
if boundary_preflight:
    commands[0] = [sys.executable, "-m", "pytest", "-q", *probes, f"--junitxml={out/'results.xml'}"]
    commands = commands[:1]
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
accepted=len(results)==(1 if boundary_preflight else 4) and all(row["returncode"]==0 for row in results) and before==after and not final_ownership["nonowned_changes"] and all(suite.get(k)=="0" for k in ("failures","errors","skipped"))
native_after=hashlib.sha256(native_path.read_bytes()).hexdigest()
probes_unchanged=all(hashlib.sha256(Path(name).read_bytes()).hexdigest()==row["sha256"] and hashlib.sha256(Path(row["frozen"]).read_bytes()).hexdigest()==row["sha256"] for name,row in probe_sources.items())
accepted=accepted and native_before==native_after and probes_unchanged
lock_delta=[]
if kind in {"astra","astra_r15","astra_r18"}:
    lock=json.loads((branch/"requirements/portable/web-assets.lock.json").read_text(encoding="utf-8"))
    for name, entry in lock["files"].items():
        assert hashlib.sha256((branch/"zscope/web/static/vendor"/name).read_bytes()).hexdigest()==entry["sha256"]
    for name, entry in lock["first_party"].items():
        actual=hashlib.sha256((branch/"zscope/web/static"/name).read_bytes()).hexdigest()
        if actual != entry["sha256"]:
            lock_delta.append({"name":name,"locked":entry["sha256"],"actual":actual})
    expected={"index.html","dashboard_workbench.js"} if kind in {"astra","astra_r18"} else {"dashboard_workbench.js"}
    assert {row["name"] for row in lock_delta}==expected
ledger=json.loads((HERE/"tasks.json").read_text(encoding="utf-8"))
task_id = "/root/astra_first_cause_r20" if kind=="first_cause_r20" else "/root/astra_instance_ui_r18" if kind=="astra_r18" else "/root/astra_v3_editor_r6" if kind in {"astra","astra_r15"} else next(row["bridge_task_id"] for row in ledger["tasks"] if row["id"]=={"main":"SCAN-SESSION-R12","checkpoint":"SCAN-CHECKPOINT-R17","contract":"CONTRACT-VALIDATION-R12","context_r18":"VALIDATION-CONTEXT-R18","stop_r19":"U01-STOP-AT-R18","job_cli_r20":"U01-JOB-CLI-WINDOW-R20","mcp":"MCP-FINDINGS-R12"}[kind])
if kind == "job_cli_r20":
    producer = next(row for row in ledger["tasks"] if row["id"] == "U01-JOB-CLI-WINDOW-R20")
    if producer.get("agent_kind") == "native_subagent":
        task_id = producer["agent_task_id"]
proof={"kind":kind,"task_id":task_id,
       "started_at":started,"finished_at":dt.datetime.now(dt.timezone.utc).isoformat(),"junit":suite.attrib,"commands":results,
       "ownership":ownership,"after_ownership":final_ownership,"before_all_inputs":before,"after_all_inputs":after,
       "delivered_hashes":files,"after_hashes":{name:after[name] for name in files},"source_unchanged":before==after,
       "source_snapshot":str(out/"source-before"),"independent_acceptance_passed":accepted and not boundary_preflight,
       "boundary_preflight_only":boundary_preflight,"bounded_probe_validation_passed":accepted,
       "independent_probe_sources":probe_sources,"independent_probes_unchanged":probes_unchanged,
       "native_before":native_before,"native_after":native_after,
       "expected_static_lock_delta":lock_delta,"static_lock_full_verify":"pending root intake/update" if kind in {"astra","astra_r15","astra_r18"} else "not relevant",
       "integrated":False,"whole_package_complete":False,
       "scope":"Actual native fixture and controlled model for S01; real Linux/SQLite/owner/HTTP/browser over controlled scanners and synthetic report/assumption data. Full scanner/consumer/real-project/formal/portable acceptance remains separate."}
(out/"review.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"accepted":accepted,"junit":suite.attrib,"receipt":str(out/"review.json")}))
sys.exit(0 if accepted else 1)
