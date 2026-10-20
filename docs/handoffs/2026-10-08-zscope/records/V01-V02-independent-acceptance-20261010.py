"""Independent defensive acceptance. No real sanitizer fixtures or model requests."""
import hashlib, json, os, re, signal, subprocess, sys, tempfile, time
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
LOCAL = Path("/mnt/c/Users/10273/Documents/Codex/2026-10-09/task-3")
RECORDS = ROOT / "docs/handoffs/2026-10-08-zscope/records"
WORK = Path(tempfile.mkdtemp(prefix="zscope-v01-v02-independent-20261010-"))
RUN_ID = WORK.name.rsplit("-", 1)[-1]
RESULT = {"role":"independent defensive acceptance; real sanitizer fixtures excluded",
          "started_utc":datetime.now(timezone.utc).isoformat(),
          "python":sys.executable,"project_root":str(ROOT),"work":str(WORK),
          "checks":[],"real_sanitizer":"not_run; awaiting separate scope review",
          "git":"not_run; previous access denial not retried"}
COMPAT = ["tests/test_source_search.py","tests/test_semantic_cache_only.py","tests/test_mcp_read_only.py","tests/test_tool_registry.py","tests/test_evidence_tools.py","tests/test_tool_schema_strict.py","tests/test_tool_policy.py","tests/test_tool_use_eval.py","tests/test_analyzer_tool_policy.py","tests/test_mcp_policy.py","tests/test_mcp_http_server.py","tests/test_mcp_security.py","tests/test_config_v2.py","tests/test_cli_config_v2.py","tests/test_candidate_ledger.py","tests/test_active_discovery.py","tests/test_single_entry_active_discovery.py","tests/test_balanced_rollout.py","tests/test_balanced_rollout_operator.py","tests/test_json_output_agents.py","tests/test_java_source_backend.py","tests/test_java_joern_backend.py","tests/test_java_analyzer_candidates.py","tests/test_java_semantic_modeler_schema.py","tests/test_java_evidence_merge.py","tests/test_reference_configs.py","tests/test_agent_docs.py","tests/test_investigation_evidence.py","tests/test_bounded_investigation.py","tests/test_investigation_runtime.py","tests/test_audit_coverage.py","tests/test_external_investigation.py","tests/test_external_findings_import.py","tests/test_security_semantics_tool.py","tests/test_semantic_contract_chain.py","tests/test_candidate_decision_context.py","tests/test_finding_attribution_contract.py","tests/test_incremental_replay.py","tests/test_indexing_pipeline.py","tests/test_clang_identity_validation.py","tests/test_clang_incremental_extraction.py","tests/test_svf_cache.py","tests/test_conditional_ownership_contracts.py","tests/test_wrapper_contract_compiler.py","tests/test_wrapper_failure_guards.py","tests/test_contract_only_publication.py","tests/test_pool_protocol_modeling.py","tests/test_semantic_contract_schema.py","tests/test_incremental_semantic_modeling.py","tests/test_source_contract_boundaries.py","tests/test_pair_evidence_authority.py","tests/test_snapshot_observation_shadow.py","tests/test_semantic_demand.py","tests/test_global_modeler.py","tests/test_semantic_modeling_usage.py","tests/test_semantic_model_retry.py","tests/test_validation_pipeline.py","tests/test_validation_runner.py","tests/test_parallel_shared_semantics.py","tests/test_scan_session_resume_svf.py","tests/test_report_schema_v2.py","tests/test_review_runtime.py","tests/test_portable_release.py","tests/test_portable_runtime.py","tests/test_release_contract.py","tests/test_range_release_aggregate.py","tests/test_history_reconciler.py","tests/test_snapshot_store.py","tests/test_semantic_coordinator_effects.py","tests/test_modeling_provider_usage.py","tests/test_decision_facts.py","tests/test_evidence_completion.py","tests/test_fp_suppression_guards.py","tests/test_review_fact_checks.py","tests/test_review_regressions.py","tests/test_shared_read_cache.py","tests/test_source_lifecycle_provider.py","-k","not test_real_mutation_replay and not test_real_direct_bitcode_dependency_cache_and_svf and not test_native_code_to_real_terminal_tool_workbook_and_pool_consumers"]
manifest = json.loads((RECORDS / "V01-V02-final-workspace-round2.json").read_text())
paths = set(manifest["frozen_inputs"]["files"])
paths.update(x for x in COMPAT if x.startswith("tests/") and x.endswith(".py"))
paths.update(str(p.relative_to(ROOT)) for p in (ROOT/"zscope").rglob("*.py")
             if not any(part.startswith(".") for part in p.relative_to(ROOT).parts))
paths.update(["AGENTS.md","pyproject.toml",
 "docs/handoffs/2026-10-08-zscope/WORK_PACKAGES.md",
 "docs/handoffs/2026-10-08-zscope/ACCEPTANCE.md",
 "docs/handoffs/2026-10-08-zscope/records/V01-V02-acceptance-regressions.py",
 "docs/handoffs/2026-10-08-zscope/records/V01-V02-reacceptance-regressions.py",
 "docs/handoffs/2026-10-08-zscope/records/V01-V02-reacceptance-integration.py"])
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def snapshot():
    values = {}
    for rel in sorted(paths):
        p = ROOT / rel
        if p.resolve().is_relative_to(ROOT.resolve()) and p.is_file():
            values[rel] = digest(p)
        else:
            values[rel] = "missing"
    combined = hashlib.sha256("".join(f"{h}  {p}\n" for p,h in values.items()).encode()).hexdigest()
    return {"files":values,"combined_sha256":combined}
RESULT["inputs_before"] = snapshot()
RESULT["artifact_sources"] = {p.name:digest(p) for p in [
    Path(__file__), LOCAL/"test_v01_v02_independent_drift.py"]}
environment = {k:os.environ[k] for k in (
    "PATH","LANG","LC_ALL","LC_CTYPE","TZ","LD_LIBRARY_PATH") if k in os.environ}
environment.update({"PYTHONDONTWRITEBYTECODE":"1","PYTEST_DISABLE_PLUGIN_AUTOLOAD":"1",
                    "PYTHONPATH":str(ROOT),"TMPDIR":str(WORK),
                    "XDG_CACHE_HOME":str(WORK/"cache")})
RESULT["environment_policy"] = "allowlisted noncredential variables; model credentials not forwarded"
def run(label, args, timeout, junit=False, extra_env=None):
    out, err = WORK/(label+".stdout.log"), WORK/(label+".stderr.log")
    command = [sys.executable,*args]
    env = dict(environment)
    if extra_env:
        env.update(extra_env)
    print(json.dumps({"event":"start","label":label,"command":command,
                      "timeout_seconds":timeout}), flush=True)
    start = time.monotonic()
    stopped = None
    with out.open("wb") as stdout, err.open("wb") as stderr:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=stdout,
                                   stderr=stderr, start_new_session=True)
        while process.poll() is None:
            if time.monotonic()-start > timeout:
                stopped = "timeout"
            elif out.stat().st_size + err.stat().st_size > 8*1024*1024:
                stopped = "output_limit"
            if stopped:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                break
            time.sleep(.1)
        exit_code = process.wait()
    entry = {"label":label,"command":command,"cwd":str(ROOT),"exit_code":exit_code,
             "elapsed_seconds":round(time.monotonic()-start,3),
             "stopped":stopped,"stdout":str(out),"stderr":str(err),
             "stdout_sha256":digest(out),"stderr_sha256":digest(err)}
    xml = WORK/(label+".xml")
    if junit and xml.is_file():
        doc = ET.parse(xml).getroot()
        suites = [doc] if doc.tag=="testsuite" else list(doc.findall("testsuite"))
        counts = {k:sum(int(s.get(k,"0")) for s in suites)
                  for k in ("tests","failures","errors","skipped")}
        entry["counts"]={"passed":counts["tests"]-counts["failures"]-counts["errors"]-counts["skipped"],
                         "failed":counts["failures"],"errors":counts["errors"],
                         "skipped":counts["skipped"],"tests":counts["tests"]}
        entry["failures"]=[{"node":c.get("classname","")+"::"+c.get("name",""),
                           "message":f.get("message","")[:1000]}
                          for c in doc.iter("testcase") for f in list(c)
                          if f.tag in ("failure","error")]
        entry["junit"]=str(xml)
        entry["junit_sha256"]=digest(xml)
    else:
        entry["counts"]=None
    RESULT["checks"].append(entry)
    RESULT["inputs_after_latest_check"]=snapshot()
    RESULT["changed_inputs_latest_check"]=[p for p,h in RESULT["inputs_before"]["files"].items()
        if RESULT["inputs_after_latest_check"]["files"].get(p)!=h]
    (LOCAL/"V01-V02-independent-acceptance-current.json").write_text(
        json.dumps(RESULT,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"event":"finish","label":label,"exit_code":exit_code,
                      "counts":entry["counts"],"stopped":stopped,
                      "changed_inputs":RESULT["changed_inputs_latest_check"]}),flush=True)
def pytest(label, targets, timeout=300):
    run(label,["-m","pytest","-q","-p","no:cacheprovider","--tb=short",
               "--basetemp="+str(WORK/(label+"-tmp")),
               "--junitxml="+str(WORK/(label+".xml")),*targets],timeout,junit=True)
os.chdir(ROOT)
pytest("unit",["tests/test_dynamic_reproduction.py"])
pytest("original-negative",[str(RECORDS/"V01-V02-acceptance-regressions.py")])
pytest("r01-r09-negative",[str(RECORDS/"V01-V02-reacceptance-regressions.py")])
pytest("new-file-drift",[str(LOCAL/"test_v01_v02_independent_drift.py")])
pytest("integration-safe",[str(RECORDS/"V01-V02-reacceptance-integration.py")+
 "::test_missing_optional_candidate_identity_does_not_abort_scan_without_provider"])
pytest("compatibility",COMPAT,timeout=900)
run("compileall",["-m","compileall","-f","-q","zscope","scripts","test","tests"],300,
    extra_env={"PYTHONPYCACHEPREFIX":str(WORK/"compile-cache")})
run("mypy",["-m","mypy","zscope","--cache-dir",str(WORK/"mypy-cache")],600)
RESULT["inputs_after"] = snapshot()
RESULT["changed_inputs"]=[p for p,h in RESULT["inputs_before"]["files"].items()
    if RESULT["inputs_after"]["files"].get(p)!=h]
RESULT["finished_utc"] = datetime.now(timezone.utc).isoformat()
RESULT["overall"]="not_accepted" if any(c["exit_code"]!=0 for c in RESULT["checks"]) or RESULT["changed_inputs"] else "ordinary_checks_passed_real_checks_pending"
path = LOCAL/("V01-V02-independent-acceptance-20261010-"+RUN_ID+".json")
path.write_text(json.dumps(RESULT,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
(LOCAL/"V01-V02-independent-acceptance-current.json").write_text(
    json.dumps(RESULT,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
print(json.dumps({"event":"complete","overall":RESULT["overall"],"result":str(path),
                  "changed_inputs":RESULT["changed_inputs"]}),flush=True)

