"""Prepare disjoint workers from frozen contracts, without changing root."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import sys

assert sys.platform == "linux"
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4]
root=json.loads((ROOT/"artifacts/coordinator-r16-astra-projection-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
assert all(hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==sha for p,sha in root.items())
contract=json.loads((ROOT/"artifacts/coordinator-contract-r12-r5-acceptance-20261015/review.json").read_text(encoding="utf-8"))
assert contract["independent_acceptance_passed"]
main=json.loads((ROOT/"artifacts/coordinator-scan-session-r12-r3-acceptance-20261015/review.json").read_text(encoding="utf-8"))
assert main["independent_acceptance_passed"]
specs=[
 {"id":"VALIDATION-CONTEXT-R18","workspace":"validation-context-r18","owner":"zcode","session_id":"sess_a0adb99b15","owns":["zscope/core/validation/runner.py","zscope/core/validation/evidence_completion.py","zscope/agents/validator_agent/agent.py","zscope/core/validation/execution_context.py","tests/test_validation_context_workers.py"],"depends_on":["CONTRACT-VALIDATION-R12"],"overlay":"contract"},
 {"id":"U01-STOP-AT-R18","workspace":"config-stop-at-r18","owner":"zcode","owns":["zscope/config/v3.py","zscope/config/v3_preparation.py","zscope/cli/cli.py","zscope/orchestration/jobs/service.py","zscope/orchestration/execution_profile.py","tests/test_config_stop_at_consumers.py"],"depends_on":["U01-CONFIG","U01-ENTRYPOINTS-R6"],"overlay":"root"},
 {"id":"DOC-IDENTITY-R18","workspace":"doc-identity-r18","owner":"dsh","session_id":"sess_bdab8c13fb","owns":["docs/modules/configuration-state.md","docs/modules/retrieval-backends.md"],"depends_on":["SCAN-SESSION-R12","CONTRACT-VALIDATION-R12"],"overlay":"contract_main"},
 {"id":"ASTRA-INSTANCE-UI-R18","workspace":"astra-instance-ui-r18","owner":"Astra","owns":["zscope/web/static/dashboard_workbench.js","zscope/web/static/index.html","tests/test_instance_coverage_ui.py","tests/fixtures/instance_coverage_ui.cjs"],"depends_on":["SCAN-SESSION-R12","ASTRA-JOB-PROJECTION-R15"],"overlay":"main"},
]
ledger=json.loads((HERE/"tasks.json").read_text(encoding="utf-8"));ids={r["id"] for r in ledger["tasks"]}
for spec in specs:
    # Keep dependency names that actually exist; no invented prerequisite node.
    spec["depends_on"]=[name for name in spec["depends_on"] if name in ids]
    sources={name:(ROOT/name,sha) for name,sha in root.items()}
    if "contract" in spec["overlay"]:
        for name,sha in contract["delivered_hashes"].items():sources[name]=(Path(contract["source_snapshot"])/name,sha)
        for name in ("tests/test_contract_build_scope.py","tests/test_native_wrapper_inference.py","tests/test_single_slot_pool.py","tests/test_retention_protocols.py"):
            sources[name]=(ROOT/".coordination/20261014/workspaces/contract-validation-r12"/name,contract["after_all_inputs"][name])
    if "main" in spec["overlay"]:
        for name,sha in main["delivered_hashes"].items():sources[name]=(Path(main["source_snapshot"])/name,sha)
        name="tests/test_scan_session_resume_svf.py";sources[name]=(ROOT/".coordination/20261014/workspaces/scan-session-r12"/name,main["after_all_inputs"][name])
    workspace=ROOT/".coordination/20261014/workspaces"/spec["workspace"];workspace.mkdir(exist_ok=False)
    for name,(source,sha) in sources.items():
        assert hashlib.sha256(source.read_bytes()).hexdigest()==sha
        target=workspace/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
    task={**spec,"write_paths":spec["owns"],"isolated_workspace_linux":str(workspace),"model":"gpt-6-astra" if spec["owner"]=="Astra" else "deepseek/deepseek-v4.1-flash" if spec["owner"]=="dsh" else "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"}
    proof={"captured_at":dt.datetime.now(dt.timezone.utc).isoformat(),"task":task,"files":[{"path":name,"sha256":sha} for name,(_,sha) in sorted(sources.items())],"root_changed":False,"interface_contracts":"Accepted MainR3 and/or ContractR5 only; whole parent packages remain open."}
    (HERE/"followups-r12"/(spec["workspace"]+"-baseline.json")).write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps({"id":spec["id"],"workspace":str(workspace),"inputs":len(sources)}),flush=True)
(HERE/"followups-r12/parallel-r18-prepared.json").write_text(json.dumps({"at":dt.datetime.now(dt.timezone.utc).isoformat(),"tasks":specs},ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
