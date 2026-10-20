"""Publish a failed current-root attempt without replacing historical passes."""
from pathlib import Path
import datetime as dt
import json
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
out=ROOT/"artifacts/coordinator-r14-source-roots-intaken-20261015"
source=json.loads((out/"source-evidence.json").read_text(encoding="utf-8"))
suite=ET.parse(out/"results.xml").getroot().find("testsuite")
assert suite.get("tests")=="1136" and suite.get("failures")=="1" and source["direct_source_unchanged"]
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
review={"at":at,"tests":1136,"passed":1135,"failed":1,"errors":0,"skipped":0,"test_file_count":source["test_file_count"],"source_inputs":len(source["after"]),"source_unchanged":True,"commands":source["commands"],"quality_commands_executed":1,"quality_commands_passed":0,"joint_verification_passed":False,"whole_package_complete":False,"failure":"test_actual_job_engine_over_http_with_controlled_scanner: socket.connect timed out after prior successful local HTTP detail replies","probe_pending":"artifacts/root-r14-http-file-probes-20261015","capture":"default fd on ext4 TMPDIR; capture FileNotFoundError did not recur"}
(out/"review.json").write_text(json.dumps(review,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
path=HERE/"tasks.json"
ledger=json.loads(path.read_text(encoding="utf-8"))
ledger["updated_at"]=at
ledger["current_accepted_stage"].update(current_root_status="R14 source-root intake joint failed at HTTP TCP connect; current root verification pending",latest_joint_attempt=str((out/"review.json").relative_to(ROOT)).replace("\\","/"),latest_joint_attempt_passed=False)
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
path=HERE/"continuation-r6.json"
continuation=json.loads(path.read_text(encoding="utf-8"))
continuation.update(latest_joint_attempt="artifacts/coordinator-r14-source-roots-intaken-20261015/review.json",latest_joint_attempt_passed=False,current_root_status="source-root fix intaken; R14 1135pass/1 HTTP connect timeout; root joint pending",prior_pass_is_current_root=False,updated_at=at)
path.write_text(json.dumps(continuation,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
note=f"## {at} · Current root R14 joint failed; MCP independent pass held\n\n- Current root R14: 1135 pass/1fail/0error/skip,73 files,1004 inputs unchanged. Failure is actual HTTP TCP socket.connect timeout in test_agent_integration_boundaries, after six HTTP200 detail replies. Default fd/ext4 TMPDIR capture worked; no old capture exception. Pipeline stopped at pytest; remaining five quality commands did not run. Receipt artifacts/coordinator-r14-source-roots-intaken-20261015/review.json. Root source-root fix is intaken; previous1132 R13 is historical, not verification of current root.\n- Shared source-root repair had218/0/0skip+compileall/mypy353/Black, finished03:21:43, twofiles intaken; coordinator-authored, no independent-worker claim. Current HTTP single/file repetition probes retain10s timeout/no capture downgrade, full joint rerun still required.\n- MCP task_e4ab0da557 independent358/0/0skip+all four checks passed03:31:08 with1005 stable inputs, receipt artifacts/coordinator-mcp-findings-r12-ijson-ready-acceptance-20261015/review.json. Earlier352/6skip is held failed acceptance; locked ijson3.5.1 installed by require-hashes. MCP not intaken while current-root probes run.\n- Contract task_6b0ca95206 independent11/0/0skip is only the identity boundary slice. Producer892/5 failures observed separately, exact-byte five-case reproduction assigned task_2d639b45b8 after old processes ended. Kimi task_658717aaa6 continues original ScanSession repair. No old S06 action or expanded conditional work.\n\n---\n\n"
for name in ("PROGRESS.md","DAG.md"):
    path=HERE/name
    path.write_text(note+path.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
print(json.dumps(review))
