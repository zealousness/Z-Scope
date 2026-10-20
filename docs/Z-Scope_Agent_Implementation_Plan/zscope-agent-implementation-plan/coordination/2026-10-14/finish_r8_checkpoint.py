"""Publish only a green current-byte joint receipt and reconcile the DAG."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-r8-u01-ui-integrated-20261014"
source = json.loads((OUT / "source-evidence.json").read_text(encoding="utf-8"))
assert source["direct_source_unchanged"]
assert len(source["commands"]) == 6 and all(row["returncode"] == 0 for row in source["commands"])
assert all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == sha for name, sha in source["after"].items())
suites = ET.parse(OUT / "results.xml").getroot().findall("testsuite")
assert suites and all(suite.get(key) == "0" for suite in suites for key in ("errors", "failures", "skipped"))
count = sum(int(suite.get("tests", "0")) for suite in suites)
assert count >= 635
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
finished = dt.datetime.fromisoformat(source["captured_at"]).astimezone(dt.timezone(dt.timedelta(hours=8))).isoformat()
review = {"verified_at":at, "finished_at":finished, "passed":count, "failed":0,"errors":0,"skipped":0,
          "quality_commands_passed":6, "pytest_file_count":34, "bound_input_files":len(source["after"]),
          "current_bytes_match":True,"pytest_capture":source["pytest_capture"],"temporary_directory":source["temporary_directory"],
          "source_evidence":"artifacts/coordinator-r8-u01-ui-integrated-20261014/source-evidence.json",
          "previous_failure_retained":"artifacts/coordinator-r7-u01-ui-integrated-20261014 (634 passed, 1 failed)",
          "scope":source["scope"], "whole_package_complete":False,
          "commands":[{"returncode":row["returncode"],"log":row["log"],"started_at":row["started_at"]} for row in source["commands"]]}
assert not (OUT / "review.json").exists()
(OUT / "review.json").write_text(json.dumps(review,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
ledger_path = HERE / "tasks.json"
ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
rows = {row["id"]:row for row in ledger["tasks"]}
for identifier in ("U01-ENTRYPOINTS","ASTRA-V3-EDITOR"):
    rows[identifier].update(status="independent_passed_integrated_joint_passed_slice",joint_verification=True,
                            joint_evidence=review["source_evidence"],whole_package_complete=False,checked_at=at)
astra = rows["ASTRA-V3-EDITOR"]
astra.update(phase3_acceptance=True,acceptance_evidence="artifacts/coordinator-astra-r6-phase3-20261014/review.json",
             intake_evidence="artifacts/intake-astra-phase3-r6-20261014/receipt.json",
             acceptance_scope="real all-target config HTTP/browser + native datetime control/real owner; 409 contract fixture; scanner/report controlled")
rows["HTTP-INTEGRATION"].update(status="current_source_joint_validation_passed_full_scanner_wiring_pending",joint_evidence=review["source_evidence"])
rows["CURRENT-JOINT-R7"].update(status="completed_current_integration_slice",evidence=review["source_evidence"],result={"passed":count,"failed":0,"errors":0,"skipped":0},quality_checks="six commands exit0",finished_at=finished,whole_package_complete=False)
if "CURRENT-JOINT-R7" not in rows["UX-INTEGRATION"]["depends_on"]:
    rows["UX-INTEGRATION"]["depends_on"].append("CURRENT-JOINT-R7")
remaining = set(rows)
done = set()
layers = []
while remaining:
    ready = [row["id"] for row in ledger["tasks"] if row["id"] in remaining and set(row["depends_on"]) <= done]
    assert ready, "cycle or unknown dependency"
    layers.append(ready)
    remaining.difference_update(ready)
    done.update(ready)
ledger["topological_layers"] = layers
ledger["updated_at"] = at
ledger["current_accepted_stage"] = {"source_evidence":review["source_evidence"],"passed":count,"failed":0,"skipped":0,"quality_commands":6,
                                    "bound_input_files":len(source["after"]),"original_clone_inputs":971,"readonly_dependencies_added":10,
                                    "scope":"U01 CLI/editor/HTTP + Astra config integration slice; S01/S08 R2 not intaken; not whole-package or real-project effect acceptance"}
ledger_path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
stage_path = HERE / "continuation-r6.json"
stage = json.loads(stage_path.read_text(encoding="utf-8"))
stage.update(updated_at=at,current_joint="artifacts/coordinator-r8-u01-ui-integrated-20261014",current_joint_status="passed_current_u01_ui_bytes_s01_s08_review2_pending",
             current_joint_result={"passed":count,"failed":0,"errors":0,"skipped":0,"quality_commands_passed":6},last_verified_root_joint=review["source_evidence"],
             next_task_rows=[rows[name] for name in ("S01-INST-EXEC","S08-SESSION-SCHEDULER","U01-ENTRYPOINTS","ASTRA-V3-EDITOR")])
stage_path.write_text(json.dumps(stage,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
text=f"""## {at[:19]} +08:00 · 当前根目录联合通过（覆盖下方历史失败/旧状态）

- 当前字节联合 `{OUT.relative_to(ROOT).as_posix()}`：{count} passed / 0 failed / 0 error / 0 skipped，34个测试文件；原30文件保留并扩展4文件，不与历史519/583/97/54/22/83/201/10等集合相加。compileall全产品/scripts/test/tests、mypy zscope、评估脚本mypy、相关Black、本地静态资源锁共6命令exit0，{len(source['after'])}输入前后及发布收据时SHA一致。完成时间 {finished}。收据 `artifacts/coordinator-r8-u01-ui-integrated-20261014/review.json`。
- 18:24异常由DrvFS匿名临时文件unlink后ftruncate的ENOENT实际复现；验证启动器使用独立ext4 /tmp，default fd捕获保持。后续634/1是独立真实浏览器零秒输入格式问题，Chromium省略`:00`导致Playwright严格比较失败；Astra仅修fixture原生规范化并保留12秒deadline/owner/partial/resume/无重复断言，独立10通过后21:41:19导入1文件。失败/探针/旧JUnit全部保留。
- U01 `task_8e1ce5c8cc`（ZCode精确glm-5.3）独立201通过，21:13:35导入8文件，共享HTTP22通过；Astra `/root/astra_v3_editor_r6` phase2/3独立真实多目标编辑10通过（各集合独立），21:28:55导入6文件、21:41:19导入fixture增量，当前同根联合通过。多目标保存200/完整GET回读成立，执行仍禁止；config409仅合同fixture、无CAS，扫描器/报告仍synthetic。
- Kimi `task_09da468c8a`与ZCode `task_c1fb932358`原会话R2均实际执行，尚未独立验收/导入。前轮S01新5消费反例与S08新2耐久反例失败已归档，详见 `artifacts/coordinator-s01-r1-consumers-20261014/review.json`、`artifacts/coordinator-s08-r1-durability-20261014/review.json`。当前通过不覆盖这些隔离副本；S01全消费者与ScanSession接线、S08事务结算与完整scanner/窗口/remaining接线仍待验收。
- 原Bridge owner80748保持，无新服务或重复派单；Astra当前停写。原S06-R02已由用户确认完成归档，不恢复、不查询、不派发，不列外部阻塞。S01/S08共享ScanSession由协调者串行集成，其他主包仍按{len(rows)}节点/{len(layers)}层依赖推进，不以切片关闭整包。
- 最新环境收据 `artifacts/coordinator-r7-runtime-login-20261014.json`：WSL Ubuntu Python3.13.15/pytest9.1.1/editable当前根，login shell十工具PATH可解析、WPA/Saber无缺库；直接Python PATH仅五工具（另份runtime收据），native显式批量工具SHA d39cbe72...未变。当前进程LLM三变量及ijson缺失；未运行真实LLM/项目效果、formal benchmark或portable实物smoke。S10/Q01/Q02条件扩展及业务/外部材料等待单列。

---

"""
for name in ("PROGRESS.md","DAG.md"):
    destination=HERE/name
    destination.write_text(text+destination.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
(HERE/"CHECKPOINT-R7.md").write_text(text.replace("\n---\n\n", "\n"),encoding="utf-8",newline="\n")
assert all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha for name,sha in source["after"].items()), "bookkeeping changed a tested input"
print(json.dumps({"passed":count,"quality_commands":6,"input_files":len(source["after"]),"finished_at":finished,"tasks":len(rows),"layers":len(layers),"receipt":str(OUT/"review.json")}))
