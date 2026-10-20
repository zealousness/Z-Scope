"""Archive the stable S01 R1 and queue concrete consumer-boundary repair."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
from uuid import uuid4
from audit_followup_r6 import audit, ROOT

HERE = Path(__file__).resolve().parent
OUT = ROOT / "artifacts/coordinator-s01-r1-consumers-20261014"
WORK = ROOT / ".coordination/20261014/workspaces/s01-analysis-r6"
ownership = audit(WORK.name)
assert ownership["safe_to_review"], ownership
hashes = {row["path"]: row["after"] for row in ownership["changes"]}
archive = OUT / "initial-delivery"
archive.mkdir(exist_ok=False)
for name in list(hashes) + ["DELIVERY.md", "artifacts/instance-analysis-tests-r2.xml"]:
    target = archive / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(WORK / name, target)
shutil.copyfile(HERE / "followups-r6/test_instance_navigation_consumers.py", OUT / "failed-probe.py")
review = {"task_id": "task_9e8e7e3dc4", "observed_model": "volceapi/kimi-k3",
          "finished_at": "2026-10-14T21:31:10.016698+08:00", "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
          "junit": {"passed": 2, "failed": 5, "errors": 0, "skipped": 0}, "owned_source_hashes": hashes,
          "ownership": ownership, "independent_acceptance_passed": False, "integrated": False,
          "scope": "Synthetic scope probes through actual SymbolCatalog/metadata consumers; not native effect acceptance.",
          "result_receipt": str(HERE / "route-check/bridge-response-r6-public-0f6d63a365.json"), "whole_package_complete": False}
(OUT / "review.json").write_text(json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
message = """S01 R2：继续原sess_261a55289f和s01-analysis-r6副本、原6文件所有权。task_9e8e7e3dc4已21:31:10 completed，get_result完整无warnings/failure，observed_model确认kimi-k3；没有API故障，不转交。
原2个守卫反例由协调者独立重跑已通过，生命周期/全局pass隔离修复保留。新消费端审查仍5fail，合成边界测试调用真实SymbolCatalog/门面，不是native效果验收：根followups-r6/test_instance_navigation_consumers.py；artifacts/coordinator-s01-r1-consumers-20261014/{results.xml,review.json,initial-delivery}。5改动源码/DELIVERY/worker292最终JUnit已归档，不导入根。
直接修已确认缺口，不再长规划：
1 __getattr__对非callable原样透传“普通属性不会带符号事实”判断错误。实际zscope/tools/symbols.py:408-411的SymbolCatalog._function_records读取_function_index，即使list_functions已拦仍得到另一变体函数。改为明确scope-neutral属性allowlist（project_root/language等必要元数据），拒绝/空化其余符号/缓存/数据库句柄并记gap，尤其_function_index、各类型/宏/全局/回调cache。实际消费API要得到可用类型空值，不能None导致AttributeError然后假称已隔离。
2 _scoped_function_infos没核对显式file：请求f@other.c仍改成scope.source返回unit.c；必须拒绝。同方法len(infos)>1只记gap仍返回全部重载，必须消费处拒绝。返回的导航USR/源码范围必须与精确native身份核对，缺证据停止该路径，不把相同名称+同file授权。
3 get_function_type_context / get_function_symbol_context只核对入口名字然后委托旧base投影，实际仍返回foreign BuildContext类型或ALT=1宏；必须有精确当前BuildContext+native USR/范围收据才用，否则空结果+gap。未知未带ID也不是通配，不以删除foreign标签来绿。无需本轮实现完整S01-SYMBOL，安全拒绝并说明召回缺口即可。
所有进入候选/验证/反证/LLM工具的消费路径都遵守同一拒绝规则；get_function_impl/metadata/type/symbol应共同核对显式file、歧义/过期以及相同native实例范围。不要用gap计数/consumer_scope_complete=false代替消费拒绝。
保留真实native双宏正反例，仅ALT有double_free；保留现18测试和foreign/missing/stale/TU/overload/path等所有反例，原2协调守卫只读。新增5协调反例只读，补你拥有test_instance_analysis.py对应测试。源码/CFG冲突不弱回退，实验默认不变，未接导航/图/全局建模仍明确gap。
全部WSL /home/zeal/venv313/bin/python经根test_slot.py --workspace本副本 --，PYTHONPATH本副本、ext4TMPDIR、两槽；native只读d39cbe72...不重建。完成相同相关/native回归、compileall/mypy和必要局部Black。保留旧287/292 JUnit，最终新文件名/逐文件SHA/实际命令和时间。根scan_session/code_index/共享契约/报告等仍只读。没有provider/权限/审核变更，不操作旧S06，不commit/push/reset/clean，完整扫描接线仍协调者且不声称整S01关闭。稳定交付后停止修改。"""
request = {"id": "s01-analysis-r6-review2", "branch": "s01-analysis-r6-review2", "tool": "dispatch_task",
           "arguments": {"agent": "kimi", "session_id": "sess_261a55289f", "model": "volceapi/kimi-k3",
                         "cwd": str(ROOT), "title": "S01-INST-EXEC-R2", "message": message,
                         "request_id": str(uuid4()), "user_requested": True}}
request_path = HERE / "followups-r6/s01-analysis-r6-review2-request.json"
request_path.write_text(json.dumps(request, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
queue = HERE / "route-check/bridge-queue/100-s01-analysis-r6-review2.request.json"
with queue.open("x", encoding="utf-8", newline="\n") as output:
    output.write(json.dumps(request, ensure_ascii=False) + "\n")
print(json.dumps({"review": str(OUT / "review.json"), "request": request["id"], "request_id": request["arguments"]["request_id"]}))
