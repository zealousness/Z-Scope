"""Archive a real conditional-definition body leak and resume the idle Kimi session."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
from uuid import uuid4
from audit_followup_r6 import audit, ROOT

HERE=Path(__file__).resolve().parent
WORK=ROOT/".coordination/20261014/workspaces/s01-analysis-r6"
OUT=ROOT/"artifacts/coordinator-s01-r3-native-body-20261014"
ownership=audit(WORK.name)
assert ownership["safe_to_review"]
files={row["path"]:row["after"] for row in ownership["changes"]}
archive=OUT/"initial-delivery"
archive.mkdir(exist_ok=False)
for name in list(files)+["DELIVERY.md","artifacts/instance-analysis-tests-r4.xml"]:
    target=archive/name
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(WORK/name,target)
shutil.copyfile(HERE/"followups-r6/test_instance_native_body.py",OUT/"failed-probe.py")
review={"task_id":"task_8088785d9b","observed_model":"volceapi/kimi-k3","finished_at":"2026-10-14T22:21:45.567699+08:00",
        "checked_at":dt.datetime.now(dt.timezone.utc).isoformat(),"ownership":ownership,"after_hashes":files,"source_unchanged":True,
        "independent_acceptance_passed":False,"native_body_probe":{"failed":1,"skipped":0},"integrated":False,"whole_package_complete":False,
        "reason":"Actual native two conditional definitions: ALT-scoped facts current/complete, but get_function_impl returns BASE body from another source range.",
        "other_collection":"coordinator-s01-r3-acceptance:227 passed/80 skipped due missing login compiler PATH, Black fails one owned test. Intermediate, not acceptance."}
(OUT/"review.json").write_text(json.dumps(review,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
message="""S01 协调R4（你第5轮）最后一个已确认native函数体边界返修，继续原sess_261a55289f、s01-analysis-r6、原6文件所有权。task_8088785d9b已22:21:45 completed/observed kimi-k3，完整get_result无failure/warnings；原共享验证/成员收据3反例修复保留，暂不导入根。
新增真实native失败，不是合成index double：只读协调探针followups-r6/test_instance_native_body.py。unit.c由#ifdef ALT选择两处独立的void f(void)定义：ALT在line2含ALT_MARKER，BASE在line4含BASE_MARKER；compile_commands两命令、实际ClangBatch、实际CodeIndex、plan2实例。ALT的get_function_program_facts当前complete且USR匹配，但ScopedCodeIndex.get_function_impl('f',file='unit.c',include_context=False)仍返回line4 BASE_MARKER。当前get_impl只是比较base导航自身index_name，未将实际native owner源码范围与导航body对应；同文件同USR也不能授权另一变体的body。
失败JUnit/稳定5源码/DELIVERY/worker307已保全：根artifacts/coordinator-s01-r3-native-body-20261014/{review.json,results.xml,initial-delivery}。真实工具d39cbe72...未重建。协调者probe只读，允许在你拥有test_instance_analysis.py补原生对应正反例。两个实例都实际编译和查事实，不能通过skip/native工具降级/禁用所有native分析掩盖。
修复要求：get_function_impl与metadata共同把被返回正文/记录的文件、native USR、真实源码范围核对到当前实例实际program-function事实。不能只对导航投影自身比index_name，不能按裸名/同file/sameUSR回退第一变体。可从当前native owner范围获取精确当前源码正文，或在范围/USR对应不可核验时返回显式gap/unsupported；本探针允许无法安全取body时返回None且记录gap，仍保持原相同源码body的真实ALT double_free positive/基线0。不同USR重载、同USR但不同条件定义范围、显式文件/路径逃逸/过期反例均保留。不得补tag伪造范围收据；未知构建不是通配。
保留按scope共享验证、无scope义务needs_review、单次冻结/一次裁决/统计缓存生命周期；原10协调探针+新native_body必须全通过且0skip，成员标签不得退化。所有已支持不变量不放宽，完整S01-SYMBOL/ScanSession接线仍pending且源码根只读。
另：协调者扩大15既有协议文件时直接WSL启动缺clang PATH，产生227pass80skip（不是可接受验收）；这已定位为启动环境差异。必须使用WSL Ubuntu login shell（bash -lc），该环境10个工具PATH已核实，WPA/Saber无缺库。/home/zeal/venv313/bin/python经根test_slot.py --workspace本副本 --，显式Z_SCOPE_TEST_CLANG_INDEXER原工具，PYTHONPATH本副本、ext4TMPDIR两槽。你上轮307工件不替代本轮当前字节。协调者Black还复现tests/test_instance_analysis.py需格式化，必须对这个拥有文件实际Black，保留两处既有parallel非变更风格即可，不扩大无关格式化。
完成相关/native全集合、compileall/mypy和局部Black；旧287/292/303/307 JUnit全部保留，最终新文件名/稳定逐文件SHA/命令时间/未测/接线。根/其他副本/scan_session/code_index/共享验证及contracts/report/config/provider权限/旧S06只读，不commit/push/reset/clean，不声称整包完成。最终稳定交付后停止写入；无普通API超时证据，不转交ZCode。"""
request={"id":"s01-analysis-r6-review4","branch":"s01-analysis-r6-review4","tool":"dispatch_task","arguments":{
    "agent":"kimi","session_id":"sess_261a55289f","cwd":str(ROOT),"model":"volceapi/kimi-k3","title":"S01-INST-EXEC-R4",
    "message":message,"request_id":str(uuid4()),"user_requested":True}}
(HERE/"followups-r6/s01-analysis-r6-review4-request.json").write_text(json.dumps(request,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
queue=HERE/"route-check/bridge-queue/100-s01-analysis-r6-review4.request.json"
with queue.open("x",encoding="utf-8",newline="\n") as output:
    output.write(json.dumps(request,ensure_ascii=False)+"\n")
print(json.dumps({"review":str(OUT/"review.json"),"request":request["id"]}))
