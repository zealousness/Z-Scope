"""Archive stable failed R2 deliveries before same-session R3 code repair."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
from uuid import uuid4
from audit_followup_r6 import audit, ROOT

HERE = Path(__file__).resolve().parent
specs = [
    ("s01-analysis-r6", "task_09da468c8a", "sess_261a55289f", "kimi", "volceapi/kimi-k3", "2026-10-14T21:52:20.342253+08:00", "coordinator-s01-r2-acceptance-20261014", 7, 3, "results-native.xml", "route-check/bridge-response-r6-public-85cf46237c.json"),
    ("s08-session-r6", "task_c1fb932358", "sess_3b6b9a19b2", "zcode", "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3", "2026-10-14T21:51:54.759436+08:00", "coordinator-s08-r2-acceptance-20261014", 5, 2, "results.xml", "route-check/bridge-response-r6-public-384a6dbcc3.json"),
]
s01_message = """S01 协调R3（你交付中的第4轮）真实独立验收返修。继续原sess_261a55289f、s01-analysis-r6、原6文件所有权；R2 task_09da468c8a已21:52:20 completed、observed kimi-k3，完整get_result无failure/warnings。旧7反例由协调者独立重跑全过，不重复返工；源码稳定，未导入根。
新增3fail已经实际复现，不能再只扩大标签/事后过滤：
1 真实native双宏→真实ParallelAnalyzer→实际共享验证helper路径，候选已产生、两个实例已分析，但_run_scan_validation_queue约930行重新创建Analyzer(code_index=self.code_index, semantic_result=self.semantic_result)，是未包装base index且复用旧全局semantic_result。前置Analyzer的scope包装不保护后置Validator/工具/反证。协调探针只在真实Analyzer.__init__旁观传参后仍执行原构造/候选/队列，不mock其成功。
2 同一BuildContext但类型payload的function_identity.usr指向other，get_function_type_context仍返回该类型。
3 类型/宏payload仅外层build_context_id=当前ctx、子宏ALT无任何身份收据，get_function_symbol_context仍接受。_iter_build_ids的tag检查不是精确native收据；当前入口自身native facts有效不能替代被返回投影的来源核验。
证据根artifacts/coordinator-s01-r2-acceptance-20261014/{review.json,results-native.xml,initial-delivery}；只读新探针followups-r6/test_instance_validation_scope.py，与原guard/navigation两探针合跑7pass3fail0skip。首轮漏native env的7pass2fail1skip单独保留，最终native轮已显式工具，不用首轮代替native结论。原worker303/JUnit/5改动源码/DELIVERY已归档。
修复：共享验证必须保持当前精确BuildContext+native USR/范围作用域。可按精确scope分组pending并给每个真实验证helper传InstanceScope与ScopedCodeIndex、semantic_result=None/空语义，或等价正确实现；单次全局ledger冻结/义务一次裁决、缓存/去重/状态/统计生命周期都保留，禁止在无scope helper里先验证再按ID过滤。缺失/多scope/无法核验义务不得走base，应保留明确needs_review/gap。你拥有parallel_analyzer.py/analyzer.py，需直接修复该共享调用位置，不修改协调者scan_session/code_index/验证公共文件。
类型/宏/metadata收据必须绑定被消费内容自身的native USR、源码范围和当前构建；同构建ID、父对象的tag、字符串名称不授权成员事实。当前base API未提供充分收据时安全拒绝并记consumer gap即可；不必本轮完成S01-SYMBOL。你前轮新增的仅buildID positive是假定不足的正例，需改为真正充分收据的正例或明确unsupported，并保留真实native标准根候选positive。不能通过给数据补USR标签来制造收据。
保留真实native仅ALT double_free/基线0、全部24+既有foreign/missing/stale/TU/overload/path及closed/close/concurrent反例，默认实验开关不改。新增协调探针只读，自己补拥有测试；native工具只读d39cbe72...，每次native测试显式Z_SCOPE_TEST_CLANG_INDEXER。WSL /home/zeal/venv313/bin/python经根test_slot.py --workspace本副本 --，PYTHONPATH本副本，ext4TMPDIR两槽。完成相关/native完整集合、compileall/mypy、局部Black，旧287/292/303全部保留，新JUnit文件名，最终稳定SHA/时间/未测/接线说明。根目录、其他副本、共享contracts/report/config/provider权限和旧S06只读；不commit/push/reset/clean，不声称整S01完成。最终稳定交付后停写。"""
s08_message = """S08 协调R3返修，继续原sess_3b6b9a19b2、s08-session-r6和R2扩展7文件所有权。task_c1fb932358已21:51:54 completed、observed精确glm-5.3，get_result完整且无failure/warnings；当前7源码稳定，未导入根，无活跃同会话任务。R2结果正文结束于修测试heredoc阶段，DELIVERY/DELIVERY.md仍R1旧SHA，不能当R2完成收据；本轮务必把真实回归/质量/最终交付收口。
原5协调探针已独立重跑全过：stale claim/input/owner拒绝、batch上限首轮保留pending、父子事务提交后真实进程退出恢复有child。这些修复保留。
新2fail：
1 queue.settle同一discoveries里两个相同child都先归入new_items，第二次INSERT触发UNIQUE，整次合法去重结果被queue_unavailable503拒绝。要求同结果内(kind,scope,build)去重并正确计duplicates，不能只处理数据库已有项。仍保持父verdict+全部新child同事务、失败全回滚、精确input/token/bound_attempt锁。
2 max_attempts=1,max_batches=1，父项首次因discovery_batch_limit被defer保留；同输入重开scheduler后claim_batch把该deferred按attempt耗尽转failed，run drained/remaining0。你的settle文档宣称结构上限deferral不受attempt-bound，但claim路径未落实。必须让这种未接纳发现可持久保持真实remaining且停止该轮；同输入resume不能清空，不能无限忙循环/无界重复handler。输入变化后的recover要撤销该前提并重新核验。可明确持久blocked原因并在claim/scheduler恢复消费处尊重，避免把它误报普通执行失败；普通handler错误/延期的max_attempts仍有界。
新只读协调探针followups-r6/test_scheduler_settlement_edges.py，合原两文件是5pass2fail；artifacts/coordinator-s08-r2-acceptance-20261014/{review.json,results.xml,initial-delivery}。源码7文件、旧R1交付和当前R2JUnit已归档。
副本还已有DELIVERY/junit-r2-full.xml：159 tests/158pass1fail0skip，test_resume_changed_input_recovers_and_reruns_all首次窗口4项全done，断言done_first非空且<4失败。该工件时间晚于Bridge终态，来源未被协调者确认为最终worker轮，不能拿来宣称通过。把真实owner恢复测试改成有确定同步/控制的“先完成一部分、保留另一部分”，保持非空真remaining、input_revoked/queue_recovered、第二次真实全量重验等原断言，不放宽为允许首轮全完成，不靠延长/放大时间碰运气。首轮partial status但queue全done也须检查owner/scanner有限收尾的语义是否真一致。
DELIVERY必须更新R2/R3真实SHA/命令时间与剩余，不覆盖历史JUnit；纠正原task_28...“API故障取消”的错误说法（实际协调者提交代码反例正常cancel），时钟跳变可能提前也可能延后，不能宣称只延后。收据可顶层DELIVERY.md或原DELIVERY目录说明/JUnit；artifacts亦可。所有新增测试/质量在WSL /home/zeal/venv313/bin/python经根test_slot.py --workspace本副本 --，ext4TMPDIR两槽。完整相关pytest、compileall zscope scripts test tests、mypy zscope、局部Black；保留原3/24/119、R2失败159和新5/2失败证据，最终新文件名。源7文件之外只读，root/其他副本/ScanSession/ParallelAnalyzer/provider权限/旧S06不操作，不commit/push/reset/clean，不绕审核。完整scanner接线仍协调者，standalone通过不关闭S08/JOB04/JOB06。最终稳定交付后停止写入。"""
for workspace, task_id, session, agent, model, finished, artifact, passed, failed, junit, result_receipt in specs:
    audit_result = audit(workspace)
    assert audit_result["safe_to_review"]
    out = ROOT / "artifacts" / artifact
    work = ROOT / ".coordination/20261014/workspaces" / workspace
    hashes = {row["path"]:row["after"] for row in audit_result["changes"]}
    assert all(hashlib.sha256((work/name).read_bytes()).hexdigest()==sha for name,sha in hashes.items())
    archive = out / "initial-delivery"
    archive.mkdir(exist_ok=False)
    names = list(hashes)
    if agent == "kimi":
        names += ["DELIVERY.md", "artifacts/instance-analysis-tests-r3.xml"]
    else:
        names += [str(path.relative_to(work)) for path in (work/"DELIVERY").iterdir() if path.is_file()]
    for name in names:
        target = archive/name
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(work/name,target)
    review = {"task_id":task_id,"observed_model":model,"finished_at":finished,"checked_at":dt.datetime.now(dt.timezone.utc).isoformat(),
              "ownership":audit_result,"after_hashes":hashes,"source_unchanged":True,"independent_acceptance_passed":False,
              "probe_result":{"passed":passed,"failed":failed,"errors":0,"skipped":0},"junit":junit,
              "result_receipt":result_receipt,"integrated":False,"whole_package_complete":False}
    (out/"review.json").write_text(json.dumps(review,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    request = {"id":workspace+"-review3","branch":workspace+"-review3","tool":"dispatch_task","arguments":{
        "session_id":session,"cwd":str(ROOT),"agent":agent,"model":model,"title":("S01-INST-EXEC-R3" if agent=="kimi" else "S08-SESSION-SCHEDULER-R3"),
        "message":s01_message if agent=="kimi" else s08_message,"user_requested":True,"request_id":str(uuid4())}}
    path = HERE/"followups-r6"/(workspace+"-review3-request.json")
    path.write_text(json.dumps(request,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    queue = HERE/"route-check/bridge-queue"/("100-"+request["id"]+".request.json")
    with queue.open("x",encoding="utf-8",newline="\n") as stream:
        stream.write(json.dumps(request,ensure_ascii=False)+"\n")
    print(json.dumps({"workspace":workspace,"failed_review":str(out/"review.json"),"request":request["id"],"request_id":request["arguments"]["request_id"]}))
