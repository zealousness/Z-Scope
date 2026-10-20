"""Archive failed S01 delivery and send one authorized repair on its idle session."""
from pathlib import Path
import datetime as dt
import json
from uuid import uuid4
from audit_followup_r10 import audit, ROOT, HERE

route=HERE/"route-check"
policy=json.loads((route/"bridge-response-r11-preflight-agents.json").read_text(encoding="utf-8"))
assert policy["coordinator"]["dispatch_enabled"] and policy["coordinator"]["runtime_context"]=="coordinator"
branch=ROOT/".coordination/20261014/workspaces/s01-symbol-r10"
out=ROOT/"artifacts/coordinator-s01-symbol-probes-r10-20261015"
ownership=audit(branch.name)
assert not ownership["nonowned_changes"]
for name in [row["path"] for row in ownership["changes"]]+["DELIVERY.md"]:
    target=out/"initial-delivery"/name
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes((branch/name).read_bytes())
probe=HERE/"followups-r10/test_symbol_consumer_receipts.py"
(out/"failed-probe-current-fixture.py").write_bytes(probe.read_bytes())
review={"task_id":"task_9579265ee7","observed_model":"volceapi/kimi-k3","finished_at":"2026-10-14T23:28:14.022858+08:00",
        "checked_at":dt.datetime.now(dt.timezone.utc).isoformat(),"ownership":ownership,
        "independent_acceptance_passed":False,"source_unchanged":True,
        "probe_result":{"passed":1,"failed":5,"skipped":0},"integrated":False,"whole_package_complete":False,
        "tool_description_baseline":"artifacts/coordinator-tool-description-baseline-r10-20261015/review.json"}
(out/"review.json").write_text(json.dumps(review,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
message="""S01-SYMBOL R11独立验收返修，继续原sess_261a55289f、新副本s01-symbol-r10，原6文件所有权保持。task_9579265ee7已10月14日23:28:14 completed/observed K3/get_result完整无failure或warning。未导入根。原373生产者通过不能替代独立验收。
协调只读探针 followups-r10/test_symbol_consumer_receipts.py 实际1pass/5fail/0skip，两轮均复现；JUnit与4源码/DELIVERY冻结于根artifacts/coordinator-s01-symbol-probes-r10-20261015/{review.json,results-current-fixture.xml,initial-delivery,failed-probe-current-fixture.py}。前5项是明确合成owner形状单测并将dependency preflight held current；最后是真实ClangBatch/CodeIndex、先取helper正例，再实际修改flags.h，dependencies_current_status==stale_build_context却仍返回旧helper，非mock native。
五项失败：1 owner缺file但同USR/line仍授权callee；2 get_callees('f@unit.c:2-2')导航别名绕过_scope.names_entry判定，返回同USR另一owner.line9的wrong调用；3 program facts incomplete仍返回callees（应同时撤回callers/list）；4 get_callers显式callee_file='foreign.c'完全忽略；5真实头文件变化后已有_context_row_cache继续授予旧callee（应同时撤回callers/list及符号类型等实际迁移消费者）。
修复必须所有返回路径在发布/复用前复核当前构建依赖和完整native身份；未知/缺失/过期/显式文件不符均空+可定位gap，不能只贴build标签或在报告写gap仍返回污染数据。get_callees别名/USR/裸名要一致核验真实owner，非入口被调函数也必须在当前实例内按唯一USR/文件/位置消歧；重载/同名/不同header静态函数不能按name任选。当前USR查询query.split('@')会破坏c:@F标识，需覆盖实际native USR与导航alias正反例。callers精确callee_file与USR要同时核对，未知不能当通配。所有native正例保留，不准全禁消费/跳过工具来变绿。
迁移的消费者目前无条件_record_blocked以迁就旧只读测试，导致已安全供给的消费者仍记成unscoped。本轮可以先保持保守缺口但不宣称这些完整；如需要演进旧预期，请先给确切2处断言及新正反例，不直接越权写只读test_instance_analysis。完整contracts按USR选择及共享helper instance_scope接线仍属于协调者后续范围，不关闭S01主包。
工具描述失败已由协调者对根/本副本完整36文件实际各35pass1fail、工具和测试哈希均同派发baseline，证据artifacts/coordinator-tool-description-baseline-r10-20261015。根旧断言已由协调者同步实际symbols/text/files契约并加强默认结果无正文；你本副本只读旧测试暂不修改，不把省略该文件算全部通过。你的DELIVERY首行07:23+08/23:23Z与JUnit23:23+08、终态23:28不符，最终说明用真实命令/JUnit时间修正。
继续WSL Ubuntu zeal bash -lc +原test_slot两槽/ext4TMPDIR/PYTHONPATH本副本，真实native只读d39cbe72...。保留原373以及协调6探针和R9原12探针全部0skip，compileall/mypy/局部Black；必要可在自有两新测试补真实依赖/USR/别名/重载/外来file回归，最终稳定SHA和实际命令日志/时间完整后停写DELIVERY。原失败JUnit、旧DELIVERY和探针不得删改。根/共享Analyzer/ScanSession/全局契约调用方/规则/UI/native/provider权限和已归档S06-R02只读，不commit/push/reset/clean，不换模型绕审核。"""
request={"id":"s01-symbol-r10-review1","branch":"s01-symbol-r10-review1","tool":"dispatch_task","arguments":{
    "agent":"kimi","session_id":"sess_261a55289f","cwd":str(ROOT),"model":"volceapi/kimi-k3",
    "title":"S01-SYMBOL-R11","message":message,"request_id":str(uuid4()),"user_requested":True}}
(HERE/"followups-r10/s01-symbol-r10-review1-request.json").write_text(json.dumps(request,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
with (route/"bridge-queue/100-s01-symbol-r10-review1.request.json").open("x",encoding="utf-8",newline="\n") as stream:
    stream.write(json.dumps(request,ensure_ascii=False)+"\n")
print(json.dumps({"review":str(out/"review.json"),"request":request["id"]}))
