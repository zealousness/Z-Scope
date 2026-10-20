"""Prepare disjoint next dependencies from the green, current R9 source snapshot."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-r9-s01-s08-intaken-20261014"
FOLLOWUPS = HERE / "followups-r10"

S01 = """继续 S01-SYMBOL，Kimi 负责精确编译实例的符号/类型/宏/图与契约消费者迁移。上一阶段S01-INST-EXEC经协调者修复及独立312通过、5文件集成，并与S08/U01/Astra同版本联合后才发此任务；不是整包完成。
新副本s01-symbol-r10是当前已验根目录快照，不要继续写旧s01-analysis-r6。原R4 task_6e14411a6c为正常cancelled，确认native callee泄露后停写；协调者随后force include_context=False、清除无收据callee/comment、去重复owner检查并加缓存不变回归。不能恢复这处旧实现或以blocked gap掩盖仍返回的异构数据。没有普通API超时证据，不转模型。
独占 zscope/retrieval/knowledge_db.py、code_index.py、instance_index.py、zscope/semantics/contracts.py、新tests/test_full_symbol_build_scope.py；可以新增tests/test_instance_symbol_native.py。其余全部只读，特别native/clang工具、clang_backend/batch、Analyzer/ParallelAnalyzer/ScanSession、规则与UI。需要新producer事实或共享文件时给出确切缺口/调用点，由协调者串行处理，不伪造native收据。
目标是把现有被ScopedCodeIndex明确阻止的实际消费逐项接到精确BuildContext+native USR事实，而非给全局投影补build标签。类型、宏、callee/caller/引用、对应合同与缓存每项必须有自己的当前实例成员收据；同build不同USR、相同USR不同条件定义、同名不同TU/重载不能借用。原导航API可留显式未知，但scoped实际入口应消费已能核验的数据，未知链接不是全目标、未知构建不是通配。不能仅登记能力标签/事后贴候选ID来宣布迁移完成。
逐项交付已接入消费者及仍unsupported清单。优先真实ClangBatch双宏条件callee/类型/宏正反例，至少实际Analyzer或共享ValidationRunner消费者读取新精确数据，不能只有fake调用清单。保留ALT真实double_free和BASE无候选、条件定义native起始行拒绝、显式文件/重载/过期依赖/成员收据/共享cache隔离全部旧回归；不准删除探针、skip或降低native标准。合同建立的证据必须绑定实际符号/构建，不把调用上下文或仅外层buildtag当授权。
先读docs/modules/retrieval-backends.md、configuration-state.md、实施11/16/21及root AGENTS与实际调用者。完成相关已有+新native测试、compileall/mypy及变更文件Black（仅必要格式）。交付最终稳定SHA、JUnit、各命令真实时间、未测和所需接线；停写后再发最终说明。不能声称完整S01/全扫描/真实模型效果已完成。"""

MCP = """实施 U01-MCP-JOBS，ZCode glm-5.3负责剩余MCP入口迁移，协调者继续共享扫描接线；前端仍Astra。
当前Web作业已复用orchestration.jobs.ScanJobService，但MCP provider仍创建旧内存ScanRequestService并调用start/status。这不是同一个持久job后台，服务重开后不能继承真实job状态。本任务以当前源码确认该差异，并把MCP作业控制统一到已有真实持久service，不另造线程/内存作业数据库，不通过HTTP自调Web，不启动新Bridge/模型代理。
新副本u01-mcp-r10，独占 zscope/mcp/provider.py、新zscope/mcp/jobs_adapter.py、tests/test_mcp_http_server.py、test_mcp_policy.py、test_mcp_read_only.py、test_mcp_security.py、新tests/test_mcp_jobs.py。其他源码/config/jobs/service/scan_request/Web/CLI/native/规则/文档只读。provider内部必要构造参数可调整，新增工具schema有明确命名和strict参数，保持read_only/candidate_blind权限边界与现policy/审计/输出限制；不要扩大读取任意URL/命令或新增权限平台。
MCP默认scan run/status应返回实际job/run/revision/input绑定；提供查询/事件游标/结果及取消/恢复所需同源接口，控制操作使用request_id/base_revision，重放冲突语义与Web相同。由当前saved config定位项目store，v3单目标路径与prepare禁启多目标行为复用当前parser/service，不能自造近似schema或把完整多目标编辑等同可执行。旧run内存状态不具新job确认资格；不用历史report授予当前确认。
必须真实Linux SQLite+ScanJobService+实际detached owner子进程，允许明确受控scanner/report但不能mock服务成功；覆盖两个provider实例/重建服务共享状态、同request_id重复启动只有一owner、revision冲突、cancel/resume、输入变化、结果绑定与read-only/candidate_blind不能启动/控制。保留MCP安全/SQL/路径/权限全部既有正反例，不用放宽工具schema来迁就测试。扫描器尚未完成工作项接线的边界保持诚实，不宣称JOB04/JOB06/完整U01。
相关MCP及jobs回归、compileall/mypy、变更必要Black在WSL执行，给稳定源码SHA/命令时间/JUnit/所有未测。完成后停止写入并交DELIVERY.md；共享文档/scan_session由协调者独立验收后集成。"""

ASTRA = """请Astra继续U01/U02实际用户流程审查与必要前端修复。新副本astra-ux-r10来自S01/S08/U01当前同源联合通过快照；旧astra-config-r6与phase1/2/3全部只读，保留旧证据。前端仍由你开发，后台及根目录由协调者集成。
独占zscope/web/static/**（vendor及LICENSE只读）、tests/test_agent_workbench_ui.py、tests/fixtures/agent_workbench_ui.cjs；DELIVERY.md/artifacts可写。后端、锁、共享docs、provider、native/旧S06全部只读。不新增服务或用户chat，不自行重启Bridge。
对照20用户体验与16的UX01-09，实际检查当前配置编辑→重新准备→启动→断开重连→取消/截止→恢复→报告验收/回答撤回流程。列出每条实际可执行路径、合同fixture和后端未接入；实际scanner/report仍受控合成，不能算真实项目效果。仅修复当前可复现的前端问题和容易误导的已消费能力表述，不编造尚未接线的多目标执行、完整队列remaining或stop_at意图生效。发现后端问题提交最小复现和调用点，不改后端。
保持phase3原生datetime规范化和12秒真实截止/owner/partial/resume/无重复断言。验证桌面/手机、键盘、加载/空/错/409/草稿与迟到响应；合同409无CAS仍如实标记。当前所有profiles/相对路径/env引用不丢，不把空密码覆盖已存值。不对不存在的后端能力新增成功fixture来形成完成声明。
真实HTTP/SQLite/浏览器用WSL运行，截图/JUnit/逐文件SHA/实际时间/未测一起交付。若审查无需要修复的前端缺陷，可零产品变更交证据矩阵，不为产生代码而改动。必须完成实际执行及静态资源离线核对，锁文件由协调者接收后更新，不能自行写根目录。"""

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    review = json.loads((OUT / "review.json").read_text(encoding="utf-8"))
    source = json.loads((OUT / "source-evidence.json").read_text(encoding="utf-8"))
    assert review["quality_commands_passed"] == 6 and review["skipped"] == 0
    assert all(source["intaken_features"].values()) and source["direct_source_unchanged"]
    assert all(digest(ROOT / name) == sha for name, sha in source["after"].items())
    FOLLOWUPS.mkdir(exist_ok=False)
    tasks = [
        {"id":"S01-SYMBOL", "workspace":"s01-symbol-r10", "agent":"kimi", "model":"volceapi/kimi-k3",
         "session_id":"sess_261a55289f", "owns":["zscope/retrieval/knowledge_db.py","zscope/retrieval/code_index.py","zscope/retrieval/instance_index.py","zscope/semantics/contracts.py","tests/test_full_symbol_build_scope.py","tests/test_instance_symbol_native.py"], "message":S01},
        {"id":"U01-MCP-JOBS", "workspace":"u01-mcp-r10", "agent":"zcode", "model":"97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3",
         "session_id":"sess_a0adb99b15", "owns":["zscope/mcp/provider.py","zscope/mcp/jobs_adapter.py","tests/test_mcp_http_server.py","tests/test_mcp_policy.py","tests/test_mcp_read_only.py","tests/test_mcp_security.py","tests/test_mcp_jobs.py"], "message":MCP},
        {"id":"ASTRA-UX-R10", "workspace":"astra-ux-r10", "agent":"Astra", "model":"gpt-6-astra",
         "owns":["zscope/web/static/**","tests/test_agent_workbench_ui.py","tests/fixtures/agent_workbench_ui.cjs"], "message":ASTRA},
    ]
    for task in tasks:
        workspace = ROOT / ".coordination/20261014/workspaces" / task["workspace"]
        workspace.mkdir(exist_ok=False)
        for name, sha in source["after"].items():
            target = workspace / name
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT / name,target)
            assert digest(target) == sha
        task["isolated_workspace"] = str(workspace)
        task["isolated_workspace_linux"] = "/mnt/c/" + workspace.as_posix()[3:]
        task["depends_on"] = ["CURRENT-JOINT-R9"]
        common = f"""
唯一写目录：{workspace}；WSL：{task['isolated_workspace_linux']}。根项目cwd保持{ROOT}仅供Bridge会话定位，执行/修改必须显式cd隔离副本；不能继续写旧副本。此副本{len(source['after'])}输入逐字节来自最终R9收据{OUT.relative_to(ROOT)}，未拥有路径一律只读。
Linux测试/质量统一WSL Ubuntu zeal login shell bash -lc，/home/zeal/venv313/bin/python，经根协调test_slot.py --workspace <副本绝对Linux路径> -- <argv>运行；PYTHONPATH本副本、独立ext4 TMPDIR、最多2槽。不能原生Windows结论/skip工具/改pytest捕获来变绿。Z_SCOPE_TEST_CLANG_INDEXER=/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer，工具SHA d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399，只读不重编译。所有既有失败/探针保留。
Astra浏览器：ZSCOPE_UI_PLAYWRIGHT_MODULE=/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright；ZSCOPE_UI_CHROMIUM=/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome；三个EVIDENCE变量均本副本artifacts，ZSCOPE_UI_MULTI_TARGET_EDITING=1。锁只读，vendor/LICENSE不改，不联网抓取新资源。
根/其他副本/凭据/provider/权限配置和已归档S06-R02不操作，不commit/push/reset/clean。最终交付DELIVERY.md+artifacts，源码逐文件SHA及测试命令/UTC+8时间/范围/未测/剩余必须完整；全部检查完成且停写后才报告终态。协调者独立验收、共享文件集成及联合回归，不把worker自报或切片等同整包完成。普通API失败如实保存，不通过换模型绕过审核。
"""
        task["message"] += common
        baseline = {"captured_at":dt.datetime.now(dt.timezone.utc).isoformat(),"task":task,
                    "files":[{"path":name,"sha256":sha} for name,sha in source["after"].items()],
                    "joint_evidence":review["source_evidence"],"dispatched":False}
        (FOLLOWUPS / (task["workspace"]+"-baseline.json")).write_text(json.dumps(baseline,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
        if task["agent"] != "Astra":
            request = {"id":task["workspace"],"branch":task["workspace"],"tool":"dispatch_task","arguments":{
                "agent":task["agent"],"model":task["model"],"session_id":task["session_id"],"cwd":str(ROOT),
                "title":task["id"],"message":task["message"],"request_id":str(uuid4()),"user_requested":True}}
            (FOLLOWUPS/(task["workspace"]+"-request.json")).write_text(json.dumps(request,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    prepared = {"at":dt.datetime.now(dt.timezone.utc).isoformat(),"source_files":len(source["after"]),"tasks":tasks,"dispatched":False}
    (FOLLOWUPS/"prepared.json").write_text(json.dumps(prepared,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    assert all(digest(ROOT/name)==sha for name,sha in source["after"].items())
    print(json.dumps({"prepared":[task['id'] for task in tasks],"source_files":len(source['after']),"dispatched":False}))

if __name__ == "__main__":
    main()
