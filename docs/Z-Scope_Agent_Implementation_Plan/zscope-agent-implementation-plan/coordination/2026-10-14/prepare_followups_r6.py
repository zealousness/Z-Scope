"""Prepare isolated follow-ups only after the current root acceptance is green."""

from pathlib import Path, PureWindowsPath
import datetime as dt
import hashlib
import json
import shutil
from uuid import uuid4
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WINDOWS_ROOT = PureWindowsPath(r"C:\Users\10273\home\work\Z-Scope_1.31\Z-Scope")
PLAN = HERE.parents[1]
FOLLOWUPS = HERE / "followups-r6"
CURRENT = ROOT / "artifacts/coordinator-r6-integrated-20261014"

S01 = """实施 S01-INST-EXEC：把当前精确编译实例实际交给分析消费，不能只增加计划、标签或 mock 调度。
当前 entry_instances 仍 scheduled_instances=null/scan_coverage_complete=false；ScanSession 仍 analyze_function_entries(entries)。
你独占 analyzer.py、parallel_analyzer.py、entry_instances.py、新 retrieval/instance_index.py、test_all_variant_scan.py、新 test_instance_analysis.py；其余源码只读。
协调者独占根目录、scan_session.py、code_index.py、全局建模/共享契约/验证器公共文件及报告/路由接线。需要这些修改时交付精确接线说明，不越权写文件。
实现可由协调者调用的真实实例分析入口，以精确 BuildContext+native USR 选择当前事实，传给真实 Analyzer 及既有验证链。作用域必须贯穿所消费的事实和候选/结果身份、缓存/去重；不能仅事后给 issue 贴 build_context_id。
可用专门 scoped CodeIndex facade，但旧导航、图或语义消费者无法保持作用域时必须明确 gap/unsupported，不静默取第一实例、裸函数名或退回其他构建。未知构建不是通配符。
首切片限定实际 native 双宏/同名函数的当前构建；至少一例仅在一个变体存在的真实候选经过实际分析链，与正常变体分开；覆盖 foreign/missing identity、头文件/宏变化、不同 TU/重载和显式文件选择拒绝。模型响应可以明确受控，native/Analyzer/候选/验证消费不可用假调用列表代替。不要为变绿删除当前反例。
当前根目录已修 normalized ../ entry 拒绝，保留该行为。不要声称完整 S01-SYMBOL、链接、全变体建模或真实 LLM 扫描已完成。
交付 actual execution API、相关正反例、真实 Linux/native JUnit、compileall/mypy、必要 Black、SHA 和未消费缺口。若实现需要超出独占文件，先交付已可验证部分和具体所需文件/调用位置，由协调者处理共享接线。"""

S08 = """实施 S08-SESSION-SCHEDULER：消费已验收 WorkQueue 和 JobWindowHook，支持真实扫描工作边界、有限收尾、批次公平与 remaining。
独占新 jobs/session_scheduler.py、jobs/scheduler_hook.py、jobs/owner.py、新 tests/test_job_session_scheduler.py。现有 store/service/work_queue/scheduler.py、parallel_analyzer.py、scan_session.py 只读，协调者独占接线。owner 已含本轮 job/attempt 同事务终态修复，必须保留。
提供真实持久队列的 session 调度消费器，声明工作键包含 kind+稳定 scope+精确 build，绑定 job/input/run/owner。claim_token 完成/延期必需；旧 claim、旧 run、旧输入不能消费新工作。工作回调由当前进程/源码重新登记，不从 JSON 恢复命令、证明或执行权限。
截止停止新 claim，允许已领取工作有界收尾，真实剩余队列持久化；有新增根因进入下一批、重复去重、有界尝试/延期与长期未决轮转，业务未知记问题/延期而非 waiting_user。恢复重新核对输入和当前回调，仅有效完成可复用；不能把 resume 重新全扫冒充 remaining。
owner 需向真实 scanner 传递当前 hook 所需标识，合作截止优先于 watchdog；watchdog 是有限收尾的后备。保存真实 pending 时不能被 owner 的空占位覆盖；没有已测剩余分母时保持 unknown。所有 job/run/token 必须核对，不向日志泄露 token。
测试使用真实 SQLite、实际 hook/调度器及独立子进程，覆盖截止前后 claim、在途收尾、watchdog、取消、重开/输入失效、旧 token 与新根/难例公平。可用明确受控工作回调，但不可 mock job/DB/owner 成功。
明确独立消费器尚需 ScanSession/ParallelAnalyzer 接入，不能仅本模块通过就关闭 JOB04/JOB06/S08。交付接线 API、必要 owner/env 合同、真实 Linux JUnit/质量/SHA 和剩余缺口；不改共享文件或实验默认值。"""

U01 = """实施 U01-ENTRYPOINTS：当前严格 v3 模型已有，但 CLI prepare/validate、初始化器和语言模板未统一；不做任何前端。
独占新 config/editor.py、cli/config_cli.py、cli/init.py、两份 zscope.c_cpp.yaml/zscope.java.yaml、tests/test_cli_config_v2.py、tests/test_reference_configs.py、新 tests/test_config_v3_entrypoints.py。
config/v3.py、v3_preparation.py、config.py/v2.py、Web/MCP/README/模块/21、static 和 UI tests 全部只读。协调者接 Web/MCP/文档，Astra独占 UI。
CLI prepare 必须与 Web 同用 prepare_saved_config，v3 多 target 保留并禁启，不因 EffectiveConfig 单目标组合而无法检查全部 target。validate 显示实际版本，不把 v3 输出写成 v2；验证与执行区分。
初始化器/两语言模板以当前严格 v3 模型为准，root 相对配置文件目录、target/compile_commands 相对工程；从不同 cwd 的实际 CLI round-trip 正反例。模型 profile/env 引用及人工资料不丢；不展示绝对工具路径或私有 endpoint。preset 映射与未消费的 focus/reproduction/workers/platform/stop_at 不能伪装启用，实验默认不改。
为协调者提供小型 config/editor.py 服务：在同一配置目录解析/验证待保存文件，v3 调用现有 parse_user_config_v3 而不强迫多 target 组合执行；v2仍走当前 loader。提供结构化编辑读取投影，保持原始 document（含所有 llms profiles/相对路径/环境变量引用）与实际版本；多 target 可以合法编辑保存但执行仍禁启。全部约束重用当前 parser/schema，不能另造近似解析器或修改模型来迁就 UI。
Web 接线约定保持现有 GET /api/config/structured 的 config/config_version/language 和 POST {config:document}，新 helper 由协调者接入 ConfigService；无需你修改 routes/services。保存仍原子且验证失败不覆盖原文件。
相关测试用实际 CLI/文件/解析器，多目标、不同 cwd、错误配置不覆盖、profiles/相对路径往返、Java无编译数据库；运行 Linux pytest/compileall/mypy/Black 并交付 SHA。不要声称完整 U01 画像、MCP 作业控制或所有配置意图已消费。"""

ASTRA = """请由 Astra 亲自继续 ASTRA-V3-EDITOR，用户已授权本轮分工；原97项UI验收保留为历史，不累加。本次只在指定隔离目录开发，根目录仍由协调者集成。
独占 static/**、tests/test_agent_workbench_ui.py、tests/fixtures/agent_workbench_ui.cjs 以及本分支 DELIVERY/artifacts。所有后端、共享文档、锁、native/协议和旧S06-R02只读，不恢复旧会话。
把现有 v3 只读配置体验推进为可编辑：工程/语言/platform、全部targets、preset、focus/reproduction、timezone/stop_at/max_workers、模型设置。当前公开模型是唯一字段依据；root 相对配置目录、目标路径相对root。保留所有未编辑 llms profiles、相对值和环境变量引用，不经旧v2 builder降级，不把空密码覆盖已有设置。未消费字段继续用清楚用户文案披露，多目标执行保持禁启。
当前真实 GET/POST /api/config/structured 合同 config/config_version/language 与 POST {config:document} 不改。协调者正让 U01 producer提供 parser-only 多目标编辑 helper，之后接入 ConfigService；该接线尚未交付时，多目标保存联调必须记待接入，不可 mock 成功后宣称真实通过。单目标可用现有真实服务。发现必要后端缺口给具体复现，协调者处理，不自己改后端。
旧 v2 编辑保持当前实际支持；v3草稿、失败/409/迟到响应、切换配置和保存后重新准备需保护用户输入，取消未保存状态不能启动错误版本。清楚区分配置 stop_at 意图与当前 jobs 显式进程截止，不声称新的任务级调度已接入。
用真实 HTTP/ConfigService/SQLite/浏览器验证可运行路径；scanner/报告如仍受控合成必须标注。验证手机/键盘/空错加载与无外部请求，并保存截图/最终稳定SHA/实际Linux JUnit。UI可声明合同fixture，但必须与真实端到端证据分开。
此轮不改变全部后端消费或完整 U01/U02/S08 完成状态。最终交付返回本chat可读的路径和SHA；不要操作根目录锁或启动重复服务。"""


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    evidence = json.loads((CURRENT / "source-evidence.json").read_text(encoding="utf-8"))
    suites = ET.parse(CURRENT / "results.xml").getroot().findall("testsuite")
    assert evidence["direct_source_unchanged"]
    assert len(evidence["commands"]) == 6 and all(c["returncode"] == 0 for c in evidence["commands"])
    assert suites and all(int(s.get(k, "0")) == 0 for s in suites for k in ("failures", "errors", "skipped"))
    assert sum(int(s.get("tests", "0")) for s in suites) >= 574
    FOLLOWUPS.mkdir(exist_ok=False)
    audit = json.loads((ROOT / "artifacts/coordinator-readonly-audit-20261014/review.json").read_text(encoding="utf-8"))
    names = {f["path"] for f in audit["files"]}
    names.update(str(p.relative_to(ROOT)) for p in PLAN.glob("*.md"))
    names.update(str((HERE / n).relative_to(ROOT)) for n in ("API_CONTRACT.md", "NEXT_BACKEND_CONTRACT.md", "test_slot.py"))
    # Extension-based historical inventories omit metadata and vendor licenses.
    # These are real test/package inputs and must accompany an isolated copy.
    names.update(n for n in (".editorconfig", ".gitattributes", "LICENSE") if (ROOT / n).is_file())
    names.update(str(p.relative_to(ROOT)) for p in (ROOT / "zscope/web/static/vendor").glob("*.LICENSE"))
    rows = [{"path": n, "sha256": digest(ROOT / n)} for n in sorted(names)]
    stage = json.loads((HERE / "continuation-r6.json").read_text(encoding="utf-8"))
    prompts = {"S01-INST-EXEC": S01, "S08-SESSION-SCHEDULER": S08, "U01-ENTRYPOINTS": U01, "ASTRA-V3-EDITOR": ASTRA}
    for task in stage["planned"]:
        relative = Path(".coordination/20261014/workspaces") / task["workspace"]
        workspace = ROOT / relative
        workspace.mkdir(exist_ok=False)
        for row in rows:
            target = workspace / row["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / row["path"], target)
        task["isolated_workspace_windows"] = str(WINDOWS_ROOT / PureWindowsPath(relative.as_posix()))
        task["isolated_workspace_linux"] = str(workspace)
        common = f"\n当前根目录联合回归与6项质量命令已通过，真实收据 {CURRENT.relative_to(ROOT)}。本任务仅在 {task['isolated_workspace_windows']}（WSL {workspace}）修改独占文件。\n先读快照 AGENTS/architecture、计划11/16/21及当前源码，不把历史切片等同整包。所有产品质量在WSL Ubuntu /home/zeal/venv313/bin/python，PYTHONPATH必须为本隔离目录。\n每次 pytest/native/质量命令通过根目录协调 test_slot.py --workspace <本隔离目录Linux绝对路径> -- <argv> 执行，最多两个并发检查；临时文件已自动放独立ext4 /tmp，不使用/mnt/c TMPDIR。native测试设置 Z_SCOPE_TEST_CLANG_INDEXER=/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer。Astra浏览器设置 ZSCOPE_UI_PLAYWRIGHT_MODULE=/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright，ZSCOPE_UI_CHROMIUM=/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome；ZSCOPE_UI_EVIDENCE 指向本分支 artifacts。native只读 /home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer，SHA d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399，不重建。\n共享root、其他分支、凭据/provider/权限、旧S06会话不操作；不commit/push/reset/clean。允许本分支DELIVERY.md/artifacts；交付逐文件SHA、JUnit/实际命令/时间/未测和需协调接线范围。工具按当前公开参数schema，不重放旧错误调用。\n"
        message = prompts[task["id"]] + common
        baseline = {"captured_at": dt.datetime.now(dt.timezone.utc).isoformat(), "task": task, "files": rows, "joint_evidence": str(CURRENT.relative_to(ROOT))}
        (FOLLOWUPS / f"{task['workspace']}-baseline.json").write_text(json.dumps(baseline, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if task["agent"] == "Astra":
            request = {"threadId": task["existing_thread"], "model": "gpt-6-astra", "prompt": message}
        else:
            request = {"id": task["workspace"], "branch": task["workspace"], "tool": "dispatch_task", "arguments": {"agent": task["agent"], "model": task["model"], "cwd": str(WINDOWS_ROOT), "title": task["id"], "message": message, "request_id": str(uuid4()), "user_requested": True}}
        (FOLLOWUPS / f"{task['workspace']}-request.json").write_text(json.dumps(request, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"id": task["id"], "workspace": str(workspace), "request": f"{task['workspace']}-request.json", "inputs": len(rows)}), flush=True)
    assert all(digest(ROOT / row["path"]) == row["sha256"] for row in rows), "source changed during preparation"
    (FOLLOWUPS / "prepared.json").write_text(json.dumps({"at": dt.datetime.now(dt.timezone.utc).isoformat(), "tasks": stage["planned"], "source_files": len(rows), "dispatched": False}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
