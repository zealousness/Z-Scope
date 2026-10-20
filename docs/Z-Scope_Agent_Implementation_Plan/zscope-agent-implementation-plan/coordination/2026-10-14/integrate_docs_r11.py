"""Describe accepted bounded consumers and MCP jobs before final joint capture."""
from pathlib import Path
import datetime as dt
import json

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
assert (ROOT/"zscope/mcp/jobs_adapter.py").is_file()
assert (ROOT/"tests/test_full_symbol_build_scope.py").is_file()

def replace(name, old, new):
    p=ROOT/name
    text=p.read_text(encoding="utf-8")
    assert text.count(old)==1,(name,old[:80])
    p.write_text(text.replace(old,new),encoding="utf-8",newline="\n")

replace("README.md",
    "Dashboard 的 `POST /api/scan` 可按请求传入 `scan_depth`，并以 `GET /api/scan/status?scan_id=...` 查询 effective depth、实际 token usage 与最终 completeness；服务拒绝任意命令、环境或输出路径字段。MCP 对应提供 `zscope.scan.run` / `zscope.scan.status`，以及只读的 `zscope://reports/latest` 与 `zscope://rules/effective`。",
    "Dashboard 当前作业入口为 `GET/POST /api/jobs`，复用工程侧持久 `ScanJobService`。Linux 上 MCP 的 `zscope.scan.run` 同样创建持久作业，必需 `request_id`，可选 `scan_depth`、带时区的绝对 `stop_at`；返回 `job_id`、`run_id`、`revision` 和输入绑定，重复请求重放同一作业。`zscope.scan.status` 必需 `job_id`。旧 Web `/api/scan` 的内存状态不能替代持久作业状态。接口不接受任意命令、环境、cwd 或输出路径。只读资源 `zscope://reports/latest`、`zscope://rules/effective` 保留。")
replace("README.md",
    "管理工具固定为 `zscope.knowledge.query`、`zscope.entries.discover`、`zscope.scan.run`、`zscope.scan.status`、`zscope.wiki.status` 和 `zscope.wiki.query`。",
    "管理工具包括 `zscope.knowledge.query`、`zscope.entries.discover`、`zscope.scan.run`、`zscope.scan.status`、`zscope.wiki.status`、`zscope.wiki.query`，以及 `zscope.jobs.list`、`zscope.jobs.events`、`zscope.jobs.result`、`zscope.jobs.cancel`、`zscope.jobs.resume`。作业工具仅在 `default` profile 提供，要求 Linux 后台和已保存配置；`read_only`、`candidate_blind` 不构造作业服务。events 使用 `job_id` 和可选非负 `after_seq`；cancel/resume 必需 `job_id`、`base_revision`、`request_id`，冲突语义与 Web 相同。显式 null 不是省略字段。result 目前提供本轮报告绑定，尚无 MCP findings 投影。多目标配置仍可编辑、不可执行；完整扫描队列接线和只执行剩余项仍未完成。")
replace("docs/modules/interfaces-reporting.md",
    "- Web `POST /api/scan` 与 MCP `zscope.scan.run` 只接受 `scan_depth` 覆盖并异步启动扫描；状态接口返回 effective depth、实际 token usage 和最终 completeness。MCP 同时提供 `zscope://reports/latest` 与 `zscope://rules/effective` 只读资源。接口不得接受任意命令、环境、cwd 或输出路径。",
    "- 当前 Web `/api/jobs` 与 Linux MCP 作业工具复用 `ScanJobService`；MCP `zscope.scan.run` 要求 `request_id`，可选 `scan_depth`/绝对 `stop_at`，`zscope.scan.status` 使用 `job_id`。list/events/result/cancel/resume 由 `mcp/jobs_adapter.py` 适配同源服务，取消和恢复核对 `base_revision`/`request_id`，事件使用 `after_seq`。边界在定位 store 前拒绝显式 null、类型错误及未知字段，默认 ToolPolicy 未启用 strict_schema 时也保持此行为。read_only/candidate_blind 不创建该服务；result 只提供本轮报告绑定，findings 投影未接入。旧 `/api/scan` 内存状态不具持久作业身份。MCP 只读资源保留，接口不接受任意命令、环境、cwd 或输出路径。")
replace("docs/modules/interfaces-reporting.md","  - zscope/mcp/provider.py\n","  - zscope/mcp/provider.py\n  - zscope/mcp/jobs_adapter.py\n")
replace("docs/modules/interfaces-reporting.md","  - tests/test_mcp_policy.py\n","  - tests/test_mcp_policy.py\n  - tests/test_mcp_jobs.py\n")
replace("docs/architecture.md",
    "以及 `zscope.knowledge.query`、`zscope.entries.discover`、`zscope.scan.run`、`zscope.scan.status`、`zscope.wiki.status`、`zscope.wiki.query` 六个管理工具；不暴露 raw 名称或重复 alias",
    "以及 `zscope.knowledge.query`、`zscope.entries.discover`、`zscope.scan.run`、`zscope.scan.status`、`zscope.wiki.status`、`zscope.wiki.query` 和五个持久作业工具 `zscope.jobs.list/events/result/cancel/resume`；作业工具在 Linux/default profile 复用保存配置对应的 ScanJobService，read_only/candidate_blind 不创建作业服务，不暴露 raw 名称或重复 alias")
replace("docs/modules/execution-orchestration.md",
    "逐实例入口不运行旧全局建模、确定性事实建模或主动发现；图、导航缓存与无成员收据的类型/宏/契约返回显式缺口。",
    "逐实例入口不运行旧全局建模、确定性事实建模或主动发现。当前实例的 native call/reference 收据已供给受限 callee/caller、函数枚举和类型/宏/全局引用，查询按当前构建、native USR、文件和位置消歧，发布与复用前复核依赖；真实头文件变化撤回旧缓存。完整定义、其他图查询、导航缓存与无成员收据的契约仍为显式缺口。")
replace("docs/modules/retrieval-backends.md","  - tests/test_instance_analysis.py\n","  - tests/test_instance_analysis.py\n  - tests/test_full_symbol_build_scope.py\n  - tests/test_instance_symbol_native.py\n")
p=ROOT/"docs/modules/retrieval-backends.md"
p.write_text(p.read_text(encoding="utf-8")+"""
## 2026-10-15 受限逐实例符号消费者

`CodeIndex.get_compilation_facts` 按精确 BuildContext 读取 native 成员收据；`ScopedCodeIndex` 逐次核对当前构建依赖和完整 native 入口身份，再解析 callee/caller 的唯一 USR、文件与位置。缺少 owner 文件、导航别名不符、歧义重载、外来 callee_file 或不完整事实均返回空与缺口。真实头文件变化会撤回已有调用、宏和类型缓存。默认索引的其他导航 API 不因此获得逐实例证明权限。

当前只提供已有收据能核验的引用；类型完整定义、复杂图/链接与 native callee USR 到契约匹配的共享调用链尚未闭合。已供给消费者仍保留保守 blocked 标签，并另记 served_consumers；这些标签不等于完整迁移或全扫描覆盖。ScanSession 仍未调用逐实例入口。真实 native C/C++ fixture 与受控模型回归不能代替真实项目效果验收。
""",encoding="utf-8",newline="\n")
receipts={name:json.loads((ROOT/"artifacts"/label/"review.json").read_text(encoding="utf-8")) for name,label in (
    ("S01","coordinator-s01-symbol-r11-acceptance-20261015"),("MCP","coordinator-mcp-r11-acceptance-20261015"))}
assert all(row["independent_acceptance_passed"] for row in receipts.values())
status=ROOT/"docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/21_IMPLEMENTATION_STATUS.md"
status.write_text(status.read_text(encoding="utf-8")+f"""
## 2026-10-15 · R11 受限符号消费、MCP 持久作业与 UX 修复

S01 `task_0afb819799` 的受限符号消费者与 MCP `task_feb229984d` 已经协调者独立验收，分别 {receipts['S01']['junit']['tests']} 与 {receipts['MCP']['junit']['tests']} 项通过、零跳过，源码冻结后按所有权导入；Astra UX r10 独立88项通过，3文件于01:29:51导入。各集合不相加。最终合并字节的联合结果独立记录在 `artifacts/coordinator-r11-all-intaken-20261015`，本段不代替该收据。

S01 首交付五项身份/失效反例失败、MCP 首交付四项 null 边界及一项 mypy 失败均保留；修复后重新独立验收。工具描述断言在派发基线及首交付完整36项文件中同样失败，协调者同步当前搜索契约并加强默认符号结果无正文检查，完整文件进入联合集合。Astra 修复首次可编辑业务前提仍被原生 fieldset 禁用的问题，真实 HTTP/SQLite 回答、撤回、第二客户端409、断网草稿和重连验证保留。

这些是明确边界的交付：完整 ScanSession/队列/checkpoint/公平剩余工作、契约 USR 传递及更广图/链接仍待接入。共享验证直接调用 ValidationRunner.run，单补 Analyzer 构造参数不足以绑定契约上下文。MCP result 尚无 findings 投影；受控 scanner/report/assumption 数据不代表真实项目扫描效果，formal/portable 与 S10/Q 条件扩展单列。未恢复旧 S06-R02、未提交或推送。
""",encoding="utf-8",newline="\n")
print(json.dumps({"at":dt.datetime.now(dt.timezone.utc).isoformat(),"docs_updated":True,"whole_packages_complete":False}))
