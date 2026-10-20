# 2026-10-14 协调接口 v1

状态：供本轮并行实现使用的内部合同，**尚未声明产品已支持**。现有 public config v2 继续有效，v3/preset 演进单独列入 DAG。Web/CLI 接同一后台服务；新增模块不得自行提升 Validator 结论。Astra 亲自实现所有前端与用户体验。

## 文件所有权

| 所有者 | 可写范围 |
|---|---|
| Astra，`01a13811-2ebb-7301-bc19-03e9ddc7e0f1`，`gpt-6-astra` | `zscope/web/static/**`、`tests/test_agent_workbench_ui.py`、`tests/fixtures/agent_workbench_ui.cjs`；保留原有 dirty 内容 |
| 后端协调/集成 | `zscope/web/server.py`、`services.py`、`review_reports.py`、既有 `reporting/views.py`、`scan_request.py` 及公共配置/入口接线；README、模块说明、21；只有协调者整合这些文件 |
| S08 实现分支 | 新增 `zscope/orchestration/jobs/**`、`tests/test_scan_jobs.py`、`tests/test_scan_job_execution.py`；不得改上述公共文件 |
| U02 投影分支 | 新增 `zscope/reporting/acceptance.py`、`tests/test_acceptance_projection.py` |
| U02 处置分支 | 新增 `zscope/config/acceptance_feedback.py`、`tests/test_acceptance_feedback.py` |
| S09 准备分支 | 新增 `scripts/agent_plan_evaluation.py`、`tests/test_agent_plan_evaluation.py`；不能改正式 benchmark/scorer、Range 或 truth |

`task_0947f2854f` 的 caller-wake 开发已交由用户处置；本轮不派发、续发、重试、修改或代做。其异步路径、native、协议核验、规则和相关共享文档改动需要隔离；所有其他分支不得写这些文件。

## 现有服务

继续使用 `GET /api/scan/prepare`、`GET /api/findings?view=with_needs_review`、`GET /api/issue_report?issue_id=...`、`POST /api/business_review`，保留现有精确范围、回答 revision、409 冲突及草稿保护。旧 scan 接口仅用于现有能力；不能将内存 `_runs` 显示为可重启持久作业。

`/api/findings` 的轻量响应新增 `acceptance` 与 `coverage` 投影，不要求 UI 使用 `full_report=1`。每条实际 finding 增加：

```json
{
  "acceptance": {
    "state": "pending",
    "reason": "current_evidence_incomplete",
    "resource_label": null,
    "build_context_id": null,
    "trigger_summary": null,
    "reproduction": {"status": "not_measured", "summary": null},
    "sources_count": null
  }
}
```

`state`：`confirmed|business_conditional|pending|ruled_out`。覆盖缺口单独呈现，不充当第四种问题裁决。严格依据现有程序 proof、有效 `protocol_assessment`、裁决字段和缺口投影；仅模型 verified/high score 不足以 confirmed，仅 rejected/no reproduction 不足以 ruled_out；未知旧报告保守 pending。投影不是重验或新证明。仅实际存在的当前收据/可信裁决可映射确认，缺乏有效性资料必须带原因。业务 conditional 与技术 pending 分开。UI 不从函数名、颜色、置信度或计数推定状态。

响应级 `coverage`：`{completeness: string|null, build_coverage: object|null, gaps: array, deferred_count: integer|null}`，由 report metadata 和实际未决/工作项生成；未知/未测为 null，不填 0。保持原 `issues`、摘要、报告身份。来源数量按实际不同来源去重，缺失为 null。

## 持久作业接口

统一 schema `zscope.scan-jobs.v1`。路径中 job ID 通过查询或 JSON 传递，服务器仅接受服务器持有的 saved config；不接任意 argv/env、任意 URL 或客户端伪造状态。错误 envelope：`{error: string, code: string, details?: object}`；不存在 404，版本/运行冲突 409，不可用 503，请求错误 400。错误不输出凭据或普通页面 traceback。

| 方法/路径 | 请求 | 响应 envelope |
|---|---|---|
| GET `/api/jobs` | 无；列出当前配置所属工程 | `{schema,jobs:[Job],latest_job_id:string|null,capabilities}` |
| POST `/api/jobs` | `{scan_depth?:fast|balanced|deep, stop_at?:带时区的 ISO8601 绝对时间, request_id:string}` | 202 `{schema,job:Job}` |
| GET `/api/jobs/detail` | `job_id` | `{schema,job:Job}` |
| GET `/api/jobs/events` | `job_id,after_seq` 非负整数 | `{schema,job_id,events:[Event],next_seq,has_more}` |
| GET `/api/jobs/result` | `job_id` | `{schema,job_id,report_id:string|null,report_available:boolean,reason:string|null,findings:object|null,coverage,questions:[Question],artifacts:array}` |
| POST `/api/jobs/cancel` | `{job_id,base_revision:integer,request_id:string}` | `{schema,job:Job}` |
| POST `/api/jobs/resume` | `{job_id,base_revision:integer,request_id:string}` | 202 `{schema,job:Job}`，新 run_id、原 job_id |

`findings` 直接复用轻量 findings payload，含 acceptance/coverage，不是另一个报告真源。无报告时 findings=null，返回具体原因，不拼造空的完整报告。

集成补充（13:20 UTC+8）：Job.report.report_id 与 result.report_id 是持久绑定快照的内容 SHA-256，用于重新核验工件。嵌套 findings.report_id 是既有集中复核的 scope identity，不能与工件摘要混用。只有绑定快照的完整内容仍等于当前报告，才使用当前报告的复核 scope；其他历史快照使用自身路径 scope，UI 保留历史查看并按现有当前报告核对限制进入详情/处置。GET result 重读并核验所解析字节，不把项目当前报告替换成旧作业的结果。

```text
Job:
  job_id, run_id, revision (monotonic integer), input_revision
  status: queued|running|stopping|completed|partial|cancelled|failed|lost
  phase: actual phase string|null
  started_at: ISO8601|null; updated_at: ISO8601
  resolved_stop_time: ISO8601 with offset|null
  owner: {state: alive|exited|lost|unknown, process_id: integer|null}
  progress: {completed: integer|null, total: integer|null, active: integer|null,
             deferred: integer|null, unit: string|null}
  coverage: {completeness,build_coverage,gaps,deferred_count}
  pending_count: integer|null
  questions: [Question]
  report: {available:boolean, report_id:string|null, path:string|null}
  artifacts: [{kind:string,path:string,status:string}]
  capabilities: {cancel:boolean,resume:boolean, reasons:[{code,message}]}
  error: {code,message}|null

Question:
  id, question, affected_scope, current_assumption, impact, answer_revision

Event:
  seq: monotonic integer, job_id, run_id, at: ISO8601,
  kind: string, message: string, data: bounded object
```

List 级 `capabilities={create:boolean, reasons:[{code,message}]}`；cancel/resume 键在每个 job.capabilities，UI 必须据此启用操作。未知分母为 null，不显示百分比；动态发现不预设总数。未测范围不是安全。业务未知进入 questions，其余工作继续。终态仍保存未决与覆盖缺口。

Owner 由独立进程持有，Web 重启/客户端关闭不影响它。进程身份必须核对启动时间/实际 owner token/input revision，PID 相同不足以取消或恢复。输入变更恢复须重新核验并持久记录原因，不能将 JSON 动态 receipt 恢复为确认权限。request_id 在同一工程内幂等，重复请求不另启进程。stop_at 仅为本轮窗口，不创建定时任务；窗口结束停止新工作、有限收尾、partial 和续跑剩余项。不得仅以杀掉 scanner 代替 JOB04 完整验收。

13:50 UTC+8验收缺陷：review-repro/s08-input-cache/review.json 已以稳定代码和合成项目复现同service实例 `_fingerprint(None)` 在config mtime/size不变时忽略源码修改。每次新attempt/start/resume必须重新核对真实源码/构建/工具输入；可缓存只读store定位但不能把仅配置stat缓存当新attempt输入绑定。该缺陷原Kimi修复并补正反例前，S08不能接入根目录或交Astra真实作业验收。不是修改权限、换模型或扩大保留分支范围。

## 集中验收处置

新 schema `zscope.acceptance-dispositions.v1`。独立于业务前提 store、validation verdict、baseline/suppression、Review Memory。处置不改变确认程度，不从 pending 隐藏风险；风险接受只作显式标记。

GET `/api/acceptance/dispositions?report_id=...&issue_id=...`：

```json
{
  "schema": "zscope.acceptance-dispositions.v1",
  "report_id": "...",
  "issue_id": "...",
  "build_context_id": null,
  "context_revision": "opaque-server-scope-digest",
  "revision": 0,
  "disposition": null,
  "writable": true
}
```

POST 同路径请求：

```json
{
  "report_id": "...",
  "issue_id": "...",
  "build_context_id": null,
  "base_revision": 0,
  "base_context_revision": "opaque-server-scope-digest",
  "request_id": "...",
  "type": "risk_accept",
  "reason": "..."
}
```

type：`duplicate|risk_accept|followup|clear`。duplicate 必须补 `duplicate_of`（当前报告中真实、不同且同构建的 issue）；risk_accept 必须有 reason，可补 `expires_at`；followup 必须有 reason，可补 `title`，仅记录本地待办，不擅自建外部任务或修改业务源码。clear 撤回处置但保留历史。服务器从当前 report 绑定真实 issue/object/build，不信任客户端范围。跨构建/未知构建不作通配复用；报告/问题失效，409 并保留客户端草稿。

成功 POST：`{schema,success:true,report_id,issue_id,build_context_id,context_revision,revision,disposition,writable}`。disposition 为 `{type,reason,duplicate_of?:string,title?:string,expires_at?:string,updated_at,request_id}` 或 null。乐观 revision 单调增长；原子保存、幂等重发、冲突与异常不覆盖旧记录。未确认风险接受不成为证据。现有“误报”仍走现有反馈/Review Memory/构建 baseline；现有 business_review 专供业务前提。

2026-10-14 集成审查补充：`context_revision` 是服务端当前 report/issue/build/issue_digest/object_digest 的不透明摘要；POST 必须回传 `base_context_revision`（缺失 400，不匹配 409）。数字 revision 只覆盖同一证据范围的处置记录，不足以识别首次尚未保存的旧草稿。证据/对象改变后不得凭旧 `base_revision=0` 写入新范围；UI 保留草稿并显式要求重新载入。只读存储拒绝 POST，不能只在 GET 标记 writable=false。

## 验证边界

### U01-CONFIG 隔离分支接入边界

16:49 UTC+8 已实现 producer：默认 `GET /api/scan/prepare` 通过 `prepare_saved_config` 支持 v2 原 payload 与 v3 只读扩展；显式服务端 scan_depth override 暂仍走旧组合路径，多 target 在此路径拒绝。v3 返回 `version3.schema=zscope.config-v3-preparation.v1`、project_root、platform、targets[{id,compile_commands,database_exists,build,messages}]、preset{preset,mapped_depth,depth_source,mapping_note}、focus、reproduction、max_workers、execution{timezone,stop_at_local,resolved_stop_time,scheduler_consumer_wired:false}、wiring、declared_not_consumed、machine_flags、start_capability{startable,reasons}。多个 target 顶层 build.status=multi_target，link_targets=unverified，startable=false，不取第一个 target 伪造完整执行。machine_flags 的 focus/reproduction/max_workers/platform/stop_window_scheduler 全部 false；准备不执行模型、native、构建、扫描或 extension provider。UI 默认 start 省略 scan_depth 使用 saved preset，既有 v2 编辑表单不得回写/降级 v3。

持久作业基础已导入，真实 HTTP/SQLite/detached owner 控制样本通过；result.findings 为完整轻量响应，内部列表键是 findings（不是 issues）。resume 是新 attempt 的重新尝试，重核输入、不继承旧 stop_at 窗口；当前未保证只消费 remaining queue。独立队列和协作调度仍未接线，不能把进程级终止冒充 JOB04/06。v3 配置的 execution.stop_at 只解析/展示，不自动成为此作业窗口；用户显式本轮 jobs.stop_at 与配置 intent 消费分开。

该节点仅依赖本契约，已解锁。配置正式模型从12的v3提案实现；ConfigLoader公开调用形状保持 `load(path, scan_depth?, read_only?) -> EffectiveConfig`，共享Web/MCP路由由协调者接入，静态与UI测试仍全部Astra所有。v3的project.root相对配置目录，其余项目路径相对解析后的root；多target必须保留明确身份，未接线时拒绝误将第一target冒充全部。preset最终替换用户档位，临时内部映射必须显式留在ScanIntent/ExecutionProfile，不能把overnight作为shadow实验的别名。时窗只解析本轮绝对停止边界，不建立周期任务。全量CLI/init/MCP/模板迁移和Web/UX联调仍为节点验收范围；首个严格模型/解析切片不算完整U01。

Astra：真实 JS 状态/草稿/迟到响应、键盘/空/错/加载、服务不可用和四态/覆盖呈现；独立 fixture，不冒称后台已交付。后台：真实持久数据库、owner 执行/断开/取消/重启/PID 重用/输入变化/时窗/恢复及四态的保守反例。集成：真实 HTTP envelope 与 CLI 同源、当前 dirty 输入版本、含空格路径和无凭据泄露。所有产品测试、compileall/mypy 在 Linux/WSL。

本轮只读检查：普通沙箱 WSL 调用返回 E_ACCESSDENIED；随后经正式权限升级只读调用成功，Ubuntu `/home/zeal/venv313/bin/python` 3.13.15 可用。不是测试通过证据。native SHA 为 `d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399`，本轮不重建共享工具。
