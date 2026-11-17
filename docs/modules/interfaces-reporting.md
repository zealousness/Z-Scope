---
doc_contract: zscope-module-v1
covers:
  - zscope/reporting
  - zscope/web
  - zscope/mcp
sources:
  - zscope/web/semantics_service.py
  - zscope/reporting/assembler.py
  - zscope/reporting/artifact_reuse.py
  - zscope/reporting/schema.py
  - zscope/reporting/json_io.py
  - zscope/reporting/shared_objects.py
  - zscope/reporting/immutable_evidence.py
  - zscope/reporting/job_result_projection.py
  - zscope/reporting/sarif_exporter.py
  - zscope/web/server.py
  - zscope/web/services.py
  - zscope/web/projects.py
  - zscope/web/scan_jobs_service.py
  - zscope/orchestration/jobs/schedules.py
  - zscope/web/review_reports.py
  - zscope/reporting/issue_markdown.py
  - zscope/mcp/server.py
  - zscope/mcp/provider.py
  - zscope/mcp/jobs_adapter.py
  - zscope/mcp/http_server.py
  - zscope/mcp/security.py
tests:
  - tests/test_semantics_ui.py
  - tests/test_report_assembler.py
  - tests/test_shared_read_cache.py
  - tests/test_report_schema_v2.py
  - tests/test_sarif_exporter.py
  - tests/test_web_dashboard_server.py
  - tests/test_config_editor_http.py
  - tests/test_web_projects.py
  - tests/test_scan_schedules.py
  - tests/test_project_preparation.py
  - tests/test_issue_markdown.py
  - tests/test_report_views.py
  - tests/test_protocol_assessment.py
  - tests/test_protocol_feedback.py
  - tests/test_protocol_review_ui.py
  - tests/test_mcp_security.py
  - tests/test_mcp_policy.py
  - tests/test_mcp_jobs.py
  - tests/test_job_result_projection.py
  - tests/test_job_result_http_binding.py
  - tests/test_instance_coverage_ui.py
  - tests/test_lightweight_instance_metadata.py
  - tests/test_mcp_read_only.py
  - tests/test_mcp_saved_config_prepare_r37.py
  - tests/test_web_wiki_api.py
---

人工 rejected feedback may additionally create a project-local ReviewRecord
under `.zscope/review-memory`. The API reports this as `review_memory`; failure
to archive it does not roll back saved report feedback. Records retain the
original rebuttal and evidence references and are not Wiki constraints. Review
Memory exports retain the review id, extraction status, PatternMatch audit and
active digest; audit events use a forward hash chain. LLM output cannot add
evidence references or source identity.

# 接口与报告

报告的 `metadata.artifact_reuse` 分开汇总分层摘要和初始结构化裁决的查询、命中、重算原因、本轮模型任务与 Token；分层摘要另列跨构建命中数。单入口和批量 Markdown 显示同一复用摘要。零查询的命中率为 null，历史产物用量不计入本轮，模型任务数不能当作包含重试的物理请求次数。真实扫描用量继续由 `llm_usage` 记录，复用统计不改 Finding 与报告视图的语义。

## 项目原语 Web 接口

一级“项目原语”与概览、扫描、设置中的引导共用 `SemanticsService`。所有 `/api/semantics` 请求沿用 `X-ZScope-Project` 的已选 YAML 身份隔离；Java 不适用。读取包含状态、document、分页 entries/entry、精确 symbols 和登记 evidence；写入包含 declare/primitive、validate/save/draft、review/complete、tasks/cancel 与单向 migrate。保存携带文档版本，条目审阅同时携带 row_version 和 evidence_version；整批正式校验通过才原子写入，冲突返回 409 并保留本地草稿。

源码只从绑定工程的登记条目读取，证据限于工程登记的语义证据目录。历史证据可阅读，失效证据不能确认当前条目。发现任务不生成漏洞报告，也不能借用报告写入权限。原 C/C++ 工作簿执行语义写入返回迁移提示；问题复核和业务回答仍走独立报告绑定链路。

运行 manifest 记录 `validation_policy_version`；缺失或不匹配的历史报告不能直接跳过重扫。Validator 缓存 v10 撤销旧的义务丢失/仅按评分晋升路径，历史文件本身保持可读。这是结果复用身份检查，不增加用户操作步骤。

候选 v3.5 的 `build_context_id` 保留在 Ledger 和报告终态中。普通/语义去重、finding root、exact-sink root 与同站点聚合均按构建隔离：相同源码位置的不同编译实例不得合并成一个主发现，未知实例也不并入已知实例。同一构建内仍合并重复证据。人工误报反馈只影响其构建 baseline；不能通过位置 suppression 绕过构建范围。

## 职责与非职责

本子系统负责将分析结果装配成稳定报告 schema、视图、Markdown、JSON 和 SARIF，并通过 Dashboard 与 MCP 提供受控访问。它是内部分析状态与人类、CI 或外部客户端之间的接口边界。

它不负责生成底层候选、运行 Validator 或重新解释后端原始输出。

## 主入口和数据流

- `ReportAssembler` 接收已验证/待复核 finding、元数据和去重结果，构建默认与 `with_needs_review` 视图并持久化。
- Review 实验报告保留检查范围、编译事实身份、检查器结果与证明、复核封套、checkpoint 引用、父子候选关系和条件构建触发条件。`rejection_refuted_unconfirmed` 仅作为人工优先级信号；条件风险计入 review，不能由当前构建的安全结论覆盖。旧报告缺少这些字段时不获得新拒绝权限。
- 批量 Markdown 报告必须从与 JSON 相同的扫描级最终投影渲染；入口级结果仅作中间 provenance，不能覆盖共享 Validator 队列完成后的 confirmed/needs_review 终态。单入口 `ScanSessionResult` 同时返回 JSON 与 Markdown 报告路径（带 task id 时使用对应文件名）。
- 报告同时输出 effective scan depth、持久 rollout stage/enrollment/semantic-discovery mode、实际 token usage、按 agent/stage 的 usage、finish reason、补证转换、Security Semantic Map 路径/coverage、主动发现单元/独占发现和未覆盖区域。
- C/C++ fast 的 `zscope.fast-static-scan.v1` 同时输出 packaged catalog 版本和 active/neutral/unsupported 完整性、项目 YAML 摘要、primitive/derived/pending/stale 数量、逐 BuildContext 授权/拒绝、pointer/dispatcher 精度、confirmed contract 的规则消费者及未分类系统调用。正常扫描不得在报告生成过程中触发原语 discovery 或修改 YAML。
- 当前 Web `/api/jobs` 与 Linux MCP 作业工具复用 `ScanJobService`；MCP `zscope.scan.run` 要求 `request_id`，可选 `scan_depth`/绝对 `stop_at`，`zscope.scan.status` 使用 `job_id`。list/events/result/cancel/resume 由 `mcp/jobs_adapter.py` 适配同源服务，取消和恢复核对 `base_revision`/`request_id`，事件使用 `after_seq`。创建时保存配置的 `execution.stop_at` 若已过期，两个入口都返回 `stop_window_closed`（400）而不是接受一个开局即停的作业；显式 `stop_at` 请求按原语义处理。边界在定位 store 前拒绝显式 null、类型错误及未知字段，默认 ToolPolicy 未启用 strict_schema 时也保持此行为。read_only/candidate_blind 不创建该服务。MCP result 经 `reporting/job_result_projection.py` 读取本轮不可变报告快照并复用轻量 finding/acceptance 投影；在信封读取前后和快照加载后核对 job/run/input/report 绑定，变动时有限重试或返回 `attempt_changed`，相同字节不代表相同 run。外层 `report_id` 仍为快照字节摘要，内层为复核 scope 身份；仅当完整逻辑报告与保存配置所定位的当前报告相等时共享 scope，否则保持历史快照 scope。无报告、丢失、篡改、损坏或未测 coverage 不伪装为空且完整。旧 `/api/scan` 内存状态不具持久作业身份。MCP 只读资源保留，接口不接受任意命令、环境、cwd 或输出路径。
- Web `GET /api/wiki/status`、`GET /api/wiki/query` 与 MCP `zscope.wiki.status`、`zscope.wiki.query` 复用 `zscope/wiki/control.py`；它们只能读取当前配置锁定的项目 Wiki/source context，不接受 project root、state root、build 或 rollback 参数。
- Wiki status 使用固定 bounded metadata projection，不返回绝对路径、页面正文或内部异常；query 参数在 project discovery 前校验，损坏/过期 Wiki 只触发带 reason 的 direct-source fallback。
- schema 层维护结构化报告兼容性，finding roots/identity 信息用于低噪声投影。
- `issue_aggregation.py` 在 finding-root 投影之后、视图构建之前折叠同位点结果：同缺陷家族 + 同函数 + 同结构化 sink 锚点（行距链式聚类）的 confirmed/needs_review 项合并为一个 primary，CWE 与类别标签取成员并集（`cwes`/`categories`），成员转 `deduplicated_alias` 终态保留审计；run_manifest 记录 `aggregation_count`/`aggregation_alias_count`。
- SARIF exporter 将完成后的报告转换为 SARIF v2.1.0，并保留稳定 fingerprint 和证据位置；`properties.cwe` 为主 CWE，`properties.cwes` 与 tags 携带完整 CWE 集合。
- 内部 `orchestration.external_findings.ExternalFindingsImporter` 提供离线 `parse(bytes, format=...)` / `register(batch, registrar)`，支持严格 `zscope.external-findings.v1` JSON 和受限 inline SARIF 2.1.0；SARIF 的 `run.properties.zscope` 必须明确 context 与含源码 SHA 的 coverage。它不解析外部 URI、不启动扫描器、不连接供应商或修改 Web/MCP 接口。具体 schema、预算及调用示例见该模块与测试；外部结果只进入未确认候选，真实供应商接入和独立对照需要另外验收。
- Web server 负责路由，services 负责配置、报告、反馈和索引状态等业务操作。
- 项目配置页通过 `GET /api/scan/prepare` 展示已保存配置的只读准备结果，与 `zscope-config prepare --json` 复用相同模型。编辑或重新载入配置会丢弃旧检查及迟到响应；缺失/损坏编译数据库给出处理提示，不把工具存在性当作运行验收。具体职责见[配置、语义与状态](configuration-state.md)。
- `GET/POST /api/config/structured` 保持原始文档与版本/语言投影合同；ConfigService 复用 `config/editor.py` 的正式 parser 和原子保存。v3 多目标可完整读取、保存、准备，执行仍禁启；未知键、错误语言字段或空 targets 不能覆盖已保存文件。当前配置保存未提供 revision/CAS，不能把前端 409 恢复处理当成服务端已有冲突检测。
- Dashboard 的脚本、样式和许可证位于 `zscope/web/static/vendor/` 并随 wheel 发布，支持无外网加载。更新工具 `scripts/portable/web_assets.py --update` 生成静态 Tailwind CSS 和资源 SHA-256 锁，常规发布只校验已提交资源。
- Web 验证反馈保留 validator 的原始 `validation_reasoning`（Dashboard 中只读展示）；人工反驳 / 复核说明保存于 issue 级 `user_rebuttal`，随报告、snapshot final reports 与 finding_baselines 持久化。rejected 的 suppression reason 优先取 `user_rebuttal`，历史数据回退到 `validation_reasoning`。
- Issue 详情与离线阅读器共用 `static/report_view.js`。结构化证据整章默认折叠，标题可展开/收起，章节导航自动展开目标；旧版 JSON 证据章节同样适用。`reporting/issue_markdown.py` 从完整 finding 生成 `zscope.issue-markdown.v1`，列表压缩不得影响正文；真实源码行号与片段内行号必须区分，IR 记录编号不构成源码位置。
- `reporting/issue_markdown.py` 以确定性字段映射生成结构化证据摘要及折叠附录；原始 JSON 完整保留，重复字段只在展示中合并。候选阶段事实、启发式保护条件扫描和配置的引擎不得升级为验证结论，坐标必须绑定正确的文件与函数范围。展示变更不改变复核基线或导入协议。
- `web/review_reports.py` 提供 `/api/issue_report`、`/api/offline_report`、`/api/import_reviews` 和 `/api/import_reviews/resolve`。导出 ZIP 包含内嵌本地资源的 HTML 与独立 Markdown，默认及含复核视图共享 issue 文件。原始说明作为历史只读内容，本次说明默认为空。
- Markdown 导入只接受本次人工说明和验证状态；空说明在任何持久化前跳过。按报告/issue 身份和验证/证据基线做增量合并；冲突保留线上结果，人工确认时再次检查版本。不得信任导入文件中的其他正文，也不得用整个离线 findings 替换线上报告。旧单 HTML 导入不再支持。
- 离线目录读写需浏览器授权；不支持时选择 Markdown/ZIP 并下载修改包。只保存修改过的文件，保存前比较磁盘内容，失败保留草稿。单 Markdown 上限 16 MiB，导入总正文上限 128 MiB、最多 10000 条；超限报错，不截断复核内容。
- MCP stdio/HTTP server 复用工具与资源 provider；远程 HTTP 额外经过 token、allowlist 和绑定地址校验。
- MCP `zscope.config.prepare` 工具（空参数对象）与 `zscope://config/preparation` 资源复用正式 `v3_preparation.prepare_saved_config`，返回与 CLI/Web 相同的已保存配置准备投影，包括 v3 字段 wiring 与 start capability。provider 按正式 loader 的顺序先展开用户主目录，再固定绝对配置路径；每次请求重读该路径，default profile 自动创建的懒作业 adapter 也复用同一路径，不在构造时启动 service；不接受客户端另选配置、target 或执行参数。default/read_only 的列举和访问仍与 ToolPolicy 取交集；candidate_blind 不披露或开放该工具、资源。准备不启动索引、模型或扫描，不验证工具运行与模型连通性；MCP 启动仍先组合单 target 配置，已构造 provider 可检查后来保存的多目标文档，但多目标执行仍拒绝。
- MCP 启动 profile 为 default/read_only/candidate_blind，与 ToolPolicy 在列举和执行两端取交集。只读工厂跳过后端、迁移、项目语义写入和扫描服务；盲调查额外拒绝 findings、报告、任意 SQL 和结论资源。stdio 支持换行 JSON 和旧 Content-Length，协议输出与 stderr 日志隔离；只读请求按序有界调度并接入请求级协作取消。接入示例与缓存限制见 [只读 MCP](../mcp-read-only.md)。
- MCP `zscope.knowledge.query` 按页返回：`offset` 起始、`has_more` 标记是否还有剩余行；工具结果超过 `max_result_chars` 硬上限时保留头部 preview 和截断元数据，而不是整体替换为空桩。
- Web/MCP 扫描请求接受 `scan_depth`，响应回显 effective depth 与 usage 摘要；CLI/YAML/API 最终都走同一严格配置校验。

## 必须保持的不变量

- `report_views.default` 与 `report_views.with_needs_review` 的语义和计数必须一致且可复算。
- 报告 schema 变更必须保持明确版本、向后兼容策略和对应测试。
- 默认 JSON 使用自包含的 `zscope.shared-json.v1` 存储封套：根对象与按内容摘要寻址的对象表保留完整逻辑数据和顺序。`reporting/json_io.py` 统一读取新旧格式；消费者不得直接对报告使用 `json.load`。对象校验拒绝缺失引用、摘要错误和环。共享对象按访问懒加载，修改隔离；从磁盘读取不会恢复进程内证明权限。
- 共享视图的只读缓存不代表内容变化；嵌套写入使自身及祖先失效，未修改的投影仍复用内容引用。dataclass 输出保留共享视图的独立副本，不通过字典子类构造或展开全部证据完成转换。
- 契约、决策事实切片和证明的 JSON 输出使用数组，内部不可变 tuple 保持不变；证据池继续保留真正非 JSON 内部值的类型。不能因这些标准输出携带 tuple 而使整份候选回退为深拷贝。
- 报告组装与最终注释完成后只发布一次，原子替换并同步文件和目录；序列化失败保留旧报告。旁路 `*.timings.json` 记录对象表、序列化和落盘耗时，不为补计时重写报告。`zscope-report export --input report.json --output report.legacy.json --format legacy-json` 完整展开旧格式。
- 检查点使用 `zscope.review-checkpoint.v2`：候选状态、运行参数与完整证据通过内容引用保存，`evidence/objects.sqlite3` 事务提交对象后再发布引用。历史 v1 仍可读取，历史产物不原地迁移。备份检查点需保留整个 evidence 目录。
- SARIF location、rule、level、code flow 和 partial fingerprint 必须来自结构化 finding，不能从展示文本猜测。
  导出优先使用显式文件与行号，正确解析带 Windows 盘符或可选列号的历史 location；文件 URI 对空格、`#`、`%`、`?` 等字符编码，避免变成 URI 片段或查询参数。
- Web 保存反馈必须通过统一 config/review store，不能创建第二套状态语义。
- MCP 工具必须经过 ToolPolicy；远程非 loopback 绑定必须要求认证 token 和客户端 allowlist。
  HTTP MCP 空批次返回 JSON-RPC invalid request，不能按无响应通知接受。Dashboard POST/DELETE 在进入业务服务前拒绝非法或负数 Content-Length、损坏 JSON/编码及非对象 JSON。
- API 和日志不得泄露 LLM key、Bearer token、敏感源码范围或用户配置秘密。
- Dashboard 不能依赖外部 CDN、在线字体或运行时安装前端工具；新增 Tailwind 类后同步生成的 CSS。
- Wiki 控制面必须保持只读；query 的 subject 数量、候选相对路径、文档扫描上限和 context token 上限必须在进入 source index 前校验。
- 新 finding 必须显式携带 `zscope.finding-attribution.v1`；`discovered_by` 是可重叠集合，`decided_by` 与 `decision_level` 独立。旧报告可以推断，但必须标记 `attribution_inferred=true`。
- `model_verdict` 与 `policy_disposition` 必须分别保存。没有 proof 的 LLM rejected 仍属于可报告待复核项，不能被接口层过滤。
- `semantic_shadow` 中仅由 candidate-blind LLM 发现的候选即使模型或 V0 proof 判定成立，也只能闭合为 `shadow_observation`；它保留在 candidate terminal telemetry 中，但不得进入默认或 needs-review 用户视图。与确定性规则/backend 来源合并的同一 obligation 保留正常决策权。
- 预算耗尽只使确实启用且未完成的阶段变为 partial；partial 结果可正常读取和导出，但 CLI/CI 可通过退出码 2 区分。

## 常见变更应落到哪里

- 报告字段、视图和元数据：`zscope/reporting/schema.py`、`assembler.py`、`views.py`。
- 根因投影、同位点聚合或导出：`finding_roots.py`、`issue_aggregation.py`、`sarif_exporter.py`。
- Dashboard 路由与静态资源：`zscope/web/server.py`、`dashboard_server.py`、`static/`。
- Web 业务规则：`zscope/web/services.py`，优先复用 config/reporting 层。
- MCP provider、传输或安全：`zscope/mcp/`，同时验证 stdio 与 HTTP 边界。

## 对象协议验收展示

持久作业 HTTP 接线由 `scan_jobs_service.py` 将保存配置绑定到 orchestration jobs 服务；请求只允许深度、绝对时窗、幂等身份与操作版本，不接客户端 argv/env 或另一配置路径。jobs 后台未交付或当前平台不可用时返回503，不能以旧内存 scan 状态代替。作业结果只读取并核验本轮绑定快照，复用 `ReportFeedbackService.project_report` 的轻量四态/覆盖投影；历史快照与当前报告内容不同就使用独立复核 scope，不静默进入当前问题处置。当前 adapter fixture 测试只验证 HTTP 边界，不替代 detached owner、时窗和续跑的实际进程验收。

Dashboard 轻量 findings 在压缩前从完整证据生成 `acceptance`，区分 `confirmed`、`business_conditional`、`pending`、`ruled_out`。模型分数、人工处置、缺少复现结果不会提升确认程度；无法从报告重新导出当前证明的结果保持 pending。响应级 `coverage` 保留扫描完整性、构建覆盖、未完成数量及有界缺口，未知计数为 null。

独立处置接口 `GET/POST /api/acceptance/dispositions` 支持 duplicate、risk_accept、followup、clear，使用配置层 `AcceptanceFeedbackStore` 的项目内 SQLite；不写验证结论、业务回答、suppression 或 Review Memory。GET/成功 POST 返回数字 `revision` 和服务端 `context_revision`，POST 必须回传 `base_revision` 与 `base_context_revision`。报告、证据、对象或构建变化返回409，首次尚未保存的旧草稿也不能凭数字版本0写入新证据范围。risk_accept 过期和 clear 保留历史，followup 仅记录本地待办。

对象协议候选的 `business_conditional`（业务前提待核实）与 `protocol_pending`（技术证据未闭合）是现有 `needs_review` 的程序投影，不改变确认结果统计。JSON、汇总 Markdown 和 WebUI 共用的单条 Markdown 保留 `protocol_assessment` 的适用范围、来源、未确认前提及技术缺口。问题在验收阶段集中展示，不在夜间扫描中逐条询问。历史报告可显示当时的结果，但重新扫描必须重新取得当前重放收据；单独保存的状态字段没有证明权限。

`GET /api/issue_report` 的 `business_review` 同时返回最新回答与版本。`POST /api/business_review` 只接受当前报告/问题/上下文版本及回答 ID、yes/no/unknown、来源说明、预期回答版本；适用范围由服务端报告取得，不能从客户端覆盖。同一问题的多条回答事务提交，冲突返回 409；保存不会调用原通用 finding feedback，也不直接改写历史报告。前端保留切换问题时的草稿和失败提交，拒绝失效证据草稿提交，迟到的读取/保存响应不能覆盖当前问题。页面明确提示下次扫描重验；普通离线复核导入仍不写业务回答。确认结果的 Markdown 保留用户声明与来源，避免丢失成立条件。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_report_assembler.py tests/test_report_schema_v2.py tests/test_report_views.py
python -m pytest -q tests/test_sarif_exporter.py tests/test_web_dashboard_server.py
python -m pytest -q tests/test_mcp_policy.py tests/test_mcp_http_server.py tests/test_mcp_security.py
python -m pytest -q tests/test_web_wiki_api.py tests/test_wiki_control.py
python -m pytest -q tests/test_issue_markdown.py tests/test_report_views.py
```

## 权威源码和关联文档

单入口与批量 JSON 的 `metadata.build_coverage` 区分编译实例提取完整性和扫描覆盖。单入口分析运行在按实例固定的 `ScopedCodeIndex` 上，因此覆盖统计通过 `coverage_index()` 读取未包裹索引：`view="instance"`、`pinned_build_context_id` 标明这是该入口源码的实例视图，实例枚举本身仍只返回固定上下文。多变体仍经过旧导航消费者、失败实例或没有链接归属时列出对应原因；`extraction_complete=true` 不能解释为 `scan_complete=true`，也不代表没有缺陷，`view="instance"` 在验收投影中永不提升为扫描覆盖。批量报告在合并后从同一未包裹索引重算，入口级视图不能覆盖扫描级计数。每个被计数实例另按当前输入复核：`instance_input_status` 给出逐 build 的 `current`/`stale_*`/`unmeasured`（无收据即为 unmeasured），陈旧实例进入 `uncurrent_instances` 并追加 `stale_compilation_instance_inputs`，因此“已索引”不再等于“输入仍当前”；验收投影按同样上限携带这两个字段，不因缺失而回退为已核验。

- 稳定入口见本文 frontmatter 的 `sources`。
- 用户可见输出、WebUI 和 MCP 命令见 `README.md`。
- Markdown 契约、离线复核操作及接口示例见 [离线复核](../offline-reviews.md)。
- 接口与持久化关系见 `docs/architecture.md` 的“对外接口”和“持久化与反馈平面”。

完整事实的函数索引可在同一不可变对象版本间复用。索引只保存编码后的引用，每次返回独立可修改视图；局部修改过的 AST 重新遍历，事实或依赖变化不能复用旧版本。该优化不恢复证明权限，也不删去任何证据。

检查点编码可直接复用本对象库已经原子提交的不可变证据引用，避免再次遍历整份 facts。跨对象库、数据库替换或视图修改时仍完整编码所需内容；自包含报告继续携带全部依赖对象，读取时校验摘要及缺失引用。

Ledger 接收终态时将 JSON 证据保存到会话内的不可变对象池。原始 ticket 与最终 outcome 都在此时转入同一个池，避免 ticket 继续持有独立检查点读取器的完整对象表；全部可达证据仍保留，pending 期间的更新行为不变。后续生命周期快照及报告投影拥有独立修改视图，复用未修改的证据内容；外部调用者继续修改原输入不会改变已保存终态。非 JSON 内部值保留原有深拷贝行为，不隐式改变类型。对象池仅属于当前 Ledger，不赋予持久化证明权限。

验证回放包也通过统一共享 JSON 读写层保存，旧回放仍可读取；严格读取继续拒绝重复键、非有限数字和损坏引用，逻辑分组摘要及完整输入不变。独立评分启动前归档器只保留脱离共享解码器的摘要，完整报告与回放证据先落盘，不让父进程持有完整对象图与评分器争用内存。

只读消费者可使用 `read_report(..., immutable=True)`：相同内容对象只解码一次，避免遍历时重新物化每次逻辑出现。共享视图拒绝修改，显式深拷贝返回独立可修改视图；默认读取行为保持兼容。评分器使用这一边界，matcher 本身及完整字段、顺序保持不变。

旧格式导出通过不可变读取视图流式展开完整内容；重复引用复用同一只读容器，导出过程不构造另一份展开后的可修改对象图。

## 2026-10-14 当前持久作业与只读准备切片

Web `GET/POST /api/jobs` 与 detail/events/result/cancel/resume 适配同一 `ScanJobService`：工程侧 SQLite 是状态真源，独立 owner 持有扫描进程，页面或 Web 服务断开不丢 owner。查询核对 PID/启动身份，失联为 lost；启动异常保留真实失败并返回503，版本/运行冲突409。request_id 幂等、取消范围和新 attempt 输入摘要由服务端绑定，不能传任意命令/环境或伪造状态。测试替换的 scanner 明确为受控合成，不能算真实模型扫描。

result 的外层 report_id 是绑定报告原始字节摘要；嵌套 findings 是既有轻量 API 的完整 payload，列表键为 findings，内部 report_id 是集中复核范围，二者分开。正式报告读取器核验 shared-json 对象图，缺引用/摘要冲突拒绝；历史快照不替换当前报告或借当前 scope 写入处置。未知进度分母保留 null，entry_instances 尚未逐实例执行时 coverage 保留缺口。

当前 deadline 由 owner 对扫描进程实施有界终止并标 partial；实例运行已通过 `SessionWorkScheduler` 接入真实剩余队列（作业/run/owner/输入绑定、窗口监视、`pending.json` 持久化），但公平批次口径与“只重跑剩余项”的 resume 语义仍未闭合，不将该路径当完整 JOB04/JOB06。resume 是新 run 的重新尝试，重新核对输入和失效事件，不保证只执行剩余项，也不继承已结束窗口。配置 execution.stop_at 解析展示与显式作业 stop_at 请求分开；创建时配置窗口已过期以 `stop_window_closed` 拒绝。

作业 `pending_count` 是当前 job/input 已测量队列中的 pending/active/deferred 数，业务问题数量独立取 questions。无队列收据时该值为 null；报告含问题不代表测量过剩余工作。owner 从真实队列读取完整 SQL 计数，队列仍有剩余或失败项时不发布 completed。该行为已用受控 scanner 和真实 owner/SQLite 验证，完整扫描接线仍按实际消费逐项验收。

作业界面独立显示已记录业务问题数，剩余未知保持“未测量”。打开作业结果时同时核对 job、run、input_revision、report_id、响应绑定及外层报告字节摘要；相同报告字节不代表相同运行范围。迟到的成功或失败响应还核对当前请求序号。已展示的作业验收结果在所选运行、输入或报告变化时清空并提示重新读取；用户显式加载的当前报告独立于作业选择。页面标题对运行中和终态均保持准确，报告与覆盖结论独立呈现。

Web jobs result 也复用 `project_job_result` 的同轮绑定核对；它保留 Web 已选择的当前报告文件（包括单入口 `report.json`）作为复核 scope，仅在完整逻辑报告相等时共享。MCP 默认从保存配置定位项目当前批量报告；这不是新增客户端可传入的文件路径参数。HTTP/SQLite/owner 与同 hash 真实 resume 的回归使用明确受控报告，不代表真实项目扫描效果、大报告性能或整个 U01/U02 完成。

## 编译实例结果视图

### 首轮 WebUI 导航与呈现（2026-10-23）

Dashboard 默认进入项目概览，以扫描任务、问题工作台、覆盖与诊断、项目设置作为其余一级入口。准备与历史仍复用现有持久作业服务；问题默认读取 `with_needs_review` 并按严重度排列，已排除项可以显式筛选。逐实例与覆盖信息移至诊断页，系统验收、人工复核、业务前提回答与处置保持原有独立语义和保存接口。

`dashboard_navigation.js` 只管理展示、过滤与 hash 定位，不增加 HTTP API 或配置 schema。问题链接绑定报告 scope 与 issue；任务快照链接分别携带 job/run/input、外层 artifact 摘要和内层 report scope，不能混用两种报告身份。恢复时复用原始加载与绑定检查；失效链接阻止展示可编辑的当前结果，需用户显式回到当前报告。当前报告列表刷新只在同 report、issue、BuildContext 范围内保留复核草稿，不向另一构建复制；业务回答和处置继续使用各自版本检查。

结构化配置编辑以载入时的表单为比较基线；未改动的可选字段、环境变量引用及命名模型 profile 保持原值，包括省略的 `semantics_file`。显式编辑语义路径或从 Java 切换到 C/C++ 时才写入相应字段，切换到 Java 时移除 C/C++ 专属字段。

新建扫描统一由模式选择与单个启动按钮发起，显式停止时间同样应用于快速检查。Java、多目标、未保存配置与后台 capabilities 的原门禁保持。重新尝试仍创建新 run，不继承旧截止窗口。未知工作量与覆盖保持未测量，已记录缺口数不宣称完整覆盖。

`dashboard_redesign.css` 提供本地自有样式；新模块进入静态资源摘要锁。桌面问题页采用列表与详情两栏，低于 1100px 切换列表/详情，手机使用抽屉导航。原报告 Markdown、离线导入导出与业务模型能力保留。`docs/webui-redesign/` 的原型、匹配截图、录屏和取舍清单使用显式合成数据，与真实 HTTP/SQLite 的回归证据分开记录。

### 工程选择与时间计划（2026-10-24）

`zscope --web`（保留 `--dashboard` 别名）可以不传配置，先进入最近工程、执行机目录浏览与创建向导。`ProjectLibrary` 的 registry 是执行用户的 `~/.zscope/web/projects.json`，只记录配置路径、工程身份与最近打开时间，不另存模型或密钥。`/api/projects`、`/api/projects/browse` 与打开／创建接口只负责定位、校验和创建 YAML；browse 展示服务器实际运行机器上的目录，不能误称为浏览器本地上传或本机文件授权。创建只接受现有工程目录和工程内相对编译数据库路径，以独占创建写入 YAML，不覆盖旧文件。

选择工程后，业务请求通过 `X-ZScope-Project` 绑定 registry 中的明确工程，响应与写入仍属该工程的配置、反馈与作业服务；不依赖服务器全局“当前工程”切换其他标签页。缺失、未知、失效或符号链接重定向的身份拒绝请求，不能自动借用另一工程。配置密钥不写 registry 或导航链接；配置保存仍使用既有 parser、草稿与空密码保留语义。

公共 v3 都以 YAML 父目录为唯一工程根，配置不再接受独立 `project.root` / `source_root`。v3 preset 与扫描深度统一为 `fast|balanced|deep`，Java 仅 fast；旧预设必须显式迁移。配置中的工程内相对路径可随工程迁移，但绝对编译数据库、链接记录及 native 收据要在目标执行机重建；历史报告可读不代表缓存获得新机器上的当前证据权限。

`GET/POST /api/schedules` 和 `POST /api/schedules/cancel` 增加当前已选 YAML 作用域内的持久时间计划，不接受请求另传配置或执行命令。开始可立即或带时区绝对时间，结束可直到完成或绝对总截止；每日可附 `{timezone,start,end}` 窗口，支持跨午夜。计划状态与 `job_status` 分开；每日计划默认循环，只有后台真实作业完成才终止后续窗口，窗口结束、零问题或未知覆盖不能触发前端“完成”。总截止先到用 expired；关闭网页继续，关闭 WSL／主机或休眠时不能计算，重开原工程可唤起持久计划。

执行仍由 `ScanJobService` 与独立 owner 负责，日历协调器只在有效窗口保留／启动动作；下一窗口同 job 使用新 run、owner token 和未来截止，旧窗口不继承。启动与消费前核对实际输入，外部 rearm 或源码／构建变化阻止自动接管。请求幂等、计划版本、取消竞争和本轮 job/run/input 身份共同约束操作；默认取消同时请求停止仍匹配的当前运行，显式 `stop_running=false` 只撤未来窗口。续作只承诺复用经核对的可恢复状态，不承诺精确仅剩余队列。日历／后台细节见[执行与编排](execution-orchestration.md)。

问题工作台保留首轮已接入能力，本轮仍待用户取舍，没有作为本轮重新设计完成。追加原型 `docs/webui-redesign/followup.html` 与实际产品、历史对照截图分别标注；原型不发 API 或执行扫描。2026-10-24 的真实 native 双宏 fixture 已通过 ScanSession → detached owner → SQLite → HTTP → 桌面／手机链路，证据在 `artifacts/ui-redesign-validation/py313/native-current/`；它不等于全工程扫描、模型效果或正式 benchmark 验收。历史失败记录保留于首轮交付文档，本轮结果见 [FOLLOWUP-VALIDATION](../webui-redesign/FOLLOWUP-VALIDATION.md)。

Dashboard 从当前报告投影中的 `metadata.entry_instances` 展示精确 BuildContext 与 native USR 对应的实例结果；作业结果始终来自同轮绑定快照，不能借当前报告补齐旧任务的数据。轻量投影保留固定的实例与 `metadata.job` 字段，展示元数据不替代外层 job/run/input/report 绑定权限。

计划、调度、已分析与本轮执行、复用分别计量；作业执行计数还须与外层 job/run 相符，缺字段或未知 schema 保持未测量。实例身份范围完整不等于 `scan_coverage_complete`，零候选不授予安全结论。报告验收投影将明确的 `scan_coverage_complete: false` 表示为一般 `entry_instance_coverage_incomplete`；不能从 False 或计数推断具体能力尚未接入。生产者明确提供的 `entry_instance_analysis_unwired` 及其他原始缺口继续保留，缺失覆盖数据保持未知。USR 等精确身份折叠展示，按实例查找不合并同名编译变体。本轮新增浏览器链使用真实双宏 native fixture、ScanSession、owner、SQLite 与 HTTP；它只验证受限 fixture 与界面消费，未验收真实项目、模型效果或完整扫描。
