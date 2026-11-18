# Z-SCOPE 架构优化计划

> **历史文档，2026-11-17 归档。** 原位置：`docs/progress_docs/architecture_optimization_plan.md`。本文保留早期阶段拆分、身份统一和服务拆分方案及当时实施结果，不再作为当前优化待办。当前职责见[模块导航](../../modules/README.md)，后续工作见[现行实施计划](../../plans/agent-scanning/README.md)。

本文档把当前审阅结论整理为可执行的优化路线，目标是在不牺牲现有 benchmark 能力的前提下，降低主流程复杂度，稳定用户反馈/baseline 语义，并让候选、验证、报告三个阶段可以独立演进。

## 1. 优化目标

- 让 `Analyzer` 从“全能总控”收敛为工作流协调层。
- 统一候选 issue identity，避免 dedup、baseline、SARIF、Web 反馈各自造 key。
- 明确 Web / MCP 的远程暴露边界；MCP 远程能力必须显式开启。
- 把候选生成、验证、历史复核、报告视图拆成独立模块，降低后续加规则和加后端的回归风险。
- 将用户配置、人工 rejected baseline、历史 snapshot 统一成可解释的 review memory。

## 2. 阶段计划

### P0：稳定反馈与发布边界

- `finding_baselines` 同时保存精确 `dedup_key` 与行号无关的 `stable_fingerprint`。
- Analyzer 查询 baseline 时先精确匹配，再按稳定指纹匹配，解决代码插入/删除导致行号变化后 rejected issue 失效的问题。
- Web dashboard 配置读写使用 CLI 传入的同一个 config path，避免 UI 展示或覆盖错误配置文件。
- 发布包包含 `zscope/web/static/*.html`，pytest 只收集 `tests/`。

验收：

- 人工 rejected 的 `src/demo.c:42` 在后续变为 `src/demo.c:57` 时仍能被 `false_positive` baseline 命中。
- `python -m pytest -q` 全绿。

### P1：拆分 Analyzer 主流程

建议目标模块：

- `CandidatePipeline`：统一调用 regex / clang / graph / SVF / Joern，输出 evidence-only candidates。
- `ValidationPipeline`：封装 suppression、baseline、Validator、score、needs_review 降级策略。
- `HistoryReconciler`：处理 snapshot final report、历史 issue 复核、人工 rejected issue 的复用。
- `ReportAssembler`：只负责最终 report、views、SARIF、Markdown。
- `WorkflowRunner`：读取 workflow YAML，编排上述 pipeline。

迁移顺序：

1. 先抽 `ValidationPipeline`，因为 baseline/suppression/validator 逻辑最容易影响误报率。
2. 再抽 `HistoryReconciler`，把 maintain/resume 语义从 Analyzer 中移出。
3. 最后抽 `CandidatePipeline`，统一候选器的输入输出协议。

当前进度：

- 已落地 `zscope/core/validation/pipeline.py`，集中处理人工 suppression、baseline 命中、score 计算、history feedback score，以及 Validator 输出到 `validated` / `needs_review` / `uncertain` / `rejected` 的归类策略。
- 已落地 `zscope/core/validation/runner.py`，承接 Validator LLM 调用、entry-root retry、contract-scope rejection 修正、score/outcome 分流和 review memory 回写；`Analyzer._step_validate_findings()` 已收敛为 runner 调用。
- 已落地 `zscope/orchestration/history_reconciler.py`，集中处理 historical issue 分组，以及复核失败时保留为 `needs_review` 的语义。
- 已落地 `zscope/core/candidates/pipeline.py`，把本地规则、图规则、后端信号的收集、统一合并、候选统计和 IR 持久化从 `Analyzer` 主流程中剥离。
- 已落地 `zscope/reporting/assembler.py`，集中处理最终报告构建、report views、metadata 刷新、JSON/Markdown/snapshot 持久化。
- 已落地 `zscope/orchestration/workflow_runner.py`，把 `Analyzer.run()` 的 state 创建、workflow step 执行、返回报告分流和最终持久化编排迁出主类。
- 已删除未被生产流程调用的旧 auto-accept reasoning 兼容路径；所有候选都必须通过 Validator / ValidationPipeline 分流。
- 已落地 `zscope/core/validation/evidence.py`，把 Validator evidence pack、按漏洞类别追加的校验要求、entry-root dead-code/contract-scope 误拒绝修正规则从 `Analyzer` 中剥离。
- 已落地 `zscope/semantics/inference.py`，把 typedef 扫描、用户配置、历史 snapshot 和函数名启发式合并成本地候选语义的逻辑从 `Analyzer` 中剥离。
- 已落地 `zscope/core/candidates/adapters.py` 与 `zscope/core/candidates/backend_signals.py`，把 clang matcher 归一化、rule candidate 去重、unified evidence merge、Clang KnowledgeDB pair 和 Joern CPG 候选转换从 `Analyzer` 中剥离。
- 已落地 `zscope/snapshots/policy.py`，把 trivial/lightweight snapshot 构造、短函数安全契约点识别和轻量宏/包装器判定从 `Analyzer` 中剥离。
- 已落地 `zscope/orchestration/agent_policy.py`，把 agent contract/prompt 拼接、skill routing、subagent metadata 压缩和 tool policy 组装从 `Analyzer` 中剥离。
- 已完成 `zscope/core` 子包化：`analysis/` 只保留顶层分析协调器，`candidates/` 收拢 regex/clang/graph/SVF/后端信号候选生成，`validation/` 收拢验证流水线和证据构造。
- 已将非核心职责迁出 `core`：规则到 `zscope/rules/`，快照到 `zscope/snapshots/`，报告到 `zscope/reporting/`，告警适配到 `zscope/alerts/`，工具运行时到 `zscope/tools/`，编排到 `zscope/orchestration/`，语义模型到 `zscope/semantics/`，clang tooling evidence 到 `zscope/retrieval/`。
- 已新增 `zscope/semantics/models.py`，把 `LocalPatternSemantics`、API 名称启发式分类和 category/attr 映射从候选器实现中抽出，避免 `Analyzer` 和候选器继续承载语义硬编码。
- 已新增 `zscope/semantics/user_config_context.py`，把 prompt 所需的相关用户配置上下文筛选、scope 匹配和配置列表解析从 `Analyzer` 中迁出。
- 已删除 `Analyzer` 上一批仅做转发的语义/候选兼容入口，测试改为直接验证 `semantics`、`candidates`、`backend_signals` 模块函数。
- Analyzer 仍负责注册 step handler 和调用各阶段运行时对象，但候选收集、候选适配/去重、语义推断、snapshot 策略、agent/tool 策略、历史复核、Validator evidence pack、验证运行循环、验证结果归类、报告组装和顶层 run 编排已从主类中剥离。

### P2：统一 Issue Identity

建立单一 identity API，供以下场景复用：

- report 去重：`dedup_key`
- 用户反馈：`stable_fingerprint`
- SARIF：`partialFingerprints`
- baseline/suppression：精确 key + 稳定指纹
- benchmark：候选与 ground truth 的辅助匹配

建议字段：

- `category`
- `file_path`，不含行号
- `function` / `sink_function`
- `root_cause_token`
- `rule` / `candidate_source`
- `source` / `sink`
- `resource_object`

原则：

- `dedup_key` 可以用于单次报告内合并，但不能作为唯一长期 baseline key。
- `stable_fingerprint` 不包含行号，且字段不足时返回空，避免过宽 suppress。
- baseline 匹配结果应写明 `match_strategy`：`dedup_key`、`stable_fingerprint`、`backfilled_stable_fingerprint`。

当前进度：

- 已落地 `zscope/common/issue_identity.py`，集中提供 `canonical_issue_key`、`stable_issue_fingerprint`、字段归一化和重复合并逻辑。
- `UserConfigStore.get_finding_baseline_for_issue()` 已按 `dedup_key`、`stable_fingerprint`、`backfilled_stable_fingerprint` 分层匹配，并在结果中写回 `match_strategy`。
- 已新增可选 `source_context_fingerprint`，保存 baseline 时从 `code_snippet`、验证 evidence snippet、SVF reported snippet 或 AST/clang matcher span 中提取第三层校验；稳定指纹命中时若双方都有源码上下文且冲突，则拒绝匹配。
- 已新增 `zscope/memory/review_memory.py`，把人工 false-positive suppression、finding baseline 查询和 Validator 记忆写入收敛到轻量门面，`ValidationPipeline` 与 Analyzer 的 Validator 记忆回写已通过该门面访问。

### P3：语义配置源收敛

当前默认 allocator/free/lock/copy sink 等语义散落在 regex、clang、graph、user_config inference 中。建议迁移为：

- 内置 `zscope/semantics/defaults.yaml`
- 用户 workbook / YAML overlay
- `SemanticOverlayCompiler`
- 候选器只消费 compiled overlay

验收：

- 新增一个项目私有 allocator 只需在 overlay 中配置一次。
- regex/clang/graph 识别结果一致。

当前进度：

- 已新增 `zscope/semantics/defaults.yaml`，将内置 allocator/free/copy/lock/unlock 语义放入可打包的数据文件。
- `SemanticOverlayCompiler` 现在会把内置默认语义与用户 workbook/YAML overlay 编译到同一套 overlay 输出中。
- `Analyzer._get_local_pattern_semantics()` 现在先加载内置默认语义，再合并 typedef、用户配置、snapshot 和命名启发式。
- regex / clang AST-CFG / graph 候选器的默认 API 集合已统一改为从 `defaults.yaml` 懒加载；跨候选器通用语义放在 `api_roles`，clang/graph 专用扩展放在 `checker_roles`，显式传入的项目语义只作为 overlay 叠加。
- user config inference 的“跳过内置 API”名单也改为读取同一套默认语义，避免宏/包装器推断与候选器默认模型分叉。
- prompt 相关的用户配置上下文筛选已迁入 `zscope/semantics/user_config_context.py`，后续 Analyzer 只消费筛选后的上下文字符串。

### P4：Web 与 MCP 服务化

拆分 `zscope/web/server.py`：

- `ConfigService`
- `ReportFeedbackService`
- `SourceSnippetService`
- `WorkbookService`
- `DashboardHttpServer`

MCP remote HTTP：

- 远程能力显式开启，不作为普通本地分析流程的隐式默认项。
- 开启时强制显式 host、认证策略和 allowlist。
- `security.py` 的远程配置校验接入 CLI 启动路径。

当前进度：

- `--mcp-http` 仍是显式开启入口；默认 bind host 保持 loopback。
- 非 loopback 绑定时必须同时提供 `--mcp-auth-token-env` 和 `--mcp-client-allowlist`，否则 CLI 启动失败。
- HTTP 传输层支持 Bearer token 校验和客户端 IP allowlist。
- 已新增 `zscope/web/services.py`，拆出 `ConfigService`、`WorkbookService`、`SourceSnippetService`、`ReportFeedbackService`，HTTP handler 保持原 API 但开始委托服务层。
- `UserConfigService` 已接管 dashboard 中 warnings、external functions、paired functions、pointer targets、function intents 的 CRUD 逻辑，HTTP handler 只保留路由和响应状态码处理。
- `CpgService` 已接管 dashboard 中 CPG 状态查询和异步构建触发逻辑，HTTP handler 不再直接依赖 JoernBackend 实现类型。
- `run_server()` 不再维护 `_code_index` / `_project_config` / `_user_config_store` / `_snapshot_store` 这类业务对象全局变量，改为把运行时对象装配进对应 service。
- 已新增 `zscope/web/dashboard_server.py`，把 dashboard HTTP bind、展示 URL 和 `serve_forever` 生命周期从 handler / `run_server()` 中剥离。
- `ReportFeedbackService.save_validation_feedback()` 已接管 `/api/save_findings` 的报告加载、validation 更新、snapshot 更新、feedback 持久化和报告保存。
- `zscope/web/server.py` 已删除 service 委托后的不可达旧实现和大部分兼容 helper，文件体积从 900+ 行降到约 240 行，只保留路由、HTTP 状态码处理和少量兼容入口。

### P5：报告与基准闭环

- SARIF fingerprint 使用同一套 issue identity。
- benchmark 输出记录候选来源、stable fingerprint、baseline 命中情况。
- rejected baseline 不直接删除候选，而是标注 suppression source，便于审计回放。

当前进度：

- SARIF `partialFingerprints` 已新增 `zscopeStableIssueFingerprint`，并优先基于 `stable_issue_fingerprint` 生成。
- SARIF `properties.zscope` 已输出 `stable_fingerprint`、`candidate_source`、`baseline_match_strategy`、`suppression_source`。
- benchmark `issue_identity` 已优先使用同一套 `stable_issue_fingerprint`，并新增可审计的 `issue_identity_records` / `false_positive_issue_records`。
- 预验证阶段命中的人工 suppression / finding baseline 不再静默丢弃，而是作为 rejected audit observation 写入报告 metadata，保留 `rejection_source` 与 `baseline_match_strategy` 供回放审计。
- `ReviewMemory` 已作为 review feedback 门面落地，后续若要把历史 snapshot、用户显式 accepted/rejected 证据和 Validator 记忆组合成更强的解释层，可以在该门面后扩展而不再扩大 Analyzer。

## 3. 人工 rejected 后行号漂移的解决方案

问题：用户在 Web 中把某个 issue 标为 `rejected` 后，系统会把它写入 baseline。旧逻辑主要按 `dedup_key` 精确匹配，而部分 `dedup_key` 包含 `src/file.c:line`。后续代码插入/删除导致行号变化时，同一误报会重新出现。

方案：

1. 保存 baseline 时，除原 `dedup_key` 外，计算 `stable_fingerprint`。
2. `stable_fingerprint` 使用类别、文件、函数/sink、root cause、规则/source、source/sink/resource 等字段，不使用行号。
3. 后续扫描查询 baseline 时：
   - 先按当前 `dedup_key` 精确命中；
   - 未命中则计算当前 issue 的 `stable_fingerprint`；
   - 如果稳定指纹命中旧 rejected baseline，则标记为 `suppressed_baseline`。
4. 老 baseline 若没有 `stable_fingerprint`，查询时从 `issue_json` 回填。

风险控制：

- 字段太少时不生成稳定指纹，避免“同文件同类别”这种过宽匹配。
- 匹配策略记录在 `match_strategy` 中，方便 Web 或日志解释命中原因。
- 已加入源码窗口 hash / AST sink span 作为可选第三层校验；缺失上下文时保持向后兼容，双方都有上下文且冲突时阻止 stable baseline 命中。
