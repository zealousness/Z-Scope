---
doc_contract: zscope-module-v1
covers:
  - zscope/reporting
  - zscope/web
  - zscope/mcp
sources:
  - zscope/reporting/assembler.py
  - zscope/reporting/schema.py
  - zscope/reporting/json_io.py
  - zscope/reporting/shared_objects.py
  - zscope/reporting/immutable_evidence.py
  - zscope/reporting/sarif_exporter.py
  - zscope/web/server.py
  - zscope/web/services.py
  - zscope/web/review_reports.py
  - zscope/reporting/issue_markdown.py
  - zscope/mcp/server.py
  - zscope/mcp/provider.py
  - zscope/mcp/http_server.py
  - zscope/mcp/security.py
tests:
  - tests/test_report_assembler.py
  - tests/test_shared_read_cache.py
  - tests/test_report_schema_v2.py
  - tests/test_sarif_exporter.py
  - tests/test_web_dashboard_server.py
  - tests/test_issue_markdown.py
  - tests/test_report_views.py
  - tests/test_mcp_security.py
  - tests/test_mcp_policy.py
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

## 职责与非职责

本子系统负责将分析结果装配成稳定报告 schema、视图、Markdown、JSON 和 SARIF，并通过 Dashboard 与 MCP 提供受控访问。它是内部分析状态与人类、CI 或外部客户端之间的接口边界。

它不负责生成底层候选、运行 Validator 或重新解释后端原始输出。

## 主入口和数据流

- `ReportAssembler` 接收已验证/待复核 finding、元数据和去重结果，构建默认与 `with_needs_review` 视图并持久化。
- Review 实验报告保留检查范围、编译事实身份、检查器结果与证明、复核封套、checkpoint 引用、父子候选关系和条件构建触发条件。`rejection_refuted_unconfirmed` 仅作为人工优先级信号；条件风险计入 review，不能由当前构建的安全结论覆盖。旧报告缺少这些字段时不获得新拒绝权限。
- 批量 Markdown 报告必须从与 JSON 相同的扫描级最终投影渲染；入口级结果仅作中间 provenance，不能覆盖共享 Validator 队列完成后的 confirmed/needs_review 终态。单入口 `ScanSessionResult` 同时返回 JSON 与 Markdown 报告路径（带 task id 时使用对应文件名）。
- 报告同时输出 effective scan depth、持久 rollout stage/enrollment/semantic-discovery mode、实际 token usage、按 agent/stage 的 usage、finish reason、补证转换、Security Semantic Map 路径/coverage、主动发现单元/独占发现和未覆盖区域。
- Web `POST /api/scan` 与 MCP `zscope.scan.run` 只接受 `scan_depth` 覆盖并异步启动扫描；状态接口返回 effective depth、实际 token usage 和最终 completeness。MCP 同时提供 `zscope://reports/latest` 与 `zscope://rules/effective` 只读资源。接口不得接受任意命令、环境、cwd 或输出路径。
- Web `GET /api/wiki/status`、`GET /api/wiki/query` 与 MCP `zscope.wiki.status`、`zscope.wiki.query` 复用 `zscope/wiki/control.py`；它们只能读取当前配置锁定的项目 Wiki/source context，不接受 project root、state root、build 或 rollback 参数。
- Wiki status 使用固定 bounded metadata projection，不返回绝对路径、页面正文或内部异常；query 参数在 project discovery 前校验，损坏/过期 Wiki 只触发带 reason 的 direct-source fallback。
- schema 层维护结构化报告兼容性，finding roots/identity 信息用于低噪声投影。
- `issue_aggregation.py` 在 finding-root 投影之后、视图构建之前折叠同位点结果：同缺陷家族 + 同函数 + 同结构化 sink 锚点（行距链式聚类）的 confirmed/needs_review 项合并为一个 primary，CWE 与类别标签取成员并集（`cwes`/`categories`），成员转 `deduplicated_alias` 终态保留审计；run_manifest 记录 `aggregation_count`/`aggregation_alias_count`。
- SARIF exporter 将完成后的报告转换为 SARIF v2.1.0，并保留稳定 fingerprint 和证据位置；`properties.cwe` 为主 CWE，`properties.cwes` 与 tags 携带完整 CWE 集合。
- Web server 负责路由，services 负责配置、报告、反馈和索引状态等业务操作。
- Dashboard 的脚本、样式和许可证位于 `zscope/web/static/vendor/` 并随 wheel 发布，支持无外网加载。更新工具 `scripts/portable/web_assets.py --update` 生成静态 Tailwind CSS 和资源 SHA-256 锁，常规发布只校验已提交资源。
- Web 验证反馈保留 validator 的原始 `validation_reasoning`（Dashboard 中只读展示）；人工反驳 / 复核说明保存于 issue 级 `user_rebuttal`，随报告、snapshot final reports 与 finding_baselines 持久化。rejected 的 suppression reason 优先取 `user_rebuttal`，历史数据回退到 `validation_reasoning`。
- Issue 详情与离线阅读器共用 `static/report_view.js`。结构化证据整章默认折叠，标题可展开/收起，章节导航自动展开目标；旧版 JSON 证据章节同样适用。`reporting/issue_markdown.py` 从完整 finding 生成 `zscope.issue-markdown.v1`，列表压缩不得影响正文；真实源码行号与片段内行号必须区分，IR 记录编号不构成源码位置。
- `reporting/issue_markdown.py` 以确定性字段映射生成结构化证据摘要及折叠附录；原始 JSON 完整保留，重复字段只在展示中合并。候选阶段事实、启发式保护条件扫描和配置的引擎不得升级为验证结论，坐标必须绑定正确的文件与函数范围。展示变更不改变复核基线或导入协议。
- `web/review_reports.py` 提供 `/api/issue_report`、`/api/offline_report`、`/api/import_reviews` 和 `/api/import_reviews/resolve`。导出 ZIP 包含内嵌本地资源的 HTML 与独立 Markdown，默认及含复核视图共享 issue 文件。原始说明作为历史只读内容，本次说明默认为空。
- Markdown 导入只接受本次人工说明和验证状态；空说明在任何持久化前跳过。按报告/issue 身份和验证/证据基线做增量合并；冲突保留线上结果，人工确认时再次检查版本。不得信任导入文件中的其他正文，也不得用整个离线 findings 替换线上报告。旧单 HTML 导入不再支持。
- 离线目录读写需浏览器授权；不支持时选择 Markdown/ZIP 并下载修改包。只保存修改过的文件，保存前比较磁盘内容，失败保留草稿。单 Markdown 上限 16 MiB，导入总正文上限 128 MiB、最多 10000 条；超限报错，不截断复核内容。
- MCP stdio/HTTP server 复用工具与资源 provider；远程 HTTP 额外经过 token、allowlist 和绑定地址校验。
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
- Web 保存反馈必须通过统一 config/review store，不能创建第二套状态语义。
- MCP 工具必须经过 ToolPolicy；远程非 loopback 绑定必须要求认证 token 和客户端 allowlist。
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

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_report_assembler.py tests/test_report_schema_v2.py tests/test_report_views.py
python -m pytest -q tests/test_sarif_exporter.py tests/test_web_dashboard_server.py
python -m pytest -q tests/test_mcp_policy.py tests/test_mcp_http_server.py tests/test_mcp_security.py
python -m pytest -q tests/test_web_wiki_api.py tests/test_wiki_control.py
python -m pytest -q tests/test_issue_markdown.py tests/test_report_views.py
```

## 权威源码和关联文档

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
