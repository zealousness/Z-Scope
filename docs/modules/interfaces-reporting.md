---
doc_contract: zscope-module-v1
covers:
  - zscope/reporting
  - zscope/web
  - zscope/mcp
sources:
  - zscope/reporting/assembler.py
  - zscope/reporting/schema.py
  - zscope/reporting/sarif_exporter.py
  - zscope/web/server.py
  - zscope/web/services.py
  - zscope/mcp/server.py
  - zscope/mcp/provider.py
  - zscope/mcp/http_server.py
  - zscope/mcp/security.py
tests:
  - tests/test_report_assembler.py
  - tests/test_report_schema_v2.py
  - tests/test_sarif_exporter.py
  - tests/test_web_dashboard_server.py
  - tests/test_mcp_security.py
  - tests/test_mcp_policy.py
  - tests/test_web_wiki_api.py
---

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
- SARIF exporter 将完成后的报告转换为 SARIF v2.1.0，并保留稳定 fingerprint 和证据位置。
- Web server 负责路由，services 负责配置、报告、反馈和索引状态等业务操作。
- Dashboard 的脚本、样式和许可证位于 `zscope/web/static/vendor/` 并随 wheel 发布，支持无外网加载。更新工具 `scripts/portable/web_assets.py --update` 生成静态 Tailwind CSS 和资源 SHA-256 锁，常规发布只校验已提交资源。
- Web 验证反馈保留 validator 的原始 `validation_reasoning`（Dashboard 中只读展示）；人工反驳 / 复核说明保存于 issue 级 `user_rebuttal`，随报告、snapshot final reports 与 finding_baselines 持久化。rejected 的 suppression reason 优先取 `user_rebuttal`，历史数据回退到 `validation_reasoning`。
- MCP stdio/HTTP server 复用工具与资源 provider；远程 HTTP 额外经过 token、allowlist 和绑定地址校验。
- MCP `query_knowledge` 按页返回：`offset` 起始、`has_more` 标记是否还有剩余行；工具结果超过 `max_result_chars` 硬上限时保留头部 preview 和截断元数据，而不是整体替换为空桩。
- Web/MCP 扫描请求接受 `scan_depth`，响应回显 effective depth 与 usage 摘要；CLI/YAML/API 最终都走同一严格配置校验。

## 必须保持的不变量

- `report_views.default` 与 `report_views.with_needs_review` 的语义和计数必须一致且可复算。
- 报告 schema 变更必须保持明确版本、向后兼容策略和对应测试。
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
- 根因投影或导出：`finding_roots.py`、`sarif_exporter.py`。
- Dashboard 路由与静态资源：`zscope/web/server.py`、`dashboard_server.py`、`static/`。
- Web 业务规则：`zscope/web/services.py`，优先复用 config/reporting 层。
- MCP provider、传输或安全：`zscope/mcp/`，同时验证 stdio 与 HTTP 边界。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_report_assembler.py tests/test_report_schema_v2.py tests/test_report_views.py
python -m pytest -q tests/test_sarif_exporter.py tests/test_web_dashboard_server.py
python -m pytest -q tests/test_mcp_policy.py tests/test_mcp_http_server.py tests/test_mcp_security.py
python -m pytest -q tests/test_web_wiki_api.py tests/test_wiki_control.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 用户可见输出、WebUI 和 MCP 命令见 `README.md`。
- 接口与持久化关系见 `docs/architecture.md` 的“对外接口”和“持久化与反馈平面”。
