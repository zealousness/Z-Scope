---
doc_contract: zscope-module-v1
covers:
  - zscope/reporting
  - zscope/web
  - zscope/mcp
sources:
  - zscope/reporting/assembler.py
  - zscope/reporting/finding_roots.py
  - zscope/reporting/schema.py
  - zscope/reporting/sarif_exporter.py
  - zscope/cli/explain.py
  - zscope/web/server.py
  - zscope/web/services.py
  - zscope/mcp/server.py
  - zscope/mcp/http_server.py
  - zscope/mcp/security.py
tests:
  - tests/test_report_assembler.py
  - tests/test_report_schema_v2.py
  - tests/test_sarif_exporter.py
  - tests/test_web_dashboard_server.py
  - tests/test_mcp_security.py
  - tests/test_decision_trace.py
---

# 接口与报告

## 职责与非职责

本子系统负责将分析结果装配成稳定报告 schema、视图、Markdown、JSON 和 SARIF，并通过 Dashboard 与 MCP 提供受控访问。它是内部分析状态与人类、CI 或外部客户端之间的接口边界。

它不负责生成底层候选、运行 Validator 或重新解释后端原始输出。

## 主入口和数据流

- `ReportAssembler` 只接收冻结 Candidate Ledger outcomes，经过 Finding-root v2 投影后构建默认与 `with_needs_review` 视图并持久化；entry-local issue list 和历史非 canonical 报告不能作为 live finding 输入。
- 每个 terminal validation cluster 同时生成 `zscope.issue-decision-trace.v1`。报告 finding 只嵌入 trace ref/hash、唯一终态事件、终态权威、原因码和 open clauses；候选、模型结构化输入输出、provider/工具结果与 policy 输入保存在 snapshot 目录的内容寻址 sidecar 中。
- 报告同时输出 effective scan depth、持久 rollout stage/enrollment/semantic-discovery mode、实际 token usage、按 agent/stage 的 usage、finish reason、补证转换、Security Semantic Map 路径/coverage、主动发现单元/独占发现和未覆盖区域。
- Web `POST /api/scan` 与 MCP `zscope.scan.run` 只接受 `scan_depth` 覆盖并异步启动扫描；状态接口返回 effective depth、实际 token usage 和最终 completeness。MCP 同时提供 `zscope://reports/latest` 与 `zscope://rules/effective` 只读资源。接口不得接受任意命令、环境、cwd 或输出路径。
- schema 层维护结构化报告兼容性。`zscope.finding-root.v2` 只在最终视图做非破坏性低噪声投影：同 candidate、同结构化 sink，或同 defect family/file/function/obligation shape/subject/decision region 的 finding 可选择一个 primary；全部 cluster、occurrence、来源和证据仍保存在 terminal records 与 alias 中。
- SARIF exporter 将完成后的报告转换为 SARIF v2.1.0，并保留稳定 fingerprint 和证据位置。
- Web server 负责路由，services 负责配置、报告、反馈和索引状态等业务操作。
- MCP stdio/HTTP server 复用工具与资源 provider；远程 HTTP 额外经过 token、allowlist 和绑定地址校验。
- Web/MCP 扫描请求接受 `scan_depth`，响应回显 effective depth 与 usage 摘要；CLI/YAML/API 最终都走同一严格配置校验。

## 必须保持的不变量

- `report_views.default` 与 `report_views.with_needs_review` 的语义和计数必须一致且可复算。
- `confirmed` 同时属于 default 与 with-needs-review，`needs_review` 只属于后者；rejected、shadow 和 engine failure 仅保留 terminal trace。Finding-root 只做 primary/alias 展示投影，不能删除底层 cluster trace。
- `zscope-explain` 只能读取冻结的 report/manifest/trace/evidence/usage。它在输出前验证事件链、trace 文档 hash、所有内容寻址引用与 usage sidecar；`policy-replay` 不调用模型，`reverify` 只重放该 cluster 的冻结 verifier 输入且在代码 revision 变化时拒绝比较。
- Finding-root 投影不得使用 benchmark truth、规则名、自由文本相似度或 LLM，也不得改变 Candidate Ledger/Validator identity；不能跨 defect family、函数、subject 或 decision region 合并，反证、blocking negative evidence 与事实冲突都会阻断合并。needs-review 只有在 required/missing fact 与阻断契约一致时才能合并。
- live 报告不得注册 report-time semantic-dedup hook 或 LLM cache。历史报告展示只能调用 `zscope.compat.reports` 的只读副本，不得回流 Ledger、Proof 或 promotion。
- 报告 schema 变更必须保持明确版本、向后兼容策略和对应测试。
- SARIF location、rule、level、code flow 和 partial fingerprint 必须来自结构化 finding，不能从展示文本猜测。
- Web 保存反馈必须通过统一 config/review store，不能创建第二套状态语义。
- MCP 工具必须经过 ToolPolicy；远程非 loopback 绑定必须要求认证 token 和客户端 allowlist。
- API 和日志不得泄露 LLM key、Bearer token、敏感源码范围或用户配置秘密。
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
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 用户可见输出、WebUI 和 MCP 命令见 `README.md`。
- 接口与持久化关系见 `docs/architecture.md` 的“对外接口”和“持久化与反馈平面”。
