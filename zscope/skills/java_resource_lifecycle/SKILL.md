---
name: java_resource_lifecycle
languages: [java]
description: Audit Java Closeable/AutoCloseable resource lifecycle and transaction cleanup.
category: java_reliability_security
triggers:
  - FileInputStream/FileOutputStream/Reader/Writer/Socket
  - JDBC Connection/Statement/PreparedStatement/ResultSet
  - channels, streams, zip/archive handles
  - manual close without try-with-resources
  - readAllBytes/readString on unbounded request/file/archive content
  - temporary files/directories and cleanup-sensitive paths
allowed_tools:
  - search_code
  - read_code
  - get_semantic_context
  - query_code_graph
  - trace_data_flow
  - query_static_findings
allowed_mcp_tools:
  - zscope.code.search
  - zscope.code.read
  - zscope.semantic.context
  - zscope.graph.query
  - zscope.flow.trace
  - zscope.findings.query
---

## 工具调用纪律

- 已有 `symbol_id` 时直接传给后续工具，不要重新搜索，也不要自行构造或修改 `symbol_id`。
- `partial`、`unsupported`、`unavailable` 不能解释为“没有漏洞”或“没有路径”。
- `may` 数据流路径和未验证 finding 只能作为调查线索，不能当作已证明结论。
- 分页只使用返回的 `page.next_offset`；不要用完全相同的参数重复调用工具。

Trace each resource acquisition through normal returns, exceptions, early exits,
and ownership transfer. Prefer issues when a resource is neither covered by
try-with-resources nor closed in a finally/error path.

For JDBC and transaction-like APIs, check nested ResultSet/Statement/Connection
ownership and rollback/commit behavior. If a framework clearly owns lifecycle
management, record that as negative evidence rather than reporting a leak.

For active audit, inspect normal returns, exceptions, early returns, and helper
ownership transfer. Also check resource exhaustion from unbounded reads or loops,
temporary files without cleanup or safe permissions, and archive/stream handles.
Framework-managed resources should be treated as negative evidence.

Mark non-candidate findings as `java_llm_active_audit` and keep source/sink or
acquire/release evidence explicit.
