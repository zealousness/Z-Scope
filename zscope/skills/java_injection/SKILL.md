---
name: java_injection
languages: [java]
description: Audit Java SQL, command, expression, and template injection paths.
category: java_security
triggers:
  - Statement.execute/executeQuery/executeUpdate with dynamic SQL
  - MyBatis ${} substitution
  - JPA/JPQL string concatenation and Criteria fallbacks
  - Mongo/NoSQL query documents built from text
  - LDAP/JNDI lookup or search filters
  - Runtime.exec or ProcessBuilder
  - expression/template/script evaluation with external input
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

Trace untrusted Java request, message, CLI, file, or database-derived data into
SQL, JPQL/JPA, NoSQL, LDAP/JNDI, process execution, expression evaluation,
template rendering, or scripting sinks. A valid finding needs the source, the
sink, the call path, and why the guard is missing or insufficient.

For SQL, distinguish true parameter binding from string concatenation. `#{}` or
PreparedStatement setters can be mitigating evidence; MyBatis `${}` and dynamic
table/order fields require a strict allowlist.

For command execution, prefer an issue only when user-controlled text can affect
the executable or arguments. Fixed executable plus allowlisted separate
arguments may be safe.

For active audit, inspect reachable service, mapper, repository, and helper
callees even when the controller itself only passes a DTO. Check DTO fields,
headers, path variables, message payloads, and environment/CLI values. Mark
non-candidate findings as `java_llm_active_audit` and include concrete source,
sink, entry path, and guard analysis.
