---
name: java_authz
languages: [java]
description: Audit Java authentication, authorization, tenant, and object-level access control checks.
category: java_security
triggers:
  - controller/service methods changing or reading sensitive objects
  - missing @PreAuthorize/Secured/RolesAllowed or equivalent checks
  - userId/accountId/tenantId path or query parameters
  - repository lookups followed by updates/deletes/downloads
  - Servlet Filter, HandlerInterceptor, and Spring Security permitAll rules
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

Check whether the current principal is authenticated and authorized for the
specific object, tenant, role, or operation. A valid finding needs an exposed
entry, a sensitive action or data read, attacker-controlled identity/object key,
and absence of an effective authorization check.

Do not treat naming alone as proof. Positive evidence includes missing or
bypassed annotations, service-layer checks that validate only existence, tenant
filters omitted from repository queries, or object IDs accepted from the caller
without ownership comparison.

For active audit, classify the action as read, state change, admin operation,
tenant-scoped operation, or object download/delete. Check annotations,
filter/interceptor behavior, SecurityFilterChain matchers, role checks, tenant
predicates in repository queries, and ownership comparison after lookup. A
Filter/Interceptor that observes credentials but still unconditionally
continues the chain is an authorization boundary concern.

Non-candidate findings must be marked `java_llm_active_audit` and should stay
review-only unless merged with a proof-carrying local/backend candidate.
