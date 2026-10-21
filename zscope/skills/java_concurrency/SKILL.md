---
name: java_concurrency
languages: [java]
description: Audit Java shared mutable state, unsafe publication, races, and lock/async hazards.
category: java_concurrency
triggers:
  - static mutable fields and singleton services
  - non-thread-safe collections accessed from controllers/listeners/schedulers
  - CompletableFuture, Executor, Thread, Timer, @Async
  - synchronized/Lock/volatile/Atomic misuse
  - mutable caches, SimpleDateFormat, parser instances, or shared DTO builders
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

Identify shared mutable state that can be accessed concurrently by request
threads, listeners, schedulers, async callbacks, or executor tasks. A valid
finding needs the shared object, at least two plausible concurrent paths or a
framework concurrency contract, and missing or inconsistent synchronization.

Check unsafe publication, double-checked locking without volatile, compound
operations on ConcurrentHashMap or Atomic values, lock ordering, callbacks under
locks, and non-thread-safe date/format/parser/cache objects stored in singletons.

For active audit, use the framework concurrency contract: Spring singleton
controllers/services, servlet filters, listeners, schedulers, and async tasks can
run concurrently. A finding needs shared mutable state plus a plausible
concurrent access path or framework-managed multi-threaded entry. Immutable
constants and request-scoped locals are negative evidence.

Mark non-candidate findings as `java_llm_active_audit`.
