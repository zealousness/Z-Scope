---
name: shared_state_race
languages: [c_cpp]
description: Audit shared global/static/heap state accessed without synchronization.
category: concurrency
triggers:
  - global/static mutable state
  - thread creation or callback registration
  - reference count or list/map mutation
  - shared memory read/write
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
- 列表分页使用返回的 `page.next_offset`，`search_code` 的 `scope=text/files` 续页保留返回的 `view_id`；`read_code` 源码续取使用 `data.source.next_start_line` 作为 `start_line`，同时省略或更新 `end_line`；不要用完全相同的参数重复调用工具。

Identify the shared object, the concurrent access paths, and the missing or
inconsistent protection. Look for races that corrupt state, lose updates, create
UAF through unsynchronized lifetime changes, or violate reference-count
protocols. Do not report single-threaded state without a plausible concurrent
caller.

Also check protocol races that are not plain read/write pairs: lookup before
insert-lock create-if-absent paths, ignored CAS/compare-exchange slot claims,
mutable global mode used to select callbacks, RCU registration/enqueue handoff,
lost wakeups after queue publication, and callbacks that can destroy their own
context before the caller resumes using it.
