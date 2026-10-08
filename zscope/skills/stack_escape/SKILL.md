---
name: stack_escape
languages: [c_cpp]
description: Audit escaping stack addresses and asynchronous lifetime bugs.
category: lifetime
triggers:
  - return address of local variable
  - store local address into global or heap object
  - pass local address to pthread_create/CreateThread/callback
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

Determine whether a local variable address outlives the stack frame. Treat
thread starts, callbacks, timers, async IO, and retained global/container fields
as lifetime-extending sinks. A finding needs the local object, the escape sink,
and why the consumer can outlive the creator.
