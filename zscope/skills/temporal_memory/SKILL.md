---
name: temporal_memory
languages: [c_cpp]
description: Audit UAF, double free, invalid free, and use after close/unmap.
category: temporal_memory_safety
triggers:
  - free/realloc/close/fclose/munmap
  - pointer alias is released on multiple paths
  - object is removed from a container and later reused
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

Track the released object and aliases after the release point. Check for later
dereference, second release, release by both caller and callee, realloc failure
misuse, and stale pointers left in global/list state. A valid finding should name
the release, the later use/release, and the path that connects them.
