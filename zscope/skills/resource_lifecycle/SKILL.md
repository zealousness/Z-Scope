---
name: resource_lifecycle
languages: [c_cpp]
description: Trace acquired resources through normal and error paths.
category: resource_management
triggers:
  - malloc/calloc/realloc/strdup
  - open/fopen/socket/shm_open/mmap
  - lock acquisition or reference-count increment
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
allowed_mcp_resources:
  - zscope://knowledge/stats
  - zscope://snapshots/list
---

## 工具调用纪律

- 已有 `symbol_id` 时直接传给后续工具，不要重新搜索，也不要自行构造或修改 `symbol_id`。
- `partial`、`unsupported`、`unavailable` 不能解释为“没有漏洞”或“没有路径”。
- `may` 数据流路径和未验证 finding 只能作为调查线索，不能当作已证明结论。
- 分页只使用返回的 `page.next_offset`；不要用完全相同的参数重复调用工具。

For each acquire site, enumerate exits. Decide whether the resource is released,
stored with durable ownership, transferred to the caller, or leaked. Include
error labels, early returns, goto cleanup order, partial initialization, and
list/container removal without destruction. Distinguish intentional ownership
transfer from missing release.
