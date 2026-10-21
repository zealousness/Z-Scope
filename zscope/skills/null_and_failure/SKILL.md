---
name: null_and_failure
languages: [c_cpp]
description: Audit unchecked allocation/API failures and null dereferences.
category: reliability_memory_safety
triggers:
  - malloc/calloc/realloc/external API returns pointer or handle
  - function parameter can be NULL
  - initialization returns error but later fields/handles are used
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

Check whether returned pointers, handles, and initialization status are validated
before use. Include negative error codes, sentinel handles, partially initialized
objects, and cleanup that assumes initialization succeeded. Do not report if a
prior contract or guard proves non-null/non-error.
