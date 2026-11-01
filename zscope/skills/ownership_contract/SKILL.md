---
name: ownership_contract
languages: [c_cpp]
description: Audit caller/callee ownership and API lifetime contract mismatches.
category: api_contract
triggers:
  - function returns pointer/handle
  - function stores caller-provided pointer
  - alloc/free wrappers or paired functions are configured
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

Model who owns each object before and after the call. Check whether callers free
borrowed pointers, leak owned returns, pass stack memory to retained fields, or
free resources that callee already consumed. Use configured paired functions and
external function semantics when available.

Include non-pointer API contracts: encoded/reliable descriptors versus raw file
descriptors, role-specific release arguments, semantic units such as packet
count versus busy-work count, and file/mapping type contracts. If types match
but the representation or unit differs, keep the finding as an ownership/API
contract issue.
