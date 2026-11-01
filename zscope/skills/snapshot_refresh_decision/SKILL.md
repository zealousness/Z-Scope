---
name: snapshot_refresh_decision
languages: [c_cpp, java]
description: Decide whether an existing function snapshot must be refreshed after code changes.
category: modeling
triggers:
  - snapshot refresh decision is requested
  - implementation changed and semantic cache validity is uncertain
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
Determine whether the semantic contract or defect-relevant behavior has changed.

Output exactly one JSON block:

```json
{
  "type": "snapshot_refresh_decision",
  "func_name": "cache_get",
  "refresh_needed": true,
  "reason": "memcpy调用新增了size参数检查",
  "what_changed": ["添加了buffer_size边界检查", "修改了错误返回路径"],
  "risk_if_not_refreshed": "high"
}
```

Field rules:
- `refresh_needed`: true or false.
- `risk_if_not_refreshed`: one of `low`, `medium`, `high`.
- `reason` and `what_changed`: 用中文描述，且聚焦行为变化，不写泛化结论。
- If unsure, prefer `refresh_needed: true` and explain uncertainty.
