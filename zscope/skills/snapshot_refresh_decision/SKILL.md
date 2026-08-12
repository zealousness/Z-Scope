---
name: snapshot_refresh_decision
languages: [c_cpp, java]
description: Decide whether an existing function snapshot must be refreshed after code changes.
category: modeling
triggers:
  - snapshot refresh decision is requested
  - implementation changed and semantic cache validity is uncertain
allowed_tools:
  - get_function_impl
  - get_function_snapshot
  - get_file_snippet
  - get_callers
allowed_mcp_tools:
  - zscope.code.get_function_impl
  - zscope.get_function_snapshot
---
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
