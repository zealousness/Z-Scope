---
name: ownership_contract
description: Audit caller/callee ownership and API lifetime contract mismatches.
category: api_contract
triggers:
  - function returns pointer/handle
  - function stores caller-provided pointer
  - alloc/free wrappers or paired functions are configured
allowed_tools:
  - get_function_impl
  - get_function_snapshot
  - get_callers
  - get_call_graph
  - get_type_info
allowed_mcp_tools:
  - zscope.get_function_snapshot
  - zscope.query_knowledge
---

Model who owns each object before and after the call. Check whether callers free
borrowed pointers, leak owned returns, pass stack memory to retained fields, or
free resources that callee already consumed. Use configured paired functions and
external function semantics when available.
