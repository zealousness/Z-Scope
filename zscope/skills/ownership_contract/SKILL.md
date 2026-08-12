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
  - get_function_impl
  - get_function_snapshot
  - get_callers
  - get_call_graph
  - get_type_info
allowed_mcp_tools:
  - zscope.get_function_snapshot
  - zscope.knowledge.query
---

Model who owns each object before and after the call. Check whether callers free
borrowed pointers, leak owned returns, pass stack memory to retained fields, or
free resources that callee already consumed. Use configured paired functions and
external function semantics when available.

Include non-pointer API contracts: encoded/reliable descriptors versus raw file
descriptors, role-specific release arguments, semantic units such as packet
count versus busy-work count, and file/mapping type contracts. If types match
but the representation or unit differs, keep the finding as an ownership/API
contract issue.
