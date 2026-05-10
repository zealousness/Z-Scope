---
name: code_semantic_modeling
description: Model a C function as a compact reusable semantic snapshot.
category: modeling
triggers:
  - function implementation is first seen
  - callee snapshot is missing or stale
allowed_tools:
  - get_function_impl
  - get_function_snapshot
  - get_file_snippet
  - get_callers
  - get_type_info
allowed_mcp_tools:
  - zscope.get_function_impl
  - zscope.get_function_snapshot
allowed_mcp_resources:
  - zscope://snapshots/list
---

Capture the function's contract, side effects, resources, error paths, and
concurrency behavior. Preserve facts needed by downstream audit skills:
ownership transfer, allocation and release balance, lock acquisition and release,
thread creation, IO boundaries, size parameters, nullable parameters, and
security-relevant callees.
