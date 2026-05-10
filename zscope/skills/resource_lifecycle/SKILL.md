---
name: resource_lifecycle
description: Trace acquired resources through normal and error paths.
category: resource_management
triggers:
  - malloc/calloc/realloc/strdup
  - open/fopen/socket/shm_open/mmap
  - lock acquisition or reference-count increment
allowed_tools:
  - get_function_impl
  - get_function_snapshot
  - get_file_snippet
  - get_call_graph
  - get_callers
  - get_type_info
  - verify_taint_reachability
allowed_mcp_tools:
  - zscope.get_function_impl
  - zscope.query_knowledge
allowed_mcp_resources:
  - zscope://knowledge/stats
  - zscope://snapshots/list
---

For each acquire site, enumerate exits. Decide whether the resource is released,
stored with durable ownership, transferred to the caller, or leaked. Include
error labels, early returns, goto cleanup order, partial initialization, and
list/container removal without destruction. Distinguish intentional ownership
transfer from missing release.
