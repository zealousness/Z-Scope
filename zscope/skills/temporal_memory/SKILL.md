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
  - get_function_impl
  - get_function_snapshot
  - get_file_snippet
  - get_call_graph
  - query_pointer_alias
  - verify_taint_reachability
allowed_mcp_tools:
  - zscope.code.get_function_impl
  - zscope.knowledge.query
---

Track the released object and aliases after the release point. Check for later
dereference, second release, release by both caller and callee, realloc failure
misuse, and stale pointers left in global/list state. A valid finding should name
the release, the later use/release, and the path that connects them.
