---
name: shared_state_race
description: Audit shared global/static/heap state accessed without synchronization.
category: concurrency
triggers:
  - global/static mutable state
  - thread creation or callback registration
  - reference count or list/map mutation
  - shared memory read/write
allowed_tools:
  - get_function_impl
  - get_function_snapshot
  - get_file_snippet
  - get_call_graph
  - get_callers
  - find_function_pointers
  - query_pointer_alias
allowed_mcp_tools:
  - zscope.query_knowledge
  - zscope.get_function_impl
---

Identify the shared object, the concurrent access paths, and the missing or
inconsistent protection. Look for races that corrupt state, lose updates, create
UAF through unsynchronized lifetime changes, or violate reference-count
protocols. Do not report single-threaded state without a plausible concurrent
caller.
