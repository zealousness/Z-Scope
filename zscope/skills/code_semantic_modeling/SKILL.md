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
  - zscope.code.get_function_impl
  - zscope.get_function_snapshot
allowed_mcp_resources:
  - zscope://snapshots/list
---

Capture the function's contract, side effects, resources, error paths, and
concurrency behavior. Preserve facts needed by downstream audit skills:
ownership transfer, allocation and release balance, lock acquisition and release,
thread creation, IO boundaries, size parameters, nullable parameters, and
security-relevant callees.

Create a detailed semantic snapshot of the provided C function based on the JSON
schema injected by the caller.

Output rules:
- Output a JSON block wrapped in ```json ... ``` that strictly follows the
  injected schema.
- All descriptive fields such as summary, meaning, key_semantics, and role MUST
  be in Chinese.
- If a section is not applicable, keep the required field and use an empty
  array or object.
- Do not omit memory/resource/concurrency/path fields.
- Prefer concrete line numbers, ownership states, lock states, and caller
  obligations over broad summaries.

Special attention:
1. Resource lifecycle: for every resource (memory, fd, lock), state whether it
   is allocated, freed, or transferred to caller.
2. Error paths: describe what happens to acquired resources in every early
   return or error branch.
3. Contracts: document assumptions about input pointers, for example
   "不可为NULL" or "可为NULL，内部已处理".
4. Dispatch coverage: if the function routes by switch/case, message type, or
   function-pointer tables, record the dispatch key, default handling, and
   whether branch-owned buffers/resources are released after each route.
5. Global data structure membership: when a function inserts/removes nodes from
   global hash tables, lists, bitmaps, or registries, record the structure name,
   add/remove operation, lock scope, and all conditions under which the node
   should later be removed.
6. Conditional control parameters: if a boolean/enum/literal parameter selects
   different cleanup or removal paths, record the parameter meaning, each branch
   target, and any role/type field that should map to that parameter.
