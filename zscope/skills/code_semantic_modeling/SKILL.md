---
name: code_semantic_modeling
languages: [c_cpp, java]
description: Model a C function as a compact reusable semantic snapshot.
category: modeling
triggers:
  - function implementation is first seen
  - callee snapshot is missing or stale
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
allowed_mcp_resources:
  - zscope://snapshots/list
---

## 工具调用纪律

- 已有 `symbol_id` 时直接传给后续工具，不要重新搜索，也不要自行构造或修改 `symbol_id`。
- `partial`、`unsupported`、`unavailable` 不能解释为“没有漏洞”或“没有路径”。
- `may` 数据流路径和未验证 finding 只能作为调查线索，不能当作已证明结论。
- 分页只使用返回的 `page.next_offset`；不要用完全相同的参数重复调用工具。

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
