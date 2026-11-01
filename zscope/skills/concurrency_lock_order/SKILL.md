---
name: concurrency_lock_order
languages: [c_cpp]
description: Audit lock balance, inconsistent lock order, and deadlocks.
category: concurrency
triggers:
  - pthread_mutex_lock/pthread_rwlock_*lock/mtx_lock/spin_lock
  - multiple locks are acquired in one path
  - goto/return while a lock is held
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
  - zscope://knowledge/functions
---

## 工具调用纪律

- 已有 `symbol_id` 时直接传给后续工具，不要重新搜索，也不要自行构造或修改 `symbol_id`。
- `partial`、`unsupported`、`unavailable` 不能解释为“没有漏洞”或“没有路径”。
- `may` 数据流路径和未验证 finding 只能作为调查线索，不能当作已证明结论。
- 列表分页使用返回的 `page.next_offset`，`search_code` 的 `scope=text/files` 续页保留返回的 `view_id`；`read_code` 源码续取使用 `data.source.next_start_line` 作为 `start_line`，同时省略或更新 `end_line`；不要用完全相同的参数重复调用工具。

Build an ordered list of locks per path. Check that every acquisition is
released on all exits, that nested lock order is consistent across functions,
and that callbacks or callees do not acquire conflicting locks. Include
condition-variable waits only if the associated lock protocol is wrong.

For timer, callback, signal, or exception paths, treat re-entrant helper calls
and async-signal-unsafe locking/logging as lock-order evidence. A self-delete
timer callback or a signal handler that probes a mutex/semaphore can deadlock
even when the direct function body has only one visible lock.
