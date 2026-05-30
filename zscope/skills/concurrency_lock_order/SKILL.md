---
name: concurrency_lock_order
description: Audit lock balance, inconsistent lock order, and deadlocks.
category: concurrency
triggers:
  - pthread_mutex_lock/pthread_rwlock_*lock/mtx_lock/spin_lock
  - multiple locks are acquired in one path
  - goto/return while a lock is held
allowed_tools:
  - get_function_impl
  - get_function_snapshot
  - get_file_snippet
  - get_call_graph
  - get_callers
  - get_type_info
allowed_mcp_tools:
  - zscope.code.get_function_impl
  - zscope.knowledge.query
allowed_mcp_resources:
  - zscope://knowledge/functions
---

Build an ordered list of locks per path. Check that every acquisition is
released on all exits, that nested lock order is consistent across functions,
and that callbacks or callees do not acquire conflicting locks. Include
condition-variable waits only if the associated lock protocol is wrong.

For timer, callback, signal, or exception paths, treat re-entrant helper calls
and async-signal-unsafe locking/logging as lock-order evidence. A self-delete
timer callback or a signal handler that probes a mutex/semaphore can deadlock
even when the direct function body has only one visible lock.
