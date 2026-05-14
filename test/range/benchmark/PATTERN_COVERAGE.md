# C Memory and Concurrency Pattern Coverage

Source document: `docs/c_memory_concurrency_patterns.md`.

This matrix records how the `test/range` benchmark maps the pattern catalog to
realistic task-dispatcher code. Version 3 adds `src/lifecycle.c`, a lifecycle
and cache subsystem that exercises the missing patterns through normal project
surfaces: control messages, cache entries, callbacks, async flush workers,
config reload, condition variables, fd events, and mmap-backed rule tables.

## Memory Patterns

| Pattern family | Covered by | Notes |
| --- | --- | --- |
| Null pointer dereference | RANGE-018 | Missing delimiter in control-message parsing. |
| Out-of-bounds read/write | RANGE-001, RANGE-030 | Parser length trust and fixed stack buffer off-by-one. |
| Integer overflow in allocation/copy size | RANGE-002, RANGE-015, RANGE-017 | Binary payload, network receive, and serialization paths. |
| Signed/unsigned conversion | RANGE-029 | Negative receive result converted to `size_t`. |
| Use-after-free / stale lifetime | RANGE-020, RANGE-022, RANGE-036 | Cache borrowed pointer, callback context, and unmapped rule table. |
| Double free | RANGE-006 | Cleanup path frees the same local allocation twice. |
| Memory/resource leak | RANGE-007, RANGE-013, RANGE-028 | Error path leaks, thread-id array leak, and `realloc` pointer loss. |
| Invalid free | RANGE-032 | Frees an offset into a caller-owned line buffer. |
| Stack escape | RANGE-024 | Detached thread receives a stack `FlushJob`. |
| Stack overflow / uncontrolled stack allocation | RANGE-033 | User-controlled VLA size. |
| Uninitialized read / padding disclosure | RANGE-031 | Partially initialized status struct is sent over the network layer. |
| Type confusion / wrong cleanup type | RANGE-014 | `TaskConfig*` passed to a cleanup routine expecting `SharedResources*`. |
| Alignment / strict-aliasing-sensitive cast | RANGE-034 | Wire bytes cast from `packet + 1` to `uint32_t*`. |
| Format string | RANGE-004 | Global log buffer used as the `printf` format string. |

## Concurrency Patterns

| Pattern family | Covered by | Notes |
| --- | --- | --- |
| Data race on shared state | RANGE-009, RANGE-016 | Unsynchronized counter and shutdown flag. |
| Non-atomic read-modify-write | RANGE-009, RANGE-021 | Counter increment and refcount changes. |
| Check-then-act / TOCTOU | RANGE-011, RANGE-020, RANGE-026, RANGE-035, RANGE-036 | File permission check, borrowed cache value, lazy config, stale fd, and stale mmap pointer. |
| Deadlock / recursive locking | RANGE-005 | Registry unregister holds the mutex and calls lookup. |
| Missing unlock on error path | RANGE-025 | Config reload returns while holding `g_config_lock`. |
| Callback while holding lock | RANGE-023 | External callback invoked under lifecycle cache lock. |
| Condition-variable lost wakeup | RANGE-027 | Predicate guarded by `if` instead of a loop. |
| Double-checked locking / unsafe publication | RANGE-019, RANGE-026 | Half-initialized cache entry publication and lazy config read. |
| Thread lifecycle / detached async work | RANGE-013, RANGE-024 | Thread argument ownership and detached worker argument lifetime. |
| Concurrent container modification | RANGE-019, RANGE-020, RANGE-021, RANGE-022 | Cache list mutation, borrowed values, and refcount races. |
| Refcount lifetime errors | RANGE-021 | Refcount updates happen after dropping the container lock. |
| Event and fd reuse lifetime | RANGE-035 | Closed fd remains globally watched. |
| Flag-controlled lifetime | RANGE-016 | Shutdown flag read/write lacks synchronization. |

## Trigger Surfaces

| Trigger surface from the pattern doc | Covered by | Implementation surface |
| --- | --- | --- |
| Public API and init/deinit | RANGE-013, RANGE-014, RANGE-016 | `td_init`, `td_cleanup`, worker startup/shutdown. |
| Message or serialized input | RANGE-001, RANGE-017, RANGE-018, RANGE-029, RANGE-031, RANGE-034 | Task parser, serializer, lifecycle control message, packet/status wire paths. |
| Callback/function pointer/plugin | RANGE-005, RANGE-022, RANGE-023 | Plugin registry and lifecycle callback storage/firing. |
| Event loop/fd dispatch | RANGE-035 | Watched connection close and later dispatch. |
| State machine/cache/singleton | RANGE-019, RANGE-020, RANGE-026 | Lifecycle cache and lazy global config. |
| Ownership transfer/refcount/container | RANGE-020, RANGE-021, RANGE-022, RANGE-024, RANGE-032 | Borrowed value, refcount, callback context, async job, and substring ownership. |
| Queue/producer-consumer | RANGE-009, RANGE-016, RANGE-027 | Dispatcher queue and lifecycle pending work condition variable. |
| Reload/error path | RANGE-025, RANGE-028 | Config reload and metrics resize. |
| mmap/shared mapping | RANGE-036 | Rule-table map/unmap and later matching. |
| Signal/start-stop path | RANGE-016 | Signal handler and cleanup both modify shutdown state. |

## Deliberately Not Scored In v3

The catalog also mentions ABA, RCU/epoch reclamation, and explicit atomic memory
ordering bugs. Those are best tested in a dedicated lock-free queue/cache
subsystem. The current `test/range` fixture intentionally avoids adding a tiny
contrived lock-free snippet only to tick those boxes, because that would make
the benchmark less representative of this project. If Z-SCOPE needs a lock-free
specialty benchmark later, add a separate subsystem and ground truth rather than
mixing those patterns into this dispatcher fixture.
