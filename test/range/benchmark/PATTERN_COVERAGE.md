# C Memory and Concurrency Pattern Coverage

Source document: `docs/c_memory_concurrency_patterns.md`.

This matrix records how the `test/range` benchmark maps the pattern catalog to
realistic task-dispatcher code. Version 6 extends `src/lifecycle.c`, a lifecycle
and cache subsystem that exercises the missing patterns through normal project
surfaces: control messages, cache entries, callbacks, async flush workers,
config reload, condition variables, fd events, mmap-backed rule tables,
message-field-driven global-container registration protocols, and composite
scheduler-pipe failures. Version 6 also adds nested child-list cleanup, AVL key
normalization, stale tree-node, and macro-gated lock coverage.

## Memory Patterns

| Pattern family | Covered by | Notes |
| --- | --- | --- |
| Null pointer dereference | RANGE-018 | Missing delimiter in control-message parsing. |
| Out-of-bounds read/write | RANGE-001, RANGE-030 | Parser length trust and fixed stack buffer off-by-one. |
| Integer overflow in allocation/copy size | RANGE-002, RANGE-015, RANGE-017 | Binary payload, network receive, and serialization paths. |
| Signed/unsigned conversion | RANGE-029 | Negative receive result converted to `size_t`. |
| Use-after-free / stale lifetime | RANGE-020, RANGE-022, RANGE-036, RANGE-047 | Cache borrowed pointer, callback context, unmapped rule table, and stale AVL node after failure cleanup. |
| Double free | RANGE-006 | Cleanup path frees the same local allocation twice. |
| Memory/resource leak | RANGE-007, RANGE-013, RANGE-028, RANGE-037, RANGE-038, RANGE-039, RANGE-040, RANGE-045 | Error path leaks, thread-id array leak, `realloc` pointer loss, global-container hook/architecture gaps, unlink-without-release, nested mutex cleanup omission, and child-list leaks. |
| Invalid free | RANGE-032 | Frees an offset into a caller-owned line buffer. |
| Stack escape | RANGE-024 | Detached thread receives a stack `FlushJob`. |
| Stack overflow / uncontrolled stack allocation | RANGE-033 | User-controlled VLA size. |
| Uninitialized read / padding disclosure | RANGE-031 | Partially initialized status struct is sent over the network layer. |
| Type confusion / wrong cleanup type | RANGE-014 | `TaskConfig*` passed to a cleanup routine expecting `SharedResources*`. |
| Alignment / strict-aliasing-sensitive cast | RANGE-034 | Wire bytes cast from `packet + 1` to `uint32_t*`. |
| Format string | RANGE-004 | Global log buffer used as the `printf` format string. |
| Infinite loop / algorithmic DoS | RANGE-042, RANGE-043 | Self-referential list node traps traversal and repeats error logging. |
| Key truncation / lookup-insert mismatch | RANGE-046 | AVL lookup compares full strings while insertion stores only a truncated key. |

## Concurrency Patterns

| Pattern family | Covered by | Notes |
| --- | --- | --- |
| Data race on shared state | RANGE-009, RANGE-016, RANGE-048 | Unsynchronized counter, shutdown flag, and architecture-specific no-op locking. |
| Non-atomic read-modify-write | RANGE-009, RANGE-021 | Counter increment and refcount changes. |
| Check-then-act / TOCTOU | RANGE-011, RANGE-020, RANGE-026, RANGE-035, RANGE-036 | File permission check, borrowed cache value, lazy config, stale fd, and stale mmap pointer. |
| Deadlock / recursive locking | RANGE-005, RANGE-041, RANGE-044 | Registry recursive lock, scheduler/control ABBA lock inversion, and timer callback cascade waiting. |
| Missing unlock on error path | RANGE-025 | Config reload returns while holding `g_config_lock`. |
| Callback while holding lock | RANGE-023 | External callback invoked under lifecycle cache lock. |
| Condition-variable lost wakeup | RANGE-027 | Predicate guarded by `if` instead of a loop. |
| Double-checked locking / unsafe publication | RANGE-019, RANGE-026 | Half-initialized cache entry publication and lazy config read. |
| Thread lifecycle / detached async work | RANGE-013, RANGE-024 | Thread argument ownership and detached worker argument lifetime. |
| Concurrent container modification | RANGE-019, RANGE-020, RANGE-021, RANGE-022 | Cache list mutation, borrowed values, and refcount races. |
| Refcount lifetime errors | RANGE-021 | Refcount updates happen after dropping the container lock. |
| Event and fd reuse lifetime | RANGE-035 | Closed fd remains globally watched. |
| Flag-controlled lifetime | RANGE-016 | Shutdown flag read/write lacks synchronization. |
| Global-container registration lifecycle | RANGE-037, RANGE-038, RANGE-039, RANGE-040, RANGE-045 | Message actions allocate and register sessions/subscriptions into global containers, while cleanup is missing, unreachable, incomplete, or ignores nested child nodes. |
| Tree/list corruption and traversal liveness | RANGE-042, RANGE-043, RANGE-047 | Close leaves a removed pipe node self-linked; route registration leaves a freed node in AVL/duplicate links. |

## Trigger Surfaces

| Trigger surface from the pattern doc | Covered by | Implementation surface |
| --- | --- | --- |
| Public API and init/deinit | RANGE-013, RANGE-014, RANGE-016 | `td_init`, `td_cleanup`, worker startup/shutdown. |
| Message or serialized input | RANGE-001, RANGE-017, RANGE-018, RANGE-029, RANGE-031, RANGE-034, RANGE-037, RANGE-038, RANGE-039 | Task parser, serializer, lifecycle control message, packet/status wire paths, and message action fields that drive registration or release. |
| Callback/function pointer/plugin | RANGE-005, RANGE-022, RANGE-023 | Plugin registry and lifecycle callback storage/firing. |
| Event loop/fd dispatch | RANGE-035 | Watched connection close and later dispatch. |
| Scheduler/pipe dispatch | RANGE-041, RANGE-042, RANGE-043, RANGE-044 | Pipe dispatch, close, and timer callbacks interact through scheduler and control-block locks. |
| Tree/index management | RANGE-046, RANGE-047 | Policy and route AVL-style indexes exercise key normalization mismatch and stale inserted nodes. |
| State machine/cache/singleton | RANGE-019, RANGE-020, RANGE-026, RANGE-037, RANGE-038 | Lifecycle cache, lazy global config, and transport-specific global session registries. |
| Ownership transfer/refcount/container | RANGE-020, RANGE-021, RANGE-022, RANGE-024, RANGE-032, RANGE-037, RANGE-038, RANGE-039, RANGE-040, RANGE-045, RANGE-047 | Borrowed value, refcount, callback context, async job, substring ownership, global-container ownership, nested child ownership, and stale tree ownership. |
| Queue/producer-consumer | RANGE-009, RANGE-016, RANGE-027 | Dispatcher queue and lifecycle pending work condition variable. |
| Reload/error path | RANGE-025, RANGE-028 | Config reload and metrics resize. |
| mmap/shared mapping | RANGE-036 | Rule-table map/unmap and later matching. |
| Signal/start-stop path | RANGE-016 | Signal handler and cleanup both modify shutdown state. |
| Conditional compilation / architecture variant | RANGE-048 | Locking macros compile to real locks on 64-bit builds and no-ops elsewhere. |

## GCR-Leak Variants Added In v4

| Variant | Covered by | Notes |
| --- | --- | --- |
| GCR-A: hook slot exists but release hook is not registered | RANGE-037 | Mesh session ADD registers into `g_control_sessions`; disconnect checks `pfnDropSession`, which remains NULL after init. |
| GCR-B: architecture has no release trigger | RANGE-038 | Customize OPEN creates a globally owned session while customize cleanup has no session removal path. |
| Unregister without release | RANGE-039 | DETACH removes a session from the global list but leaks the allocated node, owner string, and mutex resource. |
| Nested subresource cleanup omission | RANGE-040 | Subscription unregister frees the global-container node but omits `pthread_mutex_destroy` for its embedded mutex. |

## Composite Scheduler/Pipe Failures Added In v5

| Variant | Covered by | Notes |
| --- | --- | --- |
| ABBA lock inversion | RANGE-041 | Dispatch holds `g_pipe_scheduler.sched_lock` then waits for `ctrl_lock`; close holds `ctrl_lock` then waits for scheduler lock. |
| Self-referential list node | RANGE-042 | Close unlinks a pipe and writes `pipe->next = pipe`, creating a cycle for later traversals. |
| Log amplification in liveness failure | RANGE-043 | Dispatch logs every time it sees the poisoned self-linked node, turning the loop into resource exhaustion. |
| Cascade wait through timer callback | RANGE-044 | Timer callback waits for `ctrl_lock` while close can be stuck holding it and waiting for the scheduler lock. |

## Nested Containers And AVL Variants Added In v6

| Variant | Covered by | Notes |
| --- | --- | --- |
| Primary node delete misses secondary list | RANGE-045 | `_lifecycle_delete_os_node` removes and frees `OSNode` but never walks `OSNode.proc_head` to release `ProcNode` children. |
| Full-key lookup vs truncated-key insert | RANGE-046 | `_policy_avl_find_full_key` compares caller full keys against stored keys, while upsert inserts only `POLICY_AVL_KEY_LIMIT` bytes. |
| AVL insert failure leaves stale freed node | RANGE-047 | `_lifecycle_avl_register_route` inserts before later failure cleanup, then frees the node without removing AVL or duplicate-list links. |
| Macro-gated locking | RANGE-048 | `MACRO_GUARDED_LOCK` protects shared state only on selected 64-bit build macros and is a no-op otherwise. |

## Deliberately Not Scored In v3

The catalog also mentions ABA, RCU/epoch reclamation, and explicit atomic memory
ordering bugs. Those are best tested in a dedicated lock-free queue/cache
subsystem. The current `test/range` fixture intentionally avoids adding a tiny
contrived lock-free snippet only to tick those boxes, because that would make
the benchmark less representative of this project. If Z-SCOPE needs a lock-free
specialty benchmark later, add a separate subsystem and ground truth rather than
mixing those patterns into this dispatcher fixture.
