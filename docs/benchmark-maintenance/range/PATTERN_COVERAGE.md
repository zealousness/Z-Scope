# C Memory and Concurrency Pattern Coverage

Source document: `docs/c_memory_concurrency_patterns.md`.

This matrix records how the `test/range` benchmark maps the pattern catalog to
realistic task-dispatcher code. Version 15 corrects two structured source anchors
without changing the truth count. Version 14 adds a high-priority `ISSUE43-*`
tier for stream-journal, zero-copy, resource-quota, pointer, and lock-cache
runtime models. Version 11 adds a high-priority `ISSUE42-*` tier from GitHub
issue #42 runtime, shared-memory, signal, timer, and callback models. Version 8
adds a high-priority `ISSUE41-*` tier
from GitHub issue #41 distributed C/S messaging and task-creation models.
Version 7 adds a high-priority `REAL-*` tier from GitHub issue #40 real-project
abstract vulnerability models; those entries are weighted above the original
`RANGE-*` findings by the scorer. Version 6
extends `src/lifecycle.c`, a lifecycle
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
| Out-of-bounds read/write | RANGE-001, RANGE-030, ISSUE42-006, ISSUE42-010, ISSUE42-014, ISSUE43-001, ISSUE43-003, ISSUE43-004, ISSUE43-005 | Parser length trust, fixed stack buffer off-by-one, issue #42 lcore/freelist/cache index mismatches, and issue #43 stream segment/digest/footer/prefix bounds defects. |
| Integer overflow in allocation/copy size | RANGE-002, RANGE-015, RANGE-017, ISSUE41-001 | Binary payload, network receive, serialization paths, and issue #41 spec-vs-fixed-label-limit mismatch. |
| Signed/unsigned conversion | RANGE-029 | Negative receive result converted to `size_t`. |
| Heap/object pointer misuse | ISSUE43-002, ISSUE43-006, ISSUE43-008, ISSUE43-009, ISSUE43-010, ISSUE43-011 | Zero-copy heap overflow, advanced-pointer free, unchecked allocation, untrusted pointer dereference, unchecked object offset, and uninitialized cursor use. |
| Use-after-free / stale lifetime | RANGE-020, RANGE-022, RANGE-036, RANGE-047, ISSUE42-005, ISSUE42-029, ISSUE43-012 | Cache borrowed pointer, callback context, unmapped rule table, stale AVL node after failure cleanup, pbuf pool premature destroy, WORK self-destruction, and expired stream snapshot flush. |
| Double free | RANGE-006 | Cleanup path frees the same local allocation twice. |
| Memory/resource leak | RANGE-007, RANGE-013, RANGE-028, RANGE-037, RANGE-038, RANGE-039, RANGE-040, RANGE-045, ISSUE42-002, ISSUE42-009, ISSUE42-022, ISSUE43-015, ISSUE43-018 | Error path leaks, thread-id array leak, `realloc` pointer loss, global-container hook/architecture gaps, unlink-without-release, nested mutex cleanup omission, child-list leaks, TLS/thread-cache leaks, CRCU/TLSCB cleanup gaps, journal fd leaks, and incomplete lock-cache reset. |
| Resource allocation without limits | ISSUE43-007, ISSUE43-013, ISSUE43-014 | Stream batch allocation, replay-window reservation, and per-segment fd opening use external counts without quota or throttling. |
| Invalid free | RANGE-032, ISSUE43-006 | Frees an offset into a caller-owned line buffer or an advanced heap cursor. |
| Stack escape | RANGE-024 | Detached thread receives a stack `FlushJob`. |
| Stack overflow / uncontrolled stack allocation | RANGE-033 | User-controlled VLA size. |
| Uninitialized read / padding disclosure | RANGE-031, ISSUE42-008 | Partially initialized status or arena-info structs are exposed to callers. |
| Type confusion / wrong cleanup type | RANGE-014 | `TaskConfig*` passed to a cleanup routine expecting `SharedResources*`. |
| Alignment / strict-aliasing-sensitive cast | RANGE-034 | Wire bytes cast from `packet + 1` to `uint32_t*`. |
| Format string | RANGE-004 | Global log buffer used as the `printf` format string. |
| Infinite loop / algorithmic DoS | RANGE-042, RANGE-043, ISSUE41-003 | Self-referential list node traps traversal, repeated error logging, and receive retry with no timeout. |
| Key normalization / lookup-insert mismatch | RANGE-046 | AVL lookup and insertion use different route-key representations. |

## Concurrency Patterns

| Pattern family | Covered by | Notes |
| --- | --- | --- |
| Data race on shared state | RANGE-009, RANGE-016, RANGE-048, ISSUE41-007, ISSUE42-004, ISSUE42-009, ISSUE42-016, ISSUE42-017, ISSUE42-021, ISSUE43-016 | Unsynchronized counter, shutdown flag, architecture-specific no-op locking, task-array expansion, issue #42 reader PID, CRCU, QRCU, PCM, shared-memory creation races, and issue #43 stream watermark updates. |
| Non-atomic read-modify-write | RANGE-009, RANGE-021 | Counter increment and refcount changes. |
| Check-then-act / TOCTOU | RANGE-011, RANGE-020, RANGE-026, RANGE-035, RANGE-036, ISSUE42-013, ISSUE42-023, ISSUE42-026 | File permission check, borrowed cache value, lazy config, stale fd, stale mmap pointer, FixPool registration, shared-memory path attach, and ftok-style key generation. |
| Deadlock / recursive locking | RANGE-005, RANGE-041, RANGE-044, ISSUE42-027, ISSUE42-028 | Registry recursive lock, scheduler/control ABBA lock inversion, timer callback cascade waiting, wheel-timer self-delete, and signal/semaphore re-entry. |
| Missing or invalid unlock on error path | RANGE-025, ISSUE43-017 | Config reload returns while holding `g_config_lock`; lock-cache abort can unlock a mutex it does not own. |
| Callback while holding lock | RANGE-023 | External callback invoked under lifecycle cache lock. |
| Condition-variable lost wakeup | RANGE-027, ISSUE42-020 | Predicate guarded by `if` instead of a loop, and trigger-mode same-core wake without scheduling. |
| Double-checked locking / unsafe publication | RANGE-019, RANGE-026 | Half-initialized cache entry publication and lazy config read. |
| Thread lifecycle / detached async work | RANGE-013, RANGE-024 | Thread argument ownership and detached worker argument lifetime. |
| Concurrent container modification | RANGE-019, RANGE-020, RANGE-021, RANGE-022 | Cache list mutation, borrowed values, and refcount races. |
| Refcount lifetime errors | RANGE-021, ISSUE41-009 | Refcount updates happen after dropping the container lock, and shared listener cleanup ignores outstanding references. |
| Event and fd reuse lifetime | RANGE-035 | Closed fd remains globally watched. |
| Flag-controlled lifetime | RANGE-016 | Shutdown flag read/write lacks synchronization. |
| Global-container registration lifecycle | RANGE-037, RANGE-038, RANGE-039, RANGE-040, RANGE-045 | Message actions allocate and register sessions/subscriptions into global containers, while cleanup is missing, unreachable, incomplete, or ignores nested child nodes. |
| Tree/list corruption and traversal liveness | RANGE-042, RANGE-043, RANGE-047 | Close leaves a removed pipe node self-linked; route registration leaves a freed node in AVL/duplicate links. |

## Trigger Surfaces

| Trigger surface from the pattern doc | Covered by | Implementation surface |
| --- | --- | --- |
| Public API and init/deinit | RANGE-013, RANGE-014, RANGE-016 | `td_init`, `td_cleanup`, worker startup/shutdown. |
| Message or serialized input | RANGE-001, RANGE-017, RANGE-018, RANGE-029, RANGE-031, RANGE-034, RANGE-037, RANGE-038, RANGE-039, ISSUE41-002, ISSUE41-008, ISSUE43-001, ISSUE43-002, ISSUE43-003, ISSUE43-004, ISSUE43-005, ISSUE43-009, ISSUE43-010, ISSUE43-011 | Task parser, serializer, lifecycle control message, packet/status wire paths, message action fields, and stream-journal wire fields that drive bounds, pointer, and cursor behavior. |
| Callback/function pointer/plugin | RANGE-005, RANGE-022, RANGE-023 | Plugin registry and lifecycle callback storage/firing. |
| Event loop/fd dispatch | RANGE-035 | Watched connection close and later dispatch. |
| Scheduler/pipe dispatch | RANGE-041, RANGE-042, RANGE-043, RANGE-044 | Pipe dispatch, close, and timer callbacks interact through scheduler and control-block locks. |
| Tree/index management | RANGE-046, RANGE-047 | Policy and route AVL-style indexes exercise key normalization mismatch and stale inserted nodes. |
| State machine/cache/singleton | RANGE-019, RANGE-020, RANGE-026, RANGE-037, RANGE-038 | Lifecycle cache, lazy global config, and transport-specific global session registries. |
| Ownership transfer/refcount/container | RANGE-020, RANGE-021, RANGE-022, RANGE-024, RANGE-032, RANGE-037, RANGE-038, RANGE-039, RANGE-040, RANGE-045, RANGE-047 | Borrowed value, refcount, callback context, async job, substring ownership, global-container ownership, nested child ownership, and stale tree ownership. |
| Queue/producer-consumer | RANGE-009, RANGE-016, RANGE-027 | Dispatcher queue and lifecycle pending work condition variable. |
| Reload/error path | RANGE-025, RANGE-028 | Config reload and metrics resize. |
| mmap/shared mapping | RANGE-036, ISSUE42-011, ISSUE42-018, ISSUE42-021, ISSUE42-023 | Rule-table map/unmap, shared-memory file-type handling, named-pipe permissions, concurrent zone creation, and path attach races. |
| Signal/start-stop path | RANGE-016, ISSUE42-019, ISSUE42-028 | Signal handler and cleanup both modify shutdown state; issue #42 adds callstack and exception-reservation signal paths. |
| Stream journal and lock-cache maintenance | ISSUE43-006, ISSUE43-007, ISSUE43-012, ISSUE43-013, ISSUE43-014, ISSUE43-015, ISSUE43-016, ISSUE43-017, ISSUE43-018 | Runtime stream batch and lock-cache APIs exercise cursor ownership, resource quotas, async flush, fd lifecycle, watermark races, invalid unlock, and incomplete cleanup. |
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
| Log amplification in liveness failure | RANGE-043 | Dispatch logs every time it sees the parked self-linked node, turning the loop into resource exhaustion. |
| Cascade wait through timer callback | RANGE-044 | Timer callback waits for `ctrl_lock` while close can be stuck holding it and waiting for the scheduler lock. |

## Nested Containers And AVL Variants Added In v6

| Variant | Covered by | Notes |
| --- | --- | --- |
| Primary node delete misses secondary list | RANGE-045 | `_lifecycle_delete_os_node` removes and frees `OSNode` but never walks `OSNode.proc_head` to release `ProcNode` children. |
| Route-key lookup vs bounded-key insert | RANGE-046 | `_policy_avl_find_route_key` compares caller route keys against stored keys, while upsert inserts only `POLICY_AVL_KEY_LIMIT` bytes. |
| AVL insert failure leaves stale freed node | RANGE-047 | `_lifecycle_avl_register_route` inserts before later failure cleanup, then frees the node without removing AVL or duplicate-list links. |
| Conditional locking | RANGE-048 | `COUNTER_SLOT_LOCK` protects shared state only on selected build macros and is a no-op otherwise. |

## Real Project Issue #40 Tier Added In v7

| Variant family | Covered by | Notes |
| --- | --- | --- |
| Global registry lifecycle and cleanup races | REAL-001, REAL-002, REAL-004, REAL-006, REAL-011, REAL-015, REAL-017, REAL-018 | Issue-derived node/list/tree cleanup cases with unlink-before-free, nested member leaks, rollback gaps, and query-time allocation leaks. |
| Role/path/state-sensitive release mistakes | REAL-007, REAL-021, REAL-022 | Models client/server role-parameter mismatches and system-call failure paths that leave local state changed. |
| Initialization, publication, and memory-order failures | REAL-009, REAL-016, REAL-024, REAL-025, REAL-026, REAL-031 | Covers premature publication, refcount-after-unlock, callback-under-lock, stack async jobs, and macro-gated synchronization. |
| Parser, protocol, and wire-format defects | REAL-010, REAL-013, REAL-014, REAL-019, REAL-020, REAL-028, REAL-029, REAL-030 | Routed through `td_handle_protocol_message` and `_runtime_process_protocol_task`: receive frame, decode header, dispatch by message type, then hit alignment, length miscalculation, missing magic checks, busy receive loops, wrong success returns, signed length casts, stale fd reuse, and key truncation. |
| Error-path resource ownership mistakes | REAL-003, REAL-005, REAL-008, REAL-012, REAL-023, REAL-027 | Covers double cleanup, unregister leaks, log-path leaks, unchecked insert results, missing unlocks, and realloc pointer loss. |

## Distributed C/S Issue #41 Tier Added In v8

| Variant family | Covered by | Notes |
| --- | --- | --- |
| C/S receive and protocol validation | ISSUE41-002, ISSUE41-003, ISSUE41-005, ISSUE41-010 | Routed through `td_handle_distributed_cs_message` and `_peer_process_session_message`: receive a peer frame, trust an unchecked length after magic validation, retry EAGAIN/EINTR without timeout, accept protocol mismatch in non-strict auth mode, and write to closed peers without SIGPIPE mitigation. |
| Task creation and task-index lifecycle | ISSUE41-006, ISSUE41-007, ISSUE41-009 | Task creation and retry paths exercise partial initialization leaks, dynamic global task-array expansion races, and resource cleanup without reference-count checks. |
| Wire compatibility and fd conversion | ISSUE41-004, ISSUE41-008, ISSUE41-011 | Models reliable-fd/raw-fd type confusion, missing cross-version filtering, and raw work-fd values passed to validators expecting encoded fds. |
| Spec-vs-runtime capacity mismatch | ISSUE41-001 | Collection registration and label-cache replacement model a hidden fixed byte cap that is lower than the declared element-count specification. |

## Runtime/Shared-Memory Issue #42 Tier Added In v11

| Variant family | Covered by | Notes |
| --- | --- | --- |
| Shared-memory and process-table lifecycle | ISSUE42-011, ISSUE42-018, ISSUE42-021, ISSUE42-023, ISSUE42-025, ISSUE42-026 | Routed through `td_handle_issue42_shared_memory_message` and `_issue42_process_shared_memory_message`: reserved-file type handling, named-pipe permissions, memzone concurrent create, POSIX shm path attach race, PCM state transition, and ftok-style key creation. |
| Runtime callbacks, event loops, timers, and work items | ISSUE42-001, ISSUE42-020, ISSUE42-027, ISSUE42-029 | Models callback parameter semantic mismatch, flushJob same-core wake gaps, wheel-timer self-delete deadlock, and WORK self-destruction race. |
| Allocator/cache/resource management | ISSUE42-002, ISSUE42-005, ISSUE42-009, ISSUE42-022, ISSUE42-024 | Covers thread-cache leaks, pbuf premature destroy, CRCU pending-batch race/leak, TLSCB preallocation cleanup, and Lfhash allocator/free mismatch. |
| Bounds, formatting, byte order, and output state | ISSUE42-003, ISSUE42-006, ISSUE42-007, ISSUE42-008, ISSUE42-010, ISSUE42-014 | Covers big-endian `ctz`, lcore index OOB, thread-name overflow, uninitialized arena outputs, freelist size mismatch, and FixPool cache-count OOB. |
| Runtime global state and signal safety | ISSUE42-004, ISSUE42-013, ISSUE42-015, ISSUE42-016, ISSUE42-017, ISSUE42-019, ISSUE42-028 | Covers single-field multi-reader state with downstream owner checks, ops registration race, arena traversal logic, QRCU mode race, PCM slot race, callstack signal race, and semaphore work from signal handlers. |

## Stream Journal / Lock-Cache Issue #43 Tier Added In v14

| Variant family | Covered by | Notes |
| --- | --- | --- |
| Stream wire bounds and zero-copy memory | ISSUE43-001, ISSUE43-002, ISSUE43-003, ISSUE43-004, ISSUE43-005 | Routed through `td_runtime_process_stream_batch` and `_runtime_process_stream_batch`: segment count, fragment copy length, digest window, footer backtracking, and prefix compaction all derive from stream metadata. |
| Pointer, cursor, and allocation contracts | ISSUE43-006, ISSUE43-008, ISSUE43-009, ISSUE43-010, ISSUE43-011, ISSUE43-012 | Covers advanced-pointer free, unchecked index allocation, untrusted wire pointer dereference, unchecked object offset, uninitialized cursor, and expired async snapshot use. |
| Resource quotas and fd lifecycle | ISSUE43-007, ISSUE43-013, ISSUE43-014, ISSUE43-015 | Covers batch allocation, replay-window allocation, per-segment descriptor opening, and journal validation without close. |
| Lock-cache state and cleanup | ISSUE43-016, ISSUE43-017, ISSUE43-018 | Routed through `td_runtime_maintain_lock_cache`: global watermark updates lack a common lock, abort can unlock without ownership, and reset leaves replay/scratch/fd state behind. |

## Deliberately Not Scored In v3

The catalog also mentions ABA, RCU/epoch reclamation, and explicit atomic memory
ordering bugs. Those are best tested in a dedicated lock-free queue/cache
subsystem. The current `test/range` fixture intentionally avoids adding a tiny
contrived lock-free snippet only to tick those boxes, because that would make
the benchmark less representative of this project. If Z-SCOPE needs a lock-free
specialty benchmark later, add a separate subsystem and ground truth rather than
mixing those patterns into this dispatcher fixture.
