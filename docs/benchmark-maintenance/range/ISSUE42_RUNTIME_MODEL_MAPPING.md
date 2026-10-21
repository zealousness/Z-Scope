# Issue #42 Runtime/Shared-Memory Model Mapping

This file documents how the 28 scored models from
https://github.com/zealousness/Z-Scope/issues/42 are represented in the
`test/range` benchmark. It is benchmark maintenance metadata and should not be
included in Z-SCOPE target prompts.

## Flow

The issue #42 suite is modeled as a runtime subsystem with several natural
project entry shapes instead of a synthetic all-in-one opcode dispatcher:

1. Shared-memory session ingress: `td_runtime_apply_shared_memory_event`
   decodes an fd/wire frame and flows through `_runtime_accept_session_frame`.
2. Worker cache and packet-pool maintenance: `td_runtime_refresh_cache` flows
   through `_runtime_refresh_worker_context`.
3. Shared-memory mapping and key lifecycle: `td_runtime_configure_memory` and
   `td_runtime_shutdown_session` flow through memory/session lifecycle helpers.
4. Pool, RCU, and arena maintenance: `td_runtime_configure_pool` flows through
   `_runtime_apply_pool_plan`.
5. Process-table publication: `td_runtime_publish_process_state` flows through
   `_runtime_publish_process_record`.
6. Event and timer handling: `td_runtime_schedule_event` flows through
   `_runtime_dispatch_event_cycle`.
7. Signal handling: `td_runtime_handle_signal` flows through
   `_runtime_handle_fault_signal`.

`td_run_runtime_maintenance` is only a worker harness that exercises the same
public APIs a background maintenance task would call. The target source does not
contain issue-numbered or defect-named functions.

## Models

| Ground truth | Source model | Function | Main concern |
| --- | --- | --- | --- |
| ISSUE42-001 | VM-001 INIT-SLEEP-BUSYFLAG-MISUSE | `_runtime_init_sleep_window` | Callback parameter semantic mismatch: busy work count used as packet count. |
| ISSUE42-002 | VM-001 TC-Leak | `_runtime_close_thread_cache` | Thread-local cache wrapper is destroyed while cached blocks remain allocated. |
| ISSUE42-003 | VM-002 BE-ByteOrder | `_runtime_find_bitmap_delta` | Big-endian byte offset is derived from little-endian `ctz` semantics. |
| ISSUE42-004 | VM-002 SHARED-RWLOCK-READERPID-RACE | `_runtime_read_lock_owner` | Multiple readers overwrite one diagnostic reader PID field. |
| ISSUE42-005 | VM-003 PBUF pool premature destroy | `_runtime_release_packet_pool` | Shared pool can be freed while tasks still hold references. |
| ISSUE42-006 | VM-004 PMD timer lcore OOB | `_runtime_read_timer_ticks` | Lcore id indexes a fixed per-core table without validation. |
| ISSUE42-007 | VM-005 thread-name overflow | `_runtime_prepare_worker_label` | External thread name can exceed the 16-byte pthread name storage. |
| ISSUE42-008 | VM-006 arena info uninitialized output | `_runtime_query_arena_usage` | Output stats struct is copied with fields never initialized. |
| ISSUE42-009 | VM-007 CRCU multi-writer race/leak | `_runtime_enqueue_rcu_batch` | Pending-batch check occurs outside the writer lock. |
| ISSUE42-010 | VM-008 mmpool array size mismatch | `_runtime_rebuild_available_list` | Configured lcore count can exceed fixed scratch-array capacity. |
| ISSUE42-011 | VM-009 reserved file size check | `_runtime_map_reserved_region` | Regular-file size rules are applied to character-device mappings. |
| ISSUE42-013 | VM-011 FixPool ops registration race | `_runtime_register_pool_ops` | Global ops slot is checked outside the update lock. |
| ISSUE42-014 | VM-012 FixPool cache iteration OOB | `_runtime_count_pool_cache` | Cache count iteration uses an external lcore limit instead of array length. |
| ISSUE42-015 | VM-013 ShmDbg arena group logic | `_runtime_walk_arena_groups` | Arena-group lookup is driven by partition index rather than stable group identity. |
| ISSUE42-016 | VM-014 QRCU version race | `_runtime_schedule_rcu_release` | Mutable global RCU mode and callback table are used without stable synchronization. |
| ISSUE42-017 | VM-015 PCM slot race | `_runtime_claim_process_slot` | CAS result is ignored before writing process-table identity fields. |
| ISSUE42-018 | VM-016 NamedPipe permission | `_runtime_open_named_segment` | Shared-memory name and permissions are hard-coded for a narrow deployment. |
| ISSUE42-019 | VM-017 signal stack race | `_runtime_capture_signal_stack` | Signal path logs and mutates shared callstack state. |
| ISSUE42-020 | VM-018 flushJob same-core wake | `_runtime_queue_local_flush` | Same-core trigger-mode wake queues an event without scheduling work. |
| ISSUE42-021 | VM-019 Smmap concurrent creation | `_runtime_create_shared_zone` | Shared-memory zone lookup happens before insert locking. |
| ISSUE42-022 | VM-020 TLSCB preallocation | `_runtime_cleanup_tls_reserve` | Partial TLSCB setup can leak reserved virtual space on cleanup. |
| ISSUE42-023 | VM-021 OsalShmPosixGetAddrByPath | `_runtime_map_linked_segment` | Link/EEXIST handling races with open of the shared-memory path. |
| ISSUE42-024 | VM-022 Lfhash alloc/free mismatch | `_runtime_release_hash_node` | User-provided allocator and free callbacks are not paired. |
| ISSUE42-025 | VM-023 PCM server state missing | `_runtime_mark_process_online` | Client init branch misses the process-state transition. |
| ISSUE42-026 | VM-024 ftok concurrent issue | `_runtime_make_shared_key` | Path state and key generation are not made atomic. |
| ISSUE42-027 | VM-025 wheel timer self-delete deadlock | `_runtime_cancel_wheel_timer` | Callback can re-enter timer deletion with conflicting lock order. |
| ISSUE42-028 | VM-026 signal semaphore interrupt | `_runtime_write_exception_record` | Signal handler performs semaphore-protected work. |
| ISSUE42-029 | VM-027 WORK self-destruction race | `_runtime_finish_current_event` | Callback can free the current event before post-callback updates. |

ISSUE42-012 was retired in benchmark v13 because the modeled log-level concern
is code style / observability hygiene rather than a concrete security flaw.

All 28 scored findings are assigned to tier `real_project_issue42` with weight 3.
