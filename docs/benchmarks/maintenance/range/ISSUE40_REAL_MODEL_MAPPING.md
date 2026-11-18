# GitHub Issue #40 Real-Model Tier

This file is benchmark-maintenance context, not target-project context for
Z-SCOPE analysis prompts.

GitHub issue #40 contains 31 real-project abstract vulnerability models. They
are represented in this fixture as `REAL-001` through `REAL-031`, all in
`src/lifecycle.c`, and are scored as the `real_project_issue40` tier with
weight `3`. The older `RANGE-*` findings remain the `legacy_range` tier with
weight `1`.

Protocol and wire-format models are intentionally routed through a realistic
message flow:

`td_handle_protocol_message` -> `_runtime_process_protocol_task` ->
receive protocol frame -> decode header -> dispatch by message type -> protocol
handler.

The individual `REAL-*` helper functions remain explicit entries so the
benchmark can still measure local reasoning, but reports that find the issue
from the protocol entry or dispatcher path should also be discoverable.

| Benchmark ID | Source model | Entry function | Pattern |
| --- | --- | --- | --- |
| REAL-001 | VM-001 | `_runtime_remove_module_record` | Unlink-before-free registry cleanup race. |
| REAL-002 | VM-002 | `_runtime_remove_system_node` | Parent node deletion misses child records. |
| REAL-003 | VM-003 | `_runtime_apply_component_stage` | Duplicate cleanup on rollback path. |
| REAL-004 | VM-004 | `_runtime_detach_component_record` | Detached component leaks after config removal failure. |
| REAL-005 | VM-005 | `_runtime_remove_file_record` | Unregister frees wrapper but leaks path payload. |
| REAL-006 | VM-006 | `_runtime_activate_service_path` | Activation rollback drops nested session resources. |
| REAL-007 | VM-007 | `_runtime_release_reader_channel` | Role-specific reader cleanup uses wrong release path. |
| REAL-008 | VM-013 | `_runtime_flush_log_buffer` | Error logging path leaks allocated message text. |
| REAL-009 | VM-014 | `_runtime_publish_init_sequence` | Object is published before initialization completes. |
| REAL-010 | VM-010 | `_runtime_message_header_probe` | Packet header field read after insufficient length check. |
| REAL-011 | VM-011 | `_runtime_unload_patch_member` | Patch unload misses nested table-node release. |
| REAL-012 | VM-012 | `_runtime_insert_policy_node` | AVL insertion failure is ignored after ownership transfer. |
| REAL-013 | VM-013B | `_runtime_protocol_frame_length` | Protocol unit count drives unsafe copy length. |
| REAL-014 | VM-014B | `_runtime_read_control_magic` | Offline parser trusts count before magic validation. |
| REAL-015 | VM-015 | `_runtime_unload_resource_table` | Table unload skips nested bucket cleanup. |
| REAL-016 | VM-016 | `_runtime_read_service_flag` | Service flag is set before shared state is complete. |
| REAL-017 | VM-017 | `_runtime_prune_patch_tree` | Tree cleanup frees root but leaks children. |
| REAL-018 | VM-018 | `_runtime_query_peak_stats` | Peak-stat query leaks its temporary PID list. |
| REAL-019 | VM-NDC | `_runtime_read_peer_record` | Network receive loop spins on repeated failures. |
| REAL-020 | VM-SSL | `_runtime_read_tls_record` | Secure-channel failure path returns success. |
| REAL-021 | VM-RCRP | `_runtime_release_channel_role` | Client sends hardcoded role to server release path. |
| REAL-022 | VM-SII | `_runtime_switch_io_mode` | System-call failure does not restore local state. |
| REAL-023 | VM-LOCK | `_runtime_link_allocated_node` | Allocation failure returns while holding a lock. |
| REAL-024 | VM-REF | `_runtime_release_shared_node` | Refcount is updated after dropping the container lock. |
| REAL-025 | VM-CALLBACK | `_runtime_notify_registry_listener` | External callback is invoked under registry lock. |
| REAL-026 | VM-ASYNC | `_runtime_submit_background_work` | Detached worker receives a stack job pointer. |
| REAL-027 | VM-REALLOC | `_runtime_resize_message_buffer` | Realloc result overwrites the only global pointer. |
| REAL-028 | VM-SIGNED | `_runtime_receive_record_payload` | Negative receive length is cast to `size_t`. |
| REAL-029 | VM-FD | `_runtime_reopen_cached_descriptor` | Closed descriptor remains globally watched. |
| REAL-030 | VM-KEY | `_runtime_route_by_partition_key` | Route-key lookup and bounded-key insertion diverge. |
| REAL-031 | VM-MACRO | `_runtime_update_metric_counter` | Macro-gated lock compiles out around shared counter update. |
