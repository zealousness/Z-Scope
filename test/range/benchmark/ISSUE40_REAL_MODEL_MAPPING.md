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

`td_handle_real_protocol_message` -> `_real_model_process_protocol_task` ->
receive protocol frame -> decode header -> dispatch by message type -> protocol
handler.

The individual `REAL-*` helper functions remain explicit entries so the
benchmark can still measure local reasoning, but reports that find the issue
from the protocol entry or dispatcher path should also be discoverable.

| Benchmark ID | Source model | Entry function | Pattern |
| --- | --- | --- | --- |
| REAL-001 | VM-001 | `_real_model_module_cleanup_race` | Unlink-before-free registry cleanup race. |
| REAL-002 | VM-002 | `_real_model_osnode_remove_race` | Parent node deletion misses child records. |
| REAL-003 | VM-003 | `_real_model_error_branch_double_cleanup` | Duplicate cleanup on rollback path. |
| REAL-004 | VM-004 | `_real_model_comp_destroy_detach_leak` | Detached component leaks after config removal failure. |
| REAL-005 | VM-005 | `_real_model_unregister_file_leak` | Unregister frees wrapper but leaks path payload. |
| REAL-006 | VM-006 | `_real_model_activation_rollback_gap` | Activation rollback drops nested session resources. |
| REAL-007 | VM-007 | `_real_model_reader_channel_role_leak` | Role-specific reader cleanup uses wrong release path. |
| REAL-008 | VM-013 | `_real_model_log_buffer_leak` | Error logging path leaks allocated message text. |
| REAL-009 | VM-014 | `_real_model_init_sequence_publication` | Object is published before initialization completes. |
| REAL-010 | VM-010 | `_real_model_message_alignment_overread` | Unaligned packet field read after insufficient length check. |
| REAL-011 | VM-011 | `_real_model_patch_unload_member_leak` | Patch unload misses nested table-node release. |
| REAL-012 | VM-012 | `_real_model_avl_insert_unchecked_return` | AVL insertion failure is ignored after ownership transfer. |
| REAL-013 | VM-013B | `_real_model_protocol_length_miscalc` | Protocol unit count drives unsafe copy length. |
| REAL-014 | VM-014B | `_real_model_magic64_missing_check` | Offline parser trusts count before magic validation. |
| REAL-015 | VM-015 | `_real_model_resource_table_unload_leak` | Table unload skips nested bucket cleanup. |
| REAL-016 | VM-016 | `_real_model_atomic_order_flag_race` | Ready flag is set before shared state is complete. |
| REAL-017 | VM-017 | `_real_model_patch_tree_child_leak` | Tree cleanup frees root but leaks children. |
| REAL-018 | VM-018 | `_real_model_peak_stats_leak` | Peak-stat query leaks its temporary PID list. |
| REAL-019 | VM-NDC | `_real_model_recv_busy_loop` | Network receive loop spins on repeated failures. |
| REAL-020 | VM-SSL | `_real_model_ssl_error_returns_ok` | Secure-channel failure path returns success. |
| REAL-021 | VM-RCRP | `_real_model_hardcoded_role_release` | Client sends hardcoded role to server release path. |
| REAL-022 | VM-SII | `_real_model_syscall_state_not_restored` | System-call failure does not restore local state. |
| REAL-023 | VM-LOCK | `_real_model_missing_unlock_after_alloc` | Allocation failure returns while holding a lock. |
| REAL-024 | VM-REF | `_real_model_refcount_after_unlock` | Refcount is updated after dropping the container lock. |
| REAL-025 | VM-CALLBACK | `_real_model_callback_under_lock` | External callback is invoked under registry lock. |
| REAL-026 | VM-ASYNC | `_real_model_detached_stack_job` | Detached worker receives a stack job pointer. |
| REAL-027 | VM-REALLOC | `_real_model_realloc_lost_pointer` | Realloc result overwrites the only global pointer. |
| REAL-028 | VM-SIGNED | `_real_model_signed_recv_to_size` | Negative receive length is cast to `size_t`. |
| REAL-029 | VM-FD | `_real_model_stale_fd_after_close` | Closed descriptor remains globally watched. |
| REAL-030 | VM-KEY | `_real_model_key_truncation_route` | Full-key lookup and truncated-key insertion diverge. |
| REAL-031 | VM-MACRO | `_real_model_macro_guarded_counter` | Macro-gated lock compiles out around shared counter update. |
