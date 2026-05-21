# Ground Truth - Vulnerability Documentation

This document mirrors the canonical scorer truth in
`benchmark/ground_truth.json`. It is an answer key for benchmark maintenance and
must not be included in Z-SCOPE analysis prompts.

## Overview

The current benchmark contains 93 valid vulnerabilities. Version 10 promotes
manually verified extra findings from the
`auto_unified_wsl_structured_20260520_2` benchmark run and adds alternate
public-wrapper anchors for already-known issues.

`benchmark/ground_truth.json` remains the scoring source of truth. This Markdown
file is a human-readable maintenance view.

## Canonical Vulnerabilities

| ID | CWE | Category | Location | Summary |
| --- | --- | --- | --- | --- |
| RANGE-001 | CWE-125 | bounds | `src/parser.c:53-95` | `_parse_task_buffer` trusts `payload_length` and can read beyond the supplied task buffer. |
| RANGE-002 | CWE-190 | integer_overflow | `src/executor.c:140-143` | `_executor_handle_network_request` multiplies an unchecked internal `Task` binary size before copying. Valid under the internal-entry contract. |
| RANGE-004 | CWE-134 | format_string | `src/executor.c:192` | `_executor_log_message` passes attacker-controlled `g_log_buffer` as the `printf` format string. |
| RANGE-005 | CWE-833 | deadlock | `src/plugin.c:97-99` | `_plugin_unregister` holds `registry->mutex` and calls `_plugin_lookup`, which locks the same mutex again. |
| RANGE-006 | CWE-415 | double_free | `src/executor.c:156-162` | `_executor_cleanup_resources` frees `temp_buffer`, then may free it again when `resource_a > 0`. |
| RANGE-007 | CWE-401 | memory_leak | `src/network.c:191-206` | `_net_handle_error` leaks `error_msg` and, on ENOMEM, `recovery_buffer`. |
| RANGE-009 | CWE-362 | race | `src/main.c:82` | Worker threads increment `g_shared_counter` without synchronization. |
| RANGE-011 | CWE-367 | toctou | `src/parser.c:356-361` | `_validate_task` checks file permissions separately from the later `fopen`. |
| RANGE-012 | CWE-78 | command_injection | `src/executor.c:87`, `src/executor.c:220-236` | Command text and `TASK_ENV` are concatenated and passed to `system`. |
| RANGE-013 | CWE-401 | memory_leak | `src/main.c:187-195` | `td_init` allocates `thread_ids` for worker arguments and never releases it. |
| RANGE-014 | CWE-843 | type_confusion | `src/main.c:287`, `src/executor.c:151-166` | `td_cleanup` passes `TaskConfig*` to `_executor_cleanup_resources`, which expects `SharedResources*` and destroys invalid mutex addresses. |
| RANGE-015 | CWE-190 | integer_overflow | `src/network.c:175-186` | `_net_recv_string` allocates `max_len + 1` without checking wraparound, then receives up to `max_len` bytes. |
| RANGE-016 | CWE-362 | race | `src/main.c:55-62`, `src/main.c:51-52`, `src/main.c:625` | `g_running` is read by workers and written by cleanup/signal paths without atomic or mutex synchronization. |
| RANGE-017 | CWE-190 | integer_overflow | `src/parser.c:223-240` | `_serialize_task` adds `sizeof(TaskHeader)` to untrusted `payload_len` without overflow checking, then copies `payload_len` bytes. |
| RANGE-018 | CWE-476 | null_pointer_dereference | `src/lifecycle.c:95-104` | `_lifecycle_parse_control_message` dereferences the `strchr` result without checking that `:` exists. |
| RANGE-019 | CWE-362 | object_publication | `src/lifecycle.c:121-130` | `_lifecycle_add_entry` publishes a cache entry to the global list before `value` initialization completes. |
| RANGE-020 | CWE-416 | use_after_free | `src/lifecycle.c:140-144`, `src/lifecycle.c:152-159` | `_lifecycle_get_value` returns a borrowed value after unlocking while `_lifecycle_remove_entry` can free it. |
| RANGE-021 | CWE-362 | refcount_race | `src/lifecycle.c:174-181`, `src/lifecycle.c:190-199` | `_lifecycle_ref_get` and `_lifecycle_ref_put` update `ref_count` after dropping the cache lock. |
| RANGE-022 | CWE-416 | use_after_free | `src/lifecycle.c:209-221`, `src/lifecycle.c:152-159` | Callback registration stores a cache-entry context that can later be removed and freed. |
| RANGE-023 | CWE-667 | held_lock_callback | `src/lifecycle.c:225-230` | `_lifecycle_fire_callback_under_lock` invokes an externally supplied callback while holding the cache mutex. |
| RANGE-024 | CWE-562 | stack_escape | `src/lifecycle.c:247-259`, `src/lifecycle.c:234-238` | `_lifecycle_schedule_flush` passes the address of a stack `FlushJob` to a detached worker thread. |
| RANGE-025 | CWE-667 | missing_unlock | `src/lifecycle.c:263-267` | `_lifecycle_reload_config` returns on allocation failure while still holding `g_config_lock`. |
| RANGE-026 | CWE-362 | double_checked_locking | `src/lifecycle.c:277-285` | `_lifecycle_get_config_length` checks `g_active_config` outside the mutex before lazy initialization. |
| RANGE-027 | CWE-366 | lost_wakeup | `src/lifecycle.c:288-294` | `_lifecycle_wait_for_work` uses `if` instead of a predicate loop around `pthread_cond_wait`. |
| RANGE-028 | CWE-401 | realloc_misuse | `src/lifecycle.c:299-306` | `_lifecycle_resize_metrics` overwrites the only metrics pointer with `realloc` result and can leak the old allocation. |
| RANGE-029 | CWE-195 | signed_unsigned | `src/lifecycle.c:317-322` | `_lifecycle_recv_packet` casts a negative receive result to `size_t` and uses it as a `memcpy` length. |
| RANGE-030 | CWE-193 | off_by_one | `src/lifecycle.c:331-333` | `_lifecycle_format_topic` writes the NUL terminator one byte past the stack buffer. |
| RANGE-031 | CWE-457 | uninitialized_read | `src/lifecycle.c:338-342` | `_lifecycle_send_status` sends a partially initialized stack struct, including padding and unset fields. |
| RANGE-032 | CWE-590 | invalid_free | `src/lifecycle.c:350-354` | `_lifecycle_release_value_slice` frees a pointer into the middle of the caller's buffer. |
| RANGE-033 | CWE-121 | stack_overflow | `src/lifecycle.c:358-361` | `_lifecycle_parse_frame` uses an attacker-controlled VLA size on the stack. |
| RANGE-034 | CWE-704 | alignment | `src/lifecycle.c:364-370` | `_lifecycle_decode_unaligned_id` casts `packet + 1` to `uint32_t*` and dereferences it. |
| RANGE-035 | CWE-672 | stale_fd | `src/lifecycle.c:373-383`, `src/lifecycle.c:388-392` | `_lifecycle_close_connection` closes a watched descriptor without clearing the global fd used by later event dispatch. |
| RANGE-036 | CWE-416 | use_after_free | `src/lifecycle.c:415-418`, `src/lifecycle.c:422-428` | `_lifecycle_unload_rules` unmaps the rules table without clearing the global pointer used by later rule matching. |

## Version 10 Additions

These entries were added after manually reviewing GT-outside findings from the
WSL unified benchmark run. They are included only when the finding has a concrete
entry path, source/sink, and distinct root cause.

| ID | CWE | Category | Location | Summary |
| --- | --- | --- | --- | --- |
| RANGE-049 | CWE-401 | memory_leak | `src/plugin.c:45-58` | `_plugin_register` overwrites an occupied plugin slot without invoking the previous cleanup path or releasing stored plugin state. |
| RANGE-050 | CWE-362 | race | `src/lifecycle.c:377-392`, `src/main.c:375-378`, `src/main.c:107-110` | `g_watched_fd` is shared by receiver and public event paths without synchronization, so events can dispatch on the wrong connection. |
| RANGE-051 | CWE-78 | command_injection | `src/platform_linux.c:30-37`, `src/platform_windows.c:38-55` | `platform_execute_task` forwards caller-controlled task strings directly to `system`/`CreateProcess`. |
| RANGE-052 | CWE-362 | race | `src/main.c:216-233`, `src/main.c:627-642` | `g_ready` is read by submit paths while cleanup can concurrently tear down dispatcher queue state. |
| RANGE-053 | CWE-362 | race | `src/lifecycle.c:405-418`, `src/lifecycle.c:422-428`, `src/main.c:381-385` | Rule-map globals are mapped, unmapped, and read without synchronization across public `td_configure_rules` callers. |
| REAL-032 | CWE-195/CWE-190 | signed_unsigned | `src/main.c:514-515`, `src/lifecycle.c:1413-1423` | `td_run_real_resource_cases` casts negative `mode` values to huge unsigned counts before the peak-stat allocation path. |

## Retired Findings

The following original findings are retained in
`benchmark/ground_truth.json` under `excluded_vulnerabilities` for audit trail
purposes, but they are no longer scored:

| Former ID | Reason |
| --- | --- |
| RANGE-003 | The post-multiplication check `total_size < size` catches unsigned wrap for multiplication by 2, and `_allocate_buffer` is not currently reachable from benchmark entry paths. |
| RANGE-008 | `_validate_task` validates a freshly parsed task before it is queued to workers; the fixture does not provide a concrete concurrent writer for `task->payload.command.command`. |
| RANGE-010 | `_plugin_dispatch` and `_executor_execute_task` acquire opposite field names, but on different mutex objects (`g_shared_resources` vs. `g_exec_resources`), so the deadlock is not concrete. |

## Maintenance Notes

- `benchmark/ground_truth.json` is the scoring source of truth.
- `benchmark/entries.json` should include direct entries for every vulnerability that is not naturally reachable from the public API prompts.
- `benchmark/PATTERN_COVERAGE.md` maps the benchmark to `docs/c_memory_concurrency_patterns.md` and should be updated whenever new fixture patterns are added.
- If a future fixture intentionally models an internal function as an untrusted entry, record that assumption in the `scope` or `notes` field so precision analysis can distinguish public reachability from internal-contract auditing.
