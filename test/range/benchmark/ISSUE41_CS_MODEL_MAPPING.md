# Issue #41 Distributed C/S Model Mapping

This file documents how the 11 models from
https://github.com/zealousness/Z-Scope/issues/41 are represented in the
`test/range` benchmark. It is intentionally excluded from Z-SCOPE analysis
context because it is benchmark maintenance metadata.

## Flow

The issue #41 suite is modeled as a distributed client/server message framework:

1. Public API: `td_handle_distributed_cs_message`
2. Internal entry: `_issue41_process_cs_message`
3. Receive: `_issue41_receive_cs_frame`
4. Header decode and copy: `_issue41_header_length_not_validated`
5. Task creation: `_issue41_create_task_from_cs_frame`
6. Task indexing/enqueue: `_issue41_dynamic_array_expand_race`,
   `_issue41_enqueue_cs_task`
7. Dispatch: `_issue41_dispatch_cs_task`
8. Domain handlers: the 11 `ISSUE41-*` functions below

## Models

| Ground truth | Source model | Function | Main concern |
| --- | --- | --- | --- |
| ISSUE41-001 | VM-001 DSBL-SizeMiscalc | `_issue41_label_cache_size_miscalc` | Fixed label-cache limit is smaller than the declared collection element spec. |
| ISSUE41-002 | VM-002 MPCW-HeaderValidation | `_issue41_header_length_not_validated` | Message magic is checked but protocol length is trusted for copy. |
| ISSUE41-003 | VM-003 RRT-TimeoutMitigation | `_issue41_recv_retry_without_timeout` | EAGAIN/EINTR receive retry has no timeout or retry budget. |
| ISSUE41-004 | VM-004 FDTC-MismatchedParameterType | `_issue41_reliable_fd_to_raw_interface` | Encoded reliable fd is passed to an interface expecting raw fd. |
| ISSUE41-005 | VM-005 PMMP-LaxProtocolMismatchProtection | `_issue41_lax_protocol_mismatch` | Protocol mismatch is accepted outside strict auth mode. |
| ISSUE41-006 | VM-006 PRL-PartialResourceLeakOnRetry | `_issue41_partial_resource_leak_on_retry` | Multi-step init leaks a partition on failure and retry can use an uninitialized tag. |
| ISSUE41-007 | VM-007 DAE-RiskDynamicArrayExpansion | `_issue41_dynamic_array_expand_race` | Task-array expansion swaps a global pointer without synchronization. |
| ISSUE41-008 | VM-008 VIC-MissingVersionFiltering | `_issue41_missing_version_filter` | High-version handler processes low-version state without version filtering. |
| ISSUE41-009 | VM-009 RCR-MissingReferenceCount | `_issue41_missing_reference_count` | Shared listener cleanup ignores outstanding references. |
| ISSUE41-010 | VM-010 SSP-SIGPipeNotHandled | `_issue41_sigpipe_not_handled` | Send path writes to a peer fd without SIGPIPE mitigation. |
| ISSUE41-011 | VM-011 FEM-FdEndiannessMismatch | `_issue41_raw_fd_missing_encode` | Attribute setup passes raw work fd where encoded fd is expected. |

All 11 findings are assigned to tier `real_project_issue41` with weight 3 so
they are reported separately from legacy synthetic findings and from the issue
#40 `REAL-*` tier.
