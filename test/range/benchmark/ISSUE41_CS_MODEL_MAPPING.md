# Issue #41 Distributed C/S Model Mapping

This file documents how the 11 models from
https://github.com/zealousness/Z-Scope/issues/41 are represented in the
`test/range` benchmark. It is intentionally excluded from Z-SCOPE analysis
context because it is benchmark maintenance metadata.

## Flow

The issue #41 suite is modeled as a distributed client/server message framework:

1. Public API: `td_handle_distributed_cs_message`
2. Internal entry: `_peer_process_session_message`
3. Receive: `_peer_receive_frame`
4. Header decode and copy: `_peer_decode_header_window`
5. Task creation: `_peer_create_task_from_frame`
6. Task indexing/enqueue: `_peer_expand_task_table`,
   `_peer_enqueue_task`
7. Dispatch: `_peer_dispatch_task`
8. Domain handlers: the 11 `ISSUE41-*` functions below

## Models

| Ground truth | Source model | Function | Main concern |
| --- | --- | --- | --- |
| ISSUE41-001 | VM-001 DSBL-SizeMiscalc | `_peer_prepare_label_cache` | Fixed label-cache limit is smaller than the declared collection element spec. |
| ISSUE41-002 | VM-002 MPCW-HeaderValidation | `_peer_decode_header_window` | Message magic is checked but protocol length is trusted for copy. |
| ISSUE41-003 | VM-003 RRT-TimeoutMitigation | `_peer_receive_session_frame` | EAGAIN/EINTR receive retry has no timeout or retry budget. |
| ISSUE41-004 | VM-004 FDTC-MismatchedParameterType | `_peer_bridge_descriptor` | Encoded reliable fd is passed to an interface expecting raw fd. |
| ISSUE41-005 | VM-005 PMMP-LaxProtocolMismatchProtection | `_peer_route_protocol_context` | Protocol mismatch is accepted outside strict auth mode. |
| ISSUE41-006 | VM-006 PRL-PartialResourceLeakOnRetry | `_peer_prepare_retry_context` | Multi-step init leaks a partition on failure and retry can use an uninitialized tag. |
| ISSUE41-007 | VM-007 DAE-RiskDynamicArrayExpansion | `_peer_expand_task_table` | Task-array expansion swaps a global pointer without synchronization. |
| ISSUE41-008 | VM-008 VIC-MissingVersionFiltering | `_peer_select_version_window` | High-version handler processes low-version state without version filtering. |
| ISSUE41-009 | VM-009 RCR-MissingReferenceCount | `_peer_publish_shared_session` | Shared listener cleanup ignores outstanding references. |
| ISSUE41-010 | VM-010 SSP-SIGPipeNotHandled | `_peer_send_control_reply` | Send path writes to a peer fd without SIGPIPE mitigation. |
| ISSUE41-011 | VM-011 FEM-FdEndiannessMismatch | `_peer_export_descriptor_token` | Attribute setup passes raw work fd where encoded fd is expected. |

All 11 findings are assigned to tier `real_project_issue41` with weight 3 so
they are reported separately from legacy synthetic findings and from the issue
#40 `REAL-*` tier.
