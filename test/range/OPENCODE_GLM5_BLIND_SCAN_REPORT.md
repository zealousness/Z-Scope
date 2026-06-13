# opencode GLM-5 Blind Scan Report for `test/range`

## Setup

- Tool: `opencode run`
- Model: `alibaba-cn/glm-5`
- Source input: sanitized copy at `.opencode_range_blind_input`
- Original target: `test/range`
- Command wall time: `198.8` seconds

The sanitized copy contained only:

- `src/`
- `include/`
- `internal/`
- `CMakeLists.txt`
- `Makefile`

The copy intentionally excluded:

- `GROUND_TRUTH.md`
- `benchmark/ground_truth.json`
- `CODEX_BLIND_SCAN_REPORT.md`
- `.zscope_*`
- `benchmark_runs`
- prior reports and benchmark artifacts

## Prompt Method

The prompt asked GLM-5 to follow the same blind-review method used by Codex:

- build a source map first
- read public wrappers, headers, and internal prototypes
- use pattern search for risky C sinks and lifecycle/concurrency patterns
- manually confirm candidates
- do not modify files
- do not read any ground truth or prior reports
- output a Markdown table and `TOTAL_CANDIDATES=<n>`

## opencode Result

GLM-5 reported:

- Raw candidates: `22`
- Unique GT hits after de-duplication: `18`
- Duplicate candidate rows: `2`
- False positives: `2`
- GT total: `121`

Metrics:

- Unique recall: `18 / 121 = 14.88%`
- Raw candidate false-positive rate: `2 / 22 = 9.09%`
- Unique precision excluding duplicate rows: `18 / (18 + 2) = 90.00%`

## Candidate Mapping

| # | opencode location | opencode summary | Mapping | Result |
| --- | --- | --- | --- | --- |
| 1 | `src/lifecycle.c:_lifecycle_format_topic:333` | `topic[sizeof(topic)]` off-by-one write | `RANGE-030` | TP |
| 2 | `src/lifecycle.c:_lifecycle_recv_packet:322` | negative receive cast to `size_t` then `memcpy` | `RANGE-029` | TP |
| 3 | `src/lifecycle.c:_peer_decode_header_window:1711` | protocol body length underflow and unchecked copy | `ISSUE41-002` | TP |
| 4 | `src/lifecycle.c:_peer_create_task_from_frame:1917` | same trusted header length reaches another copy | duplicate of `ISSUE41-002` root | Duplicate |
| 5 | `src/lifecycle.c:_runtime_apply_component_stage:1225-1226` | double free of `node->payload` | `REAL-003` | TP |
| 6 | `src/executor.c:_executor_cleanup_resources:162` | double free of `temp_buffer` | `RANGE-006` | TP |
| 7 | `src/lifecycle.c:_lifecycle_avl_register_route:939` | inserted route node freed while tree keeps pointer | `RANGE-047` | TP |
| 8 | `src/lifecycle.c:_peer_publish_shared_session:1819-1838` | global resource freed while still linked | `ISSUE41-009` | TP |
| 9 | `src/lifecycle.c:_lifecycle_release_value_slice:354` | invalid free of pointer into caller buffer | `RANGE-032` | TP |
| 10 | `src/lifecycle.c:_lifecycle_schedule_flush:256` | detached thread receives stack `FlushJob` | `RANGE-024` | TP |
| 11 | `src/lifecycle.c:_runtime_submit_background_work:1519` | detached thread receives stack `ServiceAsyncJob` | `REAL-026` | TP |
| 12 | `src/lifecycle.c:_lifecycle_ref_get:181-182` | refcount increment after unlock | `RANGE-021` | TP |
| 13 | `src/lifecycle.c:_lifecycle_ref_put:197-200` | refcount decrement/free after unlock | duplicate of `RANGE-021` root | Duplicate |
| 14 | `src/plugin.c:_plugin_dispatch` + `src/executor.c:_executor_execute_task` | opposite lock order deadlock | retired `RANGE-010` pattern, different mutex objects | FP |
| 15 | `src/plugin.c:_plugin_unregister:99` | recursive locking through `_plugin_lookup` | `RANGE-005` | TP |
| 16 | `src/lifecycle.c:_lifecycle_parse_control_message:96` | unchecked `strchr` result | `RANGE-018` | TP |
| 17 | `src/lifecycle.c:_lifecycle_parse_frame:359` | attacker-controlled VLA stack allocation | `RANGE-033` | TP |
| 18 | `src/executor.c:_executor_log_message:192` | format string via `printf(g_log_buffer)` | `RANGE-004` | TP |
| 19 | `src/lifecycle.c:_peer_prepare_retry_context:1763` | uninitialized `tag` on retry/resource-limit path | `ISSUE41-006` | TP |
| 20 | `src/lifecycle.c:_lifecycle_close_pipe:726,732` | pipe list self-reference causing traversal failure | `RANGE-042` | TP |
| 21 | `src/lifecycle.c:_peer_bridge_descriptor:1740` | claimed fd index can reach 1024 | guarded by `< 1024`; did not capture GT fd-type mismatch | FP |
| 22 | `src/main.c:_worker_thread:87` | unsynchronized `g_shared_counter++` | `RANGE-009` | TP |

## Missed GT Surface

GLM-5 missed `103` of `121` GT issues. Notable missed clusters:

- most service-resource lifecycle leaks and object-publication cases
- most protocol semantic issues in ISSUE41
- most shared-memory/runtime callback models in ISSUE42
- multiple global-state races
- file-type, permission, signal, timer, and allocator-pairing semantics
- command injection, task parser bounds, serialization overflow, and network receive allocation overflow

## Observations

GLM-5 was precise on obvious C sink patterns and several lifecycle primitives:

- off-by-one writes
- negative-to-unsigned `memcpy`
- double free
- stack object escape
- invalid free
- recursive lock deadlock
- format string

It was much weaker on broad recall. It stopped after 22 candidates and did not exhaust the dense `lifecycle.c` benchmark surface. It also reported the retired lock-order issue between `plugin.c` and `executor.c`, which GT explicitly excludes because the two paths use different mutex objects.

## Command Used

```powershell
opencode run --model alibaba-cn/glm-5 --dir .opencode_range_blind_input --dangerously-skip-permissions "<blind scan prompt>"
```

