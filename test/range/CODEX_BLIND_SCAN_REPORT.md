# Codex Blind Scan Report for `test/range`

## Scope and Rules

- Target: `test/range`
- Role: SOTA model representative performing a blind code review
- Constraints followed:
  - No internet access
  - No use of related TP files
  - No access to other conversations
  - `GROUND_TRUTH.md` and `benchmark/ground_truth.json` were not read until the blind scan was stopped

Potential answer-key or prior-run material was intentionally excluded during blind scan:

- `test/range/GROUND_TRUTH.md`
- `test/range/benchmark/ground_truth.json`
- `.zscope_*`
- `benchmark_runs`
- `current_eval.json`
- `Z_SCOPE_TEST_PLAN.md`
- other benchmark/report artifacts likely to contain prior analysis

## Timing

- Blind scan start: `2026-06-13T09:58:42.2721574+08:00`
- Blind scan stop: `2026-06-13T10:01:52.4924881+08:00`
- Scan duration: `190.22` seconds, about `03:10.220`

The stop time was recorded before opening the ground truth files.

## Tools Used

- `Get-Date -Format o`
  - Recorded start and stop timestamps.
- `Get-ChildItem`
  - Listed `test/range` directories and file sizes.
- `rg --files`
  - Built the source file inventory quickly.
- `rg -n`
  - Searched for high-risk C/C++ patterns:
    - `memcpy`, `memmove`, `strcpy`, `strcat`, `snprintf`, `strncpy`
    - `malloc`, `calloc`, `realloc`, `free`
    - `pthread`, `LOCK`, `UNLOCK`
    - `len`, `size`, `count`, `index`, `offset`, `fd`
    - arrays, loops, and conditionals around buffer or lifecycle state
- `Get-Content`
  - Read source files and split large `src/lifecycle.c` into chunks.
- PowerShell `ConvertFrom-Json`
  - After blind scan, loaded `benchmark/ground_truth.json` for structured GT comparison.

## Scan Method

1. File inventory
   - Confirmed source files under `src/`, public headers under `include/`, and internal prototypes under `internal/`.
   - Identified `src/lifecycle.c` as the dominant file by size and API density.

2. API and data model mapping
   - Read `include/types.h`, `include/common.h`, and `include/task_dispatcher.h`.
   - Read internal `.ph` files to understand helper entry points.
   - Mapped public wrappers in `src/main.c` to internal helpers.

3. Pattern scan
   - Used `rg` to locate risky sinks and range-sensitive code.
   - Prioritized:
     - externally influenced lengths and counts
     - protocol field lengths
     - signed-to-unsigned conversions
     - fixed arrays indexed by caller-controlled values
     - `realloc` overwriting the only pointer
     - `free` on non-owned pointers
     - stack object escape to detached threads
     - callback invocation under locks
     - lock order and missing unlock paths
     - stale global fd or pointer state

4. Manual confirmation
   - Checked each candidate for source-to-sink plausibility.
   - Grouped duplicate manifestations into one root-cause finding when they matched a single GT issue.

5. Ground truth comparison
   - After scan stop, read `GROUND_TRUTH.md` and `benchmark/ground_truth.json`.
   - Used the JSON as canonical scoring source.

## Metrics

- Ground truth vulnerabilities: `121`
- Blind candidates: `112`
- True positives: `95`
- False positives: `17`
- False negatives: `26`

Formulas:

- Recall = `TP / GT = 95 / 121 = 78.51%`
- False positive rate / false discovery rate = `FP / (TP + FP) = 17 / 112 = 15.18%`

## True Positive IDs

The following blind findings matched GT entries:

```text
RANGE-001, RANGE-002, RANGE-004, RANGE-005, RANGE-006, RANGE-007,
RANGE-009, RANGE-011, RANGE-012, RANGE-013, RANGE-014, RANGE-015,
RANGE-016, RANGE-017, RANGE-018, RANGE-019, RANGE-020, RANGE-021,
RANGE-022, RANGE-023, RANGE-024, RANGE-025, RANGE-026, RANGE-027,
RANGE-028, RANGE-029, RANGE-030, RANGE-031, RANGE-032, RANGE-033,
RANGE-034, RANGE-036, RANGE-039, RANGE-040, RANGE-041, RANGE-042,
RANGE-043, RANGE-045, RANGE-047, RANGE-049, RANGE-051, RANGE-052,
RANGE-053,
REAL-002, REAL-003, REAL-004, REAL-005, REAL-006, REAL-007,
REAL-008, REAL-009, REAL-010, REAL-011, REAL-012, REAL-013,
REAL-015, REAL-016, REAL-017, REAL-018, REAL-019, REAL-021,
REAL-023, REAL-024, REAL-025, REAL-026, REAL-027, REAL-028,
REAL-029, REAL-030, REAL-031,
ISSUE41-002, ISSUE41-003, ISSUE41-006, ISSUE41-009, ISSUE41-011,
ISSUE42-002, ISSUE42-004, ISSUE42-005, ISSUE42-006, ISSUE42-007,
ISSUE42-008, ISSUE42-009, ISSUE42-010, ISSUE42-013, ISSUE42-014,
ISSUE42-017, ISSUE42-019, ISSUE42-021, ISSUE42-022, ISSUE42-023,
ISSUE42-025, ISSUE42-026, ISSUE42-027, ISSUE42-028, ISSUE42-029
```

## Missed GT IDs

The following GT entries were not found during blind scan:

```text
RANGE-035, RANGE-037, RANGE-038, RANGE-044, RANGE-046, RANGE-048,
RANGE-050, REAL-001, REAL-014, REAL-020, REAL-022, REAL-032,
ISSUE41-001, ISSUE41-004, ISSUE41-005, ISSUE41-007, ISSUE41-008,
ISSUE41-010, ISSUE42-001, ISSUE42-003, ISSUE42-011, ISSUE42-015,
ISSUE42-016, ISSUE42-018, ISSUE42-020, ISSUE42-024
```

Miss patterns:

- More semantic protocol-model issues, especially ISSUE41/ISSUE42 items.
- File type and permission semantics that require domain interpretation.
- Some intentional benchmark models where the code is not obviously memory unsafe but represents a lifecycle or state-machine violation.
- A few global-state races where I saw the surrounding area but did not split the exact GT root cause.

## False Positive Candidates

These were blind candidates I considered actionable but which did not map to scored GT entries:

1. `_net_create_connection`: negative `fd` is only checked as `< 1024`, so a negative descriptor could index `g_connections[fd]`.
2. `_net_send_data`: if `send()` returns `0`, the loop can spin forever because `total_sent` does not advance.
3. `_parse_config_string`: negative `atoi()` results assigned to unsigned config fields can become huge before validation rejects or routes them.
4. `_extract_payload`: zero-length payload allocation via `_safe_malloc(0)` is treated as failure, creating ambiguous behavior rather than a memory bug.
5. `_parse_arguments`: when the maximum argument count is reached, the final token may remain unsplit, producing surprising parsing semantics.
6. `td_init`: several initialization failure paths leak earlier allocations or initialized synchronization objects.
7. `td_init`: worker threads are started before `g_dispatcher.running` is set, creating an initialization ordering race.
8. `td_submit_task`: if cleanup stops workers while the queue is full, submitters waiting on `queue.cond` can block indefinitely.
9. `_worker_thread`: popped queue slot is not cleared, leaving a stale pointer in the ring buffer after task free.
10. `_packet_receiver_thread`: calls `_lifecycle_dispatch_watched_event(packet, sizeof(packet))` after `_lifecycle_recv_packet` without using the actual received length.
11. `_runtime_resize_message_buffer`: `count == 0` can lead to `g_service_metrics[0]` write after a zero-size realloc path.
12. `_runtime_header_alloc`: `size + 8` can overflow before allocation.
13. `_runtime_release_hash_node`: `node_size + 32` can overflow before the allocator callback.
14. `_runtime_map_reserved_region`: mapped anonymous region is stored globally without a visible unmap cleanup path.
15. `_runtime_open_named_segment`: overwrites `g_runtime_named_pipe.addr` without freeing any previous allocation.
16. `_runtime_create_shared_zone`: if `zone->addr` allocation fails, the zone is still inserted with a null backing pointer.
17. `_runtime_apply_memory_plan`: casts `uint64_t map_size` to `size_t` after a mapping helper check, but still passes the truncated value to other helpers on platforms where `size_t` is smaller.

## Why So Many Were Found Quickly

The benchmark is dense: many issues are intentionally concentrated in `src/lifecycle.c` and repeat a small set of vulnerability shapes. Once the first examples were confirmed, the same mental template applied repeatedly:

- length field to copy length
- return value to unsigned length
- stack object to detached worker
- lookup under lock, mutation after unlock
- callback while holding a lock
- global descriptor or mapping not cleared
- public wrapper passing attacker-controlled count into fixed arrays

`rg` made candidate discovery fast, and chunked manual reading filtered the obvious non-issues. The speed came from combining structural source mapping with repeated vulnerability templates, not from GT access.

## Repro Notes

Representative commands used during blind scan:

```powershell
Get-Date -Format o
Get-ChildItem -LiteralPath .\test\range -Force
rg --files .\test\range
rg -n "strcpy|strncpy|strcat|sprintf|snprintf|memcpy|memmove|malloc|calloc|realloc|free|fgets|scanf|atoi|strtol|strlen|sizeof|\[.*\]|for\s*\(|while\s*\(|if\s*\(" .\test\range\src .\test\range\include .\test\range\internal
rg -n "TODO|FIXME|vuln|bug|unsafe|overflow|underflow|bounds|range|length|len|size|capacity|index|offset|count|argc|argv" .\test\range\src .\test\range\include .\test\range\internal
```

Representative GT comparison command used after blind scan:

```powershell
$gt = Get-Content -Raw -LiteralPath .\test\range\benchmark\ground_truth.json | ConvertFrom-Json
$gt.vulnerabilities | Select-Object id,file,function,line,end_line,category,title
```

