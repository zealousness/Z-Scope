# C Memory And Concurrency Optimization Plan

> **历史文档，2026-11-17 归档。** 原位置：`docs/progress_docs/c_memory_concurrency_optimization_plan.md`。本文保存早期 C 内存与并发优化路线及当时的评测记录；“current”、指标、门槛和 remaining work 不代表现行状态或新增任务。当前行为见[分析流水线](../../modules/analysis-pipeline.md)，后续设计见[专业扫描规划](../../Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/19_PROFESSIONAL_SCANNING.md)，评测规则见[Range 协议](../../range-benchmark.md)。

This plan turns Z-SCOPE from a prompt-heavy reviewer into an evidence-first C
memory and concurrency scanner. The near-term acceptance target is:

- recall >= 70%
- false positive rate <= 50%
- benchmark runs must not rely on range-specific custom prompts or hardcoded
  fixture names

## 1. Guiding Principle

LLMs should not be the first source of truth for C memory/concurrency facts.
They are used to interpret project semantics, complete missing context and
reject false positives. Local analysis should produce the candidate and evidence
shape first.

Target pipeline:

1. regex local rule or backend signal creates a candidate
2. candidate carries source, sink, object/lock, path hints and guards
3. Deep Worker optionally expands the path under a focused skill
4. Validator decides verified / needs review / rejected
5. report generation suppresses known false positives and records metrics

## 2. Implemented In This Stage

The current codebase has landed the first evidence-driven stage:

- `UnifiedBackend` combines Clang indexing with SVF/Saber enrichment.
- `KnowledgeDB` stores functions, types, globals, direct calls, indirect calls,
  taint signatures and lightweight evidence tables.
- `RegexCandidateGenerator` generates issue-like candidates for common
  C memory/concurrency classes.
- Candidates are routed through the same vulnerability skills, Deep Worker
  planning, validator flow and report output as LLM findings.
- `UserConfigStore` supports suppressions and baselines so manual false-positive
  feedback can affect later runs.
- `scripts/evaluate_range_regression.py` and
  `test/range/benchmark/evaluate_zscope_report.py` provide regression metrics.
- `test/range` is the tracked fixture; build outputs, snapshots and benchmark
  runs are ignored.
- `RiskBudgetPlanner` keeps the existing `max_*` settings as hardware-backed
  hard caps while deriving lower per-entry effective budgets for graph
  recursion, premodel depth, callee breadth and focused subagent tickets.

## 3. Current Vulnerability Coverage

The supported vulnerability scanning skills are:

| Skill | Focus |
| --- | --- |
| `bounds_and_integer` | OOB, integer overflow, signed/unsigned misuse, stack overflow, alignment, uninitialized reads |
| `resource_lifecycle` | leaks, fd/handle lifecycle, stale resources, cleanup paths |
| `temporal_memory` | UAF, double free, invalid free |
| `null_and_failure` | null dereference and unchecked failure paths |
| `stack_escape` | returning or publishing stack addresses to async contexts |
| `concurrency_lock_order` | missing unlock, recursive locks, callback/IO under lock, lock ordering |
| `shared_state_race` | shared globals, check-use races, refcount races, lost wakeups |
| `ownership_contract` | caller/callee ownership mismatch, transfer/borrow ambiguity |
| `string_and_format` | format strings, command strings, NUL termination, string construction |

## 4. Candidate Rules To Keep Generic

Rules may match stable C idioms, but must not match range-only names. Valid
examples:

- `malloc/calloc/realloc` size arithmetic before a copy/allocation sink
- `free` followed by reuse, double free, invalid free of stack/offset pointers
- `pthread_mutex_lock` followed by early return without unlock
- `pthread_cond_wait` guarded by `if` instead of a loop
- `access/stat/lstat/faccessat/fstatat` followed by `open/fopen/creat`
- non-literal `printf/fprintf/syslog`
- global state names containing common state words such as flag/counter/status
  accessed without visible locking

Invalid examples:

- matching a benchmark function name such as `_plugin_lookup`
- matching a benchmark helper such as `_check_file_permission`
- matching a benchmark struct such as `TaskHeader`
- emitting a candidate solely because a fixture line appears in ground truth

## 5. Low False Positive Strategy

1. Keep report defaults focused on verified findings and high-score
   `needs_review` items.
2. Require each regex candidate to carry positive evidence and, where
   possible, negative evidence such as guards or ownership transfer.
3. Deduplicate by defect class, canonical source/sink and object/lock identity,
   not only by line text.
4. Persist user suppressions and baselines before validation when the match is
   stable.
5. Treat benchmark-extra discoveries as normal findings only when they are
   source-verifiable; do not create a special benchmark-only issue tier.

## 6. High Recall Strategy

1. Keep regex local rules broad enough to cover the C idiom, then use the
   validator to reject weak paths.
2. Preserve unexecuted Deep Worker candidates in the main analyzer context so a
   small worker budget does not silently drop risky code.
3. Feed SVF indirect calls and Saber signatures into the same candidate/evidence
   path instead of leaving them as passive query data.
4. Use risk-adaptive budgets so low-risk functions do not consume full
   recursion/premodel/subagent capacity while protocol-heavy functions can
   approach the configured hard caps.
5. Expand entry discovery for public APIs, network/IPC, file parsing, callbacks,
   thread starts and environment/input handling.
6. Add regression fixtures for every new memory/concurrency pattern before
   relaxing thresholds.

## 7. Benchmark Protocol

For objective `test/range` runs:

1. build in WSL/Linux, not from native Windows paths
2. use `indexing.backend: unified`
3. keep `project.prompt_autofill.enabled: false`
4. keep `benchmark/entries.json` without `custom_prompt`
5. keep API keys in environment variables or ignored local env files, never in
   committed YAML
6. delete previous snapshots and benchmark output before a fresh run
7. report precision, recall, false positive rate, scan wall time and seconds per
   function

Useful commands:

```bash
cmake -S test/range -B test/range/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
python test/range/benchmark/check_entry_coverage.py \
  --config test/range/zscope.benchmark.yaml \
  --truth test/range/benchmark/ground_truth.json
python -m zscope.cli.cli -c test/range/zscope.benchmark.yaml --build-cpg
python -m zscope.cli.cli -c test/range/zscope.benchmark.yaml --verbose
python test/range/benchmark/evaluate_zscope_report.py \
  --report test/range/zscope_batch_report.json \
  --truth test/range/benchmark/ground_truth.json
```

For local benchmark keys, copy `test/range/zscope.local.env.example` to
`test/range/zscope.local.env`, set `Z_SCOPE_API_KEY`, and uncomment the export
line. The local file is ignored by git and is sourced by
`test/range/benchmark/run_zscope_scan.sh`.

## 8. Current No-Custom-Prompt Result

Run: `test/range/benchmark_runs/unified_20260514_no_custom_prompt`

Environment:

- WSL Ubuntu
- `indexing.backend: unified`
- Clang indexing succeeded
- SVF `wpa` and `saber` succeeded
- `benchmark/entries.json` contains no `custom_prompt`
- `project.prompt_autofill.enabled: false`

Metrics:

| Metric | Value |
| --- | ---: |
| entries | 42 |
| reported issues | 35 |
| ground truth | 33 |
| true positives | 30 |
| false positives | 5 |
| false negatives | 3 |
| precision | 85.71% |
| false positive rate over reported issues | 14.29% |
| recall | 90.91% |
| F1 | 88.24% |
| scan wall time | 5173 s |
| scan speed | 123.17 s/entry |

Missed ground truth IDs: `RANGE-005`, `RANGE-013`, `RANGE-014`.

The result meets the current stage target of recall >= 70% and false positive
rate <= 50%. Remaining work should focus on generic type-contract checks,
cross-function init cleanup ownership, and recursive-lock proof without fixture
function-name matching.

## 8.1 Current WSL Auto-Unified Range Result

Run: `test/range/benchmark_runs/auto_unified_wsl_protocolfix_20260530_035047`

Environment:

- WSL Ubuntu
- automatic entry discovery enabled
- `indexing.backend: unified`
- `header_files: ["*.h"]`
- clangd indexing succeeded
- SVF `wpa` and Saber succeeded
- 820 SVF indirect-call edges and 13 Saber bugs imported
- no `svf unavailable` fallback was used

Metrics:

| View | Reported | Ground truth | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| default | 136 | 122 | 83 | 53 | 39 | 61.03% | 68.03% | 64.34% |
| with needs_review | 237 | 122 | 100 | 137 | 22 | 42.19% | 81.97% | 55.71% |

Note: this run used benchmark truth v12. Benchmark v13 retired
`ISSUE42-012/log_level_misuse` as a style-only logging case, so the current
scored truth count is 121.

Compared with `auto_unified_wsl_benchfix_20260529_001`, the default view
improved from 77 TP / 45 FN / 63.11% recall to 83 TP / 39 FN / 68.03% recall.
The with-needs-review view improved from 99 TP / 23 FN / 81.15% recall to
100 TP / 22 FN / 81.97% recall, but its FP count increased from 109 to 137.

The default result is still below the near-term 70% recall target, while the
with-needs-review result exceeds the recall target but fails the FP-rate target.
The next iteration should therefore focus on validator/scorer alignment for
security-impact semantics and on needs_review precision.

Remaining with-needs-review misses:

- `RANGE-023`, `RANGE-049`
- `REAL-001`, `REAL-012`, `REAL-014`
- `ISSUE41-004`, `ISSUE41-010`
- `ISSUE42-002`, `ISSUE42-004`, `ISSUE42-005`, `ISSUE42-006`,
  `ISSUE42-010`, `ISSUE42-011`, `ISSUE42-013`,
  `ISSUE42-016`, `ISSUE42-017`, `ISSUE42-019`, `ISSUE42-024`,
  `ISSUE42-025`, `ISSUE42-026`, `ISSUE42-028`

Observed dominant miss cause: the new protocol/runtime candidates are usually
created and routed, but the validator rejects several as code-quality,
fail-safe, stub, no-observable-impact, or non-signal-context issues. Examples:
`fd_type_mismatch`, `file_type_validation`, `reader_state_race`,
`global_mode_race`, `slot_race`, `state_machine`, and `signal_deadlock`.
Benchmark v13 strengthens those impact chains instead of relying on
range-specific name rules.

## 9. Current Clang AST/CFG Candidate Rules

The Clang candidate generator uses clangd/CodeIndex function bodies and
synthesized statement/CFG facts. It should use parsed calls, local
declarations, condition guards, event streams, configured resource/lock/macro
models and backend call edges first. Regex-like fragments are allowed only as a
statement parser fallback inside an indexed function body; rules must not
depend on benchmark function names or fixture-only identifiers.

Current checker rules:

- `clang_cfg_same_object_released_twice`
- `clang_cfg_use_after_release`
- `clang_cfg_acquire_without_release_on_exit`
- `clang_cfg_return_with_lock_held`
- `clang_cfg_alloc_result_deref_without_null_guard`
- `clang_cfg_realloc_lost_original`
- `clang_cfg_out_param_used_before_success_check`
- `clang_cfg_external_length_field_reaches_copy`
- `clang_cfg_allocation_size_arithmetic_without_overflow_guard`
- `clang_cfg_size_addition_without_overflow_guard`
- `clang_cfg_narrowing_size_cast_without_range_guard`
- `clang_cfg_nonliteral_format_string`
- `clang_cfg_path_check_before_open`
- `clang_cfg_object_published_before_initialization`
- `clang_cfg_double_checked_global_without_atomic`
- `clang_cfg_cond_wait_guarded_by_if`
- `clang_cfg_borrowed_pointer_returned_after_unlock`
- `clang_cfg_sizeof_index_write`
- `clang_cfg_unaligned_integer_pointer_cast`
- `clang_cfg_fd_closed_without_owner_invalidation`
- `clang_cfg_callback_while_lock_held`
- `clang_cfg_macro_guarded_lock_may_compile_to_noop`

Out-param resource rules treat calls like
`uiRet = SHM_FileMngFileCreate(path, &fd)` as:

- `uiRet`: status value
- `fd`: resource carrier
- misuse only if `fd` is used or released before the `uiRet` success check

## 10. Internal Sink Extraction Plan

Problem: automatic entry discovery starts from public APIs, thread entries and
communication boundaries, but some reports stop at the facade or a nearby
helper instead of consistently lifting the concrete vulnerable internal
source/sink into the candidate sent to Validator.

Non-overlap with existing layers:

- Entry discovery only decides where analysis starts.
- Backend indexing only provides facts: functions, calls, types, macros,
  globals, SVF/Saber signals and backend-specific facts.
- Candidate layer is responsible for suspicious source/sink evidence.
- Validator decides exploitability and reportability.
- Report/scorer only presents and measures validated output.

Implemented baseline:

- The local candidate layer now scans depth-limited project callees from each
  entry, including helpers that do not use a leading underscore naming
  convention.
- Internal callee candidates are lifted with:
  - `function` / `location`: concrete vulnerable helper or sink.
  - `analyzed_from` / `entry_function`: public API, task entry or boundary
    function that made the helper reachable.
  - `call_path`: bounded entry-to-sink call chain.
  - `evidence_pack.path.complete_to_entry=true`.
- Clang AST matcher facts are also collected for reachable callees, not only
  for the entry function.
- Lifted call-path edges now carry best-effort argument evidence. Clang AST
  `CallExpr` argument references are preferred when tooling evidence is
  available; otherwise the candidate records source-text fallback extraction
  with `evidence_source=source_text_best_effort`.
- Lifted call-path edges now include non-conclusive guard summaries. The
  summary records caller-side and callee-entry condition/assert/validation
  facts for mapped arguments, with `is_conclusive=false` so Validator remains
  responsible for deciding whether a guard is sufficient.
- Lifted internal sink dedup now merges repeated candidates for the same
  concrete sink. The primary candidate keeps the sink location while
  `duplicate_sources`, `call_paths` and evidence-pack duplicate call edges keep
  the alternate entry paths.
- The lifted candidate still carries `validation_required=true` and is sent to
  Validator; the candidate layer does not auto-convict.

Remaining implementation plan:

1. Use backend-specific strengths.
   Clang: call edges, declarations, type widths, macros, local CFG guards.
   SVF: value-flow/object identity and memory bug signals.
   Joern: CPG data-flow from configured boundary sources to semantic sinks.
   Unified: Clang + SVF/Saber only. It merges Clang local candidates, SVF
   signals and call graph reachability into one evidence pack instead of
   emitting parallel near-duplicates. Joern remains a separate backend profile.

2. Benchmark gates.
   The regression script now supports backend-specific candidate coverage:

   ```bash
   python scripts/evaluate_range_regression.py \
     --project-root test/range \
     --candidate-backend unified \
     --min-recall 0.75
   ```

   This is intentionally recall-focused: candidate precision is expected to be
   low before Validator review. Full benchmark precision/FPR must still be
   measured after LLM validation.

## 11. Remaining Work

- Keep the v6 candidate-coverage gate active:

  ```bash
  python scripts/evaluate_range_regression.py \
    --project-root test/range \
    --regex-candidates \
    --min-precision 0.60 \
    --min-recall 0.75 \
    --min-f1 0.67
  ```

  The gate uses the current `benchmark/ground_truth.json` truth version and
  combines local regex candidates with graph/protocol candidates. It is
  a fast signal for candidate coverage, not a replacement for full LLM +
  validator benchmark runs.

- Build more cross-function alias and ownership proofs instead of relying on
  same-function source slices.
- Add lock-order graph extraction across functions.
- Convert more SVF/Saber output into structured candidates with stable dedup
  keys.
- Add sanitizer harness generation for high-confidence memory candidates.
- Keep `test/range` broad, but add additional real-project-style fixtures for
  ring buffers, callback cancellation, RCU/epoch lifetime and custom allocators.



