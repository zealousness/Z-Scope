# C Memory And Concurrency Optimization Plan

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

1. deterministic rule or backend signal creates a candidate
2. candidate carries source, sink, object/lock, path hints and guards
3. Deep Worker optionally expands the path under a focused skill
4. Validator decides verified / needs review / rejected
5. report generation suppresses known false positives and records metrics

## 2. Implemented In This Stage

The current codebase has landed the first evidence-driven stage:

- `UnifiedBackend` combines Clang indexing with SVF/Saber enrichment.
- `KnowledgeDB` stores functions, types, globals, direct calls, indirect calls,
  taint signatures and lightweight evidence tables.
- `DeterministicCandidateGenerator` generates issue-like candidates for common
  C memory/concurrency classes.
- Candidates are routed through the same vulnerability skills, Deep Worker
  planning, validator flow and report output as LLM findings.
- `UserConfigStore` supports suppressions and baselines so manual false-positive
  feedback can affect later runs.
- `scripts/evaluate_range_regression.py` and
  `test/range/benchmark/evaluate_zscope_report.py` provide regression metrics.
- `test/range` is the tracked fixture; build outputs, snapshots and benchmark
  runs are ignored.

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
2. Require each deterministic candidate to carry positive evidence and, where
   possible, negative evidence such as guards or ownership transfer.
3. Deduplicate by defect class, canonical source/sink and object/lock identity,
   not only by line text.
4. Persist user suppressions and baselines before validation when the match is
   stable.
5. Treat benchmark-extra discoveries as normal findings only when they are
   source-verifiable; do not create a special benchmark-only issue tier.

## 6. High Recall Strategy

1. Keep deterministic rules broad enough to cover the C idiom, then use the
   validator to reject weak paths.
2. Preserve unexecuted Deep Worker candidates in the main analyzer context so a
   small worker budget does not silently drop risky code.
3. Feed SVF indirect calls and Saber signatures into the same candidate/evidence
   path instead of leaving them as passive query data.
4. Expand entry discovery for public APIs, network/IPC, file parsing, callbacks,
   thread starts and environment/input handling.
5. Add regression fixtures for every new memory/concurrency pattern before
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

## 9. Remaining Work

- Build more cross-function alias and ownership proofs instead of relying on
  same-function source slices.
- Add lock-order graph extraction across functions.
- Convert more SVF/Saber output into structured candidates with stable dedup
  keys.
- Add sanitizer harness generation for high-confidence memory candidates.
- Keep `test/range` broad, but add additional real-project-style fixtures for
  ring buffers, callback cancellation, RCU/epoch lifetime and custom allocators.
