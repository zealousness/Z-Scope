# Z-SCOPE Range Benchmark Test Plan

This note is for the next Codex/Z-SCOPE run against this project. Treat
`test/range` as a benchmark fixture, not as an ordinary sample project.

## Goal

Measure whether Z-SCOPE can find intentionally planted C defects in a compact
task dispatcher project. The benchmark should report recall, precision, F1, and
per-CWE coverage against `benchmark/ground_truth.json`.

Current scorer truth is benchmark v13 with 121 scored vulnerabilities. The
`REAL-*` items are a higher-priority tier derived from GitHub issue #40 real
project models, `ISSUE41-*` is a separate high-priority tier derived from
GitHub issue #41 distributed C/S messaging and task-creation models, and
`ISSUE42-*` covers the shared-memory/runtime callback models from GitHub issue
#42. These tiers are weighted above the original `RANGE-*` findings.

Protocol-oriented `REAL-*` findings should be exercised through the realistic
message path `td_handle_protocol_message` ->
`_runtime_process_protocol_task` whenever possible. The helper entries are
kept as direct scan targets, but the intended project-level behavior is a
receive/decode/dispatch/handler flow.

The `ISSUE41-*` tier should be exercised through the distributed C/S path
`td_handle_distributed_cs_message` -> `_peer_process_session_message`. This path
models receive-frame handling, task creation, task-array indexing, enqueue, and
dispatch before reaching the specific issue #41 handlers.

The `ISSUE42-*` tier should be exercised through the shared-memory/runtime path
`td_handle_issue42_shared_memory_message` ->
`_issue42_process_shared_memory_message`. This path models fd-backed receive
fallback, shared-memory names, runtime opcode dispatch, callback execution,
signal paths, timer/work self-destruction, and allocator/process-table helpers.

## Mandatory Execution Rule

Run Z-SCOPE from WSL. Do not run the benchmark through native Windows Python or
native Windows build tools. The C project uses pthreads, Unix headers, and path
assumptions that are most stable under Linux.

Recommended working directory:

```bash
cd /mnt/c/Users/10273/home/work/Z-Scope
```

If clangd, gcc, make, or Python dependencies are missing inside WSL, install or
fix them in WSL, then rerun. Do not paper over WSL failures by switching to a
Windows-only run.

For automatic entry discovery, use the WSL-only runner:

```bash
test/range/benchmark/run_auto_unified_wsl.sh
```

The runner hard-fails outside WSL and hard-fails when `gclang`, `get-bc`,
`wpa`, or `saber` are unavailable. A benchmark run that logs SVF/Saber as
unavailable is not a valid unified range benchmark.

## One-Time Configuration

Fill the LLM placeholders in:

```text
test/range/zscope.benchmark.yaml
```

Required fields:

- `llms.default.base_url`
- `llms.default.api_key`
- `llms.default.models[0]`
- `llms.smart_model.base_url`
- `llms.smart_model.api_key`
- `llms.smart_model.models[0]`

Keep secrets out of Git. If a private configured copy is needed, create a local
ignored copy such as `test/range/zscope.local.yaml`.

## Benchmark Assets

- `zscope.benchmark.yaml`: Z-SCOPE config for this fixture.
- `benchmark/entries.json`: fixed entry list for batch analysis.
- `benchmark/ground_truth.json`: hidden scoring truth for evaluator use only.
- `benchmark/PATTERN_COVERAGE.md`: maintenance matrix for the C
  memory/concurrency pattern catalog.
- `scripts/external_benchmark.py evaluate`: canonical scorer for Z-SCOPE JSON
  reports. It reports both aggregate metrics and a false-positive split where
  duplicate hits on already matched ground-truth items are listed separately
  from effective false positives.
- `entry_functions_list.json`: latest generated automatic entry-discovery list.
- `zscope_batch_report.json` and `zscope_batch_report.md`: latest generated
  batch report preserved locally for comparison.
- `current_eval.json`: current `external_benchmark.py evaluate` output for the
  preserved batch report.

Do not include `GROUND_TRUTH.md` or `benchmark/ground_truth.json` in the
analysis prompt/context given to Z-SCOPE. They are answer keys, not
target-project documentation. The intended public project context is source
code, headers, `README.md`, build files, and `benchmark/entries.json`.

## Latest Preserved Result

The latest preserved batch report is from 2026-06-09:

- Report files: `zscope_batch_report.json` and `zscope_batch_report.md`.
- Generated entry list: `entry_functions_list.json`.
- Current scorer output: `current_eval.json`.
- Default view: TP 92, raw FP 52, duplicate-of-matched 44, effective FP 8,
  FN 29, precision 0.9200, recall 0.7603, F1 0.8326.
- With `needs_review`: TP 113, raw FP 107, duplicate-of-matched 92,
  effective FP 15, FN 8, precision 0.8828, recall 0.9339, F1 0.9076.

For reporting comparisons, use effective FP and `false_positive_rate`. Keep raw
FP and duplicate-of-matched counts visible so repeated reports against the same
ground-truth issue are auditable instead of silently hidden.

## Baseline Commands

From the repository root in WSL:

```bash
cd /mnt/c/Users/10273/home/work/Z-Scope
test/range/benchmark/run_auto_unified_wsl.sh
```

For the older fixed-entry protocol, use:

```bash
cd /mnt/c/Users/10273/home/work/Z-Scope
python -m pip install -e .
make -C test/range clean
make -C test/range
cmake -S test/range -B test/range/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
python test/range/benchmark/check_entry_coverage.py \
  --config test/range/zscope.benchmark.yaml \
  --truth test/range/benchmark/ground_truth.json
python -m zscope.cli.cli -c test/range/zscope.benchmark.yaml --build-cpg
python -m zscope.cli.cli -c test/range/zscope.benchmark.yaml --verbose
python scripts/external_benchmark.py evaluate \
  --report test/range/zscope_batch_report.json \
  --truth test/range/benchmark/ground_truth.json \
  --output test/range/current_eval.json
```

`--build-cpg` is the cheap preflight. It should index functions without calling
the LLM. The full scan requires valid model settings. If `cmake` is unavailable,
use `bear -- make -C test/range` and adjust `project.compile_commands_path` only
if the resulting file is not `test/range/build/compile_commands.json`.

## Scoring Rules

Use the shared `zscope.benchmark.v3` scorer for formal comparisons. The scorer
matches an issue when Z-SCOPE reports the same file, a compatible defect class,
and an acceptable function/location anchor. Acceptable function anchors include
the primary truth function, `secondary_function`, structured `entry_function`,
structured `sink_function`, and `call_path` evidence. This matters because
Z-SCOPE often reports the concrete sink helper while the truth item names the
public wrapper.

Line checks use the truth `line` to `end_line` range plus tolerance. Truth
`line <= 1` is treated as an unknown placeholder, not as a strict source line.
The scorer also uses CWE/category aliases and ground-truth keyword hits as
tie-breakers because report phrasing can vary across models.

Primary metrics:

- True positives: ground-truth defects matched by at least one reported issue.
- False negatives: ground-truth defects not matched.
- Raw false positives: reported issues that match no ground-truth item.
- Duplicate-of-matched: raw false positives that duplicate an already matched
  ground-truth issue or share the same root cause with that matched issue.
- Effective false positives: raw false positives minus duplicate-of-matched
  issues. This is the FP count used for precision and false-positive rate.
- Recall: TP / total ground truth.
- Precision: TP / (TP + effective FP).
- F1: harmonic mean of precision and recall.

The evaluation output includes `matched_pairs`; inspect it before classifying a
miss as a real Z-SCOPE false negative.

## Known Pitfalls

- The repository README and some project Markdown contain mojibake. Prefer source
  code and structured benchmark assets over those corrupted comments.
- On 2026-05-12, WSL preflight reached `--build-cpg` successfully but logged
  `Failed to start clangd: No such file or directory: 'clangd'`, then fell back
  to regex indexing. Install `clangd` in WSL before treating a run as a full
  unified-backend benchmark result.
- Do not run `make -C test/range clean` in parallel with CMake generation. Both
  touch `test/range/build/`, and the clean step can fail with
  `rm: cannot remove 'build/CMakeFiles': Directory not empty`.
- Keep `analysis.snapshot_dir` project-local (`test/range/.zscope_snapshots`)
  when launching from the repository root; otherwise Z-SCOPE stores scan
  snapshots in the repository-level `.zscope_snapshots/` directory and can
  accidentally reuse state from unrelated runs.
- `GROUND_TRUTH.md` line numbers can drift from current source. The canonical
  line ranges for scoring are in `benchmark/ground_truth.json`.
- Running from `/mnt/c/...` may be slower than a native WSL filesystem. If a tool
  has NTFS path issues, copy the repo into WSL, but keep the command path and
  report paths explicit in the run log.
- Full Z-SCOPE analysis will fail if the LLM placeholders are not replaced.
- The fixture intentionally contains dangerous code such as `system()`. Do not
  pass destructive shell strings when manually running the compiled sample.
