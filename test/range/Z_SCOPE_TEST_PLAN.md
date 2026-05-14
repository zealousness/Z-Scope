# Z-SCOPE Range Benchmark Test Plan

This note is for the next Codex/Z-SCOPE run against this project. Treat
`test/range` as a benchmark fixture, not as an ordinary sample project.

## Goal

Measure whether Z-SCOPE can find intentionally planted C defects in a compact
task dispatcher project. The benchmark should report recall, precision, F1, and
per-CWE coverage against `benchmark/ground_truth.json`.

Current scorer truth is benchmark v3 with 33 scored vulnerabilities. Older
observed-run notes below refer to previous 12-item and 14-item truths and are
retained as historical context only.

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
- `benchmark/evaluate_zscope_report.py`: scorer for Z-SCOPE JSON reports.

Do not include `GROUND_TRUTH.md`, `DELIVERY.md`, or
`benchmark/ground_truth.json` in the analysis prompt/context given to Z-SCOPE.
They are answer keys, not target-project documentation. The intended public
project context is source code, headers, `README.md`, build files, and
`benchmark/entries.json`.

## Baseline Commands

From the repository root in WSL:

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
python test/range/benchmark/evaluate_zscope_report.py \
  --report test/range/zscope_batch_report.json \
  --truth test/range/benchmark/ground_truth.json
```

`--build-cpg` is the cheap preflight. It should index functions without calling
the LLM. The full scan requires valid model settings. If `cmake` is unavailable,
use `bear -- make -C test/range` and adjust `project.compile_commands_path` only
if the resulting file is not `test/range/build/compile_commands.json`.

## Scoring Rules

The scorer matches an issue when Z-SCOPE reports the same file and a nearby line
for the same defect class. It also uses CWE/category/keyword text as tie-breakers
because Z-SCOPE report phrasing can vary across models.

Primary metrics:

- True positives: ground-truth defects matched by at least one reported issue.
- False negatives: ground-truth defects not matched.
- False positives: reported issues that match no ground-truth item.
- Recall: TP / total ground truth.
- Precision: TP / reported issues considered.
- F1: harmonic mean of precision and recall.

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

## Observed Run: 2026-05-13

Environment:

- WSL Ubuntu
- `clangd` installed from apt (`Ubuntu clangd version 18.1.3`)
- Z-SCOPE config: `test/range/zscope.benchmark.yaml`
- Model: DashScope OpenAI-compatible `glm-5`
- SVF/gllvm unavailable, so SVF-enhanced pointer/lifetime analysis was disabled.

Result:

```text
Functions analyzed: 14
Total issues found: 47
Total duration seconds: 15548.37
Total context tokens: 855654
```

Benchmark scorer:

```json
{
  "true_positives": 11,
  "false_positives": 36,
  "false_negatives": 1,
  "precision": 0.234,
  "recall": 0.9167,
  "f1": 0.3729,
  "missed": ["RANGE-003"]
}
```

Operational notes:

- Full run wall-clock was long: started at `2026-05-12 22:17:51`, completed at
  `2026-05-13 00:30:49`.
- The first two entries were slow because Z-SCOPE built reusable snapshots for
  common macros/helpers. Progress became faster after cache warm-up.
- DashScope `glm-5` had intermittent `InvalidChunkLength`, SSL EOF, and bad MAC
  errors; Z-SCOPE retry logic recovered and the run completed.
- The result has high recall but low precision. The evaluator counted 47 report
  issues against the previous 12-item ground truth. Benchmark v2 later retired
  the disputed `_allocate_buffer` overflow item and added clearer memory and
  concurrency findings; benchmark v3 later expanded lifecycle/cache/callback,
  event, reload, and mmap patterns.
- `GROUND_TRUTH.md` line numbers can drift from current source. The canonical
  line ranges for scoring are in `benchmark/ground_truth.json`.
- Running from `/mnt/c/...` may be slower than a native WSL filesystem. If a tool
  has NTFS path issues, copy the repo into WSL, but keep the command path and
  report paths explicit in the run log.
- Full Z-SCOPE analysis will fail if the LLM placeholders are not replaced.
- The fixture intentionally contains dangerous code such as `system()`. Do not
  pass destructive shell strings when manually running the compiled sample.
