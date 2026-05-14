# Task Dispatcher Benchmark Delivery Notes

`test/range` is a C benchmark fixture for evaluating Z-SCOPE and other static or
AI-assisted code review tools. The project intentionally contains vulnerabilities
and should not be treated as production code.

## Current Benchmark

- Benchmark version: v3
- Scored vulnerabilities: 33
- Scoring truth: `benchmark/ground_truth.json`
- Human-readable answer key: `GROUND_TRUTH.md`
- Pattern coverage matrix: `benchmark/PATTERN_COVERAGE.md`

Version 3 adds a realistic lifecycle/cache subsystem in `src/lifecycle.c` and
`internal/lifecycle.ph`. The added code models common project surfaces from
`docs/c_memory_concurrency_patterns.md`: control messages, cache publication,
borrowed object lifetime, refcounts, callbacks, async flush workers, config
reload, condition variables, network packet/status paths, fd event dispatch, and
mmap-backed rule tables.

## Build Files

- Linux/WSL/macOS: `Makefile`
- Windows batch build: `build.bat`
- Windows cleanup: `clean.bat`
- Windows run helper: `run.bat`

Recommended benchmark execution remains WSL-based because the fixture uses
pthreads and Unix APIs.

## Important Files

- `include/`: public headers and shared macros.
- `internal/`: private `.ph` headers for module boundaries.
- `src/`: C source for dispatcher, parser, plugin, executor, network, and
  lifecycle/cache behavior.
- `benchmark/entries.json`: fixed analysis entry list for Z-SCOPE batch runs.
- `benchmark/check_entry_coverage.py`: preflight that verifies scored findings
  are reachable from configured entries and that entry names resolve uniquely.
- `benchmark/evaluate_zscope_report.py`: report scorer.
- `benchmark/PATTERN_COVERAGE.md`: mapping from the C memory/concurrency pattern
  catalog to concrete benchmark findings.

## Maintenance Rules

- Do not include `GROUND_TRUTH.md`, `DELIVERY.md`, or
  `benchmark/ground_truth.json` in analysis context given to Z-SCOPE.
- Keep `benchmark/ground_truth.json` as the scoring source of truth.
- Update `benchmark/entries.json` whenever a new vulnerability is only reachable
  through an internal entry point.
- Run `benchmark/check_entry_coverage.py` after changing entries, truth, or
  source functions.
- Update `benchmark/PATTERN_COVERAGE.md` whenever adding or retiring memory and
  concurrency patterns.
