# Z-SCOPE Unified Mode Historical Test Report

This report records an older benchmark run from 2026-05-13. It is retained only
as historical context. The current scorer truth is benchmark v3 with 33 valid
findings; use `benchmark/ground_truth.json` for scoring and
`benchmark/PATTERN_COVERAGE.md` for coverage maintenance.

## Historical Run

- Target: `test/range` task dispatcher benchmark
- Mode: Z-SCOPE unified mode under WSL
- Knowledge backend: clangd plus SVF KnowledgeDB where available
- Report scorer: `benchmark/evaluate_zscope_report.py`
- Historical truth size: 12 findings
- Historical unique issues: 22
- Historical true positives: 6
- Historical false positives: 16
- Historical false negatives: 6
- Historical precision: 0.2727
- Historical recall: 0.5000
- Historical F1: 0.3529
- Historical duration: 14143.56 seconds
- Historical context tokens: 836699

## Lessons Preserved

The historical run showed that Z-SCOPE could use deeper call graph, data-flow,
taint, and pointer-alias tools, but recall still depended heavily on stable local
rules and high-quality evidence packs.

Important improvement themes from that run:

- Allocation-size overflow should be generated deterministically from local size
  expressions.
- Free-state automata should identify double-free and invalid-free candidates
  before LLM validation.
- Owner allocation exit-path analysis should feed leak candidates directly into
  evidence packs.
- Lock acquisition sequences and condition-variable predicates need structured
  local extraction.
- Benchmark scoring should distinguish pre-planted findings from general audit
  observations so precision is not dominated by useful but out-of-scope reports.

## Current Status

Benchmark v3 retires disputed historical findings `RANGE-003`, `RANGE-008`, and
`RANGE-010`, keeps the clarified v2 findings, and adds lifecycle/cache/callback,
event, reload, and mmap-backed patterns. Re-run the benchmark against the current
truth before comparing any new Z-SCOPE result.
