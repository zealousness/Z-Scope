# scan_demand_equivalence fixtures

Synthetic inputs for `tests/test_scan_demand_equivalence.py` (S07-ORACLE node,
first executable oracle for the INC01–INC05 scan-demand equivalence question).

- `scenarios.json` — the synthetic program (functions, source, call edges),
  staged input mutations, demand-hint descriptors, one audit-unit descriptor
  with candidate-desert coverage keys, a manual contract row, and two synthetic
  build digests for the cross-build scenarios.
- `stale_serialized_plan.json` — a real output of the production shadow planner
  `plan_semantic_demand` (`zscope.semantic-demand.shadow.v1`) for the initial
  scenario, produced by `generate_reference_fixture()` in the test module. It
  is used to prove that a serialized plan replays only for identical current
  inputs and never authorizes execution, proof, or cost claims.

These files contain inputs only. There is no defect truth, no answer label and
no expected verdict here: expectations live in the test assertions and never
enter scanner or model context. The fixtures are synthetic; they are not
production events and do not close INC05/RAPI10 or any formal benchmark.

Dimensions without production events are explicitly untested by this oracle
and never reported as passing:

- real LLM calls and their usage/costs (the shadow plan keeps `usage` at
  `unknown` with null attempts/tokens; actual execution accounting is separate);
- native clang program facts (program coverage stays an explicit unknown);
- ValidationPipeline verdict buckets, dynamic receipts, and reproduction runs;
- multi-variant full scans, wall-clock performance, and formal scoring.
