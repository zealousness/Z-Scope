# External Benchmark First Run

Date: 2026-05-16

This is the first smoke run of the three-layer external benchmark harness in
`scripts/external_benchmark.py`. These are intentionally small samples, not full
benchmark suites. All three runs used `--mode candidates`, which evaluates the
regex/local and graph candidate layer only. Full LLM-backed Z-SCOPE runs read
`test/range/zscope.local.env` by default and can override model settings with
`Z_SCOPE_BASE_URL` and `Z_SCOPE_MODEL`.

## Results

| Layer | Suite | Entries | Ground Truth | Safe Entries | Issues | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Juliet memory sample from SV-COMP Juliet_Test | 24 | 12 | 12 | 6 | 6 | 0 | 6 | 1.0000 | 0.5000 | 0.6667 |
| 2 | SV-COMP memsafety sample | 9 | 7 | 2 | 15 | 4 | 11 | 3 | 0.2667 | 0.5714 | 0.3636 |
| 3 | Magma libpng patch-function sample | 5 | 5 | 0 | 0 | 0 | 0 | 5 | 0.0000 | 0.0000 | 0.0000 |

## LLM Smoke

After wiring `test/range/zscope.local.env` into the external harness, a tiny
full Z-SCOPE smoke run was executed on 4 Juliet files:

| Suite | Mode | Entries | Ground Truth | Safe Entries | Issues | TP | FP | FN | Precision | Recall | F1 | Wall Time |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `juliet_llm_smoke` | full Z-SCOPE | 4 | 2 | 2 | 2 | 2 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 96.43s |

## Run Artifacts

Generated data is ignored by git and lives under:

- `benchmarks/external/workspace/juliet_memory_svcomp_sample/runs/20260516_094850`
- `benchmarks/external/workspace/svcomp_memsafety_sample/runs/20260516_094850`
- `benchmarks/external/workspace/magma_libpng_sample/runs/20260516_094850`
- `benchmarks/external/workspace/juliet_llm_smoke/runs/20260516_094655`

## Notes

- These are sample counts. Juliet C/C++ does not have only 12 defects; this run
  selected 24 preprocessed SV-COMP Juliet files and therefore produced 12 bad
  entries plus 12 good entries.
- The Juliet sample was taken from SV-COMP's preprocessed `c/Juliet_Test`
  subset because it was immediately available in the current environment. The
  harness also supports an extracted NIST Juliet C/C++ tree.
- Use `--max-cases 0` for all matched Juliet or SV-COMP tasks, and
  `--max-bugs 0` for all Magma bug patches for one target.
- Preprocessed `.i` files are projected into scan-friendly `.c` files that keep
  only selected entry functions. This avoids indexing noise from system headers
  and keeps the external benchmark path compatible with Z-SCOPE's regex backend.
- SV-COMP scoring is property-level and file/function matched; line numbers are
  intentionally not required because SV-COMP YAML files usually label property
  truth rather than exact vulnerability lines.
- Magma's repository contains bug patches and target fetch scripts, not a
  ready-to-scan target tree. The libpng target was fetched at the Magma commit
  and patch metadata was used to infer affected functions. The Magma number
  above is a wiring smoke result, not a formal Magma vulnerability result until
  target setup and bug patches are applied cleanly.

## Next Formal Run

For a formal comparison against a pure model, run each prepared suite in three
conditions:

1. pure LLM on entry source only
2. pure LLM with repository context and no Z-SCOPE candidates
3. full Z-SCOPE pipeline with candidates, backend signals, Deep Worker, and
   Validator

The generated `ground_truth.json` files are shared across all three conditions.



