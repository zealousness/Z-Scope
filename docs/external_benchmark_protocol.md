# External Benchmark Protocol

This protocol adds a three-layer external benchmark path for Z-SCOPE:

1. **Juliet memory subset/full selection** for fast, labeled CWE regression.
2. **SV-COMP MemSafety/Concurrency subset/full selection** for property-oriented verifier-style tasks.
3. **Magma target subset/full patch selection** for real-project bug patches after a target source tree is materialized.

The harness lives in `scripts/external_benchmark.py`. It creates a generated suite
under `benchmarks/external/workspace/<suite>/` with:

- `project/`: copied source subset, `compile_commands.json`, and scan outputs
- `benchmark/entries.json`: Z-SCOPE entry functions
- `benchmark/ground_truth.json`: file/function/category truth
- `zscope.benchmark.yaml`: portable Z-SCOPE config, defaulting to `indexing.backend: regex`

Generated corpora and runs are ignored by git.

When the source corpus provides preprocessed `.i` files, the harness writes a
scan-friendly `.c` projection containing the selected entry functions. This is a
compatibility layer for Z-SCOPE's source indexer, not a claim that the smoke
sample is the full upstream benchmark.

## Recommended First Pass

Run the cheap candidate layer first:

```bash
python scripts/external_benchmark.py run-prepared \
  --suite-root benchmarks/external/workspace/juliet_memory_sample \
  --condition candidate_layer \
  --run-kind smoke
```

Then run the full LLM-backed pipeline when API credentials and backend tools are
available:

```bash
export Z_SCOPE_BASE_URL="https://api.openai.com/v1"
export Z_SCOPE_MODEL="gpt-5.2"
export Z_SCOPE_API_KEY="..."
python scripts/external_benchmark.py run-prepared \
  --suite-root benchmarks/external/workspace/juliet_memory_sample \
  --condition full_zscope_pipeline \
  --run-kind sample
```

Each run writes `summary.json`, `evaluation.json`, and `evaluation_views.json`.
`summary.json` uses schema `zscope.benchmark.v3` and includes environment
metadata, default and `with_needs_review` metrics, trajectory references,
cost metrics, final-answer/final-outcome separation, and a deterministic grader
rubric.

`zscope.benchmark.v3` also records `matched_pairs` with the truth id, matched
issue index, issue identity, and the reason each issue matched. The scorer
accepts primary or secondary function anchors, structured `entry_function` /
`sink_function` / `call_path` attribution, category/CWE aliases for custom
range classes, and treats truth `line <= 1` as an unknown placeholder rather
than a strict line requirement.

For a multi-condition comparison over the same generated ground truth:

```bash
python scripts/external_benchmark.py run-matrix \
  --suite-root benchmarks/external/workspace/juliet_memory_sample \
  --conditions pure_llm_entry_source pure_llm_repo_context full_zscope_pipeline \
  --trials 3 \
  --run-kind sample
```

The matrix writes `matrix_summary.json` with per-condition precision/recall/F1
mean/stdev and stability metrics: issue Jaccard, true-positive overlap, and
false-positive overlap.

## Prepare Examples

Juliet, from an extracted NIST Juliet C/C++ tree:

```bash
python scripts/external_benchmark.py prepare-juliet \
  --source /path/to/Juliet/C \
  --max-cases 30 \
  --name juliet_memory_sample
```

Use `--max-cases 0` for all matched Juliet files under `--source`. Full Juliet
C/C++ is much larger than the smoke samples in this repository; expect a large
number of entries and high token cost for full LLM-backed scans.

Use `--cwes ALL --flow-variants` with no following values if you want all CWE
families and all flow variants under the supplied Juliet source tree. The
default CWE list intentionally selects memory-relevant classes only.

SV-COMP, from an `sv-benchmarks/c` checkout:

```bash
python scripts/external_benchmark.py prepare-svcomp \
  --source /path/to/sv-benchmarks/c \
  --max-cases 30 \
  --properties valid-memtrack valid-free valid-deref valid-memsafety data-race \
  --name svcomp_memsafety_sample
```

Use `--max-cases 0` for all matched SV-COMP tasks under `--source`.

Magma, metadata-only or with a fetched target source:

```bash
python scripts/external_benchmark.py prepare-magma \
  --magma-root /path/to/magma \
  --target libpng \
  --target-source /mnt/c/tmp/zscope_external_sources/magma_full/libpng/repo \
  --max-bugs 5 \
  --name magma_libpng_sample \
  --copy-full-source
```

Use `--max-bugs 0` for all bug patches for the selected Magma target.

When `--target-source` points to a fetched/patched target checkout, the script
infers affected functions and emits entries. With `--copy-full-source`, it also
copies the complete target source tree into the generated suite project. The
full Magma source checkout should live under `C:\tmp`, for example
`/mnt/c/tmp/zscope_external_sources/magma_full`, matching the Juliet and
SV-COMP raw corpus layout.

## API Key And Model Env

`run-prepared --mode zscope` reads `test/range/zscope.local.env` by default, and
also accepts `--env-file`. Both `Z_SCOPE_API_KEY=...` and
`export Z_SCOPE_API_KEY=...` are supported. If unset, the generated external
benchmark config defaults to:

- `Z_SCOPE_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1`
- `Z_SCOPE_MODEL=glm-5`

## Pure Model Comparison

Use the same generated `ground_truth.json` for three comparable runs:

1. `pure_llm_entry_source`: pure model over the entry function source only
2. `pure_llm_repo_context`: pure model with repo context but without Z-SCOPE candidates
3. `full_zscope_pipeline`: full Z-SCOPE with regex candidates, graph candidates, backend signals,
   Deep Worker, and Validator

This keeps the base model constant and measures the value of Z-SCOPE's evidence
and verification layers rather than model choice.

## Formal Run Commands

Juliet formal selection:

```bash
python scripts/external_benchmark.py prepare-juliet \
  --source /path/to/Juliet/C \
  --workspace benchmarks/external/workspace \
  --name juliet_memory_formal \
  --max-cases 0
```

SV-COMP formal selection:

```bash
python scripts/external_benchmark.py prepare-svcomp \
  --source /path/to/sv-benchmarks/c \
  --workspace benchmarks/external/workspace \
  --name svcomp_memsafety_formal \
  --max-cases 0 \
  --properties valid-memtrack valid-free valid-deref valid-memsafety data-race
```

Magma target formal selection:

```bash
python scripts/external_benchmark.py prepare-magma \
  --magma-root /path/to/magma \
  --target libpng \
  --target-source /mnt/c/tmp/zscope_external_sources/magma_full/libpng/repo \
  --workspace benchmarks/external/workspace \
  --name magma_libpng_formal \
  --max-bugs 0 \
  --copy-full-source
```

In all three prepare commands, `0` means "all matched cases/bugs", not zero
cases. Pair formal suites with `run-prepared --run-kind formal` or
`run-matrix --run-kind formal`.

