# Range global-model diagnostic

This directory preserves the developer-only global semantic-model diagnostic.
It is not a release benchmark and must not be used to claim Range quality.

Run it on Linux/WSL with the normal deep toolchain on `PATH` and explicit
`Z_SCOPE_LLM_BASE_URL`, `Z_SCOPE_LLM_MODEL`, and `Z_SCOPE_API_KEY` variables:

```bash
bash benchmarks/experiments/range_global_model/run.sh
```

Outputs default to `benchmark-artifacts/experiments/range_global_model/`.
