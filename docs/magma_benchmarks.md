# Magma Benchmarks

This document records the WSL-ready Magma benchmark layer for Z-SCOPE.
Magma is used as the real-project benchmark layer, not as the primary
large-scale CWE coverage benchmark.

## Source

Magma checkout:

```text
/mnt/c/tmp/zscope_external_sources/magma
```

Full materialized source root:

```text
/mnt/c/tmp/zscope_external_sources/magma_full
```

The full materializer executes each target's Magma `fetch.sh`, so it clones or
downloads the complete upstream source tree at the commit pinned by Magma. For
large GitHub targets where `git clone` was interrupted by TLS/network errors,
the tree was completed with shallow `git fetch <commit>` against the pinned
commit.

Materialize command:

```bash
cd /path/to/Z-Scope
python3 scripts/materialize_magma_full_sources.py \
  --magma-root /mnt/c/tmp/zscope_external_sources/magma \
  --output-root /mnt/c/tmp/zscope_external_sources/magma_full \
  --force
```

## Generated Suites

Each target is generated as a separate benchmark workspace so formal runs can be
scheduled independently.

| Target | Full files | C/C++ source files in project | Magma bugs | Source-backed entries |
| --- | ---: | ---: | ---: | ---: |
| libpng | 495 | 88 | 7 | 7 |
| libsndfile | 358 | 208 | 18 | 18 |
| libtiff | 636 | 134 | 14 | 13 |
| libxml2 | 4,664 | 193 | 17 | 14 |
| lua | 109 | 68 | 4 | 4 |
| openssl | 24,195 | 1,764 | 20 | 9 |
| php | 20,662 | 1,765 | 16 | 16 |
| poppler | 758 | 635 | 22 | 21 |
| sqlite3 | 1,923 | 401 | 20 | 19 |
| Total | 53,800 | 5,256 | 138 | 121 |

Generated workspaces:

```text
benchmarks/external/workspace/magma_libpng
benchmarks/external/workspace/magma_libsndfile
benchmarks/external/workspace/magma_libtiff
benchmarks/external/workspace/magma_libxml2
benchmarks/external/workspace/magma_lua
benchmarks/external/workspace/magma_openssl
benchmarks/external/workspace/magma_php
benchmarks/external/workspace/magma_poppler
benchmarks/external/workspace/magma_sqlite3
```

The remaining 17 bugs are present in `selected_bugs` metadata but did not map to
a source-backed function entry with the current lightweight extractor:

```text
libtiff: TIF012
libxml2: XML004 XML005 XML007
openssl: SSL002 SSL003 SSL004 SSL005 SSL006 SSL007 SSL008 SSL009 SSL011 SSL012 SSL013
poppler: PDF008
sqlite3: SQL001
```

## Recreate

```bash
cd /path/to/Z-Scope
for target in libpng libsndfile libtiff libxml2 lua openssl php poppler sqlite3; do
  python3 scripts/external_benchmark.py prepare-magma \
    --magma-root /mnt/c/tmp/zscope_external_sources/magma \
    --target "$target" \
    --target-source "/mnt/c/tmp/zscope_external_sources/magma_full/$target/repo" \
    --workspace benchmarks/external/workspace \
    --name "magma_$target" \
    --max-bugs 0 \
    --copy-full-source
done
```

If generated from Windows for speed, convert `zscope.benchmark.yaml` paths back
to `/mnt/c/...` before running Z-SCOPE. The current generated suites have WSL
paths in their Z-SCOPE configs.

## Run

Candidate-only run for one target:

```bash
cd /path/to/Z-Scope
python3 scripts/external_benchmark.py run-prepared \
  --suite-root benchmarks/external/workspace/magma_libpng \
  --mode candidates
```

Full Z-SCOPE LLM-backed run for one target:

```bash
cd /path/to/Z-Scope
python3 scripts/external_benchmark.py run-prepared \
  --suite-root benchmarks/external/workspace/magma_libpng \
  --mode zscope \
  --env-file test/range/zscope.local.env
```

## WSL Smoke Checks

libpng candidate smoke on the full-source workspace:

```text
entries: 7
issues: 0
TP: 0
FP: 0
FN: 7
precision: 0.0
recall: 0.0
f1: 0.0
```

lua candidate smoke on the full-source workspace:

```text
entries: 4
issues: 0
TP: 0
FP: 0
FN: 4
precision: 0.0
recall: 0.0
f1: 0.0
```

These smoke results are expected to be harsher than Juliet/SV-COMP candidates:
Magma bugs are real-project patch-level vulnerabilities and often need semantic
or path-sensitive reasoning. Use Magma primarily for the full Z-SCOPE and pure
LLM comparison layer.
