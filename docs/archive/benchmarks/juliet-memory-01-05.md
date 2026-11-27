# Juliet Memory 01-05 Benchmark

> **历史文档，2026-11-17 整理归档。** 原位置：`docs/progress_docs/juliet_memory_01_05_benchmark.md`。正文中的状态、接口、路径、测试与后续建议保留记录时含义；当前说明见[文档总导航](../../README.md)，本类记录见[归档索引](README.md)。

This benchmark is the first Z-SCOPE external benchmark layer. It uses the
official NIST Juliet C/C++ 1.3 test suite and selects the C/C++ memory-oriented
CWE families with flow variants `01` through `05`.

## Location

Generated suite:

```text
<repo>/benchmarks/external/workspace/juliet_memory_01_05
```

Raw official archive used locally:

```text
/mnt/c/tmp/juliet-c-cpp-v1.3.zip
```

Extracted source root used locally:

```text
/mnt/c/tmp/juliet-c-cpp-v1.3-full/C
```

The generated workspace is intentionally ignored by git because it contains
copied benchmark source files and run artifacts. Z-SCOPE should be executed
from WSL, so generated configs use `/mnt/c/...` paths.

## Scope

Selected CWE families:

```text
CWE121 CWE122 CWE124 CWE126 CWE127 CWE190 CWE191 CWE195 CWE401 CWE415
CWE416 CWE457 CWE476 CWE562 CWE590 CWE680 CWE761 CWE762 CWE789
```

Generated manifest:

```text
selected_files: 4411
entries: 8784
ground_truth: 4392
safe_entries: 4392
complete: true
```

Per-CWE bad-entry distribution:

| CWE | Bad entries |
| --- | ---: |
| CWE-121 | 590 |
| CWE-122 | 630 |
| CWE-124 | 230 |
| CWE-126 | 180 |
| CWE-127 | 230 |
| CWE-190 | 450 |
| CWE-191 | 345 |
| CWE-195 | 120 |
| CWE-401 | 202 |
| CWE-415 | 102 |
| CWE-416 | 106 |
| CWE-457 | 217 |
| CWE-476 | 50 |
| CWE-562 | 3 |
| CWE-590 | 335 |
| CWE-680 | 60 |
| CWE-761 | 60 |
| CWE-762 | 382 |
| CWE-789 | 100 |

## Recreate

```powershell
wsl bash -lc 'cd <repo> && \
  python3 scripts/external_benchmark.py prepare-juliet \
    --source /mnt/c/tmp/juliet-c-cpp-v1.3-full/C \
    --workspace benchmarks/external/workspace \
    --name juliet_memory_01_05 \
    --max-cases 0 \
    --flow-variants 01 02 03 04 05'
```

## Run

Cheap regex/graph candidate run:

```bash
cd <repo>
python3 scripts/external_benchmark.py run-prepared \
  --suite-root benchmarks/external/workspace/juliet_memory_01_05 \
  --mode candidates
```

Full Z-SCOPE LLM-backed run:

```bash
cd <repo>
python3 scripts/external_benchmark.py run-prepared \
  --suite-root benchmarks/external/workspace/juliet_memory_01_05 \
  --mode zscope \
  --env-file test/range/zscope.local.env
```

The full suite is substantially larger than the earlier smoke tests. A Windows
PowerShell candidate attempt exceeded a 5-minute local command timeout and is
not the correct execution environment. Use WSL for all Z-SCOPE benchmark runs.

## WSL Smoke Check

WSL smoke suite:

```text
benchmarks/external/workspace/juliet_memory_01_05_wsl_smoke
```

Candidate run result:

```text
entries: 20
issues: 3
true_positives: 2
false_positives: 1
false_negatives: 8
precision: 0.6667
recall: 0.2
f1: 0.3077
```
