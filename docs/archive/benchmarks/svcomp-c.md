# SV-COMP C Benchmarks

> **历史文档，2026-11-17 整理归档。** 原位置：`docs/progress_docs/svcomp_c_benchmarks.md`。正文中的状态、接口、路径、测试与后续建议保留记录时含义；当前说明见[文档总导航](../../README.md)，本类记录见[归档索引](README.md)。

This document records the WSL-ready SV-COMP C benchmark workspaces for Z-SCOPE.
The source corpus is the official `sv-benchmarks` `c/` archive from GitLab.

## Source

Downloaded archive:

```text
/mnt/c/tmp/sv-benchmarks-c-main-redownload.zip
```

Extracted source root:

```text
/mnt/c/tmp/sv-benchmarks-c-main-full/c
```

The first 278 MB download was incomplete and should not be used. The complete
archive is about 1.57 GB. Windows `tar.exe` reported errors on some license
symlink entries, but the C source, preprocessed source, `.yml`, and `.set`
benchmark files needed by the harness are present.

## C.MemSafety

Generated suite:

```text
<repo>/benchmarks/external/workspace/svcomp_c_memsafety
```

Scope:

```text
set_files:
  Arrays.set
  Heap-Termination.set
  VerifyThis-Loops.set
  VerifyThis-Recursive.set
  Heap.set
  LinkedLists.set
  Juliet.set

properties:
  valid-memtrack
  valid-free
  valid-deref
  valid-memsafety
```

Manifest:

```text
selected_tasks: 3981
entries: 3981
ground_truth: 2126
safe_entries: 1855
complete: true
```

Violating-task distribution:

| Property bucket | Count |
| --- | ---: |
| memory_safety | 876 |
| memory_leak | 511 |
| invalid_free | 732 |
| integer_overflow | 7 |

Recreate:

```bash
cd <repo>
python3 scripts/external_benchmark.py prepare-svcomp \
  --source /mnt/c/tmp/sv-benchmarks-c-main-full/c \
  --workspace benchmarks/external/workspace \
  --name svcomp_c_memsafety \
  --max-cases 0 \
  --set-files Arrays.set Heap-Termination.set VerifyThis-Loops.set VerifyThis-Recursive.set Heap.set LinkedLists.set Juliet.set \
  --properties valid-memtrack valid-free valid-deref valid-memsafety
```

## C.Concurrency

Generated suite:

```text
<repo>/benchmarks/external/workspace/svcomp_c_concurrency
```

Scope:

```text
set_files:
  Concurrency.set

properties: []
```

Manifest:

```text
selected_tasks: 1060
entries: 1060
ground_truth: 630
safe_entries: 430
complete: true
```

Violating-task distribution:

| Property bucket | Count |
| --- | ---: |
| data_race | 600 |
| memory_safety | 22 |
| integer_overflow | 8 |

Recreate:

```bash
cd <repo>
python3 scripts/external_benchmark.py prepare-svcomp \
  --source /mnt/c/tmp/sv-benchmarks-c-main-full/c \
  --workspace benchmarks/external/workspace \
  --name svcomp_c_concurrency \
  --max-cases 0 \
  --set-files Concurrency.set \
  --properties
```

## Run

Candidate-only run:

```bash
cd <repo>
python3 scripts/external_benchmark.py run-prepared \
  --suite-root benchmarks/external/workspace/svcomp_c_memsafety \
  --mode candidates

python3 scripts/external_benchmark.py run-prepared \
  --suite-root benchmarks/external/workspace/svcomp_c_concurrency \
  --mode candidates
```

Full Z-SCOPE LLM-backed run:

```bash
cd <repo>
python3 scripts/external_benchmark.py run-prepared \
  --suite-root benchmarks/external/workspace/svcomp_c_memsafety \
  --mode zscope \
  --env-file test/range/zscope.local.env

python3 scripts/external_benchmark.py run-prepared \
  --suite-root benchmarks/external/workspace/svcomp_c_concurrency \
  --mode zscope \
  --env-file test/range/zscope.local.env
```

## WSL Smoke Checks

MemSafety smoke suite:

```text
benchmarks/external/workspace/svcomp_c_memsafety_wsl_smoke
entries: 20
ground_truth: 10
safe_entries: 10
candidate issues: 0
TP: 0
FP: 0
FN: 10
precision: 0.0
recall: 0.0
f1: 0.0
```

Concurrency smoke suite:

```text
benchmarks/external/workspace/svcomp_c_concurrency_wsl_smoke
entries: 20
ground_truth: 13
safe_entries: 7
candidate issues: 23
TP: 10
FP: 13
FN: 3
precision: 0.4348
recall: 0.7692
f1: 0.5556
```

All benchmark generation and run commands above are WSL commands. Z-SCOPE should
not be run through the Windows virtual environment for these suites.
