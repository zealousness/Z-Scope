# Z-SCOPE Range Benchmark Test Plan

This note is for the next Codex/Z-SCOPE run against this project. Treat
`test/range` as a benchmark fixture, not as an ordinary sample project.

## Goal

Measure whether Z-SCOPE can find intentionally planted C defects in a compact
task dispatcher project. The benchmark should report recall, precision, F1, and
per-CWE coverage against `benchmark/ground_truth.json`.

Current scorer truth is benchmark v13 with 121 scored vulnerabilities. The
`REAL-*` items are a higher-priority tier derived from GitHub issue #40 real
project models, `ISSUE41-*` is a separate high-priority tier derived from
GitHub issue #41 distributed C/S messaging and task-creation models, and
`ISSUE42-*` covers the shared-memory/runtime callback models from GitHub issue
#42. These tiers are weighted above the original `RANGE-*` findings.

Protocol-oriented `REAL-*` findings should be exercised through the realistic
message path `td_handle_protocol_message` ->
`_runtime_process_protocol_task` whenever possible. The helper entries are
kept as direct scan targets, but the intended project-level behavior is a
receive/decode/dispatch/handler flow.

The `ISSUE41-*` tier should be exercised through the distributed C/S path
`td_handle_distributed_cs_message` -> `_peer_process_session_message`. This path
models receive-frame handling, task creation, task-array indexing, enqueue, and
dispatch before reaching the specific issue #41 handlers.

The `ISSUE42-*` tier should be exercised through the shared-memory/runtime path
`td_handle_issue42_shared_memory_message` ->
`_issue42_process_shared_memory_message`. This path models fd-backed receive
fallback, shared-memory names, runtime opcode dispatch, callback execution,
signal paths, timer/work self-destruction, and allocator/process-table helpers.

## Mandatory Linux Execution Rule

Run the formal unified benchmark in a Linux userspace. Native Linux can execute
the build, preflight, scan, and scoring commands directly. When the host is
Windows, enter WSL first; do not use native Windows Python or native Windows
build tools to produce a formal result. The fixture uses pthreads, Unix headers,
and a Linux LLVM/SVF toolchain.

On Windows, a typical WSL working directory is:

```bash
cd /mnt/c/Users/10273/home/work/Z-Scope
```

On native Linux, work from the actual repository checkout. If clangd, gcc,
cmake, gllvm, LLVM, SVF/Saber, or Python dependencies are missing, install or
fix them in the same Linux environment and rerun. Do not paper over a failed
Linux/WSL preflight by switching to a Windows-only run.

For automatic entry discovery under WSL, use the WSL-only runner:

```bash
test/range/benchmark/run_auto_unified_wsl.sh
```

The runner uses `$HOME/.local/share/zscope-benchmark/venv` when present. Set
`Z_SCOPE_BENCHMARK_VENV` to an alternative Linux virtual environment; never
point it at a Windows virtual environment under `/mnt/c`.

The runner intentionally hard-fails outside WSL. Do not call it on native
Linux; use the equivalent commands in "Baseline Commands" instead. Both paths
must fail closed when `gclang`, `get-bc`, `wpa`, or `saber` are unavailable. A
benchmark run that logs SVF/Saber as unavailable is not a valid unified range
benchmark.

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
- `scripts/external_benchmark.py evaluate`: canonical scorer for Z-SCOPE JSON
  reports. It reports both aggregate metrics and a false-positive split where
  duplicate hits on already matched ground-truth items are listed separately
  from effective false positives.
- `entry_functions_list.json`: latest generated automatic entry-discovery list.
- `zscope_batch_report.json`、`zscope_batch_report.md`、`metrics.json` 和
  `current_eval.json` 是本地/Release 原始生成物，不提交到 Git。
- `docs/range_reports/v1.3.1-cpp-baseline.json`：当前稳定版的冻结摘要；
  `docs/range_reports/v33_release_final2_glm51_20260810/` 保留五轮紧凑摘要、
  Git/tree、参数、哈希和门禁，完整原始报告作为 Release 资产。
- `docs/range_reports/v1.3.1-cpp-formal-fab8398.json`：`fab8398` 上重新执行的
  五轮正式复核候选，保留每轮报告、评分、summary、健康和日志的哈希；它因
  sealed-set 指标缺失而只能作为 RC 证据，不能覆盖已发布冻结基线。

Do not include `GROUND_TRUTH.md` or `benchmark/ground_truth.json` in the
analysis prompt/context given to Z-SCOPE. They are answer keys, not
target-project documentation. The intended public project context is source
code, headers, `README.md`, build files, and `benchmark/entries.json`.
Ground truth may be read by the isolated entry-coverage preflight and by the
scorer only; it must not flow from either step into the scan or LLM context.

## Latest Preserved Result

v1.3.1 冻结结果来自 2026-08-10 的五轮正式冷启动：confirmed TP 中位数
89、raw FP 2、precision 97.80%；with-review TP 134、raw FP 92、
needs-review 135；tokens 1,324,485、wall time 2,105.97 秒。权威摘要为
`docs/range_reports/v1.3.1-cpp-baseline.json`，紧凑单轮证据和哈希位于
`docs/range_reports/v33_release_final2_glm51_20260810/`。

2026-08-10 又在 `fab8398a3bac5ff4791b749fd86b0ae7347abeac` 执行五轮正式
复核：confirmed TP 中位数 87、raw FP 1、precision 98.85%；with-review TP
134、raw FP 82、needs-review 128；tokens 1,263,509、wall time 2,597.6813 秒。
五轮报告、评分、队列、truth 隔离和 unified+SVF/Saber 健康证据完整，数值
门禁通过；但两个 sealed-set delta 均不可用，因此该结果明确标记为 RC-only。
权威紧凑归档为 `docs/range_reports/v1.3.1-cpp-formal-fab8398.json`。最终发布
SHA 若不是 `fab8398`，必须在最终 SHA 重跑，不得把该结果直接绑定到后续提交。

For reporting comparisons, use effective FP and `false_positive_rate`. Keep raw
FP and duplicate-of-matched counts visible so repeated reports against the same
ground-truth issue are auditable instead of silently hidden.

## Baseline Commands

From the repository root in WSL:

```bash
cd /mnt/c/Users/10273/home/work/Z-Scope
test/range/benchmark/run_auto_unified_wsl.sh
```

On native Linux, do not invoke the WSL-named runner. After exporting the model
credentials required by `test/range/zscope.auto_unified.yaml`, run the same
cold-scan stages directly and preserve their logs/run directory:

```bash
python3 -m pip install -e .
cmake -S test/range -B test/range/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
python3 -m zscope.cli.cli -c test/range/zscope.auto_unified.yaml --build-index
python3 -m zscope.cli.cli -c test/range/zscope.auto_unified.yaml --verbose
python3 test/range/benchmark/check_entry_coverage.py \
  --root test/range \
  --entries test/range/entry_functions_list.json \
  --truth test/range/benchmark/ground_truth.json \
  --knowledge-db test/range/.zscope_knowledge_auto_unified_wsl/code_knowledge.db
python3 scripts/external_benchmark.py evaluate \
  --report test/range/zscope_batch_report.json \
  --truth test/range/benchmark/ground_truth.json \
  --output benchmark_runs/current/evaluation.json
```

The `*_wsl` directory names in the current auto-unified config are historical
artifact names; they do not imply that native Linux must launch WSL. For a
formal comparison, record the resolved config, tool versions, entry manifest,
logs, report, evaluation, and whether the run used native Linux or WSL.

For the older fixed-entry protocol, use:

```bash
cd /mnt/c/Users/10273/home/work/Z-Scope
python -m pip install -e .
make -C test/range clean
make -C test/range
cmake -S test/range -B test/range/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
python test/range/benchmark/check_entry_coverage.py \
  --config test/range/zscope.benchmark.yaml \
  --truth test/range/benchmark/ground_truth.json
python -m zscope.cli.cli -c test/range/zscope.benchmark.yaml --build-index
python -m zscope.cli.cli -c test/range/zscope.benchmark.yaml --verbose
python scripts/external_benchmark.py evaluate \
  --report test/range/zscope_batch_report.json \
  --truth test/range/benchmark/ground_truth.json \
  --output benchmark_runs/current/evaluation.json
```

`--build-index` is the canonical cheap preflight and does not call the LLM.
`--build-cpg` is only a deprecated 1.x alias. The full scan requires valid model settings. If `cmake` is unavailable,
use `bear -- make -C test/range` and adjust `project.compile_commands_path` only
if the resulting file is not `test/range/build/compile_commands.json`.

## Scoring Rules

Use the shared `zscope.benchmark.v3` scorer for formal comparisons. The scorer
matches an issue when Z-SCOPE reports the same file, a compatible defect class,
and an acceptable function/location anchor. Acceptable function anchors include
the primary truth function, `secondary_function`, structured `entry_function`,
structured `sink_function`, and `call_path` evidence. This matters because
Z-SCOPE often reports the concrete sink helper while the truth item names the
public wrapper.

Line checks use the truth `line` to `end_line` range plus tolerance. Truth
`line <= 1` is treated as an unknown placeholder, not as a strict source line.
The scorer also uses CWE/category aliases and ground-truth keyword hits as
tie-breakers because report phrasing can vary across models.

Primary metrics:

- True positives: ground-truth defects matched by at least one reported issue.
- False negatives: ground-truth defects not matched.
- Raw false positives: reported issues that match no ground-truth item.
- Duplicate-of-matched: raw false positives that duplicate an already matched
  ground-truth issue or share the same root cause with that matched issue.
- Effective false positives: raw false positives minus duplicate-of-matched
  issues. This is the FP count used for precision and false-positive rate.
- Recall: TP / total ground truth.
- Precision: TP / (TP + effective FP).
- F1: harmonic mean of precision and recall.

The evaluation output includes `matched_pairs`; inspect it before classifying a
miss as a real Z-SCOPE false negative.

## Known Pitfalls

- PowerShell may display UTF-8 Markdown as mojibake when its default decoding is
  used. Re-read with `Get-Content -Encoding utf8` or validate the original bytes
  before treating a file as corrupted; never blindly transcode benchmark docs.
- On 2026-05-12, a WSL preflight reached `--build-cpg` successfully but logged
  `Failed to start clangd: No such file or directory: 'clangd'`, then fell back
  to regex indexing. Install `clangd` in the active Linux environment before
  treating a run as a full unified-backend benchmark result.
- Do not run `make -C test/range clean` in parallel with CMake generation. Both
  touch `test/range/build/`, and the clean step can fail with
  `rm: cannot remove 'build/CMakeFiles': Directory not empty`.
- Keep `analysis.snapshot_dir` project-local (`test/range/.zscope_snapshots`)
  when launching from the repository root; otherwise Z-SCOPE stores scan
  snapshots in the repository-level `.zscope_snapshots/` directory and can
  accidentally reuse state from unrelated runs.
- `GROUND_TRUTH.md` line numbers can drift from current source. The canonical
  line ranges for scoring are in `benchmark/ground_truth.json`.
- Running from `/mnt/c/...` may be slower than a native WSL filesystem. If a tool
  has NTFS path issues, copy the repo into WSL, but keep the command path and
  report paths explicit in the run log.
- Full Z-SCOPE analysis will fail if the LLM placeholders are not replaced.
- The fixture intentionally contains dangerous code such as `system()`. Do not
  pass destructive shell strings when manually running the compiled sample.
