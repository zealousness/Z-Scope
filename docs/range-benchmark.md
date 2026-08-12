# Range C/C++ benchmark protocol

## 唯一入口

所有本地与发布执行都通过 `zscope-benchmark`：

```bash
zscope-benchmark run --language c_cpp --mode smoke
zscope-benchmark run --language c_cpp --mode trial
zscope-benchmark run --language c_cpp --mode formal --runs 5
```

`smoke` 不调用 LLM，只验证 fixture、配置、truth、CMake 构建和结构门禁；
`trial` 恰好执行一次冷扫描且永远不具备发布资格；`formal` 拒绝少于五轮并执行发布门禁。Windows 上 C/C++ 命令自动转入 WSL，Linux 直接执行。

## 真源与输入隔离

`test/range/benchmark/ground_truth.json` 是唯一评分真源。当前机器校验要求其版本为 v14，`total_vulnerabilities` 与 136 条记录及唯一 ID 一致；文档不维护另一份漏洞表。

每轮从 fixture 复制严格 allowlist：`src/**`、`include/**`、`internal/**`、`CMakeLists.txt` 和中性 README。整个 `benchmark/`、报告、缓存、构建目录和本地运行历史都不能进入 scan-input。health/index/scan 环境不含 truth 路径，报告落盘后才由独立 score 子进程读取 truth。

`benchmark/deterministic_entries.json` 只服务无 LLM 的确定性候选回归，不是 fixed-entry 正式协议，也不参与自动入口发现。

## 环境与门禁

C/C++ trial/formal 需要 Linux 用户态以及 CMake、clangd、gclang、get-bc、LLVM、SVF/Saber 全工具链，并要求显式设置 `Z_SCOPE_LLM_BASE_URL`、`Z_SCOPE_LLM_MODEL` 和 `Z_SCOPE_API_KEY`。任何深度工具缺失都会失败，不允许以降级结果形成 unified 结论。

在 WSL 中，trial/formal 会把 scan-input、构建目录、索引和 Z-SCOPE 状态放到 WSL 原生文件系统的临时工作区，结束后只把密封输入、日志、报告和评分结果导出到 `benchmark-artifacts/`。可用绝对路径环境变量 `Z_SCOPE_BENCHMARK_WORK_ROOT` 覆盖临时根；C/C++ 会拒绝 `/mnt/<drive>`，避免 DrvFS I/O 进入正式性能结果。C 配置固定使用 4 个 Validator worker，同时全局 LLM 与单 endpoint 上限仍为 4。

计时口径显式拆分：`scan_wall_seconds` 来自扫描报告的 `summary.batch_wall_seconds`，是 3600 秒发布门禁和跨轮比较指标；`end_to_end_wall_seconds` 是 runner 从输入准备到评分完成的总耗时。兼容字段 `wall_seconds` 等于 `scan_wall_seconds`。artifact 另记录验证队列 wall time、session/API call 数和实际 Validator/LLM 并发配置。

质量也必须按两种视图读取：`confirmed_recall`/`confirmed_precision` 只统计已确认 finding，`with_review_recall`/`with_review_precision` 将 needs-review 纳入人工复核队列。旧顶层 `recall` 仅是 confirmed 视图的兼容字段，不能称为“总召回”；两种视图的完整计数保存在 `quality_views`。

正式 artifact 保持 `zscope.formal-benchmark.v2`，并附加输入文件 SHA-256、manifest SHA-256、canonical phase argv、RuntimeSpec、Rule Catalog 和配置 provenance。Release evaluator 验证这些字段和 truth 隔离；历史 v2 artifact 不改写。

## 清理

```bash
zscope-benchmark clean --scope c_cpp
zscope-benchmark clean --scope c_cpp --apply
zscope-benchmark clean --scope c_cpp --apply --include-runs
```

清理默认只预览。`--apply` 仅处理声明过的生成目录/文件；大型 runs、CodeQL 和 conversation 必须再给 `--include-runs`。tracked 文件、local env/config、SARIF、越界路径和符号链接永久受保护。

## 旧命令迁移

| 旧入口 | 新入口 |
| --- | --- |
| auto unified WSL runner | `zscope-benchmark run --language c_cpp --mode trial` |
| fixed-entry scan runner | `scripts/evaluate_range_regression.py` 的确定性回归；不再是 LLM benchmark |
| formal Python script | `zscope-benchmark run --language c_cpp --mode formal --runs 5` |
| background/alert/rebuild runner | 已删除；使用 foreground artifact 或专用产品命令 |

Global-model 诊断保存在 `benchmarks/experiments/range_global_model/`，明确为非发布实验。
