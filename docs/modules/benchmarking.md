---
doc_contract: zscope-module-v1
covers:
  - zscope/benchmarking
sources:
  - zscope/benchmarking/protocol.py
  - scripts/external_benchmark.py
  - scripts/evaluate_range_regression.py
  - scripts/aggregate_range_release_runs.py
  - test/range/Z_SCOPE_TEST_PLAN.md
  - test/range/benchmark/check_entry_coverage.py
tests:
  - tests/test_benchmark_protocol.py
  - tests/test_benchmark_leakage.py
  - tests/test_range_benchmark_harness.py
  - tests/test_range_benchmark_regression.py
  - tests/test_range_release_aggregate.py
---

# Benchmark

## 职责与非职责

本子系统负责统一 benchmark 数据形状、ground truth 匹配、双视图指标、外部 suite 准备/运行、Range 回归和发布结果聚合。`test/range` 是包含故意缺陷的 fixture，用来测量检出与误报，不是待修复的普通 C 项目。

它不负责给扫描模型提供答案，不负责通过定制 benchmark 名称提升规则命中，也不把一次历史成绩写成永久产品事实。

## 主入口和数据流

- `zscope/benchmarking/protocol.py` 提供 `zscope.benchmark.v3` 相关准备、匹配、评估和产物逻辑。
- `scripts/external_benchmark.py` 是外部 suite 和 Range JSON 报告的标准评测入口。
- `scripts/evaluate_range_regression.py` 评估确定性候选的 Range 覆盖。
- `check_entry_coverage.py` 在正式扫描前核对入口覆盖；它可以读取 truth，但不得把 truth 传入扫描 prompt。
- 扫描报告生成后，独立 scorer 读取报告与 ground truth，输出 matched pairs、TP、FN、raw/effective FP、precision、recall 和 F1。
- 发布聚合脚本消费多轮 run 产物并验证稳定性、完整性和门禁。

## 必须保持的不变量

- 扫描上下文与评分答案严格隔离；benchmark leakage 测试必须持续通过。
- 正式 unified 结果要求 Linux 用户态和完整工具链，SVF/Saber 降级结果不能冒充正式结果。
- Windows 主机使用 WSL；原生 Linux 直接运行等价命令；原生 Windows 不形成正式结果。
- `run_auto_unified_wsl.sh` 只用于 WSL，原生 Linux 不调用该脚本。
- scorer 以结构化 file/function/category/location/evidence 匹配，并保留 `matched_pairs` 供人工审计。
- raw FP、duplicate-of-matched 和 effective FP 必须分开保留，不能通过静默删除重复报告美化指标。
- 不在通用规则、Agent prompt 或源码注释中嵌入 truth id、专用函数名或答案描述。

## 常见变更应落到哪里

- 通用 benchmark schema、匹配或产物：`zscope/benchmarking/protocol.py`。
- CLI harness、suite 准备和评估：`scripts/external_benchmark.py`。
- 确定性 Range 回归：`scripts/evaluate_range_regression.py` 和对应测试。
- Range fixture、入口或 truth：`test/range/`，必须同步映射、覆盖预检和版本化评测资产。
- 正式运行协议和环境：`test/range/Z_SCOPE_TEST_PLAN.md`；WSL 限定脚本不得被描述为通用 Linux runner。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_benchmark_protocol.py tests/test_benchmark_leakage.py
python -m pytest -q tests/test_range_benchmark_harness.py tests/test_range_benchmark_regression.py
python -m pytest -q tests/test_range_release_aggregate.py
python scripts/evaluate_range_regression.py --deterministic-candidates
```

完整 LLM/unified 扫描需要有效模型配置和 Linux 工具链，不应作为普通单元测试自动启动。

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- Range 执行、隔离和评分协议以 `test/range/Z_SCOPE_TEST_PLAN.md` 为准。
- 外部 suite 协议见 `docs/progress_docs/external_benchmark_protocol.md`。
- 历史结果只从当次 run 目录和 release 报告读取，不复制到本模块说明。
