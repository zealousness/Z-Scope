---
doc_contract: zscope-module-v1
covers:
  - zscope/benchmarking
sources:
  - zscope/benchmarking/protocol.py
  - zscope/benchmarking/runner.py
  - zscope/cli/benchmark.py
  - scripts/external_benchmark.py
  - scripts/evaluate_range_regression.py
  - scripts/aggregate_range_release_runs.py
  - scripts/check_benchmark_hygiene.py
  - scripts/evaluate_release_candidate.py
  - docs/range-benchmark.md
  - test/range/benchmark/check_entry_coverage.py
tests:
  - tests/test_benchmark_protocol.py
  - tests/test_benchmark_leakage.py
  - tests/test_benchmark_runner.py
  - tests/test_range_benchmark_regression.py
  - tests/test_range_release_aggregate.py
  - tests/test_formal_benchmark_runner.py
  - tests/test_release_contract.py
---

# Benchmark

## 职责与非职责

本子系统负责统一 benchmark 数据形状、ground truth 匹配、双视图指标、外部 suite 准备/运行、Range 回归和发布结果聚合。`test/range` 是包含故意缺陷的 fixture，用来测量检出与误报，不是待修复的普通 C 项目。

它不负责给扫描模型提供答案，不负责通过定制 benchmark 名称提升规则命中，也不把一次历史成绩写成永久产品事实。

## 主入口和数据流

- `zscope/benchmarking/protocol.py` 提供 `zscope.benchmark.v3` 相关准备、匹配、评估和产物逻辑。
- `zscope-benchmark` 是内置 fixture 的唯一公开入口；`smoke`、`trial`、`formal` 分别承担离线结构门禁、单轮预览和至少五轮的发布门禁。
- `scripts/external_benchmark.py` 是外部 suite 和 Range JSON 报告的标准评测入口。
- `scripts/evaluate_range_regression.py` 评估确定性候选的 Range 覆盖。
- `check_entry_coverage.py` 在正式扫描前核对入口覆盖；它可以读取 truth，但不得把 truth 传入扫描 prompt。
- 扫描报告生成后，独立 scorer 读取报告与 ground truth，输出 matched pairs、TP、FN、raw/effective FP、precision、recall 和 F1。
- 发布聚合脚本消费多轮 run 产物并验证稳定性、完整性和门禁。
- `zscope/benchmarking/runner.py` 在 WSL 原生临时文件系统运行 C/C++ scan/state，再导出 artifact；它分别记录 scan wall 与 end-to-end wall、验证队列/API call telemetry、双质量视图、命令哈希、Git tree、输入文件清单和 provenance。正式 Release 按 workflow run ID 下载不可变 artifact，并由 `scripts/evaluate_release_candidate.py` 校验 SHA、输入清单、truth 隔离和门禁。仓库归档只用于历史基线。

## 必须保持的不变量

- 扫描上下文与评分答案严格隔离；benchmark leakage 测试必须持续通过。
- 正式 unified 结果要求 Linux 用户态和完整工具链，SVF/Saber 降级结果不能冒充正式结果。
- Windows 主机使用 WSL；原生 Linux 直接运行等价命令；原生 Windows 不形成正式结果。
- `test/` 不包含执行 runner、历史报告或后台 launcher；fixture 根每种语言只保留一份正式配置。
- C/C++ formal 不读取 deterministic entry manifest，入口必须由隔离副本中的自动发现产生。
- scorer 以结构化 file/function/category/location/evidence 匹配，并保留 `matched_pairs` 供人工审计。
- raw FP、duplicate-of-matched 和 effective FP 必须分开保留，不能通过静默删除重复报告美化指标。
- 性能门禁只读取 `scan_wall_seconds`；`end_to_end_wall_seconds` 单独展示，`wall_seconds` 仅作为历史 v2 artifact 的兼容别名。
- confirmed 与 with-review 的 recall/precision 必须同时展示，旧顶层 `recall` 只能解释为 confirmed 兼容视图。
- 不在通用规则、Agent prompt 或源码注释中嵌入 truth id、专用函数名或答案描述。
- 正式 benchmark 结果不得通过提交到发布 SHA 自身来完成绑定；Release 必须消费受保护 Environment 产生、名称和内部 `git_sha` 均匹配发布 SHA 的不可变 workflow artifact。

## 常见变更应落到哪里

- 通用 benchmark schema、匹配或产物：`zscope/benchmarking/protocol.py`。
- CLI harness、suite 准备和评估：`scripts/external_benchmark.py`。
- 确定性 Range 回归：`scripts/evaluate_range_regression.py` 和对应测试。
- Range fixture、入口或 truth：`test/range/`，必须同步映射、覆盖预检和版本化评测资产。
- 正式运行协议和环境：`docs/range-benchmark.md` 与 `docs/java-benchmark.md`。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_benchmark_protocol.py tests/test_benchmark_leakage.py
python -m pytest -q tests/test_benchmark_runner.py tests/test_range_benchmark_regression.py
python -m pytest -q tests/test_range_release_aggregate.py
python scripts/check_benchmark_hygiene.py
python scripts/evaluate_range_regression.py --deterministic-candidates
```

完整 LLM/unified 扫描需要有效模型配置和 Linux 工具链，不应作为普通单元测试自动启动。

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- Range 执行、隔离和评分协议以 `docs/range-benchmark.md` 为准。
- 外部 suite 协议见 `docs/progress_docs/external_benchmark_protocol.md`。
- 历史结果只从当次 run 目录和 release 报告读取，不复制到本模块说明。
