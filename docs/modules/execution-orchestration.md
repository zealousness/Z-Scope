---
doc_contract: zscope-module-v1
covers:
  - zscope/cli
  - zscope/orchestration
  - zscope/workflows
sources:
  - zscope/cli/cli.py
  - zscope/orchestration/scan_session.py
  - zscope/orchestration/workflow_runner.py
  - zscope/orchestration/workflow_executor.py
  - zscope/workflows/default.yaml
tests:
  - tests/test_cli_output.py
  - tests/test_workflow_runner.py
  - tests/test_workflow_specs.py
  - tests/test_scan_session_resume_svf.py
---

# 执行与编排

## 职责与非职责

本子系统负责把 CLI 选项和配置转换为一次可执行扫描：选择运行模式、发现或加载入口、规划 diff impact、恢复/维护批量任务、调度并发分析、执行声明式 Workflow，并汇总运行进度。

它不负责生成底层代码事实、实现具体候选规则、决定最终报告结构或直接维护运行时 Agent prompt。

## 主入口和数据流

- `zscope/cli/cli.py` 解析 `--resume`、`--maintain`、`--diff-*`、WebUI、MCP、SARIF 和索引预热等入口参数。
- `ScanSessionRunner` 把显式入口、自动发现入口或 diff impact 入口统一成扫描会话。
- `WorkflowRunner` 创建单入口运行态并调用 `WorkflowExecutor`。
- `zscope/workflows/*.yaml` 只声明阶段顺序；具体 handler 由 Python 编排层提供。
- 批量任务经 scheduler/parallel analyzer 分发，最终结果交给报告层装配。

## 必须保持的不变量

- `--resume`、`--maintain` 和 diff impact 的互斥规则必须在真正开始扫描前验证。
- `analysis.workflow_name` 是运行时字段，不允许作为用户 YAML 配置项。
- 没有匹配入口的 diff path 应明确停止，不能静默回退到 `main`。
- 入口发现、断点续扫、历史报告备份和取消状态必须保持可审计。
- Workflow 文件和 handler 名称必须一一对应，未知 step 应明确失败。

## 常见变更应落到哪里

- 新 CLI 选项或模式分流：`zscope/cli/cli.py`，并检查配置、服务入口和退出码。
- 入口发现或 diff 选根：`entry_discovery.py`、`diff_impact.py`、`scan_session.py`。
- 扫描调度、并发、取消和预算：`scheduler.py`、`parallel_analyzer.py`、`budget.py`。
- 新 Workflow 阶段：添加/调整 `zscope/workflows/*.yaml`，同时实现并注册 handler。
- 单入口运行态和阶段装配：`workflow_runner.py`、`workflow_executor.py`。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_cli_output.py tests/test_workflow_runner.py tests/test_workflow_specs.py
python -m pytest -q tests/test_entry_discovery.py tests/test_diff_impact.py tests/test_scan_scheduler.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 完整运行流程见 `docs/architecture.md` 的“运行时主流程”和“控制平面”。
- 用户可见命令和模式见 `README.md` 的端到端使用指南。
