---
doc_contract: zscope-module-v1
covers:
  - zscope/cli
  - zscope/orchestration
  - zscope/workflows
sources:
  - scripts/balanced_rollout_operator.py
  - zscope/cli/cli.py
  - zscope/orchestration/scan_session.py
  - zscope/orchestration/parallel_analyzer.py
  - zscope/orchestration/rollout.py
  - zscope/orchestration/workflow_runner.py
  - zscope/orchestration/workflow_executor.py
  - zscope/workflows/default.yaml
tests:
  - tests/test_balanced_rollout_operator.py
  - tests/test_cli_output.py
  - tests/test_workflow_runner.py
  - tests/test_workflow_specs.py
  - tests/test_scan_session_resume_svf.py
  - tests/test_wiki_workflow.py
  - tests/test_active_discovery.py
  - tests/test_balanced_rollout.py
---

# 执行与编排

## 职责与非职责

本子系统负责把 CLI 选项和配置转换为一次可执行扫描：选择运行模式、发现或加载入口、规划 diff impact、恢复/维护批量任务、调度并发分析、执行声明式 Workflow，并汇总运行进度。

它不负责生成底层代码事实、实现具体候选规则、决定最终报告结构或直接维护运行时 Agent prompt。

## 主入口和数据流

- `zscope/cli/cli.py` 解析 `--resume`、`--maintain`、`--diff-*`、`--scan-depth`、WebUI、MCP、SARIF 和索引预热等入口参数。
- `ScanSessionRunner` 把显式入口、自动发现入口或 diff impact 入口统一成扫描会话。
- `WorkflowRunner` 创建单入口运行态并调用 `WorkflowExecutor`。
- `zscope/workflows/*.yaml` 只声明阶段顺序；具体 handler 由 Python 编排层提供。内置扫描 workflow 在入口发现后先执行一次 session 级 `wiki_compile`，该阶段完整结束后才允许进入任何 entry 分析或 Validator 验证。
- 批量任务经 scheduler/parallel analyzer 分发。确定性候选完成后，balanced/deep 在全局验证之前依次构建 Security Semantic Map、规划 coverage gap、登记主动发现 hypothesis；所有来源统一冻结 Ledger，最后按 validation cluster 验证和装配报告。单入口必须保持同样的阶段顺序。

## 必须保持的不变量

- `--resume`、`--maintain` 和 diff impact 的互斥规则必须在真正开始扫描前验证。
- `analysis.workflow_name` 是运行时字段，不允许作为用户 YAML 配置项。
- 没有匹配入口的 diff path 应明确停止，不能静默回退到 `main`。
- 入口发现、断点续扫、历史报告备份和取消状态必须保持可审计。
- 批量完整性检查必须以实际物化并调度的入口身份对齐结果，不能用签名不完整的原始入口把已完成任务误判为中断。
- Workflow 文件和 handler 名称必须一一对应，未知 step 应明确失败。
- 启用 Wiki 时，每个 scan session 只能编译并固定一次 `ProjectKnowledgeService`；所有入口和 scan-level Validator 共享该只读实例，入口 Analyzer 不得再次编译或提前关闭它，session 结束后统一释放。
- `fast` 不运行语义补全或主动发现；它们未启用时不能误标 partial。balanced/deep 中已启用阶段因预算跳过审计单元时必须保存已得结果、标记 `completeness=partial`，CLI 退出码为 2。
- scan-wide token manager 必须在配置生效边界创建一次并注入所有入口、Agent 和 LLM profile，不能为并行入口各建一份预算。

## Balanced 持久灰度决策

`BalancedRolloutController` 以严格版本化 JSON 原子保存 `telemetry_only → validator_opt_in → semantic_shadow → 10 → 50 → 100 → balanced_default` 的观察和决策。每次晋级至少要求当前阶段持续 7 天并覆盖 20 个不同项目，`100` 阶段还要求两个稳定窗口；token 守恒、归因完整或无 proof 静默拒绝任一硬不变量失败时立即回退 fast，用户阈值连续两个窗口越界时同样回退。状态记录 decision/observation 的 owner、reason 和 UTC timestamp。

`scripts/balanced_rollout_operator.py` 是该状态机唯一的离线 operator 入口。先在受保护控制面通过进程环境注入至少 32 bytes 的 `Z_SCOPE_BALANCED_ROLLOUT_HMAC_KEY`，再用 `initialize --state-file ... --owner ... --reason ...` 建立 telemetry 观察期；密钥没有 CLI/YAML 参数，也不会进入 stdout、报告或错误正文。`record` 还必须同时传入控制面读取到的 `--expected-state-sha256` 和一个严格的 `zscope.rollout-observation-window.v1` 文件。controller 在跨进程文件锁内完成验签、SHA 比较、决策、重新签名和原子替换；竞争更新只有一个能提交，成功结果同时返回 previous/state/window-file SHA。签名信封使用 HMAC-SHA256，绑定 schema、policy、C/C++ 语言、release identity、与 decision 历史一致的单调 sequence、签发时间和最长 90 天有效期。可选 `Z_SCOPE_BALANCED_ROLLOUT_RELEASE_ID` 必须由 operator 和 scanner 使用相同值；省略时绑定当前 Z-SCOPE 版本。operator 不执行用户命令、不连接遥测，也不根据窗口内容之外的信息自证 precision、token 守恒或其他指标。Observation Window 必须由中央受保护控制面从独立审计数据生成、审核并签发；控制面随后按输出 hash 校验完整状态文件，并把同一文件分发为各项目 `${snapshot_dir}/balanced_rollout_state.json`。项目扫描器只消费该只读快照，不能运行 operator 来为自己的指标背书。

安装了 `${snapshot_dir}/balanced_rollout_state.json` 后，所有入口在创建 scan-wide token manager 之前统一应用该决策。只有 scanner 进程持有相同管理密钥且信封验签、release identity、有效期与内部状态全部通过时，状态才是 managed：telemetry 强制 fast；validator opt-in 只允许显式 balanced/deep 且不运行语义/发现；semantic shadow 运行但把主动发现终态保存为 `shadow_observation`；10/50/100 使用 `project.id` 的稳定 SHA-256 bucket 做确定性 enrollment；`balanced_default` 才把 C/C++ 省略档位解析为 balanced。缺少密钥、裸状态、篡改、过期或 identity 不匹配均把文件视为 unmanaged：省略档位保持 fast，但用户显式 `--scan-depth balanced|deep` 不被项目本地文件阻断。未安装状态文件同样表示尚未启用受管灰度。Java 始终服从独立语言门禁。

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
python -m pytest -q tests/test_active_discovery.py
python -m pytest -q tests/test_balanced_rollout.py tests/test_balanced_rollout_operator.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 完整运行流程见 `docs/architecture.md` 的“运行时主流程”和“控制平面”。
- 用户可见命令和模式见 `README.md` 的端到端使用指南。
