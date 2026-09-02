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
  - zscope/orchestration/hypothesis_hunter
  - zscope/orchestration/rollout.py
  - zscope/orchestration/decision_trace.py
  - zscope/orchestration/workflow_runner.py
  - zscope/orchestration/workflow_executor.py
  - zscope/workflows/default.yaml
tests:
  - tests/test_balanced_rollout_operator.py
  - tests/test_cli_output.py
  - tests/test_workflow_runner.py
  - tests/test_workflow_specs.py
  - tests/test_scan_session_resume_svf.py
  - tests/test_p5_runtime_authority.py
  - tests/test_p4_hypothesis_hunter.py
  - tests/test_p4_hypothesis_lifecycle.py
  - tests/test_balanced_rollout.py
  - tests/test_decision_trace.py
  - tests/test_workflow_executor.py
  - tests/test_cli_ruledriven_p1.py
---

# 执行与编排

## 职责与非职责

本子系统负责把 CLI 选项和配置转换为一次可执行扫描：选择运行模式、发现或加载入口、规划 diff impact、恢复/维护批量任务、调度并发分析、执行声明式 Workflow，并汇总运行进度。

它不负责生成底层代码事实、实现具体候选规则、决定最终报告结构或直接维护运行时 Agent prompt。

## 主入口和数据流

- `zscope/cli/cli.py` 解析 `--resume`、`--maintain`、`--diff-*`、`--scan-depth`、WebUI、MCP、SARIF 和索引预热等入口参数。
- `ScanSessionRunner` 把显式入口、自动发现入口或 diff impact 入口统一成扫描会话。
- `WorkflowRunner` 创建单入口运行态并调用 `WorkflowExecutor`。
- `zscope/workflows/*.yaml` 只声明阶段顺序；具体 handler 由 Python 编排层提供。P1 的稳定阶段分别是 default `discover_entries → collect_candidates → validate_candidates → persist_report`、resume `discover_entries → plan_resume → run_pending_entries → merge_reused_reports`、maintain `discover_entries → compare_entry_state → reuse_unchanged_report → reconcile_history → run_changed_entry`。
- 批量任务经scheduler/parallel analyzer分发。所有档位先运行authoritative SecuritySpec compilation和确定性候选；balanced/deep再运行Hunter并把选择强制未确认登记到同一live Ledger，fast固定不运行Hunter。全部producer结束后freeze Ledger，再由Proof Engine/Checker/TerminalAuthority逐cluster关闭。单入口保持同样顺序。
- `DecisionTraceStore` 由单次扫描共享：Candidate Ledger、coverage planner、ValidationRunner、usage ledger 与 Finding-root 投影只追加结构化事件/内容寻址对象，最终生成一个可离线校验的 manifest。

## 必须保持的不变量

- `--resume`、`--maintain` 和 diff impact 的互斥规则必须在真正开始扫描前验证。
- `analysis.workflow_name` 是运行时字段，不允许作为用户 YAML 配置项。
- 没有匹配入口的 diff path 应明确停止，不能静默回退到 `main`。
- 入口发现、断点续扫、历史报告备份和取消状态必须保持可审计。
- 批量完整性检查必须以实际物化并调度的入口身份对齐结果，不能用签名不完整的原始入口把已完成任务误判为中断。
- Workflow 文件和 handler 名称必须一一对应，包括声明为 optional 的 step；每个声明 step 必须精确产生一条 `completed`、`skipped` 或 `failed` 记录，停止策略跳过的后续 step 必须携带原因。
- C/C++ `--mode ruledriven` 必须在创建索引或模型调用前拒绝并指向默认 Candidate Ledger；Java 暂时保留 ruledriven。
- `fast` 不运行语义补全或主动发现；它们未启用时不能误标 partial。balanced/deep 中已启用阶段因超时、取消、provider/工具故障跳过审计单元时必须保存已得结果、标记 `completeness=partial`，CLI 退出码为 2。
- scan-wide token usage ledger 必须在配置生效边界创建一次并注入所有入口、Agent 和 LLM profile，不能为并行入口各建一份账本。它只计量，不按产品硬预算停止调用。
- Ledger 必须在全部 producer 结束后显式 freeze；freeze 后不能登记新候选。每个 terminal cluster 和无候选 audit unit 都必须分别有 decision/coverage trace，usage call ID 与 token 总数必须和 JSONL sidecar 守恒。
- resume/maintain只能复用相同P5 cache epoch、RuntimeAuthorityManifest和完整terminal trace的报告；P5前cache/report/snapshot只允许compat展示或历史复核，不能形成新证据。
- 历史P5 `complete`只作为旧候选lineage；当前源码必须同时具备fresh combined successor qualification和精确独立审核evidence。缺少后者时扫描仍可执行P6 non-release qualification，但报告release gate固定加入`successor_review_not_current`。
- 每个cluster恰好一个terminal event；SecuritySpec、Hunter和Proof refs附加到该事件，不得由任何producer创建第二个terminal-authority事件。

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
python -m pytest -q tests/test_p5_runtime_authority.py
python -m pytest -q tests/test_balanced_rollout.py tests/test_balanced_rollout_operator.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 完整运行流程见 `docs/architecture.md` 的“运行时主流程”和“控制平面”。
- 用户可见命令和模式见 `README.md` 的端到端使用指南。
