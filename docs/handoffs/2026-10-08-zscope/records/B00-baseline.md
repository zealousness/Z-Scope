# B00 本地基线

日期：2026-10-08（Asia/Taipei）。执行者：当前本地 Codex 会话。

- HEAD（核对开始/结束）：`010f40210b54ba0f79a088312ce5d8be3a82ace0`。
- 分支：`v1.3.1_feat/llm-wiki`；与交接参考一致，没有回滚、切分支或拉取。
- 已跟踪文件初始无修改。原有未跟踪项：本交接目录、`benchmarks/experiments/balanced_confirmed_tp/dashboard/server.pid`、`benchmarks/experiments/balanced_confirmed_tp/m5tpr_replay_results.jsonl`，均保留。
- 适用规范：根 AGENTS.md；发现的其他 AGENTS.md 在 wiki fixture 内，不适用于产品实现。
- 执行目录：`/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope`。
- 解释器：WSL Ubuntu `/home/zeal/venv313/bin/python`，Python 3.13.15，SQLite 3.45.1，glibc 2.39；editable install 指向当前 checkout。系统 Python 3.12 不用于验证。
- 本轮没有实际扫描配置，配置/项目路径以各测试临时目录为准。

## 真实能力与差量

T01 尚缺：search_code 只有 SymbolCatalog 符号检索。read_code 已支持路径和行区间，但 runtime 读取缓存没有文件版本校验。

T02 尚缺：semantic_context 有 resolver 时刷新；无 resolver 仍调用 build_semantic_model_input。SnapshotStore 初始化会创建/迁移数据库；CodeIndex 初始化会启动后端。

T03 权限入口是 ZScopeMcpProvider 与 ToolsRuntime 的 ToolPolicy；provider 默认允许所有注册能力，包括 scan.run。只读 profile 必须约束启动过程、工具、资源和参数，不只改 annotation。

默认 depth 为 fast（配置回归已通过），子 worker 默认关闭，语义 enrichment 为 shadow；当前主动发现为 tools=[] 的单次路径。保留这些策略及六工具、Config v2、主 Ledger freeze 和统一裁决。

## 验证

以下命令均在上述 WSL 目录中用上述解释器执行；测试只使用 fake/临时项目，没有模型请求或正式扫描。

| 命令/检查 | 状态 | 退出码/结果 |
|---|---|---|
| `python -m pytest -q --collect-only tests/test_tool_registry.py tests/test_evidence_tools.py tests/test_tool_schema_strict.py tests/test_tool_policy.py tests/test_tool_use_eval.py tests/test_mcp_policy.py tests/test_mcp_security.py tests/test_active_discovery.py tests/test_candidate_ledger.py tests/test_balanced_rollout.py` | passed | 0；150 collected |
| 同组去掉 `--collect-only` | failed | 1；146 passed、4 failed、0 skipped |
| `python -m pytest -q --collect-only tests/test_config_v2.py tests/test_reference_configs.py tests/test_agent_docs.py` | passed | 0；51 collected |
| 同组去掉 `--collect-only` | passed | 0；51 passed、0 skipped |
| `python -m zscope.mcp.server --help` | passed | 0；当前只有 config、scan-depth 参数 |
| `command -v cmake gcc clang clangd gclang get-bc llvm-link llvm-nm wpa saber` | passed | 0；全部可解析 |
| `ldd` 检查实际 wpa/saber | passed | 0；无 missing shared libraries |
| `git diff --check`（实施前） | passed | 0 |
| 真实模型/正式 benchmark/真实客户端/性能采集 | not_run | 未执行 |

四项既有失败位于 test_balanced_rollout.py：telemetry_state、semantic_shadow、percentage_stage、tampered_signed_state。fixture 固定签发于 2026-07-01，90 天 TTL 于 2026-09-29 到期，而实际检查为 2026-10-08。在独立 Python 诊断进程把 rollout.datetime.now 固定为 2026-07-02，仅重跑这四项：4 passed、13 deselected，退出码 0。该诊断不替代原始失败记录，不改变生产过期策略。实施阶段将只修正测试时钟依赖。

WSL 当前进程三个 Z_SCOPE_LLM_BASE_URL/Z_SCOPE_LLM_MODEL/Z_SCOPE_API_KEY 均未设置（仅检查存在性，不输出值）；真实模型项保持未执行。无需安装依赖即可继续 T01/T02/T03。

AC01：passed。AC16：指标入口已找到（index_audit、llm_usage、report timings），真实性能尚未采集。AC17：没有执行盲扫描或读取 truth，没有把交接/答案注入模型。

implementation_status: baseline_complete

verification_status: completed_with_existing_test_failures

## 续接

从当前 HEAD 增量实现 T01→T02→T03，不覆盖用户产物。各任务新增独立记录，严格区分 mandatory 自动验收与可选真实集成。
