# 代码落点与核对地图

参考提交：`010f40210b54ba0f79a088312ce5d8be3a82ace0`。文件路径以仓库根为准。`已读` 表示当前或上一轮已读取具体源码／文档；`文档定位` 表示路径由仓库模块文档或 tree 指向，仍须本地读取实现。下列路径不是要求全部修改的清单。

| 地图 ID | 路径／符号 | 事实与建议切入点 | 核对级别 |
|---|---|---|---|
| CM01 | `AGENTS.md`；`pyproject.toml`；`zscope/config/runtime_defaults.yaml` | 根规范、Python ≥3.13、质量命令、Config v2 与 RuntimeSpec 边界；默认子 worker 关闭 | 已读 R01、R02、R17 |
| CM02 | `zscope/tools/search_code.py`；`read_code.py`；`semantic_context.py`；`registry.py` | 符号检索、已有路径读文件、resolver 刷新、六工具注册；T01/T02 首要落点 | 已读 R03～R05、R18 |
| CM02 | `zscope/tools/contracts.py`；`policy.py`；`runtime.py`；`symbols.py` | schema 生成／校验、路径与权限、coverage、symbol identity；新增逻辑先查这里 | 文档定位 R16 |
| CM03 | `zscope/orchestration/active_discovery.py` | DiscoveryProfile、ActiveDiscoveryAgent、candidate_blind_prompt_projection、fit_candidate_blind_prompt_projection、_validate_report、Coordinator | 已读 R06 |
| CM03 | `zscope/orchestration/subagents.py`；`candidates.py`；`parallel_analyzer.py`；`zscope/semantics/security_map.py` | 调查执行复用、候选登记、scan-level freeze、审计单元；调用方必须本地核对 | 文档定位 R10、R13 |
| CM04 | `zscope/orchestration/semantic_modeling.py`；`modeling_coordinator.py`；`snapshot_candidates.py` | 可达并集建模、任务去重／SCC、怀疑点适配；不是新建第二套建模流程 | snapshot adapter 已读 R14，其余 R10 文档定位 |
| CM04 | `zscope/wiki/service.py`；`zscope/wiki/context/`；`zscope/semantics/`；`zscope/snapshots/` | 固定 Wiki revision、契约资格、快照身份；具体定义先查当前调用链 | 文档定位 R12、R13 |
| CM05 | `zscope/retrieval/clang_batch.py`；`indexing_identity.py`；`indexing_inventory.py`；`clang_backend.py`；`knowledge_db.py` | 批量事实、变体 inventory、原子发布、派生事实失效 | 文档定位 R08、R09 |
| CM05 | `zscope/retrieval/bitcode_scope.py`；`build_llvm.py`；`svf_analyzer.py`；`unified_backend.py` | 入口裁剪、TU／bitcode、WPA/Saber／资源预算；先测瓶颈再改算法 | 文档定位 R09 |
| CM05 | `zscope/orchestration/entry_discovery.py`；`callback_discovery.py`；`diff_impact.py` | 根入口、回调与 diff 范围；D03/P01 需保持既有身份和覆盖 | 文档定位 R10、R11 |
| CM06 | `zscope/core/validation/pipeline.py`；`runner.py`；`evidence_completion.py`；`review_protocol.py`；`review_checks.py`；`zscope/common/validator_protocol.py` | V0～V3、程序检查、现有追加发现协议；禁止并行创建第二套终态 | 文档定位 R13 |
| CM06 | `zscope/reporting/immutable_evidence.py`；`shared_objects.py`；`assembler.py`；`json_io.py`；`sarif_exporter.py` | 不可变证据、共享报告、旧新封套读取、SARIF 归因；产物读写不能直接假设 json.load | 文档定位 R15 |
| CM07 | `zscope/mcp/provider.py`；`server.py`；`http_server.py`；`security.py`；`zscope/cli/cli.py` | 现有 server/provider、scan control、只读资源、安全边界和真实启动命令 | 文档定位 R15 |
| CM08 | `scripts/`；`zscope/benchmarking/`；`zscope/cli/index_audit.py`；`docs/modules/benchmarking.md` | 优先扩展现有审计／benchmark 入口；index-audit 已列为 console script | R02 已读，其余文档定位 |
| CM09 | `tests/` 新建隔离 fixture；验证 provider 与 runner 的具体模块待本地决定 | V01/V02 先复用验证层，执行器位置是设计选择而非已存在事实 | 拟新增／本地决策 |
| CM10 | `zscope/rules/builtin_catalog.yaml`；`catalog.py`；`extensions.py`；`docs/rule-development.md` | 规则 canonical identity/revision、YAML pack/provider 和资格；R02 规则试验复用 | 文档定位 R01、R13 |

## 已确认的代码细节

**主动发现不是完整多轮调查**：`ActiveDiscoveryAgent` 构造 `tools=[]`，默认 `max_iterations=1`，使用 single-pass final tool；两个发现 profile 的 max_agent_iterations 均为 1。新增证据的报告校验当前限制在原 projection。见 R06（已读区间 1～180、1250～1405、1550～1770）。

**全文搜索不等于符号 regex**：`SearchCodeTool` 以 SymbolCatalog.search 实现并返回 symbols；当前 regex 属于符号名匹配。T01 不应复制这条路径导致全文模式先遍历所有符号。见 R03。

**已有文件读取**：`READ_CONTRACT` 允许 symbol_id 或 file_path 二选一；file_path 必须带 start_line，execute 分派 `_read_file`。见 R04（本轮读取 1～205）。

**现有 semantic_context 有副作用**：resolver 存在时会调用并检查持久快照；没有 resolver 也有 build_semantic_model_input 调用。MCP 标记 non-readonly/open-world。见 R05（本轮读取 1～235）。

**运行时配置不属于用户 YAML**：根规范明确 Agent 启停、预算、deadline、缓存／报告策略由 RuntimeSpec 管理，开发模式可覆盖；不能新增用户顶层 analysis。见 R01、R17。

## 已知测试导航（尚未在本次执行）

| 领域 | 模块文档给出的测试入口 |
|---|---|
| 工具 | `tests/test_evidence_tools.py`、`test_tool_registry.py`、`test_tool_schema_strict.py`、`test_tool_use_eval.py`、`test_tool_policy.py` |
| MCP | `tests/test_mcp_policy.py`、`test_mcp_security.py`、`test_mcp_http_server.py` |
| 发现 | `tests/test_active_discovery.py`、`test_candidate_ledger.py`、`test_balanced_rollout.py` |
| 索引 | `tests/test_clang_batch.py`、`test_clang_identity_validation.py`、`test_indexing_performance_audit.py`、`test_svf_cache.py` |
| 建模 | `tests/test_incremental_semantic_modeling.py`、`test_wiki_workflow.py` |
| 验证 | `tests/test_validation_runner.py`、`test_validator_v3_protocol.py`、`test_review_fact_checks.py`、`test_review_experiment_protocol.py` |

这些路径用作本地发现入口，不代表所有测试都无外部依赖。先 collect／阅读 skip 条件，再分类执行。
