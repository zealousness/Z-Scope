# 15 · 本地核验、来源与验证记录

## 本轮依据

日期：2026-10-12。本地分支 `v1.3.1_feat/llm-wiki`；HEAD `010f40210b54ba0f79a088312ce5d8be3a82ace0`；实际依据包含未提交修改/未跟踪实现，不能用 HEAD 唯一复现本轮源码。

本轮以本地代码为主，读取两套设计、架构/相关模块文档、最新 handoff 状态及下列关键模块。不是全仓审计，也未执行正式扫描、模型收益或性能实验。

## 可核对的代码证据

| 结论 | 本地依据 |
|---|---|
| 文件/全文检索和范围读已实现 | [search_code.py](../../../zscope/tools/search_code.py)、[read_code.py](../../../zscope/tools/read_code.py)、source_access.py；test_source_search |
| cache-only 已实现，freshness 有边界 | [semantic_context.py](../../../zscope/tools/semantic_context.py)、registry.py、snapshots/readonly.py；test_semantic_cache_only/test_mcp_read_only |
| 条件契约不是空白 | [contracts.py](../../../zscope/semantics/contracts.py) 的 ApiContract/ObjectBinding/effects_trusted、contract_conditions/compiler；test_conditional_ownership_contracts |
| 调查已有，但通用任务未完成 | [bounded_investigation.py](../../../zscope/orchestration/bounded_investigation.py)、investigation.py、active_discovery.py；test_bounded_investigation/test_investigation_runtime |
| 外部调查仅 offline | [external_investigation.py](../../../zscope/orchestration/external_investigation.py) 的 run_external_investigation；非 offline provider 为 unsupported |
| 需求建模未改变实际调度 | [semantic_demand.py](../../../zscope/orchestration/semantic_demand.py) 的 changes_execution=false/unchanged_full_schedule；semantic_modeling.py 接线 |
| 动态复现已有 runner、缺自动生成器 | [dynamic_reproduction.py](../../../zscope/core/validation/dynamic_reproduction.py) 的 register_dynamic_reproduction_plan_provider/attempt_dynamic_reproduction，runner.py 接缝 |
| 动态/调查等默认关闭 | [runtime_defaults.yaml](../../../zscope/config/runtime_defaults.yaml)：active_investigation、semantic_snapshot_candidate、semantic_model_demand、dynamic_reproduction 为 off；semantic enrichment 为 shadow |
| 当前默认 fast | config/config.py 的 ScanConfig；config/v2.py 的 _load_scan；普通无 managed rollout 状态时默认值为 fast |
| 多变体清单不等于全量事实 | [indexing_inventory.py](../../../zscope/retrieval/indexing_inventory.py) 区分 command identity；[knowledge_db.py](../../../zscope/retrieval/knowledge_db.py) 中 translation_units.file_path UNIQUE |
| 增量 replay 仅事实索引对照 | [incremental_replay.py](../../../zscope/retrieval/incremental_replay.py) 固定 fixture，不执行漏洞扫描/SVF/LLM |
| Wiki 和 Review Memory 已有清晰职责 | [Wiki 模块](../../modules/wiki.md)、[Review Memory 模块](../../modules/review-memory.md) 及对应 service/store |

调用链核对包括单入口 Analyzer、批量 ParallelAnalyzer、ScanSession、语义发布、候选登记以及 ValidationRunner/Pipeline。未读取每个检测器全实现；本计划不宣称所有类别具有对象/代际/路径完整性。

## 历史记录应怎样使用

[旧 TASKS](../../handoffs/2026-10-08-zscope/TASKS.yaml) 与 [PROGRESS](../../handoffs/2026-10-08-zscope/PROGRESS.md) 最新记录表明：

- 搜索/只读 MCP、调查/覆盖、条件模型、shadow 需求规划、索引 replay 已有交付。
- V01/V02 后续经过修订与真实 ASan/TSan 验收，最新状态已完成，不应再引用早期 blocked。
- A01/A02 的离线实现不代表真实外部服务集成；实际模型收益、正式准确率与大仓性能仍需单独测量。
- 历史验收的容器、冻结和审批流程不是本次开发要求，不能从旧记录重新引入重流程。

本轮没有复跑历史 sanitizer/Java/大矩阵，不借用其 passed 数作为新成绩。自动 harness/输入生成、CBMC、完整 overnight UX 仍为计划能力。

## 外部组件资料

仅保留影响本方案选型的一手技术资料，本轮查询用于设计核对；**不意味着产品增加 web 能力**。具体采用版本与本地集成仍待 PoC。

| 来源 | 支持的判断与局限 |
|---|---|
| [Clang 编译数据库规范](https://clang.llvm.org/docs/JSONCompilationDatabase.html) | 同一文件可有多个 command；argv/cwd 必须精确；不提供完整链接目标结论 |
| [Infer/Pulse](https://fbinfer.com/docs/checker-pulse/) | 跨过程内存分析、latent/manifest 问题与 unknown-call 处理；其乐观未知调用策略可能损失召回，不能直接当所有 Z-Scope 对象分析的替代 |
| [Goblint 官方仓库](https://github.com/goblint/analyzer) | C 静态分析候选；能否适配业务扩展/同步模型与证据导出需实测 |
| [CBMC 展开说明](https://diffblue.github.io/cbmc/cprover-manual/md_cbmc-unwinding.html) | bounded 验证与展开范围；未找到反例不自动成为无界安全证明 |
| [GenMC](https://plv.mpi-sws.org/genmc/) | 特定弱内存模型的并发程序验证；平台和模型匹配是接入条件 |
| [ASan](https://clang.llvm.org/docs/AddressSanitizer.html)、[TSan](https://clang.llvm.org/docs/ThreadSanitizer.html) | 各自构建、检测与平台限制；不是全部内存/资源/并发错误的完备验证器 |

旧包大量 Coding 产品实践、权限/沙箱资料与 SDK 链接不再作为本版必要依据。技术取舍是结合源码与目标作出的设计判断，非上述项目对 Z-Scope 效果的保证。

## 本轮实际验证

环境：WSL Ubuntu，`<venv>/bin/python`；核对 editable import 指向本次 checkout。没有使用 Windows Python 形成测试结论。

第一组现状核验：

```bash
python -m pytest -q tests/test_source_search.py tests/test_semantic_cache_only.py \
  tests/test_mcp_read_only.py tests/test_conditional_ownership_contracts.py \
  tests/test_semantic_demand.py tests/test_audit_coverage.py \
  tests/test_external_investigation.py tests/test_dynamic_reproduction.py
```

结果：**351 passed，38.87 秒**。这是相关实现/协议测试，不是本版规划能力或真实扫描性能成绩。

第二组交接/配置/发布与调查回归：

```bash
python -m pytest -q tests/test_agent_docs.py tests/test_config_v2.py \
  tests/test_reference_configs.py tests/test_portable_runtime.py \
  tests/test_portable_release.py tests/test_bounded_investigation.py \
  tests/test_investigation_runtime.py tests/test_incremental_replay.py
python -m compileall -f -q zscope scripts test tests
python -m mypy zscope
```

结果：**201 passed、1 skipped，26.49 秒**；跳过项为 `test_real_mutation_replay`，本轮未设置 `Z_SCOPE_TEST_CLANG_INDEXER`，所以没有形成真实 native 增量回放结论。compileall 退出码 0；mypy 通过（307 个源码文件）。两组测试合计 **552 passed、1 skipped**，不存在把 skipped 计为通过。

文档专项在 WSL 使用严格 UTF-8 解码，检查无 BOM、LF、末尾换行、代码围栏、相对链接、09 删除和任务包验收编号：20 份计划文档、82 个本地链接、61 个验收场景编号，检查无错误。`git diff --check` 通过；计划目录原为未跟踪，因此另行检查其实际字节与链接，不只依赖 Git diff。

## 未执行及结论边界

未执行真实模型扫描、Range trial/formal、真实目标 sanitizer、CBMC/Pulse/Goblint/GenMC PoC、百万行性能、RTOS/目标板验收或 Portable 构建/smoke。没有新的 precision/recall/性能结论。

本次只更新计划及 AGENTS/模块导航；产品源码、已有用户修改、原专业概念包和历史验收记录保持原状。
