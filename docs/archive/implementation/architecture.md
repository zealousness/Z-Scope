# 架构优化实施记录

> **历史文档，2026-11-17 整理归档。** 原位置：`new_docs/stage1optimation/architecture_optimation.md`。正文中的状态、接口、路径、测试与后续建议保留记录时含义；当前说明见[文档总导航](../../README.md)，本类记录见[归档索引](README.md)。

## 2026-07-03

### 已完成 全局语义建模

- 在 `AnalysisConfig` 中新增 `analysis.enable_global_model`，默认值为 `False`。
- 在配置加载逻辑中支持从 `zscope.yaml` 读取 `analysis.enable_global_model`。
- 在 `zscope.yaml` 中新增默认配置项 `enable_global_model: false`。
- 为新增配置开关补充了 ConfigLoader 回归测试。

### 测试

- `python -m pytest tests/test_reporting_config.py -q` 通过：4 个测试。
- `python -m py_compile zscope/config/config.py` 通过。

### 备注

- 保留了 `zscope.yaml` 中已有的 `max_recursion_depth` 注释修改和 `max_premodel_callees: 5` 配置。

### 已完成

- 新增 `zscope/orchestration/global_modeler.py`。
- 使用 `FunctionKey(name, file_path)` 实现跨 entry 的可达调用图收集。
- 实现支持 SCC 的 ready-queue 调度：只有子组件完成后，父组件才会被提交建模。
- 复用已有 lightweight/trivial 函数的确定性 snapshot 构造逻辑。
- 通过注入 factory 的方式复用已有 `SemanticModeler` 处理非 trivial 函数。
- 增加全局建模统计计数，包括可达函数数、缓存命中数、确定性 snapshot 数、LLM snapshot 数、截断数、SCC 数、失败数、token 数和耗时。

### 测试

- `python -m pytest tests/test_global_modeler.py -q` 通过：3 个测试。
- `python -m py_compile zscope/orchestration/global_modeler.py` 通过。

### 计划偏差 / 问题记录

- 阻塞性问题，已修复：调用图收集阶段在获取函数实现后会将函数 canonicalize 为带文件路径的 key，但父节点边仍可能指向 canonicalize 前的 key，导致依赖边丢失，并允许 parent 在 callee 之前建模。已在图收集结束后增加边 canonicalization。
- 非阻塞已知限制：现有 snapshot lock 仍然只使用函数名作为锁 key。当前实现保留原行为，但还没有完全解决不同文件中同名函数的互相影响问题。

### 已完成

- 在 `ParallelAnalyzer` 中接入全局建模，并由 `analysis.enable_global_model` 控制。
- 全局建模会在 shared semantics warmup 之后、entry worker fan-out 之前运行。
- 当 `enable_global_model` 为 `False` 时，entry workflow 保持原有行为。
- 当 `enable_global_model` 为 `True` 时，per-entry 的 `premodel_reachable_callees` 会被跳过，因为 batch-level 全局建模阶段已经覆盖了可达 callees。
- 当 `enable_global_model` 为 `True` 时，per-entry 的 `model_entry` 会优先复用全局建模生成的当前 entry snapshot。如果 entry snapshot 缺失或已过期，则回退到原始 `model_entry` 逻辑。
- 增加降级保护：如果全局建模在 entry fan-out 前失败，entry-specific config 会临时关闭 `enable_global_model`，并使用原有 per-entry 建模路径。

### 测试

- `python -m pytest tests/test_global_modeler.py tests/test_parallel_shared_semantics.py tests/test_reporting_config.py -q` 通过：12 个测试。
- `python -m py_compile zscope/config/config.py zscope/orchestration/global_modeler.py zscope/orchestration/parallel_analyzer.py zscope/core/analysis/analyzer.py` 通过。

### 计划偏差 / 问题记录

- 阻塞性问题，已修复：新版全局调用图收集器最初没有保留 `max_premodel_callees=-1` 表示无限制的配置语义。现在当配置值为负数时，会使用较大的内部查询上限，并关闭 breadth cap。
- 阻塞性问题，已修复：第一版全局建模允许 entry 函数使用 deterministic trivial/lightweight snapshot，这不符合保留原始 `model_entry` 行为的要求。现在 entry 函数强制走 `SemanticModeler` 路径；deterministic trivial/lightweight snapshot 仍然用于非 entry callees。

### 测试

- `python -m pytest tests/test_global_modeler.py tests/test_parallel_shared_semantics.py tests/test_reporting_config.py tests/test_workflow_runner.py tests/test_analyzer_semantics.py -q` 通过：48 个测试。
- `python -m py_compile zscope/config/config.py zscope/orchestration/global_modeler.py zscope/orchestration/parallel_analyzer.py zscope/core/analysis/analyzer.py` 通过。

### 已完成

- 修复 snapshot lock 粒度问题：`SnapshotLockManager` 现在支持按 `func_name + file_path` 生成锁 key。
- 保留旧接口兼容性：未传入 `file_path` 时仍按函数名加锁。
- 修复全局语义建模路径：`GlobalModeler` 在建模同名不同文件函数时使用具体实现文件路径加锁。
- 修复 per-entry 语义建模路径：
  - on-demand snapshot 构建会在加锁前解析实现文件路径，并在 `acquire/release/invalidate` 中使用同一个路径。
  - 旧的 per-entry `premodel_reachable_callees` 会在检查缓存和加锁前解析 callee 实现路径，并使用 file-qualified lock。
- 收紧 on-demand 并发完成后的 snapshot 读取逻辑：当未显式传入 `file_path` 但已解析出实现路径时，优先使用解析出的路径读取 snapshot。

### 测试

- `python -m pytest tests/test_snapshot_store.py tests/test_global_modeler.py tests/test_parallel_shared_semantics.py tests/test_reporting_config.py tests/test_analyzer_semantics.py -q` 通过：58 个测试。
- `python -m py_compile zscope/snapshots/store.py zscope/orchestration/global_modeler.py zscope/core/analysis/analyzer.py` 通过。

## 2026-07-22

### 已完成：在 CodeIndex 输出边界过滤 LLVM intrinsic callee

- 在 `zscope/retrieval/code_index.py` 中新增统一判断 `_is_llvm_intrinsic_callee()`，过滤所有名称以 `llvm.` 开头的 callee。
- `_filter_callee_names()` 现在会过滤 LLVM intrinsic，覆盖函数实现上下文、regex/source fallback 和宏调用提取产生的名称列表。
- `_filter_callee_records()` 现在会过滤 LLVM intrinsic，覆盖 `CodeIndex.get_callees()` 返回给调用图、GlobalModeler 和其他上层消费者的 callee records。
- `_split_function_info_callees()` 在 project/external 分类、聚合和截断之前过滤 LLVM intrinsic，因此：
  - intrinsic 不会进入 `project_callees` 或 `external_callees`；
  - intrinsic 不占用 project/external callee 返回上限；
  - truncation 的 `total` 不再统计 intrinsic。
- `CodeIndex.get_callees(limit=N)` 改为在过滤后应用调用方 limit。如果当前底层查询结果因 intrinsic 或重复项导致不足 N 条，会逐步扩大底层查询上限，最高为 1,000,000，再返回前 N 条有效 callee，避免 intrinsic 占用 GlobalModeler breadth limit。
- 未修改 KnowledgeDB、SVF 导入器或 UnifiedBackend 的原始事实；`indirect_calls` 中的 `llvm.memset.p0.i64` 等记录仍可用于 IR/SVF 排查。
- 本阶段未将 `llvm.memset.*`、`llvm.memcpy.*` 等 intrinsic 转换为 snapshot `effects`，也未修改任何 fallback 文件。

### 新增回归测试

- `test_get_callees_filters_llvm_intrinsics_before_applying_limit`
  - 验证 `llvm.memset.*`、`llvm.memcpy.*` 被过滤；
  - 验证普通项目函数、external API 和原有去重顺序保持不变；
  - 验证过滤后仍能填满调用方请求的 limit；
  - 验证函数实现上下文中的名称型 `callees` 同样不包含 intrinsic。
- `test_function_info_filters_llvm_intrinsics_before_classification_and_truncation`
  - 验证 intrinsic 即使能匹配项目索引，也不会进入 `project_callees`；
  - 验证 intrinsic 不会进入 `external_callees`，且不会错误触发 truncation。
- `test_global_modeler_excludes_llvm_intrinsics_from_graph_and_model_input`
  - 使用同时包含项目 callee 和 `llvm.memset.p0.i64` 的 fake SVF/backend edge；
  - 验证 GlobalModeler 只建模 entry 与真实项目 callee；
  - 验证 intrinsic 不增加 `unresolved_external_callees`；
  - 验证最终 Semantic Modeler 输入/snapshot 的 project/external callee metadata 中不存在 intrinsic。
- `test_knowledge_db_preserves_llvm_intrinsic_indirect_call_facts`
  - 验证底层 `indirect_calls` 仍完整返回 `llvm.memset.p0.i64` 的 source、call file、call line 和 SVF group。

### 测试与验证

- 测试先行验证：实现前新增用例结果为 3 个失败、1 个通过；失败分别对应 CodeIndex records、function-info 分类/截断和 GlobalModeler unresolved graph，KnowledgeDB 原始数据保留用例通过。
- `python -m pytest tests/test_function_info_tool.py::test_get_callees_filters_llvm_intrinsics_before_applying_limit tests/test_function_info_tool.py::test_function_info_filters_llvm_intrinsics_before_classification_and_truncation tests/test_global_modeler.py::test_global_modeler_excludes_llvm_intrinsics_from_graph_and_model_input tests/test_knowledge_db_ir_and_config.py::test_knowledge_db_preserves_llvm_intrinsic_indirect_call_facts -q` 通过：4 个测试。
- `python -m pytest tests/test_function_info_tool.py tests/test_global_modeler.py tests/test_knowledge_db_ir_and_config.py tests/test_semantic_model_input.py tests/test_snapshot_tool.py -q` 通过：68 个测试。
- `python -m pytest tests/test_analyzer_semantics.py tests/test_function_info_tool.py tests/test_global_modeler.py tests/test_knowledge_db_ir_and_config.py tests/test_parallel_shared_semantics.py tests/test_scan_session_resume_svf.py tests/test_semantic_model_input.py tests/test_semantics_defaults.py tests/test_svf_cache.py tests/test_svf_value_flow_candidates.py -q` 通过：133 个测试。
- `python -m pytest -q` 全量回归通过：771 个测试，耗时 172.78 秒。
- `python -m py_compile zscope/retrieval/code_index.py zscope/orchestration/global_modeler.py zscope/snapshots/modeling_input.py` 通过。
- `git diff --check` 通过。

### 计划偏差 / 后续验证

- 相比原计划只在 helper 中过滤，本次额外调整了 `CodeIndex.get_callees()` 的底层查询扩容逻辑。原因是后端先执行 limit、CodeIndex 再过滤时，位于结果前部的 intrinsic 仍会占用 breadth limit，无法满足“intrinsic 不参与 callee 数量限制”的验收条件。
- 未重新运行完整 benchmark 或调用外部 LLM API。本次已通过真实 CodeIndex + fake SVF edge 的 GlobalModeler 集成测试验证调用图和 Semantic Modeler 输入；如需统计工具失败数和 token 变化，应使用临时 benchmark 配置单独运行，以避免在实施验证阶段产生未确认的 API 成本。

## 2026-07-24

### 已完成：SVF Artifact 与 KnowledgeDB 物化一致性永久修复

#### 问题现象与根因

- `global_model_20260723_090135` 的全局可达函数为 274，`global_model_20260724_132626` 在源码、入口列表和 unified backend 相同的情况下下降为 261。
- 两次 snapshot 的逐项对比显示：274 run 中有 469 个标记为 `indirect` 的 project-callee item，覆盖 190 个 snapshot 和 173 个唯一 target；261 run 中这三个数都变为 0。
- 异常时 `global_model_benchmark.db` 的关键统计为：`functions=558`、`call_edges=1134`、`indirect_calls=0`。Clang 直接调用事实仍在，SVF 间接调用事实被单独清空。
- `purge_tu_data()` 在增量重建 TU 时会按 `call_file` 删除 `indirect_calls`；旧实现没有独立记录“该 artifact 已导入当前数据库”的状态。
- 与此同时，2026-07-21 写入的 `svf_tool_status:*` 仍为 `success`。后续 resume 只验证 bitcode/tool fingerprint，因而跳过 WPA/Saber，却没有发现 KnowledgeDB 中的派生事实已经被 TU purge 删除。这形成了“工具成功、artifact 仍在、数据库物化丢失”的不一致状态。
- 现有三个 Ander DOT 均存在，并且 SHA-256 与旧 status 的 `output_hash` 完全一致：
  - `default`: `1a79b87c3a83...`
  - `entry_cluster_1`: `c0fe7aa4a495...`
  - `entry_cluster_2`: `99c5cedd597e...`
  因此问题不是源码或 SVF 输出变化，而是有效 artifact 没有重新导入数据库。
- 274 run 比 261 run 多出的 13 个 snapshot 为：
  - 11 个由间接边直接引入的 target：`_control_session_drop_from_global`、`_default_task_handler`、`_flush_worker`、`_packet_receiver_thread`、`_public_lifecycle_callback`、`_runtime_event_completion_callback`、`_runtime_header_alloc`、`_runtime_noop_free`、`_runtime_rcu_register_callback`、`_runtime_stream_flush_worker`、`_service_async_worker`；
  - 2 个二级直接 callee：`_net_accept_connection`（由 `_packet_receiver_thread` 引入）和 `LOG_DEBUG`（由 `_runtime_stream_flush_worker` 引入）。
  这解释了为什么缺少间接事实最终恰好使可达集合减少 13，而不仅是少掉一条边。

#### Metadata / materialization 契约

- 未修改 SQLite 表结构，仅新增 metadata key。
- `svf_db_generation`：全局非负整数，新数据库和旧数据库首次打开时默认初始化为 `0`。
- `svf_db_import:<tool>:<group>`：每个 Ander/Saber group 的成功物化 marker，JSON 字段包括：
  - `schema_version`；
  - `artifact_fingerprint`；
  - project-root-relative `artifact_path`；
  - `artifact_hash`；
  - `imported_row_count`；
  - `db_generation`；
  - `imported_at`。
- `imported_row_count=0` 是合法成功状态。缓存有效性不再通过查询派生表是否非空来判断。
- `purge_tu_data()` 只有在确实删除了 `indirect_calls` 或 `taint_signatures` 行时才递增 `svf_db_generation`，避免无 SVF 事实的普通 TU 清理制造无意义失效；一旦发生删除，所有旧 generation marker 都会失效。
- `purge_svf_data(group)` 同步删除该 group 的 Ander/Saber marker；`purge_svf_data_except(groups)` 只删除不再保留的 group 数据及 marker，不使保留 group 失效。
- 额外增加 `svf_db_materialization` 全局 manifest，保存当前 generation 和本次完整运行应存在的 tool/group 集合。它用于给 source fingerprint、aggregate artifact fingerprint 和 “all linked groups reused” 三个快速返回增加统一门禁。
- 快速返回前会逐个验证 manifest、group marker、tool status、artifact 相对路径和 artifact SHA-256。任何 marker 缺失、generation 过期、artifact 缺失或 hash 不匹配都会进入 group 恢复路径，不能再被 aggregate cache 绕过。

#### Resume、自动恢复与旧缓存兼容

每个 group 现在严格按以下顺序处理：

1. tool status、replay artifact 和当前 generation marker 都有效：记录 `event=cache_skip` 并跳过。
2. tool status 与 artifact 有效，但 marker 缺失或 generation 过期：记录 `event=artifact_reimport`，不运行 WPA/Saber，直接事务性重导入。
3. artifact 缺失、hash 不匹配或解析失败：记录 `event=artifact_invalid`/`event=recovery_failed`，重新运行相应工具并导入新结果。
4. 重导入和工具重跑仍失败：group 返回失败，不更新 source/artifact aggregate cache，不写入新的成功物化 marker，也不宣称 KnowledgeDB 写入成功。

旧缓存兼容行为：

- Ander 继续使用各 group 的 `callgraph_final.dot`。旧 status 没有 `artifact_path` 时按历史确定性目录推导：default 使用 `.zscope_svf/callgraph_final.dot`，其他 group 使用 `.zscope_svf_<group>/callgraph_final.dot`；只要旧 `output_hash` 匹配即可无 WPA 重导入。
- Saber 成功后将稳定排序的结果原子写入 `.zscope_svf_<safe-group>/saber_results.json`。tool status 保存相对路径和 SHA-256。
- 旧 Saber status 没有 replay JSON，无法从 stdout/stderr hash 还原原始结果，因此升级后第一次必须重跑 Saber；JSON 建立后后续 purge 可直接 replay。

#### 事务与失败语义

- `KnowledgeDB` 增加进程内 SVF materialization 写锁，并使用 SQLite savepoint 串行化每个 group 的数据库替换。WPA 子进程仍可并行运行，只有数据库写入阶段串行。
- 单个 group 的以下步骤位于同一事务：删除旧 group 数据、解析/插入 replay artifact、写入 group marker、提交。
- 任一步异常时 rollback 到 savepoint，旧 group 数据和旧 marker 保持不变；不会留下“旧数据已删、新数据只导入一半”的状态。
- `SvfOutputMapper.import_callgraph()` 和 `import_saber_bugs()` 新增 `commit` 控制并返回实际插入行数，使 analyzer 能控制事务边界。
- `KnowledgeDB.insert_indirect_call()` 和 `insert_taint_signature()` 返回 SQLite 实际插入行数，用于准确记录 marker；原有忽略返回值的调用保持兼容。

#### 实际修改文件

- `zscope/retrieval/knowledge_db.py`
  - generation、marker 清理、SVF savepoint 事务和插入计数。
- `zscope/retrieval/svf_parser.py`
  - mapper 的外部事务控制与导入行数返回。
- `zscope/retrieval/svf_analyzer.py`
  - materialization manifest 门禁、Ander/Saber replay、artifact 校验、Saber 原子 JSON、事务性 group 替换和结构化日志。
- `tests/test_svf_cache.py`
  - 更新旧 fake runner，使“成功”结果提供必要 DOT；更新不再符合新契约的 aggregate-cache 断言；新增永久修复专项测试。
- `new_docs/architecture_optimation.md`
  - 本实施记录。

没有修改 SQLite 表 schema、fallback 文件或用户已有的[历史架构优化计划](../design-plans/architecture_optimation_plan.md)、`new_docs/v1_3optlog.md` 手工内容。

#### 新增与调整的测试覆盖

- artifact/status/marker 全有效时不运行工具、不重复导入。
- status 有效但 marker 缺失时从旧 DOT 重导入，WPA 调用次数为 0。
- TU purge 删除 SVF 行后 generation 增加，旧 marker 失效并自动 replay。
- 零间接边写入 `imported_row_count=0`，后续正常缓存命中。
- artifact hash 不匹配时重跑 WPA。
- 即使 source fingerprint 命中，只要 replay artifact 缺失也不能快速返回，必须重跑工具。
- Saber 生成稳定 `saber_results.json`，marker 丢失后从 JSON replay，不重复运行 Saber。
- 导入中途注入异常时事务 rollback，原 group 数据保留且不留下部分新数据。
- 多 group 只恢复失效 group，其他有效 group 不重跑、不重导入。
- `purge_svf_data_except()` 只删除过期 group marker。
- 离线集成：导入 `td_init -> _packet_receiver_thread`，模拟 TU purge 后在不调用 WPA 的情况下恢复；GlobalModeler 随后重新遍历到 `_packet_receiver_thread -> _net_accept_connection`。

#### 测试结果

- `python -m py_compile zscope/retrieval/knowledge_db.py zscope/retrieval/svf_parser.py zscope/retrieval/svf_analyzer.py`：通过。
- 相关回归（SVF cache、KnowledgeDB、GlobalModeler、scan-session、value-flow、Clang incremental、CodeIndex）：113 个测试通过。
- 最终聚焦回归：73 个测试通过，耗时 1.27 秒。
- 完整回归第一次直接执行 `pytest -q` 时，收集阶段因当前 shell 未将仓库根目录加入 import path，`tests/test_benchmark_protocol.py` 和 `tests/test_range_benchmark_regression.py` 无法导入 `scripts`；没有测试用例实际失败。
- 使用明确环境 `PYTHONPATH=<repo> pytest -q` 后完整回归通过：811 个测试，耗时 155.29 秒。
- `git diff --check`：通过。

#### 真实 benchmark 数据库升级验证

验证对象为原异常数据库 `test/range/.zscope_knowledge/global_model_benchmark.db`，未删除或重建整个数据库，也未调用 LLM API。

1. 升级前：`functions=558`、`call_edges=1134`、`indirect_calls=0`；三个 Ander DOT 与旧 status hash 匹配。
2. 无入口的 `--build-cpg` 首先验证 default 旧缓存恢复：日志显示解析 905 条 DOT edge、`event=artifact_reimport tool=ander group=default`，没有 WPA 命令；`td_init -> _packet_receiver_thread` 和 `_packet_receiver_thread -> _net_accept_connection` 随即恢复。
3. 使用 `benchmark/entries.json` 的完整 174 入口直接运行同一 `SvfAnalyzer`：
   - `entry_cluster_1` 从旧 DOT 重导入 901 行；
   - `entry_cluster_2` 从旧 DOT 重导入 4 行；
   - 旧 Saber cache 因没有 JSON artifact 按兼容规则重跑一次，生成 `saber_results.json` 并导入 13 条 taint signature；
   - 最终 `indirect_calls=905`，group 分布为 901 + 4；两个旧 DOT 的时间戳仍为 2026-07-21，证明没有重跑 WPA。
4. 使用真实 `CodeIndex + UnifiedBackend + GlobalModeler._collect_graph`、完整 174 入口及 benchmark 配置 `max_premodel_depth=5`、`max_premodel_callees=20` 重新收集调用图：
   - `reachable=274`；
   - `_packet_receiver_thread`、`_net_accept_connection`、`_runtime_stream_flush_worker`、`LOG_DEBUG` 均重新进入可达集合。
5. 再次以完全相同配置运行 analyzer，日志为 `cache fingerprint unchanged; reusing cached data`；Ander DOT 和 Saber JSON 的 mtime 全部不变，数据库仍为 `indirect_calls=905`、`taint_signatures=13`。

这验证了异常数据库无需整体删除即可从 `indirect_calls=0` 自动恢复，并且有效 Ander artifact 的恢复不运行 WPA；升级完成后的 Saber 也进入可 replay 状态。

#### 计划偏差、剩余限制与已知问题

- 相比原计划，增加了 `svf_db_materialization` 全局 manifest。原因是仅有 generation 与 group marker 无法安全控制 `SvfAnalyzer.run()` 顶部三个 aggregate 快速返回，也无法在 source cache 命中时发现某一个 marker 或 artifact 被单独删除。
- `purge_tu_data()` 采用“实际删除 SVF 行才 bump generation”，而不是每次调用都递增。该实现符合“删除派生事实时失效”的契约，并减少无关 TU 清理造成的全局 replay。
- 实际 benchmark 验证没有重新执行耗时且会产生 API 成本的全量语义建模/LLM snapshot；验证止于真实 GlobalModeler 调用图收集，因此没有生成新的 token、耗时或 snapshot 质量指标。
- 旧 Saber cache 无 replay JSON 时无法免工具恢复；这是一次性兼容限制，首次成功升级后消失。
- 当前 generation 是数据库级而非 group 级；任一 TU purge 删除 SVF 行会保守地使所有 group marker 过期，下一次运行会从各自 artifact replay。该策略优先保证一致性，可能比精确 group invalidation 多做少量数据库导入。
- artifact 快速返回现在会计算 replay 文件 SHA-256。当前 benchmark DOT 规模较小，该成本远低于 WPA；超大项目可在后续引入受签名保护的 size/mtime 快速层，但不能取消最终内容校验。
- 进程内写锁负责同一 KnowledgeDB 实例的 group 串行化；跨进程并发仍依赖 SQLite WAL、busy timeout 和 savepoint 语义，不建议多个 scan 进程同时物化同一个数据库。

## 2026-07-27

### 已完成：`unresolved_callees` 建模输入与 deterministic snapshot 契约修复

#### 问题现象与根因

- `global_model_20260727_113839` 的 SVF/调用图阶段正常，可达函数为 274，但只完成 136 个 snapshot，失败 138 个，stage gate 因 `failed_functions > 0` 拒绝 entry fan-out，scan return code 为 1，入口 snapshot 复用为 0/174。
- 138 个失败精确分为：
  - 125 个 `semantic_model_input_invalid`：错误为 `semantic_modeler input has invalid program fields: unresolved_callees`；
  - 13 个 `semantic_model_exception`：错误为 `deterministic snapshot fields do not match the canonical shape`。
- 第一类根因：`unresolved_callees` 已加入 optional program passthrough 字段并由 `build_semantic_model_input()` 作为 list 传入，但 SemanticModeler 的 optional-field validator 仍将除 `unresolved_referenced_types` 外的所有 optional 字段按 dict 校验。因此任何非空 `unresolved_callees` 都会在 LLM 调用前被拒绝，日志中的 `context_tokens=0`。
- 第二类根因：deterministic snapshot builder 已写入非空 `unresolved_callees`，但 deterministic optional-field 白名单只包含 `unresolved_callees_truncation`，漏掉字段本身，导致短函数和 lightweight 函数在 shape check 中失败。
- 该问题与 SVF、LLM 服务和 retrieval tools 无关：本次 run 的可达集合为 274，111 个 LLM snapshot 正常完成，工具整体成功率为 99.62%。

#### 实施内容

- `zscope/agents/semantic_modeler/agent.py`
  - 将 `unresolved_callees` 与 `unresolved_referenced_types` 一样按“非空 list”校验；其他 truncation optional 字段继续按 dict 校验。
- `zscope/snapshots/policy.py`
  - 将 `unresolved_callees` 加入 deterministic snapshot optional-field 白名单；
  - 校验其必须为非空 list，且每条记录字段严格为 `callee_name`、`direct_callsite_lines`、`indirect_callsites`；
  - 校验 `unresolved_callees_truncation` 必须为 dict。
- `tests/test_json_output_agents.py`
  - 新增 SemanticModeler 接受并原样保留非空 `unresolved_callees` 的回归测试，同时确认该字段进入 prompt metadata。
- `tests/test_snapshot_store.py`
  - 新增带 unresolved callee 的 trivial deterministic snapshot 构造测试。
- `tests/test_callers_tool.py`
  - 完整回归发现旧断言未包含当前 `get_all_callers()` 已返回的 `callee_kind="unknown"`；遵循仓库规则，仅更新测试预期，没有修改对应生产行为。

#### 测试结果

- `python -m py_compile zscope/agents/semantic_modeler/agent.py zscope/snapshots/policy.py`：通过。
- 相关回归：107 个测试通过，耗时 1.08 秒。
- 两条新增契约测试和 caller evidence 回归：3 个测试通过，耗时 0.18 秒。
- 完整回归首轮：822 个通过、1 个旧 caller 测试预期失败；只调整测试预期。
- 最终完整回归：823 个测试全部通过，耗时 168.23 秒。

#### 验证边界

- 未重新运行完整 LLM benchmark，避免再次消耗约百万 token。单元与集成测试已经直接覆盖两条导致 125 + 13 失败的入口。
- 未修改 `unresolved_callees` 的分类策略、SVF 数据、KnowledgeDB 内容或 fallback 文件。

## 2026-07-27

### 已完成（阶段 A，第一部分）：Clang 调用分类与 `callee_kind` 底层事实

- `call_edges` 新增 `callee_kind`，并将 KnowledgeDB schema version 从 `10` 升至 `11`。新库默认列值和旧库 migration 均使用安全值 `unknown`；历史记录不会被错误地改写为普通函数调用。
- `insert_call_edge()` 接受 `callee_kind`；`insert_call_edges_batch()` 同时兼容既有 6 元组写入（自动填入 `unknown`）和新的 7 元组写入。`get_callees()`、`get_all_callees()`、caller 查询均返回该字段，供后续 Unified 归一化使用。
- clangd call hierarchy 路径现在按 LSP SymbolKind 分类：Function/Method/Constructor 写为 `direct/function`；Field 写为 `indirect/function_pointer_field`；Variable 写为 `indirect/function_pointer_variable`；其余 kind 保留为 `direct/unknown_callable`，不再伪装成已确认函数。
- regex fallback 现在识别 `object.callback(...)`、`pointer->callback(...)`、`local_callback(...)` 和 `(*local_callback)(...)`。成员调用写为间接 field；通过裸函数指针声明或函数指针 typedef 识别的局部调用写为间接 variable；具名但无法得到定义证据的普通调用写为 `unknown_callable`。

### 测试与兼容性

- 新增 clangd hierarchy 分类测试，覆盖 function、field、variable 和未知 SymbolKind。
- 新增 regex fallback 测试，覆盖直接函数、成员函数指针、typedef 参数函数指针和显式解引用调用。
- 新增 KnowledgeDB round-trip 测试，覆盖 `callee_kind` 写入、查询与旧 6 元组 batch 兼容。
- 旧 schema migration 测试的 schema version 断言随 migration 升级为 `11`。
- `python -m pytest tests/test_clang_incremental_extraction.py tests/test_knowledge_db_ir_and_config.py -q`：44 passed。
- `python -m py_compile zscope/retrieval/clang_extractor.py zscope/retrieval/knowledge_db.py`：通过。

### 剩余工作

- 当前阶段只建立调用类型事实，尚未将函数指针字段替换为 SVF 的真实候选，也未将 `unknown_callable` 公开为 `unresolved_callees`。
- SVF DOT 的红/黑边解析、callsite-aware 候选归属、Unified 归一化和 LLM 可见三类 callee schema 仍待后续阶段实现。

### 已完成（阶段 B）：SVF DOT 只物化显式间接边

- `CallGraphParser` 新增 `parse_edges()`，保留每条 DOT edge 的 `caller`、`callee`、`edge_color` 和 caller source port（如 `s0`）。原 `parse()` 保持返回全部调用图边的兼容行为。
- `SvfOutputMapper.import_callgraph()` 现在只将 `color=red` 的 SVF edge 写入 `indirect_calls`；`color=black` 的普通直接边继续保留在 DOT 调试产物中，但不会再被误投影为间接调用。
- 测试用的 SVF callgraph 生成器明确输出红边，避免无属性的 synthetic DOT 被错误地当作已经验证为 indirect 的真实分析结果。
- 新增 parser/mapper 回归：同一 DOT 同时含黑边和红边时，验证颜色与 source port 被保留、只有红边写入 KnowledgeDB。
- `python -m pytest tests/test_svf_cache.py -q`：22 passed。
- `python -m py_compile zscope/retrieval/svf_parser.py`：通过。

### 仍未覆盖的 SVF 事实

- source port 已保留在 parser 层，但当前 `indirect_calls` schema 尚未保存它；因此还不能将 SVF 候选安全归属到源码函数指针 callsite，也不能向 LLM 公开精确 `indirect_callsites`。这部分将随 callsite-aware schema 与 Unified 归一化阶段一起实现。

### 进行中（callsite-aware schema）：实现与测试阻塞记录

- 已将目标 KnowledgeDB schema version 提升到 `12`，设计 `indirect_calls` 的 callsite-aware 字段：`callsite_id`、`pointer_symbol`、`pointer_kind`、`pointer_type`、`pointer_signature`、`callsite_expression` 和内部 `call_guard`。
- 新唯一键包含 caller/callee、文件、行号、callsite identity、pointer symbol、source 和 SVF group，目标是避免同一 caller/callee 在不同函数指针调用点被旧唯一键合并。
- 已增加 `get_indirect_call_records()` 原始查询，并让 SVF parser 将 source port 保存为不透明 `callsite_id`（例如 `svf:s1`）。端口不等价于源码行号或字段身份，未伪造 pointer/line 元数据。
- fresh DB 的多调用点 round-trip 和 SVF port 写入路径已经实现。

#### 测试发现的阻塞问题

- 旧库 migration 专项测试发现：`_create_tables()` 的初始 `CREATE INDEX IF NOT EXISTS idx_ic_callsite ON indirect_calls(caller_name, callsite_id)` 会在 v12 表重建前作用于旧 `indirect_calls`；旧表没有 `callsite_id`，因此抛出 `sqlite3.OperationalError: no such column: callsite_id`。
- 该失败说明当前 v12 migration 尚不能用于旧数据库，callsite-aware 阶段不能标记完成，也不能据此升级 benchmark DB。
- 按仓库指令“测试不通过时只改测试与实施记录”，本轮没有在失败后修改生产迁移逻辑。专项用例暂时标记 skip，并保留明确原因，等待确认是否允许修正生产代码中的迁移顺序。

#### 阻塞解除（已获授权）

- 已将 `idx_ic_callsite` 的创建从初始 `CREATE TABLE IF NOT EXISTS indirect_calls` 脚本移至 v12 列检查和必要的表重建之后。新数据库会在列存在后创建索引；旧数据库会先复制旧行、替换表并重建索引，避免对旧表引用不存在的 `callsite_id`。
- 已恢复旧库 migration 专项用例。`python -m pytest tests/test_knowledge_db_ir_and_config.py tests/test_svf_cache.py tests/test_scan_session_resume_svf.py -q`：59 passed。
- `python -m py_compile zscope/retrieval/knowledge_db.py zscope/retrieval/svf_parser.py zscope/retrieval/unified_backend.py` 与 `git diff --check`：通过。

### 已完成（Unified projection 防护）：函数指针占位符不再伪装为 external

- `CodeIndex._split_function_info_callees()` 现在会丢弃底层 `callee_kind=function_pointer_field` 和 `function_pointer_variable` 的记录。它们是调用点证据而不是可查询的函数 identity，不能进入 `project_callees`、`external_callees` 或未来的 `unresolved_callees`。
- 新增回归覆盖“Clang 字段占位符 + SVF 项目候选”组合：字段名不再出现在 external，真实项目候选仍保留。
- `python -m pytest tests/test_function_info_tool.py tests/test_knowledge_db_ir_and_config.py tests/test_svf_cache.py -q`：80 passed。

### 已完成（LLM callee schema，基础实现）：三类 callee 与调用点字段

- `CodeIndex` 已将公开 callee 改为互斥的 `project_callees`、`external_callees` 和按需 `unresolved_callees`：
  - project item 包含 `callee_index_name`、`callee_signature`、`is_static`、`direct_callsite_lines`、`indirect_callsites` 和 `callee_summary`；
  - external 只在 backend 提供明确 `callee_signature` 时公开 `callee_name + callee_signature`；
  - 具名但没有可靠 external signature 的 direct callee 进入 `unresolved_callees`，不再伪装为 external；
  - unresolved 数组仅在非空时出现，采用独立 20 项上限和 `unresolved_callees_truncation`。
- 公开 schema 不再包含 `call_type`。直接调用只写入 `direct_callsite_lines`；间接调用只有在具有 source 行、pointer identity/kind/type/signature 和 callsite expression 的完整底层证据时才写入 `indirect_callsites`。未映射的 SVF 函数级候选仍只保留在底层，避免伪造 LLM 证据。
- `Semantic Modeler` 输入、默认 snapshot schema、确定性 snapshot 规范化和 snapshot symbol-context hash 已同步新字段。`unresolved_callees` 被修正为真正按需透传字段，而不是所有模型输入的必填字段。
- 新增三类 schema 的正向用例：project 间接调用点、带签名 external、unresolved direct target；同时将旧 `call_type/callsite_lines` 测试迁移为新字段契约，并以间接调用点变化验证 snapshot refresh。
- `PYTHONPATH=<repo> python -m pytest` 覆盖 function-info、KnowledgeDB、SVF cache、Semantic Modeler 输入、snapshot store、确定性 snapshot、JSON agent、GlobalModeler 和 scan-session：200 passed。相关模块 `py_compile` 与 `git diff --check` 通过。

### 剩余限制

- Clang 当前尚未提取 `function_pointer_type`、展开签名、完整 expression/guard；SVF source port 也尚未与源码 callsite 建立可证明映射。因此真实 benchmark 的 SVF 候选仍可能只保留在底层，不能强行写入公开 `indirect_callsites`。
- 外部函数签名当前要求上游明确提供 `callee_signature`；尚未接入 clangd/AST 系统头声明或 external 配置的自动解析。
- 尚未运行完整 LLM 语义建模 benchmark，故 `get_function_info` 失败次数、token 和最终 `_runtime_noop_free` 分支 snapshot 质量仍未验证。

### 已完成（external signature 基础链路）：clangd target detail 入库

- KnowledgeDB schema version 提升到 `13`，`call_edges` 新增 `callee_signature`；旧数据库通过 additive migration 获得空默认值。
- 单条与 batch call-edge 写入同时兼容历史 6 元组、阶段 A 的 7 元组和含签名的 8 元组；callee 查询将签名返回给 Unified/CodeIndex。
- clangd call hierarchy 将 `CallHierarchyItem.detail` 作为显式 callee declaration detail 写入 `callee_signature`。regex fallback 暂不猜测签名，继续写空值并最终归入 unresolved。
- 新增/调整测试验证 clangd detail 进入提取记录、KnowledgeDB 签名 round-trip 和 schema version 13。Clang/KnowledgeDB/function-info 聚焦回归：80 passed。

### 已完成（source port 到源码调用点的保守解析）

- `SvfOutputMapper` 现在在 materialization 时接收 project root，并读取 caller 的 Clang call-edge 事实和源码。对于成员函数指针调用，它从源码表达式、局部容器变量声明、已索引的 struct typedef 及函数指针 typedef 推导 `pointer_symbol`、kind、type、展开签名和 `callsite_expression`。
- SVF target 只有在其项目函数签名与函数指针签名兼容、且恰好匹配一个候选调用点时才得到 source line 与上述 pointer 元数据；否则保持 opaque `svf:<port>`，不写公开 `indirect_callsites`。函数签名归一化会忽略 `static`/`extern`/`inline` 存储修饰。
- 新增端到端 fixture：red SVF edge + `Ops.callback` 的 typedef/struct/source 调用，验证写入 `source:5:Ops.callback`、`Ops.callback`、`Callback`、`void (*)(void* value)` 与源码表达式。
- 对现有异常 range DB 进行了只读 resolver 诊断（不运行 benchmark、不改动 DB）：`_runtime_header_alloc` 与 `_safe_malloc` 唯一映射到 `RuntimeLfhashTable.mem_alloc_func` 第 2698 行；`_runtime_noop_free` 唯一映射到 `RuntimeLfhashTable.mem_free_func` 第 2702 行；`free` 因没有可靠外部声明签名保持未映射。
- `python -m pytest tests/test_svf_cache.py -q`：23 passed。

- source resolver 同时覆盖 `(*callback)(...)` 参数函数指针：当 caller signature 证明 `Callback callback` 是参数时，写入 `pointer_kind=parameter`、`caller.callback` 与实际 source line；局部 typedef 变量沿相同声明解析逻辑处理。
- 最终非 benchmark 回归覆盖 Clang、KnowledgeDB、SVF cache、function-info、Semantic Modeler 输入、snapshot store、确定性 snapshot、JSON agent、GlobalModeler 与 scan-session：223 passed；相关模块 `py_compile` 和 `git diff --check` 通过。
- 本轮按要求未运行完整 benchmark，也未调用外部 LLM API；benchmark 的 API/tool 失败数、token、wall time 与 `_runtime_noop_free` 最终 snapshot 语义由后续手动执行验证。
