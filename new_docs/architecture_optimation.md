# 架构优化实施记录

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
