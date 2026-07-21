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
