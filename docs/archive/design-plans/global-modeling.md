# Architecture Optimation Plan

> **历史文档，2026-11-17 归档。** 原位置：`new_docs/stage1optimation/global modeling.md`。本文保留早期全局建模方案，旧 `analysis.*` 公共配置不再适用；当前行为见[执行与编排](../../modules/execution-orchestration.md)，后续开发见[现行实施计划](../../plans/agent-scanning/README.md)。下文的“当前”、待办及验收要求均指编写时状态。

## 目标

在 benchmark/full scan 场景中，用 batch-level global modeling 替代当前 per-entry 的 `premodel_reachable_callees + model_entry` 两阶段。开启后，workflow 不再对每个 entry 单独做 premodel 和 model_entry，而是先从全部 entries 构建全局 reachable call graph，对所有需要建模的函数去重后统一建模。全部建模完成后，再进入后续漏洞分析、Deep Worker、验证和报告阶段。

核心目标：

- 降低 `get_function_snapshot -> No snapshot exists` 的空结果率。
- 避免多个 entry 重复排队 premodel 同一个 callee。
- 消除 entry A 已进入 deep_worker、entry B 仍在建共享 callee 的并发时序问题。
- 让 semantic_modeler 建上层函数时，更稳定地拿到底层 callee snapshot。
- 保留 batch 内并行能力，但不要采用粗粒度 layer barrier。

## 配置开关

新增配置：

```yaml
analysis:
  enable_global_model: false
```

参数复用：

```yaml
analysis:
  parallel_workers: 12
  max_premodel_depth: 5
  max_premodel_callees: 20
```

口径：

- `enable_global_model=false`：保持现有 per-entry workflow。
- `enable_global_model=true`：启用 batch-level global modeling。
- `parallel_workers`：复用为 global modeling 的并发 worker 数，同时仍作为后续 entry 分析并发数。
- `max_premodel_depth`：从全部 entries 出发收集 reachable call graph 的最大深度。
- `max_premodel_callees`：每个函数向下展开 callee 的最大数量。benchmark 可调大；不建议默认无限制。

## Workflow 变化

当前 default workflow：

```text
discover_entries
per-entry premodel_reachable_callees
per-entry model_entry
per-entry focused_subagent_planning
per-entry vulnerability_mining
per-entry validate_findings
persist_report
```

启用 `enable_global_model` 后：

```text
discover_entries
batch_global_model
per-entry focused_subagent_planning
per-entry vulnerability_mining
per-entry validate_findings
persist_report
```

其中 `batch_global_model` 合并原来的：

- `premodel_reachable_callees`
- `model_entry`

也就是说 entries 自身也作为 graph root 参与建模。建模完成后，entry 的 semantic snapshot 已经存在，后续阶段直接从 snapshot store 读取。

## 全局建模输入

输入：

- batch entries：`FunctionEntry` 列表。
- `CodeIndex.get_callees(func, limit=max_premodel_callees)`。
- `CodeIndex.get_function_impl(func, include_context=False)` 用于判断函数是否有源码实现、file_path、line range、是否 trivial/lightweight。

建图 key：

```text
FunctionKey = (func_name, file_path)
```

不建议继续只用 `func_name`。当前 snapshot DB 是 `(func_name, file_path)` 复合主键，但 snapshot lock 只按 `func_name`，会在同名不同文件函数上存在潜在误判。global modeling 应统一使用 `FunctionKey` 做去重、依赖边和调度锁。

## 全局 Call Graph 收集

从所有 entries 同时作为 roots 做 BFS/DFS 收集：

```text
roots = all configured/discovered entries
queue = [(entry_key, depth=0)]
visited = set()
edges = caller_key -> set(callee_key)
reverse_edges = callee_key -> set(caller_key)
```

收集规则：

- depth 超过 `max_premodel_depth` 时停止向下展开。
- 每个函数最多展开 `max_premodel_callees` 个 callee。
- 只纳入能解析到源码实现的 callee。
- trivial/lightweight 函数仍纳入节点，但可用 deterministic snapshot，避免 LLM 成本。
- 对 unresolved external/libc/API 函数不建模，可记录为 external node，不阻塞 caller 建模。

需要记录的统计：

- roots 数量。
- reachable function 数量。
- unresolved callee 数量。
- 被 depth cap 截断的边数。
- 被 breadth cap 截断的边数。
- deterministic snapshot 数量。
- LLM snapshot 数量。
- cache hit 数量。

## 函数排序与调度

不采用固定 layer 并行或全层 barrier。推荐使用动态 ready-queue：**每个函数建模前判断它所有需要建模的 callees 是否已完成；所有子边都消除后才允许建模该函数。**

### 数据结构

```text
pending_children[func] = set(callee functions that must complete before func)
parents[callee] = set(parent functions waiting for callee)
ready_queue = functions whose pending_children is empty
status[func] = pending | running | done | failed | skipped
```

初始化：

```text
for func in all_functions:
    pending_children[func] = internal_resolvable_callees(func)
    if pending_children[func] is empty:
        ready_queue.push(func)
```

调度循环：

```text
while unfinished functions exist:
    while ready_queue not empty and running_workers < parallel_workers:
        func = ready_queue.pop()
        if snapshot already exists:
            mark_done(func, reason="cache_hit")
        else:
            submit model_func(func)

    wait for any worker to finish

    for finished func:
        mark_done(func)
        for parent in parents[func]:
            pending_children[parent].remove(func)
            if pending_children[parent] is empty:
                ready_queue.push(parent)
```

这个调度方式的特点：

- 不是按 topo layer 整层等待。
- 哪个函数的子依赖先完成，哪个函数就可以立即进入建模。
- 慢函数只阻塞真正依赖它的上层函数，不阻塞同层其他无关分支。
- 与 “leaf-to-root” 目标一致，但比 layer barrier 更细粒度。

### 为什么比 layer barrier 更合适

Layer barrier 的问题：

- 一个深层慢函数会阻塞整个上一层，即使大多数上层函数并不依赖它。
- 实际调用图常有不规则 fan-out/fan-in，静态 layer 会造成 worker 空闲。
- layer 的定义在 SCC、截断边、external edge 存在时不够自然。

Ready-queue 的优势：

- 只等待真实依赖。
- 自然支持并行。
- 支持 cache hit 快速释放父节点。
- 支持失败降级后继续推进。

## 环与递归处理

真实调用图不是 DAG，可能存在递归或互相调用。

处理方式：

1. 对全局 call graph 先做 SCC 压缩。
2. SCC 之间形成 DAG。
3. 调度单位变为 `Component`。

SCC 内策略：

- 单函数 SCC：正常建模。
- 多函数 SCC：先生成 `cycle_placeholder` 或 `recursive_group_context`，再按稳定顺序逐个建模。
- SCC 内函数建模时允许看到同组函数的源码摘要，但不能要求同组所有 snapshot 已存在。
- SCC 完成后整体标记 done，释放上层 parent components。

## 建模执行策略

每个 ready function 的建模流程：

1. 用 `(func_name, file_path)` 查 snapshot。
2. 若 snapshot 存在且未过期，直接 `done(cache_hit)`。
3. 获取函数实现。
4. 若 trivial/lightweight，生成 deterministic snapshot。
5. 否则调用 `SemanticModeler`。
6. 调用前将已完成 callee snapshots 注入 context，或允许 `get_function_snapshot` 查询。
7. 成功后保存 snapshot。
8. 失败时标记 failed，但不无限阻塞 parents。

失败降级建议：

- 如果 callee 建模失败，parent 不能永久等待。
- parent 的 `pending_children` 中该 callee 可标记为 `failed_dependency` 后消除。
- parent 建模 context 中明确记录 missing/failed callee。
- 指标中记录 `failed_dependency_count`，后续用于解释质量风险。

## 后续 Entry 分析如何衔接

启用 global model 后，单 entry 分析阶段不再运行：

- `_step_premodel_reachable_callees`
- `_step_model_entry`

进入 `focused_subagent_planning` 前，`state["agent_context"]` 应附带：

- entry function snapshot。
- entry code。
- reachable snapshot summary，可限制数量。
- global model coverage metadata。

如果 entry snapshot 缺失：

- 说明 global modeling 失败或该 entry 无实现。
- 可以降级为旧的 per-entry `model_entry`，也可以标记 entry analysis degraded。
- benchmark 模式建议降级并记录指标，不直接跳过 entry。

## 预期指标变化

应该下降：

- `get_function_snapshot` 空结果率。
- semantic_modeler 建模时 callee snapshot missing 数。
- deep_worker 中 `No snapshot exists` 数。
- vulnerability_analyzer 中 `No snapshot exists` 数。
- 多 entry 重复 premodel 排队数量。

可能上升：

- global modeling 阶段 token 总量。
- 首个漏洞结果出现时间。
- snapshot DB 写入量。
- 对后续未使用函数的建模成本。

需要新增指标：

| 指标 | 含义 |
|---|---|
| global reachable functions | 全部 entries 可达函数去重数 |
| modeled functions | 本轮实际建模函数数 |
| cache hit functions | 已有 snapshot 复用数 |
| deterministic snapshot count | trivial/lightweight 自动摘要数 |
| LLM snapshot count | LLM 建模数 |
| unresolved external callees | 无源码实现或无法解析 callee 数 |
| depth capped edges | 因 `max_premodel_depth` 截断的边数 |
| breadth capped edges | 因 `max_premodel_callees` 截断的边数 |
| failed dependencies | callee 建模失败但 parent 继续建模的依赖数 |
| ready queue idle time | 因依赖未完成导致 worker 空闲时间 |

## 实现切入点

### Config

文件：

- `zscope/config/config.py`
- `zscope.yaml`
- benchmark config 文件

新增：

```python
enable_global_model: bool = False
```

### Workflow / Batch Orchestration

候选位置：

- `zscope/orchestration/parallel_analyzer.py`
- `zscope/orchestration/scan_session.py`
- `zscope/core/analysis/analyzer.py`

建议新增组件：

```text
zscope/orchestration/global_modeler.py
```

职责：

- 收集全局 call graph。
- 构造 `FunctionKey`。
- SCC 压缩。
- ready-queue 调度。
- 调用 semantic_modeler 建模。
- 输出 coverage/statistics。

### Snapshot Lock

建议将 snapshot lock key 从：

```text
func_name
```

升级为：

```text
(func_name, file_path)
```

或至少内部统一为字符串：

```text
f"{func_name}@@{file_path or ''}"
```

避免同名不同文件函数互相污染。

## 风险与边界

- `code_index.get_callees` 不能完整覆盖函数指针、callback、动态 dispatch。
- 全局建模会提高前置成本，尤其是大项目。
- 如果 graph 收集过宽，可能建模大量无漏洞相关函数。
- 如果 graph 收集过窄，后续仍会有 snapshot miss。
- SCC 内语义依赖无法严格 leaf-first，需要特殊 placeholder 或分组建模策略。
- 现有 report/token 指标需要区分 `global_model` 与后续 per-entry analysis。

## 推荐落地顺序

1. 增加 `enable_global_model` 配置，但默认关闭。
2. 实现全局 reachable graph 收集与统计，只 dry-run，不改变 workflow。
3. 实现 `FunctionKey` 与 snapshot lock key 修正。
4. 实现 ready-queue global modeler。
5. 在 benchmark config 中开启 `enable_global_model`，复用 `parallel_workers/max_premodel_depth/max_premodel_callees`。
6. 对比开启前后的：
   - `get_function_snapshot` 空结果率。
   - semantic_modeler/deep_worker/vulnerability_analyzer 的 snapshot miss。
   - token 成本。
   - wall time。
   - Recall/Precision/F1。
7. 稳定后再考虑是否替换 default workflow 中的 per-entry premodel/model_entry。
