# 架构优化实施计划：过滤 LLVM intrinsic callee

## 1. 计划状态

- 状态：待实施
- 计划日期：2026-07-22
- 实施范围：仅调整 `zscope/retrieval/code_index.py` 的对外 callee 记录过滤。
- 本阶段不修改 fallback 文件，不把 LLVM intrinsic 转换为 `effects`，不删除 KnowledgeDB 中的原始 SVF 数据。

## 2. 背景与问题

在 `test/range` benchmark 中，源码函数：

```c
unsigned char local_cursor[32] = {0};
```

经 Clang lowering 后会产生 LLVM intrinsic `llvm.memset.p0.i64`。SVF Andersen callgraph 将该 intrinsic 作为间接调用边导入 KnowledgeDB：

```text
caller_name = _runtime_stream_commit_cursor
callee_name = llvm.memset.p0.i64
call_file   = src/lifecycle.c
call_line   = 0
source      = svf-ander
```

当前 `UnifiedBackend.get_callees()` 将 `indirect_calls` 中的该记录与普通调用边合并，`CodeIndex` 再将其暴露给上层。旧版 Semantic Modeler prompt 因此出现：

```json
{
  "callee_index_name": "llvm.memset.p0.i64",
  "callsite_lines": [],
  "call_type": ["indirect"]
}
```

这会造成三个问题：

1. LLVM intrinsic 被误认为普通 external callee。
2. GlobalModeler 可能尝试把 intrinsic 放入 unresolved callee 解析流程。
3. Semantic Modeler 可能对它调用 `get_function_info` 或 `get_function_snapshot`，产生无效查询和额外 token。

## 3. 实施目标

在 `CodeIndex` 对外返回 callee 记录之前，过滤所有名称以 `llvm.` 开头的 LLVM intrinsic：

- 不出现在 `CodeIndex.get_callees()` 返回值中。
- 不出现在 `find_function_infos()` 的 `project_callees` 或 `external_callees` 中。
- 不参与 callee 数量限制和 truncation 统计。
- 不进入 GlobalModeler 的 reachable graph 或 unresolved external 统计。
- 不再进入 Semantic Modeler 的 callee metadata 和 prompt。

本阶段只做过滤，不建立 intrinsic 到统一 `effects` 的映射。`llvm.memset.*` 的内存清零语义后续如有需要另行设计。

## 4. 设计方案

### 4.1 统一名称判断

在 `CodeIndex` 内增加私有判断 helper，例如：

```python
@staticmethod
def _is_llvm_intrinsic_callee(name: str) -> bool:
    return str(name or "").strip().startswith("llvm.")
```

判断只用于 callee 输出过滤，不影响：

- 用户直接按函数名查询的 `get_function_impl()`。
- KnowledgeDB 中的原始 `indirect_calls` 数据。
- SVF callgraph 文件和调试数据。

LLVM intrinsic 使用 `llvm.` 保留命名空间，普通 C/C++ 源码函数不会自然产生带点号的函数标识符；因此当前阶段可以按前缀过滤。手写 LLVM IR 或特殊 asm symbol 的例外不在本阶段处理，但需要在风险中记录。

### 4.2 过滤点

#### A. 普通 callee records

修改 `CodeIndex._filter_callee_records()`：

- 读取 record 的 `name`。
- 先判断空值、伪 callee 和 `llvm.*`。
- 过滤后再执行去重。
- 保持当前 `limit` 由调用方控制的语义。

该路径覆盖 `CodeIndex.get_callees()`，从而影响 GlobalModeler、普通调用图和其他直接使用 callee records 的消费者。

#### B. 名称型 callee 列表

修改 `CodeIndex._filter_callee_names()`：

- 对 regex/source fallback 提取的名字使用同一 helper。
- 正常情况下源码不会产生 `llvm.*`，但统一过滤逻辑可避免未来后端或中间层混入同名伪 callee。

#### C. function-info callee 分组

修改 `CodeIndex._split_function_info_callees()` 或其进入点：

- 在 project/external 分类、聚合、截断之前过滤 `llvm.*`。
- 确保 intrinsic 不占用 `FUNCTION_INFO_CALLEES_LIMIT` 或 external callee limit。
- 确保 `project_callees_truncation` / `external_callees_truncation` 的 `total` 不包含被过滤的 intrinsic。

这样可以同时覆盖 `find_function_infos()` 和 `build_semantic_model_input()` 的结构化 metadata。

### 4.3 保留原始数据

本阶段不修改：

- `KnowledgeDB.indirect_calls` 表。
- `SvfOutputMapper.import_callgraph()`。
- UnifiedBackend 的底层 DB 查询结果。
- SVF DOT 文件和 CPG/bitcode 产物。

这样可以保留 IR 级别排查能力；过滤只发生在 CodeIndex 面向函数建模和调用关系消费者的输出边界。

## 5. 测试计划

### 5.1 CodeIndex 单元测试

新增或扩展 CodeIndex 测试，使用 fake backend/KnowledgeDB 返回：

```text
project_func
external_api
llvm.memset.p0.i64
llvm.memcpy.p0.p0.i64
```

验证：

- `get_callees()` 只返回 `project_func` 和 `external_api`。
- 所有 `llvm.*` record 都被过滤。
- 非 LLVM 名称、宏名称和正常 external API 不受影响。
- 重复项去重仍保持原有顺序。

### 5.2 function-info schema 输入测试

验证 `find_function_infos()`：

- `project_callees` 不包含 `llvm.*`。
- `external_callees` 不包含 `llvm.*`。
- intrinsic 被过滤后不会错误触发 truncation。
- `callsite_lines=0` 的 SVF intrinsic 不会出现在公开 callee metadata 中。

### 5.3 GlobalModeler 回归测试

使用包含 `{0}` 初始化或 fake SVF indirect edge 的函数，验证：

- `llvm.memset.p0.i64` 不进入 GlobalModeler graph node。
- 不增加 `unresolved_external_callees`。
- 不触发对 intrinsic 的 `get_function_info` / `get_function_snapshot` 查询。
- 其他项目 callee 仍能正常建图和建模。

### 5.4 原始数据保留测试

验证过滤不会删除底层 DB 事实：

- `indirect_calls` 仍能查询到 `llvm.memset.p0.i64`。
- SVF 解析与 DB 导入测试保持通过。
- 只有 CodeIndex 对外 projection 发生变化。

## 6. 验收标准

- `CodeIndex.get_callees()`、`find_function_infos()` 和 Semantic Modeler 输入中不存在 `llvm.*` callee。
- `llvm.memset.p0.i64` 不再出现在 GlobalModeler unresolved 统计或 Semantic Modeler prompt 中。
- `project_callees`、`external_callees` 的截断数量和 `total` 只统计可对外暴露的普通 callee。
- 原始 KnowledgeDB/SVF 数据仍完整存在。
- 正常项目函数、external API、宏和普通 indirect callee 的现有行为不变。
- 相关 CodeIndex、KnowledgeDB、SVF、Semantic Modeler 和 GlobalModeler 回归测试通过。
- 不修改任何 fallback 文件。

## 7. 风险与后续工作

### 7.1 当前阶段的语义损失

过滤后，`llvm.memset.*`、`llvm.memcpy.*`、`llvm.trap`、overflow intrinsic 等不会直接进入函数 snapshot。由于本计划明确暂不转换为 `effects`，这些 intrinsic 的 IR 级语义只保留在底层 DB/SVF 数据中。

后续如需要增强语义，可单独设计：

- `llvm.memset.*` → memory write/zero-fill effect。
- `llvm.memcpy.*` / `llvm.memmove.*` → memory copy effect。
- `llvm.trap` / `llvm.ubsantrap` → abnormal termination/error path。
- `llvm.*with.overflow` → checked arithmetic effect。

### 7.2 特殊符号风险

手写 LLVM IR、特殊 `asm` 命名或非标准编译链理论上可能产生带 `llvm.` 前缀的非 intrinsic 符号。当前 benchmark 和标准 Clang/SVF 路径不包含此类定义；后续若发现真实项目需要支持，应改为“前缀 + LLVM intrinsic registry/项目定义双重判断”。

### 7.3 过滤层次风险

本计划只修改 CodeIndex 输出边界。如果其他模块直接读取 KnowledgeDB 或 UnifiedBackend，则仍可能看到原始 `llvm.*` 边；这属于有意保留的 IR 分析行为，不应在本阶段通过额外的全局删除来解决。

## 8. 实施顺序

1. 增加 `_is_llvm_intrinsic_callee()` helper。
2. 修改 `_filter_callee_records()` 和 `_filter_callee_names()`。
3. 修改 function-info callee 分组入口，确保过滤发生在分类、聚合和截断之前。
4. 补充 CodeIndex、function-info 和 GlobalModeler 测试。
5. 运行 focused regression 与完整相关回归。
6. 对 benchmark 重新生成 Semantic Modeler prompt/工具 metrics，确认 intrinsic 查询失败数量下降。
7. 在 `new_docs/architecture_optimation.md` 或架构实施记录中记录最终行为、测试结果和任何计划偏差。
