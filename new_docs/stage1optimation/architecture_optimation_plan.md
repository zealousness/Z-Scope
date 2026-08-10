# 一、 架构优化实施计划：过滤 LLVM intrinsic callee

## 1. 计划状态

- 状态：已完成（2026-07-22）
- 计划日期：2026-07-22
- 实施范围：在 `zscope/retrieval/code_index.py` 的对外 callee 记录过滤，并在 GlobalModeler / Semantic Modeler 输入路径验证结果。
- 本阶段不修改 fallback 文件，不把 LLVM intrinsic 转换为 `effects`，不删除 KnowledgeDB 中的原始 SVF 数据。

### 实施结果与计划偏差

- 已实现 `_is_llvm_intrinsic_callee()`、`_filter_callee_names()`、`_filter_callee_records()` 和 `_split_function_info_callees()` 的统一过滤；过滤发生在 function-info 的分类、聚合与截断之前。
- `CodeIndex.get_callees(limit=N)` 改为过滤后再应用调用方上限；若底层结果被 intrinsic 或重复项占用，会扩展查询，最多读取 1,000,000 条候选。这是原计划未列出的必要调整，避免 intrinsic 挤占 GlobalModeler 的 breadth limit。
- 已验证原始 KnowledgeDB / SVF 事实仍保留。4 个 focused 测试、68 个相关测试、133 个扩展相关测试及全量 `pytest -q`（771 passed）均通过。
- 尚未重新运行会产生外部 LLM API 成本的 benchmark，因此 intrinsic 查询失败数和 token 变化仍是后续验证项。

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
- 不出现在 `find_function_infos()` 的 `project_callees`、`external_callees` 或 `unresolved_callees` 中。
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
- 确保 `project_callees_truncation` / `external_callees_truncation` / `unresolved_callees_truncation` 的 `total` 不包含被过滤的 intrinsic。

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
- `unresolved_callees` 不包含 `llvm.*`。
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
- `project_callees`、`external_callees`、`unresolved_callees` 的截断数量和 `total` 只统计可对外暴露的普通 callee。
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

1. 已完成：增加 `_is_llvm_intrinsic_callee()` helper。
2. 已完成：修改 `_filter_callee_records()` 和 `_filter_callee_names()`。
3. 已完成：修改 function-info callee 分组入口，确保过滤发生在分类、聚合和截断之前。
4. 已完成：补充 CodeIndex、function-info、GlobalModeler 与原始 DB 事实保留测试。
5. 已完成：运行 focused regression、相关回归和全量回归。
6. 待后续单独执行：对 benchmark 重新生成 Semantic Modeler prompt/工具 metrics，确认 intrinsic 查询失败数量下降；该步骤会产生外部 LLM API 成本。
7. 已完成：在 `new_docs/architecture_optimation.md` 记录最终行为、测试结果和计划偏差。

# 二、架构优化实施计划：函数指针调用分类、SVF 物化一致性与 Unified callee 归一化

## 1. 计划状态

- 状态：部分已实施
- 计划日期：2026-07-24
- 问题来源：`test/range` 全局语义建模 benchmark `global_model_20260724_132626`
- 主要样例：`_runtime_release_hash_node@src/lifecycle.c:2693-2704`
- 后端范围：`clang` / `clangd` / `unified`，重点修复 `unified = Clang + SVF` 路径
- 数据范围：`call_edges`、`indirect_calls`、SVF DOT 产物、function-info callee projection、Semantic Modeler 输入
- 本计划不通过修改 Agent fallback 文件规避后端错误，不把函数指针字段伪装成普通 external function，也不删除原始 SVF 调试产物

### 已实施范围（2026-07-24）

SVF artifact 与 KnowledgeDB 的物化一致性已完成：采用 metadata generation、per-group marker 和全局 manifest 验证数据库物化；artifact 有效但 marker 缺失时会事务性 replay，而不是重跑 WPA/Saber；恢复过程使用 savepoint 和进程内写锁。SQLite 未新增表或字段。

仍待实施的是 Clang 函数指针分类、SVF DOT 红/黑边语义解析、callsite-aware 归属、Unified callee 归一化、project/external/unresolved 的 LLM schema 以及 Global/Semantic Modeler 接入。下文中未标记“已实施”的设计均保持待办。

## 2. 背景与现象

目标源码通过结构体字段保存分配和释放函数指针：

```c
typedef void* (*RuntimeAllocFn)(size_t size);
typedef void (*RuntimeFreeFn)(void* ptr);

typedef struct {
    RuntimeAllocFn mem_alloc_func;
    RuntimeFreeFn mem_free_func;
} RuntimeLfhashTable;

int _runtime_release_hash_node(size_t node_size, int use_header_pool) {
    RuntimeLfhashTable table;
    table.mem_alloc_func = use_header_pool ? _runtime_header_alloc : _safe_malloc;
    table.mem_free_func = use_header_pool ? _runtime_noop_free : free;

    void* node = table.mem_alloc_func(node_size + 32u);
    if (!node) {
        return -1;
    }
    table.mem_free_func(node);
    return 0;
}
```

本次 benchmark 生成的公开 function metadata 却是：

```json
{
  "project_callees": [],
  "external_callees": [
    {
      "callee_index_name": "mem_alloc_func",
      "callsite_lines": [2698],
      "call_type": ["direct"]
    },
    {
      "callee_index_name": "mem_free_func",
      "callsite_lines": [2702],
      "call_type": ["direct"]
    }
  ]
}
```

这两个名称不是外部函数，而是 `RuntimeLfhashTable` 的函数指针字段。Semantic Modeler 因此对它们调用 `get_function_info`，产生两次确定性的 `Function not found`。更严重的是，真实候选目标没有进入初始 metadata，最终 snapshot 将 `_runtime_noop_free` 分支错误建模为已经释放内存。

当前 KnowledgeDB 原始事实进一步表明：

```text
call_edges:
  _runtime_release_hash_node -> mem_alloc_func  line=2698 call_type=direct
  _runtime_release_hash_node -> mem_free_func   line=2702 call_type=direct

indirect_calls:
  0 rows
```

但保留的 SVF `callgraph_final.dot` 已经解析出 `_runtime_release_hash_node` 到以下四个候选的红色边：

- `_runtime_header_alloc`
- `_safe_malloc`
- `_runtime_noop_free`
- `free`

因此问题不是单一的“模型误用工具”，而是后端在调用种类识别、SVF 结果物化、跨后端合并和公开数据建模上存在连续的信息损失。

## 3. 根因分析

### 3.1 Clang 调用边提取统一硬编码为 direct

`ClangExtractor._extract_call_edges_from_call_hierarchy()` 当前只读取 clangd outgoing call 的目标名称和位置，不检查目标 symbol kind，也不检查调用表达式是 `DeclRefExpr`、`MemberExpr` 还是函数指针变量，最终统一写入：

```python
(caller_name, caller_file, callee, callee_file, call_line, "direct")
```

正则回退 `_extract_call_edges_by_regex()` 使用：

```python
r"\b([a-zA-Z_]\w*)\s*\("
```

该表达式会从 `table.mem_alloc_func(` 中提取末尾标识符 `mem_alloc_func`，并同样硬编码为 `direct`。所以无论主路径还是回退路径，成员函数指针都可能被降格为普通具名直接调用。

### 3.2 项目函数/宏无法匹配时统一归入 external

`CodeIndex._function_info_callee_descriptor()` 当前只区分：

1. 唯一项目函数；
2. 唯一项目函数式宏；
3. 其他名称全部作为 external。

`mem_alloc_func` 和 `mem_free_func` 既不是项目函数，也不是函数式宏，于是进入 external fallback。当前 `external` 实际表示“项目函数和宏均未匹配”，并不等价于“已确认是外部库函数”。这一语义过载会把函数指针字段、解析失败符号和真实外部 API 混在一起。

### 3.3 Clang TU purge 与 SVF 缓存复用不一致

本次构建中 Clang 增量层认为 `20/20` 文件发生变化。`KnowledgeDB.purge_tu_data()` 在删除 TU 数据时会按 `call_file` 删除 `indirect_calls`。

随后 SVF 发现 source fingerprint 变化，但 BitcodeBuilder 复用了全部 merged bitcode。`SvfAnalyzer.run()` 因此走“刷新 fingerprint、不重新运行 SVF”的提前返回分支。该分支没有验证数据库中的 SVF 物化行是否仍然存在，也没有重新导入已有 DOT 产物。

最终形成：

```text
TU purge 删除 indirect_calls
  +
merged bitcode 复用导致 SVF 不运行、不重新导入
  =
indirect_calls 空表，但缓存状态仍被标为成功
```

### 3.4 SVF 导入器没有兑现“只导入间接边”的契约

`SvfOutputMapper.import_callgraph()` 的注释要求只导入现有 direct call edge 中不存在的边，但当前实现没有使用 `existing_edges`，也没有读取 DOT edge 的颜色或间接属性，而是将解析出的全部 caller → callee 边写入 `indirect_calls`。

因此在正常重跑时还存在另一个方向的污染：普通直接调用可能同时以 direct 和 indirect 两种来源进入公开 metadata。

### 3.5 UnifiedBackend 只追加，不校正

`UnifiedBackend.get_function_info_callees()` 当前先读取 `call_edges`，再把 `indirect_calls` 逐条追加到同一个列表。它不会：

- 识别 `mem_alloc_func` 是函数指针占位符；
- 用 SVF 候选替换错误的 external direct 边；
- 按 callsite 把候选目标归属到具体函数指针调用；
- 表达 unresolved indirect call；
- 抑制同一事实的 direct/indirect 冲突。

所以即使 SVF 正常导入，错误字段边仍可能和四个真实候选同时暴露。

### 3.6 Semantic Modeler 输入缺少函数指针专用语义

当前输入 schema 只有 `project_callees` 和 `external_callees`，且 external fallback 同时承载“已确认外部目标”和“项目定义未命中”两类语义。函数指针字段一旦落入 `external_callees`，模型很容易把它视为已确认外部函数；普通未解析名称也无法与可靠 external target 区分。

缺少以下必要信息：

- 函数指针/字段的规范身份；
- 调用点表达式和行号；
- 候选目标及解析来源；
- resolution status；
- 置信度和候选完整性；
- 候选 snapshot/summary。

## 4. 实施目标

### 4.1 正确性目标

- `table.mem_alloc_func(...)`、`ptr->callback(...)` 和局部函数指针 `fp(...)` 不再被标为 direct。
- 函数指针字段不再作为普通 `external_callees` 暴露。
- SVF 已解析的真实候选能够稳定进入 KnowledgeDB 和公开 metadata。
- Clang TU 重建不会造成“SVF 状态成功但 `indirect_calls` 已被删除”的不一致。
- 公开结果通过每个 callee 内的 `direct_callsite_lines` 和 `indirect_callsites` 区分直接调用与已解析的间接调用，并将目标互斥分类为 `project_callees`、`external_callees`、`unresolved_callees`。
- `_runtime_release_hash_node` 的两个调用点能够分别关联正确候选。

### 4.2 语义建模目标

- Global Modeler 可将间接候选纳入可达图，但不得把函数指针字段本身当作图节点。
- Semantic Modeler 只对 `project_callees[].callee_index_name` 查询 snapshot，不对 `mem_alloc_func` 之类的字段名调用 `get_function_info`。
- 候选目标已有 snapshot 时直接预加载摘要；缺失时按现有全局建模策略建模。
- 可定位到具名未解析目标时归入 `unresolved_callees`；无法形成可靠 callee name或无法映射调用点的底层事实不构造虚假公开 callee，模型不得据此猜测函数名。

### 4.3 增量与可恢复性目标

- SVF 缓存命中必须同时验证分析产物和 DB 物化状态。
- 数据库行被清除但 DOT/工具产物仍有效时，优先重导入而不是重新运行 WPA。
- 产物缺失或版本不兼容时才重新运行 SVF。
- 日志必须区分 `reused analysis and DB rows`、`reimported cached artifact`、`reran SVF` 和 `SVF unavailable`。

### 4.4 兼容性目标

- 现有普通 direct project/external callee 输出保持兼容。
- 同一个真实函数既被直接调用又是间接候选时，只保留一个 canonical callee 记录，并分别填充 `direct_callsite_lines` 和 `indirect_callsites`。
- LLM 可见 schema 不再包含 `call_type`；调用方式可由上述两个字段是否为空直接推导。
- `unresolved_callees` 仅在非空时暴露；`project_callees` 和 `external_callees` 继续作为常规顶层字段输出，但 item schema按本计划升级。
- 原始 `call_edges`、`indirect_calls` 和 SVF DOT 保留可诊断性。
- 不以 Prompt 修补替代后端事实修复。

## 5. 目标数据模型

### 5.1 call edge 增加 callee kind

建议为 `call_edges` 增加可迁移字段：

```text
callee_kind TEXT DEFAULT 'unknown'
```

允许值：

- `function`
- `function_like_macro`
- `function_pointer_field`
- `function_pointer_variable`
- `unknown_callable`

底层 `call_type` 可继续表示调用方式：

- `direct`
- `indirect`

不要继续用 `callee_name` 是否匹配项目函数来反推底层 `call_type`。该字段只服务 KnowledgeDB、后端归一化和诊断，不进入 LLM 可见 schema。

如暂时不迁移表结构，第一阶段可以把 `callee_kind` 保存在提取阶段内部 record，并在 function-info projection 前完成分类；但完整实施应落库，以便调试和增量复用。

### 5.2 LLM 可见的三类 callee 公开结构

function-info、snapshot program-owned context 和 Semantic Modeler 输入继续以真实 callee 为中心，不新增独立的 `indirect_callees` 或 `candidate_targets`。公开目标互斥分为三类：

- `project_callees`：已解析到唯一项目实现；
- `external_callees`：已确认的非项目外部函数，并具有可靠函数签名；
- `unresolved_callees`：具有可用名称和调用点、但无法归入前两类的目标。

#### A. project_callees

`project_callees` 新增必填 `callee_signature`，字段位置固定在 `callee_index_name` 之后、`is_static` 之前：

```json
{
  "project_callees": [
    {
      "callee_index_name": "_runtime_header_alloc@src/lifecycle.c:2680-2687",
      "callee_signature": "static void* _runtime_header_alloc(size_t size)",
      "is_static": true,
      "direct_callsite_lines": [],
      "indirect_callsites": [
        {
          "callsite_line": 2698,
          "function_pointer": "RuntimeLfhashTable.mem_alloc_func",
          "function_pointer_kind": "field",
          "function_pointer_type": "RuntimeAllocFn",
          "function_pointer_signature": "void* (*)(size_t)",
          "callsite_expression": "table.mem_alloc_func",
          "guard": "use_header_pool != 0"
        }
      ],
      "callee_summary": "..."
    }
  ]
}
```

#### B. external_callees

`external_callees` 使用真实外部函数名和可靠签名，不再使用 `callee_index_name`，也不包含 `is_static` 或 `callee_summary`：

```json
{
  "external_callees": [
    {
      "callee_name": "free",
      "callee_signature": "void free(void*)",
      "direct_callsite_lines": [],
      "indirect_callsites": [
        {
          "callsite_line": 2702,
          "function_pointer": "RuntimeLfhashTable.mem_free_func",
          "function_pointer_kind": "field",
          "function_pointer_type": "RuntimeFreeFn",
          "function_pointer_signature": "void (*)(void*)",
          "callsite_expression": "table.mem_free_func",
          "guard": "use_header_pool == 0"
        }
      ]
    }
  ]
}
```

`callee_signature` 必须来自 clangd/AST 可定位声明、编译器可见系统头声明或显式 external 配置，不能按名称猜测。只有同时具备可靠 `callee_name` 和 `callee_signature` 时才归入 `external_callees`；只有名称而签名不可确认时归入 `unresolved_callees`。本计划不为 external 生成 `callee_summary`。

#### C. unresolved_callees

新增可选顶层字段 `unresolved_callees`。它只在非空时暴露；每项只包含可确认的名称和调用点，不伪造签名、项目 identity、静态属性或 summary：

```json
{
  "unresolved_callees": [
    {
      "callee_name": "vendor_submit",
      "direct_callsite_lines": [120],
      "indirect_callsites": []
    }
  ]
}
```

三类 callee 必须互斥：同一个归一化目标不能同时出现在 `project_callees`、`external_callees` 和 `unresolved_callees`。当后端随后解析出项目实现或可靠 external identity 时，目标应从 `unresolved_callees` 迁移到相应已解析数组。

#### D. 共享调用点字段

- `direct_callsite_lines`：当前 caller 对该 callee 的直接调用行号；不存在 direct call 时必须为空数组。
- `indirect_callsites`：当前 callee 作为函数指针候选目标出现的调用点；不存在 indirect call 时必须为空数组。
- `callsite_line`：LLM 建模需要的源码行号；底层 callsite ID 不暴露。
- `function_pointer`：函数指针的规范符号身份，如 `RuntimeLfhashTable.mem_alloc_func`。
- `function_pointer_kind`：允许 `field`、`local`、`parameter`、`global`、`unknown`。
- `function_pointer_type`：源码 typedef/声明类型，如 `RuntimeAllocFn`。
- `function_pointer_signature`：展开后的函数指针签名，用于判断参数、返回值和候选兼容性。
- `callsite_expression`：目标源码中的调用表达式，不包含参数列表。
- `guard`：当前 callee 成为该间接调用目标的选择条件；无法恢复时省略，不伪造条件。

同一 callee 同时存在直接和间接调用时仍只出现一次。例如 `direct_callsite_lines=[30]` 且 `indirect_callsites` 包含第 35 行，不再生成两条 callee 记录，也不再输出 `call_type=["direct", "indirect"]`。

`mem_alloc_func`、`mem_free_func` 等函数指针字段身份只出现在 `indirect_callsites[].function_pointer`，不得成为 `external_callees[].callee_name` 或 `unresolved_callees[].callee_name`。

#### E. 数量上限与 truncation

- `project_callees` 继续使用 `FUNCTION_INFO_CALLEES_LIMIT=30`。
- `external_callees` 继续使用 `FUNCTION_INFO_EXTERNAL_CALLEES_LIMIT=20`。
- `unresolved_callees` 新增独立上限 `FUNCTION_INFO_UNRESOLVED_CALLEES_LIMIT=20`，与 external保持一致。
- `unresolved_callees` 为空时，顶层字段和 `unresolved_callees_truncation` 都省略。
- 非空且总数不超过 20 时，只暴露 `unresolved_callees`，不暴露 truncation。
- 总数超过 20 时，返回前 20 项，并增加：

```json
{
  "unresolved_callees_truncation": {
    "truncated": true,
    "returned": 20,
    "total": 27
  }
}
```

三类 callee 各自排序、去重和截断，任何一类都不得占用另一类预算。嵌套 `indirect_callsites` 使用单独预算，不能通过增加候选目标绕过顶层 callee上限。

LLM 可见 schema 不暴露 callsite ID、解析来源、SVF group、confidence 或候选完整性；这些字段只保留在底层 KnowledgeDB、SVF materialization 和归一化过程内。

### 5.3 保留候选来源和调用点

当前 `indirect_calls` 的唯一键按 caller/callee/source/group 聚合，`call_line` 常为 0，无法区分同一 caller 中多个函数指针调用点。应调整为 callsite-aware 数据：

```text
caller_name
callee_name
call_file
call_line
callsite_id
pointer_symbol
source
confidence
svf_group
```

唯一性至少包含 `callsite_id` 或 `call_file + call_line + pointer_symbol`。这些字段用于底层去重、候选归属和诊断，不进入 LLM 可见 schema。如果 SVF 暂时只能提供函数级候选，则不能向公开 `indirect_callsites` 伪造精确行号；必须先由底层 callsite 映射或 deterministic assignment resolver 完成归属。


### 5.4 SVF 物化清单

本项已实施。实际实现不新增 SQLite schema，而是在 KnowledgeDB metadata 中保存数据库级 generation、每个 tool/group 的物化 marker，以及全局 manifest：

```json
{
  "svf_db_generation": 12,
  "svf_db_import:ander:default": {
    "schema_version": 1,
  "artifact_fingerprint": "...",
    "artifact_path": ".zscope_svf/callgraph_final.dot",
    "artifact_hash": "...",
    "imported_row_count": 123,
    "db_generation": 12,
    "imported_at": 0
  },
  "svf_db_materialization": {
    "db_generation": 12,
    "groups": ["ander:default", "ander:entry_cluster_1"]
  }
}
```

`imported_row_count=0` 仍代表成功物化，不能通过派生表是否非空判断缓存状态。快速返回会同时验证 manifest、group marker、tool status、artifact 相对路径和 SHA-256；任一项失效都进入恢复流程。

`purge_tu_data()` 只有实际删除 `indirect_calls` 或 `taint_signatures` 时才递增 `svf_db_generation`。generation 为数据库级：一次实际删除会保守地使所有 group marker 过期，但避免不含 SVF 事实的普通 TU 清理造成无意义 replay。

后续 parser/callee schema 变更仍可在此 metadata 契约上增加显式版本门禁，但不得将本节已完成的实现描述为新增 SQLite 字段或 dirty 标记。

- bitcode/artifact fingerprint；
- output 文件是否存在且 hash 匹配；
- parser/materialization version；
- DB 行是否仍完整；
- 对应 group 是否被标记 dirty。

## 6. 分阶段设计方案

### 6.1 阶段 A：Clang/clangd 调用类型分类（已实施第一部分）

已于 2026-07-27 完成 `callee_kind` 落库、schema version 11 migration、clangd SymbolKind 分类，以及 regex 对 field/variable 函数指针的基础识别。复杂宏展开、需要 AST 复核的 unknown callable 和函数指针完整类型/表达式提取仍待增强。

#### A. call hierarchy 主路径

读取 clangd `CallHierarchyItem.kind`，建立明确映射：

- Function/Method → direct function；
- Field/Variable → indirect function pointer；
- 其他 kind → 进入 callsite expression/AST 复核；
- 无法确认 → `unknown_callable`，不得默认 external direct。

不要使用 magic integer，建立本地 LSP SymbolKind 常量或枚举，并补充未知版本兼容。

同时读取调用点 source range，保存 `callsite_expression`。如果 clangd 将 target URI 指向字段声明，这只能证明字段身份，不能把该字段当作实际 callee implementation。

#### B. regex 回退路径

回退分类至少覆盖：

```c
object.callback(...)
pointer->callback(...)
local_fp(...)
(*local_fp)(...)
```

成员调用可根据 callee 标识符前的 `.` / `->` 判断；局部函数指针需要结合函数局部声明、typedef 和 function symbol refs 判断。

无法可靠判断时宁可输出 `unknown_callable`，也不要硬编码 direct。正则路径应记录 `classification_source=regex` 和较低 confidence，供 Unified projection 决定是否公开。

#### C. 入库

- 更新 `call_edges` schema/migration。
- `insert_call_edge(s)` 接收 `callee_kind`。
- `KnowledgeDB.get_callees()` / `get_all_callees()` 返回该字段。
- 增量索引 purge 与 cache invalidation 覆盖新字段和新索引。

### 6.2 阶段 B：SVF parser 只导入真实间接边（已实施）

已于 2026-07-27 实现 edge color/source port 解析，并仅将 `color=red` 的边物化到 `indirect_calls`。source port 暂保留在 parser record 中，等待 callsite-aware schema 后再持久化和归属，当前不会伪造源码调用行号。

扩展 `CallGraphParser`，除 caller/callee 外解析 edge attributes 和 source port：

```python
{
    "caller": "...",
    "callee": "...",
    "edge_color": "red",
    "caller_port": "s0"
}
```

优先使用 SVF 明确的 indirect edge 标记；对于当前 DOT，红色边作为 indirect candidate，黑色边作为普通 direct edge，不写入 `indirect_calls`。

若不同 SVF 版本颜色语义不稳定，应增加版本探测或使用更结构化的 WPA 输出，不能长期依赖未经验证的颜色假设。

`existing_edges` 参数必须真正参与过滤或删除，避免注释与实现不一致。建议逻辑：

1. SVF 明确 indirect → 导入；
2. SVF direct 且 Clang 已存在 → 跳过；
3. SVF direct 但 Clang 缺失 → 保留为诊断信息或单独 source，不写入 `indirect_calls`；
4. LLVM intrinsic 按第一章计划在公开边界过滤，原始底层事实仍可保留。

### 6.3 阶段 C：SVF 缓存和 DB 物化一致性

本阶段的数据库物化一致性部分已实施。其恢复决策为：

```text
tool status + replay artifact + 当前 generation marker 有效
  -> event=cache_skip，跳过工具和导入

tool status + artifact 有效，但 marker 缺失或 generation 过期
  -> event=artifact_reimport，不运行 WPA/Saber，事务性重放 artifact

artifact 缺失、hash 不匹配或解析失败
  -> event=artifact_invalid / event=recovery_failed，重跑工具并导入新结果
```

每个 group 的“删除旧数据、解析/插入 replay artifact、写入 marker、提交”处于同一 SQLite savepoint；异常会 rollback，保留旧数据和 marker。WPA 子进程可并行，实际 DB 替换由进程内写锁串行化。Ander 使用 DOT replay；Saber 成功后写入稳定排序的 JSON replay artifact，旧 Saber status 缺少该 JSON 时首次升级需重跑一次。

结构化日志已区分 `cache_skip`、`artifact_reimport`、`artifact_invalid` 和 `recovery_failed`，不得再把“工具执行成功”误报为“数据库已经写入”。

仍待实施：SVF parser 的红/黑边语义和“只导入真实间接边”契约（见 6.2）。本次修复确保的是已解析 artifact 与 KnowledgeDB 的一致性，不改变现有 DOT edge 的分类规则。

### 6.4 阶段 D：Unified callee 归一化

不要再把 direct 和 indirect 两个列表简单拼接。新增内部规范化步骤，例如：

```python
_normalize_callee_facts(
    clang_edges,
    svf_edges,
    function_index,
    macro_index,
) -> NormalizedCalleeContext
```

规范化规则：

1. `callee_kind=function` 且唯一项目命中 → project direct callee；
2. `callee_kind=function_like_macro` → referenced macro；
3. `callee_kind=function_pointer_*` → 底层 indirect callsite，占位字段本身不进入 external；
4. SVF candidate 按 caller/callsite/pointer symbol解析到真实 canonical callee；
5. candidate 唯一项目命中 → 合并进对应 `project_callees` 记录的 `indirect_callsites`；
6. candidate 具有可靠外部函数身份和签名 → 合并进对应 `external_callees` 记录的 `indirect_callsites`；
7. 同一 canonical callee 已有 direct edge 时，只补充其 `indirect_callsites`，不复制 callee 记录；
8. 有可靠 `callee_name` 和具体调用点、但无法解析为项目或外部目标 → 归入 `unresolved_callees`；
9. 无可靠名称、无具体调用点或只有函数指针字段占位符 → 只保留底层 unresolved fact，不构造虚假公开 callee；
10. 同一目标解析级别提升时，从 unresolved迁移到project/external，三类公开数组保持互斥。

如果 SVF 暂时没有 callsite line，不得把函数级候选直接写入 LLM 可见 `indirect_callsites`，也不得任意把四个候选分别绑定到两个调用点。对于源码中简单的局部赋值，可以增加 deterministic assignment resolver 精化映射：

```text
mem_alloc_func -> {_runtime_header_alloc, _safe_malloc}
mem_free_func  -> {_runtime_noop_free, free}
```

该 resolver 只处理控制流明确、赋值在调用前、无跨函数逃逸的简单场景；复杂场景仍由 SVF/unknown 表达。

### 6.5 阶段 E：CodeIndex 和 function-info projection

更新 `_split_function_info_callees()`：

- 在 project/external/unresolved 分组前识别 `callee_kind`；
- 函数指针字段只作为底层 callsite identity，不成为公开 callee；
- 真实候选根据解析结果分类并合并进唯一 `project_callees` / `external_callees` / `unresolved_callees` 记录；
- `project_callees` 增加 `callee_signature`，固定放在 `callee_index_name` 后、`is_static` 前；
- `external_callees` 使用 `callee_name + callee_signature`，不再使用 `callee_index_name`；
- `unresolved_callees` 使用 `callee_name`，不伪造签名或summary，并仅在非空时暴露；
- 每个 callee 始终输出 `direct_callsite_lines` 和 `indirect_callsites`，不存在对应调用时使用空数组；
- LLM 可见结果不再输出 `call_type`；
- project上限保持30，external和unresolved分别使用独立20项上限；
- `unresolved_callees_truncation` 仅在 unresolved总数超过20时暴露；
- truncation 先按三类唯一 callee 分别统计，再对嵌套 `indirect_callsites` 应用独立预算；
- LLVM intrinsic 继续按第一章计划从公开 callee projection 过滤；
- 原始 source/confidence/group保留在底层，不进入 LLM 可见 projection。

更新 tool/schema 文档：

- `get_function_info.project_callees[]`、`external_callees[]` 和非空 `unresolved_callees[]` 返回 `direct_callsite_lines` 与 `indirect_callsites`；
- `project_callees[]` 必须返回 `callee_signature`；
- `external_callees` 明确只表示具有可靠名称和签名的真实 external，不包含 unresolved direct callee或函数指针字段；
- `unresolved_callees` 明确只表示无法归入 project/external的具名目标，并仅在非空时出现；
- `unresolved_callees_truncation` 使用与external相同的20项上限；
- `callee_index_name` 是唯一可用于 `get_function_snapshot` 的候选身份；
- `function_pointer` 和 `callsite_expression` 只是调用点证据，不可用于函数工具查询；
- 删除公开 `call_type`，并提升相关 schema/version。

### 6.6 阶段 F：Global Modeler 与 Semantic Modeler 输入

Global Modeler 构图规则：

- `project_callees` 中 `direct_callsite_lines` 或 `indirect_callsites` 任一非空即可加入可达图；
- 同一 `callee_index_name` 只创建一个函数节点，直接与间接调用点分别作为边事实保留；
- unresolved pointer symbol 不作为节点；
- callee 或间接调用点数量过多时遵循独立预算并记录 truncation；
- `external_callees` 和 `unresolved_callees` 不进入项目函数建模队列；external保留可靠签名和调用点，unresolved只保留名称与调用点。

Semantic Modeler program-owned input应包含候选 summary，Agent policy增加：

- 不得对 `function_pointer` 或 `callsite_expression` 调用 `get_function_info`；
- 需要候选语义时只使用父级 canonical `callee_index_name`；
- 父级 `callee_summary` 已提供时优先复用；
- `external_callees` 只按已提供签名和源码调用点建模，不得自行生成外部行为summary；
- `unresolved_callees` 仅表示未知调用边，不得猜测实现、签名、ownership或可能函数名；
- 同一 `function_pointer + callsite_line` 出现在多个父级 callee 时表示多候选分支，必须结合各自 `guard` 分别建模 effects/ownership，不能合并成无条件状态变化。

本例必须表达：

- `use_header_pool == 0`：`_safe_malloc` + `free`，成功路径释放内存；
- `use_header_pool != 0`：`_runtime_header_alloc` + `_runtime_noop_free`，第 2702 行不释放分配；
- 不能统一写成 `state_after=released`。

## 7. 文件级实施清单

### 7.1 生产代码

预计涉及：

- `zscope/retrieval/clang_extractor.py`
  - call hierarchy symbol-kind/表达式分类
  - regex fallback indirect 判断
  - 新 callee kind 入库
- `zscope/retrieval/knowledge_db.py`
  - schema migration
  - call edge/indirect call字段和查询
  - SVF materialization dirty 状态
  - purge 与 query cache invalidation
- `zscope/retrieval/svf_parser.py`
  - DOT edge attribute解析
  - 仅导入真实 indirect edge
  - callsite/source metadata
- `zscope/retrieval/svf_analyzer.py`
  - artifact reuse与 DB reimport分离
  - materialization integrity检查
  - tool status和日志修复
- `zscope/retrieval/unified_backend.py`
  - direct/indirect facts规范化
  - 不再简单 append
- `zscope/retrieval/code_index.py`
  - callee kind分类
  - project/external/unresolved三路callee分类
  - callee-centric `callee_signature`、`direct_callsite_lines`、`indirect_callsites` projection
  - canonical callee聚合与三类独立truncation
  - truncation与过滤
- `zscope/tools/function_info.py`
  - schema/描述更新
- `zscope/snapshots/modeling_input.py`
  - 注入三类callee、project/external签名和可选unresolved/truncation
- `zscope/snapshots/policy.py`
  - program-owned字段、预算和校验
- `zscope/snapshots/store.py`
  - 三类callee的持久化、shape兼容、依赖hash和刷新
- `zscope/agents/semantic_modeler/schema.py`
  - project/external item schema、可选unresolved和对应truncation
- `zscope/agents/semantic_modeler/agent.py`
  - program-owned三类callee上下文透传与校验
- `zscope/orchestration/global_modeler.py`
  - 仅project进入可达建模，external/unresolved按公开schema透传
- `zscope/agents/semantic_modeler/AGENT.md`
  - 函数指针字段与候选目标的工具使用规则

如果仓库约束要求同步 fallback 内容，应在实施前另行确认；本计划本身不授权修改任何 fallback 文件。

### 7.2 测试代码

预计新增或扩展：

- `tests/test_clang_incremental_extraction.py`
- `tests/test_function_info_tool.py`
- `tests/test_knowledge_db_ir_and_config.py`
- SVF parser/analyzer相关测试文件
- `tests/test_semantic_model_input.py`
- `tests/test_global_modeler.py`
- snapshot policy/store相关测试

### 7.3 文档与实施记录

- `new_docs/tools_introduction.md`
- `new_docs/architecture_optimation.md`
- 必要时更新数据库 schema/version说明
- benchmark metrics/语义对比记录

## 8. 数据库迁移与兼容策略

### 8.1 schema version

增加字段或表时提升 KnowledgeDB schema version，提供显式 migration。不得仅依赖旧表默认值把所有历史边继续解释为 direct。

历史 `call_edges.call_type=direct` 中无法可靠区分函数指针字段的记录应：

- 在全量重建时重新提取；
- 或在 migration 中标记 `callee_kind=unknown`，不得假定为 function；
- 不建议通过名称包含 `func/callback` 的启发式直接改写历史数据。

### 8.2 benchmark 重建

对本次 SVF materialization 修复，不要求删除或重建整个 KnowledgeDB。已在原异常数据库上验证：有效 Ander artifact 与旧 tool status 可在不调用 WPA、不调用 LLM 的情况下自动 replay，`indirect_calls` 从 0 恢复到 905，真实 `CodeIndex + UnifiedBackend + GlobalModeler._collect_graph` 的 reachable 从 261 恢复到 274。

本项已验证的恢复条件为：

- tool status success；
- DB `indirect_calls` 为空；
- DOT output存在且 hash匹配；
- 系统重新导入而不是跳过。

后续实施 `callee_kind` schema 迁移、Clang 调用重分类或 SVF 边语义变更时，仍应使用干净 DB 或完整重建验证，避免把新的底层事实改造与旧缓存兼容混为一谈。

### 8.3 snapshot refresh

调用图和 indirect candidate变化必须进入 snapshot dependency/hash：

- 函数指针候选变化时 target snapshot变 stale；
- candidate snapshot变化时依照现有 callee dependency策略刷新；
- callee在 project/external/unresolved之间迁移、project/external签名变化或unresolved集合变化时，target snapshot变 stale；
- 仅底层 confidence/source元数据变化但 LLM 可见 projection不变时不触发语义 snapshot刷新；
- 不得继续复用包含错误 external direct字段的旧 snapshot。

## 9. 测试计划

### 9.1 Clang call classification单元测试

构造 C fixture：

```c
typedef void (*Callback)(void*);
typedef struct { Callback cb; } Ops;

static void target(void* p) {}

void run(Ops* ops, Callback local) {
    target(NULL);
    ops->cb(NULL);
    local(NULL);
    (*local)(NULL);
}
```

验证：

- `target` → direct/function；
- `ops->cb` → indirect/function_pointer_field；
- `local` / `(*local)` → indirect/function_pointer_variable；
- member/variable符号不会被当作 external direct；
- clangd主路径和 regex fallback各有独立测试；
- unknown symbol kind不会默认 direct。

### 9.2 KnowledgeDB测试

- 新 callee kind可写入、查询和增量清理。
- migration后旧行使用安全默认语义。
- 已完成（物化一致性部分）：TU purge 实际删除 SVF 行时递增 `svf_db_generation`，旧 marker 失效并触发 artifact replay；不使用额外 dirty 字段。
- callgraph query cache在 direct/indirect增删后失效。
- callsite-aware indirect唯一键不会错误合并同 caller不同调用点。

### 9.3 SVF parser测试

使用最小 DOT fixture同时包含红边、黑边、port和多候选：

- 红边写入 `indirect_calls`；
- 黑边不作为 indirect导入；
- caller/callee解析正确；
- 重复导入幂等；
- LLVM intrinsic原始事实处理与第一章计划一致；
- parser version变化触发重新物化。

### 9.4 SVF cache/materialization测试

物化一致性测试已完成并通过。实际覆盖：marker/status/artifact 全有效时无工具调用和重复导入；marker 缺失时重放旧 DOT；TU purge 后 generation 失效并自动 replay；零行导入的合法缓存命中；hash 不匹配或 artifact 丢失时重跑；Saber JSON replay；savepoint rollback；多 group 只恢复失效 group；以及真实 `td_init -> _packet_receiver_thread -> _net_accept_connection` 离线恢复。相关回归 113 passed，聚焦回归 73 passed，`PYTHONPATH=/home/jager/Z-Scope pytest -q` 全量 811 passed。

后续仅在 parser/version 语义改变时扩展下列兼容矩阵：

| artifact | DB物化 | output | 预期 |
|---|---|---|---|
| unchanged | complete | valid | 直接复用 |
| unchanged | marker 缺失或 generation 过期 | valid | 重新导入，不运行WPA |
| unchanged | marker 缺失或 generation 过期 | missing | 运行WPA |
| changed | 任意 | 任意 | 运行WPA |
| unchanged | parser version changed | valid | 使用新parser重新导入 |

已完成的重点回归序列：

1. 预置成功 tool status和有效 DOT；
2. TU purge删除 `indirect_calls`；
3. BitcodeBuilder报告全部 merged group reused；
4. 验证 analyzer重新导入并恢复 edge count；
5. 验证日志不得声称“写入成功”却保持空表。

### 9.5 Unified/function-info测试

输入：

- Clang字段占位边 `mem_alloc_func` indirect；
- SVF候选 `_runtime_header_alloc`、`_safe_malloc`；
- 普通 direct project callee；
- 普通 external API；
- 同一真实函数兼有 direct/indirect来源。

验证：

- 字段占位符不成为 project/external/unresolved callee，只出现在真实候选的 `indirect_callsites[].function_pointer`；
- candidate canonical identity、静态属性和函数指针签名正确；
- 同一 canonical callee只有一条记录，direct行和indirect调用点分别聚合；
- 不存在indirect call时 `indirect_callsites=[]`，不存在direct call时 `direct_callsite_lines=[]`；
- 公开结果不包含 `call_type`、callsite ID、source、SVF group或confidence；
- project callee的 `callee_signature` 位于 `callee_index_name` 后、`is_static` 前；
- 已确认external使用 `callee_name + callee_signature`，不使用 `callee_index_name`；
- unresolved使用 `callee_name`，不包含伪造signature、is_static或summary；
- 同一归一化callee不能同时出现在project、external和unresolved中；
- `unresolved_callees` 空时字段省略，非空不超过20时无truncation，超过20时返回20项和准确的 `unresolved_callees_truncation`；
- direct external API保持正确分类和调用点；
- 同一函数的direct/indirect聚合不丢LLM需要的行号、指针身份、签名、表达式和guard；
- project 30、external 20、unresolved 20以及嵌套indirect callsite的truncation分别准确统计；
- 无可靠callee name时不输出虚假 unresolved function。

### 9.6 Global/Semantic Modeler测试

- resolved project candidate以普通 `project_callees` canonical记录进入全局可达图。
- pointer symbol本身不成为函数节点。
- 父级 callee snapshot/summary及其 `indirect_callsites` 能进入初始 prompt。
- external和unresolved不进入项目可达函数建模队列，但按各自schema进入初始prompt。
- recorder中不出现 `get_function_info(mem_alloc_func)` 或 `get_function_info(mem_free_func)`。
- 多候选条件分支不会统一为无条件释放。
- unresolved callee不会诱导模型猜测签名、实现或ownership。

### 9.7 端到端 benchmark验收

重新运行 `test/range` 相同 global model benchmark，至少验证：

- `_runtime_release_hash_node.project_callees` 包含三个项目函数候选，每个候选通过 `indirect_callsites` 表达调用点；
- `free`作为 `external_callees` canonical记录存在，且 `indirect_callsites` 包含第2702行；
- `free`记录包含 `callee_name="free"` 和 `callee_signature="void free(void*)"`；
- `external_callees`和`unresolved_callees`均不存在 `mem_alloc_func`、`mem_free_func` callee记录；
- benchmark中的具名未解析目标进入可选 `unresolved_callees`，超过20项时truncation准确；
- 公开 callee metadata不存在 `call_type`；
- `get_function_info`相关两次失败消失；
- snapshot正确区分 `use_header_pool` 两条路径；
- `indirect_calls` 不为空且包含该 target的四个候选；
- 重复增量构建后结果仍稳定，不因 TU purge再次变空。

## 10. 验收标准

- 所有成员/局部函数指针调用在公开 metadata 中不再标为 external direct。
- `_runtime_release_hash_node` 的真实四个候选可稳定查询并进入语义建模上下文。
- 已完成：KnowledgeDB 不再出现“SVF cache成功但 materialized edge为空且未重新导入”的状态；旧异常 benchmark DB 已从 `indirect_calls=0` 自动恢复到 905，reachable 恢复至 274，并在重复运行后保持稳定。
- SVF parser不再把全部普通调用图边无差别写入 `indirect_calls`。
- UnifiedBackend以互斥的 project/external/unresolved记录输出调用关系；已确认external具有签名，具名未解析目标进入可选unresolved，无可靠名称的底层事实不伪造公开callee。
- `unresolved_callees` 和 `unresolved_callees_truncation` 遵守仅非空/仅实际截断时暴露的契约，上限为20。
- Semantic Modeler不再对函数指针字段调用 `get_function_info`。
- `_runtime_release_hash_node` snapshot不再把 `_runtime_noop_free` 分支标记为 released。
- 普通 direct调用、宏调用、真实 external API和同callee direct+indirect聚合行为无回归。
- 已完成（物化范围）：相关回归 113 passed、聚焦回归 73 passed、显式 `PYTHONPATH` 的全量回归 811 passed；真实 GlobalModeler 调用图 benchmark 已验证。函数指针分类与 LLM schema 完成后，仍需运行其 focused tests、相关完整回归和完整语义建模 benchmark。
- 实施不修改用户手工改动文件，不修改 fallback 文件，除非用户另行明确授权。

## 11. 风险与控制

### 11.1 clangd SymbolKind差异

不同 clangd/LSP版本可能返回不同 kind或缺失 kind。必须保留 expression/AST复核和 unknown fallback，不能把某个 magic number永久视为函数指针。

### 11.2 regex误判

仅用 `.` / `->` 可识别成员调用，但不能完整覆盖宏展开、复杂括号和本地函数指针。regex路径必须保守，并通过低 confidence/unknown表达不确定性。

### 11.3 SVF过近似

Andersen分析可能返回超集候选。source/confidence和partial status保留在底层；公开 metadata只暴露已能映射到具体调用点的候选，并通过父级callee、`indirect_callsites`和可用`guard`表达分支。Semantic Modeler不得把所有候选effects当成同时发生。

### 11.4 DOT颜色契约

当前样例中红色代表间接解析边，但不同SVF版本需要验证。如果颜色不稳定，应使用SVF结构化输出或扩展runner导出明确edge kind，而不是依赖颜色。

### 11.5 增量缓存性能

增加 materialization检查和重导入会增加少量DB/解析成本，但应显著小于重跑WPA。需记录 reuse/reimport/rerun耗时和edge count，以验证收益。

### 11.6 schema兼容

将公开 callee schema从 `project/external + callsite_lines + call_type`调整为 `project/external/unresolved + direct_callsite_lines + indirect_callsites` 会影响 snapshot store、policy、JSON输出和消费者。实施时 project新增必填签名，external改用 `callee_name + callee_signature`，unresolved为按需可选顶层字段；每条callee记录必须为两个调用点字段提供默认空数组。需要提升schema/version并保持旧snapshot读取兼容；旧snapshot应按依赖变化标记stale，而不是直接报格式错误。

### 11.7 过度过滤

函数指针字段不得进入普通 external或unresolved；具名但未能确认项目/外部身份的direct callee应进入 `unresolved_callees`。分类必须基于callee kind、可靠签名解析和call expression，不能仅凭名称包含 `func`、`callback`、`handler`等启发式过滤。

## 12. 实施顺序

1. 已完成：固化 benchmark和DB事实，并记录 `_runtime_release_hash_node` 端到端失败现象。
2. 部分完成：SVF materialization metadata 已用 KnowledgeDB metadata 的 generation、per-group marker 和 manifest 实现；`callee_kind` 与 callsite-aware indirect 仍待设计和迁移。
3. 已完成第一部分：修复clangd call hierarchy的 Function/Method/Constructor/Field/Variable/unknown分类并补主路径单元测试；复杂 AST 复核待后续增强。
4. 已完成第一部分：regex fallback已识别成员、typedef变量和显式解引用函数指针，并保留保守unknown；复杂宏场景待后续增强。
5. 已完成：扩展SVF DOT parser，只导入红色真实间接边并在parser record保留edge color/source port。
6. 已完成：以 generation 失效（而非 dirty 标记）修复 TU purge 后的 SVF artifact 重新物化流程。
7. 已完成：per-group tool status 与 DB 物化 marker 已解耦，支持 artifact replay 和事务性 group 替换。
8. 重构UnifiedBackend callee归一化，不再简单append。
9. 扩展CodeIndex/function-info的project/external/unresolved三路callee projection：增加签名、`direct_callsite_lines`、`indirect_callsites` 和独立truncation，删除公开 `call_type`。
10. 将候选目标接入Global Modeler可达图和Semantic Modeler program-owned输入。
11. 更新Agent policy，禁止查询pointer symbol，只允许使用父级canonical `callee_index_name`。
12. 运行focused tests；如测试失败，仅修改测试与实施记录，不回退或擅自修改用户手工实现。
13. 部分完成：已运行物化修复的相关与全量回归，并在原异常 KnowledgeDB 上完成端到端恢复；函数指针 schema 改造完成后，仍需额外运行干净 DB benchmark。
14. 已完成（物化范围）：已模拟 TU purge 并在真实异常数据库上重复运行，验证 artifact replay 后 `indirect_calls=905`、`taint_signatures=13` 保持稳定。
15. 已完成（物化范围）：`new_docs/architecture_optimation.md` 已记录实际改动、测试、benchmark 恢复结果和计划偏差；后续 schema 实施须继续追加记录。

## 13. 实施完成后的指标

实施记录至少报告：

- direct/indirect/unknown callable数量；
- project/external/unresolved公开callee数量及各自truncation；
- external签名解析成功率与仅名称未解析数量；
- function-pointer callsite数量和candidate分布；
- resolved/partially resolved/unresolved比例；
- SVF cache reuse/reimport/rerun次数与耗时；
- 每group materialized edge count；
- TU purge后重物化次数；
- `get_function_info`对pointer symbol的无效调用次数；
- `_runtime_release_hash_node` snapshot语义差异；
- 全局建模API calls、tool calls、token、wall time和成功率变化；
- 原始底层边与公开projection过滤/归一化数量。

成功标准不仅是两次工具失败消失，还必须证明真实候选被恢复、增量缓存可重复、最终函数语义正确。
