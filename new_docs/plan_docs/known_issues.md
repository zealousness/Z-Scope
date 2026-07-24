# Known Issues

## KI-001 `CodeIndex.get_method()` fallback 与函数索引职责不清

### 问题描述

`CodeIndex._function_index` 已由后端的 `build_function_index()` 构建，但`CodeIndex.get_function_impl()` 在索引未命中时仍会调用后端`get_method()`，并将查询结果动态写回 `_function_index`。

在 Clang 和 Unified 后端中，`build_function_index()` 与 `get_method()`读取同一个 KnowledgeDB `functions` 表，并且都只查询非声明函数。因此在数据库状态未发生变化且索引完整构建的情况下，`get_method()` 通常无法找到`_function_index` 中不存在的函数，这条 fallback 主要是防御性兼容逻辑。

Joern 后端的两条查询路径并不完全一致：批量索引排除 external method，而单点 `get_method()` 查询没有相同过滤条件；同时批量结果按函数名暂存时可能覆盖同名函数。因此单点查询有时可能返回批量索引未保留的节点，但只返回第一条匹配，且不能按文件路径可靠消歧。

### 影响

- `_function_index` 是否为完整、权威的函数目录没有明确约定。
- `get_function_impl()` 可能在运行期间动态改变函数索引，而  `get_function_info()` 不执行相同的补查，两个接口可能观察到不同的函数集合。
- `get_method()` 只返回一个匹配，不适合处理同名函数或重载函数。
- Joern 的批量查询和单点查询过滤条件不一致，可能引入 external method 或不稳定匹配。
- 当前 fallback 的实际收益依赖后端实现，行为缺少统一契约。

### 暂缓原因

该问题属于底层函数索引构建和符号解析职责设计，不属于当前 Agent 工具交互、prompt 和上下文优化的主要范围。目前没有证据表明它阻塞 Agent 交互优化，因此暂不修改实现。

### 后续建议

后续重构时应明确选择一种模型：

1. 将 `_function_index` 定义为完整且权威的函数目录，索引构建完成后不再通过   `get_method()` 隐式补入记录。
2. 如果需要支持增量后端更新，提供统一的 `resolve_function_records()` 或显式   refresh 接口，返回全部匹配、支持 `file_path` 消歧，并统一同步函数索引。

同时应让 `get_function_impl()` 和 `get_function_info()` 复用同一符号解析层，避免两个接口采用不同的索引补全策略。

## KI-002 backend-backed macro symbol context 缺少降级提取

实施状态：`referenced_macros` 的 KnowledgeDB-backed 降级路径已修复（2026-07-23）；宏 `referenced_globals` 的自动识别明确撤销，等待后续 `search_global` 工具。

### 问题描述

`CodeIndex.find_function_infos()` 为 function-like macro 构造 function info 时，会从完整宏定义文本提取：

- `callees`
- `referenced_globals`
- `referenced_macros`

其中 `callees` 始终通过 `extract_function_calls()` 对宏体执行文本/正则提取，再尝试将名称解析为 canonical `callee_index_name`，不依赖后端提供宏调用图。

旧实现中，`_macro_function_info_symbol_context()` 在 `CodeIndex` 存在 backend 时会将 macro definition index 直接设为空。因此在 `clang`、`unified` 等 backend-backed 模式下，即使宏体实际引用了其他宏，`referenced_macros` 也通常返回空数组。

当前实现改为先对宏体执行 regex 引用发现，再由 KnowledgeDB 批量补全 macro 定义字段。ClangBackend 和 UnifiedBackend 已接入该能力；纯 regex 模式继续使用本地 macro definition index。

宏体中的普通标识符不能仅凭同名 global definition 证明为 `referenced_globals`：宏在调用点展开，局部变量或参数可能遮蔽同名 global。因此 regex + global name lookup 方案已经撤销，宏目标当前返回 `referenced_globals=[]`。

### 影响

- Clang/Unified 宏 function info 现在能够提供数据库已知的 macro 引用元数据。
- regex 只负责识别名称、引用行和调用形态；宏定义位置、definition 及 function-like 标记来自 KnowledgeDB。
- 同文件唯一候选优先；跨文件只有一个候选时才采用；多候选歧义不按排序猜测。
- function-like macro 当前仍可能同时出现在 `project_callees` 和 `referenced_macros`；其单一归属由 snapshot redesign 第八章另行实施。
- Semantic Modeler 如需判断宏体标识符是否指向 global，后续通过 `search_global` 工具获取显式候选和证据，不由当前 fallback 自动断言。

### 剩余限制

1. Joern 等没有 KnowledgeDB macro-definition 查询能力的 backend 仍不能用本路径补齐数据库字段。
2. 条件编译下同名宏存在多个可见候选时，当前保守省略歧义引用，不计算完整预处理条件可见性。
3. 空数组仍没有独立 completeness/source 元数据；数据库查询失败时采用保守空结果并写 debug 日志。
4. 宏 `referenced_globals` 保持空数组，直到 `search_global` 或展开点 AST 证据路径实施。

## KI-003 `llvm.*` intrinsic 未消费

### 问题描述

SVF 可能将 `llvm.memset.*`、`llvm.memcpy.*`、`llvm.memmove.*`、`llvm.trap` 或 overflow intrinsic 等 LLVM IR 内建操作记录为 callee。当前 `CodeIndex` 会在对外输出 callee records 前过滤全部 `llvm.*` 名称，避免 GlobalModeler 和 Semantic Modeler 将其当作普通项目函数或 external callee 查询。

过滤后的 intrinsic 仍保留在 KnowledgeDB `indirect_calls` 和原始 SVF 数据中，但当前没有后续消费者将这些 IR 级操作转换为 snapshot `effects`、错误路径或其他结构化语义。

### 影响

- `llvm.memset.*`、`llvm.memcpy.*` 和 `llvm.memmove.*` 表达的内存写入、初始化或复制语义可能不会进入函数 snapshot。
- `llvm.trap`、`llvm.ubsantrap` 等异常终止语义可能不会进入 `error_handling` 或控制流摘要。
- `llvm.*with.overflow` 等 checked arithmetic 语义可能被简化为普通运算，丢失溢出检测信息。
- callee 图和工具调用已避免 intrinsic 噪声，但语义建模结果可能因此不完整。

### 暂缓原因

不同 intrinsic 的参数、返回值和控制流含义差异较大，不能仅按名称统一映射。可靠消费还需要结合调用参数、LLVM 类型、callsite 和可能的源码对应关系设计专门的 IR effect 转换层，因此当前阶段只做 callee 过滤并保留原始事实。

### 后续建议

1. 建立受支持的 LLVM intrinsic registry，按 intrinsic family 分派转换逻辑，而不是恢复为普通 callee。
2. 将 `llvm.memset.*`、`llvm.memcpy.*`、`llvm.memmove.*` 转换为带目标、来源、长度和 callsite 证据的 memory effects。
3. 将 trap/ubsantrap 转换为异常终止或错误路径，将 overflow intrinsic 转换为 checked arithmetic effect。
4. 对无法识别或证据不足的 intrinsic 保留显式 unknown IR effect，并记录 source/completeness，避免静默丢失。
5. 增加从 SVF/KnowledgeDB 原始记录到 Semantic Modeler 输入和最终 snapshot 的端到端测试。

## KI-004 backend callee limit 与 CodeIndex 业务截断职责重叠

### 问题描述

当前 `get_callees()` 的 `limit` 同时存在于 CodeIndex、Backend 接口和底层查询中，但不同层对它承担的职责没有明确区分：

- CodeIndex 和上层调用图消费者将其理解为最终可返回、可遍历的 callee 数量上限。
- KnowledgeDB 将其直接下推为 SQLite `LIMIT`，用于限制查询结果和内存占用。
- Joern 将其转换为 `.take(limit)`，用于限制服务端计算、JSON 序列化和传输量。
- UnifiedBackend 分别按 limit 查询 direct/indirect callees，合并去重后再次截断。

当 CodeIndex 还需要执行 `llvm.*` 过滤、伪 callee 过滤或去重时，后端先截断会改变最终结果。例如后端前 N 条记录中包含 LLVM intrinsic，CodeIndex 过滤后可能只能返回少于 N 条普通 callee，即 intrinsic 实际占用了上层的 breadth limit。

当前 `CodeIndex.get_callees(limit=N)` 通过逐步扩大底层查询上限进行兼容：过滤、去重后不足 N 条且后端结果可能仍有后续记录时，将查询上限倍增，最高扩展到 1,000,000。这保证了当前过滤需求下的结果正确性，但会重复执行前缀查询，也没有从接口层消除职责重叠。

### 影响

- 后端 limit 既是资源保护参数，又被当作业务结果上限，接口语义不清晰。
- CodeIndex 为实现“过滤后截断”需要重复查询，可能增加 SQLite、Joern 或远程后端开销。
- UnifiedBackend 对 direct 和 indirect 集合分别提前截断，最终结果可能受合并顺序影响，不能表达统一的全局排序或优先级。
- KnowledgeDB 普通 `get_callees()` 的无文件限定查询使用 SQL `LIMIT`，但没有稳定 `ORDER BY`，达到上限时返回子集可能不稳定。
- 如果完全移除后端资源边界，病态调用图或大量 SVF 间接边又可能造成过大的查询结果、序列化负担和内存占用。

### 当前结论

不建议直接取消所有后端查询 limit。应取消的是“后端 limit 等同于最终业务返回上限”这一职责，而不是取消后端资源保护。最终的过滤、去重和业务截断应由 CodeIndex 统一负责；后端应提供完整或可分页读取 callee edge 的能力。

### 后续建议

1. 将 `CodeIndex.get_callees(limit=N)` 定义为唯一的业务结果上限：先过滤、去重，再返回前 N 条。
2. 在 Backend contract 中增加明确的完整查询或分页接口，例如：
   - `get_all_callees(func_name, caller_file="")`；或
   - `iter_callees(func_name, batch_size=100)` / 带 cursor 的分页查询。
3. 将后端现有 limit 重命名为 `query_limit`、`batch_size` 或类似名称，只表达资源保护，不保证等于最终返回数量。
4. CodeIndex 分页读取后端记录，按“读取 → 过滤 `llvm.*`/伪 callee → 去重 → 满足 N 条后停止”的顺序处理，替换当前倍增重查逻辑。
5. UnifiedBackend 应在完整 direct/indirect edge 集合上统一去重和排序，避免两个来源分别提前截断后再合并。
6. 为 KnowledgeDB 查询补充稳定排序；为 Joern 保留服务端分页或 batch 限制，避免一次性序列化全部 callee。
7. 保留 `get_function_info_callees()` 的完整查询语义，并逐步让普通调用图查询复用同一套 edge projection/过滤规则。
8. 增加以下回归测试：过滤项位于首批结果、跨分页重复项、direct/indirect 重名合并、稳定排序、超大间接调用集合以及后端分页提前停止。

## KI-005 通用旧 tool result 压缩可能丢失语义建模关键证据

### 问题描述

`LLMClient._prepare_messages_for_model()` 为控制上下文大小，会在每轮真实模型请求前保留最近 1 轮 tool result 原文，并将更早且超过 900 字符的 tool result 替换为通用 JSON 摘要。摘要整体最多 1,800 字符；其中 `code` 等重字段通常按前 900 字符截断。压缩后的 projection 被直接传给 `chat_completion()`，因此影响真实模型可见上下文，而非仅影响 JSONL 会话记录；内存中的完整 `conversation` 虽未被改写，但不会自动重新送入后续模型轮次。

该策略按时间和字符长度处理，尚未区分语义建模证据的重要性。类型定义、精确源码行、宏展开、锁/资源协议、直接 callee contract 与普通探索输出可能被同样压缩。当前 prompt 同时限制重复工具调用和重叠 snippet 查询，模型在发现摘要缺少精确内容时，没有明确、受支持的原始证据恢复路径。

2026-07-23 的 `_plugin_register` semantic modeler 会话已出现此模式：`include/types.h:1-100` 的旧 snippet 在最终模型请求中被压缩，`Plugin` 定义位于该片段尾部，`PluginRegistry` 定义位于后续行。该轮最终仍获得类型信息，是因为模型又请求了覆盖已有范围的 snippet，且该新结果恰好属于最近工具轮次；这不是当前压缩策略可保证的行为。

### 影响

- Semantic Modeler 可能在缺少完整类型字段、精确行号、所有权、锁状态、callback 条件或错误路径证据时生成看似完整的 snapshot。
- 通用前缀截断会优先保留文件开头的 include、无关声明或配置，丢失文件后部真正被目标函数使用的定义。
- 模型可能因“不得重复调用”的规则不敢恢复原始结果，或通过重复/重叠查询规避压缩，增加工具调用和 token 成本。
- 最终 snapshot 中的断言难以区分为源码证据、跨函数已证实事实还是模型补全推断，降低审计性。
- 当前 JSONL 默认只保留最后一个 model-facing exchange 及 tool result 摘要；若未另行保存完整 transcript，离线排查时无法可靠回溯被压缩的原始工具结果。

### 暂缓原因

该问题不应通过简单增加字符阈值或永久保留更多历史轮次解决。可靠修复需要同时调整模型上下文 projection、工具结果的语义归一化、原始证据存储、工具协议及回归评估；否则仅会在 token 成本、上下文上限和语义完整性之间移动问题。

### 后续建议

1. 保持完整原始 transcript 不可变且可审计；在其外建立按 `tool_call_id` 索引的 Evidence Ledger，记录原文、结构化事实、实体、文件行区间、依赖关系、精确性要求和压缩状态。
2. 将模型上下文分为证据等级，而不是仅按时间截断：
   - P0：目标函数源码、目标 metadata、系统/终端输出约束，始终保留原文；
   - P1：目标参数/字段相关类型定义、直接 callee contract、相关宏、锁/资源/error-path 证据，保留完整原文或无损结构化片段；
   - P2：一跳外函数、调用者列表、初始化背景及工具错误，保留结构化摘要；
   - P3：重复或与目标无实体交集的探索输出，保留极短摘要或不送入模型上下文。
3. 从目标函数签名、源码、初始 callee/global/macro metadata 建立初始实体集合；根据工具结果命中的类型、字段访问、调用、宏、资源和行区间动态提升相关证据到 P1。最近性只能作为同等级证据的排序条件。
4. 针对 `get_file_snippet` 和类型结果按声明/定义边界保留相关行，而非保留字符串前缀；当目标类型声明在片段末尾未闭合时，标记并自动或明确请求补齐到声明结束。
5. 增加受控的 `get_evidence(tool_call_id)` 或等价机制，使模型可取回已压缩结果的原文；该恢复操作不应被视为违反“不得重复工具调用”。
6. 在最终 `emit_function_snapshot` 前构建独立 evidence pack，要求每个高风险 effect、error path、ownership/lock/callback 断言能对应到证据 ID 和源码行；证据不足时应输出 `unknown`，而非推断为事实。
7. 建立压缩/未压缩对照回归：覆盖超长头文件、目标类型定义位于文件尾部、跨轮 callback/lock contract、重复查询禁止、原始证据恢复，以及 snapshot 字段的证据覆盖率、无依据断言率和 token 成本。
