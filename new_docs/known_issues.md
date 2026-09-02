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

## KI-003 `llvm.* intrinsic` 未消费

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

## KI-006 `external function config` 未启用

### 问题描述

当前 Semantic Modeler 的预加载 callee context 能区分项目函数与非项目名称，但没有为非项目函数提供程序拥有的语义契约或 `callee_summary`。本轮 `test/range` global-model benchmark 的配置显式设置：

```yaml
analysis:
  user_config_db: ""
```

因此运行时没有可用的 user-config external function contract。

仓库已有 external function 配置模型，可由用户维护 `description`、`library`、`memory_behavior`、`concurrency_behavior` 和 `return_semantics`。`get_function_info` 在项目函数未命中后也会查询该配置，并在命中时返回外部函数的伪代码说明；但这条 fallback 仅发生在模型已发起工具调用时，当前未接入 Semantic Modeler 的预加载 callee context，也不会生成或注入 external `callee_summary`。

当前也没有一份程序拥有的、经人工维护的 libc/POSIX/线程库 external contract registry。因此不能仅凭名称（如 `free`、`malloc`、`pthread_create`）或函数声明安全地推导所有权、NULL 语义、资源生命周期、线程效果和返回约束。

在 planned callee-centric schema 中，非项目函数将改名为 `unresolved_callees`。如果没有可信契约来源，`known_external` 及其 `callee_summary` 没有可靠生成路径；把名称启发式、模型猜测或未确认的 inference 结果直接写入 summary 会污染程序证据。

### 影响

- `free` 等看似熟知的库函数在当前 benchmark 中只能作为非项目名称保留，不能安全携带 ownership/释放契约。
- 模型可能为补证尝试对外部函数调用 `get_function_info`；未配置时得到 `Function not found`，增加无效工具调用。
- 外部调用的内存、资源、锁和线程语义不能稳定进入 caller snapshot，可能造成 unknown、遗漏或模型猜测。
- 即使用户配置了 external function，当前预加载路径也不会将该契约确定性渲染为 callee context；模型是否再次查询工具会影响可见证据，导致结果不稳定。
- external contract 改动目前不会作为 caller snapshot 的显式依赖参与刷新，容易出现契约变化但旧 snapshot 未更新的情况。

### 暂缓原因

外部 API 语义的可信来源、覆盖优先级、版本化、标准库范围和 snapshot 刷新策略需要统一设计。不能通过“名称像 allocator/deallocator”或 LLM 生成摘要的方式快速补齐，否则会将推测当作程序事实。

当前 benchmark 未提供用户配置，且本阶段的目标是修复函数指针调用分类、SVF 物化和 callee projection，不应同时扩大到未设计完成的外部 contract 系统。

### 后续建议

1. 将 `known_external` 定义为“命中程序拥有的可信 external contract”，而不是“名称看起来像标准库函数”。没有契约时统一为 `unresolved`。
2. 建立两级 contract source，并规定覆盖顺序：
   - 用户配置的 external function contract；
   - 经人工维护、版本化的内置标准 API registry；
   - 其余名称保持 unresolved。
3. 用户配置覆盖内置 registry；发生冲突时不得静默合并相反的 ownership、NULL 或返回语义。
4. 由程序确定性地将 `description`、`memory_behavior`、`concurrency_behavior` 和 `return_semantics` 渲染为 `callee_summary`，不得调用 LLM 生成或补全 external summary。
5. `unresolved_callees` 的 LLM 可见字段建议为：
   - 必填：`callee_name`、`resolution_kind`、`direct_callsite_lines`、`indirect_callsites`；
   - 可选：`callee_signature`、`callee_summary`；
   - 不向 LLM 暴露 contract source、置信度、配置版本或内部 callsite ID。
6. 只有命中可信 contract 时使用 `resolution_kind=known_external` 并提供 `callee_summary`；只有声明或名称时使用 `resolution_kind=unresolved`，可提供可靠 `callee_signature`，但不生成行为摘要。
7. 在 CodeIndex/modeling input 构造阶段预加载并渲染 external contract，而不是依赖模型调用 `get_function_info` 触发 fallback。
8. 为 external contract 建立规范化 hash；当用户配置或内置 registry 条目变化时，使依赖该 contract 的 caller snapshot 失效并刷新 program-owned context。
9. 增加回归测试：用户配置命中、内置 registry 命中、无契约名称、用户覆盖内置条目、冲突拒绝、summary 稳定渲染、snapshot refresh 及 benchmark 中 `user_config_db=""` 的保守行为。

## KI-007 `unresolved_referenced_types` 对标准与外部类型的分类不一致

### 问题描述

`unresolved_referenced_types` 当前不是“函数源码中出现但无法解析定义的全部类型”，而是“先通过直接项目类型候选过滤、随后定义解析失败的类型”。候选过滤发生在 `_direct_function_type_candidates()`，只有进入候选集合的名称才会由 `_collect_function_type_refs()` 尝试解析，并在解析失败时写入 `function_type_refs`，最终投影为 `unresolved_referenced_types`。

该过滤同时使用显式 builtin 集合和名称启发式：

- `uint32_t`、`size_t` 等标准类型位于 `TYPE_CONTEXT_BUILTINS`，在候选阶段被直接排除，因此不会进入 unresolved。
- `struct stat st` 经声明正则提取后只保留 tag 名 `stat`。系统头类型没有进入项目 `type_definitions`，而 `stat` 既不是大写开头，也不以 `_t` 结尾，因此未通过“已索引名称 / 大写开头 / `_t` 后缀”候选条件，也不会进入 unresolved。
- `pthread_t` 不在当前 builtin 集合中，并且以 `_t` 结尾，因此会进入候选集合；当项目索引找不到其系统头定义时，会产生 `type_definition_not_found` 并进入 unresolved。

因此，同为标准库或 POSIX 外部类型，`uint32_t`、`struct stat` 和 `pthread_t` 会分别表现为“显式忽略”“启发式静默遗漏”和“报告 unresolved”。2026-07-24 global-model benchmark 已观察到该差异：`_check_file_permission` 的 `struct stat` 与 `_runtime_protocol_frame_length` 的 `uint32_t` 均未出现在初始 `unresolved_referenced_types`，模型随后错误调用 `get_type_info` 并得到 `Type not found`；同一轮其他函数中的 `pthread_t` 则正常出现在 unresolved 列表。

### 影响

- `unresolved_referenced_types` 的语义边界不明确：调用方不能判断空列表表示“没有未解析的项目类型”，还是“外部/标准类型已被候选过滤静默省略”。
- 外部类型是否对 Semantic Modeler 可见取决于名称拼写，而不是统一的类型来源分类；`pthread_t` 可见而 `struct stat` 不可见。
- 小写且未成功索引的项目 struct/union/enum tag 也可能与 `stat` 一样在候选阶段被丢弃，无法以 unresolved 暴露索引缺口。
- 模型看到源码中的类型名却没有 resolved/unresolved 元数据时，可能误认为上下文遗漏并调用 `get_type_info`，产生无效工具调用和 `Type not found` 指标。
- benchmark 难以区分“有意忽略的 builtin”“已识别的外部类型”和“项目类型解析失败”，不利于判断类型上下文覆盖率。

### 当前结论

`uint32_t` 不进入 unresolved 是当前明确设计，并有 builtin typedef 排除测试覆盖；`struct stat` 不进入 unresolved 则是候选名称启发式和系统头不入项目索引共同造成的静默遗漏。问题不在 KnowledgeDB 的 unresolved 投影阶段，而在其上游候选集合已经丢失了这两个名称。

不建议简单删除所有 builtin 和名称过滤。否则基础标量、关键字、宏值及误识别标识符会大量进入 unresolved，重新引入类型上下文噪声。应先定义类型来源和 completeness 契约，再调整候选与投影结构。

### 后续建议

1. 明确 `unresolved_referenced_types` 只表示“项目类型解析失败”，并为被识别但不由项目索引拥有的类型增加独立分类，例如 `external_referenced_types` 或 `ignored_referenced_types`，携带 `name`、`reference_kind`、`reference_lines` 和 `reason`。
2. 将标准固定宽度整数和基础 typedef 统一标记为 `builtin_or_standard`，由程序提供稳定分类，不要求模型调用 `get_type_info`。
3. 对带显式 `struct`、`union`、`enum`、`class` 关键字的声明保留 tag kind 和原始 qualified spelling；不要仅因 tag 为小写且未索引就静默丢弃。系统定义可标记为 `external_system_type`，疑似项目定义缺失则保留为 unresolved。
4. 统一 `pthread_t`、`struct stat`、`FILE`、`DIR`、`time_t`、`sockaddr` 和固定宽度整数类型的分类规则，避免依赖大写或 `_t` 后缀决定可见性。
5. 为类型上下文增加 completeness/source 元数据，至少区分 project resolved、project unresolved、builtin/standard ignored、external/system opaque 和候选提取失败。
6. 在 Semantic Modeler policy 或 tool runtime 中使用上述分类阻止对 builtin/standard/system opaque 类型调用 `get_type_info`，并给出结构化原因，而不是统一落入 `Type not found`。
7. 增加端到端测试：`uint32_t`、`size_t`、`pthread_t`、`struct stat`、大写外部 opaque 类型、小写项目 struct tag、缺失项目 typedef，以及同一类型在项目头和系统头中的可见性冲突。

## KI-008 batch 模式按入口独立去重，无法聚合跨入口候选路径

### 问题描述

`CandidateLedger` 的数据结构支持为同一个规范化候选累计多个 `sources` 和 `call_paths`，但 batch 模式会为每个入口函数单独创建一个 `Analyzer`，并显式传入新的 `CandidateLedger()`。因此候选去重和 Deep Worker Ticket 规划只发生在单个入口的分析状态内；不同入口到达同一个内部 sink 或根因时，会分别生成候选和 Ticket，无法在派发前聚合为一张包含多条入口路径的 Ticket。

当前路径记录还存在第二层限制：source rule、local rule、graph rule 和 backend signal Ticket 写入 Ledger 时，传入的 `call_path` 均为 `[state["entry_func"]]`，没有采用候选 `evidence_pack.path.call_path`、`source_path.call_path` 等已有完整路径。Semantic snapshot 候选会传递入口到被访问函数的路径，但遍历使用 `visited` 集合，每个函数只保留首次发现的路径，同一入口内的替代调用路径也不会完整累计。

2026-07-21 的 `run_20260721_145040_359477` 共派发 1,173 个 Deep Worker session，所有 Ticket 的 `Call paths` 都只有一个元素。2026-07-27 的两次运行结果相同，均没有多 `Call paths` Ticket。这不是样本恰好未触发，而是当前 batch 生命周期和路径投影方式导致的结果。

### 影响

- 同一个内部缺陷从多个公开入口可达时会重复派发 Deep Worker，增加模型调用、工具调用和 token 成本。
- Worker 每次只能看到当前入口视角，无法同时比较不同入口的参数约束、调用边、线程上下文和保护条件。
- `Call paths: List[List[str]]` 在实际 batch Ticket 中不能兑现跨入口多路径语义，数据结构能力与运行时行为不一致。
- 同一根因的 worker report 分散在多个入口报告中，后续只能在最终报告阶段再次做 issue 去重；此时已经无法节省前面的分析成本。
- 不同入口下生成的 Candidate ID 可能重复或分别生成，不能作为 batch 范围内稳定、全局唯一的候选身份。
- 仅将各入口的 Ledger 替换为并发共享实例仍不充分：先完成规划的入口可能在其他入口提交候选路径前将 Ticket 标记为 planned 并启动 Worker，导致聚合时序不确定。

### 当前结论

当前 CandidateLedger 实际承担的是“入口内候选去重”，不是 batch 级候选去重。batch combined report 在所有入口分析完成后才生成，只合并结果，不会重新聚合 Ticket 或补发统一 Worker。

可靠修复需要将候选收集和 Worker 派发拆分为两个阶段，并在两者之间建立 batch 级同步屏障，不能只共享现有 `CandidateLedger` 对象。

### 后续建议

1. 在 batch orchestration 层建立全局 CandidateLedger；所有入口先只生成候选，不立即规划或派发 Deep Worker。
2. 候选收集完成后设置同步屏障，再按规范化 root cause、source、sink、资源和缺陷类型执行全局去重。
3. 将候选 evidence 中的完整 `call_path` 投影到 Ledger，而不是统一写入 `[entry_func]`；同一函数有多条可达路径时保留有界、去重后的路径集合。
4. 将入口、完整调用路径、call edge、参数映射、guard 和线程上下文作为一组路径证据保存，避免只有函数名数组而缺少路径约束。
5. 全局规划阶段只为一个规范化候选派发一次 Worker，并将 worker report 关联回所有受影响入口。
6. 明确 batch 级 Candidate ID 的稳定性和唯一性；不要让不同入口的独立 Ledger 生成相同但无全局身份语义的 ID。
7. 重新定义 ticket budget：区分每入口候选采集预算和 batch 级 Worker 派发预算，避免全局聚合后仍按每入口上限重复消耗。
8. 增加端到端测试：两个入口到达同一内部 sink、同一入口存在两条内部路径、并行入口完成顺序变化、路径晚到、全局只派发一次 Worker，以及 report 向多个入口回填。

## KI-009 多来源 Ticket 聚合只保留主 Ticket evidence

### 问题描述

`CandidateLedger.add()` 按 canonical dedup key 聚合重复 Ticket 时，会分别去重追加 `sources` 和 `call_paths`，但不会合并两张 Ticket 的 `evidence`。Ledger 只保存一个主 `ticket`：如果后加入 Ticket 的 `priority_score` 更高，就整体替换原主 Ticket；优先级相同或更低时保留先加入的 Ticket。最终 `Structured evidence` 因此只来自获胜 Ticket，其他来源的完整 candidate ID、checker、rule、source/sink、path、positive/negative evidence、semantic overlay evidence 和后端原始事实不会保留。

2026-07-21 的运行中有三张 `Sources` 包含两个元素的实际聚合 Ticket：

- `_runtime_detach_component_record`：`local_rule` + `graph_rule`；
- `_runtime_remove_module_record`：`local_rule` + `graph_rule`；
- `_runtime_remove_file_record`：`local_rule` + `graph_rule`。

三张 Ticket 最终均因 graph Ticket 优先级更高而保留 graph evidence。Prompt 中只能通过 `Sources` 看出 local rule 也发现过该候选，没有 `duplicate_sources`、`secondary_evidence` 或 `merged_backend_evidence` 可用于恢复 local evidence。2026-07-27 的两次运行也各有三张相同模式的多来源 Ticket。

项目内另有两套局部合并逻辑，但不能解决 CandidateLedger 的证据丢失：`merge_rule_candidate_duplicate()` 只选择性合并 positive/negative evidence、evidence refs、call paths 和重复来源摘要，不保留完整 duplicate evidence pack；Clang + SVF 的 unified evidence merge 会将 secondary evidence 放入 `merged_backend_evidence`，但该策略没有统一应用到 local、graph、snapshot 和 backend Ticket 的 Ledger 聚合。

### 影响

- `Sources` 表明多个检测器支持同一候选，但 Worker 无法查看非主检测器提供的独立证据，来源列表与可验证证据不对称。
- 优先级选择会静默丢弃可能互补或矛盾的 path、guard、alias、ownership、锁状态及后端事实。
- 主 Ticket 选择受加入顺序和 priority score 影响；同分时保留先加入者，可能导致最终 prompt 对调度顺序敏感。
- Validator 无法判断不同检测器是否真正发现同一根因，还是 dedup key 过宽造成误聚合。
- 非主 evidence 丢失后，无法审计为什么候选被合并，也无法在主 evidence 不完整或错误时回退到另一来源。
- `candidate_record` 只保存规范化 defect class、source、sink 和 root cause key，不是被丢弃 evidence 的副本，不能承担 provenance 恢复。

### 当前结论

当前多来源 Ticket 聚合采用“sources/call paths 取并集，Structured evidence 按优先级选主”的策略，而不是完整证据聚合。该策略可控制 prompt 体积，但缺少明确的 primary/secondary evidence schema、冲突处理和压缩规则，造成不可恢复的信息丢失。

### 后续建议

1. 为聚合 Ticket 定义显式 evidence schema，例如 `primary_evidence`、`secondary_evidence[]` 和 `merged_evidence_summary`，不要继续让单个 `evidence` 字段隐式代表所有来源。
2. 每个 secondary evidence 至少保留 candidate ID、candidate source、checker、rule、confidence、source、sink、path、positive/negative evidence、evidence refs 和原始 evidence pack 的可审计引用。
3. 主 evidence 选择应记录 `selection_reason`、候选优先级和加入顺序；同分处理规则必须显式且可测试。
4. 对 sources、paths、guards、aliases、semantic overlays 和 evidence refs 定义字段级合并策略；出现互相矛盾的事实时保留冲突，不得静默覆盖。
5. 将现有 Clang + SVF `merged_backend_evidence` 机制推广为统一的跨 detector evidence envelope，覆盖 source rule、semantic snapshot、local rule、graph rule 和 backend signal。
6. 为控制 prompt 大小，可在 Worker prompt 中提供 primary evidence 和 secondary evidence 摘要，但完整原文必须持久化并可通过 evidence ID 按需读取。
7. CandidateLedger 的聚合应避免直接修改或替换原始 Ticket 对象；保存不可变候选记录，再由规划阶段生成派发视图。
8. 增加回归测试：高优先级替换、同分先到、互补证据、冲突证据、多来源多路径、secondary evidence 压缩与恢复，以及 Worker/Validator 对所有来源的可见性。

## KI-010 `svf_value_flow` 丢失后端路径并混淆报告位置、函数和端点符号

### 问题描述

当前 `svf_value_flow` Candidate 使用 Saber 的内存错误信号生成 Ticket，但从 Saber 执行结果到 Deep Worker `Structured evidence` 的链路只稳定保留 bug type、文件和报告行，没有保留节点级 value-flow path、真实 source/sink endpoint、LLVM value、points-to、alias 或 object identity。

路径信息在进入 Candidate 生成器之前已经缺失：

1. `SvfRunner._parse_saber_output()` 的 SVF 2.x/3.x 正则只提取 `type`、`file` 和 `line`。
2. `.zscope_svf_saber_default/saber_results.json` 的 `bugs[]` 也只包含上述三个字段；当前没有持久化完整 Saber stdout/stderr 的原始 artifact。
3. `SvfParser.import_saber_bugs()` 将 `source_func` 和 `sink_func` 固定写为空字符串。
4. KnowledgeDB `taint_signatures` 只存储 source/sink function、bug type、file、line、tool 和 group，没有 backend path、node 或 edge 的存储结构。
5. `SvfValueFlowCandidateGenerator._normalize_backend_path()` 虽支持读取 `backend_path`、`flow_path`、`path_elements`、`path` 或 `trace`，但从 KnowledgeDB 取回的 row 不含这些字段，因此只能返回空数组。

Candidate 生成阶段随后使用 fallback 补齐缺失端点：

```python
func = bug.get("func_name") or bug.get("source_func") or entry_func
source_func = bug.get("source_func") or func or "svf_source"
sink_func = bug.get("sink_func") or bug_type or "svf_sink"
```

这会把“报告位置所在函数”写成 `source_func`，并把 `Memory Leak` 或 `Partial Memory Leak` 这样的 bug type 写成 `sink_func`。顶层 `source.file/line` 和 `sink.file/line` 又都使用同一个 reported location。随后 `interprocedural` 仅根据两个 fallback 字符串是否不同计算，因此即使没有任何跨函数 value-flow path，也会得到 `true`。

源码重建存在相同的层级混淆。`_svf_source_level_flow_events()` 将 `source_func` 作为 `source_symbol` fallback，并将 `bug_type` 作为 `sink_symbol` 的最终 fallback。函数名、源码变量/对象符号和缺陷类型由此被放入同一条选择链。`Memory Leak` 不可能在 C 源码中匹配为真实 sink symbol；从 reported snippet 推断出的 `object_symbols` 也没有 source/sink role，不会反向补齐端点。

`source_path.call_path` 是 CodeIndex 重建的 entry-to-target 函数调用链，不是 SVF value-flow path。当前结构同时携带非空调用链和空 `backend_path`，但字段命名及正向 evidence 文本容易让模型误以为已经存在 source-to-sink 证明。例如固定生成的 `SVF source <source_func> flows to sink <sink_func>` 语句，在当前数据中实际可能表达“报告位置所在函数流向 Memory Leak”，并没有后端路径支持。

### 实际证据

2026-07-21 的 `run_20260721_145040_359477` 中共有 21 个 `svf_value_flow` Deep Worker Ticket；对应 Saber artifact 包含 13 个按位置记录的 bug signal。Ticket 统计如下：

```text
value_flow.backend_path 非空：0/21
raw_backend_row 含任一路径字段：0/21
source.file == sink.file 且 source.line == sink.line：21/21
source_path.source_function 非空：0/21
source_path.sink_function 非空：0/21
source_level_flow.source_symbol 非空：0/21
source_level_flow.sink_symbol = "Memory Leak"：12/21
source_level_flow.sink_symbol = "Partial Memory Leak"：9/21
source event：0/21
sink event：0/21
expression edge：0/21
complete_source_to_sink=true：0/21
```

每个 Ticket 的 `source_level_flow.events` 只有一个 `reported_location` event。该 event 能证明 Saber 在某个源码位置报告了内存问题，但不能证明 allocation、ownership transfer、escape、free 或 leaking exit 之间的关系。

21 个 Ticket 中，`path.function` 与 `path.entry_function` 有 9 个相同、12 个不同。这个差异本身是合理的：前者表示报告所在目标函数，后者表示当前分析入口；当二者不同时，`source_path.call_path` 描述 entry-to-target 可达性。问题在于这条调用链没有携带或替代 backend value-flow 的能力，却容易与 `interprocedural=true` 一起被解释为跨函数数据流证据。

当前测试中没有直接覆盖 `_svf_source_level_flow_events()` 的 source/sink symbol 重建，也没有覆盖“bug type 不得作为 sink symbol”“function 不得冒充 value/object symbol”“空 backend path 不得生成 flow 结论”等约束。

### 影响

- Deep Worker 可能把 reported location 当作真实 source/sink 共同位置，把包含函数当作 source endpoint，把 bug type 当作 sink endpoint。
- `interprocedural=true` 和正向 `flows to sink` 文本会制造不存在的跨函数 value-flow 证据，增加确认偏差。
- 非空 `source_path.call_path` 只能证明静态 entry-to-target 函数可达性，不能弥补 allocation-to-leak、source-to-sink 或 object-flow 证据缺失。
- `source_symbol` 为空、`sink_symbol` 错误以及 endpoint context 为空，使源码重建无法产生 source/sink event 和 expression edge。
- 相同的 reported location、固定 Validator 模板、空路径和错误 fallback 被重复发送给多个入口 Ticket，增加 token 消耗而不增加证据。
- 原始 Saber stdout/stderr 未持久化，后续无法判断是 Saber 本身没有输出节点路径，还是 Z-Scope 解析器丢弃了可用信息，降低可审计性。
- 当前字段形式允许后续消费者在没有检查 completeness/provenance 的情况下使用错误端点，可能影响 Candidate 排序、Worker 结论和 Validator 判断。

### 当前结论

当前 `svf_value_flow` evidence 只能可靠表达“指定工具在指定源码位置报告了某类内存信号”。它不能表达已确认的 source、sink、跨函数 value flow 或完整泄漏路径。

`backend_path=[]` 的直接原因是进入 Candidate 生成器的 row 没有任何路径字段。由于完整 Saber stdout/stderr 没有作为 artifact 保存，目前不能进一步断言 Saber 二进制当时绝对没有输出更详细的节点信息；可以确定的是，现有 runner、artifact schema、KnowledgeDB 和 Candidate 投影均没有保留这些信息。

在节点级路径和端点映射实现之前，应将 source/sink function、source/sink symbol、cross-function proof 和 source-to-sink completeness 明确标记为 unknown，而不是使用 containing function 或 bug type 填充。

### 后续建议

1. 将每次 Saber 执行的原始 stdout、stderr、命令、工具版本、bitcode fingerprint 和返回码持久化为不可变 artifact，保留审计和重新解析能力。
2. 扩展 Saber parser 和 `saber_results.json` schema，保存后端实际提供的 node、edge、LLVM value、object ID、points-to、alias、call/return edge 及路径完整性；无法解析时保留原始片段和 parse status。
3. 扩展 KnowledgeDB：使用路径 JSON 或规范化 node/edge 表保存 backend flow，不要继续把路径压缩进只有七个摘要列的 `taint_signatures`。
4. 移除 `source_func = containing_function` 和 `sink_func = bug_type` fallback。缺失端点时使用 `null`，并分别保留 `reported_function`、`backend_bug_type` 和 `reported_location`。
5. 将 endpoint function、source/sink symbol、object symbol、LLVM value 和 bug type 定义为独立字段，禁止函数名、对象名和缺陷类型在同一 fallback 链中互相替代。
6. 将 `interprocedural` 替换为可审计状态，例如 `backend_path_available` 和 `cross_function_path_proven`。只有后端节点跨越至少两个函数且相邻边有证据时，后者才能为 true。
7. 明确分离 `backend_flow.nodes/edges`、`entry_call_chain` 和 `source_reconstruction.events/edges`。CodeIndex 调用链不得填入或暗示 SVF value-flow path。
8. 重构正向 evidence 文本：没有真实端点和路径时只写“工具在 reported location 报告 bug type”，不得生成 `source flows to sink`。
9. 源码重建应优先消费 backend node/LLVM value 到源码表达式的映射；文本推断得到的 `object_symbols` 必须携带 `evidence_kind=source_text_inference` 和 `role=unknown`，不能自动提升为 source/sink。
10. 将 completeness 拆分为独立状态：后端路径是否存在、entry 调用链是否找到、source endpoint 是否映射、sink endpoint 是否映射、源码边是否连续、运行时可行性是否证明。
11. 在 Prompt 中删除固定 checker/schema/profile、空 backend path、空 function context、重复 reported location 和通用 Validator 模板；完整原始记录保留在审计元数据中。
12. 增加单元和端到端测试：Saber 2.x/3.x 路径解析、原始输出持久化、数据库 round-trip、空路径、真实多节点路径、bug type 不作为 symbol、function/value 分离、调用链与 value-flow 分离、错误 fallback 禁止，以及 complete/proven 状态计算。

## KI-011 Validator 前后 Evidence Completion 基本重复，缺失事实请求未驱动补全

### 问题描述

当前 Validator 流程存在两次 Evidence Completion：

1. Validator 前，`complete_prevalidation()` 基于 Candidate 和已构建的 validation evidence 运行本地确定性 provider；如果得到可路由的 confirmation/rejection proof，可以直接处理 Candidate 并跳过 LLM。
2. Validator 后，当 Validator 结果进入 `needs_review` 时，`complete()` 再运行同一组 `_completion_proofs()` provider；找到 proof 后重新执行一次 Validation Pipeline，未找到则标记为 `exhausted`。

两次补全使用相同的 Candidate、代码、CFG/AST 事实和 evidence pack，中间没有重新执行事实后端，也没有增加新的代码证据。Validator 返回的：

```json
"missing_fact_request": [
  {
    "fact_kind": "value_range",
    "subject": "wire_len",
    "reason": "缺少 wire_len 的确定上界"
  }
]
```

目前只会被 Runner 校验并写入 `validator_missing_fact_requests`，随后复制到 `EvidenceCompletionRequest` 和报告遥测。Evidence Completion 不会根据 `fact_kind` 选择对应 provider，不会针对 `subject` 查询或计算事实，也不会判断生成的 proof 是否回答了具体请求。因此“完整请求数组贯通”目前只是数据与审计字段贯通，并不代表定向事实补全已经实现。

后置补全与前置补全并非在所有情况下严格相同。Validator Pipeline 会在后置补全前写入 `blocking_negative_evidence`；当该字段为 `true` 时，Evidence Completion 会过滤 rejection proof。因此后置结果可能比前置结果更少，但通常不会产生前置阶段不存在的新 proof。其他 Validator 状态字段一般不参与 provider 的事实计算。

此外，`EvidenceCompletionQueue` 当前同步运行一次本地 provider 集合，并不是真正的异步任务队列；`max_workers` 没有参与这条 provider 调度。

### 影响

- 对同一 Candidate 和同一 evidence，后置 Evidence Completion 通常重复前置计算并再次得到无 proof 的结果。
- `missing_fact_request` 看起来像可执行补全请求，实际主要承担解释、报告和审计作用，接口名称容易高估系统能力。
- 后置补全通常只增加重复计算和 `exhausted` 状态，不能补齐 LLM 指出的 value range、caller contract、ownership、lockset 等具体事实。
- 当前状态只能表示整次聚合补全 `completed/exhausted`，不能表示每个 `(fact_kind, subject)` 请求的完成情况。
- 即使任意 provider 生成 proof，也没有建立 proof 与具体请求之间的对应关系，无法证明请求已经得到回答。

### 当前结论

在没有新 evidence、且 `blocking_negative_evidence` 不改变 proof 过滤的常见情况下，Validator 前后 Evidence Completion 的结果等价。前置阶段若已找到权威 proof，Candidate 通常会跳过 Validator，因此后置阶段真正执行时大多是在重复一次已经失败的确定性补全。

当前 Evidence Completion 应理解为“在已有材料上运行确定性证明规则”，而不是“执行 Validator 提出的缺失事实请求”。

### 后续建议

应明确选择以下一种方向：

1. 如果短期不实现事实补采，删除后置重复补全，仅保留 Validator 前的 deterministic prevalidation；Validator 的 `missing_fact_request` 明确定位为审计信息。
2. 如果保留后置补全，则建立真正的定向补全链路：
   - 以 `(fact_kind, subject)` 路由到对应的确定性 fact provider；
   - 对 subject 执行新的值域、调用者契约、ownership/cleanup、lockset/HB、对象 identity 或 reachability 查询；
   - 将新事实写回 DecisionFactGraph 或等价稳定事实层；
   - 逐项记录 `completed`、`exhausted`、`unsupported` 和生成的 fact/proof 引用；
   - 仅在获得新事实后重新运行 deterministic proof 和 Validation Pipeline。
3. 为补全建立 request-to-fact/proof 对应关系，禁止无关 provider 生成的任意 proof 将全部请求笼统标记为 completed。
4. 如果保留 Queue 命名和 `max_workers` 配置，应实现真实的有界 provider 调度；否则重命名为同步 completion pass，并删除无效并发配置，避免错误预期。
5. 增加端到端测试：前后 evidence 不变时不得重复执行无收益补全；特定 fact kind/subject 只调用匹配 provider；多请求逐项状态；空请求行为；新事实写回后 proof 重算；`blocking_negative_evidence` 的过滤差异。
