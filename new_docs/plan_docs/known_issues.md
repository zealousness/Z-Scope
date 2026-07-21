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

### 问题描述

`CodeIndex.find_function_infos()` 为 function-like macro 构造 function info 时，会从完整宏定义文本提取：

- `callees`
- `referenced_globals`
- `referenced_macros`

其中 `callees` 始终通过 `extract_function_calls()` 对宏体执行文本/正则提取，再尝试将名称解析为 canonical `callee_index_name`，不依赖后端提供宏调用图。

但 `_macro_function_info_symbol_context()` 在 `CodeIndex` 存在 backend 时，会将 global definition index 和 macro definition index 直接设为空。因此在 `clang`、`svf`、`unified` 等 backend-backed 模式下，即使宏体实际引用了全局变量或其他宏，`referenced_globals` 和 `referenced_macros` 当前通常仍返回空数组。只有无 backend 的 regex 模式会使用本地定义索引扫描宏体并补齐这两个字段。

### 影响

- 同一个宏在 regex 与 backend-backed 模式下可能得到不同的 function info。
- 空数组目前无法区分“确认没有符号引用”和“backend 模式未执行宏符号上下文提取”。
- Semantic Modeler 初始 prompt 会直接预加载这两个数组，backend-backed 模式下可能缺少与宏语义相关的全局状态和嵌套宏证据。
- `callees` 仍然能够基于宏体文本返回，因此一个嵌套 function-like macro 可能出现在 `callees` 中，却没有同时出现在 `referenced_macros` 中，形成字段间不一致。

### 暂缓原因

当前 Clang、SVF 和 Unified 后端没有统一的宏级 symbol-context 查询契约。直接修改需要确定宏定义身份、跨文件同名宏消歧、条件编译以及 backend 结果与文本 fallback 的合并规则，因此未在 snapshot identity 重构中一并处理。

### 后续建议

1. 为 backend 增加按 canonical macro identity 查询的 `get_macro_symbol_context()` 接口，返回 globals/macros 引用及引用行。
2. backend 不支持该接口、查询失败或没有可判定结果时，降级使用当前 regex definition index 扫描，而不是直接返回空数组。
3. 明确区分“完整空结果”和“未知/未提取结果”；必要时增加 source/completeness 元数据，避免下游把降级结果视为完备事实。
4. 增加 regex、clang、svf、unified 的一致性测试，覆盖全局变量引用、对象式宏、function-like macro、同名宏和多行宏。
