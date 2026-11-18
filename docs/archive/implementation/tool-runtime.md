# 工具优化实施记录

> **历史文档，2026-11-17 整理归档。** 原位置：`new_docs/stage1optimation/tools_optimation.md`。正文中的状态、接口、路径、测试与后续建议保留记录时含义；当前说明见[文档总导航](../../README.md)，本类记录见[归档索引](README.md)。

## 2026-07-03

### 已完成 工具拆分

- 将原先集中在 `zscope/tools/utils.py` 中的 10 个工具拆分为一个工具一个文件：
  - `list_known_functions` -> `zscope/tools/list_functions.py`
  - `get_file_snippet` -> `zscope/tools/file_snippet.py`
  - `get_callers` -> `zscope/tools/callers.py`
  - `get_type_info` -> `zscope/tools/type_info.py`
  - `get_call_graph` -> `zscope/tools/call_graph.py`
  - `get_data_flow` -> `zscope/tools/data_flow.py`
  - `find_function_pointers` -> `zscope/tools/function_pointers.py`
  - `query_pointer_alias` -> `zscope/tools/pointer_alias.py`
  - `verify_taint_reachability` -> `zscope/tools/taint_reachability.py`
  - `get_deep_call_context` -> `zscope/tools/deep_call_context.py`
- 保留 `get_function_impl` 和 `get_function_snapshot` 的原有文件组织方式，未做迁移。
- 保留所有工具的原始逻辑、工具名、schema 和返回结构；本次只做文件级拆分。
- 将 `Analyzer._get_tools()` 中对 `zscope.tools.utils` 的集中导入改为从各工具模块直接导入，和 `get_function_impl` / `get_function_snapshot` 的导入方式保持一致。
- 将 `zscope/tools/utils.py` 改为兼容导出层，继续 re-export 原有 10 个工具类，避免潜在外部导入断裂。

### 测试

- `python -m py_compile zscope/tools/list_functions.py zscope/tools/file_snippet.py zscope/tools/callers.py zscope/tools/type_info.py zscope/tools/call_graph.py zscope/tools/data_flow.py zscope/tools/function_pointers.py zscope/tools/pointer_alias.py zscope/tools/taint_reachability.py zscope/tools/deep_call_context.py zscope/tools/utils.py zscope/core/analysis/analyzer.py` 通过。
- 兼容导出检查通过：`zscope.tools.utils` re-export 的 10 个类与新模块中的类对象一致。
- `python -m pytest tests/test_tool_policy.py tests/test_json_output_agents.py -q` 通过：16 个测试。

### 计划偏差 / 问题记录

- 非阻塞优化点：`GetFunctionImplTool` 的底层 `CodeIndex.get_function_impl()` 已支持 `file_path` 消歧，但当前工具 schema 和 `execute()` 没有暴露/传递 `file_path`。如果后续保留或合并 `get_function_impl`，建议补充 `file_path` 参数，降低同名函数歧义风险。
- 非阻塞优化点：`get_deep_call_context` 已有独立工具实现，但默认 workflow 下当前对实际运行 Agent 不可见，因此 baseline 调用次数为 0。后续需要决定是按 skill/candidate 条件暴露，还是继续保持隐藏。
- 本次未修改任何工具行为；已发现的工具设计问题先记录，留待重构完成后统一讨论。


## 2026-07-07

### 已完成 新增 get_function_info 工具

- 按[历史工具优化计划](../design-plans/tools_optimation_plan.md)实现 `get_function_info`：
  - 新增 `CodeIndex.find_function_infos()`，按 `func_name` 和可选 `file_path` 返回所有匹配函数。
  - 返回 `match_count` 与 `matches`，不返回 `ambiguous`，由调用方通过 `match_count` 判断同名/重载歧义。
  - 每个 match 返回 `function_name`、`file_path`、`index_name`、`start_line`、`end_line`、`signature`、`callers`、`callees`。
  - `callers` / `callees` 先按调用者或被调用者聚合多个调用点，输出 `callsite_lines` 数组，再按 `callers_limit` / `callees_limit` 截断。
  - 新增 `callers_limit` 和 `callees_limit` 输入字段，默认值均为 30。
  - `call_type` 在 `svf` / `unified` 后端保留 `direct` / `indirect`；在 `clang` / `clangd` 后端自动降级为 `direct`。
- 新增 `zscope/tools/function_info.py`，提供 `GetFunctionInfoTool`。
- 在 `Analyzer._get_tools()` 中注册 `GetFunctionInfoTool`；`get_function_impl` 的实现和注册均保留，未删除。
- 在 `ToolsRuntime` 中补齐 `get_function_info` 的 schema、参数校验和执行分支，保持 runtime 工具路径一致。
- 更新工具兼容导出层 `zscope/tools/utils.py`，加入 `GetFunctionInfoTool`。
- 将 `zscope/agents/semantic_modeler/AGENT.md` 和 `zscope/agents/validator_agent/AGENT.md` 中的 `get_function_impl` 替换为 `get_function_info`。
- 同步更新 `code_semantic_modeling` 与 `evidence_validation` 两个 Skill 的 `allowed_tools`，避免 Agent/Skill 工具交集策略把 `get_function_info` 过滤掉。
- 更新 `tools_introduction.md`，将本地工具总数改为 13，并补充 `get_function_info` 的输入、输出和 `call_type` 降级说明。

### 测试

- `python -m py_compile zscope/retrieval/code_index.py zscope/tools/function_info.py zscope/tools/runtime.py zscope/tools/utils.py zscope/core/analysis/analyzer.py` 通过。
- 新增 `tests/test_function_info_tool.py`，覆盖：
  - 同名函数无 `file_path` 时返回多个 match。
  - 传入 `file_path` 时能缩小到目标文件。
  - 多个调用点聚合到 `callsite_lines`，且 `callers_limit` / `callees_limit` 在聚合后生效。
  - `svf` / `unified` 后端保留 `indirect` call_type。
  - `clang` / `clangd` 后端将 call_type 降级为 `direct`。
  - `GetFunctionInfoTool` 和 `ToolsRuntime.execute_tool("get_function_info", ...)` 均返回 `match_count`。
- `python -m pytest tests/test_function_info_tool.py tests/test_analyzer_tool_policy.py tests/test_tool_policy.py tests/test_json_output_agents.py -q` 通过：23 个测试。

### 注意事项

- 当前 `CodeIndex` 的唯一函数键生成策略不只使用 `函数名@文件:行号`。当同名函数可用签名键区分时，`index_name` 可能是 `Target(void)` 这类签名键；只有签名键也冲突时才会使用 `Target@src/a/shared.c:1` 形式。
- 本次没有删除 `get_function_impl`，也没有改变 `CodeIndex.get_function_impl()` 的返回结构。后续是否隐藏或删除旧工具，应基于小规模回归中的工具调用次数、token 成本和漏洞指标决定。

## 2026-07-15  get_function_info 工具扩展

### get_function_info 工具扩展

#### 已完成 get_function_info 符号上下文数据层

- 将 KnowledgeDB schema version 升级到 8，新增 `function_symbol_refs` 表及 function/symbol 查询索引。
- 为 `global_variables` 增加 `storage_class`、`qualifiers`、`initializer` 和 `definition_kind`，并为旧数据库增加兼容迁移。
- 新增 global 写入、完整 function/global/macro 记录读取、symbol reference 批量写入与聚合查询接口。
- `get_function_symbol_context()` 按函数和文件聚合引用：
  - global 引用合并 `reference_lines`，并将 read/write 合并为 `read_write`；
  - macro 引用合并 `reference_lines`，同时关联定义位置、definition 和 `is_function_like`。
- TU 清理同步删除函数拥有的 symbol refs；删除符号定义文件时可同步清理指向该文件的引用。
- KnowledgeDB stats 增加 `global_variables` 和 `function_symbol_refs`。

#### 测试

- `python3 -m py_compile zscope/retrieval/knowledge_db.py tests/test_knowledge_db_ir_and_config.py` 通过。
- `python3 -m pytest tests/test_knowledge_db_ir_and_config.py -q` 通过：15 个测试。

#### 已完成 Clang global/macro 引用抽取

- 修复 global 判定：只处理文件作用域 `SK_VARIABLE`，不再使用 `start_line <= 5`，并排除函数局部变量、结构体/类字段和枚举子节点。
- 从源码声明补充 global 的 storage class、qualifiers、initializer 和 declaration/definition 分类。
- Clang 批量索引完成后，基于完整的 functions/globals/macros 数据重建 `function_symbol_refs`：
  - 先做精确 identifier 交集；
  - 优先使用 clangd definition 定位实际声明文件和行；
  - definition 不可用时按同文件、definition 优先级做确定性选择；
  - 排除同名局部变量和 `.` / `->` 字段访问；
  - function-like macro 只有以调用形式出现时才记录；
  - global 引用区分 `read`、`write` 和 `read_write`。
- symbol refs 按文件打开 clangd document，同一文件内复用文档，避免按函数重复打开。
- 新增 `symbol_context_extractor_version=1`。旧索引缺少该版本时强制刷新文件并重建引用关系。
- `ClangBackend`、`UnifiedBackend` 和 backend base 增加 `get_function_symbol_context()`。

#### 测试

- `python3 -m py_compile zscope/retrieval/clang_extractor.py zscope/retrieval/clang_backend.py zscope/retrieval/unified_backend.py tests/test_clang_incremental_extraction.py` 通过。
- `python3 -m pytest tests/test_clang_incremental_extraction.py tests/test_knowledge_db_ir_and_config.py -q` 通过：30 个测试。

#### 已完成 get_function_info 第二阶段接口

- `CodeIndex.find_function_infos()` 只保留 `func_name` 和可选 `file_path`，不再接收 callers/callees。
- 每个 match 不再查询或返回 `callers`，caller/reachability 继续由 `get_callers` 负责。
- 每个 match 默认直接返回：
  - `callees`；
  - `referenced_globals`；
  - `referenced_macros`。
- `callees` 条目只包含 `callee_index_name`、`callsite_lines` 和 `call_type`；已知项目函数使用统一的 `func_name@file_path:start_line-end_line` 唯一键，无法解析的外部函数保留原始名称。
- callees 仅按 `callee_index_name` 聚合。`call_type` 改为数组，按固定顺序保留 `direct`、`indirect`；同一 callee 同时存在两类调用边时返回 `["direct", "indirect"]`。
- 使用后端固定上限：callees 30、referenced globals 50、referenced macros 30。
- 仅在对应数组被截断时返回独立元数据：`callees_truncation`、`referenced_globals_truncation`、`referenced_macros_truncation`；结构统一为 `truncated/returned/total`。
- callee `total` 在 `callee_index_name` 聚合 callsites 和 call types 后计算；globals/macros `total` 在符号聚合后计算。
- Clang/Unified 后端提供完整 callee edge 查询供 `get_function_info` 计算准确 total。
- regex 后端增加精确 symbol context 降级：扫描文件作用域 global 和 macro，排除局部同名变量与字段访问，并返回直接 callee callsite lines。
- `GetFunctionInfoTool` 和 `ToolsRuntime` schema/参数校验删除 `callers_limit`、`callees_limit`；external match 返回空 callees/globals/macros，不返回 callers。

#### 测试

- `python3 -m py_compile zscope/retrieval/code_index.py zscope/retrieval/backend_base.py zscope/retrieval/clang_backend.py zscope/retrieval/unified_backend.py zscope/tools/function_info.py zscope/tools/runtime.py tests/test_function_info_tool.py` 通过。
- `python3 -m pytest tests/test_function_info_tool.py -q` 通过：9 个测试，覆盖 `callee_index_name/callsite_lines/call_type` 输出结构和 direct/indirect 类型合并。
- `python3 -m pytest tests/test_function_info_tool.py tests/test_analyzer_tool_policy.py tests/test_tool_policy.py -q` 通过：22 个测试。

#### 已完成 Agent 与工具文档同步

- 更新 semantic modeler 主 `AGENT.md`：默认从 `get_function_info` 消费 callees、referenced globals 和 referenced macros；截断语义不再写入 Agent prompt，统一由 `get_function_info` 的 tool description 说明任一 truncation 字段都表示对应数组不完整。
- 更新 `tools_introduction.md`：删除旧 callers/callees limit 输入，补充 globals/macros 输出、固定后端上限和按数组返回的 truncation 结构。
- 工具说明中的 JSON 示例已通过严格 JSON 解析。
- 未修改任何 fallback 文件。

#### 最终验证

- `python3 -m py_compile` 覆盖本次修改的 retrieval、tool 和测试模块，通过。
- `python3 -m pytest tests/test_function_info_tool.py tests/test_knowledge_db_ir_and_config.py tests/test_clang_incremental_extraction.py tests/test_code_index_cache.py tests/test_analyzer_tool_policy.py tests/test_tool_policy.py -q` 通过：65 个测试。
- 针对本次修改文件执行 `git diff --check`，通过。

#### 计划偏差 / 后续风险

- 当前主 Clang 索引器基于 clangd LSP，未直接暴露计划中提到的 `DeclRefExpr` AST 节点。实现采用“精确 identifier 交集 + clangd definition 定位”作为优先路径，definition 不可用时使用局部变量/字段排除后的确定性源码降级。
- global `access` 在 definition 不可用时通过赋值和自增/复合赋值语法分类。复杂别名、通过指针写入或宏展开后的读写仍可能归为 `read`/`unknown`，后续若接入稳定 AST reference API 可替换该降级逻辑，不需要改变工具输出 schema。

### 已完成 CodeIndex 唯一函数键统一

- `CodeIndex` 中所有函数记录统一使用 `func_name@file_path:start_line-end_line` 作为 `index_name` 和 `_function_index` 键。
- 文件路径在生成键前统一转换为 source root 相对路径并使用 `/` 分隔；缺失或异常结束行回退到起始行。
- 不再根据“是否重名”选择简单名、签名键或带 `#2` 后缀，单函数和重载函数使用同一种键格式。
- 保留简单名、C++ 限定名、模板去除名和参数签名 alias，现有调用方仍可使用 `get_function_impl("name")` 或 `get_function_impl("name(params)")` 查询。
- 未提供文件路径且 alias 对应多个函数时，按文件路径、起始行、结束行和唯一键确定性选择第一项；提供 `file_path` 时继续精确消歧。
- 修复唯一键引入后的两个兼容问题：
  - 声明注释查询改用函数记录中的规范函数名，不再用 `index_name` 查询声明索引；
  - `get_function_impl.func_name` 保持为规范函数名，位置唯一键只放在 `index_name`。
- `list_functions()` 现在返回统一后的唯一函数键。

### 测试

- 更新 regex C++ constructor/destructor/member、重载函数和 `get_function_info.index_name` 断言，覆盖统一键格式。
- `python3 -m pytest tests/test_code_index_comments.py tests/test_function_info_tool.py tests/test_knowledge_db_ir_and_config.py tests/test_clang_incremental_extraction.py tests/test_code_index_cache.py tests/test_global_modeler.py tests/test_graph_candidates.py tests/test_analyzer_tool_policy.py tests/test_tool_policy.py -q` 通过：88 个测试。

### 已完成 工具运行时单源重构

#### 统一参数校验

- 在 `zscope/framework/base.py` 增加通用 `validate_function_arguments()`，集中处理 function schema 的 required、基础 JSON 类型、enum 和可选的未知参数检查。
- `BaseTool.validate_arguments()` 统一将 schema 校验错误转换为工具标准错误结果。
- `ToolPolicy.strict_schema` 复用同一校验函数，只额外启用未知参数拒绝，不再维护独立的类型映射和校验实现。
- `ToolCallingAgent._tool_executor()` 在执行具体工具前调用 `tool.validate_arguments()`，使 Agent 与 `ToolsRuntime` 使用同一套工具参数契约，并在执行前一致拒绝非 object 参数。
- `GetFileSnippetTool.validate_arguments()` 承接文件存在性、文件总行数和行范围校验；其 schema 明确要求 `file_path/start_line/end_line`。

schema 定义和工具参数语义由具体 `BaseTool` 提供，Runtime、Agent 和 strict policy 不再分别维护逐工具校验分支。

#### 建立统一工具 Registry

- 新增 `zscope/tools/registry.py`，由 `build_tool_registry()` 按稳定顺序构造 13 个内置工具。
- 支持 `snapshot_resolver` 注入、基础与 advanced graph 工具分组，以及重名工具构造时立即报错。
- 保持 dict 插入顺序，使 schema 暴露顺序和 Agent 工具顺序稳定。
- `FollowTaintTool` 未加入该 registry，保持重构前 `ToolsRuntime` 的 13 工具边界。

#### 重写 ToolsRuntime 与 Analyzer 装配

- 从 `zscope/tools/runtime.py` 删除 13 份硬编码 OpenAI tool schema、`_validate_tool_args()` 逐工具参数分支、13 路 if/elif dispatch，以及 `_get_function_impl()` 至 `_get_deep_call_context()` 的重复执行实现。
- 新的 Runtime 执行管线统一为：参数自动补全、ToolPolicy/pre-hooks、registry 查询、`tool.validate_arguments()`、negative cache、`tool.execute()`、位置上下文更新和 post-hooks/audit。
- Runtime 保留 snippet 位置参数自动补全、函数/片段位置上下文更新、`get_type_info` negative cache、ToolPolicy 和自定义 tool iterable 注入。
- `ToolsRuntime.get_tools_schema()` 直接遍历 registry 并调用具体工具的 `get_schema()`，description 和 schema 不再存在 Runtime 与具体 Tool 两条维护路径。
- `Analyzer._get_tools()` 改为调用 `build_tool_registry()`，同时保留 advanced backend 分组、按需 snapshot resolver、Agent allowlist 和 Agent/Skill ToolPolicy 可见性过滤。
- `ListFunctionsTool.execute()` 继续返回 `pattern`；`get_call_graph` 统一执行具体 `GetCallGraphTool` 的 depth 遍历语义。
- `CodeIndex.get_file_snippet()` 增加仅供内部调用方使用的 `max_lines` 和 `default_max_lines` 参数。有效 `end_line` 范围最多返回 500 行；省略或无效时最多返回 50 行。`get_file_snippet` tool 不暴露这两个参数。

#### 测试与验证

- 新增 `tests/test_tool_registry.py`，覆盖 13 个工具的稳定名称和顺序、schema 单源、registry dispatch、Agent/Runtime 共享校验、位置自动补全、negative cache、call graph depth、Analyzer backend 分组和 snapshot resolver。
- 定向架构及相关回归：`64 passed`。
- 更新 `tests/test_entry_discovery.py` 的 `list_functions(file_root=...)` 断言，使其匹配统一后的 `func_name@file_path:start_line-end_line` 唯一函数键；该测试文件 `19 passed`。
- 排除两个缺失 `scripts` 包的 benchmark 测试后，整体回归结果为 `643 passed, 2 failed`；剩余两项失败均为 `tests/test_user_config_workbook.py` 中当前未生成预期宏资源的既有问题。
- `python -m compileall -q zscope tests/test_tool_registry.py`：通过。
- `pytest -q tests/test_code_index_cache.py tests/test_tool_policy.py tests/test_tool_registry.py`：覆盖省略/无效 `end_line` 的 50 行默认值、有效范围的 500 行上限、内部调用方覆盖上限，以及 tool schema 不暴露内部参数。
- 全量 pytest 当前仍会因 `tests/test_benchmark_protocol.py` 和 `tests/test_range_benchmark_regression.py` 导入不存在的 `scripts` 包而在收集阶段失败。

## 2026-07-16

### 已完成 `get_function_info` 宏函数查询支持

- `CodeIndex.find_function_infos()` 在普通函数零命中时继续查询 function-like macro；对象式宏不作为宏函数 match 返回。
- 宏查询支持简单名称、宏 signature 形式、返回的宏 `index_name` 和可选 `file_path`，同名宏按规范化文件路径和定义行稳定排序并全部返回。
- 宏 match 使用独立最小结构，只包含：
  - `function_name`、`file_path`、`index_name`；
  - `start_line`、`end_line`、`signature`；
  - `is_macro=true`；
  - 带 1-based 行号的完整 `code`。
- 宏 match 不返回 `callees`、`referenced_globals`、`referenced_macros`、`truncated` 或对应 truncation 字段，也不执行 callee 提取。完整宏定义是该查询的主要语义证据。
- 宏 `index_name` 使用统一格式 `macro_name@file_path:start_line-end_line`，但宏记录不写入 `_function_index`、函数 alias index 或函数调用图。

### 共享逻辑与兼容性

- 将原先分别由 `_find_backend_macro_definition()` 和 `_find_macro_definition()` 承担的单结果查询收敛为 `_find_macro_impls()`：
  - 优先使用后端 `get_macro_definitions()`；
  - 后端无匹配候选时回退到缓存的 regex 宏索引；
  - 统一执行 function-like 过滤、路径过滤、位置去重和稳定排序；
  - 继续复用 `_macro_definition_payload()`、`_macro_signature()` 和多行宏源码解析。
- `_macro_definition_payload()` 支持 `max_lines=None` 返回完整宏定义，并增加内部 `include_callees` 控制。
- `get_function_info` 使用 `max_lines=None, function_like_only=True, include_callees=False`，不截断源码也不推断宏 callee。
- `get_function_impl` 继续传入原有 `max_lines` 并保留 `callees`、`truncated`、首候选返回和 `macro_alternates_count` 行为。
- `get_function_impl` 缓存 key 加入规范化 `file_path`，避免同名宏按文件查询时错误复用其他文件的缓存结果。
- 普通函数与宏同名时保持普通函数优先；指定宏定义文件且该文件没有普通函数 match 时返回宏 match；项目宏优先于 external function fallback。
- `get_function_info` 的 external fallback 与 `get_function_impl` 对齐：
  - 使用 `sanitize_func_name()` 产生的兼容名称查询外部函数配置，使 `external_api(int)` 能命中 `external_api`；
  - 配置命中时保持 function-info 的结构化 external match，并设置 `is_external=true`；
  - 配置未命中时记录同样的 `missing_external_func` warning 并返回 `success=false`；
  - 未注入 `UserConfigStore` 时，未知函数直接返回 not found，不再返回成功的空 matches。

### 工具与文档

- 更新 `GetFunctionInfoTool` description，明确 function-like macro 的条件返回结构和完整 `code`。
- 更新 `new_docs/tools_introduction.md`，区分普通函数 match 与宏 match，说明宏结构中省略调用关系和符号上下文字段。
- 未增加工具输入参数，Runtime 继续通过统一 registry 使用同一工具 schema 和执行实现。
- 未修改任何 fallback 文件。

### 测试与验证

- 新增/更新测试覆盖：
  - 单行和多行 function-like macro；
  - 超过 500 行的宏仍返回全量源码且无 `truncated`；
  - 对象式宏不作为宏函数返回；
  - 同名宏全量返回及 `file_path` 消歧；
  - 普通函数与宏同名时的查询优先级；
  - 通过返回的宏 `index_name` 再查询；
  - 后端宏事实优先且不触发 regex fallback；
  - function-info 宏路径不执行 callee 提取；
  - Tool 与 Runtime 返回一致；
  - `get_function_impl` 既有宏字段和 callee 行为保持不变。
- 补充 external 行为测试，覆盖配置命中、配置缺失 warning、未注入 UserConfigStore，以及签名形式名称的兼容清理。
- `python3 -m py_compile zscope/retrieval/code_index.py zscope/tools/function_info.py tests/test_code_index_cache.py tests/test_function_info_tool.py`：通过。
- 更新 external 测试以匹配当前条件契约：`get_function_info` 保留 `match_count/matches` 外层，external match 中的伪源码 `code` 与 `get_function_impl` external payload 一致，不要求两个工具的顶层 schema 相同。
- 重新运行 `python3 -m pytest tests/test_function_info_tool.py tests/test_code_index_cache.py tests/test_code_index_comments.py tests/test_knowledge_db_ir_and_config.py tests/test_clang_incremental_extraction.py tests/test_global_modeler.py tests/test_analyzer_tool_policy.py tests/test_tool_policy.py tests/test_tool_registry.py -q`：`94 passed`。

## 2026-07-17

### 已完成函数查询 simple-name fallback 下沉

- 从 `GetFunctionImplTool.execute()` 移除查询前的 `sanitize_func_name()`，工具现在原样保留函数名、签名、完整声明和 `index_name`，只执行字符串归一化与空值检查。
- `GetFunctionInfoTool` 和 `GetFunctionImplTool` 的 external fallback 改为复用 `CodeIndex.fallback_function_name()`，不再各自使用不同的名称清理规则。
- 新增受控 `_fallback_function_name()`：
  - 支持从陈旧 `func_name@file_path:start_line-end_line` 提取函数名和路径 hint；
  - 支持从函数签名、完整声明和 C++ 限定名提取 simple/qualified name；
  - 拒绝显式 `#define`、函数指针声明和不符合 C/C++ 名称结构的任意文本；
  - fallback 不执行前缀、子串或编辑距离搜索。

### 统一函数匹配层

- 新增 `_find_function_matches()` 和 `_match_function_records()`，统一复用 query variants、record variants、文件路径过滤和稳定排序。
- `find_function_infos()`、`_resolve_function_name()` 和 `get_function_impl()` 共享同一匹配规则，删除不再使用的 `_resolve_ambiguous_function_alias()`、`_resolve_function_name_by_file()` 和 `_resolve_function_match_from_records()` 独立路径。
- 共享层保留 exact `_function_index` 和唯一 alias 的 O(1) 快速路径；只有歧义名称或文件过滤场景才遍历候选记录，避免 callee 名称规范化退化为全索引扫描。
- `_function_record_query_variants()` 补齐 C++ simple/tail name variants，保持 constructor、destructor 和 member function 的旧查询行为。
- 文件限定 strict 查询继续填充 `_function_file_resolution_cache`，索引重建时沿用现有失效逻辑。

### strict/fallback 行为

- `find_function_infos()` 查询顺序调整为：
  1. 显式 `#define` 直接查询 function-like macro；
  2. strict function index/signature/name 查询；
  3. 位置键的 exact macro 查询；
  4. 受控 function simple-name fallback，返回全部候选；
  5. 普通 function-like macro fallback；
  6. Tool 层 external fallback。
- 陈旧函数位置键在 strict miss 后使用键内文件路径作为 fallback hint；显式 `file_path` 优先于键内路径，旧行号不限制移动后的函数位置。
- 签名精确命中时保留 overload 消歧；参数名称等差异导致 strict miss 时，`find_function_infos()` 返回全部同名候选并通过 `match_count` 暴露歧义。
- 宏位置键先按 name/file/start/end 精确匹配完整宏定义，再考虑函数 fallback；exact end line 使用完整 definition 计算，不受 `get_function_impl.max_lines` 截断影响。

### `get_function_impl` 与缓存

- `get_function_impl()` 保留原始简单名多候选时的确定性首项行为，以兼容旧调用方。
- 从签名、完整声明或陈旧位置键派生的 fallback：
  - 唯一候选时返回该实现；
  - 多个候选时记录歧义并返回 `None`，不静默选择错误 overload。
- 后端查询遵循 strict-first：原始 query variants 未命中后，才使用 fallback name 调用 `get_method()`；后端结果先注册到 `_function_index`，再通过共享匹配层选择。
- 函数实现缓存改为在最终目标确定后使用 canonical `index_name` 构造 key；不同陈旧键或签名 fallback 到同一函数时复用同一缓存项。
- 宏实现缓存同样使用宏的 canonical `name@file:start-end` 身份；`get_function_impl` 的既有 `callees`、`truncated` 和 `macro_alternates_count` 契约保持不变。

### 工具与文档

- 更新 `GetFunctionImplTool` description 和 `func_name` schema 描述，明确支持 name、signature 和 `index_name`，以及 exact miss 后的受控 fallback。
- 更新 `new_docs/tools_introduction.md` 中 `get_function_impl` 的输入、唯一键和 fallback/overload 行为说明。
- `sanitize_func_name()` 继续保留给 callers、call graph、snapshot、data flow 和 function pointer 等尚未迁移的工具。
- 未修改任何 fallback 文件。

### 测试与验证

- 新增测试覆盖：
  - 有效与陈旧 `index_name`；
  - 旧键路径 hint 和显式 `file_path` 优先级；
  - 精确 signature/full declaration overload 选择；
  - signature mismatch 后 `find_function_infos()` 返回全部候选；
  - function-like macro `index_name` 在函数 fallback 前精确命中；
  - `GetFunctionImplTool` 不再提前丢失签名；
  - `get_function_impl` 唯一 fallback、歧义 fallback 和原始简单名兼容行为；
  - strict/fallback 后端补查顺序；
  - canonical implementation cache 复用。
- `python3 -m py_compile zscope/retrieval/code_index.py zscope/tools/code_retrieval.py zscope/tools/function_info.py tests/test_function_info_tool.py tests/test_code_index_cache.py`：通过。
- 工具、索引、Clang/KnowledgeDB 和 registry 相关回归：`101 passed`。
- entry discovery、graph candidates、analyzer semantics、global modeler 和 C++ comment/index 回归：`75 passed`。

### 已完成普通项目函数 `is_static` 输出

- `get_function_info` 与 `get_function_impl` 的普通项目函数结果新增 bool 类型 `is_static`；function-like macro 和 external function 保持条件结构并省略该字段。
- KnowledgeDB 的函数索引与 function record 查询补齐 `is_static` 读取和 bool 归一化，ClangBackend 的动态 `get_method()` 路径同步透传该字段。
- ClangExtractor 的 static 检测同时检查 clangd `detail` 和源码 signature 头部，避免 clangd 未提供 detail 时丢失 `static`。
- CodeIndex 优先使用后端显式 `is_static`；显式 `false` 具有权威性，不会被源码覆盖。字段缺失时依次检查 signature 和函数定义头部，文件读取复用 `_file_lines_cache`。
- regex 索引只根据函数名之前的定义头部设置 static 属性；源码 fallback 会屏蔽注释和字面量，并在函数体前停止，避免形参数组中的 `static` 或 local static 变量造成误判。
- 工具 description 与 `new_docs/tools_introduction.md` 已同步普通函数字段语义及 macro/external 省略规则；input schema、唯一函数键和缓存 key 均未修改。

### 测试

- 测试覆盖 regex static/非 static、local static、后端显式 true/false、缺失字段源码 fallback、KnowledgeDB round trip、Clang 提取与动态查询、Runtime 一致性，以及 macro/external 字段省略。
- 定向验证：`71 passed`（`tests/test_function_info_tool.py`、`tests/test_code_index_cache.py`、`tests/test_knowledge_db_ir_and_config.py`、`tests/test_clang_incremental_extraction.py`）。
- 合并工具、索引、Clang、Runtime、entry/graph/analyzer 相关回归：`168 passed`。
- `python3 -m py_compile` 覆盖本次实现和测试文件，通过；针对相关文件执行 `git diff --check`，通过。

## 2026-07-20 `get_callers` canonical 输入与结构化输出

### 阶段 1：新契约测试已锁定

- 新增 `tests/test_callers_tool.py`，覆盖：
  - Tool schema 只暴露 `func_name` 和可选 `file_path`；
  - Tool 固定使用 caller limit 20，并忽略历史 `limit` 输入；
  - 成功输出只包含结构化 `callers`；
  - 目标函数零命中和多命中的失败语义；
  - LLM repeat-call normalization 不再注入隐藏 `limit`；
  - CodeIndex 按 canonical caller identity 聚合 callsite lines 和 direct/indirect arrays；
  - 同名目标函数必须使用 `file_path` 或 `index_name` 消歧。
- 初始测试运行结果为 `6 failed`，失败均对应尚未实施的新接口，不包含既有回归。
- 本阶段未修改任何 fallback 文件。

### 阶段 2：backend caller 证据与 CodeIndex 聚合完成

- `CodeBackend` 增加可覆盖的 `get_function_info_callers()`，默认复用通用 caller 查询并读取足够的原始边。
- KnowledgeDB 增加专用 `get_all_callers()`：完整返回 direct caller 的文件、调用行和 `call_type`，不改变既有 `get_callers()` raw row 契约。
- `get_indirect_callers()` 补齐 call file、call line、confidence 和稳定排序，为 structured caller context 保留 SVF 证据。
- UnifiedBackend 的专用 caller 路径拼接 direct 与 indirect rows，不按 caller name 提前丢弃 mixed 类型。
- CodeIndex 新增 `find_function_callers()`：
  - 复用 strict/fallback function matching；
  - 只有唯一目标才执行 caller 查询；
  - `file_path` 可消歧同名定义；
  - caller 按 canonical `caller_index_name` 聚合；
  - callsite lines 去重升序；
  - call types 稳定输出为数组。
- 通用 `CodeIndex.get_callers()`、`GetCallGraphTool` 和其他内部消费者保持原接口。
- 阶段回归：CodeIndex caller 测试与 KnowledgeDB 测试通过，`19 passed`。

### 阶段 3：Tool、LLM 参数和文档接入完成

- `GetCallersTool` 不再调用 `sanitize_func_name()`，完整保留 name、qualified name、signature 和 `index_name` 查询。
- Tool input schema 只暴露 required `func_name` 和 optional `file_path`；删除公开 `limit`。
- Tool 内部固定调用 `find_function_callers(..., limit=20)`，历史 payload 中额外的 `limit` 不再影响行为。
- 成功响应删除 `count`，只返回 `data.callers`；零命中和多命中分别返回 `function_not_found` 与 `ambiguous_function`。
- LLMClient repeat-call 参数 normalization 删除 `get_callers` 的隐藏 `limit=20` 注入，调用签名与公开 schema 对齐。
- `new_docs/tools_introduction.md` 已同步 canonical 输入、固定上限、结构化 caller arrays 和失败语义。
- 新增 UnifiedBackend + KnowledgeDB 真实数据测试，确认同一 caller 的 direct/indirect 原始证据不会被提前去重。
- 本阶段定向测试：`7 passed`。

### 阶段 4：兼容性收紧与最终验收完成

- 对同名目标使用 `file_path` 消歧时，如果 backend 的 indirect edge 不包含 callee 文件身份，CodeIndex 会过滤该不可唯一归属的 indirect 证据，避免将 SVF 边错误绑定到某个同名实现。
- 增加 canonical `index_name` 直接查询测试，确认不会经过旧 `sanitize_func_name()` 路径。
- 当前 Semantic Modeler schema 中 `callers[].call_type` 已由用户修改为 array；旧测试仍断言 scalar。本阶段只同步测试，没有回退或改写该 schema。
- 聚焦 caller、registry、function info、KnowledgeDB、Semantic Modeler 和 analyzer 回归：`112 passed`。
- 扩展 Unified/SVF、diff impact、validation、CodeIndex cache、entry discovery、global modeler 和 snapshot tool 回归：`115 passed`。
- 最终 caller/KnowledgeDB 定向回归：`47 passed`。
- 修改文件 `compileall` 通过，相关 tracked 文件 `git diff --check` 通过。
- 全量回归：`733 passed`。
- 第十三节计划已标记为实施完成，本轮未修改任何 fallback 文件。

## 2026-07-20 `get_type_info` 文件消歧与多候选输出

### 阶段 1：新契约测试已锁定

- 新增 `tests/test_type_info_tool.py`，覆盖：
  - input schema 增加 optional `file_path`；
  - 单命中和多命中统一返回 `match_count/matches`；
  - Tool payload 删除 `id/tu_id`；
  - KnowledgeDB 多文件同名、不同 kind 和 members 隔离；
  - CodeIndex 对旧单结果 backend 的兼容包装；
  - Joern 多 typeDecl 及 per-declaration members；
  - Runtime negative cache 按 `type_name + file_path` 隔离。
- 初始测试结果：`7 failed`，失败均对应尚未实现的新 API，不包含既有回归。
- 本阶段未修改任何 fallback 文件。

### 阶段 2：多候选数据源与 CodeIndex 归一化完成

- KnowledgeDB 新增 `find_type_infos(name, file_path)`：
  - 返回全部同名类型定义；
  - 使用现有路径匹配语义进行文件限定；
  - 每条定义按内部 type id 独立查询 members；
  - public matches 删除 `id/tu_id`。
- 原 `KnowledgeDB.get_type_info()` 保持单结果和内部字段结构，继续服务旧调用方及增量索引测试。
- `CodeBackend` 增加兼容默认 `find_type_infos()`；Clang、Unified 和 Joern 提供专用实现。
- JoernClient 新增多 typeDecl 查询，在每个 declaration 内收集自己的 members，避免同名类型成员合并。
- CodeIndex 新增 `find_type_infos()`，统一 filename/line/member 字段、删除内部主键并稳定排序；原 `get_type_info()` 返回类型不变。
- 阶段回归覆盖 KnowledgeDB、legacy backend fallback、Joern 和既有 KnowledgeDB 测试：`20 passed`。

### 阶段 3：Tool 与 Runtime 接入完成

- `GetTypeInfoTool` input schema 新增 optional `file_path`，`type_name` 只执行 trim。
- Tool 改用 `CodeIndex.find_type_infos()`，单命中和多命中统一返回 `data.match_count/data.matches`。
- Tool 在输出边界再次删除 `id/tu_id`，防止第三方 backend 意外泄露内部字段。
- 零命中继续返回 `Type '...' not found`；多命中属于成功结果。
- ToolsRuntime negative cache key 从单独 `type_name` 扩展为规范化后的 `type_name + file_path`，不同声明文件的查询不再互相污染。
- Tool 与 registry/negative-cache 定向测试：`16 passed`。

### 阶段 4：Agent policy 与工具文档同步完成

- 主 Semantic Modeler `AGENT.md` 更新为：
  - `get_function_info` 与 `get_type_info` 允许多候选；
  - `get_function_snapshot` 与 `get_callers` 仍要求唯一函数命中；
  - 已知类型声明文件时向 `get_type_info` 传 `file_path`；
  - 无文件限定时检查全部 matches，不默认选择 `matches[0]`。
- `new_docs/tools_introduction.md` 将 `get_type_info` 更新为 `match_count/matches`，增加文件消歧和成员隔离说明，并从 Tool payload 删除 `id/tu_id`。
- 增加主 AGENT 静态契约测试；未修改 fallback Agent 文件。
- type/tool/KnowledgeDB/Agent 相关聚焦回归：`77 passed`。

### 阶段 5：最终验收完成

- 扩展回归覆盖 Clang 增量索引、CodeIndex cache、analyzer semantics、global modeler、snapshot/caller tool、tool policy 和 SVF session：`108 passed`。
- 残留扫描确认生产代码没有继续按旧结构读取 `get_type_info.data.members`；`tu_id` 只保留在数据库内部、计划和实施说明中。
- 修改文件 `compileall` 通过，相关 tracked 文件 `git diff --check` 通过。
- 全量回归：`742 passed`。
- 旧 `CodeIndex.get_type_info()` 和 backend `get_type_info()` 继续返回 Optional single dict；新 Tool 独立使用 `find_type_infos()`，兼容边界符合计划。
- 第十四节计划已标记为实施完成，本轮未修改任何 fallback 文件。

## 2026-07-20 `get_type_info` 保留源码定义并删除 members

### 阶段 1：修复契约测试已锁定

- 更新 `tests/test_type_info_tool.py`，要求公开 matches：
  - `full_definition` 非空；
  - 不包含 `members`；
  - `typedef struct/union` 即使 clangd 返回 `SK_CLASS`，仍按源码识别真实 kind；
  - C++ class 和 enum 保持正确 kind。
- 初始运行 `8 failed, 4 passed`，失败均对应旧 extractor 和旧 public projection。
- 主 AGENT 存在用户后续手动调整，本阶段不回退该文件，只放宽对应静态测试。

### 阶段 2：源码定义与 public projection 修复完成

- ClangExtractor 新增 LSP range 源码截取，将完整类型定义写入 `full_definition`。
- 类型 kind 优先从屏蔽注释/字面量后的源码头部识别 `struct/union/enum/class`，LSP SymbolKind 只作为 fallback。
- KnowledgeDB `find_type_infos()`、CodeIndex `find_type_infos()` 和 `GetTypeInfoTool` 的公开多候选路径均删除 `members`。
- 旧 `KnowledgeDB.get_type_info()` 继续保留内部 members，避免改变尚未迁移的单结果内部接口。
- Joern 多候选查询只返回 declaration source，不再构建重复的 members 数组。
- 定向测试：`12 passed`。

### 阶段 3：公开文档同步完成

- `GetTypeInfoTool` description 改为 source-backed type definitions，不再宣称返回 declaration-local members。
- `new_docs/tools_introduction.md` 删除 members 示例，明确 `full_definition` 是类型主体的唯一公开表示。
- 第十四节计划增加后续决策说明，标明 public members 相关旧要求已被覆盖。
- 本阶段未修改 Semantic Modeler fallback 文件。

### 阶段 4：旧类型索引自动失效完成

- ClangBackend 增加 `TYPE_EXTRACTOR_VERSION=1` 和 `type_extractor_version` metadata。
- metadata 缺失或版本变化时，即使源码 hash 未变化，也将全部相关 TU 标记为 pending；现有 batch extraction 会 purge 旧事实并重新提取。
- 无文件、无需提取和成功提取三个结束路径都会写入当前 type extractor version。
- 更新 Clang 增量测试，确认 metadata 写入和 unchanged TU 强制 refresh。
- type、Clang incremental 和 KnowledgeDB 聚焦回归：`45 passed`。

### 阶段 5：最终验收完成

- 扩展 Tool registry、Semantic Modeler、analyzer semantics、CodeIndex cache、global modeler、snapshot/caller 和 SVF session 回归：`111 passed`。
- 修改文件 `compileall` 通过，相关 tracked 文件 `git diff --check` 通过。
- 全量回归：`746 passed`。
- 当前公开 `get_type_info.matches[]` 以 `full_definition` 作为唯一类型主体，不返回 `members/id/tu_id`。
- Clang/Unified 新索引会按源码纠正 typedef struct/union 的 kind；旧索引会因 type extractor version 变化自动重建。
- 本轮未修改任何 fallback 文件。

## 2026-07-20 `get_function_snapshot` Function Info Fallback

### 实现

- `GetFunctionSnapshotTool` 在未注入 on-demand resolver 时继续通过 `build_semantic_model_input()` 完成唯一 function info 解析、完整源码读取和 snapshot refresh 检查。
- 当前 snapshot 不存在时返回：
  - `success=true`
  - `data=null`
  - `snapshot_status=missing`
  - `reason=no_snapshot`
  - 当前 canonical `function_info`
- 当前 snapshot 已过期时返回：
  - `success=true`
  - `data=null`
  - `snapshot_status=stale`
  - 原 refresh reason
  - 当前 canonical `function_info`
- `data` 的语义保持不变，只表示当前有效 snapshot 或 `null`，function info 不写入 `data`，stale snapshot 也不会返回给 Agent。
- fallback `function_info` 使用与 `get_function_info.matches[]` 对齐的核心字段：
  - `function_name`
  - `index_name`
  - `file_path`
  - `start_line`
  - `end_line`
  - `signature`
  - `is_static`
  - `is_macro`
  - `callees`
  - `referenced_globals`
  - `referenced_macros`
- 存在时透传 `callees_truncation`、`referenced_globals_truncation` 和 `referenced_macros_truncation`。
- fallback 不返回完整 `code`，避免 snapshot 查询结果不必要膨胀；Agent 需要行为证据时继续使用精确 `get_file_snippet`。
- 有 on-demand resolver 时保持原行为：工具直接委托 resolver，缺失或 stale snapshot 由 resolver 复用、确定性构建或调用 Semantic Modeler 构建。

### Agent 与文档

- 工具 description 明确 `data=null + function_info` 的 fallback 契约，并要求直接复用而不是再次调用 `get_function_info`。
- 更新主路径 Semantic Modeler：callee snapshot 缺失或 stale 且返回 fallback 时，复用 function info，只在缺少必要行为证据时请求源码片段。
- 更新主路径 Deep Worker：复用 fallback，不重复请求相同函数元数据。
- 更新 `new_docs/tools_introduction.md` 的 missing/stale 返回示例、字段语义和 Agent 使用方式。
- 更新 `new_docs/agent_introduction.md` 的工具策略说明。
- 未修改任何 fallback 文件。

### 测试

- 新增 snapshot missing fallback 测试，确认返回 canonical function info、truncation 元数据且不包含 `code`。
- 更新 symbol context stale 和 deterministic shape stale 测试，确认都返回最新 function info 且不返回 stale snapshot。
- snapshot tool、tool registry 和 Semantic Modeler JSON 输出聚焦回归：`34 passed`。
- 扩展 snapshot store、analyzer semantics 和 global modeler 回归：`93 passed`。
- `python -m compileall -q zscope/tools/snapshot_tool.py`：通过。
- 全量回归：`734 passed`。

## 2026-07-23 `get_callers` function-like macro fallback

### 实现

- `CodeIndex.find_function_callers()` 在普通函数未命中后复用 `_find_macro_impls()` 解析 function-like macro。
- 支持宏简单名称、可选 `file_path` 和 canonical 宏 `index_name`；普通函数的既有匹配优先级保持不变。
- 同名同文件的多个条件编译定义按宏符号聚合，再以宏名和文件查询底层 caller 边；不把调用边伪装成已绑定到某个条件定义行。
- 同名宏位于多个文件时保持歧义语义，要求使用 `file_path` 或 canonical identity 消歧。
- caller 结果继续复用既有 canonical caller、callsite 和 direct/indirect 聚合逻辑。

### 测试

- `python -m pytest tests/test_callers_tool.py -q`：`10 passed`。
- `python -m pytest tests/test_callers_tool.py tests/test_function_info_tool.py -q`：`39 passed`。
- 使用 `global_model_benchmark.db` 副本验证 `SERVICE_COUNTER_UNLOCK` 的简单名称和 canonical identity，均返回 `_runtime_update_metric_counter@src/lifecycle.c:1996-2002`、调用行 2000、`call_type=["direct"]`。

## 2026-07-23 Tool 层 `file_path` 零命中 fallback

### 实现

- `get_function_info` 和 `get_type_info` 在收到非空 `file_path` 时仍优先执行严格路径限定查询。
- 严格路径查询零命中时，Tool 自动执行一次同名、无 `file_path` 查询；fallback 只发生一次，不下沉到 CodeIndex，不改变底层路径过滤语义。
- 无路径查询命中时返回 `success=true`，`data.matches` 直接包含全部无路径候选，`data.match_count` 始终等于候选数量，不截断且不自动选择首项。
- fallback 成功时在顶层增加 `file_path_fallback`，只包含：
  - `reason=file_path_not_matched`
  - 原始 `requested_file_path`
  - 明确说明这些候选来自无 `file_path` 查询的 `message`
- `file_path_fallback` 不包含 `query_scope`；正常严格命中时不返回该字段。
- `get_function_info` 的无路径查询仍零命中时，才进入既有 external function fallback / not-found 分支。
- `get_type_info` 对 fallback 候选继续统一删除内部 `id`、`tu_id` 和派生 `members`；无路径查询仍零命中时保持既有失败语义。
- `get_callers` 和 `get_function_snapshot` 需要唯一目标，不纳入本次直接返回多候选的 fallback。
- Runtime 继续只缓存真正失败的 `get_type_info` 查询；fallback 成功结果不会进入 negative cache。

### 测试

- 增加 function/type 错误路径后二次查询测试，确认返回全部 matches、`match_count` 一致、提示包含原路径且没有 `query_scope`。
- 更新 type not-found 和 Runtime scoped negative-cache 调用序列，纳入额外一次无路径查询。
- 增加 Runtime fallback 成功不进入 negative cache 的回归测试。
- `python -m pytest tests/test_function_info_tool.py tests/test_type_info_tool.py tests/test_tool_registry.py -q`：`55 passed`。
- `python -m pytest -q`：`799 passed`。
