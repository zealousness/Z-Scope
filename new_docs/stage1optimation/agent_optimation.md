# 上下文优化实施记录

## 2026-07-03

### 已完成 semantic_modeler skill 合并

- 将固定用途的 `code_semantic_modeling` 规则压缩合并到 `semantic_modeler/AGENT.md`。
- 移除 `semantic_modeler` 的固定 skill 绑定，运行时不再额外拼接 `code_semantic_modeling/SKILL.md`。
- 保留 `code_semantic_modeling/SKILL.md` 文件，作为历史和后续复用参考。
- 补充约束：`semantic_modeler` 不应对当前目标函数调用 `get_function_snapshot`，因为创建该 snapshot 正是当前任务。

### 测试

- `python -m pytest -q tests/test_json_output_agents.py` 通过：6 个测试。

### 已完成 validator_agent skill 卸载

- 移除 `validator_agent` 的固定 `evidence_validation` skill 绑定，运行时不再额外拼接该 `SKILL.md`。
- 保留 `evidence_validation/SKILL.md` 文件，作为历史和后续复用参考。
- `validator_agent/AGENT.md` 已覆盖严格验证、三态 verdict、证据门槛和输出字段要求，因此本次不重写正文。

### 测试

- `python -m pytest -q tests/test_validator_agent_parsing.py tests/test_validation_runner.py tests/test_json_output_agents.py` 通过：26 个测试。

### 下一步计划

- 评估 `validator_agent/AGENT.md` 中完整 JSON 示例是否可由 runtime schema 替代，以进一步减少 prompt token。
- 每次压缩后用对应 agent 的解析/runner 测试确认结构化输出路径不受影响。

## 2026-07-08

### 已完成 trivial/lightweight快照修复

- 修复宏定义 callee 提取噪声：此前对整行 `#define MACRO(args) body` 做调用匹配，会把宏定义左侧的 `MACRO(` 误识别为自调用，导致 lightweight macro snapshot 的 `callees` 出现 self-edge。
- 现在宏 snapshot 仍保留完整 `code`，但 `callees` 只从 replacement body 中提取，例如 `#define LOG_WARN(...) _log_wrapper(...)` 只记录 `_log_wrapper`。

### 测试

- `python3 -m pytest tests/test_code_index_cache.py -q`通过：12 个测试，覆盖 backend macro 与 regex fallback macro 两条路径。

### 已完成 trivial/lightweight快照格式对齐

- 统一 deterministic snapshot 字段格式：`trivial` 与 `lightweight` 自动摘要生成的 snapshot 不再输出外层 `semantic_fingerprint`。
- `trivial` 与 `lightweight` snapshot 现在使用与 `semantic_modeler` schema 一致的顶层字段：
  - `"key_semantics": [...]`
- 更新 validation evidence 压缩逻辑：`compact_snapshot()` 现在输出 `"key_semantics": snapshot.get("key_semantics")`，不再输出 `"semantic_fingerprint"`。
- 同步测试中的 snapshot 样例，并增加断言确保 deterministic snapshot 和 validation evidence 不再携带 `semantic_fingerprint`。

### 测试

- `python -m pytest tests/test_analyzer_semantics.py tests/test_global_modeler.py tests/test_snapshot_refresh_decision_prompt.py -q` 通过：42 个测试。
- `python -m py_compile zscope/snapshots/policy.py zscope/core/validation/evidence.py` 通过。

## 2026-07-09

### 已完成 trivial/lightweight快照签名修复

- 修复函数实现 signature 展示噪声：部分 clang/LSP 后端会返回 `int (const char *) func` 这类 type spelling，不是源码声明顺序，容易误导 trivial/lightweight snapshot 阅读。
- 修复点调整到 clang/LSP 入库前：`ClangExtractor._process_symbol()` 现在优先从源码函数头生成 `signature`，再写入 `KnowledgeDB.functions.signature`。
- 因此 `get_function_impl()` 与 `get_function_info()` 仍从同一个 `_function_index` 读取 signature，不再在工具返回层做二次覆盖。

### 测试

- `python3 -m pytest tests/test_clang_incremental_extraction.py tests/test_code_index_cache.py -q` 通过：25 个测试，覆盖 clang/LSP 入库前源码签名生成和 CodeIndex 相关回归。

# JSON schema优化

## 2026-07-09

### 已完成 semantic_modeler 输出 JSON schema 对齐

- 对齐 `semantic_modeler` 的 LLM-modeled 函数快照 schema 与 `trivial` / `lightweight` 静态快照字段。
- 在 `DEFAULT_FUNCTION_SNAPSHOT_SCHEMA` 顶层 required 中新增：
  - `index_name`
  - `file_path`
  - `start_line`
  - `end_line`
  - `signature`
  - `snapshot_kind`
- 在 schema properties 中补充上述字段定义。
- `index_name` 放在原先 `location` 的顶层位置，用作函数在索引中的规范 key，例如 `name@path:start_line`。
- 将 LLM 生成快照的 `snapshot_kind` 固定为 `LLM-modeled`，用于和静态生成的 `syntactic` / `lightweight` 快照区分。
- 删除 `location` 字段。
- 本次未修改 `build_trivial_snapshot()` / `build_lightweight_snapshot()` 的实现。

### 测试

- 新增 `test_semantic_modeler_schema_aligns_llm_snapshots_with_static_snapshots`，确认新增字段在 schema required 和 properties 中均存在，并确认 `snapshot_kind` 为 `{"const": "LLM-modeled"}`。

### 已完成  semantic_modeler 输出 JSON schema role 优化

- 将 `semantic_modeler` 快照 schema 中自由文本 `role` 改为枚举数组 `roles`。
- `roles` 为 required，允许同一函数标记多个职责，例如 `parser` + `validator` 或 `resource_acquirer` + `state_mutator`。
- 当前候选项为：
  - `entrypoint`
  - `parser`
  - `validator`
  - `dispatcher`
  - `allocator`
  - `deallocator`
  - `resource_acquirer`
  - `resource_releaser`
  - `initializer`
  - `finalizer`
  - `state_mutator`
  - `state_observer`
  - `synchronization`
  - `io_boundary`
  - `wrapper`
  - `callback`
  - `error_handler`
  - `utility`
  - `unknown`
- 更新 `semantic_modeler/AGENT.md` 和 `code_semantic_modeling/SKILL.md` 中关于输出字段语言的说明：`roles` 作为 enum 保持 schema 值，不翻译为中文描述。

### 测试

- 新增测试覆盖主路径 schema 的 `roles` 枚举字段。


### 已完成 semantic_modeler 输出 JSON schema 接口字段重命名

- 删除主路径 `semantic_modeler` schema 中的 `inputs` 和 `outputs` 字段。
- 新增 `parameters` 数组，用于统一描述所有形参：
  - `name`
  - `type`
  - `meaning`
  - `direction`
  - `trust`
  - `nullable`
  - `ownership`
  - `constraints`
  - `caller_obligation`
- 新增 `return_values` 对象，只描述 C 函数 return 语义，不再混入 out parameter 或副作用：
  - `type`
  - `meaning`
  - `nullable`
  - `ownership`
  - `success_cases`
  - `failure_cases`
  - `caller_obligation`
- 更新 `semantic_modeler/AGENT.md` 输出说明，将 `Inputs/outputs` 改为 `Parameters/return values`。

### 测试

- 新增 `test_semantic_modeler_schema_uses_parameters_and_return_values`，防止 `inputs` / `outputs` 回流。


### 已完成 semantic_modeler effects 字段落地

- 按[历史快照重构方案](../../docs/archive/design-plans/snapshot_redesign.md)的统一副作用建模方向，更新主路径 `DEFAULT_FUNCTION_SNAPSHOT_SCHEMA`。
- 直接删除旧的顶层 schema 字段：
  - `memory`
  - `resources`
  - `concurrency`
- 新增 required 顶层字段 `effects`，无可观察副作用时输出空数组 `[]`。
- `effects` 单条 item 必填字段为：
  - `category`
  - `action`
  - `description`
  - `line`
  - `object`
  - `condition`
  - `risk`
- `effects.category` 候选项为：
  - `memory`
  - `resource`
  - `ownership`
  - `alias`
  - `bounds`
  - `shared_state`
  - `lock`
  - `thread`
  - `sync_protocol`
  - `io`
  - `callback`
  - `global_state`
  - `registry`
  - `other`
- 新增 `EFFECT_ACTION_ENUM`，将 `effects.action` 从自由字符串收紧为全局 enum。当前候选项为：
  - `allocate`
  - `release`
  - `resize`
  - `transfer`
  - `retain`
  - `borrow`
  - `alias`
  - `read`
  - `write`
  - `read_write`
  - `copy`
  - `move`
  - `set`
  - `check`
  - `acquire`
  - `try_acquire`
  - `unlock`
  - `create`
  - `join`
  - `detach`
  - `schedule`
  - `cancel`
  - `call`
  - `register`
  - `unregister`
  - `open`
  - `close`
  - `map`
  - `unmap`
  - `return`
  - `goto`
  - `unknown`
- `confidence` 未放入 `effects`，继续归属于 `suspicious_points` 的语义范围。
- `description`、`condition`、`state_before`、`state_after`、`guard`、`risk` 的 schema 描述均要求中文语义输出。
- 保留 `error_paths` 为 optional 字段，本次不适配 `error_path` category。
- 同步更新主路径 `semantic_modeler/AGENT.md`：
  - 要求 memory/resource/concurrency/IO/global-state 等事实统一写入 `effects`。
  - 明确 `effects` required，无副作用时使用 `[]`。
  - 明确 enum 字段保持 schema 值，避免 `effects.action` 被翻译成中文。

### 测试

- 更新 `test_semantic_modeler_schema_replaces_legacy_effect_sections`，确认旧字段已删除、`effects` required、item required 字段完整、`category/action` enum 生效、`confidence` 不在 `effects` 中。
- `python -m pytest tests/test_json_output_agents.py -q` 通过：10 个测试。


### 已完成 semantic_modeler error_handling 字段落地

- 将主路径 schema 中旧的顶层 `error_paths` 替换为 `error_handling.error_paths`。
- `error_handling` 已改为 required；其内部 required 字段为 `error_paths`，无错误路径时输出空数组。
- 为 `error_handling` 添加 description，说明其记录函数错误路径摘要，无错误路径时使用空 `error_paths` 数组。
- `error_handling.error_paths` 单条 item 必填字段为：
  - `trigger`
  - `exit_line`
  - `exit_action`
  - `resource_states`
  - `risk`
- `return_value` 保留为 optional 字段，用于记录最终返回给调用者的值；无法判断或非直接 return 路径可省略。
- `resource_states` 单条 item 必填字段为：
  - `object`
  - `state`
  - `owner`
- 为 `resource_states` 添加 description，明确其记录错误路径退出时关键资源、内存对象、锁、引用或重要状态变量的最终状态。
- 按要求，`resource_states` 内不设置 `risk`；风险统一放在错误路径外层 `risk` 字段。
- 同步更新主路径 `semantic_modeler/AGENT.md`，要求错误路径写入 `error_handling.error_paths`。

### 测试

- 新增 `test_semantic_modeler_schema_uses_error_handling`，确认旧顶层 `error_paths` 删除、新 `error_handling` 为 required 且有说明、`error_handling.error_paths` 结构完整、`return_value` 为 optional、`resource_states` 有说明且不含 `risk`。
- `python -m pytest tests/test_json_output_agents.py -q` 通过：11 个测试。


### 已完成 lightweight callers 字段落地

- 在主路径 schema 顶层新增 required `callers` 字段。
- `callers` 为轻量级上游调用关系数组；无安全相关 caller 时输出空数组。
- `callers` 单条 item 仅包含并必填：
  - `caller_name`
  - `caller_file`
  - `callsite_lines`
  - `call_type`
- `call_type` 候选项为：
  - `direct`
  - `indirect`
  - `callback`
  - `macro`
  - `unknown`
- 同步更新主路径 `semantic_modeler/AGENT.md`，要求只记录轻量级安全相关 callers。

### 测试

- 新增 `test_semantic_modeler_schema_uses_lightweight_callers`，确认 `callers` required、字段集合仅包含指定四项、`callsite_lines` 为整数数组、`call_type` enum 生效。
- 同步 `test_semantic_modeler_schema_uses_parameters_and_return_values` 到当前 schema：`direction` 不再作为 `parameters` item required 字段。
- `python -m pytest tests/test_json_output_agents.py -q` 通过：12 个测试。


### 已完成 符号属性字段补充

- 在主路径 schema 顶层 required 中，于 `snapshot_kind` 后、`summary` 前新增：
  - `is_static`
  - `is_inline`
  - `is_macro`
- 三个字段均为 boolean。
- 普通 LLM-modeled 函数默认可输出 `false`；复杂 inline 函数或复杂宏进入 LLM 建模阶段时用于保留符号形态信息。
- 更新 semantic_modeler JSON 输出测试的 mock snapshot，补充 `is_static: false`、`is_inline: false` 和 `is_macro: false`。

### 测试

- 更新 `test_semantic_modeler_schema_aligns_llm_snapshots_with_static_snapshots`，确认 `is_static` / `is_inline` / `is_macro` 在 required 和 properties 中存在且为 boolean。


### 已完成 suspicious_points.category 枚举化

- 在主路径 schema 中新增 `SUSPICIOUS_POINT_CATEGORY_ENUM`。
- 将 `suspicious_points[].category` 从自由字符串收紧为 enum。
- enum 已收敛为审计大类；具体缺陷类型或项目特定现象放入 `description` 描述，不再作为 `category` 候选项：
  - `memory_safety`
  - `resource_lifecycle`
  - `bounds`
  - `integer`
  - `string_format`
  - `null_error`
  - `ownership`
  - `concurrency`
  - `state_protocol`
  - `type_confusion`
  - `input_validation`
  - `error_handling`
  - `global_state`
  - `callback`
  - `api_contract`
  - `unknown`
- 本次未修改任何 `fallback` 文件。

### 测试

- 新增并更新 `test_semantic_modeler_schema_uses_suspicious_point_category_enum`，确认 `suspicious_points[].category` 使用 enum，并确认 `invalid_free`、`fd_encoding_mismatch` 等具体缺陷不再作为大类候选项。


### 已完成 

- 删除`key_semantics`字段。

### 测试

- `python -m pytest tests/test_json_output_agents.py -q` 通过：13 个测试。


## 2026-07-13

### 已完成 Semantic Modeler Schema 注入修复

**问题确认：**

- `SemanticModeler.run()` 原先会将 schema 序列化为文本，并通过 `{schema}` substitution 尝试写入 prompt；当前 AGENT contract 不包含该占位符，因此首轮工具会话实际没有收到完整 schema。
- `JsonOutputSpec` 只在首轮输出解析失败后的 repair 调用中通过 final tool 或 `response_format` 传入 schema，导致合法的首轮自由文本 JSON 可以在模型未见 schema 的情况下被接受。
- `input_data["schema"]` 与 `JsonOutputSpec.schema` 使用不同数据源：前者只参与无效的 prompt substitution，后者固定使用默认 schema。
- 旧 repair 路径基于初始 messages 重建请求，没有保留探索阶段的完整工具调用和工具结果。

**实施内容：**

- 在 `JsonToolAgent._run_json_conversation()` 中新增 opt-in 参数 `require_structured_finalization`，默认关闭，避免改变其他 JSON agent 的现有行为。
- 启用后，普通检索工具循环只负责收集证据；循环结束后必须执行一次独立的 schema-aware finalization。
- finalization 使用完整 conversation：
  - 支持 structured output 的模型通过 `response_format.type=json_schema` 接收 schema。
  - 不支持 structured output 的模型只接收 `emit_function_snapshot` final tool，并通过具体 function `tool_choice` 强制调用。
- finalization 返回后继续使用 `is_valid_snapshot` 做本地语义校验；首次结构化结果不合法时才进入 schema-aware repair。
- repair 路径同步改为保留完整工具会话，并在 function-tool 路径中强制 final tool。
- `SemanticModeler` 现在使用唯一的 `effective_schema`：支持 dict 或 JSON object 字符串输入，未提供时使用 `DEFAULT_FUNCTION_SNAPSHOT_SCHEMA`；同一对象直接传入 `JsonOutputSpec`，删除 prompt schema 文本替换。
- `semantic_modeler/AGENT.md` 删除已由 schema/final tool 覆盖的“单一 payload、required section、空数组/对象”等结构性重复描述，只保留中文表达、unknown 处理和证据精度等 schema 无法表达的语义要求。
- 只有 `SemanticModeler` 启用了强制结构化 finalization；Validator、Vulnerability Analyzer、Deep Worker 等 agent 的默认流程未改变。

**测试：**

- `python -m py_compile zscope/agents/base.py zscope/agents/semantic_modeler/agent.py tests/test_json_output_agents.py` 通过。
- `git diff --check -- zscope/agents/base.py zscope/agents/semantic_modeler/agent.py tests/test_json_output_agents.py` 通过。
- 本次新增用例与底层 JSON loop 回归测试通过：`6 passed`。
  - 覆盖不支持 structured output 时强制 `emit_function_snapshot`。
  - 覆盖 finalization 保留探索阶段 conversation。
  - 覆盖自定义 effective schema 进入 final tool parameters。
  - 覆盖支持 structured output 时 schema 进入 `response_format`。
  
## 2026-07-17 Snapshot identity 重构

### 阶段 0：现状审计完成

- 以[历史快照重构方案](../../docs/archive/design-plans/snapshot_redesign.md)第十一节为实施基线。
- 确认当前工作树已有多项未提交改动；本轮在现有改动上增量实现，不回退或覆盖无关修改。
- 确认 Semantic Modeler 当前有四条 LLM 建模入口：global model、entry model、premodel 和按需 snapshot。
- 确认当前 `func_name` 来源不统一，`code` 主要来自 `CodeIndex.get_function_impl()`，`location` 由调用方拼接。
- 确认 `CodeIndex.find_function_infos()` 已提供普通函数的 identity、callees、referenced globals 和 referenced macros，但普通函数缺少显式 `is_macro=false`，宏 payload 仍缺少统一的 `is_static/callees/referenced_globals/referenced_macros`。
- 确认 SnapshotStore 当前使用 `(func_name, file_path)` 作为数据库主键、缓存键和锁键，并通过 `location` 提取 `file_path`；save/load/final report/fingerprint/refresh/delete 及多个调用方均需迁移到 `index_name`。
- 确认 deterministic trivial/lightweight snapshot 当前仍依赖 `location`，后续仅迁移 snapshot 身份和持久化用途，保留 suspicious point/evidence 的源码位置语义。

### 验证

- 完成 Semantic Modeler、CodeIndex、SnapshotStore、orchestration、tool、web 和测试调用面的静态检索。
- 本阶段只完成审计和记录，未运行行为测试。

### 阶段 1：Function info 与 Semantic Modeler 输入解析层完成

- 统一 `CodeIndex.find_function_infos()` 的 identity 输出：
  - 普通函数显式返回 `is_macro=false`。
  - 函数式宏显式返回 `is_static=false`、`is_macro=true`。
- 函数式宏的 function info 现在同时返回：
  - `callees`
  - `referenced_globals`
  - `referenced_macros`
- 宏 callee 记录包含 canonical `callee_index_name`、callsite lines 和 direct call type；regex fallback 下会识别宏体引用的全局变量和其他宏。
- 新增 `zscope/snapshots/modeling_input.py`：
  - 使用 `find_function_infos()` 获取唯一函数身份。
  - 支持按 `index_name`、`file_path` 和 `start_line` 消歧。
  - 使用唯一结果的 `index_name` 调用 `get_function_impl()` 获取对应代码。
  - 输出不含 `location` 的统一 Semantic Modeler 输入。
  - 透传 `callees`、`referenced_globals`、`referenced_macros` 及 truncation 元数据。
  - 校验 function info 与实现的 `index_name/file_path/start_line` 一致性。
- 新增稳定的预 LLM 失败 reason 和日志：
  - `function_info_not_found`
  - `function_info_ambiguous`
  - `function_info_incomplete`
  - `function_impl_not_found`
  - `function_info_impl_mismatch`
- 所有解析失败日志均包含 `llm_called=false`。

### 阶段 1 测试

- 新增 `tests/test_semantic_model_input.py`，覆盖唯一解析、truncation 透传、无匹配、多匹配和元数据/实现不一致。
- 更新 function-info 宏测试到新统一契约。
- `python -m pytest -q tests/test_semantic_model_input.py tests/test_function_info_tool.py tests/test_code_index_cache.py` 通过：42 个测试。

### 阶段 2：Semantic Modeler prompt、schema 与输出拼接完成

- 在 `semantic_modeler/schema.py` 中新增 `PROGRAM_GENERATED_SNAPSHOT_FIELDS`，集中定义九个程序生成字段。
- 新增 `llm_function_snapshot_schema()`：
  - 保留完整 snapshot schema 作为最终结构。
  - 从 LLM schema 的 `required` 和 `properties` 中删除九个程序字段。
  - 自定义 schema 同样执行深拷贝转换，不修改调用方原对象。
- `SemanticModeler.run()` 输入不再读取 `location`。
- user prompt 现在直接包含：
  - 目标函数 metadata JSON；
  - 编号源码；
  - 可选 user project context。
- metadata JSON 包含 identity、callees、referenced globals/macros 及对应 truncation 元数据。
- LLM 输出完成后，程序从 `input_data` 选取九个字段并最后覆盖合并；模型返回的同名错误字段不会进入最终 snapshot。
- 输入缺少程序字段时直接返回：
  - `reason=semantic_model_input_invalid`
  - `llm_called=false`
- 更新 `semantic_modeler/AGENT.md`：
  - 删除模型输出 identity 的要求。
  - 禁止对目标函数调用 `get_function_info`。
  - 要求复用预加载 callee index/callsite/call type，并补充 `callee_behavior`。

### 阶段 2 测试

- 更新 JSON final tool 和 structured-output 测试，确认实际暴露的是 semantic-only LLM schema。
- 新增模型错误 identity 被程序覆盖的测试。
- 新增不完整输入不调用 LLM 的测试。
- 验证 prompt 含目标 metadata 和 referenced globals，且不再包含 `Location:`。
- `python -m pytest -q tests/test_json_output_agents.py tests/test_semantic_model_input.py tests/test_function_info_tool.py` 通过：44 个测试。

### 阶段 3：四条 LLM 建模路径接入统一输入完成

- entry workflow 初始化时先调用统一解析器：
  - 先解析唯一 function info；
  - 再使用 canonical `index_name` 获取实现；
  - 在 state 中保存 `entry_index_name` 和独立 `semantic_model_input`。
- entry Semantic Modeler 不再复用含 `location` 的共享 `agent_context`，改为传入独立的 canonical semantic context。
- global model 在进入 LLM 前按 `index_name/file_path/start_line` 构造统一输入。
- premodel 在进入 LLM 前重新解析 function info，并用 canonical index 获取带上下文的代码。
- 按需 snapshot 在进入 LLM 前执行同样的唯一解析和输入构造。
- 四条路径的建模日志开始使用 `index_name` 表示具体函数定义。
- 未给测试替身增加生产兼容回退；相关 fake code index 已更新为实现 `find_function_infos()`，防止测试掩盖新契约缺失。

### 阶段 3 测试

- 更新 global model 和按需 snapshot 测试替身，使其提供 canonical identity 和完整 Semantic Modeler 输入。
- 验证同名不同文件函数分别生成不同 `index_name` 上下文。
- `python -m pytest -q tests/test_global_modeler.py tests/test_analyzer_semantics.py tests/test_json_output_agents.py tests/test_semantic_model_input.py tests/test_function_info_tool.py` 通过：84 个测试。

### 阶段 4：SnapshotStore 与调用方迁移到 `index_name` 完成

- SnapshotStore API 全部改为 canonical `index_name`：
  - `save_snapshot(index_name, snapshot, code)`
  - `load_snapshot(index_name)`
  - `save_final_report(index_name, report)`
  - `load_final_report(index_name)`
  - `get_fingerprints(index_name)`
  - `needs_refresh(index_name, code)`
  - `delete_snapshot(index_name)`
- SnapshotLockManager 改为只使用 `index_name`，删除 `func_name + file_path` lock key。
- snapshot/final report cache 改为单一 `index_name` key。
- snapshot 与 final report 文件名由 `index_name` 的可读前缀和稳定 SHA-256 短 hash 唯一派生，控制长度并避免清洗碰撞。
- SQLite snapshots 表改为：
  - `index_name TEXT PRIMARY KEY`
  - 保留 `func_name/file_path/start_line/end_line` 作为展示和诊断列。
  - 删除 `location` 列。
- `save_snapshot()` 强制校验参数与 payload 中的 `index_name` 一致，并校验完整 identity。
- 删除 SnapshotStore 中 `_file_path_from_location()`、路径偏好选择和按函数名猜测 snapshot 的逻辑。
- 新增旧数据库迁移：
  - 从旧 snapshot JSON 读取或构造 canonical `index_name`。
  - 创建 index-name 文件副本和新表。
  - 成功后事务切换表名并保留 legacy 表。
  - identity 缺失、文件缺失或 key collision 时回滚，保留旧表和旧 JSON。
- deterministic trivial/lightweight snapshot：
  - 删除顶层 `location` identity。
  - 补齐 `index_name/is_static/is_macro`。
  - suspicious point 中的源码证据 `location` 保持不变。
- 完成以下生产调用方迁移：
  - global model、entry model、premodel、按需 snapshot；
  - history reconciler、report assembler、scan resume/merge；
  - snapshot tool、validation evidence、smart refresh 和 LLM snapshot save helper。
- `get_function_snapshot` 在无 on-demand resolver 时通过 `find_function_infos()` 解析唯一 `index_name`，不再直接按函数名访问存储层。

### 阶段 4 日志

- 新增/统一日志前缀：
  - `[snapshot-resolve]`
  - `[snapshot-lock]`
  - `[snapshot-store]`
  - `[snapshot-migration]`
- 解析失败记录稳定 reason 和 `llm_called=false`。
- store 保存、读取、identity mismatch、文件缺失和 final report 缺失均记录 `index_name`。
- migration 输出 total/migrated/failed/collisions，并在失败时记录异常且回滚。

### 阶段 4 测试

- 重写 `tests/test_snapshot_store.py`，覆盖：
  - index-name lock；
  - cache 独立副本；
  - fingerprint/refresh；
  - 同名不同文件 snapshot 独立读写；
  - final report；
  - 文件名与 SQLite 主键；
  - argument/payload mismatch；
  - migration 成功和失败保留旧数据。
- 更新 global model、analyzer semantics、report assembler、scan resume 和 validation 测试到新 API。
- `python -m pytest -q tests/test_snapshot_store.py tests/test_global_modeler.py tests/test_analyzer_semantics.py tests/test_report_assembler.py tests/test_scan_session_resume_svf.py tests/test_validation_runner.py tests/test_tool_registry.py` 通过：84 个测试。

### 阶段 5：日志补齐与最终验收完成

- 新增统一的 `[snapshot-llm]` 建模完成日志，覆盖：
  - global model；
  - entry model；
  - premodel；
  - 按需 snapshot。
- LLM 建模日志统一包含 `context`、`index_name`、`success` 和 `context_tokens`；失败时额外包含稳定 `reason` 和错误摘要。
- global model 补齐 `[snapshot-lock]` waiting/outcome 日志，锁标识只使用 canonical `index_name`。
- SnapshotStore 与 migration 的异常日志补充稳定 reason，包括：
  - `snapshot_index_mismatch`
  - `snapshot_file_missing`
  - `persisted_snapshot_index_mismatch`
  - `final_report_snapshot_missing`
  - `final_report_file_missing`
  - `migration_snapshot_file_missing`
  - `migration_snapshot_unreadable`
  - `migration_identity_incomplete`
  - `migration_index_collision`
  - `migration_final_report_file_missing`
  - `snapshot_migration_failed`
- 最终静态审计确认：
  - SnapshotStore schema、查询、文件名、cache、lock 和公开 API 均不再消费 `location`。
  - 剩余 `location` 均属于 suspicious point、issue、candidate 或 validation evidence 的源码证据位置。
  - Semantic Modeler 输入与 prompt 不包含 `location` 或 `Location:`。
  - LLM schema 已删除全部九个程序生成字段，完整 snapshot schema 仍保留这些字段。
  - SnapshotStore 的生产调用方均传入 canonical `index_name`。

### 阶段 5 测试

- `python -m compileall -q zscope/orchestration/global_modeler.py zscope/core/analysis/analyzer.py zscope/snapshots/store.py` 通过。
- 聚焦回归测试通过：`74 passed`。
- 完整测试结果：`709 passed, 2 failed`。
- 两个失败均位于 `tests/test_user_config_workbook.py`，缺失 `ZIP_ALLOC` 和 `ANYXML_MALLOC` 宏资源推断；与 snapshot identity、Semantic Modeler 输入和 SnapshotStore 重构无关，且与本轮实施前的完整测试失败一致。
- `git diff --check` 仅报告 `new_docs/architecture_optimation.md` 末尾空行；该文件是已有无关用户改动，本轮未修改。

### 计划偏差

- 数据库迁移没有重命名或删除旧 snapshot 文件，而是生成新的 index-name 文件副本，并保留 legacy 表和旧 JSON。这样可在迁移失败或需要人工回查时保留原始数据，语义上比计划中的“重命名或重写”更保守。
- migration 对 identity 缺失或 collision 采用整批回滚，不提交部分成功记录；结束日志中的 `skipped` 固定为 0。该行为与计划的失败不覆盖、失败不破坏旧数据要求一致，但比逐条跳过更严格。
- 除 AGENT.md 中禁止目标函数重复调用 `get_function_info` 外，运行时增加了 `target_function_info_preloaded` 拦截，防止模型忽略提示后产生冗余工具调用。
- index-name 文件名采用可读前缀加 SHA-256 短后缀，而不是完整可逆编码。文件身份仍由完整 `index_name` 唯一决定，SQLite 和 payload 保存完整值。

### 已知问题

- `SnapshotStore.save_snapshot()` 和 `save_final_report()` 先原子替换 JSON 文件，再提交 SQLite。数据库提交失败时可能留下孤立新文件；更新已有记录时还可能出现文件内容已更新但数据库 fingerprint 未更新。后续可通过临时文件、数据库事务和提交后 rename 的补偿流程增强跨文件/数据库一致性。
- backend-backed macro function info 的 `referenced_globals` 和 `referenced_macros` 当前依赖后端已建立符号上下文；后端没有数据时默认空数组。regex fallback 路径已能从宏体补齐引用，但两种 backend 模式的降级行为尚未完全统一。
- 用户配置工作簿的宏资源推断仍有两个既有失败：`ZIP_ALLOC` 和 `ANYXML_MALLOC` 未进入 resource rows。该问题不影响本轮 snapshot redesign 目标。

## 2026-07-20 Snapshot symbol context 透传

### 阶段 1：持久化契约与程序拼接完成

- 完整 function snapshot schema 新增两个必需字段：
  - `referenced_globals`
  - `referenced_macros`
- 完整 schema 同时新增两个可选 truncation 字段：
  - `referenced_globals_truncation`
  - `referenced_macros_truncation`
- `referenced_globals` item 保留程序提取的名称、类型、声明位置、storage class、initializer、读写类型和引用行。
- `referenced_macros` item 保留宏名称、定义位置、宏定义、是否为函数式宏和引用行。
- 新增 program passthrough 字段集合。LLM final tool schema 和 structured-output schema 会删除上述四个字段，模型不负责生成或修改它们。
- Semantic Modeler 最终拼接前先删除 LLM payload 中全部 program-generated/passthrough 字段，再加入输入中的程序值，防止模型注入输入中不存在的 truncation 元数据。
- trivial 和 lightweight deterministic snapshot 同样透传 symbol context，保持三类 snapshot 的持久化契约一致。
- `semantic_modeler/AGENT.md` 明确禁止模型输出 referenced globals/macros 及 truncation 元数据。

### 阶段 2：Symbol context 指纹与数据库迁移完成

- 新增 `compute_symbol_context_hash()`，哈希内容包括：
  - canonicalized `referenced_globals`
  - canonicalized `referenced_macros`
  - 实际存在的 truncation 元数据
- 顶层 symbol 数组按稳定 JSON 表示排序后计算 SHA-256，避免仅因返回顺序变化触发 refresh。
- SQLite snapshots 表新增 `symbol_context_hash TEXT NOT NULL`。
- 新建数据库直接使用新 schema。
- 已使用 `index_name` 主键但缺少该列的数据库执行增量迁移：
  - 添加 `symbol_context_hash` 列；
  - 从 snapshot JSON 回填缺失的空数组；
  - 计算并回填 hash；
  - 输出 `[snapshot-migration]` 总数、成功数和失败数日志。
- 旧复合主键数据库迁移同步补齐 referenced arrays，并在新表记录 symbol context hash。
- `SnapshotStore.save_snapshot()` 强制要求两个 referenced 数组存在，防止新 snapshot 静默退回旧契约。
- `get_fingerprints()` 现在同时返回 code、semantic 和 symbol-context 三种 hash。
- `needs_refresh()` 新增必需的当前 symbol context 参数；hash 不一致时返回：
  - `symbol_context_changed`

### 阶段 3：Snapshot 复用路径迁移完成

- 以下路径在复用 snapshot/final report 前同时比较代码和 symbol context：
  - global model cache hit；
  - entry global-snapshot reuse；
  - history reconciliation；
  - on-demand snapshot；
  - premodel；
  - smart `get_function_impl` refresh；
  - scan resume 和 skipped report merge；
  - 无 on-demand resolver 的 `get_function_snapshot` tool。
- global 和 premodel 检测到 stale snapshot 后会 invalidate 对应 `index_name` lock，避免 lock manager 的旧 `done` 状态阻止重建。
- smart refresh 无法唯一解析当前 function info 时不再返回旧 snapshot，直接保留真实实现结果。
- scan resume 在宏定义或全局符号上下文变化时不会跳过 entry，也不会合并旧 final report。
- snapshot tool 检测到 stale symbol context 时返回 `data=null` 和稳定 reason，不向 agent 暴露旧证据。
- `_save_snapshot_from_llm()` 保存前重新构造 canonical semantic input，并覆盖 symbol context，避免其他 LLM 路径直接写入自报引用字段。
- Semantic Modeler 在调用 LLM 前校验两个 referenced 字段必须为数组、truncation 字段必须为对象；无效输入以 `semantic_model_input_invalid` 终止且 `llm_called=false`。
- entry snapshot refresh 检查异常时强制进入重建流程，不再把异常解释为 snapshot 可复用。
- 删除 snapshot 或发现记录缺失时同步 invalidate 对应 build lock，避免旧 `done` 状态阻止重建。

### 测试

- 新增或扩展测试覆盖：
  - referenced globals/macros 由程序透传并覆盖 LLM 伪造值；
  - 输入不存在的 truncation 字段不会从 LLM payload 泄漏到 snapshot；
  - LLM schema 删除四个 program passthrough 字段；
  - 函数代码不变、宏定义变化时返回 `symbol_context_changed`；
  - deterministic snapshot 包含 referenced arrays；
  - 已有 index-name SQLite schema 增量增加并回填 `symbol_context_hash`；
  - snapshot tool 不返回 symbol context 已过期的 snapshot；
  - scan resume 不复用 symbol context 已变化的 final report。
- 无效 symbol context 输入不会调用 LLM；删除 snapshot 后 completed lock 可重新获取。
- 聚焦测试：`101 passed`。
- 完整测试：`716 passed, 2 failed`。
- 两个失败仍为既有的用户配置宏资源推断问题：`ZIP_ALLOC` 和 `ANYXML_MALLOC` 未进入 resource rows，与本轮 symbol context 透传无关。

### 已知问题

- symbol context 的完整性仍取决于 CodeIndex backend。backend 未返回宏或全局引用时，hash 只能反映空结果；该限制与前一阶段记录的 backend/regex fallback 行为差异相同。
- `symbol_context_hash` 能检测引用记录、宏定义和全局 initializer/type 的变化，但不会追踪 referenced global 所指向对象的深层间接依赖。

### 已完成：Global storage class 与 qualifiers 枚举化

- `referenced_globals[].storage_class` 从自由字符串收紧为 enum：
  - `static`
  - `extern`
  - `thread_local`
  - `global`
  - `unknown`
- `referenced_globals[].qualifiers` 从逗号分隔字符串改为可多选 enum 数组：
  - `const`
  - `volatile`
  - `atomic`
- qualifiers 数组允许为空并要求 `uniqueItems=true`。
- CodeIndex 对 backend 和 regex 结果统一规范化：
  - 字符串和数组输入均可接受；
  - 输出固定为 `const`、`volatile`、`atomic` 顺序；
  - 未知 qualifier 被丢弃；
  - 未知 storage class 归一化为 `unknown`。
- KnowledgeDB 内部继续使用 TEXT 保存 qualifiers，不进行数据库迁移；对外 function-info 和 snapshot 契约统一为数组。
- 旧 snapshot 加载或 symbol-context 回填时，会把 `"volatile,const"` 转换为 `["const", "volatile"]`，并重新计算 `symbol_context_hash`。
- `initializer` 继续保存原始初始化表达式字符串，不做 enum 化。

### 测试

- schema 测试确认 storage class enum 和 qualifiers 多选 enum 数组结构。
- function-info 测试确认 backend 字符串 qualifiers 被规范化为稳定数组。
- snapshot migration 测试确认旧逗号字符串被转换并参与新 hash。
- 聚焦测试：`92 passed`。
- 完整测试：`716 passed, 2 failed`；两个失败仍为既有的用户配置宏资源推断问题。

### 已完成：Referenced globals 对外字段收敛

- 按简化后的实施范围，仅修改 `CodeIndex._normalize_function_info_global()`。
- 对外 `referenced_globals[]` 固定返回九个字段：
  - `name`
  - `type`
  - `file_path`
  - `line`
  - `storage_class`
  - `qualifiers`
  - `initializer`
  - `access`
  - `reference_lines`
- 删除 CodeIndex 对外结果中的 `is_extern` 和 `definition_kind`。
- Clang extractor 和 KnowledgeDB 继续保留这两个内部索引字段，不修改内部数据库结构。
- `get_function_info`、Semantic Modeler 输入与透传、静态 snapshot 继续沿用原有直接消费 CodeIndex 结果的实现，不增加额外投影或校验层。
- 未修改[历史工具优化计划](../../docs/archive/design-plans/tools_optimation_plan.md)、fallback、Semantic Modeler、静态 snapshot 或 SnapshotStore 生产代码。

### 测试

- function-info 测试新增精确 key 集合断言，覆盖 backend 和 regex 两条 CodeIndex 路径。
- 为适配当前 schema 的内联 enum 写法，测试改为直接校验枚举值，不重新引入 schema 常量。
- 聚焦测试：`66 passed`。
- 完整测试：`716 passed, 2 failed`；两个失败仍为既有的用户配置宏资源推断问题。

## 2026-07-20 Deterministic snapshot 输出结构统一

### 阶段 0：现状审计完成

- 以[历史快照重构方案](../../docs/archive/design-plans/snapshot_redesign.md)第十二节为实施基线。
- 确认 `build_semantic_model_input()` 已向四条建模路径提供：
  - `callees`
  - `referenced_globals`
  - `referenced_macros`
  - 三类可选 truncation 元数据。
- 确认 `policy.py::_program_symbol_context()` 已把 referenced arrays 和两个 symbol truncation 字段写入 trivial/lightweight snapshot，但尚未透传 `callees_truncation`。
- 确认 deterministic snapshot 仍输出旧字段：
  - `type`
  - `is_trivial`
  - `inputs`
  - `outputs`
  - `resources`
  - `concurrency`
  - `key_semantics`
- 确认主要旧字段消费点为：
  - `core/validation/evidence.py::compact_snapshot()`
  - `semantics/inference.py::snapshot_contract_text()`
  - `common/utils.py::is_valid_snapshot()`
- 确认 SnapshotStore 已有 `symbol_context_hash` 和 `symbol_context_changed` refresh 语义；本轮 shape refresh 必须叠加在该实现上，不能覆盖现有 symbol-context 检测。
- 确认当前工作树包含用户和前序阶段的未提交改动；本轮只增量修改相关文件，不回退其他内容，不修改 fallback。

### 阶段 0 验证

- 完成 deterministic builder、四条调用路径、SnapshotStore refresh、validation evidence、semantic inference 和相关测试的静态审计。
- 本阶段未修改运行时代码，未运行行为测试。

### 阶段 1：Deterministic builder 统一完成

- 在 `zscope/snapshots/policy.py` 中新增：
  - `DETERMINISTIC_SNAPSHOT_REQUIRED_FIELDS`
  - `DETERMINISTIC_SNAPSHOT_OPTIONAL_FIELDS`
  - `DETERMINISTIC_SNAPSHOT_KINDS`
  - canonical shape 检查和统一基础构造 helper。
- trivial/lightweight snapshot 现在固定输出十九个必需字段，并仅在输入存在时输出：
  - `referenced_globals_truncation`
  - `referenced_macros_truncation`
  - `callees_truncation`
- 三类 truncation 字段按计划放在对应数组之后，`code` 始终为最后一个字段。
- 删除两类 builder 的旧顶层字段：
  - `type`
  - `is_trivial`
  - `inputs`
  - `outputs`
  - `resources`
  - `concurrency`
  - `key_semantics`
- 新增 deterministic 子结构生成：
  - conservative `return_values`
  - schema-compatible `effects`
  - `error_handling.error_paths`
  - structured callees
  - suspicious point category/lines normalization。
- lightweight 静态语义映射：
  - logging -> IO effect；
  - lock/unlock -> lock effect；
  - return/goto guard -> error path；
  - checked allocator -> pointer return contract、memory/ownership effects 和 NULL failure path；
  - pure expression -> empty effects。
- referenced arrays、三个 truncation object 和语义结构均执行可变对象隔离复制。
- mixed direct/indirect callee 无法无损转换为 scalar schema 时省略可选 `call_type`，不猜测单一类型。

### 阶段 1 测试

- 更新 trivial suspicious point、facade callee 和 checked allocator 测试到新结构。
- 新增 referenced context、三类 truncation、字段顺序、允许字段集合、深拷贝和 mixed call type 测试。
- `python -m compileall -q zscope/snapshots/policy.py` 通过。
- `python -m pytest -q tests/test_analyzer_semantics.py tests/test_global_modeler.py` 通过：`41 passed`。

### 阶段 2：下游消费与历史 shape refresh 完成

- `SnapshotStore.needs_refresh()` 在现有 fingerprint 和 symbol-context hash 检查前增加 deterministic shape 校验：
  - `syntactic/lightweight` snapshot 缺少必需字段；
  - 包含旧顶层字段；
  - 包含未允许的额外字段；
  - 字段顺序不符合 canonical shape；
  均返回 `needs_refresh=true`、`reason=snapshot_shape_changed`。
- shape 检查只作用于 deterministic snapshot，不改变 LLM-modeled snapshot 的兼容行为。
- `compact_snapshot()` 改为传递：
  - `parameters`
  - `return_values`
  - `effects`
  - `error_handling`
  - `callees`
  - referenced arrays
  - 三类可选 truncation
  - `suspicious_points`
- `snapshot_contract_text()` 改为优先消费 `return_values/effects/error_handling`；历史 snapshot 缺少新字段时继续读取 `outputs/resources/concurrency/key_semantics`，避免迁移期语义丢失。
- `is_valid_snapshot()` 不再依赖 deterministic 旧字段，改用完整 semantic field set；仍保留 `type=function_snapshot` 的历史兼容入口。
- 审计确认 global model、entry reuse、premodel、按需 snapshot、history reconciliation、scan resume、smart refresh 和 snapshot tool 均通过统一 `needs_refresh()` 获取 `snapshot_shape_changed`，无需新增分叉判断。

### 阶段 2 测试

- 新增旧 deterministic shape 触发 refresh、重建后恢复 current 状态的 SnapshotStore 测试。
- 更新 validation evidence fixture 到新 effects 结构。
- 新增 semantic inference 对新字段优先和旧字段 fallback 的测试。
- 聚焦回归：`python -m pytest -q tests/test_snapshot_store.py tests/test_analyzer_semantics.py tests/test_global_modeler.py tests/test_json_output_agents.py tests/test_validation_runner.py tests/test_snapshot_tool.py tests/test_scan_session_resume_svf.py` 通过：`100 passed`。

### 阶段 3：测试矩阵与文档同步完成

- 补齐 lightweight deterministic 分支测试：
  - logging；
  - lock；
  - unlock；
  - pure expression；
  - return guard；
  - goto guard；
  - checked allocator。
- structured callee 测试同时覆盖：
  - 单一 direct call type 转换为 scalar；
  - direct/indirect mixed 类型无法无损转换时省略可选字段。
- 更新 `new_docs/tools_introduction.md`：
  - 删除旧 deterministic snapshot 字段描述；
  - 记录十九个必需字段、三个可选 truncation、structured callees 和 shape refresh。
- 按用户追加要求更新 `new_docs/agent_introduction.md`：
  - 增加 `policy.py` 实现入口；
  - 说明 global/premodel/on-demand 的 deterministic LLM bypass；
  - 增加 deterministic 字段所有权和静态语义映射；
  - 增加 `snapshot_shape_changed` 持久化刷新语义；
  - 更新 `is_valid_snapshot()` 当前边界。
- 本阶段未修改 Semantic Modeler fallback 文件。

### 阶段 3 测试

- 修改文件 `compileall` 通过。
- `git diff --check` 对本轮代码、测试和文档文件通过。
- 扩展聚焦回归通过：`132 passed`。

### 阶段 4：最终验收完成

- 运行时字段审计确认：
  - 无 truncation 时，trivial snapshot 顶层字段严格等于十九个 required fields；
  - 三类 truncation 同时存在时，referenced truncation 位于 symbol arrays 后，callee truncation 位于 `callees` 后，`code` 仍为最后字段；
  - deterministic builder 不再输出旧顶层字段。
- 生产旧字段消费审计确认：
  - validation evidence 已完全切换到新字段；
  - 旧 `outputs/resources/concurrency/key_semantics` 只剩 semantic inference 的显式历史兼容 fallback。
- SnapshotStore 验证：
  - 旧 deterministic shape 返回 `snapshot_shape_changed`；
  - current shape 在 code/symbol context 未变化时可复用；
  - snapshot tool 不向 agent 返回旧 shape；
  - 重建 snapshot 沿用当前 store 行为，清除旧 final report 引用，已增加测试锁定。
- fallback/skills 静态 diff 为空，本轮未修改 fallback 或 skill 文件。
- 第十二节计划标记为已实施。

### 阶段 4 测试

- 最终聚焦测试：`61 passed`。
- 最终完整测试：`721 passed, 2 failed`。
- 两个失败仍为既有用户配置宏资源推断问题：
  - `ZIP_ALLOC` 未进入 resource rows；
  - `ANYXML_MALLOC` 未进入 resource rows。
- 本轮文件 `git diff --check` 通过。
- 全工作树 `git diff --check` 仍报告两个无关既有问题，本轮未修改：
  - `new_docs/architecture_optimation.md` 末尾空行；
  - `zscope/agents/semantic_modeler/schema.py` 行尾空格。

### 计划偏差

- 计划要求通用下游在迁移期保留旧字段 fallback。实际只在 `snapshot_contract_text()` 保留旧语义字段 fallback；validation evidence 直接切换到新字段，因为所有生产 validation 路径在使用 deterministic snapshot 前已经经过统一 refresh/build 流程。
- `is_valid_snapshot()` 没有改成 identity-only 严格校验。为兼容 Semantic Modeler 的 semantic-only LLM payload，改为要求完整 semantic field set，同时保留 `type=function_snapshot` 历史入口；deterministic 顶层严格性由独立 shape checker 保证。
- deterministic suspicious point 保留了 `type/reason/location/line/confidence/source` 等内部证据元数据。统一要求只限制 snapshot 顶层字段，这些嵌套证据不会破坏 canonical top-level shape。

### 已知问题

- SnapshotStore 的 `symbol_context_hash` 当前只覆盖 referenced globals/macros 及其 truncation，不覆盖 `callees` 或 `callees_truncation`。如果源码不变但 backend 的 callee identity、call type 或 truncation 结果发生变化，现有 snapshot 不会仅因 callee context 变化自动 refresh。该问题不阻塞本轮输出结构统一，后续可设计独立 dependency-context hash 或扩展现有 fingerprint。
- backend-backed macro symbol context 缺少 regex 降级的问题仍存在，详见 `new_docs/known_issues.md` 的 `KI-002`。
- 用户配置工作簿的两个既有宏资源推断失败仍未处理，与本轮 deterministic snapshot 重构无关。

## 2026-07-20 删除 deterministic suspicious point confidence

### 实施完成

- trivial/deterministic suspicious point 不再生成 `confidence` 字段。
- deterministic suspicious point normalization 会删除输入中已有的 `confidence`，避免历史或未来调用路径将其重新带入 snapshot。
- 该变化只作用于 deterministic snapshot 的 `suspicious_points`，不改变其他分析证据中的 confidence 字段。
- 新增测试断言普通 trivial contract 和 facade forwarding contract 均不包含 `confidence`。
- 本阶段覆盖上文“deterministic suspicious point 保留 confidence”的旧决策；历史记录保留用于说明实施演进。

### 验证

- 聚焦回归通过：`61 passed`。
- `policy.py` 编译检查通过。

## 2026-07-20 Callee dependency context 纳入 snapshot refresh

### 实施完成

- `compute_symbol_context_hash()` 扩展为覆盖 backend 提取的 callees、referenced globals/macros 及各自 truncation。
- callee hash 只投影程序拥有的 `callee_index_name`、`callsite_lines` 和 `call_type`；忽略 LLM 生成的 `callee_behavior` 和其他额外字段。
- callee 记录按 canonical identity 聚合，调用行去重排序，调用类型按 direct/indirect 规范化，输入顺序和重复边不影响 hash。
- `save_snapshot()` 增加可选 `dependency_context`。global、entry、on-demand、premodel 和历史 LLM snapshot 保存路径均使用建模前的 backend context 计算 fingerprint，避免依赖 LLM 是否完整复述 callee 元数据。
- deterministic snapshot 继续使用自身保存内容计算 fingerprint；其 callee 元数据直接来自同一 backend context，且 hash 投影会忽略 deterministic `callee_behavior`。
- 源码不变但 backend callee identity、callsite lines、call type 或 `callees_truncation` 变化时，`needs_refresh()` 现在返回 `symbol_context_changed`。
- 旧 SQLite 行中的 fingerprint 由不含 callee 的旧算法生成；升级后首次 refresh check 会将其视为 `symbol_context_changed` 并一次性重建，以建立新的 backend dependency fingerprint。
- 本阶段解决上文“symbol_context_hash 不覆盖 callees/callees_truncation”的已知问题；历史记录保留用于说明实施演进。

### 测试

- 新增 canonical callee hash 测试，确认 behavior、输入顺序和重复聚合方式不影响 fingerprint。
- 新增 backend callee refresh 测试，确认 LLM-only callee 不污染 fingerprint，call type 和 truncation 变化会触发刷新。
- 聚焦回归通过：`74 passed`。

## 2026-07-20 修复临时目录中的宏扫描

### 实施完成

- `_scan_function_like_macros()` 的目录过滤改为检查扫描根目录下的相对路径，不再检查完整绝对路径。
- 项目本身位于 `/tmp` 时不再被误判为应跳过的 `tmp` 子目录。
- 项目内部的 `.git`、`.venv`、`build`、`tmp` 等目录仍保持跳过行为。
- 现有两个用户配置宏推断测试直接覆盖该问题，无需新增重复测试。

### 验证

- 原两个失败用例通过：`2 passed`。
- 用户配置工作簿测试通过：`20 passed`。
- 完整回归通过：`726 passed`。
- 修改文件编译检查和 `git diff --check` 通过。
- 修复前全量回归：`724 passed, 2 failed`；失败为 `ZIP_ALLOC` 和 `ANYXML_MALLOC` 未进入宏资源推断结果。

## 2026-07-21 Snapshot callee 分流：阶段 1（CodeIndex 与 Function Info）

### 实施完成

- `find_function_infos()` 的 callee 上下文改为 `project_callees` 与 `external_callees`：项目函数和 function-like macro 进入 project 侧，其他未解析目标保留在 external 侧。
- project/external 两侧先独立聚合调用行与 direct/indirect 类型，再分别施加 30 / 20 的上限和 truncation metadata。
- project callee 现在携带程序生成的 `is_static`、`is_macro`；external callee 不推断这两个属性。
- `get_function_info` 的外部函数 payload、描述和测试已迁移至双数组契约。
- 未修改任何 fallback 文件，也未变更 snapshot runtime allowlist。

### 验证

- `python -m py_compile zscope/retrieval/code_index.py` 通过。
- Function Info 聚焦回归：`23 passed`；本阶段已修复已发现的 backend macro-fact 回归。

## 2026-07-21 Snapshot callee 分流：阶段 2（Semantic Modeler）

### 实施完成

- 统一建模输入改为透传 `project_callees`、`external_callees` 及各自 truncation metadata。
- Semantic Modeler prompt 只投影 project 侧；external 侧不进入 LLM metadata，最终 snapshot 由程序 passthrough。
- LLM 返回的 project callee 仅用于读取 `callee_behavior`；程序写回 canonical identity、调用边、`is_static` 与 `is_macro`，缺失 behavior 记为 `unknown`。
- 未增加 callee item 内容 validation；迁移仅维持 required 顶层字段存在性契约。未修改 snapshot runtime allowlist。
- 更新 Semantic Modeler agent policy、agent/tool introduction 文档；未修改 fallback 文件。

### 验证

- `py_compile` 通过：建模输入、schema、agent 与 snapshot validator。
- 聚焦 Semantic Modeler 回归：`7 passed`（覆盖 structured finalizer、program passthrough、prompt schema 和 target-query guard）。

## 2026-07-21 Snapshot callee 分流：阶段 3（Deterministic snapshot 与 refresh，已完成）

### 已完成部分

- deterministic snapshot 顶层 `callees` 已替换为 `project_callees`、`external_callees`，并使用独立 truncation 字段；project 侧保留 `is_static`、`is_macro` 与 deterministic behavior。
- SnapshotStore dependency hash 已分别投影 project/external 调用边；project linkage/macro 标记、任一数组或 truncation 变化均会影响 refresh。
- 历史 snapshot 若仍含旧 `callees` / `callees_truncation`，统一返回 `snapshot_shape_changed`，没有加入旧字段 fallback。
- snapshot tool fallback 与 validation evidence compact payload 已迁移为双数组。

### 当前验证

- SnapshotStore 聚焦回归：`16 passed`。
- Snapshot Tool 聚焦回归：`5 passed`。
- Function Info、建模输入、SnapshotStore、Snapshot Tool 与 analyzer deterministic 聚焦集合：`84 passed`（一次 facade fixture 迁移后已修复）。
- 完整 `pytest` 目前在 collection 时报两个既有环境错误：`scripts` 包不存在，影响 `test_benchmark_protocol.py` 与 `test_range_benchmark_regression.py`；未修改该范围外问题。

### 阶段完成与最终验证

- 已完成 global model、entry reuse 与四条 snapshot 保存路径的兼容性测试迁移；global-model 聚焦回归：`7 passed`。
- 增加 regex CodeIndex 直接测试，覆盖 static 项目函数与 function-like macro 的 project 分类、canonical identity、`is_static`、`is_macro`。
- 最终核心聚焦回归：`56 passed`。
- 全部可收集测试（排除两个缺失 `scripts` 模块的 benchmark 测试）结果：`706 passed, 2 failed`。两个失败是本轮开始前已存在的 `test_json_output_agents.py` schema 断言与当前 schema 字段定义不一致（`constraints`、`exit_states`），本轮未回退用户的 schema 修改。
- 修改模块 `compileall` 和工作树 `git diff --check` 均通过。
- 第十三节计划状态更新为“已实施”。

### 计划偏差

- 按用户后续决定，本期未实施 `get_function_snapshot` runtime allowlist 或 `callee_snapshot_not_allowed`；外部函数的查询权限、语义注入与 `external_function.config` 的集成留待后续单独设计。
- 按用户后续决定，未新增或强化 Semantic Modeler 对 callee item 内容的 validation；只保留迁移后 required 顶层字段存在性契约。程序拼接仍负责写回 project identity/callsite/linkage 和 external 调用边。
- benchmark 实跑未在本期执行：当前测试环境无法收集两个依赖 `scripts` 包的 benchmark 测试，且不修改该范围外环境缺失。
- 更激进的方法：callee.behavior直接复用callee snapshot的summary，不由当前semantic modeler生成。

### 已知问题

- 因未设置 runtime allowlist，模型即使在 prompt 中看不到 `external_callees`，仍可能依据源码自行请求外部函数 snapshot；prompt 分流只能降低诱因，不能强制阻止。该行为将在 `external_function.config` 集成时统一处理。
- 使用具备 macro-definition API 的 backend 时，若 backend 未返回某个 macro 定义，callee 会按“当前不可解析”归入 `external_callees`；不会根据名称猜测其项目 macro 身份。
- 完整测试仍受两个环境 collection 错误影响；上述两个 schema 断言失败已于 2026-07-22 修复。

## 2026-07-22 Semantic Modeler 单会话 Final Tool

### 阶段 0：现状审计完成

- 以[历史快照重构方案](../../docs/archive/design-plans/snapshot_redesign.md)第十四节为实施基线。
- 确认当前 Semantic Modeler 使用 `require_structured_finalization=True`：先运行普通检索工具 conversation，再创建独立 `json_finalization=1` 会话强制调用 `emit_function_snapshot`。
- 确认 global-model benchmark 中 234 个 LLM snapshot 对应 468 个 Semantic Modeler session；`platform_execute_task` 的探索与 finalization 分别生成 1,133 和 989 completion tokens，存在重复完整输出。
- 确认 `LLMClient.run_conversation_with_tools()` 当前会把所有 function tool call 交给普通 `tool_executor`，没有 terminal tool 捕获与立即结束协议。
- 确认 `JsonToolAgent` 已有 final tool schema、payload coercion、schema/semantic validator、program post-process 和 repair helper，可复用这些能力实现 opt-in 单会话路径。
- 确认工作树已有第十三节 project/external callee 双数组改动；本轮在其上增量实现，不回退或覆盖现有 schema、prompt、snapshot 和测试修改。
- 本轮只为 Semantic Modeler 启用 single-pass final tool；其他 JSON Agent 保持原 finalization/repair 行为，且不新增 callee runtime allowlist。

### 阶段 0 验证

- 完成 `zscope/framework/llm_client.py`、`zscope/agents/base.py`、Semantic Modeler、conversation recorder 和相关 JSON/loop-guard/token 测试的静态审计。
- 本阶段未修改运行时代码，未运行行为测试。

### 阶段 1：底层 terminal tool 会话协议完成

- `LLMClient.run_conversation_with_tools()` 增加默认关闭的 `terminal_tool_name`、`terminal_tool_handler` 和 `terminal_tool_required` 参数；未传入时沿用原有普通工具循环。
- terminal tool 不进入普通 `tool_executor`。单独调用且 handler 校验成功时，直接返回 terminal payload、终止工具名称、有效性和独立计数，并结束当前 recorder session。
- 非法 payload、同一响应中的重复 terminal call 或 terminal 与普通工具混用时，写入结构化 tool error 后继续同一 conversation；普通工具仍按原有重复调用保护和执行流程处理。
- 强制 terminal 模式下，模型返回 prose 会收到短提示并继续当前会话；最后一轮仅暴露 terminal tool，避免因关闭全部 tools 而丢失最终提交机会。
- `tool_call_count` 继续只统计普通工具结果；新增 `terminal_tool_call_count` / `final_tool_call_count` 用于单独观测最终提交，累计 token 仍按所有 API response 求和。

### 阶段 1 验证

- `pytest -q tests/test_llm_client_tokens.py`：`7 passed`。
- 新增普通工具 → terminal tool 的单 session 收束测试，以及非法 terminal payload 在同一 conversation 修复的测试；确认 terminal tool 不会调用普通 executor，且不会计入普通 tool call 数。

### 阶段 2：JsonToolAgent 单会话 opt-in 完成

- `_run_json_conversation()` 增加默认 `False` 的 `single_pass_final_tool` 参数；仅显式开启时把当前 `JsonOutputSpec` 的 final tool schema 合并到初始工具集合。
- single-pass handler 复用现有 payload coercion、nested key 和 validator 契约；合法 terminal payload 继续经过既有 `post_process`，因此 Semantic Modeler 的 program-owned 字段覆盖和 project callee behavior merge 顺序不变。
- single-pass 模式不再进入 `_run_json_structured_finalization()` 或独立 `_run_json_final_repair()`；非法 terminal payload 由底层在同一 conversation 回灌错误并重试，耗尽 iteration 后返回带稳定 metadata 的失败响应。
- 默认 JSON Agent 路径未改变；`require_structured_finalization` 仍只在未开启 single-pass 时运行。
- recorder 新增独立 terminal tool summary，记录名称、参数键、有效性和错误；不增加普通 tool result count。

### 阶段 2 验证

- `pytest -q tests/test_json_output_agents.py tests/test_llm_client_tokens.py`：`28 passed`。
- 新增 Semantic Modeler 无效 terminal payload → 同 conversation 修复 → program merge 成功测试；确认第二次请求包含结构化 terminal error，普通 `tool_call_count=0`，terminal call 独立计数为 2。
- 修改模块 `py_compile` 通过。

### 阶段 3：Semantic Modeler 单会话 final tool 启用完成

- Semantic Modeler 将原 `require_structured_finalization=True` 替换为 `single_pass_final_tool=True`；`emit_function_snapshot` 从第一轮起与检索工具同时可见。
- user prompt 新增阶段约束：检索阶段不得输出完整 snapshot prose/JSON，证据充分后必须调用 `emit_function_snapshot` 提交一次最终 payload。
- `semantic_modeler/AGENT.md` 同步终止工具契约；保留现有 target-query guard、project/external callee 分流、LLM semantic-only schema 和 program field merge。
- 即使 provider 标记支持 structured output，本路径也使用 terminal function tool；其他 JSON Agent 仍可继续使用既有 response-format finalization。

### 阶段 3 验证

- Semantic Modeler 测试确认 final tool schema 已在初始 `tools_schema`，有效 schema 覆盖 custom schema，prompt 包含禁止重复完整输出的约束。
- program-owned identity、referenced globals/macros 与 truncation metadata 覆盖测试通过。

### 阶段 4：异常路径与兼容性保护完成

- terminal tool 在 max iteration 的最后一轮仍可被调用；若模型只返回 prose，则仅在预算内追加 terminal 要求，耗尽预算后明确失败，不把 prose 写入 snapshot。
- XML `<invoke>` fallback 产生同名 terminal tool 时复用 capture/handler 分支；不再落入未知普通工具执行。
- 同一响应的多个 terminal call 或 terminal 与普通工具混用均拒绝 terminal payload，并回灌稳定错误；普通工具部分仍按旧流程执行。
- loop guard 和旧的 tools-disabled 行为保持兼容；未开启 single-pass 的 JSON Agent 继续使用独立 finalization/repair。

### 阶段 4 验证

- `pytest -q tests/test_llm_client_tokens.py tests/test_json_output_agents.py tests/test_json_agent_loop_guard.py tests/test_conversation_recorder.py`：`37 passed`。
- 覆盖 prose、XML invoke、mixed tool calls、invalid terminal payload、loop guard 和 recorder 兼容路径。

### 阶段 5：指标、日志与 recorder 完成

- 单会话结果统一提供 `api_call_count`、`tool_call_count`、`terminal_tool_call_count`、`final_tool_call_count`、累计 Prompt/Completion/Total Tokens；structured finalization 的额外请求也会累计 API calls。
- `JsonToolAgent` single-pass metadata 增加 `finalization_mode=single_pass_tool`、`terminal_tool_name`、`terminal_tool_valid` 和 `single_pass=true`，与旧 finalization metadata 可区分。
- global semantic-model 日志增加 finalization mode、terminal tool、有效性与 terminal call count，便于 benchmark 从日志和 metadata 双向汇总。
- conversation recorder 以 `terminal_tool_summary` 单独保存 terminal 提交，Markdown 与 JSONL 均能区分普通工具结果和最终提交；成功路径不会创建 `json_finalization=1` session。

### 阶段 5 验证

- 计数测试确认普通工具 → terminal tool 的 `api_call_count=2`、`tool_call_count=1`、`terminal_tool_call_count=1`；非法 terminal → repair 的 `api_call_count=2`、普通 tool count 为 0。
- `py_compile`（LLM client、JSON agent、Semantic Modeler、global modeler、conversation recorder）通过。

### 阶段 6：回归与交付完成

- 核心集合：`pytest -q tests/test_json_output_agents.py tests/test_llm_client_tokens.py tests/test_json_agent_loop_guard.py tests/test_conversation_recorder.py tests/test_semantic_model_input.py tests/test_global_modeler.py tests/test_snapshot_store.py tests/test_snapshot_tool.py tests/test_analyzer_semantics.py`，结果 `105 passed`。
- 全量 `pytest -q` 因缺少 `scripts` 包而在两个 benchmark 测试收集阶段停止；排除 `test_benchmark_protocol.py` 和 `test_range_benchmark_regression.py` 后，结果 `716 passed`。
- `python -m compileall -q zscope` 与 `git diff --check` 通过。
- 未修改 fallback 文件、未触碰 `/home/jager/Z-Scope-baseline`，并保留了工作区中既有的 project/external callee 及其他用户改动。

### 本计划偏差

- terminal payload 验证以通用 handler 注入 `LLMClient`，没有将 Semantic Modeler schema 逻辑写入底层客户端；语义校验和 program field merge 仍由 `JsonToolAgent`/Semantic Modeler 负责。
- terminal 参数无效时只在同一 conversation 的剩余 iteration 内修复；预算耗尽后返回失败，不再调用旧的独立 `json_finalization` repair session。
- recorder 新增 terminal summary 而未破坏既有 JSONL 事件格式；global 路径的 `[snapshot-llm]` 日志已增加单会话字段，entry/on-demand/premodel 日志本轮未逐处扩展。
- XML fallback 使用既有扁平参数解析；未额外实现复杂嵌套 XML 的 JSON 专用解码。

### 已知问题

- 当前环境无法导入 `scripts` 包，导致完整 pytest 无法收集两个 benchmark 相关文件；这与本计划实现无关，已通过其余 `716` 项回归验证。
- 尚未重新执行同配置 global-model benchmark，因此 Completion Tokens、Total Tokens、API Calls 的实际降幅尚待实测；本轮提供了按普通工具、terminal tool、API calls 与累计 token 分离统计的基础。
- 个别 provider 若持续生成 schema-invalid terminal payload，会耗尽单会话 iteration 后失败；不会持久化不完整 snapshot，但需由上层重试任务处理。
- 如果模型把 terminal tool 与普通检索工具放在同一 assistant 响应中，terminal 会被拒绝、普通工具仍执行，随后需要额外一轮重新提交最终 payload。

## 2026-07-22 Callee Summary 程序透传与无 LLM Refresh

### 实施完成

最终职责如下：

- Semantic Modeler 只生成当前函数的 summary、parameters、return_values、effects、error_handling 和 suspicious_points。
- project_callees、external_callees、symbol context、truncation metadata 和 identity 全部由程序生成或透传。
- callee_summary 只逐字来自 canonical callee snapshot 的顶层 summary。
- unknown callee 可以被模型查询以完善当前函数语义，但模型不得输出 callee summary 或任何 callee item。
- callee summary 晚到或变化时只执行 program-only snapshot refresh，不启动 LLM。

### Schema、Prompt 与 Agent 合并

- project_callees 已加入 PROGRAM_PASSTHROUGH_SNAPSHOT_FIELDS，因此 Semantic Modeler 输入必须提供 array，最终 AgentResponse.data 始终深拷贝程序记录。
- llm_function_snapshot_schema 的 properties 和 required 均完全排除 project_callees；旧的 required callee_index_name/callee_summary item schema不再暴露给模型。
- Semantic Modeler prompt 继续包含 project_callees、external_callees 及两侧 truncation metadata，保留 known/unknown summary 作为当前函数建模证据。
- AGENT.md 已改为：unknown callee 的 snapshot/function info/code 查询只用于当前函数语义，不生成 callee summary，不输出 external 或 program-owned callee 字段。
- agent.py 已删除 llm_summaries 映射、canonical identity merge、known/unknown override 和重复 identity 处理；program-owned 字段最后统一覆盖。
- 即使测试 LLM payload 伪造、乱序、稀疏或重复 project_callees，最终数组仍完整等于 program input。

### Hydration 与非全局消费路径

- hydrate_project_callee_summaries 继续在 LLM 前读取 current callee snapshot summary，缺失时写入 unknown，不增加 API Calls。
- self recursion 若已有自身 snapshot，可直接复用自身 summary；首次建模保持 unknown。
- hydration 在已有 caller snapshot 正式消费前调用 SnapshotStore program-only reconciliation。
- reconciliation timeout 或失败会以 callee_summary_reconcile_failed 终止语义输入构造，避免返回已知过期 snapshot。
- global、entry、premodel、on-demand、scan-session 与 snapshot tool 均复用该路径。
- Analyzer 的通用 LLM snapshot 保存路径也补齐 project/external callee 及其 truncation program override。
- deterministic snapshot 保持程序透传，不因 unknown 调用 LLM。

### SnapshotStore Fingerprint 与原子刷新

- symbol_context_hash 已移除 callee summary，只跟踪 project identity/调用边/static-macro、external callee、globals/macros 和 truncation。结构变化继续返回 symbol_context_changed 并要求重新建模。
- 新增 callee_summary_hash，只跟踪 canonical project identity 与透传 summary。
- SQLite 新表包含 callee_summary_hash；已有 index-name 数据库启动时回填新列并按新规则重算 symbol_context_hash；旧表迁移同步写入两个 hash。
- needs_refresh 对 summary-only 变化返回 (False, callee_summary_changed)，不会把它升级成 LLM refresh。
- reconcile_project_callee_summaries 使用 canonical index lock：
  - 先校验结构 hash 一致；
  - 深拷贝完整 program project_callees；
  - 原子更新 snapshot JSON；
  - 只更新 callee_summary_hash、timestamp 和 snapshot cache；
  - 完整保留当前函数所有 LLM semantic fields。
- 并发相同 reconciliation 会串行化为一次 refreshed 和后续 unchanged，不产生部分 JSON。

### Global Model 阶段末 Reconciliation

- Global Modeler 在所有 component 完成且没有建模失败、unresolved entry 时，从成功 current snapshot 冻结 summary_map。
- 每个 caller 重新构造 canonical program input，并以程序数组数量和顺序为准 exact match summary_map。
- summary_map 在任何 patch 前冻结，一轮即可补齐 self recursion、mutual SCC 和并发顺序造成的暂时 unknown。
- 新增统计：
  - unresolved_entry_functions
  - reconciled_functions
  - reconciliation_unchanged_functions
  - reconciliation_failures
  - unknown_project_callees
  - stage_complete
- summary_map 缺失 current snapshot/summary，或 reconciliation 返回 missing、llm_refresh_required、timeout、failed 时，计入 reconciliation_failures。

### 全局阶段门禁与断点恢复

- stage_complete 仅在 failed_functions=0、unresolved_entry_functions=0、reconciliation_failures=0 时成立。
- ParallelAnalyzer 在 global stage 未完成时直接停止，不再关闭 enable_global_model 后降级到逐入口分析。
- API、网络或模型失败不会合成 fallback summary，也不会继续漏洞挖掘和验证。
- 恢复后重新运行时，已成功 snapshot 命中 cache，仅重试失败或缺失函数。
- 完整入口列表使每个列出的函数成为 depth-0 root；普通运行仍受入口范围和 global depth/breadth 配置限制。

### Backend 与截断边界

- backend 未解析出的调用边不进入 callee 数组，因而没有 callee summary。
- 无法唯一解析为项目函数的调用进入 external_callees，只作为 prompt 证据，不生成 summary。
- project/external 继续分别应用 30/20 上限和独立 truncation metadata。
- 被 backend 遗漏或截断的函数即使独立拥有 snapshot，也不会被程序猜测并拼回 caller。
- runtime snapshot allowlist 未实施；external_function.config 未接入；fallback 文件未修改。

### 验证

新增或更新的验证覆盖：

- LLM schema properties/required 完全没有 project_callees。
- LLM 伪造 callee 输出无法改变 program records。
- known、unknown、self-recursive hydration。
- summary-only refresh 不调用 LLM，semantic fields 保持不变。
- summary_map 忽略额外 identity，缺失 identity 保持 unknown。
- self recursion 和 mutual SCC 一轮收敛，Semantic Modeler 调用次数不增加。
- 并发 reconciliation 串行化。
- failed function 和 unresolved entry 使 stage_complete=false。
- global stage failure 阻止 entry fan-out。
- SQLite split-hash migration/backfill。

执行结果：

- 聚焦集合：68 passed。
- 可收集完整回归：728 passed。
- python -m compileall -q zscope：通过。
- git diff --check：通过。
- 完整 pytest 仍有 test_benchmark_protocol.py 和 test_range_benchmark_regression.py 因环境缺少 scripts Python package 无法收集。

### 计划偏差

- 没有新增名为 semantic_input_hash 的数据库列；实际收窄既有 symbol_context_hash 作为需要重新建模的结构 fingerprint，并新增 callee_summary_hash。行为与计划一致，同时避免无必要的列重命名。
- 非全局路径没有实现常驻反向依赖监听器；通过统一 hydration 在 snapshot 消费前局部 reconciliation。Global Model 仍执行完整阶段末 reconciliation。
- SnapshotStore 的 program-only refresh 不清除 final report，因为当前函数 LLM semantic fields 未变化；结构或代码变化仍走原有 LLM refresh 和报告失效路径。

### 已知问题

- 尚未重新运行同配置 global-model benchmark，因此 Completion Tokens、Total Tokens、API Calls 和 program-only refreshed snapshot 数的实测变化仍待收集。
- 普通配置受 global depth/breadth 和 Function Info 30/20 截断限制，unknown_project_callees 可能非零；这不代表 reconciliation 失败。
- backend 没有提供的调用边无法通过 summary reconciliation 恢复。
- 当前环境缺少 scripts package 的两个 benchmark 测试收集问题仍存在，与本次实现无关。

## 2026-07-23 Referenced Types 程序注入与类型上下文刷新

### 阶段 1：KnowledgeDB 与直接类型引用提取完成

- KnowledgeDB schema version 从 8 升至 9，新增 `function_type_refs` 表及 function/type/name 三组索引。resolved 引用保存 `function_id`、`type_id` 和 canonical `type_index_name`；unresolved 引用使用空 identity、`type_id=NULL` 与稳定 `resolution_reason`。
- 新增 `KnowledgeDB.type_index_name()`、`get_all_type_definitions()`、`replace_function_type_refs()`、`get_function_type_context()` 和 transitive include closure 查询。公开 resolved item 不含 definition hash/dependency depth；unresolved 数组仅在非空时输出。
- function/type TU 清理同步删除 owned/incoming type refs；删除类型 TU 前会把引用该类型的函数文件加入 delete impact，供增量索引重新标记。
- `ClangExtractor` 在全部 TU 的 function/type/include facts 更新后原子重建直接引用。候选覆盖 signature return/parameter/function pointer，以及 body local/cast/sizeof/alignof/offsetof/compound literal/member access；只聚合目标函数直接使用的类型，不扫描 `full_definition` 展开依赖。
- resolved 主路径使用 clangd definition location 与 `type_definitions` 范围匹配；definition 不可用时仅在规范化 include closure 内唯一候选可见时保守解析，多候选和不可见类型进入 unresolved。
- quote include edge 规范化为 source-root 相对路径；相对路径、project-root 路径和唯一 suffix 候选统一为同一 include graph 节点。
- 新增 `function_type_ref_extractor_version=1`；metadata 缺失或变化时强制 unchanged TU 重建，成功完成全部引用重建后才写入当前版本。
- 本阶段未修改 `get_type_info` Tool、任何 fallback 文件或 baseline 工作树。

### 阶段 1 验证

- 新增 KnowledgeDB resolved/unresolved 聚合与 optional 输出测试。
- 新增 type TU incoming refs、function TU owned refs 清理和 delete impact 测试。
- 新增 `_plugin_register` 同类 fixture，验证 `PluginRegistry` 的 parameter/member_access 与 `Plugin` 的 local/cast/sizeof 均解析到 `include/types.h`。
- 新增 include edge canonical path 与 transitive closure 测试。
- 聚焦测试结果：`4 passed`。
- 修改模块 `py_compile` 与相关文件 `git diff --check` 通过。

### 阶段 2：Backend、CodeIndex 与 Function Info Tool 完成

- `CodeBackend` 新增默认 `get_function_type_context()` 契约；ClangBackend 从 KnowledgeDB 查询，UnifiedBackend 透明委托 Clang 主结果。
- JoernClient 新增 method return/parameter/local 的 `typeFullName` 直接引用查询；JoernBackend 将唯一且具有完整源码的 typeDecl 转为统一 resolved item，缺失、歧义或定义不完整时输出 optional unresolved，不递归展开 typeDecl 内部依赖。
- CodeIndex 集中执行 canonical normalization、去重、稳定排序和预算：direct type 最多 30 项，单项 `full_definition` 最大 8 KiB，总定义最大 32 KiB，signature return/parameter/function-pointer 优先。超大定义整项转为 `definition_too_large`，不注入残缺文本。
- CodeIndex 明确删除 backend 输入中的 `definition_hash`、`dependency_depth` 和其他非契约字段；最终 resolved item 只保留 `type_index_name`、`kind`、`full_definition`、`reference_kinds`、`reference_lines`。定义位置编码在 `type_index_name`，`full_definition` 复用 `get_file_snippet()` 的绝对行号格式。
- regex backend 增加保守 type definition index 与 transitive quote-include closure；复用 Clang 路径的直接引用分类器，只有 closure 内唯一 exact definition 才 resolved，歧义和不可见候选不按排序猜测。
- 普通函数的 `find_function_infos()` 每个 match 均返回 required `referenced_types`；function-like macro 固定返回空数组，optional unresolved/truncation 只在实际存在时输出。
- `get_function_info` Tool 不重新查询、解析、排序或截断类型上下文，直接返回 CodeIndex match；配置的 external function 补齐 required `referenced_types=[]`。Tool description 已说明三类 type-context 字段。
- 本阶段保持 `zscope/tools/type_info.py` 未修改，未改变 `get_type_info` 参数、路径限定、fallback、返回 payload 或错误语义。

### 阶段 2 验证

- 覆盖 31 个直接类型触发 count truncation、signature 类型优先、内部字段不泄漏及 30/32 KiB 契约。
- 覆盖 `get_function_info` 对 required resolved 和 optional unresolved/truncation 的透明透传。
- 覆盖 ordinary function、macro、configured external、Joern resolved/unresolved 与 regex include-closure 解析。
- 阶段相关回归：`73 passed`。
- 修改模块 `py_compile`、相关文件 `git diff --check` 通过；`zscope/tools/type_info.py` 工作树无修改。

### 阶段 3：Semantic Model 输入、Program Ownership 与 Deterministic Snapshot 完成

- `build_semantic_model_input()` 将 `referenced_types` 作为 required CodeIndex 字段深拷贝；optional `unresolved_referenced_types` 仅接受非空数组，`referenced_types_truncation` 仅接受 object，并与其他 program context 一起透传。
- 输入边界校验 resolved item 的五个公开字段，明确拒绝 `name`、`file_path`、`start_line`、`end_line`、`definition_hash` 和 `dependency_depth`；非法上下文以 `reason=semantic_model_input_invalid`、`llm_called=false` 在调用 LLM 前终止。
- persisted snapshot schema 新增 required `referenced_types` 及 optional unresolved/truncation 完整结构；`definition_hash` 不属于公开 schema。
- 三个 type-context 字段加入 program passthrough/excluded fields。LLM terminal tool schema和 structured schema均不暴露这些字段；模型即使伪造同名字段，也会在 merge 前删除并由程序输入最后覆盖。
- Semantic Modeler 首轮 metadata 直接包含完整 direct type definitions、optional unresolved 和 truncation，内部 hash 不进入 Prompt。
- `AGENT.md` 明确禁止重复查询 `referenced_types` 中已有完整定义的类型；只有 unresolved、被预算省略或目标源码中新发现的必要项目类型才允许调用现有 `get_type_info`。只知道 use-site 时不伪装成 declaration path，本轮不改变 Tool 行为。
- trivial/syntactic 与 lightweight deterministic snapshot 新增 required `referenced_types`，按 canonical 字段顺序复制 optional unresolved/truncation，并进行深拷贝和 shape 校验。
- Analyzer 通用 LLM snapshot 保存路径同步覆盖 type-context program fields，避免非 global 路径保存模型伪造或缺失的类型事实。

### 阶段 3 验证

- 覆盖统一输入 required/optional 校验、非法内部 hash 拒绝和深拷贝隔离。
- 覆盖 Prompt 含完整类型定义、LLM schema 排除 type fields、LLM 伪造无法覆盖 program context。
- 覆盖 deterministic snapshot required/optional 字段顺序、shape 与嵌套内容深拷贝。
- 本阶段测试中一个旧手写 Function Info fixture 因缺少 required `referenced_types` 失败；按约束只更新该测试 fixture，未为此改变生产实现。
- 阶段相关回归：`70 passed`。
- 修改模块 `py_compile` 与相关文件 `git diff --check` 通过。

### 阶段 4：Type Context Fingerprint、Refresh 与消费者接入完成

- SnapshotStore SQLite schema 新增独立 `type_context_hash`。新库直接创建该列；已有 index-name 数据库以 canonical empty type context 增量补列；旧主键 schema 迁移到新表时从 snapshot 当前 program context 计算。
- `compute_type_context_hash()` 对每个规范化 `full_definition` 即时计算 SHA-256，只把临时 definition digest 放入内部投影；snapshot item、数据库 JSON 和 LLM context 均不保存 `definition_hash`。
- fingerprint 同时覆盖 canonical type identity、kind、带行号定义的内部 digest、direct reference kinds/lines、resolved/unresolved 转换和 truncation。数组顺序、reference kinds/lines 顺序、CRLF/LF 与行尾空白不影响 hash。
- `save_snapshot()` 要求 persisted snapshot 含 required `referenced_types`，并同时保存 code/semantic/symbol/callee-summary/type 五类 fingerprint。
- `needs_refresh()` 在类型 fingerprint 变化时返回 `(True, "type_context_changed")`；类型变化不会走 callee-summary program-only patch。旧 snapshot 缺少 required types、optional unresolved 为空或 truncation 类型错误时返回 `snapshot_shape_changed`。
- callee summary reconciliation 增加 type hash 门禁；只要当前类型上下文与已建模版本不同，就返回 `llm_refresh_required`，不得在旧语义上只更新 callee summary。
- type refresh 日志只记录 index identity 与 old/new hash 短前缀，不记录完整定义或 context JSON。
- snapshot Tool 的 missing/stale fallback 透传 required resolved 与 optional unresolved/truncation；类型变化时不返回 stale snapshot。
- validation evidence 保留全部 type identity/reference/truncation 状态，并对 `full_definition` 使用 16 KiB 明确预算；超预算项只在 evidence projection 标记 definition omitted，不修改 persisted snapshot。
- local semantic inference 的 snapshot contract text 可消费已持久化类型上下文，不需要再次调用 LLM Tool。
- global、entry、premodel、on-demand、history、scan resume 继续复用统一 input builder 与 `needs_refresh()`，因此自动获得相同 type refresh 行为。

### 阶段 4 验证

- 覆盖 definition/member 文本与 direct reference kind 变化触发 `type_context_changed`，以及换行/尾空白/数组顺序不触发误刷新。
- 覆盖旧 snapshot shape 一次性重建、SQLite type hash 新建/迁移、fingerprint 查询和 program-only reconciliation 门禁。
- 覆盖 snapshot Tool 不返回 stale 类型证据、validation evidence 字节预算、scan resume 在类型变化时不复用旧 final report。
- 扩大消费者回归时 12 个旧测试双件因缺少 required `referenced_types` 失败；按约束只更新测试 fixture/伪 Agent 输出，未用生产兼容分支掩盖旧 shape。
- 阶段相关回归：`129 passed`。
- 修改模块 `py_compile` 与相关文件 `git diff --check` 通过。

### 阶段 5：最终验收与交付完成

- extractor 候选回归在首次本地 CPG build 中发现 parenthesized value/function argument 被 cast 正则误判为 type；已收紧为“类型右括号后必须存在 cast operand”，并要求候选为已索引类型、CamelCase 或 `_t` 风格，固定宽度整数 typedef 作为 builtin 排除。
- 增加 `path`、宏实参、`sizeof(variable)`、`uint32_t` cast 与真实 `RuntimeEvent*` 对照 fixture；range 全函数只读候选扫描的已知 false candidate 数降为 0。
- 候选语义修正后将 `function_type_ref_extractor_version` 升至 2，确保已写入 v1 metadata 的 unchanged TU 也会自动重建。存在失败 TU 时不推进该版本。
- range 本地索引仅重建 type refs（未运行全量 scan）：共 887 条 direct refs，858 resolved、29 unresolved；154 个函数存在 resolved type，15 个函数存在 unresolved type。
- 29 条 unresolved 仅涉及 `pthread_t`、`pthread_mutex_t`、`pthread_rwlock_t`、`FILE`、`pid_t`、`socklen_t`、Windows `BOOL/DWORD/OSVERSIONINFO/STARTUPINFO/PROCESS_INFORMATION` 等未进入项目 `type_definitions` 的系统/平台类型。
- `_plugin_register` 离线结果：
  - `Plugin@include/types.h:90-98`：`local/member_access`；
  - `PluginRegistry@include/types.h:110-115`：`parameter/member_access`；
  - `plugin_handle_t@include/types.h:9-9`：`cast`；
  - `task_handler_t@include/types.h:86-86`：`parameter`；
  - unresolved 为 0。
- 非 benchmark 全回归：`751 passed`。
- `python -m compileall -q zscope` 与全工作树 `git diff --check` 通过。
- 完整 pytest 两次均在 range benchmark regression 子流程开始附近无 pytest summary 异常终止；遵循用户“不运行全量 benchmark”的后续要求，不再运行这两个 benchmark 文件，也未修改生产代码规避该测试进程行为。
- `zscope/tools/type_info.py` 保持未修改；未修改 fallback 文件和 `/home/jager/Z-Scope-baseline`。

### 计划偏差

- `function_type_ref_extractor_version` 最终为 2，而非计划初始值 1：v1 本地索引暴露 cast/parenthesized value 误识别，修复候选语义后必须再次失效旧索引。
- UnifiedBackend 的实际架构是 Clang + SVF，不包含 Joern 双源合并；实现中 Unified 直接采用 Clang/KnowledgeDB type context，JoernBackend 独立提供兼容契约，没有人为合并两个同时不存在于该 backend 的结果源。
- Joern 路径首期只覆盖稳定可获取的 method return、parameter 和 local `typeFullName`；cast/sizeof/offsetof/compound literal/member owner 的完整覆盖仍以 Clang/KnowledgeDB 主路径为准。
- validation evidence 对类型定义采用独立 16 KiB 投影预算；超预算只省略 evidence 中的 definition text并保留 identity/reference/truncation，persisted snapshot 仍遵循 32 KiB 总预算。
- 按用户后续明确指令未执行完整 global-model benchmark，因此没有实施前后 token、API calls 和 wall time 的可比完整结果。曾启动的两个临时 run 均被主动终止；重试 run 在终止前产生 1 条 snapshot-llm 日志和 3 个临时 snapshot，不能作为 benchmark 指标。

### 已知问题

- 系统头和平台 SDK 类型不写入项目 `type_definitions`，因此 `pthread_t`、`FILE` 和 Windows API structs 等会以 unresolved 进入上下文；本期按计划不改变外部类型配置语义。
- Joern-only backend 的 direct type role 覆盖低于 Clang 主路径，且没有 source-backed full definition 时会输出 `definition_incomplete`。
- regex type definition fallback 使用保守源码模式，对包含复杂嵌套匿名 record、宏展开或模板语法的定义可能无法完整识别；无法唯一证明时保持 unresolved，不选择第一项。
- full definition 注入的实际 Prompt/Total Token 成本尚未通过完整 benchmark 验证，不能宣称总体 token 或 wall time 已下降；当前只证明工具调用需求和路径误用来源被程序上下文消除。
- 两个 range benchmark pytest 文件在当前全套运行中会使 pytest 进程于约 63% 无总结终止；非 benchmark 的 751 项回归全部通过。

## 2026-07-23 Backend-backed 宏 `referenced_macros` Regex Fallback

### 已完成

- 为 `KnowledgeDB` 增加批量 `get_macro_definitions_batch(names)` 查询，一次返回候选名称对应的 `macro_definitions` 完整记录；查询按 500 个名称分批，避免逐 token N+1 查询和 SQLite 参数上限问题。
- `CodeBackend` 增加默认 capability，`ClangBackend` 与 `UnifiedBackend` 透传 KnowledgeDB 实现；没有该能力的 backend 保守返回空定义集合。
- 重构 `CodeIndex._macro_function_info_symbol_context()`：
  - 先对完整宏定义执行 regex 引用发现；
  - 去除注释、字符串和字符字面量，排除目标宏名、宏形参、字段访问和预处理关键字；
  - 记录绝对引用行和 function-like 调用行；
  - 再由 KnowledgeDB 补全 macro 的定义位置、完整 definition 和 `is_function_like`。
- backend-backed macro 定义消歧采用保守规则：目标宏同文件的唯一候选优先；无同文件候选时只接受全项目唯一候选；多个候选不按排序猜测并写 debug 日志。
- object-like macro 使用全部引用行；function-like macro 只有在 token 后存在调用括号时才进入 `referenced_macros`，避免把仅作为普通标识符出现的同名 token 误识别为宏调用。
- `referenced_macros` 在成功解析、排序和去重后应用独立 limit；truncation `total` 不包含数据库未命中或歧义候选。
- 撤销宏体 regex + global name lookup 产生 `referenced_globals` 的方案：宏展开位置可能存在局部变量遮蔽，同名 global definition 不能证明实际绑定。宏目标的 `referenced_globals` 当前固定为空数组，等待后续 `search_global` 工具提供显式证据。
- 保留当前 function-like macro 的 `project_callees` 行为。本轮只补齐 `referenced_macros`，不提前实施 snapshot redesign 第八章的宏单一归属重构。
- 纯 regex/no-backend 的 `referenced_macros` 继续使用现有源码定义索引，普通函数的 `function_symbol_refs` 查询路径未改变；未修改 fallback 文件。

### 原问题离线验证

使用 `test/range/.zscope_knowledge/global_model_benchmark.db` 和现有 range 源码直接查询 `COUNTER_SLOT_UNLOCK@src/lifecycle.c:961-961`，未重建索引、未调用 LLM，最终结果为：

- `referenced_globals`：空数组；不再用名称匹配推断 `g_lifecycle_counter_lock`。
- `referenced_macros`：`UNLOCK`，定义于 `include/common.h:34`，`is_function_like=true`，完整 definition 与引用行 `[961]` 均已补齐。

### 新增测试

- KnowledgeDB macro 批量查询覆盖名称去重、缺失名称、同名 global 不混入结果以及空输入。
- backend-backed 多行宏覆盖对象式宏、function-like macro、宏形参、注释、字符串、非调用 token、`referenced_globals=[]` 和 Semantic Model 输入透传。
- 覆盖跨文件 macro 多候选保守省略，以及 function-like macro 暂时同时保留在 `project_callees`。
- 覆盖 51 个成功解析 macro 加一个歧义候选：返回 50 个，truncation `total=51`，歧义候选不计入 total。

### 测试结果

- 实施前基线：`python -m pytest tests/test_function_info_tool.py tests/test_knowledge_db_ir_and_config.py -q`，49 个测试通过。
- 新增聚焦回归：3 个测试通过。
- 相关回归：`python -m pytest tests/test_function_info_tool.py tests/test_knowledge_db_ir_and_config.py tests/test_semantic_model_input.py tests/test_global_modeler.py tests/test_snapshot_tool.py -q`，79 个测试通过。
- 非完整 range benchmark 回归：`python -m pytest -q --ignore=tests/test_range_benchmark_regression.py`，793 个测试通过，最终耗时 20.86 秒。
- `python -m py_compile zscope/retrieval/backend_base.py zscope/retrieval/knowledge_db.py zscope/retrieval/clang_backend.py zscope/retrieval/unified_backend.py zscope/retrieval/code_index.py` 通过。
- `git diff --check` 通过。

### 未执行项与剩余限制

- 未运行 `tests/test_range_benchmark_regression.py`，也未调用外部 LLM；本轮只使用现有 benchmark KnowledgeDB 做离线结果验证。
- Joern 等没有 KnowledgeDB macro-definition capability 的 backend 仍不能补齐数据库字段。
- 条件编译下同名定义的精确可见性尚未建模；存在多个无法唯一证明的候选时保持省略，不选择第一项。
- 宏 `referenced_globals` 暂不自动推断；后续由 `search_global` 工具按需查询并提供证据。

## 2026-07-23 Project Callee 宏去重与 Canonical Macro Context

### 实施完成

- `project_callees` 现在只包含真实项目函数；可唯一解析的 function-like macro 只进入 `referenced_macros`，不会转入 `external_callees`。
- 完整 snapshot schema、Function Info/Semantic input、deterministic builder、hash/reconciliation projection 均删除 `project_callees[].is_macro`。
- `referenced_macros` 统一为 `macro_index_name/definition/is_function_like/reference_lines`；公开 payload 不再包含 `name/file_path/line`。
- macro definition 复用 `CodeIndex.get_file_snippet()` 按 canonical range 读取，保留绝对 1-based 行号。

### 数据库与 Extractor

- KnowledgeDB schema 升至 v10；`macro_definitions` 新增 `macro_index_name/start_line/end_line` 和 canonical unique index。
- 新增 `function_macro_refs`，通过 function/macro 外键保存引用行；旧通用 symbol refs 继续承载 globals。
- macro 与 symbol-context extractor version 升至 2，旧索引强制重建。
- macro migration 记录 total/migrated/collision/failed；canonical collision 不覆盖旧记录。

### Snapshot 与 Global Model

- 历史 macro callee 或旧 macro item shape 返回 `snapshot_shape_changed` 并重建。
- macro summary 不再参与 caller 的 hydration、callee-summary hash 或 program-only reconciliation。
- Global Model 内部 raw callee 图遍历保持不变，避免静默丢失 macro expansion dependency；持久化 caller snapshot 不再序列化 macro callee。

### 验证

- 聚焦集合：`199 passed`。
- 排除两个 range benchmark regression 文件的可收集完整回归：`762 passed`。
- `python -m compileall -q zscope` 与 `git diff --check` 通过。
- 完整 pytest 在既有 range benchmark 区域无总结终止；终止前未出现失败。

### 计划偏差与已知问题

- 数据库内部保留旧宏字段用于查询和迁移，但所有公开上下文只使用 canonical 新 shape。
- 内部 batch insert 暂时接受旧五字段宏行并立即规范化，不形成旧数据库记录或旧 LLM payload。
- 未运行外部 LLM 或 global-model benchmark，因此只确认上下文去重和契约收敛，不宣称 token/API/wall-time 改善。

## 2026-08-04 自动发现入口解析失败修复

### 问题现象

- 自动入口发现从公开头文件生成 `FunctionEntry`，因此 entry 的 `file_path` 是声明文件，例如 `include/task_dispatcher.h` 或 `include/common.h`。
- global model 构图和 Semantic Model 输入解析原先都会携带该 header file constraint 查询实现；真实函数实现位于 `.c` 文件时，索引查询返回空结果。
- 入口随后进入 `graph.unresolved`，`unresolved_entry_functions` 增加，global-model stage gate 在 entry fan-out 前终止。该问题不是源码缺少实现，而是将声明路径错误地当成实现路径约束。

### 根因定位

- `resolve_function_info()` 首次查询失败后没有区分“普通源文件路径不匹配”和“头文件声明需要映射到实现”两种情况。
- `GlobalModeler._get_impl()` 同样直接把 entry 的 header `file_path` 传给 `CodeIndex.get_function_impl()`，导致 global graph 在进入统一 Semantic Model 输入解析前就可能把入口标记为 unresolved。
- 不能简单删除所有 file constraint：同名函数存在于多个 `.c` 文件时，必须继续保持歧义保护，不能静默选择排序第一项。

### 修复实现

- 在 `zscope/snapshots/modeling_input.py` 增加 `is_header_like_path()`，识别 `.h/.hh/.hpp/.hxx/.ph/.inc/.inl` 声明文件。
- `resolve_function_info()` 仅在“带 file hint 查询无结果且 hint 为 header-like path”时，使用空 `file_path` 重试函数查询。
- header fallback 得到多个候选时，新增 `_select_indexed_header_implementation()`：调用 `CodeIndex.get_function_impl(query, file_path="")` 获取索引选定的 canonical `index_name`，并且只有该 index 在候选中唯一匹配时才接受。
- 如果索引无法唯一选定实现，继续抛出 `function_info_ambiguous`；没有通过猜测放宽同名函数的 identity 约束。
- `GlobalModeler._get_impl()` 增加相同的 header fallback。首次按声明文件查询失败后，才去除 file constraint 重试，确保构图阶段和后续 Semantic Model 输入阶段行为一致。
- 新增 debug 日志 `[snapshot-resolve] retrying header declaration without file constraint` 和 `[global-model] retrying header declaration without file constraint`，用于区分正常 header-to-implementation fallback 与真正的入口缺失。

### 验证

- 新增 Semantic Model 输入测试，覆盖 header 声明映射到唯一 `.c` 实现。
- 新增多实现歧义测试，确认 header fallback 不会任意选择同名实现。
- 新增索引可唯一选定 canonical 实现的测试。
- 新增 global model 测试，确认 `FunctionEntry("entry", file_path="include/public_api.h")` 能进入实际实现建模，且 `unresolved_entry_functions==0`、`stage_complete==true`。
- 修复后的 WSL 自动入口 benchmark 成功解析 88 个入口，global-model 日志为 `unresolved_entries=0`，确认入口解析问题已消除。

## 2026-08-05 Global Model Stage Gate 容忍度扩大

### 问题现象

- 入口解析修复后，`auto_unified_wsl_20260804_170202` 已完成全局可达图构建：88 个入口、314 个可达函数。
- 其中 313 个函数成功生成 snapshot，只有 `_runtime_get_thread_cache@src/lifecycle.c:2246-2255` 建模失败。
- 该函数不是 entry，而是可达 callee；失败原因是 Semantic Modeler 在 50 次 terminal tool call 后仍未生成合法的 `emit_function_snapshot` JSON。
- 原 gate 要求 `failed_functions==0`。因此单个 callee 的 LLM 输出失败会丢弃其余 313 个成功 snapshot 的阶段结果，并阻止全部 88 个入口进入漏洞分析。

### 修复决策

- `failed_functions` 的统计范围包括 entry 和 callee，不能把少量非入口 callee 的偶发 LLM 格式失败等同于入口不可分析。
- `unresolved_entry_functions` 和 `reconciliation_failures` 仍代表入口身份或全局依赖一致性问题，继续保持零容忍。
- 新增 `MAX_FAILED_FUNCTIONS_FOR_STAGE = 10`，将 gate 条件从 `failed_functions==0` 调整为 `failed_functions<=10`。
- 最终 `stage_complete` 条件为：
  - `failed_functions <= 10`
  - `unresolved_entry_functions == 0`
  - `reconciliation_failures == 0`
- 该修改只放宽少量函数 snapshot 失败，不改变 unresolved entry 和 reconcile failure 的硬性阻断语义。

### Reconciliation 行为

- project-callee summary reconciliation 仍只在 `failed_functions==0` 且 `unresolved_entry_functions==0` 时执行。
- 当失败函数数量为 1 到 10 时，reconciliation 会被跳过，但只要没有 unresolved entry 和已记录的 reconciliation failure，stage gate 允许 entry fan-out。
- 因此本次修改的目标是允许扫描在少量 callee snapshot 缺失时继续，而不是把缺失 summary 伪装成已完成 reconcile。

### 测试调整

- 将单函数建模失败测试从“stage gate 必须失败”改为“在容忍范围内跳过 reconciliation，但 stage 可继续”。
- 新增阈值边界测试：`failed_functions=10` 时 `stage_complete==true`，`failed_functions=11` 时为 `false`。
- 保留 unresolved entry 回归测试，确认 `unresolved_entry_functions=1` 时即使失败函数未超阈值，stage gate 仍失败。
- `python -m pytest -q tests/test_semantic_model_input.py tests/test_global_modeler.py` 通过：26 个测试。

### Benchmark 依据

- 触发修复的 run 统计为：`reachable=314`、`modeled=313`、`failed=1`、`unresolved_entries=0`、`reconciled=0`、`reconcile_failed=0`。
- 该 run 证明入口解析修复已经生效，剩余阻断来自旧 gate 对单个 callee LLM 失败的零容忍，而不是 entry identity 解析失败。

## 2026-08-05 Semantic Model Terminal Loop Guard 与 Fresh Session 重试

### 问题现象

- `_runtime_get_thread_cache@src/lifecycle.c:2246-2255` 的 Semantic Modeler 连续调用 `emit_function_snapshot`，但 payload 始终未通过 snapshot schema 校验。
- 对话最终运行到 `max_iterations=50` 才结束，浪费了大量 LLM 调用和上下文 token，并导致该函数 snapshot 建模失败。
- 现有普通 tool loop guard 未被触发。日志中 terminal tool call 存在重复 payload，但系统仍允许模型在同一 session 中继续提交。

### 根因定位

- `LLMClient.run_conversation_with_tools()` 会先从模型返回的 `tool_calls` 中提取 terminal tool，并执行参数解析和 terminal handler 校验。
- terminal calls 处理完成后会从普通 `tool_calls` 列表中移除。
- 普通工具的 `tool_call_history`、重复签名检测和 `loop_guard_triggered` 逻辑位于该移除操作之后。
- 因此 `emit_function_snapshot` 从未进入普通工具历史，无法触发原有 identical tool call guard；无效 terminal payload 只能依赖模型自行修复或等待迭代上限。

### 重试边界决策

- 保留现有 API 级重试，继续负责单次 HTTP 请求的超时、连接异常、`429`、`5xx`、base URL cooldown 和模型 fallback。
- API 级重试复用同一份 messages，属于同一个 conversation session；全部耗尽后直接失败，不启动新的语义建模 session。
- terminal loop guard 属于成功完成多次 API 请求后的语义协议失败，不能放进 `chat_completion()` 的 API 重试循环。
- terminal guard 触发后，由 Semantic Model 层从原始函数 context 重新执行完整建模；每次创建新的 `SemanticModeler`，从而创建新的 recorder conversation session。
- 初始 session 后最多重试两次，即单个函数最多运行三个完整语义建模 session。

### Terminal Loop Guard 实现

- 为 terminal tool 增加独立的 session 级状态，不与普通工具的 `loop_guard_triggered` 混用。
- 同一 session 内满足任一条件时立即触发 guard：
  - 相同 terminal 失败第 3 次。
  - 任意 terminal 失败累计第 5 次。
- 相同失败签名包含 terminal tool 名、规范化参数和校验错误类型。
- 参数解析失败时使用原始 arguments 文本生成签名，避免不同坏格式全部折叠为 `{}`。
- mixed 或 duplicate terminal calls 中的每个无效调用分别计数；两个阈值同时满足时优先记录 identical failure limit。
- 每次失败先写入 terminal tool result 和 conversation recorder，再检查阈值。guard 触发后立即结束 session，不再请求下一轮 LLM，并显式返回 `truncated=false`。

新增或透传的 terminal metadata 包括：

- `terminal_loop_guard_triggered`
- `terminal_loop_guard_reason`
- `terminal_invalid_call_count`
- `terminal_tool_call_count`
- `repeated_terminal_tool_call`

`terminal_loop_guard_reason` 当前取值为：

- `identical_invalid_terminal_call_limit`
- `invalid_terminal_call_limit`

### Agent 层失败短路

- `JsonToolAgent` 在结构化 payload 提取和 JSON repair 前优先检查 terminal guard。
- 该顺序可以防止 schema 本身合法、但因 mixed/duplicate terminal call 被协议层拒绝的历史 payload 被重新提取并误判为成功。
- terminal guard 转换为失败 `AgentResponse`，使用 `reason=terminal_tool_loop_guard`，并完整保留 terminal、token、iteration 和调用计数。
- 普通 tool loop guard 的行为和 metadata 保持不变。

### Fresh Session Retry Runner

- 在 semantic modeler 包中新增共享 retry runner，输入为 agent factory 和 canonical semantic context。
- 每次尝试都深拷贝原始 context，并通过 factory 创建新的 `SemanticModeler`；失败 conversation history 和 agent 内部状态不会复用。
- 仅当响应失败且 `terminal_loop_guard_triggered=true` 时启动下一 session。
- 成功、普通语义失败、输入错误、API 重试耗尽异常、snapshot 保存异常和 lock 异常均不会消耗 terminal guard session 重试预算。
- 全局建模、入口建模、callee 预建模和按需 snapshot 四条路径统一接入该 runner。
- global、premodel 和 on-demand 已获取的 snapshot lock 在完整重试序列结束后才释放；snapshot 只在最终成功后保存。

聚合 metadata 包括：

- `semantic_model_attempt_count`
- `semantic_model_retry_count`
- `semantic_model_attempts`
- 跨 session 求和后的 context/cumulative token、iteration、API、普通 tool、terminal tool 和 terminal invalid call 计数

`semantic_model_attempts` 逐次记录成功状态、失败原因、terminal guard 原因和各项资源计数。顶层 terminal guard 字段表示最终一次尝试，历史 guard 信息保存在 attempts 数组中。

### 接口与配置边界

- `run_conversation_with_tools()` 新增默认参数：
  - `max_identical_invalid_terminal_calls=3`
  - `max_invalid_terminal_calls=5`
- 本次未增加 CLI 或 YAML 配置项，现有 LLM `timeout`、`max_retries`、base URL 和模型 fallback 配置不变。

### 测试与验证

- 新增测试覆盖相同无效 payload 第 3 次触发 guard、5 个不同无效 payload 第 5 次触发 guard，以及两次无效后第 3 次成功仍在原 session 内正常完成。
- 新增 duplicate terminal payload 回归，确认被协议层拒绝的 schema 合法 payload 不会绕过 guard。
- 新增 fresh-agent retry runner 测试，覆盖 context 深拷贝、新 agent 创建、最多两个重试、非 guard 失败不重试和跨 session metadata 聚合。
- 新增四条实际建模路径的集成覆盖，确认 global、entry、premodel 和 on-demand 均在首个 session guard 后使用新 agent 成功建模，并且只保存成功 snapshot。
- 聚焦测试：`64 passed`。
- 完整测试：`python -m pytest -q`，`838 passed in 160.00s`。
- `python -m compileall -q zscope tests/test_semantic_model_retry.py` 通过。
- `git diff --check` 通过。
