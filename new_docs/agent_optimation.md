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

- 按 `snapshot_redesign.md` 的统一副作用建模方向，更新主路径 `DEFAULT_FUNCTION_SNAPSHOT_SCHEMA`。
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

- 以 `new_docs/plan_docs/snapshot_redesign.md` 第十一节为实施基线。
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
- 未修改 `tools_optimation_plan.md`、fallback、Semantic Modeler、静态 snapshot 或 SnapshotStore 生产代码。

### 测试

- function-info 测试新增精确 key 集合断言，覆盖 backend 和 regex 两条 CodeIndex 路径。
- 为适配当前 schema 的内联 enum 写法，测试改为直接校验枚举值，不重新引入 schema 常量。
- 聚焦测试：`66 passed`。
- 完整测试：`716 passed, 2 failed`；两个失败仍为既有的用户配置宏资源推断问题。

## 2026-07-20 Deterministic snapshot 输出结构统一

### 阶段 0：现状审计完成

- 以 `new_docs/plan_docs/snapshot_redesign.md` 第十二节为实施基线。
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

## 2026-07-20 Snapshot callee call type 保留数组

### 实施完成

- 根据后续决策，snapshot 中 `callees[].call_type` 保留 function info 的聚合数组，不再转换为 scalar。
- 单一调用类型输出 `["direct"]` 或 `["indirect"]`；同一 callee 同时存在两类调用边时完整保留 `["direct", "indirect"]`。
- normalization 会过滤非法值、按输入顺序去重，并将历史 scalar 输入兼容为单元素数组。
- 该变化只作用于 snapshot callee 结构；`callers[].call_type` 和后端原始调用边记录仍保持各自现有结构。
- 已同步 Semantic Modeler schema、`AGENT.md`、deterministic snapshot policy、测试以及 agent/tool/snapshot redesign 文档。
- 本阶段覆盖上文阶段 3 中“转换为 scalar、mixed 类型省略”的旧决策；保留旧记录用于说明实施演进。

### 验证

- 聚焦测试通过：`81 passed`。
- `schema.py` 与 `policy.py` 的 `compileall` 通过。
- 全量回归：`722 passed, 2 failed`；失败仍为已知的 `ZIP_ALLOC` 和 `ANYXML_MALLOC` 宏资源推断问题，与本次变化无关。
- 聚焦 `git diff --check` 只报告 `schema.py:146` 的既有行尾空格；本阶段未修改该无关用户内容。

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
