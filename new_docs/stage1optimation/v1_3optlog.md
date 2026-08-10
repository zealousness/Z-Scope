# Z-Scope Stage1优化更新日志

> time：2026-07-03 至 2026-07-24

# brief

## 架构

- 新增可配置的全局语义建模阶段，通过 SCC 和依赖就绪队列按 callee 优先顺序批量构建 snapshot，并在失败时自动回退到原有 per-entry 流程。
- 统一函数身份为 canonical `index_name`：`func_name@file_path:start_line-end_line`，SnapshotStore、缓存、锁、数据库和调用方均迁移到该身份。
- 全局建模、entry、premodel 和按需 snapshot 四条 LLM 路径统一使用程序预解析的函数信息与源码输入，减少歧义和重复工具调用。

## Agent 与 Snapshot

- Semantic Modeler 改为强制 schema-aware finalization，模型只生成语义字段，身份、源码、调用关系和符号上下文由程序生成并覆盖写入。
- snapshot schema 完成重构：统一 `roles`、`parameters`、`return_values`、`effects`、`error_handling`、`callers`、`callees`、符号属性和 suspicious point 分类等结构。
- trivial/lightweight deterministic snapshot 与 LLM snapshot 对齐为统一顶层契约，并通过 `snapshot_shape_changed` 自动刷新历史旧结构。
- snapshot refresh 指纹扩展到 callees、referenced globals/macros 及 truncation 元数据，代码不变但依赖上下文变化时也会重建。
- `get_function_snapshot` 在 snapshot 缺失或过期时返回最新 canonical function info，不返回旧 snapshot，也不重复暴露完整源码。

## 工具与索引

- 将集中式工具实现拆分为独立模块，并建立 13 个内置工具的统一 Registry、参数校验和 Runtime 执行管线，消除 schema、校验和 dispatch 的重复维护。
- `get_function_info` 支持普通函数、函数式宏、同名函数消歧、canonical identity、callee、全局变量和宏引用上下文。
- `get_callers` 改为 canonical 输入和结构化 caller 输出，按 caller identity 聚合调用行并保留 direct/indirect 类型数组。
- `get_type_info` 支持文件消歧和多候选返回；最终公开结果以 `full_definition` 为类型主体，不再返回 `members`、`id` 或 `tu_id`。
- 函数查询统一 strict-first 和受控 simple-name fallback，支持 name、signature、完整声明、C++ 限定名和陈旧 `index_name`，并避免歧义 overload 被静默选错。

## 质量与兼容性

- 修复宏 self-edge、函数签名顺序、static 属性识别、同名函数锁冲突、类型旧索引失效、临时目录项目宏扫描等问题。
- 数据库迁移采用保守策略：保留 legacy 表和旧 JSON，迁移失败或 identity collision 时整批回滚。
- 最终记录中的完整回归已达到 `726 passed`；工具专项阶段曾达到 `746 passed`。各阶段编译检查和相关文件 `git diff --check` 均通过。

# detailed

## 1. 全局语义建模架构

- 在 `AnalysisConfig` 和 `zscope.yaml` 中增加 `analysis.enable_global_model`，默认关闭，保持原有工作流兼容。
- 新增 `zscope/orchestration/global_modeler.py`，在 shared semantics warmup 后、entry worker fan-out 前执行批量建模。
- 收集跨 entry 的可达调用图，并使用 SCC 和 ready queue 调度；只有 callee 所在组件完成后，caller 组件才进入建模。
- 非 entry 的 trivial/lightweight 函数可直接使用 deterministic snapshot，复杂函数复用 Semantic Modeler；entry 函数始终保留 LLM 建模语义。
- 启用全局建模后跳过重复的 per-entry callee premodel，并优先复用全局生成的 entry snapshot。
- 全局阶段失败时临时关闭对应 entry 的全局模型开关，自动回退到原有 per-entry 建模路径。
- 建模统计覆盖可达函数、缓存命中、deterministic/LLM snapshot、截断、SCC、失败、token 和耗时。
- 修复调用图 canonicalization、`max_premodel_callees=-1` 无限语义以及同名函数锁冲突等早期问题。

## 2. Canonical 函数身份与统一建模输入

- CodeIndex 的函数记录统一使用 `func_name@file_path:start_line-end_line` 作为 `index_name`，路径统一为 source root 相对路径和 `/` 分隔符。
- 简单名、签名、C++ 限定名、模板去除名等继续作为查询 alias，兼顾唯一身份和旧调用方式。
- 新增统一 Semantic Modeler 输入解析层：
  - 通过 `find_function_infos()` 解析唯一函数定义；
  - 支持 `index_name`、`file_path` 和 `start_line` 消歧；
  - 使用 canonical `index_name` 获取对应实现；
  - 校验 function info 与 implementation 的身份和位置一致性；
  - 透传 callees、referenced globals/macros 和 truncation 元数据。
- global model、entry model、premodel 和 on-demand snapshot 四条 LLM 建模路径全部接入统一输入。
- 解析失败在 LLM 调用前终止，并返回稳定原因，如 `function_info_not_found`、`function_info_ambiguous`、`function_impl_not_found` 和 `function_info_impl_mismatch`，同时记录 `llm_called=false`。

## 3. Semantic Modeler 与 JSON Schema

- 将原固定 `code_semantic_modeling` skill 的必要规则并入主 `AGENT.md`，取消运行时固定 skill 拼接，降低 prompt token；历史 skill 文件保留。
- validator_agent 同样取消固定 `evidence_validation` skill 绑定，主 Agent 契约继续承担严格验证、三态 verdict 和证据门槛。
- Semantic Modeler 启用独立的 schema-aware finalization：
  - 支持 structured output 的模型使用 `response_format.type=json_schema`；
  - 不支持 structured output 的模型强制调用 final tool；
  - finalization 和 repair 均保留完整工具会话；
  - 本地语义校验失败后才进入 repair。
- LLM schema 删除程序拥有的 identity/context 字段。模型只输出语义部分，程序在最终拼接时覆盖写入 canonical 元数据，阻止模型伪造身份或依赖上下文。
- 最终 snapshot schema 的主要变化包括：
  - 删除 `location`、`semantic_fingerprint`、`key_semantics` 及旧 `inputs/outputs`；
  - `role` 改为可多选枚举数组 `roles`；
  - 使用结构化 `parameters` 和只描述 C return 的 `return_values`；
  - 将 memory/resource/concurrency/IO/global-state 等副作用统一为 `effects`；
  - 将错误路径统一为 `error_handling.error_paths`；
  - 增加 `callers`、`callees`、`is_static`、`is_inline`、`is_macro`；
  - `suspicious_points.category` 收敛为审计大类枚举；
  - LLM-modeled snapshot 的 `snapshot_kind` 固定为 `LLM-modeled`。
- callee `call_type` 的最终契约为数组：单一类型如 `["direct"]`，混合调用完整保留 `["direct", "indirect"]`。

## 4. Deterministic Snapshot 统一

- trivial/lightweight snapshot 与 LLM snapshot 对齐，固定输出统一的十九个必需顶层字段。
- 仅在数据存在时输出 `referenced_globals_truncation`、`referenced_macros_truncation` 和 `callees_truncation`，并保持 canonical 字段顺序，`code` 始终位于最后。
- 删除 deterministic snapshot 的旧顶层字段：`type`、`is_trivial`、`inputs`、`outputs`、`resources`、`concurrency` 和 `key_semantics`。
- 增加 conservative `return_values`、schema-compatible `effects`、`error_handling.error_paths`、structured callees 和 suspicious point normalization。
- lightweight 静态映射覆盖 logging、lock/unlock、return/goto guard、checked allocator 和 pure expression。
- deterministic suspicious point 最终不再生成或保留 `confidence`；该变化不影响其他分析证据中的 confidence。
- SnapshotStore 会检查 deterministic shape。缺字段、残留旧字段、额外字段或字段顺序异常时返回 `snapshot_shape_changed`，由所有复用路径统一触发重建。
- validation evidence 已切换到新字段；semantic inference 仅保留对历史 `outputs/resources/concurrency/key_semantics` 的显式兼容读取。

## 5. SnapshotStore、指纹与迁移

- SnapshotStore、SnapshotLockManager、内存缓存和公开 API 全部迁移为单一 canonical `index_name` key。
- snapshot/final report 文件名由可读前缀和稳定 SHA-256 短 hash 派生，完整身份继续保存在 SQLite 和 payload 中。
- SQLite snapshots 表改用 `index_name TEXT PRIMARY KEY`，保留函数名、文件和行号作为展示/诊断列，删除持久化 `location`。
- 保存时强制校验参数 `index_name` 与 payload identity 一致，缺失或不一致时拒绝写入。
- 旧复合主键数据库迁移会生成新文件副本和新表，保留 legacy 表与旧 JSON；文件缺失、identity 不完整或 key collision 时回滚，不覆盖旧数据。
- snapshot 指纹最终覆盖：
  - canonical callees；
  - referenced globals；
  - referenced macros；
  - 三类对应 truncation 元数据。
- callee 指纹只使用程序拥有的 `callee_index_name`、`callsite_lines` 和 `call_type`，忽略 LLM 生成的 `callee_behavior`。
- 代码不变但 callee identity、调用行、调用类型、宏定义、全局 initializer/type 或 truncation 变化时，refresh 返回 `symbol_context_changed`。
- global、entry、premodel、on-demand、history reconciliation、scan resume、smart refresh 和 snapshot tool 均使用统一 refresh 语义。
- snapshot 缺失、删除或 stale 时会同步失效对应 build lock，避免旧 `done` 状态阻止重建。

## 6. 符号上下文与索引能力

- KnowledgeDB 新增函数符号引用数据层，记录函数到 global/macro 的引用关系，并支持增量清理和聚合查询。
- Clang/clangd 索引路径提取全局变量的 storage class、qualifiers、initializer、定义类型和引用访问模式。
- `referenced_globals` 对外固定为九个字段：名称、类型、文件、行号、storage class、qualifiers、initializer、access 和 reference lines。
- `storage_class` 收敛为 `static/extern/thread_local/global/unknown`；`qualifiers` 收敛为可多选的 `const/volatile/atomic` 数组。
- `is_extern` 和 `definition_kind` 从公开 referenced-global 结构中删除，但继续保留在内部索引层。
- function-like macro 支持 canonical identity、完整定义、callee 和引用上下文；regex fallback 可从宏体提取调用及符号引用。
- 修复 `_scan_function_like_macros()` 使用绝对路径过滤的问题，使位于 `/tmp` 下的项目不再被整体跳过，同时仍排除项目内部 `.git`、`.venv`、`build`、`tmp` 等目录。

## 7. 工具模块化与 Runtime 单源化

- 将原集中在 `zscope/tools/utils.py` 的 10 个工具拆分为独立模块；`utils.py` 保留兼容 re-export，避免外部导入断裂。
- 新增统一 `build_tool_registry()`，稳定构造 13 个内置工具，并支持 snapshot resolver 注入、基础/高级图工具分组和重名检测。
- 新增通用 `validate_function_arguments()`，由 BaseTool、Agent executor、ToolsRuntime 和 strict ToolPolicy 共享。
- ToolsRuntime 删除 13 份硬编码 schema、逐工具参数分支、if/elif dispatch 和重复执行实现。
- 新执行管线统一为参数补全、policy/hooks、registry lookup、参数校验、negative cache、tool execution、位置上下文更新和 audit。
- Analyzer 改为复用同一 Registry，同时保留 backend 分组、Agent allowlist、Skill/Agent 工具可见性过滤和 on-demand resolver。
- 工具 schema、description、参数校验和执行实现由具体 Tool 单源维护。

## 8. 函数查询与 `get_function_info`

- `get_function_info` 返回 `match_count/matches`，允许调用方显式处理同名函数或 overload 歧义。
- 普通函数 match 包含 canonical identity、签名、位置、static/macro 属性、callees 和 referenced globals/macros。
- callee 按 `callee_index_name` 聚合，调用行去重，direct/indirect 类型以数组保留；各上下文使用固定后端上限并在截断时返回独立 metadata。
- 支持 function-like macro 查询，对象式宏不作为函数返回；普通函数与宏同名时普通函数优先。
- 普通项目函数的 `is_static` 由 backend 显式值优先，缺失时再从 signature 和源码头部推断，并避免 local static、注释或字面量误判。
- 函数查询统一为 strict-first：exact identity/signature/name、精确宏 identity、受控 simple-name fallback、宏 fallback，最后才进入外部函数配置。
- 受控 fallback 支持陈旧 `index_name`、函数签名、完整声明和 C++ 限定名，但拒绝 `#define`、函数指针声明和任意模糊文本，不执行前缀、子串或编辑距离搜索。
- `get_function_impl` 对原始简单名保留旧的确定性首项兼容；由签名、完整声明或陈旧 identity 产生的多候选则返回歧义，不静默选错 overload。
- 实现缓存最终使用 canonical `index_name`，不同查询形式命中同一函数时复用同一缓存项。

## 9. `get_callers`

- 输入只保留 required `func_name` 和 optional `file_path`，内部固定 caller 上限为 20，历史 `limit` 不再影响行为。
- Tool 原样保留 name、qualified name、signature 和 `index_name`，不再提前执行名称清洗。
- CodeIndex 仅在目标函数唯一命中后查询 callers，并按 canonical `caller_index_name` 聚合。
- `callsite_lines` 去重升序，`call_type` 以稳定数组保留 direct/indirect 混合证据。
- 成功结果只返回结构化 `callers`；零命中和多命中分别返回 `function_not_found` 与 `ambiguous_function`。
- 对同名目标使用文件消歧时，无法唯一归属目标文件的 indirect edge 会被过滤，避免错误绑定。

## 10. `get_type_info`

- input schema 增加 optional `file_path`，支持同名类型跨文件消歧。
- KnowledgeDB、CodeIndex、Clang/Unified 和 Joern 增加多候选查询，Tool 统一返回 `match_count/matches`。
- 每个类型定义独立保留文件、行号、kind 和源码定义，避免同名类型事实互相合并。
- 最终公开契约以 `full_definition` 作为唯一类型主体，不返回 `members`、`id` 或 `tu_id`。
- ClangExtractor 从 LSP range 截取完整源码定义，并优先根据源码识别 `struct/union/enum/class`，解决 typedef struct/union 被误标为 class 的问题。
- 增加 type extractor version；旧索引即使源码 hash 未变化，也会在版本变化时自动失效并重新提取。
- Runtime negative cache 使用 `type_name + file_path`，不同文件的类型查询不再互相污染。

## 11. `get_function_snapshot` Fallback

- 未注入 on-demand resolver 时，工具仍通过统一建模输入解析当前唯一函数，并检查 snapshot refresh 状态。
- snapshot 缺失时返回 `snapshot_status=missing`、`reason=no_snapshot`、`data=null` 和当前 canonical `function_info`。
- snapshot 过期时返回 `snapshot_status=stale`、实际 refresh reason、`data=null` 和当前 canonical `function_info`。
- stale snapshot 不返回给 Agent；`data` 只表示当前有效 snapshot 或 `null`。
- fallback function info 包含身份、签名、位置、符号属性、callees、referenced globals/macros 和存在的 truncation metadata，但不返回完整 `code`。
- Semantic Modeler 和 Deep Worker 会直接复用该 function info；只有缺少行为证据时才请求精确源码片段，避免重复调用 `get_function_info`。

## 12. 修复、验证与已知限制

- 已修复 deterministic/lightweight 宏 callee self-edge、clang/LSP 函数签名顺序噪声、同名函数锁粒度、过期 snapshot 误复用、类型旧索引不刷新以及 `/tmp` 项目宏扫描等问题。
- 最终宏扫描修复后，原 `ZIP_ALLOC` 和 `ANYXML_MALLOC` 两个资源推断失败已通过，相关工作簿测试为 `20 passed`，Agent 文档记录的完整回归为 `726 passed`。
- 工具各专项阶段完整回归先后达到 `733`、`742` 和 `746 passed`；后续 snapshot fallback 阶段记录为 `734 passed`。这些数字对应不同实施阶段和测试树状态，不应简单视为单一递增序列。
- 各阶段均执行了相应的 `py_compile`/`compileall`、聚焦 pytest 和相关文件 `git diff --check`。
- 当前仍需关注：
  - SnapshotStore JSON 原子替换与 SQLite 提交之间缺少跨介质事务，数据库提交失败时可能留下孤立文件或 fingerprint 不一致；
  - backend 未提供完整 global/macro 事实时，symbol context 只能反映可用数据，backend 与 regex fallback 的降级能力仍不完全一致；
  - 无 AST reference API 时，复杂别名、指针写入或宏展开后的 global access 可能只能归类为 `read` 或 `unknown`；
  - 旧数据迁移会保留 legacy 表和旧 JSON，需要后续制定清理策略，但当前保守行为有利于回滚和人工核查。
