---
doc_contract: zscope-module-v1
covers:
  - zscope/config
  - zscope/semantics
  - zscope/snapshots
  - zscope/memory
  - zscope/common
sources:
  - zscope/config/config.py
  - zscope/config/preparation.py
  - zscope/config/support.py
  - zscope/config/v3.py
  - zscope/config/v3_preparation.py
  - zscope/config/editor.py
  - zscope/config/runtime_defaults.yaml
  - zscope/config/function_entry.py
  - zscope/config/user_config_store.py
  - zscope/config/protocol_feedback.py
  - zscope/semantics/business_assumptions.py
  - zscope/config/user_config_workbook.py
  - zscope/config/project_semantics.py
  - zscope/config/semantics_workflow.py
  - zscope/config/semantics_migration.py
  - zscope/orchestration/user_config_inference.py
  - zscope/semantics/contracts.py
  - zscope/semantics/standard_api.py
  - zscope/semantics/c_linux_catalog.py
  - zscope/semantics/native_wrappers.py
  - zscope/semantics/resource_coverage.py
  - zscope/semantics/retention_protocols.py
  - zscope/semantics/single_slot_pool.py
  - zscope/semantics/refcount_protocols.py
  - zscope/semantics/handle_protocols.py
  - zscope/semantics/build_scope.py
  - zscope/semantics/call_context.py
  - zscope/semantics/models.py
  - zscope/semantics/instance_semantics.py
  - zscope/semantics/inference.py
  - zscope/semantics/defaults.yaml
  - zscope/semantics/user_config_context.py
  - zscope/semantics/security_map.py
  - zscope/snapshots/store.py
  - zscope/snapshots/readonly.py
  - zscope/common/readonly.py
  - zscope/memory/review_memory.py
  - zscope/review_memory/identity.py
  - zscope/review_memory/store.py
  - zscope/common/issue_identity.py
  - zscope/common/portable.py
tests:
  - tests/test_semantics_workflow.py
  - tests/test_portable_runtime.py
  - tests/test_config_options.py
  - tests/test_config_v3.py
  - tests/test_config_v3_entrypoints.py
  - tests/test_config_v3_preparation.py
  - tests/test_mcp_saved_config_prepare_r37.py
  - tests/test_project_preparation.py
  - tests/test_investigation_runtime.py
  - tests/test_conditional_ownership_contracts.py
  - tests/test_contract_build_scope.py
  - tests/test_contract_usr_scope.py
  - tests/test_lock_modes.py
  - tests/test_native_wrapper_inference.py
  - tests/test_resource_inference_coverage.py
  - tests/test_native_model_cache.py
  - tests/test_contract_symbol_ambiguity.py
  - tests/test_retention_protocols.py
  - tests/test_protocol_feedback.py
  - tests/test_single_slot_pool.py
  - tests/test_refcount_protocols.py
  - tests/test_refcount_integration.py
  - tests/test_handle_protocols.py
  - tests/test_handle_integration.py
  - tests/test_audit_coverage.py
  - tests/test_semantic_cache_only.py
  - tests/test_config_migration.py
  - tests/test_concurrency_config.py
  - tests/test_user_config_workbook.py
  - tests/test_project_semantics.py
  - tests/test_user_config_workbook_readme.py
  - tests/test_risk_api_semantics.py
  - tests/test_user_config_overlay_new_kinds.py
  - tests/test_clang_cfg_custom_apis.py
  - tests/test_user_config_inference_new_roles.py
  - tests/test_llm_review_new_roles.py
  - tests/test_parallel_custom_prompt.py
  - tests/test_semantic_contract_chain.py
  - tests/test_semantic_contract_schema.py
  - tests/test_instance_semantics.py
  - tests/test_wrapper_failure_guards.py
  - tests/test_wrapper_error_cleanup.py
  - tests/test_wrapper_pointer_casts.py
  - tests/test_acquisition_carrier_consumers.py
  - tests/test_contract_only_publication.py
  - tests/test_pair_evidence_authority.py
  - tests/test_incremental_semantic_modeling.py
  - tests/test_semantics_defaults.py
  - tests/test_security_semantic_map.py
  - tests/test_security_map_contracts.py
  - tests/test_snapshot_store.py
  - tests/test_review_memory.py
  - tests/test_review_memory_acceptance_gaps.py
  - tests/test_review_memory_replay.py
  - tests/test_issue_dedup.py
---

# 配置、语义与状态

LLM profile 的 `context_window`（默认 192000）与 `model_context_windows`（按精确请求模型名覆盖）在 唯一 v3 正式 parser，并进入客户端与模型配置身份。默认 `max_tokens` 为 8192。窗口声明 endpoint 的单次输入加输出容量，不是扫描预算；不自动根据模型名称猜测，应按实际 endpoint 配置。运行时使用实际请求输出上限与 schema 预留空间，具体证据保留和窗口不足行为见 [Agent 运行时](agent-runtime.md)。

deep 的人工边界和进程常驻声明放在现有 `zscope.semantics.yaml` 的可选 `lifecycle` 中，公共扫描 YAML 不新增字段。`boundaries` 每项为 `id/level(feature|module)/members/confirmed`，members 使用本轮 `hierarchical_contracts.json` 导出的精确 `FN_...` ID；多 TU 成员仍须属于真实链接组。`lifetimes` 每项为 `id/build_context_id/object/lifetime(process)/reason/confirmed`。未经确认的声明仅作假设；常驻声明不豁免覆盖丢失、重复分配、无界增长或锁责任。保存、撤销及重新绑定保留该段，整个文档继续进入冻结输入与缓存身份。

`hierarchical_contracts/` 存放逐单元内容寻址缓存；键包含当前函数事实、成员/调用/链接依赖、子摘要、生命周期声明、模型及推理契约版本。`hierarchical_contracts.json` 导出可评审摘要和边界，`rule_proposals.json` 导出带裁决状态的规则提案，均不自动启用规则。取消后的已完成单元可在相同输入下复用；源码、构建、链接、声明或模型改变会使对应依赖失效。功能组合和责任传播消融通过离线 `HierarchicalDiscovery.run(compose=False|propagate=False)` 执行，缓存身份和结果记录消融参数，不混用生产结果。

ConfigLoader 只解析 v3，YAML 支持同一模型中的可选范围、Wiki、规则、后端和并发设置；v2 仅经显式 migrate 转换文件。所有配置以实际加载的 YAML 文件所在目录为唯一工程根，公共文档禁止 project.root/source_root；内部 ProjectConfig 只保留 project_root；target 身份全部保留，当前执行组合只允许一个 target，不能偷偷选择首项。scan.preset 统一 fast/balanced/deep，与执行深度同名；Java 当前仅 fast，不启用实验规则。旧 quick/overnight 不再作为别名接受，只能通过显式迁移转换为 fast/deep。IANA 时区和 stop_at 解析为本轮绝对边界，DST 不存在或重复时刻明确拒绝；CLI 和新建持久作业已消费该边界，创建时若解析出的配置窗口已过则以 `stop_window_closed`（400）拒绝，不再接受开局即停的作业；resume 不重新套用配置窗口。focus/reproduction/max_workers/platform 目前保留声明并附 wiring 状态，不等于实际执行。新 v3 默认 SVF 单进程上限为 8192 MiB，可通过 indexing.svf.heap_limit_mb 显式调整。迁移 v2 时保留旧默认 32768 MiB。两语言 parser、初始化器和 Web 的默认 preset 统一为 fast；迁移历史 v3 会显式保留旧省略值 deep。CLI prepare/validate、初始化器与语言模板已使用 v3；MCP 的创建路径已随同一作业服务消费该检查，其余执行消费端仍有剩余。

C/C++ public v3 声明工程内相对路径 `project.semantics_file`；Java 禁止该字段。旧配置仅由显式迁移器处理； discovery 和 scan 缺少此文件时明确失败。CLI 与 Web 创建工程都同时创建主配置与空语义文件，任一目标已存在时拒绝覆盖，失败回滚本次创建的文件；`zscope-config migrate-semantics` 及 Web 的同源迁移入口提供 XLSX 单向迁移，保留工作簿。

`config/semantics_workflow.py` 是首次就绪和输入当前性的共享边界。未声明、待发现、发现中、待审阅、需重新发现、可扫描由 YAML、内容寻址机器证据及当前 native 依赖计算。空文件不能就绪，零候选也必须显式完成审阅。发现收据的 workflow 摘要覆盖源码集合、编译配置、依赖、工具和原语规格；human_review 绑定决定摘要及 evidence_ref。候选确认/拒绝不要求重跑发现，但要重新完成审阅；根原语撤回或规格变化使依赖契约重新核对。旧收据无充分输入时明确要求重跑，不能仅凭时间或 confirmed 数量升级。

发现的当前性检查同时核对 native 工具及共享库。完整普通 include lookup 收据可以绑定全部可能查找名称及不存在候选，避免扫描报告或队列新增导致无意义的重新发现；更高优先级头文件、无常规后缀的存在性查询和符号链接变化仍使证据失效。不完整或不支持的 lookup 保留完整目录检查，不能通过通用“输出目录白名单”放宽。扫描中重新冻结验证快照仍使用核对过 job/run/owner/input 的运行输出范围。

`zscope-config review-semantics` 默认只读，`--declare-none` 明确声明无已知自定义原语，`--complete` 在共享校验通过后写入审阅摘要。Web 表单、逐项/批量审阅与高级 YAML 使用同一正式校验器、文档版本和跨进程工程锁，保留注释和扩展字段；机器收据不能从编辑器伪造。普通扫描只读，任务数据库不授予契约权限。

契约编译器 v30 在 native 包装推导中显式传递调用事件的精确 callee USR，避免独立发现缺少扫描 call-context 时把已绑定项目包装器当成未知调用；同名异身份仍不能互相授权。配置路径锚定后继续指向语义 YAML，业务回答摘要从同工程 `.zscope_snapshots/user_config.state.db` 读取，不能将 YAML 当作 SQLite 或回落到旧工作簿。

契约编译器 v31 保留经审阅的 `may` 作为可信的可能效果供候选发现使用，但满足守卫时的调用适用性仍为 unknown，继承的协议转换也不得成为确定效果；明确不满足守卫时仍为 does_not_apply。结构化报告保留 may，不标成 must_under_guard。该版本变更撤回旧缓存权限，避免 void 锁包装器或丢弃 close 结果的包装器凭人工确认闭合锁/资源责任。

发现阶段的 pending 状态和 may 强度分别表示“尚待人工授权”和“效果可能发生”。可能效果可以有 applies 守卫，不能仅因待审阅而把全部 case 写成 unknown，造成确认后仍无法执行。源码提案先用假设 confirmed 的正式 schema 校验，再以 pending 保存；参数/成员路径、引用、条件冲突和不支持的协议在落盘前请求修正或留下缺口。输入对象阶段为 pre，返回/出参对象为 post；宏还必须映射条件中的参数与常量，不能只改 carrier。源码模型提案的当前支持范围及调用边界见执行与编排模块，native 确定性推导的受限范围保持独立。

标准 API 的旧名称分类仅用于词法检测，不能在类型化目录之外生成参数默认为 0 的效果契约；加载和合并都保持该边界。已有精确目录的 API 只使用其中的 typed effects，例如 receive 的目的参数与整数描述符分开，send 不被名称分类伪造为 copy。

目标的返回类型与可观察返回值分开校验：void 目标不得引用返回值或借用被调者状态；可变参数的省略号不抹去固定参数类型。效果对象范围不限制守卫读取源码中的 global.NAME。返回结构的独立分配成员属于额外所有权输出，不能在删除初始化 copy 时一并丢弃。直接调用形式的宏若不能替换输入守卫，可在既有三次上限内请求有源码依据的等价返回守卫；不猜 sizeof 或具体返回常量，无法闭合的宏映射单独记录为 macro_guard_gaps。

v14 提案逐函数裁决并精简重复证据，支持目标参数名和受限 guard 表达式，使用当前 native callable 签名核对参数类型。有正向提案或结构错误时进行第二次源码反证复核；仅简单且完整的证据使用普通模型复核；调用图不完整、多节点/多分支组合、成员对象、多条款、返回值或全局条件上的 no_effect，以及 native 偏移矛盾启用推理。保守 may 不会绕过复杂证据的复核。仍有结构错误时允许第三次修正；结构完整且简单的首轮合法空结果可直接结束；复杂调用图、偏移反证或缺失上下文的空结果也需要复核，调查完成计数不等于否定证明。模式选择及原始响应分别归档，不能以节省成本为由减少调查单位。没有 no_effect 声明时只保存 unknown；不会由正向效果推导排除条件。

`primitive_object_evidence` 从当前 native 变量 USR、赋值链、调用实参与已核验标准根提取偏移反证，阻止将内部地址释放或可能向根对象之前写入的目的地址抹成参数根。它只拒绝当前证据冲突，不证明其他对象流或边界安全，也不替代 Validator。模型需分别枚举调用者对象的 copy、recv_source 和 io_release；局部缓冲或局部描述符成员不截断这些对外效果，零字节路径不能单独支撑实际写入的 must。

recv_source、send_sink、command_sink 和 I/O 获取/释放提案还必须有该目标证据图中已解析的对应根；普通输入缓冲的读取或复制、变量名和业务消息分派不能生成外部来源。该检查只约束证据可采纳性，不证明对象别名。反向 no_effect 覆盖同对象的全部相关操作：失败前写入、结构体清零影响其成员、负数转长度和返回值截断均不能忽略；UB 不授权“无效果”。本次分配对象的初始化不能绑定成传入旧对象的 pre 阶段 copy。

宏传入 `&global` 时保留地址身份，条件求值需要地址对象事实，不能拿全局变量的存储值代替地址。宏所在 TU 与函数实现的 BuildContext 可以不同；传播要求真实链接组内唯一实现及当前调用方的精确 callee USR，同名、未知链接或多个实现不能授权。派生宏保留调用方自己的构建身份。系统 ABI 目录 v2 额外接受实测 glibc strict-C 的 accept sockaddr 指针声明，仍逐构建核验标准来源和 USR，不放宽为按名称授权。

public v3 不暴露 legacy `entry_function` / `entry_functions_list`，组合到执行配置时默认启用确定性入口发现，使 `zscope-init` 生成的单 target 文档可直接扫描。入口只提供可达性和暴露面归因；C/C++ fast 的项目级静态候选发现仍覆盖全部当前函数实例。`--discover-entries` 可显式请求同一行为，`--plan-entries` 只预览并退出。

`config/editor.py` 为结构化编辑提供原始文档投影与同目录候选校验，保留所有 profiles、环境变量引用和相对值。默认校验仍严格展开环境变量；Web 创建/编辑可显式使用 `expand_environment=False`，仅在校验副本展开当前可用变量，保留尚未设置的模型连接字符串占位符，保存内容不含展开后的凭据。该模式仍调用正式 v3 parser；未设置的数值、时区等无法满足结构约束时明确拒绝，不伪造值。执行与 prepare 始终要求完整环境，文档可保存不代表当前可执行。v3 调用正式 parse-only 模型，不能为了保存多目标而强迫执行组合；v2 在所有入口统一拒绝并指向显式迁移。候选按进程/线程隔离，验证失败不替换原文，成功后原子替换；当前接口没有配置 revision/CAS。初始化器正确序列化用户路径及目标标识，避免 YAML 注释或冒号改变工程身份。

v3 schema 由模型字段表和条件表生成，包含时窗依赖、语言与 target 数据库条件及解析正规化的边界；IANA/DST、跨项 target id 唯一性、有效配置单 target 组合等运行时约束单独披露，不声称 JSON Schema 能表达全部语义。

人工 baseline 的精确键匹配和源码窗口/稳定指纹回退均要求相同构建身份；缺少身份不是通配符。Web 对已知构建的误报反馈只写入该构建的 baseline，不再额外生成按位置匹配的宽泛 suppression。旧位置 suppression 仅适用于未知构建的候选，不能覆盖已绑定编译实例的发现。不同构建的事实、缓存、去重和人工反馈隔离由 `tests/test_candidate_build_identity.py` 共同验证。

只读 MCP 使用 ConfigLoader 的内部 read_only 加载路径，保留严格 Config v3 校验并跳过 rollout 持久态、扩展 provider 预检及 usage 注册。只读快照打开不创建目录或迁移表；checkpoint 后 SQLite 用 immutable/query_only 读取，活动 WAL 明确不可用。旧快照缺完整输入身份时返回 unverifiable，源码摘要匹配不代表头文件、构建或契约仍有效。正常扫描加载与默认刷新不变，详见 [只读 MCP](../mcp-read-only.md)。

## 职责与非职责

业务前提回答保存在独立状态库的 `protocol_assumption_answers`，每次修改追加版本。键绑定前提文本、事实种类、BuildContext、入口、ObjectRef 及源码/契约依赖；它与 `zscope.semantics.yaml` 的接口授权相互独立。模型输出、普通复核文字及旧报告本身不授予业务约定或原语权限。

本子系统负责解析和校验用户配置、合并内置/项目语义、维护快照和人工反馈状态，并提供稳定 finding identity、取消和运行限制等公共设施。它连接用户领域知识、历史分析结果和当前扫描。

它不负责选择 CLI 运行模式、不实现后端索引，也不决定报告的展示格式。

## 主入口和数据流

- `ConfigLoader` 只读取严格的 `UserConfigV3`，再与打包的 `RuntimeSpec` 组合为 `EffectiveConfig`；`ProjectConfig` 负责项目路径解析。旧配置须通过独立迁移命令转换后才能加载。
- `preparation.prepare_project` 供 CLI `zscope-config prepare` 与 Web `GET /api/scan/prepare` 共用；调用方以 `read_only=True` 加载严格配置，跳过 provider、rollout 和 usage 持久态。准备视图列出实际路径、编译命令去重与变体、工具存在性及配置中的扫描模式，不启动子进程/模型、不生成索引或改写工程；未知链接归属保留为未核验，模型凭据与 endpoint 不进入结果。
- `v3_preparation.prepare_saved_config` 为 CLI、默认 Web saved-config 准备和 MCP `zscope.config.prepare` / `zscope://config/preparation` 提供同一 v3 只读合同。MCP 只绑定启动时已保存配置的路径（先 `expanduser()` 再 `resolve()`），请求时重新读取，default profile 自动创建的作业 adapter 复用同一保存路径并保持懒绑定；default/read_only 还需通过各自 profile 与 ToolPolicy，candidate_blind 保持不可见且不可调用。准备保留全部 targets、未消费字段与 start capability，不授予执行权限；fresh MCP 启动仍先走单 target 组合，多目标禁启及 focus/reproduction/max_workers/platform 未消费边界保持不变。接口细节见[接口与报告](interfaces-reporting.md)。
- public YAML 顶层只允许 `config_version`、`llms`、`project`、`scan`、`indexing`、`concurrency` 和可选 `rules`。`project.language` 只能显式为 `c_cpp` 或 `java`。
- `scan.preset` 公开为 `fast|balanced|deep`；CLI 的 `--scan-depth` 高于 YAML，YAML 高于打包默认。省略 preset 解析为 `fast`。public config 不提供 scan-wide token 预算字段。
- 三档不带产品侧 token 上限；Range Benchmark policy 分别维护完成后成本预期，并按 agent/stage 的真实 usage 验收。
- `runtime_defaults.yaml` 管理 Agent 启用状态/LLM 角色、分析预算、缓存、报告策略和稳定算法默认值；`AGENT.md`、`SKILL.md`、workflow YAML 不在此重复。
- Review 实验开关仅属于 RuntimeSpec：`validation_review_checkpoint`、`validation_review_protocol`、`validation_checked_proofs`、`validation_positive_case`、`validation_related_findings` 默认均为 false。checkpoint 单独启用时只保留完整事实和前序结果，不向模型新增事实工具；protocol 组只改变封套与验收；checked_proofs 组才启用共享编译器事实和检查工具。正面举证不修改现有置信度门槛。实验期间禁用候选结果缓存，避免复用缺少封套、事实增量或有效签名的结果。
- 根目录 `zscope.c_cpp.yaml` 与 `zscope.java.yaml` 是语言隔离的精简参考文件；Java 不接受 SVF/clang/compile database，C/C++ 不接受 Java provider 字段。
- `Z_SCOPE_RUNTIME_SPEC` 只在 `Z_SCOPE_DEVELOPER_MODE=1` 时接受绝对覆盖路径。有效规格版本、来源和 SHA-256 进入配置哈希、缓存身份及报告 provenance。
- `ProjectSemanticsStore` 是 C/C++ 项目接口的唯一人工权威；`UserConfigStore` 仅保留 suppression、baseline、业务回答等反馈状态，XLSX 只用于一次性迁移。
- C/C++ 规则合并当前 native 验证的 packaged catalog 与 YAML 中当前证据支持的 confirmed project contract。`--discover-primitives` 扫描全部精确函数实例、宏、pointer slot 与 dispatcher，但只把效果跨边界可观察、ObjectPath 精确且由规则消费的高信号接口放入人工门禁；普通 standard-operation 薄封装和未完整映射操作数的 copy helper 保留为机器事实。当前 standard-operation 自动提升仅限路径协议规则能够重放的 `access/stat/lstat/faccessat/fstatat` 委托。宏发现对精确 native 定义收据求 wrapper 传递闭包，因此 `PROJECT_LOCK()` → `LOCK(&g_lock)` → 已知锁原语可在同一次 discovery 中全部列为待复核候选。无参数宏中的精确全局实参编译为 global ObjectPath，不能伪造 argument 0；无法映射的表达式保持未知。dispatcher 仅在精确 handler 已进入当前高信号接口闭包时生成审核行；普通业务 switch 不进入语义 YAML。confirmed dispatcher 通过兼容投影提供 `dispatcher_name/file_path/message_type`，保证 graph 规则实际消费审核结果。pointer binding 只有在当前证据闭合出 exact target set 时才写入人工 YAML，未闭合 callsite 只进入 discovery coverage gap 并使 formal qualification 保持失败。正常扫描只读，不运行接口发现或相关 LLM。名称线索只用于候选排序，不授权角色。
- Discovery 的 wrapper 闭包以 BuildContext 为边界；只有当前、闭合的真实 link record 才允许把已确认根和候选沿跨 TU 精确 USR 传播。为重新核对人工 confirmed/rejected 行，冻结集合还必须包含这些接口的精确定义实例，不能只冻结每个构建的一条代表 scope。对象工厂只有在 native def-use 同时证明“可信申请结果绑定到返回局部变量”和“同一对象的直接成员由可信申请接口赋值”时才产生 pending 的 return/member ownership；底层 `calloc` 的参数 extent 属于被调函数，不能投影到高层工厂的无关参数，外层统一发布为 `may allocator` 并保留来源边等待人工确认。
- C++ discovery 还可从当前 native AST 的精确 `CXXNewExpr` 提取直接返回的 pointer factory，并把该 factory 作为根识别“返回局部聚合的成员在空值 guard 下由它创建”的接口。两类候选都保存精确 USR、签名、文件和 BuildContext variant，初次只写 `pending`；人工确认后，普通扫描的 current rebind 会重放 `CXXNewExpr` 或 `project-cxx-new:<USR>` 根，不能退回按函数名授权。
- 人工确认的 `primitive:true` 是项目级可信根；其 `derived_from` 记录审计来源，不要求公开原语继续直接调用某个内置 API。`derived_wrapper` 和宏仍重放其直接来源关系。重新绑定遇到未闭合跨 TU caller 时，只为定义 TU 与当前真实 link record 成员编译可执行 contract，组外 caller 不授权；`current_rebind.ready` 保持 false 并阻止 formal，但 fast 仍执行内置语义和可证明的本地单元。
- `security_map.db` 是独立于历史函数 snapshot 的只读安全语义 sidecar：零 LLM 骨架记录入口、调用、危险事件和 backend coverage；有证据引用的选择性 LLM delta 才能成为 claim，无可解析引用的内容仅是 observation。
- Security Map 的项目接口事件使用实例级 Registry 和共享调用解析器，记录实际对象、资源域、条件、BuildContext、证据来源及 catalog/YAML 版本；名称摘要不决定接口角色。native 证明、用户 external assumption 与 LLM advisory 必须可区分，调用可达性仍需另证。
- snapshot policy 决定完整、轻量或语法快照，store 负责持久化与复用。
- 条件观察与按需建模的两个内部开关分别为 `analysis.semantic_snapshot_candidate_mode`、`analysis.semantic_model_demand_mode`，仅允许 `off|shadow`，默认 `off`，不进入 public Config v3。前者开启时将条件观察 schema 纳入建模规格指纹，关闭保持原 schema；后者只记录需求计划，不改变快照输入身份或实际建模调度。当前会话的观察绑定不能从持久 JSON 恢复为权限。
- 受控动态复现的内部开关为 `analysis.dynamic_reproduction_mode`，仅允许 `off|shadow|on`，默认 `off`，不进入 public Config v3；配套字段限定复现次数（1..16，max ≥ required）、单次超时（1..3600 秒）、整轮验证墙钟上限 `dynamic_reproduction_deadline_seconds`（默认 900，可经 RuntimeSpec 调整）、内存上限、输出捕获上限（字节）、artifact 发布目录、授权 TTL 与隔离模式（`process|user_net_namespace`）。`off` 完全惰性：runner 边界拒绝执行、`availability()` 不探测工具链、扫描接缝不改动 issue，不编译、不执行、不注册授权；`shadow` 执行并记录 provider 元数据但不授予确认权限；`on` 才允许合格 witness 进入现有确认通道。非法的输出上限、TTL、deadline 与复现次数组合在策略校验期直接报错；策略不可用只让该能力保持惰性，不使候选扫描失败。approved-plan provider 只存在于当前进程（单槽，可从磁盘恢复不了）。复现次数按“一个 plan 的执行总次数”计量：一次 `execute()` 只跑一轮（含计划授权的 build），调度器把 `max_replays` 先分 1 次给主执行、其余留给策略要求的独立重放，不足时记录 `dynamic_reproduction_budget` 而不提前拒绝；执行预算与墙钟 deadline 都绑定到 runner，计量真实进程启动，重放不能放大授权。
- 当前启用任一语义实验，或历史报告含实验统计时，resume/maintain 不复用历史报告，以免把旧统计或观察资格当成本轮结果；函数建模缓存仍按各自输入身份判定。K01 首版仅在可核验的自包含项目、当前实际建模与发布输入一致时授予观察登记资格；存在或配置编译数据库、外部依赖、无法重核的自定义 schema 或超出库存预算时均不授予资格，不推断 TU 证明。热缓存继续供背景读取，不重新授予独立观察权限。
- Discovery 原始 native/LLM 证据和 schema 错误写入 `.zscope_snapshots/semantics/`；YAML 只保留可读摘要、引用、摘要哈希和人工状态。无法证明的提议保持 pending/unknown，不进入执行 Registry。契约编译器、catalog、native 工具与证据摘要都参与失效。
- 接口提案的原生上下文显式区分参数对象的指针槽赋值、调用结果写槽和格式串操作数；这些观察帮助模型复核旧对象与新对象、目的缓冲区与格式输入，不构成路径证明。NULL 清槽不能满足必定注册可调用回调的声明；只有回调调用而没有函数指针存储或注册根的完整事实不能支持注册。锁初始化/销毁不能替代对应 lock/unlock 根，丢弃 close 结果不能授权必定释放，字面量格式操作数不能使目的缓冲区或插入数据成为 format_sink。普通字段记账、只读字符串处理和转发不需要独立契约，真实缓冲区/输出参数及系统操作仍需保留。完整 native 事实中标量成员不能当作缓冲区，只有字段状态更新且没有缓冲区操作或间接/下标写入的成员 copy 另记 `filtered_contracts`；它不授权安全结论，也不伪装成调查失败。初稿仅被过滤时仍复核其他独立效果，调用图及证据复杂度同样决定是否启用推理。重绑定 out 指针的对象代次缺口保留诊断；旧代次写入、重绑定前别名、身份歧义或不完整 CFG 不得据此过滤；透明转发只沿实际 USR 和实参映射检查。相同对象、角色、条件、协议与配对的 must 提案包含 may；不同条件不合并。首轮与复核均保留完整范围约束；每轮携带完整源码和最新完整声明集，不累积旧草稿及重复理由。长证据 ID 仅在请求传输中映射为局部短引用，响应先恢复原 ID 再做既有精确身份与引用检查；源码、表达式和对象名不重写，完整映射与原始响应留在审计中。反证响应截断时，下一轮保留其输入草案和具体错误，不拼接截断文本，也不丢掉待修正内容。`may_under_guard` 只规范为同义的 `may`，不得升级为 must。三轮边界、完整调查范围及人工确认要求不变。
- 同一进程内，多个 Analyzer 首次打开同一快照数据库时，共用规范路径锁完成 schema 检查、建表及迁移，再进入建模任务协调；不同数据库的初始化仍可并行。
- 语义复核已完成但仍有带索引的 schema 错误时，剩余一轮只修正或明确删除这些被拒条款；不重新挖掘、不新增条款、不改写已接纳条款。程序检查差量范围，防止格式修正重新添加刚被反证排除的内部效果。复核响应截断、整体协议错误或宏守卫仍需语义改写时，不冒称已完成语义复核。失败仍保存已有有效条款并标记未完成，三轮上限不变。

- 接口反证复核使用逐条差量：未提及的声明原样保留，修改或删除必须指向当前草稿索引并给出理由和当前源码引用；允许复用替换条款中的理由和当前条款的源码引用，审计记录实际引用来源，不要求重复填写。最新条款的理由作为当前见证保留，旧草稿及整段历史解释不重复发送。修改后的全部条款仍经原 schema、对象和身份检查。引用和理由仅供审计，不构成确定性证明。完整列表的兼容响应不得悄悄丢弃已接纳的独立效果；无效条款允许直接修正。复杂声明执行有界反证推理；按实际完整草稿与复核响应判断是否完成，不能把首轮截断后的首次合法输出当作已经复核，三轮上限不变。no_effect 按排除场景展开检查，不以正向守卫成立替代反向核验；must 单独检查守卫成立时的提前返回、可空输出和被调者失败。精确构建与 USR 绑定的被调者若同样丢弃所有描述符释放结果，也不能把外层返回值当作成功释放；缺失或歧义上下文不触发该诊断。真实 native 全局变量（同名无歧义）允许将裸名称正规化为 global 操作数，不把局部量或枚举猜成全局；字段声明的项目内短源码片段帮助区分内联数组和指针槽，不授予额外证明。copy/recv 的 const 校验按所选择的指针层级进行，`const T**` 的可写指针槽与只读 T 分开，槽写入不意味着新所有权。参数成员守卫仍表示调用前状态，无法表达的写后字段条件不能用来排除真实效果。
- `ReviewMemory` 是验证反馈门面；`issue_identity.py` 为报告、baseline、SARIF 和 benchmark 提供统一身份。

独立的 `zscope/review_memory/` 归属 [Validator Review Memory](review-memory.md)，
保存项目级误报模式与 advisory context。其状态、抽取、匹配、回放及当前限制见该文档；
本模块继续负责 `zscope/memory/` 的既有 baseline/suppression 门面与公共配置。

### 最小配置与自动 native 推导

`semantics/automatic.py` 在实例语义工厂内计算当前精确 BuildContext 的确定性闭包。根仅来自该构建已授权的内置 API，不读取模型提案，也不以项目配置作为独立自动推导的种子。复用现有 native 资源包装器，并支持当前 C 源码中受限的单调用转发：参数对象保持、调用结果直接返回，允许可表达的提前返回。按真实 callee USR 调度依赖者，一个构建只计算一份，再由同构建的实例模板复用；模型调用为零。

自动契约保存在工厂签发的 `automatic_derivation` / `automatic_contracts`，不写入用户 YAML。与已确认配置分别归因，配置仍按已有 Registry 覆盖规则生效。当前源码、编译输入、标准根和推导程序的变化使旧快照失效；磁盘上的推导 JSON、置信度或历史确认不能自行取得当前执行权限。直接 native 资源核验失败不回退到词法资源推导。

自动效果可通过唯一、当前的真实 C 链接记录传给实际调用它的 TU。定义构建与消费构建分别记录，必须核对原 native body 摘要；缺失或歧义链接不导出。源构建、原生工具、标准头文件、对象或链接产物变化会撤回导出效果。当前尚不使用跨 TU 导出效果再次推导其他包装器；一般跨 TU 组合、宏转发、复杂对象/状态、一般协议和 C++ 生命周期保持原有路径或显式缺口。

单调用转发不接受参数改写、偏移、重排或默认参数、循环、隐藏结果所需的成功条件或未核验的整数转换；已识别的局部效果也不证明函数没有其他效果。扫描 metadata 的 `project_semantics.automatic_by_build` 报告推导单位、契约数、链接导入数及缺口，不将未推导函数自动解释为需要用户配置。当前自动闭包仅以内置根为起点；已确认自定义原语仍由现有项目配置和发现流程消费，尚未纳入这一独立闭包。

已授权项目条款与自动条款按精确 BuildContext/USR 对齐 native 符号表示，避免 YAML 相对路径和 native 绝对路径制造虚假重载。配置覆盖同一效果时，由 Registry 维护配对边，不重新加入已被覆盖的自动配对；其他编译变体不参与对齐。

`configuration_requirements` 区分完整效果命题相同、仅对象边界相同但条件/协议不同，以及未自动推导。只有完整命题等价才标记当前条款可由自动事实替代；不根据函数同名或有同一种 role 建议删除。它不宣称全工程最小配置。实际必要性还要比较规则消费和候选差异，使用 `scripts/audit_semantic_configuration.py --config <工程配置> --output <新文件.json>`；该命令执行内置、内置加自动推导、再加已确认配置三组 native 本地候选及 call-effect 对照，不执行 LLM，不改写 YAML，不属于正式 unified 评分。
## 必须保持的不变量

- 接口契约的 `to_dict` 是 JSON 边界：内部配对保持不可变 tuple，输出为数组；从共享报告导入的条件、证据等对象必须可以再次序列化，修改导出值不得污染原契约。纯表示转换不能改变结构指纹、契约版本或证明权限。

- 产品运行时不解析 v1；旧字段只允许由 `zscope-config migrate` 读取。未知键、重复 YAML 键、错误类型、非法枚举和未展开必需环境变量必须失败。
- public YAML 不能包含 Agent、analysis、reporting、workflow、缓存、逐 Agent 轮数、rollout 开关或 scan-wide token 预算；扫描档位是明确允许的公共资源控制。
- Java 尚未通过独立门禁，只接受 `fast`；显式请求 `balanced/deep` 必须报错，不能静默降级。C/C++ 默认切换到 balanced 之前仍以 fast 解析省略值。
- `rules.disabled_ids` 优先于 `enabled_ids`，同一 ID 同时出现时以禁用为准；表内重复或未知 ID 必须在启动外部工具/LLM 前失败。未通过资格的新内置规则必须是 experimental 且默认关闭；遗留 stable/pending 规则只保留迁移期兼容，正式发布门禁会拒绝任何默认启用但未 qualified 的规则。
- C/C++ 后端只能显式为 `unified|clang|regex`，Java 只能为 `java_unified|java_source|joern`；深度后端不可用时不得静默切换到弱后端。
- `scan.task` 空串必须激活当前语言全部适用 Skill；非空文本只覆盖审计重点。
- `concurrency` 的全部字段必须是正整数，并由调度、索引、SVF、Validator、evidence completion 与 LLM 全局限流统一读取。
- CLI/Web/MCP 加载的 YAML 所在目录就是工程目录；跨 CWD 调用不改变工程身份。公共 `project.root`、`project.source_root` 即使为 `.` 也拒绝，不能仅删除外置配置中的键来迁移。初始化器默认在 `--project-root` 目录创建 `zscope.yaml`，显式 `--output` 也必须直接位于该目录。
- 编译数据库、入口列表、include/exclude、发现范围、KnowledgeDB、snapshot 和默认 user config 的相对路径统一基于 YAML 目录；运行时解析出的绝对路径不回写 YAML。
- `zscope-config migrate --input OLD --output PROJECT/zscope.yaml` 显式迁移旧键并保留原文件；输出必须在旧配置的实际工程根。旧 v2/legacy 的相对 root 还需 `--legacy-working-directory ORIGINAL_CWD`，旧 v3 相对 root 按旧 YAML 目录解释。两个旧根不相同时拒绝自动迁移，要求先明确整理 include/exclude 与 discovery 路径，避免改变扫描范围。旧 preset 按实际深度 quick→fast、overnight→deep 转换。
- YAML 只在 discovery/人工编辑时更新；正常扫描不得修改。相同证据下的人工 confirmed/rejected 决定不能被自动覆盖，证据变化或候选消失时标为 stale，不静默删除。
- 用户可在首次 discovery 前把已知函数原语写成 `primitive:true,status:confirmed`，并提供 name/file/signature/USR 精确 selector；此时尚未知的 BuildContext variant 只由 discovery 的专用读取路径暂时接受。discovery 必须把它重绑定为当前 native exact variant，证据变化后转为 stale 供再次复核。普通 validate/prepare/scan 仍严格拒绝没有 variant 的 confirmed 行，不能把这条引导能力当成执行授权。
- 项目接口必须经过 YAML readiness 和实例身份发布屏障进入统一 `ContractRegistry`。`derived_from` 的已复核来源边会编译为实例契约的 delegate，使规则能够沿精确 wrapper 追溯实际原语；来源边不能由名称或 LLM 建议补造。配对保存接口自身的有向边，并只沿已确认的 `derived_from` 层次补入同资源族的项目 release wrapper，不做无证据的共享释放端传递闭包；合法释放仍必须匹配对象、BuildContext、条件和资源域。契约编译器 v29 使缺少这些来源边的旧缓存失效。
- 载体的 `address_of` 保留取地址关系，`p` 与 `&p` 不可互换。条件比较中的地址也必须有精确地址表达式的调用方事实；变量保存的空值或对象身份不能代替其存储地址，缺少事实保持 unknown。输出参数传入 `&p` 时解析到 `p`，传入 `pp` 时解析到 `*pp`；成员输出和函数局部参数分别处理。全局锁默认表示全局存储对象的地址，指针型全局载体可显式保留值语义。
- YAML 顶层只允许 schema_version、interfaces、dispatchers、function_pointer_bindings、discovery_receipt；未知顶层键失败。接口扩展字段和注释由 round-trip writer 保留。confirmed 接口的每个 case/precondition 都先通过类型化 predicate 校验，并且至少存在一个 `applies` case；YAML 布尔 `op: true` 不可冒充字符串操作符 `op: 'true'`，全 unknown 的审阅草案也不能进入执行 Registry。discovery_receipt 只保留计数、摘要和有界 gap 样本，逐函数 manifest、完整 gap 清单与 LLM 原始响应通过 evidence_ref 留在机器快照中，不重复写入人工维护 YAML。
- 普通重扫自动复用函数语义缓存，与历史 finding/report 复用分开。输入指纹分别记录代码 token、宏/类型依赖、相关人工配置、callee 对外契约和建模规格；规则、报告及并发参数不参与。对外指纹排除描述措辞、位置和怀疑点，只有契约变化才向调用者传播；候选、验证和报告绑定发布后的契约版本。
- 快照完整性分别校验完整内容与排除程序维护的 callee 摘要文本后的内容；仅刷新该摘要不触发 LLM 重建。接口契约、怀疑点及其他快照字段仍受完整性校验。旧缓存补充内容指纹时只更新缓存记录，不替换快照代次或清空已有报告。
- v4 契约使用 `preconditions` 和 `effect_cases` 区分调用前提与效果；`carrier` 标识资源对象，`resource_domain` 独立标识池或上下文，`protocol` 描述底层资源协议。条件只接受结构化引用和布尔表达式，自然语言留在证据说明。实际终结工具响应必须包含 `interface_contracts`，发布前再核对源码角色、载体和条件。验证失败最多尝试三次，发布有效部分并记录 partial，下一轮重试。
- 条件效果没有声明顺序优先级：命中或可能命中的相反效果、未知效果保持 unknown，不能解除义务。编译器拒绝能由受支持整数比较/合取证明重叠的矛盾效果；无法静态判定重叠时仍由消费端保守处理。资格随编译器版本失效，人工优先和既有发布屏障不变。
- 终结工具与持久化契约使用一致的可空表示：返回值/全局载体允许空参数索引，空资源域和空协议表示未声明；参数/输出参数载体必须有非负整数索引，非空协议必须声明 kind。兼容这些表示不放宽源码角色、路径和效果检查。
- 未知池协议由 LLM 提出，当前实现校验器支持侵入式空闲链表取出与归还的受限源码形态；其他实现保留未验证提议，或使用显式人工底层契约。对已有实现凭证或人工底层契约，完整可解析的外层函数与宏直接静态组合，不调用 LLM。精确空 void 函数或空语句宏生成静态空契约。循环和无法闭合的载体映射不能绕过建模。
- 未知调用按实际守卫参与组合；只有不可变且未逃逸的结果或值参数能证明其与成功分支互斥时，成功效果才可保留。重新赋值、地址逃逸、引用参数和无法解析的调用不获得该证明。失败恢复分支可有未知效果；隐藏底层返回状态不能改写为无条件成功。已登记但未验证的 callee 角色也不代表其他副作用已知。
- 错误分支归还资源并返回空值，不取消成功分支的分配契约。组合时检查释放能否到达返回同一对象的路径；只有稳定局部值/值参数的互斥守卫或已经退出的控制流可排除释放。释放后仍可能返回该对象、条件可被修改、返回其他借用对象时不获得该分配证明。
- 源码已解析完整不等于契约已证明完整。组合失败保留未核验提议，不能据此否定角色；只有实现明确只初始化等情形才拒绝加锁提议。参数的局部指针拷贝保留原身份，取地址逃逸、指针运算或重赋值会使相应绑定失效。未知函数直接出现在条件中时也记录独立返回身份，但不提升其副作用权限。
- 简单 C 对象指针转换保留资源身份，整数转换、指针运算和无法解析的转换不能充当透明映射。函数创建多个资源时，不直接继承一个底层释放端作为完整配对；复杂成员所有权仍需要额外实现证据或人工契约。
- 源码事实保留完整赋值左值，写入数组元素不等于修改下标变量，成员地址也不等于根指针变量的地址。返回值模式只消费 `carrier=return` 的申请接口；全局对象和输出参数仍进入统一事件解析，不把同次调用的状态码当作资源。
- 未知 callee 的局部返回值也有独立身份，可用于区分互斥的清理和返回分支，但不因此获得已知副作用。每个调用冻结当时的值绑定；后续赋值不修改先前调用的条件，参数重绑后的对象或池不能被发布为作用于原始参数的接口契约。
- 辅助函数发布对象的规则读取显式 `ownership_transfer` 及适用状态，不按 insert/add/register 等单词识别接口；格式化/日志调用读取 `format_sink`，Validator 的类别纠正也不通过项目函数拼写判断行为。
- 模型提出的配对边可留作调查线索，但合法释放查询只接受人工边或有当前实现证据支持的边；未核验封装不参与透明配对派生。Graph 全局资源规则核对对象、条件及池域，未知调用、对象改写或仅出现释放函数名均不能解除义务。
- `verification` 保存当前源码哈希、BuildContext/USR、编译器/catalog/native 工具版本和效果依据；schema 合法及模型置信度不赋予效果确定性。从人工契约派生的封装保留人工假设。自动池配对需要已验证的相同资源协议；人工多对多边不因协议相似而扩大。
- 入口 canonical identity 必须保留实现文件和可调用实体；当后端给出的 signature 不含方法名时（如 Java 的返回值/参数描述符），必须同时保留全限定函数名，不能因去重而丢失入口。
- 安全语义图使用入口规划产生的显式 exposure 元数据；API、通信和其他用户输入入口保留外部边界标记。线程入口本身不等于外部输入，也不按函数名称推断暴露属性。
- canonical key、stable fingerprint 和 source-context fingerprint 的用途不能互换；身份算法变更要考虑历史 baseline 兼容性。

## 常见变更应落到哪里

- public YAML 字段和严格校验：`zscope/config/support.py`；组合类型在 `config.py`，内部默认在 `runtime_defaults.yaml`。三者变更要同步 README、迁移器和配置测试。
- 旧 v2 到唯一 v3 的一次性字段映射：`zscope/cli/config_cli.py`；禁止把别名兼容加回产品 loader。
- 项目语义 schema/存储/迁移：`project_semantics.py`、`semantics_migration.py`；旧 `user_config_workbook.py` 仅服务一次性迁移和历史反馈兼容。
- 内置 API 语义或 overlay：`zscope/semantics/`；新增用户自定义角色时需同步 `models.py` 角色桶、`defaults.yaml`、`inference.py` kind 映射、候选生成器（regex/clang_ast_cfg/cpp_domains）、`evidence.py` overlay 路由与受影响 `builtin_catalog.yaml` revision。
- 快照策略和存储：`zscope/snapshots/`。
- 反馈、baseline 和 suppression：`zscope/memory/` 与 config store。
- 稳定 issue identity、公共取消/限时能力：`zscope/common/`。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_project_semantics.py tests/test_semantics_defaults.py
python -m pytest -q tests/test_security_semantic_map.py
python -m pytest -q tests/test_contract_usr_scope.py tests/test_contract_build_scope.py
python -m pytest -q tests/test_config_options.py tests/test_config_migration.py tests/test_concurrency_config.py
python -m pytest -q tests/test_snapshot_store.py tests/test_snapshot_refresh_decision_prompt.py
python -m pytest -q tests/test_review_memory.py tests/test_issue_dedup.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 路径和使用说明见 `README.md`，完整配置参考见根目录 `zscope.c_cpp.yaml` 与 `zscope.java.yaml`；状态分层见 `docs/architecture.md` 的“持久化与反馈平面”。
- 不在模块文档中复制完整 YAML 字段定义或历史 XLSX schema；以 schema 校验器和迁移报告为准。

## Portable 工具定位

`zscope.common.portable` 读取启动器提供的 bundle 根目录及资源清单，只为未显式填写的工具字段提供默认值。显式 public config v3 覆盖仍可用于实验，无需模式开关；解析不回写用户文件，错误覆盖不得改用其他工具。语言模板和 `zscope-init` 隐藏工具定位配置。源码安装不设置 bundle 根目录，保留原有 PATH 行为。

## 快照版本提交

快照正文使用唯一临时文件写入不可变版本，SQLite 事务同时发布版本指针和指纹。读取先查询已提交版本，再访问按版本缓存的正文，避免独立 SnapshotStore 实例之间的旧缓存污染。保存返回版本标识，版本化读取同时返回正文与标识；最终报告只能绑定分析时观察到的版本，冲突报告保存在快照目录的 `conflicts/`，不会覆盖新快照的报告。

旧固定文件名继续可读。保存、重协调和删除回收无引用旧版本，普通失败路径清理本次临时文件；读者遇到并发回收时重新查询指针。`get_fingerprints` 附带 `snapshot_generation`，快照与指纹版本不一致时要求刷新。

内置资源家族定义位于 `semantics/defaults.yaml` 的 `resource_families`，不把 FILE/DIR 句柄混入整数 fd 集合。该内部语义表不增加 public config v3 必填项。

## 系统契约与根协议审核

`c_linux_catalog.py` 是版本化 C/POSIX/Linux 分类、ABI、来源与 consumer 的单一权威，并生成 `standard_api.py`、role bucket、pair 和实例授权所需的数据。active/neutral/unsupported 分类必须完整；项目实际调用但未分类的系统接口会成为 formal gap。项目同名定义、用户头、错误签名、旧收据或未知身份不继承内置语义。

项目根协议和 derived wrapper 统一进入 `zscope.semantics.yaml`。pending/rejected/stale 不导入，confirmed 以精确 selector/variant 编译到 Registry；修改或撤销人工确认只影响对应接口。调用成功条件仍需程序证据，确认接口角色不等于证明运行状态。

人工审核的证明身份绑定完整资源规格，包括对象、资源域、协议、配对和适用条件；仅来源、确认状态或置信度变化不改变待确认命题。不同池或条件的同名接口不能互相代替确认。

根契约选择按独立依赖组件计算闭包，保留替代证明路径中的合取依赖，并对候选集合进行冗余消除与有界精确搜索。`graph_minimum_proven` 只描述已提供证明图内的结果；依赖清单不完整、缺失依赖、递归未闭合或搜索耗尽时，不能声称已找到实际最少人工集合，审核页的 `minimum_proven` 保持假。计数分别报告契约命题和涉及符号，不能把所有外层 wrapper 都变成人工确认项。

- 建模输入指纹将 Clang 局部符号中的字节偏移映射为按声明次序区分的身份，保持对象相等关系、作用域和文件身份；行号与格式变化复用建模结果。宏展开值、CFG 和目标 ABI 仍参与失效，原始证据及证明凭证继续绑定当前源码，不用归一化指纹授予证明权限。

接口角色发布后，候选生成仍须区分函数声明与实际调用；声明中的类型和形参不构成资源操作。函数体内调用、初始化表达式及递归调用保留。

`ProjectSemanticsStore` 以 comment-preserving round trip 和同目录临时文件原子替换 YAML。Discovery 合并按稳定 ID 串行化人工决定：同证据保留决定、变化转 stale、消失候选保留。正常扫描严格只读。

当前覆盖范围内失效的 pending 审核提议会随发布撤销，避免新版本提议与旧根协议重复积累；其他范围以及人工 confirmed/rejected 审核保留。撤销人工确认仍通过既有审核导入逻辑移除其导入行。

Native BuildContext 是按实际输入字节绑定的证明身份。`compiler_fingerprint` 只去掉最外层 BuildContext 的内容收据字段，保留程序对象内部的构建身份差异；已绑定构建身份的语义缓存记录仍随该身份失效。跨内容收据的语义复用需要重新签发当前契约，不能复用旧源码凭证。

建模 sidecar 按导航符号保存最近一份输入/结果，输入指纹仍包含规范化编译实例、依赖、代码、callee、人工约定与模型规范；编译变体切换可能替换此槽，但不会绕过输入比较。仅字节收据变化且全部语义输入一致时，无接口契约的分析快照可重定位复用。含接口契约的跨收据复用当前保守失效为 `build_receipt`，重新建模或源码组合后才能发布当前契约。候选/Validator 缓存、输出符号和证据仍保留完整 BuildContext，不能使用建模缓存路径作为证明身份；自动重签所有旧协议仍是后续优化。

精确函数事实的 `function_identity` 同样区分证明收据与语义输入：语义指纹保留 native USR，去掉由当前字节构建身份派生的 key；对象内部身份不受影响。建模物理调用与发布快照共用的 `semantic_model_unit_uid` 包含构建实例，避免同源码/签名的不同变体合并审计记录。

`ApiContract.SymbolIdentity` 同时保留精确 `build_context_id` 与 native USR，并随 YAML variant、源码组合、池协议和快照保留。USR 只由编译器链从已核验 native 事实建立；空 USR 不是通配符。闭源不可见实现只有在用户以 `external_model` 明确确认且 selector 精确绑定时才可执行，并始终标为用户假设。

`single_slot_pool` 提案描述内嵌槽、live 标记及可选代际/非法归还计数。校验要求当前 native 的 `resource_protocol_facts_version` 收据：仅接受完整的 C struct 单槽实现，核对空返回、唯一状态写入、可选自增与真实字段访问；union、嵌套宏改写、额外调用/写入及未知 native 版本保持未验证。真实空指针常量 `NULL` 可由 Clang 确认，不能仅凭名称放行。核验后的获取/归还共用池类型与字段身份，但实际归还仍要求同一对象、同一池以及调用前 live 条件。条件 operand 的 `address_of` 只用于 argument/global 的成员槽地址，地址事实缺失时保持 unknown；字段值不能代替地址。代际递增不证明永不回绕，逻辑归还不等于 free，也不自动闭合异步回调生命周期。

`reference_retention` 表示资源引用留存，和 `ownership_transfer` 的清理责任转移分开。模型可提出 `single_slot_retention`，携带资源 carrier、接收方 resource_domain 与 `slot_path`。当前校验器只接受完整、无宏/调用副作用的 C 单槽实现：失败早退不写槽，成功保存指针并返回不同状态码；源码和 native 存储/返回事件必须一致。核验后发布条件化 `retain_reference` / `retention_unchanged` 动作，保留 `release_responsibility=unresolved`。即使原提案称为所有权转移，也不能由这项源码事实取得释放或泄漏反证权限。不支持的实现仍保留未验证提案。该有限模型不证明线程安全，也尚未闭合跨 complete/cancel 的生命周期。

契约发现与效果消费分开：原始 `find` 保留全部发现信息，只作发现级查询；效果消费使用 `find_for_call`（`match_call`、转换与分配范围走同一选择链），先解析符号身份，再按构建、文件/签名与角色过滤。省略 USR 不是通配符：查询必须从当前绑定调用上下文中完整、无冲突的 native callee 事实解析 USR，只有该名称在本函数体内从未被观察时才可回退到分析入口自身的 native USR。事实不完整或过期、上下文不符、冲突、同一函数体内观察到一个名称的多个 USR、以及入口回退不能确证的递归同名情形都解析为空身份，不能靠注册表中唯一一条记录或入口回退获得效果；空身份拒绝精确 USR 记录，无 USR 的源码记录也不能回答精确 USR 查询，builtin 标准根保持名称级可选中。普通工作簿/源码行自报的 USR 在读取时被剥除，仍是名称级身份，不因此取得 native 效果。不能因重载集合中只有一个释放器就认定本次调用释放；歧义调用不提供效果、资源域、分配大小或协议转换，包装函数也不得组合出自动证明。具有同一完整符号身份的多个效果继续适用；native 条件正文与同名不同 TU/编译变体仍按精确实例查询，不跨实例合并。

候选调用作用域使用 ContextVar，避免并行分析之间串用构建身份。歧义、失效或不完整实例，以及未展开条件编译的原始函数源码，都不能推导 `must_under_guard` 效果；模型建议仍可保留为 `schema_only`。此迁移尚未让旧函数调度和导航图覆盖全部变体。

有 native 事实的 C 堆资源包装器由 `native_wrappers.py` 适配既有 `program-events.v5` / `lifecycle-value-facts.v1`，校验同一 BuildContext、函数/局部 USR、调用站点及 CFG 条件。受限值流支持直接可信根调用、局部别名、返回值、输出参数、单层字段输出、显式状态码和失败清理；输出指针与状态返回值分开。根契约（包括清理调用）、源码、native 输入及人工假设随证明发布。复杂转换、额外资源、借用备选返回、外部保存、未知副作用和循环等超限输入留下拒绝原因，不从失败的 native 核验回退到 token 强授权。没有 native 上下文的旧源码路径仍保留，但覆盖诊断明确记录缺事实。

该适配复用 ApiContract、工作簿发布屏障和 Registry，不建立另一套资源模型。`source_verified` 仅证明受支持条件下的接口效果；不授予 `fresh_no_alias` 或漏洞最终裁决权限。字段载体可发布，但字段载体根契约的任意继续组合尚未支持。跨 TU、C++ RAII、realloc、池/锁/refcount/异步仍由各自模型拥有。缓存继续使用现有代码、头文件、编译参数、callee/根契约和编译器版本依赖；原样热命中不重新执行 native 包装器核验。

`non_atomic_refcount` 提案复用 ApiContract 的 `standard_operation`，明确 carrier、`operation=init/retain/drop` 与 `count_path`。首批源码核验支持 signed 32-bit 的初始化为 1、非正值失败、retain 在最大值饱和失败、drop 后零计数的可选单次 callback；实际 native 类型、读写事件与受限完整实现一致才发布。原子/volatile、位域、无符号/其他宽度、未知属性、不受支持守卫和副作用仍未验证。模型不得把 drop 提为 deallocator，可信效果也不授权最终销毁、清理责任或线程安全；callback 的终结效果必须由当前对象路径另验。契约编译器 v24 使旧自动核验失效，工作簿/Registry 和现有消费者沿用原发布屏障，覆盖诊断标明专门路径消费范围。

单槽池归还可用提案 `return_status: true` 描述真实成功返回 1、成员/live 守卫拒绝返回 0 的实现；反向状态码不能取得该效果。运行路径同时检查状态与实际 live 变化。该扩展不改变池/槽身份和代次，不引入新 public YAML；arena/reset 和并发引用计数仍是后续任务。

`bounded_handle_table` 复用 standard_operation 和资源域，核验 signed 32-bit C 表的 2–4 个固定非负句柄值（0 合法）、独立 live/object 字段与 open/close/dup。open 使用有上界保护的底层对象序号，dup 将既有底层标识复制到空闲描述符槽；close 的明确失败参数可以在消费前或消费后报错。当前路径逐项核对真实读写效果，发布不建立普通 allocator/deallocator 配对；计数/槽外写入、来源不明整数、转换、宏、union、位域、atomic/volatile 或未知函数效果保留缺口。工作簿重载保留契约与消费者限制，不声称普通 Regex/Graph 已求解此状态机。

标准 API 目录 v4 将原有平台依赖 close 错误效果保留为 unknown，不再使用通用 helper 的 no_effect 兜底。该调整不提供平台 errno 模型或 OS 句柄路径；自定义源码协议不能替代标准接口规范。串行句柄命名空间前提复用既有业务回答状态库及依赖撤回，未增加配置或反馈存储。

锁协议沿 ApiContract 的 `protocol.lock_mode` 保存 shared/exclusive/unknown；标准 API v5 和契约编译器 v24 使旧相关语义缓存失效。模式来自明确标准规格或已核验包装器组合，不按名称猜测；缺字段、非法模式或未核验提案都为 unknown。转换动作和 CallSemanticMatch 同样保留模式，部分恢复分支未核验时，继承转换不能越过契约效果重新取得权限。工作簿和 Registry 保留原条件、载体与构建身份；旧消费者未迁移为锁实例证明的限制继续由 coverage 标明，无新增 public YAML。

标准 API v6、契约编译器 v25 将 pthread_create/join/detach/cancel 分成 start_callback、wait_callback_completion、release_join_handle、request_cancellation。转换中的线程载体、callback/context 参数和成功条件经过包装器映射、工作簿重载与调用事件解析仍保留；未核验效果不能借继承转换取得权限。join/detach 的旧线程资源配对只表示线程句柄责任，不授权上下文 free 或回调 drain。覆盖诊断分别标识语义传播与有限单工作者路径消费，不能把规则关闭视为安全或已执行。无需新增 public YAML 或反馈库。

单工作者队列消费当前标准 mutex/cond 根契约，并核对 `pthread-storage.v1` 的 opaque 字段身份、默认初始化及锁实例。coverage 的 `async_queue_sync` 区分受限 unlock/join 与单等待者 cond_wait 的通知匹配/重获路径，并明确未覆盖唤醒序列、取消模式切换和任意取消点尚不支持；`async_callback` 保留实验规则显式启用和调度边界。项目 submit/cancel/stop helper 直接重放当前源码 CFG，不新增名称驱动的 drain 契约或全局释放器配对；槽位清除、任务引用和真实完成分开。业务回答沿用精确路径范围和 revision 撤回，不增加配置项、工作簿字段或第二套状态库。

标准 API v7 新增 pthread_testcancel 的 standard_operation，只描述延迟取消点，不是释放器或完成转换。有限消费者使用当前根契约与实际取消请求，C/glibc cleanup 则由独立 native 宏/AST 收据和同 TU 回调体解释；coverage 标明默认延迟取消、注册栈和调度边界，不能把契约存在等同于实验规则已运行。异步路径 v8、assessment v12 与规则 revision 14 使旧见证重新核验，默认实验开关及集中反馈库保持原有路径。

coverage 另标记 `same_file_direct_worker_helpers`：仅同一 C 文件的已知堆根/受限整数直接调用，不等于任意 helper、cleanup 间接清理或跨 TU 已覆盖。函数体/目标/返回和当前根契约变化进入原收据失效与重放链；无需新增用户配置、全局释放器配对或业务回答来源。

标准契约已包含 timedwait/clockwait 的释放/重获与 ETIMEDOUT 条件，本切片复用标准 API v7，不新增名称配对或用户配置。coverage 标识一次无通知唤醒/核验的 realtime/monotonic 超时及直接系统 clockwait 常量限制；契约存在、消费者支持与实验规则实际执行仍分开。等待路径 v8、assessment v12、规则 revision 14 使旧见证重新重放；时钟前提进入现有集中业务验收，回答撤回不能由模型分数覆盖。

coverage 对 cond_wait 单独标识 `caller_matched_wait_predicate_recheck` 和等待不等于完成；timedwait/clockwait 明确保留 `caller_wait_unsupported`，不因工作者时钟能力已支持就声称调用方也已覆盖。异步 v8、assessment v12 与规则 revision 14 撤回旧路径授权；标准 API v7、native wait v3 与用户配置保持不变。调用方谓词、通知及真实回调变化复用既有依赖和回答 revision，不增加 drain 名称契约。

## 2026-10-14 当前持久作业与只读准备切片

精确实例语义通过 `instance_semantics` 的进程内工厂签发，并绑定 BuildContext、入口 USR、项目 YAML 摘要、catalog、业务回答、有效规则和消费者源码。保存的标签、自洽摘要和重建 dataclass 不授予执行权；Analyzer/Validator 各消费独立副本，消费前后重新核验当前依赖。当前 `builtin_current_confirmed_project_current.v2` 只消费当前 native 验证的 builtin 与证据仍匹配的 confirmed project contract；项目同名 shadow、来源或 ABI 未核验的根保留 deny/缺口，LLM suggestion 和 pending/rejected/stale 行不产生效果。

标准来源核验面由版本化 Linux/glibc LP64 catalog 驱动；每个 active 项都必须有精确 ABI、规范来源与至少一个规则消费者。调用仍须绑定当前系统声明、external linkage、无项目同名定义、精确 USR/签名、BuildContext、头文件和工具摘要；任一项缺失或变化都撤回效果。neutral 是已审计无现有安全域效果，unsupported 明确记录能力缺口；项目实际调用但未分类的系统接口会阻止 formal readiness。

`v3_preparation.prepare_saved_config` 返回与既有准备字段兼容的机器数据；默认 Web saved-config 准备通过同一后端读取 v3。v3 扩展完整列出目标、平台、preset 到现有 depth 的映射、一次窗口的解析值及未消费声明。多个 target 保留全部身份并禁止启动，不把首目标投影为全部；显式服务端 depth override 暂走旧 effective-config 组合路径，多目标仍拒绝。独立 v3 编辑器保留原始 document 的全部 targets/profiles、相对路径和环境变量引用；空密码不覆盖已有值，失败或迟到响应不丢失草稿，保存后重新准备。旧 v2 builder 已移除。配置保存尚无 revision/CAS；浏览器 409 情景仅验证合同响应下的草稿保护。准备只检查配置/路径/工具存在，不执行扫描、模型、构建或索引。

focus/reproduction/max_workers/platform 暂未接实际消费者。配置 execution.stop_at 已接 CLI 共享令牌预算与新建持久作业窗口；显式作业 stop_at 优先，同 request_id 重放保留原窗口，resume 不重新套用配置窗口。Web `/api/jobs` 与 MCP `zscope.scan.run` 创建作业时解析配置窗口，已过期的窗口以 `stop_window_closed`（400）拒绝，不写作业行、不启动 owner。owner 启动的 CLI 核对当前 job/run/owner/input 与运行目录绑定后，以持久 SQL 窗口为唯一预算来源，包括合法空窗口；部分环境或失效绑定不回退配置。独立 CLI 继续使用配置窗口。prepare 仍仅核对配置、路径和工具存在，不表示扫描已完成或模型已连接。单 target 配置可使用保存的 preset 启动作业；初始化器、模板与 CLI 配置命令已迁移，其余执行消费端仍待逐项确认。
