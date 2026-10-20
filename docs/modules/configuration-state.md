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
  - zscope/config/v2.py
  - zscope/config/v3.py
  - zscope/config/v3_preparation.py
  - zscope/config/editor.py
  - zscope/config/runtime_defaults.yaml
  - zscope/config/function_entry.py
  - zscope/config/user_config_store.py
  - zscope/config/protocol_feedback.py
  - zscope/semantics/business_assumptions.py
  - zscope/config/user_config_workbook.py
  - zscope/orchestration/user_config_inference.py
  - zscope/semantics/contracts.py
  - zscope/semantics/standard_api.py
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
  - tests/test_portable_runtime.py
  - tests/test_config_v2.py
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

实施计划 U01 的 v3 核心模型经同一 ConfigLoader 分派：v3 工程根目录按配置文件目录解析，v2 路径语义保持原样；target 身份全部保留，当前执行组合只允许一个 target，不能偷偷选择首项。quick/overnight 暂时显式映射到旧 depth，不启用实验规则。IANA 时区和 stop_at 解析为本轮绝对边界，DST 不存在或重复时刻明确拒绝；CLI 和新建持久作业已消费该边界，创建时若解析出的配置窗口已过则以 `stop_window_closed`（400）拒绝，不再接受开局即停的作业；resume 不重新套用配置窗口。focus/reproduction/max_workers/platform 目前保留声明并附 wiring 状态，不等于实际执行。CLI prepare/validate、初始化器与语言模板已使用 v3；MCP 的创建路径已随同一作业服务消费该检查，其余执行消费端仍有剩余。

`config/editor.py` 为结构化编辑提供原始文档投影与同目录候选校验，保留所有 profiles、环境变量引用和相对值。v3 调用正式 parse-only 模型，不能为了保存多目标而强迫执行组合；v2 继续走现有 loader。候选按进程/线程隔离，验证失败不替换原文，成功后原子替换；当前接口没有配置 revision/CAS。初始化器正确序列化用户路径及目标标识，避免 YAML 注释或冒号改变工程身份。

v3 schema 由模型字段表和条件表生成，包含时窗依赖、语言与 target 数据库条件及解析正规化的边界；IANA/DST、跨项 target id 唯一性、有效配置单 target 组合等运行时约束单独披露，不声称 JSON Schema 能表达全部语义。

人工 baseline 的精确键匹配和源码窗口/稳定指纹回退均要求相同构建身份；缺少身份不是通配符。Web 对已知构建的误报反馈只写入该构建的 baseline，不再额外生成按位置匹配的宽泛 suppression。旧位置 suppression 仅适用于未知构建的候选，不能覆盖已绑定编译实例的发现。不同构建的事实、缓存、去重和人工反馈隔离由 `tests/test_candidate_build_identity.py` 共同验证。

只读 MCP 使用 ConfigLoader 的内部 read_only 加载路径，保留严格 Config v2 校验并跳过 rollout 持久态、扩展 provider 预检及 usage 注册。只读快照打开不创建目录或迁移表；checkpoint 后 SQLite 用 immutable/query_only 读取，活动 WAL 明确不可用。旧快照缺完整输入身份时返回 unverifiable，源码摘要匹配不代表头文件、构建或契约仍有效。正常扫描加载与默认刷新不变，详见 [只读 MCP](../mcp-read-only.md)。

## 职责与非职责

业务前提回答保存在工作簿同名状态库的 `protocol_assumption_answers`，每次修改追加版本。键绑定前提文本、事实种类、BuildContext、入口、ObjectRef 及源码/契约依赖；显示 ID 变化不会重新解释约定，范围或依据变化则不能套用旧回答。批量写入为同一事务，检查每条预期版本，失败全部回滚；重复提交相同回答不产生新版本。该存储只保存用户声明与来源，不保存另一份缺陷裁决，也不写 suppression/baseline。模型输出、普通复核文字及旧报告本身不授予业务约定权限。

本子系统负责解析和校验用户配置、合并内置/项目语义、维护快照和人工反馈状态，并提供稳定 finding identity、取消和运行限制等公共设施。它连接用户领域知识、历史分析结果和当前扫描。

它不负责选择 CLI 运行模式、不实现后端索引，也不决定报告的展示格式。

## 主入口和数据流

- `ConfigLoader` 按版本读取严格的 `UserConfigV2`/`UserConfigV3`，再与打包的 `RuntimeSpec` 组合为 `EffectiveConfig`；`ProjectConfig` 负责项目路径解析。
- `preparation.prepare_project` 供 CLI `zscope-config prepare` 与 Web `GET /api/scan/prepare` 共用；调用方以 `read_only=True` 加载严格配置，跳过 provider、rollout 和 usage 持久态。准备视图列出实际路径、编译命令去重与变体、工具存在性及配置中的扫描模式，不启动子进程/模型、不生成索引或改写工程；未知链接归属保留为未核验，模型凭据与 endpoint 不进入结果。
- `v3_preparation.prepare_saved_config` 为 CLI、默认 Web saved-config 准备和 MCP `zscope.config.prepare` / `zscope://config/preparation` 提供同一 v2/v3 只读合同。MCP 只绑定启动时已保存配置的路径（先 `expanduser()` 再 `resolve()`），请求时重新读取，default profile 自动创建的作业 adapter 复用同一保存路径并保持懒绑定；default/read_only 还需通过各自 profile 与 ToolPolicy，candidate_blind 保持不可见且不可调用。准备保留全部 targets、未消费字段与 start capability，不授予执行权限；fresh MCP 启动仍先走单 target 组合，多目标禁启及 focus/reproduction/max_workers/platform 未消费边界保持不变。接口细节见[接口与报告](interfaces-reporting.md)。
- public YAML 顶层只允许 `config_version`、`llms`、`project`、`scan`、`indexing`、`concurrency` 和可选 `rules`。`project.language` 只能显式为 `c_cpp` 或 `java`。
- `scan.depth` 公开为 `fast|balanced|deep`；CLI 的 `--scan-depth` 高于 YAML，YAML 高于打包默认。省略 depth 目前解析为 `fast`。public config 不提供 scan-wide token 预算字段。
- 三档不带产品侧 token 上限；Range Benchmark policy 分别维护完成后成本预期，并按 agent/stage 的真实 usage 验收。
- `runtime_defaults.yaml` 管理 Agent 启用状态/LLM 角色、分析预算、缓存、报告策略和稳定算法默认值；`AGENT.md`、`SKILL.md`、workflow YAML 不在此重复。
- Review 实验开关仅属于 RuntimeSpec：`validation_review_checkpoint`、`validation_review_protocol`、`validation_checked_proofs`、`validation_positive_case`、`validation_related_findings` 默认均为 false。checkpoint 单独启用时只保留完整事实和前序结果，不向模型新增事实工具；protocol 组只改变封套与验收；checked_proofs 组才启用共享编译器事实和检查工具。正面举证不修改现有置信度门槛。实验期间禁用候选结果缓存，避免复用缺少封套、事实增量或有效签名的结果。
- 根目录 `zscope.c_cpp.yaml` 与 `zscope.java.yaml` 是语言隔离的精简参考文件；Java 不接受 SVF/clang/compile database，C/C++ 不接受 Java provider 字段。
- `Z_SCOPE_RUNTIME_SPEC` 只在 `Z_SCOPE_DEVELOPER_MODE=1` 时接受绝对覆盖路径。有效规格版本、来源和 SHA-256 进入配置哈希、缓存身份及报告 provenance。
- `UserConfigWorkbook`/`UserConfigStore` 维护人工可审阅语义以及 suppression、baseline 等旁路状态。
- C/C++ 规则只合并标准库/平台 defaults 与本轮提交并重新读取的工作簿契约。建模阶段覆盖入口可达函数和引用宏，以 `interface_contracts` 表达调用者可见的接口角色（包括显式所有权转移）；普通扫描与 `--infer-user-config` 共用增量建模和持久化。名称线索只用于建模检索，不在规则侧识别角色。
- `security_map.db` 是独立于历史函数 snapshot 的只读安全语义 sidecar：零 LLM 骨架记录入口、调用、危险事件和 backend coverage；有证据引用的选择性 LLM delta 才能成为 claim，无可解析引用的内容仅是 observation。
- Security Map 的项目接口事件使用重读后的 `api_contracts` 和共享调用解析器，记录实际对象、资源域、条件适用状态及契约版本；`resource_models`、`lock_models` 中的名称摘要不决定接口角色。锁事件属于 `callback_concurrency` 家族，多个同线调用分别保留。自动契约经过工作簿重读后仍保留来源：仅有模型推断的效果是 `llm/unknown`；源码核验的效果和人工规格分别记录为 `program`、`user`，调用可达性仍需另证。构建器版本参与安全图缓存失效。
- snapshot policy 决定完整、轻量或语法快照，store 负责持久化与复用。
- 条件观察与按需建模的两个内部开关分别为 `analysis.semantic_snapshot_candidate_mode`、`analysis.semantic_model_demand_mode`，仅允许 `off|shadow`，默认 `off`，不进入 public Config v2。前者开启时将条件观察 schema 纳入建模规格指纹，关闭保持原 schema；后者只记录需求计划，不改变快照输入身份或实际建模调度。当前会话的观察绑定不能从持久 JSON 恢复为权限。
- 受控动态复现的内部开关为 `analysis.dynamic_reproduction_mode`，仅允许 `off|shadow|on`，默认 `off`，不进入 public Config v2；配套字段限定复现次数（1..16，max ≥ required）、单次超时（1..3600 秒）、整轮验证墙钟上限 `dynamic_reproduction_deadline_seconds`（默认 900，可经 RuntimeSpec 调整）、内存上限、输出捕获上限（字节）、artifact 发布目录、授权 TTL 与隔离模式（`process|user_net_namespace`）。`off` 完全惰性：runner 边界拒绝执行、`availability()` 不探测工具链、扫描接缝不改动 issue，不编译、不执行、不注册授权；`shadow` 执行并记录 provider 元数据但不授予确认权限；`on` 才允许合格 witness 进入现有确认通道。非法的输出上限、TTL、deadline 与复现次数组合在策略校验期直接报错；策略不可用只让该能力保持惰性，不使候选扫描失败。approved-plan provider 只存在于当前进程（单槽，可从磁盘恢复不了）。复现次数按“一个 plan 的执行总次数”计量：一次 `execute()` 只跑一轮（含计划授权的 build），调度器把 `max_replays` 先分 1 次给主执行、其余留给策略要求的独立重放，不足时记录 `dynamic_reproduction_budget` 而不提前拒绝；执行预算与墙钟 deadline 都绑定到 runner，计量真实进程启动，重放不能放大授权。
- 当前启用任一语义实验，或历史报告含实验统计时，resume/maintain 不复用历史报告，以免把旧统计或观察资格当成本轮结果；函数建模缓存仍按各自输入身份判定。K01 首版仅在可核验的自包含项目、当前实际建模与发布输入一致时授予观察登记资格；存在或配置编译数据库、外部依赖、无法重核的自定义 schema 或超出库存预算时均不授予资格，不推断 TU 证明。热缓存继续供背景读取，不重新授予独立观察权限。
- 建模终结输出保留逐次原始提交和完整 schema 错误；单层 `payload` 或 `function_snapshot` 封套解包后仍必须通过完整校验。格式修复中丢失的协议提议只作为发现线索保留，由当前完整实现重新证明后才能恢复接口契约；无法证明的提议仅留在诊断中，不进入工作簿的有效契约。契约编译器版本参与缓存失效，终结尝试审计与最终快照分别留档。
- 同一进程内，多个 Analyzer 首次打开同一快照数据库时，共用规范路径锁完成 schema 检查、建表及迁移，再进入建模任务协调；不同数据库的初始化仍可并行。
- `ReviewMemory` 是验证反馈门面；`issue_identity.py` 为报告、baseline、SARIF 和 benchmark 提供统一身份。

独立的 `zscope/review_memory/` 归属 [Validator Review Memory](review-memory.md)，
保存项目级误报模式与 advisory context。其状态、抽取、匹配、回放及当前限制见该文档；
本模块继续负责 `zscope/memory/` 的既有 baseline/suppression 门面与公共配置。

## 必须保持的不变量

- 接口契约的 `to_dict` 是 JSON 边界：内部配对保持不可变 tuple，输出为数组；从共享报告导入的条件、证据等对象必须可以再次序列化，修改导出值不得污染原契约。纯表示转换不能改变结构指纹、契约版本或证明权限。

- 产品运行时不解析 v1；旧字段只允许由 `zscope-config migrate` 读取。未知键、重复 YAML 键、错误类型、非法枚举和未展开必需环境变量必须失败。
- public YAML 不能包含 Agent、analysis、reporting、workflow、缓存、逐 Agent 轮数、rollout 开关或 scan-wide token 预算；扫描档位是明确允许的公共资源控制。
- Java 尚未通过独立门禁，只接受 `fast`；显式请求 `balanced/deep` 必须报错，不能静默降级。C/C++ 默认切换到 balanced 之前仍以 fast 解析省略值。
- `rules.disabled_ids` 优先于 `enabled_ids`，同一 ID 同时出现时以禁用为准；表内重复或未知 ID 必须在启动外部工具/LLM 前失败。未通过资格的新内置规则必须是 experimental 且默认关闭；遗留 stable/pending 规则只保留迁移期兼容，正式发布门禁会拒绝任何默认启用但未 qualified 的规则。
- C/C++ 后端只能显式为 `unified|clang|regex`，Java 只能为 `java_unified|java_source|joern`；深度后端不可用时不得静默切换到弱后端。
- `scan.task` 空串必须激活当前语言全部适用 Skill；非空文本只覆盖审计重点。
- `concurrency` 的全部字段必须是正整数，并由调度、索引、SVF、Validator、evidence completion 与 LLM 全局限流统一读取。
- CLI 配置路径和目标项目路径必须区分：`project.root` 相对进程工作目录解析，其余项目相对路径依据 `project.root` 解析。
- KnowledgeDB、snapshot 和默认 user config 状态路径必须相对 `project.root`，不能因跨目录执行写入进程工作目录。
- 用户配置只向当前函数/入口注入相关片段，不能把整个工作簿无差别放入 prompt。
- 人工填写的配置不能被自动推断静默覆盖；推断行必须保留来源和置信度；只清理本次覆盖范围内已失效的 inferred 行，manual 行永不清理。失败/过期状态不参与规则，无有效变化不重写工作簿。
- 项目接口必须经过工作簿发布屏障进入统一 `ContractRegistry`；`resource_names/lock_names` 只是摘要。配对保存有向边，不做共享释放端的传递闭包；合法释放必须匹配对象，条件不确定或符号有歧义时保持未知。模型推断不能作为确定性安全证明。
- 载体的 `address_of` 保留取地址关系，`p` 与 `&p` 不可互换。输出参数传入 `&p` 时解析到 `p`，传入 `pp` 时解析到 `*pp`；成员输出和函数局部参数分别处理。全局锁默认表示全局存储对象的地址，指针型全局载体可显式保留值语义。
- 工作簿 `README` sheet 只写不读（不在 `SHEET_HEADERS` 白名单）；kind 枚举外的新取值读取时记入 `read_warnings` 并进入推理报告。
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
- `verification` 保存当前源码哈希、编译器版本和效果依据；schema 合法及模型置信度不赋予效果确定性，工作簿重读不得提升其权限。从人工契约派生的封装保留人工假设。自动池配对需要已验证的相同资源协议；人工多对多边不因协议相似而扩大。编译器及事实版本参与缓存失效；源码核验凭证与对外契约指纹分离，但有效效果权限变化必须传播。
- 入口 canonical identity 必须保留实现文件和可调用实体；当后端给出的 signature 不含方法名时（如 Java 的返回值/参数描述符），必须同时保留全限定函数名，不能因去重而丢失入口。
- 安全语义图使用入口规划产生的显式 exposure 元数据；API、通信和其他用户输入入口保留外部边界标记。线程入口本身不等于外部输入，也不按函数名称推断暴露属性。
- canonical key、stable fingerprint 和 source-context fingerprint 的用途不能互换；身份算法变更要考虑历史 baseline 兼容性。

## 常见变更应落到哪里

- public YAML 字段和严格校验：`zscope/config/v2.py`；组合类型在 `config.py`，内部默认在 `runtime_defaults.yaml`。三者变更要同步 README、迁移器和配置测试。
- v1 到 v2 的一次性字段映射：`zscope/cli/config_cli.py`；禁止把别名兼容加回产品 loader。
- 工作簿 schema/导入导出：`user_config_workbook.py`、`user_config_store.py`。
- 内置 API 语义或 overlay：`zscope/semantics/`；新增用户自定义角色时需同步 `models.py` 角色桶、`defaults.yaml`、`inference.py` kind 映射、候选生成器（regex/clang_ast_cfg/cpp_domains）、`evidence.py` overlay 路由与受影响 `builtin_catalog.yaml` revision。
- 快照策略和存储：`zscope/snapshots/`。
- 反馈、baseline 和 suppression：`zscope/memory/` 与 config store。
- 稳定 issue identity、公共取消/限时能力：`zscope/common/`。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_user_config_workbook.py tests/test_semantics_defaults.py
python -m pytest -q tests/test_security_semantic_map.py
python -m pytest -q tests/test_contract_usr_scope.py tests/test_contract_build_scope.py
python -m pytest -q tests/test_config_v2.py tests/test_config_migration.py tests/test_concurrency_config.py
python -m pytest -q tests/test_snapshot_store.py tests/test_snapshot_refresh_decision_prompt.py
python -m pytest -q tests/test_review_memory.py tests/test_issue_dedup.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 路径和使用说明见 `README.md`，完整配置参考见根目录 `zscope.c_cpp.yaml` 与 `zscope.java.yaml`；状态分层见 `docs/architecture.md` 的“持久化与反馈平面”。
- 不在模块文档中复制完整工作簿列定义或历史 schema 迁移记录。

## Portable 工具定位

`zscope.common.portable` 读取启动器提供的 bundle 根目录及资源清单，只为未显式填写的工具字段提供默认值。显式 public config v2 覆盖仍可用于实验，无需模式开关；解析不回写用户文件，错误覆盖不得改用其他工具。语言模板和 `zscope-init` 隐藏工具定位配置。源码安装不设置 bundle 根目录，保留原有 PATH 行为。

## 快照版本提交

快照正文使用唯一临时文件写入不可变版本，SQLite 事务同时发布版本指针和指纹。读取先查询已提交版本，再访问按版本缓存的正文，避免独立 SnapshotStore 实例之间的旧缓存污染。保存返回版本标识，版本化读取同时返回正文与标识；最终报告只能绑定分析时观察到的版本，冲突报告保存在快照目录的 `conflicts/`，不会覆盖新快照的报告。

旧固定文件名继续可读。保存、重协调和删除回收无引用旧版本，普通失败路径清理本次临时文件；读者遇到并发回收时重新查询指针。`get_fingerprints` 附带 `snapshot_generation`，快照与指纹版本不一致时要求刷新。

内置资源家族定义位于 `semantics/defaults.yaml` 的 `resource_families`，不把 FILE/DIR 句柄混入整数 fd 集合。该内部语义表不增加 public config v2 必填项。

## 系统契约与根协议审核

`standard_api.py` 是版本化系统 API 契约源，`ContractRegistry` 统一解析角色、对象/池、条件与复合效果。系统声明来源和编译目标决定是否适用；项目同名定义或宏重定义不继承内置语义。`schema_only` 保留为未知背景，不能创建或解除确定性生命周期义务。初始化、销毁和等待不能用普通 lock 名称表替代。

`contract_review.py` 保留证明依赖及替代路径，静态闭包后的根协议进入工作簿 `contract_review` 页。审核页含建议契约、源码依据、受影响接口和运行条件；pending/rejected 不导入，confirmed 以 `user:contract_review:<id>` 来源导入 resource/lock 页。修改或撤销审核只更新该来源的行，不影响原有人工行。调用成功条件仍需程序证据；确认接口角色不等于证明运行状态。

人工审核的证明身份绑定完整资源规格，包括对象、资源域、协议、配对和适用条件；仅来源、确认状态或置信度变化不改变待确认命题。不同池或条件的同名接口不能互相代替确认。

根契约选择按独立依赖组件计算闭包，保留替代证明路径中的合取依赖，并对候选集合进行冗余消除与有界精确搜索。`graph_minimum_proven` 只描述已提供证明图内的结果；依赖清单不完整、缺失依赖、递归未闭合或搜索耗尽时，不能声称已找到实际最少人工集合，审核页的 `minimum_proven` 保持假。计数分别报告契约命题和涉及符号，不能把所有外层 wrapper 都变成人工确认项。

- 建模输入指纹将 Clang 局部符号中的字节偏移映射为按声明次序区分的身份，保持对象相等关系、作用域和文件身份；行号与格式变化复用建模结果。宏展开值、CFG 和目标 ABI 仍参与失效，原始证据及证明凭证继续绑定当前源码，不用归一化指纹授予证明权限。

接口角色发布后，候选生成仍须区分函数声明与实际调用；声明中的类型和形参不构成资源操作。函数体内调用、初始化表达式及递归调用保留。

同一进程中的多个 Analyzer／工作簿实例按规范化文件路径共用事务锁，读取、生成数据合并、审核导入及写入作为完整事务串行发布；不同工作簿仍可并行。缓存会在其他实例原子替换文件后失效，无有效变化不重写，避免共享建模任务完成后并发发布丢失契约行。

当前覆盖范围内失效的 pending 审核提议会随发布撤销，避免新版本提议与旧根协议重复积累；其他范围以及人工 confirmed/rejected 审核保留。撤销人工确认仍通过既有审核导入逻辑移除其导入行。

Native BuildContext 是按实际输入字节绑定的证明身份。`compiler_fingerprint` 只去掉最外层 BuildContext 的内容收据字段，保留程序对象内部的构建身份差异；已绑定构建身份的语义缓存记录仍随该身份失效。跨内容收据的语义复用需要重新签发当前契约，不能复用旧源码凭证。

建模 sidecar 按导航符号保存最近一份输入/结果，输入指纹仍包含规范化编译实例、依赖、代码、callee、人工约定与模型规范；编译变体切换可能替换此槽，但不会绕过输入比较。仅字节收据变化且全部语义输入一致时，无接口契约的分析快照可重定位复用。含接口契约的跨收据复用当前保守失效为 `build_receipt`，重新建模或源码组合后才能发布当前契约。候选/Validator 缓存、输出符号和证据仍保留完整 BuildContext，不能使用建模缓存路径作为证明身份；自动重签所有旧协议仍是后续优化。

精确函数事实的 `function_identity` 同样区分证明收据与语义输入：语义指纹保留 native USR，去掉由当前字节构建身份派生的 key；对象内部身份不受影响。建模物理调用与发布快照共用的 `semantic_model_unit_uid` 包含构建实例，避免同源码/签名的不同变体合并审计记录。

ApiContract v5 的 `SymbolIdentity` 同时保留精确 `build_context_id` 与 native USR，并随源码组合、池协议、快照与工作簿嵌套契约保留。USR 只由编译器链从已核验 native 事实建立；空 USR 是名称级身份，不是匹配任意 USR 的通配符。契约编译器 v26 撤销缺少 USR 精度的旧自动证明，编译器与 `ContractRegistry` 版本一同参与注册表指纹和语义缓存失效；未指定实例的消费者不能使用实例专属契约，另一 TU 的实例也不能仅因同名或相同底层 API 获得配对关系。人工未限定构建的约定仍作为显式假设适用，不会变为源码证明。

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

精确实例语义通过 `instance_semantics` 的进程内工厂签发，并绑定 BuildContext、入口 USR、工作簿字节、业务回答、有效规则和消费者源码。保存的标签、自洽摘要和重建 dataclass 不授予执行权；Analyzer/Validator 各消费独立副本，消费前后重新核验当前依赖。当前 `builtin_current_manual_advisory_no_inferred.v1` 只消费能核验的有界标准根；项目定义、来源或 ABI 未核验的根保留 deny/缺口。manual 按真实 sheet 的符号/文件选择器进入 advisory，inferred 行不产生效果。该策略不表示全项目建模或全部语义域已经覆盖。

当前标准来源核验限定 Linux/glibc LP64 的 malloc/calloc/realloc/free：声明须绑定物理 `/usr/include/stdlib.h`，并具有当前精确构建实际读入的 stdlib/features 摘要、native include 解析、target/search 与工具身份；标准安装文件及父目录必须属于 root 且非 group/world 可写。冻结后的每次消费继续复核当前 native 二进制、已记录的实际动态库摘要与该物理安装的所有权、权限和符号链接状态；缺失、未知或变化均撤回旧效果，消费前后使用同一精确作用域。名称、USR、ABI、system-header 位和未命中用户路径均不能单独授予权限。自定义 sysroot、其他安装布局/ABI、未知来源参数及缺失收据保持拒绝；只读核验不执行保存的命令。冻结时保留同一构建完整 native 收据内容，消费时先核对收据集合未删改，再核对其当前物理依赖；不能删去曾使用的 features 记录来缩减信任检查。没有标准头/标准授权的实例仍可按原范围执行，不强制引入标准根。这是有界标准根来源契约，不代表完整实例扫描或真实项目效果已验收。

`v3_preparation.prepare_saved_config` 返回与既有准备字段兼容的机器数据；默认 Web saved-config 准备通过同一后端读取 v2/v3。v3 扩展完整列出目标、平台、preset 到现有 depth 的映射、一次窗口的解析值及未消费声明。多个 target 保留全部身份并禁止启动，不把首目标投影为全部；显式服务端 depth override 暂走旧 effective-config 组合路径，多目标仍拒绝。独立 v3 编辑器保留原始 document 的全部 targets/profiles、相对路径和环境变量引用；空密码不覆盖已有值，失败或迟到响应不丢失草稿，保存后重新准备。旧 v2 builder 不用于回写 v3。配置保存尚无 revision/CAS；浏览器 409 情景仅验证合同响应下的草稿保护。准备只检查配置/路径/工具存在，不执行扫描、模型、构建或索引。

focus/reproduction/max_workers/platform 暂未接实际消费者。配置 execution.stop_at 已接 CLI 共享令牌预算与新建持久作业窗口；显式作业 stop_at 优先，同 request_id 重放保留原窗口，resume 不重新套用配置窗口。Web `/api/jobs` 与 MCP `zscope.scan.run` 创建作业时解析配置窗口，已过期的窗口以 `stop_window_closed`（400）拒绝，不写作业行、不启动 owner。owner 启动的 CLI 核对当前 job/run/owner/input 与运行目录绑定后，以持久 SQL 窗口为唯一预算来源，包括合法空窗口；部分环境或失效绑定不回退配置。独立 CLI 继续使用配置窗口。prepare 仍仅核对配置、路径和工具存在，不表示扫描已完成或模型已连接。单 target 配置可使用保存的 preset 启动作业；初始化器、模板与 CLI 配置命令已迁移，其余执行消费端仍待逐项确认。
