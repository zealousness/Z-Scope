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
  - zscope/config/v2.py
  - zscope/config/runtime_defaults.yaml
  - zscope/config/function_entry.py
  - zscope/config/user_config_store.py
  - zscope/config/user_config_workbook.py
  - zscope/orchestration/user_config_inference.py
  - zscope/semantics/contracts.py
  - zscope/semantics/models.py
  - zscope/semantics/inference.py
  - zscope/semantics/defaults.yaml
  - zscope/semantics/user_config_context.py
  - zscope/semantics/security_map.py
  - zscope/snapshots/store.py
  - zscope/memory/review_memory.py
  - zscope/review_memory/identity.py
  - zscope/review_memory/store.py
  - zscope/common/issue_identity.py
  - zscope/common/portable.py
tests:
  - tests/test_portable_runtime.py
  - tests/test_config_v2.py
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

## 职责与非职责

本子系统负责解析和校验用户配置、合并内置/项目语义、维护快照和人工反馈状态，并提供稳定 finding identity、取消和运行限制等公共设施。它连接用户领域知识、历史分析结果和当前扫描。

它不负责选择 CLI 运行模式、不实现后端索引，也不决定报告的展示格式。

## 主入口和数据流

- `ConfigLoader` 只读取严格的 `UserConfigV2`，再与打包的 `RuntimeSpec` 组合为 `EffectiveConfig`；`ProjectConfig` 负责项目路径解析。
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
