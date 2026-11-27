# Z-Scope 自定义资源接口识别：独立能力评估与优化计划

取证日期：2026-10-13 UTC；主要源码读取与摘要对照窗口为 02:30–02:54 UTC。评估对象是 CINDALA 上正在开发的工作树，不是 HEAD 提交对应的干净版本。本文仅作评估和实施规划，不修改产品代码、配置、既有计划或测试，不创建、执行缺陷注入评测集。

## 1. 结论与取证边界

**Z-Scope 已有可复用的条件契约基础和受限源码核验链路，不能评价为只有名称启发式，也还不能称为通用自定义资源协议自动识别器。** 已知原语、可解析包装器、对象载体映射、条件效果、有向多对多配对、工作簿发布和多个规则消费者已经连接。近期 S02/S03/S04 增加了单槽池、引用留存、同 TU 具体对象路径及当前源码重放。主要差距是发现覆盖的可观测性、超出限定源码形态的效果核验、跨 TU/间接调用的路径闭合、引用计数终结语义、读写锁模式、异步回收及一般 C++ RAII。

优先顺序建议为：保住“未知不解除义务”的边界 → 增加发现/核验覆盖记录和有限的 native 包装器值流 → 一个真实链接目标的跨 TU 闭环 → 引用计数/句柄及锁模式 → 异步与 RAII。复用现有 `ApiContract`、`ContractRegistry`、`ObjectRef`、`LifecyclePaths` 和 `ValidationPipeline`，不另建配对库、协议裁决器或第二套报告终态。

### 1.1 环境、版本与并行开发

| 项目 | 实际观察 |
|---|---|
| 命令执行主机 | PowerShell 的 `COMPUTERNAME=CINDALA` |
| 执行目录 | `<repo>`；`Get-Location` 与命令执行记录一致 |
| 分支 | `v1.3.1_feat/llm-wiki` |
| HEAD | `010f40210b54ba0f79a088312ce5d8be3a82ace0` |
| 首次取证时钟 | `2026-10-13T02:30:31.1965960Z` |
| 首次文件摘要采集 | `2026-10-13T02:32:52.8733777Z`；末次摘要及期间变化见同目录 `EVIDENCE.json` |
| 工作树 | 脏；产品代码、native、测试、模块文档有大量已修改及未跟踪文件。上述 HEAD 不能唯一复现本文现状 |
| 本评估任务 | `01a13318-80b6-7592-bb2d-0d1296cd50aa`；来源任务 `01a11e1c-b0bf-731c-a0a7-551a6447700f` |
| 平台与执行机区别 | 当前任务的应用元数据标记 `hostId=durable`，但文件/命令工具在上述 CINDALA Windows 目录执行。不能把任务服务的 `/tmp/...` 路径当成本次源码所在 Linux 主机 |
| 模型核验限制 | 委派要求使用 Astra；本轮可见执行/任务接口没有返回实际模型标识，未独立核验模型型号，也未切换模型或再派发 Agent |

已读根 `AGENTS.md`、架构、模块导航、配置/状态、分析流水线、检索后端及实施计划的 README、11、19、21。指定工作区及其直接父目录未发现 `.agents/skills`；`.agents` 查询返回“系统找不到指定的文件”。随后只把产品侧 `zscope/skills/{code_semantic_modeling,ownership_contract,concurrency_lock_order}/SKILL.md` 作为被评估的运行时契约阅读，没有把它们当成本任务的仓库协作指令。未依赖本地 memory summary 来证明现状。

另一个会话 `01a12e4c-0efe-7180-91c4-d642b3b0a571` 的开发仍在进行。来自父任务的观察称，02:21:48 UTC 完成 S04 当前源码重放切片，02:24:41 UTC 后继续业务前提反馈写回。**这是转述，不是本轮独立复验。** 取证期间确实读到新 `protocol_feedback.py`、`review_reports.py` 反馈方法和 `protocol_assessment.py` 的回答版本校验；本文把它们列为“部分实现/在研”，不再建议从零开发相同功能。本轮没有向该会话发送消息、暂停、下达指令或写入其文件。

02:53:49 UTC 的摘要对照发现 13 个已采集文件在取证中变化，集中于 S04 反馈/裁决/报告、规则目录和文档；随后复读了关键变更。`object_protocol_path` 已从最初读取的 revision 2 变为 revision 3（仍默认关闭），新增 `protocol_confirmation`、旧业务事实撤回和反馈专项测试。因尚未取得这一新切片的完成声明及运行收据，本文明确将“旧切片已有验证”与“当前新增代码在研”分开；后者不能继承旧 449/262 passed 的结论。

### 1.2 验证证据等级与阻塞

本文的“已实现且有验证”表示：已读实现、已追踪调用方，并有对应仓库测试及可指认的断言；它**不表示本轮重新运行通过**。测试有三类，必须分开：纯合成/受控模型响应，真实 native 集成测试定义，以及既有实施记录转述的运行结果。出现“real terminal tool”也不等于调用真实 LLM。

| 证据 | 本轮处理 | 可得结论 |
|---|---|---|
| 源码、测试及 fixture 说明 | 只读检查；重点核对正反例、跳过条件、发布和消费链路 | 证明代码存在及测试意图/覆盖边界 |
| `21_IMPLEMENTATION_STATUS.md:149–197` 的节点记录 | 已读；其中 S02 499、S03 546、S04 449/262 passed 等是开发记录，不累加 | 支持既有验证历史，但不是本轮运行结果或当前全部脏文件的通过证明 |
| WSL `/tmp` 原始验收 JSON 与二进制身份 | 未读取成功；未验证其对应当前 native 源码 | 无法独立确认运行收据与当前工作树的一致性 |
| pytest、native 重编译、compileall、mypy、真实 LLM、正式 benchmark、portable smoke | 全部未运行 | 不给准确率、召回率、性能、当前测试通过率或发布资格结论 |

权限阻塞：命令 `wsl.exe --list --verbose` 返回原始可读错误码 **`Wsl/E_ACCESSDENIED`**（输出前缀有 UTF-16 显示乱码）。发现后记录时间为 **2026-10-13T02:34:29.0787732Z**；此时间是紧随失败后的记录时钟，不伪称精确进程失败时刻。已停止 WSL 相关步骤，没有提权、重试或换入口绕过。该错误不是工具返回的“自动审批审查拒绝”，不把两者混称。受影响的是 Linux 环境及运行证据核验，Windows 文件只读评估继续。本报告的文本/链接/摘要检查也不替代 Linux 产品测试。

## 2. 实际数据链路：发现、核验、消费分开

```text
标准规范种子 / 人工明确契约
          ↓
入口可达调用图 + 已被契约点名的配对方/透明包装伴随函数
          ↓
IncrementalSemanticModeling
  ├─ 可完整解析的包装器：静态 derive_contracts
  └─ 未知接口：SemanticModeler 提案 → compile_snapshot
                ├─ 受限源码组合 / 协议核验 → must_under_guard
                └─ 只过 schema → schema_only（不解除义务）
          ↓
工作簿合并、人工优先、失效行撤回、重新读取（发布屏障）
          ↓
ApiContract / ContractRegistry / 调用点对象、条件和资源域解析
          ├─ Regex / Clang / Graph / KnowledgeDB 查询
          ├─ Security Semantic Map → 主动发现上下文
          └─ 有界对象路径 → 候选缺失义务 → Validator 当前重放
                                                       ↓
                            当前技术证据 + 未确认业务前提 → 报告
```

入口证据：[Analyzer.prepare_semantics:482](../../../zscope/core/analysis/analyzer.py)、[ScanSession:464](../../../zscope/orchestration/scan_session.py)、[IncrementalSemanticModeling._run:166 / _publish:450](../../../zscope/orchestration/semantic_modeling.py)。前者跳过 Java，C/C++ 普通扫描进入该链路，不能把它误当只有独立 `--infer-user-config` 才执行。可达建模、反向伴随查找和 SCC 调度也不等于全仓所有配置、所有链接目标均覆盖。

另有旧的 `infer_user_config_rows:212`：它确实使用名称、函数体和调用上下文产生带 `inferred:*` 来源的候选行（如 225–239 行）。但 [CLI:408–418](../../../zscope/cli/cli.py) 先执行 `prepare_semantics`，再把旧推断中的 `resource`、`lock` 表排除，只合并辅助表；不能根据这个函数仍存在就宣称现行 C/C++ 规则按函数名自动认定释放。规则侧 `LocalPatternSemanticBuilder.build:45` 读取标准与已发布用户配置；`effects_trusted` 明确阻止单纯 inferred/schema-only 效果获得解除义务权限。

## 3. 现有能力矩阵

分类含义：**已实现且有验证**＝在列明的受限范围有代码和测试；**部分实现**＝有基础但目标能力尚未闭合；**仅设计**＝现有路线提出目标，未找到完整消费链；**未实现**＝检索目标模块未找到所述具体机制；**证据不足**＝不能从本轮证据判断效果或验收。所有行的“验证”均受 §1.2 限制。

### 3.1 自动发现与契约形成

| 能力 | 状态 | 实现与边界 | 实际接入、默认性 | 测试证据 |
|---|---|---|---|---|
| 标准申请/释放、fd、pthread 种子 | 已实现且有验证 | [standard_api.py:11](../../../zscope/semantics/standard_api.py) `standard_contracts`；[defaults.py:44](../../../zscope/semantics/defaults.py) 合并。含 NULL、fd≥0、`posix_memalign` out-param、robust mutex 的 EOWNERDEAD、realloc/cond_wait 转换。存在行为说明不代表每个消费者完整处理该行为 | 普通 C/C++ 建模与规则默认装入；项目同名定义可遮蔽标准模型 | [test_semantic_next_round.py:62](../../../tests/test_semantic_next_round.py)、[test_semantic_coordinator_effects.py:70](../../../tests/test_semantic_coordinator_effects.py)、`test_semantics_defaults.py` |
| 跨过程已知原语包装器发现 | 已实现且有验证（受限） | [contract_compiler.py:879](../../../zscope/semantics/contract_compiler.py) `derive_contracts`、:1592 `deterministic_contract_snapshot`；[semantic_modeling.py:200 / :363](../../../zscope/orchestration/semantic_modeling.py) 补伴随函数。处理多层直接调用、简单别名、参数换位、宏、成功/失败 guard。核心仍是受限源码 token/结构解释，不是通用 SSA/别名求解器 | 标准/已核验/人工根契约 → 静态包装 → 工作簿 → Registry；符合范围时绕过 LLM，默认接入 | [test_wrapper_contract_compiler.py:231 / :527](../../../tests/test_wrapper_contract_compiler.py)、[test_pool_protocol_modeling.py:262](../../../tests/test_pool_protocol_modeling.py)（受控模型；包含未被入口调用的配对方） |
| 错误清理、返回别名、指针转换 | 已实现且有验证（受限） | `derive_contracts:977–1036` 排除借用备选返回、被覆盖对象、能到达有效返回的释放；`:1106` 对未知副作用保留 unknown。支持可证明的 NULL 失败清理及指针恒等转换，不支持任意算术/截断/复杂控制流 | 同一编译、条件和发布链；不是仅凭“内部调用 malloc”认定接口 | [test_wrapper_error_cleanup.py:16 / :53 / :68 / :108](../../../tests/test_wrapper_error_cleanup.py)、[test_wrapper_failure_guards.py:70 / :80](../../../tests/test_wrapper_failure_guards.py)、[test_wrapper_pointer_casts.py:12 / :24](../../../tests/test_wrapper_pointer_casts.py) |
| 无标准原语的项目资源协议发现 | 部分实现 | [compile_snapshot:1365](../../../zscope/semantics/contract_compiler.py) 先用 LLM 的协议提议选核验器；[verify_resource_protocol:188](../../../zscope/semantics/retention_protocols.py) 仅路由三种受限协议。不是对任意 pool/arena/slab/handle/refcount 进行自动契约合成 | 普通建模可提出；仅核验成功的效果可消费，否则诊断/未核验提案。模型发现本身的真实覆盖率未知 | [test_pool_protocol_modeling.py:237 / :245 / :310](../../../tests/test_pool_protocol_modeling.py)；:310 需 `Z_SCOPE_TEST_CLANG_INDEXER`，缺失会 skip，模型响应受控 |
| 侵入式 free-list 获取/归还 | 已实现且有验证（受限） | [pool_protocols.py:19 / :172](../../../zscope/semantics/pool_protocols.py) `verify_pool_contract` / `pool_pair_compatible`；完整受限源码形态、池参数和协议一致性。它与 native 单槽核验不是同等泛化能力；不是任意链表/数组池归纳 | 产生逻辑获取/归还契约，再经包装和普通 Regex/Clang；没有另开一个通用池分析器 | [test_pool_protocol_modeling.py:164 / :183 / :255 / :310 / :432 / :479](../../../tests/test_pool_protocol_modeling.py) |
| native 内嵌单槽池 | 已实现且有验证（受限） | [single_slot_pool.py:27](../../../zscope/semantics/single_slot_pool.py) 要求 `.c`、唯一当前构建、native v5/resource receipt、真实 record USR；区分资源地址、池实例、live guard，可记代际增量。拒绝 union、未知调用、副作用、非支持宏 | 普通契约发布可用；效果消费不自动等于最终缺陷确认。物理存储仍存在，归还不是 heap free | [test_single_slot_pool.py:107 / :213 / :254 / :300 / :371 / :397 / :423](../../../tests/test_single_slot_pool.py)，含 native→工作簿→候选链 |
| 成功留存/失败未留存与所有权转移 | 部分实现 | [retention_protocols.py:27](../../../zscope/semantics/retention_protocols.py) 可核验单字段条件存储，提议 `ownership_transfer` 也只发布实际可证明的 `reference_retention`；[contracts.py:365](../../../zscope/semantics/contracts.py) 支持条件转移契约，但业务责任不能由赋值推出来 | 条件人工契约、已知契约组合可用；自动源码留存事实进入图和候选，清理责任仍需独立依据 | [test_conditional_ownership_contracts.py:46 / :151 / :192](../../../tests/test_conditional_ownership_contracts.py)、[test_retention_protocols.py:64 / :143 / :157](../../../tests/test_retention_protocols.py) |
| 出处、置信度、效果权限 | 已实现且有验证 | [ApiContract:258 / effects_trusted:278](../../../zscope/semantics/contracts.py) 存 source/confidence/evidence/verification；编译器版本 v20、契约 v5。`schema_only`、confidence=高分均不授予 must；人工/标准规格与源码核验需分别理解 | 工作簿重读后权限保留，Security Map 区分 program/user/llm；来源并不等于调用必然可达 | [test_pair_evidence_authority.py:11 / :39 / :75](../../../tests/test_pair_evidence_authority.py)、[test_security_map_contracts.py:49 / :130](../../../tests/test_security_map_contracts.py) |
| 调用点统计/错误路径挖掘未知释放器 | 未实现（本文指定机制） | `semantic_modeling.py:166` 有可达图、配对方查找和 LLM 提案，未见 K-MELD 式按资源 def-use 分组的序列支持度挖掘、反例消歧和统计资格记录 | 当前可作为 LLM 上下文线索，不存在可直接授权的通用“常见配对即契约”通道 | 无该机制专项验收；现有 `test_pool_protocol_modeling.py:262` 只验证提案及静态组合 |
| 自动识别质量/置信度校准 | 证据不足 | 未取得真实工程、独立标注下的契约发现基线；测试里的置信度值不构成概率校准 | 不给已达到的准确率/召回率承诺；当前不开展缺陷注入评测 | 受控模型测试和已报告回归数不能替代这项证据 |

### 3.2 契约消费、对象路径与遗漏边界

| 能力 | 状态 | 文件、符号与实际行为 | 接入/默认性与边界 | 测试证据 |
|---|---|---|---|---|
| 资源族、对象、out-param、字段/全局 | 已实现且有验证（消费者有界） | [ObjectBinding:151 / resolve:191](../../../zscope/semantics/contracts.py) 区分返回值、参数、输出参数、字段、全局、`address_of`；[release_status:814](../../../zscope/semantics/contracts.py) 同时核对对象、族和域 | Registry → 调用解析 → 多个候选引擎；支持 schema 不等于每个规则都支持每种载体。旧生命周期 provider 对未闭合 out-param 状态保留缺口 | [test_acquisition_carrier_consumers.py:22](../../../tests/test_acquisition_carrier_consumers.py)、[test_semantic_contract_chain.py:77 / :369](../../../tests/test_semantic_contract_chain.py)、[test_wrapper_contract_compiler.py:115 / :215 / :353](../../../tests/test_wrapper_contract_compiler.py) |
| 有向、多对多条件配对 | 已实现且有验证 | [ContractRegistry._edges:568 / allows:645](../../../zscope/semantics/contracts.py)，共享释放端不形成传递闭包；实际 release 还必须满足对象/池/guard，歧义符号拒绝授权 | 普通 Regex/Clang/Graph、KnowledgeDB、Validator 消费；不是名字的一对一字典 | [test_semantic_contract_chain.py:38 / :231 / :324](../../../tests/test_semantic_contract_chain.py)、[test_contract_symbol_ambiguity.py:25 / :47 / :67](../../../tests/test_contract_symbol_ambiguity.py) |
| 条件效果冲突与 unknown | 已实现且有验证 | [ApiContract.applicability:365](../../../zscope/semantics/contracts.py)、`contract_conditions.py` 保留 applies/no_effect/unknown；相反效果不能靠列表顺序覆盖 | 调用点 guard/事实参与；未检查返回值不自动成功，unknown 不能排除泄漏或证明安全 | [test_conditional_ownership_contracts.py:66 / :79 / :107](../../../tests/test_conditional_ownership_contracts.py)、[test_wrapper_contract_compiler.py:408 / :505](../../../tests/test_wrapper_contract_compiler.py) |
| 旧资源候选与生命周期义务消费 | 已实现且有验证（局部范围） | [regex.py:228](../../../zscope/core/candidates/regex.py)、[graph.py:203](../../../zscope/core/candidates/graph.py)、[lifecycle_analysis.py:138 / _call:293](../../../zscope/retrieval/lifecycle_analysis.py)；后者按函数路径跟踪别名/赋值版本、释放与返回，未知调用/持久所有者保持缺口 | 普通资源规则和既有 proof provider 链路；不能因为 S03 新规则关闭，就说所有资源检测默认关闭，也不能把 Graph 的跨函数线索当完整跨 TU 证明 | [test_lifecycle_obligations.py:70 / :85 / :98 / :257 / :283](../../../tests/test_lifecycle_obligations.py)、[test_source_lifecycle_provider.py:363 / :475 / :567](../../../tests/test_source_lifecycle_provider.py) |
| 同 TU 池/留存具体对象路径、代际 | 已实现且有验证（实验性） | [LifecyclePaths:86 / run:116 / _load:207](../../../zscope/core/candidates/cpp_domains/lifecycle_paths.py)；调用帧、USR、字段、池、获取代次；默认 512 步/12 层；unknown 输入、外部/间接调用、循环、unsupported conversion 均未闭合。失败路径前缀不输出完整观察 | [resource_lifecycle._run_object_protocol_paths:1215](../../../zscope/core/candidates/cpp_domains/resource_lifecycle.py)；`object_protocol_path` 最初 revision 2、末次已为在研 revision 3；`retained_slot_release` revision 1，均 experimental/default-disabled，见 [catalog:3630](../../../zscope/rules/builtin_catalog.yaml) | [test_lifecycle_paths.py:89 / :104 / :119 / :141 / :176 / :196 / :240 / :282 / :310](../../../tests/test_lifecycle_paths.py)、[test_retained_slot_teardown.py:182 / :220](../../../tests/test_retained_slot_teardown.py) |
| S04 当前重放、条件性风险和报告 | 已实现且有验证（实验规则范围） | [assess_protocol_candidate:96](../../../zscope/core/validation/protocol_assessment.py) 从当前 CodeIndex/Registry 重放，校验对象、路径、源码和契约摘要；[runner:2812](../../../zscope/core/validation/runner.py) 接入；[pipeline:93](../../../zscope/core/validation/pipeline.py) → needs_review 子状态；[issue_markdown:511](../../../zscope/reporting/issue_markdown.py) 展示 | `business_conditional` 仅技术闭合而业务前提未确认；技术缺口为 `protocol_pending`。JSON 重载不能恢复当前进程核验权限；不能泛化为所有规则统一四态 | [test_protocol_assessment.py:35 / :59 / :85 / :106 / :130 / :172 / :201 / :216](../../../tests/test_protocol_assessment.py) |
| S04 业务回答持久化及失效 | 部分实现／并行在研 | [protocol_feedback.py:15 / save:46](../../../zscope/config/protocol_feedback.py)、[user_config_store.py:113](../../../zscope/config/user_config_store.py)、[review_reports.py:105 / save_business_review:141](../../../zscope/web/review_reports.py) 已见回答与乐观版本。末次 [protocol_assessment.py:268 / :306 / :333](../../../zscope/core/validation/protocol_assessment.py) 加入 `protocol_confirmation/reset_business_facts/publish_business_facts`；[proofs.py:268](../../../zscope/core/validation/proofs.py) 接入带明确业务声明的当前路径确认 | 本轮不干预、不重复建设；不能用旧 449/262 passed 证明这些新改动已验收。新确认以当前路径和 scoped user declarations 为条件，否定业务回答不成为全局安全证明 | 新增 [test_protocol_feedback.py:46 / :64 / :76 / :87 / :106 / :140 / :181 / :230](../../../tests/test_protocol_feedback.py) 已读测试名称和入口；本轮没有完整复查全部断言或运行收据 |
| 自定义 fd/整数句柄、关闭后复用 | 部分实现 | `standard_api.py:99` 支持标准 fd 成功哨兵；`ObjectBinding`/io 角色可表示自定义载体；[resource_identity.ObjectRef:31](../../../zscope/semantics/resource_identity.py) 有代际基础 | fd=0 正确性有测试；未见通用句柄表、dup/shared ownership、close/reopen 同值新代际自动合成；不能把单槽指针代际当句柄全覆盖 | [test_lifecycle_obligations.py:257](../../../tests/test_lifecycle_obligations.py)、[test_wrapper_error_cleanup.py:114](../../../tests/test_wrapper_error_cleanup.py)；其余证据不足 |
| 引用计数 retain/drop/最后引用终结 | 部分实现（规则线索）；通用契约推断仅设计 | [resource_lifecycle.py:2298](../../../zscope/core/candidates/cpp_domains/resource_lifecycle.py) 检查局部 `ref_count` 及 free；[concurrency_shared_state.py:2601](../../../zscope/core/candidates/cpp_domains/concurrency_shared_state.py) 有更新时序规则。`ROLES` 未定义完整 retain/drop/terminal destroy 协议 | 普通规则线索仍在；未见自动验证“递减且为最后引用才销毁”的通用协议核验器。字段名/窗口规则不等于自定义引用计数识别，不得把每次 drop 当 free | `test_cpp_candidate_domains.py` 等现有领域回归；未找到完整自定义 refcount 契约→末次引用→候选→裁决专项链 |
| try-lock/锁包装器 | 已实现且有验证（成功条件有界） | `standard_api.py:127 / :154`、`derive_contracts` 支持返回成功和失败路径；内部已配平锁不伪装为对外持锁；隐藏返回状态保留 unknown | 普通锁/图规则消费对象和 guard；robust mutex 的 EOWNERDEAD 已考虑，但项目锁的任意成功码仍依赖正确契约 | [test_wrapper_failure_guards.py:80 / :133](../../../tests/test_wrapper_failure_guards.py)、[test_wrapper_contract_compiler.py:70 / :275 / :469](../../../tests/test_wrapper_contract_compiler.py) |
| 读/写模式、递归深度、升级降级 | 部分实现 | `standard_api.py:154–161` 把 rdlock/wrlock 都登记为 role=lock、family=rwlock；本轮未找到相应共享/独占模式状态与升级降级闭环 | 能识别名称对应标准锁角色，不等于能证明读锁下写操作、递归锁重复获取或 lock upgrade 的安全性 | 有基础锁条件测试；没有本轮可确认的模式矩阵和端到端消费证明 |
| 异步 callback/cancel/complete/drain | 部分实现；通用并发协议仅设计 | `standard_api.py` 有 callback/thread/cond_wait 语义，既有共享状态/回调规则提供线索；`LifecyclePaths` 只执行确定顺序的同 TU 路径，volatile/atomic 返回缺口 | S03 中 cancel→complete 的顺序测试不能证明真实调度、共同可达、HB/MHP、注销后 drain 或唯一清理。属于 [S06 计划](../../plans/agent-scanning/11_IMPLEMENTATION_BACKLOG.md) 的待补范围 | [test_lifecycle_paths.py:104 / :310](../../../tests/test_lifecycle_paths.py) 及 fixture 说明只支持所列顺序场景 |
| C++ 自定义 RAII/智能指针 | 部分实现 | [ProgramEvents.h:35](../../../native/clang-indexer/ProgramEvents.h) 发 implicit_release 析构事件；[typed_resources.py:190](../../../zscope/core/candidates/cpp_domains/typed_resources.py) 有智能指针相关模式。没有从该事件自动证明内部自定义资源释放的完整契约链 | 新单槽和具体路径限定 `.c`；不能把析构发生等同销毁其管理资源，move/release/reset/custom deleter/异常展开仍需专项模型 | 现有 native/typed-resource 基础测试；自定义 RAII 自动识别与条件消费证据不足 |
| 构建/依赖失效与多变体 | 部分实现（隔离基础有验证） | [BuildContext.create:32](../../../zscope/retrieval/build_context.py) 绑定命令、工具、依赖、target、link_target；[build_scope.py:42](../../../zscope/semantics/build_scope.py) 拒歧义/失效事实；[semantic_modeling.py:997](../../../zscope/orchestration/semantic_modeling.py) 比较 code/compilation/dependencies/callees/manual/spec，build receipt 改变后有契约者重建 | S01 已把身份送入多处候选/验证/反馈；仍有旧导航调度和缓存容量限制，link_target 为空时不能证明跨 TU 归属，完整扫描看 `metadata.build_coverage` | [test_contract_build_scope.py:27 / :73 / :98 / :140](../../../tests/test_contract_build_scope.py)、[test_native_model_cache.py:31 / :61](../../../tests/test_native_model_cache.py)、[test_incremental_semantic_modeling.py:53 / :275 / :306 / :350](../../../tests/test_incremental_semantic_modeling.py)、`test_candidate_build_identity.py` |
| 向 SVF/Saber 注入发现出的项目契约 | 证据不足／未见桥接实现 | [svf_runner.py:80 / :122](../../../zscope/retrieval/svf_runner.py) 运行 WPA/Saber；[svf_value_flow.py:144](../../../zscope/core/candidates/svf_value_flow.py) 要求 Validator 对照源码所有权。本轮检索 SVF/Unified 消费端未见 ApiContract→ExtAPI/IR allocator model 的转换 | 源码规则消费和 LLVM 后端信号可汇合，但不能宣称自定义包装器已进入 SVF 堆对象建模。潜在收益应独立小范围验证 | 无该桥接专项验收证据 |

## 4. 与一手方法的比较

以下是方法适用性对照，不是工具跑分。没有下载或运行外部工具，没有借用 Java/C# 结论证明 C/C++ 的可实现性或性能。

| 方法 | 自动推断与消费的分工 | 对 Z-Scope 的可用启发与不可照搬部分 |
|---|---|---|
| K-MELD，NDSS 2021 | Linux C：结合返回值使用/结构筛分专用 allocator；从常见错误路径操作序列挖掘 deallocator；再做路径/字段敏感的逃逸和 consumer ownership 推断。依赖“大量用法通常正确”的假设，间接调用、路径可行性与复杂别名仍有限 | 可以把调用点/错误清理路径作为**提案证据**，保留支持与反对样本；不能把常用释放或逃逸直接变成业务责任事实。论文 458 条泄漏告警中确认 218，**52% 是泄漏告警误报率，不是配对错误率**；稀有释放、device-managed 资源、不可行路径会影响结果。不能当 Z-Scope 的误报基线或锁分析能力。[论文 §IV–VI](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_5B-4_24416_paper.pdf)、[会议原页](https://www.ndss-symposium.org/ndss-paper/detecting-kernel-memory-leaks-in-specialized-modules-with-ownership-reasoning/) |
| CAFD / WrapperDetect | 从标准 allocator 种子迭代，前向检查分配结果去向、后向检查返回值来源，再以 LLM 区分可忽略与不可忽略副作用。目标是可按 malloc 建模的 S-CAF；不是释放、池域、锁协议的通用配对器 | 复用其“返回值流候选＋副作用单列”思路，扩展既有静态包装器核验；LLM 仅提出分类，Z-Scope 的 must 效果仍由检查器授予。返回资源同时写入全局/容器，或者借用外部指针，不能仅因返回 malloc 结果而获得 fresh/no-alias 资格。out-param 资源接口可被 Z-Scope 支持，却不必是 CAFD 意义上的 S-CAF。仓库以单 LLVM bitcode 为输入，本轮不移植运行。[论文 §2、§4](https://arxiv.org/html/2509.22530v2)、[作者仓库](https://github.com/for-just-we/WrapperDetect) |
| Clang ownership 属性 | 显式契约消费；`ownership_returns/takes/holds` 区分分配、释放和接管后未来释放，资源 kind 与参数索引提供模型 | 可导入已存在注解为带来源的声明契约，并与实现核验分层；`holds` 不能转成立即 free。官方页面还要求相应 analyzer 配置。属性存在不是自动推断证明。[官方属性文档](https://clang.llvm.org/docs/AttributeReference.html#ownership-holds-ownership-returns-ownership-takes-clang-static-analyzer) |
| Clang Thread Safety Analysis | 基于显式 capability 注解；共享/独占、try-acquire 成功值、scoped capability/RAII、锁对象与顺序。分析本身不作通用跨过程推断；函数指针注解也有信任和支持范围限制 | 适合作为锁模式 schema 与少量语义对照；不能声称注解系统解决了项目锁的自动发现。Z-Scope 当前 rd/wr 同 role 的信息损失应优先补齐，随后再谈 lock upgrade 和复杂 RAII。[官方说明](https://clang.llvm.org/docs/ThreadSafetyAnalysis.html) |
| GCC `malloc(deallocator, ptr-index)` | 显式关联适用 deallocator 及其参数位置，供不匹配释放等诊断消费。无参 `malloc` 的非别名性质与带 deallocator 的关联是不同承诺 | 模型导入应保留声明含义，不从“有释放关联”自动推出 fresh/no-alias，也不把释放函数绑定成全局唯一。它不提供通用项目协议挖掘。[GCC 15.2 官方文档](https://gcc.gnu.org/onlinedocs/gcc-15.2.0/gcc/Common-Function-Attributes.html) |
| Cppcheck library cfg | 外部库显式模型；std.cfg 中以 memory/resource 分组列 alloc/realloc/dealloc，参数/返回等约束另行配置 | 可借鉴可审阅、版本化的库模型与消费回归；不能把 cfg 支持误写成自动识别项目配对。无需立即引入另一份平行配置库。[官方手册](https://cppcheck.sourceforge.io/manual.html#library-configuration)、[官方 std.cfg](https://raw.githubusercontent.com/danmar/cppcheck/main/cfg/std.cfg) |
| CodeQL C/C++ Allocation | 模型接口显式区分 AllocationFunction/Expr 与 HeuristicAllocationFunction/Expr；提供大小、realloc 参数、是否需 deallocation 等扩展点 | 借鉴“已建模”和“可能分配”的类型分隔与查询消费，而非宣称该接口自动还原所有资源契约。当前 Z-Scope 可用 verification/authority 承担此分层。[官方 API](https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/models/interfaces/Allocation.qll/module.Allocation.html)、[一手源码](https://github.com/github/codeql/blob/main/cpp/ql/lib/semmle/code/cpp/models/interfaces/Allocation.qll) |

## 5. 差距与风险排序

下表是基于实现边界的工程风险分析，**不是宣称已经复现了相应产品缺陷**。

| 优先级 | 风险与影响 | 现有防线／应复用点 | 应补内容 |
|---|---|---|---|
| P0 | 未核验提案、未知 guard 或引用留存被当成 must-release/transfer，会误排除真实问题；反向把逻辑归还当 physical free 会制造 UAF/双重释放误报 | `effects_trusted`、条件冲突处理、source-protocol 核验、S04 业务前提和缺失义务 | 每个新增消费者都检验效果权限、操作种类、作用对象和 guard；发布指标区分 proposed/verified/manual/unsupported，不仅统计“契约条数” |
| P0 | 不同构建、链接目标、同名符号、池实例或获取代次混用，会同时造成误报与遗漏 | BuildContext、USR、ObjectRef、scope、候选身份、当前重放已存在 | 先完成一个真实链接目标的可核验跨 TU 边；未知链接/多目标不得按函数名拼接。缓存未命中是性能问题，错误复用是正确性问题 |
| P1 | 仅支持少数源码形态、具体无参数入口、可达导航，会漏掉真实工程常见协议；“零候选”可能只是未识别 | native 事实、受限编译器、具体路径 gaps、`build_coverage` | 每个未解决接口/路径记录原因与消费者未覆盖项；先扩展受控 wrapper 形态和入口输入，不能用放宽 must 门槛换召回 |
| P1 | 存量消费者的支持程度不一致：Registry 可表达，不代表 Regex/Graph/旧 lifecycle provider/SVF 全支持 | 现有 all-consumers 测试、统一调用解析、source lifecycle provider | 建立契约能力→消费者支持表；对未消费的 carrier/domain/mode/transition 标 unknown，避免只看 pair allows |
| P1 | refcount 的 drop、最终 destroy、借用和异步留存混淆；fd 同数值重开/dup 共享状态混淆 | resource identity 和条件效果可扩展，现有局部规则仅作线索 | 显式 retain/drop/terminal destroy/handle generation；证明最后引用与回调清理条件，未证明不得解除责任或报立即释放 |
| P1 | 读写锁被压成同类 lock，正确的 try-lock/recursive/upgrade 行为可能误判，错误写入也可能漏掉 | 成功条件、实际锁载体、锁图已有 | 增加 shared/exclusive/unknown、深度/递归约束、等待临时释放再获取；禁止只用“存在锁名”排除竞争 |
| P2 | 将顺序 cancel→complete 当并发协议，或将析构事件当资源已释放 | S03 顺序路径、S06 规划、native destructor 事件 | 要有执行上下文、可并行/HB、唯一清理条件、drain；C++ 单独做管理对象与被管理资源映射 |
| P2 | 标准规格仅在 `behavior` 文本里表达的细节被忽略，例如 close 错误后的平台状态 | `standard_api` 已有版本与来源及部分 structured transitions | 逐项核验所支持平台的成功/失败效果；不能从 no-effect 默认模板扩展所有 API，也不能因为 behavior 写了说明就宣告消费完成 |
| P2 | 缓存只跟踪已有调用者，不跟踪新访问者/回调和“无其他清理”的否定性依赖 | 当前 code/compilation/dependencies/callees/manual/spec、S07 规划 | 对新增/删除用法、回调目标集合及业务答案 revision 传播失效；全量与增量结果/未知集合都比较 |

### 5.1 与 S03/S04 的明确分工

| 现有/在研工作 | 本计划处理 |
|---|---|
| S01 构建身份、候选/反馈隔离 | 直接复用；仅补真实链接目标、全实例调度与跨 TU 的未闭合部分 |
| S02 单槽池、留存、条件契约、包装器 | 直接复用；补新的受支持形态、效果类别和发现诊断，不重建协议库 |
| S03 retained slot、同 TU 具体对象路径 | 直接复用其调用帧/代际/路径输入，扩展时保持现有范围声明；不把它改名重复实现 |
| S04 重放、业务前提、needs_review 投影 | 已交付切片保留；新增协议提供精确 obligation/provider，不能另写一套 final verdict |
| S04 回答写回/依赖失效 | 主会话在研，本计划只规定接缝验收；不再排一个并行业务反馈开发任务 |
| S05 复现、S06 异步、S07 需求建模 | 复现按缺口复用；异步归入 S06；新增依赖和调度归入 S07。没有首批收益证据就不接额外求解器/Agent |

## 6. 分阶段优化计划

工作量为熟悉本仓库的 C/C++ 分析与 Python 工程人员的**有效人日区间**，包括实现、相关回归和文档；不含等待环境恢复、外部模型服务、正式发布或全量准确率评测。阶段可按领域拆分，但共享 native/schema/消费链的修改不要在同一工作树同时推进。数字是规划估计，不是性能或精度承诺。

### P0：接续点核对与覆盖可观测性（2–4 人日）

- 范围：在 S04 反馈交付后核对当前接口与测试，只新增缺失的契约发现/核验统计。区分 `not_seen`、`proposed`、`schema_only`、`source_verified`、`manual_assumption`、`unsupported`、`stale/conflict`；这些是建模状态，不新增漏洞终态。
- 依赖/落点：`GlobalModelStats`、`semantic_modeling` 的 diagnostics/publication、现有 engine coverage 和报告 metadata。先复用现有字段，确有缺口才扩展 schema；不把状态写入 public YAML。
- 验收：一个 API 可回溯到输入符号/构建、候选来源、核验器及拒绝原因；未检查返回、未知调用、被遮蔽标准 API 和不支持协议均可见。关闭实验规则时仍可解释“有契约但未运行该消费者”。
- 场景/风险：部分模型失败、缺 native receipt、相同名字不同 TU、空实现、未被入口覆盖的 cleanup。避免逐调用重复膨胀日志；按接口和调用点分别计数。

### P1：受限 native 值流增强现有包装器核验（8–15 人日）

- 范围：以标准/人工/已核验根契约为起点，复用 `derive_contracts`；增加函数内 native def-use/CFG 对返回值和 out-param 的小范围证明。优先支持局部别名、参数换位、显式成功码、失败清理、同一字段输出；不给任意 C 控制流做通用求解器。
- 依赖/落点：P0；`ProgramEvents.h` 已有 defs/uses/参数/return/guard、`contract_compiler`、`call_context`、`contracts`。新增提案仍进入同一 `compile_snapshot` 和工作簿发布屏障。仅在缺事实时修改 native 并真实重建。
- 效果要求：将“调用者得到一个资源义务”和“可视作 fresh/no-alias 分配器”分开；最少记录外部存储、借用备选返回、不透明调用、返回前释放、成功/失败路径的差异。LLM 提议忽略 logging 不能自动消除日志函数的未知副作用。
- 验收：同一受支持源码在静态组合、工作簿重读、Regex/Clang/Graph/SecurityMap/Validator 观察到一致对象/guard/domain；错误分支上 free 不污染成功返回，成功分支被释放的对象不得成为可靠 allocator；out-param 的状态码不得当指针。改变头文件/参数/guard 或根契约后旧结果失效。
- 验证场景：两层直接 wrapper；NULL 失败；整数状态 out-param；`&p` 与 `pp`；字段输出；别名重赋值；借用或新对象混合返回；全局保存；额外申请两个资源；未知调用与函数指针；不支持转换仍 unknown。
- 风险：同样数据被 token 和 native 两条路径给出矛盾结果。决策是优先保留冲突/未知，不在失败时静默切换较弱路径授予 must。已有形态继续兼容，确认支持后再简化重复解释逻辑。

### P2：一个真实链接目标的跨 TU 与有限间接调用（12–22 人日）

- 范围：先跨 TU 直接调用及显式项目边界，再支持初始化可核验、目标集合封闭的小型函数指针表。跨 TU 自动发现可使用调用图；跨 TU **证明**必须携带每个 TU 的 BuildContext 和同一链接目标收据。
- 依赖/落点：P1、S01；`build_context/indexing_inventory/knowledge_db/code_index`、GlobalModeler/SCC、`LifecyclePaths._load`、Validator provider。不能要求两个不同 TU 的内容 BuildContext ID 字面相同，需按共享目标兼容性连接各自实例。
- 验收：同名 static 函数、两个 executable、不同宏变体和缺失 TU 不可混用；目标集合新增/变化导致摘要与消费者失效。间接调用若仅部分目标释放，效果必须 conditional/unknown，不能取一个目标证明所有调用。
- 场景：TU-A 获取、TU-B 错误清理；跨文件 queue wrapper；两种锁目标；一个空释放目标；动态重写 ops 表；目标未知/递归不收敛。参数/对象映射及路径缺口应完整进入报告。
- 风险：链接信息缺失和别名集合过宽。首版只接受可验证目标，声明余下覆盖缺口，不做按签名猜测的 must 调用。

### P3：条件化 refcount、池和句柄协议（12–24 人日，按子域交付）

- 范围：先一个项目内的非并发 refcount 实现，以及已支持单槽池的一种小扩展；独立定义 retain、drop、最后引用触发 destroy、logical return、物理 destroy、borrow/escape。之后再做句柄表的同值重用和 dup 共享底层对象。arena/slab 批量 reset 后置。
- 依赖/落点：P1；跨 TU 场景依赖 P2，业务责任反馈复用 S04。扩展 `ApiContract.protocol`/条件转换、`resource_identity`、协议 verifier、资源候选及专门事实 provider，不让一个泛化 deallocator 位替代全部操作。
- 验收：仅 decrement 不证明对象失效；`dec_and_test` 的成功分支及析构 callback 的真实对象都核验后才能授予终结效果；池实例、槽地址、获取代次独立，业务计数器回绕不能证明永久唯一。借用不增加清理责任，获得引用也不自动拥有全部底层资源。
- 场景：refcount 2→1、1→0、饱和/下溢、失败 retain、多个别名、先借用后异步；归还错池、重新获取同地址、generation wrap；handle=0 有效、close 失败状态不确定、dup、关闭后同值重开。
- 风险：引用计数本身的原子性与销毁时序超出非并发切片；先保留 S06 缺口，不以 sequential counter 证明线程安全。

### P4：锁模式和有限 C++ RAII（10–18 人日）

- 范围：标准及透明包装的 shared/exclusive/unknown 模式、try-lock 成功/失败、精确锁实例；再支持一个有明确析构效果的 scoped guard。recursive depth、upgrade/downgrade 作为显式协议，暂不从名称推断。
- 依赖/落点：P1、共享 schema 与规则资格流程；`standard_api`、`contracts/contract_conditions`、锁图/共享状态候选、native 隐式析构、Validator。对已有 Clang/GCC 注解只做受支持字段导入，保留 annotation provenance，不能把声明当源码证明。
- 验收：读锁不得为写入提供排他证明；失败 try-lock 不持锁，隐藏状态为 unknown；不同对象的同名字段不是同一锁；只获取后才释放。析构事件必须映射管理器到被管理资源；move、adopt/defer/release/reset 未支持时公开缺口。
- 场景：rdlock 下写、wrlock 下读、try-lock 两支、EOWNERDEAD、递归两次只解一次、升级自死锁、cond_wait 临时解锁、正常/异常退出 guard、空 guard、自定义 deleter。
- 风险：把既有 lock-only 规则直接喂新模式后悄悄丢字段。按消费者能力表逐一迁移；未迁移者不得用于强反证。

### P5：异步清理与完整增量（异步 15–30 人日；增量 6–12 人日）

- 范围：一个 queue/cancel/complete/unregister/drain 实际协议，把线程/回调执行上下文、共同可达和清理唯一性连入现有路径。增量另跟踪新增调用者、回调目标集合、访问者集合和否定性依赖；不是仅比较原有 callee hash。
- 依赖/落点：S06/S07，P2/P3/P4 按场景选用；callback/shared-state facts、`security_map/active_discovery`、`semantic_demand`、缓存 manifest、S04 provider。动态证据只在需要时复用 S05，不替代协议推理。
- 验收：同锁可排除数据竞争的证据，不能同时排除锁内串行 UAF；cancel 后真正 drain 与只设置标志区分；新增 callback 或修改业务回答 revision 后旧裁决失效；全量/增量在候选、最终状态、未决和覆盖上语义一致。
- 场景：cancel 与 complete 互斥、可能并发、同代/异代、回调已开始但未结束、注销阻止新调用却未 drain、join 后释放、新增消费者。未解出的调度/输入不转成安全。
- 风险：状态空间、成本和否定性依赖范围。先一个真实协议与有界 witness，报告预算/不完整；没有基线前不承诺总体提速或召回不变。

## 7. 最小首批范围及可直接交接的任务

**建议首批只实施 P0 + P1 的单构建、同 TU、直接调用子集，约 10–19 人日。** 这是对已有包装器核验的扩展和消费一致性加固，不重做已有单槽池/S04。先让未知接口“为什么没被核验”可解释，再以少量真实工程常见形态扩大可证明范围。读写锁模式可作为随后独立小切片，不能挤入首批后仍宣称只有简单包装器工作量。

| 任务 | 具体交接内容 | 完成条件 | 预计人日/依赖 |
|---|---|---|---|
| A0 当前接缝核对 | 待主会话 S04 反馈交付，读最终 diff 与对应 Linux 证据；确认 `assess_protocol_candidate`/answer revision 的入口。保留本评估列出的旧缺口，不覆盖其文档 | 区分已交付/在研/待做，关键文件和工具版本可追溯；未复验项仍标明 | 1–2；环境可用，S04 当前切片 |
| A1 发现状态与覆盖 | 在现有 stats/diagnostics 增加未见、待核验、不支持及失败原因；从已发布契约可定位输入和验证方法 | 无名称启发式晋升，无新增漏洞终态；关实验规则也显示未消费范围；不重复记录所有原始代码 | 1–2；A0 |
| A2 最小 native 证据适配 | 复用当前 defs/uses/call-result/return/guard，为包装器核验提供统一函数内值流视图；缺值、跨帧或复杂转换明确 unknown | 同一对象的 return/out-param/参数/字段能保留 USR、站点和构建；若改 native 先真实重编译 | 2–4；A1 |
| A3 wrapper 条件效果核验 | 只支持直接已知根调用、局部别名、两层包装、整数成功码和失败清理；记录外部保存/不透明调用；allocator 义务与 fresh/no-alias 资格分开 | 借用备选返回、返回前释放、未知副作用不能获得强契约；已有 token 支持与 native 冲突不降级授权 | 3–6；A2 |
| A4 发布与消费者一致性 | 复用 Workbook/Registry 发布屏障，逐查 Regex/Clang/Graph/KnowledgeDB/SecurityMap/Validator；完善缺字段未知行为；检查标准失败条件消费 | 同对象/guard/domain/authority 一致；错误池不能消除义务，schema-only 高分不能授权，单条 disabled 不抑制 backend signal | 2–3；A3 |
| A5 接续验证与说明 | 只补上述变化直接相关的正反例及增量回归，运行 Linux 定向测试；按风险 compileall/mypy/native；更新对应模块/规则目录 revision | 明确 pass/fail/skip、真实模型与受控响应；无精度承诺；默认开关按实际资格决定 | 1–2；A4；与前项测试工作部分重叠，区间不等于保证工期 |

首批暂缓：任意函数指针和跨目标链接、无 seed 的通用统计配对挖掘、任意 arena/slab/reset、无锁/RCU/弱内存、完整 refcount 并发证明、复杂 C++ 模板/RAII、SVF 自定义模型桥接、外部求解器、外部 Agent、运行缺陷注入数据集，以及把所有实验性协议规则默认开启。

### 7.1 后续验收最小判据

以后实施时为每个支持形态记录：发现是否成功、载体/条件/资源域是否正确、验证权限是否正确、哪些消费者实际使用、最终仍缺哪些义务。正例是“应该建立的契约/应该保留的风险”，反例是“不得建立的强效果/应该排除的假路径”，不要只统计告警条数。

独立质量评估需要另行授权和协议：先在真实工程接口清单上人工独立标注，分别度量候选发现覆盖、已核验契约精度、未知率、错误解除义务、最终误报与漏报；按标准包装、out-param、池、refcount、句柄、锁、构建变体分层。模型/扫描输入不得获得标注。当前不生成该数据集，不声称已有这些指标。Linux 正反例与正式 Range/发布门禁是不同用途，不能互相替代。

## 8. 交付及使用注意

本目录只有独立评估报告和取证摘要。`EVIDENCE.json` 保存读取范围内文件的前后 SHA-256、时间、末次 git 状态及活动变更列表；它不保存源码、密钥、模型 endpoint 或用户工程配置内容。哈希采集和文件读取不是原子快照，活动变更明确保留，实施前应按符号重新定位行号。

本轮没有修改源代码/配置、运行模型/扫描/测试、创建评测集、操作其他会话或 commit/push。唯一运行阻塞是上述 WSL 权限错误；模型型号和既有 Linux 原始验收收据的独立核验也未完成。报告提供可实施的优先级与任务接缝，不把现有计划中的目标、并行开发中的新代码或历史测试数量冒充当前完整能力。
