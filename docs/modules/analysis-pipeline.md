---
doc_contract: zscope-module-v1
covers:
  - zscope/core
  - zscope/rules
  - zscope/alerts
sources:
  - zscope/orchestration/hierarchical_discovery.py
  - zscope/core/analysis/analyzer.py
  - zscope/core/candidates/pipeline.py
  - zscope/core/candidates/cpp_domains/retained_slots.py
  - zscope/core/candidates/cpp_domains/lifecycle_paths.py
  - zscope/core/candidates/cpp_domains/async_paths.py
  - zscope/core/candidates/cpp_domains/pthread_cleanup.py
  - zscope/core/candidates/cpp_domains/handle_paths.py
  - zscope/core/validation/pipeline.py
  - zscope/core/validation/protocol_assessment.py
  - zscope/core/validation/runner.py
  - zscope/core/validation/proofs.py
  - zscope/core/validation/dynamic_reproduction.py
  - zscope/core/validation/reproduction_planner.py
  - zscope/core/validation/evidence_completion.py
  - zscope/core/validation/review_checks.py
  - zscope/core/validation/lock_coverage.py
  - zscope/core/validation/review_protocol.py
  - zscope/core/validation/review_session.py
  - zscope/core/validation/review_checkpoint.py
  - zscope/common/validator_protocol.py
  - zscope/rules/builtin_catalog.yaml
  - zscope/rules/catalog.py
  - zscope/rules/engine.py
  - zscope/rules/extensions.py
  - zscope/rules/query.py
  - zscope/alerts/verifier.py
tests:
  - tests/test_hierarchical_discovery.py
  - tests/test_autonomous_validation.py
  - tests/test_mode_static_foundation.py
  - tests/test_candidate_pipeline.py
  - tests/test_candidate_ledger.py
  - tests/test_candidate_build_identity.py
  - tests/test_retained_slot_teardown.py
  - tests/test_lifecycle_paths.py
  - tests/test_async_helpers.py
  - tests/test_async_helpers_incremental.py
  - tests/test_async_wake.py
  - tests/test_async_wake_incremental.py
  - tests/test_async_clock.py
  - tests/test_async_clock_incremental.py
  - tests/test_async_drain.py
  - tests/test_async_drain_incremental.py
  - tests/test_linked_lifecycle_paths.py
  - tests/test_refcount_protocols.py
  - tests/test_refcount_integration.py
  - tests/test_handle_protocols.py
  - tests/test_handle_integration.py
  - tests/test_protocol_assessment.py
  - tests/test_protocol_feedback.py
  - tests/test_validation_pipeline.py
  - tests/test_validation_runner.py
  - tests/test_validation_build_scope.py
  - tests/test_contract_usr_scope.py
  - tests/test_dynamic_reproduction.py
  - tests/test_dynamic_reproduction_execution.py
  - tests/test_reproduction_planner.py
  - tests/test_validator_review_memory.py
  - tests/test_review_fact_checks.py
  - tests/test_raii_lifecycle.py
  - tests/test_protocol_incremental_equivalence.py
  - tests/test_lock_modes.py
  - tests/test_lock_coverage.py
  - tests/test_review_experiment_protocol.py
  - tests/test_review_runtime.py
  - tests/test_validator_v3_protocol.py
  - tests/test_evidence_completion.py
  - tests/test_alert_verifier_parallel.py
  - tests/test_rule_extensions.py
  - tests/test_rule_catalog.py
  - tests/test_rule_runtime_governance.py
  - tests/test_escalation_observability.py
  - tests/test_needs_review_sub_states.py
  - tests/test_evidence_completeness_chain.py
  - tests/test_interface_probe_visibility.py
---

## Validator Review Memory

本地 `clang_cfg_acquire_without_release_on_exit` 的候选身份同时包含获取对象、资源域、获取位置及退出边。同一个 return 上的多个资源债务分别保留；新增包装器语义不能以相同退出行替换原候选。同一债务的重复发射仍合并，实验规则启用策略不变。

Project-scoped Review Memory stores human rejected finding records separately
from Wiki constraints. Matching patterns are bounded advisory hints only; they
never create proof, suppress a finding, or replace current source evidence.
Matcher 只消费同一 project、rule/revision、category 且 schema 兼容的 Candidate
稳定字段。函数名可以精确匹配，root cause、source/sink/resource identity 等
字段可以组成跨函数项目模式；groups 之间 OR、同组字段 AND。source context
fingerprint 只用于兼容性/stale，不是跨函数匹配的必需条件。命中会形成
PatternMatch receipt，Validator cache identity 包含 active proposal/contract
digest。离线 replay 只投影 baseline/advisory 两侧并报告潜在影响，不调用
Validator，也不会改变 verdict。

# 分析流水线

## 职责与非职责

`hierarchical_discovery.py` 是 deep 的默认主动发现实现。摘要分别表达预期前置/后置条件、实际效果、状态转换和带对象代次/主体/条件/履行边界的责任；父层保留子责任及真实调用边上的转移链。全局留存不等于释放，未知业务假设不授权确认。函数层使用 modeling profile，功能/模块与主动探索使用 analysis profile；所有候选复用 balanced Validator。报告 `mode_outcomes` 分列静态候选、廉价裁决、额外调查裁决/成本、deep 新候选和带语义补证的确认项；这些是运行漏斗，TP/FP、误拒和因果收益必须由已有独立评分及消融确定。`deep_supplemented_confirmed` 表示带补证上下文的确认，不单凭它宣称收益。

本子系统负责从多种事实源收集和归一化候选，维护全局 Candidate Ledger，并完成分层证据闭合、Validator 三态判断、评分、抑制/baseline 和最终 finding 投影。规则驱动扫描、LLM 主动发现的 hypothesis 与外部 SARIF 告警都在这一层进入相同的候选和验证语义。

它不负责构建 Clang/SVF/Joern 底层事实，不负责 LLM 传输实现，也不负责最终 JSON、Markdown 或 SARIF 序列化。

## 主入口和数据流

- `Analyzer` 装配索引、候选、Agent、工具、预算、快照和 Workflow handler。
- 扫描前规则预检加载包内 `builtin_catalog.yaml`、Skill 契约、显式配置的 `rule_pack_version: 1` YAML pack 和 `zscope.rule_providers` entry point，生成不可变 `EffectiveRuleSet`。
- `CandidatePipeline` 汇总 regex、Clang AST/CFG/matcher、Java 本地规则、图、SVF/Saber 和后端候选，并在合并前施加统一候选门禁。
- YAML pack 和严格 Provider V2 只负责规则特有匹配/证据；语言、CWE、defect class、severity 和 Skill 以 descriptor 为唯一真源。
- Candidate ledger 负责候选身份、合并、生命周期和证据保留。
- 报告去重在同一 canonical root 内逐一匹配独立 occurrence，后续重复可以合并到此前保留的任一位置；不同位置及构建身份仍须通过原有等价性约束。
- `runtime.analysis.validation_cache_entries=0` 同时停用内存和持久化结果缓存；启用时，缓存读写隔离嵌套证据，调用方修改某次结果不会改变其他候选复用的值。
- 三模式共享精确实例上的项目级静态候选基础。fast 面向提交前扫描，默认只展示 `confirmed`，完整保存未决项；balanced 只增强已有候选的裁决，独立根因保存为 deep 线索；deep 增加分层契约发现。所有来源完成后先冻结全局 Ledger，再按 validation cluster 验证一次。precision/recall 目标仍由既有独立 benchmark 检验，不能由模型裁决数量推定。
- C/C++ `fast` 的确定性发现按全部当前 BuildContext 建立项目级计划，而不是由入口逐次触发：每个 `(BuildContext, native USR)` 先生成一次只读 `FunctionFactSummary`，再由 Clang AST/CFG、regex 与 tooling matcher 本地引擎各消费一次。graph-view 与 graph-batch 必须共享完整的调用邻域：有闭合 link record 时在真实 link group 上共同执行一次；没有链接归属时才在精确 TU 图上共同执行一次并保留 coverage gap。这样跨 TU cleanup、ownership 和协议规则能读取被调函数，又不会按函数或入口重复执行图分析。入口只在候选产生后附加可达性和 call path。已证明路径记 `reachable=true`；图尚未闭合时必须记 `status=unknown` 与 coverage gap，不能把入口外或跨 TU 未解析直接宣称为不可达。`analysis_unit_id` 绑定 BuildContext 与 USR，候选在 Validator 前合并去重；缺少真实 link record、跨 TU 边或当前 owner 收据会进入 `zscope.fast-static-scan.v1` coverage gap，不得冒充跨 TU 结论。函数分析单元仍只计一次，因此引擎组合不改变 `duplicate_local_executions=0` 的定义。
- fast 的函数级候选摘要使用 `zscope.fast-static-cache.v12` 持久缓存；键同时绑定源码正文、精确 BuildContext/native program facts、编译器/target/依赖/tool 收据、有效规则摘要、RuntimeSpec analysis 摘要和实例语义摘要。TU/link-group 图摘要绑定全部成员函数缓存键、实例语义与当前 link receipt，任一函数或链接输入变化都会重算该图单元；backend/SVF 单元仍按本轮执行。损坏、过大、不可写或经符号链接重定向的缓存只记 cold/gap，不取得候选或证明权限。v12 将 graph-view 从函数缓存移入 TU/link-group 图缓存并与 graph-batch 一次执行，同时强制图单元消费 planner 已按精确 BuildContext/USR 解析的函数视图、宏引用收据和 program facts；link group 不得重新通过全局索引选择函数正文。生成器构造时保留所有可信且未被 shadow 的精确契约，真正的 effect 授权仍在调用点按当前 BuildContext 与 native callee USR 执行，避免空 ambient scope 提前丢弃用户接口。经真实 link record 闭合的跨 TU 调用只投影成员中带精确 USR 的已授权契约，保留其定义 BuildContext 作为审计字段；未知 USR、组外构建或名称级提示均不取得执行语义。v11 及更早缓存不会被解释为 v12 事实。
- C++ 资源域另外识别两种精确机制：函数内 raw `new` 只在成功 guard 中转移、失败状态直接返回；以及返回聚合成员由可信工厂创建、构造函数保存该聚合、析构函数遗漏该成员。后者优先在真实 link group 中分析；若项目没有 link record，只允许对 name/file/signature 在全部 BuildContext 中唯一的当前实例做一次项目级观测，并记录 `unlinked_project_observation=true`、`formal_proof=false` 和链接 coverage gap，不能据此宣称 formal 链接闭合。
- 三模式的项目静态 pass 成功后，逐入口 workflow 只补报告上下文；失败则整批原子回退逐入口静态发现。deep 只消费成功发布的精确事实清单，失败时保存 gap，不回退名称级主动发现。
- Validation runner 保留 V0/V1 和 provider 加速路径，balanced/deep 共享 V3 自主调查：全部非 shadow 未闭合义务均可调查，不再限于 high/critical、外部可达或固定 provider 可闭合的缺口。模型提出正反解释，自主组合只读查询；时间、迭代、重复查询和取消边界继续生效。
- Validator v3 的 provider wire schema 保留完整十二字段 `required`，不向兼容网关发送会覆盖外层 required 的顶层 `oneOf`；verified/rejected/uncertain 的条件组合仍由严格 parser 逐字段复核。wire schema 还按候选收窄 `missing_fact_request.fact_kind`，并把 `evidence_refs` 枚举限定为该候选当前目录中的稳定 ref，避免模型生成不存在的引用。每个确定性候选先按 `canonical rule ID + revision` 绑定 `zscope.validation-obligation-catalog.v2`；profile 明确 source/sink/path/guard/ownership/lock/state 等角色、实际 provider 和正反 claim checker，无规则 hierarchical hypothesis 按受治理的缺陷机制绑定相同验证 profile；未知规则 ID 仍不能借此绕过绑定。provider 只发布 `resolved / proven_absent / unsupported / failed`：协议认识 fact kind 不等于当前 provider 可执行，空 provider 列表不得冒充穷尽反证。Fast 在 V0 后只把事实义务闭合的 canonical candidate 送入 Validator，并保证 decision-ready 候选 1:1 裁决；无 provider 或补证失败者不消耗 LLM，固定数量抽样与 96 组上限均不存在。

- `verified` 只有在当前 BuildContext、候选/源码身份、可读 fact/edge 引用和 profile 必需角色全部重放成功且不存在 blocking counterfact 时才成为 confirmed；`rejected` 区分确定性 checker 重放的反证明与自主调查中具备当前证据、精确对象/构建、完整事实且无未决假设的具体前提反驳；后者记为 rejected_with_evidence，不记为确定性证明；全路径/无其他访问者等普遍性否定仍要求覆盖证明。`final_score`、path/contract/confidence 均标为 `ranking_only`，不授权升降级。供应商 DSML 兼容只接受单一 terminal-tool framing，随后仍执行完整 schema/UID/ref 校验；首次严格解析失败（包括 `finish_reason=length` 与畸形 terminal framing）只允许同证据的一次紧凑重试，不从残缺载荷猜测字段，首次错误与重试响应均进入审计。该修复调用是机械格式化边界：在 provider 支持的 request-local `thinking` 开关上关闭隐藏推理，避免第二次把全部 completion budget 消耗在不可见 reasoning；正常初次裁决仍保留模型推理。报告分别计数 repair、thinking-disabled 与最终 exhausted，不能把 output-limit 伪装成合法裁决。原始响应、解析错误、provider 四态、evidence delta、BuildContext currentness、claim replay 与最终 disposition 都进入同一候选事件；缓存协议 v18 绑定 obligation UID，只允许 fast 在精确构建、证据、规则 revision 和环境指纹一致时复用。balanced/deep 的 review/investigation 结果仍不跨运行复用。

- 时序内存 matcher 的同一 canonical rule 可由语义感知的 CFG adapter 补充一个受限事实源，不因此新建规则或重复资格义务：成员别名已经释放、原成员未清空，且其精确所有者随后作为当前已授权 `pthread_create` 的 context 传给工作者。secondary producer 必须在实现清单显式登记，且 canonical matcher 实现仍须存在。该候选只证明本地释放先于异步交接；工作者是否实际访问该成员仍由 Validator 的同 TU callee 事实确认，不能仅凭线程 API 名称直接晋升。
- 格式串载体由共享契约解析，V0 独立核对真实调用与实际参数，候选自带的 `format_sink` 事件不能证明可利用性。字面量反证只否定该调用的原主张；非字面量仍需输入可控性证据。
- 对象生命周期和类型/路径反证由 `ReviewClaimChecker` 绑定实际编译驱动、源码依赖、对象、规则 revision 和契约版本后签发。模型 rejected 或旧的文本/事件凭证不能替代该校验；驱动不匹配、不完整 CFG、未知池或所有者清理缺口保留 review。程序结果区分原主张已反驳、支持缺陷的反例及仍未知，不宣称整个函数安全。
- Finding attribution 显式区分 `discovered_by` 集合与 `decided_by`/`decision_level`，因此“规则发现、LLM 判定”和“LLM 独占发现”不会混为一类。
- 验证升级阶梯（balanced confirmed TP 计划）由 `runtime.analysis` 独立开关控制；V3 reattempt 默认开启，其余实验阶梯保持原默认：`validation_v3_reattempt`（R2 V3 复判）、`validation_v2b_adjudication`（R3 V2b 二次裁决）、`validation_uncertain_confirm_threshold`（τ 高置信确认通道，null 关闭；离线测量未找到通过 FDR 门禁的 τ，保持关闭）。usage 事件按 `call_kind` 派生 `escalation_rung`（initial→R1、targeted_investigation/investigation_synthesis→R2、v2b_adjudication→R3），确认项写入 `confirmed_via`（deterministic_proof | validator_model | high_confidence_band）。
- `needs_review` 落点带呈现子状态 `needs_review_sub_state`：`model_uncertain`（证据仍缺失）、`policy_pending_promotion`（义务完整且无反证、等待策略通道）、`model_rejected_unproven`（模型否决未获确定性证明）；该字段只描述呈现，不改变 disposition 语义。报告视图可用 `build_report_views(..., demote_unproven_rejections=True)` 把 rejected-unproven 在 review 视图内降级呈现（带 `downgraded_from_disposition` 痕迹），计分归因不受影响。
- 报告级 `evidence_completeness` 由验证终点从 `decision_fact_coverage`（优先）与 `evidence_completion_status`（兜底）派生；扫描期 envelope 只能是 `unknown`。
- v12 事件形态 fact provider 从验证用源码重建受限生命周期与锁集事实，规则表与 proof requirement 表一一对应；文本写保护至少要求可信 exclusive 模式及已成立效果，未知调用不补造保护。调用方词法摘要仅保留调查上下文，既不覆盖全部调用点，也不证明真实锁身份，不再授权 `_caller_lock_context_proof` 强反证。
- 前置建模统计、契约版本与快照候选策略进入报告 metadata；默认不产生怀疑点独立验证终态。内部条件观察 shadow 单列登记和验证统计，按需建模 shadow 单列计划，不作为收益证明。历史 `interface_probe` 字段仅用于旧报告兼容，本轮不再通过后置快照探测更新接口。
- Rule engine 和 alert verifier 将规则或外部告警转换为相同的验证/报告语义。
- SARIF 告警导入区分 JSON 内容与文件路径，解码本地文件 URI 及 codeFlows 路径；非本地或无效 URI 不作为项目文件读取，Windows 绝对路径不拼接 source root。
- 受控动态复现由 RuntimeSpec 的 `runtime.analysis.dynamic_reproduction_mode` 控制，默认 `off`；`shadow` 保存执行证据但不附加确认 proof，`on` 才允许合格 witness 进入统一裁决。公共项目 YAML 不暴露此字段。Validator 在确定性前置裁决之前调用会话持有的 `SessionReproductionPlanner`；独立 ValidationRunner 不借用其他扫描注册的全局 provider。库级显式 provider 接口仍可用。计划绑定项目、当前源码、依赖、候选对象/站点/缺陷族、构建实例、工具、harness、输入与二进制；任何缺失、过期或不匹配都记录原因并保留未决。
- 当前自动策略仅支持唯一、当前的编译实例及其自身包含 `main` 的 TU，以原程序入口复现，不伪造内部函数参数或初始化。构建产物、计划与结果写入独立会话目录。自动 ASan 确认还要求 native 对象、分配站点和访问站点与真实报告对应；循环、重分配、歧义访问或无法映射的对象不能依名称确认。多 TU 链接、通用 harness/输入生成与完整异步对象协议仍是未完成项；`validator_protocol` 的序列化动态复现请求仍为 `reserved_not_implemented`。
- 一次 `execute()` 只运行一轮程序。同一验证的首次构建经输入和输出核验后，把二进制摘要保存在共享预算内；后续独立重放重新核对输入和二进制并复用该构建，变化时停止，不能重新绑定新产物。该凭证不从 JSON 恢复。`plan.max_replays` 包括主执行和独立重放，实际构建、运行启动数及共享墙钟 deadline 分别计量；额度不足保持未决。生产确认要求主执行和每次独立重放都有当前凭证、匹配本候选的见证与生产信任，测试替身不能补足。未复现不构成排除证明；候选裁决后按其绑定回收动态凭证，不影响其他候选。

- 执行记录的 `source_digests` 保存输入身份被接受、build/run 之前的源码、harness 与输入摘要；证明登记和最终裁决比较该快照，登记时不得重新采样或丢弃缺失文件来取得确认。进程内执行能力同时保存实际二进制路径、摘要与绑定状态（含构建后产物），登记和最终裁决对已绑定文件的修改、删除或不可读均撤销确认；符号路径 fake 仍需测试专用授权注入。
- 构建与运行都把计划内存限额传入 RSS 采样看门狗；这是采样边界，不能表述为内核硬限额。构建内存或输出超限记为 `engine_failed/build_resource_exhaustion`，不进入候选确认。stdout/stderr 分别经管道写入有硬字节上限的日志，达到上限后以一次有界读取区分真实 EOF 与超限；恰好等于上限且完整 EOF 的输出不误报截断。主进程退出后仍按原共享 deadline、取消和资源边界读取后代持有的管道，不另设延长计时；日志读取失败不能视为完整 EOF。结束时按启动时保存的自有进程组 ID 清理，包括已经关闭管道的后代，不依赖已退出主进程的 `getpgid`。

## 必须保持的不变量

- `LifecyclePaths` 消费当前构建的原生函数、CFG 和类型收据，执行有步数/调用深度上限的具体 C 路径。同 TU 外的直接调用要求唯一已观察链接目标、精确 USR、被调 TU 的当前 BuildContext 和一致签名；const ops 表只在具体选择可求值且 native 目标集合封闭时执行所选分支，不把部分目标释放推广为全部释放。调用缓存、函数依赖、调用边及契约查询均保留各自构建身份；调用帧隔离局部变量，字段、池实例和 `ObjectRef` 获取代次随实际参数传播。重复抽取的同站点 call 只执行一次。未知入口/选择、无链接依据的外部调用、递归/循环不收敛、union、volatile/atomic 和未支持转换留下 gap，不用路径前缀宣布清理完成。
- 实验性 `object_protocol_path` 记录成功留存、失败未转交、实际归还、同代重复尝试、错池与旧代指针命中新代对象。C 地址比较与分析代次分离；池 live 条件不成立时记录 no-effect，不能称为实际 double free。入口退出不是自动的业务责任终点，成功留存也不是所有权转移。候选显式携带已闭合路径/代次事实及仍缺的业务释放规范、责任终点或后续访问义务；一般 caller/cleanup provider 仅用于调查，不能替代这些专门事实。规则默认关闭，完整路径观察仍不授予证明权限。

- 引用计数切片复用此对象路径：signed 32-bit 非原子计数的 init/retain/drop 分别记录前后值、失败守卫和获取代次。2→1 不结束对象生命周期；1→0 只有实际执行到对应对象的已核验池归还，才记录 logical_pool_return，计数或 callback 名称本身不授权释放。正计数提前归还、零计数未见归还、归还后计数操作及旧代指针修改新代对象成为条件性候选。当前仅覆盖已有内嵌单槽池对象；堆析构、原子计数、异步最终释放、句柄和 arena/reset 未扩展。

- 对象路径 v5、协议核验 v4 将 `event:nonconcurrent_reference_count` 作为独立适用前提，与对象清理规范一起通过现有验收页核实。两者都成立且当前路径重放完整才可进入既有 proof 裁决；撤回任一回答必须恢复对应缺口，不能用顺序计数推断线程安全。计数溢出/代际回绕、未知调用或执行上下文不闭合保留未决。实验规则 revision 6 仍默认关闭，其他 backend signal 不受此开关影响。

- 受限句柄路径区分 namespace、数值、描述符 ObjectRef/获取代次与底层对象身份。dup 共享底层对象且产生独立关闭义务；普通整数别名保持旧代次，close 可能操作同值重开的实际新代次。成功、消费前失败、消费后报错分别按当前槽状态核对，不用返回码猜测效果。入口仍有效的句柄另需责任终点；所有句柄观察保留 `event:serial_handle_namespace`，撤回声明重新打开缺口。最后一个描述符关闭不证明物理析构。

- 句柄表本身须为当前路径已零初始化、native 证明直接位于函数作用域且调用帧仍存活的局部表；可以传给受支持的被调函数。过期函数/内层块表地址、从已退出的内部帧导出活句柄、缺 scope 事实、堆/全局或成员表仍保留技术缺口，不用业务声明补齐表自身寿命。

- 零 LLM 安全语义图使用当前完整的程序事实绑定调用构建实例；函数/audit 输入身份保留实例差异。失效、歧义或不完整事实不授予实例专属契约，overlay 声明也不能挂到另一实例的函数上。`reference_retention` 作为资源转换观察进入主动调查，保留对象、接收方、条件和未知状态，不转换为 ownership_transfer 或最终缺陷证明。

- 生命周期消费者同时跟踪资源对象与池身份；确定的直线别名可合并，重赋值和条件别名不能冒充同一对象。合法配对、同一对象、同一池和成立的效果条件都满足时才解除义务。未知释放或解锁保留既有候选，不得使候选消失；未验证契约和未闭合条件使相关 AST proof 保持 partial。
- `retained_slot_release` 是实验性、默认关闭的 Clang 候选规则。它读取同一构建的 native v5/资源事实收据及已核验单槽池契约，识别受限 C 函数中“非空槽位或其直线局部别名被传给归还接口、退出时仍留存”的路径；不是按 complete/cancel 名称匹配。完整的先摘除后归还或归还后清空不产生本规则候选，但局部清空摘要不证明全局安全或清理成功。条件归还、对象代次、接收方存活、后续访问与共同可行路径保持显式缺失义务；补证仅调度已有 caller/cleanup/reachability provider，不把一般事实变成已闭合的协议证据。宏改写、union、额外调用、条件清空、重赋值、过期/歧义事实和跨构建契约均不能取得摘要。当前仅同 TU 的单槽池接口，任意容器、并发及跨回调代际不在此规则的证明范围。
- 所有权转移通过源码输出或 `ownership_transfer` 契约识别，`add/put/register` 等函数名称及 `g_` 前缀不能授权转移。Validator 的源码生命周期补证同样读取已发布契约，未知调用接收资源时放弃否定存在证明，不使用名称后缀猜测分配器。
- Validator 只有在索引明确分类为系统接口或缺少模型的外部接口时，才可将无函数体的接口候选关联到入口验证上下文，并保留原接口和来源分类。项目定义优先；分类缺失或查询失败时保留原函数，不按标准函数名列表、项目名前缀或 alloc/free 等片段改选。验证和报告缓存按该上下文选择策略失效，语义建模输入指纹不因此改变。
- 自动发现的注册回调以 `callback` 进入 Validator 外部入口上下文；没有普通直接调用者不能作为不可达的单独依据。信号回调的异步信号提示随入口传入证据包，注册线索不等于注册成功或漏洞证明。
- 当前池对象跟踪由 Clang/Regex 本地生命周期规则执行；Graph 共享结构化调用事件及契约版本，不宣称具备任意跨函数池别名分析。静态组合及受限实现校验不等于通用形状分析，复杂池与跨分支别名保持未知。
- 快照怀疑点默认不产生独立候选，没有公共开启开关。内部 RuntimeSpec 显式启用条件观察 shadow 时，只有当前发布会话及源码绑定通过的类型化观察才以 `candidate_source=semantic_snapshot` 登记，独立验证策略保持 `shadow_observation`，不晋升默认结果。旧 `suspicious_points` 与单独导入的缓存 JSON 不触发该任务。规则优先组 `semantic_suspicious_point` 保持原有规则行为。
- `suspicious_points` 与接口契约仍由 Validator 作为已有候选的背景读取，明确标记为未验证信息。怀疑点不写 `zscope.semantics.yaml`，也不进入 candidate-blind 主动发现提示词；暂停不计为 partial，不阻止有效报告复用。报告缓存绑定候选策略版本，旧策略产物必须重新扫描。

- 实验性 review 链路使用 `zscope.review-adjudication.v1` 封套，分别记录旧拒绝的事实／范围审查和具体缺陷案例；内部校验后仍交给 ValidatorResult v3 的统一策略。只推翻拒绝而未闭合正面案例时保留 review，原因记录在 `review_disposition_reason`，不得扩充旧 `stop_reason` 枚举或借高置信 uncertain 通道晋升。
- `check_validation_claim` 只核验绑定的原候选。当前支持完整类型中的不存在成员／内联字节数组、受限结构化所有权路径、常量或规范归纳循环的固定数组下标，以及明确检查成功返回值的静态锁访问。`lock_coverage.py` 复用当前 AST/CFG，按声明身份核对非逃逸 TU-static 锁、shared/exclusive 与全部本地访问；编译器读转换可接受 shared，写入必须 exclusive。仅支持一个指针参数的标准锁操作及当前 TU 直接 return 透明包装链；EOWNERDEAD 数值从当前预处理事实读取。访问节点、锁声明、模式和检查状态进入签名 coverage。恢复时重新运行检查，报告字典不能自行授权拒绝，也不能用 race 反证排除 UAF。
- 重复获取、upgrade/downgrade、cond_wait、成员/动态锁、未检查结果、任意辅助函数、未知别名与 C++ RAII 均保留 unknown。等待的释放/重获转换仍用于语义上下文，不能证明保护连续。路径预算为 10000 步、128 分支状态、12 轮透明包装器；超限不授予反证。共享访问 Regex/Clang 规则 revision 10 只用确定 exclusive 前缀过滤候选，未知解锁或等待清空前缀；两条规则继续 experimental/default-disabled，无正式资格提升。
- 检查器显式绑定所支持规则的 revision；旧报告没有 revision 或规则契约升级后，必须补做资格验证才能产生该规则的反证。不存在成员的反证可根据对象构造函数中的实际字段赋值登记关联清理假设，按父对象合并，启用关联回收后正常验证；仅有指针类型不会生成候选。C++ 隐式生命周期、锁别名泄漏及同语句内未建模的锁状态变化保持 unknown。
- V3 正面举证和 V2b 拒绝审查分别记录入口池、目标、工具原始结果和复核封套。正面证据仍须通过现有确认验收；完整正反证据冲突进入 review。事实摘要、TOOLFACT 引用以及调用次数都不等于程序证明。
- `propose_related_candidate` 只能登记原函数或已查询函数中的具体位置，并关联父候选和工具证据。主 Ledger 保持冻结，关联候选通过独立追加 Ledger 登记、冻结、验证，最多一代；主 Ledger 的最终快照包含追加区。未完成的关联候选保留 review。条件宏风险绑定触发条件，未获得对应构建事实时不能确认或自动拒绝。
- 事实组发现的条件宏风险即使未开启一般关联回收，也进入追加 review 区并计数。检查点恢复保留原 UID、cluster、验证证据包和完整前序结果，不通过重新注册改变原裁决对象；恢复粒度是候选验证阶段，并不恢复供应商的会话执行状态。

- 候选不得因调度边界、超时或阶段失败而静默丢失；未深挖候选必须保留可审计状态。
- `verified`、`rejected`、`uncertain`/`needs_review` 的含义不能混淆，退出策略只消费约定视图。
- 去重必须保留 occurrence、替代证据和来源，不能仅按文本或行号合并。
- 确定性 proof、LLM 判断和引擎失败必须在元数据中可区分。
- 完整且无冲突的 proof 才能确定性确认或拒绝；正反 proof 冲突直接进入 `needs_review`。没有确定性反证时，模型的 `rejected` 只是一项模型意见，不能把候选从审计视图静默隐藏。
- 缺失义务归一化只转换已知别名，未实现 provider 的义务仍保留未决。模型 verified 的高分通道及可选 uncertain 高置信通道同时检查顶层和事实切片中的缺口；空顶层列表不能遮蔽切片缺口。一般 caller/cleanup/reachability 补证不能自动消除对象代次等专门义务。独立、完整且当前有效的确定性证明仍走既有证明裁决。
- `confirmed_via` 只在 confirmed 落点写入；`needs_review_sub_state` 与 review 视图的 rejected 呈现降级都不得改变 `candidate_disposition`、计分或 truth 归因。
- τ 通道、V3 复判与 V2b 裁决每个 rung 只允许一个手段且独立开关；同一 rung 不得叠加两个确认来源。
- V2 只能在合法的单一 `missing_fact_request` 得到新证据且 `evidence_delta_hash` 改变后运行；重复、无增益、超时或不支持的请求必须停止为待复核。
- 主动发现 Agent 只能写 hypothesis/observation，不能写 confirmed finding；其 prompt 不得包含 Candidate Ledger 内容、候选/规则身份、benchmark、truth 或历史 verdict。
- 已启用阶段因超时、取消或工具失败未能覆盖全部审计单元时，已有结果仍需保存并标记 `completeness=partial`；未启用的阶段不构成 partial。token 成本只在 Benchmark 完成后评价。
- 外部告警适配后仍需遵守统一 issue identity、证据和报告 schema。
- 规则 ID/alias 全局唯一；YAML 不执行代码，未知字段、语言错配、重复 ID、缺失 Skill 和能力错配必须在构建 CodeIndex、启动外部工具或调用 LLM 之前失败。
- 确定性候选必须携带已登记 canonical `rule_id`；其语言、CWE、defect class 和 Skill 不得与 descriptor 冲突，被禁用的候选不得进入 ledger、Worker、Validator 或报告。
- SVF/Saber、Joern 和 Java signal provider 输出是 `backend_signal`，不伪装成确定性规则；Skill trigger 只路由 Worker；finding suppression 只消费已持久化的人工决策。
- 动态复现只能把“与候选对象、站点和缺陷族都相符”的受控 witness 交给现有确认通道；未复现、执行失败、超时、OOM、构建失败、工具不可用和取消都保持未决，永不构成安全反证。序列化日志、内容 hash 或模型自报结果不能恢复确认权限：确认能力是进程内、按 proof 对象身份登记的，`dynamic_witness_candidate_match` 只有在同一进程内仍持有真实执行 receipt、当前 issue 的完整绑定摘要与 live 授权身份一致时才有效，JSON 往返副本、过期 TTL 或身份漂移都会失效。未通过候选对象/站点/缺陷族或逐轮重放检查的记录只能附加描述性（inconclusive/incomplete）证明，fake 或测试信任的执行永远不具备生产确认资格。执行前必须由 runner 重新核验 harness、声明输入与被执行程序的真实摘要，并要求命令正是该程序、所有路径位于显式授权根内；核验失败或请求的隔离无法提供时记录 `unsupported` 且不执行。普通 subprocess 不等于容器隔离，执行记录必须写明实际施加的边界、逐轮日志摘要与截断情况；截断输出一律未决。

## 规则治理边界

候选协议 v3.5 显式携带 `build_context_id`。Regex/Clang 只从完整、无歧义且未报告过期的程序事实绑定该身份；原始条件编译源码不能据此声称覆盖所有分支。身份贯穿候选/义务、事实图与 Validator 缓存、Ledger ticket 和终态。合并事实图的切片只读取同一构建的事实，不能用另一变体填补缺失义务；未知构建与已知构建也保持隔离。这不等于函数调度已经遍历全部构建变体，覆盖缺口仍由 `metadata.build_coverage` 记录。

规则本身的检测语义未因身份传播而改变；候选身份算法升级会撤销旧 v3.4 候选与报告的直接复用。decision facts v1.4、security obligation v1.3 同步携带构建范围。稳定身份或构建范围发生变化时，不能沿用旧的验证 cluster。

| 机制 | 权威配置/元数据 | 进入候选的方式 | 关闭方式 |
|------|-----------------|--------------------|----------|
| 确定性规则 | 包内目录 + qualification registry + YAML pack/Provider descriptor | `candidate_kind: deterministic_rule`，由 `RulePolicy` 与统一门禁校验 | `rules.disabled_ids`；实验规则默认关闭，可用 `rules.enabled_ids` 显式启用 |
| Backend signal | `indexing` 后端与 signal provider 规划 | `candidate_kind: backend_signal`，保留 `signal_source`/`native_rule_id` | 在 `indexing` 中关闭信号源 |
| LLM 主动审计 | Security Semantic Map + coverage-gap audit unit + active Skill | 合格 hypothesis 经 CandidateRegistrar 登记为 `candidate_kind: llm_observation` | `scan.depth=fast`；`balanced/deep` 保留风险阈值、合并和目录排除，但不设 audit unit 数量上限 |
| Finding suppression | ReviewMemory/UserConfig state | 在验证/报告前匹配 finding identity | Web/用户配置中维护 |

`rules.disabled_ids` 对当前语言的内置 Regex、Clang CFG/matcher、Graph、Java local、YAML pack 和 Python provider 统一生效，且优先于 `enabled_ids`；两表出现同一 ID 时以禁用为准。表内重复 ID、未知 ID 或跨语言 ID 均严格失败。关闭规则只停止指定检测器，不承诺消除等价问题：其他规则、后端信号或 LLM 仍可独立发现它。

RuleDriven/Joern 与 SARIF alert-verify 也遵循统一验证边界。RuleDriven 把全部 backend signal 先注册进共享 Candidate Ledger，跨原生规则合并同一义务并 freeze，再走 V0–V3；SARIF alert-verify 是面向单条外部告警的有界 V1 子集。两条路径中，模型拒绝无确定性反证时都只能进入 `needs_review`。产品 token 账本只计量，不因成本阈值停止验证调用；超时、取消或工具故障仍按实际覆盖情况标记 partial。

规则目录原始字节、规范化 descriptor、相关引擎实现、enabled/disabled IDs、qualification、pack/provider 来源、当前语言与 backend 能力共同形成 effective SHA-256。该身份参与规则候选、gap plan、Validator environment fingerprint 与最终报告 provenance，但不改变 `zscope.candidate.v3.5` 的稳定候选身份，也不应使独立的程序事实或 Security Semantic Map 骨架缓存失效。

## 常见变更应落到哪里

- 规则 descriptor、ID/alias、能力与 provenance：`zscope/rules/`；检测算法本身仍位于对应 Python 引擎。
- 简单扩展规则：显式 YAML pack；复杂第三方规则：严格 `zscope.rule_providers` V2；完整契约见 `docs/rule-development.md`。
- 候选收集/合并：`pipeline.py`、ledger 和 adapters，避免在 `Analyzer` 中堆叠局部规则。
- Validator 输入、重试或评分：`zscope/core/validation/`。
- Joern 规则或规则驱动扫描：`zscope/rules/`。
- SARIF 导入和告警复核：`zscope/alerts/`。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_candidate_pipeline.py tests/test_candidate_ledger.py
python -m pytest -q tests/test_validation_pipeline.py tests/test_validation_runner.py
python -m pytest -q tests/test_validator_v3_protocol.py tests/test_evidence_completion.py
python -m pytest -q tests/test_alert_verifier_parallel.py tests/test_needs_review_governance.py
```

## 具体对象协议的条件性验收

`object_protocol_path` revision 15 绑定专用 `native_object_protocol` 验证义务：获取、对象代次、可行路径、协议观察和业务释放前提是固定最低要求；责任终点、非并发前提和后续访问按具体观察追加。通用 caller/reachability provider 不替代 native 重放，也不补造业务声明。该映射避免已重放的具体路径再次因通用状态机取证缺口阻塞验收；其他状态机规则仍保留原有通用要求。当前源码、构建、契约、反馈撤回和进程内核验收据的门禁不变，实验规则继续默认关闭。

`protocol_assessment.py` 复用 `LifecyclePaths`、CodeIndex 和运行时 ContractRegistry 核验当前完整路径。路径 v5 记录各 TU/函数绑定、链接目标及所消费契约的符号、摘要、来源和源码核验收据；Validator 重放后逐一核对源码 token 摘要及原观察，不能从候选包加载自报契约。链接记录/对象/产物、构建、任一被调事实或契约变化、旧版本路径、工具不可用均保留待补证，不解释为缺陷被排除。当前跨 TU 扩展已有单槽池/留存、非原子引用计数和有界自定义句柄表的具体顺序路径；业务责任、责任终点和执行上下文仍需 S04 的独立声明，未扩展通用 heap/OS fd 执行、任意异步交错或函数指针求解。`object_protocol_path` revision 10 继续 experimental/default-disabled；下述单工作者路径使用独立 schema，沿同一规则和验收链消费。

业务释放规范与责任终点初始为未确认的 `analysis_requirement`。其问题记录绑定 BuildContext、入口、ObjectRef、路径依赖和观察，描述性源码契约仅作为分析依据。统一 ValidationPipeline 将当前技术路径完整且只缺业务前提的候选投影为 `business_conditional`，额外技术缺口投影为 `protocol_pending`；两者均保留 `needs_review`，不会因为高分、模型拒绝或删除缺口清单自动晋升/拒绝。

Web 验收回答从项目状态库按精确范围读取，带回答版本和 `user_acceptance` 来源。当前源码重放与所有必要业务前提共同成立、没有冲突或额外技术缺口时，专门检查器签发 `checked_object_protocol_with_business_declarations`，沿原确定性 proof 分流进入 confirmed；该规则不接受序列化通用 proof 绕过业务义务。拒绝前提或改为 unknown 不签发安全反证。业务事实在每次核验前撤回，再按当前回答逐项发布；进程内收据检查回答版本，扫描中发生修改也重新读取并重放。关闭模型不关闭这种程序核验。

`protocol_assessment.v2` 的 `feedback_revisions` 参与 Validator 缓存与报告重用判断。回答改变仅使引用这些版本的结果失效；Analyzer 将受影响历史条目重新登记候选台账并排队验证，避免旧 confirmed 在报告装配时回流。批量 resume 读取相同项目状态库，读不到时不得自动跳过依赖它的报告。历史报告保留当时证据，JSON 不保存程序授权，恢复扫描重新核验。

该闭环只覆盖实验性具体对象路径规则，回答精确绑定既有路径，下一次扫描执行依赖重验，不在 Web 保存请求内立即启动扫描。没有实现任意业务约定的自动解析、跨对象范围推广、全规则四态改造或通用跨 TU/异步路径求解；规则维持默认关闭。

## 受限 pthread 回调寿命

`cpp_domains/async_paths.py` 在既有具体路径解释器上实现单工作者 pthread 见证（`zscope.pthread-delayed-path.v8`）。仅入口含直接 pthread_create、Linux glibc LP64 系统声明、默认属性、同 TU 的 `void *(void *)` 回调与已知 malloc/calloc 对象；当前根契约必须与实现支持的标准规格一致。回调函数、队列上下文、任务获取对象和线程句柄分别记录身份；调用方指针重赋值、队列槽摘除和 active 标记清零不会改变工作者局部保存的 ObjectRef。调用方同 TU 直接 helper 复用原调用帧和 CFG，提交成功/失败、取消和 stop 的效果取决于实际字段与返回守卫，不按名称推断。

调度显式选择分配/创建/同步成功。原直接回调延迟到 join；队列调度在创建后调用方首次 mutex unlock 时推进工作者到其首次 unlock，保留 native CFG 的帧和位置，随后在 join 期间继续。原顺序路径仍拒绝循环，队列工作者每个 CFG 块最多访问 8 次且共用总步数预算；命中上限为缺口。只有实际退出回调后才记录 join 返回。首个释放后成员访问成为条件性候选并立即停止，不虚构 UB 之后的效果。`complete` 仅指当前见证或选定路径闭合，全部交错、失败结果和无观察安全证明三个标记均为 false。

native `pthread-storage.v1` 标出当前系统声明的 opaque mutex/cond 字段；只有存活堆上下文中的该类型字段、创建前默认属性初始化及匹配系统 API 可执行同步状态转换，禁止把 libc union 当普通记录复制/读写。锁实例按堆对象和字段身份区分，释放/重获保留真实持有者；跨线程共享字段访问保守要求同一 mutex（连未证明只读的访问也不豁免），创建前初始化与成功 join 后访问分别处理。共同锁只支持这段顺序的可行性，不能作为 UAF 反证。单等待者 cond_wait 通过原调用解释器的可暂停步骤释放 mutex；返回值在匹配当前条件变量实例的 signal/broadcast、且 mutex 重新获取后才写入帧。通知只绑定当前 wait_id，提前通知和已消费通知都不存为后续额度；错误条件实例、重获阻塞、等待存储失效保持缺口。实际 CFG 在返回后重新检查谓词，不把通知当作谓词成立或完成。取消模式切换、未支持取消点、调用方等待、未覆盖唤醒序列、一般超时/时钟、一般工作者 helper、未知属性、不同锁或无锁访问、多工作者及跨 TU 异步仍未求解。

S04 assessment v12 重新读取入口、helper、回调的当前 native 事实、构建和 live Registry，比较完整见证后沿既有业务回答库、统一裁决与撤回链消费；候选序列化不能恢复收据。标准根依赖复验当前契约，源码体由精确构建事实绑定。异步解释前后检查当前源码/头文件、编译数据库、环境、include probes、工具及共享库摘要；进程内收据再次检查这些依赖和 Registry 版本。热/冷对照覆盖直接回调访问/目标、队列 helper、释放顺序、删除通知/错误条件实例和根契约改变，不代表动态目标集合或完整扫描等价。UAF 的恢复位置按实际解锁/通知或 join 边记录，验收问题不强加尚未执行的 join 前提。对象协议规则 revision 15、主 CWE-664、附加 CWE-416 和默认关闭保持当前目录约定。验证入口为 `test_async_contracts.py`、`test_async_paths.py`、`test_async_incremental.py`、`test_async_queue.py`、`test_async_queue_incremental.py`、`test_async_wait.py`、`test_async_wait_incremental.py`、`test_async_cleanup.py`、`test_async_cleanup_incremental.py`、`test_async_helpers.py`、`test_async_helpers_incremental.py` 及原协议/反馈/构建回归。

## 有限 RAII 与当前证据重用

有限 RAII 通过 `raii_lifecycle.ScopedGuards` 扩展原对象敏感 lifecycle 分析，不复用受限 C 协议解释器来模拟任意 C++。当前仅支持同 TU、单编译实例、单指针成员和 noexcept 的空体构造映射；析构直接 free 或通过最多八层、当前 AST 核验的单参数 noexcept 透明 deleter。正常/提前退出和函数内字面量 throw→catch(...) 分别展开作用域清理。Clang 的异常 CFG 不保证列出全部析构，异常清理依据受限结构化 AST 语义，不把缺失的 CFG 事件伪装成已观察事件。未捕获异常、任意调用抛出、构造异常、复杂控制流、模板/继承、复制/move、adopt/defer、release/reset、管理器逃逸、成员改写和锁 guard 均保留缺口。

native `cxx-lifetime-facts.v1` 保留管理器、构造及析构身份；仅声明而无体、空析构和临时析构事件不授权释放。Validator 重新取得指定 BuildContext 的事实，核对编译命令、SDK 版本、依赖和 AST 源码位置，使用原获取对象而非变量当前值进行析构清理。无构建身份、另一构建、旧工具或缺收据不能借用强证据；重新检查先撤销旧收据。`clang_cfg_acquire_without_release_on_exit` revision 10 仍为实验性、默认关闭。源代码效果只能排除该泄漏义务，不证明 UAF/并发安全；其他 C++ 协议与模式消费者尚未迁移。

Review 程序收据绑定当前契约注册表版本、候选的结构化获取事件选择和编译证据；重放中或签发后契约变化立即撤回授权，JSON 往返不恢复授权。头文件查找变化、新静态访问者或 native 实例失效必须重新计算义务，旧生命周期缓存也不能绕过当前 native 核对。统一 ValidationPipeline 的受限全量/增量对照比较候选、裁决、报告桶、未决义务和覆盖投影；不把这组对照推广成异步回调集合、全部编译变体或完整扫描等价性。

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 分层关系见 `docs/architecture.md` 的“证据平面”“智能体平面”和“验证平面”。
- Range 上的行为变更还必须遵循 `docs/range-benchmark.md`。

## 完整源码、事件与验证上下文

确定性入口、callee、Graph 和扩展 provider 读取完整函数正文；`max_function_lines` 仅限制模型展示，不能作为检测覆盖边界。源码缺失或截断必须进入未完成记录。Validator 在 token 预算以内保留完整函数，超预算时按防护、source/sink 和生命周期操作选择片段，并记录省略区间、源码摘要和续取引用；补充证据合并后重新拟合预算。上下文缺失且尚未补齐的模型判断保留待验证状态，证据版本参与缓存身份。

逐实例 C/C++ 分析中的入口及同 TU callee 正文只从当前 BuildContext 的唯一 native 函数 owner 解析；Graph 缓存键绑定该 BuildContext，系统/外部边不作为缺失的项目正文，Validator 读取正文时不请求未收据化的声明上下文。无法唯一绑定 owner 的项目调用仍进入未完成记录，不能借用项目级导航投影。

资源状态机使用带行、列和事件序号的操作序列。同一行的多个语句分别处理，文本后备屏蔽字符串、注释和宏定义中的伪操作，并保留循环头。编译器 CFG/读写事实可作为可追溯证据；文本顺序不能替代路径可行性证明。内存、FILE、DIR 的获取与释放按资源家族匹配，共享访问依据对象事实生成候选，命名不作为唯一门槛；跨线程可达性、共同锁、原子操作和所有权转移仍须验证。

自动包装器契约沿独立 discovery → 人工确认 YAML → 实例级 Registry → Regex/Clang/Graph/KnowledgeDB/SecurityMap 传播，输出参数必须解析到资源对象，不能把状态码当指针。字段/输出参数、专门 transition 或锁模式若无完整规则消费者就不能确认，覆盖诊断继续保留能力缺口。KnowledgeDB 查询和 SecurityMap 上下文不授予生命周期证明；核验失败、LLM 建议或 schema-only 高置信度都不授权效果。

规则语义变更保留 canonical ID、递增 revision 并重新验收。未取得可核验资格的新增/改动规则保持 experimental 且默认关闭；未改动的历史规则沿用 legacy pending 治理，不能因此通过正式发布资格门禁。独立生成器不带运行时 policy 时用于规则实验；产品扫描必须注入 preflight 的有效规则策略。

默认 enabled/deferred 取消沿同一解释器投递：testcancel 无待处理请求时返回；cond_wait 的取消无需通知，但必须先重获原 mutex。随后运行至多四层 cleanup，成功退出后才记录工作者结束，仍由实际 join 返回闭合调用方等待；未知锁残留和重获阻塞保留缺口。`pthread_cleanup.py` 仅在 `pthread-cleanup.v1` 核验当前 C/glibc 默认宏及 AST 后投影 setjmp 脚手架；原始输入摘要保持绑定。push 保存当前 Pointer/ObjectRef，pop(0) 不调用，pop(1) 与取消分别进入真实同 TU void(void*) 清理体。实际 free/unlock 不成为全局 deallocator 配对；清理内未知调用/取消点、控制跳出、模式变化、异常宏和跨 TU 不支持。首次 UAF 立即停止，不生成后续 cleanup/完成/join。所有源体、目标、当前标准根和业务回答沿 S04 撤回链重验；局部冷/热等价性不扩张完整调度覆盖。

工作者普通 helper 首批限定同一 C 源文件、同 BuildContext 的无属性直接函数，复用现有 native USR、签名、参数、返回及 CFG；不依赖新增提取事实。参数和返回仅为已知堆根 Pointer/ObjectRef、空值或 signed 32-bit 范围内的整数值，继续核对 native 类型/转换限制。递归/调用深度、事件步数和循环仍有界；局部/字段地址与间接目标不闭合。工作者调用栈独立于调度它的调用方栈，unlock/cond_wait 暂停保留全部活动帧，恢复只更新根调度边；重复调用分配独立 invocation，成功返回才发布结果。普通工作者中的 free 使用当前标准根和实际对象状态；cleanup handler 内普通 helper 仍未支持。取消清理按注册时保存的活动帧和参数执行，另存实际取消点路径，不能把被中断的 helper 当作返回；首个非法访问后不生成后续完成。冷热对照包括 helper 体、目标、返回值、取消点、根契约和 drain 顺序；回答撤回与序列化不授权沿用 S04。

等待结果探索（异步 v8）以通知路径为首选，仅当其停在未匹配通知的等待点时，从相同当前入口重放一次 `spurious_once`，对核验过的 timedwait/clockwait 再重放一次 `timeout_once`。每条替代路径最多一次无通知返回，最多三条路径，沿用各自步骤/循环/调用深度上限；返回值在重获原 mutex 后发布，再走真实谓词/返回码 CFG。匹配通知和取消优先，取消沿注册帧清理且不返回。先选完整非法访问见证，再选完整路径，否则保留首条缺口及各次尝试原因；不穷举唤醒位置、次数或通知/超时竞争，不推导安全。探索末尾再次复核当前源码/工具及 Registry 版本。

`pthread-wait.v3` 与 `pthread-deadline.v3` 只核验函数局部、系统定义的两字段 signed 64-bit timespec（16-byte 大小、8-byte 对齐、0/64-bit 字段偏移）、无自定义属性的局部对象及直接取地址参数和系统数值 ETIMEDOUT。消费者检查已初始化非负秒数和 0≤tv_nsec<10^9；timedwait 的默认属性条件变量对应 CLOCK_REALTIME；clockwait 参数只接受直接系统 CLOCK_REALTIME/CLOCK_MONOTONIC 单数值宏，native 同时保存定义/展开匹配及当前值，消费者核对时钟、参数和值一致。数字字面量、变量别名、显式转换和包装宏不授权。超时记录时钟不早于截止时间，返回 0 不推导其发生在截止时间之前；不读取宿主当前时间或运行等待程序。系统常量宏的直接单数值展开才可投影为当前 AST 表达式，原始事实摘要保持绑定；项目宏、包装宏、显式转换、未知值、未支持的时钟/一般时间来源及一般错误结果保持缺口。当前切片包含统一裁决、验收撤回和本地冷/热对照，不表示完整异步或增量已完成。

调用方匹配通知等待沿用 `_synchronize`/`_advance_worker`：只接收 cond_wait，验证当前标准根、条件变量与 mutex 实例、当前持锁者及并行等待的动态锁绑定。释放后推进工作者至其下一次解锁/等待/退出；通知后若原 mutex 仍由工作者持有，继续等待其释放，无关锁的 unlock 不能替代。最多四次调用方等待，每个实际等待帧的 CFG 块最多八次访问，沿用整体步骤/深度上限；普通未等待帧仍保留原循环限制。返回后执行真实 if/while 谓词，提前通知不留额度，活动标志提前清零不能消除后续 UAF。无通知、重获失败、不同锁绑定、调用方 timedwait/clockwait 或取消保持缺口。

调度前缀包含入口到调用方 helper 的所有边，再接工作者恢复边；活动 worker/helper 帧仍在同一列表中保存，恢复仅替换调度前缀。取消 cleanup 的根注册帧按实际前缀深度展开，不能按固定第一层截断。首次非法访问可以发生在 caller helper 的等待期间，候选仍锚定真实入口调用点，不补造后续等待返回或 join。`caller_condition_wait` 只记录执行/覆盖范围，不设置 worker complete/joined；同步存储销毁仍要求已有 join 约束。对应原生正反例、业务回答撤回及两 TU 冷热对照见新增 drain 测试；非完整调度或安全证明。

## 当前原生身份与验证绑定

精确实例 Analyzer 与验证 helper 共享同一工厂签发的当前语义快照，并分别物化独立 registry。候选消费者的 `restrict_to_semantics` 只收紧效果输入，不能凭布尔值或来源字符串增加权限；checker 默认值、API pattern 和直接字面量消费不能重新加入被拒绝或未知的根。当前性 guard 覆盖缓存复用、结果登记和历史持久化，变化后撤回本轮复用资格。收集闭合由实际阶段结果和当前能力收据决定，不从最终 verdict 推断。恢复的 pending 仍进入本轮一次集中裁决，序列化 confirmed/proof 不能绕过 Validator。

受限消费者要求显式 local semantics，不按 `unique_ptr`/`shared_ptr` 模板名称解除对象义务；API 名称按大小写精确匹配，真正的 `new`/`delete` 语言语义保留。当前性源码清单覆盖三个候选入口和六个效果消费者（包括 `shared_access.py`），缓存的 effective rules 摘要不能代替当前源码复核。该实例分支仍等待 S01 工厂接纳与真实 native/context 联合验收，消费端有限验收不表示完整实例扫描或恢复已经通过。

契约生产和效果消费保留精确 BuildContext 与 native USR。效果查询省略 USR 时，只能从当前完整且无冲突的入口或实际 callee 收据解析；缺失、过期、混合重载或构建冲突保持未知。原始 Registry `find` 可供发现，记录唯一不能证明调用选择了它；入口 owner 也不能覆盖同名递归调用的目标歧义。契约编译与 Registry 版本参与缓存失效，覆盖统计使用实际当前函数身份，不能把缺失绑定误报为未发布。

共享 `ValidationRunner.run` 按 scoped index 的真实实例核对候选及 evidence 的构建，在 executor/scheduler 工作入口绑定并在退出时恢复上下文。未知或冲突候选不会通过补标签取得验证资格。正常 Validator 与 EvidenceCompletionQueue 定点事实工作线程显式携带精确 build、入口 native USR 和提交时调用快照。调用参数与嵌套值复制隔离并保留消费者列表/字典语义；切换入口或绑定 legacy 空上下文清除旧 callee 映射，超时、异常及线程复用均恢复原绑定。execution_* 审计元数据不授予事实权限，候选自报字符串不能代替当前 native 收据。上述切片仍不代表所有 investigate 多轮、多 fact-kind、全建模和所有消费端已迁移；未接入部分继续单列。
