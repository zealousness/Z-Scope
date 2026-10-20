---
doc_contract: zscope-module-v1
covers:
  - zscope/cli
  - zscope/orchestration
  - zscope/workflows
sources:
  - scripts/balanced_rollout_operator.py
  - zscope/cli/cli.py
  - zscope/cli/link_record.py
  - zscope/orchestration/scan_session.py
  - zscope/orchestration/entry_discovery.py
  - zscope/orchestration/callback_discovery.py
  - zscope/orchestration/parallel_analyzer.py
  - zscope/orchestration/entry_instances.py
  - zscope/orchestration/jobs/session_scheduler.py
  - zscope/orchestration/jobs/scan_work.py
  - zscope/orchestration/semantic_modeling.py
  - zscope/orchestration/snapshot_candidates.py
  - zscope/orchestration/snapshot_observations.py
  - zscope/orchestration/semantic_demand.py
  - zscope/orchestration/investigation.py
  - zscope/orchestration/bounded_investigation.py
  - zscope/orchestration/external_findings.py
  - zscope/orchestration/external_investigation.py
  - zscope/orchestration/rollout.py
  - zscope/orchestration/workflow_runner.py
  - zscope/orchestration/workflow_executor.py
  - zscope/workflows/default.yaml
tests:
  - tests/test_job_queue_receipts.py
  - tests/test_balanced_rollout_operator.py
  - tests/test_cli_output.py
  - tests/test_link_targets.py
  - tests/test_workflow_runner.py
  - tests/test_workflow_specs.py
  - tests/test_scan_session_resume_svf.py
  - tests/test_instance_analysis.py
  - tests/test_job_session_scheduler.py
  - tests/test_scan_session_instances.py
  - tests/test_scan_session_jobs.py
  - tests/test_scan_checkpoint_resume.py
  - tests/test_job_bound_completion.py
  - tests/test_signal_callback_entries.py
  - tests/test_incremental_semantic_modeling.py
  - tests/test_wiki_workflow.py
  - tests/test_active_discovery.py
  - tests/test_investigation_evidence.py
  - tests/test_bounded_investigation.py
  - tests/test_investigation_runtime.py
  - tests/test_single_entry_active_discovery.py
  - tests/test_external_findings_import.py
  - tests/test_external_investigation.py
  - tests/test_audit_coverage.py
  - tests/test_snapshot_observation_shadow.py
  - tests/test_semantic_demand.py
  - tests/test_balanced_rollout.py
---

# 执行与编排

## 职责与非职责

本子系统负责把 CLI 选项和配置转换为一次可执行扫描：选择运行模式、发现或加载入口、规划 diff impact、恢复/维护批量任务、调度并发分析、执行声明式 Workflow，并汇总运行进度。

它不负责生成底层代码事实、实现具体候选规则、决定最终报告结构或直接维护运行时 Agent prompt。

## 主入口和数据流

- `zscope/cli/cli.py` 解析 `--resume`、`--maintain`、`--diff-*`、`--scan-depth`、WebUI、MCP、SARIF 和索引预热等入口参数。
- `zscope/cli/link_record.py` 是显式的 Linux C 链接记录准备入口：按已有编译数据库重建所列对象并执行真实链接。扫描阶段只读取产物记录和当前构建实例，不自动触发重建；有效范围和拒绝原因见代码检索模块。
- `ScanSessionRunner` 把显式入口、自动发现入口或 diff impact 入口统一成扫描会话。
- `WorkflowRunner` 创建单入口运行态并调用 `WorkflowExecutor`。
- `zscope/workflows/*.yaml` 只声明阶段顺序；具体 handler 由 Python 编排层提供。内置扫描 workflow 在入口发现后先执行一次 session 级 `wiki_compile`，该阶段完整结束后才允许进入任何 entry 分析或 Validator 验证。
- C/C++ 既有非实例分析路径在入口与索引/Wiki 就绪后，先对可达并集进行增量语义建模、合并并重读 user_config，再启动规则；直接 Analyzer、单入口、批量、diff、resume、maintain 共用此阶段。独立建模池以 `llm_max_inflight` 为上限，复用 modeling profile 和全局/endpoint 限流，不受 entry_workers 限制。依赖完成即调度父函数，递归组件冻结上一轮契约并最多迭代 RuntimeSpec 的 `semantic_model_max_rounds`（默认 3）轮，失败或未收敛标为 partial；取消仍传播中断。
- 建模任务先尝试由已验证 callee 或人工契约静态生成透明封装快照；无法确定的底层资源协议仍进入 LLM 发现和实现校验。静态快照与模型快照共用依赖调度、发布屏障和缓存；释放端提议可驱动不可达对应接口的补建。普通重扫输入不变时不调用模型也不改写工作簿。
- 模型请求归因包含稳定符号 `audit_unit_uid` 和 `semantic_modeling_attempt_N`，可与发布快照及 `.attempts.json` 中成功/失败的尝试记录关联；位置移动不改变符号 UID。旧用量事件缺少符号身份时，只能按阶段汇总，不能把线程活动次数当成逐符号 token 成本。
- 批量任务经 scheduler/parallel analyzer 分发。确定性候选完成后，balanced/deep 在全局验证之前依次构建 Security Semantic Map、规划 coverage gap、登记主动发现 hypothesis；所有候选通过 CandidateRegistrar 登记并统一冻结 Ledger，最后按 validation cluster 验证和装配报告。默认快照怀疑点只作为已有候选的验证背景；内部条件观察 shadow 在盲调查完成后、冻结前登记，单入口保持相同阶段顺序。
- `semantic_snapshot_candidate_mode` 仅为 RuntimeSpec 的 `off|shadow` 实验项。shadow schema 单独收集具有对象或 source/sink、源码位置、违反性质、成立条件和缺失事实的条件观察；当前发布会话绑定及源码校验通过后才生成未确认义务。旧 JSON、模糊说明、过期版本或无入口路径不能获得登记资格。观察独立归因为建模来源，走统一裁决但不晋升默认结果；不得进入 candidate-blind 初始提示。
- `semantic_model_demand_mode` 同样默认 `off`，shadow planner 在候选生成前读取调用图和建模上下文，记录选择、推迟、未知以及依赖闭包。类型化缺口和 D03 覆盖键只补充需求，不能作为唯一需求来源。shadow 不跳过原调度、不改变 SCC、单任务所有权或发布屏障；计划与实际执行分开进入报告，未知和推迟不缓存为安全，也不声称节省调用或 tokens。

## 必须保持的不变量

- 动态调查证据由 `InvestigationSession` 登记，绑定项目、源码、构建范围、工具、策略和模型输入身份；读取前后重新验证源码及 artifact。模型只能请求获准取证，不能自签引用或 proof。缺少构建身份时仅形成源码观察，may/partial 不提升为完整证明。
- 扩展调查范围保存在独立清单，原 AuditUnit 和 Ledger 身份不变。动态报告通过同一 CandidateRegistrar 进入未确认义务；其进程内引用不写入旧 AuditUnit 报告缓存，持久化 JSON 不能恢复授权。工具和语义刷新权限继续受只读边界约束。
- `bounded_investigation.py` 复用 JsonToolAgent 的结构化输出和取消机制，在一次式发现之外按风险、证据缺口和可查询性准入。内部 RuntimeSpec 的 `active_investigation_mode` 默认 `off`，仅允许 `shadow`；单任务最多四轮、一次范围扩展及有限 deadline，单轮失败和重复无增益查询均停止并保留未覆盖状态。阶段单元预算复用 `max_subagent_tickets`，不改变 token 计量账本或 public Config v2。
- 调查使用候选盲投影和只读工具，缺少可验证的语义、图或流仍返回 unavailable/unknown。shadow 经同一 Registrar 登记，保留 canonical obligation，但使用独立验证策略分组及 `active_investigation` 来源；不得晋升已有 active 候选、改变主 Ledger 冻结或把重叠发现计作独占 TP。工具尝试、决策调用与物理模型尝试分别计量，无法取得的物理用量明确为 unknown。
- `ExternalFindingsImporter` 仅被动解析有界 JSON/SARIF，要求显式项目、源码、构建/规则身份及获准工具版本；注册前重验源码摘要和语料权限。输出经 CandidateRegistrar 成为未确认的 `external_offline` 信号，保留外部来源、证据和来源自报覆盖。同源重复与跨工具重叠分别计数；外部 verdict、任意 metadata 或内容摘要均不授予 proof，主 Ledger 冻结规则保持。
- `ExternalInvestigationTask.from_session` 从调用方拥有的 D01 会话构造不可变任务；`run_external_investigation` 首版只消费严格离线 JSON 意图，程序调用允许的五个事实工具并登记本轮引用。它不加载 provider callback、SDK、CLI、命令、环境或凭据；真实 provider 返回 unsupported。路径/工具权限不能扩展，无写入、网络、扫描或递归 adapter；最多四步和有限 deadline，取消只作用于本次子令牌，借用会话由调用方关闭。输出明确为 external/offline 与 partial，未知 usage 不作估计，序列化任务摘要不恢复权限，也不冒充原生独立发现。
- Security Semantic Map / AuditUnit v2 对资源生命周期与回调两类单元使用对象、操作位点及构建上下文覆盖键；源码 token 提取的对象只是观测，不是别名或效果证明。构建身份不明时按稳定源码记录隔离，不按同名或同文件合并；其他家族保留现有粒度。入口根与单元分离，等价调查可共享，occurrence 保留各入口路径及其事件引用。
- 已有候选只能由程序映射到精确覆盖位点，候选自报构建或覆盖键不获得权限；同文件、同对象的一项候选不代表其他位点已检查。风险分数只控制调度，不能进入盲调查提示。计划、尝试、报告完成、真正覆盖完成、预算 deferred、阈值未选与未覆盖分别记账；仍有 unknown 或 unresolved facts 的报告保留 partial。
- v1 地图与单元可以读取迁移，但必须保留 `legacy_unverifiable`，使旧调查缓存失效；重规划、合并或缺失可选覆盖字段不能恢复 current。动态调查工厂拒绝用迁移旧地图拼接当前源码证据。

- Review 关联发现使用独立冻结的追加 Ledger，不能重新打开主 Ledger 的发现阶段。主 Ledger 的最终 lifecycle snapshot 和 summary 合并追加区；子候选走正常验证，最多一代，中断时保留未完成义务。追加区参与报告去重和计数，不应仅停留在入口报告的原始 observations 中。

- `--resume`、`--maintain` 和 diff impact 的互斥规则必须在真正开始扫描前验证。
- `analysis.workflow_name` 是运行时字段，不允许作为用户 YAML 配置项。
- 没有匹配入口的 diff path 应明确停止，不能静默回退到 `main`。
- 入口发现、断点续扫、历史报告备份和取消状态必须保持可审计。
- 自动入口发现区分头文件 API、函数体信号和候选选择阶段，打印阶段耗时及数量。头文件遍历及函数体发现有独立的 30 秒心跳，不依赖单个文件或函数完成后才能报告进度；这些优化不改变入口选择范围。
- 批量完整性检查必须以实际物化并调度的入口身份对齐结果，不能用签名不完整的原始入口把已完成任务误判为中断。
- Workflow 文件和 handler 名称必须一一对应，未知 step 应明确失败。
- 启用 Wiki 时，每个 scan session 只能编译并固定一次 `ProjectKnowledgeService`；所有入口和 scan-level Validator 共享该只读实例，入口 Analyzer 不得再次编译或提前关闭它，session 结束后统一释放。
- `fast` 不运行语义补全或主动发现；它们未启用时不能误标 partial。balanced/deep 中已启用阶段因预算跳过审计单元时必须保存已得结果、标记 `completeness=partial`，CLI 退出码为 2。
- scan-wide token manager 必须在配置生效边界创建一次并注入所有入口、Agent 和 LLM profile，不能为并行入口各建一份预算。

## Balanced 持久灰度决策

`BalancedRolloutController` 以严格版本化 JSON 原子保存 `telemetry_only → validator_opt_in → semantic_shadow → 10 → 50 → 100 → balanced_default` 的观察和决策。每次晋级至少要求当前阶段持续 7 天并覆盖 20 个不同项目，`100` 阶段还要求两个稳定窗口；token 守恒、归因完整或无 proof 静默拒绝任一硬不变量失败时立即回退 fast，用户阈值连续两个窗口越界时同样回退。状态记录 decision/observation 的 owner、reason 和 UTC timestamp。

`scripts/balanced_rollout_operator.py` 是该状态机唯一的离线 operator 入口。先在受保护控制面通过进程环境注入至少 32 bytes 的 `Z_SCOPE_BALANCED_ROLLOUT_HMAC_KEY`，再用 `initialize --state-file ... --owner ... --reason ...` 建立 telemetry 观察期；密钥没有 CLI/YAML 参数，也不会进入 stdout、报告或错误正文。`record` 还必须同时传入控制面读取到的 `--expected-state-sha256` 和一个严格的 `zscope.rollout-observation-window.v1` 文件。controller 在跨进程文件锁内完成验签、SHA 比较、决策、重新签名和原子替换；竞争更新只有一个能提交，成功结果同时返回 previous/state/window-file SHA。签名信封使用 HMAC-SHA256，绑定 schema、policy、C/C++ 语言、release identity、与 decision 历史一致的单调 sequence、签发时间和最长 90 天有效期。可选 `Z_SCOPE_BALANCED_ROLLOUT_RELEASE_ID` 必须由 operator 和 scanner 使用相同值；省略时绑定当前 Z-SCOPE 版本。operator 不执行用户命令、不连接遥测，也不根据窗口内容之外的信息自证 precision、token 守恒或其他指标。Observation Window 必须由中央受保护控制面从独立审计数据生成、审核并签发；控制面随后按输出 hash 校验完整状态文件，并把同一文件分发为各项目 `${snapshot_dir}/balanced_rollout_state.json`。项目扫描器只消费该只读快照，不能运行 operator 来为自己的指标背书。

安装了 `${snapshot_dir}/balanced_rollout_state.json` 后，所有入口在创建 scan-wide token manager 之前统一应用该决策。只有 scanner 进程持有相同管理密钥且信封验签、release identity、有效期与内部状态全部通过时，状态才是 managed：telemetry 强制 fast；validator opt-in 只允许显式 balanced/deep 且不运行语义/发现；semantic shadow 运行但把主动发现终态保存为 `shadow_observation`；10/50/100 使用 `project.id` 的稳定 SHA-256 bucket 做确定性 enrollment；`balanced_default` 才把 C/C++ 省略档位解析为 balanced。缺少密钥、裸状态、篡改、过期或 identity 不匹配均把文件视为 unmanaged：省略档位保持 fast，但用户显式 `--scan-depth balanced|deep` 不被项目本地文件阻断。未安装状态文件同样表示尚未启用受管灰度。Java 始终服从独立语言门禁。

## 常见变更应落到哪里

- 新 CLI 选项或模式分流：`zscope/cli/cli.py`，并检查配置、服务入口和退出码。
- 入口发现或 diff 选根：`entry_discovery.py`、`diff_impact.py`、`scan_session.py`。
- 扫描调度、并发、取消和预算：`scheduler.py`、`parallel_analyzer.py`、`budget.py`。
- 新 Workflow 阶段：添加/调整 `zscope/workflows/*.yaml`，同时实现并注册 handler。
- 单入口运行态和阶段装配：`workflow_runner.py`、`workflow_executor.py`。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_cli_output.py tests/test_workflow_runner.py tests/test_workflow_specs.py
python -m pytest -q tests/test_entry_discovery.py tests/test_diff_impact.py tests/test_scan_scheduler.py
python -m pytest -q tests/test_active_discovery.py
python -m pytest -q tests/test_balanced_rollout.py tests/test_balanced_rollout_operator.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 完整运行流程见 `docs/architecture.md` 的“运行时主流程”和“控制平面”。
- 用户可见命令和模式见 `README.md` 的端到端使用指南。

## 关闭与共享资源

`ScanSessionRunner` 持有本轮 `SessionReproductionPlanner` 并传给批量、单入口 Analyzer 及 ValidationRunner。独立 Analyzer 创建自己的服务；入口 worker 共用本轮服务及索引，不能重新绑定到其他项目的索引。计划和结果写入 `snapshot_dir/reproductions/<session>/<candidate>/`，初始策略串行执行，防止并行入口覆盖复现产物。业务源码保持原状，生成的程序入口仍来自真实 TU。默认 RuntimeSpec 为 off；自动多 TU 链接、通用输入生成及跨候选共享构建仍未完成。复现证据的当前性与裁决要求见分析流水线模块。

ParallelAnalyzer 关闭后拒绝接收新批次，先停止并等待调度器，再清理拥有的项目知识服务和 LLM 客户端。外部传入的客户端由调用方关闭，多重引用不会造成重复关闭。共享额度注销与已在途请求排空由 LLMClient 自身协调。

## 建模任务所有权

`modeling_coordinator.py` 跨入口、Analyzer 和按需快照合并相同命名空间、符号及输入版本的任务。Future 保存原子提交后的结果或同一失败；所有者负责最多三次格式/契约修复尝试，等待者不能另起重试。局部等待取消不传播到共享任务；独立扫描根共享活动任务，只有所有参与扫描均取消时才取消该任务。完成后的失败按参与扫描保存，下一轮可重试。新扫描可以重试缺失或失败缓存。独立符号继续并发，SCC 使用冻结契约和统一发布；指标分别记录请求、唯一任务、合并等待、内部尝试、物理 LLM 调用、等待时间和峰值并发。

扫描级中断先取消根令牌，再等待建模任务池退出，避免线程退出等待阻止取消传播。没有外部取消作用域的直接调用也建立本轮令牌；单个请求的局部超时仍不能取消其他请求依赖的共享任务。

线程入口发现从标准线程调用及实际源码参数转发推导外层封装的回调位置，支持嵌套与参数换位；不预置项目接口名称。项目同名定义和不确定的重赋值不能继承标准回调位置。这些发现只是入口线索，不授予生命周期证明。

回调注册同样产生自动入口：`signal` 的处理函数、`sigaction` 新 action 中的 `sa_handler` / `sa_sigaction`，以及 `atexit`、`at_quick_exit`、`on_exit` 的退出回调使用 `callback` exposure，参与现有去重、入口预算、批量调度和入口持久化。源代码参数转发支持嵌套函数封装、参数换位、局部别名和 action 成员映射；不根据项目接口名称猜测注册角色。已知 `sa_flags` 选择对应成员，只读取新 action，不把旧 action 输出查询或 `SIG_DFL` / `SIG_IGN` / `SIG_ERR` 当作回调。项目同名实现、重赋值和不确定对象写入不能继承过期绑定。

信号回调保留 `callback_context:signal` 和异步信号审计提示，沿调用链检查信号安全、重入和共享状态；退出回调使用 `callback_context:exit`。入口仅表示可能执行，不证明注册成功，也不授予资源生命周期证明。无法解析的动态函数指针、复杂控制流下的别名及递归增长的成员路径不猜测目标；该入口发现扩展不等于完整的间接调用图或新增系统 API 生命周期模型。

建模任务的物理尝试数直接来自全局账本已结算的同一调用事件，包含网络失败；成功响应数、提供方报告 tokens 与失败保守计量分列。等待者不重复归集所有者的用量，单个任务失败或取消也保留已发生的调用。

工作簿发布屏障完成后，`semantic_modeling` 使用同一有效 Registry 生成资源接口覆盖诊断，写入快照目录的 `.semantic-modeling/publication.json`；摘要经 `GlobalModelStats.resource_inference_coverage` 进入既有报告 metadata。接口行区分未见、提案、schema-only、源码核验、人工假设、不支持和失效/冲突；调用行保留条件和未知原因，能定位的未知调用保留源码 token 站点，不能定位时显式标记。统计分母为已调度图，入口外 cleanup 未测量，不代表全项目已覆盖。消费者能力说明与 engine coverage / rule catalog 的实际启用、执行记录分别保留，不把“已知契约”计为“检测器已执行”。诊断没有裁决权限，不另建调度器或持久化库。

注册关系在 CodeIndex 中单独保存目标身份、注册位置及异步上下文，并按源码摘要失效；调用查询以 `callback_registration` 类型返回这些边。Graph 不将注册边作为同步调用传播持锁状态。线程创建端在没有其他已覆盖上层入口时同时纳入入口，worker 入口保留，避免只检查线程体而遗漏创建端的参数与所有权义务。

## 2026-10-14 当前持久作业与只读准备切片

`jobs` 持有项目侧 SQLite、独立 owner、每次 attempt 的输入和报告绑定；控制面复用同一 service，不依赖旧内存 scan 状态。取消/崩溃/重试按精确启动身份核验，PID 重用或 zombie 不授权重复扫描。每次新 attempt 重算真实源/构建输入，配置 stat 缓存只定位 store；持久报告通过正式 shared-json reader 读取，不恢复确认资格。owner 发布终态时，job 与对应 attempt 在同一事务提交；attempt 写入失败则回滚，读取终态后无需等待另一次写入。

`entry_instances` 在索引后枚举精确 BuildContext+USR 并拒绝外来身份/错误文件；metadata 分开 planned_instances 和 scheduled_instances（未接入时 null）。`ParallelAnalyzer.analyze_entry_instances` 已提供逐实例实际 Analyzer/候选/共享验证入口；验证按唯一精确实例选择 scoped index，不允许无身份或多个身份的候选借用全局语义，无法绑定的义务保持 needs_review。批次仍沿用一次冻结及集中裁决。普通 C/C++ `ScanSessionRunner` 在当前 native 计划可核验时实际进入逐实例 Analyzer，单入口、批量和恢复共用这条路径；无法核验的实例保留缺口，不回退名称报告。计划枚举、实际分析和全扫描覆盖分别报告，当前全扫描覆盖仍为 false。

逐实例入口不运行旧全局建模、确定性事实建模或主动发现。当前实例的 native call/reference 收据已供给受限 callee/caller、函数枚举和类型/宏/全局引用，查询按当前构建、native USR、文件和位置消歧，发布与复用前复核依赖；真实头文件变化撤回旧缓存。完整定义、其他图查询、导航缓存与无成员收据的契约仍为显式缺口。函数正文只在导航文件及起始行与当前 native owner 对应时提供；不能核验的条件定义返回缺口。共享 callee/声明注释不随正文返回，未知消费者不回退裸名或第一变体。因此该入口的身份隔离通过不等于消费者齐备、全变体建模、真实链接或完整 S01 完成。

owner 截止先触发当前扫描令牌的合作停止，调度器停止领取新工作并保存真实剩余，在途 Analyzer/验证有界收尾；watchdog 处理未退出进程。resume 启动新 attempt。当前保存的是扫描范围的整体完成，逐实例部分恢复、公平持续批次和完整 JOB04/JOB06、INC05 仍未完成。

### 持久队列与精确实例扫描

`jobs.session_scheduler.SessionWorkScheduler` 提供当前进程登记的工作回调，实际消费持久 `WorkQueue`。工作身份包含 kind、稳定 scope 和精确 build；恢复只保留工作数据，重新核对 job/run/owner/input 并登记当前回调，不从 JSON 恢复命令或证明权限。每次入队、领取与结算按 store→queue 顺序持锁；`JobStore.bound_attempt` 在 job 写锁内核对绑定，直到队列事务提交才释放，事件和进度在锁外写入。逐实例产物发布前先在锁外完成 native/语义当前性校验（逐实例 receipt、依赖摘要），再进入写栅栏；发布后仍在栅栏内复核一次，因此在窗口内发生的 owner 交接会被拒收，而长时间的摘要计算不再占用 job 写锁把 owner 心跳饿死。状态读取走已初始化快路径，不在每次读取时重放建表 DDL。

`WorkQueue.settle` 在同一事务内核对当前 claim/input、提交父项 verdict 与子发现；结果内及已有身份的重复项去重，入队失败回滚父项。批次或容量上限留下有原因的持久未决父项；该驻留状态进入真实 remaining，同输入恢复不将它误作 attempts 耗尽，也不忙循环。输入变化仍通过 recovery 撤销旧完成与驻留前提，重新核验；普通 handler 失败与延期保持原尝试上限。

owner 向 scanner 传递当前作业的五项绑定环境，截止或取消时先给有界合作收尾窗口，再由 watchdog 终止未退出的进程。session 已保存的真实 pending 不被 owner 空占位覆盖；未测进度分母保留 unknown。生产 ScanSession 已通过 `scan_work` 登记实际实例分析、扫描范围集中验证和整体检查点三个阶段，消费该持久调度接口；同一扫描复用 CandidateLedger、验证缓存与一次集中裁决。取消与截止的在途停止已接入该路径，完整持续调度、公平续跑及逐实例 durable 恢复仍单独保留。

owner 收尾时通过只读 SQL 核对当前 job/input 对应队列的实际计数，`pending_count` 只包括 pending、active、deferred；业务问题单独由 questions 提供。缺失、损坏或绑定不同的队列保持未知，不把问题数或截断的 pending JSON 样本作为剩余总数。实际队列尚有剩余或 failed 工作时，即使 scanner 退出 0，也保留 partial 和可恢复状态。该计数不授予 checkpoint 或验证完成权限。

### 本轮队列收据与 remaining

owner 按当前 job/run 的 `session_scheduler_started` SQL 事件选择实际队列，核对事件的 input revision、队列在该 job/当前 run 目录内的解析路径，以及数据库的 job/input 元数据，再只读统计全部状态。它不按文件 glob、业务问题数或 pending JSON 样本推算 remaining；无 scheduler 收据的既有 canonical 队列仍按原 job/input 绑定读取。损坏、跨目录、跨输入、跨 job 或缺失队列保持未测量，不回退另一队列。该接线支持 attempt 队列，不能据此宣称 ScanSession 的完整 checkpoint、在途停止和逐实例恢复已验收。

### 绑定完成收据与跨运行复用

`JobStore.append_bound_event` 在同一事务复核 job、run、owner、输入后发布绑定事件；普通日志和手写 JSON 不会形成完成收据。`trusted_completion` 只返回同 job、输入、计划的真实生产坐标，文件和语义资格由扫描消费者继续核验。完成文件位于 producer 的 run 目录，先原子发布并计算摘要，再提交收据；缺少收据时保持未完成。

新 attempt 先实际构建当前 native 索引和精确计划，再核对实例集合、输入、编译器与默认契约内容版本、可核验语义/回答依赖及文件摘要。包含确认或 proof 权限的序列化结果保持 miss，重新执行当前分析与裁决。最终报告发布与当前 job/run/owner/input 检查共用事务围栏，避免检查后交接仍覆盖当前报告。缓存实例、本轮实际执行实例和生产 run 分开计量。

每次 attempt 使用独立队列，owner 从该 run 的真实 scheduler 收据读取全部状态；canonical 队列及 sidecar 保留。生产实例路径不再通过旧整体检查点跳过当前集中验证；`trusted_completion` 等兼容接口不授予新 attempt 的验证完成权限。

### 有界逐实例结果与结算

实例分析必须闭合实际收集、合并、持久化与登记阶段，并复核当前精确语义，才可准备逐实例结果。结果只保存无终态裁决、无 proof 权限的 pending 记录和完整成员诊断；codec 的 UID 计数与 Ledger 的 role/build/cluster/完整 occurrence 行清单分别核对，不能互相替代。

收集操作或当前性复核失败时，先记录 `cancelled`/`error` 和实际原因，再传播同一原始异常，不能把阶段留在 `running`。关闭后的恢复摘要返回独立 JSON 映射；调用方改动嵌套容器不会回写内部计量，非映射根对象被拒绝。

`JobStore` 以 store→queue 锁序核对当前 job/run/owner/input、实际 claim 和实例资格。只有队列接受本次结算后，才在同一 Store 事务发布 `instance_result_persisted` 事件及绑定收据；普通事件接口不能伪造该种绑定。恢复 reader 联合核对事件、receipt、attempt 和 producer 文件坐标，最新坏关联不能回退旧好收据。队列已提交而收据事务失败时不产生可复用结果；下一 attempt 重新分析，不宣称两个数据库之间存在分布式原子提交。

提交后观察者才计量恢复集合 R、本轮执行集合 E 与计划集合 P，要求 R∩E 为空、已结算集合 R∪E 是 P 的子集；全部计划实例成功结算时才有 R∪E=P。即使全部实例恢复，本轮也必须使用新验证缓存、重新登记当前义务并执行一次集中 Validator；达到 DONE 后才允许写新检查点和报告。文件存在、旧报告、实例 verdict 或 queue 样本不能替代该屏障。此范围仍不表示完整公平调度、所有语义域、真实项目效果或 S08 工作包验收。

恢复结果保留生产 run 的原始 duration/context/token 指标与绑定收据，另列历史成本来源；本轮报告总计只包含本轮实际执行结果和本轮集中验证、建模及去重成本。全部实例恢复仍执行当前集中验证，其实际成本照常计入。响应 token 三元组来自同一份当前成功响应统计，合法的零值不回落到旧累计量；同一共享客户端只计一次。历史结果对象被当前新结果替换后，旧恢复成本标记不随结果键继承。

共享客户端的累计统计按本轮起点计算增量；重复批次重新取起点，不清空客户端的全生命周期账本。由本轮工厂创建并交接的客户端映射只领取一次原始起点，因此 Session 的 Wiki 前置建模与后续逐实例分析共属本轮；外部已使用的普通映射从 Analyzer 接收时计起。实例构造同时接收同一项目知识服务，避免重复构造；项目级 semantic_result 仍不能进入精确实例语义链。无法从累计统计相减得到的分位数等指标保留未知，不能伪造本轮值。

### 配置停止窗口与真实预算

v3 execution.stop_at 的时区与本轮绝对边界只解析一次。CLI 把剩余窗口收紧到 ScanSessionRunner 已共享的同一个 CancellationToken，供 HTTP 等消费者读取真实剩余预算；已有更早期限、父取消及其原因保留，自身窗口先到才转为该窗口取消。release 停止 watcher，预算不因释放而延长。新建持久作业在未显式传入非空 stop_at 时保存配置窗口，显式请求优先；同 request_id 返回原作业及原窗口。已解析的绝对窗口到期后不滚到明天；初次解析 HH:MM 配置仍按配置时区选择下一次该时刻。新建持久作业（Web `/api/jobs`、MCP `zscope.scan.run`）在配置窗口解析后若该时刻已过，直接以 `stop_window_closed`（400）拒绝创建，不产生开局即停的作业；显式请求窗口不经过该检查。resume 仍开新 attempt 且不重新套用配置窗口。owner 启动的 CLI 核对当前作业、run、owner、输入版本和运行目录后，从持久窗口收紧同一共享令牌；SQL 空窗口不回退配置，部分环境或失效绑定拒绝启动。独立 CLI 保留配置窗口。逐实例部分恢复、完整扫描调度、其余 U01 字段及真实项目效果仍未完成。

共享 CancellationToken 在任何公开观察首次确认期限已生效时记录原因，不依赖 watcher 调度。原生父链的期限与显式取消按已知单调发生时刻选择，原因一旦记录便不被后来事件改写；后注册的过去期限只在注册时生效。自定义父令牌通过公开接口观察，未知发生时刻保留原有父公开原因优先，不能以观察时刻伪造取消顺序，已记录的子原因仍保持不变。父链剩余预算取最小值，期限只可收紧。
