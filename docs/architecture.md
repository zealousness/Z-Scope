# Z-SCOPE 架构文档（v1.3.2）

## 1. 架构定位

Z-SCOPE 是面向大型 C/C++ 项目的证据优先静态分析平台，并提供 Java Preview。系统以结构化代码事实、程序分析后端信号、项目语义快照和多智能体验证为基础，构建可审计、可恢复、可扩展的缺陷发现流水线。

平台采用“静态事实先行、语义推理收敛”的架构原则。C/C++ 内存、资源生命周期和并发问题首先由 Regex、Clang、SVF/Saber 与规则产生证据；Java 由 source/java_unified 结构索引、SootUp/WALA/Joern 信号和 Java 规则产生证据。LLM Agent 负责在受控上下文中补全跨模块意图、判断业务约束、验证可利用性，并将结果收敛为可追踪报告。C/C++ Joern 在 1.x 中仅保留弃用兼容入口。

Review 完整事实实验默认关闭：底层保留绑定编译配置的完整相关事实，模型按需分页，程序检查器独立核对候选义务。V3 可实验性构建 uncertain 项的正面案例，V2b 审查旧拒绝；版本化复核封套经过验收后仍由统一 ValidationPipeline 分流。关联发现进入最多一代的独立追加 Ledger，原主 Ledger 保持冻结。具体边界见[分析流水线](modules/analysis-pipeline.md)和[Benchmark](modules/benchmarking.md)。

Native 编译事实已新增按 BuildContext 隔离的持久化与精确查询，保留同一源码的不同编译实例。单实例内的同名函数通过 native USR 消歧，函数事实身份绑定 BuildContext 与 USR；未消歧时仅提供函数选项，不合并证明事件。旧函数导航投影尚不覆盖全部变体，完整扫描消费者仍在迁移；歧义程序事实不能作为单一实例证明，未知链接归属不能推出跨 TU 路径完整。具体合同见[代码检索与后端](modules/retrieval-backends.md#编译实例事实与导航投影)。

C/C++ 三种模式共享“项目级静态发现、入口后置归因、全局候选裁决”：compile database 中每个当前 BuildContext 都先取得精确 native owner 清单，每个 `(BuildContext, USR)` 的 AST/CFG/本地规则只执行一次，TU 图与实例 backend 单元各执行一次；入口不再重复触发发现，只附加 reachability 与 call path。候选携带稳定 `analysis_unit_id` 和构建身份，经全局 Ledger 去重后由 V0 与 Validator 收敛。fast 采用低成本裁决，balanced/deep 追加未闭合义务调查，只有 deep 默认运行分层 LLM 主动发现。真实 link record 未闭合时仍扫描可证明的本地单元，但本轮不得取得 formal qualification。

受限跨 TU 对象路径通过显式本地构建记录核对实际 C executable 成员，保留各 TU 的 BuildContext，并按 USR/签名连接调用与具体对象。只读、完整初始化的有限 ops 表可以按已知选择解析；未知目标或选择仍为缺口。链接产物与全部成员参与当前性检查和 Validator 重放，不把普通调用图或同名符号当作链接证明。该切片复用既有单槽池/留存路径，实验规则维持默认关闭。

非原子引用计数沿用同一契约发布、对象路径和验收链。源码核验只描述受限计数变化，实际终结效果由当前 callback 路径与对象代次确定；池逻辑归还与物理 free 分开。首批只消费 signed 32-bit 计数和内嵌单槽池，非并发执行及业务清理前提分别保留，不能从顺序计数推断线程安全。

有界自定义句柄表同样沿用此链：整数值携带获取代次，dup 创建新的描述符 ObjectRef 并共享底层对象身份，close 根据当前源码和槽状态消费实际描述符。错误返回不能单独决定消费效果，同值重开不能重用旧身份；物理析构与命名空间并发语义仍是独立边界，不将该路径推广为 OS fd 求解器。

锁契约沿同一发布链保存 shared/exclusive/unknown、成功条件及释放/重获转换。共享访问候选与 Validator 分别消费：前者不把读锁当写保护，后者从当前编译器 AST/CFG 核对非逃逸静态锁的声明身份和全部本地访问，透明包装器重新检查当前实现。签名反证只作用于原 race 义务；词法调用方摘要、递归计数、等待、升级与尚未支持的锁 guard 不能补造强保护或排除 UAF。

有限 RAII 由既有 LifecycleAnalysis 与 ReviewClaimChecker 消费：native 构造/析构 USR 和管理器身份，与同一构建的完整 AST、构造映射及析构分支共同核验。单指针 scoped heap guard 的作用域退出与明确捕获的 throw 展开各自清理保存的获取对象，空 guard 不解除其他对象义务。当前事实、标准契约、工具与依赖摘要进入进程内收据；原始事件、序列化分析或模型文本不具证明权限。其他消费者继续将未支持的 C++ 生命周期保留为 unknown。

当前证据重用同时约束正向与否定性依赖。native 头文件存在性查询参与 BuildContext；完整 AST/CFG 热载入复核实际预处理输出；Review 收据持有当前契约注册表依赖，变更或重放中失效便撤回授权。新增访问者、头文件或失效构建不能借助旧缓存继续排除候选。原 S04 回答 revision 和链接清单仍由各自检查器验证，局部等价性不替代完整扫描与异步调度覆盖。

实验性单槽对象协议扫描已连接业务前提验收：用户声明与来源保存在现有项目状态库，按对象、构建、路径及源码/契约依赖隔离。当前源码重放与全部必要声明共同成立后，仍由统一 ValidationPipeline 的程序 proof 分流确认。回答变更使依赖它的历史结论重新进入候选台账和验证；历史报告不直接改写，否定前提也不等于安全证明。范围与数据职责见[分析流水线](modules/analysis-pipeline.md)及[配置与状态](modules/configuration-state.md)。

Z-SCOPE 的定位可以归纳为三个层面：

| 层面 | 定位 |
|------|------|
| 工具属性 | 面向 C/C++ 安全审计、提供 Java Preview 的本地化 SAST 与 AI 验证平台 |
| 架构属性 | 事实平面、证据平面、智能体平面、反馈平面分层解耦 |
| 使用属性 | 支持批量扫描、diff impact 变更审计、增量维护、断点续扫、SARIF 告警复核与导出、WebUI 与 MCP 接入 |

面向的主要问题域：

| 大类 | 典型问题 |
|------|----------|
| 内存安全 | 越界、整数溢出、UAF、double free、invalid free、栈逃逸、未初始化读 |
| 资源生命周期 | 内存泄漏、fd/socket/mmap stale、初始化/释放不匹配、跨 handler 所有权转移 |
| 并发安全 | 数据竞争、refcount 竞态、缺失解锁、死锁、条件变量误用、对象提前发布 |
| 输入与逻辑安全 | 格式串、命令构造、TOCTOU、空指针、失败返回未检查 |

受限 pthread 回调寿命复用 native CFG、ObjectRef、契约发布与 S04 裁决。标准效果分开保存创建、取消请求、释放 join 句柄和等待完成；单槽队列路径进一步保留工作者首次解锁时的局部任务引用，在调用方取消排队项、停止接收后于 join 期间继续。提交/取消 helper 由当前同 TU CFG 重放，不将名称或 active 标记当作完成证明。native opaque mutex/cond 收据、实际锁实例和共享字段访问随路径核验；同锁不能排除 UAF。单等待者 cond_wait 可暂停实际调用，释放 mutex 后接收匹配条件实例的通知，重获锁后才返回并重检条件。仅选定有界调度，首个非法访问后停止并记录真实恢复位置；未匹配通知、一般唤醒/超时场景、取消模式切换/任意取消点、多工作者和完整 drain 调度仍有缺口。默认延迟取消复用当前宏/AST 收据解释受限 C/glibc cleanup，先重获等待锁再按注册栈逆序重放实际回调；原获取对象、正常 pop、取消投递和 join 完成分别记录。同一 C 文件中的工作者直接 helper 复用有界 CFG 调用帧；暂停恢复保留嵌套路径和独立局部状态，返回值仅在函数返回后发布，取消清理归属于注册帧。未知/间接目标、局部地址逃逸和 cleanup 内 helper 不扩大证明范围。业务前提在现有验收阶段集中确认，规则默认关闭。

## 2. 设计目标

实例扫描同时消费无需人工配置的确定性 native 包装器闭包：在当前 BuildContext 内从已授权标准根沿真实 USR 推导受限资源与单调用转发效果，每个构建计算一次，并保存不能推导的原因。该机器事实与已确认项目 YAML 分开，不将模型发现的全部效果复制为必填配置；配置必要性由完整契约等价及实际规则消费对照判断。此切片不证明跨 TU 或整个工程语义覆盖完整，详见[最小配置与自动 native 推导](modules/configuration-state.md#最小配置与自动-native-推导)。

Z-SCOPE 的架构目标可以概括为四句话：

1. **高检出**：多个来源并行产生候选，包括 Clang/SVF、Java 结构与信号提供器、通用规则、跨函数图候选及 LLM 挖掘；入口发现与 diff impact 确定扫描范围。语义建模提供统一接口契约，快照怀疑点仅作为验证背景。
2. **低误报**：每个候选必须携带 source/sink、路径、对象或锁、正反证据、稳定去重键，并经过 Validator、评分、用户反馈和报告分层。
3. **可恢复**：所有关键中间产物和最终报告落地到 SQLite/JSON，支持断点续扫、增量维护和失败后的继续分析。
4. **可演进**：后端、Agent、Skill、Workflow、MCP 工具和 Web 反馈均是边界清晰的可插拔模块。

设计约束：

- 被扫描项目通常是大型 C 代码库，模块多、入口多、跨文件资源关系复杂。
- LLM 使用 OpenAI 兼容 API，支持本地模型、云端模型、多模型路由和多 endpoint 负载/限流。
- 分析必须能运行在批量模式、CI/CD、WebUI、MCP 客户端和 SARIF 验证场景中。
- Worker 预算只能限制“深入分析的数量”，不能成为覆盖率边界。

## 3. 总体架构

```mermaid
flowchart TB
    Ingress["CLI<br/>WebUI<br/>MCP<br/>SARIF"]
    Config["ConfigLoader<br/>zscope.yaml + ENV"]
    Workflow["WorkflowRunner<br/>default / resume / maintain"]
    DiffImpact["DiffImpactPlanner<br/>git diff → obligations + coverage"]

    subgraph FactPlane["事实平面"]
        Index["CodeIndex<br/>统一查询接口"]
        Regex["Regex"]
        Clang["Clang / clangd"]
        JavaSource["Java source structure"]
        JavaUnified["Java unified<br/>SootUp + WALA + Joern signals"]
        Unified["Unified<br/>Clang + SVF<br/>entry clusters"]
        KDB["KnowledgeDB v7<br/>代码事实 + macro + IR"]
    end

    subgraph EvidencePlane["证据平面"]
        Candidate["CandidatePipeline<br/>rules + graph + backend signals"]
        Hierarchy["Deep hierarchical context<br/>函数 → 功能 → 模块契约"]
        Discovery["Deep candidate-blind discovery<br/>hypotheses + semantic supplements"]
        Ledger["CandidateLedger<br/>dedup + freeze"]
        SemanticDedup["Semantic report dedup<br/>programmatic"]
    end

    TokenUsage["ScanTokenUsageLedger<br/>call-level measurement only"]
    subgraph ValidationPlane["验证平面"]
        V0["V0 deterministic proof"]
        V1["V1 one structured decision"]
        V2["V2 fact delta recheck"]
        V3["V3 bounded investigation"]
    end
ReviewMemory["ReviewMemory<br/>baseline + suppression + advisory review patterns"]
    Tools["ToolsRuntime<br/>ToolPolicy + agent tools"]
    Snapshot["SnapshotStore<br/>snapshots + reports"]
    UserCfg["ProjectSemanticsStore<br/>zscope.semantics.yaml"]
    Report["ReportAssembler<br/>views / semantic dedup / SARIF / metadata"]

    Ingress --> Config --> Workflow
    Ingress --> PrimitiveDiscovery["独立原语发现 + 人工复核"] --> UserCfg
    Workflow --> DiffImpact --> SemanticsGate["只读项目语义门禁"]
    UserCfg --> SemanticsGate
    SemanticsGate --> Snapshot
    Workflow --> Index
    Index --> Regex --> KDB
    Index --> Clang --> KDB
    Index --> JavaSource --> KDB
    Index --> JavaUnified --> KDB
    Index --> Unified --> KDB
    Workflow --> Snapshot
    KDB --> Candidate
    Snapshot --> SnapshotPoints["未验证的快照背景"] --> V1
    UserCfg --> Candidate
    Candidate --> Ledger
    KDB --> Hierarchy --> Discovery --> Ledger
    Ledger --> SemanticDedup
    Ledger --> V0 --> V1 --> V2 --> V3
    TokenUsage --> Hierarchy
    TokenUsage --> Discovery
    TokenUsage --> V1
    TokenUsage --> V2
    TokenUsage --> V3
    V3 --> ReviewMemory
    Tools --> Hierarchy
    Tools --> Discovery
    Tools --> V3
    Index --> Tools
    Snapshot --> Tools
    UserCfg --> Tools
    V3 --> Report
    Report --> Snapshot
```

人工 false-positive review patterns 属于独立的 Validator Review Memory
语义域。它可以保存人工 rebuttal、源码上下文和 advisory hints，但不属于
Wiki constraint，也不能生成 deterministic proof、直接 suppression 或当前
finding 的 verdict。Review Memory 按项目、规则和类别隔离，并在源码上下文
发生漂移时失效。

配置 `review_memory.mode=extract` 或 `active` 且使用 `extraction=auto_extract`
时，人工 rejected feedback 会进入独立的持久化抽取队列；后台 worker 生成
proposal。只有 `active` 才将合格 proposal 作为 `authority=advisory` 的
Validator 上下文使用。

总体架构由事实、证据、验证和反馈四个主平面组成。事实平面负责代码索引和程序事实沉淀；证据平面共享项目级静态 pass，并在 deep 中用分层契约摘要与 candidate-blind 探索扩展主动发现；所有来源统一进入全局 Candidate Ledger。验证平面只让完整 proof 或分层 Validator 改变终态，模型 hypothesis 不能直接确认漏洞。反馈平面通过 SnapshotStore、项目语义 YAML、状态库与 ReviewMemory 分别保留中间产物、人工契约、最终报告和人工决策；旧 Security Semantic Map finder 仅用于离线对照。LLMClient 的所有 profile 共享 scan-wide token 账本；ToolsRuntime 向调查和受控发现开放白名单内的只读查询。

跨语言规则治理在既有候选生命周期上增加严格预检：`project.language` 决定 C/C++ 与 Java 后端、规则、Skill 和语义 schema；包内目录、YAML pack、指定 provider、Skill 契约和 disabled IDs 组合为不可变 `EffectiveRuleSet`。重复 ID/alias、未知字段、语言错配、缺失 Skill 或能力错配在任何外部工具/LLM 启动前失败。`zscope.candidate.v3.5` 仍是内部候选协议，规则 provenance 以兼容字段追加，不改变稳定候选身份算法。

v1.2 没有替换 v1.1 的主平面；该版本的架构增量集中在性能、精度和可审计性：diff impact 从反向入口枚举收敛为语义义务与覆盖计划；Unified/SVF 增加入口聚类、互斥/共享 bitcode pool 与缓存 manifest；Clang/KnowledgeDB 强化增量缓存、macro 和删除文件处理；Validator、alert-verify 与 LLM 客户端增加并行、fast-path、endpoint 容量控制和成本统计。v1.0 已经把原来集中在 `Analyzer` 和 `zscope/core/*.py` 的职责拆成可测试模块：

| 模块 | 主要文件 | 职责 |
|------|----------|------|
| Analysis | `zscope/core/analysis/analyzer.py` | 顶层协调器，装配 pipelines、agents、tools、workflow、budget、snapshot 与 agent policy |
| Candidates | `zscope/core/candidates/` | regex、Clang AST/CFG、SVF/Saber、Java rules/signals、Graph、KnowledgeDB 后端信号和 candidate evidence |
| Rules | `zscope/rules/` | 内置目录、descriptor/alias、`EffectiveRuleSet`、YAML pack、Provider V2、预检与 provenance |
| Validation | `zscope/core/validation/` | Validator evidence pack、验证运行、suppression、baseline、score、`needs_review` 分流 |
| Reporting | `zscope/reporting/` | `FinalReport`、JSON/Markdown、report views、semantic dedup metadata、SARIF v2.1.0 |
| Identity | `zscope/common/issue_identity.py` | `canonical_issue_key`、`stable_issue_fingerprint`、source context fingerprint、根因级去重 |
| Review Memory | `zscope/memory/review_memory.py`、`zscope/review_memory/` | 人工 false-positive 原始记录、模式 proposal、advisory hint；与 Wiki constraint 隔离 |
| Semantics | `zscope/semantics/` | 内置默认 API 语义、项目 overlay、用户配置上下文、语义推断 |
| Orchestration | `zscope/orchestration/` | workflow、entry discovery、diff impact、risk budget、subagent、history reconciler、parallel analyzer |
| Tools | `zscope/tools/` | LLM 工具运行时、参数校验、ToolPolicy、敏感路径 hook 和审计 |
| Web / MCP | `zscope/web/`、`zscope/mcp/` | Dashboard service layer、stdio/HTTP MCP、远程安全校验 |

### 3.1 配置边界：UserConfigV2/V3 + RuntimeSpec

配置加载分为三层：

1. `UserConfigV2` / `UserConfigV3` 按版本严格解析用户 YAML：v2 保留语言后端拓扑、SVF 规划、并发和规则扩展；v3 使用 llms、project、scan 与可选 execution，工程目标逐项保留，多目标执行仍明确拒绝。两版本均以 YAML 父目录为唯一工程根，不接受独立 root/source_root；项目内相对路径从该目录解析。
2. 打包的 `runtime_defaults.yaml` 解析为 `RuntimeSpec`，提供 Agent 启用状态/LLM 角色、分析预算、缓存、报告策略和稳定算法默认值。
3. loader 把两者组合为内部 `EffectiveConfig`，并把 RuntimeSpec 的版本、来源路径和 SHA-256 写入配置哈希、缓存身份与报告 metadata。

产品运行时接受严格 `config_version: 2` / `3`，不保留 v1 或旧双根字段别名。v3 preset 与有效深度统一为 fast/balanced/deep，Java 仅 fast；旧 quick/overnight 只能显式迁移为 fast/deep。旧配置由独立的 `zscope-config migrate` 读取，迁移到原工程目录并核对原路径基准，不静默扩大或缩小扫描范围。开发者覆盖必须同时设置 `Z_SCOPE_DEVELOPER_MODE=1` 和绝对路径 `Z_SCOPE_RUNTIME_SPEC`；覆盖文件也执行重复键、未知键、类型和枚举校验。

`AGENT.md`、`SKILL.md` 和 workflow YAML 分别保持 Agent prompt、Skill/Tool 和流程契约，不复制进 RuntimeSpec。KnowledgeDB、snapshot 与默认 user-config 状态路径统一相对 YAML 所在工程目录，避免跨目录运行污染进程工作目录。

## 4. 运行时主流程

### 4.1 默认扫描

默认工作流由 entry workflow 与 scan-level 收敛阶段共同组成：

1. `discover_entries`：当 `--discover-entries` 或 `project.entry_discovery.enabled` 启用时，发现公共 API、通信/IPC、线程入口、已解析的信号/退出注册回调和用户输入点，并把候选入口列表写入项目根目录 `entry_functions_list.json`。注册回调使用 `callback` exposure，信号回调保留异步执行上下文；入口线索不代表注册必然成功。
2. `prepare_semantics`：C/C++ 在扫描开始前只读加载 `zscope.semantics.yaml`，要求 pending/stale/unresolved/跨构建冲突为零，并把当前证据支持的 confirmed contract 编译为实例级 Registry；扫描不执行接口发现、不调用相关 LLM，也不写回 YAML。
3. `collect_candidates`：各入口收集规则、图与 backend signal。快照怀疑点仅供 Validator 验证已有候选时参考，不独立登记到 Candidate Ledger；发现层不得因 token 预算静默丢候选。
4. `semantic_and_gap_discovery`：fast/balanced 不做独立发现；deep 从共同静态 pass 的精确 BuildContext/USR 与真实 link record 建立函数→功能→模块契约摘要，主动查询已准入函数事实，提交无规则 hypothesis 并向已有候选补充待验证语义。旧 Security Semantic Map finder 仅保留离线对照，不默认双跑。缺少精确静态输入时明确记录 gap。
5. `freeze_ledger`：全部入口与主动发现结束后冻结全局 Ledger，按同一安全义务跨入口合并。
6. `validate_findings`：三模式共享 V0 proof 与 V1 低成本裁决；balanced/deep 对非 shadow 未闭合义务运行同一自主 Validator。provider 作为取证加速手段，调查可组合只读工具、正反解释和新事实；中风险内部候选不再被风险阈值排除。程序核对身份与引用，模型作语义判断；确定性拒绝和有证据 LLM 拒绝分别记录为 `rejected_with_proof` 与 `rejected_with_evidence`。缺少范围覆盖、业务假设或关键证据时保持未决。
7. `persist_report`：无论完整或部分完成都保存报告、地图、usage 与未覆盖区域；已启用阶段不完整时标记 partial。

当 `${snapshot_dir}/balanced_rollout_state.json` 存在时，配置生效边界在创建 usage 账本之前执行统一灰度策略。状态必须是由受保护控制面使用专用环境密钥生成的 HMAC-SHA256 信封，并通过 schema/policy/language/release identity、单调 sequence、签发时间、有效期和内部状态校验，才有权改变省略档位：telemetry/回退状态强制 fast，validator opt-in 不启用语义/发现，semantic shadow 运行候选盲发现但将其闭合为不进入用户视图的 `shadow_observation`，10/50/100 依据稳定 project-id bucket 做确定性 enrollment。CLI、Web、MCP 和报告均回显 requested/effective depth、rollout stage、bucket、认证状态与语义/发现可见性；无密钥、裸文件、篡改、过期或 identity 不匹配均视为 unmanaged，不能把省略档位切为 balanced，但不会阻断用户显式 `--scan-depth balanced|deep`。没有安装状态文件的开发/既有部署保持原配置行为。

Workflow 是 Python 编排层的执行计划，不作为大段提示词注入模型。CLI 选择运行模式：默认使用 `default`，`--resume` 切换到 `resume`，`--maintain` 切换到 `maintain`；`--mode ruledriven` 和 `--mode alert-verify` 走各自的专用入口，但仍共享 call-level usage 账本和验证协议。`ScanSessionRunner` 会在 session 步骤后决定入口形态：显式 `entry_functions_list`、入口发现候选或 diff impact 候选进入批量模式，否则回退到 `entry_function` 单入口模式。public v2 不暴露 workflow 或 `analysis` 区块，扫描成本由报告计量而不是运行时 token 门限控制。

### 4.2 批量、断点续扫和增量维护

| 模式 | 入口 | 行为 |
|------|------|------|
| 默认单入口 | `project.entry_function` | 未配置 `entry_functions_list` 且入口发现无候选时，分析单个入口并生成 `report.json/md` |
| 默认批量 | `project.entry_functions_list` 或入口发现候选 | 多线程执行每个入口，汇总 `zscope_batch_report.json/md` |
| `--diff-base` / `--diff-head` | `entry_functions_diff.json` | 从 git diff 映射变更函数并反向寻找受影响入口；报告标注 diff relevance |
| `--resume` | `resume.yaml` | 从 `snapshots.db` 跳过已有成功 final report 且无 pending validation 的函数，最后合并跳过项报告 |
| `--maintain` | `maintain.yaml` | 比较源码/语义哈希，未变更函数零 Token 复用历史报告，变更函数先调和历史缺陷再重扫 |
| `--mode ruledriven` | Joern | Joern 规则扫描后交给 LLM 验证 |
| `--mode alert-verify` | SARIF | 将外部 SAST 告警归一化为 `ExternalAlert`，再由 LLM 二次确认 |
| `--export-sarif` | 完成后的 Z-SCOPE 报告 | 将本次扫描结果导出为 SARIF v2.1.0，供代码扫描平台消费 |

diff impact 模式由 CLI 的 `--diff-base` 启用，不能与 `--resume` 或 `--maintain` 同时使用；选根语义使用内置稳定策略，不暴露为 public YAML。它会生成项目根目录 `entry_functions_diff.json`，其中包含 `path_filters`、`changed_functions`、`analysis_obligations`、`coverage_summary`、`function_coverage` 和每个入口的 `diff_focus`。`--diff-repo-root` 可显式指定 git worktree，重复 `--diff-path` 可只纳入特定路径下的 changed files / changed functions；最终扫描 root 仍可位于路径外。

## 5. 核心分层

### 5.1 控制平面：CLI + Workflow

控制平面负责把用户意图变成可执行流程：

- `zscope/cli/cli.py` 处理运行模式、WebUI、MCP、SARIF 告警验证、SARIF 导出、索引预热、`--discover-primitives` 项目原语发现和 `--diff-base/--diff-head/--diff-repo-root/--diff-path` 差异影响扫描，并暴露 `--mode`、`--sarif`、`--dashboard-host/--dashboard-port`、`--mcp-http`、`--mcp-host/--mcp-port/--mcp-endpoint`、`--mcp-auth-token-env`、`--mcp-client-allowlist` 等服务边界参数。
- `zscope/orchestration/scan_session.py` 统一入口发现、diff impact 入口规划、发现/差异结果落盘、批量加载、断点续扫和报告备份。
- `zscope/orchestration/workflow_executor.py` 执行声明式 workflow step，并在报告 metadata 中记录进度。
- `zscope/orchestration/workflow_runner.py` 装配单入口运行态，负责 state factory、workflow executor、report build/persist/finalize 回调和已有报告返回路径；history reconciler 与 validation runner 仍由 `Analyzer` step handler 调用。

`--discover-primitives` 是独立控制面命令：它构建所有精确函数实例的 native 事实，以当前验证的 packaged primitive 和 YAML 中 confirmed primitive 为根，在 link group/SCC 上发现 wrapper、宏、pointer slot 与 dispatcher。人工审核面只发布效果跨函数边界可观察、载体能精确映射并由规则实际消费的高信号契约；普通字符串/数值 standard-operation 薄封装及无法完整映射全部操作数的 copy helper 留在机器事实层。standard-operation 自动提升当前仅覆盖路径协议消费者能够重放的 `access/stat/lstat/faccessat/fstatat` 委托。宏 wrapper 在同一次命令内基于精确 native 定义收据求传递闭包，并把嵌套调用的参数或全局对象逐层映射到结构化 ObjectPath；名称相似或缺少实参映射都不能进入执行语义。dispatcher 只有在精确 handler 实例已进入该高信号接口闭包时才成为审核候选，普通业务 switch 不进入语义 YAML。pointer binding 只有在当前 native/SVF 证据给出精确、非空且闭合的目标集时才成为待复核 YAML 行；只有 slot/callsite 而没有目标集的调用进入机器 coverage gap，不能要求人工确认一个 schema 本身不允许发布的空绑定，也不能据此宣传已覆盖间接调用。模型只对首次出现、证据变化或歧义候选做一次 advisory 初审与最多一次事实补全，不能把行发布为 confirmed。结果以 pending/stale 合并到同一 YAML，原始事实和模型响应写入 `.zscope_snapshots/semantics/` 后退出。`--infer-user-config` 仅为一个版本周期的别名，不再读写 XLSX。

这种设计把“什么时候运行哪个阶段”从 Agent prompt 中拿出来，放到可测试、可审计的 Python 编排层。

### 5.2 事实平面：CodeIndex + Backends + KnowledgeDB

`CodeIndex` 是所有 Agent 和 MCP 工具看到的统一代码查询接口。底层后端可替换：

| 后端 | 主要能力 | 适用场景 |
|------|----------|----------|
| `regex` | 轻量函数提取和源码片段读取 | 用户显式选择的无外部依赖模式 |
| `clang` | clangd LSP 批量提取函数、类型、调用、宏、全局变量 | 常规结构化 C 索引路径 |
| `joern` | Java CPG 信号；C/C++ 仅 1.x 弃用兼容 | Java Preview 或旧配置迁移 |
| `unified` | ClangBackend + SVF/Saber，共享 KnowledgeDB | 需要间接调用、指针分析、内存缺陷后端信号的深度模式 |
| `java_source` | Java 源码结构、框架注解与方法索引 | 最小 Java Preview |
| `java_unified` | Java structure + SootUp/WALA/Joern provider evidence | Java Preview 默认深度模式 |

`KnowledgeDB` 当前 schema v14 不只保存传统代码事实，也保存 macro 与 Inspection IR：

- 代码事实：`functions`、`type_definitions`、`type_members`、`call_edges`、`global_variables`、`macro_definitions`、`include_edges`
- SVF/Saber 信号：`indirect_calls`、`taint_signatures`
- 证据 IR：`ir_statements`、`ir_resource_events`、`ir_lock_events`、`ir_shared_accesses`、`ir_path_slices`
- 语义契约：`function_contracts`

架构收益是明显的：LLM 的每次判断都可以回落到文件、行号、函数、路径切片、资源事件和锁事件，避免停留在自然语言印象。

内部源码检索会查找函数声明和实现前的 C/C++ 注释块，并把这些 comment block 连同带绝对行号的实现源码一起返回。LLM 侧统一先通过 `search_code` 取得精确身份，再由 `read_code` 加载定义；函数式和 object-like 宏均进入符号目录，数值/字符串等直接字面量提供保守分类，表达式宏不递归求值。这样头文件中的 API 契约、所有权说明、锁要求、宏别名和参数语义可以按需进入 Agent 上下文，同时仍然保留文件与行号来源。

Clang 后端把增量缓存分成两层：基础 TU 事实只由源码哈希、真实 pending 状态、删除影响和基础 extractor 版本失效，`indexed + hash unchanged` 的 TU 不会因为派生格式变化重新执行 documentSymbol；`function_symbol_context` 与 `function_type_refs` 则用 schema v14 既有 metadata 记录独立的 `dirty/in_progress/current/failed` 生命周期。基础刷新以有界并发执行 clangd/源码收集，再由单个 SQLite writer 用每 TU SAVEPOINT 和每批一次提交原子发布；收集失败时旧事实保持完整。派生重建同样按文件有界并发执行源码与 clangd 查询，worker 只返回行和统计，调用线程作为唯一 SQLite writer 将结果分批写入 TEMP staging；事实替换与 `current` 状态仍在同一事务发布，因此进程中断后可保留旧完整结果并只恢复派生阶段。两类派生索引同时失效时使用每文件一次的 combined semantic pass；解析按 clangd symbol identity 合并重复声明，并以 references 坐标反向映射做常数时间匹配，只有无法消歧的位置才请求 definition。semantic/source/references 缓存均有容量边界和并发 single-flight，避免超大项目常驻全量 token 或对同一声明重复发起 RPC。删除文件仍会清理对应 TU、函数、类型、调用边和 macro，并按 include/callee 影响标记相关文件强制刷新。KnowledgeDB 使用 WAL 与线程本地 SQLite connection，并对直接/间接 callee 查询做版本化缓存，写入调用图或 SVF 数据时会自动失效。

Unified 后端的 SVF 路径支持入口裁剪和入口聚类。public v2 使用 `indexing.svf.scope`、`entry_depth`、`max_selected_tus`、`fallback`、`exclusive_pools` 和 `shared_pools` 表达项目规划。`EntryBitcodeSelector` 会从入口函数沿 KnowledgeDB 调用图选择翻译单元，再通过 `llvm-nm` 的 undefined symbol 闭包补齐依赖；pool 名称必须全局唯一、路径非空且冲突引用有效。每个 SVF 分组会写入裁剪计划、入口聚类布局和 bitcode/link manifest；这些布局及 RuntimeSpec provenance 一同参与缓存身份。

### 5.3 证据平面：CandidatePipeline + Backend Signals

v1.2 继续沿用证据候选层，并把候选收集、合并、统计和 IR 持久化集中到 `zscope/core/candidates/pipeline.py`。候选来源包括：

- `zscope/core/candidates/regex.py`：基于通用 C 模式生成内存、资源、并发、输入和逻辑候选。
- `zscope/core/candidates/clang_ast_cfg.py`：用本地 AST/CFG 视图补足结构化控制流、协议字段和 copy/size 证据。
- `zscope/core/candidates/graph.py`：基于调用图、锁区域、资源协议和生命周期形态生成跨函数候选。
- `zscope/core/candidates/svf_value_flow.py` 与 `backend_signals.py`：把 SVF/Saber、KnowledgeDB、Joern/CPG 等后端信号归一化为 candidate。
- 当前和缓存语义快照的 `suspicious_points` 仅作为已有候选的未验证背景，不独立进入 `CandidateLedger` 或触发验证任务。暂停这一入口不计为 partial；怀疑点不进入 candidate-blind 主动发现投影，也不能由模型直接确认。
- Agent 新发现和 `CandidatePipeline` 产生的 merged candidates 会在 vulnerability mining 后一起进入 `pending_new_issues`，再由 Validator 统一处理。

#### 确定性规则、后端信号与规则目录

`zscope/rules/builtin_catalog.yaml` 只保存规则元数据，不把 AST/CFG、Graph 或其他复杂算法搬进 YAML。每个 `RuleDescriptor` 定义 canonical ID、language、engine、defect class、CWE、Skill、severity、revision、status、title/summary、required capabilities 和 aliases。已有 ID 原样保留；新内置规则使用 `zscope.<language>.<engine>.<slug>`，外部扩展不得占用 `zscope.` 命名空间。

扫描前工厂依次加载目录、qualification registry、`SpecRegistry`、YAML packs 和显式选中的 Python provider descriptor，校验全局 ID/alias、Skill 语言、backend capability 与 `rules.enabled_ids`/`disabled_ids`，然后生成共享的不可变 `EffectiveRuleSet`/`RulePolicy`。Provider 在此阶段只被导入，不执行 `evaluate()`。CLI、config validate、doctor、Web、MCP 与批量扫描复用同一预检/序列化服务；Analyzer 仍保留防御性预检。

候选分为三种身份：

| `candidate_kind` | 来源与契约 | 规则目录约束 |
|------------------|------------|----------------|
| `deterministic_rule` | Regex、Clang CFG/matcher、Graph、Java local、YAML pack、Python provider | 必须有已登记 canonical `rule_id`，descriptor/qualification 决定默认状态，受 `enabled_ids`/`disabled_ids` 控制 |
| `backend_signal` | SVF/Saber、Joern、Java signal provider 等后端原生事实 | 不要求目录 ID，保留 `signal_source` 和 `native_rule_id`，由 `indexing` 控制 |
| `llm_observation` | LLM 主动审计新发现 | 受 active Skill 与 Validator 约束，不伪造确定性规则 ID |

Skill trigger 是主动发现/调查的路由依据，不是漏洞规则；finding suppression 是 ReviewMemory 中的人工决策，也不是规则开关。`disabled_ids` 优先于 `enabled_ids`，只停止指定确定性检测器，其他规则、backend signal 或 LLM 仍可独立发现等价问题。中央候选门禁会在 merge/ledger 前再校验 descriptor 一致性并丢弃已禁用候选，防止实现绕过引擎内部门禁。

目录原始字节与规范化内容、qualification、相关引擎源码、enabled/disabled IDs、pack/provider 内容与版本、当前语言/backend capability 共同形成 effective SHA-256。该哈希进入规则候选、gap plan、Validator environment fingerprint 和报告 provenance，但不参与既有 candidate/finding 稳定身份算法，也不会使独立程序事实或 Security Map 骨架缓存失效。

C/C++ 确定性引擎对外保留 `RegexCandidateGenerator`、`ClangAstCfgCandidateGenerator` 和 `GraphCandidateGenerator` 稳定 facade，内部按资源/生命周期、内存/边界/整数、并发/锁/共享状态、协议/所有权/逻辑四个领域调度 detector。每个 facade 只解析一次源码/图事实，共享只读 `RuleContext` 和 `CandidateEmitter`，并保持原规则顺序、候选身份、dedup key、evidence 与置信度。Graph 查询缓存/错误记录仍归 facade；旧模块路径仅作 re-export 兼容层。Worker 中的 `SKILL_TRIGGERS`/`JAVA_SKILL_TRIGGERS` 只是路由启发式，不参与规则目录。

`CandidatePipeline.collect_signal_candidates()` 输出 `CandidateSignalBatch`，分为 `local_candidates`、`graph_candidates`、`backend_candidates` 和 `merged_candidates`。这使上层只消费 evidence-only candidate，不再直接关心候选来自 regex、Clang、SVF、Graph 还是 Joern。

确定性候选生成器不再只依赖内置 API 名称表。版本化 C/POSIX/Linux catalog 统一生成标准 contract、role bucket、pair 与精确 ABI 期望；`ProjectSemanticsStore` 把人工确认且当前 native 身份仍成立的项目 effect 编译进同一实例级 `ContractRegistry`，并把已复核 `derived_from` 来源保留为实例级 delegate。Regex/Clang/Graph 等规则在 call site 查询 resolved effect、ObjectPath 与该来源边，不维护另一套项目 malloc/free/lock/path-query 名称表。

语义配置的分层如下：

| 层级 | 作用 |
|------|------|
| packaged catalog | 已分类的 C/POSIX/Linux active/neutral/unsupported 接口、selector、condition、effect、pair、来源和 ABI |
| `zscope.semantics.yaml` | 项目 primitive、derived wrapper、macro、dispatcher 与 pointer binding 的唯一人工权威 |
| state DB | finding suppression、baseline、业务前提回答；不能授予项目接口效果 |
| local semantics | 当前 BuildContext 下已授权的 builtin 与 confirmed project contract |
| LLM Wiki | module lifecycle、function intent 等说明性上下文；不作为规则效果依据 |

图候选弥补单函数词法规则的边界，当前覆盖持锁调用会重入加锁的 helper、错误清理类型、线程参数生命周期、全局容器生命周期、对象发布后初始化、容器解链后释放、timer/pipe 等级联等待、锁顺序反转、协议状态机、字节序逻辑、fd 类型契约、shared-memory create-if-absent race、signal handler deadlock、callback self-destroy 以及 stale tree/list 链接等形态。图候选输出仍保持与其他 candidate 相同的数据形状，因此直接进入全局 Ledger 与分层 Validator，不形成旁路报告。

候选会被 `CandidateLedger` 统一去重和合并。验证和报告层还会复用 `zscope/common/issue_identity.py` 中的 `deduplicate_issues()` / `canonical_issue_key()` 对 LLM finding、规则候选、图候选和 Worker 结果做根因级合并，避免跨入口或跨信号源重复报告同一个问题。v1.2 的 `deduplicate_semantic_issues_programmatic()` 与可选 `issue_reconciler_agent` LLM 小簇判重会保留 `duplicate_sources`、`alternate_evidence` 和 `dedup_decisions`，并用类别家族、resource signature、root-cause key、source/sink、call path 和 source-context fingerprint 控制合并边界，避免仅按行号合并或把不同资源误合。每个候选携带：

| 字段 | 作用 |
|------|------|
| `candidate_id` | 稳定候选 ID |
| `dedup_key` | 跨入口、跨 Worker 的去重键 |
| `rule_id` / `rule_engine` / `rule_revision` | 确定性候选的 canonical descriptor 引用 |
| `rule_source` / `rule_catalog_sha256` | 规则来源与目录 provenance |
| `defect_class` | 缺陷类别到 Skill 的映射依据 |
| `source` / `sink` | 可验证的数据源与危险操作 |
| `positive_evidence` | 支持该候选的源码事实 |
| `negative_evidence` | 可能降低可信度的保护条件或未决事实 |
| `evidence_pack` | 结构化证据包，包含路径、对象、规则、证据引用 |
| `evidence_refs` | 指向 `ir_path_slices`、资源/锁/共享状态事件等 IR 表 |
| `validation_required` | 默认要求候选进入 Validator / ValidationPipeline，而不是由规则层直接报告 |

主动发现继续使用档位风险阈值、同 Skill 合并和 generated/vendor/test 排除，但 balanced/deep 不再用 audit unit 数量截断召回。单元函数数和初始上下文仍有界；无法执行的 audit unit 必须作为未覆盖区域留痕，已有候选仍保留在 Ledger。

### 5.4 Scan-wide token 计量

public v2 提供 `fast / balanced / deep`，档位决定启用的分析阶段、规划风险阈值和 V3 调查范围。产品运行时没有 scan-wide token 硬上限，也没有 `scan.max_llm_tokens`；2M/12M/30M 等数值只属于 Range Benchmark policy，在完整扫描结束后评价成本是否符合预期，绝不参与请求准入或提前终止。

`ScanTokenUsageLedger` 在每次真实 HTTP attempt 前登记安全估算，仅用于连接中断且 provider usage 缺失时保守计量。provider 返回后按原始 prompt+completion 结算，cached/reasoning 只作子项统计；重试、repair 和 fallback 分别计量。它不会缩短 completion allowance、拒绝新调用或取消在途请求。

每个 `LLMUsageEvent` 记录 agent、stage、candidate/cluster、model、finish reason、prompt/completion/cached/reasoning、provider/estimated、retry/repair、工具次数与新增事实数，不包含 prompt 或思维正文。报告按 agent/stage 聚合并验证 call 级守恒。Benchmark 再读取这些完成后的事实做成本门禁。

### 5.5 智能体平面：Agent + Skill + Tool

Z-SCOPE 不再默认逐入口复活旧式全量多 Agent fanout；LLM 职责围绕增量接口建模、选择性语义、candidate-blind 发现和分层验证拆分：

| Agent | 职责 | 关键输入 | 关键输出 |
|-------|------|----------|----------|
| Semantic Map enrichment | 仅补全高风险 audit unit 的关键契约 | 零 LLM 骨架、代码/后端事实 | 带可解析 evidence ref 的 semantic delta |
| Active discovery worker | 对 coverage gap 做候选盲审 | audit unit、地图投影、Skill | hypothesis / observation，不能 confirmed |
| `validator_agent` V1/V2 | 单次结构化判定与新增事实复判 | 有界 evidence slice / evidence delta | verified / rejected / uncertain 模型意见 |
| `validator_agent` V3 | balanced/deep 调查全部非 shadow 未闭合义务 | 一次连续会话、只读工具、证据、Skill | 带可解析新增事实的 investigation synthesis |
| `issue_reconciler_agent` | 增量维护中判断历史缺陷仍存在还是已修复 | 历史 issue、新代码 | still_exists / fixed |

Skill 是漏洞领域契约，用于约束分析目标和证据要求，不是检测规则。每个 `SKILL.md` 通过 frontmatter `languages` 声明适用于 `c_cpp`、`java` 或两者。`scan.task` 会被解析为 active skills，例如 `bounds_and_integer`、`resource_lifecycle`、`temporal_memory`、`shared_state_race` 等；空字符串启用当前语言全部适用 Skill，非空文本只表达审计重点。规则 descriptor 必须引用一个存在且支持相同语言的 Skill。

LLMClient 是所有 Agent 的 OpenAI-compatible 调用门面。它支持多 endpoint 容量选择、限流/cooldown、线程本地 session 和共享 scan token 计量。V1/V2 各只发起一次无工具调用：V1/V2 的 truncated 或 malformed 输出直接保持可复核并交给 V3 资格判断，不追加格式修复调用。V3 使用一个最长 50 次模型迭代的连续会话；多轮 reasoning metadata 可在会话内传递，但永不落入普通日志或报告。

ToolsRuntime 原子暴露六个证据导向工具：`search_code`、`read_code`、`get_semantic_context`、`query_code_graph`、`trace_data_flow`、`query_static_findings`。调用从轻量搜索得到 revision-aware `symbol_id`，后续源码、语义、图和流查询都绑定该精确身份；finding 查询只返回紧凑 evidence ref，再由模型按需读取原始证据。这避免名称清洗、重载歧义和一次性高聚合结果污染上下文。

六工具词汇不随后端改变。`Analyzer._get_tools()` 先建立 frozen-aware CandidateLedger 和 snapshot resolver，再由 `AGENT.md` 与 `ToolPolicy` 做角色最小白名单；能力缺口通过统一返回信封的 `coverage/status` 表达。V1/V2 不开放工具；V3 只使用角色白名单，active discovery 仍只接收预先构造的 candidate-blind 投影。MCP 从同一 `ToolContract` 生成原生 namespaced schema，另有六个管理工具，不暴露 raw/alias 重复项。

工具层还做了三类重要防护：

- 递归 schema、跨字段和项目相对路径校验，错误携带可修复的精确字段路径。
- `symbol_id` 精确解析和绝对源码行号，避免同名/重载串线与相对偏移幻觉。
- coverage、分页、截断和 evidence provenance 显式进入统一信封；空数组不再同时表示“不存在”和“不支持”。
- `ToolPolicy` 约束工具、资源、文件读取、知识库查询和 subagent spawn allowlist，并通过敏感路径 hook 降低远程或自动化场景中的越界访问风险。

### 5.6 验证平面：ValidationRunner + ValidationPipeline

自 v1.0 起，验证逻辑已经从 `Analyzer` 主流程中拆出：

| 模块 | 职责 |
|------|------|
| `zscope/core/validation/evidence.py` | 构造 Validator input、evidence pack、漏洞类别特定验证要求和 retry/修正规则所需证据 |
| `zscope/core/validation/runner.py` | 运行 Validator，处理 entry-root dead-code retry、contract-scope rejection 修正和 ReviewMemory 写入 |
| `zscope/core/validation/pipeline.py` | 应用 suppression、baseline、history feedback、score、`validated`/`needs_review`/`uncertain`/`rejected` 分流 |

这层的设计目标是让所有候选都先保持“待验证证据”的形态，再由统一的验证门禁决定是否进入 `issues[]`、`metadata.audit_observations[]` 或被 suppression/baseline 拦截。高置信规则也不再绕过验证流水线；它们只能在证据完整、无反证且满足评分门槛时被自动接受。

验证阶段使用 bounded `ValidatorEvidenceSlice v3`：每个 cluster 只传 canonical occurrence、可读事实 payload、proof、必要路径/claim 与代码窗口，输入上限 12K tokens。状态机固定为：V0 完整正/反 proof；V1 单次无工具结构化判定；从 security obligation 派生全部必需 fact kind 并只调用对应本地 provider；有 delta hash 变化才执行一次无历史 V2。未闭合的 uncertain、无 proof rejected、证据不足 verified 和可恢复格式失败可进入 V3。balanced/deep 调查全部非 shadow 未闭合义务；风险只用于排序，不再限定调查资格。V3 单会话最多 50 次模型迭代，无独立工具次数上限，但仅能使用只读白名单；重复查询立即拒绝，连续两个模型轮次没有新增事实即提前结束。`model_verdict` 与最终 `policy_disposition` 分离；无证据闭合的模型 rejected 进入 needs-review；满足有证据语义反驳约束时可记录 rejected_with_evidence，V3 verified 也必须具有可解析引用、已闭合阻断事实、无冲突且通过现有 promotion policy 才能进入默认视图。

### 5.7 持久化与反馈平面

Z-SCOPE 使用五类主要持久化区域：

| 存储 | 内容 | 作用 |
|------|------|------|
| `.zscope_knowledge/code_knowledge.db` | 代码事实、SVF 信号、Inspection IR | 全局代码知识图谱和候选证据审计 |
| `.zscope_snapshots/snapshots.db` | 语义快照索引、final report 索引 | `--resume`、`--maintain` 和函数级缓存 |
| `.zscope_snapshots/security_map.db` | 程序安全事实、semantic claim、unknown/conflict、audit unit | balanced/deep 的只读 Security Semantic Map sidecar |
| `zscope.semantics.yaml` | 精确 selector、条件、effect、pair、构建变体和人工状态 | C/C++ 项目语义的唯一人工权威 |
| `.zscope_snapshots/semantics/` | native/CFG/LLM 原始发现证据与 receipt | 机器审计材料，不是第二份配置 |
| `.zscope_snapshots/user_config.state.db` 或 `user_config.db` | 抑制、baseline、业务前提回答和历史兼容数据 | 误报反馈；与语义授权分离 |
| `.zscope_bc/bitcode_scope_<group>.json` | SVF 入口裁剪计划 | 审计本次 SVF 分析实际纳入了哪些翻译单元；WSL `/mnt/...` 场景可能写入 Linux 原生临时 bitcode 目录 |

`zscope.semantics.yaml` 顶层固定为 `interfaces`、`dispatchers`、`function_pointer_bindings` 与 `discovery_receipt`。接口同时保存 primitive 标志、精确 selector、basis、人工 status、条件分支、类型化 effect、`otherwise: unknown`、pair、证据引用与逐 BuildContext variant。`discovery_receipt` 只保存有界的人读摘要、总数、摘要和少量 coverage gap 样本；逐函数 manifest、完整 gap 集合和模型原始响应只写入其 `evidence_ref` 指向的机器快照，避免把人工配置膨胀成第二份事实数据库。XLSX 只保留一次性迁移入口，运行时不再读取其语义；module lifecycle 与 function intent 在迁移报告中删除并转由 Wiki 表达。

快照策略不再只区分“完整 LLM 语义”和“跳过”。`zscope/snapshots/policy.py` 会为短函数构造 syntactic snapshot，并把协议版本过滤、fd 编码/类型契约、协议长度、状态恢复、error status 和 facade forwarding 等短函数风险放入 `suspicious_points`。可证明的字面量语法，以及有可靠底层契约且可完整组合的透明封装，可以绕过 LLM；未知协议仍由入口前置的增量建模阶段发现，分配/释放/锁 wrapper 不按名称生成语义。

人工反馈不会只是前端状态。Web 保存验证结果时会持久化 baseline 和 suppression，下一次扫描会在验证前参与过滤和评分。`ReviewMemory` 封装 false-positive suppression、finding baseline 查询与 Validator 记忆写入；`UserConfigStore.get_finding_baseline_for_issue()` 先按 `dedup_key` 精确命中，再按 `stable_fingerprint` 或回填后的稳定指纹命中，并把 `match_strategy` 写回结果，避免行号漂移后人工 rejected 失效。

Issue identity 由 `zscope/common/issue_identity.py` 统一提供。`canonical_issue_key` 适合单次报告内根因合并，`stable_issue_fingerprint` 用于长期 baseline、SARIF partial fingerprints 和 benchmark 匹配；可选的 `source_context_fingerprint` 从源码片段或 evidence snippet 生成第三层校验，双方都有上下文且冲突时会阻止过宽的 stable baseline 命中。

Project contract 以当前调用点的 native callee identity、BuildContext 与证据摘要选择；unknown build 不是通配符。名称、描述和 LLM 建议只能进入 advisory 审计，不能补充执行角色。

报告层默认生成两类视图：`report_views.default` 只包含可报告的确认问题；`report_views.with_needs_review` 会把 `needs_review` 审计观察项也并入列表，供人工复核或 WebUI 切换查看。在视图构建前，`zscope/reporting/issue_aggregation.py` 会把同缺陷家族、同函数、同结构化 sink 锚点（行距链式聚类）的 confirmed/needs_review 结果折叠为一个 primary，CWE 与类别标签取成员并集（issue 级 `cwes`/`categories`，可归属多个 CWE），成员转 `deduplicated_alias` 终态保留审计；报告侧的 `zscope/common/defect_cwe_map.py` 集中维护类别→CWE 集合的兜底映射，保证可分类 finding 的 `cwes` 非空。`ReportAssembler` 负责最终 report、views、metadata、JSON/Markdown 和 snapshot 持久化，并支持 `deduplicate_report_issues` 钩子，让最终报告在构建视图前应用语义去重。`semantic_dedup_summary` 会记录程序化合并、LLM 小簇判重、cache hit、合并数和拒绝合并数；issue 本身保留 `duplicate_sources`、`alternate_evidence`、`dedup_decisions`、`category_family` 与 `resource_signature`。报告 metadata 另外记录规则目录 schema/hash、enabled/disabled/unavailable IDs、扩展来源和按 engine/rule 聚合的已产生候选数。CLI 的 `--export-sarif` 输出 SARIF v2.1.0：`ruleId` 直接使用 canonical `rule_id`，CWE 进入 tags/properties，历史 `CWE:rule` 写入 `properties.legacyRuleId`，engine/revision/Skill/catalog hash 进入 rule descriptor；`partialFingerprints.zscopeStableIssueFingerprint` 与 finding 身份算法保持不变。读取旧报告时仍会回退到历史 `rule` 字段，不就地改写归档。

## 6. 架构优势

### 6.1 同类工具的架构参照系

Z-SCOPE 的优势更适合放在同类工具架构取向中理解。开源工具通常强调可验证的规则、查询语言或编译器级程序事实；商用工具通常强调平台化治理、规则库覆盖、企业流程集成和集中化误报管理。Z-SCOPE 的架构重点是把这些能力中最有价值的信号转化为统一候选，再通过多智能体和反馈闭环完成二次验证。

| 类型 | 代表工具 | 架构重心 | 常见优势 | Z-SCOPE 的补强方向 |
|------|----------|----------|----------|--------------------|
| 编译器/路径分析型开源工具 | Clang Static Analyzer、Cppcheck | AST、CFG、路径约束、规则检查 | 本地运行、结果可复核、工程依赖少 | 引入跨入口语义快照、用户领域知识和 LLM 可利用性验证 |
| CPG/查询型开源工具 | CodeQL、Joern | 代码数据库、查询语言、数据流/控制流建模 | 适合沉淀漏洞模式和变体查询 | 将查询结果进入候选、去重、评分、验证和报告同一链路 |
| 规则/策略型工具 | Semgrep、各类自定义规则引擎 | 模式匹配、污点规则、策略分发 | 编写规则快，适合 CI 和团队规范 | 用 KnowledgeDB IR 与 Agent 验证补足 C 指针、资源和并发语义 |
| 商用 SAST 平台 | SonarQube、Checkmarx、Coverity、Fortify、Snyk Code | 规则库、数据流引擎、集中治理、告警流转 | 语言覆盖广，治理能力成熟，集成生态完善 | 本地可审计证据库、MCP 开放接口、SARIF 二次验证和可解释反馈闭环 |
| AI 代码审查工具 | 通用 LLM 审查、AI SAST | 自然语言语义理解、修复建议、交互式解释 | 对业务语义和修复建议友好 | 由静态证据约束模型输入，降低凭语感判断的风险 |

### 6.2 静态证据驱动的智能体分析

Z-SCOPE 将 LLM 放在“选择性语义补全、候选盲主动发现、证据闭合”三个受控位置，而非事实抽取的起点。Clang、Joern、SVF/Saber、确定性规则和 KnowledgeDB 先提供可定位、可复核的程序事实；LLM 在规则前对入口可达函数进行可缓存的接口建模，再为带风险和 coverage gap 的审计单元补语义或提出 hypothesis，再由统一 Ledger 与 Validator 收敛。这样既不把召回上限锁死在既有规则，也不恢复逐入口全量多 Agent 的重复上下文成本。

### 6.3 多源候选提高召回上限

单一引擎通常受限于自身抽象：规则型工具依赖规则表达力，CPG/查询型工具依赖查询和库模型，商用工具依赖内置规则和配置，AI 审查工具依赖上下文质量。Z-SCOPE 同时接收：

- clangd/Clang 提供的函数、类型、宏、全局变量和直接调用事实。
- SVF/Saber 提供的间接调用和内存缺陷信号。
- Joern/CPG 和 SARIF 外部告警提供的规则或第三方工具信号。
- 通用 C 确定性规则提供的本地高信号候选。
- 图候选提供跨函数协议、锁顺序、生命周期和 liveness 信号。
- 语义模型快照提供的函数职责、状态变化和跨调用摘要。
- LLM Agent 提供的项目语义、跨 handler 生命周期和业务约束理解。

多源候选统一进入 `CandidateLedger` 后再做去重、合并、验证和评分，使召回能力不绑定到单个后端或单个提示词。

### 6.4 分层验证降低误报

Z-SCOPE 将“hypothesis/候选”“模型 verdict”“policy disposition”“确认漏洞”分为不同层级。候选先由 `CandidateLedger` 根因合并，再经过 V0–V3 分层验证、`issues`/`audit_observations` 分层输出，以及用户 baseline/suppression 历史反馈。确定性 proof、模型判定和人工决策具有独立 attribution；这种设计既把降噪前移到证据闭合阶段，也保留模型拒绝但无反证的可复查线索。

### 6.5 工程化运行与开放集成

每个函数的语义快照、最终报告、批量汇总、候选 IR 和用户反馈都有落地点。大规模扫描中断后可以 `--resume`，代码小改后可以 `--maintain`，旧报告覆盖前有自动备份。MCP Server 还暴露 `zscope://config`、`zscope://knowledge/stats`、`zscope://knowledge/functions`、`zscope://snapshots/list` 等资源，并在 `ToolPolicy` 过滤后提供六个 namespaced 证据工具及六个管理工具，使 Z-SCOPE 可以作为本地代码知识底座接入外部 AI IDE。

## 7. 业界领先或差异化特性

Z-SCOPE 的差异化不在单个算法，而在“程序事实、候选证据、智能体验证、人工反馈”闭环的组合能力。

| 能力维度 | 同类工具常见方式 | Z-SCOPE 的差异化实现 | 读者直观印象 |
|----------|------------------|----------------------|--------------|
| AI 与静态分析结合 | AI 工具偏语义解释；传统 SAST 偏规则和数据流 | `evidence_pack`、`evidence_refs`、IR path/resource/lock/shared-access 证据共同约束 LLM | 模型判断具有证据锚点，可降低开放式代码点评风险 |
| C/C++ 深度语义 | 开源工具各有优势但信号分散；商用工具多为封闭引擎 | Clang、Joern、SVF/Saber、确定性规则信号统一进入候选层 | 多个后端的强项可以在同一报告里汇合 |
| 告警复核 | 商用平台依赖人工 triage；开源工具通常输出原始告警 | SARIF `alert-verify` 将外部告警转成 `ExternalAlert` 并复用 Validator | 可作为其他 SAST 的二次确认器 |
| 不确定性处理 | 一些工具以热点、严重级别或人工状态区分风险 | `verified` / `rejected` / `uncertain` 三态，加 `needs_review` 审计观察项 | 低证据问题不阻断 CI，但也不丢失 |
| 大规模扫描 | 商用平台治理强；开源工具常需自行拼接缓存和恢复 | `snapshots.db`、`--resume`、`--maintain`、批量报告备份内建 | 大型项目能长期维护扫描状态 |
| 可解释反馈 | 商用平台支持误报状态；AI 工具常依赖对话记忆 | `finding_suppressions` 与 `finding_baselines` 落在 SQLite，可查、可删、可过期 | 审计经验成为可治理数据 |
| AI IDE 集成 | 多数 SAST 以报告或平台页面为主 | MCP 暴露配置、知识库、快照和代码查询工具 | 扫描器同时也是本地代码知识服务 |
| 回归纪律 | 工具通常发布规则集，项目侧难以度量本地变化 | benchmark v4 + formal v3 跟踪双视图、归因、成本、隔离 evidence 和五轮稳定性，qualification 绑定规则 revision | 新规则需通过跨项目与变形门禁，Range 仅作开发回归 |

## 8. 高检出如何实现

高检出来自“入口覆盖、事实覆盖、候选覆盖、分析覆盖”四层叠加。与只运行规则集或只分析外部告警相比，Z-SCOPE 会主动扩大入口、事实和候选来源，再通过 Agent 和 Validator 收敛结果。

### 8.1 检出链路对比

| 环节 | 开源工具常见能力 | 商用工具常见能力 | Z-SCOPE 实现 |
|------|------------------|------------------|--------------|
| 入口发现 | 通常依赖配置、构建数据库或查询入口 | 依赖扫描配置、仓库集成和语言前端 | `entry_functions_list` + `--discover-entries` / `project.entry_discovery.enabled` 落盘 + `entry_discovery.search_root` |
| 代码事实 | AST/CFG/CPG/规则匹配，各工具侧重点不同 | 专有前端和数据流引擎 | `CodeIndex` 统一 Clang、Joern、Regex、Unified 后端 |
| 跨函数关系 | 依赖数据流查询、库模型或指针分析能力 | 专有模型和框架配置 | SVF Andersen、Saber、调用图、语义快照共同补强 |
| 候选生成 | 查询或规则命中即输出告警 | 内置规则和数据流引擎输出告警 | 确定性规则、后端信号、candidate-blind hypothesis、外部 SARIF 统一入 ledger |
| 深度验证 | 主要依赖规则精度和人工复核 | 平台化 triage 与审计流转 | V0 proof + V1/V2 结构化复判 + 高风险 V3 短调查 |

### 8.2 入口覆盖

- 显式支持批量入口 `entry_functions_list`。
- `--discover-entries` 或 `project.entry_discovery.enabled` 能扫描头文件公共 API、网络/IPC、线程创建、文件/环境/标准输入等入口。
- 自动发现结果会写入 `entry_functions_list.json`，包含 exposure、reasons、confidence 和入口级审计提示，可由人工继续编辑后复用。
- `entry_discovery.search_root` 可把入口发现限制到指定目录（支持相对路径，固定基于 YAML 所在工程目录解析），适合只审计大型仓库中的某个模块。
- handler、allocator、release、dispatch 等项目语义由 `zscope.semantics.yaml` 与独立 `--discover-primitives` 承担；正常扫描只读 confirmed contract，不通过 prompt 或名称推断注入。

### 8.3 事实覆盖

- Clang 后端提供稳定的函数、类型、调用、宏和全局变量事实。
- Unified 后端叠加 SVF Andersen 间接调用和 Saber 内存缺陷信号。
- Joern 后端可用于规则驱动模式和 CPG 查询。
- Regex 后端保证最小依赖下仍可检索源码。
- KnowledgeDB schema v7 将函数事实、调用边、污点签名、IR statement、资源事件、锁事件、共享访问和路径切片沉淀到统一数据层。

### 8.4 候选覆盖

`RegexCandidateGenerator` 和 `ClangAstCfgCandidateGenerator` 覆盖一批 C 项目高频高价值模式，包括 size arithmetic before allocation/copy、same-function resource leak、direct `realloc` assignment、double free / invalid free、stack address escape、missing unlock、callback under lock、recursive lock risk、`pthread_cond_wait` with `if`、signed-to-unsigned length conversion、off-by-one、uninitialized read、alignment cast、null dereference after unchecked result、shared global race、refcount race、object publication、non-literal format string、system command、path TOCTOU、fd close without invalidation、mmap stale pointer、ignored protocol version、state not restored、raw/encoded fd mismatch、reliable fd/raw fd contract mismatch、recv retry without budget、protocol unit/byte limit mismatch、macro-guarded lock no-op、file type validation、byte-order logic、state machine mismatch 等。规则保持通用 C 语义，不依赖 benchmark 专有函数名。

`GraphCandidateGenerator` 负责跨函数和协议形态，包括 cross-function recursive lock、lock order inversion、wrong cleanup contract、thread argument lifetime、global container lifecycle、object publication ordering、runtime/protocol state contract、fd type contract、lost wakeup、shared-memory race、signal deadlock、callback self-destroy、timer cascade wait 和 stale tree/list liveness。它与确定性规则共享候选形状和去重链路，因此不会形成一套旁路报告体系。

### 8.5 分析覆盖

生产默认的覆盖链路是共同静态发现 → balanced 自主 Validator → deep 分层契约发现。deep 的函数 inventory、调用边、功能/模块组合及未知项输出到 `hierarchical_contracts.json`；叶摘要按精确实例增量复用，父摘要绑定成员和子摘要，验证沿用同一候选 Ledger。规则提案记录待评审分类、正反例、适用/排除条件、对象身份与需要的事实；旧输入的提案保留为 stale，不自动安装。以下 Security Semantic Map / coverage-gap planner 描述的是保留的离线旧方案对照，不再默认参与 balanced/deep。

- Security Semantic Map 先以零 LLM 骨架覆盖入口、调用边、危险事件、globals/types 与 backend coverage，只在高风险 audit unit 补语义。
- Coverage-gap planner 按 known variant、diff、外部可达敏感路径、candidate desert、动态边/alias 缺口、backend 降级、跨模块协议和 semantic unknown/conflict 打分。其中 candidate desert 只消费事件家族级的覆盖 presence/count，不读取候选 ID、source/sink、位置、规则名或结论；这些候选内容也不会进入主动发现 Prompt。
- Balanced/deep 不再按 audit unit 数量截断；风险阈值继续分别过滤规划结果。每单元最多 16 个函数、24K 初始上下文，重合至少 60% 且同 Skill 的单元合并。
- Active worker 看不到 candidate/rule/truth/verdict，只能提出有位置、路径、正反证据和缺失事实的 hypothesis；缺证据内容保留为 observation。
- SARIF 和 ruledriven 模式复用统一 Ledger、归因、token 账本和分层 Validator。

## 9. 低误报如何实现

低误报依赖可解释的证据门禁、分层输出和可治理反馈。与传统规则工具“调规则”、商用平台“人工 triage”、AI 工具“让模型解释”相比，Z-SCOPE 将降噪机制内置到候选生命周期中。

### 9.1 误报控制对比

| 机制 | 同类工具常见做法 | Z-SCOPE 做法 |
|------|------------------|--------------|
| 告警前置条件 | 规则命中、查询命中或数据流路径命中 | 候选必须尽量具备 source、sink、路径、对象/锁身份、正反证据和稳定去重键 |
| 不确定结果 | 作为告警、热点、低严重级别或人工待审 | `uncertain` 与 `needs_review` 默认进入 `metadata.audit_observations` |
| 误报过滤 | 规则关闭、注释、平台状态或 suppression | `finding_suppressions` 在验证前过滤，并可按 scope、rule、过期时间治理 |
| 历史经验 | 平台状态或外部审计记录 | `finding_baselines` 参与 `history_feedback` 评分分量 |
| 重复报告 | 按规则 ID、文件行或平台实例 ID 合并 | issue identity / `deduplicate_issues()` 按类别、scope、root cause、source/sink 和文本证据合并 |
| 可解释性 | 报告引用代码位置或数据流路径 | 报告引用 `evidence_pack`、IR path/resource/lock/shared-access 证据和 Validator 理由 |

### 9.2 候选证据结构化

候选需要尽量提供 source、sink、路径完整性、对象/锁身份、正向证据和反向证据。证据会被写入 `evidence_pack` 和 KnowledgeDB IR，供 Security Map、Validator、报告和人工复查复用。结构化证据使误报控制可以基于事实判断，减少对告警文本或模型解释的单点依赖。

### 9.3 三态 Validator

Validator 可以返回：

| verdict | 含义 | 默认处理 |
|---------|------|----------|
| `verified` | source-to-sink 路径、可控性、保护缺失可以闭合 | 根据 `final_score` 进入 `issues` 或 `needs_review` |
| `rejected` | 源码保护、所有权转移、不可达路径等证据否决候选 | 丢弃或记录为抑制反馈 |
| `uncertain` | 候选有价值但缺少决定性证据 | 进入 `metadata.audit_observations` |

### 9.4 综合评分

`ValidationPipeline` 当前使用五个分量计算 `final_score`：

| 分量 | 权重 | 作用 |
|------|------|------|
| `rule_confidence` | 0.25 | 规则或后端信号本身可信度 |
| `path_completeness` | 0.25 | source/sink/path 是否闭合 |
| `contract_consistency` | 0.20 | 是否被用户配置、保护条件或反证削弱 |
| `validation_confidence` | 0.20 | Validator 的置信度 |
| `history_feedback` | 0.10 | baseline 中的历史反馈 |

Validator 启用时，`verified` 且满足 policy 才默认进入 `issues`；未决项进入审计观察。确定性反证明与自主调查的有证据语义拒绝分开记录；只有模型标签、分数或未闭合证据的 `rejected` 必须保留为 `needs_review`。V4 `DynamicReproductionRequest/Result` 和 `decision_level=V4` 只定义数据接口，本里程碑不调度 PoC、ASan 或沙箱执行。

### 9.5 人工反馈与报告分层

WebUI 保存验证状态时，`rejected` 会写入 `finding_suppressions`，后续扫描在验证前过滤；`validated`、`needs_review`、`uncertain` 会写入 `finding_baselines`，后续参与评分。最终报告区分 `issues[]`、`metadata.audit_observations[]`、`report_views.default`、`report_views.with_needs_review`、`metadata.candidate_signal_summary` 和 `metadata.candidate_ledger_summary`，既保留审计覆盖，又避免不确定候选阻断流水线。

### 9.6 同类工具公开资料参照

本章对比基于同类工具的公开官方资料，仅用于说明架构取向。

| 工具 | 参照资料 |
|------|----------|
| CodeQL | [代码数据库和查询机制](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/about-code-scanning-with-codeql) |
| Joern | [Code Property Graph](https://docs.joern.io/code-property-graph/) |
| Clang Static Analyzer | [C/C++ 静态分析](https://clang.llvm.org/docs/ClangStaticAnalyzer.html) |
| Semgrep | [SAST/taint 规则](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview) |
| SonarQube | [规则体系](https://docs.sonarsource.com/sonarqube-server/user-guide/rules/overview)、[security hotspot/taint 模型](https://docs.sonarsource.com/sonarqube-server/user-guide/rules/security-related-rules) |
| Snyk Code | [语义 AI SAST](https://docs.snyk.io/scan-using-snyk/snyk-code) |
| Checkmarx SAST | [内部代码图和数据流分析](https://docs.checkmarx.com/en/34965-324470-sast-scanner.html) |
| Coverity Scan | [路径缺陷发现能力](https://scan.coverity.com/) |

## 10. 运维与伸缩性

| 能力 | 架构机制 |
|------|----------|
| 大批量入口 | `ParallelAnalyzer` 线程池并发执行入口分析 |
| 变更审计 | `DiffImpactPlanner` 从 git diff 映射变更函数、语义义务、路径过滤和覆盖计划，报告保留 diff relevance 与 coverage |
| 中断恢复 | `--resume` 基于 final report 和 pending 状态跳过已完成项 |
| 增量维护 | `--maintain` 比较 code/semantic hash，未变更函数零 Token 复用 |
| Token 控制 | call-level usage 计量、稳定 system/schema 前缀、选择性 semantic delta、candidate-blind audit unit、V1 单次、V2 delta-only、V3 证据缺口驱动的最长 50 轮会话；成本阈值由 Benchmark 后置评价 |
| SVF 伸缩 | 入口裁剪 bitcode、入口聚类、符号闭包补齐、互斥/共享 pool、分组 link variant、manifest 缓存和 full/skip 回退 |
| 报告安全 | 覆盖批量 JSON 前自动备份，标准 SARIF 导出不改写主报告 |
| Benchmark v4 / formal v3 | 记录双视图、候选漏斗、发现×决策归因、raw/effective FP、usage 守恒、隔离 evidence、成本和五轮稳定性；policy v1 是唯一门禁源 |
| 多模型策略 | `llms` 多 profile + Agent 级 `llm_ref` + 模型列表回退 + profile 内多 `base_urls` 容量控制 |
| 代理模型兼容 | 流式调用、JSON 修复、XML tool-call fallback、自动续写 |

## 11. 对外接口

### 11.1 CLI

| 命令 | 用途 |
|------|------|
| `zscope -c zscope.yaml` | 默认扫描或批量扫描 |
| `zscope -c zscope.yaml --scan-depth balanced` | 覆盖本轮扫描档位；不设置 scan-wide token 上限 |
| `zscope -c zscope.yaml --resume` | 断点续扫 |
| `zscope -c zscope.yaml --maintain` | 增量维护 |
| `zscope -c zscope.yaml --discover-entries` | 自动入口发现 |
| `zscope -c zscope.yaml --plan-entries` | 构建索引并预览/写出入口计划，不调用 LLM |
| `zscope -c zscope.yaml --diff-base origin/main --diff-head HEAD` | 差异影响扫描，生成 `entry_functions_diff.json` 并标注 diff relevance |
| `zscope -c zscope.yaml --diff-base origin/main --diff-head HEAD --diff-repo-root /repo --diff-path src/net` | 指定 git worktree 并只纳入特定路径下的变更函数；必要扫描 root 可位于路径外 |
| `zscope -c zscope.yaml --discover-primitives` | 项目级发现 wrapper/macro/pointer/dispatcher，合并待复核 YAML 后退出 |
| `zscope-config migrate-semantics --config zscope.yaml --from-xlsx old.xlsx --output zscope.semantics.yaml` | 一次性迁移旧工作簿并生成删除/重绑定报告 |
| `zscope -c zscope.yaml --build-index` | 仅构建索引（`--build-cpg` 为弃用别名） |
| `zscope -c zscope.yaml --dashboard` | 启动 Web 仪表盘 |
| `zscope -c zscope.yaml --mcp-stdio` | 启动 MCP stdio server |
| `zscope -c zscope.yaml --mcp-http --mcp-host 127.0.0.1 --mcp-port 8765` | 启动实验性 Streamable HTTP MCP server |
| `zscope -c zscope.yaml --export-sarif zscope-results.sarif` | 扫描完成后导出 SARIF v2.1.0 |
| `zscope-rules list --config zscope.yaml [--language/--engine/--status] [--json]` | 查看规则 descriptor、来源与 effective status |
| `zscope-rules show RULE_ID --config zscope.yaml [--json]` | 查看单条规则、启停原因与 capability |
| `zscope-rules validate|test PACK...` | 验证 YAML pack 或执行其正反例 |
| `zscope --mode ruledriven -c zscope.yaml` | Joern 规则驱动模式 |
| `zscope --mode alert-verify --sarif alerts.sarif -c zscope.yaml` | SARIF 告警验证 |

### 11.2 WebUI

当前 Web 后端由 `zscope/web/server.py` 负责路由，业务逻辑委托给项目、语义、作业及报告服务。`zscope --web` 可无配置进入工程选择；业务请求以 `X-ZScope-Project` 绑定所选 YAML，不依赖全局可切换的当前工程。

| Service | 职责 |
|---------|------|
| `ConfigService` | `zscope.yaml` 文本与结构化配置读写 |
| `ProjectLibrary`（`web/projects.py`） | 最近工程、执行机目录浏览、创建与打开 YAML、按工程隔离服务 |
| `SemanticsService`（`web/semantics_service.py`） | 项目语义 YAML、独立发现任务、人工审阅、当前性与扫描就绪 |
| `ScanJobsHttpService`（`web/scan_jobs_service.py`） | 持久作业、结果快照及时间计划；执行复用 `ScanJobService` 与 owner |
| `WorkbookService` / `UserConfigService` | 历史工作簿及配置接口；C/C++ 已迁移语义接口返回 `410 semantics_moved`，warnings 保留 |
| `CpgService` | CPG/索引状态查询和异步构建触发 |
| `SourceSnippetService` | 报告位置到源码片段的安全读取 |
| `ReportFeedbackService` | `/api/save_findings` 的验证状态更新、snapshot 更新、feedback 持久化和报告保存 |
| `RuleService` | 复用扫描预检/序列化服务，提供与 CLI `--json` 相同 schema 的只读规则目录与筛选 |

主要 HTTP API：

| API | 用途 |
|-----|------|
| `GET /api/projects`、`GET /api/projects/browse` | 最近工程与执行机目录浏览 |
| `POST /api/projects/open`、`POST /api/projects/create` | 打开已有 YAML 或在已有工程目录创建配置 |
| `GET /api/semantics`、`GET /api/semantics/entries` | 当前工程原语就绪状态与语义条目 |
| `POST /api/semantics/tasks`、`POST /api/semantics/review`、`POST /api/semantics/complete` | 独立发现、审阅与完成确认 |
| `GET/POST /api/jobs`、`GET /api/jobs/<id>/result` | 持久扫描作业及绑定本轮的结果 |
| `GET/POST /api/schedules`、`POST /api/schedules/cancel` | 单次或每日运行窗口，按 YAML 作用域持久保存 |
| `GET /api/findings` | 读取当前报告中的 findings |
| `GET /api/version` | 返回当前 Z-SCOPE 版本和展示字符串 |
| `POST /api/save_findings` | 保存验证状态并持久化 feedback |
| `GET /api/issue_report?issue_id=...` | 从完整 finding 生成 Markdown 详情与复核基线 |
| `GET /api/offline_report` | 导出 HTML 阅读器与逐 issue Markdown 的 ZIP |
| `POST /api/import_reviews` | 跳过空说明、检查基线并增量回写人工复核 |
| `POST /api/import_reviews/resolve` | 冲突人工确认后再次比较当前版本再回写 |
| `GET/POST /api/config` | 读取和保存 `zscope.yaml` |
| `GET/POST /api/config/structured` | 读取和保存结构化配置 |
| `GET /api/rules?language=&engine=&skill=&status=&q=` | 查询规则目录、汇总与 effective status（只读） |
| `GET /api/cpg_status` | 查询索引构建状态 |
| `POST /api/build_cpg` | 触发索引构建 |
| `GET /api/source_snippet` | 读取报告位置附近源码片段 |
| `GET /api/user_config/warnings` | 读取配置告警 |
| `POST /api/clear_warnings` | 清理配置告警 |
| `GET/POST /api/user_config/workbook` | 读取或保存用户配置工作簿 |
| `POST /api/user_config/workbook/import` | 导入用户配置工作簿 |
| `GET /api/user_config/workbook/download` | 下载当前用户配置工作簿 |
| `GET/POST/DELETE /api/user_config/<resource>` | 用户配置 CRUD |

表中旧工作簿与用户配置 CRUD 仅为历史接口清单，不是 C/C++ 当前语义入口；迁移须通过项目原语页或 `zscope-config migrate-semantics` 显式执行。时间计划与作业恢复只复用经核对的输入和可恢复状态；关闭网页不停止后台，主机或 WSL 关闭时不能执行。详细行为见[接口与报告](modules/interfaces-reporting.md)。

### 11.3 MCP

MCP 暴露三类能力，并统一经过 `ToolPolicy` 过滤：

- Resources：`zscope://config`、`zscope://knowledge/stats`、`zscope://knowledge/functions`、`zscope://snapshots/list`
- Prompts：`zscope.entry_discovery`、`zscope.resource_lifecycle_audit`、`zscope.concurrency_audit`
- Tools：六个证据工具 `zscope.code.search`、`zscope.code.read`、`zscope.semantic.context`、`zscope.graph.query`、`zscope.flow.trace`、`zscope.findings.query`，以及 `zscope.knowledge.query`、`zscope.entries.discover`、`zscope.scan.run`、`zscope.scan.status`、`zscope.wiki.status`、`zscope.wiki.query` 和五个持久作业工具 `zscope.jobs.list/events/result/cancel/resume`；作业工具在 Linux/default profile 复用保存配置对应的 ScanJobService，read_only/candidate_blind 不创建作业服务，不暴露 raw 名称或重复 alias

stdio MCP 适合作为本地 IDE/Agent 接入。协议优先协商 `2025-06-18`，此时 tool list 携带原生 `inputSchema/outputSchema`，调用结果同时返回 text 和 `structuredContent`；兼容 `2024-11-05` 时省略后两项新能力但仍使用 namespaced 名称。HTTP MCP 是显式开启的远程实验入口：默认绑定 loopback；当绑定非 loopback 地址时，CLI 会强制要求 `--mcp-auth-token-env` 和至少一个 `--mcp-client-allowlist`，HTTP 层再做 Bearer token 与客户端 IP allowlist 校验。

## 12. 扩展点

| 扩展目标 | 推荐入口 |
|----------|----------|
| 新增代码分析后端 | 实现 `CodeBackend` ABC，并在 `CodeIndex` 工厂中注册 |
| 新增漏洞类型 | 新建或扩展 `zscope/skills/<skill>/SKILL.md`，并补充 task-to-skill 映射 |
| 新增本地候选规则 | 扩展对应 Regex/Clang/Java detector，同步 `builtin_catalog.yaml` descriptor/revision、正反例和目录校验 |
| 新增跨函数图规则 | 扩展 `GraphCandidateGenerator`，经公共 emitter 输出 canonical ID 和完整 evidence，同步目录/测试 |
| 新增外部确定性规则 | 简单正则使用 YAML pack；复杂算法使用严格 Provider V2，见 `docs/rule-development.md` |
| 新增用户配置推断 | 扩展 `infer_user_config_rows()` 或 `UserConfigWorkbook` sheet 映射，保持人工行不被覆盖 |
| 新增后端信号归一化 | 扩展 `zscope/core/candidates/backend_signals.py` 或 `adapters.py`，由 `CandidatePipeline` 汇总 |
| 新增预算信号 | 扩展 `RiskBudgetPlanner` 的打分维度，继续保留硬上限与 metadata 可解释性 |
| 新增工作流 | 添加 `zscope/workflows/*.yaml`，并实现对应 handler |
| 新增报告导出 | 在 `zscope/reporting/` 下新增 exporter，复用 `report_views`、稳定 issue identity 与去重后的 issue shape |
| 新增 MCP 能力 | 扩展 `ZScopeMcpProvider.list_tools/read_resource/get_prompt` |
| 新增领域知识源 | 引入手册、接口规范、设计文档、受限使用说明等非代码知识，并映射为可检索领域契约 |
| 新增回归场景 | 在外部 benchmark fixture、`tests/` 或独立 harness 中增加源码、ground truth 和评测脚本；新单轮输出 `zscope.benchmark.v4`，五轮正式输出 formal v3 |

## 13. 当前边界与后续方向

Z-SCOPE 已经具备证据优先、多后端、自适应语义发现、分层三态验证和反馈闭环，但仍有清晰的演进空间：

- 跨函数 alias/ownership 证明还可以进一步结构化，减少当前图候选依赖启发式的边界。
- 锁顺序图和线程上下文已经进入局部图候选，后续可扩展为项目级全局图。
- 更多 SVF/Saber/Joern 输出可以从查询信号升级为稳定候选 IR。
- V4 动态复现只预留契约；PoC、sanitizer harness 与隔离执行仍是后续独立里程碑。
- Range 只保留分布内回归定位；生产泛化依赖 public external、独立 sealed vulnerable/fixed pairs 与真实项目 shadow scan。

### 13.1 下一阶段：领域知识引导

下一阶段的重点演进方向是增强用户领域内部知识对 Z-SCOPE 的分析引导能力。大型 C 项目的真实安全约束往往并不完全体现在源码中，许多约束存在于接口手册、开发规范、设计文档、运维手册、受限使用说明、历史审计结论和团队约定中。例如，某个 API 只能在初始化阶段调用，某个回调在持锁状态下禁止重入，某个长度参数包含结尾符，某个对象释放权在特定状态机转换后转移，某类输入在生产部署中来自受信边界。

这些非代码知识会被规划为独立的领域知识层，作为现有 `UserConfigStore` 和 KnowledgeDB 的上层补充：

| 知识类型 | 示例 | 对分析的价值 |
|----------|------|--------------|
| 接口调用约束 | 前置条件、后置条件、调用顺序、错误码语义 | 发现违反调用契约的隐藏缺陷 |
| 生命周期约束 | acquire/release 配对、所有权转移、对象状态机 | 提升泄漏、UAF、double free、stale pointer 检出率 |
| 并发约束 | 持锁要求、禁止重入、线程亲和性、回调上下文 | 降低锁误报并发现跨线程真实风险 |
| 受限使用场景 | 初始化期限定、单线程假设、可信输入边界、部署开关 | 区分真实漏洞、受限风险和可接受行为 |
| 安全规范与手册 | 禁用 API、敏感参数要求、边界检查规范 | 将组织内部安全规则转化为候选生成依据 |
| 历史审计知识 | 已确认误报、真实漏洞根因、团队修复约定 | 复用人工经验，避免重复 triage |

### 13.2 规划中的架构形态

领域知识引导能力可以按四个阶段演进：

1. **文档摄取**：支持 Markdown、HTML、PDF、Word、纯文本等内部资料，按项目、模块、版本、来源和适用范围建立索引。
2. **契约归一化**：从自然语言文档中抽取 API 契约、状态机、资源所有权、并发约束、输入边界和禁止用法，形成结构化 `domain_contracts`。
3. **检索注入**：在 Security Map enrichment、coverage-gap discovery、候选生成和 V3 调查阶段，按函数名、类型名、文件路径、模块标签和调用关系检索相关领域契约。
4. **证据治理**：每条领域契约保留来源文档、章节、版本、适用范围、更新时间和置信度。文档知识作为可解释证据参与判断，但不直接覆盖源码事实。

在实现上，领域知识层应避免把整份手册直接塞入 LLM 上下文，而是将文档约束切分为可检索、可引用、可评分的最小契约单元。这样既能让 Agent 获得项目内部语义，又能保证报告中的判断可以追溯到具体文档来源。

### 13.3 对检出率和误报率的影响

领域知识会同时提升检出率和降低误报率：

| 目标 | 作用机制 |
|------|----------|
| 提升检出率 | 文档中的调用顺序、状态机、所有权转移和受限 API 规则可以生成新的候选来源，发现源码局部分析难以识别的契约违背 |
| 降低误报率 | 文档中的部署边界、初始化期限制、可信输入假设和线程模型可以作为反证或降权依据，减少把受限场景误判为通用漏洞 |
| 提升可解释性 | 报告不仅引用代码路径，也能引用内部手册章节和领域契约，使审计结论更容易被研发团队接受 |
| 提升持续治理能力 | 当手册或设计约束变化时，相关契约可以重新索引并影响后续扫描，实现“代码事实 + 领域约束”的持续同步 |

这一方向本质上是把 Z-SCOPE 从代码事实驱动的 AI SAST，进一步演进为“代码事实 + 用户领域知识”共同驱动的安全审计平台。代码仍然是最终事实基础，领域文档提供项目语义和使用边界，两者共同进入候选、验证、评分和反馈链路，以持续提高高检出、低误报能力。

架构上，这些增强都可以沿用主线分层：继续把事实、候选、验证、反馈拆开，用结构化证据驱动 LLM，降低模型独自承担静态分析本体的风险。

## 规则前的项目原语契约

项目原语已有 Web 控制面：`web/semantics_service.py` 和本地 `dashboard_semantics.js/css` 将工程声明、独立准备任务、人工审阅与扫描就绪串联。`orchestration/primitive_preparation.py` 复用 CLI 发现核心，`primitive_tasks.py` 持久化运行状态；`config/semantics_workflow.py` 统一 CLI/Web/MCP/计划的只读就绪判断与发布锁。YAML discovery_receipt 保存输入收据及人工完成摘要，任务数据库不成为第二份配置权威。空文件、过期输入和未完成审阅均不能授权扫描。

C/C++ 所有档位执行：加载并校验 YAML → 绑定当前 BuildContext/USR 与 catalog/native receipt → 编译只读实例 Registry → 规则候选登记 → 后续发现 → Ledger 冻结 → 统一验证与补证。pending、stale、unresolved、跨构建冲突或 discovery blocking gap 会在扫描前失败；正常扫描不会更新 YAML。项目级 discovery 是单独命令，在所有精确函数实例及 link-group SCC 上求 wrapper/宏/间接调用/dispatcher 闭包，每个实例事实只生成一次；宏闭包保留逐层 `derived_from` 与精确参数/全局载体映射，不能用零参数宏冒充 argument 0。

`ApiContract` 区分调用前提与效果分支，条件使用结构化比较、布尔组合和参数、返回值、全局对象、内部调用结果引用；YAML ObjectPath 结构化表达载体。具备当前实现凭证或明确 external authority 后，透明函数与宏由静态分析组合。隐藏返回状态形成 `may`，不伪造必然效果；LLM 只能给出 agree/refine/disagree/insufficient 建议，不能发布契约。

`ApiPair` 保存有依据的多对多有向边，不做共享端点的传递闭包。人工角色和配对优先，自动更新只刷新当前覆盖范围；生成数据先原子写入再重读，规则消费同一契约版本。Clang/Regex 生命周期规则要求合法配对、同一对象、同一池及成立的效果；未知释放保留候选并限制证明完整性。实现凭证绑定当前源码，人工派生契约保留假设，schema 与模型置信度不能授权安全或缺陷证明。Graph 保留已核验锁接口的可能成功分支，未知解锁不解除义务；词法锁顺序不能成为确定性路径证明。KnowledgeDB 枚举每次获取，通过共享编译器对象义务检查释放、返回和输出转移，不以释放函数名称的出现判定泄漏。全局、成员与容器清理未闭合时保持未知；任意跨函数池别名仍超出当前能力。

快照中的 `suspicious_points` 保留为未验证背景，不写项目语义 YAML，不产生 `semantic_snapshot` 候选或独立验证任务，也不进入 candidate-blind 主动发现提示词。项目接口的机器证据单独存入 `.zscope_snapshots/semantics/`；benchmark 在临时工作区清理前归档 YAML 摘要、catalog 版本、逐构建授权和语义覆盖缺口。

Discovery 复用项目级 fast planner 与 `FunctionFactSummary`，按 BuildContext+USR 去重本地分析，并在真实 link group/SCC 上传播摘要。源码、构建、catalog、native 工具或证据变化标记旧决定 stale；同源码不同变体独立存储。

标准 C/POSIX/Linux 接口来自单一版本化 packaged catalog。每项分类为 active、neutral 或 unsupported；active 必须同时具备精确声明身份/ABI、规范来源和规则消费者，且仍需当前系统头收据、external linkage、无项目同名定义、USR/签名/BuildContext/工具摘要全匹配。项目实际调用但 catalog 未分类的系统接口会阻止 formal readiness。

pending/rejected/stale 行不生效；confirmed 行作为明确人工契约导入。人工决定不会被相同证据覆盖，证据变化则转 stale。确认只沿已核验映射传播，不授权不透明释放端，也不证明某次调用成功。

报告逻辑视图不变，默认持久化改用单文件共享对象表，公共读取层解引用后向评分、回放、SARIF 和 Web 提供原逻辑数据。完整证据和源码不裁剪；检查点复用不可变内容对象。只读访问不会使共享引用失效，嵌套修改保持投影隔离；契约和决策事实的序列化边界避免把内部 tuple 带入 JSON 证据池而触发整份复制。详见接口与报告模块。

受限等待结果探索沿用原路径解释器，默认通知路径未闭合时才运行至多两个额外有界路径（各自一次无通知唤醒或超时），选择实际非法访问见证，次选已闭合路径；任何无告警结果仍不证明安全。timedwait/clockwait 的本地 timespec 布局、系统 ETIMEDOUT 与显式 CLOCK_REALTIME/CLOCK_MONOTONIC 常量出处由当前 native 收据核对，时钟和截止条件显式进入见证与验收。旧源码、宏、契约或 native 工具变化通过原当前性/增量链失效，不增加用户配置或独立调度平台。

受限 caller cond_wait 与 worker 调度共用已有精确对象/锁身份、native CFG 和 S04 证明链。等待暂时释放调用方锁，工作者按真实通知及原锁释放推进；返回后由实际条件分支决定是否再等，不能从 helper 名称、通知或活动标志推定 callback 完成。调度边保留入口到 caller helper 的路径，cleanup 根展开也使用该真实前缀；后续访问和 join 继续沿原生命周期解释。有限闭合不等于完整 drain/unregister 或全交错验证。
