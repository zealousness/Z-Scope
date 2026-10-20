# 19 · 专业内存与资源扫描改进

## 1. 与从零设计的取舍

输入为 [能力地图](../../c-ai-scanner-design/c-ai-scanner-design/01-capability-map.md)、[设计架构](../../c-ai-scanner-design/c-ai-scanner-design/02-design-architecture.md)、[指标](../../c-ai-scanner-design/c-ai-scanner-design/03-objectives-and-metrics.md) 和 [路线](../../c-ai-scanner-design/c-ai-scanner-design/04-delivery-roadmap.md)。该包是概念设计，不是 Z-Scope 已有能力清单；本章将它落到现有代码。

| 原包能力 | 决定 | Z-Scope 落点/工作包 |
|---|---|---|
| F01/F02 构建与源码身份 | 采用，优先补多变体/链接目标 | indexing_identity/inventory、KnowledgeDB、SymbolIdentity；S01 |
| F03/F04 对象、区域、代际与事件 | 采用，先最小结构再按候选精化 | 复用 IR/资源/共享事件；S01/S03 |
| F05/F06 条件摘要与项目契约 | 扩展已有 ApiContract，不重建 | semantics/contract_compiler、modeling；S02 |
| F07 语义缺口 | 采用，进入计划、验证和用户报告 | CoverageKey、AuditUnit、unknown 集合；S01/U02 |
| M01–M04 基础内存 | 复用规则与后端，补确认所需身份/路径 | cpp_domains、SVF/Saber、ValidationRunner；S03/S04 |
| M05 未初始化 | 采用区域级建模；按工具/平台声明范围 | S03 后续，不能以整对象初始化代替字段覆盖 |
| M06/M07 泄漏/自定义资源 | 提前为核心，按责任边界确认 | pool/refcount/handle/protocol；S02/S03 |
| M08 间接调用/跨函数 | 采用，按候选精化而非全仓无限内联 | CodeIndex、摘要/SCC、callback facts；S03 |
| C01–C05 并发/异步生命周期 | 重点采用，竞争与生命周期分开剪枝 | 共享事件、执行上下文与协议摘要；S06 |
| C06/C07 死锁/原子性 | 分批采用，需要明确状态机/可共达见证 | S06 |
| C08 弱内存/无锁 | 后置专用模型，不能套 pthread 锁语义 | S10 的 GenMC/平台验证 |
| A01–A04 AI 语义/探索/补证/复现 | 采用，复用现有调查基础 | S02/S04/S05/S06 |
| V01/V02 义务与切片 | 采用并统一现有不同证据路径 | proofs/review checker/fact providers；S04 |
| V03/V04 求解器 | 按缺口接局部 PoC，不先全量集成 | CBMC/GenMC；S10 |
| V05 动态复现 | 已有执行基础，补自动计划生成 | dynamic_reproduction；S05 |
| V06 四类结果 | 作为统一用户语义，不立即造第二裁决库 | ValidationPipeline 和报告投影；S04/U02 |
| E01–E07 去重/覆盖/增量/调度/评测 | 采用；现有 replay/usage 只是部分基础 | S07/S08/S09 |

不照搬“一次接入 Infer + Goblint + CBMC + GenMC”的组合，也不把 98% 写成已经达成或无条件上线门槛。先以真实正反例与独立标注建立基线，按 [10](10_EVALUATION_AND_PERFORMANCE.md) 比较。

自定义申请/释放和加锁/解锁接口的代码取证、行业对照已形成 [独立评估](../../resource-api-assessment-2026-10-13/ASSESSMENT.md)，实施拆分见 [22 资源接口子计划](22_RESOURCE_API_INFERENCE.md)。优先补发现覆盖和受限包装器核验（S02-R01–R06），后续归入 S03 的跨 TU、S02 的 refcount/句柄及 RAII、S06 的锁/异步和 S07 的完整失效。已有条件契约、单槽协议、具体对象路径及最新 S04 反馈继续复用；自动契约推断与静态规则消费分别验收，不能把命名、配对关系或 decrement 当成确定释放效果。首批 C 堆包装器、S03-R01 已观察 C 链接/const ops 及 S02-R07 的非原子计数/池状态和有界自定义句柄表、S06-R01 受限锁模式/当前静态锁覆盖的实际交付、拒绝边界及消费者限制见 [21](21_IMPLEMENTATION_STATUS.md)，平台/通用子域和其他专项仍待办，实验开关不变。

## 2. 构建身份是对象证据的前提

旧基线只有 compile inventory 能区分命令身份，TU 导航按文件路径唯一。S01 已增加 KnowledgeDB 编译实例事实、精确 BuildContext + native USR 查询，以及契约的构建作用域；旧函数/类型导航与完整扫描调度仍未全部迁移，实际进度见 [21](21_IMPLEMENTATION_STATUS.md)。目标仍是让事实、契约、候选、缓存和见证共同使用明确的 BuildContext，不能把查询切片当作整条链路完成。

最小身份包含：工程、源文件内容、编译实例（cwd/argv/响应文件/关键环境/头文件依赖）、目标 triple/ABI、工具链、真实链接目标。对单文件多配置和不同 executable 的同名符号分开记录；编译数据库只能说明编译命令，不能单独证明所有 TU 属于一个链接程序。[Clang 规范](https://clang.llvm.org/docs/JSONCompilationDatabase.html)

优先从实际构建系统/链接产物导入目标分组，人工补充只用于无法自动获得的信息。缺少目标归属时能做局部源码分析，但跨模块路径保持 unknown。

实施不能止于 schema 追加 build_id：检查 CodeIndex 查询、函数/类型/宏存储、契约 lookup、图边、SVF 分组、candidate fingerprint 和缓存键全部消费者。自动事实库可按新版本重建，人工模型单独导入并重新绑定。首条闭环先限定一个真实目标，多目标支持不得通过静默选第一条命令实现。

## 3. 对象、区域、代际与资源责任

不建设包办所有后端的统一 IR。保留后端内部表示，增加跨模块最小证据合同：

| 对象 | 必需信息 |
|---|---|
| ObjectRef | build context、allocation/acquire site、调用上下文、资源域、抽象实例集合、代际；无法区分时明确 abstract/unknown |
| Region | 基对象、字段/子对象、偏移、宽度、边界、已初始化区域 |
| Event | acquire/read/write/release/transfer/escape/publish/borrow/retain/drop/callback/task/sync，源码位置、条件和来源 |
| ExecutionContext | 入口、线程/任务/回调/ISR、可能并行关系、已知调度约束 |
| Summary | 前置条件、分支效果、别名/逃逸/责任、同步变化、未知副作用与依赖 |
| Evidence | 建立的事实、适用假设、完整性、未满足义务、可回源引用 |

同分配点不等于同实例，同地址不等于同代对象；句柄整数相同也可能已经关闭后重开。发现阶段允许较粗别名集合，确认阶段必须证明关键事件可以作用于同一实际对象/代际，否则保留待验证。

资源域按 pool/allocator/session/device/transaction 建模。释放配对要核对对象与域，不能因为同一个释放 API 出现就消除责任。

## 4. 特殊业务模型优先矩阵

| 模型 | 错误场景 | 必备安全反例/业务前提 |
|---|---|---|
| 内存池/arena/slab | 归还错误池、归还后借用、重复归还、批量 reset 后旧引用 | 不同实例、合法 pool 生命周期、reset 后无活引用 |
| 引用计数 | 取引用前销毁、重复 drop、借用跨异步边界 | retain 在可证明存活区间，最后引用/等待协议正确 |
| 队列/消息/零拷贝 buffer | 发送成功后再次释放、失败未回收、消费者重复释放 | 成功转移、失败保留、部分成功与批量发送逐项责任 |
| cancel/timeout/complete | 双路径清理、回调悬挂、超时后资源泄漏 | cancel 同步等待或单一状态 CAS 保证唯一回收 |
| register/unregister/close | 注销返回后回调仍访问、销毁顺序错误 | drain/join 确实等待在途回调，禁止新注册 |
| fd/socket/mmap/device handle | close 后复用、错误 handle 关闭、异常退出泄漏 | 进程/模块保留、dup/shared ownership、映射与描述符责任分别建模 |
| 初始化与部分失败 | 分阶段初始化后的不完整清理、重试遗留资源 | 只释放已取得资源、幂等关闭、合法重试 |
| cache/singleton/session | 将设计保留误报为泄漏、租约过期后借用 | 明确生命周期边界/容量限制/最终回收安排 |
| C++ RAII/异常/move | 自定义 deleter 错域、move 后错误使用、析构漏清理 | 析构/异常路径确实覆盖，智能指针控制块与原指针不混同 |
| RTOS/ISR/DMA | 中断或设备仍使用的缓冲区被回收、任务删除遗留 | 任务/中断级别、屏蔽范围、DMA 完成、cache/coherency 和设备约束 |

先交付前四类，再扩展注销、句柄、C++ 与平台模型。该顺序不意味着旧类别关闭；现有检测继续运行，新增能力逐类验证。

未知外部调用不默认无副作用。优先建模影响最多义务的公共接口，但不只追逐现有候选；保留对象/协议覆盖任务发现没有任何规则告警的区域。

## 5. 专业发现与调度

静态事实和标准/已核验契约先铺底，生成对象生命周期候选；Agent 阅读当前对象及协议相关实现、调用点、文档、测试，提出新假设并补缺口。与现有候选盲发现共用 Registrar，发现来源保留，不能把另一个工具已有告警记成 LLM 独占发现。

覆盖单位从“入口函数扫过”扩展为 build × object/resource family × lifecycle phase × execution context × obligation。未匹配入口的 cleanup、错误分支、后台线程、销毁回调、低频失败路径也要有扫描任务，不能只围绕外部输入或 high/critical 候选。

调度先处理高影响公共语义缺口及高风险可闭合义务，同时轮转长期未决和无候选区域，防止低外部可达资源泄漏饥饿。记录 eligible/started/completed/deferred 和原因；预算或时窗到达不删除候选。

## 6. 按类别的确认与排除

| 类别 | 支持确认的关键义务 | 不足以确认/排除 |
|---|---|---|
| UAF/double free | 同代对象、真实释放、后续访问/第二次释放、合法顺序、持有/等待约束不阻止 | 两个变量 may alias；同一分配点；两行含 free |
| 泄漏 | 实际取得、明确责任终点、可达未清理路径、无合法转移/保留 | 当前函数没有 free；未知 callee 未查明 |
| 越界 | 对象/子对象边界、偏移与访问宽度、目标整数转换/溢出、可行路径 | 数学整数计算忽略 C 类型；仅看到危险 API |
| 空指针 | 合法输入/调用条件、空值传播、可达解引用 | 未判空本身 |
| 未初始化 | 实际使用区域未初始化、目标语言操作确属错误 | 仅部分字段未写却推断整个对象错误 |
| data race | 重叠区域、至少一个写、同一次可行执行中可并发、缺乏必要 HB | 同名全局、没有发现锁、未建模原子同步 |
| 死锁 | 可共同到达的持锁/等待与合法顺序 | 锁顺序图单纯有环 |
| 业务协议 | 明确状态机/不变量、可发生的违例序列 | 文档含“异步”或两个 Agent 同意 |

正/反结论都需要范围。可行错误执行是存在性证据，不要求“所有输入必错”；排除某条路径不能排除尚未调查的其他路径。模型置信度和多数表决均不能代替义务。

**同锁 UAF 必须保留**：A 持锁借出 p 后解锁；B 持同锁释放对象；A 再持同锁使用 p。普通数据竞争可能被排除，生命周期错误仍可发生。锁集剪枝不能共享给所有缺陷类别。

## 7. 与 V0–V3 的融合

保留统一 ValidationPipeline；将现有 evidence requirements、fact providers、ReviewClaimChecker、动态 witness 汇入同一 ObligationSet/EvidenceRevision。

1. 廉价确定性核对充分时直接处理正/反证明。
2. 已有事实可解决的语义交给一次结构化判断；缺口必须结构化指出。
3. 调度相应 provider、对象切片、项目建模、局部路径或复现；每个动作说明要解决哪个义务。
4. 有新增证据再裁决；无增量停止重复 V2/V3/Reviewer，保留未决。
5. 确认项具备当前构建下可核查的静态因果见证或有效动态/模型检查见证；裁决程序校验关键身份、引用、条件、义务及冲突。

这允许改写 V1/V2/V3 具体顺序或删除冗余轮次，不把旧阶段数量当产品契约。首期不要求完整 SMT/动态复现才能确认每条问题；静态见证是有来源和条件的程序路径/协议事件，不是 LLM 自述“存在路径”。

四类用户状态由一个最终裁决服务产生：confirmed、conditional、pending、ruled_out；severity、运行是否完整、显式 suppression/baseline 分别保存。现有 model_verdict 与 policy_disposition 不直接等同四态，转换详见 [12](12_SCHEMAS_AND_EXAMPLES.md)。

## 8. 自动复现与局部验证

S05 为未闭合且适合运行的候选生成合法 harness、输入/失败注入与构建计划。优先链接真实实现；执行前核对接口前置条件、初始化、对象、源码映射及 stub 差异。纯业务资源池可能需要契约状态探针，不能指望 ASan 理解逻辑归还。

ASan 与 TSan 独立构建，分别探测当前平台工具链；前者用于其支持的内存错误，后者用于其支持的数据竞争，均非完整资源/并发证明。[ASan](https://clang.llvm.org/docs/AddressSanitizer.html)、[TSan](https://clang.llvm.org/docs/ThreadSanitizer.html)

当前实现要求多次匹配重放才授予动态确认，混合触发会保持未决。这会影响非确定性缺陷召回：S05 先保留并显示真实触发分布，后续用成对真缺陷/反例评价是否允许“一条已核验合法 witness 支持确认、额外重放只衡量稳定性”。不能仅为通过不稳定 fixture 放宽条件。

CBMC 仅用于缺口明确的局部 C 路径/整数/对象验证；不把任意 LLM 生成约束的 SAT 当证书。反例要映射原程序，UNSAT/未发现错误受展开与模型范围限制。[CBMC 展开说明](https://diffblue.github.io/cbmc/cprover-manual/md_cbmc-unwinding.html)

并发切片必须保留其他线程的销毁、发布和干扰；弱内存由匹配目标模型的专门后端处理，不用手工删同步制造可复现错误。

## 9. 工具与后端取舍

| 组件 | 本版决定 | 替换/保留依据 |
|---|---|---|
| Clang batch | 主编译语义前端继续使用 | 已有 native 工具与缓存，S01 补身份；clangd 只在确有缺口时承担补充 |
| Regex/source hints | 保留廉价线索，逐项合并冗余规则 | 不获得超出其证据的确认/反证能力 |
| SVF/Saber | 当前继续作为别名/值流/资源信号来源，按构建/对象相关范围复用 | 测量真实独占 TP、假阳性、缺口闭合与成本；有等效替代才移除对应路径，无兼容包袱 |
| Infer/Pulse | 后置顺序内存摘要 PoC，可成为部分路径替代者 | 文档说明其跨过程内存分析，也说明 latent 问题和未知调用的乐观处理；这些取舍可能影响召回。比较项目构建、结果/摘要可消费性、未知接口与模型扩展成本，不能把无告警当安全或承诺内部摘要 API 可直接复用。[Pulse](https://fbinfer.com/docs/checker-pulse/) |
| Goblint | 并发候选有缺口时优先做小 PoC | 验证项目语言扩展、同步模型与证据导出；告警统一验证，不直接 confirmed。[官方仓库](https://github.com/goblint/analyzer) |
| CBMC | 第一优先的可选局部验证 PoC，非 S03/S05 阻塞 | 比较解锁的义务、见证真实性与时间；不全仓盲运行 |
| GenMC | 弱内存/无锁有真实样本时再接 | 必须匹配支持的程序与内存模型；不当通用线程工具。[项目资料](https://plv.mpi-sws.org/genmc/) |
| ASan/TSan | 复用已写执行器，补生成器和自动调用 | 默认不对每个候选编译一遍；同构建共享，关键 witness 独立记录 |
| C/C++ Joern 兼容路径 | 不再投入新功能；清理时可删除旧兼容入口 | Java 路径单独处理，不把 C/C++ 弃用推导成 Java 删除 |
| 外部 Coding Agent/多 Agent | 延后 | 对当前内存/资源目标无必要前置价值 |

选择候选组件时保留许可、部署体积、目标架构与维护成本的实际信息，不引入长审批流程。每个 PoC 只需代表性真缺陷/安全反例、当前 baseline、独占收益/回归/成本和 adopt/drop 结论。

## 10. 增量与性能

缓存依赖不止调用图，还包括构建变体、对象访问者集合、回调注册、资源域、契约、同步与“没有其他访问”的否定性前提。新增消费者也必须触发旧结论失效。

先实现一次解析/摘要共享、按需精化、公共接口单飞、对象事件分组，再优化更复杂算法。编译/SVF/LLM/复现共用资源调度，避免每层各开满核心与内存。

现有 incremental_replay 作为事实层回归保留，另增加同版本全量与增量的候选、四态结果、coverage、未决义务对照。性能提高必须同时展示精确率、最终召回和未决变化，不用缓存 token 推断热跑收益。

## 11. Linux 到嵌入式/RTOS 的扩展

Linux 闭环后，选一个真实目标平台和工具链增加 PlatformModel：ABI/位宽、编译扩展、任务与 ISR 调度、临界区范围、分配策略、设备/DMA 完成语义。能在主机重放的部分明确为替代模型，不能宣称目标硬件已验证。

用户在启动阶段确认平台和少量关键硬件前提；未建模的同步/设备行为保持覆盖缺口。平台模型、协议模型和正反例可复用到同类项目，但不同项目约定不自动互相覆盖。
