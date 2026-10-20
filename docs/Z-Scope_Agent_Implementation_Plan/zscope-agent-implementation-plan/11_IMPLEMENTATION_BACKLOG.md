# 11 · 实施任务包与依赖

## 实施顺序

新工作包采用 S（扫描）、U（体验）、Q（后置通用 QA），替代旧 AG00–AG17 排期。旧方案的搜索/只读语义、条件契约、Sanitizer 执行不再列为从零开发。用户已授权实施，逐包状态以 [21](21_IMPLEMENTATION_STATUS.md) 为准，下面描述目标范围而非完成声明。

```text
S00 基线（本轮已部分完成，开发时只补相关差异）
 ├→ U01 启动画像/配置体验
 └→ S01 构建与对象身份
      → S02 条件资源协议
      → S03 生命周期候选 → S04 义务/裁决 → S05 自动复现
                    └→ S06 并发/异步协议
S02/S04 → S07 需求建模与增量
S04/S05 + U01 → S08 夜间任务 → U02 集中验收
S09 质量/性能随各包交付
S03/S04 → S10 可选后端/平台扩展（不阻塞首条闭环）
S08 完成并有明确需求后 → Q01/Q02 通用 Coding
```

每包交付代码行为、相关测试和必要文档，简短记录即可。依赖箭头表示消费者合同，不要求先建立审批/冻结阶段。首条闭环只需一个构建目标和一个对象协议，不等全部泛化完成。

### 资源接口专项子任务（首批及 P2/P3/P4 受限切片见 21，其余待办）

[22 资源接口识别子计划](22_RESOURCE_API_INFERENCE.md) 将独立评估 P0–P5 拆入既有工作包；`Sxx-Rnn` 是所属 S 包的子任务，不替代既有 S00–S10，也不重复建设已交付的 S02 包装器/单槽池、S03 对象路径或 S04 业务反馈。登记时全部待办；用户后续授权已启动并验收 S02-R01–R06 的首批受限切片，实际状态和能力边界统一见 [21](21_IMPLEMENTATION_STATUS.md)。

| 阶段 | 子任务／归属 | 依赖与顺序 | 详细验收 |
|---|---|---|---|
| 首批 P0 | S02-R01/R02：接续核对、覆盖诊断 | 复用 S01/S02/S03/S04 当前接口；不等待整包完成 | RAPI01 |
| 首批 P1 | S02-R03/R04/R05/R06：native 值流、条件包装器、消费一致性、定向验证 | P0 → 单构建、同 TU、直接调用；P0/P1 合计 10–19 人日 | RAPI02–RAPI05 |
| P2 | S03-R01：跨 TU 与有限间接调用 | S02-R06 + S01 真实链接目标与构建实例兼容证据 | RAPI06 |
| P3 | S02-R07：refcount／池／句柄协议 | S02-R06；跨 TU 部分依赖 S03-R01；复用 S04 专门义务 | RAPI07 |
| P4 | S06-R01：锁模式；S02-R08：有限 RAII | S02-R06 + S03/S04 消费合同；锁 guard 依赖 S06-R01 | RAPI08 |
| P5 | S06-R02：异步清理；S07-R01：完整增量 | S03/S04；按协议选用 P2/P3/P4，增量随已有能力推进，不以全部异步完成为前置 | RAPI09/RAPI10 |

详细任务、估算假设、落点、默认开关和可验证正反例只在 [22](22_RESOURCE_API_INFERENCE.md) 维护；[16](16_ACCEPTANCE_TESTS.md) 保留验收入口。当前已接续 S04、S02-R01–R06、S03-R01，以及后续授权的 S02-R07 非原子计数/池状态和有界自定义句柄表，以及 S06-R01 标准/透明包装模式和受限静态锁覆盖。其他引用计数/池形态、OS fd/dup2、动态句柄表、通用锁协议仍待办；S02-R08 单指针 scoped heap guard 已接入当前 native/AST 与 Validator，move/锁 guard 等仍未支持。S07-R01 当前协议与头文件否定性依赖、局部全量/增量对照切片已验收；S06-R02 已交付 Linux glibc LP64、同 TU、单工作者的 pthread 取消/完成见证切片；S07-R01 已验收该直接回调的失效与冷/热对照切片。后续已接入单槽 pthread 队列的实际 submit/cancel/stop helper、工作者取走后的对象引用、同锁 UAF 与 join drain，以及对应冷/热失效对照切片。后续单等待者 cond_wait 的释放/通知匹配/重获/谓词重检及相应增量对照已接入；一般唤醒/超时场景、取消模式切换/任意取消点、一般工作者 helper、通用 unregister/drain、多工作者及完整扫描/调度仍待办；不因当前切片关闭整体阶段，实际边界见 21。

## S00 · 开发起点与对照样例

**复用**：[02](02_ARCHITECTURE_AND_REUSE_MAP.md) 的已核对表、本轮 [15](15_INDUSTRY_PRACTICES_AND_SOURCES.md) 验证；开发时读实际 diff，不重做旧交接全套核验。  
**输入/输出**：当前工作树、现有扫描 → 简短基线、首个 queue/pool 真缺陷与安全反例、未测清单。  
**落点**：独立 tests/fixtures，现有评测入口；不“修复”Range fixture。  
**完成**：真实 Linux 构建可运行，初始候选/结论/缺口可观察，用户修改保留。  
**文档**：本包基线状态只更新有实际证据的项。

## S01 · 构建、符号、对象身份

**依赖**：S00。  
**落点**：retrieval/indexing_identity、indexing_inventory、knowledge_db、code_index、clang_batch、unified/bitcode_scope；semantics/contracts。  
**输入/输出**：原始编译/链接记录 → BuildContext、编译实例、精确符号、ObjectRef/Event 最小合同与覆盖。  
**行为**：支持同源多变体、同名不同 TU/目标；传播身份至契约/图/候选/缓存/见证。明确存储与查询迁移，自动缓存可重建。  
**验收**：ID01–ID04；不能只改 inventory 或报告标签。  
**文档**：retrieval-backends、configuration-state、architecture；配置有变同步模板/init。

## U01 · 一个配置入口与启动准备

**依赖**：S00，可与 S01 独立推进准备界面。  
**落点**：config/v2 或新版本 loader、cli、web/services、初始化器。  
**输入/输出**：工程路径/模型连接 → 项目画像、自动检测结果、少量待确认项、可启动扫描计划。  
**行为**：检测构建、目标、平台、文档/测试、模型与工具；默认资源重点、夜间预设、自动复现；高级设置折叠。用户无需填写 task.yaml + 多份 profile。  
**验收**：UX01–UX04；UI/CLI 配置同源，路径解析明确，失败指出可操作原因。  
**文档**：README、interfaces-reporting、configuration-state；新接口未落地前只留在本包。

## S02 · 项目条件契约与资源协议

**依赖**：S01；使用 U01 画像。  
**落点**：ApiContract、contract_conditions/compiler、semantic_modeling、user_config store、Wiki service。  
**输入/输出**：实现/调用点/文档/人工约定 → 有来源的返回分支、载体、资源域、责任及协议摘要。  
**行为**：优先 pool/refcount/queue，覆盖失败/部分成功/借用/长期保留；自动核验与人工假设分离，冲突保留，生成 revision 并通知依赖。  
**验收**：RES01–RES06；现有条件所有权测试继续作为资产；不能用名称或 confidence 授予 must 效果。  
**文档**：configuration-state、wiki、analysis-pipeline；新增 Skill 合同才改对应 Skill。

## S03 · 对象与资源生命周期候选

**依赖**：S01/S02。  
**落点**：core/candidates/cpp_domains、svf_value_flow、semantics/security_map、active_discovery。  
**输入/输出**：对象事件/条件摘要 → 内存、泄漏、重复回收、错域归还候选及缺失义务。  
**行为**：保留对象代际/区域，按责任终点判断泄漏，覆盖低外部可达 cleanup 与错误路径；主动探索不依赖已有告警。  
**验收**：MEM01–MEM05、RES03/04；真缺陷/安全反例均可解释，发现来源保留。  
**文档**：analysis-pipeline、builtin_catalog revision/CWE 映射/相关 Skill；确定性规则目录与 disabled 行为一起验证。

## S04 · 统一义务、见证与最终状态

**依赖**：S03，协议可提前与 S02 对齐。  
**落点**：validation/evidence、fact providers、proofs、runner、pipeline、review checker、reporting。  
**输入/输出**：候选/已有证据 → ObligationSet、EvidenceRevision、四类用户结果及依据。  
**行为**：同一检查器处理静态/动态/未来求解器见证；缺口定向补齐，有增量再复判，移除重复审阅；不要求所有问题动态复现。模型 rejected 无足够反证保持未决。  
**验收**：VAL01–VAL06；同锁 UAF、仅排除一条路径、无依据高置信确认与误排除均有反例。  
**文档**：analysis-pipeline、agent-runtime、interfaces-reporting；状态变更更新全部消费者。

## S05 · 自动复现计划与扫描连接

**依赖**：S04，执行器已有。  
**落点**：dynamic_reproduction、ValidationRunner、ScanSession；新增小型计划/harness 生成服务。  
**输入/输出**：当前候选/义务/真实目标 → 可运行 plan、harness/输入、原始日志、匹配见证或未决原因。  
**行为**：session 持有 provider；默认自动尝试合适候选；共享构建、分开 ASan/TSan；失败修正有界；业务源码不改。检查前提、stub、对象/代际、二进制与原程序映射。  
**验收**：DYN01–DYN07，真实 ASan/TSan 正反例，不用 fake 代替；非确定性 witness 策略先测再调。  
**文档**：analysis-pipeline、execution-orchestration、用户运行/报告说明；不把库级接口当已完成生成器。

## S06 · 并发、异步与特殊回收

**依赖**：S02/S03/S04；运行验证按需复用 S05。  
**落点**：共享/锁/回调事实、protocol summaries、candidate generators、验证 providers。  
**输入/输出**：执行上下文和对象事件 → data race、生命周期、cancel/complete、注销/drain、锁/状态协议候选与见证。  
**行为**：区分 MHP/HB、真实锁实例和成功条件；普通 race 与 UAF 使用不同剪枝；状态机覆盖共同可达路径。  
**验收**：CON01–CON06；同锁 UAF、不可并发、正确 join/drain/refcount、互斥锁环反例。  
**文档**：retrieval-backends、analysis-pipeline、领域 Skill/目录。

## S07 · 需求建模、缓存与完整增量

**依赖**：S02/S04。  
**落点**：semantic_demand/modeling、CodeIndex/KnowledgeDB、snapshot policy、dependency manifests。  
**输入/输出**：静态摘要/未知接口/coverage/候选缺口 → 实际工作闭包、单飞建模与可解释失效。  
**行为**：替换“全部可达函数先 LLM 建模”；保留未知和对象盲探索覆盖；依赖包含新增访问者/回调/否定性假设。对比原调度后才移除冗余路径。  
**验收**：INC01–INC05；事实、候选、终态、未决及覆盖同版本对照，成本真实下降且没有未解释召回损失。  
**文档**：execution-orchestration、configuration-state、retrieval-backends；删除 shadow-only 旧说明须以实际行为完成为准。

## S08 · 夜间自主作业

**依赖**：S04/S05/U01。  
**落点**：scan_session、取消/共享资源、现有 Web job 服务与 CLI；小型本地 JobStore。  
**输入/输出**：本轮扫描计划 → 独立于 UI 的持续作业、当前报告、续接点和集中问题队列。  
**行为**：时窗/资源统一调度，公平处理困难对象；夜间不等业务答复；后端局部失败继续其他工作；停止/重启核对真实进程与版本。批次追加新候选，避免无限递归。  
**验收**：JOB01–JOB06；关闭 UI 后继续、取消清理、重启失效、窗口结束 partial、缺口不变安全。  
**文档**：execution-orchestration、interfaces-reporting、architecture、README。

## U02 · 集中验收与反馈

**依赖**：U01/S04/S08；先实现四态报告骨架，不等所有领域完成。  
**落点**：reporting、web 页面/services、Review Memory/模型反馈服务。  
**输入/输出**：根因/证据/问题队列 → 简洁验收页、业务模型批量确认、复现产物和后续动作。  
**行为**：已确认优先，条件与未决可见；源码时间线/资源责任/复现一键查看；误报、重复、业务前提、风险接受分类反馈。  
**验收**：UX05–UX08；不隐藏 backlog，不要求用户读大日志或多个数据库。  
**文档**：interfaces-reporting、review-memory、README。

## S09 · 质量与性能，随各包推进

**输入/输出**：上述样例/实际扫描 → precision、候选/最终 recall、误排除、未决、coverage、成本与体验对照。  
**落点**：已有 tests/benchmarking/usage/report，按需要增加专项。  
**验收**：EVAL01–EVAL04；开发相关验证即可，正式结论另走其明确协议。  
**文档**：benchmarking/range 协议仅在其行为改变时同步，不复制历史成绩进模块说明。

## S10 · 可选后端与平台扩展

**依赖**：有明确未闭合义务或真实平台需求，不作为上述工作的前置。  
**顺序**：CBMC 局部路径 PoC → 按缺口比较 Pulse/Goblint → Linux 已闭环后首个 RTOS 模型 → 真实无锁场景需要时 GenMC。  
**交付**：代表性真缺陷/反例、构建/证据接入、当前基线、收益/成本与 adopt/drop 结论；采用时替换冗余通路，不永久堆叠。  
**验收**：PLAT01–PLAT03、BACK01；不能把外部告警直接算确认或把有界无反例当全局安全。

## Q01/Q02 · 通用 Coding，后置

Q01 复用调查/模型/执行/JobStore，补通用目标、验收与上下文恢复；Q02 增加带版本前置条件的补丁、用户修改保护、真实 before/after 回归。只有明确修复任务才改业务源码。

不先实现多 Agent、外部 SDK、任意网页工具或完整插件生态。是否引入其他 Coding Agent，以真实任务收益决定。

## 每包最小交付

一段问题/结果说明；实际改动和复用；相关命令及 pass/fail/skip；已知限制；对应用户/模块文档。无需单独代码冻结、签名、层层审查记录；尚未实现或没跑的内容如实保留。

S06-R02 默认延迟取消与受限 C/glibc cleanup，以及 S07-R01 对应依赖/冷/热对照切片已验收。工作者同文件直接 helper 的有界帧与对应失效/冷/热对照已接入；已接入一次无通知唤醒与受限 realtime timedwait、直接系统 realtime/monotonic clockwait；后续仍有一般唤醒/计时场景和通用 drain/unregister，依赖实际事实逐项推进；取消模式切换、多工作者、跨 TU 异步与完整扫描调度不因当前切片关闭。验收记录保持追加，不覆盖上一轮扩大回归失败及修复结果。

S06-R02 已接入调用方 cond_wait 的受限 drain：匹配通知、原锁重获及实际 if/while 重检，保留入口/helper/工作者和 cleanup 的责任路径。提前清零 active、通知或等待返回不能替代实际完成；对应 S07-R01 谓词/通知/回调/根契约与释放顺序对照见 21。调用方超时/无通知/取消、多工作者与通用 unregister/drain 仍待办，不关闭完整阶段。
