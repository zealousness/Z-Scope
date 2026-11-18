# 22 · 自定义资源接口识别与契约核验子计划

**登记日期：2026-10-13；后续已授权实施 S02-R01–R06、S03-R01、S02-R07 的计数/池及句柄子域，以及 S06-R01 受限锁模式。** 当前 S04、受限 C 堆包装器、已观察链接/const ops、signed 32-bit 非原子引用计数、单槽池状态归还与有界自定义句柄表、锁模式与受限当前编译锁覆盖的实际范围和 Linux/native 验收统一见 [21 实施记录](21_IMPLEMENTATION_STATUS.md)。其他引用计数/池形态、OS fd/dup2、通用锁协议/RAII、异步和完整增量仍待办，复杂链接及通用跨 TU 求解不在已交付范围。

依据是 [独立能力评估](../../research/resource-api-2026-10-13/ASSESSMENT.md) 及其 [文件取证清单](../../research/resource-api-2026-10-13/EVIDENCE.json)。独立报告保留原样，不倒写历史判断；本章将其中 P0–P5 纳入 [11 实施任务包](11_IMPLEMENTATION_BACKLOG.md)，并吸收登记时 [21](21_IMPLEMENTATION_STATUS.md) 已新增的 S04 业务前提反馈交付记录。原报告 P0–P5 是阶段编号，与风险表中的 P0/P1 优先级不是同一维度。

## 1. 已有基础与证据边界

本地取证对应 CINDALA、`v1.3.1_feat/llm-wiki`、HEAD `010f40210b54ba0f79a088312ce5d8be3a82ace0` 的脏工作树。实施时重读实际源码和最新状态，不能仅凭同一 HEAD 复用旧结论。以下只列复用点，完整文件/符号/测试矩阵仍以独立报告为依据。

| 已有基础 | 必须复用的代码与消费链（路径相对仓库根） | 不能扩大解释的边界 |
|---|---|---|
| S01 构建与对象身份切片 | `retrieval/build_context.py: BuildContext`、`indexing_inventory`、`knowledge_db`、`code_index`；`semantics/build_scope.py`、`resource_identity.py: ObjectRef` | 实例存储和精确查询不等于全变体调度或真实链接目标已闭合；未知构建不是通配符 |
| S02 标准种子与条件包装器 | `semantics/standard_api.py: standard_contracts`、`contract_compiler.py: derive_contracts / compile_snapshot`、`contracts.py: ObjectBinding / ApiContract / ContractRegistry`、`orchestration/semantic_modeling.py` | 多层直接包装、简单别名、部分 guard 已有；源码 token/结构核验不是通用值流求解。不是从零开发包装器或配对表 |
| S02 受限自定义池与留存 | `pool_protocols.py`、`single_slot_pool.py`、`retention_protocols.py` → 工作簿发布屏障 → Registry → 普通 Regex/Clang/Graph/SecurityMap | 特定 free-list、native 单槽池和留存形态已有；引用保存不证明清理责任，逻辑归还不等于物理 free |
| S03 同 TU 具体对象路径 | `core/candidates/cpp_domains/lifecycle_paths.py: LifecyclePaths`、`resource_lifecycle.py: _run_object_protocol_paths`、`retained_slots.py` | 已有调用帧、池实例、获取代次及缺口；不是完整跨 TU、入口输入求解或异步交错 |
| S04 当前重放与精确业务反馈 | `core/validation/protocol_assessment.py: assess_protocol_candidate`、`proofs/runner/pipeline`；`config/protocol_feedback.py`、`semantics/business_assumptions.py`、Web 报告验收 | 最新记录已交付限定对象/路径的回答写回、版本依赖重验和专门 proof；不再登记为待开发反馈页面。任意规范解析、跨对象推广仍未闭合 |
| S07 增量基础 | `semantic_modeling` 的代码/编译/依赖/callee/人工/spec 摘要、`semantic_demand`、snapshot policy、incremental replay | 按需 planner/shadow、事实对照不等于完整候选/裁决增量；新增访问者和否定性依赖仍需扩展 |

“已有且有验证”在独立报告中指代码、调用方和可指认测试断言；该评估没有重跑产品测试。登记时 S04 最新 523/383 passed 等是 [21](21_IMPLEMENTATION_STATUS.md) 的开发历史记录，集合有交叉，不累加，也不是本次计划编辑的测试结果。受控模型响应不等于真实 LLM，存在 native 测试定义不等于本次 native 验收通过。实际工程精度、召回、未知率及性能仍没有本次独立基线。

当前默认边界：标准/已核验契约及普通资源规则已有默认消费；`zscope.c_cpp.cpp_clang_cfg.retained_slot_release`（revision 1）和 `zscope.c_cpp.cpp_clang_cfg.object_protocol_path`（登记时 revision 3）仍为 experimental/default-disabled。本计划不改变开关，不把“新规则关闭”写成“所有资源检测关闭”，也不将候选、条件性风险或人工声明自动计为 confirmed。

## 2. 任务归属、编号与依赖

沿用 S（扫描）工作包：`Sxx-Rnn` 是该包下的资源接口专项子任务，不新增 S11 或第二条总路线。以下子任务 ID 与 `RAPI01–RAPI10` 验收 ID 的一致性已在实施接续时重新核对；P/A 编号只用于映射独立评估，不作为第二份状态账本。表中只给当前进度索引，范围和证据以 [21](21_IMPLEMENTATION_STATUS.md) 为准。

| 统一任务 ID | 对应评估 | 交付范围／归属 | 直接依赖 | 当前状态索引 |
|---|---|---|---|---|
| S02-R01 | P0 / A0 | 当前接口、消费者和证据接续核对 | S01/S02/S03/S04 已交付切片及最新 diff | 首批已验收，范围见 21 |
| S02-R02 | P0 / A1 | 发现、核验、未消费覆盖诊断 | S02-R01；复用 S07 现有统计 | 首批已验收，范围见 21 |
| S02-R03 | P1 / A2 | 同 TU 最小 native 值流证据适配 | S02-R02、当前 native 能力收据 | 首批已验收，范围见 21 |
| S02-R04 | P1 / A3 | 条件包装器及副作用核验增强 | S02-R03、已可信根契约 | 首批已验收，范围见 21 |
| S02-R05 | P1 / A4 | 发布与现有消费者效果一致性 | S02-R04、S03/S04 现有接口 | 首批已验收，范围见 21 |
| S02-R06 | P1 / A5 | 定向回归、失效核验及说明 | S02-R05；有效 Linux/native 环境 | 首批已验收，范围见 21 |
| S03-R01 | P2 | 一个真实链接目标内跨 TU／有限间接调用 | S02-R06；S01 链接目标与实例兼容证据 | 受限链接/const ops 切片已验收，范围见 21 |
| S02-R07 | P3 | 非并发 refcount、小幅池扩展，随后句柄协议 | S02-R06；跨 TU 部分依赖 S03-R01；S04 专门义务 | 非原子计数/池状态及有界句柄表切片已验收；通用/平台子域仍待办，范围见 21 |
| S06-R01 | P4 锁部分 | 锁实例、shared/exclusive、try-lock 等明确模式 | S02-R06、S03/S04 消费合同 | 标准/透明包装模式、当前 TU-static 锁覆盖切片已验收；递归/等待等通用协议仍待办，见 21 |
| S02-R08 | P4 RAII 部分 | 一个明确析构效果的 C++ scoped guard | S02-R06；锁 guard 依赖 S06-R01，另核验 C++ 事实支持 | 单指针 scoped heap guard 切片已验收；通用/锁 guard 待办，见 21 |
| S06-R02 | P5 异步部分 | 一个 queue/cancel/complete/unregister/drain 协议 | S03/S04；按实际协议选用 S03-R01、S02-R07、S06-R01 | 单工作者延迟回调、单槽队列取走/取消/停止/join 与同锁 UAF 切片已验收；单等待者条件等待/匹配通知/重获切片已接入；默认延迟取消与受限 C/glibc cleanup、同文件直接工作者 helper 切片已验收；一次无通知唤醒/受限 realtime timedwait、直接系统 realtime/monotonic clockwait、调用方 cond_wait 受限 drain 切片已验收，实测见 21；未覆盖唤醒序列/取消模式/通用 drain 与完整 RAPI09 仍待办，见 21 |
| S07-R01 | P5 增量部分 | 新访问者／回调／否定性依赖的完整失效与对照 | S02-R02/R05/R06、S04；对已支持协议接入依赖 | 当前协议/头文件否定性依赖切片已验收；直接 pthread 回调、受限队列、等待通知、cleanup 和工作者 helper 体/目标/返回/取消点/根契约失效与冷热对照切片已验收；等待结果的截止时间/谓词/宏、显式时钟选择/定义及根契约、调用方等待谓词/通知/回调与释放顺序对照切片已验收，完整调度仍待办，见 21 |

首批链路：`S02-R01 → R02 → R03 → R04 → R05 → R06`；完整 ID 均为 `S02-Rnn`。后续按缺口进入 S03-R01、S02-R07、S06-R01/S02-R08，再选择需要的 S06-R02。S07-R01 可随已支持协议推进，不要求先完成全部异步模型；回调专属验收在对应 S06 事实可用后完成。

依赖表示可消费的事实/接口，不要求 S01/S03/S04 整包先“完成”，也不新建审批或冻结阶段。首批可利用现有单构建切片；跨 TU 必须由 S01 提供真实链接目标证据，不能用不同 TU 的 BuildContext ID 字面相等代替兼容性证明。S03 路径和 S04 重放、业务声明、最终裁决继续由原包拥有；本专项只扩展所需契约、缺失义务和专门 provider。S05 动态复现按缺口复用，不是所有契约核验的前置。不得以本计划调整或中断另一会话的当前实施顺序。

## 3. 首批 P0/P1：单构建、同 TU、直接调用

目标是低误报地扩展已有包装器核验，并解释“为什么没有被识别/核验/消费”。不把名称启发式或 LLM 分数提升为确定效果，不改变漏洞终态，不新增 public YAML。

### P0 · S02-R01/R02：接续点与覆盖（2–4 人日）

- **S02-R01（1–2 人日）**：读取实施时最新 S04 反馈接口、代码 diff 和对应 Linux 证据，核对 `assess_protocol_candidate`、回答 revision 及消费者能力。不重做已交付反馈切片，也不要求长期重复审计；本次文档阅读不算该实施接续任务完成。
- **S02-R02（1–2 人日）**：复用 `orchestration/global_modeler.py: GlobalModelStats`、`semantic_modeling` diagnostics/publication、engine coverage 和 report metadata，按接口/调用点分别记录 not_seen、proposed、schema_only、source_verified、manual_assumption、unsupported、stale/conflict；先核对已有字段，只补缺失。区分“契约不存在”和“契约已知但消费者关闭/不支持”。
- **验收**：RAPI01。一个接口可回溯符号、构建、提案来源、核验器及拒绝原因；未知调用、未检查返回值、项目遮蔽标准同名接口、缺 native receipt、入口未覆盖的 cleanup 都不能被零告警掩盖。诊断不逐调用复制大段源码。
- **风险**：状态重复计数或与漏洞最终状态混用；应复用既有统计和 coverage，而非另建模型库、候选库或新调度器。

### P1 · S02-R03–R06：受限 native 值流增强（8–15 人日）

| 子任务 | 范围与修改落点（路径相对仓库根） | 可验证完成条件 | 人日 |
|---|---|---|---:|
| S02-R03 | 复用 `native/clang-indexer/ProgramEvents.h` 的 defs/uses/call-result/return/guard；在 `semantics/contract_compiler.py`、`call_context.py` 适配函数内值流 | return/out-param/参数/字段保持 USR、站点、构建与分支条件；缺值、跨帧、复杂转换为 unknown。缺事实才改 native，改后真实重编译，不使用旧工具验收 | 2–4 |
| S02-R04 | 扩展 `derive_contracts`、`contracts/contract_conditions`；只接受标准、人工或已核验根契约的直接调用、局部别名、两层包装、显式成功码、失败清理及受支持字段输出 | 资源义务与 fresh/no-alias 资格分开；借用备选返回、外部保存、不透明调用、返回前释放分别记录。LLM 声称 logging 无害不能消除未知副作用；token/native 结果冲突不回退弱路径授权 | 3–6 |
| S02-R05 | 沿 `compile_snapshot → user_config_workbook/store → ContractRegistry` 发布屏障，检查 Regex/Clang/Graph/KnowledgeDB/SecurityMap/Validator 现有消费者 | 同对象、guard、domain、authority 一致；错误池不解除义务；schema-only 高分不能授权；未支持的 carrier/mode/transition 显示缺口。核对标准失败条件，单条 disabled 不抑制 backend signal | 2–3 |
| S02-R06 | 优先扩展现有 wrapper、acquisition carrier、contract chain、build scope、incremental、source lifecycle、协议核验及规则治理测试；同步对应模块说明 | 记录 RAPI02–RAPI05 的 pass/fail/skip、工具/构建及是否受控模型；Linux 定向回归，按修改风险运行 compileall/mypy/native。规则语义变化才同步 catalog revision/CWE/Skill 契约；不机械新增重复用例 | 1–2 |

必需场景：成功/失败分支、NULL、整数成功码 out-param、`&p` 与 `pp`、字段输出、参数换位、别名重赋值、借用/新对象混合返回、错误路径清理、两个内部资源、全局保存及未知函数指针。错误分支 free 不能污染成功返回；成功返回前已释放的对象不能获得可靠 allocator 契约；out-param 状态码不能被当作资源指针。源码、头文件、参数、guard、根契约或构建改变时旧结果失效。

**首批总计 10–19 有效人日**（A0–A5 映射见任务表）：熟悉本仓库及 C/C++ 静态分析/Python 的工程人员，复用既有 native 事实、ApiContract、Registry、工作簿和 Validator，包含实现、直接相关回归及文档；部分测试工作与前项实现交叠，不重复另计。估算假设 Linux 工具链及当前 S04 接口可用，不含环境/模型服务等待、正式发行、全量准确率评测；不是日历工期或精度/性能保证。扩大到任意函数指针、跨目标、通用 RAII 等须重新估算。

## 4. 后续阶段：P2/P3 首个受限切片已实施，其余待办

### P2 · S03-R01：跨 TU 与有限函数指针（12–22 人日）

当前已实现显式真实编译/链接记录、各 TU 构建身份绑定，以及既有单槽池/留存协议在直接调用和不可变小型 ops 表上的具体路径与 S04 重放。Clang 版本、ABI、编译参数、ELF 强符号及 native 签名必须可核对；复杂库/链接形式、GCC 等未核验前端和动态可变表仍为缺口。下面保留原阶段目标与验收规格，完成范围和实际证据以 21 为准；不把此切片写成全部跨 TU/函数指针支持。

- **范围/依赖**：先一个真实链接目标内直接调用，再支持初始化可核验、目标集合封闭的小型 ops 表。依赖 S02-R06 及 S01 链接/实例证据；发现可使用调用图，证明必须携带各 TU 的身份和共同链接目标。
- **落点**：`retrieval/build_context.py`、`indexing_inventory.py`、`knowledge_db.py`、`code_index.py`；GlobalModeler/SCC、`LifecyclePaths._load`、Validator 专门 provider。链接身份补充属于 S01 合同，路径消费归 S03，不新建另一套图。
- **验收**：RAPI06、ID01–ID04。TU-A 获取/TU-B 失败清理可追溯；同名 static、不同 executable、宏变体、缺失 TU 不混用。若仅部分函数指针目标释放，效果为 conditional/unknown；目标新增/重写使摘要及消费者失效。未知目标、递归不收敛保留缺口。
- **风险**：链接记录缺失、别名集合过宽；不按名字或签名猜测确定调用。

### P3 · S02-R07：refcount、池与句柄（12–24 人日，按子域交付）

当前已交付 signed 32-bit 非原子 init/retain/drop 源码核验，复用既有池 ObjectRef、当前 callback 路径和 S04 的独立非并发/业务前提验收；小幅池扩展为成功 1/失败 0 的归还状态。真实跨 TU 与 const ops 的受限消费沿用 S03-R01。后续授权的句柄切片已扩展为 2–4 槽 signed 32-bit 自定义表：close 消费前失败/消费后报错、dup 独立描述符与共享底层对象、关闭后同值重开的新代次分别核对。handle=0、失败 dup、整数别名、错命名空间及撤回顺序独占声明均有正反例；标准 close 的平台依赖错误效果保持 unknown。RAPI07 仅上述子域已执行；unsigned/其他宽度、原子/并发、通用堆析构、OS fd/dup2/dup3、动态/数组句柄表和 arena/reset 仍待办，完整规格如下，不把切片扩张为整包关闭。

- **范围/依赖**：从一个非并发 refcount 实现和已支持池的一种小扩展开始，再处理句柄同值复用及 dup；依赖 S02-R06，跨 TU 部分依赖 S03-R01，业务责任复用 S04。子域扩张后重新估算，不能把该区间视作任意池/句柄协议全包承诺。
- **落点**：`ApiContract.protocol` 与条件 transitions、`semantics/resource_identity.py`、现有协议 verifier、资源候选和专门义务 provider。区分 retain/drop/terminal destroy、logical return、物理 free、borrow/escape。
- **验收**：RAPI07、RES03/04/09。2→1 不失效，1→0 必须核对真实析构分支/callback 及对象；覆盖失败 retain、饱和/下溢、多个别名、错误池、同地址再获取、代际回绕、handle=0、close 失败、dup 和关闭后同值重开。借用不新增清理责任，drop 不直接证明销毁。
- **风险**：原子性、并发最终释放和跨异步借用超出非并发切片，明确转交 S06，不以顺序计数证明线程安全；arena/slab reset 后置。

句柄切片的表寿命另有限制：仅消费已零初始化、native 确认为函数作用域且调用帧存活的局部表。内层块表、过期表地址、从已退出内部帧导出活句柄及堆/全局/成员表保留缺口；业务顺序独占声明不能代替这些技术事实。

### P4 · S06-R01/S02-R08：锁模式与有限 RAII（合计 10–18 人日）

S06-R01 当前已交付标准锁与透明包装器的 shared/exclusive/unknown、返回条件、EOWNERDEAD 及 cond_wait 释放/重获语义传播。受限强反证复用现有 ReviewClaimChecker 和当前编译事实，仅闭合非逃逸 TU-static 锁、一个指针参数的标准操作/直接 return 包装链及全部本地标量访问；模式、锁声明、状态分支进入签名 coverage。读锁不能过滤写入候选，失败/未知 try 不证明持锁，递归二次获取、升级、等待、成员/动态锁、任意 helper 和 RAII 保持 unknown。词法调用方摘要不再授予强反证，race 反证不能排除 UAF；两条共享访问实验规则 revision 9 继续默认关闭。RAPI08 锁模式切片及 S02-R08 单指针 scoped heap guard 已接入；正常/提前退出、明确捕获的字面量 throw、空 guard、当前简单 custom deleter 与拒绝边界见 21。move/adopt/defer/release/reset、锁 guard 和通用异常仍待办。

- **范围/依赖**：依赖 S02-R06 和 S03/S04 消费合同。S06-R01 处理标准/透明包装的 shared/exclusive/unknown、try-lock 成功条件与真实锁实例；S02-R08 处理一个明确析构效果的 C++ scoped guard，锁 guard 再依赖 S06-R01。递归深度、upgrade/downgrade 只采用明确协议；不凭名称推断。
- **落点**：`standard_api.py`、`contracts/contract_conditions`、锁图/共享状态候选、native 隐式析构事件和 Validator。C++ 管理器→资源映射需独立核验，不能把现有受限 C 路径标作已支持通用 C++。受支持 Clang/GCC 注解导入保留 annotation 来源，不把声明伪装成源码证明。
- **验收**：RAPI08、RES06、CON01–CON06。读锁不能为写入提供排他证明，失败 try-lock 不持锁、隐藏状态为 unknown；区分同名字段上的不同锁。覆盖 EOWNERDEAD、递归两次只解一次、升级、cond_wait 临时释放、正常/异常析构、空 guard 和 custom deleter；未支持 move/adopt/defer/release/reset 时保留缺口。
- **风险**：旧消费者丢弃模式字段或只凭析构事件解除义务；逐一标明消费者支持范围，未迁移者不得提供强反证。10–18 是上述两个子任务合计，不各自重复计费。

S02-R08 当前复用 native 已有的隐式析构 CFG，补充 `cxx-lifetime-facts.v1` 的管理器、构造和析构身份。既有 LifecycleAnalysis 在精确 BuildContext、同 SDK 的完整 AST 核验后解释单指针 scoped heap guard；事件标签本身不证明 free/unlock。构造仅支持 noexcept、参数→指针成员且空函数体；析构支持 free 或受限当前源码 deleter，保存原获取身份而非变量后值。异常 CFG 不总包含展开析构，明确捕获的 throw 由受限结构化 AST 解释；未知异常不补造清理。原 C 对象协议解释器及其他模式消费者仍不支持任意 C++，不增加全局 deallocator 配对。

### P5 · S06-R02/S07-R01：异步清理与完整增量

首个协议按用户选择采用 Linux pthread 单工作者队列。目前以当前 CFG 解释单槽堆队列和调用方 helper，工作者取走并解锁时保留局部引用，在 join 中继续；清空槽位和关闭接收不代替实际完成，同锁不能消除串行 UAF。opaque mutex/cond 的系统类型收据已由真实重建的 native 工具提供。只覆盖默认属性、成功结果和有界调度；后续已接入单等待者 cond_wait 的释放/通知匹配/重获与谓词重检，通知不等于完成，提前通知不积存额度。未覆盖唤醒序列、一般超时/时钟、调用方等待、取消模式切换/任意取消点、一般工作者 helper、动态目标和多工作者均保留缺口。对应源码 helper、访问及释放顺序/根契约变化的局部冷/热对照已接入 S07-R01；完整阶段规格与待办仍按下列条目执行。

- **S06-R02（15–30 人日）**：在 S03/S04 事实基础上选择一个 queue/cancel/complete/unregister/drain 实际协议；按场景依赖 S03-R01、S02-R07、S06-R01，按需复用 S05。落点为共享/回调事实、protocol summaries、`security_map/active_discovery` 和专门 provider。验收 RAPI09：cancel 与 complete 互斥/可并发、同代/异代、回调已开始未结束、仅禁止新回调与实际 drain、join 后释放都可区分；同锁排除 race 不能同时排除串行 UAF。未知调度或输入不变成安全结论。
- **S07-R01（6–12 人日）**：复用现有 semantic_demand/modeling、dependency manifests、snapshot policy 和 S04 回答 revision 失效，新增访问者、调用者、回调目标集合及“无其他清理”等否定性依赖。验收 RAPI10、INC01–INC05：添加/删除消费者、改变目标/构建/根契约/业务回答后，受影响契约与结论重算；全量与增量的候选、最终状态、未决及覆盖语义一致。已有业务答案失效不重做；回调特有对照在对应 S06 事实就绪后验收。

当前增量切片复用原 S04 回答/链接失效链，补 CompleteFactStore 的当前预处理复核、live Registry 依赖和 native `include-probes.v1`。存在性查询独立于读取内容，查询结果进入 BuildContext；标准头文件的符号链接按真实路径/摘要核对。热路径不重建 AST/CFG，但仍有实际预处理成本。统一裁决上的局部全量/增量对照不能替代完整扫描、异步回调集合或 INC05 需求调度验收；实际阶段结果见 21。
- **风险**：状态空间、否定性依赖范围和成本；先一个有界协议，报告不完整原因，不承诺未经基线验证的加速或召回不变。

## 5. 验收编号与可观察结果

本表是验收规格；RAPI01–RAPI05、RAPI06 受限链接/const ops 及 RAPI07 的非原子计数/池状态、有界自定义句柄表的实际运行见 [21](21_IMPLEMENTATION_STATUS.md)。RAPI07 的平台/通用子域、RAPI08 的复杂 RAII/锁 guard/通用锁协议仍待办；RAPI09 已有单工作者延迟回调与单槽队列切片，含活动任务引用、取消/停止、join drain 与同锁 UAF；单等待者 cond_wait 释放/匹配通知/重获已有切片，一般唤醒/超时场景、取消模式切换/任意取消点、通用 unregister/drain 与多工作者仍待办；RAPI08 锁模式/单指针 scoped heap guard 及 RAPI10 当前协议增量切片见 21，完整增量尚未关闭。[16 验收场景](16_ACCEPTANCE_TESTS.md) 只索引本表，避免维护两套细节。已有 RES/VAL/CON/INC 场景继续复用，不按编号机械造重复测试。正例分别验证应建立的契约与应保留的风险；反例验证不得授权的强效果与应排除的假路径，不只比较告警条数。

| ID | 关联任务 | 最小可观察结果与反例 |
|---|---|---|
| RAPI01 | S02-R01/R02 | 符号/构建/出处/核验器/拒绝原因/未消费范围可追溯；项目同名标准 API、缺事实或模型失败不变成已核验或安全 |
| RAPI02 | S02-R03/R04/R06 | return/out-param/字段/参数和 `p/&p/*pp` 保留同一对象与条件；重赋值、混合借用返回或未检查状态不能错误建立获取效果 |
| RAPI03 | S02-R04/R06 | 成功/失败及部分清理分别解释；借用、外部保存、返回前释放、额外资源与未知调用不被“内部调用 malloc”或 LLM 高分抹掉 |
| RAPI04 | S02-R05/R06 | 工作簿重载及各消费者的 object/guard/domain/authority 一致；不支持的效果保持 unknown，错误池和 schema-only 不能解除义务；新规则禁用不抑制 backend signal |
| RAPI05 | S02-R06 | 源码/头文件/构建/根契约/条件变化使旧核验失效；原样热复用不触发不必要核验，须以实际行为记录，不能修改完成标记充数 |
| RAPI06 | S03-R01 | 单目标跨 TU 和有限 ops 表的对象映射可追溯；同名/多目标/宏变体不串线，部分释放目标不能证明全体调用，新增目标触发失效 |
| RAPI07 | S02-R07 | retain/drop/terminal destroy/逻辑归还分离；2→1、借用、错误池、代次回绕、dup/同值重开不被折叠为立即释放或同一对象 |
| RAPI08 | S06-R01/S02-R08 | shared/exclusive/try 成功条件与真实锁一致；RAII 管理对象/资源/析构分支对应；读锁、空 guard、失败 try、未知 deleter 不得给出强保护/释放证据 |
| RAPI09 | S06-R02 | 共同可达、执行上下文和清理唯一性有见证；仅取消标志/禁止新回调不能替代 drain；同锁不能排除串行 UAF，缺口进入 S04 |
| RAPI10 | S07-R01 | 新访问者/回调/否定性依赖/答案 revision 使旧结论失效；同版本全量和增量的候选、终态、未决与覆盖一致，无关变化不伪造新的证明权限 |

## 6. 低误报约束、默认开关与暂缓项

每个新增效果必须同时保留资源族与实例、载体、成功条件、构建/符号、对象/池/代次、出处与核验权限；配对是条件化有向关系，不能退化为函数名一对一映射。自动推断与契约消费分别验收，契约 schema 可表达不等于所有引擎已支持。技术 unknown、业务假设与确定源码效果分开；S04 统一裁决仍是唯一终态入口。

不改变已有默认开关。新增确定性规则按目录/资格和正反例逐项决定，首批不默认开启两个实验性对象协议规则；后续实验结果也不能写成正式准确率。新增模式未消费时应显示缺口，不能以旧消费者省略字段的结果消除风险。

首批暂缓任意函数指针和跨目标证明、无种子通用统计挖掘、任意 arena/slab/reset、并发 refcount 全证明、无锁/RCU/弱内存、复杂 C++ 模板/RAII、SVF 自定义模型桥接、外部求解器和外部 Agent。此轮不创建或运行缺陷注入评测集；将来独立质量评估另按授权确定真实接口清单、独立标注与答案隔离，分别衡量发现覆盖、已核验契约精度、未知、错误解除义务及最终误报/漏报，不虚构现有指标。

行业方法取舍沿用独立报告的一手资料核验：K-MELD 的 52% 是泄漏告警误报率，不能当配对错误率；CAFD 的无副作用标准分配包装器不是任意池/释放/锁协议。Clang ownership/TSA、GCC malloc(deallocator,index)、Cppcheck cfg、CodeQL Allocation 的声明/模型消费与自动推断分别看待；不将 Java/C# 研究结论迁移为 C/C++ 已有能力。不下载执行外部工具，不给产品增加网页访问功能。

## 7. 后续交接与本次验证限制

接手顺序：读最新 [21](21_IMPLEMENTATION_STATUS.md) → 本章对应任务 → 独立报告的代码/测试矩阵 → 当前调用方与 diff。实际实现按根 AGENTS 的 Linux/native、规则目录及文档要求执行；共享 native/schema/消费链的修改需按依赖组织，避免同一工作树相互覆盖。记录任务 ID、实际范围、代码/工具版本、pass/fail/skip、未完成消费者和下一步；规划登记不关闭实施任务。

原计划编辑阶段遇到 `Wsl/E_ACCESSDENIED`（失败后记录时间 `2026-10-13T02:34:29.0787732Z`）；用户明确指出最终 diff、链接及原文保留校验也未完成，不能把原文中的检查范围视为通过。实施接续时重新保存六份原文、核对链接/编号/编码和独立评估摘要，并在正常可用的 WSL 执行产品验证，实际结果见 [21](21_IMPLEMENTATION_STATUS.md)。此前编辑前没有可用副本的部分不能补造原文保留证明；历史记录不倒写成新成绩。

S06-R02 的默认延迟取消子切片复用 native CFG/对象身份与 S04：仅 Linux glibc LP64 C 默认宏形态，cond_wait 在取消清理前重新取得原 mutex，testcancel 只在请求待处理时投递；cleanup 保存注册时的参数对象，最多四层，同 TU void(void*) 回调重放真实体。注册/注销由当前系统宏 token、展开 AST、调用身份和精确 BuildContext 核对，原始 CFG 保留；不凭宏名或注解推定清理。返回、break/continue/goto 跳出、宏改写、异常/C++ 宏变体、cleanup 内 helper/任意取消点和模式切换保留缺口。取消请求、清理执行、工作者结束与成功 join 分开；物理 free 与 unlock 取决于实际回调路径。S07-R01 对应局部冷热对照已验收，完整协议仍待办。

工作者普通 helper 的首批边界为同一 C 文件、同构建、当前直接目标/签名/CFG，参数和返回是已知堆根指针或受限整数；调用深度、循环和步骤继续有界。普通 helper 内的 unlock/cond_wait 可暂停整条工作者栈，重复调用隔离帧，取消区分中断位置和清理注册帧，不生成取消后的返回值。实际 free 仍由当前标准根和对象状态判断。递归、局部/字段地址、未知或间接目标、cleanup 内 helper、跨 TU/多工作者继续待办；相关 RAPI09/RAPI10 实测见 21，当前无告警不授权安全。

有界等待结果切片在默认通知路径未闭合时增加一次无通知唤醒与（仅核验 timedwait/clockwait 时）独立超时路径，最多三条路径且每条最多一次无通知返回。选择实际非法访问，次选闭合路径；无候选/有限闭合不授权安全。当前 native 收据绑定系统 timespec、直接本地地址及 ETIMEDOUT 宏出处；秒数非负、纳秒合法且默认 CLOCK_REALTIME，超时携带时钟不早于截止时间的约束，返回 0 不添加时间先后假设。重获 mutex 后发布结果，按当前 CFG 重检谓词；取消优先不返回，探索结束仍检查源码/契约当前性。RAPI10 随此范围核验截止时间、谓词/宏/根契约与 drain 改动；一般时间来源、多次唤醒/通知竞争、多工作者及通用 drain 仍待办。

等待截止时间还须核验当前 timespec 的大小、对齐及字段偏移；`-fpack-struct=1` 等布局变化、v1/v2 旧收据或伪造布局均不能授权 timedwait。v3 收据来自真实重建工具；合成篡改仅验证隔离，布局反例必须真实提取。

直接 clockwait 切片复用标准 API v7、timespec ABI、重获锁/取消清理及 S04 重放链；`pthread-wait.v3`/`pthread-deadline.v3` 核验直接系统 CLOCK_REALTIME/CLOCK_MONOTONIC 展开、当前值及调用参数。正反例覆盖两个时钟、超时/0 返回、通知/取消/helper/join、常量重定义/包装/变量/转换、旧或缺收据、ABI 布局和业务回答撤回。0 返回不证明早于截止。RAPI10 核对时钟选择/定义、谓词、根契约和 drain 的旧收据撤回及两 TU 冷热一致；实际结果见 21。一般时间来源、自定义时钟、多次唤醒与完整调度继续待办。

RAPI09 调用方等待切片验收：真实 native 条件变量与 mutex 身份、释放/匹配通知/原锁重获、嵌套 drain helper、重复通知下 while 重检与 if 误退、提前清零标志后 UAF、free 后等待、join 修复和取消 cleanup 范围。相同条件变量的不同锁绑定、无通知/提前通知、无持锁、调用方超时及超限保持缺口；等待返回不自动授权同步存储销毁。路径保留入口到 helper 及实际工作者/cleanup 边，S04 重新核验、业务回答撤回和 JSON 不授权；实验默认关闭。RAPI10 对照 helper 谓词、通知删除、回调目标、根契约与释放次序，核对实际冷热 TU 数、完整路径/候选/裁决/未决/覆盖。只覆盖至多四次调用方匹配通知等待，当前静态切片不代替真实线程执行、Sanitizer 或完整调度验收。
