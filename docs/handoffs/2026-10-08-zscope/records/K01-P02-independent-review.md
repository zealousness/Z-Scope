# K01 / P02 独立只读审查

日期：2026-10-08。审查者：Agent C。实现所有者：K01 为 Agent A，P02 为 Agent B，共享入口与裁决接线为总控。

review_status: static_review_complete_pending_G2

verification_status: not_run

本记录属于实现中的静态交叉审查，不是 G1 / G2 测试证据。审查期间实现仍在并行修改，下面的摘要仅定位当时读到的内容，不宣称冻结。Agent C 未修改产品、测试、模块文档、TASKS.yaml 或 PROGRESS.md；没有运行模型、外部服务、sanitizer、容器、Range 或重型测试。

## 已核对范围

- 根 AGENTS.md、架构与执行编排导航、WORK_PACKAGES 的 K01 / P02，以及相应验收边界。
- K01 schema、源码绑定、条件资格、Registrar 投影；单入口和批量入口中 candidate-blind 调查之后、Ledger 冻结之前的接线。
- P02 按需计划及其输入、SCC / callee 闭包、语义建模入口、实际调度和发布审计。
- 公共 ValidationRunner / ValidationPipeline 中 shadow、Validator disabled、确定性 proof、模型裁决和故障路径。
- 相应新增测试文本；此处读取测试不计为测试执行。

## 静态审查结论与反馈

| 编号 | 发现与影响 | 所有者与当前状态 |
|---|---|---|
| P02-R1 | `_plan_demand` 原先仅包住最终 planner 调用；registry、人工契约、SCC 和 contexts 准备在 try 之外。shadow 辅助准备失败可能在 `_schedule` 之前中断实际建模。 | B 已修复整个辅助准备的异常边界，保留取消传播，并新增首轮 SCC 准备失败后正常调度的负例。C 已静态重读修复；执行结果待 B / 总控。 |
| P02-R2 | D03 supplemental 原先按 symbol 与 code hash 关联，不能由此认定项目、revision 或 build 当前。 | B 已保留 map project / revision，并标记 `current_project_revision_build=unverified` 与 `supplemental_context_unverified`。C 已静态重读；这些行仍只是 advisory，不授予证明或跳过权限。 |
| K01-R1 | `ObservationBinding` 保存 modeling spec，但初版检查器不接受当前 spec / 模型输入。旧 live result 在主文件不变、header / build / schema 或模型输入改变后，仍可能被当作 current。另一个具体子例是 attach_contract 的自定义 schema 改变：默认 effective schema 摘要不变，实际自定义 schema 却变了。 | A / B 已加入模型执行前捕获的 live 输入核验 callback、publication / 注册复核，以及实际 shadow schema 摘要。cache hit 不重授 binding，无法重导 custom schema 不授 binding。C 已静态闭合，详见末节；执行数量仍由所有者 / 总控记录。 |
| K01-R2 | 初版入口路由终点只比较 name / file，未比较完整 SymbolIdentity，可能将同文件同名不同签名的 overload 路径归属到错误对象。 | A 已对绑定 snapshot 与路由终点检查完整 SymbolIdentity.key，并新增 wrong_overload / wrong_file 等负例。C 已静态闭合，待最终 G2 执行。 |
| K01-R3 | 普通 disabled 路径已有 shadow gate，但反馈 / static gate 的 `PreValidationDecision` 在此前返回默认 observations；Validator 失败也无 shadow gate，直接返回 engine_failed observations。sole K01 shadow 可能从这些路径进入默认观察列表。 | 总控已修复反馈 wrapper 与故障分流，并集中 sole K01 helper。C 静态重读确认空 report bucket；反馈保留 shadow_feedback_kind，失败保留 operational / engine_failed 原因。总控新增五条早退负例，执行结果待总控。 |
| K01-R4 | Runner 在末尾将全部父项传入 RelatedCandidateRegistry；sole K01 shadow 父项的有效 related proposal 被转换为 validator_related_discovery / llm_observation，未继承 shadow，可能经附加 Ledger 进入默认发现列表。 | 总控已在 registry 消费与任何附加 Ledger / state 写入之前过滤 sole K01 父项。C 静态重读确认 mixed / legacy 条件未变；新测试先验证有效 proposal 经真实 registry 能产子项，再验证过滤后零 state 变化。执行结果待总控。 |
| SHARED-R5 | 总控发现旧 report 的 resume / maintain 复用可能跳过新开启的实验或重新采用历史实验报告。 | 总控新增 `semantic_experiment_requires_scan`，单入口 maintain 与批量 resume 均调用。C 静态确认当前任一 shadow 或历史非空实验 metadata 都禁止复用；off 且无历史实验 metadata 不改变原判断。真实存储测试扩为当前 / 历史 snapshot / demand 与新旧 policy 共十组合，执行结果待总控。 |
| K01-R6 | 总控进一步发现仅给 compile_commands.json 做摘要不足以覆盖命令引用的外部 `@response` 文件或 `-include` 文件；主源码无 include 且数据库本身未变时，外部文件变化可能逃出 inventory。 | A / B 已保守拒绝任意显式 compile_commands_path（含自定义名称）及 inventory 中的 compile_commands.json；并拒绝 Java classpath 源文件 / 产物与非空编译环境身份。C 已静态复核这一收窄资格，没有新增参数解析器；待最终 G2。 |

当前静态可确认的不变量：

- 两个 RuntimeSpec 开关默认均为 off，只允许 off / shadow，未加入 public Config v2。
- P02 off 在 planner 导入或输入读取前返回；shadow 计划结果没有替代 `_schedule` 的执行集合。SCC、callee、重试、cache 和发布机制继续使用既有路径。
- P02 未选择项仍为 unknown；未知用量仍为 unknown，不输出虚构的省时、token 节约或安全证明。旧 map 与源码不匹配 map 不作为有效 coverage 绑定。
- K01 使用独立 `conditional_observations` schema；模糊旧 `suspicious_points` 保留背景。候选是固定白名单投影，并通过原 Registrar 的 `force_unconfirmed=True`，无外部 proof / terminal verdict 自证入口。
- K01 注册发生在 candidate-blind 调查结束后；批量验证仍在注册结束后冻结主 Ledger，未观察到为 shadow 解冻主 Ledger 的代码。
- 公共裁决在模型 confirmed / uncertain / rejected 及确定性 proof 路径上先保护 sole K01 shadow；Validator disabled 的正常 `apply_unvalidated` 返回空 report bucket。混合可信来源保留其原资格。反馈 / 失败旁路见 K01-R3。

## 审查时内容摘要

这些摘要来自 Windows 只读 `Get-FileHash -Algorithm SHA256`，用于记录代码版本，不是 Linux 测试结论。后续最终 G1 / G2 必须另取冻结输入与前后摘要。

| 文件 | 当时 SHA-256 |
|---|---|
| zscope/orchestration/snapshot_observations.py | 4e85f286b80601eb72fe194c07e33a0b76b7e97d542ee287b6826ff9cc3ac4f2 |
| zscope/orchestration/snapshot_candidates.py | 215089096172cfbe9fd92d96757ac737d146d09502747859ade8312ba9dd4abc |
| zscope/orchestration/semantic_demand.py | dab3f43eedb96c2458d2e0765ccb4b3c4e28401784bafcb81ffe18c0ead057b5 |
| zscope/orchestration/semantic_modeling.py | 59c3737273d4c1f6eb612f0a22439f80b481700b45046203ce5086f3dc3aa244 |
| zscope/core/validation/pipeline.py | 2b7854bb0755cb9dc6d996b12e152e8b37a8767160c424d8039bed5225df576a |
| zscope/core/validation/runner.py | b8341a8ae6627e3c23e17ec2a5c96d9a1645f798352f9f0270e3427d3e95f45d |

## 执行状态

本轮只执行 `git status --short`、`git diff -- <指定文件>`、`rg`、UTF-8 `Get-Content`、`Test-Path` 与摘要读取。无任何测试或 fixture 执行。一次对不存在的报告目录搜索退出 1，仅表示没有该目录中的匹配，不是产品测试失败。

| 验证项 | passed | failed | skipped | not_run |
|---|---:|---:|---:|---|
| C 独立产品测试 / fake 复现 | 0 | 0 | 0 | 全部，当前任务仅只读审查 |
| C compileall / mypy / 交接文档测试 | 0 | 0 | 0 | 全部，交由总控冻结后统一执行 |
| 真实 LLM / 性能收益 / sanitizer / 外部工具执行 | 0 | 0 | 0 | 全部，未授权本审查执行 |

包括总控最后追加的 K01-R6，本记录列出的静态发现均已完成代码复核；代码修复不等于测试通过。任务整体状态由总控据 G1 / G2 与工作包必需验收更新，本记录不将 K01 或 P02 标 done。

## 共享边界修复后的追加静态复核

以下摘要对应 K01-R4 / SHARED-R5 修复后的只读复核版本；A / B 的 freshness 接口仍在实现中，未要求全局冻结，未执行独立测试。

| 文件 | 追加复核 SHA-256 |
|---|---|
| zscope/core/validation/runner.py | bd4fa0678e2f1cb7a9fbbe49be1d0c764dda623562f8948119b252dbeaac28c7 |
| zscope/core/validation/pipeline.py | 3d55c53ee8ccfc4fb49bcca6edf7646bf779f1d622262742ca09565c3c4c9f88 |
| zscope/snapshots/policy.py | d3575ed5a75389052a4c0eda7379512091b6298cde8c5bcd3af3b5d74fe99f94 |
| zscope/orchestration/scan_session.py | fe168c7ccefce9105b535201317b3ea11385eedd8435efd8ff05b5f76f7e929b |

新增专项测试文本同时覆盖 disabled、人工反馈、baseline、static gate、engine failure 与关联发现过滤；普通 disabled 与模型 / proof 裁决仍走原 shadow gate。没有在这些共享修复中发现新的阻断项。执行通过数量仍须由总控的 Linux G1 / G2 记录提供。

## K01 输入资格与完整符号身份最终静态复核

A / B guard 接口落稳后已继续只读复核，未新增或执行测试：

- `bind_snapshot_observation` 要求进程内 callable 与执行前 expected digest；没有 guard、guard 不一致、序列化副本或新复制 binding 均没有 current 资格。
- 发布和注册重新调用 guard。guard 核对当前 modeling spec / 默认 effective schema、非密钥模型参数、原 record inputs、当前手工工作簿、本地输入清单、上下文与 callee outputs；主源码不变也不能掩盖头文件、编译数据库、模型或人工契约变化。
- 本地 inventory 使用原 ProjectSourceAccess 的许可、文件身份与预算；缺失、符号链接、扫描不完整、无法闭合的外部 include 返回不可核验。它只是本地 source-only 观察的资格，不是 TU / effects proof。
- 新 receipt 仅在新模型调用之前产生。热缓存继续复用原语义建模机制，但不会从持久 snapshot 重建观察权限。有效 custom schema 摘要进入 shadow inputs；无法无副作用重导其身份时不授 binding。
- 路由终点和 snapshot 均与完整 SymbolIdentity.key 匹配，错误 overload 不再仅凭相同 name / file 通过。
- 读取的专项测试文本覆盖模型 / 头文件 / 编译数据库 / 人工契约变化、custom schema 变化、cache-hit 无重授、wrong_overload、JSON / clone、最终注册重核和不完整输入清单。

上述保守拒绝会降低实验观察覆盖，必须保留不可核验原因，不得解释为工程安全或宣称任意工程已验证。此轮静态复核后总控追加的 K01-R6 外部编译输入缺口已由 A / B 通过保守拒绝资格关闭；其他已闭合项不再扩大审查范围。

| 文件 | 最终静态复核读取 SHA-256 |
|---|---|
| zscope/orchestration/snapshot_observations.py | b8ea4e9511a218e20ee510102498cb396a57593dd1357e76422ef896399b59ab |
| zscope/orchestration/snapshot_candidates.py | 34f788fb2d55fe713035256a19569bd182d9ddd594bcfc118285c3d2cb0ab219 |
| zscope/orchestration/semantic_modeling.py | 97292e3021fb0a0540d66ebed694ccadf483a493d997bb8fd4e50f0aadfff17c |
| zscope/orchestration/semantic_demand.py | dab3f43eedb96c2458d2e0765ccb4b3c4e28401784bafcb81ffe18c0ead057b5 |

一次按推测文件名查找 `tests/test_snapshot_conditional_observations.py` 返回不存在（退出 1），随后通过 `rg --files` 找到实际 `tests/test_snapshot_observation_shadow.py` 并读取。该检索失败不属于测试执行或验收失败。C 本轮测试计数仍全部为 not_run。

K01-R6 追加复核：`observation_project_inputs` 发现默认名称编译数据库即拒绝，`_observation_receipt.current` 发现任意显式配置数据库即拒绝，从而覆盖自定义名称；不尝试以未变数据库文本推断 response / forced include / sysroot 文件当前。专项测试文本包含 `-I`、`@response`、sysroot、`-include`、`-imacros`、空数据库、Java 与 CPATH 负例。A 报告其 54 项专项通过，本记录仅转述所有者结果，C 未独立执行。

该追加读取的 `snapshot_observations.py` SHA-256 为 `88635c1bc15bde9980d43cb10d063cb19d5b4dfbd637ab1e827710c19485345f`；`tests/test_snapshot_observation_shadow.py` 为 `ea9025dea89ad95cb0149eff980170ff3aa03a002f873f4cbfd89377a51ed07f`；`semantic_modeling.py` 为 `61d1da82aeea55ade5c2ef16aed2018bd33d4c6845e17bd7b6be8dbff0c6e4e1`。最终 G2 仍应使用其实际冻结 manifest。
