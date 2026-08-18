# Z-Scope 2.0 Security Architecture

本设计包是Z-SCOPE 2.0安全架构改造的规范来源，覆盖可审视的Security Spec Mining、
Hypothesis-driven Hunting、内部Proof Engine、旧运行时清理以及Benchmark v5。

## 当前状态

- 设计版本：`1.0.1`
- 状态：`implementing`
- 当前阶段：`P0`至`P3`已完成；`P4 hypothesis-driven-hunting`已完成产品实现和本地资格冻结，正在执行完整门禁与双角色最终审核，`E0`仍为`pending`
- 当前产品事实：仍以[`docs/architecture.md`](../../architecture.md)为准
- 基线状态：已拆分为Truth、运行配置、Scorer和产品四个可审计提交，工作树干净
- P0批准状态：cold fast/balanced基线、三方正式审核、最终证据校验和annotated design tag均已绑定
- P1完成状态：候选commit/tree已通过冻结replay、公共入口、wheel/import graph、Black和`claude-opus-5`只读product architecture审核；零blocking finding。测试通过与正式审核记录分别登记
- P2完成状态：Proof Kernel资格 corpus、完整门禁和DeepSeek `deepseek-v4-pro`最终proof-security审核已通过，零blocking finding；运行时仍固定为shadow，P5之前不得取得authority
- P3完成状态：SecuritySpec v2资格、只读Review Center和双角色审核已通过，运行时继续保持shadow
- P4实施状态：SecurityHypothesis v2、系统offer/action选择、独立shadow Ledger/CAS、selected-action Checker和120单元非Range qualification已落地；现有active discovery与稳定终态在P5前保持不变，未通过双审核前仍为`in_progress`

## 权威文件

- [目标架构](architecture.md)
- [数据与接口契约](contracts.md)
- [2.0淘汰计划](deprecation-plan.md)
- [Benchmark v5](benchmark-v5.md)
- [实施治理](implementation-governance.md)
- [阶段规格](phases/P0-baseline-and-design-freeze.md)
- [验收证据索引](acceptance/evidence-index.json)
- [P0三方审核schema](acceptance/p0-review.schema.json)
- [P0正式审核记录](acceptance/reviews/p0-product-architecture.json)
- [P1 product architecture审核schema](acceptance/p1-review.schema.json)
- [P1 product architecture审核记录](acceptance/reviews/p1-product-architecture.json)
- [架构决策记录](adr/0001-replace-vulnerability-analyzer-with-hypothesis-hunter.md)
- [Proof provider量词冻结](adr/0007-freeze-proof-provider-quantifiers.md)

## 状态机

`draft -> reviewed -> approved -> implementing -> validated -> superseded`

只有`design-manifest.json`绑定clean baseline、全部规范文件hash及正式审核记录后，状态才能从
`reviewed`进入`approved`。批准后的契约变更必须新增ADR，并把受影响阶段重置为`pending`。
最终annotated tag消息同时绑定design manifest、evidence index和三份正式审核记录的SHA-256；
这避免manifest与evidence index互相包含当前hash所形成的循环依赖。

## 不变量

1. 产品代码、Range truth/fixture和Scorer不得在同一普通变更中共同演进。
2. Hypothesis Hunter只能登记假设，不能直接确认漏洞。
3. 只有程序可重放的proof/counterproof能够直接产生`confirmed`或`rejected`。
4. 用户可以审视和覆盖部署语义，但不能改写程序事实或直接确认finding。
5. matcher v2不为保持历史召回而放宽；Range只作分布内诊断。
6. 产品运行时不设置scan-wide token硬上限，成本只观测和评测。
