# Z-Scope 2.0 Security Architecture

本设计包是Z-SCOPE 2.0安全架构改造的规范来源，覆盖可审视的Security Spec Mining、
Hypothesis-driven Hunting、内部Proof Engine、旧运行时清理以及Benchmark v5。

## 当前状态

- 设计版本：`1.0.0`
- 状态：`reviewed`
- 当前阶段：`P0 baseline-and-design-freeze`
- 当前产品事实：仍以[`docs/architecture.md`](../../architecture.md)为准
- 基线状态：已拆分为Truth、运行配置、Scorer和产品四个可审计提交，工作树干净
- 进入`approved`的阻塞：cold fast/balanced基线已冻结，但三方正式审核尚未完成；详见`design-manifest.json`

## 权威文件

- [目标架构](architecture.md)
- [数据与接口契约](contracts.md)
- [2.0淘汰计划](deprecation-plan.md)
- [Benchmark v5](benchmark-v5.md)
- [实施治理](implementation-governance.md)
- [阶段规格](phases/P0-baseline-and-design-freeze.md)
- [验收证据索引](acceptance/evidence-index.json)
- [架构决策记录](adr/0001-replace-vulnerability-analyzer-with-hypothesis-hunter.md)

## 状态机

`draft -> reviewed -> approved -> implementing -> validated -> superseded`

只有`design-manifest.json`绑定clean baseline、全部规范文件hash及正式审核记录后，状态才能从
`reviewed`进入`approved`。批准后的契约变更必须新增ADR，并把受影响阶段重置为`pending`。

## 不变量

1. 产品代码、Range truth/fixture和Scorer不得在同一普通变更中共同演进。
2. Hypothesis Hunter只能登记假设，不能直接确认漏洞。
3. 只有程序可重放的proof/counterproof能够直接产生`confirmed`或`rejected`。
4. 用户可以审视和覆盖部署语义，但不能改写程序事实或直接确认finding。
5. matcher v2不为保持历史召回而放宽；Range只作分布内诊断。
6. 产品运行时不设置scan-wide token硬上限，成本只观测和评测。
