# P4：Hypothesis-driven Hunting

## 目标

以攻击面和局部coverage gap驱动Hypothesis Hunter，恢复并强化主动挖掘，但不把Agent变成终态权威。

## 进入条件

- P2 Proof Engine可消费hypothesis。
- P3能提供SecuritySpec及unknown/conflict。
- CandidateRegistrar和Ledger freeze支持新hypothesis schema。

## 工作包

1. 实现attack-surface和LocalizedCoverageKey planner。
2. 实现Hypothesis Hunter及严格candidate-blind projection。
3. 输出defect family、subject、region、正反clause和EvidenceAction IDs。
4. 不完整输出只进入coverage observation。
5. 合格hypothesis经Registrar进入Ledger，全部发现结束后显式freeze。
6. usage、trace和coverage记录使用`hypothesis_hunter`身份。

## 验收

- candidate-blind同时检查key和scalar value。
- Prompt不含candidate、rule、truth、score或历史verdict。
- 同family不同函数不会全局抑制。
- 缺位置、subject、region或证据的hypothesis不能注册。
- Hunter不能直接改变默认视图。
- 同cluster/alias只调查一次。
- 至少三个非Range项目或结构家族产生有效、可证明假设。
- rename/wrapper/等价重排后能力稳定。
- 无信号时coverage trace记录具体原因。

## 停止与回退

发生答案泄漏、直接promotion、仅Range有效或metamorphic显著退化时保持shadow并停止P5切换。
