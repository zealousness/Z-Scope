# P4：Hypothesis-driven Hunting

## 当前实施状态

入口契约与产品实现已冻结，阶段仍为`in_progress`，等待完整门禁和双角色最终审核。P4采用独立shadow Candidate Ledger：复用同一
`CandidateRegistrar`和显式freeze语义，但不接入live验证队列或报告投影。现有
`active_discovery`继续承担稳定产品路径，直到P5执行公共cutover。

Hunter只选择系统生成的`HypothesisOffer v2`和其中已经绑定的`EvidenceAction v2`。模型不能生成
predicate、参数、coverage或终态。缺字段和无信号结果只写入内容寻址的coverage observation。

### 入口冻结矩阵

| 对象或边界 | P4冻结语义 |
|---|---|
| `LocalizedCoverageKey v2` | 绑定function、defect family、subject、region和结构fingerprint；不得按family全局抑制 |
| `AttackSurfaceAuditUnit v2` | 只由攻击面、SecuritySpec unknown/conflict、动态/backend缺口或局部candidate desert触发 |
| `HypothesisOffer v2` | 程序预绑定Proof IR、obligation、clauses、action、证据和依赖；模型只选择ID |
| `SecurityHypothesis v2` | 完整且内容hash有效时才可经Registrar进入独立shadow Ledger |
| `HypothesisCoverageObservation v1` | 不完整、无offer、无信号或协议失败的唯一落点；没有Candidate或终态语义 |
| P2 selected-action | 仅执行同一offer/obligation内的系统action；未知、重复或跨obligation引用fail closed |
| authority | 固定`shadow`和`active_product_effect=none`；P5前无用户开关 |

Qualification使用非Range、answer-free且source/expected分离的至少120个单元，覆盖至少三个无关
项目和四个P2 provider family。safe/near-miss错误注册必须为0，全部注册对象的schema、证据和
action可解析率必须为100%，并覆盖rename、wrapper、等价重排和fixed pair。当前冻结资格结果为
120个单元、48个safe case、safe/near-miss错误注册均为0、契约解析率100%，三个项目均产生
Checker可重放proof；测试通过不等于阶段complete。

### 已实现数据流

`stable candidates + active_discovery → P3 spec shadow → P4 planner/Hunter → P4 selected-action Checker → P4 shadow Ledger freeze → live Ledger freeze/validation`

P4模型只有一次严格terminal调用且没有repository tool。投影在序列化前后递归检查key与scalar；
offer绑定冻结IR、obligation、clause、action和依赖。Checker未形成完整确认proof时，选择只产生
coverage observation，不形成shadow candidate。fast不调用Hunter；alert-verify只读加载相同root manifest。
P4 refs只附加到稳定产品已经存在的唯一terminal event。

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
