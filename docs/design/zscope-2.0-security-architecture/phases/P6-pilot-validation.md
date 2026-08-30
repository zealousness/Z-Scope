# P6：离线回放与Cold Pilot

## 目标

在不依赖五轮分数的情况下证明新链路完整、证据可消费、答案隔离和成本账本守恒。

## 进入条件

- P1-P5均完成并登记证据。
- Truth v16/Benchmark v5独立轨完成门禁。
- OCI、provider usage和cold cache能力通过preflight。

## 当前进入状态

[`p6-entry-gate.json`](../acceptance/p6-entry-gate.json)精确绑定成功的Range v16独立审核
run `33247814685`及其reviewed、provenance和pair artifacts，并绑定成功的Benchmark v5
attestation run `33257971124`与Truth commit `3e05889ba5773d8fc8c7e22ae9b75dcfe43e05c4`。
该gate同时验证governance/scorer commit均为Truth祖先，且review packet catalog与packet目录从
review source到Truth commit未改变。E0因此标记为`complete`，P6在同一治理转换中标记为
`in_progress`；这只授权后续non-release cold pilot协议工作，不表示pilot已经运行或形成发布资格。

旧[`p6-entry-preflight.json`](../acceptance/p6-entry-preflight.json)继续以原字节保留为GLM-5.1
能力探针的历史blocked snapshot。它不被覆盖，也不再作为当前provider或P6进入证明。

## 执行顺序

1. 冻结trace的policy replay和certificate reverify，不调用模型。
2. 匿名通用fixture与safe pairs。
3. 一次cold fast。
4. 一次cold balanced。
5. balanced链路通过后一次cold deep。

## 验收

- eligible hypothesis/cluster实际进入对应阶段。
- EvidenceAction证书进入decision slice。
- closure、missing clauses和终态一致。
- proof完成后无额外调用。
- coverage gap存在时Planner不会无理由产生0 unit。
- 队列排空、provider usage 100%、trace/finding/token/tool call守恒。
- 无proof rejection保留needs-review。
- safe pair不被错误程序确认。
- Spec、Hunter、Proof分别输出指标。

## 停止与回退

任一链路不变量失败立即停止，不执行五轮。新增能力无质量增益却产生大量无进展成本时，返回最早失败阶段，而不是增加模型轮数。
