# P6：离线回放与Cold Pilot

## 目标

在不依赖五轮分数的情况下证明新链路完整、证据可消费、答案隔离和成本账本守恒。

## 进入条件

- P1-P5均完成并登记证据。
- Truth v16/Benchmark v5独立轨完成门禁。
- OCI、provider usage和cold cache能力通过preflight。

## 当前进入准备

[`p6-entry-preflight.json`](../acceptance/p6-entry-preflight.json)绑定到clean main树，记录了
rootless Podman实际inspect、精确内部网络、只读根文件系统、capability drop、独立cold cache
marker以及不含源码和Benchmark数据的provider usage探针。上述三项本地能力均已通过，但E0仍缺少
受保护工作流provenance和attestation；因此P6继续为`pending`，不得执行cold fast、balanced或deep。

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
