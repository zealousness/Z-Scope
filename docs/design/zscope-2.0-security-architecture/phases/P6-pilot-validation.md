# P6：离线回放与Cold Pilot

GitHub Actions 和自托管 runner 已退役。本文的 workflow dispatch、自动上传及恢复步骤仅用于解释历史协议与证据，当前不可触发；本地工具与证据验证器继续保留，停止自动化不改变既有阶段状态或发布资格。参见 [`GitHub 仓库与本地验证`](../../../github-governance.md)。

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

P6 当前 scanner provider 固定为版本控制配置中的
`deepseek-v4-flash`；provider response model 只接受该请求名与冻结部署别名
`deepseek-v4-flash-ga-260731`。Base URL/model 不接受环境覆盖，私有文件只提供
`Z_SCOPE_API_KEY`。最大正式扫描并发为8。

执行边界不可交换：

1. 运行 focused、完整 pytest、compileall、mypy、格式、hygiene、secret/tamper、Linux工具链与
   rootless OCI 等零网络门禁。
2. 任何scanner runtime、Prompt、规则、LLM adapter或Proof authority变更都先生成并验证新的
   P2/P4/P5 successor qualification；历史资格只作审计。
3. 在原生WSL Ubuntu以`llm_max_inflight=1`运行answer-free synthetic C正反例回放；它使用冻结
   DeepSeek contract，但不得读取Range fixture、Truth、expected或Scorer。标准命令及凭据边界见
   [`docs/range-benchmark.md`](../../../range-benchmark.md)“P6 单次受控 pilot 协议”。真实网络回放不进入
   零网络pytest。
4. 单点回放通过后，使用digest-pinned Python 3.13 image、新run ID、全新空cache和rootless OCI执行
   一次8路cold balanced；扫描完成后先冻结report，再由隔离scorer分别生成legacy v15与Truth v16
   product/design-risk结果。
5. `zscope.p6-balanced-quality-gate.v1`与全部守恒通过后才允许推送一个受保护PR；正常合并后才从
   精确merge SHA运行sealed self-hosted workflow。Hosted fast、balanced、deep仍按顺序执行，不能用
   本地结果替代hosted attestation。
6. qualification/evidence seal后依次执行三名互相隔离的独立审核；任一缺失、非approved或blocker
   非零都保持P6 blocked。

Cold balanced所选attempt（含重试）的实际provider tokens最多11,999,999；10,500,000是停止启动
低价值audit线索的软水位。Probe、canary、successor qualification与独立审核分别记账，不计入该上限，
但都必须usage coverage 1.0且守恒。不同attempt、cache、usage或指标不得拼接。

## 验收

- legacy v15 default：`TP >= 82/136`且`TP >= 4 * raw_FP`；with-needs-review：
  `TP >= 125/136`且`TP >= raw_FP`。
- Truth v16 product default：`TP >= 37/61`且`TP >= 4 * raw_FP`；with-needs-review：
  `TP = 61/61`且`TP >= raw_FP`。75个design-risk单独计分与守恒。
- default匹配集合必须是with-needs-review子集；全部canonical `needs_review`必须出现在后者，
  `audit_observations`独立守恒且不能在评分后按Truth隐藏误报。
- challenge（v15 default 96/136与9倍FP、v16 default 43/61与9倍FP、两个with-needs-review
  3:2 precision）只记录，不阻塞。
- eligible hypothesis/cluster实际进入对应阶段。
- EvidenceAction证书进入decision slice。
- closure、missing clauses和终态一致。
- proof完成后无额外调用。
- coverage gap存在时Planner不会无理由产生0 unit。
- 队列排空、provider usage 100%、trace/finding/token/tool call守恒。
- 无proof rejection保留needs-review。
- safe pair不被错误程序确认。
- Spec、Hunter、Proof分别输出指标。

三名exit reviewer身份固定为：Claude Code `2.1.233` + `glm-5.3` high（product architecture）、
DSH `0.1.0-rc.6` + `deepseek-v4-pro-0813` max（proof security）、Codex CLI `0.144.4` +
`gpt-5.6-sol` xhigh（independent benchmark）。scanner模型不能自签，集成操作者也不能代写审核。

## 停止与回退

任一链路不变量失败立即停止，不执行五轮。Proof/Hunter/Authority缺陷必须先在开放synthetic场景形成
red-green修复，再重跑focused、单点回放与全新cold balanced；provider身份/协议/usage缺陷同样必须重跑
provider回放及完整balanced。质量门禁失败只允许把answer-free聚合桶送入修复环节。新增能力无质量增益
却产生大量无进展成本时，返回最早失败阶段，而不是增加模型轮数。
