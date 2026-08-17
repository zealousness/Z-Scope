---
doc_contract: zscope-module-v1
covers:
  - zscope/core
  - zscope/rules
  - zscope/alerts
sources:
  - zscope/core/analysis/analyzer.py
  - zscope/core/candidates/pipeline.py
  - zscope/core/validation/pipeline.py
  - zscope/core/validation/runner.py
  - zscope/core/validation/evidence_completion.py
  - zscope/core/validation/function_ir.py
  - zscope/core/validation/fact_capabilities.py
  - zscope/core/validation/claim_verifier.py
  - zscope/core/validation/authority.py
  - zscope/core/validation/proof_kernel
  - zscope/common/validator_protocol.py
  - zscope/rules/builtin_catalog.yaml
  - zscope/rules/catalog.py
  - zscope/rules/engine.py
  - zscope/rules/extensions.py
  - zscope/rules/query.py
  - zscope/alerts/verifier.py
tests:
  - tests/test_candidate_pipeline.py
  - tests/test_candidate_ledger.py
  - tests/test_validation_pipeline.py
  - tests/test_validation_runner.py
  - tests/test_validator_v3_protocol.py
  - tests/test_evidence_completion.py
  - tests/test_fact_capabilities.py
  - tests/test_decision_trace.py
  - tests/test_proof_kernel.py
  - tests/test_p2_proof_corpus.py
  - tests/test_p2_proof_lifecycle.py
  - tests/test_p3_security_spec_lifecycle.py
  - tests/test_alert_verifier_parallel.py
  - tests/test_rule_extensions.py
  - tests/test_rule_catalog.py
  - tests/test_rule_runtime_governance.py
---

# 分析流水线

## 职责与非职责

本子系统负责从多种事实源收集和归一化候选，维护全局 Candidate Ledger，并完成分层证据闭合、Validator 三态判断、评分、抑制/baseline 和最终 finding 投影。规则驱动扫描、LLM 主动发现的 hypothesis 与外部 SARIF 告警都在这一层进入相同的候选和验证语义。

它不负责构建 Clang/SVF/Joern 底层事实，不负责 LLM 传输实现，也不负责最终 JSON、Markdown 或 SARIF 序列化。

## 主入口和数据流

- `Analyzer` 装配索引、候选、Agent、工具、预算、快照和 Workflow handler。
- 扫描前规则预检加载包内 `builtin_catalog.yaml`、Skill 契约、显式配置的 `rule_pack_version: 1` YAML pack 和 `zscope.rule_providers` entry point，生成不可变 `EffectiveRuleSet`。
- `CandidatePipeline` 汇总 regex、Clang AST/CFG/matcher、Java 本地规则、图、SVF/Saber 和后端候选，并在合并前施加统一候选门禁。
- YAML pack 和严格 Provider V2 只负责规则特有匹配/证据；语言、CWE、defect class、severity 和 Skill 以 descriptor 为唯一真源。
- Candidate ledger 负责候选身份、合并、生命周期和证据保留。
- `fast` 只运行确定性/backend 候选快车道；`balanced`/`deep` 还可接收 candidate-blind 主动发现产生的 hypothesis。所有来源完成后先冻结全局 Ledger，再按 validation cluster 验证一次。
- default、resume、maintain 与 alert-verify 都冻结相同的 Security Spec shadow policy。确定性 miner 和有限模型 proposal 只形成独立 spec CAS/compilation 对照；旧 SemanticModeler/SecuritySemanticMap 仍是产品输入，P5 前 spec 不产生候选、proof fact 或终态贡献。
- Validation runner 先执行稳定的 bounded V0 确定性 proof，再运行 V1 单次结构化判定、新增合法请求产生真实 delta 后的单次 V2 无状态复判，以及分档 V3 调查。Z-Scope 2.0 的 `RequiredFactPlan`、Proof Kernel 与严格 `TerminalAuthorityEvaluator` 当前只做 shadow 对照：输出保留在候选和 trace 中，但 P5 完成前不得改写 V1 输入、Candidate Ledger outcome 或既有 validation pipeline 终态。balanced 覆盖 high/critical 或外部可达的可执行未决 cluster，deep 覆盖全部有可执行证明动作、无完整反证的非 shadow 未决 cluster。
- Finding attribution 显式区分 `discovered_by` 集合与 `decided_by`/`decision_level`，因此“规则发现、LLM 判定”和“LLM 独占发现”不会混为一类。
- Rule engine 和 alert verifier 将规则或外部告警转换为相同的验证/报告语义。

## 必须保持的不变量

- 候选不得因调度边界、超时或阶段失败而静默丢失；未深挖候选必须保留可审计状态。
- `verified`、`rejected`、`uncertain`/`needs_review` 的含义不能混淆，退出策略只消费约定视图。
- 去重必须保留 occurrence、替代证据和来源，不能仅按文本或行号合并。
- 确定性 proof、LLM 判断和引擎失败必须在元数据中可区分。
- 完整且无冲突的 proof 才能确定性确认或拒绝。正反 proof 冲突先由 `ProofConflictResolver` 对 subject、decision region、路径/范围、dependency hash 与 completeness 做程序化消解：一方失效时采用另一方，双方仍有效时进入定向 V3；无法消解才进入 `needs_review`，模型不能投票裁决 proof 真伪。没有确定性反证时，模型的 `rejected` 只是一项模型意见，不能把候选从审计视图静默隐藏。
- `RequiredFactPlan` 从 obligation、decision slice 与 promotion 条件派生本地工作；当前 V1 前执行只在候选副本上形成 `proof_kernel_fact_first` shadow 投影，不能把未资格化 clause 写入产品 decision slice。`FunctionIRGraph v1` 只从唯一、完整的 Clang CFG 函数段构建稳定 block/statement/event、真实边、入口/全部出口和代码/backend hash；候选自己的同一行 inspection 记录不能充当 CFG。Function IR 从候选的结构化 file/location/obligation endpoint 解析源文件，同一函数的 Clang AST/CFG 构建使用 scan-local single-flight，AST JSON 与 stderr 诊断分离解析；失败必须暴露具体 capability 原因，不能缓存成无法解释的全局不可用。每项 provider 结果使用 `resolved/no_match/unsupported/timeout/provider_error/conflicting` 终态。
- `FactCapabilityRegistry` 是 V3 可执行性的唯一权威。它按当前 subject、decision region、Function IR 和 backend coverage 产生有限 `EvidenceAction`；普通 call graph、间接 callee（兼容名 `query_pointer_alias`）和 SVF bug-signature 查询只能形成 observation，不能关闭 lockset/HB/cleanup/ownership/path clause。没有 action 的 cluster 以 `V3_NOT_ELIGIBLE_NO_EXECUTABLE_GAP` 留在 needs-review。
- 并发、资源、路径/guard 和 contract/type provider 只提出严格的 `EvidenceCertificate v2`；独立 `ProofChecker` 从冻结 `ProgramProofIR v2` 与 obligation/action 重算谓词，校验 scope、量词、CFG/出口、assumption allowlist 和 code/IR/backend/dependency hash 后，才可在 shadow closure 中生成 accepted fact。入口参数绑定还要求 IR 显式标记完整的冻结签名域；只有 CFG 完整而没有该签名域时保持 unknown。RequiredFactPlan 的派生事实只关闭 fact request，不产生 terminal contribution；alert 缺少冻结 IR 时 shadow 保持 open。缺少 protocol revision 或严格字段的早期同名证书标为 `legacy_preview`，只能读取，不能关闭 P2 clause。全称命题在 alias、动态边、wrapper/transfer 或覆盖不完整时必须 unknown 且 witness 为空。产品 V1 仍使用稳定 decision slice；V1 只能再提出一个新的合法参数化请求，有真实 delta 才执行一次无历史 V2。
- V3 模型不能构造 fact、引用或自由参数，只能选择系统提供的 action ID。系统执行固定 verifier、自动绑定 subject/region/code/backend hash，把证书写回 decision slice，并立即调用 `TerminalAuthorityEvaluator`；完整正/反 proof 通过程序终态钩子在当前工具轮结束后停止，不再调用模型。重复 action 被拒绝，连续两轮没有系统接纳的 fact 即停止，50 轮只是安全上限。逐调用 `new_fact_count` 只统计实际写入 decision slice 的事实。
- 旧 `EvidenceClaimRequest` 与普通只读工具目录只用于历史 trace/replay 分类；live V3 使用有限 action 与严格 Checker，不能以 observation 晋级。Proof artifacts 进入不可变 CAS，Decision Trace 的唯一 terminal event 同时冻结 active product decision、`proof_kernel_mode=shadow` 和 shadow decision；P5 前不能把既有 policy 已确认的 finding 降级。
- 同一个唯一 terminal event 还附加 `security_spec_mode=shadow`、spec artifact refs 与 `active_product_effect=none`。Security Spec 编译冲突、过期依赖、未知字段、空 scope、证据不可解析或 reviewer identity 缺失都必须 fail-closed，且不得通过新增 terminal event 改写稳定结果。
- 主动发现 Agent 只能写 hypothesis/observation，不能写 confirmed finding；其 prompt 不得包含 Candidate Ledger 内容、候选/规则身份、benchmark、truth 或历史 verdict。
- 已启用阶段因超时、取消或工具失败未能覆盖全部审计单元时，已有结果仍需保存并标记 `completeness=partial`；未启用的阶段不构成 partial。token 成本只在 Benchmark 完成后评价。
- 外部告警适配后仍需遵守统一 issue identity、证据和报告 schema。
- 规则 ID/alias 全局唯一；YAML 不执行代码，未知字段、语言错配、重复 ID、缺失 Skill 和能力错配必须在构建 CodeIndex、启动外部工具或调用 LLM 之前失败。
- 确定性候选必须携带已登记 canonical `rule_id`；其语言、CWE、defect class 和 Skill 不得与 descriptor 冲突，被禁用的候选不得进入 ledger、Worker、Validator 或报告。
- SVF/Saber、Joern 和 Java signal provider 输出是 `backend_signal`，不伪装成确定性规则；Skill trigger 只路由 Worker；finding suppression 只消费已持久化的人工决策。

## 规则治理边界

| 机制 | 权威配置/元数据 | 进入候选的方式 | 关闭方式 |
|------|-----------------|--------------------|----------|
| 确定性规则 | 包内目录 + qualification registry + YAML pack/Provider descriptor | `candidate_kind: deterministic_rule`，由 `RulePolicy` 与统一门禁校验 | `rules.disabled_ids`；实验规则默认关闭，可用 `rules.enabled_ids` 显式启用 |
| Backend signal | `indexing` 后端与 signal provider 规划 | `candidate_kind: backend_signal`，保留 `signal_source`/`native_rule_id` | 在 `indexing` 中关闭信号源 |
| LLM 主动审计 | Security Semantic Map + coverage-gap audit unit + active Skill | 合格 hypothesis 经 CandidateRegistrar 登记为 `candidate_kind: llm_observation` | `scan.depth=fast`；`balanced/deep` 保留风险阈值、合并和目录排除，但不设 audit unit 数量上限 |
| Finding suppression | ReviewMemory/UserConfig state | 在验证/报告前匹配 finding identity | Web/用户配置中维护 |

`rules.disabled_ids` 对当前语言的内置 Regex、Clang CFG/matcher、Graph、Java local、YAML pack 和 Python provider 统一生效，且优先于 `enabled_ids`；两表出现同一 ID 时以禁用为准。表内重复 ID、未知 ID 或跨语言 ID 均严格失败。关闭规则只停止指定检测器，不承诺消除等价问题：其他规则、后端信号或 LLM 仍可独立发现它。

RuleDriven/Joern 与 SARIF alert-verify 也遵循统一验证边界。RuleDriven 把全部 backend signal 先注册进共享 Candidate Ledger，跨原生规则合并同一义务并 freeze，再走 V0–V3；SARIF alert-verify 是面向单条外部告警的有界 V1 子集。两条路径中，模型拒绝无确定性反证时都只能进入 `needs_review`。产品 token 账本只计量，不因成本阈值停止验证调用；超时、取消或工具故障仍按实际覆盖情况标记 partial。

规则目录原始字节、规范化 descriptor、相关引擎实现、enabled/disabled IDs、qualification、pack/provider 来源、当前语言与 backend 能力共同形成 effective SHA-256。该身份参与规则候选、gap plan、Validator environment fingerprint 与最终报告 provenance，但不改变 `zscope.candidate.v3.3` 的稳定候选身份，也不应使独立的程序事实或 Security Semantic Map 骨架缓存失效。

## 常见变更应落到哪里

- 规则 descriptor、ID/alias、能力与 provenance：`zscope/rules/`；检测算法本身仍位于对应 Python 引擎。
- 简单扩展规则：显式 YAML pack；复杂第三方规则：严格 `zscope.rule_providers` V2；完整契约见 `docs/rule-development.md`。
- 候选收集/合并：`pipeline.py`、ledger 和 adapters，避免在 `Analyzer` 中堆叠局部规则。
- Validator 输入、重试或评分：`zscope/core/validation/`。
- Joern 规则或规则驱动扫描：`zscope/rules/`。
- SARIF 导入和告警复核：`zscope/alerts/`。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_candidate_pipeline.py tests/test_candidate_ledger.py
python -m pytest -q tests/test_validation_pipeline.py tests/test_validation_runner.py
python -m pytest -q tests/test_validator_v3_protocol.py tests/test_evidence_completion.py tests/test_fact_capabilities.py
python -m pytest -q tests/test_proof_kernel.py tests/test_p2_proof_corpus.py tests/test_p2_proof_lifecycle.py
python -m pytest -q tests/test_security_specs.py tests/test_p3_security_spec_lifecycle.py
python -m pytest -q tests/test_alert_verifier_parallel.py tests/test_needs_review_governance.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 分层关系见 `docs/architecture.md` 的“证据平面”“智能体平面”和“验证平面”。
- Range 上的行为变更还必须遵循 `docs/range-benchmark.md`。
