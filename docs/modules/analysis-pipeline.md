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
  - tests/test_p4_hypothesis_hunter.py
  - tests/test_p4_hypothesis_qualification.py
  - tests/test_p4_hypothesis_lifecycle.py
  - tests/test_alert_verifier_parallel.py
  - tests/test_rule_extensions.py
  - tests/test_rule_catalog.py
  - tests/test_rule_runtime_governance.py
---

# 分析流水线

## 职责与非职责

本子系统负责从多种事实源收集和归一化候选，维护全局 Candidate Ledger，并完成 Proof Engine 三态闭合、抑制/baseline诊断和最终 finding 投影。确定性规则、Hunter hypothesis与外部SARIF告警都遵守同一Checker/TerminalAuthority边界。

它不负责构建 Clang/SVF/Joern 底层事实，不负责 LLM 传输实现，也不负责最终 JSON、Markdown 或 SARIF 序列化。

## 主入口和数据流

- `Analyzer` 装配索引、候选、Agent、工具、预算、快照和 Workflow handler。
- 扫描前规则预检加载包内 `builtin_catalog.yaml`、Skill 契约、显式配置的 `rule_pack_version: 1` YAML pack 和 `zscope.rule_providers` entry point，生成不可变 `EffectiveRuleSet`。
- `CandidatePipeline` 汇总 regex、Clang AST/CFG/matcher、Java 本地规则、图、SVF/Saber 和后端候选，并在合并前施加统一候选门禁。
- YAML pack 和严格 Provider V2 只负责规则特有匹配/证据；语言、CWE、defect class、severity 和 Skill 以 descriptor 为唯一真源。
- Candidate ledger 负责候选身份、合并、生命周期和证据保留。
- `fast`只运行确定性/backend候选与Proof Engine，不运行Hunter；`balanced`/`deep`还接收candidate-blind Hunter产生的强制未确认hypothesis。所有producer结束后冻结全局Ledger，再按cluster执行一次authority closure。
- default、resume、maintain与单入口扫描都先把程序事实、内置/用户语义编译为qualification-backed authoritative SecuritySpec；冲突、过期、证据不可解析和不完整Java能力fail closed。
- Hunter只选择系统预绑定的offer/action并经公共Registrar写入live Ledger；它不读取live Candidate内容、Finding-root或历史verdict，也不具proof/terminal authority。
- Proof Engine把SecurityObligation编译成ProofObligation/action，独立Checker从冻结IR重算；每个required executable clause都必须有Checker结果。缺失、冲突或unknown统一为needs-review，不回退到旧Validator。
- Finding attribution 显式区分 `discovered_by` 集合与 `decided_by`/`decision_level`，因此“规则发现、LLM 判定”和“LLM 独占发现”不会混为一类。
- Rule engine 和 alert verifier 将规则或外部告警转换为相同的验证/报告语义。

## 必须保持的不变量

- 候选不得因调度边界、超时或阶段失败而静默丢失；未深挖候选必须保留可审计状态。
- `confirmed`、`rejected_with_proof`、`needs_review` 的含义不能混淆，退出策略只消费约定视图。
- 去重必须保留 occurrence、替代证据和来源，不能仅按文本或行号合并。
- 确定性 proof、LLM 判断和引擎失败必须在元数据中可区分。
- 完整且无冲突的Checker closure才能确认或拒绝。正反proof冲突只按subject、decision region、scope、quantifier、dependency freshness与Checker结果程序化比较；无法消解保持`needs_review`，模型不能投票裁决。
- `RequiredFactPlan`从obligation与decision slice派生本地工作，但事实只有经统一registry/provider/Checker接纳才可关闭clause。`FunctionIRGraph v1`只从唯一、完整的Clang CFG函数段构建稳定block/statement/event、真实边、入口/全部出口和代码/backend hash；候选自己的同一行inspection记录不能充当CFG。构建使用scan-local single-flight，失败暴露具体capability原因。
- `FactCapabilityRegistry` 是 V3 可执行性的唯一权威。它按当前 subject、decision region、Function IR 和 backend coverage 产生有限 `EvidenceAction`；普通 call graph、间接 callee（兼容名 `query_pointer_alias`）和 SVF bug-signature 查询只能形成 observation，不能关闭 lockset/HB/cleanup/ownership/path clause。没有 action 的 cluster 以 `V3_NOT_ELIGIBLE_NO_EXECUTABLE_GAP` 留在 needs-review。
- 并发、资源、路径/guard和contract/type provider只提出严格`EvidenceCertificate v2`；独立Checker从冻结`ProgramProofIR v2`与obligation/action重算谓词，校验scope、量词、CFG/出口、assumption allowlist和code/IR/backend/dependency hash。入口参数绑定还独立校验完整签名域、参数数量、身份和slot；全称命题覆盖不完整时必须unknown且witness为空。`legacy_preview`只能读取，不能关闭live clause。
- V3 模型不能构造 fact、引用或自由参数，只能选择系统提供的 action ID。系统执行固定 verifier、自动绑定 subject/region/code/backend hash，把证书写回 decision slice，并立即调用 `TerminalAuthorityEvaluator`；完整正/反 proof 通过程序终态钩子在当前工具轮结束后停止，不再调用模型。重复 action 被拒绝，连续两轮没有系统接纳的 fact 即停止，50 轮只是安全上限。逐调用 `new_fact_count` 只统计实际写入 decision slice 的事实。
- 旧`EvidenceClaimRequest`、旧proof字段与普通观察只用于历史trace/replay分类，不能晋级。Proof artifacts进入不可变CAS，唯一terminal event冻结authoritative SecuritySpec/Hunter/Proof refs、最终outcome与完整性状态。
- `RuntimeAuthorityManifest v1`绑定代码树、配置、backend、三类artifact root、registry/checker/provider revision、trace schema和cache epoch；任一不一致阻止resume/maintain复用。
- selected action未知、重复、跨obligation、参数不匹配或内容hash篡改必须整项拒绝；proof闭合后新增模型/工具调用数必须为0。
- Hunter只能写hypothesis/observation并强制未确认；其prompt不得包含Candidate Ledger内容、候选/规则身份、benchmark、truth或历史verdict。
- 已启用阶段因超时、取消或工具失败未能覆盖全部审计单元时，已有结果仍需保存并标记 `completeness=partial`；未启用的阶段不构成 partial。token 成本只在 Benchmark 完成后评价。
- 外部告警适配后仍需遵守统一 issue identity、证据和报告 schema。
- 规则 ID/alias 全局唯一；YAML 不执行代码，未知字段、语言错配、重复 ID、缺失 Skill 和能力错配必须在构建 CodeIndex、启动外部工具或调用 LLM 之前失败。
- 确定性候选必须携带已登记canonical `rule_id`；其语言、CWE、defect class和Skill不得与descriptor冲突，被禁用的候选不得进入ledger、Proof Engine或报告。
- SVF/Saber、Joern和Java signal provider输出是`backend_signal`，不伪装成确定性规则；Skill trigger只路由Hunter/Proof adapter；finding suppression只消费已持久化的人工决策。

## 规则治理边界

| 机制 | 权威配置/元数据 | 进入候选的方式 | 关闭方式 |
|------|-----------------|--------------------|----------|
| 确定性规则 | 包内目录 + qualification registry + YAML pack/Provider descriptor | `candidate_kind: deterministic_rule`，由 `RulePolicy` 与统一门禁校验 | `rules.disabled_ids`；实验规则默认关闭，可用 `rules.enabled_ids` 显式启用 |
| Backend signal | `indexing` 后端与 signal provider 规划 | `candidate_kind: backend_signal`，保留 `signal_source`/`native_rule_id` | 在 `indexing` 中关闭信号源 |
| LLM 主动审计 | SecuritySpec + localized signal gap + active Skill | 合格 hypothesis 经CandidateRegistrar强制未确认登记为`candidate_kind: llm_observation` | `scan.depth=fast`；balanced/deep保留局部风险阈值 |
| Finding suppression | ReviewMemory/UserConfig state | 在验证/报告前匹配 finding identity | Web/用户配置中维护 |

`rules.disabled_ids` 对当前语言的内置 Regex、Clang CFG/matcher、Graph、Java local、YAML pack 和 Python provider 统一生效，且优先于 `enabled_ids`；两表出现同一 ID 时以禁用为准。表内重复 ID、未知 ID 或跨语言 ID 均严格失败。关闭规则只停止指定检测器，不承诺消除等价问题：其他规则、后端信号或 LLM 仍可独立发现它。

C/C++ ruledriven入口在建索引前拒绝，Java Preview暂保留其backend signal登记语义。SARIF alert-verify只加载并重验冻结IR/obligation/action/certificate，不运行Hunter或模型；缺少完整proof时保持`needs_review`。产品token账本只计量，不因成本阈值停止调用。

规则目录原始字节、规范化descriptor、相关引擎实现、enabled/disabled IDs、qualification、pack/provider来源、当前语言与backend能力共同形成effective SHA-256。该身份参与规则候选、localized signal plan、Proof Engine environment fingerprint与最终报告provenance，但不改变`zscope.candidate.v3.3`稳定候选身份。

## 常见变更应落到哪里

- 规则 descriptor、ID/alias、能力与 provenance：`zscope/rules/`；检测算法本身仍位于对应 Python 引擎。
- 简单扩展规则：显式 YAML pack；复杂第三方规则：严格 `zscope.rule_providers` V2；完整契约见 `docs/rule-development.md`。
- 候选收集/合并：`pipeline.py`、ledger 和 adapters，避免在 `Analyzer` 中堆叠局部规则。
- Proof obligation、Checker、适配器或诊断评分：`zscope/core/validation/`。
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
