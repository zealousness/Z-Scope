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
- Validation runner 依次执行 V0 确定性 proof、V1 单次结构化判定、按 obligation 全部必需 fact kinds 定向补证后的单次 V2 无状态复判，以及分档 V3 调查；balanced 覆盖 high/critical 或外部可达的可闭合未决 cluster，deep 覆盖全部无完整反证的非 shadow 未决 cluster。validation pipeline 再应用 suppression、baseline、评分和状态分流。
- Finding attribution 显式区分 `discovered_by` 集合与 `decided_by`/`decision_level`，因此“规则发现、LLM 判定”和“LLM 独占发现”不会混为一类。
- Rule engine 和 alert verifier 将规则或外部告警转换为相同的验证/报告语义。

## 必须保持的不变量

- 候选不得因调度边界、超时或阶段失败而静默丢失；未深挖候选必须保留可审计状态。
- `verified`、`rejected`、`uncertain`/`needs_review` 的含义不能混淆，退出策略只消费约定视图。
- 去重必须保留 occurrence、替代证据和来源，不能仅按文本或行号合并。
- 确定性 proof、LLM 判断和引擎失败必须在元数据中可区分。
- 完整且无冲突的 proof 才能确定性确认或拒绝；正反 proof 冲突直接进入 `needs_review`。没有确定性反证时，模型的 `rejected` 只是一项模型意见，不能把候选从审计视图静默隐藏。
- V2 只能在合法的单一 `missing_fact_request` 得到新证据且 `evidence_delta_hash` 改变后运行；重复、无增益、超时或不支持的请求必须停止为待复核。
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
python -m pytest -q tests/test_validator_v3_protocol.py tests/test_evidence_completion.py
python -m pytest -q tests/test_alert_verifier_parallel.py tests/test_needs_review_governance.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 分层关系见 `docs/architecture.md` 的“证据平面”“智能体平面”和“验证平面”。
- Range 上的行为变更还必须遵循 `docs/range-benchmark.md`。
