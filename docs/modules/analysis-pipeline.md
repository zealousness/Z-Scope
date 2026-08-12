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
  - tests/test_alert_verifier_parallel.py
  - tests/test_rule_extensions.py
  - tests/test_rule_catalog.py
  - tests/test_rule_runtime_governance.py
---

# 分析流水线

## 职责与非职责

本子系统负责从多种事实源收集和归一化候选，组织语义分析与深挖，完成证据打包、Validator 三态判断、评分、抑制/baseline 和最终 finding 投影。规则驱动扫描与外部 SARIF 告警复核也在这一层进入统一验证语义。

它不负责构建 Clang/SVF/Joern 底层事实，不负责 LLM 传输实现，也不负责最终 JSON、Markdown 或 SARIF 序列化。

## 主入口和数据流

- `Analyzer` 装配索引、候选、Agent、工具、预算、快照和 Workflow handler。
- 扫描前规则预检加载包内 `builtin_catalog.yaml`、Skill 契约、显式配置的 `rule_pack_version: 1` YAML pack 和 `zscope.rule_providers` entry point，生成不可变 `EffectiveRuleSet`。
- `CandidatePipeline` 汇总 regex、Clang AST/CFG/matcher、Java 本地规则、图、SVF/Saber 和后端候选，并在合并前施加统一候选门禁。
- YAML pack 和严格 Provider V2 只负责规则特有匹配/证据；语言、CWE、defect class、severity 和 Skill 以 descriptor 为唯一真源。
- Candidate ledger 负责候选身份、合并、生命周期和证据保留。
- Validation runner 构造证据切片并运行 Validator；validation pipeline 应用 suppression、baseline、评分和状态分流。
- Rule engine 和 alert verifier 将规则或外部告警转换为相同的验证/报告语义。

## 必须保持的不变量

- 候选不得因预算不足而静默丢失；未深挖候选必须保留可审计状态。
- `verified`、`rejected`、`uncertain`/`needs_review` 的含义不能混淆，退出策略只消费约定视图。
- 去重必须保留 occurrence、替代证据和来源，不能仅按文本或行号合并。
- 确定性 proof、LLM 判断和引擎失败必须在元数据中可区分。
- 外部告警适配后仍需遵守统一 issue identity、证据和报告 schema。
- 规则 ID/alias 全局唯一；YAML 不执行代码，未知字段、语言错配、重复 ID、缺失 Skill 和能力错配必须在构建 CodeIndex、启动外部工具或调用 LLM 之前失败。
- 确定性候选必须携带已登记 canonical `rule_id`；其语言、CWE、defect class 和 Skill 不得与 descriptor 冲突，被禁用的候选不得进入 ledger、Worker、Validator 或报告。
- SVF/Saber、Joern 和 Java signal provider 输出是 `backend_signal`，不伪装成确定性规则；Skill trigger 只路由 Worker；finding suppression 只消费已持久化的人工决策。

## 规则治理边界

| 机制 | 权威配置/元数据 | 进入候选的方式 | 关闭方式 |
|------|-----------------|--------------------|----------|
| 确定性规则 | 包内目录 + YAML pack/Provider descriptor | `candidate_kind: deterministic_rule`，由 `RulePolicy` 与统一门禁校验 | `rules.disabled_ids` |
| Backend signal | `indexing` 后端与 signal provider 规划 | `candidate_kind: backend_signal`，保留 `signal_source`/`native_rule_id` | 在 `indexing` 中关闭信号源 |
| LLM 主动审计 | active Skill + 受控上下文 | `candidate_kind: llm_observation` | 调整 `scan.task`/Skill 契约 |
| Finding suppression | ReviewMemory/UserConfig state | 在验证/报告前匹配 finding identity | Web/用户配置中维护 |

`rules.disabled_ids` 对当前语言的内置 Regex、Clang CFG/matcher、Graph、Java local、YAML pack 和 Python provider 统一生效。它只停止指定检测器，不承诺消除等价问题：其他规则、后端信号或 LLM 仍可独立发现它。未知、重复或跨语言 ID 严格失败；当前 backend 不具备能力的同语言 ID 允许禁用，但配置验证会给出不适用警告。

规则目录原始字节、规范化 descriptor、相关引擎实现、disabled IDs、pack/provider 来源、当前语言与 backend 能力共同形成 effective SHA-256。该身份参与配置哈希、snapshot/cache、Validator environment fingerprint 与最终报告 provenance，但不改变 `zscope.candidate.v3.3` 的稳定候选身份算法。

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
python -m pytest -q tests/test_alert_verifier_parallel.py tests/test_needs_review_governance.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 分层关系见 `docs/architecture.md` 的“证据平面”“智能体平面”和“验证平面”。
- Range 上的行为变更还必须遵循 `docs/range-benchmark.md`。
