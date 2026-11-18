# 规则开发路线

[返回根入口](../../../AGENTS.md) · 新增、修改或禁用确定性规则、YAML rule pack、Python provider 时读取。

适用于新增、修改或禁用 Java/C/C++ 确定性规则，以及 YAML rule pack 或 Python provider 开发。

1. 先读 [`docs/development/rules.md`](../../development/rules.md) 和 [`docs/modules/analysis-pipeline.md`](../../../docs/modules/analysis-pipeline.md)，区分确定性规则、backend signal、Skill trigger 与 finding suppression；不要用一类机制替代另一类。
2. 修改内置检测逻辑时，同一变更必须同步 `zscope/rules/builtin_catalog.yaml`：保持 canonical ID，并在规则语义、CWE（含 `additional_cwes` 附加 CWE）、Skill 或验证要求变化时递增 `revision`；`cwe` 仍是唯一治理主值，类别级兜底 CWE 集合集中在 `zscope/common/defect_cwe_map.py`，新增类别时同步该映射及其不变量测试。
3. 对变更的规则行为保留或补充至少一个正例和一个反例，已有有效用例直接复用；按影响选择目录一致性、候选快照和对应引擎用例，不默认重跑所有规则与后端。候选快照用来检查预期行为，不冻结实现或既有错误输出；不得让实现产生未登记 ID。
4. 验证 `rules.disabled_ids` 只停止指定确定性检测器，不得意外抑制 SVF/Saber、Joern 等 backend signal、LLM 独立发现或已持久化的 finding suppression。
5. 规则治理变更不要改写 `zscope/agents/*/AGENT.md`。`SKILL.md` 只在 Skill 语言归属或证据契约本身变化时同步。
