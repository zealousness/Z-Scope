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
  - zscope/core/validation/review_checks.py
  - zscope/core/validation/review_protocol.py
  - zscope/core/validation/review_session.py
  - zscope/core/validation/review_checkpoint.py
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
  - tests/test_validator_review_memory.py
  - tests/test_review_fact_checks.py
  - tests/test_review_experiment_protocol.py
  - tests/test_review_runtime.py
  - tests/test_validator_v3_protocol.py
  - tests/test_evidence_completion.py
  - tests/test_alert_verifier_parallel.py
  - tests/test_rule_extensions.py
  - tests/test_rule_catalog.py
  - tests/test_rule_runtime_governance.py
  - tests/test_escalation_observability.py
  - tests/test_needs_review_sub_states.py
  - tests/test_evidence_completeness_chain.py
  - tests/test_interface_probe_visibility.py
---

## Validator Review Memory

Project-scoped Review Memory stores human rejected finding records separately
from Wiki constraints. Matching patterns are bounded advisory hints only; they
never create proof, suppress a finding, or replace current source evidence.
Matcher 只消费同一 project、rule、category 且 source context 兼容的程序化
fingerprint；可用特征包括 AST、CFG、调用图、类型和宏 fingerprint。命中会
形成 PatternMatch receipt，Validator cache identity 包含 active proposal
digest。离线 replay 只投影 baseline/advisory 两侧并报告潜在影响，不调用
Validator，也不会改变 verdict。

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
- 验证升级阶梯（balanced confirmed TP 计划）由 `runtime.analysis` 独立开关控制，默认全关：`validation_v3_reattempt`（R2 V3 复判）、`validation_v2b_adjudication`（R3 V2b 二次裁决）、`validation_uncertain_confirm_threshold`（τ 高置信确认通道，null 关闭；离线测量未找到通过 FDR 门禁的 τ，保持关闭）。usage 事件按 `call_kind` 派生 `escalation_rung`（initial→R1、targeted_investigation/investigation_synthesis→R2、v2b_adjudication→R3），确认项写入 `confirmed_via`（deterministic_proof | validator_model | high_confidence_band）。
- `needs_review` 落点带呈现子状态 `needs_review_sub_state`：`model_uncertain`（证据仍缺失）、`policy_pending_promotion`（义务完整且无反证、等待策略通道）、`model_rejected_unproven`（模型否决未获确定性证明）；该字段只描述呈现，不改变 disposition 语义。报告视图可用 `build_report_views(..., demote_unproven_rejections=True)` 把 rejected-unproven 在 review 视图内降级呈现（带 `downgraded_from_disposition` 痕迹），计分归因不受影响。
- 报告级 `evidence_completeness` 由验证终点从 `decision_fact_coverage`（优先）与 `evidence_completion_status`（兜底）派生；扫描期 envelope 只能是 `unknown`。
- v12 事件形态 fact provider（`_source_lifecycle_acquire_exit_proof`、`_source_lockset_dominance_proof`、`_caller_lock_context_proof`）在引擎事件缺失时从验证用函数源码/调用点锁态重建生命周期与锁集事实，规则表与 proof requirement 表一一对应；不满足条件一律保持 needs_review。
- 扫描期接口探测（`analysis.llm_interface_inference`）的分类计数、skip 原因与 role 分布以 `run_manifest.interface_probe` 汇总，供扫描侧 A/B 归因。
- Rule engine 和 alert verifier 将规则或外部告警转换为相同的验证/报告语义。

## 必须保持的不变量

- 实验性 review 链路使用 `zscope.review-adjudication.v1` 封套，分别记录旧拒绝的事实／范围审查和具体缺陷案例；内部校验后仍交给 ValidatorResult v3 的统一策略。只推翻拒绝而未闭合正面案例时保留 review，原因记录在 `review_disposition_reason`，不得扩充旧 `stop_reason` 枚举或借高置信 uncertain 通道晋升。
- `check_validation_claim` 只核验绑定的原候选。当前支持完整类型中的不存在成员／内联字节数组、受限结构化所有权路径、常量或规范归纳循环的固定数组下标、明确检查成功返回值的静态互斥锁访问。递归、未知别名、辅助函数失败出口、复杂整数转换和未闭合并发条件返回 unknown。支持的反证带进程内签名、依赖哈希、编译环境与候选绑定；恢复时重新运行检查，报告字典不能自行授权拒绝。此能力按检查器版本管理，未改变默认检测器契约或现有规则资格状态。
- 检查器显式绑定所支持规则的 revision；旧报告没有 revision 或规则契约升级后，必须补做资格验证才能产生该规则的反证。不存在成员的反证可根据对象构造函数中的实际字段赋值登记关联清理假设，按父对象合并，启用关联回收后正常验证；仅有指针类型不会生成候选。C++ 隐式生命周期、锁别名泄漏及同语句内未建模的锁状态变化保持 unknown。
- V3 正面举证和 V2b 拒绝审查分别记录入口池、目标、工具原始结果和复核封套。正面证据仍须通过现有确认验收；完整正反证据冲突进入 review。事实摘要、TOOLFACT 引用以及调用次数都不等于程序证明。
- `propose_related_candidate` 只能登记原函数或已查询函数中的具体位置，并关联父候选和工具证据。主 Ledger 保持冻结，关联候选通过独立追加 Ledger 登记、冻结、验证，最多一代；主 Ledger 的最终快照包含追加区。未完成的关联候选保留 review。条件宏风险绑定触发条件，未获得对应构建事实时不能确认或自动拒绝。
- 事实组发现的条件宏风险即使未开启一般关联回收，也进入追加 review 区并计数。检查点恢复保留原 UID、cluster、验证证据包和完整前序结果，不通过重新注册改变原裁决对象；恢复粒度是候选验证阶段，并不恢复供应商的会话执行状态。

- 候选不得因调度边界、超时或阶段失败而静默丢失；未深挖候选必须保留可审计状态。
- `verified`、`rejected`、`uncertain`/`needs_review` 的含义不能混淆，退出策略只消费约定视图。
- 去重必须保留 occurrence、替代证据和来源，不能仅按文本或行号合并。
- 确定性 proof、LLM 判断和引擎失败必须在元数据中可区分。
- 完整且无冲突的 proof 才能确定性确认或拒绝；正反 proof 冲突直接进入 `needs_review`。没有确定性反证时，模型的 `rejected` 只是一项模型意见，不能把候选从审计视图静默隐藏。
- `confirmed_via` 只在 confirmed 落点写入；`needs_review_sub_state` 与 review 视图的 rejected 呈现降级都不得改变 `candidate_disposition`、计分或 truth 归因。
- τ 通道、V3 复判与 V2b 裁决每个 rung 只允许一个手段且独立开关；同一 rung 不得叠加两个确认来源。
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

## 完整源码、事件与验证上下文

确定性入口、callee、Graph 和扩展 provider 读取完整函数正文；`max_function_lines` 仅限制模型展示，不能作为检测覆盖边界。源码缺失或截断必须进入未完成记录。Validator 在 token 预算以内保留完整函数，超预算时按防护、source/sink 和生命周期操作选择片段，并记录省略区间、源码摘要和续取引用；补充证据合并后重新拟合预算。上下文缺失且尚未补齐的模型判断保留待验证状态，证据版本参与缓存身份。

资源状态机使用带行、列和事件序号的操作序列。同一行的多个语句分别处理，文本后备屏蔽字符串、注释和宏定义中的伪操作，并保留循环头。编译器 CFG/读写事实可作为可追溯证据；文本顺序不能替代路径可行性证明。内存、FILE、DIR 的获取与释放按资源家族匹配，共享访问依据对象事实生成候选，命名不作为唯一门槛；跨线程可达性、共同锁、原子操作和所有权转移仍须验证。

规则语义变更保留 canonical ID、递增 revision 并重新验收。未取得可核验资格的新增/改动规则保持 experimental 且默认关闭；未改动的历史规则沿用 legacy pending 治理，不能因此通过正式发布资格门禁。独立生成器不带运行时 policy 时用于规则实验；产品扫描必须注入 preflight 的有效规则策略。
