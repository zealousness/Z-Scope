# 语义建模强化版 benchmark（20260910T015537Z）——开发交接档案

## 一、数据归档位置（Windows 侧仓库内）

| 数据 | 路径 |
|---|---|
| 本轮 run 目录（全部原始产物） | `benchmark-artifacts/c_cpp/trial/20260910T015537Z/run-01/` |
| ├ report.json（双视图 issues） | 同目录（314MB 级） |
| ├ score.json / score.log | 同目录 |
| ├ llm_usage_events.jsonl（按调用归因的 tokens 明细） | 同目录 |
| ├ scan.log（6.06MB，线程级活动） | 同目录 |
| ├ summary.json / tool-health.json | 同目录 |
| └ validator-replay-bundle.json | 同目录 |
| 对比基线 run | `benchmark-artifacts/c_cpp/trial/20260905T130307Z/`（R2）、`20260906T132051Z/`（守卫）、`20260908T055018Z/`（上轮，含 score.v2.json） |
| 真值 | `test/range/benchmark/ground_truth.json` |
| 分析脚本（可复跑） | `benchmarks/experiments/balanced_confirmed_tp/sem_run_analysis.py`（三合一）、`sem_regression_refine.py`（回退分解）、`sem_snapshot_attribution.py`（语义建模候选归因） |
| 旧轮因果/backlog | `benchmarks/experiments/balanced_confirmed_tp/m5tpr_causal.py`、`m5_tpr_backlog.md` |

## 二、核心数字（开发自取，均来自上表原始产物）

- 双视图：confirm TP=68/FP=44（召回 50.0%，精度 66.0%）；review TP=96/FP_raw=358（召回 70.6%，精度 22.1%）。
- 对比上轮（20260908T055018Z）：confirm −22 TP；review −25 TP、+254 raw FP；merged 丢失 26 truth、新增 0。
- tokens：validator_agent 106.76M（initial 5.78M + targeted_investigation 100.98M）/ semantic_modeler 5.22M / decision_explainer 25K / active_discovery 0；合计 ~112M（上轮 46.1M）。
- 语义建模候选：`candidate_source=="semantic_snapshot"` 共 243 条（确认 18）→ **TP=0、确认 FP=18**；类别为宽泛家族标签（error_handling 55/state_protocol 25/concurrency 21），rule 全部 None。
- AST 层 `candidate_priority_group=="semantic_suspicious_point"` 的 40 条 → 22 确认 TP / 0 FP（确定性产出，非语义建模挖掘）。
- funnel：exclusive_by_discovery = {deterministic_rule 162, semantic_modeling 243, unknown 259}；by_discovery_and_decision 中 semantic_modeling|validator_llm 18、semantic_modeling|unresolved 225。

## 三、merged 丢失的 26 truth（上轮有、本轮无）

ISSUE42-013, ISSUE42-021, ISSUE42-026, ISSUE42-027, ISSUE43-012, ISSUE43-016, ISSUE43-017,
RANGE-005, RANGE-009, RANGE-014, RANGE-016, RANGE-020, RANGE-021, RANGE-022, RANGE-031, RANGE-038,
RANGE-041, RANGE-044, RANGE-048, REAL-001, REAL-004, REAL-005, REAL-021, REAL-024, REAL-025, REAL-031

其中多数本轮**同函数条目=0**（确定性候选失语），语义建模未补位。

## 四、开发待查的三个怀疑点

1. 语义建模候选类别太宽泛（error_handling/state_protocol 等家族标签）→ 无法与 truth 的缺陷级类别配对；
2. 确定性规则失语站点清单（上表 26 truth 的 function 列表见 `sem_regression_refine.py` 输出）；
3. validator 的 targeted_investigation 100.98M tokens 失控（上轮同阶段体量小得多）。

## 五、已知的计量缺口（修复建议给开发）

- issue 级 `discovered_by` 为空（funnel 归因在候选信封层，issue 上只有 `candidate_source`）——特性/来源归因请用 `candidate_source` 字段；
- 验证特性旗标（validation_uncertain_replay_review / validation_demote_source_lifecycle_confirm / validation_obligation_infunction_release_guard / validation_checked_proofs）在 issue 上全部缺席（重写移除了注入）；score.log 无 M3′/checked_proofs 痕迹。
