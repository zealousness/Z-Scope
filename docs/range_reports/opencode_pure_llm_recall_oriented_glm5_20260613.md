# opencode 纯 LLM 召回优先扫描报告

生成时间：2026-06-13 +08:00

## 结论

本次按“尽可能多命中 TP”的目标重新跑了一版 `opencode --pure --model alibaba-cn/glm-5`。候选生成阶段仍保持纯 LLM 边界：只使用带行号的 `test/range` 源码上下文，不使用 benchmark ground truth、CodeQL、Z-Scope、grep、shell、测试或静态分析器。Ground truth 只在最后 evaluator 评估阶段使用。

召回优先版显著提高 TP：default view 从 best-practice 的 10 个 TP 提升到 50 个 TP，with_review 提升到 51 个 TP。代价也很直接：default 误报率从 `0.0909` 升到 `0.5098`，with_review 误报率升到 `0.5785`。这说明纯 LLM 通过 prompt 和多 pass 可以把召回拉高到约 `0.42`，但要继续接近 Z-Scope full pipeline，仍需要工具化上下文、跨函数检索和验证闭环。

## 总览数据

| 方案 | 结果数 | TP | FP | FP(raw) | 重复命中 | FN | 召回率 | 误报率 | Precision | F1 | 执行时间 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| best-practice default | 12 | 10 | 1 | 2 | 1 | 111 | 0.0826 | 0.0909 | 0.9091 | 0.1515 | 660s |
| best-practice with_review | 13 | 10 | 2 | 3 | 1 | 111 | 0.0826 | 0.1667 | 0.8333 | 0.1504 | 660s |
| recall-oriented confirmed_only | 120 | 47 | 33 | 73 | 40 | 74 | 0.3884 | 0.4125 | 0.5875 | 0.4677 | 2546s |
| recall-oriented default | 152 | 50 | 52 | 102 | 50 | 71 | 0.4132 | 0.5098 | 0.4902 | 0.4484 | 2546s |
| recall-oriented with_review | 173 | 51 | 70 | 122 | 52 | 70 | 0.4215 | 0.5785 | 0.4215 | 0.4215 | 2546s |
| recall-oriented raw default | 162 | 50 | 54 | 112 | 58 | 71 | 0.4132 | 0.5192 | 0.4808 | 0.4444 | 2546s |
| recall-oriented raw with_review | 184 | 51 | 72 | 133 | 61 | 70 | 0.4215 | 0.5854 | 0.4146 | 0.4180 | 2546s |

`recall-oriented default` 使用 confirmed + probable 候选；`with_review` 额外加入 speculative 候选。raw 版本不做跨 pass 去重，只用于确认去重是否误伤 TP。raw 结果没有增加 TP，说明当前保守去重没有吞掉有效召回，正式对比建议使用去重后的 recall-oriented default/with_review。

## 方法

本次不使用 Z-Scope 的 vulnerability-analyzer prompt，也不复用 best-practice 的高置信约束，而是改成 recall-first 的纯 LLM 审计：

1. **源码上下文**：复用 `source_bundle_numbered.txt`，包含 `test/range/include`、`test/range/internal`、`test/range/src` 的源码和行号。
2. **六个专题 pass**：`memory_resource_recall`、`concurrency_recall`、`bounds_integer_recall`、`state_ownership_recall`、`error_init_recall`、`protocol_worker_recall`。
3. **三层候选**：`confirmed_issues`、`probable_issues`、`speculative_issues`；default 纳入 confirmed + probable，with_review 纳入全部候选。
4. **召回优先指令**：要求模型报告不同资源、不同函数、不同错误路径和不同并发根因，不能只报最高置信问题。
5. **确定性后处理**：只做 JSON 恢复、类别规范化、保守去重和报告格式转换；不读取 ground truth，不新增漏洞判断。

opencode formatted 输出中有少量非法 JSON 转义和 UTF-16/NUL 包装，因此后处理按 issue 对象逐条恢复。原始候选 184 条，去重后 confirmed 120 条、probable 32 条、speculative 21 条；default 152 条，with_review 173 条。

## 命中情况

recall-oriented default 命中的 50 个 ground truth：

`ISSUE41-002`、`ISSUE41-006`、`ISSUE42-002`、`ISSUE42-006`、`ISSUE42-007`、`ISSUE42-010`、`ISSUE42-014`、`ISSUE42-017`、`RANGE-002`、`RANGE-004`、`RANGE-006`、`RANGE-012`、`RANGE-013`、`RANGE-018`、`RANGE-019`、`RANGE-020`、`RANGE-021`、`RANGE-022`、`RANGE-023`、`RANGE-024`、`RANGE-027`、`RANGE-028`、`RANGE-029`、`RANGE-030`、`RANGE-032`、`RANGE-033`、`RANGE-034`、`RANGE-040`、`RANGE-042`、`RANGE-045`、`RANGE-047`、`REAL-002`、`REAL-003`、`REAL-004`、`REAL-006`、`REAL-008`、`REAL-009`、`REAL-010`、`REAL-013`、`REAL-015`、`REAL-017`、`REAL-018`、`REAL-021`、`REAL-023`、`REAL-024`、`REAL-026`、`REAL-027`、`REAL-028`、`REAL-029`、`REAL-032`。

with_review 额外命中 `ISSUE42-013`，因此 TP 从 50 增至 51。`REAL-018` 在本轮 recall-oriented default 中已命中。

## 执行时间

六个 pass 合计 `2545.67s`，约 42.4 分钟：

| Pass | 时间 |
| --- | ---: |
| memory_resource_recall | 688.54s |
| concurrency_recall | 187.08s |
| bounds_integer_recall | 665.33s |
| state_ownership_recall | 380.18s |
| error_init_recall | 274.23s |
| protocol_worker_recall | 350.31s |

召回优先版比 best-practice 版慢很多，主要原因是 prompt 鼓励模型输出更多候选和更宽的专题覆盖。它仍比完整 Z-Scope pipeline 快，但 precision 明显低于 Z-Scope。

## 解读

这版回答了“纯 LLM 在高召回目标下是否只能输出很少告警”的问题：不是。只要 prompt 明确要求 recall-first、多专题、多置信层候选，GLM-5 可以输出 150+ 条候选，并把 TP 从 10 提到 50/51。

但它也暴露了纯 LLM 的边界：没有工具验证时，很多 plausible finding 会变成 effective FP；同时仍有 70 个 ground truth 未命中。未命中的部分主要仍是跨函数数据流、复杂并发、资源所有权链和状态机路径，靠 prompt engineering 很难稳定覆盖。

后续如果还想继续提高纯 LLM 召回，可以尝试按文件/入口分片、多轮独立采样、让模型先列函数级风险清单再逐项展开。但这会进一步增加告警数和误报，需要另配验证层，否则报告可用性会下降。

## 产物

- Run 目录：`test/range/benchmark_runs/opencode_pure_llm_recall_oriented_glm5_20260613_092210`
- 源码上下文包：`source_bundle_numbered.txt`
- 六个 prompt：`prompt_memory_resource_recall.txt`、`prompt_concurrency_recall.txt`、`prompt_bounds_integer_recall.txt`、`prompt_state_ownership_recall.txt`、`prompt_error_init_recall.txt`、`prompt_protocol_worker_recall.txt`
- 去重后报告：`opencode_recall_oriented_report.json`
- 去重后评估：`opencode_recall_oriented_evaluation.json`、`opencode_recall_oriented_evaluation.with_needs_review.json`
- raw no-dedup 报告：`opencode_recall_oriented_raw_report.json`
- raw no-dedup 评估：`opencode_recall_oriented_raw_evaluation.json`、`opencode_recall_oriented_raw_evaluation.with_needs_review.json`
- 后处理摘要：`postprocess_summary.json`
