# opencode 纯 LLM 最佳实践扫描报告

生成时间：2026-06-12 11:14:00 +08:00

## 结论

本次重新测试使用 `opencode --pure --model alibaba-cn/glm-5`，不复用 Z-Scope vulnerability-analyzer prompt，不调用 CodeQL、Z-Scope、benchmark ground truth、测试或静态分析器；候选生成只依赖带行号的源码上下文和 GLM-5 的代码审计推理。

这版流程按当前公开研究和业界 AI code review 的纯 LLM 最佳实践组织：repository-level context、分专题多 pass、证据路径约束、negative-evidence check、置信度分层、结构化 JSON 输出，以及后处理去重/行号规范化。这里的“最佳实践”指方法论已经对齐当前纯 LLM 审计的主流做法，不表示纯 LLM 能达到 Z-Scope 这类工具增强 pipeline 的覆盖能力上限。

最终 default view：

| 方案 | 结果数 | TP | FP | FP(raw) | 重复命中 | FN | 召回率 | 误报率 | Precision | F1 | 执行时间 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 旧 opencode GLM-5，Z-Scope 风格 prompt | 17 | 12 | 5 | 5 | 0 | 109 | 0.0992 | 0.2941 | 0.7059 | 0.1739 | 258s |
| 新 opencode GLM-5，纯 LLM 最佳实践 default | 12 | 10 | 1 | 2 | 1 | 111 | 0.0826 | 0.0909 | 0.9091 | 0.1515 | 660s |
| 新 opencode GLM-5，纯 LLM 最佳实践 with_review | 13 | 10 | 2 | 3 | 1 | 111 | 0.0826 | 0.1667 | 0.8333 | 0.1504 | 660s |

本次优化显著降低误报：default view 误报率从 `0.2941` 降到 `0.0909`，precision 从 `0.7059` 升到 `0.9091`。代价是召回下降：TP 从 12 降到 10。换句话说，纯 LLM 最佳实践更像“高置信审计报告”，不是高召回漏洞发现器。

## 方法说明

本次不再使用 Z-Scope prompt，而是使用纯 LLM 代码审计的最佳实践流程：

1. **源码上下文标准化**：生成 `source_bundle_numbered.txt`，只包含 `test/range/include`、`test/range/internal`、`test/range/src` 的源码和行号，不含 benchmark answer key、CodeQL、Z-Scope 或任何 analyzer 输出。
2. **分专题多 pass**：分别运行 memory/resource lifetime、concurrency/locking、bounds/integer/string、ownership/state-machine 四个审计 pass，避免单个大 prompt 混淆任务目标。
3. **证据路径约束**：每条 finding 必须包含 source/acquire、sink/release/missing-check、相关函数/共享状态路径。
4. **反证检查**：prompt 要求每条 finding 写出 `negative_evidence_checked`，即检查是否已有 cleanup、锁保护、长度校验、所有权转移。
5. **置信度分层**：`confirmed_issues` 用于 default view，`review_candidates` 用于 with_review view。
6. **确定性后处理**：只对四个 pass 的 JSON 输出做去重、类别规范化、行号从 bundle 全局行映射回源码行；不看 ground truth，不做漏洞发现。

这个设计对齐了当前纯 LLM 漏洞检测的主流建议：不要只给函数片段，而要给 repository-level/context-rich 信息；复杂任务要分解；模型输出必须证据化、结构化，并通过自检/反证降低 hallucination。参考包括 CORRECT 对 context-rich vulnerability evaluation 的论证、SECVULEVAL 对 C/C++ 真实漏洞 rich context 的强调，以及 LLM code security survey 对检测技术、数据集、指标和挑战的总结。

## 命中情况

default view 命中的 10 个 ground truth：

| ID | 主要问题类型 | 对应 finding |
| --- | --- | --- |
| RANGE-004 | format_string | `BP_LLM_2` `_executor_log_message` |
| RANGE-006 | double_free | `BP_LLM_1` `_executor_cleanup_resources` |
| RANGE-018 | null/state inconsistency | `BP_LLM_7` `_lifecycle_parse_control_message` |
| RANGE-021 | refcount/race | `BP_LLM_9` `_lifecycle_ref_get` |
| RANGE-022 | refcount/race | `BP_LLM_10` `_lifecycle_ref_put` |
| RANGE-023 | held_lock_callback | `BP_LLM_6` `_lifecycle_notify_entry_callback` |
| RANGE-024 | stack_escape | `BP_LLM_12` `_lifecycle_schedule_flush` |
| RANGE-028 | race/shared global | `BP_LLM_11` `_lifecycle_resize_metrics` |
| RANGE-029 | bounds/signed conversion | `BP_LLM_8` `_lifecycle_recv_packet` |
| RANGE-030 | off_by_one/bounds | `BP_LLM_5` `_lifecycle_format_topic` |

effective FP 只有 1 个：`BP_LLM_3` `_lifecycle_add_entry` 的 memory leak。raw FP 里另有 `BP_LLM_4` `_lifecycle_fire_registered_callback`，但 evaluator 将它归为 duplicate-of-matched，不计入 effective FP。

with_review 额外加入 `BP_LLM_R1` `_executor_execute_task` lock-order/race 候选，但没有新增 TP，只增加 1 个 effective FP。因此当前纯 LLM best-practice 版本建议以 default view 作为主结果。

## 与旧版 opencode 的差异

旧版 prompt 强调“prefer fewer high-quality concrete issues”，但仍是一次性 repo-wide 审计，并复用了 Z-Scope 的 skill/checklist 语汇。它召回更高，命中了 `ISSUE41-006`、`ISSUE42-006`、`ISSUE42-010`、`ISSUE42-028`、`RANGE-032`、`RANGE-047`、`REAL-018` 等本次未命中的问题；但 FP 也更多，误报率 `0.2941`。

新版 prompt 更符合纯 LLM 高置信审计实践：每个专题独立推理并强制反证，因此结果更少、更稳、更容易人工复核。它额外稳定命中了旧版没命中的 `RANGE-018`、`RANGE-022`、`RANGE-023`、`RANGE-028`、`RANGE-029`，但漏掉若干跨模块或真实项目 issue，尤其是 `REAL-018`。这说明纯 LLM 单靠 prompt engineering 很难同时获得高 precision 和高 recall；要覆盖 `REAL-*` 和 `ISSUE41/42-*` 这类复杂问题，仍需要 Z-Scope 的工具化上下文、跨函数检索和验证循环。

## 执行时间

纳入本次 best-practice 结果的四个候选生成 pass：

| Pass | 时间 |
| --- | ---: |
| memory_resource_lifetime | 112.65s |
| concurrency_locking | 139.16s |
| bounds_integer_string | 259.48s |
| ownership_state_machine | 148.56s |
| 合计 | 659.85s |

曾试跑一个 opencode merge/verify pass，但 opencode 尝试读取/写入本地文件，超出了本次“纯 LLM 只看输入上下文”的边界；因此该 merge 输出未作为检测来源，也未计入 660s 主结果。最终报告使用四个专题 pass 的直接 LLM 输出加确定性去重/规范化。

## 产物

- 源码上下文包：`test/range/benchmark_runs/opencode_pure_llm_best_practice_glm5_20260612_104926/source_bundle_numbered.txt`
- 四个专题 prompt：`prompt_memory_resource.txt`、`prompt_concurrency_locking.txt`、`prompt_bounds_integer_string.txt`、`prompt_ownership_state.txt`
- 四个专题输出：`memory_resource.stdout.txt`、`concurrency_locking.stdout.txt`、`bounds_integer_string.stdout.txt`、`ownership_state.stdout.txt`
- 最终报告 JSON：`opencode_best_practice_report.json`
- default 评估：`opencode_best_practice_evaluation.json`
- with_review 评估：`opencode_best_practice_evaluation.with_needs_review.json`

## 参考

- [CORRECT / Everything You Wanted to Know About LLM-based Vulnerability Detection](https://arxiv.org/html/2504.13474v1)
- [Benchmarking LLMs for Real-World C/C++ Vulnerability Detection / SECVULEVAL](https://openreview.net/forum?id=0A3qzLmRHd)
- [A Systematic Literature Review of LLMs in Code Security](https://arxiv.org/html/2412.15004v4)
- [AI Code Review in 2025: Technologies, Challenges & Best Practices](https://www.mend.io/blog/ai-code-review-technologies-challenges-best-practices/)
