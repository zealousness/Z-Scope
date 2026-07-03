# Benchmark Metrics

>Model: GLM-5

## 一、效率与成本指标

### 1.1 单次运行总览

| 阶段 | Agent | Total Tokens | Prompt Tokens | Completion Tokens | 用时 | 备注 |
|---|---|---:|---:|---:|---:|---|
| Total | - | 95,976,629 | 88,801,257 | 7,175,372 | 23,286s (7.3h) | Token 使用 `zscope_run.log` 的 `[LLM API Trace]` 聚合；用时为外层 scan wall time |
| index warmup<br>(step0) | - | 0 | 0 | 0 | 14.98s | 仅含 scan 内 shared semantics 与 entry code-index lookup；`--build-cpg` 缓存复用 |
| discover_entries<br>(step1) | - | 0 | 0 | 0 | 0 | 直接使用 `entry_functions_list.json` |
| premodel_reachable_callees<br>(step1.5) | - | 0 | 0 | 0 | 4.00s | 本次日志显示 `0 modeled`，均复用 snapshot/cache |
| model_entry<br>(step2) | semantic_modeler | 2,227,333 | 1,915,708 | 311,625 | 15,110.00s | workflow step 累计工作时长 |
| focused_subagent_planning<br>(step3) |  skill selection | 693,731 | 323,973 | 369,758 | 49,466.00s | 主要为 skill selection；该 step 内还会执行 deep_worker，见下一行 |
| focused_subagent_planning<br>(step3) | deep_worker | 19,279,649 | 16,993,257 | 2,286,392 | 106,037.00s | Agent session 累计 |
| vulnerability_mining<br>(step4) | vulnerability_analyzer | 30,251,564 | 29,601,504 | 650,060 | 39,419.00s | workflow step 累计工作时长 |
| validate_findings<br>(step5) | validator_agent | 43,358,980 | 39,865,631 | 3,493,349 | 118,275.00s | workflow step 累计工作时长 |
| persist_report<br>(step6) | issue_reconciler_agent | 165,372 | 101,184 | 64,188 | 912.00s | 包含 batch 语义去重中的 issue_reconciler 调用 |

### 1.2 单入口平均

>入口数量：152

| 阶段 | Agent | Total Tokens | Prompt Tokens | Completion Tokens | 用时 | 备注 |
|---|---|---:|---:|---:|---:|---|
| Total | - | 631,425.19 | 584,218.80 | 47,206.39 | 153.20s | 以 152 个入口均摊外层 scan wall time 与 API trace token |
| index warmup<br>(step0) | - | 0 | 0 | 0 | 0.10s | 仅含 scan 内 shared semantics 与 entry code-index lookup |
| discover_entries<br>(step1) | - | 0 | 0 | 0 | 0 |  直接使用 `entry_functions_list.json` |
| premodel_reachable_callees<br>(step1.5) | - | 0 | 0 | 0 | 0.03s | 本次日志显示 `0 modeled`，均复用 snapshot/cache |
| model_entry<br>(step2) | semantic_modeler | 14,653.51 | 12,603.34 | 2,050.16 | 99.41s |  |
| focused_subagent_planning<br>(step3) |  skill selection | 4,564.02 | 2,131.40 | 2,432.62 | 325.43s | 主要为 skill selection；该 step 内还会执行 deep_worker |
| focused_subagent_planning<br>(step3) | deep_worker | 126,839.80 | 111,797.74 | 15,042.05 | 697.61s | Agent session 累计；实际执行发生在 step3 |
| vulnerability_mining<br>(step4) | vulnerability_analyzer | 199,023.45 | 194,746.74 | 4,276.71 | 259.34s |  |
| validate_findings<br>(step5) | validator_agent | 285,256.45 | 262,273.89 | 22,982.56 | 778.12s |  |
| persist_report<br>(step6) | issue_reconciler_agent | 1,087.97 | 665.68 | 422.29 | 6.00s | 包含 batch 语义去重中的 issue_reconciler 调用 |

说明：

- `index warmup（step0）` 不属于 `zscope/workflows/default.yaml` 的步骤。它表示 CLI 创建 `CodeIndex`、加载/预热索引、Clang/SVF/KnowledgeDB 准备等工作流开始前的成本。
- 用时口径：`Total` 用时来自 `metrics.json.scan_wall_seconds`；各 workflow step 用时来自日志中 step start/completed 的累计工作时长，因批量扫描并行执行，不能与外层 wall time 直接相加。

## 二、工具质量指标

### 2.1 不同工具的单次运行总计调用次数

| 工具名 | 不同 Agent 总计调用次数 | semantic_modeler | skill_selection | deep_worker | vulnerability_analyzer | validator_agent | issue_reconciler_agent |
|---|---:|---:|---:|---:|---:|---:|---:|
| get_function_impl | 1,945 | 17 | 0 | 0 | 0 | 1,928 | 0 |
| get_function_snapshot | 2,814 | 286 | 0 | 2,125 | 400 | 3 | 0 |
| get_file_snippet | 6,365 | 326 | 0 | 2,657 | 741 | 2,641 | 0 |
| get_type_info | 1,151 | 169 | 0 | 556 | 107 | 319 | 0 |
| get_callers | 1,231 | 60 | 0 | 953 | 218 | 0 | 0 |
| get_call_graph | 698 | 0 | 0 | 90 | 17 | 591 | 0 |
| get_data_flow | 77 | 0 | 0 | 51 | 26 | 0 | 0 |
| get_deep_call_context | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| list_known_functions | 561 | 0 | 0 | 0 | 0 | 561 | 0 |
| find_function_pointers | 13 | 0 | 0 | 0 | 13 | 0 | 0 |
| query_pointer_alias | 18 | 0 | 0 | 17 | 1 | 0 | 0 |
| verify_taint_reachability | 66 | 0 | 0 | 63 | 3 | 0 | 0 |


### 2.2 不同工具的单入口平均调用次数

>入口数量：152

| 工具名 | 不同 Agent 总计调用次数 | semantic_modeler | skill_selection | deep_worker | vulnerability_analyzer | validator_agent | issue_reconciler_agent |
|---|---:|---:|---:|---:|---:|---:|---:|
| get_function_impl | 12.80 | 0.11 | 0.00 | 0.00 | 0.00 | 12.68 | 0.00 |
| get_function_snapshot | 18.51 | 1.88 | 0.00 | 13.98 | 2.63 | 0.02 | 0.00 |
| get_file_snippet | 41.88 | 2.14 | 0.00 | 17.48 | 4.88 | 17.38 | 0.00 |
| get_type_info | 7.57 | 1.11 | 0.00 | 3.66 | 0.70 | 2.10 | 0.00 |
| get_callers | 8.10 | 0.39 | 0.00 | 6.27 | 1.43 | 0.00 | 0.00 |
| get_call_graph | 4.59 | 0.00 | 0.00 | 0.59 | 0.11 | 3.89 | 0.00 |
| get_data_flow | 0.51 | 0.00 | 0.00 | 0.34 | 0.17 | 0.00 | 0.00 |
| get_deep_call_context | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| list_known_functions | 3.69 | 0.00 | 0.00 | 0.00 | 0.00 | 3.69 | 0.00 |
| find_function_pointers | 0.09 | 0.00 | 0.00 | 0.00 | 0.09 | 0.00 | 0.00 |
| query_pointer_alias | 0.12 | 0.00 | 0.00 | 0.11 | 0.01 | 0.00 | 0.00 |
| verify_taint_reachability | 0.43 | 0.00 | 0.00 | 0.41 | 0.02 | 0.00 | 0.00 |

### 2.3 不同工具的质量指标

| 工具名 | 单次运行总计调用次数 | 成功率 | 格式错误率 | 参数错误率 | 其他错误率 | 空结果率 | Loop Guard 警告次数 | Loop Guard 拦截次数 | 证据命中率 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| get_function_impl | 1,945 | 98.71% | 0.00% | 1.23% | 0.05% | 0.00% | 5 | 1 | 95.63% |
| get_function_snapshot | 2,814 | 100.00% | 0.00% | 0.00% | 0.00% | 1.88% | 4 | 0 | 25.30% |
| get_file_snippet | 6,365 | 98.82% | 0.00% | 1.12% | 0.06% | 0.00% | 155 | 5 | 90.77% |
| get_type_info | 1,151 | 81.74% | 0.00% | 18.26% | 0.00% | 0.00% | 3 | 0 | 81.74% |
| get_callers | 1,231 | 100.00% | 0.00% | 0.00% | 0.00% | 8.45% | 8 | 0 | 91.55% |
| get_call_graph | 698 | 100.00% | 0.00% | 0.00% | 0.00% | 23.35% | 1 | 0 | 100.00% |
| get_data_flow | 77 | 100.00% | 0.00% | 0.00% | 0.00% | 100.00% | 0 | 0 | 0.00% |
| get_deep_call_context | 0 | - | - | - | - | - | 0 | 0 | - |
| list_known_functions | 561 | 100.00% | 0.00% | 0.00% | 0.00% | 46.07% | 18 | 1 | 0.00% |
| find_function_pointers | 13 | 100.00% | 0.00% | 0.00% | 0.00% | 100.00% | 0 | 0 | 0.00% |
| query_pointer_alias | 18 | 100.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0 | 0 | 83.33% |
| verify_taint_reachability | 66 | 100.00% | 0.00% | 0.00% | 0.00% | 57.58% | 0 | 0 | 19.70% |

### 2.4 不同工具的错误情况统计

| 工具名 | 错误总次数 | Function not found | Loop Guard blocked repeated call | Failed to read file | Sensitive path denied by policy | Type not found |
|---|---:|---:|---:|---:|---:|---:|
| get_function_impl | 25 | 24 | 1 | 0 | 0 | 0 |
| get_function_snapshot | 0 | 0 | 0 | 0 | 0 | 0 |
| get_file_snippet | 75 | 0 | 4 | 69 | 2 | 0 |
| get_type_info | 210 | 0 | 0 | 0 | 0 | 210 |
| get_callers | 0 | 0 | 0 | 0 | 0 | 0 |
| get_call_graph | 0 | 0 | 0 | 0 | 0 | 0 |
| get_data_flow | 0 | 0 | 0 | 0 | 0 | 0 |
| get_deep_call_context | 0 | 0 | 0 | 0 | 0 | 0 |
| list_known_functions | 0 | 0 | 0 | 0 | 0 | 0 |
| find_function_pointers | 0 | 0 | 0 | 0 | 0 | 0 |
| query_pointer_alias | 0 | 0 | 0 | 0 | 0 | 0 |
| verify_taint_reachability | 0 | 0 | 0 | 0 | 0 | 0 |

说明：
- `get_deep_call_context` 调用次数为 0 的原因是因为默认 workflow 下它对所有实际运行 Agent 都不可见：`vulnerability_analyzer` 的 Agent tools 声明了该工具，但当前 active vulnerability skills 未声明它；其他 Agent 本身也未声明该工具，因此运行时不会暴露给任何 Agent。
- `参数错误` 包括：`Function not found`、`Failed to read file`、`Type not found`;`其他错误`包括：`Sensitive path denied by policy`、`Loop Guard blocked repeated call`。
- `证据命中率` 指的是工具返回的结构化锚点（file/function/line/symbol/candidate_id/dedup_key 等）是否在后续 finding、validation result、audit observation 或 rejection evidence 中显式出现。仅用 Python 代码计算时，`证据命中率` 不能等价于完整语义层面的“有效调用率”。


## 三、上下文质量指标（待分析）

## 四、漏洞指标

| 视图 | Report Issues | Ground Truth | TP | FP | FN | Recall | Precision | F1 | 误报率 | Needs Review 比例 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 默认视图 | 190 | 121 | 98 | 14 | 23 | 80.99% | 87.50% | 84.12% | 12.50% | - |
| Needs Review 视图 | 265 | 121 | 111 | 27 | 10 | 91.74% | 80.43% | 85.71% | 19.57% | 28.30% |

说明：

- `误报率` 使用 `metrics.json` 中的 `false_positive_rate` 字段。
- `Needs Review 比例 = (Needs Review 视图 Report Issues - 默认视图 Report Issues) / Needs Review 视图 Report Issues = 75 / 265 = 28.30%`。
