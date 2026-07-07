# Benchmark Metrics

>Model: GLM-5

## 一、效率与成本指标

### 1.1 单次运行总览

| 阶段 | Agent | Total Tokens | Prompt Tokens | Completion Tokens | 用时 | 备注 |
|---|---|---:|---:|---:|---:|---|
| Total | - | 131,470,129 | 122,699,113 | 8,771,016 | 18,190s (5.1h) | Token 使用 `zscope_run.log` 的 `[LLM API Trace]` 聚合；用时为外层 scan wall time |
| build_cpg / index warmup<br>(step0) | - | 0 | 0 | 0 | 101.00s | 工作流开始前的 CodeIndex/clangd/CPG 准备成本；无 LLM token |
| discover_entries<br>(step1) | - | 0 | 0 | 0 | 0.00s | 直接使用配置的 entries；无 LLM token |
| premodel_reachable_callees<br>(step1.5) | semantic_modeler | 1,132,138 | 968,226 | 163,912 | 5,951.00s | workflow step 累计工作时长 |
| model_entry<br>(step2) | semantic_modeler | 3,233,792 | 2,857,409 | 376,383 | 13,870.00s | workflow step 累计工作时长 |
| focused_subagent_planning<br>(step3) | skill_selection | 709,638 | 300,172 | 409,466 | 9,498.00s | skill routing 的 Agent session 累计；该 step 内还会执行 deep_worker |
| focused_subagent_planning<br>(step3) | deep_worker | 31,747,684 | 28,658,304 | 3,089,380 | 110,088.00s | Agent session 累计；实际执行发生在 step3 |
| vulnerability_mining<br>(step4) | vulnerability_analyzer | 46,788,335 | 45,931,540 | 856,795 | 30,737.00s | workflow step 累计工作时长 |
| validate_findings<br>(step5) | validator_agent | 47,672,168 | 43,874,657 | 3,797,511 | 99,159.00s | workflow step 累计工作时长 |
| persist_report<br>(step6) | issue_reconciler_agent | 186,374 | 108,805 | 77,569 | 2,341.00s | 包含 batch 语义去重中的 issue_reconciler 调用 |

### 1.2 单入口平均

>入口数量：174

| 阶段 | Agent | Total Tokens | Prompt Tokens | Completion Tokens | 用时 | 备注 |
|---|---|---:|---:|---:|---:|---|
| Total | - | 755,575.45 | 705,167.32 | 50,408.14 | 104.54s | 以入口数量均摊外层 scan wall time 与 API trace token |
| build_cpg / index warmup<br>(step0) | - | 0.00 | 0.00 | 0.00 | 0.58s | 工作流开始前准备成本均摊 |
| discover_entries<br>(step1) | - | 0.00 | 0.00 | 0.00 | 0.00s | 直接使用配置的 entries |
| premodel_reachable_callees<br>(step1.5) | semantic_modeler | 6,506.54 | 5,564.52 | 942.02 | 34.20s |  |
| model_entry<br>(step2) | semantic_modeler | 18,585.01 | 16,421.89 | 2,163.12 | 79.71s |  |
| focused_subagent_planning<br>(step3) | skill_selection | 4,078.38 | 1,725.13 | 2,353.25 | 54.59s | skill routing session 累计 |
| focused_subagent_planning<br>(step3) | deep_worker | 182,457.95 | 164,702.90 | 17,755.06 | 632.69s | Agent session 累计；实际执行发生在 step3 |
| vulnerability_mining<br>(step4) | vulnerability_analyzer | 268,898.48 | 263,974.37 | 4,924.11 | 176.65s |  |
| validate_findings<br>(step5) | validator_agent | 273,977.98 | 252,153.20 | 21,824.78 | 569.88s |  |
| persist_report<br>(step6) | issue_reconciler_agent | 1,071.11 | 625.32 | 445.80 | 13.45s | 包含 batch 语义去重中的 issue_reconciler 调用 |

说明：
- `build_cpg / index warmup（step0）` 不属于 `zscope/workflows/default.yaml` 的步骤，表示 CLI 创建 CodeIndex、clangd/CPG/KnowledgeDB 准备等工作流开始前成本。
- 用时口径：`Total` 用时来自 `metrics.json.scan_wall_seconds`；workflow step 用时来自日志 step start/completed 的累计工作时长；`deep_worker` 与 `issue_reconciler_agent` 使用 conversation session 累计时长。
- 报告归档口径 token：Prompt 121,046,468，Completion 8,034,525，Total 129,425,656。

## 二、工具质量指标

### 2.1 不同工具的单次运行总计调用次数

| 工具名 | 不同 Agent 总计调用次数 | semantic_modeler | skill_selection | deep_worker | vulnerability_analyzer | validator_agent | issue_reconciler_agent |
|---|---:|---:|---:|---:|---:|---:|---:|
| get_function_impl | 2,455 | 105 | 0 | 0 | 0 | 2,350 | 0 |
| get_function_snapshot | 3,950 | 597 | 0 | 2,924 | 426 | 3 | 0 |
| get_file_snippet | 9,412 | 762 | 0 | 4,399 | 1,196 | 3,055 | 0 |
| get_type_info | 1,700 | 347 | 0 | 781 | 145 | 427 | 0 |
| get_callers | 1,830 | 132 | 0 | 1,442 | 256 | 0 | 0 |
| get_call_graph | 928 | 0 | 0 | 143 | 21 | 764 | 0 |
| get_data_flow | 119 | 0 | 0 | 90 | 29 | 0 | 0 |
| get_deep_call_context | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| list_known_functions | 747 | 0 | 0 | 0 | 0 | 747 | 0 |
| find_function_pointers | 12 | 0 | 0 | 0 | 12 | 0 | 0 |
| query_pointer_alias | 19 | 0 | 0 | 19 | 0 | 0 | 0 |
| verify_taint_reachability | 120 | 0 | 0 | 117 | 3 | 0 | 0 |

### 2.2 不同工具的单入口平均调用次数

>入口数量：174

| 工具名 | 不同 Agent 总计调用次数 | semantic_modeler | skill_selection | deep_worker | vulnerability_analyzer | validator_agent | issue_reconciler_agent |
|---|---:|---:|---:|---:|---:|---:|---:|
| get_function_impl | 14.11 | 0.60 | 0.00 | 0.00 | 0.00 | 13.51 | 0.00 |
| get_function_snapshot | 22.70 | 3.43 | 0.00 | 16.80 | 2.45 | 0.02 | 0.00 |
| get_file_snippet | 54.09 | 4.38 | 0.00 | 25.28 | 6.87 | 17.56 | 0.00 |
| get_type_info | 9.77 | 1.99 | 0.00 | 4.49 | 0.83 | 2.45 | 0.00 |
| get_callers | 10.52 | 0.76 | 0.00 | 8.29 | 1.47 | 0.00 | 0.00 |
| get_call_graph | 5.33 | 0.00 | 0.00 | 0.82 | 0.12 | 4.39 | 0.00 |
| get_data_flow | 0.68 | 0.00 | 0.00 | 0.52 | 0.17 | 0.00 | 0.00 |
| get_deep_call_context | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| list_known_functions | 4.29 | 0.00 | 0.00 | 0.00 | 0.00 | 4.29 | 0.00 |
| find_function_pointers | 0.07 | 0.00 | 0.00 | 0.00 | 0.07 | 0.00 | 0.00 |
| query_pointer_alias | 0.11 | 0.00 | 0.00 | 0.11 | 0.00 | 0.00 | 0.00 |
| verify_taint_reachability | 0.69 | 0.00 | 0.00 | 0.67 | 0.02 | 0.00 | 0.00 |

### 2.3 不同工具的质量指标

| 工具名 | 单次运行总计调用次数 | 成功率 | 格式错误率 | 参数错误率 | 其他错误率 | 空结果率 | Loop Guard 警告次数 | Loop Guard 拦截次数 | 证据命中率 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| get_function_impl | 2,455 | 99.51% | 0.00% | 0.49% | 0.00% | 0.00% | 1 | 0 | 95.11% |
| get_function_snapshot | 3,950 | 100.00% | 0.00% | 0.00% | 0.00% | 14.43% | 10 | 0 | 23.06% |
| get_file_snippet | 9,412 | 99.10% | 0.00% | 0.83% | 0.07% | 0.00% | 225 | 12 | 92.15% |
| get_type_info | 1,700 | 79.71% | 0.00% | 20.29% | 0.00% | 0.00% | 4 | 0 | 79.71% |
| get_callers | 1,830 | 100.00% | 0.00% | 0.00% | 0.00% | 8.58% | 16 | 0 | 91.42% |
| get_call_graph | 928 | 100.00% | 0.00% | 0.00% | 0.00% | 20.15% | 3 | 0 | 99.89% |
| get_data_flow | 119 | 100.00% | 0.00% | 0.00% | 0.00% | 100.00% | 0 | 0 | 0.00% |
| get_deep_call_context | 0 | - | - | - | - | - | 0 | 0 | - |
| list_known_functions | 747 | 100.00% | 0.00% | 0.00% | 0.00% | 46.78% | 27 | 0 | 0.00% |
| find_function_pointers | 12 | 100.00% | 0.00% | 0.00% | 0.00% | 100.00% | 0 | 0 | 0.00% |
| query_pointer_alias | 19 | 100.00% | 0.00% | 0.00% | 0.00% | 5.26% | 0 | 0 | 68.42% |
| verify_taint_reachability | 120 | 100.00% | 0.00% | 0.00% | 0.00% | 53.33% | 0 | 0 | 22.50% |

### 2.4 不同工具的错误情况统计

| 工具名 | 错误总次数 | Function not found | Failed to read file | Loop Guard blocked repeated call | Sensitive path denied by policy | Type not found |
|---|---:|---:|---:|---:|---:|---:|
| get_function_impl | 12 | 12 | 0 | 0 | 0 | 0 |
| get_function_snapshot | 0 | 0 | 0 | 0 | 0 | 0 |
| get_file_snippet | 85 | 0 | 77 | 7 | 1 | 0 |
| get_type_info | 345 | 0 | 0 | 0 | 0 | 345 |
| get_callers | 0 | 0 | 0 | 0 | 0 | 0 |
| get_call_graph | 0 | 0 | 0 | 0 | 0 | 0 |
| get_data_flow | 0 | 0 | 0 | 0 | 0 | 0 |
| get_deep_call_context | 0 | 0 | 0 | 0 | 0 | 0 |
| list_known_functions | 0 | 0 | 0 | 0 | 0 | 0 |
| find_function_pointers | 0 | 0 | 0 | 0 | 0 | 0 |
| query_pointer_alias | 0 | 0 | 0 | 0 | 0 | 0 |
| verify_taint_reachability | 0 | 0 | 0 | 0 | 0 | 0 |

说明：
- `get_deep_call_context` 调用次数为 0 的原因是默认 workflow 下它对所有实际运行 Agent 都不可见：`vulnerability_analyzer` 的 Agent tools 声明了该工具，但当前 active vulnerability skills 未声明它；其他 Agent 本身也未声明该工具，因此运行时不会暴露给任何 Agent。
- `get_function_impl` 和 `get_function_snapshot` 的 `callers/callees` 为空不代表工具结果为空；只有成功结果缺少 `data` 或 `data` 本身为空时，才计为空结果。
- `参数错误` 包括：`Function not found`、`Failed to read file`、`Type not found`; `其他错误`包括：`Sensitive path denied by policy`、`Loop Guard blocked repeated call`。
- `证据命中率` 指的是工具返回的结构化锚点（file/function/line/symbol/candidate_id/dedup_key 等）是否在后续 finding、validation result、audit observation 或 rejection evidence 中显式出现。仅用 Python 代码计算时，`证据命中率` 不能等价于完整语义层面的“有效调用率”。

## 三、上下文质量指标（待分析）

## 四、漏洞指标

| 视图 | Report Issues | Ground Truth | TP | FP | FN | Recall | Precision | F1 | 误报率 | Needs Review 比例 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 默认视图 | 113 | 136 | 82 | 11 | 54 | 60.29% | 88.17% | 71.61% | 11.83% | - |
| Needs Review 视图 | 229 | 136 | 122 | 31 | 14 | 89.71% | 79.74% | 84.43% | 20.26% | 50.66% |

说明：
- `误报率` 使用 `metrics.json` 中的 `false_positive_rate` 字段。
- `Needs Review 比例 = (Needs Review 视图 Report Issues - 默认视图 Report Issues) / Needs Review 视图 Report Issues = 116 / 229 = 50.66%`。

## 五、后端质量指标

