# 全局语义建模与 Baseline 语义建模对比分析

## 1. 对比范围

本报告只比较 Semantic Modeler 相关阶段，不包含漏洞挖掘、Deep Worker、Validator、Issue Reconciler 或漏洞指标。效率统一使用 Token 指标衡量。

对比对象：

- Baseline：`unified_20260706_121745`
  - `premodel_reachable_callees`
  - `model_entry`
- 全局建模：`global_model_20260723_183830`
  - batch-level `global-model`

两次运行均使用 GLM-5 和完整的 174 个 benchmark 入口配置。

数据来源：

- Baseline：`Z-Scope-baseline/test/range/benchmark_runs/unified_20260706_121745/metrics.md` 与对应 `zscope_run.log`
- 全局建模：`Z-Scope/test/range/benchmark_runs/global_model_20260723_183830/metrics.md`、`global_model_efficiency_metrics.json`、`global_model_metrics.json` 与对应 `zscope_run.log`

Baseline 的 Token 直接取自 `metrics.md`；API Calls 及工具调用通过日志中的 workflow step 区间限定为上述两个前置阶段，并按唯一 `tool_call_id` 统计。Baseline `metrics.md` 工具表中的 `1,943` 次是整次 scan 的全部 semantic_modeler 会话，另含后续阶段触发的 43 个 on-demand 建模会话及其 325 次工具调用；本报告排除这部分后采用 `1,618` 次，以便与 batch-level `global-model` 阶段直接比较。

需要特别说明，`global_model_20260723_183830` 不是一次完整成功的运行：261 个可达函数中完成 259 个，2 个建模失败，完整性门禁随后拒绝启动入口阶段。因此本报告中的 `1,963,183` Token 是该不完整运行的可观测成本，不能直接视为一次完整成功运行的最终成本。两次运行的代码版本、snapshot schema 和 Agent contract 也不完全相同，结果适合评估方案变化，不是严格控制变量实验。

## 2. 主要结论

- 可观测总 Token 从 `4,365,930` 降至 `1,963,183`，减少 `2,402,747`，降幅为 `55.03%`。但新运行有 2 个函数未完成，该降幅只能视为不完整运行的观测结果。
- Prompt Token 减少 `61.10%`，Completion Token 仅减少 `12.05%`。输入侧压缩显著，但结构化输出成本仍然偏高。
- 产生 Token Trace 的 LLM 响应由 `1,234` 次降至 `496` 次，减少 `59.81%`；单次响应平均总 Token 增加 `11.87%`，其中 Completion Tokens / API Call 增加 `118.82%`。
- 实际工具调用由 `1,618` 次降至 `300` 次，减少 `81.46%`。snapshot、源码片段、类型和 caller 查询均明显减少，说明全局建模有效压缩了跨入口重复探索。
- 全局阶段发现 `261` 个可达函数，完成 `259` 个 snapshot，其中 `32` 个为 deterministic snapshot、`227` 个为 LLM snapshot，建模成功率为 `99.23%`。
- `_runtime_release_channel_role` 和 `_runtime_stream_copy_fragment` 在 LLM 流式响应超时并耗尽重试后建模失败。入口 fan-out 因完整性门禁被拒绝，因此本轮没有执行 `174` 个入口的 snapshot 复用。

## 3. Token 与 API 成本

| 指标 | Baseline | 全局语义建模 | 变化量 | Baseline 单入口平均 | 全局语义建模单入口平均 | 单入口平均变化量 | 变化率 |
|---|---:|---:|---:|---:|---:|---:|---:|
| API Calls | 1,234 | 496 | -738 | 7.09 | 2.85 | -4.24 | -59.81% |
| Prompt Tokens | 3,825,635 | 1,487,984 | -2,337,651 | 21,986.41 | 8,551.63 | -13,434.78 | -61.10% |
| Completion Tokens | 540,295 | 475,199 | -65,096 | 3,105.14 | 2,731.03 | -374.11 | -12.05% |
| Total Tokens | 4,365,930 | 1,963,183 | -2,402,747 | 25,091.55 | 11,282.66 | -13,808.89 | -55.03% |

Baseline Token 为以下两个阶段之和：

- `premodel_reachable_callees`：`1,132,138`
- `model_entry`：`3,233,792`

单次 API 成本进一步拆分如下：

| 指标 | Baseline | 全局语义建模 | 变化率 |
|---|---:|---:|---:|
| Prompt Tokens / API Call | 3,100.19 | 2,999.97 | -3.23% |
| Completion Tokens / API Call | 437.84 | 958.06 | +118.82% |
| Total Tokens / API Call | 3,538.03 | 3,958.03 | +11.87% |

分析：

- API Calls 采用 `[LLM API Trace]` 口径，表示成功返回并记录 Token 的 LLM 响应数。新运行另有未产生 Token Trace 的超时请求，其 Token 消耗和供应商计费无法从现有日志确认，因此不包含在 `1,963,183` 中。
- Prompt 总量减少 `61.10%`，主要来自跨入口去重、调用次数减少以及上下文压缩。
- Completion 总量仅减少 `12.05%`，同时每次响应的 Completion Token 增加 `118.82%`，使 Completion 在总 Token 中的占比由 `12.38%` 上升至 `24.21%`。
- 每个成功 LLM snapshot 平均对应 `2.19` 条 Token Trace，平均消耗 `8,648.38` Token，说明当前主要成本已从重复输入进一步转向结构化输出与 finalization。
- 表中的单入口平均均以配置的 174 个入口归一化。由于新运行没有启动入口 fan-out，这些数值是成本归一化结果，不代表实际执行了单入口流程。

## 4. Semantic Modeler 工具调用次数对比

| 工具 | Baseline | 全局语义建模 | 变化量 | Baseline 单入口平均 | 全局语义建模单入口平均 | 单入口平均变化量 | 变化率 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `get_function_impl` | 52 | 0 | -52 | 0.30 | 0.00 | -0.30 | -100.00% |
| `get_function_snapshot` | 462 | 67 | -395 | 2.66 | 0.39 | -2.27 | -85.50% |
| `get_file_snippet` | 682 | 115 | -567 | 3.92 | 0.66 | -3.26 | -83.14% |
| `get_type_info` | 304 | 67 | -237 | 1.75 | 0.39 | -1.36 | -77.96% |
| `get_callers` | 118 | 31 | -87 | 0.68 | 0.18 | -0.50 | -73.73% |
| `get_function_info` | 0 | 19 | +19 | 0.00 | 0.11 | +0.11 | 新增工具路径 |
| `emit_function_snapshot` | 0 | 1 | +1 | 0.00 | 0.01 | +0.01 | 新增终结工具 |
| Total | 1,618 | 300 | -1,318 | 9.30 | 1.72 | -7.57 | -81.46% |

分析：

- `get_function_impl` 已退出全局语义建模工具路径，补充函数定位由 `get_function_info` 承担。
- `get_function_snapshot`、`get_file_snippet` 和 `get_callers` 分别减少 `85.50%`、`83.14%` 和 `73.73%`，说明依赖顺序建模和 snapshot-first 策略显著减少了重复探索。
- `get_type_info` 减少 `77.96%`，当前占全部工具调用的 `22.33%`。调用量最高的是 `get_file_snippet`，占全部工具调用的 `38.33%`。
- 工具调用降幅 `81.46%` 高于 API Calls 降幅 `59.81%`，说明单个 LLM snapshot 的工具探索轮次也得到压缩。
- `emit_function_snapshot` 是当前 schema 的终结工具。本轮出现 1 次 payload 格式错误，但同一会话修复后成功，不属于最终失败的两个函数。

## 5. 当前全局建模工具质量与运行完整性问题

Baseline 报告没有提供仅针对两个前置语义阶段、并按相同工具口径统计的成功率，因此本节不进行不可靠的成功率差值计算，只记录新全局建模阶段本身可确认的问题。

| 工具 | Calls | 成功率 | 参数错误率 | 格式错误率 | 其他错误率 | 空结果率 | Loop Guard 警告/拦截 | 主要问题 |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `get_file_snippet` | 115 | 99.13% | 0.87% | 0.00% | 0.00% | 0.00% | 2/0 | 1 次行号越界 |
| `get_function_snapshot` | 67 | 100.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0/0 | 无失败 |
| `get_type_info` | 67 | 95.52% | 4.48% | 0.00% | 0.00% | 0.00% | 0/0 | 3 次 `Type not found` |
| `get_callers` | 31 | 96.77% | 3.23% | 0.00% | 0.00% | 0.00% | 0/0 | 1 次函数未找到 |
| `get_function_info` | 19 | 100.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0/0 | 无失败 |
| `emit_function_snapshot` | 1 | 0.00% | 0.00% | 100.00% | 0.00% | 0.00% | 0/0 | 1 次 payload 格式错误，后续修复成功 |

整体工具成功率为 `98.00%`，共 6 次工具错误：

1. `get_type_info` 产生 3 次 `Type not found`，分别涉及 `Dispatcher`、基础类型 `size_t` 和 `plugin_callback_t`。
2. `get_file_snippet` 对 `src/lifecycle.c` 请求了越界行号；`get_callers` 无法解析宏 `COUNTER_SLOT_LOCK`。
3. `_runtime_enqueue_rcu_batch` 首次调用 `emit_function_snapshot` 时 payload 格式错误，但 Agent 随后重新提交并成功保存 snapshot。

运行完整性如下：

| 检查项 | 结果 |
|---|---:|
| 配置入口 | 174 |
| 全局可达函数 | 261 |
| 完成建模函数 | 259 |
| Deterministic / LLM snapshot | 32 / 227 |
| 建模失败 | 2 |
| 全局建模成功率 | 99.23% |
| Global model start/end | 1/1 |
| Global fallback | 0 |
| 入口 snapshot 复用 | 未执行（日志 0/174） |
| Scan return code | 1 |

两个最终失败函数为：

- `_runtime_release_channel_role@src/lifecycle.c:1461-1470`
- `_runtime_stream_copy_fragment@src/lifecycle.c:3095-3115`

二者均因 LLM 流式响应超时并耗尽重试而失败。全局建模调度虽然结束，但完整性门禁因 `failed=2` 拒绝启动入口 fan-out，因此没有执行入口 snapshot 复用，也没有触发 per-entry premodel 或入口 LLM 建模。`metrics.md` 末尾“所有入口复用全局 snapshot”的文字与其自身表格、完整性计数及日志冲突，应视为报告生成错误。

## 6. 综合判断

本轮可以确认的效率收益包括：

- 可观测 Prompt Token 减少 `61.10%`；
- 可观测 Completion Token 减少 `12.05%`；
- 可观测 Total Token 减少 `55.03%`；
- 产生 Token Trace 的 LLM 响应减少 `59.81%`；
- 工具调用减少 `81.46%`；
- 259 个成功 snapshot 中，32 个由 deterministic 路径生成，227 个由 LLM 生成。

这些数据表明，全局建模仍然有效减少了跨入口重复输入和工具探索。但是，本轮不是完整成功运行，两个失败请求也没有 Token Trace，因此 `55.03%` 不能作为完整运行的最终 Token 降幅。当前最明显的成本问题是输出侧：Completion Tokens / API Call 比 Baseline 增加 `118.82%`，总 Token 降幅主要由 Prompt 和响应数量下降贡献。

完整性方面，`259/261` 的建模结果未能通过严格阶段门禁，入口复用完全没有执行。因而本轮能够证明“全局阶段接近完成时的可观测 Token 和工具成本明显下降”，但不能证明完整的 174 入口流程已经成功闭环。

## 7. 后续优化建议

按优先级建议：

1. 对两个失败函数补充可恢复重试或基于已保存 snapshot 的断点续跑，并完成一次 `261/261`、入口复用实际执行的运行后再确定最终 Token 降幅。
2. 修复 `metrics.md` 完整性结论生成逻辑，使结论直接受 `scan_return_code`、`failed_functions` 和 `entry_snapshot_reuse_count` 约束，避免表格与结论矛盾。
3. 审计 snapshot schema 中高 Token 输出字段，压缩重复描述，重点降低 Completion Tokens / API Call。
4. 对 `emit_function_snapshot` 增加提交前 schema 校验或更精确的 repair 提示，避免终结 payload 格式错误。
5. 在 Agent policy 或 runtime 中过滤基础类型查询、校验 snippet 行号范围，并为宏 caller 查询提供 canonical identity。
6. 在相同代码版本、schema、模型参数和完整性要求下补跑 Baseline semantic-only 与 global-model，使用 Total Token、Prompt/Completion 构成、API Trace 数和唯一工具调用数形成严格 A/B 对比。
