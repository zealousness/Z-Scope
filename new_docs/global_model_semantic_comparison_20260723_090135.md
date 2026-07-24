# 全局语义建模与 Baseline 语义建模对比分析

## 1. 对比范围

本报告只比较 Semantic Modeler 相关阶段，不包含漏洞挖掘、Deep Worker、Validator、Issue Reconciler 或漏洞指标。

对比对象：

- Baseline：`unified_20260706_121745`
  - `premodel_reachable_callees`
  - `model_entry`
- 全局建模：`global_model_20260723_090135`
  - batch-level `global-model`

两次运行均使用 GLM-5 和完整的 174 个 benchmark 入口。

数据来源：

- Baseline：`Z-Scope-baseline/test/range/benchmark_runs/unified_20260706_121745/metrics.md` 与对应 `zscope_run.log`
- 全局建模：`Z-Scope/test/range/benchmark_runs/global_model_20260723_090135/metrics.md`、`global_model_efficiency_metrics.json`、`global_model_metrics.json` 与对应 `zscope_run.log`

Baseline 的 token 和阶段用时直接取自 `metrics.md`；API Calls 及工具调用通过日志中的 workflow step 区间限定为上述两个前置阶段，并按唯一 `tool_call_id` 统计。Baseline `metrics.md` 工具表中的 `1,943` 次是整次 scan 的全部 semantic_modeler 会话，另含后续阶段触发的 43 个 on-demand 建模会话及其 325 次工具调用；本报告排除这部分后采用 `1,618` 次，以便与新运行的 batch-level `global-model` 阶段直接比较。

需要注意，两次运行日期、代码版本、snapshot schema 和 Agent contract 不完全相同，因此结果适合评估整体方案变化，不是严格控制变量的性能实验。

## 2. 主要结论

- 全局建模总 token 从 `4,365,930` 降至 `1,773,012`，减少 `2,592,918`，降幅为 `59.39%`。
- Prompt token 减少 `63.25%`，Completion token 减少 `32.03%`。输入侧压缩仍是主要收益，但输出侧也已经实现绝对量下降。
- LLM API 调用由 `1,234` 次降至 `552` 次，减少 `55.27%`；单次 API 平均总 token 同时减少 `9.22%`，因此调用次数下降能够充分转化为总 token 收益。
- 实际工具调用由 `1,618` 次降至 `421` 次，减少 `73.98%`。其中 snapshot 查询减少 `89.83%`、源码片段调用减少 `87.39%`、caller 查询减少 `89.83%`，说明全局依赖顺序、canonical metadata 预加载和 snapshot-first 策略显著压缩了重复探索。
- 全局阶段完成了 `274` 个可达函数的建模，其中 `38` 个使用 deterministic snapshot，`236` 个使用 LLM，失败数为 `0`；随后 `174/174` 个入口全部复用全局 snapshot，其中 170 个为 `current`、4 个为 `cosmetic_change_only`，没有发生全局回退或 per-entry LLM 建模。
- 现有耗时数据口径仍然不同，不能直接计算加速比。Baseline 的 `19,821s` 是并发 entry step 的累计工作时长，新运行的 `1,010.78s` 是 12 个 worker 并行后的 batch wall time。

## 3. Token 与 API 成本

| 指标 | Baseline | 全局语义建模 | 变化量 | Baseline 单入口平均 | 全局语义建模单入口平均 | 单入口平均变化量 | 变化率 |
|---|---:|---:|---:|---:|---:|---:|---:|
| API Calls | 1,234 | 552 | -682 | 7.09 | 3.17 | -3.92 | -55.27% |
| Prompt Tokens | 3,825,635 | 1,405,776 | -2,419,859 | 21,986.41 | 8,079.17 | -13,907.24 | -63.25% |
| Completion Tokens | 540,295 | 367,236 | -173,059 | 3,105.14 | 2,110.55 | -994.59 | -32.03% |
| Total Tokens | 4,365,930 | 1,773,012 | -2,592,918 | 25,091.55 | 10,189.72 | -14,901.83 | -59.39% |

Baseline token 为以下两个阶段之和：

- `premodel_reachable_callees`：`1,132,138`
- `model_entry`：`3,233,792`

单次 API 成本进一步拆分如下：

| 指标 | Baseline | 全局语义建模 | 变化率 |
|---|---:|---:|---:|
| Prompt Tokens / API Call | 3,100.19 | 2,546.70 | -17.85% |
| Completion Tokens / API Call | 437.84 | 665.28 | +51.95% |
| Total Tokens / API Call | 3,538.03 | 3,211.98 | -9.22% |

分析：

- API 调用减少 `55.27%`，同时每次调用的平均 prompt 也缩短 `17.85%`，两项收益共同推动 Prompt token 大幅下降。
- Completion 单次成本仍增加 `51.95%`，说明当前结构化 snapshot 输出比 Baseline 更长；但由于调用次数明显减少，Completion 总量最终仍下降 `32.03%`。
- 每个 LLM snapshot 平均使用 `2.34` 次 API 调用，说明除主生成请求外，仍存在一定的工具循环、structured finalization 或 repair 开销。
- 当前每入口语义建模成本为 `10,189.72` token，仅为 Baseline 的 `40.61%`。

## 4. 耗时对比

| 指标 | 数值 | 口径 |
|---|---:|---|
| Baseline premodel 累计工作时长 | 5,951s | 174 个 entry workflow step 的并发累计值 |
| Baseline model_entry 累计工作时长 | 13,870s | 174 个 entry workflow step 的并发累计值 |
| Baseline 语义建模累计工作时长 | 19,821s（5.51 worker-hours） | 上述两个阶段之和，不是 wall time |
| Shared semantics 前置准备 | 0.14s | 日志显式 duration |
| 全局建模 wall time | 1,010.78s（16.85min） | 独立 batch-level global-model 的实际经过时间 |
| 全局建模吞吐 | 16.26 functions/min | `274 / 1,010.78s` |
| 全局 LLM snapshot 吞吐 | 14.01 snapshots/min | `236 / 1,010.78s` |
| Scan 剩余时间（非纯语义） | 138.08s | scan wall time 扣除全局建模和 shared semantics；包含入口复用、后续空操作 workflow、持久化和调度等 |
| Scan 总 wall time | 1,149.00s（19.15min） | 外层脚本实际经过时间 |

不能将 `19,821s` 与 `1,010.78s` 直接计算为加速比，原因是：

- Baseline 数值是多个并发线程的 step 时长求和。
- 全局建模数值是 12 个 worker 并行运行后的 wall time。
- Baseline 的语义阶段与后续漏洞分析阶段交错调度，没有独立记录纯语义建模的 batch wall time。

可以确认的是，新运行在 `16.85min` 内准备好了全部 274 个可达函数 snapshot，并使 174 个入口全部完成 snapshot 复用。日志中仍有 174 次 `premodel_reachable_callees` workflow step 的开始和完成记录，但这些步骤没有触发 per-entry LLM 或实际重建。剩余 `138.08s` 约占 scan wall time 的 `12.02%`，是扣减得到的混合时间，不应全部计入语义建模耗时。

## 5. Semantic Modeler 工具调用次数对比

| 工具 | Baseline | 全局语义建模 | 变化量 | Baseline 单入口平均 | 全局语义建模单入口平均 | 单入口平均变化量 | 变化率 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `get_function_impl` | 52 | 0 | -52 | 0.30 | 0.00 | -0.30 | -100.00% |
| `get_function_snapshot` | 462 | 47 | -415 | 2.66 | 0.27 | -2.39 | -89.83% |
| `get_file_snippet` | 682 | 86 | -596 | 3.92 | 0.49 | -3.43 | -87.39% |
| `get_type_info` | 304 | 264 | -40 | 1.75 | 1.52 | -0.23 | -13.16% |
| `get_callers` | 118 | 12 | -106 | 0.68 | 0.07 | -0.61 | -89.83% |
| `get_function_info` | 0 | 12 | +12 | 0.00 | 0.07 | +0.07 | 新增工具路径 |
| Total | 1,618 | 421 | -1,197 | 9.30 | 2.42 | -6.88 | -73.98% |

分析：

- `get_function_impl` 已完全退出语义建模工具路径，少量补充定位由 `get_function_info` 承担。
- `get_function_snapshot` 从 462 次降至 47 次。全局建模按依赖顺序生产 snapshot 后，不再需要像 per-entry 流程一样反复查询重叠 callee。
- `get_file_snippet` 和 `get_callers` 分别减少 `87.39%` 和 `89.83%`，说明源码与上游调用关系的重复探索大幅减少。
- `get_type_info` 只减少 `13.16%`，目前占全部工具调用的 `62.71%`，已经成为最主要的剩余工具成本。
- 工具调用降幅 `73.98%` 高于 API 调用降幅 `55.27%`，说明新流程不仅减少了 session 数量，也减少了单个 LLM snapshot 的探索轮次。

## 6. 当前全局建模工具质量问题

Baseline 报告没有提供仅针对两个语义建模阶段、并按唯一 `tool_call_id` 去重后的成功率，因此本节不进行不可靠的成功率差值计算，只记录新全局建模阶段本身可确认的问题。

| 工具 | Calls | 成功率 | 参数错误率 | 格式错误率 | 其他错误率 | 空结果率 | oop Guard 警告/拦截 | 主要问题 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `get_type_info` | 264 | 83.71% | 16.29% | 0.00% | 0.00% | 0.00% | 0/0 | 43 次 `Type not found` |
| `get_file_snippet` | 86 | 98.84% | 1.16% | 0.00% | 0.00% | 0.00% | 3/0 | 1 次路径错误，3次Loop Guard 警告 |
| `get_function_snapshot` | 47 | 100.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0/0 | 无失败 |
| `get_callers` | 12 | 91.67% | 8.33% | 0.00% | 0.00% | 0.00% | 0/0 | 1 次函数未找到 |
| `get_function_info` | 12 | 1.67% | 8.33% | 0.00% | 0.00% | 0.00% | 0/0 | 1 次函数未找到 |

整体工具成功率为 `89.07%`，主要问题集中在 `get_type_info`：

1. `get_type_info` 同时贡献了 `62.71%` 的调用量和 `93.48%` 的工具失败（43/46），是当前最值得优先处理的工具路径。
2. `get_file_snippet` 仍可能生成相对路径错误，例如本轮唯一失败为不存在的 `include/plugin.h`。
3. 本轮只出现了已注册的五类工具，没有非法工具名调用，也没有 Loop Guard 拦截或全局建模失败。

## 7. 综合判断

新一轮全局建模已经把架构收益较充分地转化为实际成本下降：

- 统一建模 274 个可达函数，建模成功率 `100%`；
- 174 个入口全部复用；per-entry workflow step 虽正常执行，但未触发 LLM 重建或全局回退；
- 工具调用减少 `73.98%`；
- API 调用减少 `55.27%`；
- Prompt token 减少 `63.25%`；
- Completion token 减少 `32.03%`；
- Total token 减少 `59.39%`。

相对 Baseline，本轮单次 API 平均总 token 也下降了 `9.22%`，因此重复建模消除、探索轮次压缩和 prompt 缩短能够共同反映到总成本上。当前全局建模的主要瓶颈已经收敛为两个更具体的问题：

- Completion Tokens / API Call 仍比 Baseline 高 `51.95%`；
- `get_type_info` 占全部工具调用 `62.71%`，且存在较高的失败率。

总体上，当前结果已经证明全局建模不仅实现了“去重、统一和稳定复用”，也显著降低了 token 与工具成本。由于两次运行并非同代码版本和同 schema，本结论应理解为方案级收益，而不是严格 A/B 性能结论。

## 8. 后续优化建议

按优先级建议：

1. 在 runtime 或 Agent policy 中过滤基础类型和已知索引外类型，降低 `get_type_info` 的无效调用率。
2. 审计 snapshot schema 中高 token 输出字段，继续降低 Completion Tokens / API Call；当前输出侧仍是相对 Baseline 唯一上升的单次成本。
3. 将 canonical 类型信息随函数 metadata 或依赖任务预加载，减少 LLM 主动查询类型的必要性。
4. 对 `get_file_snippet` 的文件参数增加 canonical path 提示或自动解析，消除 `include/plugin.h` 一类相对路径错误。
5. 细分 scan 剩余的 `138.08s`，区分 snapshot 校验、入口 workflow 初始化、后续空操作步骤、报告持久化和线程池调度成本。
6. 在同一代码版本、相同 schema、相同模型参数下补跑一次 Baseline semantic-only benchmark，并同时记录独立 semantic wall time、唯一建模函数数和唯一 `tool_call_id`，形成严格 A/B 对比。
