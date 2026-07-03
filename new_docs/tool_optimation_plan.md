# Tool Optimation Plan

本文是 Week 3「工具调用降噪与工具优化」执行计划，基于 `metrics.md`、`current_problem_list.md` 和 `tools_introduction.md` 制定。目标是在不改变 Z-SCOPE 主体架构的前提下，降低重复/无效工具调用，提升单次工具调用的证据价值，并为 Week 4 Skill 路由优化留下清晰接口。

## 一、目标与验收指标

### 1.1 Week 3 目标

| 目标 | 对应问题 | 说明 |
|---|---|---|
| 降低高频工具调用成本 | C-001, C-002, U-001, U-002 | 优先处理 `get_file_snippet` 和 validator 阶段的重复取证 |
| 提升工具调用有效性 | U-003, U-004, U-005, R-001, R-003 | 减少空结果、参数错误和低证据命中调用 |
| 修正工具可见性不一致 | T-001, T-002, T-003 | 明确哪些工具应暴露、哪些工具应隐藏 |
| 建立工具优化 A/B 回归方法 | M-002, M-003 | 每个优化项都能和 baseline 指标对比 |

### 1.2 验收指标

| 指标 | Baseline | Week 3 目标 |
|---|---:|---:|
| 总 Tool Call 次数 | 14,939 | 下降 15%-25% |
| `get_file_snippet` 总调用次数 | 6,365 | 下降 20%-30% |
| `get_file_snippet` Loop Guard 警告次数 | 155 | 下降 50% 以上 |
| validator_agent 单入口平均 Total Tokens | 285,256.45 | 下降 15% 以上 |
| `get_type_info` 参数错误率 | 18.26% | 降至 10% 以下 |
| `list_known_functions` 调用次数 | 561 | 下降 50% 以上 |
| 默认视图 Precision | 87.50% | 不下降 |
| 默认视图 Recall | 80.99% | 不下降超过 1 个百分点 |

说明：工具优化优先保证 Recall 不明显下降；若 Precision 或成本显著改善但 Recall 下降，需要单独列为风险实验，不能直接合入默认流程。

## 二、优化范围

### 2.1 本周纳入范围

| 范围 | 内容 |
|---|---|
| 工具可见性 | Agent tools 与 Skill allowed_tools 的交集策略、默认可见工具集合 |
| 工具返回质量 | 空结果提示、候选建议、错误消息结构化 |
| 工具调用降噪 | 重复 snippet 读取、泛化函数搜索、低 ROI 图/数据流工具 |
| Agent 使用规范 | 在 Agent/Skill prompt 中加入更明确的工具使用约束 |
| 指标回归 | 用现有 `extract_efficiency_metrics.py` 重算工具质量指标 |

### 2.2 本周暂不纳入范围

| 范围 | 原因 |
|---|---|
| 大规模重构 evidence pack | 更接近 Week 5 上下文管理任务 |
| 完整 Skill 路由策略改造 | 属于 Week 4 主任务 |
| 修改漏洞判定标准 | 会混淆工具优化与研判质量优化效果 |
| 新增复杂静态分析 backend | 风险高，超出 Week 3 工具层降噪目标 |

## 三、问题到优化项映射

| 优化项 | 解决问题 | 优先级 | 预期收益 | 风险 |
|---|---|---|---|---|
| O-001 snippet 调用去重与复用提示 | U-001, U-002, L-001, C-002 | P0 | 降低最高频工具调用和 validator token | 可能少取必要上下文 |
| O-002 validator 工具白名单收紧 | U-003, L-002, C-002 | P0 | 减少 `list_known_functions` 和泛化搜索 | 可能影响少量缺失函数名定位 |
| O-003 `get_type_info` 参数规范化与候选提示 | U-004 | P1 | 降低 Type not found | 需要改工具返回协议 |
| O-004 文件路径校验与错误提示优化 | U-005 | P1 | 降低 Failed to read file | 需要确认 code_index 路径解析能力 |
| O-005 低 ROI 工具默认降权/限制 | R-001, R-002, R-003 | P1 | 减少空结果工具调用 | 可能影响少数图/污点可达性证据 |
| O-006 工具可见性一致性修正 | T-001, T-002, T-003 | P1 | 消除“声明但不可见”的混乱 | 暴露新工具可能增加调用成本 |
| O-007 工具结果中加入 evidence reuse key | U-001, U-002, M-002 | P2 | 便于 Agent 复用已有证据 | 需要 Agent prompt 配合 |

## 四、具体实施计划

### 4.1 O-001: snippet 调用去重与复用提示

现状：

- `get_file_snippet` 调用 6,365 次，是最高频工具。
- 单入口平均调用 41.88 次。
- Loop Guard 警告 155 次，拦截 5 次。
- deep_worker 调用 2,657 次，validator_agent 调用 2,641 次。

实施方案：

| 步骤 | 修改点 | 说明 |
|---|---|---|
| 1 | 在工具结果中返回稳定 `snippet_key` | 格式建议：`file_path:start_line:end_line` |
| 2 | 在 Agent prompt/Skill contract 中要求复用已读 snippet | 明确“同一文件区间不要重复读取” |
| 3 | 对重叠区间做提示 | 如果请求区间被已有片段覆盖，返回提示或缓存结果 |
| 4 | 在 conversation metadata 中记录已读 snippet 摘要 | 供后续轮次引用，减少重复取证 |

验收：

- `get_file_snippet` 总调用次数下降 20% 以上。
- `get_file_snippet` Loop Guard 警告下降 50% 以上。
- 默认 Recall 不下降超过 1 个百分点。

### 4.2 O-002: validator 工具白名单收紧

现状：

- validator_agent 是最大 token 消耗方：43,358,980 tokens。
- `list_known_functions` 全部 561 次调用均来自 validator_agent。
- `list_known_functions` 空结果率 46.07%，证据命中率 0.00%，Loop Guard 警告 18 次。

实施方案：

| 步骤 | 修改点 | 说明 |
|---|---|---|
| 1 | 从 `evidence_validation.allowed_tools` 中移除或条件化 `list_known_functions` | 默认验证应基于 evidence pack 和具体函数名，不做泛化搜索 |
| 2 | 在 validator prompt 中限制函数列表搜索 | 仅当 evidence pack 缺失函数名且无法从路径恢复时允许 |
| 3 | 优先使用 `get_function_snapshot` / `get_file_snippet` | 避免从函数全集搜索开始 |

验收：

- `list_known_functions` 调用次数下降 50% 以上。
- validator_agent token 下降 10% 以上。
- Precision 不下降。

风险与回退：

- 如果出现因函数名缺失导致的 FN 增加，改为保留工具但加 `max_calls_per_session=1` 或仅在 retry 时暴露。

### 4.3 O-003: `get_type_info` 参数规范化与候选提示

现状：

- `get_type_info` 参数错误率 18.26%。
- 2.4 中 `Type not found` 210 次。

实施方案：

| 步骤 | 修改点 | 说明 |
|---|---|---|
| 1 | 对查询名做轻量规范化 | 去掉 `struct `、`enum `、指针符号、数组后缀等噪声 |
| 2 | 区分“类型不存在”和“疑似宏/变量/字段名” | 错误返回中增加 `reason_code` |
| 3 | 返回相近候选类型 | 如 prefix/fuzzy match top 5 |
| 4 | 在 prompt 中约束不要用变量名/宏名查询类型 | 降低明显错误参数 |

验收：

- `get_type_info` 参数错误率降至 10% 以下。
- `Type not found` 次数下降 40% 以上。

### 4.4 O-004: 文件路径校验与错误提示优化

现状：

- `get_file_snippet` 错误总次数 75。
- 其中 `Failed to read file` 69 次，`Sensitive path denied by policy` 2 次。

实施方案：

| 步骤 | 修改点 | 说明 |
|---|---|---|
| 1 | 工具错误返回中增加 path resolution detail | 区分不存在、路径不在 source root、行号越界 |
| 2 | 返回候选相近路径 | 对 basename 做候选匹配 |
| 3 | prompt 中要求使用 repo 相对源码路径 | 禁止使用绝对路径、临时路径、敏感配置路径 |
| 4 | 对 sensitive path 错误单独提示 | 明确这是 policy 拒绝，不要重试同一路径 |

验收：

- `Failed to read file` 下降 50% 以上。
- `Sensitive path denied by policy` 不再重复发生。

### 4.5 O-005: 低 ROI 工具默认降权/限制

现状：

- `get_data_flow` 调用 77，空结果率 100%，证据命中率 0.00%。
- `find_function_pointers` 调用 13，空结果率 100%，证据命中率 0.00%。
- `verify_taint_reachability` 调用 66，空结果率 57.58%，证据命中率 19.70%。

实施方案：

| 工具 | 调整建议 | 说明 |
|---|---|---|
| `get_data_flow` | 默认不在 broad scan 首轮暴露，仅在 bounds/string/taint 明确场景暴露 | 避免无目标数据流查询 |
| `find_function_pointers` | 仅在 shared_state_race 或 callback/dispatch 证据存在时暴露 | 低频按需启用 |
| `verify_taint_reachability` | 要求必须提供 source/sink/function 三元组 | 防止泛化可达性查询 |

验收：

- 三类工具总调用次数下降 30% 以上。
- 若 Recall 下降，抽样检查是否因为少了关键图证据。

### 4.6 O-006: 工具可见性一致性修正

现状：

- `get_deep_call_context` 对所有实际运行 Agent 不可见，调用次数为 0。
- `vulnerability_analyzer` 声明了 `get_deep_call_context`，但 active vulnerability skills 未声明。
- vulnerability skills 中声明了 `get_function_impl`，但 `vulnerability_analyzer` Agent tools 未声明，因此不可见。

实施方案：

| 工具 | 当前状态 | 建议 |
|---|---|---|
| `get_deep_call_context` | Agent 声明但 Skill 未声明 | 短期不直接开放；先定义触发条件和预期用途 |
| `get_function_impl` for VA | Skill 声明但 Agent 未声明 | 默认仍不开放，避免 mining 阶段过度读取完整实现；必要时给特定 skill 增加低频 escape hatch |
| `validator_agent.get_callers` | Agent 声明但 Skill 未声明 | 保持不可见；验证应基于 evidence pack 中路径 |
| `semantic_modeler.list_known_functions` | Agent 声明但 Skill 未声明 | 保持不可见；建模应围绕当前函数和已知 callee |

验收：

- `tools_introduction.md` 与实际 policy 保持一致。
- `metrics.md` 中 0 调用工具标明是“未暴露”还是“暴露但未使用”。

### 4.7 O-007: 工具结果 evidence reuse key

实施方案：

| 工具 | 建议增加字段 |
|---|---|
| `get_file_snippet` | `evidence_key`, `file`, `start_line`, `end_line`, `covered_range` |
| `get_function_snapshot` | `evidence_key`, `function_name`, `file_path`, `snapshot_version` |
| `get_function_impl` | `evidence_key`, `function_name`, `file_path`, `line_range` |
| `get_type_info` | `evidence_key`, `query`, `resolved_type`, `candidate_types` |

收益：

- Agent 可以在 reasoning 中引用稳定 key。
- 后续计算证据命中率时更可靠。
- 为 Week 5 evidence pack 去重打基础。

## 五、实施顺序

| 顺序 | 任务 | 预计产出 | 依赖 |
|---:|---|---|---|
| 1 | 增加工具调用样本审计脚本，抽样查看低 ROI/错误调用 | `test_scripts/sample_tool_calls.py` 或扩展现有脚本 | 无 |
| 2 | 完成 snippet 去重和 prompt 约束 | 代码 patch + 单元测试 | O-001 |
| 3 | 收紧 validator 的 `list_known_functions` 使用 | Skill/Agent policy patch + 回归对比 | O-002 |
| 4 | 优化 `get_type_info` 和 `get_file_snippet` 错误返回 | 工具 patch + 单元测试 | O-003, O-004 |
| 5 | 调整低 ROI 工具暴露策略 | Skill allowed_tools 或 policy 条件化 | O-005 |
| 6 | 重新跑小规模 benchmark，对比 metrics | 新 run 目录 + 更新对比表 | 前 5 项 |

## 六、实验设计

### 6.1 小规模实验

| 实验 | 范围 | 目的 |
|---|---|---|
| E-001 | 10-20 个入口 | 验证工具调用次数是否下降 |
| E-002 | 包含已知 FN/FP 的入口子集 | 检查 Recall/Precision 是否受损 |
| E-003 | validator-heavy issue 子集 | 验证 validator token 是否下降 |

### 6.2 全量回归

全量回归只在小规模实验通过后执行。回归后需要复用 Week 2 指标脚本生成：

- `metrics.json`
- `efficiency_metrics.json`
- `metrics.md`
- baseline vs optimized 对比表

### 6.3 对比维度

| 维度 | 必看指标 |
|---|---|
| 漏洞效果 | Default Recall、Precision、F1、误报率；Needs Review Recall、Precision、误报率 |
| 成本 | Total Tokens、validator tokens、VA tokens、deep_worker tokens |
| 工具量 | 总 Tool Call、单入口平均 Tool Call、按 Agent/工具分布 |
| 工具质量 | 成功率、参数错误率、空结果率、Loop Guard 警告/拦截、证据命中率 |

## 七、风险控制

| 风险 | 表现 | 回退策略 |
|---|---|---|
| 工具收紧导致漏报 | Recall 下降或 FN 增加 | 恢复该工具可见性，改为 prompt 限制或 max-call 限制 |
| snippet 去重导致缺上下文 | validator 返回 uncertain 增加 | 允许扩大区间或在 retry 轮次重新读取 |
| 低 ROI 工具被隐藏后影响特殊漏洞 | 并发/数据流类漏洞漏报 | 对特定 skill 或 candidate signal 按需暴露 |
| 错误返回变复杂导致 LLM误解 | 参数错误未下降或重试增加 | 保持错误字段短小结构化，增加明确 action hint |

## 八、本周交付物

| 交付物 | 路径 | 说明 |
|---|---|---|
| 工具优化计划 | `new_docs/tool_optimation_plan.md` | 本文件 |
| 工具调用抽样脚本 | `test_scripts/` | 如需要新增脚本，必须放在本目录 |
| 优化 patch | `zscope/tools/`, `zscope/skills/`, `zscope/agents/` | 按实验拆分小 patch |
| 小规模回归结果 | `test/range/benchmark_runs/` | 与 baseline 目录区分 |
| 对比指标表 | `new_docs/` 或 run 目录 | 记录优化前后指标变化 |

## 九、第一批建议执行项

优先从低风险、高收益项开始：

1. 抽样分析 `get_file_snippet` Loop Guard 警告和 `Failed to read file` 的真实调用参数。
2. 给 `get_file_snippet` 返回稳定 `snippet_key`，并在 validator/deep_worker prompt 中要求复用。
3. 限制 validator 默认使用 `list_known_functions`。
4. 给 `get_type_info` 增加类型名规范化和候选类型提示。
5. 小规模回归后再决定是否调整 `get_data_flow`、`find_function_pointers`、`verify_taint_reachability` 的默认可见性。
