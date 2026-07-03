# Current Problem List

基于 `new_docs/metrics.md` 当前指标整理。优先级含义：P0 表示会直接影响 baseline 结论或主要质量指标；P1 表示明显影响成本/效率/工具质量；P2 表示需要继续观察或作为后续优化项。

## 一、总体效果问题

| 编号 | 优先级 | 问题 | 指标证据 | 影响 | 初步方向 |
|---|---|---|---|---|---|
| Q-001 | P0 | 默认视图 Recall 仍偏低 | 默认视图 Recall 80.99%，FN 23 | 默认报告会漏掉约 19% ground truth 漏洞 | 分析 FN 的类别、入口、是否被 Needs Review 捕获；决定哪些 uncertain 应提升为默认报告 |
| Q-002 | P0 | Needs Review 提升 Recall 但显著牺牲 Precision | Needs Review Recall 91.74%，Precision 80.43%，误报率 19.57%；默认 Precision 87.50%，误报率 12.50% | Needs Review 能覆盖更多真实问题，但审核负担上升 | 对 Needs Review 的 75 个增量 issue 做问题画像，区分“有效疑似”与低质量候选 |
| Q-003 | P1 | Needs Review 占比偏高 | Needs Review 比例 28.30% | 近三成结果需要额外人工/LLM 复核 | 细分 Needs Review 来源 Agent、漏洞类型、缺失证据原因 |

## 二、效率与成本问题

| 编号 | 优先级 | 问题 | 指标证据 | 影响 | 初步方向 |
|---|---|---|---|---|---|
| C-001 | P0 | 单次 benchmark token 成本非常高 | Total 95,976,629 tokens；单入口平均 631,425 tokens | 大规模回归评测成本高，影响迭代速度 | 优先压缩 validator、vulnerability_analyzer、deep_worker 输入上下文 |
| C-002 | P0 | validator_agent 是最大 token 消耗方 | validate_findings 43,358,980 tokens；单入口平均 285,256 tokens | 验证阶段成为主要成本瓶颈 | 减少重复取代码、改用更紧凑 evidence pack、限制验证轮次 |
| C-003 | P1 | deep_worker 成本和工作时长偏高 | deep_worker 19,279,649 tokens；单入口平均 126,839 tokens；单入口累计工作时长 697.61s | focused subagent 带来较大额外开销 | 限制 ticket 数量、合并相邻 ticket、提高 ticket 触发门槛 |
| C-004 | P1 | vulnerability_analyzer prompt token 占比极高 | vulnerability_analyzer Prompt 29,601,504 / Total 30,251,564 | mining 阶段主要消耗来自上下文输入，而非输出 | 精简 entry context、snapshot 摘要、candidate ledger |
| C-005 | P1 | skill_selection 成本不可忽略 | skill_selection 693,731 tokens；单入口平均 4,564 tokens；累计工作时长 49,466s | 路由本身不产出漏洞，但消耗稳定存在 | 对固定 benchmark/task 缓存 skill selection；减少 routing prompt |

## 三、工具可见性与工具集合问题

| 编号 | 优先级 | 问题 | 指标证据 | 影响 | 初步方向 |
|---|---|---|---|---|---|
| T-001 | P1 | `get_deep_call_context` 对所有实际运行 Agent 不可见 | 调用次数 0；metrics 说明中确认默认 workflow 下未暴露给任何 Agent | 表中该工具无法评估真实质量，也无法发挥设计作用 | 决定是否把它加入相关 vulnerability skills，或从默认工具质量表中单独标记为“未暴露” |
| T-002 | P1 | 部分 Agent 声明工具被 active Skill 过滤 | 例如 `semantic_modeler.list_known_functions`、`validator_agent.get_callers`、`vulnerability_analyzer.get_deep_call_context` | Agent prompt/工具设计和 runtime policy 不一致 | 梳理 Agent tools 与 Skill allowed_tools 的交集，消除无效声明或补齐 skill 权限 |
| T-003 | P1 | vulnerability skills 声明了 `get_function_impl`，但 `vulnerability_analyzer` 默认不可用 | `vulnerability_analyzer` 对 `get_function_impl` 调用为 0；tools_optimation 中确认 Agent tools 未声明 | mining 阶段只能用 snapshot/snippet，无法在需要时获取完整函数实现 | 判断是否应允许 VA 在低频场景调用 impl，或明确禁止并优化 snapshot/snippet |
| T-004 | P2 | `issue_reconciler_agent` 当前无本地工具 | issue_reconciler_agent 所有工具调用为 0；构造函数传入 `tools=[]` | 语义去重无法主动补充代码证据 | 如果后续发现去重误合并/漏合并，再考虑加入只读 evidence 工具 |

## 四、工具调用质量问题

| 编号 | 优先级 | 问题 | 指标证据 | 影响 | 初步方向 |
|---|---|---|---|---|---|
| U-001 | P0 | `get_file_snippet` 调用量过高 | 总调用 6,365；单入口平均 41.88；deep_worker 2,657，validator_agent 2,641 | 文件片段读取是最高频工具，容易推高上下文和重复调用 | 引入 snippet cache/evidence pack 复用；限制重复读取同一区间 |
| U-002 | P1 | `get_file_snippet` 重复调用明显 | Loop Guard 警告 155 次，拦截 5 次 | Agent 多次请求相同片段，浪费轮次并触发 guard | 在 prompt 中要求复用已有片段；工具返回中强化“已提供证据”索引 |
| U-003 | P1 | `list_known_functions` 低价值调用较多 | 总调用 561；空结果率 46.07%；证据命中率 0.00%；Loop Guard 警告 18，拦截 1 | 主要由 validator_agent 调用，可能是泛化搜索而非证据检索 | 限制 validator 使用函数列表搜索；优先从 evidence pack/call path 获取目标函数 |
| U-004 | P1 | `get_type_info` 参数错误率高 | 参数错误率 18.26%；2.4 中 Type not found 210 次 | Agent 经常查询不存在或无法解析的类型名 | 增强类型名规范化；工具返回候选类型建议；prompt 约束不要查宏/变量名 |
| U-005 | P1 | `get_file_snippet` 存在路径/读取失败 | 错误总次数 75，其中 Failed to read file 69，Sensitive path denied 2 | 参数构造或路径来源存在问题，影响证据读取 | 增加路径校验/候选路径提示；在 prompt 中强调只用 repo 相对源码路径 |
| U-006 | P2 | `get_function_impl` 存在函数不存在错误 | 错误总次数 25，其中 Function not found 24 | 少量函数名解析不准，主要影响 validator 取证 | 对函数名做 snapshot/known-functions 预校验或 fuzzy suggestion |

## 五、低 ROI 工具问题

| 编号 | 优先级 | 问题 | 指标证据 | 影响 | 初步方向 |
|---|---|---|---|---|---|
| R-001 | P1 | `get_data_flow` 当前几乎没有有效产出 | 调用 77；成功率 100%；空结果率 100%；证据命中率 0.00% | 工具调用成功但没有返回有效数据，可能是 backend 数据不足或查询参数不合适 | 抽样检查调用参数；确认 unified backend 数据流覆盖情况；必要时降低默认可见性 |
| R-002 | P1 | `find_function_pointers` 当前没有有效产出 | 调用 13；空结果率 100%；证据命中率 0.00% | 函数指针工具低频且未产生证据 | 检查是否 benchmark 中函数指针场景少，或工具查询入口不匹配 |
| R-003 | P1 | `verify_taint_reachability` 空结果率高、证据命中率低 | 调用 66；空结果率 57.58%；证据命中率 19.70% | 污点可达性验证可能没有稳定支持最终判断 | 分析成功但空结果样本，区分“确实不可达”和“工具能力不足” |
| R-004 | P2 | `get_function_snapshot` 证据命中率偏低 | 调用 2,814；成功率 100%；证据命中率 25.30% | snapshot 可能更多用于中间推理，或存在过量读取 | 不直接视为无效，但需要抽样判断是否存在过度取 snapshot |

## 六、Loop Guard 与重复行为问题

| 编号 | 优先级 | 问题 | 指标证据 | 影响 | 初步方向 |
|---|---|---|---|---|---|
| L-001 | P1 | 重复片段读取集中在 `get_file_snippet` | Loop Guard 警告 155，拦截 5 | 说明单 session 内确实存在重复工具请求 | 在 Agent 上下文中保留已读片段目录；对同参调用直接提醒复用 |
| L-002 | P2 | 函数列表搜索也有重复行为 | `list_known_functions` Loop Guard 警告 18，拦截 1 | validator 可能反复探索函数名空间 | 限制列表搜索轮次；提供候选函数缓存 |

## 七、指标口径与后续分析缺口

| 编号 | 优先级 | 问题 | 指标证据 | 影响 | 初步方向 |
|---|---|---|---|---|---|
| M-001 | P1 | 上下文质量指标仍未分析 | `## 三、上下文质量指标（待分析）` 为空 | 缺少对上下文压缩、证据完整性、上下文污染的量化判断 | 下一步补充 context 命中率、上下文冗余率、关键信息缺失率等指标 |
| M-002 | P1 | 证据命中率只是 Python 近似指标 | metrics 说明中明确不能等价于完整语义“有效调用率” | 低证据命中不一定代表工具无效，高命中也不代表语义有效 | 对关键工具做抽样人工/LLM 复核，校准 proxy 指标 |
| M-003 | P2 | workflow step 用时与 Total wall time 口径不同 | metrics 说明中指出 step work seconds 因并行不能相加 | 容易误读各阶段耗时占比 | 报告中区分 wall time、累计 worker time、LLM API time |

## 八、优先处理建议

| 顺序 | 建议处理项 | 对应问题 |
|---:|---|---|
| 1 | 做 FN/Needs Review 增量画像，确定 Recall 与 Precision 的主要矛盾 | Q-001, Q-002, Q-003 |
| 2 | 降低 validator 和 snippet 调用成本，优先处理 `get_file_snippet` 重复读取 | C-002, U-001, U-002, L-001 |
| 3 | 修正工具可见性策略，明确 `get_deep_call_context`、`get_function_impl` 是否应暴露给相关 Agent | T-001, T-002, T-003 |
| 4 | 排查低 ROI 图/数据流工具，决定优化参数、修 backend，还是降低默认暴露 | R-001, R-002, R-003 |
| 5 | 补齐上下文质量指标，解释为什么高 token 成本没有转化为更高默认 Recall | M-001, C-001, Q-001 |
