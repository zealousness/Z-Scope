# Z-SCOPE 2.0 淘汰与迁移计划

## 直接删除

| 能力 | 当前问题 | 2.0处置 |
|---|---|---|
| focused subagent不可达实现 | 无条件return后仍保留大段代码 | 删除实现、配置、测试和报告字段 |
| VulnerabilityAnalyzer | 产品无实例化点，名称仍污染workflow/usage | 删除运行时Agent和Prompt，由Hypothesis Hunter替代能力 |
| DeepWorker/SubAgentOrchestrator | 仅被不可达规划路径引用 | 删除运行时代码和ticket配置 |
| C/C++ ruledriven公共旁路 | 与默认Candidate Ledger重复 | 删除公共模式，规则统一进入默认流水线 |
| LLM报告语义去重 | 与Finding-root v2重复且不可作为身份权威 | 删除LLM判重，只保留Finding-root v2 |
| IssueReconciler判重职责 | 一个Agent承担历史维护与报告判重两种职责 | 删除判重职责，历史维护职责重命名并保留 |

## 等价替换后删除（P5候选已执行）

| 能力 | 替代条件 | 删除门禁 |
|---|---|---|
| SemanticModeler/GlobalModeler | SecuritySpecCompiler和函数摘要缓存 | shadow契约召回、增量命中与结果不变量通过 |
| on-demand旧semantic snapshot LLM补全 | 有限SecuritySpec提议和reverify | 所有live调用点迁移 |
| Validator v2/generic forced-final | Proof Engine和严格v3契约 | 默认、maintain、alert-verify均使用统一终态 |
| 旧Agent usage维度 | hypothesis_hunter/security_spec_miner/proof_engine | 历史artifact映射测试通过 |

上述四项在P5候选wheel与live import graph中均不可达；旧字段只由compat显式迁移，用户保存并由
严格loader重新加载后才能用于新扫描。P5双审核与全部强制门禁通过前，候选wheel仍不可发布。

## 保留

- Candidate Ledger、跨入口去重和Finding-root v2。
- Clang、Joern、SVF、KnowledgeDB、SnapshotStore及调用图事实。
- call级token usage ledger；只观测，不准入或截断扫描。
- alert-verify用例，但迁移到共享Proof Engine。
- maintain历史finding reconciliation，但不参与报告判重。
- 旧配置转换和历史artifact读取器，位于只读compat边界。

## Compatibility边界

- 旧执行实现不得继续打包在产品namespace。
- Arm A/E和D4仅保存协议、hash和外部容器执行契约。
- 删除字段在2.0给出明确迁移错误，不静默忽略。
- production import graph不得依赖compat执行器。

## 删除证据

每项删除前必须在`runtime-reachability-manifest.v1`中记录：

- 静态import和动态加载点；
- workflow handler；
- 公共入口；
- wheel内容；
- 测试专用或Benchmark专用调用；
- 替代路径和冻结replay对照。
