# Z-SCOPE 文档导航

`docs/` 统一收纳项目级专题文档；根 README、AGENTS 以及工具和 fixture 的就近说明保留各自入口。先按任务选择下列分类；使用说明、当前实现、后续规划和历史证据分别维护，避免把旧方案或历史测试结果当作当前事实。

| 要做的事 | 阅读入口 |
|---|---|
| 安装、配置、扫描、报告与常用命令 | [项目 README](../README.md)、[使用指南](guides/README.md) |
| 理解系统与定位源码 | [总体架构](architecture.md)、[模块导航](modules/README.md) |
| 开发规则、索引、Agent 与工具，排查运行问题 | [开发专题](development/README.md)、[仓库协作说明](../AGENTS.md) |
| 查看当前开发路线与已实施切片 | [开发规划](plans/README.md)、[Agent 与专业扫描计划](plans/agent-scanning/README.md) |
| 运行与维护评测 | [Benchmark 协议](benchmarks/README.md) |
| 查看 WebUI 交互方案及实际对照 | [产品设计](design/README.md) |
| 阅读概念设计、方法论和调研 | [研究资料](research/README.md) |
| 查阅某一次审查、评测或发布记录 | [报告与审查](reports/README.md)、[发布记录](releases/README.md) |
| 追溯旧方案、历史实施与评测记录 | [历史归档](archive/README.md) |

## 内容边界

- 当前接口与配置以源码、测试和根 README 为准；模块文档说明稳定职责与不变量。
- `plans/` 区分规划目标与已交付切片，实际实施状态单独记录；研究提案和原型不自动等于产品能力。
- `reports/`、`releases/` 和 `archive/` 中的指标、提交、路径和测试结果只属于对应记录，不改写为新一轮结论。
- 每篇文档只有一个正式位置。更新引用时指向真实新位置，不保留平行正文或旧目录跳转副本。
- 根目录只保留本文导航和总体架构；专题文档放入对应分类，历史运行产物不混入当前规划。

仓库协作规则集中在 [agent-rules/](agent-rules/documentation/AGENTS.md)，按根 AGENTS 的任务路由读取。运行时 Agent prompt 和 Skill 属于产品源码，继续保存在 `zscope/agents/` 与 `zscope/skills/`。
