# Z-SCOPE 模块导航

本目录按稳定子系统说明 Z-SCOPE 的代码所有权、主数据流、关键不变量和测试入口。模块文档用于快速定位，不替代源码、测试、[`docs/architecture.md`](../architecture.md) 或根目录 [`AGENTS.md`](../../AGENTS.md)。

## 顶层包映射

每个 `zscope/` 顶层包必须且只能归属一份模块文档：

| 子系统文档 | 覆盖的顶层包 | 主要职责 |
|---|---|---|
| [执行与编排](execution-orchestration.md) | `cli`、`orchestration`、`workflows` | 运行模式、入口规划、调度、Workflow 执行 |
| [分析流水线](analysis-pipeline.md) | `core`、`rules`、`alerts` | 候选收集、分析、验证、规则和外部告警复核 |
| [代码检索与后端](retrieval-backends.md) | `retrieval` | 索引、KnowledgeDB、Clang、Joern、Unified、SVF/Saber |
| [Agent 运行时](agent-runtime.md) | `framework`、`agents`、`skills`、`tools` | LLM 客户端、Agent/Skill 规范、工具运行时和策略 |
| [配置、语义与状态](configuration-state.md) | `config`、`semantics`、`snapshots`、`memory`、`common` | 配置模型、语义覆盖、快照、反馈、稳定身份和公共设施 |
| [LLM Wiki](wiki.md) | `wiki` | 项目说明文档发现、分类、索引、Wiki 知识和 Validator 上下文 |
| [接口与报告](interfaces-reporting.md) | `reporting`、`web`、`mcp` | 报告装配、SARIF、Dashboard、MCP 服务边界 |
| [Benchmark](benchmarking.md) | `benchmarking` | 通用评测协议、Range fixture、评分和发布聚合 |

## 使用方式

1. 先根据用户诉求选择根 `AGENTS.md` 中的使用者、开发者或 Range 路线。
2. 开发任务再按上表选择子系统；跨子系统变更应同时检查上下游不变量。
3. 文档中的 `sources` 和 `tests` 元数据只列稳定入口，完整依赖关系仍以代码搜索和测试为准。
4. 新增顶层包或移动职责时，同步更新本索引、对应模块文档和 `tests/test_agent_docs.py` 所约束的覆盖关系。
