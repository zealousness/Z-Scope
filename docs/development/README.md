# 开发专题

先读[仓库协作说明](../../AGENTS.md)并按[模块导航](../modules/README.md)定位源码。本目录提供具体子系统的深入参考，不重复维护用户配置全文。

| 主题 | 文档 |
|---|---|
| 确定性规则、YAML rule pack 与 provider | [规则开发与治理](rules.md) |
| Clang 批量前端与 SVF 输入 | [批量索引与验收](clang-batch-indexing.md) |
| clangd 派生引用的实现与剩余规模验收 | [派生索引优化说明](clangd-derived-index.md) |
| Semantic Modeler 输入、输出与快照 | [Semantic Modeler 专题](semantic-modeler.md) |
| Agent 工具与可见性 | [工具专题](tools.md) |
| 会话录制、事件及排查 | [事件字典](conversation-events.md) |
| 内存、资源与并发缺陷模式 | [模式目录](c-memory-concurrency-patterns.md) |
| GitHub 协作与发布流程 | [仓库治理](github-governance.md) |

具体字段以当前工具声明、模型和消费者为准。仍未完成的规模验收不等于已证明的性能收益；混合保存的旧问题与修复过程见[历史实施记录](../archive/implementation/README.md)。
