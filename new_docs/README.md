# 专题说明与实施记录

本目录保留专题参考、实现说明和按日期记录的实施过程。已完成或被替代的设计方案统一移入[历史设计归档](../docs/archive/design-plans/README.md)，不再在此保留重复正文。

## 专题参考与后续事项

| 文档 | 保留用途 |
|---|---|
| [clangd 派生索引优化说明](clangd_large_project_optimization_plan.md) | 最终采用的解析、缓存和恢复方案；目标大仓规模验收仍未完成，保留其真实边界。 |
| [Semantic Modeler 说明](agent_introduction.md) | 专题参考；当前入口与合同以[Agent 运行时](../docs/modules/agent-runtime.md)及源码为准。 |
| [工具说明](tools_introduction.md) | 工具专题参考；实际暴露能力与字段以工具声明、运行时策略及源码为准。 |
| [会话录制事件字典](conversation_recorder_events.md) | 录制事件与排查参考，根 README 仍引用该入口。 |
| [问题与修复记录](known_issues.md) | 混合保存历史诊断、已修复项及后续建议；不把旧问题描述直接当作当前缺陷或新任务。 |
| [LLM Wiki 方法论](stage3-llm-wiki/llm-wiki.md) | 原始设计输入资料；当前产品行为见[LLM Wiki 模块](../docs/modules/wiki.md)。 |

## 历史实施与实验记录

以下文件保留当时的决策、测试结果和未完成项，用于追溯。旧配置、源码路径、测试命令和“当前”均按记录日期理解，不将历史结果改写为本轮通过，也不直接套用旧验收流程。

- [上下文优化实施记录](stage1optimation/agent_optimation.md)
- [工具优化实施记录](stage1optimation/tools_optimation.md)
- [架构优化实施记录](stage1optimation/architecture_optimation.md)
- [V1.3 更新说明](stage1optimation/Z-Scope-V1.3更新说明.md)
- [Wiki 实施记录](stage3-llm-wiki/llm_wiki_implementation.md)
- [Review Memory 实施记录](validator_review_memory_implementation.md)
- [Review 完整事实实验记录](review_evidence_v1_results.md)

新任务从[仓库协作说明](../AGENTS.md)、[模块导航](../docs/modules/README.md)及[现行实施计划](../docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/README.md)进入。实验记录中仍待验证的收益继续保持待验证，不因归档旧方案而宣称完成。
