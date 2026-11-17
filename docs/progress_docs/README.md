# 专题协议与历史评测记录

已完成或被替代的架构、内存并发、分层分析和看板方案统一放在[历史设计归档](../archive/design-plans/README.md)。当前架构和后续任务分别见[模块导航](../modules/README.md)与[现行实施计划](../Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/README.md)。

## 继续保留的专题资料

- [外部 Benchmark 协议](external_benchmark_protocol.md)：仍被 Benchmark 模块引用；覆盖现有准备、sample 与 formal 执行入口，实际命令以当前脚本为准。
- [C 内存与并发模式目录](c_memory_concurrency_patterns.md)：通用缺陷模式与 Skill 映射，作为设计输入参考。
- [历史看板视觉稿](zscope_dashboard_redesign_demo.html)：已归档看板方案的配套 Demo，不代表当前 WebUI；实际交付见[WebUI 对照记录](../webui-redesign/README.md)。

## 历史工作区与评测记录

以下文件记录当时的本地工作区、样本选择、运行及限制。机器绝对路径、模型、指标和 smoke 结果仅属于原记录，不是现行环境默认值或新的正式结果；不因文中仍有命令示例而直接启动扫描。

- [外部 Benchmark 首轮记录](external_benchmark_first_run.md)
- [Juliet Memory 01–05 工作区与 smoke 记录](juliet_memory_01_05_benchmark.md)
- [SV-COMP C 工作区与 smoke 记录](svcomp_c_benchmarks.md)
- [Magma 工作区与 smoke 记录](magma_benchmarks.md)
