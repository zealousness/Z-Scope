# 历史设计与实施方案

以下文档于 2026-11-17 从日常文档目录移入归档。正文保留原方案与当时记录；其中的配置、接口、待办和预期性能不代表当前产品状态。文内仓库路径若未明确说明，仍按原文的仓库根目录口径理解。

| 历史文档 | 原位置 | 当前替代入口 |
|---|---|---|
| [全局语义建模](global-modeling.md) | `new_docs/stage1optimation/global modeling.md` | [执行与编排](../../modules/execution-orchestration.md) |
| [工具优化计划](tools_optimation_plan.md) | `new_docs/stage1optimation/tools_optimation_plan.md` | [Agent 运行时](../../modules/agent-runtime.md) |
| [Wiki 接入计划](llm_wiki_implementation_plan.md) | `new_docs/stage3-llm-wiki/llm_wiki_implementation_plan.md` | [LLM Wiki](../../modules/wiki.md) |
| [派生索引性能计划](derived_rebuild_performance_plan.md) | `new_docs/stage4optimation/derived_rebuild_performance_plan.md` | [最终优化说明](../../development/clangd-derived-index.md) |
| [Web 看板重设计方案](zscope_dashboard_redesign_implementation_plan.md) | `docs/progress_docs/zscope_dashboard_redesign_implementation_plan.md` | [WebUI 实际交付记录](../../design/webui/README.md) |
| [旧阶段优化总计划](next_optimization_implementation_plan.md) | `docs/progress_docs/next_optimization_implementation_plan.md` | [现行实施计划](../../plans/agent-scanning/README.md)及[实施状态](../../plans/agent-scanning/21_IMPLEMENTATION_STATUS.md) |
| [早期架构优化计划](architecture_optimization_plan.md) | `docs/progress_docs/architecture_optimization_plan.md` | [模块导航](../../modules/README.md) |
| [早期 C 内存与并发优化计划](c_memory_concurrency_optimization_plan.md) | `docs/progress_docs/c_memory_concurrency_optimization_plan.md` | [专业扫描规划](../../plans/agent-scanning/19_PROFESSIONAL_SCANNING.md) |
| [旧版分层分析说明](layered_optimization.md) | `docs/progress_docs/layered_optimization.md` | [当前架构](../../architecture.md) |
| [Balanced confirmed TP 提升计划](balanced_confirmed_tp_plan.md) | `new_docs/balanced_confirmed_tp_plan.md` | [分析流水线](../../modules/analysis-pipeline.md)及[Benchmark](../../modules/benchmarking.md) |
| [ValidatorEvidenceSlice v3 字段提案](ValidatorEvidenceSlice_v3_design.md) | `new_docs/ValidatorEvidenceSlice_v3_design.md` | [当前输入投影](../../../zscope/core/validation/evidence.py)及[输出协议](../../../zscope/common/validator_protocol.py) |
| [intrinsic 与 callee 架构优化计划](architecture_optimation_plan.md) | `new_docs/stage1optimation/architecture_optimation_plan.md` | [代码检索与后端](../../modules/retrieval-backends.md) |
| [快照重构方案与记录](snapshot_redesign.md) | `new_docs/stage1optimation/snapshot_redesign.md` | [配置、语义与状态](../../modules/configuration-state.md) |
| [Structured Evidence 字段提案](structured_evidence_field_redesign.md) | `new_docs/stage2optimation/structured_evidence_field_redesign.md` | [分析流水线](../../modules/analysis-pipeline.md)及[Agent 运行时](../../modules/agent-runtime.md) |
| [旧版 Validator 上下文字段提案](validator_context_field_redesign.md) | `new_docs/stage2optimation/validator_context_field_redesign.md` | [分析流水线](../../modules/analysis-pipeline.md) |

历史交接与执行证据仍保存在[日期化交接目录](../../handoffs/README.md)。当前实施计划中尚未完成的设计继续留在原规划包，不因包含历史背景而整包归档。

当前专题说明和有效后续事项已统一进入[文档总导航](../../README.md)，对应开发过程见[历史实施记录](../implementation/README.md)，评测协议见[Benchmark 导航](../../benchmarks/README.md)。原位置列仅用于迁移追溯。
