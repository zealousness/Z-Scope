# 02 · 本地架构与复用地图

## 核对边界

依据 2026-10-12 本地工作树及关键测试，不再以远端 HEAD 的模块文档推断现状。根目录已有大量用户修改；本次保留。旧交接 [TASKS.yaml](../../handoffs/2026-10-08-zscope/TASKS.yaml) 只解释历史工作包状态，不替代源码；旧 B/T/D/K/P/V/A 编号与本包 S/U/Q 编号不同。

## 实际主流程

`CLI/WebUI/MCP → 配置/入口/索引/Wiki → 可达并集增量语义建模并发布 → 确定性/backend 候选 → balanced/deep 地图与候选盲发现 → 全局 Ledger 收敛 → V0/V1/定向补证/V2/V3 → 统一分流/去重/报告/反馈`。

- 当前默认档位仍是 `fast`；它跳过主动发现，**不等于没有前置 LLM 接口建模**。
- C/C++ 各档位目前都先走增量语义建模。需求 planner 的 shadow 只记录建议，尚不改变全量调度。
- 一次式主动发现、默认关闭的 bounded investigation、Validator V3 是三种不同调用路径，不能统称已具备持续自主 Agent。
- 当前主 Ledger 冻结是扫描内部收敛手段，不是代码冻结或开发门禁。目标改为明确批次与 evidence revision；保留其去重价值，不要求永久保留具体机制。

## 已核对的复用表

下列路径均相对仓库根，测试“存在”不等于本轮全部执行。已执行范围见 [15](15_INDUSTRY_PRACTICES_AND_SOURCES.md)。

| 本地入口 | 当前事实 | 本版处理与剩余缺口 |
|---|---|---|
| `tools/search_code.py`、`read_code.py`、`source_access.py` | search 已支持 symbols/text/files；范围读、revision、分页已实现 | 直接复用，不新增第二套 grep/read；扩展对象查询时仍复用源码引用 |
| `tools/semantic_context.py`、`registry.py` | 已有 cache_only/ensure_current；read_only/candidate_blind profile 强制缓存读 | 删除旧“待实现 strict-read”；缓存身份不足仍为 unverifiable，不声称图/流可用 |
| `mcp/provider.py`、`retrieval/cached_index.py`、`snapshots/readonly.py` | 只读 MCP 可避免初始化重后端；缺失能力显式不可用 | 接入启动调查；无需重做只读服务器 |
| `orchestration/investigation.py`、`bounded_investigation.py` | 有会话、证据引用、范围扩展和有界调查 | 复用调查内核；默认 off，当前模式仅 off/shadow，不是通用任务持久运行时 |
| `orchestration/active_discovery.py`、`semantics/security_map.py` | candidate-blind 假设、AuditUnit/CoverageKey、统一登记已存在 | 扩展对象/协议覆盖与持久未决队列，不再另造主动发现系统 |
| `orchestration/external_investigation.py` | 仅 offline provider 执行意图导入，真实 provider 返回 unsupported | 不能描述为已集成外部 Coding Agent；后置且非默认依赖 |
| `orchestration/external_findings.py` | 外部结果归一化/被动导入 | 复用候选导入边界，不作为外部工具已实际运行的证明 |
| `semantics/contracts.py`、`contract_conditions.py`、`contract_compiler.py` | api-contract.v4；已有 preconditions/effect_cases、载体、resource_domain、protocol 及条件冲突处理 | 直接扩展；SymbolIdentity 目前不含 build context，需 S01 连同消费者修正 |
| `orchestration/semantic_modeling.py`、`semantic_demand.py` | SCC、静态透明封装、契约发布/重读、缓存；需求规划 shadow 明确 changes_execution=false | S07 才改为实际需求执行；不能提前宣传节省模型调用 |
| `core/validation/runner.py`、`pipeline.py`、`proofs.py` | 分层 Validator、正反证明、模型意见与最终分流分离 | S04 收敛义务/见证检查；无需重建第二裁决器 |
| `core/validation/dynamic_reproduction.py` | ASan/TSan runner、日志、对象/站点/类别匹配、重放、预算/取消及扫描接缝 | 复用执行基础；默认 off，普通扫描未安装自动 plan provider，不自动生成 harness/输入 |
| `retrieval/indexing_inventory.py`、`incremental_replay.py` | 多编译上下文清单、固定编译 fixture 增量/全量事实对照 | 清单不是分析覆盖；replay 不运行漏洞扫描/LLM/SVF，不能宣称最终召回一致 |
| `retrieval/knowledge_db.py` | translation_units.file_path 为 UNIQUE，部分存储/查询仍使用裸函数名 | S01 修正多变体和同名符号身份；不能仅给报告追加 variant 字段 |
| `retrieval/clang_batch.py`、`unified_backend.py`、`svf_analyzer.py` | 批量 Clang、统一索引、位码分组/SVF/Saber/缓存已有 | 首先复用，按真实成本和独占 TP 决定替换范围 |
| `wiki/service.py`、`source_index.py` | constraint-only revision、会话 pin、原文 fallback | 保留单一文档知识域，不再建设自动 Wiki 页面库 |
| `review_memory/`、`memory/review_memory.py` | 人工误报经验为 advisory，suppression 与背景提示分离 | 复用反馈；执行经验不得替代当前对象证据 |
| `framework/llm_client.py`、`llm_usage.py`、`agents/base.py` | 模型路由、协议、重试、用量、工具循环已有 | 共用一个客户端/账本；新增调度不能套重复无限重试 |
| `web/services.py`、`cli/cli.py`、`orchestration/scan_session.py` | 扫描入口、作业、恢复/维护已存在 | 先补夜间会话和三段体验；不先造独立 Agent CLI/全新 UI |

旧 handoff 最新记录中 V01/V02 已闭环，包含真实 ASan/TSan 历史验收；不能继续沿用早期 blocked 表述。该结果不等于自动生成器、CBMC、真实客户工程或正式准确率已完成。

## 目标架构与责任

```text
一个配置入口 + 本地 WebUI/CLI
  → 启动项目画像/本轮扫描计划
  → ScanSession + 持久 Job（调度、取消、续接、资源时窗）
  → BuildContext / Object / Event / ConditionalSummary
       ├─ 规则 + SVF/Saber 等候选
       └─ 对象/协议级 Agent 探索
  → Candidate + OpenObligations（同一登记与去重）
  → 确定性检查 / 定向调查 / 可选局部验证 / 自动复现
  → 同一 WitnessChecker 与 ValidationPipeline
  → 已确认 / 条件性 / 待验证 / 已排除 + 覆盖 + 集中验收
```

优先在已有 `retrieval`、`semantics`、`orchestration`、`core/validation`、`web` 中扩展；新增小文件按职责命名，不预建空目录。Q01 真有通用任务需求时才创建 `qa_agent`，届时同步模块 covers 唯一归属。

## 删除、替换与延后

| 项目 | 决定 |
|---|---|
| 全可达 LLM 建模作为一切扫描的前置 | 用静态摘要 + 需求闭包 + 未知覆盖替换；先验证召回，不以 shadow 结果冒充完成 |
| V1/V2/V3 重复阅读同一证据 | 统一 evidence revision 和未闭合义务；无事实增量不再反复复判 |
| 多套候选发现/调查会话 | 共用执行、证据与成本基础；保持“盲发现”和“候选验证”的输入区别 |
| 审批、权限与内网建设 | 从本计划移除；工作区一致性与真实证据仍保留 |
| 旧配置/工具/schema 兼容层 | 无兼容目标；更新所有当前消费者并给一次性重建/导入说明 |
| 用户工作簿作为唯一必经 UI | 以资源模型表单/统一存储为主，工作簿可导入导出；保留人工内容与来源 |
| 通用修复 Agent、外部 SDK、多 Agent | 后置，以实际任务收益再决定 |
| 新后端全量叠加 | 不采用；每个后端有明确缺口、样例和退出条件，见 19 |

复用的是质量资产与职责，不是把历史实现设为不可更改的红线。人工资料和已有用户改动需要保留；自动派生缓存允许按新版本重建。
