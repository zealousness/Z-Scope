# Derived Rebuild（function_symbol_context / function_type_refs）千万行规模性能优化计划

> **历史文档，2026-11-17 归档。** 原位置：`new_docs/stage4optimation/derived_rebuild_performance_plan.md`。本文是核心实现之前的候选方案，“待评审”、代码行号和性能外推保留当时含义。最终采用的方案与尚未完成的规模验收见[clangd 派生索引优化说明](../../development/clangd-derived-index.md)，当前职责见[代码检索与后端](../../modules/retrieval-backends.md)。

> 状态：计划（待评审）
> 范围：`zscope/retrieval/clang_extractor.py` 的组合式 derived 重建（`_rebuild_symbol_and_type_refs`，file-major pass）
> 证据：2026-09-06 实测日志（10M 行项目，`files=1731/9742` ≈ 17.8% 进度）

---

## 1. 实测证据与量级推算

取自 `[function_symbol_context]` / `[function_type_refs]` 连续三条日志（files=1729→1731，计数为累计值）：

| 指标（17.8% 进度时） | function_symbol_context | function_type_refs |
| --- | --- | --- |
| candidates（命中索引名的标识符出现） | 772,547 | 429,876 |
| filtered(shadow/field/macro_non_call) | 14,298 | 0 |
| semantic(req / resolved) | 1,726 / 100,059 | 1,725 / 33,266 |
| local（语义 token 直接判本地） | 99,417 | 32,633 |
| **references(req / resolved)** | **7,381,197 / 28,003** | **1,489,129 / 160** |
| definitions(req / timeout) | 643,905 / 2 | 49,515 / 0 |
| unresolved | 629,156 | 369,700 |

推算（按现行速率外推到 9,742 个文件全量）：

- 进入 LSP 消歧的出现点 ≈ 772,547 − 14,298 − 199,476 ≈ **55.9 万**（symbol 阶段），type 阶段 ≈ 36.4 万。
- `references` 平均 **≈13.2 次请求/出现点**（同名索引符号多，每个候选组代表各发一次 `textDocument/references`），解析率仅 **0.38%**（type 阶段 0.011%）。
- 全量外推：`references` ≈ **4,100 万次**、`definitions` ≈ **360 万次**、unresolved ≈ **350 万**。这就是"耗时极长"的直接原因。
- 另：semantic 阶段每文件仅 1 次 `semanticTokens/full`（req≈files），不是瓶颈；每次新增文件日志间隔约 13–24 秒/文件，主要时间都耗在 references/definition 往返上。

## 2. 根因分析（代码定位）

流程回顾：逐文件 open document → 1 次 semanticTokens → 逐函数逐行正则扫描标识符（`_collect_function_symbol_refs`，L3155 起）→ 命中索引 global/macro 名即成为 candidate → 语义 token 快速路径 → `_resolve_symbol_occurrence`（L3910）/`_resolve_cross_kind_occurrence`（L3965）：

1. **B1（主瓶颈）逐候选全项目 references 拉取**：`_resolve_candidate_by_references`（L4114）对每个同名候选组的代表调用 `_candidate_reference_locations`（L4186）→ 每组一次 `textDocument/references`（L4260），把全项目引用集摊成坐标倒排索引，再用出现点坐标做成员判定（L4160）。同名候选越多，单点成本越高；对最终绑定为"外部符号/系统头"的出现点，**N 次请求全部白打**（这就是 99.6% 请求浪费的来源）。
2. **B2 共享缓存过小导致抖动**：`_DERIVED_REFERENCE_CACHE_MAX_ENTRIES = 256`（L3354）、`_DERIVED_REFERENCE_CACHE_MAX_LOCATIONS = 500_000`。千万行项目有 ≥10 万个不同符号，256 条 LRU 在文件间反复驱逐 → 同一符号的 references 集合被跨文件反复重拉；且每次驱逐/重插都要重建坐标倒排索引（`_index_reference_locations`/`_trim_reference_resolution_cache`，L4344/L4389），CPU 也随 50 万坐标规模水涨船高。
3. **B3 definition 兜底"逐坐标 + 精确行匹配"基本失效**：`_definition_locations_cached`（L4458）按 (file,line,char) 逐点请求；`_resolve_symbol_candidate`（L4522）要求返回位置与候选行**完全相等**（L4536），clangd 返回前向声明/头文件声明、宏展开位置或外部符号时全部 miss → 64.4 万次请求近 0 命中，并产生 62.9 万 unresolved。
4. **B4 缺少外部符号廉价预筛**：没有任何"该名字在该文件内根本绑不到索引符号"的判定；系统头/三方库中同名实体的使用点被当成完整候选走完全流程。
5. **B5 并发模型受限**：derived 重建固定绑定到 pool 的单一 shard（`clang_extractor_pool.py:537` `_DERIVED_SHARD_INDEX`），`_run_derived_file_jobs`（L2119）多个线程共享**一个 clangd 进程/连接**（L2160），往返无法并行放大；且存在共享条件变量上的单飞与逐请求等待开销。
6. **B6 每文件 open/close 文档**（L2697-2702, L2772-2776）：9,742 次 open/preamble 构建 + close，次级但可合并（同文件在 symbol/type 两阶段共用一次，已做；跨文件无复用）。

## 3. 优化方案总览（按收益排序）

| 编号 | 方案 | 针对瓶颈 | 预期收益 | 优先级 |
| --- | --- | --- | --- | --- |
| S1 | 绑定判定改为 USR 主导：每出现点至多 1 次 `symbolInfo`/`definition`，废除逐候选 references 路径 | B1,B3 | references 请求 4,100 万 → ~0；总耗时预计降 10–30× | P0 |
| S2 | (file,name) 级绑定备忘录 + 外部名快速否决（会话级共享） | B4,B2 | 剩余 definition 请求再降 ~60–80% | P0 |
| S3 | 可见性前置收窄：include-closure + 名字相等先于任何 LSP 请求；可见候选唯一即直接采纳 | B1 | 大量出现点 0 请求 | P0 |
| S4 | USR↔符号 / 引用范围索引持久化（DB cache 表），增量重建按符号失效 | B2,B3 | 二次及增量重建接近 O(变更符号) | P1 |
| S5 | 并发与运行时：derived 重建用满 pool 全部 shard（多 clangd）+ 请求级指标暴露 | B5 | 2–4×（叠加在 S1–S3 之上） | P1 |
| S6 | 缓存常量与驱逐策略重校准（S1 落地后 references 缓存仅作兜底） | B2 | 次级 | P2 |

## 4. 详细设计

### 4.1 S1：USR 主导的绑定判定（核心重构）

现状两条路径（references 成员判定 + definition 精确行匹配）都绕开了 clangd 已给出的"精确绑定"答案。改为：

```
对每个 candidate 出现点 (file, line, char, kind, candidates_after_visibility):
  1. 语义 token 快速路径（保留现状：local 判定、kind 证明、唯一候选直采）。
  2. 否则发 1 次 textDocument/symbolInfo（已声明能力，L460；返回 usr/id/name/kind）。
     - symbolInfo 不可用或失败的回退：1 次 textDocument/definition（现有 get_definition）。
  3. 用返回的 USR 查 usr→索引符号 映射（内存 dict + S4 的 DB 缓存）：
     - 命中且与候选 kind 相符 → 直接采用该候选（occurrence resolved, 0 歧义）。
     - USR 为空/外部（usr 不在映射中）→ 记为 external binding：
       stats["filtered_external"] += 1，不进 unresolved（或单列 reason="external_symbol"）。
     - symbolInfo 返回名与扫描名不一致（宏展开等）→ 回退 definition 位置匹配
       （位置匹配放宽：候选声明 start_line ≤ target_line ≤ end_line，宏/类型已如此，
        函数/全局同样按声明区间匹配，而非单行相等）。
  4. 仅当 USR 与位置都无法区分剩余 ≥2 个可见候选（极少数同 USR 双记录）时，
     才允许 references 成员判定，并只对"可见候选"执行（见 S3）。
```

- `_candidate_canonical_identity`（L3788）已具备 symbolInfo 封装，直接复用并下沉为出现点级解析原语；`symbol_info_requests` 已在 stats 中（L3404）。
- 废弃/降级 `_resolve_candidate_by_references` 中"对所有组代表预取全量引用集"的循环（L4135-4144 的 eager 预取是 13.2 请求/出现点的直接来源）。
- `textDocument/symbolInfo` 是 clangd 轻量请求（不做全索引引用收集），单次成本远低于 references；definition 次之。
- 定义位置匹配规则统一为"声明区间 + 文件匹配"（`_paths_match` 已有，L4542），消除头文件声明 vs .c 定义行号不一致导致的 miss。

### 4.2 S2：(file,name) 备忘录与外部名否决

- `binding_memo: dict[(file_key, name), Binding]`，Binding ∈ {usr+symbol_id, external, ambiguous}。
  - 同一文件内同名标识符 99% 绑定一致；首见出现点做 LSP 请求，后续直接查表。
  - 一致性风险（宏/全局同名跨界绑定、局部 shadow）已由语义 token 路径优先拦截；当出现点的语义 token 签名（kind/modifier 摘要）与 memo 记录的签名不一致时强制重请求。
- `external_names: dict[file_key, set[str]]`：definition/symbolInfo 判定为外部的名字记入；该文件后续同名出现点 0 请求直接跳过。这直接消化 unresolved 大头（日志中 definitions 近 0 命中 + 62.9 万 unresolved 的主因）。
- 两个 memo 挂在 `_new_derived_resolution_caches()`（L2053 附近）上，全 pass 共享；线程安全沿用现有 per-key single-flight 机制（`_shared_resolution_cache_get_or_compute`）。

### 4.3 S3：可见性前置收窄

- `_visible_candidates`（include-closure 过滤）已存在，但 references 预取发生在 `visible or candidates` 上——不可见候选也会拉引用。改为：**不可见候选一律不参与任何 LSP 判定**；可见唯一 → 直接采纳（现 L3931-3936 已有，扩大其适用面：先收窄再判唯一）。
- `_load_include_closures`（L3319）一次性批量加载，成本可接受；确保 type 阶段同样先收窄。

### 4.4 S4：USR/引用范围索引持久化

- KnowledgeDB 新增两张 cache 表（跟随现有 staging 风格）：
  - `usr_symbol_cache(usr PK, table_name, symbol_id, name, kind, decl_file, decl_start_line, decl_end_line, source_hash)`；
  - `symbol_reference_scope(usr, ref_file, ref_line, ref_char)`——重建过程中"已成功解析出现点"的聚合，等价于 references 集合，但只含真实绑定。
- 写入时机：重建 pass 内按文件批次 upsert；失效按 (decl_file, source_hash) 与现有文件快照哈希比对。
- 收益：增量/二次重建中，未变更符号的出现点 0 LSP 请求；兜底 references 判定也可先查本地 scope 索引。
- 兼容：全部为派生缓存表，可随时 drop+rebuild，不参与 KnowledgeDB 对外契约。

### 4.5 S5：并发与运行时

- derived 重建不再钉死单一 shard：按文件列表哈希分发到 pool 的全部 N 个 shard（每 shard 独立 clangd，启动参数已含 `-j`，L276），聚合端（staging/consume）仍在调用线程串行——沿用 `_run_derived_file_jobs` 的 submit/consume 骨架即可，把"worker = 单 extractor"改成"worker = shard[i].extractor"。
- `get_request_metrics`（L576）已有按方法的延迟/超时统计：在 `_log_derived_progress` 里每 30 秒附加输出 references/definition/symbolInfo 的 avg/p95，作为验收与回归依据。
- open/close 文档维持现状（每文件一次），在多 shard 下不再是显著项。

### 4.6 S6：缓存重校准（S1 落地后）

- references 缓存仅保留给"USR/位置都无法消歧"的兜底：`_DERIVED_REFERENCE_CACHE_MAX_ENTRIES` 256 → 4096，`MAX_LOCATIONS` 500k → 200 万（或按 `-DERIVED_SEMANTIC_BYTES_PER_TOKEN` 的估字节法统一）；坐标倒排索引仅在兜底路径构建。

## 5. 实施阶段

| 阶段 | 内容 | 预计工作量 | 验证 |
| --- | --- | --- | --- |
| Phase 0 | 观测加固：进度日志加 per-method avg/p95、`filtered_external`、`binding_memo` 命中率；在现有项目上采 30 分钟基线 | 0.5 天 | 基线报告 |
| Phase 1 | S1+S3+S2（出现点级 USR 解析、可见性收窄、(file,name) 备忘录；references 降级为兜底） | 2–3 天 | 全量单测 + 中型项目 A/B：请求数与耗时对比 |
| Phase 2 | S4 持久化（usr_symbol_cache / symbol_reference_scope + 失效） | 1–2 天 | 增量重建耗时对比（目标：变更符号数的线性关系） |
| Phase 3 | S5 并发（多 shard 分发）+ S6 常量校准 | 1–2 天 | 8 核机 2–4× 并行收益验证 |
| 收尾 | 文档（`docs/modules/`、`new_docs`）、`unresolved` 语义说明（external 不再计为失败） | 0.5 天 | 评审 |

依赖关系：Phase 1 是全部收益主体，可独立发布；Phase 2/3 相互独立，可并行。

## 6. 预期结果（对比现行外推）

| 指标（全量 9,742 文件） | 现行外推 | Phase 1 后 | Phase 2/3 后 |
| --- | --- | --- | --- |
| references 请求 | ~4,100 万 | ≈0（仅兜底） | ≈0 |
| definition/symbolInfo 请求 | ~360 万 | ≤ 每出现点 1 次，且 (file,name) 去重后 ≈ 数万级 | 增量场景 ≈ 变更符号级 |
| unresolved 语义 | 350 万（大量为外部符号误报） | external 单列，true-unresolved 大幅下降 | 同左 |
| 墙钟时间 | 数天量级 | 预计 10–30× 提升 | 叠加 2–4×（并行）+ 增量近零 |

## 7. 风险与兼容性

- **语义等价**：USR 判定与"位置成员判定"在 C 语义下等价（同名不同实体的 USR 必不同）；风险集中在宏展开位置 symbolInfo 失准 → 已设计 definition 回退与 token 签名强制重请求。
- **C++ 限制**：重载函数、命名空间别名场景 symbolInfo 返回的 USR 与索引符号可能对不齐，保持"对不齐 → 回退位置区间匹配"的兜底，不追求 100% 消歧。
- **clangd 版本**：`textDocument/symbolInfo` 为 clangd 扩展，能力协商已声明（L460）；不可用时自动退回 definition 路径（仍为 1 请求/出现点）。
- **Windows 路径**：`_paths_match`/`_reference_file_key` 的大小写策略沿用现状，新增 memo key 统一走 `_reference_file_key`。
- **测试**：`tests/test_clang_derived_reference_resolution.py`、`tests/test_partial_derived_rebuild.py`、`tests/test_clang_incremental_extraction.py` 为回归主体；新增：external 名否决、memo 一致性（语义 token 签名冲突重请求）、声明区间匹配、多 shard 分发聚合正确性。

## 8. 明确不做（本轮）

- 不改 `function_symbol_context` / `function_type_refs` 的输出行语义（function_id/global_id/macro_id/line/access_kind 契约不变，`tests/test_global_modeler.py:298` 等契约不动）。
- 不引入 clang AST/`textDocument/ast` 逐节点遍历（成本与 references 同量级）。
- 不在本轮处理 Java 侧；不动 backend 之外的工具层。
