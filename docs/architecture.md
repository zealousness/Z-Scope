# Z-SCOPE Architecture

本文档描述当前开发版架构。重点是候选证据层、后端分工、用户配置注入和 LLM 验证边界。

## 1. 总体流水线

```mermaid
flowchart LR
    A["Entry discovery / entry_functions_list"] --> B["CodeIndex backend"]
    B --> C["Semantic overlay"]
    C --> D["Candidate evidence layer"]
    D --> E["CandidateLedger dedup"]
    E --> F["Deep Worker focus"]
    F --> G["Validator Agent"]
    G --> H["Report views"]
```

核心规则：

- CodeIndex 和后端负责抽取事实。
- Candidate layer 负责把事实变成候选证据。
- CandidateLedger 做根因级合并。
- Deep Worker 可对高风险候选做局部深挖。
- Validator Agent 独立审核，输出 `verified`、`needs_review` / `uncertain` 或 `rejected`。
- 报告层默认只展示可报告问题，Web 和 benchmark 可切换包含 `needs_review` 的视图。

## 2. 后端分工

| backend | 事实来源 | 候选层职责 |
| --- | --- | --- |
| `regex` | 源码文本、函数体、用户配置语义 | 低依赖本地模式匹配，输出 `regex_local_rule` |
| `clang` | clangd/CodeIndex 函数、调用边、类型、宏、KnowledgeDB | 输出 `clang_ast_cfg` 和 `clang_knowledgedb_call_edges` |
| `unified` | Clang + SVF/Saber + KnowledgeDB | 同时输出 Clang 候选、SVF value-flow 候选和后端信号 |
| `joern` | Joern CPG、`run.scan`、CPG data-flow、semantic sink/operator 规则、用户配置 | 输出 `joern_cpg` 候选 |

`unified` 的含义是 Clang 和 SVF 同时可参与候选生成，不是额外的 YAML 模式。

## 3. Semantic Overlay

用户配置会被 `SemanticOverlayCompiler` 编译成统一 overlay：

- `resource_models`：allocator、deallocator、reallocator、resource acquire/release、copy sink。
- `lock_models`：lock/unlock。
- `macro_models`：内存申请释放宏、copy 宏等。
- `pointer_target_models`：函数指针目标。
- `dispatcher_models`：消息分发器和 handler。
- `lifecycle_models`：模块初始化和清理。
- `function_intent_models`：外部 API、通信边界、线程边界、并发约束。

候选层使用 overlay 扩展项目私有语义，例如把 `VOS_MemAlloc` 当作 allocator、把 `VOS_MemFree` 当作 deallocator、把 `SHM_FileMngFileCreate(..., &fd)` 当作出参资源获取。

## 4. Candidate Evidence Layer

候选层只产生 evidence-only candidate。所有候选都必须满足：

- 有稳定 `candidate_id` 和 `dedup_key`。
- 有 `candidate_source` 和 `evidence_checker`。
- 有 source/sink、正向证据、反向证据或待验证说明。
- 有 `evidence_pack`，其中保留后端、路径、用户配置和原始事实。
- 设置 `validation_required=true`，不允许直接作为最终漏洞。

当前候选来源：

- `regex_local_rule`
- `clang_ast_cfg`
- `clang_knowledgedb_call_edges`
- `svf_value_flow`
- `joern_cpg`
- `graph/protocol`

## 5. Clang AST/CFG Candidates

`ClangAstCfgCandidateGenerator` 使用 clangd/CodeIndex 返回的函数体构造本地 statement/CFG 事实。虽然它还不是完整 libclang visitor，但它已经具备结构化证据：

- declaration table：局部声明、类型、指针层级、初始化状态。
- condition guards：`if` / `while` / `for` 条件。
- scope summary：basic block、return line、branch line。
- event stream：acquire、release、deref、return、lock、unlock、out-param use 等。
- cfg_path：候选触发路径上的关键行号。

已落地 checker：

- `clang_cfg_same_object_released_twice`
- `clang_cfg_use_after_release`
- `clang_cfg_acquire_without_release_on_exit`
- `clang_cfg_return_with_lock_held`
- `clang_cfg_alloc_result_deref_without_null_guard`
- `clang_cfg_realloc_lost_original`
- `clang_cfg_out_param_used_before_success_check`

出参规则会把 `uiRet = SHM_FileMngFileCreate(path, &fd)` 中的 `uiRet` 识别为状态值，把 `fd` 识别为资源 carrier。若 `fd` 在 `uiRet` 成功检查前被使用或释放，会生成 `bad_parameter_or_api_misuse` 候选。

## 6. SVF/Saber Value Flow

SVF/Saber 输出写入 KnowledgeDB 的 `taint_signatures`。`SvfValueFlowCandidateGenerator` 将其转为 `svf_value_flow` 候选，保留：

- bug type：如 `NeverFree`、`DoubleFree`、UAF。
- source function / sink function。
- 文件、行号、函数范围、函数签名。
- `svf_group`。
- 原始 backend row。

该候选的路径默认 `complete_in_function=false`，因为 Validator 需要把 LLVM/SVF 层面的事实和 C 源码所有权语义重新对齐。

## 7. Joern CPG Candidates

Joern 后端候选包括：

- `run.scan` 内置规则。
- user_config paired-function 检查。
- user_config `function_intents` 到危险 sink 的 CPG data-flow。
- semantic sink 批量规则：copy/string、format、command/exec、file path、allocation size。
- semantic operator 规则：division/modulo divisor、shift amount、pointer dereference。

data-flow 检查把用户声明的入口/边界函数作为 source，把默认危险 sink 和用户配置 copy/format/command sink 作为 sink，例如：

- `memcpy` / `memmove`
- `strcpy` / `strncpy`
- `sprintf` / `snprintf`
- `system`
- `fopen` / `open`
- `malloc` / `calloc` / `realloc`
- 用户配置的 `kind=copy` 函数

Joern 命中的结果统一转为 `joern_cpg` candidate，然后进入同一套去重和验证流程。

## 8. Dedup And Report Views

去重分两层：

- `CandidateLedger`：候选进入 Deep Worker 前按根因、source/sink、路径和资源对象合并。
- `issue_dedup`：最终报告前合并 LLM finding、候选、Worker 结果和历史反馈。

报告视图：

- `report_views.default`：默认可报告问题。
- `report_views.with_needs_review`：包含人工复核项。

benchmark 会分别计算这两种视图的检出率和误报率。

## 9. Validator Boundary

Validator 必须审核：

- 入口是否真实可达。
- source 是否受外部、线程、通信或上层 API 控制。
- sink 是否危险且可触发。
- CFG/data-flow 路径是否闭合。
- 用户配置是否说明了所有权转移、借用、释放、锁协议或 suppression。
- 是否存在反证，例如失败路径已返回、资源已转移给 caller、清理在上层完成。

规则命中、SVF 命中和 Joern 命中都不是最终漏洞结论。

## 10. 当前差距

- Clang AST/CFG 仍基于 clangd 函数体重建局部事实，尚未接入完整 libclang AST visitor 或真实 CFG dump。
- SVF/Saber 已有 `svf_value_flow` 候选，但还没有完整 source-level path reconstruction。
- Joern 已有配置驱动 data-flow、semantic sink 和 operator 规则，但还需要扩展到更多 CWE、项目协议和跨函数 Joern 查询。
- 历史文档已清理核心文档，其他专题文档后续仍需按当前口径复查。
