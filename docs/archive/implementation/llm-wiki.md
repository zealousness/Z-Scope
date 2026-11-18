# LLM Wiki 实施记录

> **历史文档，2026-11-17 整理归档。** 原位置：`new_docs/stage3-llm-wiki/llm_wiki_implementation.md`。正文中的状态、接口、路径、测试与后续建议保留记录时含义；当前说明见[文档总导航](../../README.md)，本类记录见[归档索引](README.md)。

## 2026-08-26：JSON Schema 落成

### 阶段目标

把实施计划第 6～11 章中的固定契约从 Markdown 代码块落成为可被构建和审计工具读取的 Draft 2020-12 JSON Schema 文件，确保 `IngestWorkset`、`WikiChangeSet`、Wiki 对象和 Validator `project_knowledge` 使用同一版本化定义。

### 实际文件

- `zscope/wiki/schemas/document-source.schema.json`
- `zscope/wiki/schemas/document-section.schema.json`
- `zscope/wiki/schemas/document-source-manifest.schema.json`
- `zscope/wiki/schemas/project-constraint.schema.json`
- `zscope/wiki/schemas/document-ref.schema.json`
- `zscope/wiki/schemas/wiki-edge.schema.json`
- `zscope/wiki/schemas/wiki-revision.schema.json`
- `zscope/wiki/schemas/wiki-page-frontmatter.schema.json`
- `zscope/wiki/schemas/wiki-index.schema.json`
- `zscope/wiki/schemas/wiki-event.schema.json`
- `zscope/wiki/schemas/wiki-ingest-workset.schema.json`
- `zscope/wiki/schemas/wiki-changeset.schema.json`
- `zscope/wiki/schemas/validator-project-knowledge.schema.json`
- `zscope/wiki/schemas/schema-registry.json`
- `tests/test_wiki_schema_contract.py`

每个 schema 使用固定 `$id=zscope.<contract>.v1`、Draft 2020-12 `$schema`、`additionalProperties=false`（显式允许任意字段的 frontmatter 除外），并与实施计划中的 13 个 JSON 代码块逐项字典等价。`schema-registry.json` 是 `$id` 到文件名的唯一解析表；实现 JSON Schema 校验器时必须把该表注册到 resolver，不能依赖网络抓取或隐式 URI 解析。

### 固定 reason/status 约束

- `WikiChangeSet.outcome` 固定为 `changed`、`background_only`、`conflict_only`、`extraction_failed` 或 `source_rejected`。
- 无约束说明文档返回 `background_only`，其 `source_results.extraction_status` 为 `no_constraints_found` 或 `background_page_updated`，`constraint_proposals=[]`；程序事件记录 `constraints_created=0`，不得解释为“项目没有约束”，也不得产生负面 Validator 证据。
- `source_fallback` 和 `none` 的 `project_knowledge` 不携带 Wiki 约束或页面摘录；`wiki` 模式必须绑定 revision。冲突/过期约束只能出现在冲突或 unknown 摘要中。

JSON Schema 负责字段、类型、枚举、格式、正则、数量和额外字段约束；集合不交集、引用 allowlist、digest/行号可解析性、outcome 状态机、token 预算和 Validator catalog 注册等跨字段不变量仍由程序 lint 固定执行。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_schema_contract.py tests/test_agent_docs.py
```

结果：`9 passed`（6 个既有 Agent 文档测试 + 3 个 schema 契约测试）。另外使用标准库 `json.loads()` 逐个解析 13 个 schema 和 registry，全部成功；未运行实际 benchmark。

### 后续阶段边界

- 本节记录的是最初的契约落成阶段；`zscope/wiki/` 运行时代码、Markdown discovery、source index、Compiler、Validator 接入和程序 lint 已在后续阶段 1～10 逐项落地。
- 跨字段不变量和 YAML frontmatter/body 校验由后续 lint/store 阶段负责；这些规则不重复编码为可误解的单字段 JSON Schema。
- `$ref` 使用 schema ID，生产校验器必须加载 `schema-registry.json`；当前环境未安装 `jsonschema`，因此仓库回归使用标准库 registry/ref 漂移检查和程序自有 lint。

## 2026-08-26：阶段 1——发现、分类、分节和 manifest

### 阶段目标

按计划把 `project.root` 下的 Markdown 变成可审计、可重建的确定性来源清单。该阶段不调用 LLM，不写入 Wiki revision，也不运行 benchmark。

### 实际文件

- `zscope/wiki/discovery.py`：递归 `.md`/`.markdown` 发现；目录剪枝；root 边界、文件 symlink、UTF-8、单文件/总文件数/总字节限制；稳定 POSIX 路径和 `sha256:` 原始字节 digest。
- `zscope/wiki/classification.py`：mandatory runtime/truth/generated 排除、frontmatter provenance、显式文档契约、已知 README/docs/output 路径、内容辅助阈值、受限 project-relative override 和 fail-closed `unknown`。
- `zscope/wiki/markdown_parser.py`：ATX/Setext heading、1-based 非重叠 section 行号、heading path、代码符号、`module:` 提示、规范性词、相对链接、语言和稳定 section digest；超长内容按有界片段处理。
- `zscope/wiki/source_manifest.py`：生成 `zscope.document-source-manifest.v1` 的 accepted/excluded/unsupported 集合、稳定 source/descriptor ID、tree/content-derived root digest、canonical manifest digest 和 JSON 持久化函数。
- `tests/test_wiki_ingestion.py`：fixture 分类、稳定 digest、Markdown section 特征、override/m mandatory 不可绕过、非法 UTF-8/越界 symlink/大小限制测试。

### 固定行为和 reason code

- accepted 仅允许 explanatory；generated/runtime/truth/sensitive/unknown 均写入排除 descriptor，不进入 source corpus。
- mandatory exclusion 在 frontmatter 和用户 override 之前执行，不能删除或覆盖；`.zscope_knowledge` 等生成目录在 discovery 前剪枝。
- 不支持的扩展只计入 `unsupported_extensions`，不读取正文；非法 UTF-8、越界 symlink、超限和不可读文件分别记录稳定 issue reason。
- source ID 为 `hash(project_id | markdown_document | relative_path)`，与 content digest 解耦；manifest digest 排除 `created_at` 和自身 digest，因此同一输入的两次构建稳定。
- malformed/duplicate frontmatter、非法 `zscope_document.kind` 和无充分证据文档均 fail closed 为 `unknown`；敏感内容只记录 reason，不落正文。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_ingestion.py
```

结果：`5 passed`。另外执行 `python -m compileall -f -q zscope/wiki tests/test_wiki_ingestion.py` 成功；没有运行实际 benchmark。

### 未完成项

- `source-index.db`、FTS/内存倒排查询和 direct source fallback 属于阶段 2。
- section 超长内容的完整段落/表格边界切分、SQLite 索引和 schema 实例 lint 将在阶段 2 继续完善；本阶段仅生成内存 section 对象。

## 2026-08-26：阶段 2——source-index 和 direct source fallback

### 阶段目标

在不调用 LLM 的前提下，把阶段 1 的 accepted explanatory Markdown 重建为独立的 `source-index.db`，并让 Validator 查询可以从原始文档返回带稳定 provenance 的有限摘录。Wiki DB、Compiler 和 Validator verdict 均不在本阶段改动。

### 实际文件

- `zscope/wiki/source_index.py`
  - 固定 `documents`、`sections`、`links`、`classification_events` SQLite 表；可用 SQLite 时增加 `sections_fts`，FTS5 shadow 表仅作为 SQLite 内部实现细节。
  - `SourceIndex.rebuild()` 每次清空并从 manifest/discovery/Markdown parser 重建，校验 accepted 文件存在且 content digest 与 manifest 一致。
  - FTS 不可用时使用同一排序规则的内存扫描；查询结果按 score、relative path、行号、section ID 稳定排序。
  - 支持 exact symbol、module scope、candidate path、fact-kind、resource/lock identity 和受限 lexical hit；仅 generic fact-kind 没有 identity/scope anchor 时不返回结果，避免把其他 API 的范围说明误注入候选。
  - 每次 excerpt 返回 `docref_`、相对路径、heading path、1-based 行号、原文、`match_reasons` 和 score；默认最多 5 个 section、2 个文档、2,000 tokens，硬上限 3,500 tokens。
- `zscope/wiki/context/direct_documents.py`：直接复用 `SourceIndex.search()`，命中返回 `source_fallback`，无命中返回 `none` 和 `no_relevant_project_constraint`。
- `zscope/wiki/__init__.py`：导出 `SourceIndex`、`SourceIndexBuild`、`build_source_index`。
- `tests/test_wiki_source_index.py`：README `parse_byte` 值域命中、Validator `value_range` 别名、未知 API 无命中、SQLite schema/重建稳定性测试。

### 固定行为和 reason code

- source index 只包含 manifest `accepted` 中的 `explanatory` 文档；AGENTS、GROUND_TRUTH、报告、secret 和 `.zscope_knowledge` 不进入 sections。
- `SourceIndex.search()` 不生成 constraint；它只返回 source excerpt。命中时 DirectDocumentResolver 的 `fallback_reason` 保留上游原因（例如 `compiler_unavailable`），无命中固定为 `no_relevant_project_constraint`。
- 文档最多出现于两个不同 relative path，section 和 token 预算均为硬限制；预算裁剪不会改变文件和行号 provenance。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_source_index.py
```

结果：`4 passed`。另外执行：

```text
python -m pytest -q tests/test_wiki_ingestion.py tests/test_wiki_source_index.py tests/test_wiki_schema_contract.py tests/test_agent_docs.py
```

结果：`17 passed`（包含阶段 1、阶段 2、schema 和 Agent 文档覆盖测试）。未运行实际 benchmark。

### 未完成项

- 尚未将 `ProjectKnowledgeService` 和 Validator runner 接入 source index；当前可由 `DirectDocumentResolver` 独立调用。
- FTS 查询目前保留与内存扫描一致的确定性评分实现，后续可在不改变排序契约的前提下增加查询性能优化。
- 模块文档测试路径已统一为现有的 `tests/test_wiki_ingestion.py`；阶段 2 未运行实际 benchmark。

## 2026-08-26：阶段 3——Wiki skeleton、revision、原子发布和 rollback

### 阶段目标

在不调用 Compiler LLM 的前提下，把 accepted source manifest 转换为可回放的 project/module/source 中文 Markdown 页面骨架，建立 `DocumentRef`、revision、SQLite projection、active pointer、程序事件和 rollback 边界。背景文档不自动提升为结构化 constraint。

### 实际文件

- `zscope/wiki/identity.py`：稳定 object ID、slug 和 canonical digest helper。
- `zscope/wiki/store/revision_store.py`：固定 `wiki.db` projection、staging/revisions/quarantine 目录、六个页面章节、refs/constraints/edges/revision JSON、fsync 后 atomic `active.json`、程序拥有的 `log.md` 和 rollback。
- `zscope/wiki/store/__init__.py`：导出 `WikiStore`/`WikiBuildResult`。
- `tests/test_wiki_revision_store.py`：骨架发布、ref provenance、无约束 `background_only`/`constraints_created=0`、active pointer 和 rollback 测试。
- `docs/modules/wiki.md`、`docs/modules/README.md`、`AGENTS.md`、`tests/test_agent_docs.py`：登记新增 `zscope/wiki` 顶层包并保持模块覆盖契约。

### 固定行为和 reason/status

- deterministic skeleton 的 revision `compiler.kind=deterministic`，`constraint_count=0`，`outcome=background_only`；普通背景句子只进入页面摘要，不进入 `constraints.json` 或 Validator negative evidence。
- 每个 active revision 有 project overview；accepted source 生成 source page，解析出的 `module:` 提示生成 module page；页面 frontmatter 使用 `zscope.wiki-page-frontmatter.v1`，正文严格包含六个固定二级标题。
- 每个 section 生成 `zscope.document-ref.v1`，保留 source digest、excerpt digest、relative path、heading path 和 1-based 行号；程序拥有 refs/active pointer/log，LLM 尚未获得写权限。
- 发布先写 `staging/<revision>.tmp`，完成 revision/page/ref projection 后 rename 到不可变 `revisions/<revision>`，最后 fsync + replace `active.json`；旧 revision 保留，可 rollback 到任意已发布 revision。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_revision_store.py tests/test_wiki_source_index.py tests/test_wiki_ingestion.py tests/test_wiki_schema_contract.py tests/test_agent_docs.py
```

结果：`20 passed`。没有运行实际 benchmark。

### 未完成项

- 尚未实现 WikiChangeSet 校验、LLM Compiler workset、增量 dirty closure、freshness/conflict/stale 传播和正式 ProjectKnowledgeService。
- 当前 skeleton 的跨字段 schema lint 仍需补充，后续阶段将验证 refs、页面 frontmatter/body、active revision 和变更集 allowlist 的完整闭包。

## 2026-08-26：阶段 4——IngestWorkset、WikiChangeSet 和 Compiler 边界

### 阶段目标

把 Compiler 的输入/输出边界实现为程序可校验对象。模型只处理由程序从 bounded workset 派生的输入 projection；没有 LLM 时也能产出明确的 `background_only/no_constraints_found` 结果；有 provider 时所有 JSON 仍须经过同一 ChangeSet 状态机。

### 实际文件

- `zscope/wiki/compiler/workset.py`：从 accepted manifest 和 source-index section 构建 `zscope.wiki-ingest-workset.v1`，固定 source/page allowlist、dirty source 集合和四项资源限制。
- `zscope/wiki/compiler/changeset.py`：校验 workset/revision identity、source ref allowlist、page operation、source_rejected、background_only、changed、conflict_only、extraction_failed 的跨字段不变量。
- `zscope/wiki/compiler/compiler.py`：无 provider 时返回确定性 background-only；provider 输出解析失败或不符合边界时降级 extraction_failed，不发布新内容。
- `zscope/agents/wiki_compiler/AGENT.md`：声明中文 Markdown、引用、权限、禁止 verdict/truth/secret 和无约束文档行为。
- `tests/test_wiki_compiler.py`：无 LLM、约束注入拒绝和 malformed provider fallback 测试。

### 固定行为和 reason/status

- IngestWorkset 的 `added_source_ids`、`changed_source_ids`、`removed_source_ids` 必须互斥，所有 `allowed_source_refs` 来自 accepted source section；target page 不能为空。
- `background_only` 只允许 `no_constraints_found`/`background_page_updated`，`constraint_proposals=[]` 且不得产生 graph mutation；这不表示项目没有约束，也不生成负面 Validator 证据。
- `extraction_failed` 保留旧 active revision，page/constraint/edge/retire 变更全部为空；`source_rejected` 只能审计 `docdesc_`，不能引用 rejected source ref。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_compiler.py tests/test_wiki_revision_store.py tests/test_wiki_source_index.py tests/test_wiki_ingestion.py tests/test_wiki_schema_contract.py tests/test_agent_docs.py
```

结果：`23 passed`。没有运行实际 benchmark。

### 未完成项

- 尚未接入真实 LLM client、Compiler multi-page merge、quarantine/lint 深度检查和增量 dirty closure。
- 尚未把 active Wiki context 接入 Validator；下一阶段实现 freshness、冲突/过期传播和 read-only ProjectKnowledgeService。

## 2026-08-26：阶段 5——增量 freshness、dirty closure、冲突和 writer lock

### 阶段目标

使来源变更可以只影响必要页面和约束，删除来源不会静默保留 active 约束；同一 slot 的等值约束合并引用，不同值保留冲突；同一项目的 Wiki writer 不能并发发布。

### 实际文件

- `zscope/wiki/maintenance.py`：`compare_manifests`、`dirty_page_closure`、`merge_constraint_proposals`、`propagate_stale` 和 `WikiWriterLock`。
- `tests/test_wiki_maintenance.py`：修改来源 delta、依赖闭包、等值合并、冲突保留、删除后 stale 和排他锁测试。

### 固定行为和 reason/status

- source identity 保持稳定，content/path digest 变化进入 `changed_source_ids`；新增/修改/删除三组 source ID 必须互斥。
- dirty closure 从 source page 传播到 module/project/dependent page，并以稳定 ID 排序；无关页面不进入 closure。
- 同一 subject/kind/scope 且 normalized value 相等时只保留一个 constraint 并合并 `source_refs/page_refs`；值不同则双方 `status=conflicted` 且互相写入 `conflicts_with`，不得静默覆盖。
- 删除来源支持的 constraint 标记 `stale`；stale/conflicted 后续不得进入 active Validator context。
- `WikiWriterLock` 使用项目状态目录下的独占创建锁；锁占用超时返回错误，退出时清理锁文件。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_maintenance.py
```

结果：`4 passed`。没有运行实际 benchmark。

### 未完成项

- 尚未把 dirty closure 与 `WikiStore.build_skeleton` 的增量发布连接起来，也未实现完整 freshness/revision manifest 比对和 conflict page projection。
- Validator 仍未消费 active revision；下一阶段进入 shadow ProjectKnowledgeService。

## 2026-08-26：阶段 6——ProjectKnowledgeService、Validator shadow 和配置接入

### 阶段目标

把 Wiki/source fallback 以独立 `project_knowledge` 投影接入 Validator v3，同时保持 `off` 默认兼容、shadow 不改变模型/verdict、active revision 与 source manifest pin 一致。Compiler 不可用时必须回到 direct source。

### 实际文件

- `zscope/wiki/service.py`：只读 `ProjectKnowledgeService.resolve_for_candidate()`；候选 obligation 解析、revision freshness、Wiki page 选择、source fallback、预算、selection trace 和 context digest。
- `zscope/core/validation/evidence.py`：将 project knowledge 作为独立辅助字段加入 v3 slice，并把 constraint/page/source refs 注册到 `evidence_ref_catalog`。
- `zscope/core/validation/runner.py`：可选注入 scan-pinned service；构建 evidence pack 时解析 project knowledge，服务失败只保留原 evidence。
- `zscope/core/analysis/analyzer.py`：根据 project Wiki mode 建 manifest/source-index/store，一次创建 scan-level service；`build_only` 只构建不注入，`shadow/active` 注入只读 resolver；关闭 Analyzer 时释放 Wiki store/index。
- `zscope/config/config.py`、`zscope/config/v2.py`：增加严格 `project.wiki` 配置（mode、state_dir、分类 override、资源/上下文限制）。
- `tests/test_wiki_service.py`、`tests/test_validator_project_knowledge.py`、`tests/test_config_v2.py`：source fallback、active revision pin、catalog attribution、off/default 和 root-relative 配置测试。

### 固定行为和 reason/status

- `resolution_mode=source_fallback` 时 `wiki_revision_id=null`、`constraints=[]`、`page_excerpts=[]`，只返回 source excerpts；无命中返回 `none/no_relevant_project_constraint`。
- Wiki 页面只有在 active revision 的 `source_manifest_digest` 与当前 scan manifest 一致时可读取；过期/缺失/无 Compiler 命中均降级原文搜索。
- 文档约束作为 `authority=documented_contract` 的辅助上下文，不是 deterministic proof，不得单独确认/拒绝候选；`project_knowledge` 的 ref 必须进入同一 evidence catalog。
- `project.wiki.mode=off` 是默认；`build_only` 不注入；`shadow`/`active` 共享同一只读 resolver，模式差异只由上层 rollout/消费策略决定。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_service.py tests/test_validator_project_knowledge.py tests/test_config_v2.py tests/test_validation_runner.py
```

结果：`80 passed`。没有运行实际 benchmark。

### 未完成项

- 尚未把真实 Compiler LLM 与 ChangeSet 合并接入 active mode；当前 skeleton 仅提供背景页，因此 active mode 在 Compiler 不可用时按设计走 direct fallback。
- 尚未增加 CLI `wiki discover/build/lint/status/query/rollback`、shadow telemetry 和 report attribution；后续阶段完成控制面和灰度评估。

## 2026-08-26：阶段 7——active/shadow Validator 消费边界

### 阶段目标

完成从 Analyzer 到 Validator v3 的 scan-level 注入边界：一次扫描只创建一个 manifest/source-index/store/service，Validator 线程共享 pinned digest；Wiki context 失败时保留原 evidence slice 和既有 verdict 语义。

### 实际文件

- `zscope/core/analysis/analyzer.py`：Wiki preflight、state-dir 相对 project.root 解析、manifest/source-index/revision pin、build_only 不注入和资源关闭。
- `zscope/core/validation/runner.py`：可选 `project_knowledge_service` 注入 evidence pack；解析异常只记录 warning 并继续原验证路径。
- `zscope/core/validation/evidence.py`：`project_knowledge` 进入 v3 slice，constraint/page/source ref 注册到 `evidence_ref_catalog`。
- `tests/test_validator_project_knowledge.py`：辅助上下文、source ref catalog 和空 constraints 边界测试。

### 固定行为和 reason/status

- Validator 输入中的 Wiki context 是独立辅助字段，绝不复用 `semantic_claims`、deterministic proof 或 finding verdict。
- `source_fallback`/`none` 不携带 Wiki page 或 constraint；`source_excerpts` 仅来自 accepted source-index，路径、标题、行号和 digest 由程序保留。
- active revision manifest 不匹配、Wiki store 损坏、查询异常或 Compiler 不可用均回落 direct source/base evidence；文档内容不能单独 reject/verify candidate。

### 验证命令和结果

```text
python -m pytest -q tests/test_agent_docs.py tests/test_wiki_cli.py tests/test_wiki_service.py tests/test_wiki_compiler.py tests/test_wiki_revision_store.py tests/test_wiki_maintenance.py tests/test_validator_project_knowledge.py
```

结果：`19 passed`。没有运行实际 benchmark。

### 未完成项

- 当前 active Wiki 页面仍是 deterministic skeleton；真实 LLM constraint/page merge 和冲突 projection 尚未启用。
- 尚未记录完整 Wiki injection telemetry（selected IDs、knowledge tokens、fallback reason）到 scan report；下一阶段补齐控制面、审计和灰度指标。

## 2026-08-26：阶段 8——Wiki CLI 控制面和最小灰度入口

### 阶段目标

提供 project-root scoped 的 discover/build/status/query/rollback 命令，让 Wiki 状态可在不运行漏洞 benchmark 的情况下单独构建、检查和回放。

### 实际文件

- `zscope/cli/wiki.py`：独立 `zscope-wiki --root <project.root>` 命令组；所有命令使用同一 manifest/source-index/state 根。
- `pyproject.toml`：注册 `zscope-wiki` console script。
- `tests/test_wiki_cli.py`：discover/build/status/query fixture 测试。
- `docs/modules/wiki.md`：登记 CLI/service/compiler/store 入口和测试。

### 固定行为和 reason/status

- `discover` 只写 manifest；`build` 先重建 source-index，再发布 deterministic skeleton；`status` 只读 active pointer；`query` 始终走 source fallback；`rollback` 只能切换已存在 revision。
- CLI 不读取 GROUND_TRUTH、AGENTS、生成物或 secret，不执行 benchmark，不把 CLI 文本作为 Validator proof。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_cli.py tests/test_wiki_service.py tests/test_validator_project_knowledge.py tests/test_config_v2.py
```

结果：`38 passed`。没有运行实际 benchmark。

### 未完成项

- 尚未接入真实 Compiler LLM、shadow telemetry/report attribution、完整 `lint` 子命令和正式 A/B/replay 评估；这些属于后续灰度阶段。

## 2026-08-26：阶段 9——真实 LLM Compiler adapter 和安全回退

### 阶段目标

在已有 deterministic Compiler 外增加 OpenAI-compatible provider adapter，但保留程序拥有的 workset、ChangeSet 校验和无 LLM fallback。网络/模型输出只作为候选变更，不能直接发布。

### 实际文件

- `zscope/wiki/compiler/llm_compiler.py`：发送最小 system/user 请求和 `build_llm_input_projection()` 结果，解析 JSON/tool-call，并调用 `validate_changeset`；解析失败由上层 `WikiCompiler` 变成 `extraction_failed`。
- `tests/test_wiki_llm_compiler.py`：fake client 的结构化 ChangeSet 测试，无真实 endpoint、API key 或 benchmark。
- `zscope/agents/wiki_compiler/AGENT.md`：Compiler 权限和无约束文档说明。

### 固定行为和 reason/status

- LLM 只能看到 Workset 派生的 projection，不可任意读取 project.root、shell、网络或未发布页面；所有 source/page/ref identity 由程序分配。
- `background_only/no_constraints_found` 是合法成功结果；空 constraint 不等于项目不存在约束，也不产生负面 Validator 证据。
- malformed JSON、未知字段、越权 ref、错误状态机和 provider 异常均不发布新 page/constraint/edge，旧 active revision 保持不变。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_llm_compiler.py tests/test_wiki_compiler.py tests/test_wiki_service.py
```

结果：`6 passed`。没有访问真实 LLM endpoint，也没有运行实际 benchmark。

### 未完成项

- 尚未在 Analyzer config 中启用真实 Compiler provider（默认仍 deterministic/off）；尚未实现 prompt/version/model provenance 的完整 revision merge、quarantine 和 rate-limit telemetry。

## 2026-08-26：阶段 10——revision lint、CLI lint 和发布审计

### 阶段目标

为发布后的 revision 增加不依赖可选 `jsonschema` 包的程序 lint：检查 page/frontmatter identity、六个固定正文标题、page 文件闭包、`docref` 可解析性、active manifest pin 和 failed revision 标记。

### 实际文件

- `zscope/wiki/lint.py`：`LintResult`、`lint_revision`。
- `zscope/cli/wiki.py`：`zscope-wiki lint`，失败以非零退出并输出结构化错误。
- `tests/test_wiki_lint.py`：正常 revision 与 unresolved source ref 检测。

### 固定行为和 reason/status

- lint 失败不会把 revision 自动切成 active；active pointer 只能指向通过发布流程的 revision。
- page 内 `[docref_*]` 必须存在于同 revision 的 program-owned ref projection；frontmatter page_id、磁盘页面路径和 SQLite projection 必须一致。
- lint 输出只含错误/警告 reason，不复制原始敏感正文或模型响应。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_lint.py tests/test_wiki_cli.py tests/test_wiki_service.py
```

结果：`4 passed`。没有运行实际 benchmark。

### 未完成项

- 尚未接入完整 Draft 2020-12 实例校验器、WikiChangeSet 的 schema registry resolver 和发布前 lint failpoint 回放；后续补充故障注入与安全审计。

## 2026-08-26：阶段 11——ChangeSet 发布、离线 Schema resolver 和 active constraint 查询

### 阶段目标

把经过校验的 `WikiChangeSet` 真正发布为不可变 Wiki revision，并让 Compiler 的 bounded source section、结构化约束和页面内容在同一 revision 中闭包一致。补上本地 Schema registry resolver，确保没有网络和可选依赖时仍能执行核心契约校验；Validator active 查询只消费当前 revision 中 status=active 且来源引用可解析的约束。

### 实际文件

- `zscope/wiki/store/revision_store.py`
  - 新增 `WikiStore.apply_changeset()` 和 `compile_and_apply()`。
  - 校验 workset identity、active base revision 和 ChangeSet 状态；`extraction_failed`/`source_rejected` 只写 quarantine event，不切换 `active.json`。
  - 变更在内存中完成 refs、页面、constraint、edge 合并，更新 manifest/revision pin，写入 staging 后原子发布；等值约束合并来源引用，冲突/删除来源保留 conflicted/stale 状态。
  - Compiler 页面只能使用 fixed six headings；程序覆盖 page identity、project、digest、source/constraint refs，不能接受模型伪造的 program-owned 字段。
- `zscope/wiki/compiler/changeset.py`
  - 增加 page、constraint、edge、retire 的 allowlist 和 authority/schema 检查，以及 source result 必须属于 workset 的校验。
  - 变更集先通过本地 Schema registry，再执行 outcome 状态机和跨字段不变量。
- `zscope/wiki/compiler/workset.py`、`zscope/wiki/schemas/wiki-ingest-workset.schema.json`
  - Workset 新增固定 `source_sections` 投影，包含 section digest、行号、符号、module hints、规范性词和链接；所有被接受的 Markdown section 均完整投影，不再提供源字符截断预算。
- `zscope/wiki/schema.py`、`tests/test_wiki_schema_resolver.py`
  - 新增 registry 加载、local `$ref` 检查和 Draft 2020-12 常用关键字的无依赖校验；安装 `jsonschema` 时自动委托完整 Draft 2020-12 validator，禁止网络 resolver。
- `zscope/wiki/service.py`
  - active revision 查询结构化 constraints，按 obligation 的 kind、subject、module、path scope 做确定性匹配；只返回 active/documented_contract 且绑定 source refs 的约束。
- `zscope/core/analysis/analyzer.py`、`zscope/config/config.py`、`zscope/config/v2.py`
  - `compiler_enabled` 时通过现有 `wiki_compiler`/default client 运行 bounded Compiler，并以 project writer lock 保护发布；新增 compiler/output/source/wall 限制配置，默认仍关闭。
- `tests/test_wiki_revision_store.py`、`tests/test_wiki_compiler.py`
  - 覆盖真实 ChangeSet→revision、失败不切 active、source sections 投影及 Validator active constraint 消费。

### 固定行为和安全边界

- `IngestWorkset` 与 `WikiChangeSet` 的 identity、source/page/ref allowlist、schema 和状态机均由程序校验；模型输出不能写 SQLite、manifest、active pointer、log 或 workset 外页面。
- 发布顺序固定为：校验 → 内存合并 → staging 文件 → 不可变 revision → SQLite projection → fsync/原子替换 `active.json` → program event/log。任一步骤在 active pointer 切换前失败，旧 revision 保持可读。
- Compiler 无法使用、响应 malformed、schema 不合法或 provider 抛错时，active revision 不变；Validator 从 source-index direct fallback，不将失败包装成“无约束”。
- `source_sections` 是 bounded source projection，不授予模型任意路径读取权限；敏感/生成/truth/runtime 文档仍不会进入 section。
- 单个 Markdown 文件在进入 Compiler 前按 section 规划为不重叠的临时 chunk；chunk 不进入 revision 或 manifest identity，按 `concurrency.wiki_compiler_workers` 并发执行后在父 Workset 边界原子聚合。未暴露上下文窗口的模型按 32K token 保守预算规划，超长 section 使用 fragment 引用而不是截断。
- 无结构化约束的说明文档仍可更新背景页面，但 `constraint_proposals=[]`、`constraints_created=0`，不会产生负面 Validator 证据。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_*.py tests/test_validator_project_knowledge.py tests/test_config_v2.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_agent_docs.py
python -m compileall -f -q zscope
```

结果：`119 passed`，`compileall` 成功；未运行实际 benchmark，未访问真实 LLM endpoint。

### 后续阶段边界

- 仍需补充正式 failpoint 故障注入、完整 revision/page/constraint schema 实例闭包 lint、真实 provider provenance（prompt/model/version）写入和 report-level Wiki selection telemetry。
- 仍需把 manifest delta/dirty closure 自动接入 Analyzer 的增量维护调度，并完成 replay/A-B 灰度评估；这些工作不改变本阶段已经固定的发布和 fallback 边界。

## 2026-08-26：阶段 12——增量 manifest、dirty closure、freshness 和 Wiki telemetry

### 阶段目标

将来源 manifest 变化接入维护调度，避免 source 变更时用无约束 skeleton 覆盖已有 active constraints；同时让 stale/ref 可解析性和 Wiki context 注入状态可以在 scan report 中回放。

### 实际文件

- `zscope/wiki/store/revision_store.py`
  - 每个 revision 保存 `source-manifest.json`，新增 `revision_manifest()` 读取 pinned manifest。
  - `apply_changeset()` 传播 changed/removed source 的 stale 状态，更新页面 manifest/compiler revision pin，并保持旧 revision 可 rollback。
- `zscope/core/analysis/analyzer.py`
  - preflight 读取 active revision 的旧 manifest，调用 `compare_manifests()` 和 `dirty_page_closure()`，仅把 dirty page/source delta 放入新的 IngestWorkset。
  - manifest mismatch 不再直接调用 `build_skeleton()`；确定性 Compiler 也通过同一 ChangeSet 发布边界刷新 refs/stale。`build_skeleton()` 只用于首次无 active revision 的初始化。
  - `compiler_enabled` 继续是显式 opt-in；无 client 时使用 deterministic background-only 维护，不访问真实 endpoint。
- `zscope/wiki/service.py`
  - active constraint 必须有当前 revision 中 `resolvable=true` 的 source refs；stale/conflicted/失效引用不会进入 Validator context。
  - 新增 `telemetry_snapshot()`，记录 resolution mode、selected IDs、fallback reason、knowledge tokens 和 incremental facts；背景 skeleton 不被计为 Wiki injection。
- `zscope/wiki/schema.py`、`zscope/wiki/lint.py`
  - revision lint 现在校验 revision/manifest/page/ref/constraint/edge 实例、引用闭包、页面 heading 顺序、compiler revision、manifest pin 和 active constraint 可解析性。
- `zscope/reporting/schema.py`
  - 将 Wiki selection/fallback/injection telemetry 复制到 `run_manifest.wiki_telemetry`；只保存计数、ID 频次和 reason，不复制页面正文、secret 或模型原始响应。
- `tests/test_wiki_maintenance.py`、`tests/test_wiki_service.py`
  - 覆盖 changed manifest 的 revision refresh/stale propagation，以及 active mode 在只有背景页时 `wiki_context_injected=false`。
- `docs/modules/wiki.md`
  - 更新 store、schema、lint、active constraint 和 fallback 边界。

### 固定行为和安全边界

- 旧 manifest 来自 active revision 的不可变副本；current manifest 只在新 revision 发布后写入，因此 delta 计算不会因预先覆盖 manifest 而退化为空。
- dirty closure 至少包含 project page，并沿 source→page→depends_on 闭包稳定排序；Workset 的 `source_sections` 只包含 accepted Markdown 的有界 section。
- source 变化/删除时，不能解析的旧 `DocumentRef` 标记 `resolvable=false`，其支持的 constraint 标记 `stale`；active Validator 只消费可解析 current refs。
- `wiki_context_injected=true` 的必要条件是 active effective mode、实际 Wiki resolution、正向 incremental facts 和非零 knowledge-context tokens；仅 selected page IDs 或背景摘要不足以证明注入。
- 所有 fallback 仍保留 `source_fallback`/`none` 语义，Wiki 维护失败不改变 deterministic Validator proof 或 candidate verdict。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_*.py tests/test_validator_project_knowledge.py tests/test_config_v2.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_agent_docs.py
python -m compileall -f -q zscope
```

结果：`121 passed`，`compileall` 成功；没有运行实际 benchmark，也没有访问真实 LLM endpoint。

### 后续阶段边界

- 仍需增加真实 failpoint（staging、SQLite projection、active pointer）故障注入和完整 event-log replay。
- 仍需把 telemetry 汇总与现有 report schema 的 `metadata`/`validation_performance` 固定字段做最终兼容审计，并完成不依赖 benchmark 的 replay/A-B harness；正式 benchmark 仍需用户明确授权后才能运行。

## 2026-08-26：阶段 13——发布故障注入、Validator contract 校验和 report attribution

### 阶段目标

补齐发布链路最后的故障边界和 Validator 输入校验：active pointer 失败时旧 revision 必须继续生效，新 revision 标记 failed；`project_knowledge` 在进入 evidence pack 前执行 schema 与跨字段校验；Wiki telemetry 进入 run manifest，但不携带页面正文或模型响应。

### 实际文件

- `zscope/wiki/store/revision_store.py`
  - 抽取 `_publish_active()` 原子指针切换与 `_mark_revision_failed()`；指针 failpoint 不会覆盖旧 active，失败 revision 写入 `lint.status=failed` 和失败 event。
- `zscope/wiki/service.py`、`zscope/core/validation/runner.py`
  - 新增 `validate_project_knowledge()`，检查 schema、mode 互斥、token 预算、selection ID 闭包及 active/documented constraint 条件；非法 context 被丢弃并保留原 evidence。
  - shadow 模式只保存 telemetry，不向 Validator 模型输入注入 project knowledge；active 模式才放入 evidence pack。
- `zscope/reporting/schema.py`
  - `run_manifest.wiki_telemetry` 固定记录 effective mode、resolution/fallback 计数、selected ID 频次、incremental facts、knowledge tokens 和 injection marker。
- `zscope/cli/wiki.py`
  - 增加 `rebuild-index`，只重建 deterministic source index 和 manifest，不发布 Wiki revision。
- `zscope/agents/validator_agent/AGENT.md`、`zscope/agents/wiki_compiler/AGENT.md`
  - 固定 Wiki context 的输入字段、authority/freshness/conflict 规则和 `source_sections` 不可信文本边界。
- `tests/test_wiki_revision_store.py`、`tests/test_wiki_service.py`
  - 增加 active pointer failpoint、context contract 和 telemetry marker 覆盖。

### 固定行为和安全边界

- 发布成功顺序是 SQLite projection commit 后才切 active pointer；切换失败时旧 pointer 不变，失败 revision 不可被 Validator 读取。
- `wiki_context_injected=true` 只在 active effective mode、实际 Wiki resolution、正向 structured incremental facts 与非零 context tokens 同时满足时成立；背景页、selected IDs 或 source fallback 不足以证明注入。
- `project_knowledge` 是 Validator 的辅助文档上下文；任何 schema/引用/预算错误都不会改变既有 deterministic proof、verdict 或 needs-review 语义。
- report 只保存 telemetry 摘要和 ID 计数，不保存完整 Markdown、secret、prompt、reasoning 或 provider 原始响应。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_*.py tests/test_validator_project_knowledge.py tests/test_config_v2.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_agent_docs.py tests/test_report_schema_v2.py tests/test_report_assembler.py
python -m compileall -f -q zscope scripts test tests
```

结果：`146 passed`，`compileall` 和 `git diff --check` 成功；没有运行实际 benchmark，也没有访问真实 LLM endpoint。

### 后续阶段边界

- 仍需完成独立的 replay/A-B harness、event-log rebuild verification 和正式灰度门禁；本阶段没有运行 benchmark，也不宣称 precision/recall 改善。

## 2026-08-26：阶段 14——只读控制面、维护调度和五模式 replay

### 阶段目标

完成计划阶段 8 中不依赖正式 benchmark 的控制面和 replay 工作：Web/MCP 只允许读取 Wiki status/query；Analyzer 在 `build_only`、manifest refresh 和 opt-in Compiler enrichment 下发布正确 revision，同时避免未变 manifest 的无意义 revision churn；使用固定候选回放五种 Wiki context 模式。

### 实际文件

- `zscope/wiki/control.py`
  - 新增共享 `wiki_status()` / `wiki_query()`；state dir 必须为 project-root 相对路径。
  - query 重新构建 deterministic source manifest/index，按当前配置的分类覆盖、文档资源上限和 context token 上限返回 `zscope.validator-project-knowledge.v1`。
- `zscope/mcp/provider.py`
  - 新增只读 `zscope.wiki.status` 与 `zscope.wiki.query`；调用者不能覆盖 project root/state dir，且不暴露 build/rollback。
- `zscope/web/services.py`、`zscope/web/server.py`
  - 新增 `WikiControlService`、`GET /api/wiki/status`、`GET /api/wiki/query`。
  - query 固定使用重复 `subject`、`fact_kind`、project-root 相对 `candidate_file` 和有界 `max_tokens`；未知参数 fail closed。
- `zscope/core/analysis/analyzer.py`
  - `build_only` 在 active manifest 改变时也通过 ChangeSet 发布 current revision，然后关闭 Wiki 资源并保持 Validator 不注入。
  - `auto_maintain + compiler_enabled` 可在 manifest 未变时把 deterministic revision enrichment 为 LLM revision；active 已由 `llm`/`mixed` Compiler 生成时不重复维护。
- `zscope/wiki/compiler/workset.py`、`zscope/wiki/compiler/changeset.py`
  - `allowed_subject_ids` 从 bounded source sections 的 project/module/symbol/path 身份生成；constraint/edge subject 越出 allowlist 时拒绝。
- `zscope/wiki/store/revision_store.py`、`zscope/wiki/lint.py`
  - `audit-events.jsonl` 使用 `zscope.wiki-event.v1` 的 `previous_event_digest -> event_digest` 哈希链，publish/rollback/failure 事件由程序追加，lint 检测断链。
- `scripts/replay_llm_wiki_context.py`
  - 固定回放 `control/direct/shadow/active/unavailable` 五种模式，只计算 context、selection 和 telemetry，不启动扫描、不访问 LLM、不运行 benchmark。
- `tests/test_wiki_control.py`、`tests/test_web_wiki_api.py`、`tests/test_mcp_policy.py`
  - 覆盖共享 control、只读接口、配置锁定路径、输入预算、ToolPolicy 和写操作不可见。
- `tests/test_wiki_maintenance.py`、`tests/test_wiki_context_replay.py`、`tests/test_wiki_revision_store.py`、`tests/test_wiki_compiler.py`
  - 覆盖 build-only manifest refresh、一次性 Compiler enrichment、revision churn 抑制、五模式 replay、event hash chain 和 subject allowlist。
- `docs/modules/wiki.md`、`docs/modules/interfaces-reporting.md`
  - 登记控制面入口、调度语义、哈希链和回归命令。

### 固定行为和安全边界

- Web/MCP 只能查询配置锁定的 project root 和 state dir；不能通过请求读取其他项目、传任意路径、构建或回滚 Wiki。
- status 不创建状态目录；query 只创建进程内 source index，并在结束时关闭 index/store。
- `build_only` 可以维护持久 Wiki，但永远不创建 `ProjectKnowledgeService` 给 Validator。
- manifest 变化始终允许 deterministic freshness revision；manifest 未变时只有显式 `auto_maintain + compiler_enabled` 且 active 尚未 LLM enrichment 才调用 Compiler。
- 五模式 replay 的输出显式记录 `benchmark_executed=false`、`llm_called=false`；它只能证明结构、selection、fallback 和 telemetry，不证明 precision/recall 改善。
- 正式 benchmark、A/B 质量门禁和分桶灰度仍未执行，继续保持计划完成标准未勾选。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_control.py tests/test_web_wiki_api.py tests/test_mcp_policy.py tests/test_web_rules_api.py tests/test_wiki_service.py
python -m pytest -q tests/test_wiki_maintenance.py tests/test_wiki_control.py tests/test_web_wiki_api.py tests/test_mcp_policy.py
```

结果分别为 `29 passed` 和 `28 passed`。没有运行实际 benchmark，没有访问真实 LLM endpoint。

完整非 benchmark 回归补充结果：

```text
python -m pytest -q tests/test_wiki_*.py tests/test_validator_project_knowledge.py tests/test_config_v2.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_report_schema_v2.py tests/test_report_assembler.py tests/test_mcp_policy.py tests/test_web_wiki_api.py tests/test_web_rules_api.py
python -m compileall -f -q zscope scripts test tests
git diff --check
```

结果为 `171 passed`，`compileall` 和 `git diff --check` 成功。单独执行 `tests/test_agent_docs.py` 为 `5 passed, 1 failed`，失败原因是当前工作区中用户侧 tracked benchmark 文件 `test/range/benchmark/check_entry_coverage.py`（连同同目录其他 benchmark 文件）处于删除状态，而 `docs/modules/benchmarking.md` 仍登记该路径。该异常与 LLM Wiki 变更无关；遵守不回退用户手工修改和不运行 benchmark 的约束，本阶段未恢复、重建或改写这些文件。

### 后续阶段边界

- 运行完整非 benchmark Wiki/Validator/Web/MCP/report 回归、`compileall` 和 `git diff --check`。
- 审计 Compiler 多页面中文 Markdown、wikilink 和 event-log rebuild verification 的完成性；缺失部分继续按计划实施。
- 正式 precision/recall、误报下降和分桶灰度门禁必须等待用户允许实际 benchmark 后验证。

## 2026-08-26：阶段 15——多页面中文 Wiki、index schema 和事件回放重建

### 阶段目标

关闭计划完成标准中尚未证明的“Compiler 维护多页面中文 Markdown 和 wikilink”，并使程序拥有的 `index.md`、`audit-events.jsonl` 与 `log.md` 成为可校验、可重建的固定投影。该阶段只使用 fake Compiler 和本地 fixture。

### 实际文件

- `zscope/wiki/page_format.py`
  - 固定页面六个中文 H2 和 index 六个中文 H2。
  - 定义 `[[page_id|中文标题]]` wikilink 解析、中文正文检查、frontmatter 后 body 提取和程序 index link 投影。
- `zscope/wiki/compiler/changeset.py`
  - upsert 页面必须严格满足 heading 顺序、中文正文、source ref 展示和 wikilink allowlist。
  - Constraint-only ChangeSet 不再包含页面变更；显式配置 `max_constraints` 时，Compiler proposal 数量和发布后的 revision constraints 总数越界都必须 fail closed，默认 `null` 不施加持久化数量预算。Validator 选择匹配约束和 direct source 摘录时均由程序最多保留 20 条，剩余条数分别写入 `omitted_constraint_count` 和 `omitted_source_excerpt_count`，不依赖 schema 数组上限。
- `zscope/wiki/compiler/llm_compiler.py`、`zscope/agents/wiki_compiler/AGENT.md`
  - Compiler prompt/Agent contract 固定中文页面结构、wikilink 语法和来源索引要求。
  - Compiler 通过终态工具 `emit_wiki_changeset` 提交结果，初次提交失败后最多进行两次修复重试；revision provenance 固定记录 `prompt_version=zscope.wiki-compiler.prompt.v3`、provider identity 和模型名。
- `zscope/wiki/store/revision_store.py`
  - skeleton 与 ChangeSet revision 的 `index.md` 均由程序生成，带 `zscope.wiki-index.v1` frontmatter、body digest、固定六节和只指向 `pages/<slug>.md` 的同 revision 链接。
  - `log.md` 不再追加不可重建的自由文本，而是从 `audit-events.jsonl` 原子重建。
- `zscope/wiki/events.py`
  - 重放 event schema、连续 event ID、previous digest 和 event digest；重建最后成功 publish/rollback 指向的 active revision，并收集 failed revision/quarantined workset。
  - 从同一 replay 结果生成固定 Markdown log 投影。
- `zscope/wiki/lint.py`
  - 校验 event replay active 与 `active.json` 一致、`log.md` 字节等价、index schema/heading/digest/link、页面正文/digest/磁盘投影和 wikilink target。
- `tests/test_wiki_compiler.py`、`tests/test_wiki_llm_compiler.py`
  - 覆盖多页面中文 Markdown、互链要求、越权 wikilink 拒绝和 prompt/model provenance。
- `tests/test_wiki_revision_store.py`、`tests/test_wiki_lint.py`
  - 覆盖两个中文页面经 Compiler 发布、index schema、event replay、log 重建和投影篡改检测。
- `docs/modules/wiki.md`、[历史 Wiki 接入计划](../design-plans/llm_wiki_implementation_plan.md)
  - 登记页面/index/event 契约；将多页面 Wiki 和五模式结构 replay 标记完成，真实 A/B/benchmark 继续未完成。

### 固定行为和安全边界

- 模型只能提交页面正文建议；page identity、frontmatter、revision、index、event、log 和 active pointer 始终由程序拥有。
- 多页面输出不是简单接受数组：每个页面必须是有中文正文的固定六节 Markdown，并通过同 ChangeSet wikilink 形成显式关系。
- `source_refs_used` 必须实际出现在页面“来源索引”，不能只藏在结构化字段中；Markdown 中出现的 docref 也必须属于 workset allowlist。
- index 不接受模型正文或链接；所有条目从同 revision page projection 生成。
- event replay 只能根据 schema-valid hash chain 改写 `log.md`；断链、篡改或 active transition 不一致由 lint 拒绝。
- 本阶段没有访问真实 LLM、没有启动扫描、没有运行实际 benchmark，不据此宣称质量指标改善。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_compiler.py tests/test_wiki_llm_compiler.py tests/test_wiki_revision_store.py tests/test_wiki_lint.py
python -m pytest -q tests/test_wiki_*.py tests/test_validator_project_knowledge.py
python -m pytest -q tests/test_wiki_*.py tests/test_validator_project_knowledge.py tests/test_config_v2.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_report_schema_v2.py tests/test_report_assembler.py tests/test_mcp_policy.py tests/test_web_wiki_api.py tests/test_web_rules_api.py
python -m compileall -f -q zscope scripts test tests
git diff --check
```

测试结果分别为 `15 passed`、`46 passed` 和 `174 passed`；`compileall` 与 `git diff --check` 均通过。另针对 Validator Wiki 输入的物化 Schema、registry resolver、运行时实例校验和注入边界复核：

```text
python -m pytest -q tests/test_wiki_schema_contract.py tests/test_wiki_schema_resolver.py tests/test_validator_project_knowledge.py tests/test_wiki_service.py
```

结果为 `9 passed`。`zscope.validator-project-knowledge.v1` 继续作为 `ValidatorEvidenceSlice v3.project_knowledge` 的唯一输入契约，不新增并行或隐式格式。

### 后续阶段边界

- 对照计划逐项审计剩余配置 exclusion、active revision pin/cache、控制面和安全测试证据。
- 真实 A/B、precision/recall、误报下降和正式 benchmark 仍等待用户明确授权。

## 2026-08-26：阶段 16——配置 exclusion、扫描级 revision pin 和 Validator cache 闭包

### 阶段目标

修复完成度审计发现的三个运行时缺口：`project.wiki.documents.exclude` 必须真实进入 Analyzer、Web、MCP 的 manifest/source-index；一次扫描期间的 Validator worker 必须消费同一 Wiki revision 快照；Validator cache 必须把实际注入的 project knowledge identity 纳入 key。同步补充 prompt-injection 越权回归，证明文档正文始终作为不可信数据处理。

### 实施内容

- `zscope/wiki/classification.py`
  - 分类 override 固定为 `exclude/explanatory/generated` 三组；`exclude` 使用项目相对 glob，命中后生成 `classification=unknown`、`reason=user_excluded_path` 的 fail-closed descriptor。
  - mandatory runtime/truth、生成 provenance 和敏感内容的判断优先于用户 exclusion，用户配置不能掩盖这些更强分类。
  - `exclude` 参与 `override_digest`，因此配置变化会改变 source manifest 和后续 revision/cache identity。
- `zscope/config/v2.py`
  - Wiki 文档 glob 在配置加载时拒绝绝对路径、Windows drive path 和 `..`。
  - 同一个 glob 不能同时声明为 explanatory 和 generated；exclusion 与分类规则重叠时由 exclusion 作为更严格的 corpus filter 生效。
- `zscope/core/analysis/analyzer.py`、`zscope/wiki/control.py`、`zscope/web/services.py`、`zscope/mcp/provider.py`
  - Analyzer、只读 control、Web 和 MCP 使用同一组 `exclude/explanatory/generated` override 构建 manifest 和 source index。
  - SourceIndex 分类事件使用与 manifest 相同的 override，避免 accepted/excluded projection 与审计事件发生语义漂移。
- `zscope/wiki/service.py`、`zscope/wiki/source_index.py`
  - `ProjectKnowledgeService` 构造时一次性快照 active revision ID、compiler kind、constraints、document refs 和 pages；后续候选查询不再读取 active pointer 或 Wiki SQLite。
  - active pointer 即使被其他维护进程切换，本扫描仍返回 pinned revision；下一次扫描创建新 service 时才观察新 revision。
  - SourceIndex 明确记录空/非空 memory projection 已加载，Validator worker 不会因空结果重新跨线程读取 SQLite。
  - Wiki selection telemetry 使用锁保护，多个 Validator worker 并发累计不会丢计数。
- `zscope/core/validation/runner.py`
  - active `project_knowledge` 的 cache identity 固定包含 schema version、resolution mode、Wiki revision、source manifest digest、context digest 和 ranking version。
  - validation cluster 相同但 project knowledge context 不同的候选不得复用 verdict；off 或 shadow 未注入 context 时保留既有兼容 key。
- `docs/modules/wiki.md`
  - 固定 exclusion 全链路、scan-level immutable revision snapshot 和 cache identity 不变量。

### 新增和更新测试

- `tests/test_wiki_ingestion.py`：说明性文档 exclusion、manifest identity、mandatory/sensitive 不可被掩盖。
- `tests/test_wiki_source_index.py`：manifest override 与 classification event、documents projection 一致。
- `tests/test_wiki_maintenance.py`：Analyzer 将 exclusion 同时传入 manifest 和 source index。
- `tests/test_web_wiki_api.py`、`tests/test_mcp_policy.py`：只读控制面使用配置中的 exclusion，调用者不能另行指定 corpus。
- `tests/test_wiki_service.py`：active pointer 中途切换后仍固定旧 revision；四线程并发查询不访问跨线程 SQLite，telemetry 计数完整。
- `tests/test_validation_runner.py`：同一 cluster 的不同 context digest 产生不同 cache key；无 Wiki 输入保持兼容分支。
- `tests/test_wiki_compiler.py`：正文中的 prompt-injection 文本可以进入 bounded workset，但模型若据此输出 verdict、越权 page 或非法路径，ChangeSet 校验失败并降级为 `extraction_failed`，不发布任何内容。
- `tests/test_config_v2.py`：document exclusion 保存、非相对 glob 和冲突分类 glob 拒绝。

### 固定行为和安全边界

- `documents.exclude` 只增加排除项，不得删除 mandatory exclusion；被排除正文不进入 Wiki、Compiler 或 direct-source query。
- exclusion 配置、manifest、source-index classification event、Web/MCP query 必须使用同一 override identity。
- `ProjectKnowledgeService` 是 scan-scoped immutable reader；维护进程发布或 rollback 不能使一次扫描混用两个 revision。
- project knowledge context 的任何 schema、mode、revision、manifest、selection 或 digest 变化都会使 active Validator cache 失效。
- 文档中的 prompt、命令、verdict、路径和工具请求都只是文本；程序只接受 workset allowlist 和固定 ChangeSet Schema 内的对象。
- 本阶段没有访问真实 LLM endpoint、没有启动项目扫描、没有运行实际 benchmark，也不据此声明 precision/recall 或误报指标改善。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_ingestion.py tests/test_wiki_source_index.py tests/test_wiki_service.py tests/test_wiki_compiler.py tests/test_wiki_maintenance.py tests/test_validation_runner.py tests/test_config_v2.py tests/test_web_wiki_api.py tests/test_mcp_policy.py
python -m pytest -q tests/test_wiki_*.py tests/test_validator_project_knowledge.py tests/test_config_v2.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_report_schema_v2.py tests/test_report_assembler.py tests/test_mcp_policy.py tests/test_web_wiki_api.py tests/test_web_rules_api.py
python -m pytest -q tests/test_agent_docs.py
python -m compileall -f -q zscope scripts test tests
git diff --check
```

结果分别为 `130 passed`、`186 passed`、`6 passed`；`compileall` 与 `git diff --check` 均通过。额外运行的 Black check 显示 11 个既有大文件会产生全文件格式化，因此未执行批量重写，避免引入与本阶段无关的格式 churn。

### 后续阶段边界

- 继续审计 read-only control 的异常结果长度、损坏 active/revision 文件和敏感错误信息是否全部 bounded/fail closed。
- 对照计划补充 revision/page/index/event 的恶意内容和投影篡改矩阵，避免只依赖单一路径测试。
- 真实 A/B、precision/recall、误报下降和正式 benchmark 仍等待用户明确授权。

## 2026-08-26：阶段 17——只读控制面状态文件加固和损坏 Wiki 降级

### 阶段目标

闭合 read-only control 的损坏状态、路径越权、无界状态输出和内部异常泄漏边界。`active.json`、revision metadata 或 Wiki SQLite 不可信/损坏时，status 必须返回固定错误码，query/Analyzer 必须优先保留 direct-source fallback，而不是尝试路径拼接、透传异常或完全丢失项目文档上下文。

### 实施内容

- `zscope/wiki/store/revision_store.py`
  - active pointer 固定最大 `64 KiB`，revision metadata 固定最大 `1 MiB`；两者拒绝 symlink、非法 UTF-8、非 JSON object 和不支持的 schema version。
  - revision ID 固定匹配 `^wikirev_[a-z0-9_:-]+$`，source manifest digest 固定匹配 SHA-256 格式。
  - `active_revision()`、`revision_manifest()`、`build_skeleton()`、ChangeSet publication、`_publish_active()` 和 `rollback()` 在任何路径拼接或文件写入前验证 revision ID，阻断 `../` traversal。
  - 新增只读 `read_active_pointer()`、`read_revision_metadata()` 和 `WikiStore.revision_metadata()`，control/service 复用同一校验实现。
- `zscope/wiki/control.py`
  - `wiki_status` 返回固定 `zscope.wiki-status.v1` 投影，只包含相对 `state_dir`、active identity、bounded revision/compiler/lint metadata 和固定错误对象；不返回 project root、state root、页面正文或原始异常。
  - active pointer 无效、revision 无效和 manifest 不一致分别返回 `invalid_active_pointer`、`invalid_revision`、`stale_revision`。
  - query 在 manifest discovery 前校验 subject 数量/长度/控制字符、fact kind、candidate 相对路径和 token 范围。
  - active/revision/DB 损坏时关闭不可用 WikiStore，以 `invalid_revision` 降级到已构建的 source index；无 active、stale revision、deterministic compiler 和 Wiki no-hit 使用各自固定 fallback reason。
- `zscope/wiki/service.py`
  - scan-level revision snapshot 的 compiler metadata 改为通过 bounded revision reader 获取，不再直接拼接 revision 文件路径。
- `zscope/core/analysis/analyzer.py`
  - source manifest/index 已成功建立后，即使 Wiki preflight、active pointer、DB、maintenance 或 snapshot 初始化失败，active/shadow 模式仍返回仅含 source index 的 `ProjectKnowledgeService`。
  - `build_only` 仍不向 Validator 暴露 context；source index 自身构建失败时仍 fail closed 为无 Wiki service。
- `zscope/web/server.py`、`zscope/web/services.py`
  - Web query 最多解析 64 个字段。
  - Wiki status/query 不再向 HTTP 响应透传内部异常；仅白名单参数错误保留最多 500 字符，其余返回固定 unavailable 文本。
- `zscope/mcp/provider.py`
  - MCP 在调用 control 前拒绝控制字符、绝对/drive/`..` candidate path 和无界 fact kind。
  - 内部 control/config/filesystem 异常统一转换为固定 unavailable 文本，再执行既有 MCP result hard limit。

### 新增和更新测试

- `tests/test_wiki_control.py`
  - status 固定 schema、无绝对路径、bounded projection。
  - traversal pointer 不读取 root 外伪造 revision，也不泄漏其中内容。
  - 损坏 active pointer 时 query 返回 README direct-source excerpt 和 `invalid_revision`。
  - 非法 candidate path 在 manifest discovery 前拒绝。
- `tests/test_wiki_revision_store.py`
  - build/rollback 在路径访问前拒绝不可信 revision ID。
- `tests/test_wiki_maintenance.py`
  - Analyzer 面对损坏 pointer 仍建立 direct-source-only service。
- `tests/test_web_wiki_api.py`、`tests/test_mcp_policy.py`
  - HTTP/MCP 不暴露包含本机路径或 secret 的内部异常；MCP 非法路径不会调用 control。

### 固定行为和安全边界

- `active.json` 是程序拥有但仍按不可信磁盘输入处理；其 revision ID 不能成为任意路径读取或写入能力。
- status 是 bounded metadata projection，不是 state directory browser；页面、constraints、完整 revision JSON、绝对路径和异常堆栈不进入响应。
- Wiki 损坏不能伪装成“无约束”，也不能使已成功建立的 direct source index 失效；fallback reason 必须明确是 invalid/stale/no-active/no-match/compiler-unavailable。
- Web/MCP 参数验证发生在项目文档扫描前，非法请求不能触发全项目 discovery。
- 本阶段没有访问真实 LLM endpoint、没有启动项目扫描、没有运行实际 benchmark，也不声明质量门禁改善。

### 验证命令和结果

首次针对性测试结果为 `46 passed, 2 failed`；两个失败均为测试 fixture 已存在 `.zscope_knowledge/wiki` 时重复 `mkdir`，没有进入产品断言。按仓库指令只把两处测试准备改为 `exist_ok=True`，未在失败后继续修改产品代码。

```text
python -m pytest -q tests/test_wiki_control.py tests/test_wiki_revision_store.py tests/test_wiki_maintenance.py tests/test_wiki_service.py tests/test_web_wiki_api.py tests/test_mcp_policy.py
python -m pytest -q tests/test_wiki_*.py tests/test_validator_project_knowledge.py tests/test_config_v2.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_report_schema_v2.py tests/test_report_assembler.py tests/test_mcp_policy.py tests/test_web_wiki_api.py tests/test_web_rules_api.py
python -m pytest -q tests/test_agent_docs.py
python -m compileall -f -q zscope scripts test tests
git diff --check
```

修正测试准备后结果分别为 `48 passed`、`195 passed`、`6 passed`；`compileall` 与 `git diff --check` 均通过。

### 后续阶段边界

- 因本阶段曾出现测试失败，遵守用户指令，失败后只修改测试和本实施记录；新增的状态文件安全细节尚未同步扩写到模块文档，留待下一阶段在测试开始前统一处理。
- 下一阶段审计 page/index/event 中超长字段、Unicode/control character、symlink 和 disk/SQLite projection 不一致的完整恶意矩阵。
- 真实 A/B、precision/recall、误报下降和正式 benchmark 仍等待用户明确授权。

## 2026-08-26：阶段 18——page/index/event 恶意投影矩阵和运行时完整 lint

### 阶段目标

完成阶段 17 延后的模块文档同步，并把 page、index、source manifest、log、audit event、SQLite projection 和 Wiki state directory 统一纳入 bounded/untrusted-input 模型。active/shadow 在消费 Wiki revision 前必须验证磁盘与 SQLite 闭包；任何超限、控制字符、symlink、路径越权、哈希链损坏或投影不一致都丢弃 Wiki snapshot，同时保留 direct-source fallback。

### 实施内容

- `zscope/wiki/store/revision_store.py`
  - 新增 `resolve_project_state_root()`：state directory 必须是 project-root 相对路径，现存路径组件不得是 symlink。
  - 新增 `resolve_state_child()`：revision、manifest、page 和 index 等 state-relative 路径逐组件拒绝 absolute、`..` 和 symlink，解析结果必须留在 state root。
  - source manifest 固定最大 `64 MiB`，拒绝 symlink、非法 UTF-8 和非 JSON object。
  - active pointer 只允许固定四个字段；timestamp 最长 80 字符且不含控制字符。
  - revision metadata 使用 `zscope.wiki-revision.v1` 做完整 Schema 校验，不只检查 revision ID 和 digest。
  - append audit event 前先完整 replay 现有链；损坏、超限或 symlink 链不能被下一次 append 当作空链重新开始。`project_id` 固定为 1～160 字符且不含控制字符。
- `zscope/wiki/events.py`
  - audit JSONL 使用二进制逐行读取，不再一次性 `read_text()`。
  - 固定文件上限 `64 MiB`、单行上限 `64 KiB`、事件数量上限 `100000`。
  - UTF-8、Schema、event ID、previous digest、event digest、transition revision 和 rendered text 控制字符分别产生稳定 reason code。
  - audit file symlink、不可读或超限时返回失败 replay，不读取目标内容。
- `zscope/wiki/lint.py`
  - 显式 revision ID 在路径访问前校验；revision metadata 通过 bounded store reader 获取。
  - pages、refs、constraints、edges 每类最多读取 `10000` 项；JSON blob 最大 `1 MiB`，page Markdown 最大 `2 MiB`，index 最大 `4 MiB`，log 最大 `64 MiB`。
  - lint error 输出最多 `512` 项，超出时追加 `lint_error_limit_exceeded`，避免损坏投影制造无界诊断。
  - frontmatter、constraint/ref/edge JSON 非 object、超长或 malformed 均形成固定错误，不再使 lint 抛出未处理异常。
  - DB canonical slug 必须与 frontmatter 相同并满足固定 slug pattern；page/index/log 文件路径拒绝 symlink 和 root 外解析。
  - page/index/log 使用 bounded UTF-8 reader，并继续验证 body digest、wikilink/ref closure、disk/SQLite 字节投影和 event-derived log。
- `zscope/wiki/service.py`
  - `ProjectKnowledgeService` pin revision 前执行完整 `lint_revision()`；lint 失败直接拒绝 Wiki snapshot。
  - runtime snapshot 再施加 `10000` row、`1 MiB` JSON 和 `2 MiB` Markdown 上限，避免 lint 后并发篡改或异常 SQLite projection 进入 Validator。
- `zscope/wiki/page_format.py`
  - Wiki Markdown 拒绝 NUL 和其他非换行/制表控制字符。
  - index label 删除控制字符、折叠换行并转义反斜杠和方括号；不符合 canonical slug pattern 的页面不进入 index link。
- `zscope/wiki/source_manifest.py`
  - `project_id` 固定为 1～160 字符且不含控制字符，使 source/page/index/revision/event identity 使用同一边界。
- `zscope/core/analysis/analyzer.py`、`zscope/cli/wiki.py`、`zscope/wiki/control.py`
  - Analyzer、CLI 和 control 复用 state-root resolver。
  - state directory symlink 被拒绝时，active/shadow Analyzer 使用内存 SourceIndex 保留 direct-source context；`build_only` 不产生 Validator service，也不向 symlink 目标写入文件。
- Schema 和文档
  - `zscope.wiki-page-frontmatter.v1`、`zscope.wiki-index.v1`、`zscope.wiki-event.v1`、`zscope.wiki-revision.v1` 的 `project_id.maxLength` 固定为 160；event `occurred_at.maxLength` 固定为 80。
  - 同步计划 JSON 代码块、物化 Schema、`docs/modules/wiki.md` 和 `docs/modules/interfaces-reporting.md`。

### 新增和更新测试

- `tests/test_wiki_lint.py`
  - traversal revision ID 在路径访问前失败。
  - symlink index 和 DB 中 `../../` canonical slug 被拒绝，不读取外部投影。
  - event 中控制字符即使重算 digest 仍无效；损坏链不能 append；超长 JSONL 行固定失败。
- `tests/test_wiki_control.py`
  - symlink state directory 被拒绝且目标目录不产生文件。
  - page 文件被篡改时 query 丢弃 Wiki 并从 README direct fallback。
  - SQLite object 数量超过 runtime lint 上限时同样降级。
- `tests/test_wiki_maintenance.py`
  - Analyzer 遇到 symlink state directory 时构建 `:memory:` SourceIndex，继续返回候选相关原文，且不写 symlink 目标。
- `tests/test_wiki_compiler.py`
  - Markdown 控制字符拒绝；index title escaping 和非法 slug 过滤。
- `tests/test_wiki_ingestion.py`
  - 超长或含控制字符的 project ID 在 manifest 构建前拒绝。
- `tests/test_wiki_schema_contract.py`
  - 继续验证计划代码块、物化 Schema 和 registry 字典等价，防止新增长度约束漂移。

### 固定行为和安全边界

- Wiki state、revision 和 page 目录的任何 symlink 都不能成为 root 外读写通道。
- audit log 损坏时只能失败和人工/程序重建，不能静默重置 chain head。
- revision metadata 中的 `lint.status=passed` 不是充分条件；Validator 消费前仍需重新执行 bounded disk/SQLite/event lint。
- runtime lint 失败表示 Wiki unavailable，不表示源文档没有约束；source index 可用时必须带具体 fallback reason 返回原文。
- 页面 Markdown 和 index label 中的 prompt、控制字符或 Markdown link 语法不能改变 index target、event log 或 Validator authority。
- 本阶段没有访问真实 LLM endpoint、没有启动项目扫描、没有运行实际 benchmark，也不声明 precision/recall、误报率或性能门禁结果。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_schema_contract.py tests/test_wiki_schema_resolver.py tests/test_wiki_lint.py tests/test_wiki_control.py tests/test_wiki_revision_store.py tests/test_wiki_service.py tests/test_wiki_maintenance.py tests/test_wiki_compiler.py tests/test_wiki_ingestion.py tests/test_wiki_cli.py tests/test_web_wiki_api.py tests/test_mcp_policy.py
python -m pytest -q tests/test_wiki_*.py tests/test_validator_project_knowledge.py tests/test_config_v2.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_report_schema_v2.py tests/test_report_assembler.py tests/test_mcp_policy.py tests/test_web_wiki_api.py tests/test_web_rules_api.py tests/test_agent_docs.py
python -m compileall -f -q zscope scripts test tests
git diff --check
```

结果分别为 `80 passed`、`211 passed`；`compileall` 与 `git diff --check` 均通过。本阶段测试首轮即通过，没有在测试失败后修改产品代码。

### 后续阶段边界

- 审计 CLI `status/query/discover/build/rebuild-index` 是否全部复用 public config 中的 documents override 和资源上限；当前 standalone CLI 仍主要使用固定默认值。
- 审计 rollback/rebuild 的 read-only/write control 授权、writer lock 和并发发布行为，补充两个进程争用与 crash-recovery 的离线故障矩阵。
- 真实 A/B、precision/recall、误报下降和正式 benchmark 仍等待用户明确授权。

## 2026-08-26：阶段 19——CLI 配置闭包、只读控制面和 writer lock（部分完成）

### 阶段目标

使 standalone `zscope-wiki` 与 Analyzer、Web、MCP 使用同一 public config 闭包；将 `status`、`lint`、`query` 固定为无状态写入的只读操作；将 `discover`、`build`、`rebuild-index`、`rollback` 固定为同一项目级 writer lock 下的写操作；同时加固 crash recovery 和 source manifest 原子替换。

### 已实施内容

- `zscope/cli/wiki.py`
  - 增加 `--config/-c`，保留 `--root`；两者同时提供但解析出的 root 不一致时 fail closed。
  - config 模式固定读取 `project.root`、`project.id`、`project.wiki.state_dir`、三组 document override、discovery 三项资源上限和可选 `max_constraints`；该字段默认 `null`，用于限制 Compiler proposal 数量及项目 Wiki 数据库每个 revision 保存的 constraints 总数。`project_knowledge` 的 Wiki/fallback 共享 4096 token 上限，单次调用可收紧但不可超过该值。
  - `query` 复用 `wiki_query()` 的 Wiki-first/direct-source fallback 路径；`status` 复用 bounded `wiki_status()`；`lint` 使用 read-only `WikiStore`。
  - 四个写命令统一持有 `<state_dir>/locks/compiler.lock`；rollback 测试在实际调用 `WikiStore.rollback()` 时校验 owner JSON 已存在。
- `zscope/wiki/store/revision_store.py`、`zscope/wiki/control.py`
  - `WikiStore(read_only=True)` 不创建 state/revisions/staging/quarantine，不建表，要求已有完整投影，并使用 SQLite URI `mode=ro`。
  - control query 打开 active Wiki 时使用 read-only store；无状态或损坏状态继续使用内存 source index/fallback，不创建 Wiki DB。
- `zscope/wiki/maintenance.py`
  - writer lock owner 固定为 `zscope.wiki-writer-lock.v1` JSON：`schema_version`、`pid`、`token`、`created_at`。
  - 只在 owner JSON 完整且 PID 已死亡时恢复 stale lock；malformed、超限、不可读和 symlink lock fail closed。
  - release 前重新读取 owner，只在 PID/token 仍属于当前持有者时删除；后来者替换 owner 后不会被旧持有者误删。
- `zscope/wiki/source_manifest.py`
  - manifest 改为同目录临时文件、flush、`fsync`、`os.replace()`；replace 故障保留旧 manifest，并清理临时文件。

### 新增和更新测试

- `tests/test_wiki_cli.py`
  - config 的 project ID、custom state dir、exclude/explanatory/generated override、单文件资源上限和 query token 上限真实生效。
  - root/config 冲突在写状态前失败。
  - status/lint/query 面对不存在的 state 不创建目录或 DB。
  - rollback 在 writer lock owner JSON 存在期间执行。
- `tests/test_wiki_maintenance.py`
  - 两个 writer 争用、dead-PID stale recovery、malformed owner、symlink lock 和 owner token 替换后不误删。
- `tests/test_wiki_ingestion.py`
  - source manifest 原子替换 failpoint 保留旧文件且清理临时文件。

### 测试失败处理和未闭合项

首次针对性测试为 `52 passed, 1 failed`：测试错误地假设 `generated` override 能覆盖已由 `docs/` 路径契约确定的 explanatory 分类。按第 5.5 节顺序，测试改用尚未分类的根目录文档验证 generated override，没有修改产品代码。

第二次针对性测试仍为 `52 passed, 1 failed`：fixture 自带 `.zscope_knowledge` 示例目录，使“默认 state 不存在”断言无效。只在测试副本中删除该目录，没有修改产品代码。修正后针对性结果为 `53 passed`。

继续审计发现：当 `project.wiki.state_dir` 使用 `var/wiki` 一类普通自定义路径时，Markdown discovery 尚未按解析后的动态 state path 剪枝；第二次 `discover` 会把前一次产生的 lock/manifest/state 投影计入 root/manifest identity。该缺口已由 `test_wiki_cli_custom_state_dir_does_not_change_its_own_manifest` 固定为 `strict xfail`。由于本阶段已经出现 pytest 失败，遵守用户指令，没有继续修改产品代码；因此阶段 19 不能标记为完全完成。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_cli.py tests/test_wiki_maintenance.py tests/test_wiki_ingestion.py tests/test_wiki_revision_store.py tests/test_wiki_control.py tests/test_wiki_schema_contract.py tests/test_wiki_schema_resolver.py
python -m pytest -q tests/test_wiki_*.py tests/test_validator_project_knowledge.py tests/test_config_v2.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_report_schema_v2.py tests/test_report_assembler.py tests/test_mcp_policy.py tests/test_web_wiki_api.py tests/test_web_rules_api.py tests/test_agent_docs.py
python -m compileall -f -q zscope scripts test tests
git diff --check
```

最终结果分别为 `53 passed, 1 xfailed` 和 `221 passed, 1 xfailed`；`compileall` 与 `git diff --check` 均通过。没有访问真实 LLM endpoint、没有启动项目扫描、没有运行实际 benchmark。

### 后续阶段边界

- 在新的实施阶段中，将解析后的 `project.wiki.state_dir` 作为 mandatory prune root 传入 discovery/manifest/source-index，并移除对应 strict xfail。
- 完成动态 state pruning 后，重新验证 custom state 下连续 discover/build/query 的 manifest digest 稳定性和 Wiki revision freshness。
- 真实 A/B、precision/recall、误报下降和正式 benchmark 仍等待用户明确授权。

## 2026-08-26：阶段 20——动态 Wiki state directory discovery 剪枝

### 阶段目标

闭合阶段 19 遗留的 custom state directory 自包含问题。无论 `project.wiki.state_dir` 是默认 `.zscope_knowledge/wiki` 还是 `var/wiki` 一类普通 project-relative 路径，CLI、Analyzer、Web/MCP control 的下一次文档发现都不得把该 state tree 的 lock、manifest、SQLite projection、revision、page、index 或 event 文件重新纳入语料、source index 或 manifest digest。

### 实施内容

- `zscope/wiki/discovery.py`
  - `discover_markdown()` 新增 `prune_paths`；接受单一路径或最多 64 条路径，单条最长 512 字符、最多 32 个组件。
  - 路径必须是无控制字符、无 drive、非绝对、无 `.`/`..` 的 project-relative 目录前缀；空值、POSIX absolute、Windows drive/absolute 和 traversal 均 fail closed。
  - 目录遍历在读取 entry 前按相对路径组件匹配；命中 prune root 或其任何子树直接跳过，不产生 source、issue、unsupported-extension 统计或 digest 输入。动态 root 不需要在文件系统中预先存在，且不会解析或跟随 symlink。
- `zscope/wiki/source_manifest.py`、`zscope/wiki/source_index.py`
  - manifest 构建和 SourceIndex 的直接 discovery 路径均透传同一 `prune_paths`。SourceIndex 在没有 manifest 时先以同一剪枝规则建 manifest，随后以同一规则重扫，避免 manifest/source index 出现集合不一致。
- `zscope/cli/wiki.py`、`zscope/wiki/control.py`、`zscope/core/analysis/analyzer.py`
  - 复用已验证的 state root，并将其相对 `project.root` 的路径同时传入 manifest 和 SourceIndex。
  - CLI 的 `discover`、`build`、`rebuild-index`，control 的 `wiki_query()` 和 Analyzer 的 scan-pinned service 使用完全相同的动态剪枝；state root 因 symlink 被拒绝时，Analyzer 原有的内存 direct-source fallback 保持不变。
- `tests/test_wiki_cli.py`、`tests/test_wiki_ingestion.py`、`tests/test_wiki_source_index.py`、`tests/test_wiki_control.py`、`tests/test_wiki_maintenance.py`
  - 移除 custom state dir 的 strict `xfail`；连续两次 `zscope-wiki --config ... discover` 现在必须得到相同 manifest digest。
  - 新增动态 `var/wiki` 下 Markdown 不进入 discovery/manifest 的断言，以及 unsafe prune root 的参数化拒绝测试。
- `docs/modules/wiki.md`
  - 明确动态 `project.wiki.state_dir` 是 discovery/manifest/source-index 的受验证 prune root，不依赖默认目录名。

### 固定行为和安全边界

- 状态目录剪枝是路径前缀规则，不是文件名黑名单；`var/wiki` 不会因名称不在 `MANDATORY_PRUNE_DIRS` 而泄漏进语料。
- 动态 state tree 不出现在 accepted、excluded descriptor、unsupported extension 计数或 project root digest 中，因此一次 Wiki 写入不会令下一轮产生虚假的 source delta 或 stale revision。
- 此机制只排除运行时 state output；说明性原始 Markdown 仍由既有 deterministic 分类和用户 document override 决定，不把状态文件伪装成 generated-artifact descriptor。
- 本阶段没有访问真实 LLM endpoint、没有启动项目扫描、没有运行实际 benchmark。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_ingestion.py tests/test_wiki_source_index.py tests/test_wiki_cli.py tests/test_wiki_control.py tests/test_wiki_maintenance.py
python -m pytest -q tests/test_wiki_*.py tests/test_validator_project_knowledge.py tests/test_config_v2.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_report_schema_v2.py tests/test_report_assembler.py tests/test_mcp_policy.py tests/test_web_wiki_api.py tests/test_web_rules_api.py tests/test_agent_docs.py
python -m compileall -f -q zscope scripts test tests
git diff --check
```

初始结果分别为 `53 passed` 和 `228 passed`；补齐各入口自定义 state directory 回归后，相关测试为 `56 passed`，最终完整离线回归为 `231 passed`。`compileall` 与 `git diff --check` 均通过。本阶段所有 pytest 首轮均通过；没有在测试失败后修改产品代码。

### 后续阶段边界

- 阶段 19 的动态 state pruning 缺口已闭合；后续维护无需保留该 xfail。
- 真实 A/B、precision/recall、误报下降和正式 benchmark 仍等待用户明确授权。

## 2026-08-27：阶段 21——Schema 迁移到 Wiki 产品包

### 阶段目标

将版本化 Wiki/Validator JSON Schema 从 `new_docs` 文档目录迁移到产品包内的稳定位置，避免运行时契约依赖源码文档目录，并确保安装后的 wheel 仍能离线解析全部 `$ref`。

### 实施内容

- 将 13 份 Draft 2020-12 schema 与 `schema-registry.json` 移至 `zscope/wiki/schemas/`；`new_docs/schemas/` 不再保留副本。
- `zscope/wiki/schema.py` 的默认 resolver 路径改为相对于 `zscope/wiki/schema.py` 的 `schemas/` 子目录，源代码 checkout 与安装包使用同一解析逻辑。
- `schema-registry.json.base_directory` 更新为 `zscope/wiki/schemas`；registry 的 `$id`、文件名映射和本地 `$ref` 闭包保持不变。
- `pyproject.toml` 增加 `wiki/schemas/*.json` package-data，确保 wheel/sdist 安装时携带 registry 和全部 schema 文件。
- `tests/test_wiki_schema_contract.py` 改为校验产品包路径；计划中的 schema JSON 代码块仍作为唯一内容基准，测试继续防止代码块、实体文件和 registry 漂移。

### 固定行为和迁移边界

- `new_docs` 只保存设计计划和实施记录；schema 实体属于 `zscope/wiki` 产品包，不是文档缓存或运行时 state。
- `schema-registry.json` 仍是唯一 `$id` 解析表；删除、改名或漏打包任一实体文件都会在 resolver 初始化时 fail closed。
- 不保留 `new_docs/schemas` 兼容副本，避免两套 schema 漂移；需要自定义目录时仍可通过 `SchemaRegistry(schema_dir=...)` 显式传入。
- 本阶段只迁移文件和路径引用，不改变任何 schema 字段、版本、Validator 输入格式或 Wiki 状态目录。
- 本阶段没有访问真实 LLM endpoint、没有启动项目扫描、没有运行实际 benchmark。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_schema_contract.py tests/test_wiki_schema_resolver.py tests/test_agent_docs.py
python -m pytest -q tests/test_wiki_*.py tests/test_validator_project_knowledge.py tests/test_config_v2.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_report_schema_v2.py tests/test_report_assembler.py tests/test_mcp_policy.py tests/test_web_wiki_api.py tests/test_web_rules_api.py tests/test_agent_docs.py
python -m compileall -f -q zscope scripts test tests
git diff --check
python -m pip wheel --no-deps --no-build-isolation . -w <temporary-directory>
unzip -l <wheel> | grep 'zscope/wiki/schemas/'
```

迁移后结果为 `11 passed`（schema/registry/resolver 与 Agent 文档测试）和 `231 passed`（完整 Wiki/Validator 离线回归）；`compileall` 与 `git diff --check` 均通过。离线 wheel 构建成功，wheel 内包含全部 14 个 `zscope/wiki/schemas/*.json` 文件。不会以删除 `new_docs/schemas` 后的文件计数作为运行时可用性的充分证明。

## 2026-08-27：阶段 22——Compiler candidate 发布前校验与页面身份修复

### 修复目标

闭合 demo 暴露的 Wiki Compiler 发布失败链路：增量维护必须使用真实 project overview 页面身份；程序生成的 slug 必须与 page Schema 一致；任何 candidate revision 只有在完整 lint 通过后才能成为 active；模型不能伪造 Compiler provenance。本阶段只实施代码、测试和文档修复，不运行 demo 扫描，也不修改现有 demo active revision。

### 实施内容

- `zscope/wiki/maintenance.py`、`zscope/wiki/compiler/workset.py`
  - `dirty_page_closure()` 改为强制显式传入 `project_page_id`，拒绝空值并移除 `page_project` 默认占位符。
  - Workset 未显式指定目标页面时，使用 `stable_id("page", project_id, "project")`，与 deterministic skeleton 的 project overview 页面身份一致。
- `zscope/core/analysis/analyzer.py`
  - 增量维护优先从 active revision 中查找 `page_kind=project_overview` 或 `canonical_slug=project` 的真实 `page_id`；缺失时才按相同稳定身份算法重建。
  - source-to-page、depends-on 和 dirty closure 均使用真实页面 ID，不再把不存在的 `page_project` 发送给 Compiler。
- `zscope/wiki/identity.py`
  - `slugify()` 不再保留下划线；`page_project` 会规范化为 `page-project`，保证程序生成的 canonical slug 满足 page frontmatter Schema。
- `zscope/wiki/store/revision_store.py`
  - 最终页面 frontmatter 在写盘前执行 `zscope.wiki-page-frontmatter.v1` 实例校验。
  - candidate revision 完成 staging、不可变目录和 SQLite projection 后，在 active pointer 切换前执行完整 `lint_revision()`。
  - lint 失败时标记该 revision 为 failed、重建程序拥有的 `log.md` 并抛出 `WikiChangeSetApplyError`；旧 active pointer 保持不变。
  - lint 通过后把真实 warning/error 计数写回 `revision.json` 和 SQLite；active pointer 发布失败同样标记 failed 并重建日志。
- `zscope/wiki/compiler/llm_compiler.py`
  - 终态 payload 校验前和最终返回前都由程序无条件覆盖 `compiler.kind`、adapter identity、prompt version 和实际 client model，模型提交的同名 metadata 不再保留。
- `zscope/wiki/compiler/changeset.py`
  - 将 `background_only` 的约束变更错误与 source extraction status 错误拆分，非法 status 返回精确诊断，不再统一误报为 `background_only cannot create constraints`。

### 新增和更新测试

- `tests/test_wiki_maintenance.py`
  - 覆盖真实稳定 project page ID、默认 Workset target、slug 规范化，以及 Analyzer auto-maintain 不再产生 `page_project`。
- `tests/test_wiki_revision_store.py`
  - 覆盖安全 slug、candidate lint 失败保持旧 active、失败 revision metadata、audit/log 一致性。
- `tests/test_wiki_llm_compiler.py`
  - Fake LLM 主动提交伪造 provenance，断言最终 metadata 仍由程序覆盖。
- `tests/test_wiki_compiler.py`
  - 覆盖 `background_only` 非法 source status 的精确错误信息。

### 固定行为和恢复边界

- page ID 与 canonical slug 是不同身份层：page ID 使用稳定 hash，slug 只用于受 Schema 约束的可读路径；二者不得通过 `page_project` 占位符混用。
- revision 目录或 SQLite projection 已生成不代表可发布；完整 lint 是 active pointer 之前的强制门禁。
- failed candidate 可以保留用于审计，但不能成为 Validator 的 pinned Wiki snapshot；旧 active revision 继续服务，或者在 manifest 不匹配时走 direct-source fallback。
- Compiler provenance 不属于模型可编辑知识，不能用 ChangeSet payload 覆盖真实调用信息。
- 当前 demo active revision 保持原状；本阶段不执行 rollback，也不运行 Z-SCOPE/demo 扫描。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_maintenance.py tests/test_wiki_compiler.py tests/test_wiki_llm_compiler.py tests/test_wiki_revision_store.py tests/test_wiki_lint.py
python -m pytest -q tests/test_wiki_maintenance.py tests/test_wiki_compiler.py tests/test_wiki_llm_compiler.py tests/test_wiki_revision_store.py tests/test_wiki_lint.py tests/test_wiki_service.py tests/test_wiki_workflow.py tests/test_wiki_schema_resolver.py tests/test_agent_docs.py
python -m pytest -q tests/test_wiki_*.py tests/test_validator_project_knowledge.py tests/test_config_v2.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_report_schema_v2.py tests/test_report_assembler.py tests/test_mcp_policy.py tests/test_web_wiki_api.py tests/test_web_rules_api.py tests/test_agent_docs.py
python -m black zscope/wiki/maintenance.py zscope/wiki/compiler/workset.py zscope/wiki/identity.py zscope/core/analysis/analyzer.py zscope/wiki/compiler/changeset.py zscope/wiki/compiler/llm_compiler.py zscope/wiki/store/revision_store.py tests/test_wiki_maintenance.py tests/test_wiki_compiler.py tests/test_wiki_llm_compiler.py tests/test_wiki_revision_store.py
python -m py_compile zscope/wiki/maintenance.py zscope/wiki/compiler/workset.py zscope/wiki/identity.py zscope/core/analysis/analyzer.py zscope/wiki/compiler/changeset.py zscope/wiki/compiler/llm_compiler.py zscope/wiki/store/revision_store.py
git diff --check
```

三组 pytest 分别为 `45 passed`、`62 passed` 和 `247 passed`；定向 Black 完成，`py_compile` 与 `git diff --check` 均通过。未访问 LLM endpoint，未启动 demo 扫描。

## 2026-08-27：阶段 23——Wiki Compiler 统一加载 Agent 契约

### 实施内容

- `zscope/agents/wiki_compiler/AGENT.md`
  - 补齐 source/page ID allowlist、来源提示词不可信和运行时终态工具由程序提供等契约。
  - 该文件成为 Wiki Compiler 稳定 system prompt 的唯一文本来源。
- `zscope/wiki/compiler/llm_compiler.py`
  - 通过 `SpecRegistry().get_agent("wiki_compiler")` 加载 `AGENT.md`，使用 `AgentSpec.to_prompt_block()` 作为 system message。
  - 删除 Provider 内重复的硬编码 system prompt；代码仅保留 final-tool schema、终态处理器、重试参数和模型 provenance。
  - `compiler.prompt_version` 更新为 `zscope.wiki-compiler.agent.v1`。
- `tests/test_wiki_llm_compiler.py`
  - 断言发送给模型的 system message 与注册表加载的 `wiki_compiler/AGENT.md` 完全一致，防止契约文件和实际提示漂移。

### 固定边界

- `AGENT.md` 负责稳定业务和安全规则；Workset、工具 schema、终态校验结果和重试上限仍由程序提供，不能写死到文档中。
- 找不到 `wiki_compiler/AGENT.md` 时 Provider 直接失败，不回退到隐含的旧硬编码 prompt。
- 本阶段不运行 demo 扫描，不访问真实 LLM endpoint，不修改 demo active revision。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_llm_compiler.py tests/test_wiki_compiler.py tests/test_wiki_revision_store.py
python -m pytest -q tests/test_wiki_*.py tests/test_validator_project_knowledge.py tests/test_config_v2.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_report_schema_v2.py tests/test_report_assembler.py tests/test_mcp_policy.py tests/test_web_wiki_api.py tests/test_web_rules_api.py tests/test_agent_docs.py
python -m black zscope/wiki/compiler/llm_compiler.py tests/test_wiki_llm_compiler.py
python -m py_compile zscope/wiki/compiler/llm_compiler.py
git diff --check
```

定向回归为 `41 passed`，完整 Wiki/Validator 离线回归为 `261 passed`；Black、`py_compile` 和 `git diff --check` 均通过。未访问真实 LLM endpoint，未启动 demo 扫描。

## 2026-08-27：阶段 24——删除来源的确定性维护路径

### 问题

当文档因删除或 `documents.exclude` 从当前 manifest 消失时，增量 Workset 只有 `removed_source_ids`，没有原始文档正文、`source_sections` 或可安全提供给模型的旧 Wiki 内容。此前仍会调用 LLM，模型只能凭来源 ID 猜测页面内容，导致无效 Markdown 覆盖或错误描述删除来源。

### 实施内容

- `zscope/wiki/compiler/compiler.py`
  - `WikiCompiler.compile()` 在 provider 前识别 removed-only delta（`removed_source_ids` 非空且 added/changed 为空）。
  - 直接生成 `outcome=background_only`、空 `page_changes`/`constraint_proposals`/`edge_proposals`/`retire_proposals` 的 deterministic ChangeSet，使用 `zscope.wiki.removal.v1` provenance。
  - 每个 removed source 只记录 `no_constraints_found` 和固定 reason `removed_source_invalidated_deterministically`；provider 完全不调用。
- `zscope/agents/wiki_compiler/AGENT.md`
  - 明确 removed source 不得被推测、重述或重建；删除导致的 ref/page/constraint stale 由程序处理；removed-only 不生成内容。
- `zscope/wiki/store/revision_store.py`（复用既有逻辑）
  - 继续将旧 DocumentRef 设为 `resolvable=false`，将依赖 constraint 设为 `stale`，将引用已删除 source 的页面设为 `stale`，并发布与当前 manifest 一致的新 revision。

### 新增测试

- `tests/test_wiki_compiler.py`
  - provider 即使存在也不会在 removed-only Workset 中调用；ChangeSet 不含任何内容变更。
- `tests/test_wiki_revision_store.py`
  - 端到端验证删除来源后 active revision 更新、manifest pin 更新、ref 不可解析、constraint/page stale，且旧页面正文不会被模型重写。

### 固定边界

```text
removed-only:  program stale propagation -> publish current-manifest revision
added/changed: LLM may compile current source sections -> Store merge + stale propagation
mixed:         LLM only handles added/changed; Store always handles removed sources
```

删除来源不是内容生成任务；旧页面仍可作为历史审计投影保留，但 stale 页面和 constraint 不得进入 active Validator context。当前阶段不运行 demo 扫描、不访问真实 LLM endpoint、不修改 demo active revision。

### 验证命令和结果

```text
python -m pytest -q tests/test_wiki_compiler.py tests/test_wiki_revision_store.py tests/test_wiki_maintenance.py
python -m pytest -q tests/test_wiki_*.py tests/test_spec_registry.py tests/test_validator_project_knowledge.py tests/test_config_v2.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_report_schema_v2.py tests/test_report_assembler.py tests/test_mcp_policy.py tests/test_web_wiki_api.py tests/test_web_rules_api.py tests/test_agent_docs.py
```

本阶段定向测试为 `37 passed`；完整 Wiki/Validator 离线回归为 `263 passed`。未访问真实 LLM endpoint，未启动 demo 扫描。

## 2026-08-28：阶段 25——未物化父 revision 的全量 bootstrap

### 问题

父 revision 可能只有 deterministic skeleton、空页面投影，或此前 LLM 编译失败而未产生页面。此时即使当前 manifest 发生 added、changed 或 removed delta，也不能按普通增量处理；否则 removed-only 会只传播 stale，增改也只把变更文档交给 Compiler，项目会长期停留在未建立 Wiki 的状态。

### 实施内容

- `zscope/core/analysis/analyzer.py`
  - 沿父 revision lineage 查找成功的 LLM/mixed publish event，并以 `changed_pages>0` 作为页面已物化证据。
  - 未找到物化证据时，将当前 manifest 的全部 accepted source IDs 放入 `added_source_ids`，保留本次 `removed_source_ids`，并将全部已有页面作为 bootstrap 目标。
  - 父 revision 没有任何 page row 时，按 skeleton 的稳定命名规则生成 project/module/source page allowlist，避免 bootstrap 只能创建 project 页面。
  - 已物化 revision 继续使用原有 added/changed 增量和 removed-only 确定性路径。
- `zscope/wiki/compiler/compiler.py`
  - 保持 removed-only 的纯形状判断：只要 Workset 只有 `removed_source_ids` 就不读取或生成删除来源内容。
  - 是否需要 bootstrap 由 Analyzer 根据父 revision 的物化证据决定；未物化时 Analyzer 会把当前 accepted 文档放入 `added_source_ids`，因此不会命中该快速路径。

### 新增测试

- `tests/test_wiki_maintenance.py` 覆盖父 revision 未物化时的 added、changed、removed 三类 delta，确认当前所有 accepted 文档都会进入 bootstrap Workset。
- `tests/test_wiki_compiler.py` 确认有既有页面的 removed-only 仍不调用 LLM。

### 验证结果

```text
python -m pytest -q tests/test_wiki_maintenance.py tests/test_wiki_compiler.py
```

定向测试为 `30 passed`；未运行 demo 扫描，未访问真实 LLM endpoint。

## 2026-08-31：阶段 26——Constraint-only 运行时知识层

### 决策

Constraint 与生成式 Wiki 页面承担了重复的语义职责，而 Validator 的匹配、来源校验和 stale 传播本来就需要结构化对象。因此保留 `ProjectConstraint` 作为唯一运行时语义派生产物，停止生成式 Markdown 页面进入新 revision 或 Validator context。原始 Markdown 仍是事实来源；旧 revision 的页面仅保留读取/回放兼容。

### 实施内容

- 新增 `zscope.project-constraint-proposal.v1`。终态工具 `emit_project_constraints` 只接收 `constraint_proposals`；每条 proposal 显式提交 `subject_kind`，其值受固定 enum 限制；`schema_version` 不进入 final tool schema，由程序补充，不再添加额外的 `allowed_subject_kinds` 或模型 `summary` 输出字段。`summary` 由程序根据 outcome、proposal 数量和 source results 确定性生成。
- `LLMWikiCompilerProvider` 在终态处理器中由程序补齐 changeset 外壳、source results、outcome 和 compiler provenance；模型不能提交 `constraint_id`、scope、status、authority、revision/digest、`normalized_value`、`page_refs`、页面或 edge 字段。
- `WikiStore` 为每条 proposal 稳定生成 constraint ID、subject kind、project/module scope、`authority=documented_contract`、active status、manifest/revision metadata；按 subject/kind/scope 合并相同 statement，保留不同 statement 为 conflicted，并对来源删除确定性传播 stale。
- 新 revision 写入 refs、constraints、manifest、index、audit/log projection，`pages/` 和 `edges.json` 为空；页面不参与 digest、匹配和 Validator 注入。
  - `ProjectKnowledgeService` 只选择 active、documented_contract 且 source refs 可解析的 Constraint；没有有效 Constraint 或 Compiler 不可用时从 source-index 获取全部相关原文候选，再由程序最多保留 20 条并记录 `omitted_source_excerpt_count`。
- 删除 `page_excerpts`、`selected_page_ids` 和 Constraint 的 `normalized_value/page_refs` 运行时字段；旧 revision lint/迁移时剥离历史字段以保持可读性。
- 更新 Wiki Compiler/Validator Agent 契约、模块文档、schema registry 和迁移后的测试；未运行 demo 扫描。

### 验证

```text
python -m pytest -q tests/test_wiki_*.py tests/test_validator_project_knowledge.py tests/test_agent_docs.py
python -m pytest -q
python -m compileall -q zscope tests
git diff --check
```

Constraint/Validator 定向回归为 `115 passed`；完整回归为 `1917 passed, 5 skipped`。未访问真实 LLM endpoint，未运行 demo 扫描。

## 2026-08-31：阶段 27——LLM 输入投影

### 目标

将 Compiler 的模型可见输入从内部 `IngestWorkset` 收敛为稳定、可审计的语义投影，降低上下文冗余和程序字段被模型复述/篡改的风险，同时保留程序对完整 Workset 的终态校验能力。

### 输入契约

`build_llm_input_projection(workset)` 对单个 Markdown 文档生成以下固定顶层字段：

```json
{
  "file_path": "README.md",
  "title": "llm_wiki_demo",
  "change": "initial",
  "sections": [
    {
      "ref_id": "docref_...",
      "heading_path": ["项目和模块约束", "标签 API"],
      "start_line": 9,
      "end_line": 14,
      "text": "..."
    }
  ]
}
```

`sections` 仅来自当前文档，`ref_id` 按 `stable_id("docref", source_id, section_id)` 重建，并从程序维护的 catalog 取得路径。多文档、缺少 catalog、source ID 不匹配、越过当前 delta 或 malformed section 时，投影立即拒绝；removed-only 和 noop 不进入 Compiler。`change` 在无 base revision 且仅有新增来源时为 `initial`，其余进入 Compiler 的变化为 `incremental`。

### 所有权边界

模型只看到上述投影和 `AGENT.md` 契约；`workset_id`、source ID、base revision、manifest digest、source catalog、subject ID allowlist、limits、revision metadata 和发布状态均由程序保留。终态工具 schema 在每条 proposal 内暴露 `subject_kind` enum，不增加额外的 `allowed_subject_kinds` 输出字段。模型终态工具只提交语义 proposal，Provider 再用完整 Workset 生成 ChangeSet 外壳、程序生成 `summary`，并执行 schema、source-ref、subject allowlist 和状态机校验。多个文档的 proposal 在程序侧合并后一次性发布 revision；`summary` 不参与 revision identity。

### 验证

```text
python -m pytest -q tests/test_wiki_llm_compiler.py tests/test_wiki_compiler.py
python -m compileall -q zscope tests
git diff --check
```

结果：`17 passed`（LLM projection/Compiler）；未访问真实 LLM endpoint，未运行 demo 扫描。

## 2026-09-01：阶段 28——Validator 输入投影

### 目标和范围

本阶段记录 Validator 侧 `project_knowledge` 输入投影的落地实现。目标是把 Wiki/source fallback 的完整、可审计上下文转换为 Validator LLM 可直接理解且大小受控的投影，同时保留程序拥有的 revision、manifest、selection 和引用闭包信息。

本阶段不改变 Validator 的确定性证据、candidate ledger 或 verdict 状态机；Wiki 约束仍然只是文档辅助上下文，不能单独确认、拒绝或改变 candidate 终态。也没有运行 Z-Scope demo 扫描或真实 LLM endpoint。

### 实际数据流

```text
candidate/raw issue + evidence pack
        │
        ├─ ProjectKnowledgeService.resolve_for_candidate()
        │    ├─ 从 candidate/evidence obligation 构造查询目标
        │    ├─ Wiki active constraint 匹配（revision/manifest/ref 已 pin）
        │    └─ 无有效 Wiki 命中时 SourceIndex direct fallback
        │
        ├─ validate_project_knowledge()
        │    └─ schema、mode、预算、selection/ref 闭包和状态校验
        │
        └─ build_validator_evidence_slice_v3()
             ├─ build_validator_project_knowledge_projection()
             ├─ 压缩为模型可见字段
             └─ 将 constraint/source ref 注册到 evidence_ref_catalog
```

`ValidationRunner._build_evidence_pack()` 在候选证据构建完成后调用 Wiki service。`shadow` 模式仍只记录选择和预算 telemetry，不把投影放进模型输入；`active` 模式才把通过校验的 `project_knowledge` 放入 evidence pack，随后由 v3 evidence slice 生成最终 Validator 输入。Wiki service 或投影校验失败时保留原始 evidence，不把异常伪装成“无约束”。

### 模型可见投影

模型看到的顶层字段固定为：

| 字段 | 来源和用途 |
| --- | --- |
| `resolution_mode` | 程序标记 `wiki`、`source_fallback` 或 `none`；用于理解上下文来源 |
| `wiki_revision_id` | 当前 Wiki revision；source fallback/none 为 `null` |
| `target` | 候选目标的紧凑身份与义务范围 |
| `constraints` | 匹配到的、带可解析 source ref 的文档约束 |
| `source_excerpts` | direct fallback 或辅助来源摘录 |
| `conflicts` | 冲突约束的有界摘要，不是已裁决结论 |
| `omitted_constraint_count` | 因 20 条选择上限或 token 预算未注入的约束数 |
| `omitted_source_excerpt_count` | 因选择上限或 token 预算未注入的原文摘录数 |
| `fallback_reason` | fallback/no-hit 的程序原因 |

manifest digest、context digest、selection 排名细节、完整 source catalog 和内部预算信息留在程序拥有的审计 envelope 中，不直接暴露给模型。`schema_version` 也由程序保留在完整对象中，不作为该紧凑模型投影的顶层字段。

### `target` 字段映射和修复

`build_validator_project_knowledge_projection()` 不再从已匹配的 constraints 反向推导候选身份。`target.subject_ids` 和 `target.obligation_kinds` 必须来自 candidate/evidence obligation：

- subject 优先读取 candidate 的 `subject_ids`、`subject_id` 或 `subject`；对象 subject 读取 `canonical_id`/`id`。
- obligation kind 优先读取 `obligation_kinds`，其次读取 `missing_fact_kinds`、`fact_kinds`、单值 `obligation_kind` 或 `fact_kind`。
- 字符串会统一包装成数组，数组去重并保留稳定顺序；缺失时返回空数组，而不是用约束 subject 填充。
- `target.module_ids` 当前来自 service 构造的 obligation；本阶段保留程序字段，不允许模型修改。candidate 解析器的模块、subject 和多义务完整覆盖仍列为 TODO。

`candidate_file` 由候选的 `candidate_file`、`relative_file`、`file_path` 或 `file` 获取，并统一为 project-root 相对 POSIX 路径；如果候选未直接提供文件，则从 `location` 的 `path:line[:column]` 形式提取路径。绝对路径会去掉前导 `/`，历史占位值 `unknown.md` 不会覆盖真实候选路径；最终没有路径时才使用 `unknown.md`。因此此前输入中出现的 `unknown.md` 会被 `src/...` 等真实候选文件修复。

`function_name` 优先使用 service target 的 `function_name`/`function_id`，否则回退到 candidate 的 `function`。service 内部同时保留 `function_id`、`entry_function` 等查询字段，但紧凑 projection 只公开 Validator 判断所需的函数名称。

### 约束和冲突投影

每条约束投影保留：`constraint_id`、`kind`、去掉 subject-kind 前缀后的 `subject_id`、`subject_kind`、`statement`、`authority`、`normativity`、`status`、`source_refs` 和 `conflicts_with`。`subject_kind` 来自程序生成的约束对象；其合法值由 project-knowledge schema 的 enum 限制。

进入 active context 的约束必须满足：

1. `status` 为 `active` 或 `conflicted`；
2. `authority=documented_contract`；
3. 至少有一个 source ref，且该 ref 在当前 pinned revision 中可解析。

同一 subject/kind/scope 的冲突约束以图连通分量生成 `conflicts` 摘要，并将双方 ID 和 source refs 交给 Validator。冲突只表示文档存在不一致，Validator 必须结合代码证据判断，不能把任一冲突声明当成自动反证或证明。stale、不可解析引用、推荐性/描述性/unknown 语句不作为 negative evidence。

### 程序校验和引用闭包

`validate_project_knowledge()` 使用本地 schema registry 验证 `zscope.validator-project-knowledge.v1`，并补充以下跨字段检查：

- `wiki` 必须有 revision；`source_fallback`/`none` 不得携带 Wiki revision 或编译约束；`none` 必须为空；
- `estimated_tokens` 不得超过 selection 的 `max_tokens`；
- `selected_constraint_ids` 必须全部存在于当前 constraints；
- `selected_source_ref_ids` 必须来自 source excerpts 或 constraints 的 source refs；
- 每条约束必须满足 active/conflicted、documented_contract 和 source-ref 条件。

v3 slice 生成后，所有 constraint ID 和 source ref 会加入 `evidence_ref_catalog`，分别标记为 `project_constraint` 与 `project_document_ref`，并带有限摘要。Validator 只能引用 catalog 中存在的 ref；单独出现的 UID、hash 或未知 constraint ID 不构成证据。

### 预算、稳定性和降级

ProjectKnowledgeService 默认共享 `4096` token 上限；调用方可以传更小值但不能超过该上限。Wiki constraint 和 direct source excerpt 各最多选择 20 条，超出部分通过 omitted count 审计。排序按 kind、canonical subject 和 constraint ID 等稳定键执行，context digest 对除自身外的完整 envelope 计算，确保同一 candidate/revision 输入可复现。

Wiki 无 active revision、revision lint 失败、manifest 不匹配、Compiler 不可用或查询无命中时，系统回退到 source-index：有相关原文则 `source_fallback`，无命中则 `none/no_relevant_project_constraint`。任何 service/schema 异常都只丢弃 project knowledge，保留既有 Validator evidence 和 needs-review 语义。

### 实际修改文件

- `zscope/core/validation/evidence.py`：新增/维护紧凑投影、candidate 字段解析和 v3 evidence slice 注入。
- `zscope/core/validation/runner.py`：在 evidence pack 阶段调用 service，区分 shadow 与 active，并在失败时保留基础证据。
- `zscope/wiki/service.py`：构造 target、匹配 active/conflicted constraints、生成冲突摘要、执行 direct fallback 和 context telemetry。
- `zscope/wiki/context/obligation.py`：从 candidate/evidence 建立稳定查询 obligation，规范化文件路径和义务 kind 别名。
- `zscope/wiki/schemas/validator-project-knowledge.schema.json`：固定 target 数组字段、candidate_file 路径约束、subject-kind/obligation-kind enum 及冲突字段。
- `zscope/agents/validator_agent/AGENT.md`：说明 project knowledge 是辅助上下文、冲突处理、引用规则和模型可见字段。
- `tests/test_validator_project_knowledge.py`、`tests/test_wiki_service.py`：覆盖投影字段、candidate_file 修复、source ref catalog、fallback、预算和冲突语义。

### 验证记录

本阶段实施期间使用了相关 pytest 和静态检查验证代码契约；未运行 demo 扫描：

```text
python -m pytest -q tests/test_validator_project_knowledge.py tests/test_wiki_service.py tests/test_validation_runner.py
python -m compileall -q zscope tests
git diff --check
```

测试覆盖的关键断言包括：`unknown.md` 能由候选 location 修复为真实 `candidate_file`；target 的 subject/kind 缺失时保持空数组；constraint subject kind、status 和 conflicts_with 可被投影；source refs 可进入 catalog；shadow 不注入模型；Wiki 失败可回退 direct source。

### 后续 TODO

- 完善 candidate 解析器，稳定解析 `target.module_ids`、`target.subject_ids`、`target.obligation_kinds`，覆盖函数、模块、文件、资源、锁及多义务候选。
- 为解析失败定义统一的 `unknown`/空值审计语义，避免不同 candidate adapter 产生不一致的隐式回退。
- 增加 projection 的独立 snapshot/replay 测试，固定排序、digest、token 计数和 evidence catalog 闭包。
- 在不改变 active/shadow 边界的前提下，补充 report-level Wiki selection telemetry 与 Validator 输入审计关联。
