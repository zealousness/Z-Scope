---
doc_contract: zscope-module-v1
covers:
  - zscope/wiki
sources:
  - zscope/wiki/models.py
  - zscope/wiki/discovery.py
  - zscope/wiki/classification.py
  - zscope/wiki/markdown_parser.py
  - zscope/wiki/source_manifest.py
  - zscope/wiki/source_index.py
  - zscope/wiki/maintenance.py
  - zscope/wiki/service.py
  - zscope/wiki/control.py
  - zscope/wiki/page_format.py
  - zscope/wiki/events.py
  - zscope/wiki/schema.py
  - zscope/wiki/lint.py
  - zscope/wiki/compiler/compiler.py
  - zscope/wiki/compiler/changeset.py
  - zscope/wiki/compiler/workset.py
  - zscope/wiki/compiler/llm_compiler.py
  - zscope/wiki/store/revision_store.py
  - zscope/cli/wiki.py
  - zscope/wiki/context/obligation.py
  - zscope/wiki/context/direct_documents.py
tests:
  - tests/test_wiki_ingestion.py
  - tests/test_wiki_source_index.py
  - tests/test_wiki_maintenance.py
  - tests/test_wiki_compiler.py
  - tests/test_wiki_revision_store.py
  - tests/test_wiki_service.py
  - tests/test_wiki_cli.py
  - tests/test_validator_project_knowledge.py
  - tests/test_wiki_schema_contract.py
  - tests/test_wiki_schema_resolver.py
  - tests/test_wiki_lint.py
  - tests/test_wiki_control.py
  - tests/test_wiki_context_replay.py
  - tests/test_wiki_workflow.py
---

# LLM Wiki

## 职责与边界

本模块从配置解析后的 `project.root` 递归发现 Markdown，确定性地区分说明性文档、生成物、运行时指令、benchmark truth、敏感内容和未知文件。只有 explanatory 文档进入 source index 或 Wiki 编译输入；原始文档只读。

模块还负责按 heading 和行号建立稳定 source section、生成 manifest、执行无 LLM 的候选相关文档查询，并为后续 Wiki revision/compiler 提供版本化来源身份。它不负责漏洞证明、candidate 终态、Validator verdict 或修改原始项目文档。

## 主数据流

`project.root -> discovery -> classification -> Markdown sections -> source-manifest/source-index -> WikiStore/direct fallback -> session-pinned ProjectKnowledgeService -> entry analysis/Validator/Web/MCP`

扫描 workflow 将 Wiki 编译作为 session 级前置阶段：入口发现完成后执行一次 `wiki_compile`，等待编译、发布或 direct-source fallback 准备全部结束，再启动入口分析和验证。批量入口、辅助 Analyzer 与 scan-level Validator 共享同一个只读服务；单个入口结束不得释放共享资源，由 session 在扫描结束时统一关闭。

Wiki 页面、constraint、revision 和 Compiler 结果由 bounded `IngestWorkset`/`WikiChangeSet` 派生；`WikiStore.apply_changeset()` 在 staging、SQLite projection 和原子 active pointer 之间发布不可变 revision。source index 必须独立于 Wiki store，使 Compiler 不可用或 Wiki 损坏时仍能返回带路径、标题、行号和 digest 的原文摘录。Schema `$ref` 只通过本地 registry 解析，不访问网络。

Compiler upsert 页面必须使用固定六个中文二级标题；多页面更新使用 `[[page_id|中文标题]]` 形成闭包内 wikilink。程序校验中文正文、heading 顺序、source ref 和 wikilink target，并生成符合 `zscope.wiki-index.v1` 的 `index.md`。`audit-events.jsonl` 是 `log.md` 和 active transition replay 的唯一事件来源；`log.md` 可以从完整有效的事件链原子重建。

LLM Compiler 的稳定业务、安全和 Markdown 规则唯一维护于 `zscope/agents/wiki_compiler/AGENT.md`；Provider 通过 `SpecRegistry` 将该 Agent 契约加载为 system prompt，不再在 Python 中复制硬编码业务提示。终态工具 schema、当前 Workset 和重试次数由程序作为运行时参数提供。Compiler 只能通过终态工具 `emit_wiki_changeset` 提交完整 ChangeSet，正文 JSON 不作为成功输出。每次终态提交立即执行 Schema、workset allowlist 和跨字段不变量校验；失败原因作为 tool result 回送模型，初次提交后最多进行两次修复重试。

`project.wiki.max_context_tokens`、`compiler_max_tokens`、`max_source_chars`、`max_output_chars`、`max_wall_seconds` 和 `max_pages` 默认均为 `null`，表示不施加对应的 Wiki 局部预算。显式正整数仍可收紧单个项目；`compiler_max_tokens=null` 时 Compiler 不覆盖 `llms.<profile>.max_tokens`，通用 LLM Client 的物理请求 completion 上限保持有效。Schema 大小、ID allowlist、磁盘读取、模型上下文窗口和 provider timeout 等结构性边界不属于这些可选预算。

`zscope/wiki/control.py` 是 Web 与 MCP 共用的只读控制面，只暴露 active revision status 和候选相关 query。调用方不能传入任意 project root、state root 或写操作；Web 使用 `GET /api/wiki/status`、`GET /api/wiki/query`，MCP 使用 `zscope.wiki.status`、`zscope.wiki.query`。

## 必须保持的不变量

- 遍历不跟随目录 symlink；文件 symlink 解析后越出 root 必须拒绝。
- 配置解析后的 `project.wiki.state_dir` 以受验证的 project-relative 动态 prune root 传入 discovery、manifest 与 source index；该目录及其子树不会进入语料、digest 或索引，即使其名称不是默认 `.zscope_knowledge`。
- `.git`、`.zscope_knowledge`、扫描输出、Wiki 输出、`AGENTS.md`、`GROUND_TRUTH.md`、生成报告和敏感文件不得进入 explanatory corpus；用户 override 不能删除 mandatory exclusion。
- `project.wiki.documents.exclude` 是 fail-closed 的项目相对 corpus 过滤器，必须同时作用于 Analyzer、Web 和 MCP 的 manifest/source-index；命中项保留 `user_excluded_path` descriptor，且 override digest 进入 manifest identity。
- revision freshness digest 只纳入受支持的 Markdown 文档及其读取/分类结果；非 Markdown 文件和 `unsupported_extensions` 仅作为发现诊断元数据，不得因日志、报告、源码或其他生成物的增删改触发 Wiki maintenance。
- 不确定分类 fail closed 为 `unknown`；同一路径不能同时成为 accepted source 和 excluded descriptor。
- `source_id` 由 project identity、source kind 和相对路径稳定计算，content digest 单独表示版本。
- project overview 页面身份由 `stable_id("page", project_id, "project")` 或 active revision 中同类页面的真实 `page_id` 决定；增量 dirty closure 必须显式接收该 ID，不得使用 `page_project` 一类占位符。默认 Workset 也必须指向同一个稳定页面身份。
- 页面 `canonical_slug` 必须满足 page frontmatter Schema；程序生成 slug 时将下划线和其他非法字符归一化为连字符，不能把非法路径写入 candidate revision。
- 纯 `removed_source_ids` delta 不调用 LLM，也不接受页面正文、约束、边或 retire proposal；RevisionStore 仅复制历史投影并确定性传播 ref 不可解析和 page/constraint stale，再发布 current-manifest revision。只有包含 added/changed source 的混合 delta 才允许 Compiler 生成内容。
- 上述 removed-only 快速路径仅适用于父 revision lineage 中已有成功 LLM/mixed 页面发布（publish event 的 `changed_pages>0`）；若父 revision 只是 deterministic skeleton、空投影或此前编译失败，任何 added/changed/removed delta 都必须将当前 accepted 文档升级为全量 bootstrap 输入，重新进入页面生成。
- removed-only 的 deterministic ChangeSet 使用 `zscope.wiki.removal.v1` provenance，并只记录受影响的 `docsrc` ID 和固定 reason；不得生成“源文档原内容”或“旧 Wiki 内容”的猜测性 Markdown。
- direct fallback 只返回有来源的原文摘录；没有命中返回 `none`，不能从文档猜测 constraint，也不能改变 Validator verdict。
- active Wiki context 只消费当前 manifest pin 下 status=active、authority=documented_contract 且 source refs 可解析的 constraint；背景页本身不计作 Wiki 注入证据。
- `ProjectKnowledgeService` 在扫描开始时快照一个 active revision；并发 Validator worker 不得重新读取 active pointer。Validator cache identity 必须包含 project knowledge schema、mode、revision、manifest、context digest 和 ranking version。
- 同一 scan session 不得由入口 Analyzer 重复执行 Wiki preflight/Compiler，也不得并发争抢 `compiler.lock`；共享服务的生命周期必须覆盖全部入口与最终验证队列。
- candidate revision 在切换 active pointer 前必须完成 page frontmatter Schema 校验和完整 `lint_revision()`；lint 结果必须写回 revision metadata，不能预置固定 `passed`。lint、SQLite projection 或 active pointer 发布失败时将该 revision 标记为 failed、重建程序拥有的 `log.md`，并保留旧 active revision。
- Compiler provenance 是程序拥有的字段；无论模型是否提交 `compiler` metadata，发布前都必须以实际 adapter、prompt version 和 client model 无条件覆盖。Compiler unavailable 时同样不切换 active pointer；Validator 记录 fallback reason 并回到 source-index direct fallback。
- `build_only` 在 manifest 改变时也必须发布 current revision，但不向 Validator 暴露 context；`auto_maintain + compiler_enabled` 可对 deterministic revision 做一次 LLM enrichment，已经是 LLM/mixed revision 且 manifest 未变时不得产生 revision churn。
- `audit-events.jsonl` 使用 `zscope.wiki-event.v1` 哈希链；每个事件的 `previous_event_digest` 必须连接前一事件，lint 必须检测断链。
- event replay 重建的 active revision 必须与 `active.json` 一致；`log.md` 必须与同一事件链的程序投影字节等价。
- `active.json`、revision metadata、source manifest、page/index/log 和 audit event 文件都按不可信磁盘输入处理：固定 revision ID、大小、UTF-8、symlink 和 state-root 路径边界，任何非法状态不得参与路径拼接。
- audit event replay 使用有界逐行读取；损坏链不能被下一次 append 重置为新链。lint 对 SQLite object 数量、JSON/Markdown 大小、错误输出和 disk/SQLite projection 执行固定上限。
- active/shadow 查询在运行时消费 revision 前必须通过完整 bounded lint；page/index/event 或 SQLite projection 被篡改时丢弃 Wiki snapshot，并保留 direct-source fallback。
- Compiler 一次 upsert 多个页面时，每个页面必须链接另一个本次修改页面；wikilink、Markdown source ref 和 index link 都只能指向同 revision 已授权对象。
- Web/MCP Wiki query 必须服从配置中的 project root、state dir、分类覆盖和显式配置的资源/token 上限；默认 `null` 时不得自行恢复旧的 2000/3500 token 隐式上限，且不得暴露 build、rollback 或任意文件读取能力。
- Wiki state directory 必须是 project-root 内不经过 symlink 的相对目录；status 只返回 bounded metadata projection，不返回绝对路径或内部异常文本。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_wiki_discovery.py tests/test_wiki_source_index.py
python -m pytest -q tests/test_wiki_schema_contract.py tests/test_agent_docs.py
python -m pytest -q tests/test_wiki_control.py tests/test_web_wiki_api.py tests/test_mcp_policy.py
python -m pytest -q tests/test_wiki_context_replay.py tests/test_wiki_maintenance.py
python -m pytest -q tests/test_wiki_compiler.py tests/test_wiki_revision_store.py tests/test_wiki_lint.py
```
