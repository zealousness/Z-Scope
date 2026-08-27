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
---

# LLM Wiki

## 职责与边界

本模块从配置解析后的 `project.root` 递归发现 Markdown，确定性地区分说明性文档、生成物、运行时指令、benchmark truth、敏感内容和未知文件。只有 explanatory 文档进入 source index 或 Wiki 编译输入；原始文档只读。

模块还负责按 heading 和行号建立稳定 source section、生成 manifest、执行无 LLM 的候选相关文档查询，并为后续 Wiki revision/compiler 提供版本化来源身份。它不负责漏洞证明、candidate 终态、Validator verdict 或修改原始项目文档。

## 主数据流

`project.root -> discovery -> classification -> Markdown sections -> source-manifest/source-index -> WikiStore/direct fallback -> ProjectKnowledgeService -> Validator/Web/MCP`

Wiki 页面、constraint、revision 和 Compiler 结果由 bounded `IngestWorkset`/`WikiChangeSet` 派生；`WikiStore.apply_changeset()` 在 staging、SQLite projection 和原子 active pointer 之间发布不可变 revision。source index 必须独立于 Wiki store，使 Compiler 不可用或 Wiki 损坏时仍能返回带路径、标题、行号和 digest 的原文摘录。Schema `$ref` 只通过本地 registry 解析，不访问网络。

Compiler upsert 页面必须使用固定六个中文二级标题；多页面更新使用 `[[page_id|中文标题]]` 形成闭包内 wikilink。程序校验中文正文、heading 顺序、source ref、wikilink target、页面/output 数量上限，并生成符合 `zscope.wiki-index.v1` 的 `index.md`。`audit-events.jsonl` 是 `log.md` 和 active transition replay 的唯一事件来源；`log.md` 可以从完整有效的事件链原子重建。

`zscope/wiki/control.py` 是 Web 与 MCP 共用的只读控制面，只暴露 active revision status 和候选相关 query。调用方不能传入任意 project root、state root 或写操作；Web 使用 `GET /api/wiki/status`、`GET /api/wiki/query`，MCP 使用 `zscope.wiki.status`、`zscope.wiki.query`。

## 必须保持的不变量

- 遍历不跟随目录 symlink；文件 symlink 解析后越出 root 必须拒绝。
- 配置解析后的 `project.wiki.state_dir` 以受验证的 project-relative 动态 prune root 传入 discovery、manifest 与 source index；该目录及其子树不会进入语料、digest 或索引，即使其名称不是默认 `.zscope_knowledge`。
- `.git`、`.zscope_knowledge`、扫描输出、Wiki 输出、`AGENTS.md`、`GROUND_TRUTH.md`、生成报告和敏感文件不得进入 explanatory corpus；用户 override 不能删除 mandatory exclusion。
- `project.wiki.documents.exclude` 是 fail-closed 的项目相对 corpus 过滤器，必须同时作用于 Analyzer、Web 和 MCP 的 manifest/source-index；命中项保留 `user_excluded_path` descriptor，且 override digest 进入 manifest identity。
- 不确定分类 fail closed 为 `unknown`；同一路径不能同时成为 accepted source 和 excluded descriptor。
- `source_id` 由 project identity、source kind 和相对路径稳定计算，content digest 单独表示版本。
- direct fallback 只返回有来源的原文摘录；没有命中返回 `none`，不能从文档猜测 constraint，也不能改变 Validator verdict。
- active Wiki context 只消费当前 manifest pin 下 status=active、authority=documented_contract 且 source refs 可解析的 constraint；背景页本身不计作 Wiki 注入证据。
- `ProjectKnowledgeService` 在扫描开始时快照一个 active revision；并发 Validator worker 不得重新读取 active pointer。Validator cache identity 必须包含 project knowledge schema、mode、revision、manifest、context digest 和 ranking version。
- revision 发布失败或 Compiler unavailable 不切换 active pointer；Validator 记录 fallback reason 并回到 source-index direct fallback。
- `build_only` 在 manifest 改变时也必须发布 current revision，但不向 Validator 暴露 context；`auto_maintain + compiler_enabled` 可对 deterministic revision 做一次 LLM enrichment，已经是 LLM/mixed revision 且 manifest 未变时不得产生 revision churn。
- `audit-events.jsonl` 使用 `zscope.wiki-event.v1` 哈希链；每个事件的 `previous_event_digest` 必须连接前一事件，lint 必须检测断链。
- event replay 重建的 active revision 必须与 `active.json` 一致；`log.md` 必须与同一事件链的程序投影字节等价。
- `active.json`、revision metadata、source manifest、page/index/log 和 audit event 文件都按不可信磁盘输入处理：固定 revision ID、大小、UTF-8、symlink 和 state-root 路径边界，任何非法状态不得参与路径拼接。
- audit event replay 使用有界逐行读取；损坏链不能被下一次 append 重置为新链。lint 对 SQLite object 数量、JSON/Markdown 大小、错误输出和 disk/SQLite projection 执行固定上限。
- active/shadow 查询在运行时消费 revision 前必须通过完整 bounded lint；page/index/event 或 SQLite projection 被篡改时丢弃 Wiki snapshot，并保留 direct-source fallback。
- Compiler 一次 upsert 多个页面时，每个页面必须链接另一个本次修改页面；wikilink、Markdown source ref 和 index link 都只能指向同 revision 已授权对象。
- Web/MCP Wiki query 必须服从配置中的 project root、state dir、分类覆盖和资源/token 上限，且不得暴露 build、rollback 或任意文件读取能力。
- Wiki state directory 必须是 project-root 内不经过 symlink 的相对目录；status 只返回 bounded metadata projection，不返回绝对路径或内部异常文本。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_wiki_discovery.py tests/test_wiki_source_index.py
python -m pytest -q tests/test_wiki_schema_contract.py tests/test_agent_docs.py
python -m pytest -q tests/test_wiki_control.py tests/test_web_wiki_api.py tests/test_mcp_policy.py
python -m pytest -q tests/test_wiki_context_replay.py tests/test_wiki_maintenance.py
python -m pytest -q tests/test_wiki_compiler.py tests/test_wiki_revision_store.py tests/test_wiki_lint.py
```
