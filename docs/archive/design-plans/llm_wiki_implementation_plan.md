# Z-SCOPE Karpathy LLM Wiki 接入实施计划

> **历史文档，2026-11-17 归档。** 原位置：`new_docs/stage3-llm-wiki/llm_wiki_implementation_plan.md`。本文保留 Wiki 接入时的设计与遗留事项，不代表当前配置或接口；其中 v2 配置文件、测试路径及 `project.root` 均为历史引用。当前职责与入口见[LLM Wiki](../../modules/wiki.md)，当时实施过程见[Wiki 实施记录](../implementation/llm-wiki.md)。未完成目标需结合现行实现重新确认。

**状态**：架构与实施计划

**方法论**：[`llm-wiki.md`](../../research/llm-wiki-method.md) 中的 Karpathy LLM Wiki 方法论

**首期输入**：从配置解析后的 project.root 递归发现的 Markdown 说明性文档

**首期消费方**：validator_agent

**目标**：把项目/模块文档中的约束编译为持久的 Constraint projection，并在验证候选时提供相关约束；Wiki Compiler LLM 不可用时，直接从同一批原始文档中检索。

**当前实现决策（2026-08）**：运行时只保留结构化 `ProjectConstraint`，不再把 LLM 生成的 Markdown 页面作为 Validator 知识层。LLM 只提交最小语义 proposal；ID、scope、authority、status、revision、digest、去重和 stale 传播均由程序生成。本文早期章节中的“生成页面”“page_excerpts”“page_changes”等设计均由本节及第 7 节之后的 Constraint-only 契约取代。

---

## 1. 执行摘要

Z-SCOPE 增加一个位于原始项目文档与 Validator 之间的知识编译层。系统从 project.root 开始递归发现 .md 和 .markdown 文件，使用程序规则区分说明性文档、生成物、运行时指令、评测答案、敏感内容和未知文件。只有说明性文档进入知识语料。原始文档只读；Wiki Compiler LLM 只负责从有界原文中提取约束语义；程序负责身份、引用、权限、schema、lint、版本、日志和原子发布。

Validator 不遍历整个 Wiki，也不在每个候选上重新总结所有文档。构建或维护 Constraint projection 后，ProjectKnowledgeService 根据候选的文件、模块、函数、API、资源、锁、缺陷类型和 missing fact，选取少量 active、documented_contract 约束和来源引用，作为可选的 project_knowledge 加入现有 ValidatorEvidenceSlice v3。

降级路径与 Wiki Compiler LLM 解耦。文档发现、分类、Markdown 分节和本地索引均由程序完成。Compiler 因关闭、认证、限流、网络、超时、schema 或模型错误不可用时，DirectDocumentResolver 在已接受的原始文档章节中做确定性检索，返回带相对路径、标题、行号和 digest 的原文摘录。若 Validator 自身的 LLM 不可用，继续遵循现有失败或 needs_review 语义；文档检索不能伪装成验证。

Wiki 是项目约束上下文层，不是第二套漏洞证明系统：

1. 原始说明性文档是输入，Wiki 是可重建派生物。
2. CodeIndex、KnowledgeDB、deterministic proof、candidate evidence 和 Validator protocol 仍是漏洞判断的权威边界。
3. 文档可以说明 API 值域、前置条件、所有权、锁协议和模块边界，但不能单独证明当前代码路径满足这些条件。
4. 没有文档、没有命中、Wiki 过期或构建失败都不能被解释为候选成立或不成立。
5. 冲突、过期和不确定内容必须显式保留。
6. 首期不引入向量数据库、远程搜索服务或网络抓取。

---

## 2. 方法论映射

| Karpathy 概念 | Z-SCOPE 实现 |
|---|---|
| Raw sources | project.root 内通过策略接受的说明性 Markdown；只读、带 digest |
| Wiki | .zscope_knowledge/wiki/revisions/ 下的 Constraint/ref 投影和审计 metadata；页面目录仅为旧 revision 兼容 |
| Schema | zscope/agents/wiki_compiler/AGENT.md + program-owned JSON schemas |
| Ingest | 发现、分类、分节、索引、LLM 约束提取、程序物化、校验、暂存、发布 |
| Query | 候选义务解析后查询结构化约束；无有效约束时直接搜索原文 section |
| Lint | 引用、链接、孤立页、冲突、freshness、路径、安全、语言和预算检查 |
| index.md | 内容导向导航，程序校验闭包和 metadata |
| log.md | 程序根据结构化事件生成的追加日志，LLM 不直接写入 |
| Query result filing | 只有有来源且可复用的项目知识进入后续维护，不自动把单次 verdict 写回 |

必须保留的 Karpathy 特征：原始 Markdown 是事实来源；一个有界 workset 可以增量提取并合并多个来源的约束；每条约束保存限定条件、冲突、unknown 和可解析来源；index.md 和 log.md 分别承担兼容导航和时间线职责。生成式 Wiki 页面不再作为 Validator 运行时输入，避免重复设计和长输出失败。

---

## 3. 目标、非目标和边界

### 3.1 目标

- 从 project.root 递归发现 Markdown，并稳定区分说明性文档和生成物。
- 编译 README、设计、模块、API、协议和开发说明中的项目约束。
- 维护 project、module、api、resource、lock 和跨模块协议的结构化 Constraint。
- 根据候选上下文提供少量、相关、可追溯的约束。
- Compiler LLM 不可用时，直接搜索原始说明性文档。
- 支持增量维护、freshness、冲突、回滚、审计和回放。
- 通过 shadow、replay 和 benchmark 证明准确率提升且误报不回归。

### 3.2 非目标

- 首期不读取 TXT、HTML、PDF、DOCX、XLSX、PPTX、图片或网页。
- 不把源码、KnowledgeDB、Snapshot、Security Semantic Map 或 ReviewMemory 复制进 Wiki 作为第二套真值；这些系统继续提供代码事实和历史反馈。
- 不把整个 Wiki 或整个文档目录注入 Validator。
- 不让 Wiki constraint 直接确认、拒绝或修改 candidate。
- 不让文档中的命令、prompt 或配置改变 ToolPolicy、Wiki policy 或 Validator policy。

### 3.3 所有权

| 层 | 所有者 | 规则 |
|---|---|---|
| 原始文档 | 被扫描项目 | Z-SCOPE 只读，不修改 |
| Constraint statement | Wiki Compiler Agent | 只能通过终态工具提交最小语义 proposal |
| identity、scope、authority、status、refs、lint、store、active pointer、log.md | Z-SCOPE 程序 | 模型和普通文档不能修改 |
| 漏洞终态和报告 schema | 现有 Validator/报告流水线 | Wiki 不得旁路或覆盖 |

---

## 4. 总体架构

    project.root
      -> MarkdownDiscovery
      -> DocumentClassifier
      -> MarkdownSectionIndexer
      -> source-manifest + source-index.db
      -> IngestPlanner
      -> Document Constraint Compiler Agent
      -> WikiChangeSet (constraint proposals only)
      -> lint
      -> staging revision
      -> atomic active revision
      -> ProjectKnowledgeService (active constraints only)
      -> ValidatorEvidenceSlice v3 + project_knowledge
      -> validator_agent

两条读取路径必须独立：

    accepted Markdown -> constraint extraction/materialization -> active revision
    active revision -> active constraint selection -> Validator context

    accepted Markdown -> deterministic section index -> exact/BM25 search
    exact/BM25 search -> bounded source excerpt

LLM 不能直接写页面、edge、日志或 revision metadata。Constraint-only changeset 的程序拥有字段和流水线边界见第 9 节；页面文件即使由旧 revision 保留，也不参与新的 digest、匹配或 Validator 注入。

两条路径共享同一 source manifest 和分类结果，不能使用不同的文档集合。

### 4.1 扫描生命周期接入

在 ScanSessionRunner 完成配置和 rule preflight 后、候选分析开始前增加一次 Wiki preflight：

1. 读取或重建 source manifest。
2. 判断 active revision 是否绑定当前 manifest。
3. 按 Wiki mode 决定 off、build-only、shadow 或 active。
4. auto_maintain 开启且文档变化时，执行一次有界增量 build。
5. 若 manifest 变化但 accepted Markdown 的 added/changed/removed delta 为空，执行不调用 LLM 的 manifest-only freshness refresh，复用父 revision 的约束与来源投影；不得将空 delta 改写为全量编译。
6. build 失败不阻断扫描，记录事件并使用 direct source fallback。
7. 注入只读 ProjectKnowledgeService；并行入口共享同一 pinned revision、source index 和查询缓存。

不得在每个入口或候选上重复扫描文档、创建 store 或调用 Compiler。

---

## 5. Markdown 发现和分类

### 5.1 发现规则

MarkdownDiscovery 必须使用 config.project.project_root.resolve() 作为唯一根：

- 递归发现 .md 和 .markdown，记录 project-root 相对 POSIX 路径。
- 不跟随目录 symlink；文件 symlink 解析后越出 project.root 必须拒绝。
- 先执行目录剪枝和 mandatory policy，再打开文件。
- 限制单文件大小、总文件数、总字节数；超限记录 skip reason。
- 只接受 UTF-8；非法编码不转码。
- 目录和文件按规范化相对路径排序，确保 manifest digest 稳定。
- 遍历前剪枝 .git、Z-SCOPE state/output、Wiki revision/staging 和构建缓存，防止自摄取。

### 5.2 分类

| 分类 | Wiki | direct search | 含义 |
|---|---:|---:|---|
| explanatory | 是 | 是 | README、架构、模块、API、协议、设计和运维语义 |
| generated_artifact | 否 | 否 | 报告、运行输出、覆盖率、profile、模型输出和自动汇总 |
| runtime_instruction | 否 | 否 | AGENTS、CLAUDE、GEMINI、SKILL、Agent prompt、workflow 指令 |
| benchmark_truth | 否 | 否 | ground truth、答案、评分说明、预期漏洞清单 |
| sensitive_rejected | 否 | 否 | secret、Authorization、私有响应、原始 chain-of-thought |
| unknown | 否 | 否 | 无法可靠判断，fail closed |
| unsupported | 否 | 否 | 非 Markdown，只统计扩展名，不读取正文 |


弱特征不能覆盖 mandatory exclusion。每个 descriptor 保存 classification_reason、命中规则和 content digest。

### 5.3 Mandatory exclusions

至少排除：

- .git、.zscope_knowledge、.zscope_snapshots、扫描输出和构建缓存。
- GROUND_TRUTH.md、benchmark answer、评分和 ablation truth。
- report、batch report、SARIF 运行投影、logs、conversation、model trace 和生成汇总。
- AGENTS.md、CLAUDE.md、GEMINI.md、SKILL.md 及 zscope/agents 下的 AGENT.md。
- vendored dependency、包缓存和第三方生成目录。
- Wiki active、revisions、staging、quarantine、index.md 和 log.md。
- 命中 secret、完整认证头、私有 endpoint 响应或原始 reasoning 的文件。

用户只能增加排除项或在非 mandatory 范围内指定 explanatory/generated，不能删除以上规则。

### 5.4 分类 override

配置示例：

    project:
      wiki:
        documents:
          exclude:
            - legacy/generated/**
          classify:
            explanatory:
              - docs/contracts/**/*.md
            generated:
              - artifacts/**/*.md

glob 必须是 project-root 相对路径，不含 ..；同一路径同时命中 explanatory 和 generated 时配置失败。override digest 进入 source manifest 和配置 identity。

### 5.5 分类策略

对每个候选 Markdown 按以下顺序执行，命中后原则上停止继续降级判断：

1. **路径安全和格式检查**：检查扩展名、root 内路径、symlink、UTF-8、文件大小和 mandatory 目录；失败分别归类为 `unsupported`、`sensitive_rejected` 或跳过 reason。
2. **强制排除**：命中 truth、runtime instruction、Wiki/output、依赖缓存或其他 mandatory pattern 时，直接归类，不允许 frontmatter 或用户 override 覆盖。
3. **程序 provenance**：读取受限 frontmatter 和首部生成标记。`generated_by`、`artifact_kind`、`source_manifest_digest`、`do_not_edit` 或 Z-SCOPE 注册的 producer identity 能证明文件是生成物时，归类为 `generated_artifact`。
4. **显式文档契约**：`zscope_document.kind: explanatory` 或 `zscope_document.kind: generated` 可以在非 mandatory 范围内给出明确结果；值非法、重复或与用户 override 冲突时，分类失败为 `unknown`，不能猜测。
5. **已知文件/目录契约**：项目 README、docs/architecture、docs/modules、API/协议目录可以作为说明性正向证据；固定报告路径、coverage/profile/trace 目录可以作为生成物证据。这里的文件名只是契约的一部分，不是单独的通用规则。
6. **内容辅助特征**：统计 generated 标记、机器字段、重复时间戳、候选/指标表、token/latency 字段、自动汇总格式和“不要编辑”等特征。内容特征只能在达到明确阈值并且没有相反强证据时使用，不能凭一个关键词分类。
7. **用户追加 override**：只在前述规则没有形成 mandatory 结论时生效，且必须是 project-root 相对 glob。override 只解决项目特有的已知目录，不改变全局分类语义。
8. **不确定处理**：仍无明确结论，归类为 `unknown`，同时不进入 Wiki 和 direct-source index。

### 5.6 分类输出

每个 descriptor 至少写入：

- `classification` 和 `classification_reason`；
- `matched_rules`，按优先级稳定排序；
- `override_id`（如果使用了用户规则）；
- 文件 size、content digest、source manifest sequence 和 observed timestamp。

不得把完整敏感正文或模型原始输出写入分类事件。分类结果进入 source-manifest 和 `classification_events`，使后续维护能回答“为什么这个文件被接受/排除”。

### 5.7 典型结果

| 文件 | 结果 | 原因 |
|---|---|---|
| `README.md` | explanatory | 项目说明文件契约，且无生成 provenance |
| `docs/api.md` | explanatory | API 文档目录和规范性章节匹配 |
| `docs/api.generated.md` | generated_artifact | frontmatter 声明 producer/artifact_kind |
| `artifacts/scan-report.md` | generated_artifact | 输出目录契约，即使正文可读 |
| `AGENTS.md` | runtime_instruction | mandatory 文件名/运行时指令契约 |
| `GROUND_TRUTH.md` | benchmark_truth | mandatory benchmark truth 契约 |
| `notes.md` | unknown | 没有足够 provenance 或稳定内容证据 |

`unknown` 不是错误报告，也不是“按默认说明文档处理”。它是保护性状态：记录原因、允许用户通过受限 project-relative override 重新分类，并在 manifest 中统计，防止不确定内容污染 Validator。

---

## 6. 原始文档模型和索引

### 6.1 DocumentSource schema

`DocumentSource` 是一个文件级不可变来源描述。`source_id` 只由 project identity、source kind 和 project-relative path 计算，不包含 content digest；文件更新通过 `content_digest` 变化表示。

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "zscope.document-source.v1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema_version", "source_id", "project_id", "source_kind",
    "relative_path", "content_digest", "size_bytes", "classification",
    "classification_reason", "input_language", "module_hints",
    "observed_at"
  ],
  "properties": {
    "schema_version": {"const": "zscope.document-source.v1"},
    "source_id": {"type": "string", "pattern": "^docsrc_[a-z0-9_:-]+$"},
    "project_id": {"type": "string", "minLength": 1, "maxLength": 160},
    "source_kind": {"const": "markdown_document"},
    "relative_path": {"type": "string", "pattern": "^(?!/)(?!.*\\.\\.)(?:[^/]+/)*[^/]+$"},
    "content_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "size_bytes": {"type": "integer", "minimum": 1, "maximum": 10485760},
    "classification": {"const": "explanatory"},
    "classification_reason": {"type": "string", "enum": [
      "explicit_project_readme", "explicit_document_contract",
      "explanatory_path_contract", "explanatory_override",
      "content_explanatory_threshold"
    ]},
    "input_language": {"type": "string", "enum": ["zh-CN", "en", "mixed", "unknown"]},
    "module_hints": {"type": "array", "maxItems": 32, "uniqueItems": true, "items": {"type": "string", "pattern": "^module:[a-z0-9_.:/-]+$"}},
    "frontmatter": {"type": "object", "additionalProperties": true, "maxProperties": 64},
    "observed_at": {"type": "string", "format": "date-time"}
  }
}
```

被排除或不支持的文件不伪装成 `DocumentSource`，而使用第 6.4 节的 manifest descriptor 记录；不会把敏感正文写入任何 descriptor。manifest 中的排除项使用 `descriptor_id`，不复用 accepted `source_id`。

### 6.2 DocumentSection schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "zscope.document-section.v1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema_version", "section_id", "source_id", "heading_path",
    "heading_level", "start_line", "end_line", "text_digest",
    "excerpt", "symbols", "module_hints", "normative_terms", "link_targets"
  ],
  "properties": {
    "schema_version": {"const": "zscope.document-section.v1"},
    "section_id": {"type": "string", "pattern": "^docsec_[a-z0-9_:-]+$"},
    "source_id": {"type": "string", "pattern": "^docsrc_[a-z0-9_:-]+$"},
    "heading_path": {"type": "array", "minItems": 1, "maxItems": 8, "items": {"type": "string", "minLength": 1, "maxLength": 240}},
    "heading_level": {"type": "integer", "minimum": 1, "maximum": 6},
    "start_line": {"type": "integer", "minimum": 1},
    "end_line": {"type": "integer", "minimum": 1},
    "text_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "excerpt": {"type": "string", "minLength": 1, "maxLength": 8192},
    "symbols": {"type": "array", "maxItems": 128, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 240}},
    "module_hints": {"type": "array", "maxItems": 32, "uniqueItems": true, "items": {"type": "string", "pattern": "^module:[a-z0-9_.:/-]+$"}},
    "normative_terms": {"type": "array", "maxItems": 64, "uniqueItems": true, "items": {"type": "string", "enum": ["must", "must_not", "shall", "shall_not", "required", "only", "should", "recommended", "range", "ownership", "lock", "error"]}},
    "link_targets": {"type": "array", "maxItems": 128, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 512}}
  }
}
```

解析器只接受 UTF-8 Markdown，支持 frontmatter、ATX/Setext heading、表格、列表、引用、fenced code 和同仓相对链接；不执行代码、不抓取外链。`start_line <= end_line`，section 之间不得出现重叠范围；超大 section 按子标题、段落和表格边界切分。

### 6.3 source-index.db schema

`source-index.db` 与 `wiki.db` 分离。以下 SQLite schema 是固定的；除 SQLite 自己的 `sqlite_sequence` 外，不允许额外业务表：

```sql
CREATE TABLE documents (
  source_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  relative_path TEXT NOT NULL UNIQUE,
  content_digest TEXT NOT NULL,
  size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
  input_language TEXT NOT NULL CHECK (input_language IN ('zh-CN','en','mixed','unknown')),
  module_hints_json TEXT NOT NULL,
  frontmatter_json TEXT NOT NULL,
  observed_at TEXT NOT NULL
);

CREATE TABLE sections (
  section_id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL REFERENCES documents(source_id) ON DELETE CASCADE,
  heading_path_json TEXT NOT NULL,
  heading_level INTEGER NOT NULL CHECK (heading_level BETWEEN 1 AND 6),
  start_line INTEGER NOT NULL CHECK (start_line > 0),
  end_line INTEGER NOT NULL CHECK (end_line >= start_line),
  text_digest TEXT NOT NULL,
  excerpt TEXT NOT NULL,
  symbols_json TEXT NOT NULL,
  module_hints_json TEXT NOT NULL,
  normative_terms_json TEXT NOT NULL
);

CREATE TABLE links (
  source_id TEXT NOT NULL REFERENCES documents(source_id) ON DELETE CASCADE,
  target TEXT NOT NULL,
  link_kind TEXT NOT NULL CHECK (link_kind IN ('relative_markdown','anchor','mailto','external_url')),
  PRIMARY KEY (source_id, target, link_kind)
);

CREATE TABLE classification_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  relative_path TEXT NOT NULL,
  classification TEXT NOT NULL CHECK (classification IN ('explanatory','generated_artifact','runtime_instruction','benchmark_truth','sensitive_rejected','unknown','unsupported')),
  reason TEXT NOT NULL,
  matched_rules_json TEXT NOT NULL,
  content_digest TEXT,
  observed_at TEXT NOT NULL
);
```

启用 FTS5 时只创建固定的 `sections_fts(section_id UNINDEXED, heading_text, excerpt, symbols_text)` 虚表；不支持 FTS5 时使用等价的内存倒排索引，查询结果必须遵守同一排序和预算规则。

### 6.4 source-manifest.json schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "zscope.document-source-manifest.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "project_id", "project_root_digest", "scanner", "accepted", "excluded", "unsupported_extensions", "override_digest", "source_manifest_digest", "created_at"],
  "properties": {
    "schema_version": {"const": "zscope.document-source-manifest.v1"},
    "project_id": {"type": "string", "minLength": 1, "maxLength": 160},
    "project_root_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "scanner": {"type": "object", "additionalProperties": false, "required": ["discovery_version", "classifier_version", "parser_version"], "properties": {
      "discovery_version": {"type": "string", "minLength": 1},
      "classifier_version": {"type": "string", "minLength": 1},
      "parser_version": {"type": "string", "minLength": 1}
    }},
    "accepted": {"type": "array", "items": {"$ref": "zscope.document-source.v1"}},
    "excluded": {"type": "array", "items": {"type": "object", "additionalProperties": false, "required": ["descriptor_id", "relative_path", "classification", "reason"], "properties": {
      "descriptor_id": {"type": "string", "pattern": "^docdesc_[a-z0-9_:-]+$"},
      "relative_path": {"type": "string"},
      "classification": {"type": "string", "enum": ["generated_artifact","runtime_instruction","benchmark_truth","sensitive_rejected","unknown"]},
      "reason": {"type": "string", "minLength": 1},
      "content_digest": {"type": ["string","null"], "pattern": "^sha256:[0-9a-f]{64}$"}
    }}},
    "unsupported_extensions": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}},
    "override_digest": {"type": ["string","null"], "pattern": "^sha256:[0-9a-f]{64}$"},
    "source_manifest_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "created_at": {"type": "string", "format": "date-time"}
  }
}
```

`accepted` 数组中的每一项必须通过 `zscope.document-source.v1`；`excluded` 数组中的每一项只能通过上述排除项 descriptor schema。两类数组不能共享同一个 `relative_path` 的 current accepted 状态。

计划中的 JSON 代码块已同步落成为 `zscope/wiki/schemas/*.schema.json`。文件名和 `$id` 的唯一映射记录在 `zscope/wiki/schemas/schema-registry.json`；实现校验器时先加载 registry，再以 schema `$id` 解析 `$ref`，禁止通过网络解析外部 URI。计划代码块与文件必须保持字典等价，漂移由 `tests/test_wiki_schema_contract.py` 检测。

---

## 7. 当前 Constraint-only 数据模型

### 7.1 LLM proposal 与程序物化

LLM 终态工具名为 `emit_project_constraints`。工具参数只包含 `constraint_proposals` 数组；每条 proposal 只能提交以下六个语义字段，其中 `subject_kind` 使用固定 enum，`subject_id` 由模型生成并由程序校验。`schema_version` 不属于 final tool schema，由程序接收后补充为 `zscope.project-constraint-proposal.v1`。`summary` 也不属于 final tool schema，由程序根据 outcome、proposal 数量和 source results 确定性生成。不得提交 changeset 外壳、source results、outcome，也不得提交 `constraint_id`、`subject`、`scope`、`authority`、`status`、`source_manifest_digest`、`created_revision_id`、`normalized_value`、`page_refs` 或任何页面/edge 字段。

```json
{
  "subject_id": "api:parse_byte",
  "subject_kind": "api",
  "kind": "input_range",
  "statement": "parse_byte accepts values from 0 to 255.",
  "normativity": "required",
  "source_refs": ["docref_example"]
}
```

程序对 proposal 做 allowlist、source-ref、敏感内容、长度和 outcome 校验，然后生成完整 `zscope.project-constraint.v1`：稳定 `constraint_id`、subject kind、project/module scope、`authority=documented_contract`、`status=active`、当前 manifest digest、revision ID、去重和冲突关系。`normalized_value` 被明确移除；语义全部保留在 `statement` 中。

### 7.2 ProjectConstraint runtime contract

Validator 只接收 active 且至少有一个可解析 `source_ref` 的 Constraint。Constraint 的必需程序字段为：`constraint_id`、`subject`、`scope`、`kind`、`statement`、`authority`、`normativity`、`status`、`source_refs`、`conflicts_with`、`source_manifest_digest`、`created_revision_id`。stale、conflicted、retired 和无法解析来源的记录留在 revision/audit 中，但不进入 active Validator context。

### 7.3 Revision projection

每次成功 ingest 仍发布不可变 revision、`refs.json`、`constraints.json`、`source-manifest.json`、`revision.json`、`index.md` 和审计事件；新 revision 的 `pages/` 为空，`edges.json` 为空。旧 revision 的页面和可选历史字段只为读取/回放兼容，不参与新的 Constraint digest 或运行时匹配。

## 8. Wiki 数据模型（历史兼容说明）

以下旧版 schema 示例保留用于理解历史 revision 的读取兼容边界；实现和新数据以第 7 节及 `zscope/wiki/schemas/*.schema.json` 为准。

### 7.1 ProjectConstraint schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "zscope.project-constraint.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version","constraint_id","subject","scope","kind","statement","normalized_value","authority","normativity","status","source_refs","page_refs","conflicts_with","source_manifest_digest","created_revision_id"],
  "properties": {
    "schema_version": {"const": "zscope.project-constraint.v1"},
    "constraint_id": {"type": "string", "pattern": "^constraint_[a-z0-9_:-]+$"},
    "subject": {"type": "object", "additionalProperties": false, "required": ["kind","canonical_id"], "properties": {
      "kind": {"type": "string", "enum": ["project","module","api","symbol","resource","lock","type","configuration","topic"]},
      "canonical_id": {"type": "string", "minLength": 1, "maxLength": 300}
    }},
    "scope": {"type": "object", "additionalProperties": false, "required": ["project_id","module_ids","path_globs"], "properties": {
      "project_id": {"type": "string", "minLength": 1},
      "module_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^module:[a-z0-9_.:/-]+$"}},
      "path_globs": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^(?!/)(?!.*\\.\\.)"}}
    }},
    "kind": {"type": "string", "enum": ["module_boundary","public_api","entry_exposure","input_range","input_format","caller_precondition","return_contract","error_contract","nullability","size_contract","ownership_acquire","ownership_release","ownership_transfer","resource_lifecycle","requires_lock","protects_state","lock_order","threading_contract","configuration_constraint","sanitizer_or_guard","documented_exception","known_false_positive_pattern"]},
    "statement": {"type": "string", "minLength": 1, "maxLength": 2000},
    "normalized_value": {"type": ["object","array","string","number","boolean","null"]},
    "authority": {"const": "documented_contract"},
    "normativity": {"type": "string", "enum": ["required","recommended","descriptive","unknown"]},
    "status": {"type": "string", "enum": ["draft","active","stale","superseded","conflicted","quarantined","retired"]},
    "source_refs": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string", "pattern": "^docref_[a-z0-9_:-]+$"}},
    "page_refs": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^page_[a-z0-9_:-]+$"}},
    "conflicts_with": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^constraint_[a-z0-9_:-]+$"}},
    "source_manifest_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "created_revision_id": {"type": "string", "pattern": "^wikirev_[a-z0-9_:-]+$"},
    "supersedes": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^constraint_[a-z0-9_:-]+$"}}
  }
}
```

未知 `kind`、空 `source_refs`、`authority` 非 `documented_contract` 或 `status=active` 但无法解析 source ref 时拒绝发布。

### 7.2 DocumentRef schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "zscope.document-ref.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version","ref_id","source_id","relative_path","heading_path","start_line","end_line","source_digest","excerpt_digest","resolvable"],
  "properties": {
    "schema_version": {"const": "zscope.document-ref.v1"},
    "ref_id": {"type": "string", "pattern": "^docref_[a-z0-9_:-]+$"},
    "source_id": {"type": "string", "pattern": "^docsrc_[a-z0-9_:-]+$"},
    "relative_path": {"type": "string", "pattern": "^(?!/)(?!.*\\.\\.)(?:[^/]+/)*[^/]+$"},
    "heading_path": {"type": "array", "minItems": 1, "maxItems": 8, "items": {"type": "string", "minLength": 1}},
    "start_line": {"type": "integer", "minimum": 1},
    "end_line": {"type": "integer", "minimum": 1},
    "source_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "excerpt_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "resolvable": {"type": "boolean"},
    "excerpt": {"type": "string", "maxLength": 8192}
  }
}
```

`resolvable=true` 要求当前文件 digest、行区间和 excerpt digest 全部校验通过；否则 ref 只能用于 stale/quarantined 历史记录。

### 7.3 WikiEdge schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "zscope.wiki-edge.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version","edge_id","from_id","edge_type","to_id","source_refs","status"],
  "properties": {
    "schema_version": {"const": "zscope.wiki-edge.v1"},
    "edge_id": {"type": "string", "pattern": "^wikiedge_[a-z0-9_:-]+$"},
    "from_id": {"type": "string", "minLength": 1, "maxLength": 300},
    "edge_type": {"type": "string", "enum": ["documents","owns","depends_on","calls","acquires","releases","protects","constrains","conflicts_with"]},
    "to_id": {"type": "string", "minLength": 1, "maxLength": 300},
    "source_refs": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string", "pattern": "^docref_[a-z0-9_:-]+$"}},
    "status": {"type": "string", "enum": ["active","stale","conflicted","retired"]}
  }
}
```

### 7.4 WikiRevision schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "zscope.wiki-revision.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version","revision_id","parent_revision_id","project_id","source_manifest_digest","compiler","pages_digest","constraints_digest","edges_digest","lint","dirty_modules","created_at","active"],
  "properties": {
    "schema_version": {"const": "zscope.wiki-revision.v1"},
    "revision_id": {"type": "string", "pattern": "^wikirev_[a-z0-9_:-]+$"},
    "parent_revision_id": {"type": ["string","null"], "pattern": "^wikirev_[a-z0-9_:-]+$"},
    "project_id": {"type": "string", "minLength": 1, "maxLength": 160},
    "source_manifest_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "compiler": {"type": "object", "additionalProperties": false, "required": ["kind","identity","prompt_version"], "properties": {
      "kind": {"type": "string", "enum": ["deterministic","llm","mixed"]},
      "identity": {"type": "string", "minLength": 1, "maxLength": 240},
      "prompt_version": {"type": ["string","null"], "maxLength": 120},
      "model": {"type": ["string","null"], "maxLength": 160}
    }},
    "pages_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "constraints_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "edges_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "lint": {"type": "object", "additionalProperties": false, "required": ["status","errors","warnings"], "properties": {
      "status": {"type": "string", "enum": ["passed","failed"]},
      "errors": {"type": "integer", "minimum": 0},
      "warnings": {"type": "integer", "minimum": 0}
    }},
    "dirty_modules": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^module:[a-z0-9_.:/-]+$"}},
    "created_at": {"type": "string", "format": "date-time"},
    "active": {"type": "boolean"}
  }
}
```

只有 `lint.status=passed`、`lint.errors=0`、所有 current refs 可解析且 `active=true` 的 revision 才能被 `active.json` 指向。

---

## 8. 页面格式和信息架构

### 8.1 页面类型固定枚举

`page_kind` 只能取 `project_overview`、`module`、`api_contract`、`resource_protocol`、`lock_protocol`、`configuration`、`topic` 或 `source`。每个 active revision 必须有一个 `project_overview` 页面；每个已解析的 module 至少有一个 `module` 页面；其他类型按 constraint/edge 是否存在创建。

### 8.2 Page frontmatter schema

Markdown frontmatter 使用 YAML 序列化，但必须严格符合以下 JSON-compatible schema；frontmatter 不允许额外字段：

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "zscope.wiki-page-frontmatter.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version","page_id","page_kind","canonical_slug","title","project_id","module_ids","subject_ids","status","source_ids","constraint_ids","depends_on","generated_language","compiler_revision","content_digest"],
  "properties": {
    "schema_version": {"const": "zscope.wiki-page-frontmatter.v1"},
    "page_id": {"type": "string", "pattern": "^page_[a-z0-9_:-]+$"},
    "page_kind": {"type": "string", "enum": ["project_overview","module","api_contract","resource_protocol","lock_protocol","configuration","topic","source"]},
    "canonical_slug": {"type": "string", "pattern": "^(?!/)(?!.*\\.\\.)(?:[a-z0-9-]+/)*[a-z0-9-]+$"},
    "title": {"type": "string", "minLength": 1, "maxLength": 240},
    "project_id": {"type": "string", "minLength": 1, "maxLength": 160},
    "module_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^module:[a-z0-9_.:/-]+$"}},
    "subject_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 300}},
    "status": {"type": "string", "enum": ["active","stale","conflicted","retired","quarantined"]},
    "source_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^docsrc_[a-z0-9_:-]+$"}},
    "constraint_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^constraint_[a-z0-9_:-]+$"}},
    "depends_on": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^page_[a-z0-9_:-]+$"}},
    "generated_language": {"const": "zh-CN"},
    "compiler_revision": {"type": "string", "pattern": "^wikirev_[a-z0-9_:-]+$"},
    "content_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
  }
}
```

### 8.3 页面正文 schema

页面正文必须按以下固定顺序包含六个二级标题，标题文本不可变；每节正文可以是中文 Markdown，但不得包含 frontmatter 字段、Validator verdict 或未引用的 active constraint：

```yaml
body_schema: zscope.wiki-page-body.v1
required_headings:
  - "摘要"
  - "适用范围和模块边界"
  - "已声明约束"
  - "限定条件、例外和常见误报模式"
  - "冲突与未决问题"
  - "来源索引"
```

`已声明约束` 中的每个 active constraint 必须使用 `[constraint_<id>]`；`来源索引` 中的每个 source ref 必须使用 `[docref_<id>] path:start-end`。没有结构化约束的背景页面仍保留固定章节，但 `constraint_ids` 必须为空，且不得将普通背景句子提升为 constraint。

### 8.4 index.md schema

`index.md` 的 frontmatter 严格符合以下 schema，正文只能由程序从 active pages 和 Compiler 的中文摘要投影生成：

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "zscope.wiki-index.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version","project_id","revision_id","source_manifest_digest","generated_language","content_digest"],
  "properties": {
    "schema_version": {"const": "zscope.wiki-index.v1"},
    "project_id": {"type": "string", "minLength": 1, "maxLength": 160},
    "revision_id": {"type": "string", "pattern": "^wikirev_[a-z0-9_:-]+$"},
    "source_manifest_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "generated_language": {"const": "zh-CN"},
    "content_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
  }
}
```

正文固定包含“项目概览”“模块”“API 与协议”“资源与锁”“冲突与过期”“维护信息”六个二级标题；链接只能指向同一 revision 的 page slug。

### 8.5 log event schema

`log.md` 不是 LLM 输出文件。程序先写固定 JSON event，再按固定中文模板物化 Markdown：

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "zscope.wiki-event.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version","event_id","event_type","project_id","occurred_at","actor","status","payload_digest","previous_event_digest","event_digest"],
  "properties": {
    "schema_version": {"const": "zscope.wiki-event.v1"},
    "event_id": {"type": "integer", "minimum": 1},
    "event_type": {"type": "string", "enum": ["discover","ingest","build","lint","publish","rollback","maintenance","fallback"]},
    "project_id": {"type": "string", "minLength": 1, "maxLength": 160},
    "occurred_at": {"type": "string", "format": "date-time", "maxLength": 80},
    "actor": {"type": "string", "enum": ["program","wiki_compiler","system"]},
    "status": {"type": "string", "enum": ["started","succeeded","failed","quarantined","rolled_back"]},
    "payload_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "previous_event_digest": {"type": ["string","null"], "pattern": "^sha256:[0-9a-f]{64}$"},
    "event_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "revision_id": {"type": ["string","null"], "pattern": "^wikirev_[a-z0-9_:-]+$"},
    "workset_id": {"type": ["string","null"], "pattern": "^workset_[a-z0-9_:-]+$"},
    "fallback_reason": {"type": ["string","null"], "maxLength": 120}
  }
}
```

---

## 9. Wiki 编译与维护

> 2026-08-31 修订说明：本章早期草案中的页面生成和完整 Workset 输入契约已由当前 Constraint-only 实现取代。现行模型输入、字段映射和边界以文末“Compiler 输入投影”修订为准；完整 Workset 仍是程序内部校验与发布边界。

### 9.1 Wiki Compiler Agent

必须读取 workset 内的说明性 section 和 active pages；把新知识融入 project/module/API/resource/lock 页面；写中文 Markdown、维护 wikilink、保留限定条件、冲突和 unknown；提出带 source refs 的 constraint 和 edge；对不再支持的内容提出 stale/supersede。

不得输出 finding verdict、deterministic proof 或 candidate 修改；不得伪造 ref、subject、page identity 或 authority；不得摄取生成物、runtime instruction、truth 或敏感内容；不得修改 log.md、active pointer、SQLite、manifest 或 workset 外页面。

### 9.2 IngestWorkset schema

`IngestWorkset` 是程序创建的只读任务边界；Agent 只能访问其中列出的 source refs 和 active pages：

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "zscope.wiki-ingest-workset.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version","workset_id","project_id","base_revision_id","source_manifest_digest","added_source_ids","changed_source_ids","removed_source_ids","allowed_source_refs","source_ref_catalog","source_sections","allowed_subject_ids","limits","created_at"],
  "properties": {
    "schema_version": {"const": "zscope.wiki-ingest-workset.v1"},
    "workset_id": {"type": "string", "pattern": "^workset_[a-z0-9_:-]+$"},
    "project_id": {"type": "string", "minLength": 1},
    "base_revision_id": {"type": ["string","null"], "pattern": "^wikirev_[a-z0-9_:-]+$"},
    "source_manifest_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "added_source_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^docsrc_[a-z0-9_:-]+$"}},
    "changed_source_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^docsrc_[a-z0-9_:-]+$"}},
    "removed_source_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^docsrc_[a-z0-9_:-]+$"}},
    "allowed_source_refs": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^docref_[a-z0-9_:-]+$"}},
    "source_ref_catalog": {"type": "array", "maxItems": 4096, "items": {"$ref": "zscope.document-ref.v1"}},
    "source_sections": {"type": "array", "maxItems": 4096, "items": {"$ref": "zscope.document-section.v1"}},
    "allowed_subject_ids": {"type": "array", "maxItems": 4096, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 300}},
    "limits": {"type": "object", "additionalProperties": false, "required": ["max_constraints","max_wall_seconds"], "properties": {
      "max_constraints": {"type": ["integer", "null"], "minimum": 1},
      "max_wall_seconds": {"type": ["integer", "null"], "minimum": 1}
    }},
    "initial": {"type": "boolean"},
    "created_at": {"type": "string", "format": "date-time"}
  }
}
```

`added_source_ids`、`changed_source_ids` 和 `removed_source_ids` 不得交集；`allowed_source_refs` 必须来自这些 source ID。`initial` 是程序拥有的 bootstrap 标记。Agent 无权读任意路径、shell、网络或未发布 staging。

资源预算采用显式 opt-in：`project.wiki.compiler_max_tokens`、`max_wall_seconds` 和 `max_constraints` 默认均为 `null`，表示不施加对应 Wiki 局部上限。配置正整数时才收紧；`max_constraints` 同时限制 Compiler proposal 数量和项目 Wiki 数据库每个 revision 保存的 constraints 总数，Validator 每个候选由程序最多选择 20 条并记录 `omitted_constraint_count`，不依赖 schema 数组上限；`project_knowledge` 的 Wiki 与 direct source fallback 共用 4096 token 上限，调用方只能进一步收紧；`compiler_max_tokens=null` 仅表示 Compiler 不覆盖请求参数，仍保留 `llms.<profile>.max_tokens` 的通用单请求 completion 上限。Markdown 源文件大小只由 `project.wiki.max_file_bytes` 控制。大型文件采用 section 到临时 compiler chunk 的不重叠切分，chunk 并发数由 `concurrency.wiki_compiler_workers` 控制，默认 `4`；未知上下文窗口按 32K token 规划。

Direct source fallback 同样由程序对 ranked 摘录执行最多 20 条的运行时截断，并在 `omitted_source_excerpt_count` 中记录未注入的候选数量；该数量限制不由 schema 数组上限实现。

### 9.3 WikiChangeSet schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "zscope.wiki-changeset.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version","workset_id","base_revision_id","outcome","source_results","page_changes","constraint_proposals","edge_proposals","retire_proposals","unresolved_conflicts","summary"],
  "properties": {
    "schema_version": {"const": "zscope.wiki-changeset.v1"},
    "workset_id": {"type": "string", "pattern": "^workset_[a-z0-9_:-]+$"},
    "base_revision_id": {"type": ["string","null"], "pattern": "^wikirev_[a-z0-9_:-]+$"},
    "compiler": {"type": "object", "additionalProperties": false, "required": ["kind", "identity", "prompt_version"], "properties": {
      "kind": {"type": "string", "enum": ["deterministic", "llm", "mixed"]},
      "identity": {"type": "string", "minLength": 1, "maxLength": 240},
      "prompt_version": {"type": ["string", "null"], "maxLength": 120},
      "model": {"type": ["string", "null"], "maxLength": 160}
    }},
    "outcome": {"type": "string", "enum": ["changed","background_only","conflict_only","extraction_failed","source_rejected"]},
    "source_results": {"type": "array", "minItems": 1, "items": {"type": "object", "additionalProperties": false, "required": ["source_ref","extraction_status","source_refs_used","constraint_ids","reason"], "properties": {
      "source_ref": {"type": "string", "pattern": "^(docsrc|docdesc)_[a-z0-9_:-]+$"},
      "extraction_status": {"type": "string", "enum": ["constraints_found","no_constraints_found","background_page_updated","conflict_detected","extraction_failed","source_rejected"]},
      "source_refs_used": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^docref_[a-z0-9_:-]+$"}},
      "constraint_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^constraint_[a-z0-9_:-]+$"}},
      "reason": {"type": "string", "minLength": 1, "maxLength": 1000}
    }}},
    "page_changes": {"type": "array", "items": {"type": "object", "additionalProperties": false, "required": ["operation","page_id","source_refs_used"], "properties": {
      "operation": {"type": "string", "enum": ["upsert","retire"]},
      "page_id": {"type": "string", "pattern": "^page_[a-z0-9_:-]+$"},
      "markdown": {"type": "string", "minLength": 1, "maxLength": 1000000},
      "source_refs_used": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^docref_[a-z0-9_:-]+$"}},
      "reason": {"type": "string", "maxLength": 1000}
    }}},
    "constraint_proposals": {"type": "array", "items": {"$ref": "zscope.project-constraint.v1"}},
    "edge_proposals": {"type": "array", "items": {"$ref": "zscope.wiki-edge.v1"}},
    "retire_proposals": {"type": "array", "items": {"type": "object", "additionalProperties": false, "required": ["object_type","object_id","reason"], "properties": {
      "object_type": {"type": "string", "enum": ["page","constraint","edge"]},
      "object_id": {"type": "string", "minLength": 1},
      "reason": {"type": "string", "minLength": 1, "maxLength": 1000}
    }}},
    "unresolved_conflicts": {"type": "array", "items": {"type": "object", "additionalProperties": false, "required": ["subject_id","constraint_ids","reason"], "properties": {
      "subject_id": {"type": "string", "minLength": 1},
      "constraint_ids": {"type": "array", "minItems": 2, "uniqueItems": true, "items": {"type": "string", "pattern": "^constraint_[a-z0-9_:-]+$"}},
      "reason": {"type": "string", "minLength": 1, "maxLength": 1000}
    }}},
    "summary": {"type": "string", "minLength": 1, "maxLength": 2000}
  }
}
```

`page_changes.markdown` 只在 `operation=upsert` 时允许且必须存在；`operation=retire` 不得带 markdown。所有 source refs、page IDs、constraint subjects 和 edge endpoints 必须落在 Workset allowlist 或已发布 active revision 中。LLM 输出不得包含 finding verdict、deterministic proof、candidate 修改、active pointer、log.md 或任意文件操作。

ChangeSet 还必须执行以下跨字段不变量，不能只做逐字段 JSON Schema 校验：

| `outcome` | 必须满足 | 禁止内容 |
|---|---|---|
| `changed` | 至少一个 `page_changes`、`constraint_proposals`、`edge_proposals` 或 `retire_proposals` 非空；`source_results` 至少有 `constraints_found` 或 `background_page_updated` | `unresolved_conflicts` 可以非空，但冲突对象必须显式标记 conflicted |
| `background_only` | 所有 `source_results.extraction_status` 只能是 `no_constraints_found` 或 `background_page_updated`；`constraint_proposals=[]` | 不得生成 active constraint 或负面 Validator 证据 |
| `conflict_only` | `unresolved_conflicts` 非空；相关 constraint proposal 的 `status` 必须为 `conflicted` | 不得把同一冲突 slot 发布为 active |
| `extraction_failed` | `page_changes=[]`、`constraint_proposals=[]`、`edge_proposals=[]`、`retire_proposals=[]`；至少一个 source result 为 `extraction_failed` | 不得生成新的 Wiki 内容 |
| `source_rejected` | `page_changes=[]`、`constraint_proposals=[]`、`edge_proposals=[]`、`retire_proposals=[]`；所有 source result 的 `source_ref` 必须是 `docdesc_` | rejected descriptor 不得出现在 `allowed_source_refs` 或 active revision |

`source_ref=docsrc_...` 只能引用 accepted `DocumentSource`；`source_ref=docdesc_...` 只能引用 manifest 的排除项 descriptor。`source_rejected` 的 `source_refs_used` 必须为空；其他 outcome 不得使用 `docdesc_...`。这样 rejected descriptor 可以被审计，但不会把被拒绝文件伪装成可引用的说明性来源。

`outcome` 和 `extraction_status` 必须区分以下情况：

| 状态 | 含义 | Validator 行为 |
|---|---|---|
| `background_only` / `no_constraints_found` | 文档有效，但没有发现可结构化约束 | 不生成 constraint；可选维护 topic/module/source 页面，不产生负面证据 |
| `background_only` / `background_page_updated` | 文档没有约束，但对 Wiki 导航或背景页面有价值 | 只消费页面背景，不进入 `project_knowledge.constraints` |
| `conflict_only` | 发现约束，但同一 scope 的值无法裁决 | 约束保持 conflicted，只提供冲突摘要 |
| `extraction_failed` | 文档解析、模型输出或 ChangeSet 校验失败 | 不发布新内容，保留旧 active revision，必要时走 direct-source fallback |
| `source_rejected` | 文档被路径、敏感、truth 或 runtime-instruction 策略排除 | 不进入 Wiki 或 direct-source index |

`source_refs_used` 仍必须保留，用于证明来源确实被处理过；`constraint_ids=[]` 不表示项目不存在约束，只表示本次来源没有产生可结构化约束。若没有值得维护的背景页面，`page_changes` 可以为空，程序仍应记录 `constraints_created=0` 的结构化 build event。LLM 不得通过自然语言字段绕过上述状态机。

### 9.4 校验、暂存和发布

1. 校验 schema、workset identity 和输出边界。
2. 校验所有 page/source/ref/subject 均在 allowlist。
3. 归一化 constraint kind、scope、normativity 和 refs。
4. 检查中文页面、链接、路径、敏感内容和长度。
5. 合并未变页面，生成完整 staging revision。
6. 运行引用、冲突、freshness、孤立页、语言、安全和预算 lint。
7. 写入不可变 revision 和 manifest。
8. 用临时 DB 重建 active projection。
9. 最后原子替换 active.json。
10. 写结构化 publish event，再物化 log.md。

任何失败都保留旧 active revision；failed staging 只保存 digest、reason 和必要诊断，不能被 Validator 读取。

### 9.5 增量

按 stable source_id 和 digest 计算 source -> constraint -> page -> dependent page 的 dirty closure。新增来源创建相关 workset；修改来源只重建依赖页面；删除来源使唯一支持的 constraint stale；无法唯一映射 module 时使用 module:unknown；无关模块页面正文和 digest 保持不变。

每次扫描只调用一次 ensure_current。项目级 writer lock 防止并发构建；扫描 pin revision，运行中发布的新 revision 在下一次扫描生效。

---

## 10. Direct source fallback

### 10.1 触发条件

Compiler profile 未配置/关闭、认证/endpoint/限流/网络/超时/schema/模型错误、没有 active revision、manifest 不一致、revision/ref 校验失败、Wiki 无相关命中但原始文档有命中、或 context 超预算无法裁剪时，使用 source_fallback。

固定 reason code：compiler_disabled、compiler_unavailable、no_active_revision、stale_revision、invalid_revision、no_wiki_match、context_overflow。

### 10.2 候选查询构造

ConstraintObligationBuilder 从 candidate/evidence pack 提取 project、entry、function、relative file、确定性 module、source/sink/caller/callee、type、resource、lock、defect class、rule id 和 missing fact kind。无法确定 module 时保持 unknown，不猜唯一归属。

查询词按以下顺序构造：精确 symbol/API/config key；module/path heading；resource/lock/type；fact kind 同义词；低权重 defect family 词。value_range 可使用 range、min、max、长度、范围、上限、下限。

### 10.3 排序和预算

heading/frontmatter 精确 symbol 最高；其次是 module/path scope、正文精确 symbol、规范性 fact-kind 语句、BM25、链接图距离。降低只有通用安全词、只在代码示例、描述性弱约束和重复 section 的分数。source-index 返回的候选集不在 direct fallback 层预先按 20 条截断；ProjectKnowledgeService 对 ranked 摘录执行最多 20 条和共享 4096 token 预算的程序截断，并通过 `omitted_source_excerpt_count` 记录未注入数量。记录稳定 tie-break 和 ranking trace。

### 10.4 返回

source_fallback 返回 resolution_mode、source_manifest_digest、wiki_revision_id 为空、source_excerpts、ref_id、relative_path、heading_path、start_line、end_line、text、match_reasons、score、conflicts、unknowns、selected/omitted 和 fallback_reason。它返回原文，不从原文生成无引用 constraint。无命中返回 resolution_mode none 和 no_relevant_project_constraint，不能用低相关度内容填满预算。

Validator LLM 接收的 `project_knowledge` 是从上述完整对象派生的紧凑投影：顶层只保留 `resolution_mode`、`wiki_revision_id`、`target`、`constraints`、`source_excerpts`、`conflicts`、`omitted_constraint_count`、`omitted_source_excerpt_count` 和 `fallback_reason`；`target` 统一包含真实 `candidate_file`、`function_name`、`subject_ids` 和 `obligation_kinds`。后两者只从 candidate/evidence obligation 解析，禁止从 constraints 反向补充；每条 constraint 显式包含 `subject_kind`。manifest/context digest、selection 预算明细和其他完整性字段由程序保留，不进入模型输入。

上述紧凑投影同时包含 `omitted_source_excerpt_count`，用于区分“命中但因运行时预算未注入”的原文摘录与没有命中。

---

## 11. Validator 接入

### 11.1 ProjectKnowledgeService

提供只读接口：

    resolve_for_candidate(candidate, evidence_pack, max_tokens)
        -> ProjectKnowledgeContext

内部顺序：构造 ConstraintObligation；检查 active revision freshness；查询 active constraints/edges；选择 page excerpts；Wiki 无效或无命中时查询 source-index；校验 refs、digest、scope；应用预算和稳定排序；生成 context digest、selection trace 和 fallback reason。

### 11.2 当前代码接入点

- zscope/core/validation/evidence.py：保留现有 evidence pack 和 ValidatorEvidenceSlice v3，增加独立 project knowledge 构建器。
- zscope/core/validation/runner.py：在 _validator_input 构造 evidence slice 前调用 ProjectKnowledgeService，并记录 revision/context digest。
- zscope/agents/validator_agent/AGENT.md：增加文档约束 authority、freshness、conflict、unknown 和引用规则。
- zscope/common/validator_protocol.py：只增加可选字段，不改变现有 required result。
- zscope/config/v2.py 和 config.py：增加严格 project.wiki 配置和 project-root 相对路径解析。
- zscope/reporting：增加 Wiki attribution metadata，不复制页面正文。

### 11.3 project_knowledge schema

`project_knowledge` 是 `ValidatorEvidenceSlice v3` 内的可选字段，不复用 `semantic_claims`。它只传递候选相关的项目文档约束和有界摘录；完整 Wiki 页面、完整原始 Markdown 和 Wiki Compiler 原始响应都不得进入该字段。

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "zscope.validator-project-knowledge.v1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema_version", "resolution_mode", "project_id", "wiki_revision_id",
    "source_manifest_digest", "context_digest", "target", "constraints",
    "source_excerpts", "conflicts", "unknowns", "selection"
  ],
  "properties": {
    "schema_version": {"const": "zscope.validator-project-knowledge.v1"},
    "resolution_mode": {"type": "string", "enum": ["wiki", "source_fallback", "none"]},
    "project_id": {"type": "string", "minLength": 1, "maxLength": 160},
    "wiki_revision_id": {"type": ["string", "null"], "pattern": "^wikirev_[a-z0-9_:-]+$"},
    "source_manifest_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "context_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "target": {
      "type": "object",
      "additionalProperties": false,
      "required": ["module_ids", "subject_ids", "obligation_kinds", "candidate_file"],
      "properties": {
        "module_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^module:[a-z0-9_.:/-]+$"}},
        "subject_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 300}},
        "obligation_kinds": {"type": "array", "items": {"type": "string", "enum": ["module_boundary", "public_api", "entry_exposure", "input_range", "input_format", "caller_precondition", "return_contract", "error_contract", "nullability", "size_contract", "ownership_acquire", "ownership_release", "ownership_transfer", "resource_lifecycle", "requires_lock", "protects_state", "lock_order", "threading_contract", "configuration_constraint", "sanitizer_or_guard", "documented_exception", "known_false_positive_pattern", "unknown"]}},
        "candidate_file": {"type": "string", "pattern": "^(?!/)(?!.*\\.\\.)(?:[^/]+/)*[^/]+$"},
        "function_id": {"type": ["string", "null"], "maxLength": 300},
        "entry_function": {"type": ["string", "null"], "maxLength": 300}
      }
    },
    "constraints": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["constraint_id", "kind", "subject_id", "subject_kind", "statement", "authority", "normativity", "status", "source_refs"],
        "properties": {
          "constraint_id": {"type": "string", "pattern": "^constraint_[a-z0-9_:-]+$"},
          "kind": {"type": "string", "enum": ["module_boundary", "public_api", "entry_exposure", "input_range", "input_format", "caller_precondition", "return_contract", "error_contract", "nullability", "size_contract", "ownership_acquire", "ownership_release", "ownership_transfer", "resource_lifecycle", "requires_lock", "protects_state", "lock_order", "threading_contract", "configuration_constraint", "sanitizer_or_guard", "documented_exception", "known_false_positive_pattern"]},
          "subject_id": {"type": "string", "minLength": 1, "maxLength": 300},
          "subject_kind": {"type": "string", "enum": ["project", "module", "api", "symbol", "resource", "lock", "type", "configuration", "topic"]},
          "statement": {"type": "string", "minLength": 1, "maxLength": 1600},
          "authority": {"const": "documented_contract"},
          "normativity": {"type": "string", "enum": ["required", "recommended", "descriptive", "unknown"]},
          "status": {"const": "active"},
          "source_refs": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string", "pattern": "^docref_[a-z0-9_:-]+$"}}
        }
      }
    },
    "source_excerpts": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["ref_id", "relative_path", "heading_path", "start_line", "end_line", "text", "match_reasons", "score"],
        "properties": {
          "ref_id": {"type": "string", "pattern": "^docref_[a-z0-9_:-]+$"},
          "relative_path": {"type": "string", "pattern": "^(?!/)(?!.*\\.\\.)(?:[^/]+/)*[^/]+$"},
          "heading_path": {"type": "array", "minItems": 1, "maxItems": 8, "items": {"type": "string", "minLength": 1, "maxLength": 240}},
          "start_line": {"type": "integer", "minimum": 1},
          "end_line": {"type": "integer", "minimum": 1},
          "text": {"type": "string", "minLength": 1, "maxLength": 8192},
          "match_reasons": {"type": "array", "minItems": 1, "maxItems": 8, "uniqueItems": true, "items": {"type": "string", "enum": ["exact_symbol", "module_scope", "path_scope", "fact_kind", "resource_identity", "lock_identity", "bm25", "link_distance"]}},
          "score": {"type": "number", "minimum": 0}
        }
      }
    },
    "conflicts": {
      "type": "array",
      "maxItems": 8,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["subject_id", "constraint_ids", "reason", "source_refs"],
        "properties": {
          "subject_id": {"type": "string", "minLength": 1, "maxLength": 300},
          "constraint_ids": {"type": "array", "minItems": 2, "uniqueItems": true, "items": {"type": "string", "pattern": "^constraint_[a-z0-9_:-]+$"}},
          "reason": {"type": "string", "minLength": 1, "maxLength": 1000},
          "source_refs": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string", "pattern": "^docref_[a-z0-9_:-]+$"}}
        }
      }
    },
    "unknowns": {
      "type": "array",
      "maxItems": 8,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["kind", "subject_id", "reason"],
        "properties": {
          "kind": {"type": "string", "enum": ["missing_document", "ambiguous_module", "stale_source", "unresolved_scope", "unsupported_fact_kind"]},
          "subject_id": {"type": "string", "minLength": 1, "maxLength": 300},
          "reason": {"type": "string", "minLength": 1, "maxLength": 1000}
        }
      }
    },
    "selection": {
      "type": "object",
      "additionalProperties": false,
      "required": ["max_tokens", "estimated_tokens", "selected_constraint_ids", "omitted_constraint_count", "omitted_source_excerpt_count", "selected_source_ref_ids", "ranking_version", "fallback_reason"],
      "properties": {
        "max_tokens": {"type": ["integer", "null"], "minimum": 256, "maximum": 4096, "default": 4096},
        "estimated_tokens": {"type": "integer", "minimum": 0},
        "selected_constraint_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^constraint_[a-z0-9_:-]+$"}},
        "omitted_constraint_count": {"type": "integer", "minimum": 0},
        "omitted_source_excerpt_count": {"type": "integer", "minimum": 0},
        "selected_source_ref_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^docref_[a-z0-9_:-]+$"}},
        "ranking_version": {"type": "string", "minLength": 1, "maxLength": 120},
        "fallback_reason": {"type": ["string", "null"], "enum": ["compiler_disabled", "compiler_unavailable", "no_active_revision", "stale_revision", "invalid_revision", "no_wiki_match", "context_overflow", "no_relevant_project_constraint", null]}
      }
    }
  }
}
```

除 JSON Schema 外，还必须执行以下跨字段不变量：

| 条件 | 约束 |
|---|---|
| `resolution_mode=wiki` | `wiki_revision_id` 非空；`constraints` 可以非空；`fallback_reason` 为 `null` |
| `resolution_mode=source_fallback` | `wiki_revision_id=null`；`constraints=[]`；`source_excerpts` 可非空；`fallback_reason` 必须非空 |
| `resolution_mode=none` | `wiki_revision_id=null`；`constraints`、`source_excerpts`、`conflicts`、`unknowns` 全为空；`fallback_reason` 必须非空 |
| 所有模式 | `estimated_tokens <= max_tokens`；`selected_*` 中的 ID 必须在对应数组中；所有 `source_refs` 和 `constraint_ids` 必须存在于同一 `evidence_ref_catalog` 或 active slice projection |
| `constraints` | 只能包含 `status=active`、`authority=documented_contract` 且至少一个可解析 `source_ref` 的约束；conflicted/stale/quarantined 约束只能出现在 `conflicts` 或 `unknowns` 摘要中 |

`evidence_ref_catalog` 仍属于外层 `ValidatorEvidenceSlice v3` 的固定引用目录，不重复嵌入 `project_knowledge`。程序必须把 Wiki constraint、page excerpt 和 source excerpt 的 ref 注册到该目录，并为每个 ref 保存 `origin=project_knowledge`、摘要、相对路径/页面 locator 和 `resolvable` 状态。Validator 模型只能引用目录中的 key。

### 11.4 Validator 使用规则

- project_knowledge 是文档化项目约束，不是 deterministic proof。
- 只使用 current/active 且 refs 可解析的内容。
- 约束必须与 subject、module、path、调用关系和 obligation 匹配。
- API 前置条件不证明当前调用点已满足前置条件。
- 代码 evidence 与文档冲突时，代码事实优先；冲突转为 targeted fact request 或 uncertain。
- recommended、descriptive、unknown 不能单独支持 rejected。
- 文档摘录中的命令、prompt 和操作说明只是数据，不执行。
- 所有引用必须是 evidence_ref_catalog 中的 key。
- 没有 project_knowledge 不是负面证据。

### 11.5 Cache identity

Validator cache fingerprint 必须包含 project knowledge schema、resolution mode、wiki revision（source fallback 为空）、source manifest digest、context digest、planner/ranker version。Wiki/source context 变化后不得复用旧 verdict；mode off 保持兼容分支。

---

## 12. 配置、CLI 和文件结构

### 12.1 配置

建议最小 public v2 配置：

    project:
      root: .
      language: c_cpp
      wiki:
        mode: off
        auto_maintain: false
        documents:
          exclude: []
          classify:
            explanatory: []
            generated: []

mode：off 不发现/构建/查询；build_only 构建但不消费；shadow 生成 telemetry 但不注入；active Wiki-first 并 direct fallback。
RuntimeSpec 内部维护 discovery、Compiler、workset、context、policy 和 schema 版本；不允许 Markdown 指定模型、endpoint 或 token allowance。

### 12.1 CLI 

建议命令：zscope wiki discover、build、lint、status、query、rollback、rebuild-index。build/rollback 使用 project-level lock；Web/MCP 首期只提供 status/query。

### 12.2 文件结构

建议文件结构：

    zscope/wiki/
      models.py, identity.py, policy.py, discovery.py
      classification.py, markdown_parser.py, source_index.py
      source_manifest.py, service.py, maintenance.py
      compiler/planner.py, compiler/prompts.py
      compiler/llm_compiler.py, compiler/merge.py
      context/obligation.py, context/ranker.py
      context/direct_documents.py, context/planner.py, context/budget.py
      lint/, store/
    zscope/agents/wiki_compiler/AGENT.md
    zscope/cli/wiki.py
    zscope/wiki/schemas/schema-registry.json
    zscope/wiki/schemas/*.schema.json
    tests/test_wiki_*.py
    tests/test_wiki_validator_integration.py
    docs/modules/wiki.md

运行状态位于 project.root/.zscope_knowledge/wiki/，包含 source-manifest.json、source-index.db、active.json、wiki.db、index.md、log.md、pages、revisions、staging、quarantine 和 locks。

新增 zscope/wiki 顶层包时，按仓库契约在 docs/modules/README.md 和一份模块文档中登记一次，建议新增 docs/modules/wiki.md。

---

## 13. 注意事项

source-index.db 保存原始 Markdown 索引；wiki.db 保存 revisions、pages、constraints、refs、edges、conflicts、context cache 和 wiki_events。两者分离确保 Wiki 损坏或 Compiler 不可用时 direct fallback 仍可运行。

发布使用 staging、fsync、不可变 revision、临时 projection 和最后切换 active.json。失败时恢复旧 active；failed revision 不可读。

状态：current 可选入 context；stale 不入 active；superseded 不入默认 context；conflicted 只进入冲突摘要；quarantined 完全不可见。相同 constraint slot 的同值合并 refs，不同值保留冲突；LLM 不能静默删除另一方。

Markdown 是不可信数据。Compiler 无 shell、网络、任意写和 root 外读权限；ChangeSet 只能引用 workset catalog；外链不抓取；secret、Authorization、私有响应、完整 prompt、模型原始回复和 reasoning 不进 Wiki、log 或报告；GROUND_TRUTH、答案、评分和 ablation truth 在 discovery 前排除；Wiki/output 目录剪枝防止自摄取。

---

## 14. 实施顺序

### 阶段 0：契约和 fixture

冻结分类枚举、mandatory exclusions、schema、reason code 和目录布局。fixture 包含 README 值域、模块说明、冲突文档、生成报告、AGENTS、ground truth、secret 和 symlink。

### 阶段 1：发现、分类、分节、manifest

实现 discovery、classification、markdown parser、source manifest。验收重复 digest 稳定、mandatory exclusion 不可绕过、非法 UTF-8/越界 symlink/超大文件有 reason。

### 阶段 2：source-index 和 direct fallback

实现 source-index.db、FTS/倒排 fallback、ConstraintObligation、query terms、排序、预算和 excerpt。无任何 LLM 时能从 README 返回正确 API 值域、文件、标题、行号和 digest；无命中返回 none。

### 阶段 3：Wiki model、revision、页面骨架

实现 page/constraint/ref/edge/revision/change set schema、staging、lint、atomic publish、rollback、rebuild、event log。先生成 project/module 骨架，不启用 LLM synthesis。

### 阶段 4：Wiki Compiler Agent

实现 wiki_compiler AGENT、workset planner、strict ChangeSet、多页面中文 Markdown、引用 allowlist、quarantine 和有限格式修复。模型不能伪造 refs、越权访问、修改 log/active pointer、输出 verdict 或摄取生成物。

### 阶段 5：增量 freshness 和冲突

实现 dirty closure、source 删除/移动、stale/supersede/conflict、writer lock、scan-level revision pin 和 ensure_current。无关页面 digest 不变；stale/conflicted 不进入 current context。

### 阶段 6：Validator shadow

实现 Wiki-first ProjectKnowledgeService 和 source fallback。shadow 构造 context 但不注入模型，记录 selection、tokens、fallback、conflict。验收同一 candidate digest 稳定、现有输入和 verdict 不变。

### 阶段 7：Validator active

增加独立 project_knowledge.v1 和 catalog refs；更新 runner、slice budget、Agent contract、cache fingerprint 和 report attribution。Wiki 无效、过期、无命中或 Compiler 不可用时自动 direct fallback；文档前置条件不能单独 reject。

### 阶段 8：控制面、评估和灰度

完成 CLI status/lint/build/query/rollback/rebuild-index，Web/MCP 只读 query/status。运行 Control、direct docs、Wiki shadow、Wiki active、Wiki unavailable 五组 replay/A-B；按 off -> build_only -> shadow -> opt-in active -> 分桶灰度推进。

---

## 15. 测试和回归

发现/分类：嵌套 Markdown、CRLF、UTF-8、symlink、mandatory path、generated marker、frontmatter、unknown、override、report/Wiki/AGENTS/SKILL/truth/secret 隔离和 unsupported extension。

Parser/index：frontmatter、ATX/Setext heading、表格、列表、code fence、相对链接、section 行号/digest、FTS5 与 fallback 等价、删除无残留、自摄取防护。

Direct fallback：精确 API 优先、module/path/fact-kind 匹配、value_range 命中 README 0..255、401/429/timeout/malformed/client=None 仍返回原文、digest 变化使 cache 失效、无命中不生成推测。

Compiler/store/incremental：多页面更新、伪造 ref/authority/subject/path/verdict 拒绝、有限重试/quarantine、冲突保留、failpoint 恢复、rollback、DB rebuild、writer lock、dirty closure 和 log 幂等重建。

Validator：off 兼容、shadow 不注入、active 独立 project_knowledge、source ref 可进入 catalog、stale/conflicted 不作为支持或反证、文档前置条件不能单独 reject、裁剪不删除 proof/decision fact ID、context 变化使 cache 失效。

建议命令：

    python -m pytest -q tests/test_wiki_*.py
    python -m pytest -q tests/test_validator_evidence_slice.py tests/test_validator_v3_protocol.py
    python -m pytest -q tests/test_validation_runner.py tests/test_candidate_evidence.py
    python -m pytest -q tests/test_config_v2.py tests/test_cli_config_v2.py
    python -m pytest -q tests/test_agent_docs.py
    python -m compileall -f -q zscope scripts test tests

若出现与本功能无关的既有测试失败，遵守仓库交接要求，只修改本功能测试与实施记录，不回退用户手工文件或顺带修改无关产品逻辑。

---

## 16. 评估、灰度、风险和完成标准

固定同一源码 revision、配置、candidate ledger、后端、模型和 endpoint，比较 Control、Direct docs、Wiki shadow、Wiki active 和 Wiki unavailable。指标包括 verified precision、rejection precision、recall、F1、false-positive rate、跨模块准确率、uncertain missing-fact 质量、context 命中/引用、冲突/过期/no-hit、tokens、latency、direct search P50/P95、分类漏入和 fallback 成功率。

truth、secret 或 runtime instruction 泄漏；active revision 无法重建；ref 不可解析；atomic publish 失败；verified precision 下降；或 Wiki unavailable 不能 fallback，均立即停止灰度。误报下降不能通过隐藏 candidate 或制造大量 uncertain 获得。

完成标准：

- [x] project.root Markdown 发现、路径安全、UTF-8 和资源限制。
- [x] explanatory/generated/runtime_instruction/benchmark_truth/sensitive/unknown 分类和 manifest。
- [x] mandatory exclusions 无法由 public config 删除。
- [x] section parser、line locator、digest、source-index 可重建。
- [x] 不依赖 LLM 的 direct query 可返回候选相关原文。
- [x] page、constraint、ref、edge、ChangeSet、revision schema；已落盘为 `zscope/wiki/schemas/*.schema.json`，由 `schema-registry.json` 统一解析并由 `tests/test_wiki_schema_contract.py` 防漂移。
- [x] Compiler 按文档提取带 source ref 的结构化 Constraint；页面生成已从新 revision 和 Validator context 移除，程序负责 identity、scope、lint、stale 和发布。
- [x] 程序拥有 identity、authority、lint、publish、rollback、active pointer、log.md。
- [x] source 变更/删除传播 stale，冲突不静默覆盖。
- [x] Validator 使用独立 project_knowledge.v1，文档约束不能单独成为 proof。
- [x] Compiler/revision/Wiki 命中失败自动 direct fallback；Validator LLM 故障保留现有 needs-review 语义。
- [x] context budget、stable selection、cache fingerprint、attribution 和 fallback reason 可回放。
- [x] off/build_only/shadow/active、CLI status/query/build/lint/rollback/rebuild-index 可用。
- [x] 安全、truth、secret、prompt injection、自摄取和 symlink 测试通过。
- [x] `control/direct/shadow/active/unavailable` 五模式结构 replay 可离线执行，且显式证明未调用 LLM/benchmark。
- [ ] 真实 A/B 和正式 benchmark 达到 verified precision 不下降、误报降低门禁。
- [x] docs/modules/wiki.md、配置、CLI、迁移和实施记录同步。

## 17.TODO
 - Validator project_knowledge：完善 candidate 解析器，稳定填充 `target.module_ids`、`target.subject_ids` 和 `target.obligation_kinds`，覆盖函数、模块、文件、资源、锁及多义务候选；在解析失败时记录可审计的空值/unknown 语义。
 - 段落级Wiki更新：源文档删除把全部相关constraints记为stale，新增文档执行wiki_incremental。源文档修改只把删除/修改段落的constraints记为stale，修改/新增段落执行wiki_incremental。还要考虑到文档级增删改和段落级增删改同步发生的情况。
 - 目前constraints会无限增长，可每隔一段时间删除stale constraints。
