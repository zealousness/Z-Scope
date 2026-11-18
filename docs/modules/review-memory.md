---
doc_contract: zscope-module-v1
covers:
  - zscope/review_memory
sources:
  - zscope/review_memory/models.py
  - zscope/review_memory/schema.py
  - zscope/review_memory/schemas/schema-registry.json
  - zscope/review_memory/identity.py
  - zscope/review_memory/store.py
  - zscope/review_memory/extractor.py
  - zscope/review_memory/lifecycle.py
  - zscope/review_memory/matcher.py
  - zscope/review_memory/projector.py
  - zscope/review_memory/replay.py
  - zscope/cli/review_memory.py
  - zscope/web/services.py
  - zscope/core/validation/runner.py
  - zscope/config/config.py
  - zscope/config/support.py
tests:
  - tests/test_review_memory_acceptance_gaps.py
  - tests/test_review_memory_extractor_boundaries.py
  - tests/test_review_memory_lifecycle.py
  - tests/test_review_memory_replay.py
  - tests/test_validator_review_memory.py
  - tests/test_validator_replay.py
  - tests/test_validation_runner.py
  - tests/test_web_user_config_workbook_api.py
  - tests/test_config_options.py
  - tests/test_agent_docs.py
---

# Validator Review Memory

## 职责与非职责

`zscope/review_memory/` 保存人工拒绝 finding 的原始反馈，并将误报模式作为历史 advisory 上下文提供给 Validator。本文描述当前源码行为；设计目标与当前限制分开列出，不以实施记录中的阶段完成标记代替运行时事实。

三个相近模块的边界如下：

| 模块 | 所有权与用途 | 状态载体 |
|---|---|---|
| `zscope/review_memory/` | ReviewRecord、模式提议、历史提示、抽取任务和回放记录 | 独立项目级 `review-memory.db` 和 JSON/JSONL |
| `zscope/memory/review_memory.py` | 既有 baseline/suppression 反馈门面 | `UserConfigStore`；归属[配置、语义与状态](configuration-state.md) |
| `zscope/wiki/` | 项目说明文档与约束上下文，不承载误报模式 | Wiki revision；归属[LLM Wiki](wiki.md) |

本模块不生成候选、不替代源码索引、不改变 Validator verdict、不生成 deterministic rejection proof，也不向 `finding_suppressions` 写入模式。精确人工 rejected 仍按原反馈流程保存 baseline/suppression；这不是误报模式的自动抑制权限。

## 主入口和数据流

```text
Web save_validation_feedback
  └─ persist_validation_feedback
       ├─ 既有 baseline / suppression
       └─ rejected → ReviewRecord
       └─ auto_extract worker / CLI extract
                             └─ 程序型 proposal / LLM 语义提议
                                  └─ qualification → advisory
                                       └─ matcher → projector
                                            └─ Validator v3 evidence_slice.review_memory
```

- `ReportFeedbackService` 在 `project.review_memory.mode != off` 时尝试创建 Store。当前归档位于既有 user-config 反馈持久化分支内，没有 `user_config_store` 时会提前返回。
- 只有 rejected 更新生成 ReviewRecord；有 `user_rebuttal` 时状态为 `pending_extraction`，无说明时为 `insufficient`。Web 请求不调用抽取 LLM。
- 归档分支异常进入 `review_memory.errors`，不回滚已执行的 baseline/suppression 写入。Store 初始化异常当前只使 Store 不可用，未逐条回传初始化错误。
- `extraction=auto_extract` 时，`extract/active` 保存反馈后自动创建并消费后台任务；`async_cli` 保留手动 CLI 抽取。
- Validation runner 仅在 `mode=active` 时查询模式；查询异常记 debug 日志，继续原验证路径。

单条成功归档的反馈响应包含：

```json
{
  "review_memory": {
    "recorded": true,
    "records": 1,
    "review_id": "review_...",
    "extraction_status": "pending_extraction",
    "items": [{"review_id": "review_...", "extraction_status": "pending_extraction"}],
    "errors": []
  }
}
```

批量响应以 `items` 表达逐条结果；顶层 `review_id`、`extraction_status` 仅在成功归档一条时提供。

## 数据模型与源码所有权

| 对象 | 主要字段 | 边界 |
|---|---|---|
| ReviewRecord | `review_id`、`project_id`、`finding`、`candidate_snapshot`、`candidate_projection`、`user_rebuttal`、`source_context`、`evidence_refs`、`repository_identity`、`status`、`created_at` | Candidate 快照和人工说明不得被抽取器覆盖；projection 由程序按稳定字段契约生成 |
| PatternProposal | `pattern_id`、`scope`、`match_contract`、`contract_digest`、兼容的 `trigger_features`、`false_positive_reason`、`required_checks`、`counter_conditions`、引用、源指纹、来源 review IDs、`generator`、状态和时间 | match contract 由 Candidate 已有字段组成；LLM 只能选择程序提供的谓词，不能发明路径或值 |
| PatternMatch | pattern/scan/issue 身份、`match_basis`、`source_compatible`、`injected`、`validator_status`、成本、`overturned` | Store 可持久化；当前 CLI replay 写入的是投影记录，不是实际 Validator 调用回执 |
| extraction job | `job_id`、`review_ids`、`status`、`attempts`、`error`、时间 | 独立 SQLite 表，不属于 Wiki revision |

`identity.py` 用规范排序 JSON 的 SHA-256 前缀生成 review/pattern ID，时间采用 UTC。Web review ID 的输入含项目、issue ID、dedup key 和 rebuttal；pattern ID 由项目、scope 和规范化 match contract 派生，因此相同模式可合并不同 review event。当前 `project_id()` 优先使用配置 ID，否则回退项目路径，不等于完整 Git 仓库身份校验。

`save_record()` 对同一 review ID 禁止修改项目、finding、原始 rebuttal、源码上下文、引用、仓库身份和创建时间；抽取状态、错误等可更新。当前 Web 从 finding 现有字段复制 snippet/fingerprint/refs，`repository_identity` 写为空对象；它没有重新从源码文件读取、核验引用或自动补全 Git 身份。

## Store、Schema 与审计

默认目录相对 YAML 所在工程目录：

```text
.zscope/review-memory/
├── review-memory.db          # records / proposals / matches / extraction_jobs
├── active.json               # advisory pattern IDs、revision、digest、更新时间
├── records/<review_id>.json
├── proposals/<pattern_id>.json
├── audits/events.jsonl       # event、at、prev_hash、event_hash 与事件载荷
├── replays/<scan_id>.jsonl   # save_match 追加记录
└── exports/                 # 预建目录；CLI export 使用显式 --output
```

- Store 拒绝绝对 `state_dir`、`..`，并对解析后的状态根检查 project-root 包含关系。不要据此推断所有子路径都具备抗 symlink 竞态保护。
- records/proposals/active JSON 使用临时文件替换；SQLite 写入、JSON 发布、审计追加是分开的步骤，不构成跨介质事务。`active.json` 不是完整不可变 revision 快照。
- 每次保存 proposal 都重建 advisory 集合摘要并递增 active revision；非 advisory proposal 保存也会触发 revision 变化。
- Schema registry 独立于 Wiki，登记 review record、pattern proposal、pattern match 和 operation 四份 schema。`validate_registered()` 检查 schema ID 与文件 `$id`；安装 `jsonschema` 时执行 Draft 2020-12 校验，未安装时只保留手写校验，不能宣称完整 schema 校验始终启用。
- `append_audit()`、`verify_audit_integrity()` 位于 `store.py`；`audit.py` 目前只是说明入口。hash chain 可检查事件链一致性，但不是签名或可信时间证明。事件未保存全部对象快照，不能单凭事件链重建完整状态。
- `export_json()` 返回 records、proposals、matches、jobs、active 与 audit integrity；应连同原始数据库和 JSON 状态备份，而不是将摘要当作恢复机制。

## 抽取与生命周期

`proposal_from_record()` 从 Candidate JSON 的程序稳定字段投影生成 `match_contract`。支持函数名、history/candidate identity、root cause、source/sink/resource identity、candidate kind/source 和其他已注册枚举字段。contract 的 groups 为 OR，每组的 all 谓词为 AND；函数名可以产生函数级命中，root-cause/语义字段可以跨函数复用。`candidate_id`、位置、代码片段和自由文本只用于审计。旧的 `trigger_features` proposal 仍按旧逻辑读取。

`extract_with_llm()` 使用 `LLMClient.chat_completion` 请求 JSON，补充原因、检查条件、反例条件和候选特征。LLM 引入原记录之外的 evidence ref 会被拒绝；不在程序特征白名单中的 `(kind, value)` 被标成 `matchable=false`。CLI 使用 `llms.default`，模型和 extractor version 写入 `generator`。原始 rebuttal 保留在 ReviewRecord 中。

当前 qualification 要求：项目非空、状态为 `proposed/advisory`、至少一个非空 matchable feature、非空 evidence refs，以及 required checks 或 counter conditions 至少一项非空。它尚不核验引用是否可解析、规则版本或特征真实性；不要把它等同于完整设计门禁。

- 单条记录抽取成功后变为 `extracted`，失败变为 `proposal_failed` 并保存错误；默认跳过失败和已抽取记录。`--retry-failed` 仅重试 `proposal_failed`，`--retry-all` 强制重新抽取所有选中的最新记录；两者不能同时使用。`superseded` 记录始终排除，不会被任何抽取模式重新处理。
- 无 rebuttal 的记录不调用 LLM 抽取，CLI 会生成程序型 proposal；模式不会因归档本身获得 advisory 权限。
- Pattern schema 接受 `pending_extraction`、`proposal_failed`、`proposed`、`semantic_only`、`advisory`、`stale`、`disabled`、`deprecated`，但 Store 尚非严格的状态迁移图。
- `enable` 调用 qualification；目前 `disabled/stale` 不在 qualification 允许状态内，不能把 `enable` 当作通用恢复开关。
- `stale` 显式修改一个模式；`refresh-stale --fingerprint` 将源指纹与给定全集无交集的 advisory 模式标为 stale。不要只传单个 finding 的指纹冒充项目当前完整集合。
- jobs 使用 `pending/running/completed/failed`。当前没有 worker lease、并发领取和崩溃自动恢复；不要并行执行同一 job。客户端初始化失败和尝试次数回写等路径仍需更完整的治理。

## Validator 匹配、预算与缓存

runner 从 Store 读取当前项目 proposal，再由 `match_patterns()` 筛选 advisory。新 contract 严格比较 project、rule、rule revision、category/defect class 和 Candidate schema scope；所有 required predicates 必须满足，groups 之间取 OR。函数名既可作为精确条件，也可与语义字段组合。新 contract 不把 source context fingerprint 作为跨函数必需条件；它仍用于兼容性/stale 管理。历史无 contract proposal 保留原 source fingerprint 兼容行为。

matcher 只比较 Candidate 已存在且注册的规范化字段，不在扫描时计算新的 AST/CFG，也不采用自然语言相似度。每个 finding 默认最多 3 个 hint，projector 继续执行 token budget，命中永远标记 `authority=advisory`。

`project_hints()` 输出 `zscope.validator-review-memory.v1`，含 `authority: advisory`、`hints` 与候选/选中/省略数量、token budget。当前固定最多 3 条，按 JSON 字符数除以 4 估算单条成本；超预算停止选择。该估算不是模型 tokenizer 计数，也未包含完整封套开销。

runner 在整体 evidence slice 拟合前附加 hints；默认 hint budget 1200，整体 slice 上限 12000。当前未动态强制“最多 10%”，提高配置预算可能突破该比例。`max_patterns_per_finding=0` 的 matcher 早退也尚未完善，不能依赖它独立关闭注入；关闭功能应使用 `mode=off`。

cache identity 包括 Review Memory schema、project ID、active revision/digest 和 active pattern IDs；目前不是单 finding 的 selected pattern 集合，也没有独立 source-compatibility digest。查询与 cache 读取不是同一原子快照。

必须保持的语义边界：历史模式只能提示重新检查；当前源码证据优先，不能仅凭命中模式拒绝 finding、生成 proof、跳过 Validator 或写 suppression。`validator_agent/AGENT.md` 中的 Review Memory 规则属于产品运行时契约。

## 配置与 CLI

以下是合并到现有 `config_version: 3` YAML 的项目配置片段，不是完整配置文件：

```yaml
project:
  review_memory:
    mode: off
    state_dir: .zscope/review-memory
    project_scope: project
    extraction: auto_extract
    llm_enabled: true
    max_patterns_per_finding: 3
    max_context_tokens: 1200
    stale_on_source_drift: true
    allow_direct_suppression: false
```

`off` 关闭 Web 归档和 Validator 注入；`archive` 只归档；`extract` 自动抽取但不注入；`active` 自动抽取并增加 advisory 注入。`extraction=async_cli` 时不自动消费任务。数量/token 非负，scope/extraction 固定取值，direct suppression 永远不得开启。

实际命令入口是 `zscope-review-memory`，不是 `zscope review-memory`。以下占位 ID 需替换为 list/proposals/jobs 返回值：

```bash
zscope-review-memory -c zscope.yaml list
zscope-review-memory -c zscope.yaml show REVIEW_ID
zscope-review-memory -c zscope.yaml extract --review-id REVIEW_ID
zscope-review-memory -c zscope.yaml extract --review-id REVIEW_ID --retry-failed
zscope-review-memory -c zscope.yaml extract --review-id REVIEW_ID --retry-all
zscope-review-memory -c zscope.yaml extract --enqueue
zscope-review-memory -c zscope.yaml jobs
zscope-review-memory -c zscope.yaml extract --job-id JOB_ID
zscope-review-memory -c zscope.yaml proposals
zscope-review-memory -c zscope.yaml enable PATTERN_ID
zscope-review-memory -c zscope.yaml disable PATTERN_ID
zscope-review-memory -c zscope.yaml stale PATTERN_ID
zscope-review-memory -c zscope.yaml replay PATTERN_ID --input report.json --output replay.json
zscope-review-memory -c zscope.yaml export --output review-memory.json
```

所有命令显式指定配置。YAML 父目录是唯一工程根，跨目录执行宜使用绝对配置路径；工程内相对路径从该目录解析，不再填写独立根目录字段。`--enqueue` 只存任务，需另行执行 `--job-id`；没有自动消费。`extract` 可能向配置模型服务发送完整 ReviewRecord（含 snippet 和人工说明），并非所有源码都只留本机。导出文件同样可能包含敏感源码，应在发送、共享或提交前审查。

## Replay 与测量边界

`review_memory.replay.paired_replay()` 读取报告 `issues/findings`，比较历史状态与假想 hint 投影，输出 `mode=offline_paired_projection`、`validator_invoked=false`、`verdict_changed=false`。CLI 经统一报告读取层支持传统 JSON 和共享对象存储封套，可写 JSON 结果，并保存命中 PatternMatch。

`potential_false_suppression` 统计命中且历史状态为 validated/confirmed/true_positive 的项，不是实测误抑制；`pattern_overturn_count` 当前按命中且 rejected/false_positive、有 rebuttal 的项计数，不等于模式被人工推翻。CLI match 的 `injected/overturned` 也来自投影/历史状态，不能作为实际 Validator 遥测。该回放不验证输入报告项目身份，运行前必须人工确认项目归属。

另有 `zscope/benchmarking/replay_bundle.py` 的构建期 `review_memory` 可选字段，参与 group/bundle hash，并由 `validator_replay.py` 投影给 executor。当前它把同一 projection 复制到各 group，不执行逐 finding 匹配或完整 advisory 校验；哈希绑定不代表内容获得 proof 权限。Review Memory CLI 尚未串联该 executor 做 baseline/advisory 成对执行，不能把离线投影称为真实 Validator paired replay。相关独立执行协议见[Benchmark 模块](benchmarking.md)。

## 常见变更应落到哪里

- 数据契约与身份：`models.py`、`schemas/`、`schema.py`、`identity.py`。
- 持久化、任务、发布与审计：`store.py`；不要写入 Wiki 或既有 baseline 数据库。
- LLM 语义抽取与激活门禁：`extractor.py`、`lifecycle.py`。
- 模式选择与上下文预算：`matcher.py`、`projector.py`；接入点在 validation runner。
- 反馈 API：`web/services.py`；CLI 命令：`cli/review_memory.py`。
- 抽取 Agent 契约位于 `zscope/agents/review_memory/AGENT.md`；CLI 使用 compact extraction projection，并通过 `emit_review_pattern` final tool 提交。final tool/schema 校验失败最多重试两次，LLM 网络重试仍由共享 `LLMClient` 管理。
- CLI 抽取通过共享 conversation recorder 将完整 LLM 会话归档到
  `<YAML 所在工程目录>/.zscope_conversations/`，与其他 Agent 使用相同的 JSONL/Markdown
  格式；`records/` 和 `proposals/` 仍分别保存原始反馈与结构化抽取结果。
- 公共配置：`config/config.py`、`config/v3.py`、`config/support.py`；不要向用户 YAML 暴露 RuntimeSpec 私有字段。
- 运行时能力变化同步本文及对应跨模块文档；本次文档建立不修复上述实现限制。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_agent_docs.py
python -m pytest -q tests/test_review_memory_acceptance_gaps.py tests/test_review_memory_extractor_boundaries.py tests/test_review_memory_lifecycle.py tests/test_review_memory_replay.py tests/test_validator_review_memory.py
python -m pytest -q tests/test_config_options.py tests/test_web_user_config_workbook_api.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_validator_replay.py
```

这些测试是定向契约/回归入口，不代表所有设计门禁或生产安全已验收；不需要启动 benchmark 扫描。

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`；架构位置见[架构文档](../architecture.md)。
- 反馈接口见[接口与报告](interfaces-reporting.md)，Validator 决策边界见[分析流水线](analysis-pipeline.md)。
- 既有 baseline/suppression 见[配置、语义与状态](configuration-state.md)；Wiki 语义见[LLM Wiki](wiki.md)。
- [实施记录](../archive/implementation/review-memory.md)保留历史阶段，本模块文档以当前源码为准。
