# 数据与接口契约

本文冻结2.0首版公共和内部契约的语义。字段级JSON Schema在相应实施阶段生成，不能改变本文的
权限边界和状态机。

## SecuritySpec v2

必需语义字段：

- `spec_uid`、`revision`、`kind`
- `subject`、精确符号签名和参数/返回槽
- `scope`：项目、模块、文件、函数或调用点
- `predicate`及有限DSL参数
- `evidence_refs`、`dependency_hashes`
- `origin`、`confidence`、`status`
- `conflicts`、`supersedes`

无可解析证据、scope为空或predicate不在注册表中的LLM输出只能成为observation。

## SecuritySpecReviewEvent

审阅事件不可变，至少包含：

- event/spec/revision UID
- reviewer identity、时间、理由
- action：approve-scoped、narrow、reject、defer、reverify、revoke
- before/after spec hash
- scope override和依赖影响摘要
- previous event hash

审阅不得改写程序事实。匿名或未认证Web会话只能读取和导出。

## SecurityHypothesis v2

必须包含：

- hypothesis/audit-unit UID
- defect family、subject、decision region
- source/sink或资源对象
- falsifiable positive/negative clauses
- 当前支持、反对、未知事实
- 可执行EvidenceAction IDs
- 结构化位置和证据引用

不完整hypothesis只能保存为coverage observation，不能进入Ledger。

## ProgramProofIR与证书

`ProofObligation`显式分为 confirmation、counterproof 和 open clauses；open clause 不产生 action 或 terminal contribution。`EvidenceAction`必须绑定固定subject/region、predicate和有限参数 schema。

P2 首批 predicate registry 的量词和 coverage 语义冻结如下；未列为 executable 的 predicate
只能返回 `unknown`，不能由模型文本、普通 repository tool observation 或相似名称推断：

| Provider family | 首批 executable predicate | 量词与完整性要求 |
|---|---|---|
| concurrency | `lock_must_hold_at_access` | `must_at_point`；对所有到达精确访问语句的 CFG 路径取 must 交集，锁对象和访问语句必须唯一。CFG、对象 identity 或动态边不完整时为 `unknown`。没有完整跨线程图时不得产生 `happens_before`。 |
| resource | `cleanup_covers_all_exits` | `for_all_exits`；绑定精确资源 identity 并枚举全部可达出口。存在未解析 alias、ownership transfer、wrapper、动态调用或出口时，全称 cleanup 结论为 `unknown`；具体未清理出口可作为存在性 witness。 |
| path/guard | `source_sink_path_exists`、`guard_dominates_sink` | 路径存在使用 `exists_path` 和具体相邻 CFG edge witness；不存在与 dominance 使用完整 CFG 的全称证明。dominance 只关闭结构 fact，不能替代 value-range 或安全 counterproof。 |
| contract/type | `external_entry_parameter_binding`、`record_layout_matches` | `exact_binding` / `exact_layout`；只接受冻结入口 identity、参数槽、Clang layout 和 dependency hash。缺少闭世界 caller、alias 或 ownership contract 时为 `unknown`。 |

严格字段级 schema 位于 `schemas/`。`ProgramProofIR v2`、`FunctionSecuritySummary`、
`ProofObligation`、`EvidenceAction v2`、`EvidenceCertificate v2` 和 `ProofCheckResult` 均使用
canonical JSON 内容寻址。内容 hash 不等于 proof：独立 Checker 必须从冻结 IR 重新计算 predicate，
并校验 action、clause、subject、region、量词、CFG 节点/边、出口集合、assumption allowlist 及
code/IR/backend/dependency hash。

`EvidenceCertificate v2`至少包含：

- certificate/action/verifier UID和版本
- status：verified_true、verified_false、unknown、conflicting
- predicate polarity和量词
- subject、decision region
- CFG节点/边、路径或全部出口集合
- assumptions、coverage和coverage completeness
- code、IR、backend和dependency hash
- content hash

只有`verified_true`且量词coverage完整的证书才能关闭clause。

缺少 `protocol_revision=2` 的早期同名 `EvidenceCertificate v2` 是 `legacy_preview`。compat 可以
展示其原始内容，但 live Proof Engine、closure、promotion 和 TerminalAuthority 必须拒绝它。

## TerminalAuthority

每个cluster只有一个终态权威事件：

- `CONFIRMED_DETERMINISTIC_PROOF`
- `CONFIRMED_VERIFIED_CLOSURE`
- `REJECTED_DETERMINISTIC_COUNTERPROOF`
- `NEEDS_REVIEW_OPEN_CLAUSES`
- `NEEDS_REVIEW_EVIDENCE_CONFLICT`
- `NEEDS_REVIEW_MODEL_REJECT_NO_PROOF`
- `NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE`

## WebUI API

- `GET /api/security-specs`
- `GET /api/security-specs/{spec_uid}`
- `POST /api/security-specs/{spec_uid}/reviews`
- `GET /api/security-specs/export?format=json|xlsx`
- `POST /api/security-specs/import`

JSON是规范归档格式。XLSX只用于离线批量审阅；导入必须校验spec revision、hash、字段白名单和
reviewer identity，过期或冲突版本不得覆盖现状。

## Compatibility

历史报告、配置和Benchmark artifact通过只读compat层加载。compat对象不得进入live SecuritySpec、
Proof Engine或promotion路径，除非完成显式版本迁移和重新验证。
