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

P3 首版 DSL registry 固定为 13 个 predicate，`kind` 必须与 `predicate` 相同：

| family | predicate | 严格参数 |
|---|---|---|
| dataflow | `source` / `sink` | 精确 source/sink slot 与有限 label |
| dataflow | `propagate` / `sanitize` | 非空 from slots、精确 to slot 与有限 label |
| resource | `acquire` / `release` | 精确 resource slot 与有限 resource kind |
| resource | `transfer` | 精确 resource slot 与不同的有限 from/to owner |
| concurrency | `lock` / `unlock` | 精确 lock slot 与有限 lock mode |
| protocol | `state_transition` / `sentinel` | 精确 state/value slot、结构化值与有限 sentinel meaning |
| callback/contract | `callback_retains` | 精确 callback/retained slots 与有限 lifetime |
| callback/contract | `caller_contract` | 精确 target slots 与有限 caller requirement |

slot 只能是 `parameter:N`、`return`、`receiver` 或精确 `field:...`。registry 不接受脚本、
正则、查询代码、自由 predicate 或自然语言条件。LLM 只能从系统给出的 subject、scope、
evidence、predicate 和 slot ID 中选择，且最高状态为 `proposed`。

状态转换固定为 `observation -> proposed -> verified_scoped -> project_active -> stable`；
异常状态为 `conflicting / rejected / quarantined`。`project_active` 和 `stable` 必须绑定单一
review 或 qualification authority，不能同时绑定二者。P5 live只把qualification-backed `stable`
规格的最高有效revision编译为authoritative输入；冲突、过期依赖和不可解析evidence一律不编译。SecuritySpec、review event、
qualification、compiled spec 和 archive 均使用 strict schema、canonical JSON 和 SHA-256 内容寻址。

## SecuritySpecReviewEvent

审阅事件不可变，至少包含：

- event/spec/revision UID
- reviewer identity、时间、理由
- action：approve-scoped、narrow、reject、defer、reverify、revoke
- before/after spec hash
- scope override和依赖影响摘要
- previous event hash

审阅不得改写程序事实。匿名或未认证Web会话只能读取和导出。

P3 Web 服务器没有可信 reviewer identity，`REVIEWER_IDENTITY_MODE` 固定为
`unavailable_read_only`。review POST 和 apply-import 必须返回
`403 reviewer_identity_unavailable`；import 只允许严格 dry-run 校验与影响预览，不能持久化。

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

P4 首版把模型权限进一步冻结为“选择而非构造”。程序先生成内容寻址的
`AttackSurfaceAuditUnit v2`、`LocalizedCoverageKey v2` 和 `HypothesisOffer v2`。每个 offer
已经绑定精确 defect family、subject、decision region、结构化位置、`ProofObligation`、有限
`EvidenceAction v2`、证据和依赖 hash。Hunter 的严格输出只包含 audit-unit identity、选中的
offer/action/fact/evidence ID、coverage status 和 unresolved reason；它不能提交自由 predicate、
参数、coverage 声明、候选状态或终态。

系统从已验证的 offer 与选择结果物化 `SecurityHypothesis v2`。未知、重复、跨 obligation 或
内容不一致的 action ID 使该选择整体失败；缺 location、subject、region、证据或有效 action 的
输出只形成`HypothesisCoverageObservation v1`。P5中合格hypothesis通过`CandidateRegistrar`
写入live Ledger时必须强制未确认；Hunter不能提交candidate状态或terminal disposition，只有后续
Proof Engine可关闭该candidate。

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

P5的`TerminalAuthorityDecision v3`还必须绑定重新校验的Checker result refs、proof root和
`integrity_status=verified`。模型verdict、旧proof字段、legacy certificate、Validator v2或compat
bridge都不能关闭candidate。完整required executable clause集合中任一缺少Checker结果时只能
`needs_review`；结果存在也不等于clause已关闭，只有Checker重新计算后
`status=accepted`且certificate状态为`verified_true`才能关闭对应clause。required clause若不在
executable registry、未被选择、Checker返回unknown/conflicting/rejected，均必须保持
`needs_review`，尤其不得把unknown counterproof解释为counterproof不存在。

## RuntimeAuthorityManifest v1

每次live run绑定source tree、effective config、backend、SecuritySpec/Hunter/Proof root、
registry/checker/provider revision、Decision Trace schema、`zscope.runtime-authority.p5` cache epoch和
内容hash。resume/maintain遇到旧epoch、缺manifest、manifest/hash不一致或terminal trace不完整时
必须重新扫描，不能把历史report或snapshot迁移成新证据。

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
