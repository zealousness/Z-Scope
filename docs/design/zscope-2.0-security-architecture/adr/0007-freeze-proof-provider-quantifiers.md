# ADR-0007：冻结首批 Proof Provider 的量词与 Coverage 语义

- 状态：accepted-for-design-candidate
- 日期：2026-08-17
- 影响阶段：P2、P5、P6

## 背景

ADR-0003 已确定内部 Proof Kernel、可重放证书和独立 Checker 的权限边界，但
`contracts.md` 尚未逐类冻结并发、资源、路径/guard、contract/type provider 的量词和
coverage 语义。P2 的进入条件因此不能仅靠现有 shadow 实现或测试数量推定满足。

## 决策

首批 provider 使用有限 predicate registry。每个 predicate 固定 provider family、fact kind、
量词、允许参数、coverage domain 和 fail-closed 条件；模型不能新增 predicate、参数、assumption
或 coverage 声明。

1. 并发 provider 首批资格化 `lock_must_hold_at_access`。它对所有到达目标访问语句的 CFG 路径
   做 must 分析，要求精确访问语句和锁对象身份。没有完整跨线程图时，局部语句顺序不得生成
   `happens_before` 证书。
2. 资源 provider 首批资格化 `cleanup_covers_all_exits`。它对精确资源身份和全部可达出口做全称
   分析；未解析 alias、transfer、wrapper、动态调用或出口会使全称结论为 `unknown`。
3. 路径/guard provider 首批资格化 `source_sink_path_exists` 和 `guard_dominates_sink`。存在性结论
   必须携带具体路径 witness；不可达和 dominance 等全称结论要求完整 CFG。dominance 不能替代
   value-domain proof。
4. contract/type provider 首批资格化 `external_entry_parameter_binding` 和
   `record_layout_matches`。它只接受可重放的入口绑定、Clang record layout 和冻结依赖；全局
   caller contract、field-sensitive alias 或 ownership contract 缺少闭世界事实时保持
   `unknown`。

`EvidenceCertificate v2` 只有在独立 Proof Checker 从冻结 `ProgramProofIR v2` 重新计算后才能
产生可关闭 clause 的 `ProofCheckResult`。只重算内容 hash、接受模型文本或信任 provider 的
`verified_true` 均不构成检查。

## 兼容性与阶段边界

- 早期缺少 `protocol_revision=2` 的同名证书归类为 `legacy_preview`，只读展示，不能进入 live
  closure 或 promotion。
- P2 只资格化上述有限 predicate；未资格化 predicate 必须显示为 non-executable/unknown。
- P2 完成后 Proof Kernel 仍保持 `shadow`。只有 P5 可以申请运行时 authority，且必须有
  source-to-evidence 门禁阻止提前切换或用户配置绕过。
- Java Preview 在 P2 只验证 schema 通用性与 fail-closed，不用不完整 provider 产生终态。

## 审核与停止条件

本 ADR 和对应 schema 必须先由 `proof_security` 角色只读批准，P2 才能从 `pending` 进入
`in_progress`。若伪造证书可晋级、全称命题在 coverage 不完整时关闭、模型文本可生成 fact，
或 P5 前可切换 authority，则本决策未通过。
