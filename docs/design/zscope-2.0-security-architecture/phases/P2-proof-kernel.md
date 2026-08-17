# P2：Proof Kernel

## 目标

建立模型不能绕过的程序验真内核，先用通用 fixture 证明 soundness，再以 shadow 接入产品流水线；P2 不转移稳定产品终态权威，P5 才能执行 cutover。

## 进入条件

- P1完成。
- Decision Trace和冻结policy replay可用。
- 四个首批provider family的量词和coverage语义已在contracts中冻结。
- ADR-0007、字段级schema和上述分族语义通过`proof_security`只读预审；预审前阶段保持`pending`。

## 工作包

1. 定义ProgramProofIR、ProofObligation、EvidenceAction、EvidenceCertificate和ProofCheckResult schema。
2. 实现独立Proof Checker和内容寻址证书存储。
3. 实现并发、资源、路径/guard、contract/type provider。
4. 统一V0、RequiredFactPlan、V1/V2、V3和TerminalAuthority。
5. 迁移alert-verify到同一终态语义。
6. 为证书、代码hash、CFG边、scope和量词添加篡改检测。

## 当前实施状态

- ADR-0007 和六份严格 schema 已冻结，contract-freeze `proof_security` 预审 approved；阶段为 `in_progress`。
- 有限 registry 只登记可执行谓词；其他 predicate 保持 non-executable/unknown。Provider 只提出证书，独立 Checker 是 accepted fact 的唯一来源。
- ProgramProofIR、ProofObligation（confirmation/counterproof/open 三类 clause）、EvidenceAction、EvidenceCertificate、ProofCheckResult 与不可变 CAS 已实现；早期同名证书只作 `legacy_preview`。
- V0/RequiredFactPlan、V1/V2、V3 和 alert-verify 记录同一 shadow lifecycle；RequiredFactPlan 的派生事实即使被 Checker 接纳也不产生 terminal contribution，alert 缺少冻结 IR 时 shadow 明确 fail-closed。稳定 Candidate Ledger outcomes、Finding-root 投影和产品终态不变，source-to-evidence gate 固定 `proof_kernel_mode=shadow`。
- answer-free corpus 已冻结为 120 项：四个 family 各 10 正例、20 near-miss，80 个 safe case；本机 Clang 21.1.8 source-to-IR baseline 另行冻结。完整门禁与 DeepSeek-V4-Pro Max `final_soundness` 只读审核均已通过且无 blocking finding，P2 标记 complete；Proof Kernel 仍保持 shadow，P5 之前不得取得产品终态权威。

## 通用fixture资格

每个predicate family至少10个正例、20个near-miss反例，并覆盖rename、wrapper、宏/等价分支重排。
fixture不得使用Range函数、truth ID或独有常量。

## 验收

- 100%模型接纳事实具有可重放证书。
- safe corpus false acceptance为0。
- coverage不完整的全称命题只能unknown。
- proof冲突不由模型投票。
- 完整proof后LLM/tool调用数为0。
- 每个terminal cluster只有一个TerminalAuthority事件。
- policy replay和原终态一致。

## 停止与回退

伪造证书能够晋级、模型文本能够直接写fact、proof后继续调用或通用safe corpus退化时立即停止。
Range分数变化不得用于豁免soundness门禁。
