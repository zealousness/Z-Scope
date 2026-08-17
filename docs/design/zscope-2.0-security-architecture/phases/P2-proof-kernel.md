# P2：Proof Kernel

## 目标

建立模型不能绕过的程序验真和统一终态权威，先用通用fixture证明soundness，再接入产品流水线。

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
