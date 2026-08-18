# ADR-0003：内部Proof Kernel作为终态权威

- 状态：accepted-for-design
- 日期：2026-08-17
- 影响阶段：P2、P5、P6

## 决策

采用内部ProgramProofIR、EvidenceAction、EvidenceCertificate和独立Proof Checker。Clang、Joern、
SVF和KnowledgeDB继续作为事实源，不新增CodeQL或Infer运行时依赖。

## 理由

模型适合提出假设和选择证明动作，但不能成为fact真实性或proof完整性的最终权威。内部证书协议可
统一默认扫描、maintain和alert-verify，并支持离线replay。

## 后果

- 模型文本不能直接关闭clause。
- 完整proof/counterproof产生后必须提前终止。
- 动态ASan/UBSan作为后续V4，不阻塞首版静态Proof Kernel。
