# ADR-0004：Benchmark v5与Truth v16

- 状态：accepted-for-design
- 日期：2026-08-17
- 影响阶段：E0、P6、P7

## 决策

Benchmark v4与truth v15保持只读。2.0正式评测使用Benchmark v5、Truth v16 verification contract、
matcher v2和Finding-root v2。

## 理由

当前v15没有逐项contract和safe entry，单一finding指标也不能评价Security Spec、Hypothesis和Proof。
matcher v2已经解决keyword和跨锚点宽松匹配问题，不应为维持旧召回再次放宽。

## 后果

- v4/v5不可直接宣称回归。
- v16需要fixed/near-miss对照和独立attestation。
- Range通过不构成默认切换，仍需external、sealed和shadow。
