# ADR-0006：产品与Benchmark双轨治理

- 状态：accepted-for-design
- 日期：2026-08-17
- 影响阶段：全部阶段

## 决策

产品实现和Truth/Scorer治理由独立变更推进，在P6前通过门禁汇合。普通PR不得同时修改产品检测逻辑、
Range truth/fixture和Scorer。

## 理由

Range长期作为开发集使用，产品、fixture和truth共同演进会产生无法审计的反馈环，且无法证明真实项目泛化。

## 后果

- CI增加change-scope和答案泄漏检查。
- 活跃sealed/v16 case只反馈聚合结果和根因类别。
- 新能力必须先通过匿名fixture、metamorphic和非Range项目验证。
