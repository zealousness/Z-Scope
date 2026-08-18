# P7：Formal、External、Sealed与Rollout

## 目标

以五轮稳定性和跨项目泛化决定是否灰度，而不是用Range单点分数直接切换默认档位。

## 执行

- 同一Git、配置、规则、模型、Prompt、provider和工具链下分别执行fast/balanced/deep五轮cold。
- 随后执行public external、独立sealed及真实项目shadow。
- Token只作Pareto和非回归观测，不截断产品扫描。

## Range v16门禁

- balanced/deep confirmed median recall不低于85%。
- precision相对冻结基线下降不超过1个百分点。
- TP Jaccard不低于0.90，五轮recall极差不超过2个百分点。
- safe-entry alert rate通过Benchmark v5 policy。
- proof false acceptance为0。
- provider usage、trace、归因、队列和token守恒。

## 默认切换门禁

- sealed recall相对fast提升至少3个百分点，precision下降不超过1个百分点。
- Hunter在至少三个真实项目、两个CWE family产生独占confirmed TP。
- shadow precision@25不低于70%，high/critical precision不低于80%。
- 匿名项目和safe corpus无明显退化。
- 质量差距小于1个百分点时选择median tokens/confirmed TP最低方案。

## 回退

任何proof soundness、答案隔离、trace守恒或precision硬门禁失败立即回退fast。灰度状态和回退原因写入受保护rollout记录。
