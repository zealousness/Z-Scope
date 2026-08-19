# P1：死代码与Workflow清理

## 实施状态

`complete`。零模型冻结replay、通用实现、公共入口smoke、wheel/import graph和本地质量门已通过；`claude-opus-5`对clean候选commit `9b7dc480533de051ec1ea533efae25cf3e58d1e2` / tree `99b386fe89d9fe5ff30cdcd0f1aaed763c02ed57`完成只读product architecture审核，decision为`approved`且blocking findings为空。本阶段未创建新的设计批准tag。

## 目标

删除2.0不再支持的不可达执行路径，同时保持冻结候选、终态和视图不变。

## 进入条件

- P0为complete，设计状态为approved。
- runtime reachability manifest已审核。
- 有不调用模型的冻结replay输入。

## 工作包

1. 删除focused subagent不可达块、VulnerabilityAnalyzer、DeepWorker和SubAgentOrchestrator。
2. 删除subagent配置、报告字段和runtime defaults。
3. 删除C/C++ ruledriven公共旁路，规则统一进入Candidate Ledger。
4. 删除LLM报告判重，Finding-root v2成为唯一展示投影。
5. 拆分IssueReconciler历史维护职责。
6. workflow改为中性阶段名并校验每个step实际执行。
7. 建立compat只读包和旧usage维度映射。

## 测试

- import/dynamic loader和wheel内容测试
- workflow step-handler一致性
- removed config迁移错误
- frozen replay候选/终态/视图等价
- default/resume/maintain/alert-verify smoke
- compat只读和禁止live执行测试

## 验收

- 产品wheel和runtime import graph不含已删除Agent。
- 不存在无条件return后的不可达大块。
- 所有公共入口仍产生与P0等价的冻结结果。
- 旧配置不被静默忽略。
- full pytest、compileall、mypy和Black gate通过。
- P1 product architecture审核绑定同一clean候选commit/tree，decision为`approved`且blocking findings为空。

## 停止与回退

若候选、终态、视图或公共入口行为发生非预期变化，回退对应删除提交，补充reachability证据后再继续。
