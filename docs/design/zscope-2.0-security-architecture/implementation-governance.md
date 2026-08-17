# 实施与反Benchmark定制治理

## 双轨治理

产品轨P1-P5与评测轨Truth v16/Benchmark v5并行，P6前汇合。职责隔离：

- 产品PR不得同时修改`zscope/**`和Range truth/fixture。
- Truth PR不得修改产品代码、规则、Prompt或Scorer。
- Scorer PR不得修改产品检测逻辑或fixture。
- 跨域需求必须拆分变更，由独立Benchmark reviewer批准依赖顺序。

该不变量由`scripts/check_zscope_2_change_scope.py`和CI的
`Z-SCOPE 2.0 change-scope governance`作业强制执行。脚本只根据Git路径分域，
不读取truth内容，也不影响产品运行时。

## 反定制门禁

CI递归扫描agents、core、orchestration、retrieval、rules、semantics、tools和reporting，禁止：

- truth ID、Range函数名和fixture独有常量；
- benchmark、score、ground truth或答案描述进入产品Prompt；
- 为单个Range case增加predicate分支；
- 只检查JSON key而不检查普通scalar value的candidate-blind过滤。

任何新rule、spec predicate、proof verifier或hunter策略至少需要：

- 正例和near-miss安全反例；
- rename；
- wrapper提取/内联；
- 宏或等价控制流重排；
- fixed pair；
- 至少三个无关项目或结构家族。

仅在Range有效的实现保持experimental且默认关闭。

## 阶段证据

阶段不能仅凭“测试通过”完成。evidence index必须绑定：

- implementation commit/tree；
- schema和文档hash；
- test命令、环境和artifact hash；
- 基线差异；
- 已知限制和停止条件审计；
- product、proof或benchmark reviewer结论。

`python scripts/check_zscope_2_design_evidence.py`校验设计文档hash、acceptance schema、证据artifact、
commit/tree、阶段状态和审批门禁。被忽略且未复制到当前worktree的`benchmark-artifacts/`只产生明确
限制告警；持有归档的审计环境使用`--strict-external-artifacts`要求大件存在且hash一致。告警不等于
这些外部artifact已经在本地重放或复核。

## 全局检查

每阶段合并前至少执行：

- 相关pytest和完整pytest；
- compileall、mypy、Black check；
- benchmark hygiene和answer isolation；
- Agent文档检查；
- wheel/package-data检查；
- runtime reachability；
- trace/certificate篡改测试。

## 结果归因

性能变化必须归因到candidate discovery、SecuritySpec、hypothesis、provider/verifier、proof closure、
promotion、Finding-root、matcher或truth contract。无法定位到首个变化环节的“召回提升”不能作为验收证据。
