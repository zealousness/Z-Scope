# P0：基线与设计冻结

## 目标

在产品实现前建立可重建基线、批准设计和运行时可达性清单。本阶段只允许设计、清单和验证工具变更，
不改变产品判定、Range fixture/truth或Scorer语义。

## 进入条件

- 当前工作树修改已提交、拆分或具有可审计patch SHA。
- 能定位最近一次fast/balanced报告、usage和Decision Trace。
- 设计包处于`reviewed`。

## 工作包

1. 生成`runtime-reachability-manifest.v1`：Agent实例化、workflow handler、配置消费者、公共入口和wheel内容。
2. 生成`baseline-artifact-manifest.v1`：Git/config/rules/model/Prompt/provider、报告、usage、Ledger、trace和matcher v2评分hash。
3. 建立设计manifest和acceptance evidence校验器。
4. 扩展答案泄漏和change-scope检查，但不改评分逻辑。
5. 由product architecture、proof security和independent benchmark角色审核设计。

## 交付物

- clean baseline commit/tree
- approved `design-manifest.json`
- runtime reachability manifest
- baseline artifact manifest
- P0 evidence records
- annotated design tag

## 验收

- 所有规范文件hash守恒且链接有效。
- 每项计划删除代码都有调用方、打包和替代证据。
- 基线artifact可从记录的commit/config重建。
- 设计提交不包含产品、truth、fixture或Scorer修改。
- 文档、schema、hygiene和package-data检查通过。

## 停止与回退

任一基线不可重建、工作树不能形成clean commit、删除项存在未知调用方或manifest不守恒时，保持
`reviewed`并停止P1。设计修订通过新ADR完成，不覆盖旧记录。
