# P3：Security Spec Mining与用户审视

## 目标

以有限、可解释、可版本化规格替代逐函数自由语义建模，并为用户提供只审视项目语义、不编写查询代码的界面。

## 进入条件

- P2证书和trace契约稳定。
- SecuritySpec DSL及状态机已冻结。
- Web写操作能够取得reviewer identity；否则仅实现只读模式。

## 工作包

1. 从AST、调用点和现有用户配置确定性提取规格。
2. 只对unknown项目语义调用LLM生成proposed规格。
3. 实现schema、scope、evidence、conflict和dependency校验。
4. 实现SecuritySpecCompiler和精确增量失效。
5. 实现WebUI列表、详情、编译预览、影响预览和审阅事件。
6. 实现规范JSON与严格XLSX导入导出。
7. shadow运行并与旧SemanticModeler对照。

## 当前实施状态

- P2证书与trace契约已完成并保持shadow，P3从P2-complete commit进入。
- 严格SecuritySpec、review event、qualification、compiled spec和archive schema已冻结；有限DSL
  registry只允许13个声明式predicate，不接受查询代码或自由参数。
- 当前Web无可信reviewer identity，因此Review Center固定只读。review和apply-import必须
  fail-closed；只有独立qualification可以在P3产生`stable`规格。
- Security Spec编译模式固定为shadow，旧SemanticModeler在P5之前继续承担当前产品输入。

## 验收

- active/stable规格100%具有说明、scope、证据和影响预览。
- stable规格100%绑定批准或qualification。
- 过期XLSX、hash冲突和未知字段严格失败。
- scope缩小和revoke产生精确失效。
- 100个盲审单元关键契约召回不低于85%，unsupported不高于5%。
- evidence refs 100%可解析。
- 未修改项目第二次扫描语义LLM调用下降至少80%。
- shadow不改变finding终态或视图。
- 至少覆盖三个非Range项目/API风格。

## 停止与回退

若用户需要写查询代码、影响范围不可解释、冲突被覆盖或shadow改变结果，规格保持proposed/shadow，
不得进入project_active。
