---
name: zscope-prompt-autofill
description: 根据 C 源代码和 Z-SCOPE entry_functions_list 自动补齐 custom_prompt。
category: orchestration
triggers:
  - entry_functions_list 中 custom_prompt 为空、缺失或过短
  - 用户要求为函数生成分析提示词或 custom_prompt
  - 用户提及 Z-SCOPE 提示词、分析提示、custom_prompt
allowed_tools:
  - list_known_functions
  - get_function_impl
  - get_call_graph
references:
  - references/prompt-patterns.md
  - references/existing-examples.md
---

# Z-SCOPE Custom Prompt 自动补齐

此 skill 在 Z-SCOPE 运行时由 `PromptAutofillExecutor` 执行。它不是直接照搬
Claude Code/OpenCode 的文件系统工作流，而是把原始流程转译到 Z-SCOPE 已有
能力：

- entry JSON 来自 `project.entry_functions_list`
- 源码根目录来自 `project.source_root`
- 函数定位和源码读取使用 `CodeIndex.get_function_impl`
- 直接 callee 使用 `CodeIndex.get_callees`
- JSON 写回仅修改 `custom_prompt` 字段

## 运行目标

读取 batch entry 列表，筛选 `custom_prompt` 为空、缺失或过短的函数，基于源码
证据生成中文 custom_prompt。已有完整 custom_prompt 默认不覆盖。

## 必须保留的领域知识

以下知识属于用户定制审计上下文，必须作为 custom_prompt 注入，而不是泛化掉：

- DDM 资源接口：`DDM_ALLOC`、`DDM_FREE`、`DDM_BitMapGetFree`、
  `DDM_BitMapSet`、`DDM_BitMapUnSet`
- mesh/xmesh handler 的跨 handler 生命周期
- `Proc`/`MsgProc` 消息处理、分发、释放职责
- 全局 hash/链表/位图结构的挂载与摘除关系
- 条件参数路径选择风险，例如 `VOS_TRUE`/`VOS_FALSE`/`0`/`1` 硬编码导致释放端
  走错摘除分支
- 角色字段到释放条件参数的映射，例如 `ucXxxType`、`enXxxMode`、
  `ucXdrtType`

## 识别模式

执行器应识别并生成以下类别：

1. 消息分发函数：`MsgProc`、`Dispatch`、`Route`，以及 `switch/case` 或
   `astMsgProcApi` 表驱动分发。
2. 资源分配函数：`Create`、`Add`、`Alloc`、`Apply`、`Register`、`Bind`、
   `Connect`、`Join`，或调用 DDM/系统分配接口。
3. 资源释放函数：`Delete`、`Remove`、`Free`、`Release`、`Close`、`Destroy`、
   `Leave`，或调用 DDM/系统释放接口。
4. 故障兜底函数：`Fault`、`Error`、`Cleanup`、`Abort`。
5. 只读查询函数：`Get`、`Query`、`Info`、`Stat`。
6. 初始化/销毁函数：`Init`、`Finit`、`ResInit`、`ResFinit`。
7. 条件参数路径选择函数：释放/关闭函数调用中存在
   `VOS_TRUE`/`VOS_FALSE`/`0`/`1` 字面量，并且源码中存在角色/类型字段。

## 生成规则

- 资源分配函数必须声明“跨handler生命周期，请不要报告为泄漏”。
- 资源释放函数应声明“这是 Xxx 的配对释放handler”，配对关系可从已有
  custom_prompt 或函数命名推断。
- 全局数据结构操作必须添加条件覆盖完整性检查项。
- 并发操作必须添加锁保护检查项。
- 每个检查项使用 `(1)(2)(3)` 编号，通常 3 到 5 条。
- 条件参数硬编码时必须显式说明参数语义映射风险，并引导反向验证调用方。

模板和完整案例见：

- `references/prompt-patterns.md`
- `references/existing-examples.md`
