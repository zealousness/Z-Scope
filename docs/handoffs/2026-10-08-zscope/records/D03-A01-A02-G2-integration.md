# D03 / A01 / A02 集成验收

日期：2026-10-08。HEAD `010f40210b54ba0f79a088312ce5d8be3a82ace0`；验收对象为当前未提交工作区，逐文件输入摘要与完整命令见 [机器记录](D03-A01-A02-G2-validation.json)。

## 接线与边界

- 两个扫描入口将同一 SecuritySemanticMap 传入候选覆盖投影，按对象、位点和构建上下文保守计数；未知身份、旧版覆盖和未完成调查不升级为完整覆盖。
- A01 的离线意图通过 D01 受限会话执行和登记；不引入 SDK、任意命令或外部网络执行。
- A02 只导入严格 JSON / SARIF 子集，重新校验源码、范围及身份后进入同一候选 Registrar；输入 verdict 和 proof 不获得确认或排除权限。
- 六工具、Config v2、Clang AST+SVF、Ledger 冻结和统一裁决保持兼容。

## 实际结果

WSL Ubuntu，`/home/zeal/venv313/bin/python`，Python 3.13.15。独立临时目录 `/tmp/zscope-parallel-20261008/G2-D03-offline`。

37 个测试文件组合：**646 passed、0 failed、0 errors、0 skipped**，退出码 **0**。pytest 用时 104.27 秒，完整记录驱动用时 110.714 秒；冻结输入前后摘要一致，`changed_inputs=[]`。范围包括工具/MCP、Config v2、Java、候选 Ledger、主动发现、D01/D02/D03、离线 A01/A02、契约链、归因及文档。

D03 G1 为 217 passed，独立审查为 12 passed；A01 最终 G1 为 162 passed；A02 G1 为 124 passed。各项历史失败及无效采样保留在对应记录，不以本次结果抹去。

## 放行与未执行

D03 满足确定性实现验收，登记 done，解锁 K01/P02。A01/A02 的本地离线增量已通过 G1/G2，但真实 SDK 权限约束、供应商资格和授权未满足，整体仍 deferred。真实外部调用、模型收益、正式 benchmark 为 **not_run**。本记录不宣称任何实验晋升或准确率、性能收益。
