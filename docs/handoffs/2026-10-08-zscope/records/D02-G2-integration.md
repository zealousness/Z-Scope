# D02：集成验收

2026-10-08，总控。HEAD `010f40210b54ba0f79a088312ce5d8be3a82ace0`，分支 `v1.3.1_feat/llm-wiki`，保留原工作区增量。没有提交或推送。

## 实现与接线

一次式发现继续按原路径执行；新增有界 Worker 独立使用 D01 登记证据、JsonToolAgent、只读工具和取消令牌。RuntimeSpec 默认 off、只允许 shadow，四轮上限、有限时间、最多一次范围扩展；公共 Config v2 拒绝实验字段。单入口和批量入口使用同一工厂，Ledger 冻结前登记，shadow 与 active 使用独立验证策略分组并保留原 canonical obligation。

同名 callee 的歧义扩展、无增益停止与取消时证据清单遗漏已由独立审查复现并修复；父取消和单单元 deadline 分别测试。见 [G1](D02-bounded-investigation.md)、[独立审查](D02-independent-review.md)。三个原始问题的修复后 fake 断言通过，不替代集成回归。

## 执行结果

真实命令、PATH、完整输入文件 SHA-256 和日志位置保存在 [D02-G2-validation.json](D02-G2-validation.json)。执行器为 WSL Ubuntu `/home/zeal/venv313/bin/python`，实际 cwd 是当前仓库的 `/mnt/c/.../Z-Scope`。pytest basetemp/cache/JUnit 均独占 `/tmp/zscope-parallel-20261008/G2-D02/`。

- 30 个测试文件覆盖工具、MCP、Config v2、Java、Ledger、主动发现、rollout、D01/D02 和文档。
- **455 passed、0 failed、0 errors、0 skipped**；pytest exit 0。pytest wall 87.23 秒，含后置摘要核验的驱动 wall 93.840 秒，不作性能收益宣称。
- 全选源码、配置、测试/fixture、脚本及模块文档的测试前后摘要一致，`changed_inputs=[]`。测试期间三个工作 agent 停止产品写入；新增 records 不属于产品输入。
- G1 最终 150 passed，定向 mypy、compileall 和 diff-check 通过。早期 fixture/类型诊断及输入变化的运行在 G1 中保留，未累加或借用其计数宣布通过。

## 验收与限制

AC07/08/10/18 的候选盲权限、范围拒绝、不可变身份、取消、循环停止、缓存/来源与关闭兼容均通过 deterministic/fake 验收；AC16 的决策/工具尝试及 unknown usage 口径已测试。普通 legacy 语义不可核验和只读图/流 unavailable 均保留，不以隐式刷新绕过限制。

真实模型调用、物理请求取消延迟、模型收益/成本、独占 TP 和正式 benchmark **not_run**；没有凭据或外发源码。D02 以默认关闭的确定性实现交付，未晋升 active。最终全仓 compileall/mypy 与后续合流回归仍由批次收尾单列。

G1/G2 已通过，解锁 D03 和 A01 的本地 fake/离线实现；不解锁尚缺 D03 的 P02。
