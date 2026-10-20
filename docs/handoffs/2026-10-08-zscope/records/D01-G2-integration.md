# D01：G2 集成验收

HEAD/分支保持 G0，未提交。D01 实现、初次测试错误和修复过程见 `D01-investigation-evidence.md`；总控在所属源码冻结后重新执行上一批组合用例并加入 D01。

实际环境为固定 WSL Ubuntu Python 3.13.15/PATH。完整 argv、输入 SHA256、退出码和日志路径见 `D01-G2-validation.json`。结果：**394 passed、0 failed、0 skipped、0 errors，exit 0**；全部记录输入在前后保持一致。原 356 项旧结果未用于替代本次执行。

专项最终 89 项、定向 mypy/compileall 与所属 diff check 已通过；本组合包含工具/MCP、strict Config v2、Java、候选 Ledger、主动发现、单入口兼容及文档测试。只读交叉审查确认：范围位置绑定、复读后版本核验、typed projection 和持久化权限边界均已修复。共享模块文档同步登记。

D01 不需要真实模型或重型引擎验收；真实模型、正式 benchmark、portable smoke 均为 not_run。原始 artifact 为 session_only，不宣称持久重放；后续 factory 仍须校验初始 Map 与源码版本。全仓最终质量检查将在本并行批次合流后另行记录。

G1/G2 通过，解锁 D02 和 K02；主 Ledger 冻结与统一裁决保持。
