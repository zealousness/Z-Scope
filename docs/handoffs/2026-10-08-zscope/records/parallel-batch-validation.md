# 剩余工作包并行批次验收

日期：2026-10-08。总控加三个 agent，共享原工作区。HEAD `010f40210b54ba0f79a088312ce5d8be3a82ace0`、分支 `v1.3.1_feat/llm-wiki` 不变；全部交付仍未提交。基线与新模块摘要见 [G0](parallel-G0-native.json)、[最终工作区](parallel-final-workspace.json)，测试环境见 [实际进程环境](final-environment.json)。

## 交付与剩余状态

| 工作包 | 当前状态与交付 | 详细记录 |
|---|---|---|
| D01 | done：程序登记 evidence_ref、版本／范围绑定、受限工具及报告映射；内容 hash 不获得 proof 权限 | [D01](D01-investigation-evidence.md) |
| D02 | done：最多四轮的有界 shadow 调查、扩围授权、无增益停止、取消与用量状态 | [D02](D02-bounded-investigation.md) |
| D03 | done：对象／位点／构建上下文覆盖键、入口 occurrence、旧版迁移不可核验状态及覆盖计数 | [D03](D03-audit-coverage.md) |
| P01 | done：复用命令身份的变体清单、八类真实增量／全量差分与隔离测量 | [P01](P01-incremental-replay.md) |
| K02 | done：冲突条件效果保守合并、资格版本失效；manual／wrapper／SCC 原路径保持 | [K02](K02-conditional-contracts.md) |
| K01 | done：类型化条件观察、可撤销的 source-only 会话资格、独立 shadow 验证分组与统计 | [K01](K01-conditional-observation-shadow.md) |
| P02 | done：候选产生前的需求规划、SCC 依赖闭包、typed 缺口补充；只记录，不改变执行 | [P02](P02-shadow-planner.md) |
| A01 | deferred：fake／离线适配 G1/G2 通过；真实 SDK 强制权限接口未核验 | [A01](A01-offline-adapter.md) |
| A02 | deferred：离线 JSON／SARIF 导入 G1/G2 通过；真实供应商资格、版本及执行授权未满足 | [A02](A02-offline-import.md) |
| V01 | blocked：按用户最新指示遗留；无 provider／fixture／测试半成品，实际验证未执行 | [V01](V01-blocked.md) |
| V02 | deferred：依赖 V01，TSAN 尚未解锁；不安装 CBMC 替代 | [V02](V02-deferred.md) |
| R01 | deferred：缺少代表性工程的实际 WPA 瓶颈证据；未修改生产 SVF | [R01](R01-readiness.md) |
| R02 | deferred：缺少授权修复样本及隔离保留集；未生成或安装规则 | [R02](R02-readiness.md) |

前置 B00–T03 的既有实现保持。六工具、public Config v2、Clang AST+SVF、候选冻结与统一裁决均保留；D02/K01/P02 默认 off，没有自动晋升 active。

## 实测门禁

| 门禁 | 实际结果 | 证据 |
|---|---|---|
| D01 G2 | 394 passed，0 failed／skipped，输入稳定 | [机器记录](D01-G2-validation.json) |
| P01 / K02 G2 | 353 passed，0 failed／skipped，输入稳定；另有独立真实工具验收 | [机器记录](P01-K02-G2-validation.json) |
| D02 G2 | 455 passed，0 failed／skipped，输入稳定 | [机器记录](D02-G2-validation.json) |
| D03 / A01 / A02 G2 | 646 passed，0 failed／skipped，输入稳定 | [机器记录](D03-A01-A02-G2-validation.json) |
| 最终 K01 / P02 与全批兼容回归 | **1297 passed、0 failed、0 errors、0 skipped、2 deselected**，exit 0，输入稳定 | [完整命令及摘要](K01-P02-G2-validation.json) |
| compileall | exit 0，覆盖 zscope / scripts / test / tests | [质量记录](final-quality.json) |
| mypy | exit 0，306 source files | [质量记录](final-quality.json) |
| Linux diff 检查 | exit 0，识别既有 CRLF，未做无关换行转换 | [质量记录](final-quality.json) |

以上套件彼此重叠，不累加为独立测试总数。最终 70 文件包含工具/MCP、Config v2、Java、Ledger、主动发现、建模与契约、报告复用、Review、发布回归及交接文档。两项 deselected 是已单独通过的 P01 重型测试；本轮真实 native 契约消费者仍实际运行。源码、工具路径、工具摘要、测试目录和环境分别留档，不能仅按 HEAD 复用结论。

## 保留的失败与未执行项

首轮 G2 发生新增测试与冻结通知的交接竞态，检测到摘要漂移后仅中止自己拥有的 pytest；309 项已通过、1 项中断及剩余未执行不构成最终验收。已从新目录完整重跑。各任务中的实现迭代失败、驱动目录错误、mypy 报错、原始 CRLF 检查失败和 P01 初始 skipped／动态库失败均保留在各自记录，没有覆盖成 passed。

K01 只对可核验的自包含 source-only 输入授予观察资格；编译数据库、外部 include／classpath、无法重核的自定义 schema、库存超限和热缓存都保持背景／不可核验。旧语义、图或流 unavailable 不触发隐式刷新，缺少构建身份不能成为 TU 或全程序证明。

真实 LLM、正式 benchmark、生产实际跳过、实验晋升、外部 SDK／扫描、ASAN／TSAN 及 portable smoke 均 **not_run**。现有三个 LLM 环境变量未设置，未安装依赖、复制凭据、向外部服务发送源码、创建分支、提交或推送。

后续先核对实际工作区，再按 TASKS.yaml 的阻塞条件继续；不得重建已完成部分、回滚参考提交、恢复旧 JSON 权限，或将未执行的真实验收标为通过。
