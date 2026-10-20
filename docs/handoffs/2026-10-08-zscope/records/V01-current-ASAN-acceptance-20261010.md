# V01 当前源码 ASAN 验收与 V02 环境核对 — 2026-10-10

结论：**V01 原工作包最小闭环验收通过，状态更新为 done；V02 继续 blocked，真实 TSAN 保持 not_run。** 本轮没有修改产品或测试，没有新模型请求。旧报告、已有修改和四项漂移修复保留，未提交或推送。

## 当前输入与执行边界

产品 `dynamic_reproduction.py` SHA256 为 `77fdcd1671849348bffcbff643e711b2c260d3ff73907f3d9ac4297b19f6aba7`。以 [资源返修记录](V01-V02-resource-repair-20261010.md) 的最终格式化验证清单冻结输入，403 项在本轮前后全部一致；上一轮清单的 120 项归档摘要也全部核验一致。已有普通验证 1736 passed、compileall/mypy 通过继续有效，未为相同产品/测试输入重复执行该矩阵。

在 WSL Linux 用户态运行独立验收 driver，复用原固定本地镜像与五项节点。镜像 ID `1cbbca32768c3c2d7c0dfa6888790808c05672438f20718472f43f0ac8d9707c`，编译器为 Debian GCC 14.2.0。容器实际检查全部通过：断网、UID/GID 1000、只读根与输入、全部 capabilities dropped、no-new-privileges、seccomp filter、pids 256、内存 2 GiB、CPU 2、可执行 tmpfs 512 MiB。镜像使用 `--pull=never`；未安装或下载。

driver 只调整本轮结果目录、当前输入基线与产品摘要断言；内部观察器、五项节点、镜像、挂载和限制保持原值。观察器只读返回证据并在清理前复制原始日志，不替换产品函数、策略或测试。容器属于验收基础设施；产品记录仍如实标为 `process`，不把 subprocess 宣称为容器沙箱。

## 真实 ASAN 与原门禁

本轮 **5 passed、0 failed、0 errors、0 skipped**，总耗时 16.973 秒，未触发外层截止或输出预算。覆盖结果如下。

| 原门禁 | 证据与结果 |
| --- | --- |
| 真实内存缺陷正例、候选站点及共享裁决 | heap-buffer-overflow 定位到正例第 19 行；主执行及两次独立重放一致，候选确认与共享 prevalidation 断言通过 |
| 相似正确反例、无 sanitizer 输出不拒绝候选 | 主执行和两次重放均为 `not_reproduced`；不产生确认或拒绝证明 |
| 无关 crash 不确认原候选 | crash 定位到 unrelated helper 第 35 行；候选站点不匹配，资格拒绝且保持未决 |
| build 生成二进制、真实摘要与重放绑定 | 三次真实构建/运行使用 `post_build_output`，二进制摘要与两次重放一致；允许完成候选确认 |
| 构建失败不拒绝候选 | 编译错误形成 `engine_failed:build_failed`，没有启动候选 run，没有拒绝证明 |
| 资源、超时、取消、信任、版本漂移与兼容性 | 沿用同输入的资源返修普通证据：独立资源 8、四漂移 4、专项 139、原负例 25、R01–R09 16、集成 1、兼容 1543，合计 1736 次通过，含重复覆盖 |
| 输入、命令、二进制、日志及重放身份 | 本轮 313 项只读 staged inputs、13 次 runner 调用、12 次 fixture run、4 次 build、4 组独立重放；58 份原始日志共 27,526 字节，观察器错误为空，归档摘要逐项核验通过 |

详细命令、版本、输入/二进制摘要、stdout/stderr、退出码、sanitizer 栈和 source mapping 均保存于 [ASAN 原始证据](V01-current-ASAN-acceptance-20261010/ASAN-evidence/observed-executions.json)；五节点 JUnit、隔离检查及完整 driver 见 [本轮目录](V01-current-ASAN-acceptance-20261010/)。本轮自有容器已清理，exit 0。

状态依据为 [WORK_PACKAGES.md 的 V01/V02](../WORK_PACKAGES.md) 和 [ACCEPTANCE.md 的 AC06/AC10/AC11/AC17/AC18](../ACCEPTANCE.md)。真实 TSAN 属于 V02；自动 plan/harness/input 生成器是后续能力，CBMC 是可选替代，均不增加为 V01 的门禁。这里通过的是授权微型 fixture 的最小闭环，不外推为任意工程、全程序安全或真实压力组验收。

## V02 的实际剩余阻塞

本轮只读核对镜像和现有工具链身份。当前镜像 ID 以及 ASAN 实际编译器摘要与此前隔离工具链清单一致；该不可变镜像只有 GCC 14.2.0，cc/gcc/gcc-14 为同一编译器，TSAN runtime SHA256 仍为 `d4d8d0b7b10a25c6a129e8049cff0228fa53d16d7f6f86560ad9d215402530d4`。没有第二个编译器/runtime 可选。

宿主已有 Clang 18.1.3、GCC 13.3.0 及各自 TSAN 库，文件摘要与旧只读清单一致；它们尚未在当前获准容器内验证兼容，不能把宿主安装当作隔离验收通过。旧运行时错误为 `FATAL: ThreadSanitizer: unexpected memory mapping`，本轮不进一步推断具体根因。

本轮新增 TSAN 探针 **0**、线程 fixture 构建 **0**、执行 **0**。没有重试旧失败配置、关闭 ASLR、改变内核/seccomp/capabilities、使用 privileged 或新增工具链挂载。V01 依赖已满足后，V02 的最小缺项是：**一个能在同等获准隔离边界中运行的兼容 TSAN 编译器/runtime**，随后完成所选路线的真实正反例与资格验收。现有获准固定镜像没有这个条件，故保持 blocked/not_run。见 [本轮只读诊断](V01-current-ASAN-acceptance-20261010/tsan-current-diagnostic.json) 与 [旧错误原文](V01-V02-remaining-gates-20261010/TSAN-runtime-addendum.json)。

## 协调消息、Bridge 与交接检查

已收到协调任务补充要求和已验证 Bridge→DSH 连接资料，并核对进程 route patch 摘要。该资料只证明连接；`manual` 不代表工具沙箱，项目工具权限尚未验收。本轮无代码返修需要，未创建 Bridge session、派发 DeepSeek、重复发送旧 54,628 字节包或修改长期配置。私有 route 配置和凭据不进入本轮仓库归档。见 [资料接收记录](V01-current-ASAN-acceptance-20261010/bridge-materials-receipt.json)。

交接文档修改后在 WSL 执行 `tests/test_agent_docs.py`；最终结果及 Markdown 编码、状态、差异和摘要检查见 [final-validation.json](V01-current-ASAN-acceptance-20261010/final-validation.json)。最终归档索引见 [final-evidence-manifest.json](V01-current-ASAN-acceptance-20261010/final-evidence-manifest.json)。
