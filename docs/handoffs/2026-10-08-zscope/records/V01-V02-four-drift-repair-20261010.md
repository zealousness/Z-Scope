# V01/V02 四项文件漂移缺口修复与独立核验

2026-10-10 UTC，CINDALA。**本轮四项普通逻辑缺口已修复并独立通过；V01 保持 in_progress，V02 保持 blocked，整体尚未放行。**

产品修改仅为 `zscope/core/validation/dynamic_reproduction.py`：执行记录保存输入被接受、build/run 之前的源码/harness/input 摘要，证明登记和最终裁决比较该快照；进程内执行记录保存实际二进制路径、摘要和绑定状态，登记及最终裁决重新读取文件核验。真实生产执行要求二进制匹配，包括构建后生成、计划未预填摘要的产物。已有真实文件的 fake 执行仍保存二进制绑定；符号路径 fake 仍需显式测试专用授权注入。保留完整候选身份、精确 proof 对象授权、TTL、独立重放、共享预算、取消、清理、off/shadow 行为，原断言未修改。

最终产品 SHA-256：`511c33409b4f9abf283c7a9c8719cff21c2f6c79101e2f121d746064d3487e0e`。两份补丁由已授权的 DeepSeek Harness 官方 headless 和既有凭据解析取得，独立审查后应用。首次源码补丁因遗漏 fake 路径及执行后采样退回，未应用。二进制第一次请求明确以 `max-tokens`/32768/exit 1 结束；通过官方进程级覆盖将 maxTokens 调为 65536 后，同一材料正常返回补丁，未放宽安全或权限，未修改全局模型配置或凭据。

| 验证 | 结果 |
|---|---|
| 四项独立源码/二进制 mutate/delete 回归 | 4 passed，0 failed，0 skipped |
| 原专项单测 | 126 passed |
| 原验收负例 | 25 passed |
| R01–R09 负例 | 16 passed |
| 安全扫描接缝集成 | 1 passed |
| 77 文件兼容集 | 1543 passed，0 skipped |
| compileall / 全量 mypy | exit 0 / exit 0 |
| 普通用例合计 | 1715 passed，0 failed，0 skipped |
| 同范围隔离 ASAN 五节点 | 5 passed，0 failed，0 skipped |

测试与质量检查均在 WSL Linux 中执行。测试前后 403 个核对输入摘要稳定，`changed_inputs=[]`；相对本轮修复前冻结基线，仅审查过的产品文件改变。当前交接文档为验证完成后的独立更新。ASAN 五节点保持此前批准的固定镜像、断网、非 root、只读输入、cap-drop/no-new-privileges 和资源上限；这描述独立验收环境，不代表产品本身具有容器隔离。

## 仍需完成的验收

- 真实 TSAN 尚未在符合条件的独立环境完成 G3 复验；既有获准容器的运行时探测失败仍为 not_run，不以宿主 WSL 自验或 mock 告警代替。
- approved-plan 的 harness/输入计划生成器及序列化请求仍为 reserved_not_implemented，按原工作包继续核对。
- CBMC 分支未实施；本轮未执行 TSAN、压力测试或 range/truth，未安装依赖、改变权限、提交或推送。

## 可继续核验的证据

- [完整普通验证报告](V01-V02-four-drift-repair-20261010/ordinary-validation.json)、[JUnit 与日志](V01-V02-four-drift-repair-20261010/ordinary-evidence/)、[归档摘要](V01-V02-four-drift-repair-20261010/evidence-manifest.json)。
- [原四项回归](V01-V02-four-drift-repair-20261010/test_v01_v02_independent_drift.py)、[最终 driver](V01-V02-four-drift-repair-20261010/V01-V02-postrepair-acceptance-20261010.py)。
- [调用、补丁与独立审查](V01-V02-four-drift-repair-20261010/model-evidence/)。源码修订 session：`session-be6d74c9-f676-489a-aad6-46673164bde7`；二进制修订 session：`session-fb6a18a8-ffa9-4f68-9bcd-5d7c0bceed47`。最新 responseID：`021791606471846fa9d9f845586d8bc45315f2ec71acc48b14b5a`；官方事件未暴露 requestID。
- [修复后 ASAN 独立报告](V01-V02-four-drift-repair-20261010/ASAN-postrepair-validation.json)、[实际隔离及原始证据](V01-V02-four-drift-repair-20261010/ASAN-evidence/)。

历史报告完整保留，仓库副本隐藏私有 endpoint，原始调用元数据和临时配置保留在本任务工作目录。未输出私有模型推理或凭据值。
