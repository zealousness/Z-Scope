# V01/V02 资源返修、独立审查与普通复验 — 2026-10-10

本轮在 CINDALA 本地完成 RG01/RG02 修复与普通复验；**资源缺口已闭合，V01 仍为 in_progress，V02 仍为 blocked，整体未放行。** HEAD 保持 `010f40210b54ba0f79a088312ce5d8be3a82ace0`，分支保持 `v1.3.1_feat/llm-wiki`。已有修改、旧报告和此前四项漂移修复均保留；未提交、推送、安装依赖或调整安全边界。

## 精确外发授权与实际调用

用户在当前本地对话直接批准将 54,628 字节资源返修材料发送到其确认的 volceapi.com 网关。本轮核对长度和 SHA256 `2522e048dcdac6235daacb38eeba0e69ee3efee05f94693ef7f26194e5f8ac97` 后，通过原 Harness、原脚本、原配置进行一次调用，正常 completed/exit 0。没有更换网关、修改载荷、关闭安全守卫或发送授权上下文；此前拒绝记录继续保留。

会话为 `session-5017afd3-5c7c-4562-82bc-b15b6a3f5c2f`，模型 `deepseek-v4.1-flash`，返回最终补丁文本 15,875 字节。工具、持久会话和重试保持禁用；官方凭据解析保持原设置，未读取凭据文件或记录密钥值，隐藏推理正文未保存。私有 endpoint 和凭据引用不进入仓库，原始调用记录保留在本地任务目录；仓库保存脱敏的 [调用记录](V01-V02-resource-repair-20261010/model-evidence/submission-result.json) 和 [精确载荷清单](V01-V02-resource-repair-20261010/model-evidence/packet-manifest.json)。

## 最终实现与独立审查

产品只修改 `zscope/core/validation/dynamic_reproduction.py`：构建阶段传入计划 RSS 限额，内存或输出超限以 `build_resource_exhaustion` 停止，不启动 run、不形成候选裁决；stdout/stderr 改为有界管道读取，每流日志在写入及 hash 前均不超过声明 cap，恰好等于 cap 且真实 EOF 时保持完整。后代延迟输出仍使用原共享 deadline、取消和资源边界，结束时按已保存的自有进程组 ID 清理。

DeepSeek 修订通过原八项资源断言。追加的进程生命周期检查发现：后代关闭两流后继续运行时仍会遗留。当前 agent 本地补齐 EOF 后的无条件自有进程组清理，并使管道读取异常失败关闭，不能冒充完整 EOF；没有新增外发请求。修订后的八项资源及五项边界检查全部通过，随后才应用到产品。模型候选、退回原因及最终 [独立审查](V01-V02-resource-repair-20261010/model-evidence/independent-review-accepted.json) 均保存。

十三项资源/边界用例迁入 `tests/test_dynamic_reproduction.py`；原 110 个顶层函数 AST 未改变，原断言未删除或弱化。首次迁入漏加 `hashlib` 导入导致两项 NameError，专项为 137 passed、2 failed；补齐导入后 139 passed。首次日志与失败保留，没有将失败记录改为通过。主 venv 缺少 Black，改用已有 WSL formatter，仅格式化新增或变更区域，没有安装依赖。

最终产品 SHA256：`77fdcd1671849348bffcbff643e711b2c260d3ff73907f3d9ac4297b19f6aba7`。见 [产品补丁](V01-V02-resource-repair-20261010/product.patch) 和 [测试补丁](V01-V02-resource-repair-20261010/tests.patch)。

## 实际普通复验

全部测试及质量检查使用 WSL `/home/zeal/venv313/bin/python`，Python 3.13.15，安装指向当前仓库；测试进程只转发非凭据 allowlist 环境。

| 检查 | 实际结果 |
| --- | --- |
| 原八项有界资源断言 | 8 passed |
| 四项源码/二进制 mutate/delete 回归 | 4 passed |
| 产品专项，含十三项新增回归 | 139 passed |
| 原验收负例 | 25 passed |
| R01–R09 负例 | 16 passed |
| 安全扫描接缝集成 | 1 passed |
| 77 文件兼容集 | 1543 passed，3 项重型 native deselected |
| 上述普通验证执行合计 | 1736 passed，0 failed，0 skipped |
| compileall / 全量 mypy | exit 0 / exit 0 |

合计是上表矩阵的执行项计数，八项独立资源断言也已纳入产品专项，不宣称 1736 个互异断言。第一验证窗口的 403 个输入稳定；补导入后仅专项测试文件发生计划内变化，第二窗口重跑专项和 compileall，403 个输入也稳定。末轮按仓库 Black 配置（100 列）调整变更区换行，产品 AST 不变；最终摘要再次运行专项 139 项、漂移 4 项及 compileall 通过，第三窗口 403 输入稳定。兼容集和 mypy 使用与最终产品 AST 相同的已执行源码，未为测试导入和纯换行重复执行。验证窗口及差异见 [最终普通报告](V01-V02-resource-repair-20261010/ordinary-final-validation.json) 和 [末轮格式/复验记录](V01-V02-resource-repair-20261010/repo-format-validation.json)，首次失败保存于 [首轮报告](V01-V02-resource-repair-20261010/ordinary-first-validation.json)。

## 尚未验证的部分与状态

- 当前 runner 摘要未执行真实 ASAN。此前 5 passed 的隔离 ASAN 及 1715 passed 的旧普通验证保持历史有效，不沿用为新摘要的真实工具结论；V01 保持 in_progress。
- 本轮没有重跑真实 TSAN。既有固定镜像 GCC14.2 runtime 的 `unexpected memory mapping` 仍使线程 fixture 未执行，V02 保持 blocked/not_run，详见 [剩余门禁记录](V01-V02-remaining-gates-20261010.md)。未改 ASLR、内核、capabilities、seccomp、挂载或容器边界。
- 自动 harness/输入/计划生成器是后续能力限制，CBMC 是可选替代；二者不新增为所选路线的必须门禁。真实 TSAN 属于 V02，不作为 V01 的依赖。
- 未执行新的 sanitizer、真实内存压力组、Range/truth、未知项目构建或第三方工程。本轮 bounded watchdog 用模拟阈值，新增输出控制每流最多 64 字节；原专项中已有的有界进程测试仍按原断言执行。

本轮同步 `TASKS.yaml` 的旧阻碍口径、追加 `PROGRESS.md`，并更新分析流水线的稳定资源契约。文档核验及最终输入摘要见同名证据目录。
