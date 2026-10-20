# V01/V02 最新独立状态及 DeepSeek 实际修复尝试

2026-10-10 UTC，CINDALA。**V01 不予放行，V02 blocked。** 普通验收 1711 passed、4 failed；兼容 1543 个不同节点全部通过；compileall/mypy 通过。随后单独批准的 ASAN 五节点真实验收为 **5 passed、0 skipped、exit 0**。文档要求另重复检查 6 passed。四项普通源码/二进制漂移问题仍未修复。

[ASAN 追加报告](V01-V02-ASAN-independent-addendum-20261010.md) 保存修改前完整真实证据：同容器先核验非 root、只读根/限定输入、断网、全 cap-drop/no-new-privileges、2GiB/2CPU/256 PID、512MiB tmpfs；全部生效。四个运行类节点各执行一次主运行与两次独立 replay，总共 12 次 fixture 运行/8 次 replay；构建失败没有运行产物。固定镜像、精确命令、原始流、逐轮分类及 313 staging 输入摘要均已归档。TSAN/压力/range/truth 未运行；容器已清理。

403 个记录输入在测试、归档、两次模型提交后重新核验，仍无变化；模型未修改产品。ASAN 证据摘要再核验无错误。不得将未来修改后的代码与这一修改前批次混为通过。

## 用户批准与实际发送范围

用户明确同意通过本机 DeepSeek Harness 发送四项缺陷所需 dynamic_reproduction.py 片段、失败测试、必要要求与日志。既有 Desktop standard 会话没有当前可调用的已验证传输，按明确授权使用**安装内官方 bundled CLI 的新 headless 会话**，没有强行接管或修改原会话元数据。

新会话：`session-6345b6e2-1245-440c-ae91-f953c08b9655`。
原会话 `bc51fb3a-c9e7-445e-b6e3-855461b3179c` 保持不变。

初次提交 2026-10-10 03:12:09.603–03:12:11.532 UTC，正式单次 require_escalated 审批通过。输入 86726 bytes，SHA-256
`dcb23273d5d6a68df4dd39eb612154fcc8250b313145b44c36f327d3e14dda71`。
仅 15 个相关源码区间、必要 helper、四项纯 fake 失败回归/原始断言日志及范围内验收要求；不含凭据、其它仓库文件、旧会话历史、真实 ASAN/TSAN 代码/日志或 range/truth。源码基线 `fcec3fcc0f8de809b2dbc02f82abff7a3092abf074812524ed1a569513f54172`。

单次临时 --patch 收窄模型工具，并以官方 tools.guard 单调拒绝所有文件/进程/Web/外部代理工具；不会让外部代理代做被拒绝动作。禁用用户/项目自动指令发现及额外模型标题调用，cwd 为自有范围包，所有必要文本由已核验 stdin 输入。临时限制没有添加持久权限，没有读取、输出、更换或配置凭据；既有官方适配器在内部使用既有连接。

## 实际阻塞

**两次调用均 exit=1，未收到模型补丁或其它修复响应。** 已创建/续接会话并实际提交请求，不能称为修复成功。

官方客户端错误类别均为：
`AUTH: Authentication Fails`，现有客户端模型认证被拒绝。
第一次 request_id：`2680c481-fb3f-4523-9fa0-4baf53deabd3`；
第二次：`ba6725dc-f7a2-46c0-bf7e-4ee814bd83fc`。
原始 stderr 已保存；此报告不重复其中脱敏密钥提示。

第一次还出现 settings 等待 configEditor：临时收窄层误停了这项官方服务依赖。已恢复该正常依赖，模型工具禁用/守卫保持不变；没有改认证配置或权限。
03:14:50.944–03:14:52.785 UTC，通过正式审批在同一新会话发送 554 bytes 的继续请求（SHA
`ce7467026e79bc7c16a4dd8dbc825da7a55756491e0d703f836dbcba7f530b4f`）。
第二次不再有 settings 警告，仍为相同 AUTH 错误，因此停止进一步认证尝试。没有寻找其它密钥、切换账号来规避拒绝、配置凭据或改用旧 standard 会话强行接管。模型输出事件没有工具调用，也没有补丁。

这不是 auto-review 拒绝、WSL/容器隔离失败或历史 cybersecurity 内容标记；本次正式审批均成功。修复现在的最小前置条件是用户在 **DeepSeek Harness 正常界面恢复有效的模型连接**；不要在聊天中提供密钥。此后可以按已批准范围直接续接这个新 session，收到补丁后审查/整合，再独立运行四项边界、相关回归及差异核验，不通过继续同范围返修。无需再次确认这次已批准的外发范围。

## 交付

- [状态 JSON](V01-V02-independent-status-20261010.json)：准确命令、时间、输入摘要、结果、错误类别及恢复条件。
- [初次提交记录](V01-V02-DeepSeek-repair-submission-20261010/submission-result.json)、[第二次记录](V01-V02-DeepSeek-repair-submission-20261010/submission-result-attempt2.json)。
- [发送范围清单](V01-V02-DeepSeek-repair-submission-20261010/submission-scope.json)、[已批准上下文](V01-V02-DeepSeek-repair-submission-20261010/repair-context.json)。
- 原始 headless.stdout.jsonl / headless.stderr.log 及第二次原始流、临时 overlay/guard 和驱动保存于上述提交目录。
- [原四项独立验收报告](V01-V02-independent-reacceptance-20261010.md)，[原回归](test_v01_v02_independent_drift.py)及[ASAN 真实证据](V01-V02-ASAN-independent-addendum-20261010.md)全部保留。

当前无活动测试、容器或 headless 修复进程；产品实现未变。四项失败的后续修复和“直到达标”目标因有效模型认证条件尚缺而未完成。

