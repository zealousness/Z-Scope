# R6 并行实现的预审观察

此文件是运行中副本的协调者预审记录，不能充当终态验收；后续以生产者稳定交付源码为准。

## S01-INST-EXEC · task_c5ebd65572

20:38 检查到 `instance_index.py` 的 `_unscoped` 仍调用底层未隔离导航方法，`__getattr__` 也默认透传。仅在最终 coverage 中列出 unscoped consumers，不能阻止这些返回值进入候选/验证/反证。初始派单明确要求未支持消费者保留缺口，禁止回落首变体。验收时检查最终代码是否已禁止使用未绑定返回值；若未修复，应在原会话终态后返修，不能按候选携带 BuildContext 标签宣布隔离完成。

20:48 合成隔离边界探针复现 1 fail（`artifacts/coordinator-s01-consumer-probe-r6-20261014/results.xml`，仅合成契约反例，不代表 native 效果验收）。还需核对：scoped 执行不能先用 base index 跑全局 modeling/shared semantics/project fact pass/active discovery 再赋实例标签；`analyze_entry_instances` 目前丢弃底层完整 results 字典，仅返回摘要 outcomes，协调者无法直接生成完整报告；其生命周期也绕过公共 `analyze_function_entries` 的关闭/占用保护。以稳定交付判断是否返修。

## U01-ENTRYPOINTS · task_9abeb34f8f

20:38 检查到 `config/editor.py` 使用同一进程固定 `.zscope-config-editor-{pid}.tmp`。Web 服务使用线程处理 HTTP，两次并发保存可能互相覆盖临时内容或删除对方文件。验收应覆盖真实并发候选文件隔离，使用同配置目录中的独立命名临时文件；这与当前未实现的 GET→POST CAS 是不同问题。编辑读取还需由协调者接线时先按当前正式 parser 验证，不能因读投影保留原文而绕过严格 schema。

20:40 执行探针时，生产者已于 20:39:50 将候选名改为目标名、进程和线程身份。协调者两次并发真实保存探针为 1 passed，见 `artifacts/coordinator-editor-probe-r6-20261014/results.xml`。此项当前未复现，稳定交付验收仍需复核；不把预审疑点继续列为已确认阻塞。

20:42 实际 CLI 路径往返探针复现 2 fail：包含 ` # ` 的路径被截断、包含 `: ` 的路径生成非法 YAML。见 `artifacts/coordinator-editor-probe-r6-20261014/init-paths.xml` 和 `followups-r6/u01-path-probe-review.json`。用户控制的 root、target id、编译数据库路径需按 YAML 标量正确序列化；不更换/放宽正式 parser。

## S08-SESSION-SCHEDULER · task_28a929d996 → task_b41bc0eb99

20:46 真实 SQLite 探针复现 3 fail：旧 claim 的 verdict 被拒绝前已接纳 discoveries；输入版本变化后旧回调与新发现仍完成；owner 变化后旧回调仍提交。证据 `artifacts/coordinator-s08-guard-probe-r6-20261014/results.xml` 与 `followups-r6/s08-guard-probe-review.json`。20:50:03 通过标准 MCP 正常取消初轮，完整结果无分页/错误/警告，同一 session ready 后于20:50:56派发原会话返修 `task_b41bc0eb99`。未验收、未导入，不涉及模型转交或审核限制回避。

## Astra 第一阶段

20:36 收到稳定交付及六文件 SHA。已审阅桌面和手机截图、真实 HTTP 与合同故障分类。独立四项浏览器验收正在新目录执行。多目标真实 400 属于待接线证据，合同 409 不证明服务端已有 CAS。UI 文件不在协调者预审过程中改动。
