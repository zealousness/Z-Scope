# 03 · 扫描任务与 Agent 运行时

## 两类运行时，先扩展已有扫描器

专业扫描使用现有 ScanSession、Workflow、候选登记和 ValidationRunner。新增的是夜间作业管理、证据工作项和可续接状态；不先把整个扫描改写成一个自由聊天循环。

调查复用 InvestigationSession/BoundedInvestigationWorker 和 JsonToolAgent。通用修复任务 Q01/Q02 才需要独立 TaskSpec、补丁与 TaskAcceptance；与扫描共享执行服务和模型客户端，不能直接修改 finding 终态。

## 持久对象

| 对象 | 含义与单一所有者 |
|---|---|
| ScanIntent | 用户本轮目标、构建/模块范围、业务前提与运行时窗；启动准备服务 |
| ScanJob / Run | 一个作业及某次执行，包含 input revision、当前阶段、完成度和未决原因；ScanSession |
| WorkItem | 对象/协议/候选的建模、调查或复现工作；统一调度器 |
| EvidenceRevision | 程序维护的证据版本与依赖；证据层 |
| Execution | 一次编译/运行/后端进程的身份、日志、退出状态；执行服务 |
| QuestionQueue | 无法从项目材料解决的业务问题，影响范围与保守处理；验收服务 |

Job 引用现有 KnowledgeDB/Wiki/契约/报告，不复制出第二套事实库。状态和小事件可存同一 SQLite，原始日志单独存文件。字段由真实消费者需要决定。

## 状态与用户交互

`queued → preparing → running → completed | partial | failed | cancelled`。显式暂停为 `paused`；恢复建立新的 attempt 并保留前次记录。

“completed”只说明计划内工作已处理，不说明项目没有缺陷；还有证据不足的候选时，结果仍可为正常完成并列出未决。后端失败、范围未处理或时窗结束造成未完成工作，则 job 标 partial。

夜间默认不转 waiting_user：缺少业务语义记 QuestionQueue，依赖它的项标待验证，其他项继续。工程根/模型连接/全部构建目标均无效等无法产生有效工作的阻塞，启动时直接指出；运行中整体失效时保存现场并结束为 failed/partial，等验收再处理。用户中途取消始终优先。

## 主循环与进度

```text
核对输入与在途执行
→ 拉取可执行 WorkItem
→ 按共享资源与剩余时窗调度
→ 执行查询/建模/验证/复现
→ 持久化真实结果，更新义务、coverage 与问题队列
→ 有新增事实才重新裁决受影响候选
→ 生成当前可读报告
→ 继续或记录终态
```

Agent 选择下一条证据动作，程序掌握任务身份、阶段、最终裁决与资源限制。每个模型请求共用现有 LLMClient；物理请求重试和用量仍由该客户端记录一次。

停滞按证据增量、重复查询、同错误指纹判断；有限重试后换可用方法或保留未决，不机械追加 Reviewer。物理上下文窗口、进程时限和用户指定时窗真实生效；用量账本只计量，调度器负责停止新工作。

## 收敛与新发现

现有 Ledger.freeze 保留到替换实现完成。目标引入批次关闭与 evidence revision：本批集合确定后验证；调查产生的新根因通过同一 Registrar 加入下一批；同一候选新事实只增加版本并触发受影响义务，不递归全扫。

停止条件为无新可执行工作、连续无增益或达到本轮资源时窗。待处理项持久化；不会因批次结束或未选中而变成 rejected。candidate-blind 发现仍不读取历史 verdict/评分来猜答案，候选验证可以读取该候选的现有证据。

## 续接与执行真实性

恢复先核对 source/build/contract/model 身份、在途 PID/启动时间、产物和依赖变化。只重用仍有效的证据；未知执行结果不能假定退出 0，也不盲目重复写操作。

动态 witness 目前依赖进程内 receipt，序列化日志不能恢复确认资格。首版恢复需要重新执行并重新校验受影响动态候选；如以后要持久化复用，应设计明确的执行记录重核机制，不能仅移除 receipt 检查。

WebUI 断开不应中止夜间作业。S08 使用一个本地 job owner 承担进程与状态；客户端只负责控制/查看。实际未实现 owner 独立运行前，不承诺关闭浏览器或终端后任务继续。

## 后置的通用任务

Q01 的 inspect/edit/execute/verify 是可循环工作方式，不是审批阶段。finish_task 只是完成建议，TaskAcceptance 从实际补丁、构建和测试判断任务。通用 Coding 的任务成功与扫描确认缺陷使用不同状态。

多 Agent 不是首期条件；出现明确并行瓶颈后，再用独立上下文、共享只读事实及单一文件写入者扩展。
