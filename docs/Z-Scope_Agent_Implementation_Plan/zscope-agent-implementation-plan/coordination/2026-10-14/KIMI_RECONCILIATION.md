# Kimi 已送请求逐项对账

截至 **2026-10-14 12:00 UTC+8**，本轮全部 Kimi dispatch_request 文件已逐个核对。以下四个当前请求均有公开 dispatch 成功回执及本次新 check_task（reconcile-*）回执，**已经实际送达；不是待发送**。四项当前均 running，observed_model 仍为 null；selector 均为 `volceapi/kimi-k3`，不把 selector 当完整采样证明。

| 范围 | 原请求/失败任务 | 恢复或确认发送 ID | 会话 | 最新状态与产物 |
|---|---|---|---|---|
| S08-OWNER | bare selector `task_5da2bda636` 在提示前失败；完整 selector `task_6b7b3fc3cf` 后为 bridge_restarted | `task_914e1ba719` | 复用 `sess_66640fd67a` 原会话 | running，工具活动持续；jobs 已有 models/store/fingerprint/identity/runner/scheduler_hook/owner 七文件；service/__main__/完整测试尚未交付，不算 S08 完成 |
| S01-INST | `task_1198b0d674` 为 bridge_restarted | `task_fed6debc7d` | 复用 `sess_9669ed4555` 原会话 | running，最近仍读调用方；截至此核对尚无 test_all_variant_scan.py/DELIVERY，不把 running 当开发完成 |
| U02-PROJECTION | request `4392c2f8-33d3-4542-ae22-ab182c181672` 无公开接受回执，不能凭队列当已送；恢复前会话清单单独核对 | `task_ab2f74e4fd` / request `1e703d58-ae70-4b1a-9dde-88aff0c78875` | 新会话 `sess_5b2791bb4a`，不是重复活跃会话 | running，DELIVERY与49例Linux日志已落盘；两个新文件已按稳定摘要接入根目录，等待终态回执 |
| U02-DISPOSITION | request `e7208177-0923-4c18-a81f-fee45a147f62` 无公开接受回执，不能凭队列当已送；恢复前会话清单单独核对 | `task_d248900b18` / request `0ba4b4bc-a960-4e85-8709-a54f23145843` | 新会话 `sess_8fa76506e8`，不是重复活跃会话 | running，DELIVERY与24例Linux日志已落盘；两个新文件已按稳定摘要接入根目录，等待终态回执 |

原始/恢复回执共7个已接受Kimi请求，当前仅上述4个活跃开发任务。旧失败保留，不重新执行旧请求。U02两个早期无接受回执请求不自动重放；有当前活跃接受任务后不存在漏派理由。未发现需要补派的其它失败/结果不明Kimi请求，计划内尚未解锁节点仍按DAG等待，不把它们计作漏派。

公开核对证据：bridge-response-{s08-owner,s08-owner-qualified,s01-instances,resume-s08-after-transport,resume-s01-after-transport,u02-projection-confirmed-kimi,u02-disposition-confirmed-kimi}.json；bridge-response-reconcile-{s08,s01,projection,disposition}.json；bridge-response-current-sessions-before-u02.json。旧请求保留在bridge-queue，consumed标志禁止重放。

两个U02隔离模块没有修改任何继承的931个基线源文件，intake摘要收据已保存；根目录真实HTTP集成集合79 passed/11.33s（acceptance-integration-tests.xml）。此结果和独立49/24例集合重叠，**不累加**。U02已可后端接线；前端context_revision增量与真实浏览器联调待Astra续接。

尚未确认S08/S01是否有Windows工具错误影响进度，正在检查公开工具活动与实际文件，不把缺少错误回执解释为工具完全正常。U02有真实WSL日志，不是仅Windows测试声明。由于Bridge不支持给running turn追加提示，不发会被busy拒绝的重复dispatch；如确实长期无产品进展，将保留当前修改，在同一允许会话要求最小交付，而不是换模型绕行。

用户保留 `task_0947f2854f` 未查询、未续发、未改写、未恢复，本次对账不覆盖该被隔离分支。
