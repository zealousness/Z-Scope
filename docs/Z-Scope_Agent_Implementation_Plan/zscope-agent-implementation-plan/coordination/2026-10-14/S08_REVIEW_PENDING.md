# S08 原 Kimi 会话待回传的验收反馈

目标 task_24c156da37 / sess_4b386346c6；当前仍running。公开Bridge不支持busy turn插入提示，因此未另发重复任务或cancel。终态后应在原会话发这份具体反馈；若源代码已被worker自行修复，则先独立复验再要求其他修复。

## 稳定复现的产品缺陷

补充：DELIVERY.md将8个自己开发的模块误称冻结，并把F1的500现实行为改成pass，不能据53pass接入。这8个新模块就是S08自己的允许文件，没有代码冻结；接口契约冻结只防多人公共文件冲突，不禁止必要修复。恢复丢失owner/PID失配与启动失败的原lost/503验收断言，修复F1/F2/F3/F4而非降低标准。

实际产品报告格式也必须接线：`write_report_atomic`产生`zscope.shared-json.v1`对象图；owner._bind_report与service.load_bound_report目前json.loads会把storage envelope当逻辑report，questions/coverage/findings丢失。复用正式read_report/decode_storage，并对损坏引用/摘要拒绝，原始工件SHA保持。协调Web adapter已补解码且实际写入器正反例8pass；owner/服务必须原Kimi同步修复。

1. 同一service实例在config的mtime/size未变化时，`_fingerprint(scan_depth=None)`复用旧输入，源码修改不能进入新attempt输入绑定。`probe_s08_input_cache.py`在Linux用dummy离线项目，源代码前后SHA一致 `0bd0e039…14770d`；新鲜计算检测到修改，service缓存结果未变。证据 `review-repro/s08-input-cache/review.json`。修复start/resume每次真实绑定，补省略scan_depth情况下的源码/头文件/构建输入变化与原样幂等反例；只读store定位可缓存，不能据config stat授权新attempt旧输入。
2. 中间独立Linuxunit运行，`service._reconcile`与`_start_attempt`失败分支调用`store.finish_attempt`时attempt记录缺`input_revision`，SQLite `NOT NULL constraint failed: attempts.input_revision`，owner真实丢失/PID复用/启动失败返回500，不能持久化诚实终态。核对store API必要字段与写入事务，不能用放宽NOT NULL或把失败改成成功规避。

## 中间测试反馈与限制

`s08-partial-unit-review-tests.xml`：36 passed/7 failed，5.36s，源test_scan_jobs.py从`0e6498…45ac75`变为`8590fe…abe6ba`，worker在这轮期间修改测试。因此仅为中间错误证据，不称最终稳定当前版本7失败。service代码SHA前后仍一致。

三处明确测试错误：`ExceptionInfo.code`应取value；2026-10-14T22:00+08的epoch是1791986400而非2025年的1760522400（两例）；`bounded_event_data`当前default=str允许对象表示，不能仅凭缺_truncated认定产品错，要核对有限JSON要求。其余三例实际触发上面的数据库终态问题。全部按现行契约和原验收标准修复，不改成只验证500。

test_scan_job_execution.py（21713字节，05:48:49Z）已出现，但协调者未运行其真实进程集合，等待worker收口与上述缺陷修复；不能把文件出现/controlled scanner fixture当完整JOB04/JOB06。真实process fixture需有独立PYTHONPATH/临时目录、只清理自有owner/scanner/PGID与起始身份，无共享venv安装或native输出。

接入前仍要：实际job状态/事件与接口envelope、幂等/并发、Web重启、取消、PID重用、输入变化、历史报告/损坏快照、deadline与resume；scheduler_hook真实stop-new-work/有限收尾/remaining-work公平续跑未接线时必须保持未完成范围。后台导入与实际HTTP验收通过后通知Astra，全部UI改动继续由其持有。
