# S01 编译实例切片中间审查

目标为 ZCode task_2238db90f9 / sess_13e7fecbfc，当前 turn 尚运行，未向 busy session 重复派发。这里只记稳定中间源码的消费者边界问题，终态后需核对最终版本，再向原会话提交仍存在的问题；不将中间证据当最终失败集合。

Linux `probe_s01_scope.py` 使用明确合成 facts 调用实际新 helper `_query_context_instances`，源码前后 SHA 相同 `9a2e254d2b035de447d84bb187f913601b7500e8fe187146af4e11c248390b50`，证据 `review-repro/s01-scope-boundary/review.json`：

- 查询 bc-a 时 complete facts 的 function_identity 为 bc-b / key=bc-b:usr-main，当前接受为实例且 gap=null。不能仅依据传给 getter 的 context 参数就信任返回 identity；返回身份、USR/key 与所请求的精确 context 不一致或缺失时应保持明确缺口，不能混合 bc-a 的调度范围与 bc-b 的身份。
- 显式 entry file=unit.c 首查询 function_identity_not_found，file-less 同 context 查询只找到 other.c 的同名定义；当前接受并标 selected_by=entry_file。显式文件约束不能被无文件重查绕过。若实际 API 将定义记录到真实 header/另一文件，需有精确来源映射证据，不能按同名或容忍路径后缀授权。默认保守 gap，并保留真实未选中文件说明。

还要按最终 DELIVERY 核实：当前 Analyzer/Validator 未逐实例消费，scan_coverage_complete=false；CDB 期望变体与已索引实例逐源对账、当前依赖复核和报告级 completeness 仍未闭合。这些保持待办，枚举边界不能算完整 S01，不据此解锁需要完整贯穿的下游。任何修复只在原 S01 isolate 自有文件/测试进行，不扩到 frontend/native/protocol 或用户保留 caller 分支。
