# 会话录制事件字典（conversation-event v2）

`--verbose` 启用的会话录制器把每次模型交互、工具调用与执行器决策写成一个**只追加**的事件流，用于事后审计 llm_client 层与工具行为：重试是否合理、模型回退是否频繁、工具参数是否反复解析失败、loop guard 是否误伤等。

## 目录结构与文件

```text
.zscope_conversations/
  run_YYYYMMDD_HHMMSS_<pid>/      # 每个进程一次运行（同秒创建会追加 uuid 后缀）
    manifest.json                 # 运行清单（schema/版本/配置摘要，会话开始时写入）
    index.jsonl                   # 每会话一行的汇总索引（session_end 时追加一次）
    <agent>-<NNNN>.jsonl          # 只追加事件流（每行一个事件）
    <agent>-<NNNN>.md             # 人类可读快照（只保留最近 K 轮交换）
```

所有事件都带 `schema_version`（`zscope.conversation-event.v2`）与单调递增 `seq`。JSONL 始终同步追加；markdown 快照按 `Z_SCOPE_CONVERSATION_MD_REWRITE_EVENT_INTERVAL` 个事件（默认 8）批量重写，刷新间隔只影响 markdown，不延迟 JSONL。

## 事件类型

| event | 触发点 | 关键字段 |
|---|---|---|
| `session_start` | 会话开始 | `agent_name`, `label`, `tools_schema_hash`, `attribution`, `metadata`（config sha256、zscope 版本等） |
| `exchange` | 每次成功的模型调用 | `model`, `base_url`, `finish_reason`, `messages`, `response_message`, `duration_ms`, `attempt_count`, `context_tokens`, `usage_event_id`, `attribution` |
| `attempt` | 仅失败尝试（成功尝试计入 exchange.attempt_count） | `model`, `base_url`, `attempt`, `outcome`, `error`, `delay_ms` |
| `tool_call` | 工具执行前 | `tool`, `tool_call_id`, `args`（解析后的 JSON；解析失败时为 null） |
| `tool_result` | 工具执行后（含异常） | `status`, `result`/`error`, `tool_call_id`, `duration_ms`, `blocked`（repeat guard）, `cached_replay`, `repeat_count`, `args_raw`, `args_parse_error` |
| `terminal_tool` | 终端工具提交 | `tool_call_id`, `valid`, `error`, `payload` |
| `iteration_control` | 执行器的隐式决策 | `kind`, `detail`（见下） |
| `loop_guard` | 重复工具 guard 触发 | `tool`, `repeat_count`, `disabled_tools`, `reason`, `scope`, `recovered` |
| `session_end` | 会话结束（含异常/截断） | `iterations`, `finish_reason`, `truncated`, `terminal_tool_valid`, `loop_guard_triggered`, `cumulative_prompt/completion/total_tokens`, `wall_seconds` |

`attempt.outcome` 取值：`rate_limited` / `http_5xx` / `http_{status}` / `auth_retry` / `timeout` / `tls_error` / `connect_error` / `request_error` / `model_fallback`。

`iteration_control.kind` 取值：`final_instruction`（最后一轮提示）、`forced_final_by_executor`、`low_iteration_warning`、`length_continuation`（续写提示）、`terminal_prose_reprompt`（detail 说明 `no_terminal_call` / `no_tool_calls`）、`final_iteration_tool_calls_rejected`。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `Z_SCOPE_CONVERSATION_REASONING` | `off` | 思考内容策略：`off` 全部剥离；`tail:N` 保留末尾 N 字符并加 `<key>_truncated: true`；`full` 全量保留 |
| `Z_SCOPE_CONVERSATION_MAX_FIELD_BYTES` | `65536` | 单字段字节上限（最小 256），超限写 `{__truncated__: true, preview, original_chars}` |
| `Z_SCOPE_CONVERSATION_MD_TAIL_EXCHANGES` | `3` | markdown 快照保留的最近交换轮数 |
| `Z_SCOPE_CONVERSATION_MD_REWRITE_EVENT_INTERVAL` | `8` | 每 N 个事件重写一次 markdown |
| `Z_SCOPE_CONVERSATION_FLUSH_INTERVAL_SECONDS` | `0` | markdown 重写最小间隔（只作用于 markdown） |

## 相对 v1 的变化

- v1 整会话覆盖写 markdown；v2 是**只追加 JSONL 事件流** + 有界 markdown 尾部快照。
- v1 缺失的信号（attempt 失败、iteration_control、loop_guard、工具耗时/异常参数、累计 token、截断原因）全部补齐；v1 只有 session_start/exchange/session_end。
- schema 版本化 + 运行级 manifest/index，支持多会话聚合与脚本化分析。
- 思考内容默认不落盘（`off`），需要审计思维链时显式开 `tail:N`/`full`。
- `benchmarking/protocol.copy_conversation_trajectory` 无需改动（只拷贝文件）；`benchmarks/experiments/range_global_model/generate_metrics.py` 依赖的三类事件名不变。

## 用录制内容审计 llm_client 与工具（示例）

- **KI-012（思考断裂/无限思考）**：开 `Z_SCOPE_CONVERSATION_REASONING=tail:4000`，对比 `exchange.finish_reason == "length"` 的 `response_message.reasoning_content` 是否被截断在句中、`iteration_control(kind=length_continuation)` 是否连续多轮，以及 `session_end.truncated` 与轮数分布。
- **KI-013（loop guard 误伤）**：`loop_guard` 事件的 `disabled_tools`/`reason`/`scope` + 之前同参数的 `tool_call`/`tool_result(cached_replay)` 链，判断是模型真死循环还是合法重查；`session_end.loop_guard_triggered` 直接给出触发与否。
- **重试/回退审计**：`attempt.outcome` 与 `delay_ms` 序列回答“为什么这一轮花了 40s”；`model_fallback` 频次反映主模型稳定性。
- **工具质量审计**：`tool_result.args_parse_error` 非空 = 模型输出参数不规范；`duration_ms` 长尾定位慢工具；`blocked=true` 即 repeat guard 生效记录。

回归测试：`tests/test_conversation_recorder.py`（单元）、`tests/test_llm_client_recording.py`（llm_client 集成埋点）、`tests/test_wiki_writer_lock.py`（锁存活探测回归）。
