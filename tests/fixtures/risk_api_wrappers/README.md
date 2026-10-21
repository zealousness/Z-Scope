# risk_api_wrappers fixture — 标注基线

用途:验证用户自定义风险接口识别强化(13 类角色模型)在候选与规则层的端到端效果。

## 用户自定义接口标注(ground truth)

写入 user_config.xlsx `resource`/`lock` 表的期望行:

| symbol_name        | kind              | pair            | 备注 |
|--------------------|-------------------|-----------------|------|
| _safe_malloc       | allocator         | _safe_free      | 含关键词,启发式可识别 |
| _safe_free         | deallocator       | _safe_malloc    | |
| get_buffer         | allocator         | put_buffer      | **无关键词**,只能靠 body 推理/LLM/人工 |
| put_buffer         | deallocator       | get_buffer      | **无关键词** |
| mutex_enter        | lock              | mutex_exit      | **无 "lock" 关键词** |
| mutex_exit         | unlock            | mutex_enter     | **无关键词** |
| cb_register        | callback_register |                 | 回调注册器 |
| file_open_wrap     | io_acquire        | file_close_wrap | fd 获取 |
| file_close_wrap    | io_release        | file_open_wrap  | fd 释放 |
| net_send_wrap      | send_sink         |                 | 网络发送 sink |
| net_recv_wrap      | recv_source       |                 | 外部输入源 |
| audit_log          | format_sink       |                 | 格式化 sink |

`src/wrap_impl.c` 中包装函数体各自收敛到唯一标准风险 API,是 body 推理与
LLM 审查的证据来源;`channel_up`/`channel_down`/`get_buffer`/`put_buffer`
刻意不带任何 action 关键词。

## 期望缺陷(entry.c)

| 函数 | 期望 defect_class | 依赖的自定义接口 |
|------|-------------------|------------------|
| leak_via_get_buffer | memory_leak | get_buffer/put_buffer |
| unlock_missing_on_error | missing_unlock | mutex_enter/mutex_exit |
| callback_under_lock | held_lock_callback | mutex_enter + cb_register |
| fd_leak_on_error | fd_leak | file_open_wrap/file_close_wrap |
| recv_len_confusion | signed_unsigned | net_recv_wrap |
| log_user_format | format_string | audit_log |

## 基线记录(2025-09,强化前)

- `_safe_malloc/_safe_free`:全部层可识别(名称启发式)。
- `get_buffer/put_buffer`、`mutex_enter/mutex_exit`、全部 io/net/log/cb
  包装:启发式 0 识别;无 workbook 行时规则层全部漏报。
- `security_map` 信号层:所有包装均不命中(词边界正则)。
