# M5-TPR 引擎/治理 Backlog（20260908T055018Z run 归因产物）

来源：合并视图 17 个未挖掘 TP 的逐条归因（merged_missed_probe.py + 三轮候选史对比）。

## A1 候选层回归（4 条，最高优先——修复即恢复）

守卫 run 有候选、本轮归零。规则对象已定位：

| truth | 类别 | 守卫 run 候选规则 | 函数 |
|---|---|---|---|
| RANGE-006 | double_free | `clang_cfg_same_object_released_twice` | `_executor_cleanup_resources` (executor.c) |
| RANGE-025 | race | `clang_cfg_unsynchronized_shared_flag_or_counter` | `_lifecycle_reload_config` (lifecycle.c) |
| RANGE-027 | lost_wakeup | `clang_cfg_cond_wait_guarded_by_if` | `_lifecycle_wait_for_work` (lifecycle.c) |
| RANGE-052 | race | `clang_cfg_unsynchronized_shared_flag_or_counter` | `td_submit_task` (main.c) |

怀疑变更：9533f06 的 `cpp_domains/*` 大重构（concurrency_shared_state 369 行、protocol_ownership_logic 311 行、resource_lifecycle 285 行）+ `clang_ast_cfg.py` 的 `complete_in_function` 语义变化（恒 True → `ordering_known`）+ native indexer `ProgramEvents.h`（+165）。

**下一步（定位到门）**：对 4 个函数用当前 ClangAstCfgCandidateGenerator 跑 `generate_issues`，确认是哪一层挡住（AST 事实形状 / 规则触发条件 / complete_in_function 门）。

## A2 引擎规则盲区（7 条，三轮全 0 候选）

| truth | 类别 | 函数 |
|---|---|---|
| RANGE-024 | stack_escape | `_lifecycle_schedule_flush` |
| RANGE-035 | stale_fd | `_lifecycle_close_connection` |
| RANGE-039 | memory_leak | `_lifecycle_mesh_control_message` |
| RANGE-050 | race | `_lifecycle_watch_connection` |
| REAL-019 | busy_loop | `_runtime_read_peer_record` |
| ISSUE42-009 | check_then_act_race | `_runtime_enqueue_rcu_batch` |
| ISSUE43-009 | untrusted_pointer | `_runtime_stream_follow_wire_pointer` |

## 已裁定/已恢复

- ISSUE43-012（expired_pointer ↔ invalid_free 框架，作者裁定可计）→ `use_after_free` 家族 += `invalid_free`，**三轮全部恢复**（R2 126 / 守卫 125 / 本轮 122）。
- RANGE-009（race ↔ lock_protocol_violation，作者确认）→ `race` 家族扩充，本轮恢复。

## A0 引擎 bug：parent_release 规则的跨结构体成员污染（新定位，2 条）

REAL-003 / REAL-023 站点的候选声称 `node->tag` 泄漏，但 **ServiceNode 结构体没有 tag 成员**（key/name/payload/state/role/ref_count/mutex/children/next/left/right）；`char* tag` 属于 **struct PeerSessionResource（lifecycle.c:1070）**——parent_release 规则的成员名推导发生**跨结构体污染**。validator 的类型身份检查正确反驳（TOOLFACT 类型布局证据）。

修复方向：`clang_cfg_parent_release_without_owned_member_cleanup` 的成员名推导需要先做类型绑定校验（fact store 的类型解析已具备该能力——validator 反驳用的就是它），成员不存在于目标 struct 时不得出候选。

## B1 已落地

`allocation_limit` 家族 += `fd_allocation_without_limits`（ISSUE43-014 恢复，+1 TP）。
`race` 家族 += `lock_protocol_violation`（RANGE-009 恢复，+1 TP，作者已确认 20260908）。

## B2 框架分化待裁定（4 条，M5-8c 治理）

| truth（类别） | 位点 | 同函数现存框架 | 行距 | 裁定问题 |
|---|---|---|---|---|
| REAL-003 (double_free) | `_runtime_apply_component_stage` | memory_leak | 6 | double_free 被引擎报成泄漏——规则误框架？ |
| REAL-023 (missing_unlock) | `_runtime_link_allocated_node` | memory_leak | 9 | missing_unlock 无对应规则产出 |
| ISSUE42-023 (toctou) | `_runtime_map_linked_segment` | resource_allocation_without_limits | 0 | toctou 被报成资源分配——同位点双主张？ |
| ISSUE43-012 (expired_pointer) | `_runtime_stream_schedule_expired_flush` | invalid_free + memory_leak | 1 | expired_pointer 语义接近 invalid_free——别名候选？ |

## 引擎改标核查（2 条）

RANGE-009/RANGE-052（race truth）本轮同函数产出 `type_confusion` 框架——race 规则被改标成 type_confusion？核实 9533f06 的 concurrency_shared_state 重构。
