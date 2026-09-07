# M5-8c 复核工作表 — 21 个有效 FP（v2 口径，守卫 run 20260906T132051Z）

disposition 三选一：`truth_gap`（真缺陷，走真值扩充）/ `design_exemption`（故意不计分，进豁免清单）/ `model_error`（留 FP，回 validation 修复）。
`m5_8a_merge` = 由 M5-8a 合并消化，不属于治理对象。

## 汇总（按建议 disposition）

| # | 建议 disposition | 条目 |
|---|---|---|
| | **m5_8a_merge** | **10** |
| | **model_error(待复核)** | **4** |
| | **truth_gap(候选)** | **4** |
| | **design_exemption** | **3** |

| # | id | 类别 | 位点 | DL | 确定性证明 | 建议 disposition |
|---|---|---|---|---|---|---|
| 1 | CLANG_CFG_RESOURCE_ALLOCATION_WITHOU | resource_allocation_without_limits | utils.c:22 | V3 | - | design_exemption |
| 2 | CLANG_CFG_RESOURCE_ALLOCATION_WITHOU | resource_allocation_without_limits | utils.c:23 | V0 | external_value_controls_unbounded_allocation | design_exemption |
| 3 | CLANG_CFG_RESOURCE_ALLOCATION_WITHOU | resource_allocation_without_limits | utils.c:14 | V3 | - | design_exemption |
| 4 | GRAPH_BOUNDS_41ca788f89 | bounds | lifecycle.c:1803 | V3 | - | m5_8a_merge |
| 5 | CLANG_CFG_INTEGER_OVERFLOW_c4475510e | integer_overflow | lifecycle.c:300 | V3 | - | m5_8a_merge |
| 6 | CLANG_CFG_INTEGER_OVERFLOW_a8622033a | integer_overflow | lifecycle.c:1531 | V3 | - | m5_8a_merge |
| 7 | CLANG_CFG_MEMORY_LEAK_7834fbd3f2 | memory_leak | lifecycle.c:1468 | V3 | - | m5_8a_merge |
| 8 | CLANG_CFG_RESOURCE_ALLOCATION_WITHOU | resource_allocation_without_limits | lifecycle.c:97 | V3 | - | m5_8a_merge |
| 9 | CLANG_CFG_RESOURCE_ALLOCATION_WITHOU | resource_allocation_without_limits | network.c:175 | V3 | - | m5_8a_merge |
| 10 | CLANG_CFG_RESOURCE_ALLOCATION_WITHOU | resource_allocation_without_limits | lifecycle.c:2643 | V0 | external_value_controls_unbounded_allocation | m5_8a_merge |
| 11 | CLANG_CFG_RESOURCE_ALLOCATION_WITHOU | resource_allocation_without_limits | parser.c:224 | V3 | - | m5_8a_merge |
| 12 | GRAPH_SIGNAL_RACE_c6a75c8a70 | signal_race | main.c:133 | V3 | - | m5_8a_merge |
| 13 | CLANG_CFG_UNINITIALIZED_POINTER_daa2 | uninitialized_pointer | lifecycle.c:1767 | V0 | deterministic_cfg_obligation_path | m5_8a_merge |
| 14 | CLANG_CFG_HEAP_OVERFLOW_e7dce26746 | heap_overflow | lifecycle.c:2685 | V3 | - | model_error(待复核) |
| 15 | CLANG_CFG_INTEGER_OVERFLOW_a4fe5d34b | integer_overflow | lifecycle.c:2681 | V3 | - | model_error(待复核) |
| 16 | CLANG_CFG_RESOURCE_ALLOCATION_WITHOU | resource_allocation_without_limits | lifecycle.c:2631 | V3 | - | model_error(待复核) |
| 17 | CLANG_CFG_RESOURCE_ALLOCATION_WITHOU | resource_allocation_without_limits | lifecycle.c:2674 | V3 | - | model_error(待复核) |
| 18 | CLANG_CFG_INVALID_FREE_523fc6217c | invalid_free | lifecycle.c:3273 | V0 | deterministic_cfg_obligation_path | truth_gap(候选) |
| 19 | CLANG_CFG_MEMORY_LEAK_74299e2a73 | memory_leak | lifecycle.c:3277 | V0 | owned_member_left_live_when_parent_released | truth_gap(候选) |
| 20 | CLANG_CFG_RESOURCE_ALLOCATION_WITHOU | resource_allocation_without_limits | lifecycle.c:2286 | V0 | external_value_controls_unbounded_allocation | truth_gap(候选) |
| 21 | CLANG_CFG_RESOURCE_ALLOCATION_WITHOU | resource_allocation_without_limits | utils.c:43 | V0 | external_value_controls_unbounded_allocation | truth_gap(候选) |

## 逐条明细

### 1. CLANG_CFG_RESOURCE_ALLOCATION_WITHOUT_LIMITS_c383ff5873  —  建议: design_exemption

- **identity**: `v1|resource_allocation_without_limits|src/utils.c|_safe_calloc|structured_root_e85789a124c6d8e1|clang_cfg_external_size_`
- **类别/规则**: resource_allocation_without_limits / clang_cfg_external_size_allocation_without_limit
- **位点**: src/utils.c:22  (function: _safe_calloc)  decision_level: V3
- **source**: size_t nmemb * size_t size
- **sink**: void* _safe_calloc(size_t nmemb, size_t size) {
- **确定性证明**: 无
- **同函数 truth**: 无
- **同函数已匹配 TP**: 否
- **建议理由**: 包装/基础设施站点（utils.c/_safe_*），真值集刻意不登记；对应 M5-8b 降级或豁免清单
- **确认理由（模型）**:
  > 候选成立：`_safe_calloc`（src/utils.c:22-29）直接调用 `calloc(nmemb, size)` 且对 nmemb/size 无任何大小上限。存在一条具体的网络输入到 sink 的路径：`_td_peer_session_worker`（main.c:483）→ `td_run_peer_session_cases`（main.c:592）→ `_peer_process_session_message`（lifecycle.c:1974-1979）→ `_peer_receive_frame` 从 work_fd 套接字读取数据并 `memcpy` 进 `frame->header`（request_id 字段 uint32_t 完全由对端控制，仅校验 magic 0x5a53，无范围校验）→ `_peer_create_task_from_frame`（lifecycle.c:1913 `ta…
- **代码上下文**:
```c
     18:     }
     19:     return ptr;
     20: }
     21: 
  >> 22: void* _safe_calloc(size_t nmemb, size_t size) {
     23:     void* ptr = calloc(nmemb, size);
     24:     if (!ptr && nmemb > 0 && size > 0) {
     25:         LOG_ERROR("Memory allocation failed: %zu * %zu bytes", nmemb, size);
     26:         return NULL;
```

### 2. CLANG_CFG_RESOURCE_ALLOCATION_WITHOUT_LIMITS_7a8f435265  —  建议: design_exemption

- **identity**: `v1|resource_allocation_without_limits|src/utils.c|_safe_calloc|structured_root_8208a797ae02a695|clang_cfg_external_size_`
- **类别/规则**: resource_allocation_without_limits / clang_cfg_external_size_allocation_without_limit
- **位点**: src/utils.c:23  (function: _safe_calloc)  decision_level: V0
- **source**: nmemb * size
- **sink**: void* ptr = calloc(nmemb, size);
- **确定性证明**: external_value_controls_unbounded_allocation(外部可控值在完整路径上到达分配点，且缺少上界防护)
- **同函数 truth**: 无
- **同函数已匹配 TP**: 否
- **建议理由**: 包装/基础设施站点（utils.c/_safe_*），真值集刻意不登记；对应 M5-8b 降级或豁免清单
- **确认理由（模型）**:
  > 外部可控值在完整路径上到达分配点，且缺少上界防护
- **代码上下文**:
```c
     19:     return ptr;
     20: }
     21: 
     22: void* _safe_calloc(size_t nmemb, size_t size) {
  >> 23:     void* ptr = calloc(nmemb, size);
     24:     if (!ptr && nmemb > 0 && size > 0) {
     25:         LOG_ERROR("Memory allocation failed: %zu * %zu bytes", nmemb, size);
     26:         return NULL;
     27:     }
```

### 3. CLANG_CFG_RESOURCE_ALLOCATION_WITHOUT_LIMITS_b190d0371a  —  建议: design_exemption

- **identity**: `v1|resource_allocation_without_limits|src/utils.c|_safe_malloc|structured_root_08c4b854cee70537|clang_cfg_external_size_`
- **类别/规则**: resource_allocation_without_limits / clang_cfg_external_size_allocation_without_limit
- **位点**: src/utils.c:14  (function: _safe_malloc)  decision_level: V3
- **source**: size
- **sink**: void* ptr = malloc(size);
- **确定性证明**: 无
- **同函数 truth**: 无
- **同函数已匹配 TP**: 否
- **建议理由**: 包装/基础设施站点（utils.c/_safe_*），真值集刻意不登记；对应 M5-8b 降级或豁免清单
- **确认理由（模型）**:
  > 已验证 CWE-770（无限制资源分配）漏洞。在公开API函数 `td_process_control_message`（include/task_dispatcher.h:114 声明）中，参数 `msg` 完全由外部调用者控制。该函数调用 `_lifecycle_parse_control_message`（src/main.c:338），后者计算 `key_len = (sep - msg)`（冒号在消息中的位置），然后以 `key_len + 1` 为大小调用 `_safe_malloc`（src/lifecycle.c:97）。`_safe_malloc` 直接调用 `malloc(size)`（src/utils.c:14），未对 size 做任何限制。`_lifecycle_parse_control_message` 仅有 NULL 检查，无任何上限守卫。攻击者可通过向此公开API传递超长消息（例如在末尾放一个冒…
- **代码上下文**:
```c
     10: 
     11: int g_log_level = LOG_LEVEL_INFO;
     12: 
     13: void* _safe_malloc(size_t size) {
  >> 14:     void* ptr = malloc(size);
     15:     if (!ptr && size > 0) {
     16:         LOG_ERROR("Memory allocation failed: %zu bytes", size);
     17:         return NULL;
     18:     }
```

### 4. GRAPH_BOUNDS_41ca788f89  —  建议: m5_8a_merge

- **identity**: `v1|bounds|src/lifecycle.c|_peer_expand_task_table|structured_root_ba618d8f9d523703|unchecked_param_indexes_fixed_global_`
- **类别/规则**: bounds / unchecked_param_indexes_fixed_global_array
- **位点**: src/lifecycle.c:1803  (function: _peer_expand_task_table)  decision_level: V3
- **source**: task_index
- **sink**: g_peer_task_array[task_index] = g_peer_session_broker.tasks;
- **确定性证明**: 无
- **同函数 truth**: ISSUE41-007
- **同函数已匹配 TP**: 是（多框架重复）
- **建议理由**: 与已匹配 TP 同位点同机制家族的多框架重复 → 按 M5-8a 并入代表，不作为独立 FP 治理
- **确认理由（模型）**:
  > 验证确认可触发的 bounds 漏洞（越界写）。源：`_peer_receive_frame` 从网络 fd 读取原始字节，`request_id` (uint32_t) 完全由攻击者控制，无任何校验。`_peer_create_task_from_frame` 行 1913 将 `request_id` 转为 `int` (`task->task_id = (int)frame->header.request_id`)，当 `request_id = 0xFFFFFFFF` 时 `task_id = -1`，行 1924 调用 `_peer_expand_task_table((size_t)task->task_id)` 得到 `SIZE_MAX`。在 `_peer_expand_task_table` 中，`task_index = SIZE_MAX >= g_peer_task_array_cap` 触发扩容，`new_…
- **代码上下文**:
```c
     1799:         SAFE_FREE(old_array);
     1800:     }
     1801: 
     1802:     if (g_peer_task_array) {
  >> 1803:         g_peer_task_array[task_index] = g_peer_session_broker.tasks;
     1804:     }
     1805:     return 0;
     1806: }
     1807: 
```

### 5. CLANG_CFG_INTEGER_OVERFLOW_c4475510e8  —  建议: m5_8a_merge

- **identity**: `v1|integer_overflow|src/lifecycle.c|_lifecycle_resize_metrics|structured_root_299c94a2e2b47834|clang_cfg_allocation_size`
- **类别/规则**: integer_overflow / clang_cfg_allocation_size_arithmetic_without_overflow_guard
- **位点**: src/lifecycle.c:300  (function: _lifecycle_resize_metrics)  decision_level: V3
- **source**: g_metrics, count * sizeof(size_t)
- **sink**: g_metrics = (size_t*)_safe_realloc(g_metrics, count * sizeof(size_t));
- **确定性证明**: 无
- **同函数 truth**: RANGE-028
- **同函数已匹配 TP**: 是（多框架重复）
- **建议理由**: 与已匹配 TP 同位点同机制家族的多框架重复 → 按 M5-8a 并入代表，不作为独立 FP 治理
- **确认理由（模型）**:
  > 整数溢出候选成立：源为公共 API td_manage_runtime_config(const char* text, size_t metric_count)（include/task_dispatcher.h:115 公开声明）的 size_t 形参 metric_count，由外部调用者按 API 契约直接控制（FACT_V3_b745f1d29471f659f2db17140ffe82da）。代表调用路径 td_manage_runtime_config → _lifecycle_resize_metrics 已由代码证实：src/main.c:360 直接调用 _lifecycle_resize_metrics(metric_count)，且该调用点是后者的唯一仓库内调用者（FACT_V3_1c9544a95a458d3d1950ee4f4f3978be）。汇点为 src/lifecycle.c:300 的 coun…
- **代码上下文**:
```c
     296:     return 0;
     297: }
     298: 
     299: int _lifecycle_resize_metrics(size_t count) {
  >> 300:     g_metrics = (size_t*)_safe_realloc(g_metrics, count * sizeof(size_t));
     301:     if (!g_metrics) {
     302:         return -1;
     303:     }
     304: 
```

### 6. CLANG_CFG_INTEGER_OVERFLOW_a8622033ae  —  建议: m5_8a_merge

- **identity**: `v1|integer_overflow|src/lifecycle.c|_runtime_resize_message_buffer|structured_root_0875d1c836ea5aed|clang_cfg_allocation`
- **类别/规则**: integer_overflow / clang_cfg_allocation_size_arithmetic_without_overflow_guard
- **位点**: src/lifecycle.c:1531  (function: _runtime_resize_message_buffer)  decision_level: V3
- **source**: g_service_metrics, count * sizeof(size_t)
- **sink**: g_service_metrics = (size_t*)_safe_realloc(g_service_metrics, count * sizeof(size_t));
- **确定性证明**: 无
- **同函数 truth**: REAL-027
- **同函数已匹配 TP**: 是（多框架重复）
- **建议理由**: 与已匹配 TP 同位点同机制家族的多框架重复 → 按 M5-8a 并入代表，不作为独立 FP 治理
- **确认理由（模型）**:
  > 整数溢出缺陷确认。源：td_run_service_coordination_cases 的 size_t 参数 count（公开入口，非 static/非 test-only，声明于 internal/lifecycle.ph，为配置扫描根入口）。汇：src/lifecycle.c:1531 处 count * sizeof(size_t) 直接传递给 _safe_realloc→realloc。入口到汇的可行路径：td_run_service_coordination_cases（src/main.c:531）→ _runtime_resize_message_buffer（src/lifecycle.c:1531）。源可控性：count 作为公开 API 参数完全由调用方控制，入口内无任何范围校验直接透传。守卫分析：全部路径上不存在 count <= SIZE_MAX/sizeof(size_t) 之类的前置溢出检查；被调…
- **代码上下文**:
```c
     1527:     return 0;
     1528: }
     1529: 
     1530: int _runtime_resize_message_buffer(size_t count) {
  >> 1531:     g_service_metrics = (size_t*)_safe_realloc(g_service_metrics, count * sizeof(size_t));
     1532:     if (!g_service_metrics) {
     1533:         return -1;
     1534:     }
     1535:     g_service_metrics[0] = count;
```

### 7. CLANG_CFG_MEMORY_LEAK_7834fbd3f2  —  建议: m5_8a_merge

- **identity**: `v1|memory_leak|src/lifecycle.c|_runtime_release_channel_role|structured_root_f37d3dc302b19caa|clang_cfg_parent_release_w`
- **类别/规则**: memory_leak / clang_cfg_parent_release_without_owned_member_cleanup
- **位点**: src/lifecycle.c:1468  (function: _runtime_release_channel_role)  decision_level: V3
- **source**: ServiceNode* node = _service_alloc_node(key, "member");
- **sink**: SAFE_FREE(node);
- **确定性证明**: 无
- **同函数 truth**: REAL-021
- **同函数已匹配 TP**: 是（多框架重复）
- **建议理由**: 与已匹配 TP 同位点同机制家族的多框架重复 → 按 M5-8a 并入代表，不作为独立 FP 治理
- **确认理由（模型）**:
  > 函数 _runtime_release_channel_role（src/lifecycle.c:1461-1470）调用 _service_alloc_node(key, "member") 分配 ServiceNode，其中 line 1125 通过 _str_dup(payload) 为 node->payload 分配了堆内存（"member" 的副本）。随后 line 1467 调用 _service_release_by_role(node, 0)，该函数在 is_member=0 时仅释放 node->name（line 1171），不释放 node->payload。最后 line 1468 的 SAFE_FREE(node) 仅释放 struct 本身，不递归释放成员指针。项目中没有 _service_release_node/_service_free_node 等专用清理函数。因此 node->payloa…
- **代码上下文**:
```c
     1464:         return -1;
     1465:     }
     1466:     node->role = role;
     1467:     _service_release_by_role(node, 0);
  >> 1468:     SAFE_FREE(node);
     1469:     return 0;
     1470: }
     1471: 
     1472: int _runtime_switch_io_mode(int fd) {
```

### 8. CLANG_CFG_RESOURCE_ALLOCATION_WITHOUT_LIMITS_24714c94dd  —  建议: m5_8a_merge

- **identity**: `v1|resource_allocation_without_limits|src/lifecycle.c|_lifecycle_parse_control_message|structured_root_5e8db8cb4d94f7fa|`
- **类别/规则**: resource_allocation_without_limits / clang_cfg_external_size_allocation_without_limit
- **位点**: src/lifecycle.c:97  (function: _lifecycle_parse_control_message)  decision_level: V3
- **source**: key_len + 1
- **sink**: char* key = (char*)_safe_malloc(key_len + 1);
- **确定性证明**: 无
- **同函数 truth**: RANGE-018
- **同函数已匹配 TP**: 是（多框架重复）
- **建议理由**: 与已匹配 TP 同位点同机制家族的多框架重复 → 按 M5-8a 并入代表，不作为独立 FP 治理
- **确认理由（模型）**:
  > 已验证 CWE-770 资源无限制分配缺陷，四个要素全部由代码证据闭环：(1) 源：入口 td_process_control_message(const char* msg, int transport_id) 声明于公共头文件 include/task_dispatcher.h:114，msg 为外部调用方直接提供的无长度约束字符串；(2) 汇：src/lifecycle.c:97 的 char* key = (char*)_safe_malloc(key_len + 1)，其中 key_len = (size_t)(strchr(msg, ':') - msg)（第 95-96 行）完全由 msg 中 ':' 的位置决定；(3) 路径：src/main.c:338 直接调用 _lifecycle_parse_control_message(msg)，发生在任何长度校验之前；(4) 守卫：_lifecycle_parse_c…
- **代码上下文**:
```c
     93:     }
     94: 
     95:     const char* sep = strchr(msg, ':');
     96:     size_t key_len = (size_t)(sep - msg);
  >> 97:     char* key = (char*)_safe_malloc(key_len + 1);
     98:     if (!key) {
     99:         return NULL;
     100:     }
     101: 
```

### 9. CLANG_CFG_RESOURCE_ALLOCATION_WITHOUT_LIMITS_aecb80411f  —  建议: m5_8a_merge

- **identity**: `v1|resource_allocation_without_limits|src/network.c|_net_recv_string|structured_root_ae1b58e6d2f18896|clang_cfg_external`
- **类别/规则**: resource_allocation_without_limits / clang_cfg_external_size_allocation_without_limit
- **位点**: src/network.c:175  (function: _net_recv_string)  decision_level: V3
- **source**: max_len + 1
- **sink**: char* buffer = (char*)_safe_malloc(max_len + 1);
- **确定性证明**: 无
- **同函数 truth**: RANGE-015
- **同函数已匹配 TP**: 是（多框架重复）
- **建议理由**: 与已匹配 TP 同位点同机制家族的多框架重复 → 按 M5-8a 并入代表，不作为独立 FP 治理
- **确认理由（模型）**:
  > 该候选成立：公共 API `td_receive_string`（include/task_dispatcher.h:108 声明，src/main.c:313-315）将调用者提供的 `size_t max_len` 参数不作任何校验、无任何上限限制地直接转发给 `_net_recv_string`（src/network.c:174），后者在第 175 行执行 `_safe_malloc(max_len + 1)`。源（调用者可控的 max_len）、汇（堆分配）、源可控性（参数直达分配点，函数体仅一行转发）、缺守卫（分配前既无 max_len 大小检查也无调用方上限，_safe_malloc 只是 malloc 包装器，仅返回 NULL 表示失败，不能阻止超大分配尝试）全部由代码证据证实。调用者传入任意大 max_len 即可触发不受限分配，符合 CWE-770（无限制的资源分配）。该入口为 header 声明的公共 AP…
- **代码上下文**:
```c
     171:     return 0;
     172: }
     173: 
     174: char* _net_recv_string(int fd, size_t max_len) {
  >> 175:     char* buffer = (char*)_safe_malloc(max_len + 1);
     176:     if (!buffer) {
     177:         return NULL;
     178:     }
     179:     
```

### 10. CLANG_CFG_RESOURCE_ALLOCATION_WITHOUT_LIMITS_d514f8731e  —  建议: m5_8a_merge

- **identity**: `v1|resource_allocation_without_limits|src/lifecycle.c|_runtime_cleanup_tls_reserve|structured_root_9e969b19d2fa9614|clan`
- **类别/规则**: resource_allocation_without_limits / clang_cfg_external_size_allocation_without_limit
- **位点**: src/lifecycle.c:2643  (function: _runtime_cleanup_tls_reserve)  decision_level: V0
- **source**: reserve_size ? reserve_size : 4096
- **sink**: info.reserved_base = _safe_malloc(reserve_size ? reserve_size : 4096);
- **确定性证明**: external_value_controls_unbounded_allocation(外部可控值在完整路径上到达分配点，且缺少上界防护)
- **同函数 truth**: ISSUE42-022
- **同函数已匹配 TP**: 是（多框架重复）
- **建议理由**: 与已匹配 TP 同位点同机制家族的多框架重复 → 按 M5-8a 并入代表，不作为独立 FP 治理
- **确认理由（模型）**:
  > 外部可控值在完整路径上到达分配点，且缺少上界防护
- **代码上下文**:
```c
     2639: 
     2640: int _runtime_cleanup_tls_reserve(size_t reserve_size, int tlscb_ready) {
     2641:     RuntimeTlscbInfo info;
     2642:     memset(&info, 0, sizeof(info));
  >> 2643:     info.reserved_base = _safe_malloc(reserve_size ? reserve_size : 4096);
     2644:     info.reserved_size = reserve_size;
     2645:     if (tlscb_ready) {
     2646:         info.tlscb = (char*)_safe_malloc(64);
     2647:     }
```

### 11. CLANG_CFG_RESOURCE_ALLOCATION_WITHOUT_LIMITS_fa6b779fa3  —  建议: m5_8a_merge

- **identity**: `v1|resource_allocation_without_limits|src/parser.c|_serialize_task|structured_root_b65456826d5d3220|clang_cfg_external_s`
- **类别/规则**: resource_allocation_without_limits / clang_cfg_external_size_allocation_without_limit
- **位点**: src/parser.c:224  (function: _serialize_task)  decision_level: V3
- **source**: total_len
- **sink**: *buffer = _safe_malloc(total_len);
- **确定性证明**: 无
- **同函数 truth**: RANGE-017
- **同函数已匹配 TP**: 是（多框架重复）
- **建议理由**: 与已匹配 TP 同位点同机制家族的多框架重复 → 按 M5-8a 并入代表，不作为独立 FP 治理
- **确认理由（模型）**:
  > 该候选为 CWE-770 无上限资源分配，证据链完整闭合。(1) 汇点：src/parser.c:223-224 中 `total_len = sizeof(TaskHeader) + payload_len` 后立即执行 `*buffer = _safe_malloc(total_len)`，分配大小完全由 `payload_len` 驱动。(2) 源可控性：`payload_len` 取自 `Payload` 联合体（include/types.h:49-63）的 `binary.size`/`text.length`（均为调用方可控的 size_t 字段）或命令字符串 strlen；公开入口 `td_serialize_task_message(const Task* task,...)`（src/main.c:329-331）为无校验透传，调用方完全控制 Task 载荷字段，网络任务路径（src/executor.c:1…
- **代码上下文**:
```c
     220:         payload_data = task->payload.binary.data;
     221:     }
     222:     
     223:     size_t total_len = sizeof(TaskHeader) + payload_len;
  >> 224:     *buffer = _safe_malloc(total_len);
     225:     if (!*buffer) {
     226:         return -1;
     227:     }
     228:     
```

### 12. GRAPH_SIGNAL_RACE_c6a75c8a70  —  建议: m5_8a_merge

- **identity**: `v1|signal_race|src/main.c|td_init|structured_root_651e786cd5a02ca9|signal_path_mutates_shared_state_or_logs|signal/excep`
- **类别/规则**: signal_race / signal_path_mutates_shared_state_or_logs
- **位点**: src/main.c:133  (function: td_init)  decision_level: V3
- **source**: signal/exception handler path
- **sink**: g_dispatcher.threads = (pthread_t*)_safe_calloc(
- **确定性证明**: 无
- **同函数 truth**: RANGE-013
- **同函数已匹配 TP**: 是（多框架重复）
- **建议理由**: 与已匹配 TP 同位点同机制家族的多框架重复 → 按 M5-8a 并入代表，不作为独立 FP 治理
- **确认理由（模型）**:
  > 验证为 signal_race (CWE-479) 漏洞。信号处理链 _signal_handler (src/main.c:51-54) 注册于 SIGINT/SIGTERM (src/main.c:203-204)，在 td_init 中被 main() 调用 (src/main.c:664)。信号触发路径：_signal_handler → td_runtime_handle_signal (src/main.c:732) → _runtime_handle_fault_signal (lifecycle.c:2955) → _runtime_capture_signal_stack (lifecycle.c:2560) 和 _runtime_write_exception_record (lifecycle.c:2772)。该信号处理链在信号上下文中执行了多项非异步信号安全 (async-signal-unsafe) 操…
- **代码上下文**:
```c
     129:     memset(&g_dispatcher, 0, sizeof(Dispatcher));
     130:     
     131:     if (config_str) {
     132:         if (_parse_config_string(config_str, &g_dispatcher.config) != 0) {
  >> 133:             LOG_ERROR("Failed to parse config");
     134:             return -1;
     135:         }
     136:     } else {
     137:         g_dispatcher.config.queue_size = DEFAULT_QUEUE_SIZE;
```

### 13. CLANG_CFG_UNINITIALIZED_POINTER_daa28aec63  —  建议: m5_8a_merge

- **identity**: `v1|uninitialized_pointer|src/lifecycle.c|_peer_prepare_retry_context|uninitialized_pointer_unknown_char__tag_char__tag_r`
- **类别/规则**: uninitialized_pointer / clang_cfg_pointer_may_be_uninitialized_before_use
- **位点**: src/lifecycle.c:1767  (function: _peer_prepare_retry_context)  decision_level: V0
- **source**: char* tag;
- **sink**: return tag[0];
- **确定性证明**: deterministic_cfg_obligation_path(确定性 AST/CFG 事件证实了所报告的安全义务)
- **同函数 truth**: ISSUE41-006
- **同函数已匹配 TP**: 是（多框架重复）
- **建议理由**: 与已匹配 TP 同位点同机制家族的多框架重复 → 按 M5-8a 并入代表，不作为独立 FP 治理
- **确认理由（模型）**:
  > 确定性 AST/CFG 事件证实了所报告的安全义务
- **代码上下文**:
```c
     1763:         return -1;
     1764:     }
     1765: 
     1766:     if (g_peer_partition_count >= PEER_RESOURCE_LIMIT) {
  >> 1767:         return tag[0];
     1768:     }
     1769:     g_peer_partition_count++;
     1770:     partition->resource_id = (int)g_peer_partition_count;
     1771:     partition->tag = _str_dup("cs-shm-partition");
```

### 14. CLANG_CFG_HEAP_OVERFLOW_e7dce26746  —  建议: model_error(待复核)

- **identity**: `v1|heap_overflow|src/lifecycle.c|_runtime_header_alloc|structured_root_c2898ca0f0f5504d|clang_cfg_narrowed_allocation_or`
- **类别/规则**: heap_overflow / clang_cfg_narrowed_allocation_original_length_copy
- **位点**: src/lifecycle.c:2685  (function: _runtime_header_alloc)  decision_level: V3
- **source**: char* raw = (char*)_safe_malloc(size + 8u);
- **sink**: memcpy(raw, "I42ALLOC", 8);
- **确定性证明**: 无
- **同函数 truth**: 无
- **同函数已匹配 TP**: 否
- **建议理由**: 无确定性佐证；需人工复核确认理由是否成立（若成立转 truth_gap 候选）
- **确认理由（模型）**:
  > 已通过代码证据确认完整触发路径。公开 API td_runtime_configure_memory 的 uint64_t map_size 参数完全由外部调用方控制，未经任何范围校验即流入 _runtime_apply_memory_plan → _runtime_release_hash_node(node_size+32u, use_header_pool=1) → _runtime_header_alloc(size+8u) → memcpy(raw,"I42ALLOC",8)。当 map_size ∈ [2⁶⁴-40, 2⁶⁴-33] 时，size+8u 无符号回绕使分配量变为 0-7 字节，而 memcpy 固定写入 8 字节，导致堆上越界写入 1-8 字节。_safe_malloc(0..7) 在此范围内几乎必然返回非 NULL 指针。整条链路上不存在任何防止整数回绕或越界拷贝的守卫（if(!raw) 仅处理 ma…
- **代码上下文**:
```c
     2681:     char* raw = (char*)_safe_malloc(size + 8u);
     2682:     if (!raw) {
     2683:         return NULL;
     2684:     }
  >> 2685:     memcpy(raw, "I42ALLOC", 8);
     2686:     return raw + 8u;
     2687: }
     2688: 
     2689: static void _runtime_noop_free(void* ptr) {
```

### 15. CLANG_CFG_INTEGER_OVERFLOW_a4fe5d34b7  —  建议: model_error(待复核)

- **identity**: `v1|integer_overflow|src/lifecycle.c|_runtime_header_alloc|structured_root_13ca2a8807e2370c|clang_cfg_allocation_size_ari`
- **类别/规则**: integer_overflow / clang_cfg_allocation_size_arithmetic_without_overflow_guard
- **位点**: src/lifecycle.c:2681  (function: _runtime_header_alloc)  decision_level: V3
- **source**: size + 8u
- **sink**: char* raw = (char*)_safe_malloc(size + 8u);
- **确定性证明**: 无
- **同函数 truth**: 无
- **同函数已匹配 TP**: 否
- **建议理由**: 无确定性佐证；需人工复核确认理由是否成立（若成立转 truth_gap 候选）
- **确认理由（模型）**:
  > 已验证整数溢出漏洞。源：公共API函数 td_runtime_configure_memory (include/task_dispatcher.h:133-134) 的参数 map_size (uint64_t) 完全由外部调用者控制。完整调用路径：td_runtime_configure_memory → _runtime_apply_memory_plan → _runtime_release_hash_node((size_t)map_size, 1) → _runtime_header_alloc(node_size + 32u) → _safe_malloc(size + 8u) (src/lifecycle.c:2681)。当 node_size 在 [SIZE_MAX-39, SIZE_MAX-32] 范围内时，node_size+32u 不溢出但 size+8u 溢出，导致 _safe_malloc 收到一个很…
- **代码上下文**:
```c
     2677:     return NULL;
     2678: }
     2679: 
     2680: static void* _runtime_header_alloc(size_t size) {
  >> 2681:     char* raw = (char*)_safe_malloc(size + 8u);
     2682:     if (!raw) {
     2683:         return NULL;
     2684:     }
     2685:     memcpy(raw, "I42ALLOC", 8);
```

### 16. CLANG_CFG_RESOURCE_ALLOCATION_WITHOUT_LIMITS_8806e35df0  —  建议: model_error(待复核)

- **identity**: `v1|resource_allocation_without_limits|src/lifecycle.c|_runtime_create_shared_zone|structured_root_3a1624d9fe0f2471|clang`
- **类别/规则**: resource_allocation_without_limits / clang_cfg_external_size_allocation_without_limit
- **位点**: src/lifecycle.c:2631  (function: _runtime_create_shared_zone)  decision_level: V3
- **source**: size ? size : 1
- **sink**: zone->addr = _safe_malloc(size ? size : 1);
- **确定性证明**: 无
- **同函数 truth**: ISSUE42-021
- **同函数已匹配 TP**: 否
- **建议理由**: 无确定性佐证；需人工复核确认理由是否成立（若成立转 truth_gap 候选）
- **确认理由（模型）**:
  > 经过完整调用链分析，确认存在真实的 CWE-770 资源分配无限制漏洞。漏洞路径：公开 API `td_runtime_configure_memory`（声明于 include/task_dispatcher.h:133-134）的 `map_size` 参数完全由外部调用者控制，该函数在 src/main.c:712-715 为薄封装，无任何参数校验，直接将 `map_size` 转发给 _runtime_apply_memory_plan（src/lifecycle.c:2896-2906）。_runtime_apply_memory_plan 在 src/lifecycle.c:2901 行以 `(size_t)map_size` 直接传递给 _runtime_create_shared_zone，该函数在 src/lifecycle.c:2631 行调用 `_safe_malloc(size ? size : 1)` …
- **代码上下文**:
```c
     2627:         return NULL;
     2628:     }
     2629:     STR_COPY(zone->name, stable_name);
     2630:     zone->size = size;
  >> 2631:     zone->addr = _safe_malloc(size ? size : 1);
     2632: 
     2633:     LOCK(&g_runtime_memzone_lock);
     2634:     zone->next = g_runtime_memzones;
     2635:     g_runtime_memzones = zone;
```

### 17. CLANG_CFG_RESOURCE_ALLOCATION_WITHOUT_LIMITS_75226a729e  —  建议: model_error(待复核)

- **identity**: `v1|resource_allocation_without_limits|src/lifecycle.c|_runtime_map_linked_segment|structured_root_ac0b275ca47d7938|clang`
- **类别/规则**: resource_allocation_without_limits / clang_cfg_external_size_allocation_without_limit
- **位点**: src/lifecycle.c:2674  (function: _runtime_map_linked_segment)  decision_level: V3
- **source**: shm_size ? shm_size : 1
- **sink**: return _safe_malloc(shm_size ? shm_size : 1);
- **确定性证明**: 无
- **同函数 truth**: ISSUE42-023
- **同函数已匹配 TP**: 否
- **建议理由**: 无确定性佐证；需人工复核确认理由是否成立（若成立转 truth_gap 候选）
- **确认理由（模型）**:
  > 已验证资源分配无上限(CWE-770)漏洞。源:shm_size 来自公开 API 调用方传入的 wire 帧头 RuntimeFrameHeader.size(uint32_t,src/lifecycle.c:2018-2026),经 _runtime_receive_frame(lifecycle.c:2832-2833)memcpy 拷贝,最大可达 UINT32_MAX(约4GB)。汇:生命周期函数 _runtime_map_linked_segment(lifecycle.c:2668/2674)调用 _safe_malloc(shm_size?shm_size:1),_safe_malloc(utils.c:13-20)是无上限的 malloc 包装。可控路径:公开 API td_run_runtime_maintenance / td_runtime_apply_shared_memory_event(include…
- **代码上下文**:
```c
     2670: 
     2671:         int fd = open(link_path, O_RDONLY);
     2672:         if (fd >= 0) {
     2673:             close(fd);
  >> 2674:             return _safe_malloc(shm_size ? shm_size : 1);
     2675:         }
     2676:     }
     2677:     return NULL;
     2678: }
```

### 18. CLANG_CFG_INVALID_FREE_523fc6217c  —  建议: truth_gap(候选)

- **identity**: `v1|invalid_free|src/lifecycle.c|_runtime_stream_schedule_expired_flush|structured_root_7263f959b094d528|clang_cfg_free_d`
- **类别/规则**: invalid_free / clang_cfg_free_derived_pointer_alias
- **位点**: src/lifecycle.c:3273  (function: _runtime_stream_schedule_expired_flush)  decision_level: V0
- **source**: char* expired_snapshot = job->snapshot;
- **sink**: SAFE_FREE(expired_snapshot);
- **确定性证明**: deterministic_cfg_obligation_path(确定性 AST/CFG 事件证实了所报告的安全义务)
- **同函数 truth**: ISSUE43-012
- **同函数已匹配 TP**: 否
- **建议理由**: 确定性证明 + 模型 双方一致确认，最可能是真值遗漏 → 人工复核后走 truth 扩充
- **确认理由（模型）**:
  > 确定性 AST/CFG 事件证实了所报告的安全义务
- **代码上下文**:
```c
     3269: 
     3270:     STR_COPY(job->journal_path, journal_path ? journal_path : "runtime-stream");
     3271:     job->snapshot = _str_dup(job->journal_path);
     3272:     char* expired_snapshot = job->snapshot;
  >> 3273:     SAFE_FREE(expired_snapshot);
     3274: 
     3275:     pthread_t tid;
     3276:     if (pthread_create(&tid, NULL, _runtime_stream_flush_worker, job) != 0) {
     3277:         SAFE_FREE(job);
```

### 19. CLANG_CFG_MEMORY_LEAK_74299e2a73  —  建议: truth_gap(候选)

- **identity**: `v1|memory_leak|src/lifecycle.c|_runtime_stream_schedule_expired_flush|structured_root_a1e81984b065682a|clang_cfg_parent_`
- **类别/规则**: memory_leak / clang_cfg_parent_release_without_owned_member_cleanup
- **位点**: src/lifecycle.c:3277  (function: _runtime_stream_schedule_expired_flush)  decision_level: V0
- **source**: job->snapshot = _str_dup(job->journal_path) at line 3271
- **sink**: SAFE_FREE(job);
- **确定性证明**: owned_member_left_live_when_parent_released(被识别为归属成员的字段在其父对象被释放时仍然存活)
- **同函数 truth**: ISSUE43-012
- **同函数已匹配 TP**: 否
- **建议理由**: 确定性证明 + 模型 双方一致确认，最可能是真值遗漏 → 人工复核后走 truth 扩充
- **确认理由（模型）**:
  > 被识别为归属成员的字段在其父对象被释放时仍然存活
- **代码上下文**:
```c
     3273:     SAFE_FREE(expired_snapshot);
     3274: 
     3275:     pthread_t tid;
     3276:     if (pthread_create(&tid, NULL, _runtime_stream_flush_worker, job) != 0) {
  >> 3277:         SAFE_FREE(job);
     3278:         return -1;
     3279:     }
     3280:     pthread_detach(tid);
     3281:     return 0;
```

### 20. CLANG_CFG_RESOURCE_ALLOCATION_WITHOUT_LIMITS_2ce921cde6  —  建议: truth_gap(候选)

- **identity**: `v1|resource_allocation_without_limits|src/lifecycle.c|_runtime_close_thread_cache|structured_root_c1db2e417dab9d6a|clang`
- **类别/规则**: resource_allocation_without_limits / clang_cfg_external_size_allocation_without_limit
- **位点**: src/lifecycle.c:2286  (function: _runtime_close_thread_cache)  decision_level: V0
- **source**: block_size ? block_size : 64
- **sink**: cache->cached_blocks[slot] = (char*)_safe_malloc(block_size ? block_size : 64);
- **确定性证明**: external_value_controls_unbounded_allocation(外部可控值在完整路径上到达分配点，且缺少上界防护)
- **同函数 truth**: ISSUE42-002
- **同函数已匹配 TP**: 否
- **建议理由**: 确定性证明 + 模型 双方一致确认，最可能是真值遗漏 → 人工复核后走 truth 扩充
- **确认理由（模型）**:
  > 外部可控值在完整路径上到达分配点，且缺少上界防护
- **代码上下文**:
```c
     2282:         return -1;
     2283:     }
     2284: 
     2285:     size_t slot = cache->cached_count % ARRAY_SIZE(cache->cached_blocks);
  >> 2286:     cache->cached_blocks[slot] = (char*)_safe_malloc(block_size ? block_size : 64);
     2287:     cache->cached_count++;
     2288: 
     2289:     SAFE_FREE(g_runtime_thread_cache);
     2290:     return 0;
```

### 21. CLANG_CFG_RESOURCE_ALLOCATION_WITHOUT_LIMITS_3df9bebea6  —  建议: truth_gap(候选)

- **identity**: `v1|resource_allocation_without_limits|src/utils.c|_str_dup|structured_root_5c9b6de94b237448|clang_cfg_external_size_allo`
- **类别/规则**: resource_allocation_without_limits / clang_cfg_external_size_allocation_without_limit
- **位点**: src/utils.c:43  (function: _str_dup)  decision_level: V0
- **source**: len
- **sink**: char* dup = (char*)_safe_malloc(len);
- **确定性证明**: external_value_controls_unbounded_allocation(外部可控值在完整路径上到达分配点，且缺少上界防护)
- **同函数 truth**: 无
- **同函数已匹配 TP**: 否
- **建议理由**: 确定性证明 + 模型 双方一致确认，最可能是真值遗漏 → 人工复核后走 truth 扩充
- **确认理由（模型）**:
  > 外部可控值在完整路径上到达分配点，且缺少上界防护
- **代码上下文**:
```c
     39: 
     40: char* _str_dup(const char* s) {
     41:     if (!s) return NULL;
     42:     size_t len = strlen(s) + 1;
  >> 43:     char* dup = (char*)_safe_malloc(len);
     44:     if (dup) {
     45:         memcpy(dup, s, len);
     46:     }
     47:     return dup;
```
