## v3_fp #1: CLANG_CFG_MEMORY_LEAK_dce5a2fbb1
- truth: None | rule: clang_cfg_parent_release_without_owned_member_cleanup | func: _runtime_remove_file_record
- loc: src/lifecycle.c:1263
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["cleanup_coverage", "ownership_transfer"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_03abffbe7c3264ce8af66a6b8afacb6c", "FACT_V3_11e4
- reasoning: 内存泄漏成立且有完整触发路径。源：_runtime_remove_file_record（src/lifecycle.c:1258）调用 _service_alloc_node(name, "/virtual/fs/node")，后者在第1125行通过 _str_dup（src/utils.c:40-48，内部 _safe_malloc 堆分配）创建 node->payload，并在1127行初始化 mutex。汇：该函数仅在第1262行释放 node->name、第1263行释放 node，全程未释放 node->payload，且未调用 pthread_mutex_destroy，堆字符串随结构体 free 而泄漏（CWE-401）。所有权确认：本函数未调用 _service_insert_locked，节点未挂入任何全局注册表，payload 无所有权转移（FACT_V3_11e41b28ed6388896ed502e939761fd0）。清理覆盖确认：同文件正确模式 _runtime_detach_component_record（1251-1253行）与 _runtime_apply_component_stage（1231行）均先释放 payload，SAFE_FREE 宏（include/common.h:24）仅释放置空指针，不存在隐式 payload 释放，本函数缺省属遗漏（FACT_V3_03abffbe7c3264ce8af66a6b8afacb6c）。路径：入口 td_run_service_cleanup_cases（src/main.c:490-503）第498行直接调用 _runtime_remove_file_record（path-edge:0 与 evidence:positive:2）。泄漏对象为固定字面量 "/virtual/fs/node" 的堆副本，每次成功调用必然泄漏，与 name 取值无关，无任何守卫可阻断。

## v3_fp #2: GRAPH_PREMATURE_DESTROY_95cf6c8971
- truth: None | rule: destroy_shared_pool_while_active_tasks_remain | func: _runtime_release_packet_pool
- loc: src/lifecycle.c:2348
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["source_controllability", "source_sink_reachability", "value_range"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_087f1f7652e8e4e4ca875
- reasoning: 已证实具体且必然触发的缺陷：_runtime_release_packet_pool（src/lifecycle.c:2339-2358）在 active_tasks>0 分支（2348行）先释放 g_runtime_pbuf_pool->buffer（2349行）与 g_runtime_pbuf_pool（2350行），随后第2351-2352行读取 g_runtime_pbuf_pool->buffer 与 ->active_tasks。SAFE_FREE（include/common.h:24）释放后把指针置 NULL，因此第2351行三元条件 g_runtime_pbuf_pool->buffer 是对 NULL 指针的解引用，进程必然崩溃（SIGSEGV）；若宏不置空则为 use-after-free。源码路径：入口 td_run_runtime_maintenance（src/main.c:756）第784行以字面量 active_tasks=1 调用 td_runtime_refresh_cache（src/main.c:706-710）→ _runtime_refresh_worker_context（src/lifecycle.c:2886-2894，第2891行调用）→ _runtime_release_packet_pool（src/lifecycle.c:2348）。source 可控性为硬编码：active_tasks 恒为 1，分支无任何条件可跳过；guard 分析显示无 NULL 检查，SAFE_FREE 置空反而把读已释放内存变成确定的空指针解引用，缺陷每次调用入口 API 即触发，属于 premature_destroy/CWE-416 语义下的确定性缺陷。

## v3_fp #3: CLANG_CFG_MEMORY_LEAK_57a2e42dae
- truth: None | rule: clang_cfg_parent_release_without_owned_member_cleanup | func: _runtime_release_reader_channel
- loc: src/lifecycle.c:1300
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["cleanup_coverage", "ownership_transfer"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_4483d61fdce5af0f46c2a13e7ab35a5a", "FACT_V3_aa78
- reasoning: 内存泄漏候选经代码验证成立。源头：_runtime_release_reader_channel(src/lifecycle.c:1289) 调用 _service_alloc_node(key, "reader")，后者在 1125 行将 _str_dup("reader") 的堆副本赋给 node->payload，同时 1124 行将 _str_dup(key) 赋给 node->name（_str_dup 通过 _safe_malloc/malloc 分配，快照确认返回调用者所有的堆指针）。汇点：SAFE_FREE(node)(src/lifecycle.c:1300) 仅释放结构体本身（include/common.h:24 的宏只对传入指针 free 并置空）。守卫分析：_service_release_by_role(src/lifecycle.c:1164-1174) 在 is_member=0 时只 SAFE_FREE(node->name)，不释放 node->payload；_runtime_release_reader_channel 的两条分支（1295 行 role==1 与 1299 行 else）均以 is_member=0 调用它，随后 SAFE_FREE(node)，因此 node->payload 在两条路径上都从未被释放，也没有任何外部析构器或所有权转移覆盖它。触发路径：公开入口 td_run_service_cleanup_cases(src/main.c:490-503) 在 500 行调用 _runtime_release_reader_channel，每次调用固定泄漏一份 "reader" 字符串副本。负向证据（"成员是否归父节点所有、是否有外部析构器"）已被代码直接证伪：payload 由 _service_alloc_node 内分配并归 node 所有，函数内无其他释放逻辑。判定 verified，CWE-401 内存泄漏。

## v3_fp #4: CLANG_CFG_INTEGER_OVERFLOW_c4475510e8
- truth: None | rule: clang_cfg_allocation_size_arithmetic_without_overflow_guard | func: _lifecycle_resize_metrics
- loc: src/lifecycle.c:300
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["guard_dominance", "source_controllability", "source_sink_reachability"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_5cf641393165b626b
- reasoning: 整数溢出候选已由代码证据完整证实。源是公共 API td_manage_runtime_config（include/task_dispatcher.h:115 声明）的 size_t 参数 metric_count：头文件对该参数无任何取值范围约束，实现 src/main.c:356-362 也不做校验，调用方可控制完整 size_t 范围。路径是直接无条件调用：src/main.c:360 将 metric_count 原样传给 _lifecycle_resize_metrics。汇点是 src/lifecycle.c:300 的 count * sizeof(size_t)：该乘法前没有任何 a <= SIZE_MAX/sizeof(size_t) 类前置检查，_safe_realloc（src/utils.c:31-38）仅包装 realloc 也不做溢出校验，整条路径无任何等价防护。触发后果明确：64 位下取 count = 0x2000000000000001 时乘积回绕为 8，realloc 仅分配 8 字节，随后 src/lifecycle.c:305-307 的循环向 g_metrics[0..count-1] 写入 count 个元素，形成大规模堆越界写。零仓库内调用者属于头文件声明公共 API 的预期情况，不能作为拒绝依据；该公共 API 本身就是外部触发点，满足 verified 所需的源、汇点、可控性与可行路径。

## v3_fp #5: CLANG_CFG_UNCHECKED_ALLOCATION_a39466f5db
- truth: None | rule: clang_cfg_allocation_result_used_without_null_check | func: _runtime_stream_build_index
- loc: src/lifecycle.c:3205
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["guard_dominance", "source_controllability", "source_sink_reachability"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_6e91c0c9e91f90817
- reasoning: 函数 _runtime_stream_build_index（src/lifecycle.c:3194-3208）使用 _safe_calloc 分配 index 数组，但 _safe_calloc 在底层 calloc 失败且 nmemb>0、size>0 时仅记录日志并返回 NULL（src/utils.c:22-29），不保证非 NULL。调用方在 line 3204-3205 直接执行 index[0] = &first 与 (int)index[0]->length，两者之间无任何 NULL 检查，构成 CWE-690 未检查分配返回值导致的空指针解引用。entry_count 源自外部 wire 缓冲区中的 RuntimeStreamHeader.batch_size（uint32_t，由 memcpy 完全覆盖，src/lifecycle.c:3072-3074），通过公开入口 td_runtime_process_stream_batch（src/main.c）→ _runtime_process_stream_batch（line 3396）→ _runtime_stream_build_index 的路径可控。攻击者可构造包含 RUNTIME_STREAM_MAGIC 和大 batch_size 的 wire 数据，使 calloc 分配大块内存失败，触发空指针解引用。

## v3_fp #6: CLANG_CFG_RESOURCE_ALLOCATION_WITHOUT_LIMITS_fa6b779fa3
- truth: None | rule: clang_cfg_external_size_allocation_without_limit | func: _serialize_task
- loc: src/parser.c:224
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["guard_dominance", "source_controllability", "source_sink_reachability"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_0ff1c804a072ab858
- reasoning: 已验证 CWE-770（无限制资源分配）漏洞。_serialize_task 第224行调用 _safe_malloc(total_len)，其中 total_len = sizeof(TaskHeader) + payload_len。payload_len 来源于三个完全由调用方/攻击者控制的路径：strlen(task->payload.command.command)+1（第213行）、task->payload.text.length（第216行）、task->payload.binary.size（第219行）。入口函数 td_serialize_task_message（src/main.c:329，非静态公开API）在第330行直接调用 _serialize_task，established 调用链 td_serialize_task_message → _serialize_task → _safe_malloc(total_len)。在 total_len 计算之后到 _safe_malloc 调用之前，没有任何大小上限检查、拒绝策略或阈值守卫。_safe_malloc（src/utils.c:13-20）本身仅为 malloc 的简单封装，不实施任何大小限制。攻击者可通过构造包含超大 payload 长度的 Task 结构体，触发巨量内存分配，导致拒绝服务（内存耗尽）。

## v3_fp #7: CLANG_CFG_PREMATURE_DESTROY_9bf560d822
- truth: None | rule: clang_cfg_active_owner_destroy_without_quiescence | func: _runtime_release_packet_pool
- loc: src/lifecycle.c:2349
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["guard_dominance", "source_controllability", "source_sink_reachability"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_c81ca7d2730bf2671
- reasoning: 代码证据完整证实了 premature_destroy 缺陷的触发路径。`_runtime_release_packet_pool`（src/lifecycle.c:2339-2358）在 `active_tasks > 0` 时执行 SAFE_FREE(g_runtime_pbuf_pool->buffer)（2349）和 SAFE_FREE(g_runtime_pbuf_pool)（2350），随后 2351-2352 行立即解引用已释放的 `g_runtime_pbuf_pool->buffer` 和 `g_runtime_pbuf_pool->active_tasks`。SAFE_FREE 宏（include/common.h:24）将指针置 NULL，因此 2351 行表现为空指针解引用（等价于释放后使用）。源参数 `active_tasks` 来自公开入口 `td_runtime_refresh_cache`（main.c:706-710）的第 4 个参数，调用方可控；内部路径 `td_run_runtime_maintenance`（main.c:784 硬编码 active_tasks=1）与 `_td_runtime_worker`（main.c:804）也经此链触发。调用链中无任何锁、quiescence 契约或边界检查来阻止该分支的执行。`if(active_tasks>0)` 不是防护条件，而是触发 premature destroy 的条件。该缺陷在 worker 线程中确定性地触发，属于已验证的可利用漏洞。

## v3_fp #8: CLANG_CFG_INTEGER_OVERFLOW_a8622033ae
- truth: None | rule: clang_cfg_allocation_size_arithmetic_without_overflow_guard | func: _runtime_resize_message_buffer
- loc: src/lifecycle.c:1531
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["guard_dominance", "source_controllability", "source_sink_reachability", "value_range"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_31
- reasoning: 已验证整数溢出缺陷（CWE-190）：sink 位于 src/lifecycle.c:1531 的 count * sizeof(size_t)，该乘法结果直接传入 _safe_realloc 作为 realloc 大小。count 为无符号 size_t，当外部调用者传入 count > SIZE_MAX/8 时乘法回绕，实际分配远小于 count 声称的元素个数；随后 1535 行 g_service_metrics[0] = count 向过小分配写入大值，可造成堆内存破坏。源可控性成立：count 是公开头文件 include/task_dispatcher.h:160-161 声明的公共 API td_run_service_coordination_cases 的 size_t 参数，头文件未给出任何取值范围约束；入口函数在 src/main.c:531 将 count 原样透传给 _runtime_resize_message_buffer，全程无范围检查。守卫分析：乘法之前不存在任何上限检查（无 a <= SIZE_MAX/b 式前置条件），_safe_realloc（src/utils.c:31-38）仅包装 realloc，同样不校验溢出，因此缺少或不足以防止溢出的守卫。入口到 sink 的可达路径由代码直接证实（main.c:531 → lifecycle.c:1531），且该入口为本证据包指定的当前分析入口（reachable_from_entry=true）；仓库内零调用者属于头文件声明公共 API 的预期情形，按验证规则不得单独据此判定死代码。综合代码证据，源、sink、可控性、路径与守卫缺失均已证实，判定 verified。

## v3_fp #9: GRAPH_SIGNAL_RACE_c6a75c8a70
- truth: None | rule: signal_path_mutates_shared_state_or_logs | func: td_init
- loc: src/main.c:133
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["lockset"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_fd43046a08d18f229977e6d25e4fe37b"]}
- reasoning: 该候选条目描述信号处理器路径中的信号竞争（CWE-479，异步信号安全违规）。代码证据证实：1) td_init（src/main.c:203-204）为 SIGINT/SIGTERM 注册 _signal_handler；2) _signal_handler（src/main.c:51-54）→ td_runtime_handle_signal → _runtime_handle_fault_signal（src/lifecycle.c:2955-2960）；3) _runtime_capture_signal_stack（src/lifecycle.c:2560-2585）在信号上下文中执行 _safe_calloc（calloc 堆分配，非 async-signal-safe）、LOG_ERROR（fprintf/vfprintf 非 async-signal-safe）、无锁写入全局 g_runtime_callstack_info；4) _runtime_write_exception_record（src/lifecycle.c:2772-2780）以 hold_sem=1 执行阻塞 pthread_mutex_lock（非 async-signal-safe，死锁风险）、snprintf、LOG_ERROR；5) 无任何保护措施（无 sigprocmask/pthread_sigmask、无自管管道、无信号安全队列）；6) 信号可在注册后任意时刻递送，可打断工作线程（src/main.c:56-95）及主线程正在执行的分配/日志/锁操作，造成死锁或数据竞争。候选条目将 sink 标注为 src/main.c:182 的 g_dispatcher.threads = _safe_calloc，该分配在信号注册（line 203-204）之前，不被所述信号处理器直接中断；但信号路径本身在 lifecycle.c:2566 执行了同类 _safe_calloc 分配，该行号映射偏移不影响缺陷本质。CWE-479 信号处理函数使用不可重入函数 经代码证据证实。

## v3_fp #10: CLANG_CFG_OUT_OF_BOUNDS_WRITE_4ad865fa0d
- truth: None | rule: clang_cfg_unbounded_count_indexes_fixed_array | func: _runtime_stream_compact_segments
- loc: src/lifecycle.c:3086
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["guard_dominance", "source_controllability", "source_sink_reachability", "value_range"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_33
- reasoning: 漏洞成立。公开 API 入口 td_runtime_process_stream_batch（src/main.c:741-747）将外部调用方可控的 wire 参数直接转发给 _runtime_process_stream_batch（main.c:745），后者在 src/lifecycle.c:3388 无条件调用 _runtime_stream_compact_segments。sink 位于 src/lifecycle.c:3085-3090 的循环：segments 是固定 8 元素栈数组（RUNTIME_STREAM_SEGMENT_LIMIT=8u，src/lifecycle.c:2973），循环上界 header.segment_count 是 uint16_t，_runtime_stream_read_header（3067-3078）仅校验 magic 字段，segment_count 原样取自线上字节（偏移 4），可被设为 65535，远超数组容量 8。当 segment_count>8 时，segments[i].id= i 等写操作（3086-3089）越界写栈内存，构成 CWE-787 栈越界写。调用链上（_runtime_stream_read_header、_runtime_stream_compact_segments、_runtime_process_stream_batch）均无 segment_count<=RUNTIME_STREAM_SEGMENT_LIMIT 的边界检查；td_run_runtime_maintenance 内部路径使用本地 local_wire（回退默认 header，segment_count=2）虽然安全，但不约束公开入口直接接收外部 wire 的情形，不构成支配性防护。来源可控、路径可达、缺失防护均已被代码证据证实。

## v3_fp #11: GRAPH_MEMORY_LEAK_4e09b125b2
- truth: None | rule: registered_global_object_missing_release_hook | func: _lifecycle_mesh_disconnect
- loc: src/lifecycle.c:582
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["cleanup_coverage", "ownership_transfer"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_db504c1813b763b9e1ea035a1addc9fd", "FACT_V3_f783
- reasoning: 已验证内存泄漏(CWE-401)。触发路径: 公开API `td_handle_mesh_message(msg, transport_id)` (src/main.c:389) 接收外部可控的 msg 参数。当 msg 以 "ADD:" 开头时，`_lifecycle_mesh_control_message` (src/lifecycle.c:558-566) 通过 hook `pfnAddSession` 调用 `_control_session_add_to_global` (line 477-501)，该函数使用 `_safe_calloc` 分配 ControlSession 结构体、`_str_dup` 分配 owner 字符串，并插入全局链表 `g_control_sessions`。随后第 392 行无条件调用 `_lifecycle_mesh_disconnect(msg)` (line 577-586)。该函数在第 582 行检查 `g_mesh_control_hooks.pfnDropSession != NULL`——但此函数指针从未被注册。`_lifecycle_mesh_authorize_init` (line 546-551) 仅注册了 `pfnAddSession` 和 `pfnExpireSession`，没有设置 `pfnDropSession`。由于 `g_mesh_control_hooks` 是静态全局变量且仅在该函数中写入，`pfnDropSession` 永远为 NULL。因此 `_lifecycle_mesh_disconnect` 始终走 `return 0` 路径，不会释放任何已分配的 session。`g_control_sessions` 链表没有其他清理函数（`_lifecycle_service_shutdown` 仅释放 LifecycleEntry 列表，不涉及 ControlSession）。每次调用 ADD: 路径都导致 ControlSession 和 owner 字符串永久泄漏。

## v3_fp #12: GRAPH_BOUNDS_41ca788f89
- truth: None | rule: unchecked_param_indexes_fixed_global_array | func: _peer_expand_task_table
- loc: src/lifecycle.c:1803
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["guard_dominance", "source_controllability", "source_sink_reachability", "value_range"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_35
- reasoning: 已验证越界写入漏洞。`_peer_expand_task_table` (src/lifecycle.c:1784-1806) 中，当 `task_index >= SIZE_MAX-15` 时，重分配容量计算 `new_cap = ((task_index / 16u) + 1u) * 16u` 发生无符号整数溢出，结果为 0。`_safe_calloc(0, 8)` 在 glibc 上返回非空指针，随后 line 1803 `g_peer_task_array[task_index] = ...` 以越界索引写入零容量分配。`task_index` 有两个攻击者可控来源：(1) 网络帧 `PeerSessionHeader.request_id` (uint32_t) 经 `(int)→(size_t)` 转换，request_id=0xFFFFFFFF 产生 SIZE_MAX；(2) `td_run_peer_session_cases` 的 `report_len` 参数。`_peer_decode_header_window` 只校验 magic 和最小长度，不对 request_id 做任何范围检查。守卫 `task_index >= g_peer_task_array_cap` 触发了重分配逻辑，但容量计算溢出使守卫失效。`calloc(0, 8)` 在目标平台 (Linux/glibc) 返回非空指针，故写入路径可达。

## v3_fp #13: CLANG_CFG_RESOURCE_ALLOCATION_WITHOUT_LIMITS_aecb80411f
- truth: None | rule: clang_cfg_external_size_allocation_without_limit | func: _net_recv_string
- loc: src/network.c:175
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["guard_dominance", "source_controllability", "source_sink_reachability"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_32f9d0e0bffae1198
- reasoning: 候选为 src/network.c:175 处 _safe_malloc(max_len + 1) 的无上限堆分配（CWE-770）。源代码证据显示：max_len 是公开 API td_receive_string(int fd, size_t max_len)（声明于 include/task_dispatcher.h:108，src/main.c:313-315）的 size_t 参数，调用方可直接传入任意值直至 SIZE_MAX，无任何调用方侧上限。调用链 td_receive_string → _net_recv_string → _safe_malloc 为直接调用、无分支阻断，且该入口即为本次扫描的当前分析入口（reachable_from_entry=true），按协议视为公共触发点。守卫分析：_safe_malloc（src/utils.c:13-20）只检查 malloc 返回值是否为 NULL（分配失败处理），不施加大小上限；_net_recv_data 的 len==0 检查在分配之后，无法阻止大内存分配；_net_recv_string 在 line 175 之前对 max_len 没有任何检查。源（调用方可控的 max_len）、汇（_safe_malloc(max_len+1)）、可控性（公开 API 参数）、可行路径（td_receive_string→_net_recv_string）、缺失守卫（无上限检查）五项均已由代码证据闭合，故判定为 verified。

## v3_fp #14: CLANG_CFG_OUT_OF_RANGE_POINTER_OFFSET_15890f30a1
- truth: None | rule: clang_cfg_unchecked_object_offset_deref | func: _runtime_stream_map_object_offset
- loc: src/lifecycle.c:3230
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["guard_dominance", "source_controllability", "source_sink_reachability", "type_layout"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_11
- reasoning: 已验证越界指针偏移（CWE-823）。公开非静态 API td_runtime_process_stream_batch（src/main.c:741-747）接受外部可控的 wire 缓冲区，_runtime_stream_read_header 仅校验 magic（RUNTIME_STREAM_MAGIC=0x5354524du，源码公开常量）与长度，object_offset 字段从 wire 偏移 44 处原样 memcpy 至 header 结构，无任何范围校验。_runtime_process_stream_batch（src/lifecycle.c:3398）直接以 _runtime_stream_map_object_offset(header.object_offset) 透传。目标函数内（3222-3232），栈对象 RuntimeStreamObject（sizeof≈48 字节）的地址加上 object_offset 后，field[0]='X' 与 field[1]='\0' 写入越界栈内存。object_offset 为 uint32_t 可至 4GB，仅需 >46 即可造成栈破坏。入口到 sink 为全直接调用链，无提前返回路径。内部调用者 td_run_runtime_maintenance 传入固定 local_wire（magic 0x493432u ≠ RUNTIME_STREAM_MAGIC），回退到默认 header object_offset=OFFSET_OF(label)=4，该路径安全，但公开入口的 wire 完全由调用方控制，不存在支配性防护。

## v3_fp #15: CLANG_CFG_MEMORY_LEAK_281ff448f3
- truth: None | rule: clang_cfg_parent_release_without_owned_member_cleanup | func: _runtime_release_reader_channel
- loc: src/lifecycle.c:1296
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["cleanup_coverage", "ownership_transfer"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_5a2ad9f606dbcc6177d928d6221e3442", "FACT_V3_dd43
- reasoning: 泄漏链已由代码证据完整闭合:1) 源:src/lifecycle.c:1289 调用 _service_alloc_node(key, "reader"),其实现(src/lifecycle.c:1118-1129)通过 _safe_calloc 分配 ServiceNode 后执行 node->payload = _str_dup(payload ? payload : "payload"),_str_dup(src/utils.c:40-48)使用 _safe_malloc 在堆上复制 "reader",即 node->payload 是确定存在的堆分配;2) 汇:src/lifecycle.c:1296 与 1300 的 SAFE_FREE(node) 仅释放结构体本身(include/common.h:24 的宏只 free(ptr));3) 守卫缺失:_runtime_release_reader_channel 两条分支(role==1 与 role!=1)均调用 _service_release_by_role(node, 0),其实现(src/lifecycle.c:1164-1174)在 is_member==0 时只执行 SAFE_FREE(node->name),不释放 node->payload,函数内再无其他清理调用(callees 仅为 _service_alloc_node/_service_release_by_role/SAFE_FREE),节点为函数局部变量、未插入任何全局容器或树,所有权未转移,payload 在两条路径上均无释放点,构成确定性 CWE-401 泄漏;4) 可达性与可控性:当前分析入口 td_run_service_cleanup_cases(src/main.c:490-503)在 500 行以 stable_key/mode 调用 _runtime_release_reader_channel,reachable_from_entry=true,泄漏与 key/mode 取值无关,每次调用必然发生。结论:veri

## v3_fp #16: CLANG_CFG_OUT_OF_BOUNDS_WRITE_c6b2b13933
- truth: None | rule: clang_cfg_unbounded_count_indexes_fixed_array | func: _runtime_stream_compact_segments
- loc: src/lifecycle.c:3089
- via: validator_model pass: investigation_synthesis conf: None v3_turns: None
- ref_state: []
- closure: {"complete": true, "reason": "required_facts_closed", "resolved_fact_kinds": ["guard_dominance", "source_controllability", "source_sink_reachability", "value_range"], "remaining_fact_kinds": [], "fact_uids": ["FACT_V3_15
- reasoning: 函数 _runtime_stream_compact_segments 在 src/lifecycle.c:3085-3089 的循环中，以 header.segment_count 为界写入固定大小数组 segments[8]（RUNTIME_STREAM_SEGMENT_LIMIT=8）。segment_count 是 uint16_t 类型（0~65535），由 _runtime_stream_read_header 从外部可控的 wire 缓冲区通过 memcpy 解析而来，该函数仅校验 parsed.magic，未对 segment_count 做任何范围检查（src/lifecycle.c:3072-3073）。调用链 td_runtime_process_stream_batch → _runtime_process_stream_batch → _runtime_stream_compact_segments 完整可到达，调用方 _runtime_process_stream_batch 在 line 3388 直接传 wire 给 _runtime_stream_compact_segments，未在调用前检查 header.segment_count ≤ RUNTIME_STREAM_SEGMENT_LIMIT。攻击者构造 wire 数据段（magic=0x5354524d, segment_count>8）即可触发对 segments 数组的越界写，写入位置为 segments[i].id/offset/length/fd，覆盖栈上后续数据。该缺陷满足 CWE-787 所有条件：外部可控源、无保护、可到达越界写sink。

## v1_fp #1: CLANG_CFG_INVALID_FREE_523fc6217c
- truth: None | rule: clang_cfg_free_derived_pointer_alias | func: _runtime_stream_schedule_expired_flush
- loc: src/lifecycle.c:3273
- via: deterministic_proof pass: None conf: None v3_turns: None
- ref_state: []
- closure: null
- reasoning: 确定性 AST/CFG 事件证实了所报告的安全义务

## v1_fp #2: CLANG_CFG_INTEGER_OVERFLOW_f6313cca5d
- truth: None | rule: clang_cfg_size_addition_without_overflow_guard | func: _serialize_task
- loc: src/parser.c:223
- via: deterministic_proof pass: None conf: None v3_turns: None
- ref_state: []
- closure: null
- reasoning: 确定性 AST/CFG 事件证实了所报告的安全义务

## v1_fp #3: SVF_VALUE_FLOW_2fb63c353a1e
- truth: None | rule: None | func: _net_handle_error
- loc: src/network.c:191
- via: deterministic_proof pass: initial conf: None v3_turns: None
- ref_state: []
- closure: null
- reasoning: 必需的事实消解已产出完整的确定性证明；最终处置由策略层决定。

## v1_fp #4: CLANG_CFG_MEMORY_LEAK_724ef095c6
- truth: None | rule: clang_cfg_role_specific_release_argument_mismatch | func: _runtime_release_reader_channel
- loc: src/lifecycle.c:1295
- via: deterministic_proof pass: None conf: None v3_turns: None
- ref_state: []
- closure: null
- reasoning: 确定性 AST/CFG 事件证实了所报告的安全义务
