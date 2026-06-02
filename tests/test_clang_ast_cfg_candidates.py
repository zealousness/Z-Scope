from zscope.core.analysis.analyzer import Analyzer
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.regex import LocalPatternSemantics


def _rules(code: str, *, semantics=None, overlay=None):
    generator = ClangAstCfgCandidateGenerator(semantics, semantic_overlay=overlay)
    return generator.generate_issues("demo", code, "src/demo.c")


def test_clang_ast_cfg_detects_double_free_and_use_after_free() -> None:
    code = """
10 | int demo(void) {
11 |     char *p = malloc(16);
12 |     free(p);
13 |     free(p);
14 |     p[0] = 1;
15 |     return 0;
16 | }
"""

    issues = _rules(code)
    rules = {issue["rule"] for issue in issues}

    assert "clang_cfg_same_object_released_twice" in rules
    assert "clang_cfg_use_after_release" in rules
    double_free = next(issue for issue in issues if issue["rule"] == "clang_cfg_same_object_released_twice")
    assert double_free["candidate_source"] == "clang_ast_cfg"
    assert double_free["evidence_pack"]["checker"] == "clang_ast_cfg_checker"
    assert double_free["evidence_pack"]["ast_cfg"]["cfg_path"] == [12, 13]


def test_clang_ast_cfg_safe_free_comes_from_packaged_default_semantics() -> None:
    code = """
10 | int demo(char *p) {
11 |     SAFE_FREE(p);
12 |     SAFE_FREE(p);
13 |     return 0;
14 | }
"""

    default_rules = {issue["rule"] for issue in _rules(code)}
    assert "clang_cfg_same_object_released_twice" in default_rules

    semantics = LocalPatternSemantics()
    semantics.add_api("deallocator", "SAFE_FREE", "user_config")
    configured_rules = {issue["rule"] for issue in _rules(code, semantics=semantics)}
    assert "clang_cfg_same_object_released_twice" in configured_rules


def test_clang_ast_cfg_member_releases_do_not_double_free_parent() -> None:
    semantics = LocalPatternSemantics()
    semantics.add_api("deallocator", "SAFE_FREE", "user_config")
    code = """
10 | int demo(Node *node) {
11 |     SAFE_FREE(node->payload);
12 |     SAFE_FREE(node->name);
13 |     SAFE_FREE(node);
14 |     return 0;
15 | }
"""

    rules = {issue["rule"] for issue in _rules(code, semantics=semantics)}

    assert "clang_cfg_same_object_released_twice" not in rules


def test_clang_ast_cfg_preserves_member_allocation_identity() -> None:
    semantics = LocalPatternSemantics()
    semantics.add_api("allocator", "make_child", "user_config")
    semantics.add_api("deallocator", "SAFE_FREE", "user_config")
    code = """
10 | int demo(Node *node) {
11 |     node->children = make_child();
12 |     SAFE_FREE(node);
13 |     return 0;
14 | }
"""

    issues = _rules(code, semantics=semantics)
    leak = next(issue for issue in issues if issue["rule"] == "clang_cfg_acquire_without_release_on_exit")

    assert "`node->children` is acquired" in leak["description"]


def test_clang_ast_cfg_detects_acquire_without_release_on_return() -> None:
    code = """
20 | int demo(void) {
21 |     char *p = malloc(32);
22 |     if (!p) return -1;
23 |     return 0;
24 | }
"""

    issues = _rules(code)

    assert any(issue["rule"] == "clang_cfg_acquire_without_release_on_exit" for issue in issues)
    assert not any(issue["rule"] == "clang_cfg_alloc_result_deref_without_null_guard" for issue in issues)


def test_clang_ast_cfg_treats_returning_allocator_wrappers_as_ownership_transfer() -> None:
    code = """
10 | void *safe_alloc(size_t size) {
11 |     void *ptr = malloc(size);
12 |     if (!ptr && size > 0) {
13 |         return NULL;
14 |     }
15 |     return ptr;
16 | }
"""

    issues = _rules(code)

    assert not any(issue["rule"] == "clang_cfg_acquire_without_release_on_exit" for issue in issues)


def test_clang_ast_cfg_suppresses_varargs_format_forwarding_wrappers() -> None:
    wrapper = """
20 | void log_wrapper(const char *fmt, ...) {
21 |     va_list args;
22 |     va_start(args, fmt);
23 |     vfprintf(stderr, fmt, args);
24 |     va_end(args);
25 | }
"""
    direct_sink = """
30 | void demo(char *message) {
31 |     printf(message);
32 | }
"""

    wrapper_rules = {issue["rule"] for issue in _rules(wrapper)}
    direct_rules = {issue["rule"] for issue in _rules(direct_sink)}

    assert "clang_cfg_nonliteral_format_string" not in wrapper_rules
    assert "clang_cfg_nonliteral_format_string" in direct_rules


def test_clang_ast_cfg_tracks_common_wrapper_and_ownership_shapes() -> None:
    code = """
40 | Task *demo(size_t payload_len, int fd) {
41 |     Task *task = (Task *)_safe_calloc(1, sizeof(Task));
42 |     if (!task) return NULL;
43 |     char **args = (char **)_safe_calloc(4, sizeof(char *));
44 |     if (task->payload.command.args) {
45 |         task->payload.command.args[0] = _str_dup("x");
46 |     }
47 |     void *binary_data = _safe_malloc(payload_len);
48 |     if (binary_data) {
49 |         task->payload.binary.data = binary_data;
50 |     }
51 |     if (!args) {
52 |         free(task);
53 |         return NULL;
54 |     }
55 |     char filepath[MAX_PATH_LEN];
56 |     return task;
58 | }
"""
    local_fd_cleanup = """
60 | int cleanup_error(int fd) {
61 |     if (fd >= 0) {
62 |         close(fd);
63 |     }
64 |     return -1;
65 | }
"""
    lifecycle_close = """
70 | int close_lifecycle_connection(int fd) {
71 |     if (fd >= 0) {
72 |         close(fd);
73 |     }
74 |     return 0;
75 | }
"""

    issues = _rules(code)
    local_fd_rules = {issue["rule"] for issue in _rules(local_fd_cleanup)}
    lifecycle_rules = {issue["rule"] for issue in _rules(lifecycle_close)}
    rules = {issue["rule"] for issue in issues}

    assert "clang_cfg_use_after_release" not in rules
    assert "clang_cfg_unbounded_vla_or_stack_array" not in rules
    assert "clang_cfg_fd_closed_without_owner_invalidation" not in local_fd_rules
    assert "clang_cfg_fd_closed_without_owner_invalidation" in lifecycle_rules
    assert not any(
        issue["rule"] == "clang_cfg_acquire_without_release_on_exit"
        and "binary_data" in "\n".join(issue.get("positive_evidence", []))
        for issue in issues
    )


def test_clang_ast_cfg_detects_return_while_lock_held() -> None:
    code = """
30 | int demo(pthread_mutex_t *m) {
31 |     pthread_mutex_lock(m);
32 |     return -1;
33 | }
"""

    issues = _rules(code)
    issue = next(issue for issue in issues if issue["rule"] == "clang_cfg_return_with_lock_held")

    assert issue["defect_class"] == "missing_unlock"
    assert "line 31" in "\n".join(issue["positive_evidence"])
    assert issue["evidence_pack"]["path"]["backend"] == "Clang function body plus synthesized local CFG"


def test_clang_ast_cfg_respects_custom_user_config_out_param_acquire() -> None:
    semantics = LocalPatternSemantics()
    semantics.add_api("deallocator", "SHM_FileClose", "user_config")
    overlay = {
        "resource_models": [
            {
                "name": "SHM_FileMngFileCreate",
                "kind": "resource_acquire",
                "carrier": "argument_resource",
                "return_semantics": "returns resource via output argument",
                "memory_behavior": {"allocates": True},
                "source": "user_config",
            },
            {
                "name": "SHM_FileClose",
                "kind": "resource_release",
                "carrier": "argument_resource",
                "source": "user_config",
            },
        ],
        "lock_models": [],
        "macro_models": [],
    }
    code = """
40 | int demo(const char *path) {
41 |     VOS_UINT32 uiRet = 0;
42 |     int fd = -1;
43 |     uiRet = SHM_FileMngFileCreate(path, &fd);
44 |     return uiRet;
45 | }
"""

    issues = _rules(code, semantics=semantics, overlay=overlay)
    leak = next(issue for issue in issues if issue["rule"] == "clang_cfg_acquire_without_release_on_exit")

    assert "fd" in leak["positive_evidence"][0]
    assert "uiRet" not in leak["positive_evidence"][0]
    assert leak["evidence_pack"]["ast_cfg"]["events"][0]["variable"] == "fd"


def test_clang_ast_cfg_suppresses_out_param_leak_after_configured_release() -> None:
    semantics = LocalPatternSemantics()
    semantics.add_api("deallocator", "SHM_FileClose", "user_config")
    overlay = {
        "resource_models": [
            {
                "name": "SHM_FileMngFileCreate",
                "kind": "resource_acquire",
                "carrier": "argument_resource",
                "return_semantics": "returns resource via output argument",
                "memory_behavior": {"allocates": True},
                "source": "user_config",
            }
        ],
    }
    code = """
50 | int demo(const char *path) {
51 |     int fd = -1;
52 |     int rc = SHM_FileMngFileCreate(path, &fd);
53 |     if (rc != 0) return rc;
54 |     SHM_FileClose(fd);
55 |     return 0;
56 | }
"""

    issues = _rules(code, semantics=semantics, overlay=overlay)

    assert not any(issue["rule"] == "clang_cfg_acquire_without_release_on_exit" for issue in issues)


def test_clang_ast_cfg_detects_out_param_use_before_status_guard() -> None:
    overlay = {
        "resource_models": [
            {
                "name": "SHM_FileMngFileCreate",
                "kind": "resource_acquire",
                "carrier": "argument_resource",
                "return_semantics": "returns resource via output argument",
                "memory_behavior": {"allocates": True},
                "source": "user_config",
            },
            {
                "name": "SHM_FileClose",
                "kind": "resource_release",
                "carrier": "argument_resource",
                "source": "user_config",
            },
        ]
    }
    semantics = LocalPatternSemantics()
    semantics.add_api("deallocator", "SHM_FileClose", "user_config")
    code = """
70 | int demo(const char *path) {
71 |     int fd = -1;
72 |     int rc = SHM_FileMngFileCreate(path, &fd);
73 |     SHM_FileClose(fd);
74 |     if (rc != 0) return rc;
75 |     return 0;
76 | }
"""

    issues = _rules(code, semantics=semantics, overlay=overlay)
    issue = next(issue for issue in issues if issue["rule"] == "clang_cfg_out_param_used_before_success_check")

    assert issue["defect_class"] == "bad_parameter_or_api_misuse"
    assert issue["evidence_pack"]["ast_cfg"]["events"][1]["kind"] == "use_before_status_guard"
    assert issue["evidence_pack"]["ast_cfg"]["checker_basis"].startswith("clangd-indexed")


def test_clang_ast_cfg_detects_common_c_specialized_patterns() -> None:
    code = """
100 | int demo(TaskHeader *header, const char *payload_data, size_t len, const char *path) {
101 |     size_t payload_len = header->payload_length;
102 |     char command[4096];
103 |     memcpy(command, payload_data, MIN(payload_len, sizeof(command) - 1));
104 |     void *response = _safe_malloc(payload_len * 2);
105 |     printf(command);
106 |     if (_check_file_permission(path, R_OK) != 0) return -1;
107 |     FILE *fp = fopen(path, "r");
108 |     return response ? 0 : -1;
109 | }
"""

    issues = _rules(code)
    rules = {issue["rule"] for issue in issues}

    assert "clang_cfg_external_length_field_reaches_copy" in rules
    assert "clang_cfg_allocation_size_arithmetic_without_overflow_guard" in rules
    assert "clang_cfg_nonliteral_format_string" in rules
    assert "clang_cfg_path_check_before_open" in rules


def test_clang_ast_cfg_detects_command_injection_evidence() -> None:
    execute_code = """
100 | int demo(const char *command) {
101 |     char *full_command = build_command(command);
102 |     int result = system(full_command);
103 |     free(full_command);
104 |     return result;
105 | }
"""
    builder_code = """
110 | char *build_command(const char *cmd) {
111 |     const char *env_value = getenv("TASK_ENV");
112 |     char *full_cmd = _safe_malloc(128);
113 |     strcpy(full_cmd, cmd);
114 |     if (env_value) {
115 |         strcat(full_cmd, env_value);
116 |     }
117 |     return full_cmd;
118 | }
"""

    execute_rules = {issue["rule"] for issue in _rules(execute_code)}
    builder_rules = {issue["rule"] for issue in _rules(builder_code)}

    assert "clang_cfg_system_with_nonliteral_command" in execute_rules
    assert "clang_cfg_shell_command_concat_env" in builder_rules


def test_clang_ast_cfg_detects_refcount_and_signed_unsigned_patterns() -> None:
    code = """
160 | int ref_get(const char *key, int fd, char *dst, size_t dst_size) {
161 |     LOCK(&g_lifecycle.lock);
162 |     LifecycleEntry *entry = _find_entry_locked(key);
163 |     UNLOCK(&g_lifecycle.lock);
164 |     if (!entry) return -1;
165 |     entry->ref_count++;
166 |     char temp[512];
167 |     int received = _net_recv_data(fd, temp, sizeof(temp));
168 |     size_t copy_len = (size_t)received;
169 |     memcpy(dst, temp, copy_len);
170 |     return entry->ref_count;
171 | }
"""

    issues = _rules(code)
    rules = {issue["rule"] for issue in issues}

    assert "clang_cfg_refcount_update_after_unlock" in rules
    assert "clang_cfg_negative_length_cast_to_size_t" in rules


def test_clang_ast_cfg_detects_concurrency_and_low_level_c_patterns() -> None:
    code = """
120 | int demo(unsigned char *packet) {
121 |     LifecycleEntry *entry = _safe_calloc(1, sizeof(LifecycleEntry));
122 |     LOCK(&g_lifecycle.lock);
123 |     entry->next = g_lifecycle.entries;
124 |     g_lifecycle.entries = entry;
125 |     entry->value = _str_dup("value");
126 |     if (g_pending_jobs == 0) {
127 |         pthread_cond_wait(&g_lifecycle.cond, &g_lifecycle.lock);
128 |     }
129 |     const uint32_t *id = (const uint32_t *)(packet + 1);
130 |     return *id;
131 | }
"""

    issues = _rules(code)
    rules = {issue["rule"] for issue in issues}

    assert "clang_cfg_object_published_before_initialization" in rules
    assert "clang_cfg_cond_wait_guarded_by_if" in rules
    assert "clang_cfg_unaligned_integer_pointer_cast" in rules


def test_clang_ast_cfg_detects_lifecycle_gap_patterns() -> None:
    code = """
200 | int demo(const char *path, int fd, char *line, size_t field_count) {
201 |     FlushJob job;
202 |     memset(&job, 0, sizeof(job));
203 |     pthread_t tid;
204 |     pthread_create(&tid, NULL, worker_thread, &job);
205 |     StatusReply reply;
206 |     reply.code = 200;
207 |     _net_send_data(fd, &reply, sizeof(reply));
208 |     char *value = strchr(line, '=');
209 |     free(value + 1);
210 |     char frame[field_count * 128];
211 |     memset(frame, 0, sizeof(frame));
212 |     return 0;
213 | }
"""

    issues = _rules(code)
    rules = {issue["rule"] for issue in issues}

    assert "clang_cfg_stack_address_passed_to_thread" in rules
    assert "clang_cfg_partial_aggregate_sent_with_sizeof" in rules
    assert "clang_cfg_free_non_owner_pointer_expression" in rules
    assert "clang_cfg_unbounded_vla_or_stack_array" in rules


def test_clang_ast_cfg_detects_range_unified_missed_patterns() -> None:
    td_init = """
181 |     g_dispatcher.threads = (pthread_t*)_safe_calloc(
182 |         g_dispatcher.config.thread_count, sizeof(pthread_t));
183 |     if (!g_dispatcher.threads) {
184 |         return -1;
185 |     }
187 |     int* thread_ids = (int*)_safe_calloc(
188 |         g_dispatcher.config.thread_count, sizeof(int));
189 |     if (!thread_ids) {
190 |         return -1;
191 |     }
193 |     for (uint32_t i = 0; i < g_dispatcher.config.thread_count; i++) {
194 |         thread_ids[i] = (int)i;
195 |         pthread_create(&g_dispatcher.threads[i], NULL, _worker_thread, &thread_ids[i]);
196 |     }
"""
    log_leak = """
1296 | int _real_model_log_buffer_leak(const char* message, int emit_error) {
1297 |     char* log_copy = _str_dup(message ? message : "log");
1298 |     if (!log_copy) {
1299 |         return -1;
1300 |     }
1301 |     if (emit_error) {
1302 |         LOG_ERROR(log_copy);
1303 |         return -1;
1304 |     }
1305 |     SAFE_FREE(log_copy);
1306 |     return 0;
1307 | }
"""
    avl_insert = """
1345 | int _real_model_avl_insert_unchecked_return(const char* key) {
1346 |     RealModelNode* node = _real_model_alloc_node(key, "avl");
1347 |     if (!node) {
1348 |         return -1;
1349 |     }
1350 |     _real_model_fake_avl_insert(node, 1);
1351 |     return 0;
1352 | }
"""
    protocol_len = """
1354 | int _real_model_protocol_length_miscalc(const unsigned char* packet, size_t packet_len,
1355 |                                         unsigned char* out, size_t out_len) {
1356 |     if (!packet || !out || packet_len < 4) {
1357 |         return -1;
1358 |     }
1359 |     uint32_t units = packet[0];
1360 |     size_t copy_len = (size_t)(units * 8);
1361 |     if (copy_len <= out_len) {
1362 |         memcpy(out, packet + 4, copy_len);
1363 |     }
1364 |     return (int)copy_len;
1365 | }
"""
    ssl_probe = """
1437 | int _real_model_ssl_error_returns_ok(int fd, int ssl_accept_times) {
1438 |     int is_rpc_msg = 0;
1439 |     int ret = 0;
1440 |     if (ssl_accept_times == 0) {
1441 |         ret = _net_recv_data(fd, &is_rpc_msg, sizeof(is_rpc_msg));
1442 |         if (ret != 0 || is_rpc_msg) {
1443 |             LOG_ERROR("secure channel probe failed");
1444 |             return ret;
1445 |         }
1446 |     }
1447 |     return 0;
1448 | }
"""
    refcount_close = """
1804 | int _peer_missing_reference_count(int resource_id, int close_now) {
1805 |     LOCK(&g_peer_session_broker.lock);
1806 |     PeerResource* res = _peer_find_resource(resource_id);
1813 |         res->resource_id = resource_id;
1814 |         res->ref_count = 2;
1815 |         res->tag = _str_dup("shared-listener");
1816 |         res->next = g_peer_session_broker.resources;
1817 |         g_peer_session_broker.resources = res;
1818 |     }
1820 |     if (close_now) {
1821 |         SAFE_FREE(res->tag);
1822 |         SAFE_FREE(res);
1823 |         UNLOCK(&g_peer_session_broker.lock);
1824 |         return 0;
1825 |     }
1826 |     return res->ref_count;
1829 | }
"""

    cases = {
        "clang_cfg_heap_thread_argument_owner_not_released": td_init,
        "clang_cfg_log_error_path_allocation_not_released": log_leak,
        "clang_cfg_unchecked_insert_after_ownership_handoff": avl_insert,
        "clang_cfg_protocol_units_length_reaches_copy_without_packet_bound": protocol_len,
        "clang_cfg_probe_error_branch_can_return_success_status": ssl_probe,
        "clang_cfg_shared_resource_freed_without_refcount_protocol": refcount_close,
    }
    for expected_rule, code in cases.items():
        rules = {issue["rule"] for issue in _rules(code)}
        assert expected_rule in rules

    refcount_rules = {issue["rule"] for issue in _rules(refcount_close)}
    assert "clang_cfg_shared_resource_freed_without_refcount_protocol" in refcount_rules
    assert "clang_cfg_use_after_release" not in refcount_rules


def test_clang_ast_cfg_detects_unchecked_param_global_array_index() -> None:
    vulnerable = """
10 | uint64_t demo(uint32_t lcore_id) {
11 |     RuntimeTimerControl* ctrl = g_runtime_timer_ctrl[lcore_id];
12 |     return ctrl ? ctrl->ticks : 0;
13 | }
"""
    guarded = """
20 | int demo(int reliable_fd) {
21 |     if (!_peer_is_inter_fd(reliable_fd)) {
22 |         return -1;
23 |     }
24 |     g_peer_descriptor_slots[reliable_fd].fd = reliable_fd;
25 |     return 0;
26 | }
"""

    vulnerable_rules = {issue["rule"] for issue in _rules(vulnerable)}
    guarded_rules = {issue["rule"] for issue in _rules(guarded)}

    assert "clang_cfg_unchecked_param_indexes_fixed_global_array" in vulnerable_rules
    assert "clang_cfg_unchecked_param_indexes_fixed_global_array" not in guarded_rules


def test_clang_ast_cfg_detects_unchecked_strchr_result() -> None:
    code = """
90 | char* demo(const char* msg) {
91 |     const char* sep = strchr(msg, ':');
92 |     size_t key_len = (size_t)(sep - msg);
93 |     return key_len ? strdup(msg) : NULL;
94 | }
"""

    rules = {issue["rule"] for issue in _rules(code)}

    assert "clang_cfg_unchecked_strchr_result" in rules


def test_clang_ast_cfg_detects_role_specific_release_literal_mismatch() -> None:
    semantics = LocalPatternSemantics()
    semantics.add_api("deallocator", "SAFE_FREE", "user_config")
    code = """
1280 | int demo(const char* key, int role) {
1281 |     RealModelNode* node = _real_model_alloc_node(key, "reader");
1282 |     if (!node) {
1283 |         return -1;
1284 |     }
1285 |     node->role = role;
1286 |     if (node->role == 1) {
1287 |         _real_model_server_release_by_role(node, 0);
1288 |         SAFE_FREE(node);
1289 |         return 0;
1290 |     }
1291 |     _real_model_server_release_by_role(node, 0);
1292 |     SAFE_FREE(node);
1293 |     return 0;
1294 | }
"""

    issues = _rules(code, semantics=semantics)
    mismatch = next(
        issue
        for issue in issues
        if issue["rule"] == "clang_cfg_role_specific_release_argument_mismatch"
    )

    assert mismatch["category"] == "memory_leak"
    assert "node->role == 1" in mismatch["source"]
    assert "release_by_role(node, 0)" in mismatch["sink"]


def test_clang_ast_cfg_detects_registry_unlink_free_after_unlock() -> None:
    semantics = LocalPatternSemantics()
    semantics.add_api("deallocator", "SAFE_FREE", "user_config")
    code = """
1176 | int demo(const char* key) {
1177 |     RealModelNode* node = _real_model_alloc_node(key, "module");
1178 |     if (!node) {
1179 |         return -1;
1180 |     }
1181 |     LOCK(&g_real_registry.lock);
1182 |     _real_model_insert_locked(node);
1183 |     g_real_registry.head = node->next;
1184 |     UNLOCK(&g_real_registry.lock);
1185 |     SAFE_FREE(node->payload);
1186 |     SAFE_FREE(node->name);
1187 |     SAFE_FREE(node);
1188 |     return 0;
1189 | }
"""

    issues = _rules(code, semantics=semantics)
    race = next(
        issue
        for issue in issues
        if issue["rule"] == "clang_cfg_registry_unlink_free_after_unlock"
    )

    assert race["category"] == "race"
    assert "g_real_registry.head = node->next" in race["source"]


def test_clang_ast_cfg_detects_raw_fd_to_encoded_validator_mismatch() -> None:
    code = """
1843 | int demo(int listen_fd, int work_fd) {
1844 |     for (int i = 0; i < 2; i++) {
1845 |         int raw_work_fd = work_fd + i;
1846 |         if (_issue41_validate_encoded_fd(raw_work_fd) < 0) {
1847 |             return -1;
1848 |         }
1849 |     }
1850 |     return _issue41_validate_encoded_fd(listen_fd);
1851 | }
"""

    issues = _rules(code)
    mismatch = next(
        issue
        for issue in issues
        if issue["rule"] == "clang_cfg_raw_fd_revalidated_as_encoded"
    )

    assert mismatch["category"] == "fd_encoding_mismatch"
    assert "raw_work_fd" in mismatch["source"]
    assert "validate_encoded_fd" in mismatch["sink"]


def test_clang_ast_cfg_detects_state_not_restored_and_ignored_version() -> None:
    state_code = """
1461 | int demo(int fd) {
1462 |     int previous = g_real_registry.state;
1463 |     g_real_registry.state = fd;
1464 |     if (fcntl(fd, F_GETFD) < 0) {
1465 |         return -1;
1466 |     }
1467 |     previous = g_real_registry.state;
1468 |     return previous;
1469 | }
"""
    version_code = """
1790 | int demo(const unsigned char* report, size_t len) {
1791 |     if (!report || len < 2) {
1792 |         return -1;
1793 |     }
1795 |     uint8_t version = report[0];
1796 |     uint8_t state = report[1];
1797 |     (void)version;
1798 |     if (state == TASK_STATUS_FAILED) {
1799 |         return -1;
1800 |     }
1801 |     return 0;
1802 | }
"""

    state_rules = {issue["rule"] for issue in _rules(state_code)}
    version_rules = {issue["rule"] for issue in _rules(version_code)}

    assert "clang_cfg_global_state_not_restored_on_error" in state_rules
    assert "clang_cfg_parsed_protocol_version_is_ignored" in version_rules


def test_clang_ast_cfg_detects_structured_protocol_shapes() -> None:
    semantics = LocalPatternSemantics()
    semantics.add_api("deallocator", "SAFE_FREE", "user_config")
    code = """
1367 | uint64_t magic64(const unsigned char* blob, size_t len) {
1368 |     if (!blob || len < 16) {
1369 |         return 0;
1370 |     }
1371 |     uint64_t expected_magic = PROTOCOL_MAGIC;
1372 |     uint64_t count = 0;
1373 |     memcpy(&count, blob + 8, sizeof(count));
1374 |     return count + expected_magic;
1375 | }
1676 | int label(unsigned int element_count) {
1677 |     size_t label_len = (size_t)element_count * PROTOCOL_ELEMENT_INFO_SIZE;
1678 |     if (label_len > PROJECT_LABEL_CACHE_LIMIT) {
1679 |         return -1;
1680 |     }
1681 |     return (element_count <= PROJECT_SPEC_MAX_ELEMENTS) ? 0 : -1;
1682 | }
1711 | int recv_loop(int fd, unsigned char* dst, size_t want) {
1712 |     size_t received = 0;
1713 |     while (received < want) {
1714 |         int rc;
1715 |         do {
1716 |             rc = _net_recv_data(fd, dst + received, want - received);
1717 |         } while (rc == -1 && (errno == EAGAIN || errno == EINTR));
1718 |         if (rc <= 0) {
1719 |             continue;
1720 |         }
1721 |         received += (size_t)rc;
1722 |     }
1723 |     return 0;
1724 | }
1766 | int expand(size_t task_index) {
1767 |     if (task_index >= g_task_array_cap) {
1768 |         size_t new_cap = ((task_index / 16u) + 1u) * 16u;
1769 |         ProjectTask** new_array = (ProjectTask**)_safe_calloc(new_cap, sizeof(ProjectTask*));
1770 |         ProjectTask** old_array = g_task_array;
1771 |         g_task_array = new_array;
1772 |         g_task_array_cap = new_cap;
1773 |         SAFE_FREE(old_array);
1774 |     }
1775 |     return 0;
1776 | }
"""

    issues = _rules(code, semantics=semantics)
    rules = {issue["rule"] for issue in issues}

    assert "clang_cfg_wide_count_read_without_magic_guard" in rules
    assert "clang_cfg_fixed_byte_limit_before_spec_count_check" in rules
    assert "clang_cfg_recv_retry_loop_without_timeout_or_budget" in rules
    assert "clang_cfg_global_dynamic_array_resize_without_lock" in rules
    magic_issue = next(
        issue for issue in issues if issue["rule"] == "clang_cfg_wide_count_read_without_magic_guard"
    )
    assert magic_issue["category"] == "protocol_validation"
    assert magic_issue["cwe"] == "CWE-20"
    assert "protocol magic validation" in magic_issue["sink"]


def test_clang_ast_cfg_callback_under_lock_is_contract_risk_not_exploit_claim() -> None:
    code = """
10 | int demo(plugin_callback_t cb, void *ctx) {
11 |     pthread_mutex_lock(&g_lock);
12 |     g_entry_callback(ctx);
13 |     pthread_mutex_unlock(&g_lock);
14 |     return 0;
15 | }
"""

    issue = next(
        issue for issue in _rules(code) if issue["rule"] == "clang_cfg_callback_while_lock_held"
    )

    assert issue["confidence"] == 0.68
    assert issue["impact_level"] == "medium"
    assert "if callers can register" in issue["root_cause"]
    assert "externally controllable" in " ".join(issue["negative_evidence"])


def test_clang_ast_cfg_detects_callback_context_and_mapping_lifetime() -> None:
    callback_code = """
220 | int demo(const char *key, plugin_callback_t cb) {
221 |     LOCK(&g_lifecycle.lock);
222 |     g_callback_entry = _find_entry_locked(key);
223 |     g_entry_callback = cb;
224 |     UNLOCK(&g_lifecycle.lock);
225 |     return g_callback_entry ? 0 : -1;
226 | }
"""
    mapping_code = """
230 | int demo(void) {
231 |     if (g_rules_map && g_rules_len > 0) {
232 |         munmap(g_rules_map, g_rules_len);
233 |     }
234 |     return 0;
235 | }
"""

    callback_rules = {issue["rule"] for issue in _rules(callback_code)}
    mapping_rules = {issue["rule"] for issue in _rules(mapping_code)}

    assert "clang_cfg_global_callback_stores_borrowed_object" in callback_rules
    assert "clang_cfg_global_mapping_unmapped_without_invalidation" in mapping_rules


def test_clang_ast_cfg_macro_lock_race_uses_generic_macro_guard_shape() -> None:
    code = """
140 | uint32_t demo(uint32_t delta) {
141 |     PROJECT_FAST_LOCK();
142 |     uint32_t old_value = g_shared_counter;
143 |     g_shared_counter = old_value + delta;
144 |     PROJECT_FAST_UNLOCK();
145 |     return g_shared_counter;
146 | }
"""

    issues = _rules(code)
    issue = next(issue for issue in issues if issue["rule"] == "clang_cfg_macro_guarded_lock_may_compile_to_noop")

    assert issue["defect_class"] == "race"
    assert "PROJECT_FAST_LOCK" in issue["source"]


def test_clang_ast_cfg_evidence_contains_declarations_and_guards() -> None:
    code = """
80 | int demo(size_t len) {
81 |     char *p = malloc(len);
82 |     if (!p) return -1;
83 |     return 0;
84 | }
"""

    issues = _rules(code)
    issue = next(issue for issue in issues if issue["rule"] == "clang_cfg_acquire_without_release_on_exit")
    ast_cfg = issue["evidence_pack"]["ast_cfg"]

    assert any(row["name"] == "p" and row["pointer_depth"] >= 1 for row in ast_cfg["declarations"])
    assert any("!p" in row["condition"] for row in ast_cfg["condition_guards"])
    assert 82 in ast_cfg["scope_summary"]["branch_lines"]


def test_clang_ast_cfg_attaches_optional_tooling_evidence() -> None:
    def tooling_provider(*, func_name: str, file_path: str, start_line: int, end_line: int):
        return {
            "schema": "clang_tooling_evidence_v1",
            "status": "command_prepared_not_executed",
            "function": func_name,
            "file": file_path,
            "range": {"start_line": start_line, "end_line": end_line},
        }

    generator = ClangAstCfgCandidateGenerator(tooling_evidence_provider=tooling_provider)
    issues = generator.generate_issues(
        "demo",
        """
90 | int demo(void) {
91 |     char *p = malloc(16);
92 |     return 0;
93 | }
""",
        "src/demo.c",
    )
    issue = next(issue for issue in issues if issue["rule"] == "clang_cfg_acquire_without_release_on_exit")

    tooling = issue["evidence_pack"]["ast_cfg"]["clang_tooling"]
    assert tooling["schema"] == "clang_tooling_evidence_v1"
    assert tooling["function"] == "demo"
    assert tooling["range"] == {"start_line": 90, "end_line": 93}


def test_analyzer_converts_clang_tooling_matcher_facts_to_candidates() -> None:
    tooling = {
        "schema": "clang_tooling_evidence_v1",
        "status": "executed",
        "execution_enabled": True,
        "compile_command_found": True,
        "range": {"start_line": 100, "end_line": 120},
        "ast_dump": {
            "summary": {
                "target_function": {
                    "name": "demo",
                    "line": 100,
                    "type": "int (char *)",
                    "matcher_facts": [
                        {
                            "rule_id": "clang_ast_copy_size_relation",
                            "category": "bounds",
                            "callee": "memcpy",
                            "line": 108,
                            "arg_count": 3,
                        },
                        {
                            "rule_id": "clang_ast_resource_balance_summary",
                            "category": "resource_lifecycle",
                            "acquire_call_count": 1,
                            "release_call_count": 0,
                        },
                        {
                            "rule_id": "clang_ast_resource_release_call",
                            "category": "resource_lifecycle",
                            "callee": "free",
                            "line": 112,
                        },
                        {
                            "rule_id": "clang_ast_same_argument_released_twice",
                            "category": "double_free",
                            "callee": "free",
                            "line": 116,
                            "resource_symbol": "p",
                            "first_release_line": 112,
                            "second_release_line": 116,
                        },
                        {
                            "rule_id": "clang_ast_release_then_call_argument_use",
                            "category": "use_after_free",
                            "callee": "printf",
                            "line": 118,
                            "resource_symbol": "p",
                            "release_line": 116,
                            "use_line": 118,
                        },
                    ],
                }
            }
        },
        "cfg_dump": {"summary": {"parse_ok": True, "block_count": 3, "edge_count": 2}},
    }

    issues = Analyzer._clang_tooling_matcher_candidates_from_evidence("demo", "src/demo.c", tooling)
    rules = {issue["rule"] for issue in issues}

    assert rules == {
        "clang_ast_copy_size_relation",
        "clang_ast_resource_balance_summary",
        "clang_ast_same_argument_released_twice",
        "clang_ast_release_then_call_argument_use",
    }
    bounds = next(issue for issue in issues if issue["defect_class"] == "bounds")
    leak = next(issue for issue in issues if issue["defect_class"] == "memory_leak")
    double_free = next(issue for issue in issues if issue["defect_class"] == "double_free")
    uaf = next(issue for issue in issues if issue["defect_class"] == "use_after_free")
    assert bounds["candidate_source"] == "clang_ast_matcher"
    assert bounds["evidence_pack"]["checker"] == "clang_ast_matcher_checker"
    assert bounds["evidence_pack"]["clang_tooling"]["ast_target_function"]["matcher_facts"]
    assert leak["location"] == "src/demo.c:100"
    assert double_free["impact_level"] == "high"
    assert uaf["evidence_pack"]["clang_matcher_fact"]["resource_symbol"] == "p"


def test_analyzer_runs_clang_ast_cfg_checker_only_for_clang_like_backends() -> None:
    class UnifiedBackend:
        pass

    class FakeIndex:
        backend_name = "unified"
        backend = UnifiedBackend()

        def get_function_impl(self, name: str, warn_missing: bool = False):
            return None

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    analyzer.user_config = object()
    analyzer._local_pattern_semantics = LocalPatternSemantics()
    analyzer._semantic_overlay = {
        "resource_models": [],
        "lock_models": [],
        "macro_models": [],
        "dispatcher_models": [],
        "lifecycle_models": [],
        "pointer_target_models": [],
        "function_intent_models": [],
    }
    state = {
        "entry_func": "api_demo",
        "impl_result": {
            "file": "src/demo.c",
            "code": """
60 | int api_demo(void) {
61 |     char *p = malloc(8);
62 |     return 0;
63 | }
""",
            "callees": [],
        },
    }

    issues = analyzer._detect_local_rule_candidates(state)
    clang_issues = [issue for issue in issues if issue.get("candidate_source") == "clang_ast_cfg"]

    assert clang_issues
    assert clang_issues[0]["evidence_checker"] == "clang_ast_cfg_checker"
    assert clang_issues[0]["evidence_pack"]["checker"] == "clang_ast_cfg_checker"


def test_analyzer_lifts_internal_clang_sink_to_entry_call_path() -> None:
    class UnifiedBackend:
        pass

    class FakeIndex:
        backend_name = "unified"
        backend = UnifiedBackend()

        def get_function_impl(self, name: str, warn_missing: bool = False):
            if name == "parse_inner":
                return {
                    "file": "src/demo.c",
                    "start_line": 70,
                    "end_line": 75,
                    "code": """
70 | int parse_inner(size_t len) {
71 |     if (len == 0) return -1;
72 |     char *buf = malloc(len);
73 |     return buf ? 0 : -1;
74 | }
""",
                    "callees": ["malloc"],
                }
            return None

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    analyzer.user_config = object()
    analyzer._local_pattern_semantics = LocalPatternSemantics()
    analyzer._semantic_overlay = {
        "resource_models": [],
        "lock_models": [],
        "macro_models": [],
        "dispatcher_models": [],
        "lifecycle_models": [],
        "pointer_target_models": [],
        "function_intent_models": [],
    }
    state = {
        "entry_func": "api_demo",
        "impl_result": {
            "file": "src/demo.c",
            "start_line": 60,
            "end_line": 64,
            "code": """
60 | int api_demo(size_t len) {
61 |     if (len > 1024) return -1;
62 |     return parse_inner(len);
63 | }
""",
            "callees": ["parse_inner"],
        },
    }

    issues = analyzer._detect_local_rule_candidates(state)
    lifted = [
        issue
        for issue in issues
        if issue.get("function") == "parse_inner" and issue.get("candidate_source") == "clang_ast_cfg"
    ]

    assert lifted
    assert lifted[0]["analyzed_from"] == "api_demo"
    assert lifted[0]["internal_sink_lifted"] is True
    assert lifted[0]["call_path"] == ["api_demo", "parse_inner"]
    assert lifted[0]["evidence_pack"]["path"]["call_path"] == ["api_demo", "parse_inner"]
    assert lifted[0]["evidence_pack"]["path"]["complete_to_entry"] is True
    call_edges = lifted[0]["evidence_pack"]["path"]["call_edges"]
    assert call_edges[0]["caller"] == "api_demo"
    assert call_edges[0]["callee"] == "parse_inner"
    assert call_edges[0]["parameter_mapping"][0] == {
        "arg_index": 0,
        "actual": "len",
        "formal": "len",
        "source_parameter": "len",
    }
    guard_summary = call_edges[0]["guard_summary"]
    assert guard_summary["caller_side"]["checks"][0]["guard_kind"] == "bounds_or_range_check"
    assert guard_summary["caller_side"]["checks"][0]["symbols"] == ["len"]
    assert guard_summary["callee_entry"]["checks"][0]["guard_kind"] in {
        "null_or_presence_check",
        "bounds_or_range_check",
    }
    assert guard_summary["caller_side"]["is_conclusive"] is False

