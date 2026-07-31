from zscope.core.analysis.analyzer import Analyzer
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.regex import LocalPatternSemantics


def _rules(code: str, *, semantics=None, overlay=None):
    generator = ClangAstCfgCandidateGenerator(semantics, semantic_overlay=overlay)
    return generator.generate_issues("demo", code, "src/demo.c")


def _dir_semantics():
    semantics = LocalPatternSemantics()
    semantics.add_api("allocator", "opendir", "user_config")
    semantics.add_api("deallocator", "closedir", "user_config")
    return semantics


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


def test_clang_ast_cfg_suppresses_terminal_branch_release_before_normal_cleanup() -> None:
    cases = {
        "multiline": """
10 | int demo(const char *path) {
11 |     DIR *dir = opendir(path);
12 |     if (!dir) return -1;
13 |     if (bad()) {
14 |         closedir(dir);
15 |         return -1;
16 |     }
17 |     work(dir);
18 |     closedir(dir);
19 |     return 0;
20 | }
""",
        "same_line": """
30 | int demo(const char *path) {
31 |     DIR *dir = opendir(path);
32 |     if (!dir) return -1;
33 |     if (bad()) { closedir(dir); return -1; }
34 |     work(dir);
35 |     closedir(dir);
36 |     return 0;
37 | }
""",
        "gapped": """
40 | int demo(const char *path) {
41 |     DIR *dir = opendir(path);
42 |     if (!dir) return -1;
43 |     if (bad()) {
44 |         closedir(dir);
45 |         log_error();
46 |         mark_failed();
47 |         cleanup_tmp();
48 |         return -1;
49 |     }
50 |     closedir(dir);
51 |     return 0;
52 | }
""",
    }

    for name, code in cases.items():
        rules = {issue["rule"] for issue in _rules(code, semantics=_dir_semantics())}

        assert "clang_cfg_same_object_released_twice" not in rules, name
        assert "clang_cfg_use_after_release" not in rules, name
        assert "clang_cfg_acquire_without_release_on_exit" not in rules, name


def test_clang_ast_cfg_terminal_branch_release_does_not_hide_fallthrough_leak() -> None:
    code = """
10 | int demo(int bad) {
11 |     char *p = malloc(16);
12 |     if (!p) return -1;
13 |     if (bad) { free(p); return -1; }
14 |     return 0;
15 | }
"""

    issues = _rules(code)

    assert any(
        issue["rule"] == "clang_cfg_acquire_without_release_on_exit" and issue["location"] == "src/demo.c:14"
        for issue in issues
    )
    assert not any(issue["rule"] == "clang_cfg_same_object_released_twice" for issue in issues)


def test_clang_ast_cfg_terminal_release_returning_freed_global_is_uaf() -> None:
    code = """
10 | int demo(int active_tasks) {
11 |     g_runtime_pbuf_pool = _safe_calloc(1, sizeof(RuntimePbufPool));
12 |     if (active_tasks > 0) {
13 |         SAFE_FREE(g_runtime_pbuf_pool);
14 |         return g_runtime_pbuf_pool->active_tasks;
15 |     }
16 |     return 0;
17 | }
"""

    issue = next(issue for issue in _rules(code) if issue["rule"] == "clang_cfg_use_after_release")

    assert issue["defect_class"] == "use_after_free"
    assert issue["location"] == "src/demo.c:14"
    assert "g_runtime_pbuf_pool" in issue["sink"]


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


def test_clang_ast_cfg_detects_same_member_double_free() -> None:
    code = """
10 | int demo(Node *node) {
11 |     free(node->payload);
12 |     free(node->payload);
13 |     SAFE_FREE(node->name);
14 |     SAFE_FREE(node);
15 |     return 0;
16 | }
"""

    issues = _rules(code)
    double_free = next(issue for issue in issues if issue["rule"] == "clang_cfg_same_object_released_twice")

    assert double_free["defect_class"] == "double_free"
    assert "node->payload" in double_free["description"]


def test_clang_ast_cfg_detects_parent_release_without_owned_member_cleanup() -> None:
    explicit_code = """
10 | int demo(const char *key) {
11 |     ServiceNode *node = make_node(key);
12 |     node->children = make_child("proc");
13 |     SAFE_FREE(node->name);
14 |     SAFE_FREE(node);
15 |     return 0;
16 | }
"""
    implicit_code = """
20 | int delete_os_node(OSNode **root) {
21 |     OSNode *os = *root;
22 |     *root = os->next;
23 |     SAFE_FREE(os);
24 |     return 0;
25 | }
"""

    explicit = next(
        issue
        for issue in _rules(explicit_code)
        if issue["rule"] == "clang_cfg_parent_release_without_owned_member_cleanup"
    )
    implicit = next(
        issue
        for issue in _rules(implicit_code)
        if issue["rule"] == "clang_cfg_parent_release_without_owned_member_cleanup"
    )

    assert explicit["defect_class"] == "memory_leak"
    assert "node->children" in explicit["description"]
    assert "child/list" in implicit["description"]


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
    shared_fd_close = """
80 | static int g_watched_fd;
81 | int close_shared_connection(int fd) {
82 |     g_watched_fd = fd;
83 |     close(fd);
84 |     return 0;
85 | }
"""

    issues = _rules(code)
    local_fd_rules = {issue["rule"] for issue in _rules(local_fd_cleanup)}
    lifecycle_rules = {issue["rule"] for issue in _rules(lifecycle_close)}
    shared_fd_rules = {issue["rule"] for issue in _rules(shared_fd_close)}
    rules = {issue["rule"] for issue in issues}

    assert "clang_cfg_use_after_release" not in rules
    assert "clang_cfg_unbounded_vla_or_stack_array" not in rules
    assert "clang_cfg_fd_closed_without_owner_invalidation" not in local_fd_rules
    assert "clang_cfg_fd_closed_without_owner_invalidation" not in lifecycle_rules
    assert "clang_cfg_fd_closed_without_owner_invalidation" in shared_fd_rules
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


def test_clang_ast_cfg_suppresses_out_param_leak_after_braced_failure_return() -> None:
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
60 | int demo(const char *path) {
61 |     int fd = -1;
62 |     int rc = SHM_FileMngFileCreate(path, &fd);
63 |     if (rc != 0) { return rc; }
64 |     SHM_FileClose(fd);
65 |     return 0;
66 | }
"""

    issues = _rules(code, semantics=semantics, overlay=overlay)

    assert not any(issue["rule"] == "clang_cfg_acquire_without_release_on_exit" for issue in issues)
    assert not any(issue["rule"] == "clang_cfg_out_param_used_before_success_check" for issue in issues)


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

    assert "clang_cfg_object_published_before_initialization" not in rules
    assert "clang_cfg_cond_wait_guarded_by_if" in rules
    assert "clang_cfg_unaligned_integer_pointer_cast" in rules


def test_clang_ast_cfg_keeps_object_publication_when_not_same_lock_region() -> None:
    code = """
120 | int demo(void) {
121 |     LifecycleEntry *entry = _safe_calloc(1, sizeof(LifecycleEntry));
122 |     LOCK(&g_lifecycle.lock);
123 |     g_lifecycle.entries = entry;
124 |     UNLOCK(&g_lifecycle.lock);
125 |     entry->value = _str_dup("value");
126 |     return 0;
127 | }
"""

    rules = {issue["rule"] for issue in _rules(code)}

    assert "clang_cfg_object_published_before_initialization" in rules


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


def test_clang_ast_cfg_promotes_wide_count_before_magic_when_count_reaches_copy_sink() -> None:
    code = """
10 | uint64_t read_magic(const unsigned char *blob, size_t len) {
11 |     if (!blob || len < 16) return 0;
12 |     uint64_t count = 0;
13 |     memcpy(&count, blob + 8, sizeof(count));
14 |     unsigned char preview[16];
15 |     unsigned char seed[16] = {0};
16 |     memcpy(preview, seed, (size_t)count);
17 |     return count;
18 | }
"""

    issue = next(
        issue
        for issue in _rules(code)
        if issue["rule"] == "clang_cfg_wide_count_before_magic_reaches_memory_sink"
    )

    assert issue["defect_class"] == "bounds"
    assert issue["candidate_priority_group"] == "exact_sink"
    assert "memcpy(preview, seed" in issue["sink"]


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


def test_clang_ast_cfg_detects_free_of_derived_pointer_alias() -> None:
    code = """
10 | void demo(char *base, size_t offset) {
11 |     char *cursor = base;
12 |     cursor += offset;
13 |     free(cursor);
14 | }
"""

    rules = {issue["rule"] for issue in _rules(code)}

    assert "clang_cfg_free_derived_pointer_alias" in rules


def test_clang_ast_cfg_detects_unchecked_allocation_use() -> None:
    code = """
10 | void demo(size_t count) {
11 |     char *buf = malloc(count);
12 |     buf[0] = 0;
13 | }
"""

    issues = _rules(code)

    assert any(issue["rule"] == "clang_cfg_allocation_result_used_without_null_check" for issue in issues)


def test_clang_ast_cfg_detects_wire_integer_pointer_deref() -> None:
    code = """
10 | typedef struct Header { uintptr_t addr; } Header;
11 | void demo(Header *hdr) {
12 |     uint32_t *state = (uint32_t *)(uintptr_t)hdr->addr;
13 |     *state = 1;
14 | }
"""

    rules = {issue["rule"] for issue in _rules(code)}

    assert "clang_cfg_wire_integer_cast_to_pointer_deref" in rules


def test_clang_ast_cfg_detects_unchecked_object_offset_access() -> None:
    code = """
10 | typedef struct Record { unsigned char bytes[16]; } Record;
11 | void demo(size_t offset) {
12 |     Record local;
13 |     unsigned char *field = ((unsigned char *)&local) + offset;
14 |     field[0] = 1;
15 | }
"""

    rules = {issue["rule"] for issue in _rules(code)}

    assert "clang_cfg_unchecked_object_offset_deref" in rules


def test_clang_ast_cfg_detects_maybe_uninitialized_pointer_use() -> None:
    code = """
10 | void demo(int flag, char *src) {
11 |     char *cursor;
12 |     if (flag) cursor = src;
13 |     cursor[0] = 1;
14 | }
"""

    rules = {issue["rule"] for issue in _rules(code)}

    assert "clang_cfg_pointer_may_be_uninitialized_before_use" in rules


def test_clang_ast_cfg_detects_unbounded_heap_allocation() -> None:
    code = """
10 | void *demo(size_t replay_window) {
11 |     return malloc(replay_window * sizeof(int));
12 | }
"""

    issues = _rules(code)

    assert any(issue["rule"] == "clang_cfg_external_size_allocation_without_limit" for issue in issues)


def test_clang_ast_cfg_detects_fixed_array_count_overflow() -> None:
    code = """
10 | void demo(size_t item_count) {
11 |     int slots[4];
12 |     for (size_t i = 0; i < item_count; ++i) {
13 |         slots[i] = 0;
14 |     }
15 | }
"""

    rules = {issue["rule"] for issue in _rules(code)}

    assert "clang_cfg_unbounded_count_indexes_fixed_array" in rules


def test_clang_ast_cfg_detects_fd_leak_on_error_return() -> None:
    code = """
10 | int demo(const char *path, int bad) {
11 |     int fd = open(path, 0);
12 |     if (fd < 0) return -1;
13 |     if (bad) return -2;
14 |     close(fd);
15 |     return 0;
16 | }
"""

    rules = {issue["rule"] for issue in _rules(code)}

    assert "clang_cfg_fd_open_return_without_close" in rules


def test_clang_ast_cfg_detects_unlock_without_matching_lock() -> None:
    code = """
10 | void demo(pthread_mutex_t *lock) {
11 |     pthread_mutex_unlock(lock);
12 | }
"""

    issues = _rules(code)
    rule = next(issue for issue in issues if issue["rule"] == "clang_cfg_unlock_without_matching_lock")

    assert rule["category"] == "lock_protocol_violation"
    assert rule["cwe"] == "CWE-832"


def test_analyzer_prioritizes_dangerous_callees_for_local_rule_scan() -> None:
    queue = [
        ("boring_helper", 1, ["entry", "boring_helper"]),
        ("decode_wire_offset", 1, ["entry", "decode_wire_offset"]),
        ("cleanup_fd_owner", 1, ["entry", "cleanup_fd_owner"]),
    ]

    ordered = Analyzer._prioritize_callee_queue(queue)

    assert ordered[0][0] in {"cleanup_fd_owner", "decode_wire_offset"}
    assert ordered[-1][0] == "boring_helper"


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


def test_clang_ast_cfg_emits_heap_overflow_for_narrowed_allocation_then_original_copy() -> None:
    code = """
300 | int demo(Header header, const char *source) {
301 |     size_t alloc_len = (uint16_t)header.fragment_len;
302 |     char *fragment = _safe_malloc(alloc_len + 1);
303 |     size_t copy_len = header.fragment_len;
304 |     memcpy(fragment, source, copy_len);
305 |     SAFE_FREE(fragment);
306 |     return 0;
307 | }
"""

    issues = _rules(code)
    heap = next(issue for issue in issues if issue["rule"] == "clang_cfg_narrowed_allocation_original_length_copy")

    assert heap["defect_class"] == "heap_overflow"
    assert heap["candidate_priority_group"] == "exact_sink"
    assert "alloc_len" in heap["description"]
    assert not any(
        issue["defect_class"] == "integer_overflow"
        and issue["function"] == "demo"
        and issue["location"] == "src/demo.c:302"
        for issue in issues
    )


def test_clang_ast_cfg_suppresses_bounded_short_lived_unbounded_allocation_candidate() -> None:
    code = """
400 | int demo(Header header) {
401 |     size_t alloc_len = (uint16_t)header.fragment_len;
402 |     char *fragment = _safe_malloc(alloc_len + 1);
403 |     if (!fragment) return -1;
404 |     SAFE_FREE(fragment);
405 |     return 0;
406 | }
"""

    issues = _rules(code)

    assert not any(issue["defect_class"] == "resource_allocation_without_limits" for issue in issues)


def test_clang_ast_cfg_keeps_lifetime_sensitive_external_allocation_candidate() -> None:
    code = """
410 | int demo(uint32_t segment_count) {
411 |     int *fd_table = (int*)_safe_calloc(segment_count, sizeof(int));
412 |     if (!fd_table) return -1;
413 |     for (uint32_t i = 0; i < segment_count; i++) {
414 |         fd_table[i] = i;
415 |     }
416 |     SAFE_FREE(fd_table);
417 |     return 0;
418 | }
"""

    issues = _rules(code)

    assert any(issue["defect_class"] == "resource_allocation_without_limits" for issue in issues)


def test_clang_ast_cfg_resolves_size_alias_for_external_allocation_candidate() -> None:
    code = """
419 | int demo(uint32_t replay_window) {
420 |     size_t bytes = (size_t)replay_window * sizeof(RuntimeStreamSegment);
421 |     g_runtime_stream_client.replay_window = _safe_malloc(bytes);
422 |     if (!g_runtime_stream_client.replay_window) return -1;
423 |     return 0;
424 | }
"""

    issue = next(
        issue
        for issue in _rules(code)
        if issue["rule"] == "clang_cfg_external_size_allocation_without_limit"
    )

    assert issue["defect_class"] == "resource_allocation_without_limits"
    assert "replay_window" in issue["source"]


def test_clang_ast_cfg_emits_file_type_validation_order() -> None:
    code = """
420 | void *demo(uint32_t mode, uint64_t file_size, uint64_t map_size) {
421 |     if (map_size == 0 || map_size > (uint64_t)SIZE_MAX) return NULL;
422 |     if (file_size < map_size) return NULL;
423 |     if (RUNTIME_IS_CHR(mode)) {
424 |         LOG_INFO("character device mapping accepted");
425 |     } else if (!RUNTIME_IS_REG(mode)) {
426 |         return NULL;
427 |     }
428 |     return mmap(NULL, (size_t)map_size, PROT_READ, MAP_PRIVATE, -1, 0);
429 | }
"""

    issue = next(issue for issue in _rules(code) if issue["rule"] == "clang_cfg_file_type_validation_after_mapping_size_check")

    assert issue["defect_class"] == "file_type_validation"
    assert issue["candidate_priority_group"] == "semantic_suspicious_point"


def test_clang_ast_cfg_emits_premature_destroy_for_active_shared_pool() -> None:
    code = """
430 | int demo(int active_tasks) {
431 |     RuntimePbufPool *pool = _safe_calloc(1, sizeof(RuntimePbufPool));
432 |     if (!pool) return -1;
433 |     g_runtime_pbuf_pool = pool;
434 |     if (active_tasks > 0) {
435 |         SAFE_FREE(g_runtime_pbuf_pool->buffer);
436 |         SAFE_FREE(g_runtime_pbuf_pool);
437 |         return active_tasks;
438 |     }
439 |     SAFE_FREE(pool);
440 |     return 0;
441 | }
"""

    issues = _rules(code)

    assert any(issue["defect_class"] == "premature_destroy" for issue in issues)


def test_clang_ast_cfg_emits_unsynchronized_global_watermark_update() -> None:
    code = """
450 | uint64_t demo(uint64_t observed, int maintenance) {
451 |     if (maintenance) {
452 |         LOCK(&g_runtime_stream_lock);
453 |         g_runtime_stream_client.watermark = observed;
454 |         g_runtime_stream_watermark = observed;
455 |         UNLOCK(&g_runtime_stream_lock);
456 |         return observed;
457 |     }
458 |     uint64_t previous = g_runtime_stream_watermark;
459 |     g_runtime_stream_watermark = observed;
460 |     g_runtime_stream_client.watermark = previous + 1;
461 |     return g_runtime_stream_watermark;
462 | }
"""

    issue = next(
        issue
        for issue in _rules(code)
        if issue["rule"] == "clang_cfg_global_state_written_with_and_without_lock"
    )

    assert issue["defect_class"] == "unsynchronized_shared_state"
    assert "watermark" in issue["description"]


def test_clang_ast_cfg_emits_global_pointer_length_publication_without_lock() -> None:
    code = """
470 | int demo(const char *path, size_t len) {
471 |     int fd = open(path, O_RDONLY);
472 |     if (fd < 0) return -1;
473 |     g_rules_map = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
474 |     close(fd);
475 |     if (g_rules_map == MAP_FAILED) return -1;
476 |     g_rules_len = len;
477 |     return 0;
478 | }
"""

    issue = next(
        issue
        for issue in _rules(code)
        if issue["rule"] == "clang_cfg_global_pointer_length_pair_published_without_lock"
    )

    assert issue["defect_class"] == "unsynchronized_shared_state"
    assert "pointer/length" in issue["description"]


def test_clang_ast_cfg_emits_permission_mode_mismatch() -> None:
    code = """
480 | int demo(const char *shm_name, uint32_t requested_perm) {
481 |     g_runtime_named_pipe.fd = 42;
482 |     g_runtime_named_pipe.perm = 0660u;
483 |     if (shm_name && strcmp(shm_name, "product-namedpipe") == 0) {
484 |         LOG_INFO("using product-specific named pipe");
485 |     }
486 |     if ((requested_perm & 0004u) != 0 && (g_runtime_named_pipe.perm & 0004u) == 0) {
487 |         return -1;
488 |     }
489 |     return 0;
490 | }
"""

    issue = next(
        issue
        for issue in _rules(code)
        if issue["rule"] == "clang_cfg_requested_permission_not_applied_to_mode"
    )

    assert issue["defect_class"] == "permission"
    assert "Requested" in issue["description"]


def test_clang_ast_cfg_emits_timer_callback_lock_order_candidate() -> None:
    code = """
500 | int demo_timer_callback(int pipe_id) {
501 |     PipeNode *pipe = g_pipe_scheduler.head;
502 |     while (pipe) {
503 |         if (pipe->pipe_id == pipe_id) {
504 |             LOCK(&pipe->ctrl_lock);
505 |             UNLOCK(&pipe->ctrl_lock);
506 |             return 0;
507 |         }
508 |         pipe = pipe->next;
509 |     }
510 |     return -1;
511 | }
"""

    issue = next(
        issue
        for issue in _rules(code)
        if issue["rule"] == "clang_cfg_timer_callback_object_lock_without_scheduler_lock"
    )

    assert issue["defect_class"] == "deadlock"
    assert "Timer/callback" in issue["description"]


def test_clang_ast_cfg_emits_pointer_backtrack_underread_and_underwrite() -> None:
    read_code = """
500 | int demo(const char *wire, size_t wire_len, size_t footer_backtrack) {
501 |     const char *footer = wire + wire_len - footer_backtrack;
502 |     uint32_t marker = 0;
503 |     memcpy(&marker, footer, sizeof(marker));
504 |     return (int)marker;
505 | }
"""
    write_code = """
510 | int demo(char *window, size_t prefix_len) {
511 |     char *target = window - prefix_len;
512 |     memset(target, 0, 16);
513 |     return 0;
514 | }
"""

    read_issue = next(issue for issue in _rules(read_code) if issue["rule"] == "clang_cfg_unchecked_pointer_backtrack")
    write_issue = next(issue for issue in _rules(write_code) if issue["rule"] == "clang_cfg_unchecked_pointer_backtrack")

    assert read_issue["defect_class"] == "buffer_underread"
    assert write_issue["defect_class"] == "buffer_underwrite"


def test_clang_ast_cfg_emits_pointer_backtrack_for_decremented_footer_pointer() -> None:
    code = """
520 | int demo(const char *wire, size_t wire_len, Header header) {
521 |     const char *footer = wire + wire_len - sizeof(uint32_t);
522 |     footer -= header.footer_backtrack;
523 |     uint32_t marker = 0;
524 |     memcpy(&marker, footer, sizeof(marker));
525 |     return (int)marker;
526 | }
"""

    issue = next(issue for issue in _rules(code) if issue["rule"] == "clang_cfg_unchecked_pointer_backtrack")

    assert issue["defect_class"] == "buffer_underread"
    assert "footer_backtrack" in issue["source"]


def test_clang_ast_cfg_emits_fixed_array_member_write_count_overflow() -> None:
    code = """
530 | int demo(Header header) {
531 |     Segment segments[4];
532 |     for (uint32_t i = 0; i < header.segment_count; i++) {
533 |         segments[i].offset = i;
534 |     }
535 |     return 0;
536 | }
"""

    issue = next(issue for issue in _rules(code) if issue["rule"] == "clang_cfg_unbounded_count_indexes_fixed_array")

    assert issue["defect_class"] == "out_of_bounds_write"
    assert "header.segment_count" in issue["description"]


def test_clang_ast_cfg_emits_offset_length_overread() -> None:
    code = """
540 | int demo(const unsigned char *source, size_t source_len, Header header, unsigned char *out, size_t out_len) {
541 |     const unsigned char *digest = source + header.digest_offset;
542 |     size_t digest_len = MIN(header.digest_len, out_len);
543 |     memcpy(out, digest, digest_len);
544 |     return 0;
545 | }
"""

    issue = next(issue for issue in _rules(code) if issue["rule"] == "clang_cfg_offset_length_copy_without_source_bound")

    assert issue["defect_class"] == "buffer_overread"
    assert "digest_offset" in issue["description"]


def test_clang_ast_cfg_emits_heap_overflow_for_distinct_header_alloc_and_copy_lengths() -> None:
    code = """
550 | int demo(Header header, const char *source, size_t source_len) {
551 |     size_t alloc_len = (uint16_t)header.fragment_len;
552 |     size_t copy_len = MIN(header.copy_len, source_len);
553 |     char *fragment = _safe_malloc(alloc_len + 1);
554 |     memcpy(fragment, source, copy_len);
555 |     SAFE_FREE(fragment);
556 |     return 0;
557 | }
"""

    issue = next(issue for issue in _rules(code) if issue["rule"] == "clang_cfg_narrowed_allocation_original_length_copy")

    assert issue["defect_class"] == "heap_overflow"
    assert "copy_len" in issue["sink"]


def test_clang_ast_cfg_emits_owned_allocated_member_leaks_for_payload_and_tree_children() -> None:
    payload_code = """
560 | int demo(const char *key) {
561 |     ServiceNode *node = _service_alloc_node(key, "tree");
562 |     node->payload = _safe_strdup(key);
563 |     SAFE_FREE(node->name);
564 |     SAFE_FREE(node);
565 |     return 0;
566 | }
"""
    tree_code = """
570 | int demo(const char *key) {
571 |     ServiceNode *node = _service_alloc_node(key, "tree");
572 |     node->left = _service_alloc_node("left", "child");
573 |     node->right = _service_alloc_node("right", "child");
574 |     SAFE_FREE(node->name);
575 |     SAFE_FREE(node);
576 |     return 0;
577 | }
"""

    payload_leak = next(
        issue
        for issue in _rules(payload_code)
        if issue["rule"] == "clang_cfg_parent_release_without_owned_member_cleanup"
    )
    tree_leak = next(
        issue
        for issue in _rules(tree_code)
        if issue["rule"] == "clang_cfg_parent_release_without_owned_member_cleanup"
    )

    assert "node->payload" in payload_leak["description"]
    assert "node->" in tree_leak["description"]


def test_clang_ast_cfg_emits_slot_overwrite_leak() -> None:
    code = """
570 | int plugin_register(PluginRegistry *registry, const char *name, void *context) {
571 |     size_t slot = _hash_string(name) % registry->capacity;
572 |     Plugin *plugin = &registry->plugins[slot];
573 |     STR_COPY(plugin->name, name);
574 |     plugin->context = context;
575 |     registry->count++;
576 |     return 0;
577 | }
"""

    issue = next(issue for issue in _rules(code) if issue["rule"] == "clang_cfg_slot_overwrite_without_existing_owner_cleanup")

    assert issue["defect_class"] == "memory_leak"
    assert "plugin->context" in issue["sink"]


def test_clang_ast_cfg_emits_key_truncation_and_key_generation_race() -> None:
    truncation_code = """
580 | int demo(const char *route_key) {
581 |     ServiceNode *existing = _service_find_locked(route_key);
582 |     if (existing) return 0;
583 |     ServiceNode *node = _service_alloc_node(route_key, "policy");
584 |     strncpy(node->key, route_key, 31);
585 |     return _service_tree_insert(node, 0);
586 | }
"""
    race_code = """
590 | int demo(const char *path, int project_id) {
591 |     if (!_file_exists(path)) { LOG_WARN("missing"); }
592 |     int key = (int)(_hash_string(path) & 0xffffu) | ((project_id & 0xff) << 16);
593 |     LOCK(&g_runtime_ftok_lock); if (_runtime_find_shared_zone(path) != NULL) { LOG_WARN("collision"); }
594 |     UNLOCK(&g_runtime_ftok_lock);
595 |     return key;
596 | }
"""

    truncation = next(issue for issue in _rules(truncation_code) if issue["rule"] == "clang_cfg_full_key_lookup_truncated_key_insert")
    race = next(issue for issue in _rules(race_code) if issue["rule"] == "clang_cfg_path_state_key_generation_before_locked_registration")

    assert truncation["defect_class"] == "key_truncation"
    assert race["defect_class"] == "key_generation_race"


def test_clang_ast_cfg_emits_header_length_copy_without_wire_bound() -> None:
    code = """
600 | int demo(const unsigned char *wire, size_t wire_len, unsigned char *out, size_t out_len) {
601 |     Header header;
602 |     memcpy(&header, wire, sizeof(header));
603 |     if (header.magic != MAGIC) return -1;
604 |     size_t body_len = (size_t)header.length - sizeof(Header);
605 |     if (body_len <= out_len) {
606 |         memcpy(out, wire + sizeof(Header), body_len);
607 |     }
608 |     return 0;
609 | }
"""

    issue = next(issue for issue in _rules(code) if issue["rule"] == "clang_cfg_header_length_reaches_copy_without_wire_bound")

    assert issue["defect_class"] == "bounds"
    assert "body_len" in issue["sink"]


def test_clang_ast_cfg_detects_multiline_allocation_used_without_null_check() -> None:
    code = """
610 | int demo(uint32_t entry_count) {
611 |     RuntimeStreamSegment first = {0};
612 |     RuntimeStreamSegment **index =
613 |         (RuntimeStreamSegment **)_safe_calloc(entry_count,
614 |                                              sizeof(RuntimeStreamSegment *));
615 |     index[0] = &first;
616 |     return (int)index[0]->length;
617 | }
"""

    issue = next(issue for issue in _rules(code) if issue["rule"] == "clang_cfg_allocation_result_used_without_null_check")

    assert issue["defect_class"] == "unchecked_allocation"
    assert issue["location"] == "src/demo.c:615"


def test_analyzer_candidate_budget_keeps_exact_before_generic_and_observes_excess() -> None:
    issues = [
        {
            "id": "GEN1",
            "function": "demo",
            "category": "resource_allocation_without_limits",
            "defect_class": "resource_allocation_without_limits",
            "validation_budget_class": "generic",
            "candidate_priority_group": "generic_audit",
            "confidence": 0.9,
            "evidence_pack": {},
        },
        {
            "id": "GEN2",
            "function": "demo",
            "category": "resource_allocation_without_limits",
            "defect_class": "resource_allocation_without_limits",
            "validation_budget_class": "generic",
            "candidate_priority_group": "generic_audit",
            "confidence": 0.8,
            "evidence_pack": {},
        },
        {
            "id": "GEN3",
            "function": "demo",
            "category": "resource_allocation_without_limits",
            "defect_class": "resource_allocation_without_limits",
            "validation_budget_class": "generic",
            "candidate_priority_group": "generic_audit",
            "confidence": 0.7,
            "evidence_pack": {},
        },
        {
            "id": "EXACT",
            "function": "demo",
            "category": "heap_overflow",
            "defect_class": "heap_overflow",
            "validation_budget_class": "exact",
            "candidate_priority_group": "exact_sink",
            "confidence": 0.75,
            "evidence_pack": {},
        },
    ]

    budgeted = Analyzer._apply_candidate_validation_budget(issues)

    assert budgeted[0]["id"] == "EXACT"
    assert [issue["id"] for issue in budgeted if issue.get("validation_required") is False] == []
    assert budgeted[-1]["id"] == "GEN3"
    assert budgeted[-1]["validation_budget_class"] == "generic_soft_overrun"
    assert "retained for validation" in budgeted[-1]["validation_budget_observation"]


def test_analyzer_candidate_budget_keeps_quota_lifetime_sensitive_generic() -> None:
    issues = [
        {
            "id": f"GEN{index}",
            "function": "demo",
            "category": "resource_allocation_without_limits",
            "defect_class": "resource_allocation_without_limits",
            "validation_budget_class": "generic",
            "candidate_priority_group": "generic_audit",
            "confidence": 0.7,
            "source": "segment_count",
            "sink": "fd_table = _safe_calloc(segment_count, sizeof(int))",
            "description": "thread segment allocation has no quota",
            "evidence_pack": {},
        }
        for index in range(4)
    ]

    budgeted = Analyzer._apply_candidate_validation_budget(issues)

    assert all(issue.get("validation_required") is not False for issue in budgeted)
    assert {issue["validation_budget_class"] for issue in budgeted} == {"quota_lifetime_sensitive_generic"}


def test_analyzer_balanced_callee_queue_preserves_original_prefix_before_danger_sort() -> None:
    queue = [
        ("first_plain", 1, ["root", "first_plain"]),
        ("second_plain", 1, ["root", "second_plain"]),
        ("late_release_helper", 1, ["root", "late_release_helper"]),
        ("late_alloc_helper", 1, ["root", "late_alloc_helper"]),
        ("late_plain", 1, ["root", "late_plain"]),
    ]

    selected = Analyzer._balanced_callee_queue(queue, 4)

    assert [item[0] for item in selected[:2]] == ["first_plain", "second_plain"]
    assert {item[0] for item in selected[2:]} == {"late_alloc_helper", "late_release_helper"}

