from zscope.core.deterministic_candidates import (
    DeterministicCandidateGenerator,
    DeterministicSemantics,
)


def _classes(code: str) -> set[str]:
    issues = DeterministicCandidateGenerator().generate_issues(
        "entry",
        code,
        "src/demo.c",
    )
    return {str(issue["defect_class"]) for issue in issues}


def test_memory_and_concurrency_candidate_patterns() -> None:
    code = r"""
int entry(const unsigned char* data, size_t data_len, size_t max_len, size_t count) {
    const TaskHeader* header = (const TaskHeader*)data;
    const char* payload_data = (const char*)data + sizeof(TaskHeader);
    size_t payload_len = header->payload_length;
    memcpy(dst, payload_data, payload_len);

    size_t total_len = sizeof(TaskHeader) + payload_len;
    void* response = _safe_malloc(payload_len * 2);
    char* s = (char*)_safe_malloc(max_len + 1);
    g_metrics = (size_t*)_safe_realloc(g_metrics, count * sizeof(size_t));

    char* error_msg = (char*)_safe_malloc(256);
    char* recovery_buffer = (char*)_safe_malloc(1024);

    char* sep = strchr(command, ':');
    size_t key_len = (size_t)(sep - command);

    LOCK(&g_lock);
    if (!response) {
        return -1;
    }
    UNLOCK(&g_lock);

    return 0;
}
"""
    assert {
        "bounds",
        "integer_overflow",
        "realloc_misuse",
        "memory_leak",
        "null_pointer_dereference",
        "missing_unlock",
    }.issubset(_classes(code))


def test_deeper_c_lifetime_and_thread_patterns() -> None:
    code = r"""
int entry(const char* key, plugin_callback_t cb, int fd, size_t field_count) {
    LifecycleEntry* entry = (LifecycleEntry*)_safe_calloc(1, sizeof(LifecycleEntry));
    LOCK(&g_lifecycle.lock);
    g_lifecycle.entries = entry;
    entry->value = _str_dup(key);
    UNLOCK(&g_lifecycle.lock);

    LOCK(&g_lifecycle.lock);
    LifecycleEntry* found = _find_entry_locked(key);
    const char* value = found ? found->value : NULL;
    g_callback_entry = _find_entry_locked(key);
    UNLOCK(&g_lifecycle.lock);
    found->ref_count++;
    LOCK(&g_lifecycle.lock);
    g_entry_callback(g_callback_entry);
    UNLOCK(&g_lifecycle.lock);

    FlushJob job;
    pthread_create(&g_flush_thread, NULL, _flush_worker, &job);

    if (g_pending_jobs == 0) {
        pthread_cond_wait(&g_cond, &g_lifecycle.lock);
    }

    int received = _net_recv_data(fd, temp, sizeof(temp));
    size_t copy_len = (size_t)received;
    memcpy(dst, temp, copy_len);

    char topic[32];
    topic[sizeof(topic)] = '\0';

    StatusReply reply;
    reply.code = 200;
    _net_send_data(fd, &reply, sizeof(reply));

    free(value + 1);
    char frame[field_count * 128];
    const uint32_t* id = (const uint32_t*)(packet + 1);
    return *id;
}
"""
    assert {
        "object_publication",
        "use_after_free",
        "refcount_race",
        "held_lock_callback",
        "stack_escape",
        "lost_wakeup",
        "signed_unsigned",
        "off_by_one",
        "uninitialized_read",
        "invalid_free",
        "stack_overflow",
        "alignment",
    }.issubset(_classes(code))


def test_project_semantics_extend_typedefs_and_custom_memory_apis() -> None:
    semantics = DeterministicSemantics(
        type_aliases={"VOS_UINT32": "unsigned int"},
        allocators={"VOS_MemAlloc": ["user_config"]},
        deallocators={"VOS_MemFree": ["user_config"]},
        copy_sinks={"VOS_MemCopy": ["semantic_snapshot"]},
    )
    code = r"""
int entry(VOS_UINT32 count, VOS_UINT32 width) {
    VOS_UINT32 total_size = count * width;
    void* leaked = VOS_MemAlloc(total_size);
    VOS_MemCopy(dst, leaked, total_size);

    void* p = VOS_MemAlloc(128);
    VOS_MemFree(p);
    VOS_MemFree(p);
    return 0;
}
"""
    issues = DeterministicCandidateGenerator(semantics).generate_issues(
        "entry",
        code,
        "src/demo.c",
    )
    classes = {str(issue["defect_class"]) for issue in issues}

    assert {"integer_overflow", "memory_leak", "double_free"}.issubset(classes)
    assert any(
        "VOS_MemAlloc" in evidence and "user_config" in evidence
        for issue in issues
        for evidence in issue.get("positive_evidence", [])
    )


def test_scalar_arguments_are_not_double_free_candidates() -> None:
    code = r"""
int entry(int pipe_id) {
    _lifecycle_tick_timer_callback(pipe_id);
    _lifecycle_close_pipe(pipe_id);
    return _lifecycle_dispatch_pipe_tick(pipe_id);
}
"""
    assert "double_free" not in _classes(code)


def test_socket_cleanup_close_is_not_stale_fd_candidate() -> None:
    code = r"""
int entry(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (bind(fd, 0, 0) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}
"""
    assert "stale_fd" not in _classes(code)


def test_name_heuristics_cover_custom_alloc_and_lock_wrappers() -> None:
    code = r"""
int entry(size_t packet_len) {
    VOS_Lock(&g_lock);
    if (packet_len == 0) {
        return -1;
    }
    VOS_Unlock(&g_lock);

    void* p = VOS_MemAlloc(packet_len + 1);
    return 0;
}
"""
    issues = DeterministicCandidateGenerator().generate_issues(
        "entry",
        code,
        "src/demo.c",
    )
    classes = {str(issue["defect_class"]) for issue in issues}

    assert {"missing_unlock", "integer_overflow", "memory_leak"}.issubset(classes)
    assert any(
        "name_heuristic" in evidence
        for issue in issues
        for evidence in issue.get("positive_evidence", [])
    )


def test_deterministic_reasoning_is_chinese_and_evidence_backed() -> None:
    code = r"""
int entry(size_t payload_len) {
    void* response = _safe_malloc(payload_len * 2);
    return response ? 0 : -1;
}
"""
    issues = DeterministicCandidateGenerator().generate_issues(
        "entry",
        code,
        "src/demo.c",
    )
    issue = next(item for item in issues if item["defect_class"] == "integer_overflow")

    reasoning = issue["reasoning"]
    assert "确定性规则" in reasoning
    assert "关键证据" in reasoning
    assert "根因" in reasoning
    assert "line 3" in reasoning
    assert "Deterministic candidate generated" not in reasoning
