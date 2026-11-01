import pytest

from semantic_fixtures import configured_test_semantics
from zscope.core.candidates.regex import (
    RegexCandidateGenerator,
    LocalPatternSemantics,
    current_compiler_intrinsic_names,
)


def test_current_compiler_intrinsic_requires_exact_native_builtin_identity() -> None:
    facts = {
        "functions": [
            {
                "events": [
                    {
                        "event_kind": "call",
                        "callee": {
                            "name": "__builtin_ctzll",
                            "usr": "c:@F@__builtin_ctzll",
                            "canonical_signature": "int (unsigned long long)",
                            "external_linkage": True,
                            "has_definition": False,
                        },
                    }
                ]
            }
        ]
    }
    assert current_compiler_intrinsic_names(facts) == frozenset({"__builtin_ctzll"})

    facts["functions"][0]["events"][0]["callee"]["has_definition"] = True
    assert current_compiler_intrinsic_names(facts) == frozenset()


def test_restricted_generator_accepts_only_native_proven_compiler_intrinsic() -> None:
    facts = {
        "functions": [
            {
                "events": [
                    {
                        "event_kind": "call",
                        "callee": {
                            "name": "__sync_bool_compare_and_swap",
                            "usr": "c:@F@__sync_bool_compare_and_swap",
                            "canonical_signature": "_Bool (volatile unsigned int *, unsigned int, unsigned int)",
                            "external_linkage": True,
                            "has_definition": False,
                        },
                    }
                ]
            }
        ]
    }
    generator = RegexCandidateGenerator(
        LocalPatternSemantics(),
        program_facts_provider=lambda *_args: facts,
        restrict_to_semantics=True,
    )
    generator.program_facts = facts
    assert generator._semantic_call_allowed(
        "__sync_bool_compare_and_swap", "standard_operation"
    )

    generator.program_facts = {}
    assert not generator._semantic_call_allowed(
        "__sync_bool_compare_and_swap", "standard_operation"
    )


def _native_call_event(line: int, name: str, signature: str) -> dict:
    return {
        "event_kind": "call",
        "location": {"line": line},
        "assignment_target": "",
        "callee": {
            "name": name,
            "usr": f"c:@F@{name}",
            "canonical_signature": signature,
            "is_system_header": False,
        },
    }


def test_regex_detects_exact_nonvoid_status_masked_by_later_return() -> None:
    code = """
10 | int demo(int value) {
11 |     update_state(value);
12 |     return close_state(value);
13 | }
"""
    facts = {
        "functions": [
            {
                "events": [
                    _native_call_event(11, "update_state", "int (int)"),
                    _native_call_event(12, "close_state", "int (int)"),
                ]
            }
        ]
    }

    issues = RegexCandidateGenerator(
        configured_test_semantics(),
        program_facts_provider=lambda *_args: facts,
    ).generate_issues("demo", code, "demo.c")

    issue = next(item for item in issues if item["rule"] == "error_probe_can_return_success")
    assert issue["defect_class"] == "unchecked_return"
    assert "int (int)" in issue["positive_evidence"][0]


@pytest.mark.parametrize(
    ("statement", "signature"),
    [
        ("(void)update_state(value);", "int (int)"),
        ("update_state(value);", "void (int)"),
    ],
)
def test_regex_does_not_infer_masked_status_without_unchecked_nonvoid_receipt(
    statement: str,
    signature: str,
) -> None:
    code = f"""
10 | int demo(int value) {{
11 |     {statement}
12 |     return close_state(value);
13 | }}
"""
    facts = {
        "functions": [
            {
                "events": [
                    _native_call_event(11, "update_state", signature),
                    _native_call_event(12, "close_state", "int (int)"),
                ]
            }
        ]
    }

    issues = RegexCandidateGenerator(
        configured_test_semantics(),
        program_facts_provider=lambda *_args: facts,
    ).generate_issues("demo", code, "demo.c")

    assert not any(item["rule"] == "error_probe_can_return_success" for item in issues)


def test_regex_does_not_treat_condition_call_as_discarded_status() -> None:
    code = """
10 | bool demo(int value) {
11 |     if (BeforeFile(value) || GetRestartPoint(value) < 4) {
12 |         return true;
13 |     }
14 |     return false;
15 | }
"""
    facts = {
        "functions": [
            {
                "events": [
                    _native_call_event(11, "BeforeFile", "_Bool (int)"),
                    _native_call_event(11, "GetRestartPoint", "unsigned int (int)"),
                ]
            }
        ]
    }

    issues = RegexCandidateGenerator(
        configured_test_semantics(), program_facts_provider=lambda *_args: facts
    ).generate_issues("demo", code, "demo.cc")

    assert not any(item["rule"] == "error_probe_can_return_success" for item in issues)


def test_regex_ignores_compile_time_stack_extents_and_comment_operators() -> None:
    code = """
10 | void demo(uint64_t value, size_t file_size, int fd) {
11 |     char first[sizeof(value)];
12 |     char second[kStackBufferSize];
13 |     char third[Footer::kEncodedLength];
14 |     mmap(/*addr=*/nullptr, file_size, PROT_READ, MAP_SHARED, fd, 0);
15 | }
"""

    rules = {
        item["rule"]
        for item in RegexCandidateGenerator(configured_test_semantics()).generate_issues(
            "demo", code, "demo.cc"
        )
    }

    assert "unbounded_vla_or_stack_array" not in rules
    assert "inline_allocation_size_overflow" not in rules


def test_regex_stale_resource_rules_require_persistent_nonterminal_owner() -> None:
    code = """
10 | struct File {
11 |   ~File() { close(fd_); munmap(mapping_, length_); }
12 |   int fd_;
13 |   void *mapping_;
14 |   size_t length_;
15 | };
16 | int cleanup_local(int fd) { close(fd); return 0; }
"""

    rules = {
        item["rule"]
        for item in RegexCandidateGenerator(configured_test_semantics()).generate_issues(
            "cleanup_local", code, "demo.cc"
        )
    }

    assert "fd_closed_without_invalidation" not in rules
    assert "mapping_unmapped_without_pointer_clear" not in rules


def test_regex_sigpipe_rule_requires_peer_descriptor_evidence() -> None:
    regular = """
10 | int write_file(int fd, const char *data, size_t size) {
11 |     return write(fd, data, size);
12 | }
"""
    peer = regular.replace("write_file(int fd", "write_peer(int peer_fd").replace(
        "write(fd,", "write(peer_fd,"
    )
    generator = RegexCandidateGenerator(configured_test_semantics())

    regular_rules = {item["rule"] for item in generator.generate_issues("write_file", regular, "demo.c")}
    peer_rules = {item["rule"] for item in generator.generate_issues("write_peer", peer, "demo.c")}

    assert "write_without_sigpipe_handling" not in regular_rules
    assert "write_without_sigpipe_handling" in peer_rules


def _classes(code: str) -> set[str]:
    issues = RegexCandidateGenerator(configured_test_semantics()).generate_issues(
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


def test_helper_publication_before_late_initialization_is_object_publication() -> None:
    code = r"""
int entry(const char* key) {
    Node* node = (Node*)_safe_calloc(1, sizeof(Node));
    if (!node) {
        return -1;
    }
    STR_COPY(node->key, key);
    _node_insert_locked(node);
    node->payload = _str_dup(key);
    pthread_mutex_init(&node->mutex, NULL);
    return 0;
}
"""
    issues = RegexCandidateGenerator(configured_test_semantics()).generate_issues(
        "entry", code, "src/demo.c"
    )

    assert any(
        issue.get("rule") == "object_published_by_helper_before_initialization"
        for issue in issues
    )


def test_function_pointer_callback_under_lock_is_detected() -> None:
    code = r"""
int entry(plugin_callback_t cb, void* ctx) {
    LOCK(&g_lock);
    if (cb) {
        (*cb)(ctx);
    }
    UNLOCK(&g_lock);
    return 0;
}
"""
    issues = RegexCandidateGenerator(configured_test_semantics()).generate_issues(
        "entry", code, "src/demo.c"
    )

    assert any(issue.get("rule") == "callback_while_lock_held" for issue in issues)


def test_fixture_shaped_names_do_not_create_special_candidates() -> None:
    code = r"""
int label(unsigned int element_count) {
    size_t label_len = (size_t)element_count * PROJECT_ELEMENT_INFO_SIZE;
    if (label_len > PROJECT_LABEL_CACHE_LIMIT) {
        return -1;
    }
    return (element_count <= PROJECT_SPEC_MAX_ELEMENTS) ? 0 : -1;
}

int expand(size_t task_index) {
    if (task_index >= g_project_task_array_cap) {
        size_t new_cap = ((task_index / 16u) + 1u) * 16u;
        ProjectTask** new_array = _safe_calloc(new_cap, sizeof(ProjectTask*));
        ProjectTask** old_array = g_project_task_array;
        g_project_task_array = new_array;
        g_project_task_array_cap = new_cap;
        SAFE_FREE(old_array);
    }
    return 0;
}

int bridge(int reliable_fd) {
    return lower_is_inter_fd(reliable_fd);
}

int authorize(int detected_protocol, int auth_level) {
    if (detected_protocol != 3 && auth_level != 7) {
        return 0;
    }
    return -1;
}

int transform(int work_fd) {
    int raw_work_fd = work_fd + 1;
    return project_validate_encoded_fd(raw_work_fd);
}

int inspect(const unsigned char* report) {
    uint8_t version = report[0];
    (void)version;
    return 0;
}

int retry(Node* node, int fail_step) {
    node->tag = 1;
    if (fail_step) {
        return -1;
    }
    return 0;
}

void close_resource(Resource* res) {
    int count = res->ref_count;
    (void)count;
    SAFE_FREE(res);
}
"""
    issues = RegexCandidateGenerator().generate_issues("entry", code, "src/demo.c")
    rules = {issue.get("rule") for issue in issues}

    assert rules.isdisjoint(
        {
            "implementation_limit_differs_from_protocol_limit",
            "global_array_resize_without_lock",
            "reliable_fd_passed_to_raw_fd_classifier",
            "protocol_mismatch_can_return_success",
            "parsed_version_is_ignored",
            "raw_fd_revalidated_as_encoded",
            "partial_resource_not_released_on_retry_failure",
            "shared_resource_freed_without_refcount_protocol",
        }
    )


def test_structural_error_path_candidate_is_invariant_to_identifier_renaming() -> None:
    observed = []
    for owner, allocator in (
        ("orchid_buffer", "arena_alloc"),
        ("quartz_payload", "region_create"),
        ("violet_record", "object_new"),
    ):
        code = f"""
int load(int should_stop) {{
    void* {owner} = {allocator}(64);
    if (should_stop) {{
        return -1;
    }}
    free({owner});
    return 0;
}}
"""
        semantics = LocalPatternSemantics()
        semantics.add_api("allocator", allocator, "user_config")
        issues = RegexCandidateGenerator(semantics).generate_issues("load", code, "src/demo.c")
        observed.append(
            {
                (issue.get("defect_class"), issue.get("rule"))
                for issue in issues
                if issue.get("rule") == "error_path_allocation_not_released"
            }
        )

    assert observed == [
        {("memory_leak", "error_path_allocation_not_released")},
        {("memory_leak", "error_path_allocation_not_released")},
        {("memory_leak", "error_path_allocation_not_released")},
    ]


def test_cpp_new_transferred_only_on_success_reports_failed_status_leak() -> None:
    code = """
Status DB::Open(const Options& options, DB** dbptr) {
    *dbptr = nullptr;
    DBImpl* impl = new DBImpl(options);
    Status status = impl->Recover();
    if (status.ok()) {
        impl->FinishOpen();
        *dbptr = impl;
    }
    return status;
}
"""

    issues = RegexCandidateGenerator().generate_issues("DB::Open", code, "db/db_impl.cc")
    issue = next(
        item
        for item in issues
        if item.get("rule") == "error_path_allocation_not_released"
    )

    assert issue["defect_class"] == "memory_leak"
    assert issue["evidence_pack"]["ownership"]["acquire"] == "cxx_new"
    assert issue["evidence_pack"]["path"]["complete_in_function"] is True
    assert "failure of status.ok()" in issue["evidence_pack"]["path"]["path_constraints"][0]


@pytest.mark.parametrize(
    "cleanup",
    [
        "if (!status.ok()) { delete impl; }",
        "*dbptr = impl;",
    ],
)
def test_cpp_new_failed_status_leak_requires_an_unrepaired_failure_path(cleanup: str) -> None:
    code = f"""
Status DB::Open(const Options& options, DB** dbptr) {{
    DBImpl* impl = new DBImpl(options);
    Status status = impl->Recover();
    if (status.ok()) {{
        *dbptr = impl;
    }}
    {cleanup}
    return status;
}}
"""

    issues = RegexCandidateGenerator().generate_issues("DB::Open", code, "db/db_impl.cc")

    assert not any(
        item.get("rule") == "error_path_allocation_not_released" for item in issues
    )


def test_ignored_decoded_control_field_is_structural_and_name_invariant() -> None:
    observed = []
    for dropped, checked, packet in (
        ("orchid_tag", "quartz_state", "wire_record"),
        ("violet_mode", "amber_status", "input_bytes"),
    ):
        code = f"""
int inspect(const unsigned char* {packet}, size_t payload_size) {{
    if (!{packet} || payload_size < 2) {{
        return -1;
    }}
    uint8_t {dropped} = {packet}[0];
    uint8_t {checked} = {packet}[1];
    (void){dropped};
    if ({checked} == 7) {{
        return -1;
    }}
    return 0;
}}
"""
        issues = RegexCandidateGenerator().generate_issues(
            "inspect", code, "src/demo.c"
        )
        observed.append(
            [
                issue
                for issue in issues
                if issue.get("rule") == "decoded_control_field_ignored"
            ]
        )

    assert [len(items) for items in observed] == [1, 1]
    assert all(
        item[0].get("defect_class") == "protocol_validation"
        for item in observed
    )


def test_project_semantics_extend_typedefs_and_custom_memory_apis() -> None:
    semantics = LocalPatternSemantics(
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
    issues = RegexCandidateGenerator(semantics).generate_issues(
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


def test_safe_free_macro_requires_explicit_deallocator_contract() -> None:
    code = r"""
int entry(char* p) {
    char* owned = malloc(16);
    SAFE_FREE(owned);
    SAFE_FREE(owned);
    return 0;
}
"""

    default_issues = RegexCandidateGenerator().generate_issues("entry", code, "src/demo.c")
    assert not any(issue.get("rule") == "same_pointer_freed_twice" for issue in default_issues)

    semantics = LocalPatternSemantics(deallocators={"SAFE_FREE": ["user_config"]})
    configured_issues = RegexCandidateGenerator(semantics).generate_issues("entry", code, "src/demo.c")
    assert any(issue.get("rule") == "same_pointer_freed_twice" for issue in configured_issues)


def test_safe_free_parent_still_reports_unreleased_member_allocations() -> None:
    code = r"""
int entry(const char* key) {
    RealModelNode* node = _real_model_alloc_node(key, "tree");
    if (!node) {
        return -1;
    }
    node->left = _real_model_alloc_node("left", "child");
    node->right = _real_model_alloc_node("right", "child");
    SAFE_FREE(node->payload);
    SAFE_FREE(node->name);
    SAFE_FREE(node);
    return 0;
}
"""
    issues = RegexCandidateGenerator(configured_test_semantics()).generate_issues(
        "entry", code, "src/demo.c"
    )

    assert all(
        not (
            issue.get("rule") == "same_function_allocation_not_released"
            and issue.get("source") == "node"
        )
        for issue in issues
    )
    member_leaks = [
        issue
        for issue in issues
        if issue.get("rule") == "member_allocation_not_released_with_parent"
    ]
    assert {issue.get("source") for issue in member_leaks} == {
        "node->left = _real_model_alloc_node(\"left\", \"child\");",
        "node->right = _real_model_alloc_node(\"right\", \"child\");",
    }


def test_state_restore_requires_assigning_state_back_to_previous() -> None:
    code = r"""
int entry(int fd) {
    int previous = g_real_registry.state;
    g_real_registry.state = fd;
    if (fcntl(fd, F_GETFD) < 0) {
        return -1;
    }
    previous = g_real_registry.state;
    return previous;
}
"""
    issues = RegexCandidateGenerator().generate_issues("entry", code, "src/demo.c")

    assert any(issue.get("rule") == "global_state_not_restored_on_error" for issue in issues)


def test_unchecked_insert_after_node_allocation_is_ownership_candidate() -> None:
    code = r"""
int entry(const char* key) {
    RealModelNode* node = _real_model_alloc_node(key, "avl");
    if (!node) {
        return -1;
    }
    _real_model_fake_avl_insert(node, 1);
    return 0;
}
"""
    issues = RegexCandidateGenerator(configured_test_semantics()).generate_issues(
        "entry", code, "src/demo.c"
    )

    assert any(issue.get("rule") == "unchecked_insert_after_ownership_handoff" for issue in issues)


def test_scalar_return_code_from_function_pointer_call_is_not_borrowed_pointer() -> None:
    semantics = LocalPatternSemantics(type_aliases={"VOS_UINT32": "unsigned int"})
    code = r"""
typedef unsigned int VOS_UINT32;
typedef struct FileOps {
    VOS_UINT32 (*pfnCreate)(const char* path, VOS_UINT32* fd);
} FileOps;

VOS_UINT32 entry(FileOps* ops, const char* path, VOS_UINT32* out_fd) {
    VOS_UINT32 uiRet = 0;
    VOS_UINT32 fd = 0;
    LOCK(&g_lock);
    uiRet = ops->pfnCreate(path, &fd);
    UNLOCK(&g_lock);
    *out_fd = fd;
    return uiRet;
}
"""
    issues = RegexCandidateGenerator(semantics).generate_issues(
        "entry",
        code,
        "src/demo.c",
    )

    assert all(issue.get("rule") != "borrowed_pointer_returned_after_unlock" for issue in issues)
    assert all(issue.get("rule") != "stack_address_to_retaining_api" for issue in issues)


def test_stack_address_to_retaining_api_reports_escape() -> None:
    code = r"""
int entry(void) {
    int fd = 0;
    register_async_context(&fd);
    return 0;
}
"""
    issues = RegexCandidateGenerator().generate_issues(
        "entry",
        code,
        "src/demo.c",
    )

    assert any(issue.get("rule") == "stack_address_to_retaining_api" for issue in issues)


def test_pointer_return_after_unlock_still_reports_borrowed_pointer() -> None:
    code = r"""
const char* entry(Node* node) {
    LOCK(&g_lock);
    const char* value = node->value;
    UNLOCK(&g_lock);
    return value;
}
"""
    issues = RegexCandidateGenerator(configured_test_semantics()).generate_issues(
        "entry",
        code,
        "src/demo.c",
    )

    assert any(issue.get("rule") == "borrowed_pointer_returned_after_unlock" for issue in issues)


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


def test_custom_alloc_and_lock_names_require_explicit_semantics() -> None:
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
    issues = RegexCandidateGenerator().generate_issues(
        "entry",
        code,
        "src/demo.c",
    )
    classes = {str(issue["defect_class"]) for issue in issues}

    assert not {"missing_unlock", "integer_overflow", "memory_leak"}.intersection(classes)
    semantics = LocalPatternSemantics()
    for role, name in (
        ("lock", "VOS_Lock"),
        ("unlock", "VOS_Unlock"),
        ("allocator", "VOS_MemAlloc"),
    ):
        semantics.add_api(role, name, "user_config")
    configured = RegexCandidateGenerator(semantics).generate_issues("entry", code, "src/demo.c")
    assert {"missing_unlock", "integer_overflow", "memory_leak"}.issubset(
        {i["defect_class"] for i in configured}
    )


def test_regex_reasoning_is_chinese_and_evidence_backed() -> None:
    code = r"""
int entry(size_t payload_len) {
    void* response = _safe_malloc(payload_len * 2);
    return response ? 0 : -1;
}
"""
    issues = RegexCandidateGenerator(configured_test_semantics()).generate_issues(
        "entry",
        code,
        "src/demo.c",
    )
    issue = next(item for item in issues if item["defect_class"] == "integer_overflow")

    reasoning = issue["reasoning"]
    assert "Regex 本地规则" in reasoning
    assert "关键证据" in reasoning
    assert "根因" in reasoning
    assert "line 3" in reasoning
    assert "Regex candidate generated" not in reasoning
