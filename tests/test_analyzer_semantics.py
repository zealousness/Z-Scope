from zscope.core.analysis.analyzer import Analyzer
from zscope.core.candidates.regex import (
    RegexCandidateGenerator,
    LocalPatternSemantics,
)
from zscope.core.candidates.graph import FunctionView, GraphCandidateGenerator
from zscope.core.candidates.adapters import dedupe_rule_candidates
from zscope.core.candidates.backend_signals import (
    class_from_joern_category,
    split_config_pair_names,
)
from zscope.common.issue_identity import normalize_issue_category, normalize_issue_fields
from zscope.semantics.inference import add_api_from_semantic_text
from zscope.rules.engine import RuleMatch


def _graph_view(
    generator: GraphCandidateGenerator,
    name: str,
    code: str,
    *,
    signature: str | None = None,
) -> FunctionView:
    return FunctionView(
        name=name,
        file_path="src/lifecycle.c",
        signature=signature or f"int {name}(RealModelNode *node)",
        lines=tuple(generator._parse_lines(code)),
        callees=(),
    )


class NullCodeIndex:
    def get_function_impl(self, name: str, warn_missing: bool = False):
        return None


def test_snapshot_semantic_text_does_not_reclassify_described_function_as_api() -> None:
    semantics = LocalPatternSemantics()
    analyzer = object.__new__(Analyzer)
    text = """
    {
      "resources": {"locks": [{"release_line": 744}]},
      "summary": "walks a global list, acquires pipe->ctrl_lock, releases it before return",
      "cleanup_on_error": "no dynamic memory allocation; no cleanup required"
    }
    """

    add_api_from_semantic_text(
        semantics,
        "_lifecycle_tick_timer_callback",
        text,
        "semantic_snapshot",
    )

    assert "_lifecycle_tick_timer_callback" not in semantics.lock_apis
    assert "_lifecycle_tick_timer_callback" not in semantics.unlock_apis
    assert "_lifecycle_tick_timer_callback" not in semantics.deallocators


def test_facade_callee_candidates_recurse_into_internal_helpers() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False):
            impls = {
                "_outer": {
                    "file": "src/demo.c",
                    "code": "1 | int _outer(size_t n) { return _inner(n); }",
                    "callees": ["_inner"],
                },
                "_inner": {
                    "file": "src/demo.c",
                    "code": """
10 | int _inner(size_t n) {
11 |     char* p = _safe_malloc(n * 64);
12 |     return p ? 0 : -1;
13 | }
""",
                    "callees": [],
                },
            }
            return impls.get(name)

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    issues = analyzer._detect_direct_callee_rule_candidates(
        {"callees": ["_outer"]},
        RegexCandidateGenerator(),
    )

    assert any(issue.get("function") == "_inner" for issue in issues)


def test_facade_callee_candidates_expand_dispatcher_siblings_at_depth_cap() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False):
            impls = {
                "dispatch_msg": {
                    "file": "src/demo.c",
                    "code": """
1 | int dispatch_msg(int type, size_t n) {
2 |     switch (type) {
3 |     case 1: return handle_a();
4 |     case 2: return handle_b(n);
5 |     default: return handle_c();
6 |     }
7 | }
""",
                    "callees": ["handle_a", "handle_b", "handle_c"],
                },
                "handle_a": {
                    "file": "src/demo.c",
                    "code": "10 | int handle_a(void) { return 0; }",
                    "callees": [],
                },
                "handle_b": {
                    "file": "src/demo.c",
                    "code": """
20 | int handle_b(size_t n) {
21 |     char* p = _safe_malloc(n * 64);
22 |     return p ? 0 : -1;
23 | }
""",
                    "callees": [],
                },
                "handle_c": {
                    "file": "src/demo.c",
                    "code": "30 | int handle_c(void) { return 0; }",
                    "callees": [],
                },
            }
            return impls.get(name)

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    issues = analyzer._detect_direct_callee_rule_candidates(
        {"callees": ["dispatch_msg"]},
        RegexCandidateGenerator(),
        max_depth=1,
    )

    assert any(issue.get("function") == "handle_b" for issue in issues)


def test_graph_candidates_detect_free_wrapper_omitted_dynamic_payload() -> None:
    semantics = LocalPatternSemantics()
    semantics.add_api("deallocator", "SAFE_FREE", "user_config")
    generator = GraphCandidateGenerator(object(), semantics)
    creator = _graph_view(
        generator,
        "_real_model_alloc_node",
        """
10 | RealModelNode* _real_model_alloc_node(const char* key) {
11 |     RealModelNode* node = SAFE_CALLOC(1, sizeof(*node));
12 |     node->payload = _str_dup(key);
13 |     return node;
14 | }
""",
    )
    cleanup = _graph_view(
        generator,
        "_real_model_free_node",
        """
20 | void _real_model_free_node(RealModelNode* node) {
21 |     if (!node) return;
22 |     SAFE_FREE(node);
23 | }
""",
    )

    issues = generator.generate_for_views([creator, cleanup])
    leak = next(issue for issue in issues if issue["rule"] == "paired_free_wrapper_omits_dynamic_member")

    assert leak["category"] == "memory_leak"
    assert leak["function"] == "_real_model_free_node"
    assert leak["location"] == "src/lifecycle.c:22"
    assert "node->payload" in "\n".join(leak["positive_evidence"])


def test_graph_candidates_detect_helper_alloc_wrapper_member_leak_without_primitive_pair_fp() -> None:
    semantics = LocalPatternSemantics()
    semantics.add_api("deallocator", "SAFE_FREE", "user_config")
    generator = GraphCandidateGenerator(NullCodeIndex(), semantics)
    unregister = _graph_view(
        generator,
        "_real_model_unregister_file_leak",
        """
100 | int _real_model_unregister_file_leak(const char* name) {
101 |     RealModelNode* node = _real_model_alloc_node(name, "/virtual/fs/node");
102 |     SAFE_FREE(node->name);
103 |     SAFE_FREE(node);
104 |     return 0;
105 | }
""",
        signature="int _real_model_unregister_file_leak(const char* name)",
    )
    primitive_release = _graph_view(
        generator,
        "_lifecycle_release_value_slice",
        """
110 | int _lifecycle_release_value_slice(char* line) {
111 |     char* value = strchr(line, '=');
112 |     free(value + 1);
113 |     return 0;
114 | }
""",
        signature="int _lifecycle_release_value_slice(char* line)",
    )

    issues = generator.generate_for_views([unregister, primitive_release])

    leak = next(
        issue
        for issue in issues
        if issue["rule"] == "same_function_helper_alloc_wrapper_member_leak"
    )
    assert leak["category"] == "memory_leak"
    assert leak["function"] == "_real_model_unregister_file_leak"
    assert "payload/path" in leak["description"]
    assert not any(
        issue.get("rule") == "paired_free_wrapper_omits_dynamic_member"
        and issue.get("function") == "_lifecycle_release_value_slice"
        for issue in issues
    )


def test_graph_candidates_detect_paired_key_truncation_before_generic_race_terms() -> None:
    generator = GraphCandidateGenerator(object(), LocalPatternSemantics())
    lookup = _graph_view(
        generator,
        "_real_model_lookup_full_key",
        """
30 | RealModelNode* _real_model_lookup_full_key(const char* full_key) {
31 |     return strcmp(g_rules_map[i].full_key, full_key) == 0 ? g_rules_map[i].node : NULL;
32 | }
""",
    )
    insert = _graph_view(
        generator,
        "_real_model_insert_key",
        """
40 | int _real_model_insert_key(RealModelNode* node, const char* key) {
41 |     strncpy(node->key, key, REAL_KEY_LIMIT);
42 |     g_rules_map[g_rules_len++] = node;
43 |     return 0;
44 | }
""",
    )

    issues = generator.generate_for_views([lookup, insert])
    truncation = next(issue for issue in issues if issue["rule"] == "paired_full_key_lookup_truncated_insert")

    assert truncation["category"] == "key_truncation"
    assert truncation["function"] == "_real_model_insert_key"
    assert normalize_issue_category("race in rules map caused by key truncation") == "key_truncation"
    drifted = {"category": "race", "description": "full key lookup uses a truncated key after strncpy"}
    normalize_issue_fields(drifted)
    assert drifted["normalized_category"] == "key_truncation"


def test_graph_candidates_detect_self_referential_pipe_log_amplification() -> None:
    generator = GraphCandidateGenerator(object(), LocalPatternSemantics())
    close_pipe = _graph_view(
        generator,
        "_lifecycle_close_pipe",
        """
50 | int _lifecycle_close_pipe(Pipe* pipe) {
51 |     pipe->next = pipe;
52 |     return 0;
53 | }
""",
    )
    traversal = _graph_view(
        generator,
        "_lifecycle_dump_pipe_chain",
        """
60 | int _lifecycle_dump_pipe_chain(Pipe* pipe) {
61 |     while (pipe) {
62 |         LOG_ERROR("pipe state %d", pipe->state);
63 |         pipe = pipe->next;
64 |     }
65 |     return 0;
66 | }
""",
    )

    issues = generator.generate_for_views([close_pipe, traversal])
    amplification = next(
        issue
        for issue in issues
        if issue["rule"] == "paired_self_referential_traversal_log_amplification"
    )

    assert amplification["category"] == "log_amplification"
    assert amplification["function"] == "_lifecycle_dump_pipe_chain"
    assert amplification["location"] == "src/lifecycle.c:62"
    assert normalize_issue_category("busy loop from log amplification resource exhaustion") == "log_amplification"
    assert normalize_issue_category("CWE-479 signal handler shared state race") == "signal_race"
    drifted = {"category": "busy_loop", "description": "self-referential traversal causes log amplification"}
    normalize_issue_fields(drifted)
    assert drifted["normalized_category"] == "log_amplification"


def test_graph_candidates_expand_thin_runtime_fanout_at_depth_cap() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False):
            impls = {
                "api_schedule": {
                    "file": "src/lifecycle.c",
                    "code": "1 | int api_schedule(int same_core) { return runtime_cycle(same_core); }",
                    "callees": ["runtime_cycle"],
                },
                "runtime_cycle": {
                    "file": "src/lifecycle.c",
                    "code": """
10 | int runtime_cycle(int same_core) {
11 |     int rc = 0;
12 |     rc |= queue_flush(same_core);
13 |     rc |= cancel_timer();
14 |     rc |= finish_event();
15 |     return rc;
16 | }
""",
                    "callees": ["queue_flush", "cancel_timer", "finish_event"],
                },
                "queue_flush": {
                    "file": "src/lifecycle.c",
                    "code": """
20 | int queue_flush(int same_core) {
21 |     RuntimeEvent ev;
22 |     memset(&ev, 0, sizeof(ev));
23 |     if (same_core) {
24 |         ev.next = g_runtime_event_base.level_trigger_list;
25 |         g_runtime_event_base.level_trigger_list = &ev;
26 |         return 0;
27 |     }
28 |     return -1;
29 | }
""",
                    "callees": [],
                },
                "cancel_timer": {"file": "src/lifecycle.c", "code": "30 | int cancel_timer(void) { return 0; }", "callees": []},
                "finish_event": {"file": "src/lifecycle.c", "code": "40 | int finish_event(void) { return 0; }", "callees": []},
            }
            return impls.get(name)

    generator = GraphCandidateGenerator(FakeIndex(), LocalPatternSemantics())
    issues = generator.generate_for_entry(
        "api_schedule",
        FakeIndex().get_function_impl("api_schedule"),
        max_depth=1,
        max_functions=16,
    )

    assert any(issue["category"] == "lost_wakeup" and issue["function"] == "queue_flush" for issue in issues)


def test_graph_candidates_detect_protocol_contract_variants() -> None:
    generator = GraphCandidateGenerator(object(), LocalPatternSemantics())
    bitmap = _graph_view(
        generator,
        "find_bitmap_delta",
        """
10 | size_t find_bitmap_delta(const unsigned char* input, size_t len) {
11 |     uint64_t left = 0;
12 |     uint64_t right = 0;
13 |     memcpy(&left, input + 1, sizeof(left));
14 |     memcpy(&right, input + 9, sizeof(right));
15 |     uint64_t diff = left ^ right;
16 |     return (size_t)(__builtin_ctzll(diff) >> 3);
17 | }
""",
    )
    output = _graph_view(
        generator,
        "query_usage",
        """
20 | int query_usage(UseInfo* out) {
21 |     if (!out) return -1;
22 |     UseInfo tmp;
23 |     tmp.total_size = 4096;
24 |     tmp.used_size = 1024;
25 |     *out = tmp;
26 |     return 0;
27 | }
""",
    )

    issues = generator.generate_for_views([bitmap, output])
    categories = {issue["category"] for issue in issues}

    assert "byte_order_logic" in categories
    assert "uninitialized_output" in categories


def test_graph_candidates_detect_callback_self_destroy_and_role_contract() -> None:
    generator = GraphCandidateGenerator(object(), LocalPatternSemantics())
    callback = _graph_view(
        generator,
        "_completion_callback",
        """
10 | static int _completion_callback(void* arg, uint32_t* result) {
11 |     RuntimeEvent* event = (RuntimeEvent*)arg;
12 |     if (result) *result = 0;
13 |     SAFE_FREE(event);
14 |     return 0;
15 | }
""",
    )
    caller = _graph_view(
        generator,
        "finish_event",
        """
20 | int finish_event(int destroy) {
21 |     RuntimeEvent* event = (RuntimeEvent*)_safe_calloc(1, sizeof(RuntimeEvent));
22 |     event->callback_arg = event;
23 |     event->callback = destroy ? _completion_callback : NULL;
24 |     if (event->callback) {
25 |         event->callback(event->callback_arg, NULL);
26 |     }
27 |     event->running = 0;
28 |     SAFE_FREE(event);
29 |     return 0;
30 | }
""",
    )
    role_release = _graph_view(
        generator,
        "release_channel",
        """
40 | int release_channel(Node* node, int role) {
41 |     node->role = role;
42 |     service_release_by_role(node, 0);
43 |     SAFE_FREE(node);
44 |     return 0;
45 | }
""",
    )

    issues = generator.generate_for_views([caller, callback, role_release])
    categories = {issue["category"] for issue in issues}

    assert "callback_self_destroy_race" in categories
    assert any(issue["rule"] == "role_specific_release_uses_hardcoded_role" for issue in issues)


def test_graph_candidates_detect_fd_type_contract() -> None:
    generator = GraphCandidateGenerator(object(), LocalPatternSemantics())
    bridge = _graph_view(
        generator,
        "bridge_descriptor",
        """
10 | int bridge_descriptor(int reliable_fd) {
11 |     return lower_is_inter_fd(reliable_fd);
12 | }
""",
        signature="int bridge_descriptor(int reliable_fd)",
    )

    issues = generator.generate_for_views([bridge])

    assert any(issue["category"] == "fd_type_mismatch" for issue in issues)


def test_lifted_internal_sink_dedup_merges_entry_paths() -> None:
    first = {
        "candidate_id": "a",
        "function": "shared_helper",
        "location": "src/demo.c:42",
        "defect_class": "bounds",
        "rule": "clang_cfg_copy",
        "source": "len",
        "sink": "memcpy",
        "internal_sink_lifted": True,
        "entry_function": "api_a",
        "analyzed_from": "api_a",
        "call_path": ["api_a", "shared_helper"],
        "positive_evidence": ["api_a reaches shared_helper"],
        "evidence_pack": {
            "internal_sink_lifted": True,
            "sink_function": "shared_helper",
            "call_path_edges": [{"caller": "api_a", "callee": "shared_helper"}],
        },
    }
    second = {
        "candidate_id": "b",
        "function": "shared_helper",
        "location": "src/demo.c:42",
        "defect_class": "bounds",
        "rule": "clang_cfg_copy",
        "source": "len",
        "sink": "memcpy",
        "internal_sink_lifted": True,
        "entry_function": "api_b",
        "analyzed_from": "api_b",
        "call_path": ["api_b", "shared_helper"],
        "positive_evidence": ["api_b reaches shared_helper"],
        "evidence_pack": {
            "internal_sink_lifted": True,
            "sink_function": "shared_helper",
            "call_path_edges": [{"caller": "api_b", "callee": "shared_helper"}],
        },
    }

    deduped = dedupe_rule_candidates([first, second])

    assert len(deduped) == 1
    assert deduped[0]["call_paths"] == [
        ["api_a", "shared_helper"],
        ["api_b", "shared_helper"],
    ]
    assert deduped[0]["duplicate_sources"][0]["entry_function"] == "api_b"
    assert "api_b reaches shared_helper" in deduped[0]["positive_evidence"]


def test_premodel_callee_retrieval_failure_is_non_fatal() -> None:
    class FailingIndex:
        def get_callees(self, name: str, limit: int = 30):
            raise RuntimeError("bad parameter or other API misuse")

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FailingIndex()

    assert analyzer._premodel_callees(
        "entry",
        object(),
        max_depth=1,
        max_callees=5,
    ) == (0, 0, 0)


def test_premodel_callee_collection_uses_per_level_cap_and_light_impls() -> None:
    class FanoutIndex:
        def __init__(self):
            self.impl_context_flags: list[bool] = []
            self.callee_calls: list[str] = []

        def get_callees(self, name: str, limit: int = 30):
            self.callee_calls.append(name)
            graph = {
                "entry": ["a0", "a1", "a2", "a3"],
                "a0": ["b0", "b1", "b2"],
                "a1": ["b3", "b4", "b5"],
            }
            return [{"name": child} for child in graph.get(name, [])]

        def get_function_impl(
            self,
            name: str,
            warn_missing: bool = False,
            include_context: bool = True,
        ):
            self.impl_context_flags.append(include_context)
            return {
                "func_name": name,
                "file": "src/demo.c",
                "start_line": 1,
                "end_line": 4,
                "code": f"1 | int {name}(void) {{\n2 |     return 0;\n3 | }}\n",
                "callees": [],
            }

    class SnapshotStore:
        def load_snapshot(self, func: str):
            return {"func_name": func}

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FanoutIndex()
    analyzer.snapshot_store = SnapshotStore()
    analyzer._get_tools = lambda *args, **kwargs: []
    analyzer._tool_policy_for_agent = lambda *args, **kwargs: None

    modeled, skipped, tokens = analyzer._premodel_callees(
        "entry",
        object(),
        max_depth=2,
        max_callees=2,
    )

    assert (modeled, skipped, tokens) == (0, 4, 0)
    assert analyzer.code_index.callee_calls == ["entry", "a0", "a1"]
    assert analyzer.code_index.impl_context_flags == [False, False, False, False]


def test_trivial_snapshot_keeps_security_contract_points_auditable() -> None:
    cases = [
        (
            "_issue41_lax_protocol_mismatch",
            "protocol_mixup",
            """
1731 | int _issue41_lax_protocol_mismatch(int detected_protocol, int auth_level) {
1732 |     if (detected_protocol != ISSUE41_PROTOCOL_RPC) {
1733 |         if (auth_level != ISSUE41_AUTH_STRICT) {
1734 |             return 0;
1735 |         }
1736 |     }
1737 |     return 0;
1738 | }
""",
        ),
        (
            "_issue41_missing_version_filter",
            "version_filtering",
            """
1790 | int _issue41_missing_version_filter(const unsigned char* report, size_t len) {
1791 |     uint8_t version = report[0];
1792 |     uint8_t state = report[1];
1793 |     (void)version;
1794 |     return state == TASK_STATUS_FAILED ? -1 : 0;
1795 | }
""",
        ),
        (
            "_issue41_raw_fd_missing_encode",
            "fd_encoding_mismatch",
            """
1843 | int _issue41_raw_fd_missing_encode(int listen_fd, int work_fd) {
1844 |     int raw_work_fd = work_fd + 1;
1845 |     return _issue41_validate_encoded_fd(raw_work_fd);
1846 | }
""",
        ),
        (
            "_issue41_reliable_fd_to_raw_interface",
            "fd_type_mismatch",
            """
1727 | int _issue41_reliable_fd_to_raw_interface(int reliable_fd) {
1728 |     return _issue41_is_inter_fd(reliable_fd);
1729 | }
""",
        ),
        (
            "_real_model_syscall_state_not_restored",
            "state_inconsistency",
            """
1461 | int _real_model_syscall_state_not_restored(int fd) {
1462 |     int previous = g_real_registry.state;
1463 |     g_real_registry.state = fd;
1464 |     if (fcntl(fd, F_GETFD) < 0) {
1465 |         return -1;
1466 |     }
1467 |     previous = g_real_registry.state;
1468 |     return previous;
1469 | }
""",
        ),
        (
            "_real_model_protocol_length_miscalc",
            "bounds",
            """
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
""",
        ),
    ]

    for func_name, category, code in cases:
        snapshot = Analyzer._build_trivial_snapshot(
            func_name,
            {
                "file": "src/lifecycle.c",
                "start_line": 1700,
                "end_line": 1900,
                "signature": f"int {func_name}(void)",
                "code": code,
                "callees": [],
            },
            "src/lifecycle.c:1700",
        )

        assert snapshot["snapshot_kind"] == "syntactic"
        assert snapshot["is_trivial"] is True
        assert any(point["category"] == category for point in snapshot["suspicious_points"])

    assert not Analyzer._is_trivial_function(cases[-1][2], max_lines_threshold=10)


def test_trivial_snapshot_marks_facade_forwarding_as_auditable() -> None:
    snapshot = Analyzer._build_trivial_snapshot(
        "td_runtime_apply_shared_memory_event",
        {
            "file": "src/main.c",
            "start_line": 100,
            "end_line": 106,
            "signature": "int td_runtime_apply_shared_memory_event(...)",
            "code": """
100 | int td_runtime_apply_shared_memory_event(int fd, const unsigned char* wire) {
101 |     return _runtime_accept_session_frame(fd, wire);
102 | }
""",
            "callees": ["_runtime_accept_session_frame"],
        },
        "src/main.c:100",
    )

    assert any(
        point["type"] == "facade_forwarding_contract"
        and point["category"] == "entry_forwarding"
        for point in snapshot["suspicious_points"]
    )


def test_checked_allocator_wrappers_use_lightweight_snapshots() -> None:
    code = """
13 | void* _safe_malloc(size_t size) {
14 |     void* ptr = malloc(size);
15 |     if (!ptr && size > 0) {
16 |         LOG_ERROR("Memory allocation failed: %zu bytes", size);
17 |         return NULL;
18 |     }
19 |     return ptr;
20 | }
"""
    impl = {
        "file": "src/utils.c",
        "start_line": 13,
        "end_line": 20,
        "signature": "void* _safe_malloc(size_t size)",
        "code": code,
        "callees": ["malloc", "LOG_ERROR"],
    }

    assert not Analyzer._is_trivial_function(code, max_lines_threshold=10)
    assert Analyzer._is_lightweight_snapshot_candidate("_safe_malloc", impl)

    snapshot = Analyzer._build_lightweight_snapshot(
        "_safe_malloc",
        impl,
        "src/utils.c:13",
    )

    assert snapshot["snapshot_kind"] == "lightweight"
    assert snapshot["resources"]["allocation"] == "malloc"
    assert snapshot["error_handling"]["caller_obligation"]
    assert snapshot["suspicious_points"] == []


def test_validation_evidence_pack_preserves_entry_reachability_context() -> None:
    class FakeIndex:
        def get_file_snippet(self, path: str, start: int, end: int):
            return "10 | sink();"

        def get_callers(self, name: str, limit: int = 8):
            return []

        def get_callees(self, name: str, limit: int = 12):
            return []

    class FakeSnapshotStore:
        def load_snapshot(self, name: str):
            return {"summary": "internal sink"}

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    analyzer.snapshot_store = FakeSnapshotStore()
    issue = {
        "id": "RULE_1",
        "function": "_real_model_comp_destroy_detach_leak",
        "location": "src/lifecycle.c:1241",
        "category": "memory_leak",
        "entry_function": "td_run_real_cleanup_cases",
        "analyzed_from": "td_run_real_cleanup_cases",
        "reachable_from_entry": True,
        "call_path": ["td_run_real_cleanup_cases", "_real_model_comp_destroy_detach_leak"],
        "evidence_pack": {
            "path": {
                "complete_to_entry": True,
                "call_path": ["td_run_real_cleanup_cases", "_real_model_comp_destroy_detach_leak"],
            }
        },
    }
    state = {
        "entry_func": "td_run_real_cleanup_cases",
        "agent_context": {
            "func_name": "td_run_real_cleanup_cases",
            "entry_custom_prompt": "Public API declared in a header file.",
        },
    }

    pack = analyzer._build_validation_evidence_pack(issue, state, "int sink(void) { return -1; }")

    assert pack["entry_context"]["current_analysis_entry"] == "td_run_real_cleanup_cases"
    assert pack["entry_context"]["entry_exposure"] == "api"
    assert pack["entry_context"]["entry_is_external_root"] is True
    assert pack["entry_context"]["zero_callers_is_expected_for_entry"] is True
    assert "zero repository callers" in pack["entry_context"]["public_trigger"]
    assert pack["entry_context"]["reachable_from_entry"] is True
    assert pack["entry_context"]["call_path"] == [
        "td_run_real_cleanup_cases",
        "_real_model_comp_destroy_detach_leak",
    ]
    requirements = "\n".join(pack["validation_requirements"])
    assert "Do not reject an internal callee solely" in requirements
    assert "zero repository callers" in requirements
    assert "entry_is_external_root is true" in requirements
    assert "real_model" not in requirements


def test_entry_root_dead_code_rejection_is_detected() -> None:
    evidence_pack = {
        "entry_context": {
            "current_analysis_entry": "td_run_real_resource_cases",
            "entry_exposure": "api",
            "entry_is_external_root": True,
            "reachable_from_entry": True,
            "call_path": ["td_run_real_resource_cases", "_real_model_peak_stats_leak"],
        }
    }
    rejected = {
        "verdict": "rejected",
        "reasoning": "td_run_real_resource_cases没有调用者，main函数也不调用，因此是死代码。",
    }
    model_name_rejected = {
        "verdict": "rejected",
        "reasoning": "该函数属于real_model测试代码，函数名包含race，说明是故意构造的模型代码而非生产漏洞。",
    }
    guard_rejected = {
        "verdict": "rejected",
        "reasoning": "调用路径存在，但释放函数在所有失败分支都执行，因此没有泄漏。",
    }

    assert Analyzer._is_entry_root_dead_code_rejection(rejected, evidence_pack) is True
    assert Analyzer._is_entry_root_dead_code_rejection(model_name_rejected, evidence_pack) is False
    assert Analyzer._is_entry_root_dead_code_rejection(guard_rejected, evidence_pack) is False


def test_entry_root_contract_scope_rejection_is_not_rewritten() -> None:
    assert not hasattr(Analyzer, "_is_entry_root_contract_scope_rejection")


def test_validation_pack_marks_current_entry_as_reachable() -> None:
    class FakeIndex:
        def get_file_snippet(self, file_path: str, line: int, context: int = 20):
            return ""

        def get_callers(self, name: str, limit: int = 8):
            return []

        def get_callees(self, name: str, limit: int = 12):
            return []

    class FakeSnapshotStore:
        def load_snapshot(self, name: str):
            return {}

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    analyzer.snapshot_store = FakeSnapshotStore()

    pack = analyzer._build_validation_evidence_pack(
        {
            "id": "ROOT_1",
            "function": "td_run_real_resource_cases",
            "location": "src/main.c:210",
            "category": "memory_leak",
        },
        {
            "entry_func": "td_run_real_resource_cases",
            "agent_context": {
                "func_name": "td_run_real_resource_cases",
                "entry_custom_prompt": "Public API declared in a header file.",
            },
        },
        "int td_run_real_resource_cases(void) { return 0; }",
    )

    assert pack["entry_context"]["reachable_from_entry"] is True
    assert pack["entry_context"]["entry_is_external_root"] is True


def test_resolve_issue_locations_fills_observation_line_only_locations() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False):
            assert name == "_lifecycle_recv_packet"
            return {
                "file": "src/lifecycle.c",
                "start_line": 312,
                "end_line": 323,
                "code": "",
                "callees": [],
            }

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    issues = [
        {
            "function": "_lifecycle_recv_packet",
            "location": "318-322",
            "category": "memory_safety",
            "description": "褰揰net_recv_data杩斿洖-1鏃讹紝(size_t)received杞崲涓篠IZE_MAX锛屽鑷磎emcpy瓒婄晫璇诲啓",
        }
    ]

    analyzer._resolve_issue_locations(issues)

    assert issues[0]["location"] == "src/lifecycle.c:318-322"
    assert issues[0]["file"] == "src/lifecycle.c"
    assert issues[0]["line"] == 318
    assert issues[0]["start_line"] == 318
    assert issues[0]["end_line"] == 322


def test_resolve_issue_locations_recovers_observation_location_from_evidence_refs() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False):
            raise AssertionError("location should be recovered before function fallback")

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    issues = [
        {
            "function": "_issue41_missing_reference_count",
            "location": "",
            "category": "memory_safety",
            "validation_status": "uncertain",
            "evidence_pack": {
                "finding_summary": {"location": ""},
                "evidence_refs": ["candidate source at src/issue41.c:641"],
            },
        }
    ]

    analyzer._resolve_issue_locations(issues)

    assert issues[0]["location"] == "src/issue41.c:641"
    assert issues[0]["file"] == "src/issue41.c"
    assert issues[0]["line"] == 641
    assert issues[0]["start_line"] == 641


def test_validator_source_sink_contribute_to_score_components() -> None:
    class FakeUserConfig:
        def get_finding_baseline(self, _key):
            return None

    analyzer = object.__new__(Analyzer)
    analyzer.user_config = FakeUserConfig()
    issue = {
        "id": "ISSUE_1",
        "function": "_lifecycle_schedule_flush",
        "location": "src/lifecycle.c:247-260",
        "category": "stack_escape",
        "subcategory": "stack_escape",
        "confidence": 0.95,
        "rule_confidence": 0.95,
        "reasoning": "鍏ュ彛 api_send test reasoning",
        "validation_reasoning": "鍏ュ彛 api_send test reasoning",
        "source": "api_send 鍙傛暟 len",
        "positive_evidence": ["pthread_create(&tid, NULL, _flush_worker, &job)"],
    }
    validator = type(
        "FakeValidator",
        (),
        {
            "input_data": {
                "evidence_pack": {
                    "validation_requirements": ["涓枃"],
                }
            }
        },
    )()
    val_data = {
        "confidence_score": 0.95,
        "source": "FlushJob job allocated on the stack",
        "sink": "_flush_worker reads job->path after pthread_detach",
    }

    score = analyzer._score_components(issue, val_data)

    assert score["path_completeness"] == 0.75
    assert score["contract_consistency"] == 0.8
    assert score["final_score"] >= 0.8
    assert issue["reasoning"].startswith("鍏ュ彛 api_send")
    assert issue["validation_reasoning"] == issue["reasoning"]
    assert issue["source"] == "api_send 鍙傛暟 len"
    assert "涓枃" in "\n".join(validator.input_data["evidence_pack"]["validation_requirements"])


def test_validator_rejections_are_not_persisted_as_broad_baselines() -> None:
    class FakeUserConfig:
        def __init__(self):
            self.upserts = []

        def upsert_finding_baseline(self, dedup_key, status, issue):
            self.upserts.append((dedup_key, status, issue))

    analyzer = object.__new__(Analyzer)
    analyzer.user_config = FakeUserConfig()

    analyzer._remember_validation_result(
        {
            "id": "RULE_1",
            "function": "api_entry",
            "location": "src/demo.c:42",
            "category": "memory_leak",
            "dedup_key": "memory_leak|src/demo.c|42|node",
        },
        "rejected",
    )

    assert analyzer.user_config.upserts == []


def test_joern_rule_match_normalizes_to_evidence_only_candidate() -> None:
    analyzer = object.__new__(Analyzer)
    match = RuleMatch(
        rule_id="paired_SHM_FileOpen_SHM_FileClose",
        rule_name="Missing SHM_FileClose for SHM_FileOpen",
        category="resource",
        score=7.0,
        func_name="api_open",
        file_path="src/demo.c",
        line_number=42,
        code_snippet="handle = SHM_FileOpen(path);",
        evidence=[{"acquire": "SHM_FileOpen", "release": "SHM_FileClose"}],
    )

    candidate = analyzer._joern_rule_match_to_candidate(match, "entry")

    assert candidate["candidate_source"] == "joern_cpg"
    assert candidate["defect_class"] == "memory_leak"
    assert candidate["finding_kind"] == "joern_cpg_candidate"
    assert candidate["evidence_pack"]["candidate_source"] == "joern_cpg"
    assert candidate["evidence_pack"]["path"]["backend"] == "Joern CPG"
    assert "SHM_FileOpen" in "\n".join(candidate["positive_evidence"])


def test_joern_category_mapping_preserves_specific_classes() -> None:
    assert class_from_joern_category("integer_overflow") == "integer_overflow"
    assert class_from_joern_category("path_traversal") == "path_traversal"
    assert class_from_joern_category("null_pointer_dereference") == "null_pointer_dereference"
    assert class_from_joern_category("buffer_overflow") == "bounds"


def test_joern_candidate_scope_uses_entry_reachability() -> None:
    class FakeIndex:
        def get_callees(self, name: str, limit: int = 80):
            graph = {
                "entry": [{"name": "wrapper"}],
                "wrapper": [{"name": "api_open"}],
                "api_open": [],
            }
            return graph.get(name, [])

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()

    assert analyzer._match_reachable_from_entry("entry", "api_open")
    assert analyzer._match_reachable_from_entry("entry", "ns:api_open")
    assert not analyzer._match_reachable_from_entry("entry", "unrelated")


def test_clang_pair_row_normalizes_to_candidate() -> None:
    analyzer = object.__new__(Analyzer)
    row = {
        "function": "api_open",
        "file_path": "src/demo.c",
        "line": 12,
        "acquire_func": "SHM_FileOpen",
        "release_func": "SHM_FileClose",
    }

    candidate = analyzer._clang_pair_row_to_candidate(
        row,
        entry_func="entry",
        pair_source="user_config",
    )

    assert candidate["candidate_source"] == "clang_knowledgedb_call_edges"
    assert candidate["finding_kind"] == "clang_callgraph_candidate"
    assert candidate["defect_class"] == "memory_leak"
    assert candidate["evidence_pack"]["resource_pair"] == {
        "acquire": "SHM_FileOpen",
        "release": "SHM_FileClose",
        "source": "user_config",
    }
    assert "ownership transfer" in "\n".join(candidate["negative_evidence"])


def test_config_pair_names_split_csv() -> None:
    assert split_config_pair_names("CloseA, CloseB") == ["CloseA", "CloseB"]
 


