import time

from zscope.core.validation.evidence_completion import EvidenceCompletionQueue
from zscope.core.validation.proofs import deterministic_decision_proof


def test_evidence_completion_promotes_only_backend_attached_proof_once() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "category": "race",
        "validation_cluster_uid": "VAL_1",
        "evidence_completion_proofs": [
            {
                "outcome": "reject",
                "proof_kind": "lock_dominates_access",
                "producer_engine": "clang_ast_cfg",
                "fact_ids": ["cfg:1"],
                "code_hash": "code",
                "facts": ["lock_dominates_access", "all_accesses_guarded"],
                "complete": True,
            }
        ],
    }

    request = queue.complete(issue, validator_data={"verdict": "rejected"})

    assert request is not None
    assert request.missing_fact == "lock_or_happens_before"
    assert issue["evidence_completion_status"] == "completed"
    assert len(issue["deterministic_proofs"]) == 1
    assert queue.complete(issue, validator_data={"verdict": "rejected"}) is None


def test_evidence_completion_records_missing_fact_without_inventing_proof() -> None:
    queue = EvidenceCompletionQueue()
    issue = {"impact_level": "critical", "category": "bounds"}

    request = queue.complete(issue, validator_data={"verdict": "verified"})

    assert request is not None
    assert issue["evidence_completion_status"] == "exhausted"
    assert issue["evidence_completion_terminal_status"] == "exhausted"
    assert "deterministic_proofs" not in issue


def test_evidence_completion_derives_lock_proof_only_for_all_local_assignments() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "category": "unsynchronized_shared_state",
        "rule": "clang_cfg_global_state_written_with_and_without_lock",
        "resource_signature": "state.current",
    }
    evidence = {
        "function_context": {
            "code": """
LOCK(&state.lock);
state.current = event;
UNLOCK(&state.lock);
LOCK(&state.lock);
state.current = NULL;
UNLOCK(&state.lock);
"""
        }
    }

    queue.complete(
        issue,
        validator_data={"verdict": "rejected"},
        validation_evidence=evidence,
    )

    assert issue["evidence_completion_status"] == "completed"
    assert issue["deterministic_proofs"][0]["proof_kind"] == "lock_dominates_access"


def test_evidence_completion_refuses_lock_proof_when_one_write_is_unlocked() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "category": "unsynchronized_shared_state",
        "rule": "clang_cfg_global_state_written_with_and_without_lock",
        "resource_signature": "state.current",
    }
    evidence = {
        "function_context": {
            "code": """
LOCK(&state.lock);
state.current = event;
UNLOCK(&state.lock);
state.current = NULL;
"""
        }
    }

    queue.complete(
        issue,
        validator_data={"verdict": "rejected"},
        validation_evidence=evidence,
    )

    assert issue["evidence_completion_status"] == "exhausted"
    assert "deterministic_proofs" not in issue


def test_evidence_completion_derives_terminating_null_guard_proof() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "rule": "clang_cfg_allocation_result_used_without_null_check",
        "source": "task = _safe_calloc(1, sizeof(*task));",
        "sink": "task->state = READY;",
    }
    evidence = {
        "function_context": {
            "code": """
task = _safe_calloc(1, sizeof(*task));
if (!task || !frame) {
    SAFE_FREE(task);
    return NULL;
}
task->state = READY;
"""
        }
    }

    queue.complete(issue, validator_data={"verdict": "rejected"}, validation_evidence=evidence)

    assert issue["evidence_completion_status"] == "completed"
    assert issue["deterministic_proofs"][0]["proof_kind"] == "guard_dominates_sink"


def test_evidence_completion_confirms_complete_cfg_obligation_path() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {"kind": "header_length", "line": 10},
                    {"kind": "header_length_copy", "line": 14},
                ]
            },
        },
    }
    evidence = {
        "function_context": {"code": "uint32_t len = header.length;\nmemcpy(dst, src, len);"}
    }

    queue.complete(issue, validator_data={"verdict": "verified"}, validation_evidence=evidence)

    assert issue["evidence_completion_status"] == "completed"
    proof = issue["deterministic_proofs"][0]
    assert proof["outcome"] == "confirm"
    assert proof["proof_kind"] == "deterministic_cfg_obligation_path"


def test_evidence_completion_prevalidation_promotes_complete_cfg_proof() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {"kind": "header_length", "line": 10},
                    {"kind": "header_length_copy", "line": 14},
                ]
            },
        },
    }

    completed = queue.complete_prevalidation(
        issue,
        validation_evidence={"function_context": {"code": "uint32_t len;\nmemcpy(dst, src, len);"}},
    )

    assert completed is True
    assert issue["evidence_completion_terminal_status"] == "completed_with_proof"
    assert issue["deterministic_proofs"][0]["proof_kind"] == "deterministic_cfg_obligation_path"


def test_evidence_completion_uses_structured_ast_null_guard_without_source_text() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "rule": "clang_cfg_alloc_result_deref_without_null_guard",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "condition_guards": [{"line": 11, "condition": "!task || !frame"}],
                "scope_summary": {"return_lines": [12]},
                "events": [
                    {"kind": "acquire", "line": 10, "variable": "task"},
                    {"kind": "deref", "line": 14, "variable": "task"},
                ],
            },
        },
    }

    queue.complete(issue, validator_data={"verdict": "rejected"})

    proof = issue["deterministic_proofs"][0]
    assert proof["outcome"] == "reject"
    assert proof["proof_kind"] == "guard_dominates_sink"
    assert proof["code_hash"]


def test_evidence_completion_rejects_failed_fd_acquisition_branch() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "rule": "clang_cfg_fd_open_return_without_close",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "condition_guards": [{"line": 21, "condition": "fd < 0"}],
                "events": [
                    {
                        "kind": "fd_open",
                        "line": 20,
                        "variable": "fd",
                        "expression": "int fd = open(path, 0);",
                    },
                    {
                        "kind": "return_without_fd_close",
                        "line": 22,
                        "variable": "fd",
                        "expression": "return -1;",
                    },
                ],
            },
        },
    }

    queue.complete(issue, validator_data={"verdict": "rejected"})

    proof = issue["deterministic_proofs"][0]
    assert proof["outcome"] == "reject"
    assert proof["proof_kind"] == "failed_acquisition_exit"


def test_evidence_completion_confirms_rule_scoped_structured_contract() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "rule": "clang_cfg_unchecked_pointer_backtrack",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {"kind": "pointer_backtrack", "line": 10},
                    {"kind": "backtracked_pointer_sink", "line": 12},
                ]
            },
        },
    }

    queue.complete(issue, validator_data={"verdict": "verified"})

    proof = issue["deterministic_proofs"][0]
    assert proof["outcome"] == "confirm"
    assert proof["proof_kind"] == "deterministic_cfg_obligation_path"


def test_evidence_completion_confirms_ordered_publication_contract() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "rule": "published_before_member_initialization",
        "evidence_pack": {
            "path": {
                "function": "publish",
                "source_line": 10,
                "publish_line": 20,
                "late_init_line": 30,
                "complete_in_function": True,
            }
        },
    }

    queue.complete(issue, validator_data={"verdict": "verified"})

    proof = issue["deterministic_proofs"][0]
    assert proof["outcome"] == "confirm"
    assert proof["proof_kind"] == "ordered_publication_before_initialization"


def test_evidence_completion_keeps_allocator_wrapper_without_caller_taint_as_review() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "rule": "clang_cfg_external_size_allocation_without_limit",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {
                        "kind": "unbounded_allocation",
                        "line": 10,
                        "expression": "void* safe_malloc(size_t size) {",
                    }
                ]
            },
        },
    }

    queue.complete(issue, validator_data={"verdict": "rejected"})

    assert issue["evidence_completion_status"] == "exhausted"
    assert "deterministic_proofs" not in issue


def test_evidence_completion_rejects_dynamic_array_as_fixed_array() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "rule": "clang_cfg_unbounded_count_indexes_fixed_array",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "declarations": [{"name": "items", "pointer_depth": 1}],
                "events": [
                    {"kind": "fixed_array", "line": 10, "variable": "items"},
                    {"kind": "count_loop", "line": 11, "expression": "for (i = 0; i < count; ++i)"},
                    {"kind": "array_write", "line": 12, "variable": "items"},
                ],
            },
        },
    }

    queue.complete(issue, validator_data={"verdict": "rejected"})

    assert issue["deterministic_proofs"][0]["proof_kind"] == "dynamic_array_not_fixed_storage"


def test_evidence_completion_rejects_global_resource_owner_transfer() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "rule": "clang_cfg_acquire_without_release_on_exit",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {"kind": "acquire", "line": 10, "expression": "g_cache.buffer = allocate();"},
                    {"kind": "exit", "line": 12, "expression": "return 0;"},
                ]
            },
        },
    }

    queue.complete(issue, validator_data={"verdict": "rejected"})

    assert issue["deterministic_proofs"][0]["proof_kind"] == "durable_global_owner_transfer"
    proof = deterministic_decision_proof(issue, outcome="reject")
    assert proof is not None
    assert proof.proof_kind == "durable_global_owner_transfer"


def test_evidence_completion_proofs_route_all_structured_transfer_and_graph_contracts() -> None:
    queue = EvidenceCompletionQueue()
    fd_issue = {
        "impact_level": "high",
        "rule": "clang_cfg_fd_open_return_without_close",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {
                        "kind": "fd_open",
                        "line": 10,
                        "variable": "fd",
                        "expression": "int fd = open(path, 0);",
                    },
                    {
                        "kind": "return_without_fd_close",
                        "line": 12,
                        "variable": "fd",
                        "expression": "return fd;",
                    },
                ]
            },
        },
    }
    queue.complete(fd_issue, validator_data={"verdict": "rejected"})
    assert deterministic_decision_proof(fd_issue, outcome="reject") is not None

    graph_issue = {
        "impact_level": "high",
        "rule": "published_before_member_initialization",
        "evidence_pack": {
            "path": {
                "function": "publish",
                "source_line": 10,
                "publish_line": 20,
                "late_init_line": 30,
                "complete_in_function": True,
            }
        },
    }
    queue.complete(graph_issue, validator_data={"verdict": "verified"})
    assert deterministic_decision_proof(graph_issue, outcome="confirm") is not None


def test_evidence_completion_rejects_matched_unlock_on_complete_local_path() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "rule": "clang_cfg_unlock_without_matching_lock",
        "evidence_pack": {"path": {"complete_in_function": True}},
    }
    evidence = {
        "function_context": {
            "code": """
void tick(void) {
    LOCK(&state.lock);
    update();
    UNLOCK(&state.lock);
}
"""
        }
    }

    queue.complete(issue, validator_data={"verdict": "rejected"}, validation_evidence=evidence)

    proof = deterministic_decision_proof(issue, outcome="reject")
    assert proof is not None
    assert proof.proof_kind == "matching_lock_dominates_unlock"


def test_evidence_completion_confirms_failure_return_while_lock_is_held() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "critical",
        "rule": "clang_cfg_return_with_lock_held",
        "evidence_pack": {"path": {"complete_in_function": True}},
    }
    evidence = {
        "function_context": {
            "code": """
int link(void) {
    LOCK(&state.lock);
    void *node = allocate();
    if (!node) {
        return -1;
    }
    UNLOCK(&state.lock);
    return 0;
}
"""
        }
    }

    queue.complete(issue, validator_data={"verdict": "verified"}, validation_evidence=evidence)

    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.proof_kind == "lock_held_on_failure_return"


def test_evidence_completion_rejects_parent_cleanup_when_member_acquisition_failed() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "rule": "clang_cfg_parent_release_without_owned_member_cleanup",
        "source": "proc->name = duplicate(input);",
        "sink": "SAFE_FREE(proc);",
        "evidence_pack": {"path": {"complete_in_function": True}},
    }
    evidence = {
        "function_context": {
            "code": """
int attach(void) {
    proc->name = duplicate(input);
    if (!proc->name) {
        SAFE_FREE(proc);
        return -1;
    }
    return 0;
}
"""
        }
    }

    queue.complete(issue, validator_data={"verdict": "rejected"}, validation_evidence=evidence)

    proof = deterministic_decision_proof(issue, outcome="reject")
    assert proof is not None
    assert proof.proof_kind == "failed_member_acquisition_cleanup"


def test_evidence_completion_confirms_detached_stack_thread_argument() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "category": "stack_escape",
        "rule": "clang_cfg_stack_address_passed_to_thread",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {"kind": "stack_object", "line": 2, "variable": "job"},
                    {"kind": "thread_arg_escape", "line": 3, "variable": "job"},
                ]
            },
        },
    }
    evidence = {
        "function_context": {
            "code": """
void start(void) {
    Job job;
    pthread_create(&tid, NULL, worker, &job);
    pthread_detach(tid);
}
"""
        }
    }

    queue.complete(issue, validator_data={"verdict": "verified"}, validation_evidence=evidence)

    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.proof_kind == "async_stack_address_escape"


def test_evidence_completion_confirms_field_sensitive_incomplete_cleanup() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "category": "incomplete_cleanup",
        "evidence_pack": {"path": {"complete_in_function": True}},
    }
    evidence = {
        "function_context": {
            "code": """
void reset(Cache *cache) {
    cache->primary = duplicate(name);
    cache->scratch = duplicate(name);
    SAFE_FREE(cache->primary);
}
"""
        }
    }

    queue.complete(issue, validator_data={"verdict": "verified"}, validation_evidence=evidence)

    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.proof_kind == "incomplete_owner_cleanup"


def test_evidence_completion_does_not_reject_when_validator_reports_blocking_counterfact() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "rule": "clang_cfg_unlock_without_matching_lock",
        "blocking_negative_evidence": True,
        "evidence_pack": {"path": {"complete_in_function": True}},
    }
    evidence = {"function_context": {"code": "LOCK(&lock);\nUNLOCK(&lock);"}}

    queue.complete(issue, validator_data={"verdict": "rejected"}, validation_evidence=evidence)

    assert issue["evidence_completion_status"] == "exhausted"
    assert deterministic_decision_proof(issue, outcome="reject") is None


def test_evidence_completion_confirms_owned_member_left_live_when_parent_freed() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "rule": "clang_cfg_parent_release_without_owned_member_cleanup",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [{"kind": "owned_member_leak", "line": 8, "variable": "node->children"}]
            },
        },
    }
    evidence = {
        "function_context": {"code": "node->children = service_alloc_child();\nSAFE_FREE(node);"}
    }

    queue.complete(issue, validator_data={"verdict": "uncertain"}, validation_evidence=evidence)

    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.proof_kind == "owned_member_left_live_when_parent_released"


def test_evidence_completion_keeps_parent_release_as_review_without_member_acquisition() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "rule": "clang_cfg_parent_release_without_owned_member_cleanup",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [{"kind": "owned_member_leak", "line": 7, "variable": "node->children"}]
            },
        },
    }
    evidence = {"function_context": {"code": "SAFE_FREE(node);"}}

    queue.complete(issue, validator_data={"verdict": "uncertain"}, validation_evidence=evidence)

    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_v12_confirms_external_value_reaching_real_allocation_sink() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "function": "reserve",
        "evidence_pack": {
            "path": {
                "function": "reserve",
                "complete_in_function": True,
                "complete_to_entry": True,
                "call_edges": [
                    {
                        "caller": "entry",
                        "callee": "reserve",
                        "call_line": 7,
                        "parameter_mapping": [
                            {
                                "formal": "length",
                                "actual": "wire_len",
                                "source_parameter": "wire_len",
                            }
                        ],
                        "guard_summary": {"caller_side": {"checks": []}},
                    }
                ],
            },
            "ast_cfg": {
                "events": [
                    {
                        "kind": "unbounded_allocation",
                        "line": 11,
                        "variable": "length",
                        "expression": "return allocate(length);",
                    }
                ]
            },
        },
    }

    queue.complete_prevalidation(
        issue,
        validation_evidence={
            "function_context": {
                "code": "void *reserve(size_t length) { return allocate(length); }"
            }
        },
    )

    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.proof_kind == "external_value_controls_unbounded_allocation"


def test_v12_does_not_confirm_allocator_declaration_as_allocation_sink() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "function": "allocate",
        "evidence_pack": {
            "path": {
                "function": "allocate",
                "complete_in_function": True,
                "complete_to_entry": True,
                "call_edges": [
                    {
                        "caller": "entry",
                        "callee": "allocate",
                        "parameter_mapping": [
                            {
                                "formal": "length",
                                "actual": "wire_len",
                                "source_parameter": "wire_len",
                            }
                        ],
                    }
                ],
            },
            "ast_cfg": {
                "events": [
                    {
                        "kind": "unbounded_allocation",
                        "line": 10,
                        "variable": "size_t length",
                        "expression": "void *allocate(size_t length) {",
                    }
                ]
            },
        },
    }

    assert queue.complete_prevalidation(issue) is False
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_v12_confirms_unchecked_allocation_arithmetic() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {
                        "kind": "integer_size_arithmetic",
                        "line": 20,
                        "expression": "void *p = allocate(request->count * sizeof(Item));",
                    }
                ]
            },
        }
    }

    queue.complete_prevalidation(issue)

    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.proof_kind == "allocation_arithmetic_overflow_reaches_sink"


def test_v12_confirms_scanned_entry_parameter_reaching_system_sink() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "function": "execute_task",
        "entry_identity": "src/api.c::int execute_task(const char *command)",
        "rule": "clang_cfg_system_with_nonliteral_command",
        "evidence_pack": {
            "path": {
                "function": "execute_task",
                "complete_in_function": True,
                "complete_to_entry": True,
            },
            "ast_cfg": {
                "condition_guards": [{"line": 5, "condition": "!command"}],
                "events": [
                    {
                        "kind": "system_call",
                        "line": 8,
                        "variable": "command",
                        "api": "system",
                        "expression": "return system(command);",
                    }
                ],
            },
        },
    }

    assert queue.complete_prevalidation(
        issue,
        validation_evidence={
            "function_context": {
                "code": "int execute_task(const char *command) { return system(command); }"
            }
        },
    )

    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.proof_kind == "entry_parameter_reaches_system_sink"


def test_v12_does_not_confirm_local_command_buffer_as_external_source() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "function": "execute_task",
        "entry_identity": "src/api.c::int execute_task(const char *name)",
        "rule": "clang_cfg_system_with_nonliteral_command",
        "evidence_pack": {
            "path": {
                "function": "execute_task",
                "complete_in_function": True,
                "complete_to_entry": True,
            },
            "ast_cfg": {
                "events": [
                    {
                        "kind": "system_call",
                        "line": 8,
                        "variable": "command",
                        "api": "system",
                        "expression": "return system(command);",
                    }
                ]
            },
        },
    }

    assert not queue.complete_prevalidation(
        issue,
        validation_evidence={
            "function_context": {
                "code": 'int execute_task(const char *name) { char command[32] = "true"; return system(command); }'
            }
        },
    )
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_v12_does_not_confirm_system_sink_with_structured_sanitizer() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "function": "execute_task",
        "entry_identity": "src/api.c::int execute_task(const char *command)",
        "rule": "clang_cfg_system_with_nonliteral_command",
        "evidence_pack": {
            "path": {
                "function": "execute_task",
                "complete_in_function": True,
                "complete_to_entry": True,
            },
            "ast_cfg": {
                "events": [
                    {"kind": "command_sanitizer", "line": 7, "variable": "command"},
                    {
                        "kind": "system_call",
                        "line": 8,
                        "variable": "command",
                        "api": "system",
                        "expression": "return system(command);",
                    },
                ]
            },
        },
    }

    assert not queue.complete_prevalidation(
        issue,
        validation_evidence={
            "function_context": {
                "code": "int execute_task(const char *command) { return system(command); }"
            }
        },
    )
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_v12_confirms_entry_supplied_callback_invoked_under_lock() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "function": "notify_listener",
        "rule": "clang_cfg_callback_while_lock_held",
        "code_snippet": "\n".join(
            [
                "10 | LOCK(&registry.lock);",
                "11 | callback_slot = cb;",
                "12 | callback_slot(node);",
                "13 | UNLOCK(&registry.lock);",
            ]
        ),
        "evidence_pack": {
            "path": {
                "function": "notify_listener",
                "complete_in_function": True,
                "complete_to_entry": True,
                "call_edges": [
                    {
                        "caller": "public_entry",
                        "callee": "notify_listener",
                        "call_line": 40,
                        "parameter_mapping": [
                            {
                                "formal": "cb",
                                "actual": "cb",
                                "source_parameter": "cb",
                            }
                        ],
                    }
                ],
            },
            "ast_cfg": {
                "events": [
                    {
                        "kind": "lock",
                        "line": 10,
                        "expression": "LOCK(&registry.lock);",
                    },
                    {
                        "kind": "callback_call",
                        "line": 12,
                        "expression": "callback_slot(node);",
                    },
                ]
            },
        },
    }

    assert queue.complete_prevalidation(issue)

    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.proof_kind == "external_callback_invoked_under_lock"
    assert "call_edge:public_entry->notify_listener:40" in proof.fact_ids


def test_v12_does_not_confirm_stored_callback_without_entry_parameter_assignment() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "function": "notify_listener",
        "rule": "clang_cfg_callback_while_lock_held",
        "code_snippet": "\n".join(
            [
                "10 | LOCK(&registry.lock);",
                "12 | callback_slot(node);",
                "13 | UNLOCK(&registry.lock);",
            ]
        ),
        "evidence_pack": {
            "path": {
                "function": "notify_listener",
                "complete_in_function": True,
                "complete_to_entry": True,
                "call_edges": [
                    {
                        "caller": "public_entry",
                        "callee": "notify_listener",
                        "call_line": 40,
                        "parameter_mapping": [],
                    }
                ],
            },
            "ast_cfg": {
                "events": [
                    {
                        "kind": "lock",
                        "line": 10,
                        "expression": "LOCK(&registry.lock);",
                    },
                    {
                        "kind": "callback_call",
                        "line": 12,
                        "expression": "callback_slot(node);",
                    },
                ]
            },
        },
    }

    assert not queue.complete_prevalidation(issue)
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_v12_does_not_confirm_callback_when_matching_unlock_is_absent() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "function": "notify_listener",
        "rule": "clang_cfg_callback_while_lock_held",
        "code_snippet": "\n".join(
            [
                "10 | LOCK(&registry.lock);",
                "11 | callback_slot = cb;",
                "12 | callback_slot(node);",
                "13 | UNLOCK(&other.lock);",
            ]
        ),
        "evidence_pack": {
            "path": {
                "function": "notify_listener",
                "complete_in_function": True,
                "complete_to_entry": True,
                "call_edges": [
                    {
                        "caller": "public_entry",
                        "callee": "notify_listener",
                        "call_line": 40,
                        "parameter_mapping": [
                            {
                                "formal": "cb",
                                "actual": "cb",
                                "source_parameter": "cb",
                            }
                        ],
                    }
                ],
            },
            "ast_cfg": {
                "events": [
                    {
                        "kind": "lock",
                        "line": 10,
                        "expression": "LOCK(&registry.lock);",
                    },
                    {
                        "kind": "callback_call",
                        "line": 12,
                        "expression": "callback_slot(node);",
                    },
                ]
            },
        },
    }

    assert not queue.complete_prevalidation(issue)
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_v12_signal_proof_requires_structured_signal_root_and_unsafe_call() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "line": 30,
        "defect_class": "signal_deadlock",
        "call_paths": [["src/main.c::void dispatch(int signal, void *ucontext)"]],
        "security_obligation": {"subject_uid": "signal-state"},
    }
    evidence = {"function_context": {"code": 'snprintf(buffer, sizeof(buffer), "%d", signal);'}}

    queue.complete_prevalidation(issue, validation_evidence=evidence)

    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.proof_kind == "registered_signal_path_calls_unsafe_operation"


def test_v12_signal_proof_recovers_traceable_line_from_location() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "location": "src/runtime.c:2765",
        "defect_class": "signal_deadlock",
        "call_paths": [["src/main.c::void dispatch(int signal, void *ucontext)"]],
        "security_obligation": {"subject_uid": "signal-state"},
    }
    evidence = {"function_context": {"code": 'snprintf(buffer, sizeof(buffer), "%d", signal);'}}

    assert queue.complete_prevalidation(issue, validation_evidence=evidence)

    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.fact_ids == ("source_cfg:2765",)
    assert proof.cfg_nodes == ("2765",)


def test_v12_self_link_requires_traversal_without_cycle_guard() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {"line": 8, "defect_class": "infinite_loop"}
    evidence = {
        "function_context": {"code": "while (node) { node = node->next; }\nnode->next = node;"}
    }

    queue.complete_prevalidation(issue, validation_evidence=evidence)

    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.proof_kind == "reachable_self_link_without_cycle_guard"


def test_v12_self_link_does_not_prove_unrelated_deadlock_candidate() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {"location": "src/list.c:8", "defect_class": "deadlock"}
    evidence = {
        "function_context": {"code": "while (node) { node = node->next; }\nnode->next = node;"}
    }

    assert queue.complete_prevalidation(issue, validation_evidence=evidence) is False
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_untraceable_provider_record_does_not_close_completion_as_proved() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "evidence_completion_proofs": [
            {
                "outcome": "confirm",
                "proof_kind": "registered_signal_path_calls_unsafe_operation",
                "producer_engine": "project_call_contract_signal_v12",
                "proof_version": "zscope.decision-proof.v4",
                "fact_ids": [],
                "cfg_nodes": [],
                "code_hash": "body-v1",
                "facts": [
                    "signal_context_reachable",
                    "async_signal_unsafe_operation",
                ],
                "completeness": "complete",
            }
        ]
    }

    assert queue.complete_prevalidation(issue) is False
    assert issue["prevalidation_fact_completion"] == "not_applicable"
    assert issue.get("evidence_completion_status") != "completed"


def test_traceable_provider_replaces_same_kind_untraceable_replay_record() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "location": "src/runtime.c:2765",
        "defect_class": "signal_deadlock",
        "call_paths": [["src/main.c::void dispatch(int signal, void *ucontext)"]],
        "security_obligation": {"subject_uid": "signal-state"},
        "deterministic_proofs": [
            {
                "outcome": "confirm",
                "proof_kind": "registered_signal_path_calls_unsafe_operation",
                "producer_engine": "project_call_contract_signal_v12",
                "proof_version": "zscope.decision-proof.v4",
                "fact_ids": [],
                "cfg_nodes": [],
                "code_hash": "body-v1",
                "facts": [
                    "signal_context_reachable",
                    "async_signal_unsafe_operation",
                ],
                "completeness": "complete",
            }
        ],
    }
    evidence = {"function_context": {"code": 'snprintf(buffer, sizeof(buffer), "%d", signal);'}}

    assert queue.complete_prevalidation(issue, validation_evidence=evidence)

    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.fact_ids == ("source_cfg:2765",)


def test_v12_rejects_allocation_only_when_every_caller_is_bounded() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "function": "reserve",
        "evidence_pack": {
            "path": {
                "function": "reserve",
                "complete_in_function": True,
                "complete_to_entry": True,
                "call_edges": [
                    {
                        "caller": "entry",
                        "callee": "reserve",
                        "parameter_mapping": [{"formal": "length", "actual": "length"}],
                        "guard_summary": {
                            "caller_side": {
                                "checks": [{"text": "if (length > MAX_LENGTH) return -1;"}]
                            }
                        },
                    }
                ],
            },
            "ast_cfg": {
                "events": [
                    {
                        "kind": "unbounded_allocation",
                        "line": 11,
                        "variable": "length",
                        "expression": "return allocate(length);",
                    }
                ]
            },
        },
    }

    queue.complete_prevalidation(issue)

    assert deterministic_decision_proof(issue, outcome="confirm") is None
    proof = deterministic_decision_proof(issue, outcome="reject")
    assert proof is not None
    assert proof.proof_kind == "all_reachable_callers_bound_allocation"


def test_v12_single_access_needs_project_complete_access_set() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [{"kind": "shared_state_access", "line": 5, "variable": "global_state"}]
            },
            "concurrency": {},
        }
    }

    assert queue.complete_prevalidation(issue) is False
    assert deterministic_decision_proof(issue, outcome="reject") is None


def test_v12_rejects_copy_when_exact_allocation_length_matches() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "rule": "clang_cfg_narrowed_allocation_original_length_copy",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {
                        "kind": "narrowed_heap_allocation",
                        "line": 10,
                        "variable": "buffer",
                        "api": "payload_len",
                        "expression": "void *buffer = allocate(payload_len);",
                    },
                    {
                        "kind": "original_length_heap_copy",
                        "line": 12,
                        "variable": "buffer",
                        "api": "payload_len",
                        "expression": "memcpy(buffer, payload, payload_len);",
                    },
                ]
            },
        },
    }

    assert queue.complete_prevalidation(issue)
    proof = deterministic_decision_proof(issue, outcome="reject")
    assert proof is not None
    assert proof.proof_kind == "exact_allocation_length_covers_copy"


def test_v12_does_not_equate_different_allocation_and_copy_lengths() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "rule": "clang_cfg_narrowed_allocation_original_length_copy",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {
                        "kind": "narrowed_heap_allocation",
                        "line": 10,
                        "variable": "buffer",
                        "api": "payload_len - 1",
                    },
                    {
                        "kind": "original_length_heap_copy",
                        "line": 12,
                        "variable": "buffer",
                        "api": "payload_len",
                    },
                ]
            },
        },
    }

    assert queue.complete_prevalidation(issue) is False
    assert deterministic_decision_proof(issue, outcome="reject") is None


def test_v12_rejects_reported_leak_when_same_resource_is_released_before_exit() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "rule": "clang_cfg_acquire_without_release_on_exit",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {
                        "kind": "acquire",
                        "line": 20,
                        "variable": "owner.items",
                        "expression": "owner->items = allocate(count);",
                    },
                    {"kind": "exit", "line": 23, "expression": "return NULL;"},
                ]
            },
        },
    }
    evidence = {
        "function_context": {
            "code": """void *build(Owner *owner) {
owner->items = allocate(count);
if (!initialize(owner->items)) {
    SAFE_FREE(owner->items);
    return NULL;
}
return owner;
}"""
        }
    }

    assert queue.complete_prevalidation(issue, validation_evidence=evidence)
    proof = deterministic_decision_proof(issue, outcome="reject")
    assert proof is not None
    assert proof.proof_kind == "matching_release_precedes_reported_exit"


def test_v12_does_not_apply_release_proof_to_different_field() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "rule": "clang_cfg_acquire_without_release_on_exit",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {
                        "kind": "acquire",
                        "line": 20,
                        "expression": "owner->items = allocate(count);",
                    },
                    {"kind": "exit", "line": 22, "expression": "return NULL;"},
                ]
            },
        },
    }
    evidence = {
        "function_context": {
            "code": "owner->items = allocate(count);\nSAFE_FREE(owner->backup);\nreturn NULL;"
        }
    }

    assert queue.complete_prevalidation(issue, validation_evidence=evidence) is False


def test_v12_release_after_reported_early_exit_is_not_a_rejection_proof() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "rule": "clang_cfg_acquire_without_release_on_exit",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {
                        "kind": "acquire",
                        "line": 100,
                        "expression": "info->reserved = allocate(size);",
                    },
                    {"kind": "exit", "line": 102, "expression": "return 0;"},
                ]
            },
        },
    }
    evidence = {
        "function_context": {
            "code": """info->reserved = allocate(size);
if (!ready) {
    return 0;
}
SAFE_FREE(info->reserved);
return 0;"""
        }
    }

    assert queue.complete_prevalidation(issue, validation_evidence=evidence) is False
    assert deterministic_decision_proof(issue, outcome="reject") is None


def test_v12_release_in_sibling_branch_does_not_prove_later_exit_safe() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "rule": "clang_cfg_acquire_without_release_on_exit",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {
                        "kind": "acquire",
                        "line": 40,
                        "expression": "node = allocate();",
                    },
                    {"kind": "exit", "line": 46, "expression": "return 0;"},
                ]
            },
        },
    }
    evidence = {
        "function_context": {
            "code": """node = allocate();
if (failed) {
    free(node);
    return -1;
}
publish(node);
return 0;"""
        }
    }

    assert queue.complete_prevalidation(issue, validation_evidence=evidence) is False
    assert deterministic_decision_proof(issue, outcome="reject") is None


def test_v12_rejects_parent_cleanup_when_member_acquisition_failed() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "line": 8,
        "rule": "clang_cfg_parent_release_without_owned_member_cleanup",
        "sink": "free(task);",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {"events": [{"kind": "owned_member_leak", "line": 8}]},
        },
    }
    evidence = {
        "function_context": {
            "code": """Task *task = calloc(1, sizeof(*task));
task->payload.command = duplicate(text);
if (!task->payload.command) {
    free(task);
    return NULL;
}
return task;"""
        }
    }

    assert queue.complete_prevalidation(issue, validation_evidence=evidence)
    proof = deterministic_decision_proof(issue, outcome="reject")
    assert proof is not None
    assert proof.proof_kind == "zero_initialized_member_failed_before_parent_release"


def test_v12_rejects_leak_when_resource_moves_to_caller_owned_field() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "rule": "clang_cfg_acquire_without_release_on_exit",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {
                        "kind": "acquire",
                        "line": 17,
                        "expression": "registry->plugins = allocate(capacity);",
                    },
                    {"kind": "exit", "line": 29, "expression": "return 0;"},
                ]
            },
        },
    }
    evidence = {
        "function_context": {
            "code": "int init(Registry *registry, size_t capacity) {\n"
            "registry->plugins = allocate(capacity);\nreturn 0;\n}"
        }
    }

    assert queue.complete_prevalidation(issue, validation_evidence=evidence)
    proof = deterministic_decision_proof(issue, outcome="reject")
    assert proof is not None
    assert proof.proof_kind == "caller_owned_field_transfer"


def test_v12_does_not_treat_local_owner_field_as_caller_transfer() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "rule": "clang_cfg_acquire_without_release_on_exit",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {"kind": "acquire", "line": 2, "expression": "local.plugins = allocate(2);"},
                    {"kind": "exit", "line": 3, "expression": "return 0;"},
                ]
            },
        },
    }
    evidence = {
        "function_context": {"code": "int init(void) { local.plugins = allocate(2); return 0; }"}
    }

    assert queue.complete_prevalidation(issue, validation_evidence=evidence) is False


def test_v12_propagates_terminating_bound_to_derived_allocation_size() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=True)
    issue = {
        "rule": "clang_cfg_external_size_allocation_without_limit",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {
                "condition_guards": [{"line": 4, "condition": "cmd_len > MAX_COMMAND_LEN"}],
                "scope_summary": {"return_lines": [5]},
                "events": [
                    {
                        "kind": "unbounded_allocation",
                        "line": 9,
                        "variable": "total_len",
                        "expression": "void *buffer = allocate(total_len);",
                    }
                ],
            },
        },
    }
    evidence = {
        "function_context": {
            "code": """size_t cmd_len = strlen(command);
if (cmd_len > MAX_COMMAND_LEN) {
    return -1;
}
size_t total_len = sizeof(Header) + cmd_len + 1;
void *buffer = allocate(total_len);"""
        }
    }

    assert queue.complete_prevalidation(issue, validation_evidence=evidence)
    proof = deterministic_decision_proof(issue, outcome="reject")
    assert proof is not None
    assert proof.proof_kind == "terminating_allocation_upper_bound"


def test_failed_fd_acquisition_guard_can_span_nested_diagnostic_branch() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "rule": "clang_cfg_fd_open_return_without_close",
        "evidence_pack": {
            "path": {
                "complete_in_function": True,
                "path_constraints": ["line 56: if (client_fd < 0) {"],
            },
            "ast_cfg": {
                "condition_guards": [
                    {"line": 56, "condition": "client_fd < 0"},
                    {"line": 57, "condition": "errno != EAGAIN"},
                ],
                "events": [
                    {
                        "kind": "fd_open",
                        "line": 55,
                        "variable": "client_fd",
                        "expression": "int client_fd = accept(server_fd, 0, 0);",
                    },
                    {
                        "kind": "return_without_fd_close",
                        "line": 60,
                        "variable": "client_fd",
                        "expression": "return -1;",
                    },
                ],
            },
        },
    }

    assert queue.complete_prevalidation(issue)
    proof = deterministic_decision_proof(issue, outcome="reject")
    assert proof is not None
    assert proof.proof_kind == "failed_acquisition_exit"


def test_requested_fact_resolution_dispatches_only_named_fact_kind(monkeypatch) -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=False)
    calls = []

    monkeypatch.setattr(
        queue,
        "_allocation_context_proof",
        lambda issue: calls.append("value_range") or None,
    )
    monkeypatch.setattr(
        queue,
        "_guard_dominance_proof",
        lambda issue, evidence: calls.append("guard") or None,
    )
    issue = {"validation_cluster_uid": "VAL_TYPED"}

    resolution = queue.resolve_requested_fact(
        issue,
        validator_data={
            "verdict": "uncertain",
            "missing_fact_request": {
                "fact_kind": "value_range",
                "subject_uid": "length",
                "reason": "need the exact bound",
            },
        },
    )

    assert resolution is not None
    assert resolution.status == "exhausted"
    assert "value_range" in calls
    assert "guard" not in calls


def test_requested_fact_resolution_rejects_duplicate_request() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=False)
    issue = {
        "validation_cluster_uid": "VAL_TYPED",
        "fact_completion_by_kind": {
            "caller_contract": [{"fact_uid": "FACT_CONTRACT", "value": "non-null"}]
        },
    }
    validator_data = {
        "verdict": "uncertain",
        "missing_fact_request": {
            "fact_kind": "caller_contract",
            "subject_uid": "callee",
            "reason": "need the contract",
        },
    }

    first = queue.resolve_requested_fact(issue, validator_data=validator_data)
    second = queue.resolve_requested_fact(issue, validator_data=validator_data)

    assert first is not None and first.status == "completed_partial"
    assert first.evidence_delta_hash
    assert second is not None and second.status == "duplicate_request"


def test_requested_fact_resolution_rejects_forged_fact_uid() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=False)
    issue = {
        "validation_cluster_uid": "VAL_TYPED",
        "fact_completion_by_kind": {
            "caller_contract": [{"fact_uid": "FACT_FORGED", "value": "non-null"}]
        },
    }
    resolution = queue.resolve_requested_fact(
        issue,
        validator_data={
            "verdict": "uncertain",
            "missing_fact_request": {
                "fact_kind": "caller_contract",
                "reason": "need the contract",
            },
        },
        validation_evidence={"evidence_ref_catalog": {"FACT_REAL": {"kind": "fact"}}},
    )

    assert resolution is not None
    assert resolution.status == "unsupported"
    assert issue["validator_missing_fact_request_rejected"] == "unknown_fact_uid"
    assert issue["rejected_fact_uids"] == ["FACT_FORGED"]


def test_requested_fact_resolution_times_out_provider(monkeypatch) -> None:
    queue = EvidenceCompletionQueue(
        enable_v12_providers=False,
        fact_timeout_seconds=0.01,
    )

    def slow_provider(*_args):
        time.sleep(0.05)
        return []

    monkeypatch.setattr(queue, "_requested_completion_proofs", slow_provider)
    issue = {"validation_cluster_uid": "VAL_TIMEOUT"}

    resolution = queue.resolve_requested_fact(
        issue,
        validator_data={
            "verdict": "uncertain",
            "missing_fact_request": {
                "fact_kind": "value_range",
                "reason": "need an exact range",
            },
        },
    )

    assert resolution is not None
    assert resolution.status == "timeout"
    assert issue["evidence_completion_terminal_status"] == "timeout"
    assert issue["evidence_completion_error"] == "fact provider timed out"


def test_requested_fact_resolution_contains_provider_exception(monkeypatch) -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=False)

    def broken_provider(*_args):
        raise RuntimeError("backend unavailable")

    monkeypatch.setattr(queue, "_requested_completion_proofs", broken_provider)
    issue = {"validation_cluster_uid": "VAL_ERROR"}

    resolution = queue.resolve_requested_fact(
        issue,
        validator_data={
            "verdict": "uncertain",
            "missing_fact_request": {
                "fact_kind": "value_range",
                "reason": "need an exact range",
            },
        },
    )

    assert resolution is not None
    assert resolution.status == "provider_error"
    assert issue["evidence_completion_terminal_status"] == "provider_error"
    assert issue["evidence_completion_error"] == "RuntimeError: backend unavailable"


def test_required_fact_resolution_closes_all_obligation_kinds_before_v2() -> None:
    queue = EvidenceCompletionQueue(enable_v12_providers=False)
    issue = {
        "validation_cluster_uid": "VAL_MULTI_FACT",
        "function": "publish_state",
        "file": "src/state.c",
        "line": 42,
        "dependency_code_hash": "code-sha",
        "security_obligation": {
            "obligation_uid": "OBL_SHARED_STATE",
            "subject_uid": "state.current",
            "required_fact_kinds": ["lockset", "happens_before", "caller_contract"],
        },
        # The model only noticed one gap. The obligation still requires all three.
        "missing_fact_kinds": ["lockset"],
        "decision_fact_slice": {
            "fact_uids": [],
            "dependency_code_hashes": [],
            "missing_fact_kinds": ["lockset", "happens_before", "caller_contract"],
            "coverage": "partial",
        },
        "fact_completion_by_kind": {
            "lockset": [{"value": "state.lock held at write"}],
            "happens_before": [{"value": "unlock synchronizes with reader lock"}],
            "caller_contract": [{"value": "public caller may publish concurrently"}],
        },
    }

    batch = queue.resolve_required_facts(
        issue,
        validator_data={
            "verdict": "uncertain",
            "missing_fact_request": {
                "fact_kind": "lockset",
                "subject_uid": "state.current",
                "function_uid": "publish_state",
                "reason": "need the write lockset",
            },
        },
    )

    assert [value.fact_kind for value in batch.resolutions] == [
        "lockset",
        "happens_before",
        "caller_contract",
    ]
    assert batch.evidence_delta["fact_kinds"] == [
        "caller_contract",
        "happens_before",
        "lockset",
    ]
    assert len(batch.evidence_delta["facts"]) == 3
    for fact in batch.evidence_delta["facts"]:
        assert fact["fact_uid"].startswith("FACT_LOCAL_")
        assert fact["producer_engine"] == "local_deterministic_fact_provider"
        assert fact["dependency_code_hash"] == "code-sha"
        assert fact["evidence_ref"] == fact["fact_uid"]
        assert fact["location"] == {
            "file": "src/state.c",
            "function": "publish_state",
            "line": 42,
        }
    assert issue["decision_fact_coverage"] == "complete"
    assert issue["missing_fact_kinds"] == []
    assert issue["candidate_promotion_eligible"] is True
    assert len(issue["decision_fact_slice"]["facts"]) == 3


def test_completed_local_fact_normalizes_event_alias_in_decision_slice() -> None:
    issue = {
        "missing_fact_kinds": ["event:acquire", "ownership_transfer"],
        "decision_fact_slice": {
            "fact_uids": [],
            "dependency_code_hashes": [],
            "missing_fact_kinds": ["event:acquire", "ownership_transfer"],
            "coverage": "partial",
        },
    }

    EvidenceCompletionQueue._apply_fact_delta_to_decision_context(
        issue,
        [
            {
                "fact_uid": "FACT_TRANSFER",
                "fact_kind": "ownership_transfer",
                "dependency_code_hash": "transfer-code-sha",
            }
        ],
    )

    assert issue["missing_fact_kinds"] == []
    assert issue["decision_fact_coverage"] == "complete"
