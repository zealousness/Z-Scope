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
        "function_context": {
            "code": "uint32_t len = header.length;\nmemcpy(dst, src, len);"
        }
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
                    {"kind": "fd_open", "line": 20, "variable": "fd", "expression": "int fd = open(path, 0);"},
                    {"kind": "return_without_fd_close", "line": 22, "variable": "fd", "expression": "return -1;"},
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
                    {"kind": "fd_open", "line": 10, "variable": "fd", "expression": "int fd = open(path, 0);"},
                    {"kind": "return_without_fd_close", "line": 12, "variable": "fd", "expression": "return fd;"},
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
            "ast_cfg": {"events": [{"kind": "owned_member_leak", "line": 8, "variable": "node->children"}]},
        },
    }
    evidence = {"function_context": {"code": "node->children = service_alloc_child();\nSAFE_FREE(node);"}}

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
            "ast_cfg": {"events": [{"kind": "owned_member_leak", "line": 7, "variable": "node->children"}]},
        },
    }
    evidence = {"function_context": {"code": "SAFE_FREE(node);"}}

    queue.complete(issue, validator_data={"verdict": "uncertain"}, validation_evidence=evidence)

    assert deterministic_decision_proof(issue, outcome="confirm") is None
